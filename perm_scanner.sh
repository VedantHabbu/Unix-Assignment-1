#!/usr/bin/env bash
#
# perm_scanner.sh - Filesystem Permission Anomaly Scanner
#
# Recursively scans a directory tree for permission problems defined in a
# policy file, reports owner/group/mode for every finding, and suggests a
# chmod command to fix each one.
#
# Default is AUDIT-ONLY mode: nothing is changed.
# With --fix, every single repair is shown and must be approved (y/N).
#
# Usage:
#   ./perm_scanner.sh [-p policy.conf] [-o report.txt] [--fix] <directory>
#
# Exit codes: 0 = no anomalies, 1 = usage/error, 2 = anomalies found

set -u

# ---------------------------------------------------------------- defaults --
POLICY="policy.conf"
REPORT=""
FIX=0
ROOT=""

usage() {
    cat <<EOF
Usage: $0 [options] <directory>

Options:
  -p, --policy FILE   policy file to use (default: policy.conf)
  -o, --output FILE   write the audit report to FILE
                      (default: audit_report_<date>_<time>.txt)
      --fix           interactive repair mode: ask before EACH fix
  -h, --help          show this help

Policy file format (one rule per line, # starts a comment):
  CHECK world_writable        files/dirs writable by others (sticky dirs ignored)
  CHECK executable <dir>      executable files inside <dir>
  CHECK setuid                files with the SUID or SGID bit set
  EXCLUDE <path>              do not scan this path
  (relative paths are taken relative to the scanned directory)
EOF
}

die() { echo "Error: $*" >&2; exit 1; }

# ------------------------------------------------------- argument parsing --
while [ $# -gt 0 ]; do
    case "$1" in
        -p|--policy) [ $# -ge 2 ] || die "$1 needs a file name"; POLICY="$2"; shift 2 ;;
        -o|--output) [ $# -ge 2 ] || die "$1 needs a file name"; REPORT="$2"; shift 2 ;;
        --fix)       FIX=1; shift ;;
        -h|--help)   usage; exit 0 ;;
        -*)          echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
        *)           [ -z "$ROOT" ] || die "only one directory can be scanned"; ROOT="$1"; shift ;;
    esac
done

[ -n "$ROOT" ]   || { usage >&2; exit 1; }
[ -d "$ROOT" ]   || die "'$ROOT' is not a directory"
[ -r "$POLICY" ] || die "cannot read policy file '$POLICY'"

ROOT=$(cd "$ROOT" && pwd)                       # absolute, no trailing slash
[ -n "$REPORT" ] || REPORT="audit_report_$(date +%Y%m%d_%H%M%S).txt"

# Turn a policy path into an absolute path under the scan root.
resolve() {
    local p="${1%/}"
    case "$p" in
        /*) echo "$p" ;;
        *)  echo "$ROOT/$p" ;;
    esac
}

# ----------------------------------------------------- read the policy file --
# awk strips comments and blank lines, and upper-cases the keyword.
CHECKS=()        # e.g. "world_writable", "executable|/abs/dir", "setuid"
EXCLUDES=()      # absolute paths

while IFS=$'\t' read -r kw arg1 rest; do
    case "$kw" in
        CHECK)
            case "$arg1" in
                world_writable|setuid)
                    CHECKS+=("$arg1") ;;
                executable)
                    [ -n "$rest" ] || die "policy: 'CHECK executable' needs a directory"
                    CHECKS+=("executable|$(resolve "$rest")") ;;
                *)  die "policy: unknown check '$arg1'" ;;
            esac ;;
        EXCLUDE)
            [ -n "$arg1" ] || die "policy: EXCLUDE needs a path"
            EXCLUDES+=("$(resolve "$arg1${rest:+ $rest}")") ;;
        *)  die "policy: unknown keyword '$kw'" ;;
    esac
done < <(awk '
    { sub(/#.*/, "") }                 # drop comments
    NF == 0 { next }                   # skip blank lines
    {
        kw = toupper($1); a1 = $2
        $1 = ""; $2 = ""; rest = $0
        gsub(/^[ \t]+|[ \t]+$/, "", rest)
        printf "%s\t%s\t%s\n", kw, a1, rest
    }' "$POLICY")

[ ${#CHECKS[@]} -gt 0 ] || die "policy file contains no CHECK rules"

# ------------------------------------------- build the find exclusion part --
# Result looks like:  ( -path A -o -path B ) -prune -o
PRUNE=()
for ex in "${EXCLUDES[@]+"${EXCLUDES[@]}"}"; do
    PRUNE+=(-path "$ex" -o)
done
if [ ${#PRUNE[@]} -gt 0 ]; then
    unset 'PRUNE[${#PRUNE[@]}-1]'                 # drop the trailing -o
    PRUNE=( \( "${PRUNE[@]}" \) -prune -o )
fi

# run_find <start-dir> <tests...>  -> NUL-separated list of matching paths
run_find() {
    local start="$1"; shift
    find "$start" "${PRUNE[@]+"${PRUNE[@]}"}" "$@" -print0 2>/dev/null
}

# ------------------------------------------------------------ run the scan --
F_CHECK=()   # label of the rule that matched
F_PATH=()    # path of the file
F_FIX=()     # chmod argument that fixes it

add_findings() {        # add_findings <label> <chmod-op> <start-dir> <find tests...>
    local label="$1" op="$2" start="$3" p; shift 3
    while IFS= read -r -d '' p; do
        F_CHECK+=("$label"); F_PATH+=("$p"); F_FIX+=("$op")
    done < <(run_find "$start" "$@")
}

WARNINGS=()
for rule in "${CHECKS[@]}"; do
    case "$rule" in
        world_writable)
            # files, plus directories that are NOT sticky (sticky ones like /tmp are fine)
            add_findings "WORLD-WRITABLE" "o-w" "$ROOT" \
                \( -type f -o \( -type d ! -perm -1000 \) \) -perm -0002 ;;
        setuid)
            add_findings "SETUID/SETGID" "ug-s" "$ROOT" -type f -perm /6000 ;;
        executable\|*)
            dir="${rule#executable|}"
            if [ -d "$dir" ]; then
                add_findings "EXEC-IN-${dir#"$ROOT"/}" "a-x" "$dir" -type f -perm /111
            else
                WARNINGS+=("executable check: '$dir' does not exist, skipped")
            fi ;;
    esac
done

TOTAL=${#F_PATH[@]}

# ---------------------------------------------------------- write the report --
generate_report() {
    local i info owner group octal sym
    echo "=================================================================="
    echo " FILESYSTEM PERMISSION AUDIT REPORT"
    echo "=================================================================="
    echo " Date        : $(date '+%Y-%m-%d %H:%M:%S')"
    echo " Host / user : $(hostname) / $(id -un)"
    echo " Scanned     : $ROOT"
    echo " Policy file : $POLICY"
    echo " Mode        : $([ "$FIX" -eq 1 ] && echo 'INTERACTIVE FIX' || echo 'AUDIT ONLY (no changes made)')"
    echo " Checks      : $(printf '%s ' "${CHECKS[@]}" | sed "s#|$ROOT/# #g; s#|# #g")"
    if [ ${#EXCLUDES[@]} -gt 0 ]; then
        echo " Excluded    : ${EXCLUDES[*]}"
    fi
    for w in "${WARNINGS[@]+"${WARNINGS[@]}"}"; do echo " WARNING     : $w"; done
    echo "------------------------------------------------------------------"

    if [ "$TOTAL" -eq 0 ]; then
        echo " No permission anomalies found."
    fi

    for ((i = 0; i < TOTAL; i++)); do
        info=$(stat -c '%U|%G|%a|%A' -- "${F_PATH[i]}")
        IFS='|' read -r owner group octal sym <<< "$info"
        printf '%3d. [%s] %s\n' "$((i + 1))" "${F_CHECK[i]}" "${F_PATH[i]}"
        printf '     owner=%s  group=%s  mode=%s (%s)\n' "$owner" "$group" "$octal" "$sym"
        printf '     suggested fix: chmod %s %q\n' "${F_FIX[i]}" "${F_PATH[i]}"
    done

    echo "------------------------------------------------------------------"
    echo " SUMMARY: $TOTAL anomal$([ "$TOTAL" -eq 1 ] && echo y || echo ies) found"
    if [ "$TOTAL" -gt 0 ]; then
        printf '%s\n' "${F_CHECK[@]}" | awk '{ n[$0]++ } END { for (k in n) printf "   %-28s %d\n", k, n[k] }' | sort
    fi
    echo "=================================================================="
}

generate_report | tee "$REPORT"

# ------------------------------------------------- interactive repair mode --
if [ "$FIX" -eq 1 ] && [ "$TOTAL" -gt 0 ]; then
    # Read answers from the terminal, not from the find output.
    if { : < /dev/tty; } 2>/dev/null; then TTY=/dev/tty; else TTY=/dev/stdin; fi

    applied=0; skipped=0; failed=0
    echo
    echo "Interactive fix mode: each change needs your approval (default = No)."
    { echo; echo "FIX LOG"; echo "-------"; } >> "$REPORT"

    for ((i = 0; i < TOTAL; i++)); do
        p="${F_PATH[i]}"; op="${F_FIX[i]}"
        before=$(stat -c '%a (%A)' -- "$p" 2>/dev/null) || { echo "  $p no longer exists, skipped"; continue; }
        echo
        printf '[%d/%d] %s  %s\n' "$((i + 1))" "$TOTAL" "${F_CHECK[i]}" "$p"
        printf '       current mode : %s\n' "$before"
        printf '       command      : chmod %s %q\n' "$op" "$p"
        printf '       Apply this fix? [y/N] '
        read -r ans < "$TTY" || ans=""

        case "$ans" in
            y|Y|yes|YES)
                if chmod "$op" -- "$p"; then
                    after=$(stat -c '%a (%A)' -- "$p")
                    echo "       -> APPLIED, new mode: $after"
                    echo "APPLIED  chmod $op $(printf '%q' "$p")   $before -> $after" >> "$REPORT"
                    applied=$((applied + 1))
                else
                    echo "       -> FAILED (permission denied?)"
                    echo "FAILED   chmod $op $(printf '%q' "$p")" >> "$REPORT"
                    failed=$((failed + 1))
                fi ;;
            *)
                echo "       -> skipped"
                echo "SKIPPED  chmod $op $(printf '%q' "$p")" >> "$REPORT"
                skipped=$((skipped + 1)) ;;
        esac
    done

    summary="Fixes: $applied applied, $skipped skipped, $failed failed"
    echo; echo "$summary"
    echo "$summary" >> "$REPORT"
fi

echo
echo "Report saved to: $REPORT"

[ "$TOTAL" -eq 0 ] && exit 0 || exit 2
