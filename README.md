# Filesystem Permission Anomaly Scanner

**UNIX System Programming (BCS515C) – Assignment 1, Project 39**
Vedant Habbu (1RF24CS180), Class 5C · RV Institute of Technology and Management

A Bash utility that recursively scans a directory tree for permission problems defined in a policy file. It reports the owner, group and mode of each finding and suggests a `chmod` command to fix it. It is **audit-only by default**: a file is changed only when that individual repair is approved.

## Problem statement

> Recursively scan a specified tree for permission patterns defined in a policy, such as world-writable files or executable files in selected locations. Exclude configured paths, report ownership and modes, and generate suggested remediation commands. Operate in audit-only mode unless each repair is explicitly approved.

## Files

| File | Purpose |
|------|---------|
| `perm_scanner.sh` | The scanner |
| `policy.conf` | Rules: which checks to run and which paths to exclude |
| `setup_demo.sh` | Creates a `demo/` test tree with planted permission problems |
| `audit_report_*.txt` | Sample reports from the test runs |
| `screenshots/` | Terminal screenshots of the test runs |

## Policy file format

```
CHECK world_writable        # files/dirs writable by others (sticky dirs ignored)
CHECK executable <dir>      # executable files inside <dir>
CHECK setuid                # files with the SUID or SGID bit
EXCLUDE <path>              # do not scan this path
```

Relative paths are relative to the directory being scanned.

## Usage

```bash
./perm_scanner.sh [-p policy.conf] [-o report.txt] [--fix] <directory>
```

| Option | Purpose |
|--------|---------|
| `-p, --policy FILE` | Policy file (default: `policy.conf`) |
| `-o, --output FILE` | Report file (default: `audit_report_<date>_<time>.txt`) |
| `--fix` | Ask y/N before each individual fix |
| `-h, --help` | Show help |

Exit codes: `0` no anomalies · `1` usage or read error · `2` anomalies found.

## Running the demo

Git does not keep most permission bits, so recreate the test tree after cloning:

```bash
chmod +x *.sh
./setup_demo.sh                  # build demo/ with planted problems
./perm_scanner.sh demo           # audit only – changes nothing
./perm_scanner.sh --fix demo     # approve or skip each fix (default: No)
./perm_scanner.sh demo           # re-scan to confirm the fixes
```

The audit finds 7 anomalies in the demo tree: 3 world-writable, 1 SUID, and 3 executables in `tmp/` and `uploads/`. The safe files, the sticky `public/` directory and the excluded `.cache/` and `build/` folders are not reported.

## Requirements

Linux with Bash and GNU `find`, `stat` and `awk`. It was tested on Fedora Linux.
