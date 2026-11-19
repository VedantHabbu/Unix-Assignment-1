#!/usr/bin/env bash
# setup_demo.sh - creates a test folder full of permission problems
# so perm_scanner.sh has something to find in the demo.

DEMO="${1:-demo}"
rm -rf "$DEMO"
mkdir -p "$DEMO"/{docs,shared,public,tmp,uploads,bin,.cache,build}
cd "$DEMO" || exit 1

# --- normal, safe files (should NOT be reported) ---
echo "hello"        > docs/readme.txt;   chmod 644 docs/readme.txt
echo "echo hi"      > bin/tool.sh;       chmod 755 bin/tool.sh     # exec in bin is allowed
echo "a,b,c"        > tmp/data.csv;      chmod 644 tmp/data.csv
chmod 1777 public                                                  # sticky dir, like /tmp

# --- problems the scanner should catch ---
echo "secret notes" > docs/notes.txt;    chmod 666 docs/notes.txt  # world-writable file
chmod 777 shared                                                   # world-writable dir
echo "rm -rf ~"     > tmp/run.sh;        chmod 755 tmp/run.sh      # executable in tmp
echo "jpgdata"      > uploads/photo.jpg; chmod 755 uploads/photo.jpg  # executable upload
echo "x"            > "uploads/my file.txt"; chmod 777 "uploads/my file.txt"  # both, with a space
echo "binary"       > bin/suid_tool;     chmod 4755 bin/suid_tool  # setuid

# --- problems inside EXCLUDED folders (should be ignored) ---
echo "junk"         > .cache/junk;       chmod 777 .cache/junk
echo "out"          > build/out.bin;     chmod 777 build/out.bin

cd - > /dev/null
echo "Demo tree created in ./$DEMO"
ls -lR "$DEMO"
