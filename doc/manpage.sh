#!/bin/sh
# Regenerate doc/tcpflow.1 from doc/tcpflow.1.md (needs pandoc).
# With --check, only check that the committed page shows the same text as the
# Markdown (needs pandoc and groff; CI runs this). The rendered text is
# compared, so that another pandoc version does not count as a change.
set -eu
cd "$(dirname "$0")"
gen() { pandoc -s -f markdown-smart -t man tcpflow.1.md -o "$1"; }
show() { MANWIDTH=80 groff -man -Tascii "$1" 2>/dev/null | col -bx; }

if [ "${1-}" != --check ]; then
    gen tcpflow.1
    exit 0
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
gen "$tmp/new.1"
show tcpflow.1 > "$tmp/old.txt"
show "$tmp/new.1" > "$tmp/new.txt"
if ! diff -u "$tmp/old.txt" "$tmp/new.txt"; then
    echo "doc/tcpflow.1 is out of date: run doc/manpage.sh" >&2
    exit 1
fi
