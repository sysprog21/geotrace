#!/usr/bin/env bash

# Verify clang-format-20 conformance for tracked C/H files.
#
# clang-format-20 is pinned: 22 reformats the _Static_assert chain in
# src/world-map.c differently, so a floating version would flip the check
# red on a runner image bump rather than on a real style change.

set -e -u -o pipefail

if [ -z "${CLANG_FORMAT:-}" ]; then
    if command -v clang-format-20 > /dev/null 2>&1; then
        CLANG_FORMAT="clang-format-20"
    else
        echo "Error: clang-format-20 is required (other versions differ in style)" >&2
        exit 1
    fi
fi

version=$("$CLANG_FORMAT" --version 2> /dev/null | grep -oE 'version [0-9]+' | awk '{print $2}')
if [ "$version" != "20" ]; then
    echo "Error: \$CLANG_FORMAT ($CLANG_FORMAT) reports version '$version', expected 20" >&2
    exit 1
fi

mapfile -d '' -t FILES < <(git ls-files -z -- 'src/*.c' 'src/*.h' 'include/geotrace/*.h' 'tests/*.c' 'tests/*.h')

# An empty set means the pathspec stopped matching (directory rename, broken
# git invocation), not a clean tree. Without this the check goes green while
# enforcing nothing.
if [ ${#FILES[@]} -eq 0 ]; then
    echo "Error: no tracked C sources matched; pathspec is stale" >&2
    exit 1
fi

# One scratch file for the whole run, removed on any exit: clang-format failing
# under set -e would otherwise skip the cleanup and leave it behind.
expected=$(mktemp)
trap 'rm -f "$expected"' EXIT

ret=0
for file in "${FILES[@]}"; do
    "$CLANG_FORMAT" "$file" > "$expected"
    if ! diff -u -p --label="$file" --label="expected coding style" "$file" "$expected"; then
        ret=1
    fi
done

exit $ret
