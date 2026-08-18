#!/usr/bin/env bash

# Security checks over first-party C sources, headers, and tests.
#
# 1. Banned functions -- unsafe libc calls with safer alternatives.
# 2. Credential / secret patterns -- catch accidental key leaks.
# 3. Dangerous preprocessor -- detect disabled hardening.
# 4. Shell escapes -- popen/system outside the one PATH-pinning wrapper.

set -u -o pipefail

failed=0

banned='(^|[^[:alnum:]_])(gets|sprintf|vsprintf|strcpy|stpcpy|strcat|atoi|atol|atoll|atof|mktemp|tmpnam|tempnam)[[:space:]]*\('
subshell='(^|[^[:alnum:]_])(popen|system)[[:space:]]*\('
secrets='(password|secret|api_key|private_key|token)[[:space:]]*=[[:space:]]*"[^"]+'
dangerous_pp='#[[:space:]]*((undef|define)[[:space:]]+__SSP__|undef[[:space:]]+_FORTIFY_SOURCE|define[[:space:]]+_FORTIFY_SOURCE[[:space:]]+0)'

# Emit "<line number>:<code>" for every line of $1 with C comments removed.
#
# A line-classifying regex cannot do this job in either direction: a banned
# name mentioned in a comment failed the build, and a line that merely looked
# like a comment continuation hid a real call. So track block-comment and
# literal state across the whole file, character by character. String and char
# literals are preserved (they are where hardcoded secrets live) and their
# contents are not scanned for comment openers, so "/*" inside a string cannot
# swallow the code that follows.
strip_comments()
{
    awk '
    {
        line = $0
        start = NR
        sub(/\r$/, "", line)   # CRLF would hide the trailing backslash below
        # Splice backslash-newline continuations first, the way a C compiler
        # does: a call, a comment delimiter, or a string can be broken across
        # physical lines that way, and scanning the pieces separately would see
        # neither half. The spliced result reports at the first line.
        while (line ~ /\\$/) {
            if ((getline nextline) <= 0) break
            line = substr(line, 1, length(line) - 1) nextline
        }
        out = ""
        i = 1
        n = length(line)
        while (i <= n) {
            c = substr(line, i, 1)
            d = substr(line, i, 2)
            if (in_block) {
                if (d == "*/") { in_block = 0; i += 2 } else { i++ }
                continue
            }
            if (in_lit) {
                out = out c
                if (c == "\\") { out = out substr(line, i + 1, 1); i += 2; continue }
                if (c == quote) in_lit = 0
                i++
                continue
            }
            if (d == "/*") { in_block = 1; i += 2; continue }
            if (d == "//") break
            if (c == "\"" || c == "\047") { in_lit = 1; quote = c }
            out = out c
            i++
        }
        printf "%d:%s\n", start, out
    }' "$1"
}

# Join a line that begins with "(" onto the one before it, but only when that
# line ends in an identifier character. A call split between its name and its
# argument list spans two physical lines, which a per-line grep would never
# match; requiring the identifier keeps unrelated parenthesised expressions
# from being glued to whatever precedes them. The first line keeps its number,
# so reports still point at the call.
join_split_calls()
{
    awk '
    NR == 1 { buf = $0; next }
    {
        rest = $0
        sub(/^[0-9]+:[[:space:]]*/, "", rest)
        if (rest ~ /^\(/ && buf ~ /[A-Za-z0-9_][[:space:]]*$/) {
            buf = buf rest
            next
        }
        print buf
        buf = $0
    }
    END { if (NR) print buf }'
}

# report <label> <pattern> [extra grep flag]
#   Matches against $code, which is numbered and comment-free, so the reported
#   hits are exactly the ones that decide pass/fail.
report()
{
    local label=$1 pattern=$2 flag=${3:-} hits
    hits=$(printf '%s\n' "$code" | grep ${flag:+"$flag"} -E "$pattern") || return 0
    echo "$label in $f:"
    printf '%s\n' "$hits"
    failed=1
}

mapfile -d '' -t FILES < <(git ls-files -z -- 'src/*.c' 'src/*.h' \
    'include/geotrace/*.h' 'tests/*.c' 'tests/*.h')

# An empty set means the pathspec stopped matching, not that the tree is
# clean. Without this the job goes green while scanning nothing.
if [ ${#FILES[@]} -eq 0 ]; then
    echo "Error: no tracked C sources matched; pathspec is stale" >&2
    exit 1
fi

# probe_popen in src/platform.c is the one sanctioned shell escape, and it is
# only sanctioned because the command it runs is prefixed with a fixed PATH.
# Check that construction here: if the pinning ever changes shape, the
# exemption below stops being justified and this fails instead of quietly
# waving the call through. Match against the comment-stripped source, so a
# comment quoting the expected text cannot satisfy the check.
#
# This is text matching, not analysis: it cannot prove the buffer is still the
# pinned one by the time popen sees it. That is what review is for; this only
# catches the pinning being dropped outright.
platform_code=$(strip_comments src/platform.c)
if ! printf '%s\n' "$platform_code" | grep -q '#define PROBE_PATH "PATH=/' \
    || ! printf '%s\n' "$platform_code" \
    | grep -q 'snprintf(pinned, sizeof(pinned), PROBE_PATH "%s", cmd)'; then
    echo "src/platform.c: probe_popen no longer builds a PATH-pinned command" >&2
    exit 1
fi

for f in "${FILES[@]}"; do
    code=$(strip_comments "$f" | join_split_calls)

    report "Banned function" "$banned"
    report "Possible hardcoded secret" "$secrets" -i
    report "Dangerous preprocessor directive" "$dangerous_pp"

    # Exempt probe_popen's own call by rewriting that one call's text, never by
    # dropping the line it sits on: a second shell escape sharing the line
    # would go with it. Count occurrences rather than lines, and exempt nothing
    # unless there is exactly one, because the text alone cannot tell the
    # PATH-pinned buffer from a second variable that happens to be spelled
    # "pinned". A call rewritten to take anything else stops matching and is
    # reported either way.
    if [ "$f" = "src/platform.c" ]; then
        sanctioned=$(printf '%s\n' "$code" | grep -oE 'popen\(pinned, "r"\)' | wc -l)
        if [ "$sanctioned" -eq 1 ]; then
            code=$(printf '%s\n' "$code" \
                | sed 's/popen(pinned, "r")/SANCTIONED_PROBE()/')
        fi
    fi
    report "popen/system outside probe_popen" "$subshell"
done

if [ $failed -eq 0 ]; then
    echo "Security checks passed."
fi

exit $failed
