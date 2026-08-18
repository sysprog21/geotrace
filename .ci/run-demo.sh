#!/usr/bin/env bash

# Run <binary> --demo for <seconds> and require that it actually rendered.
#
# usage: run-demo.sh <binary> [seconds] [extra args...]
#
# Exit status alone is a weak gate: the binary handles SIGTERM, so a run that
# deadlocked before drawing anything exits exactly like a healthy one (0, or
# 124 when the kill escalates). Frames are the progress signal instead. The
# capture, resolver, and UI threads all have to make progress for bytes to
# reach stdout, so this doubles as the integration exercise for a sanitizer
# build, which unit tests alone never give.

set -e -u -o pipefail

BIN=${1:?usage: run-demo.sh <binary> [seconds] [extra args...]}
SECONDS_TO_RUN=${2:-3}
shift 2 2> /dev/null || shift $#

# One frame of a small terminal is already a few hundred bytes, and a healthy
# 3 s run writes tens of kilobytes. Well below one frame means it never drew.
MIN_OUTPUT_BYTES=2048

# And a ceiling, because the frame pacer has no other gate: a UI that never
# sleeps just redraws as fast as the terminal accepts. Volume is comparable
# across machines here because a non-tty stdout means the fixed 100x32 fallback
# size, so a caller that knows the frame rate can set a tight bound:
#
#   3 s at --fps=1  ~23 KB rendered, ~425 KB with the sleep removed
#   3 s at --fps=60 ~197 KB
#
# The default is loose enough for any rate; DEMO_MAX_BYTES tightens it for a
# run whose rate is known.
MAX_OUTPUT_BYTES=${DEMO_MAX_BYTES:-1048576}

out=$(mktemp)
trap 'rm -f "$out"' EXIT

status=0
sh scripts/run-with-timeout.sh "$SECONDS_TO_RUN" "$BIN" --demo "$@" > "$out" || status=$?

# 124 is the timeout kill: expected for a UI that runs until interrupted.
if [ "$status" -ne 0 ] && [ "$status" -ne 124 ]; then
    echo "$BIN --demo failed with status $status" >&2
    exit 1
fi

bytes=$(wc -c < "$out")
if [ "$bytes" -lt "$MIN_OUTPUT_BYTES" ]; then
    echo "$BIN --demo rendered $bytes bytes in ${SECONDS_TO_RUN}s, expected at least $MIN_OUTPUT_BYTES" >&2
    echo "(exit status was $status, so a hang before the first frame looks like success without this check)" >&2
    exit 1
fi

if [ "$bytes" -gt "$MAX_OUTPUT_BYTES" ]; then
    echo "$BIN --demo $* wrote $bytes bytes in ${SECONDS_TO_RUN}s, more than $MAX_OUTPUT_BYTES: the frame pacer is not sleeping" >&2
    exit 1
fi

# Bytes alone would also be satisfied by a loop emitting nothing but escape
# sequences, so require map content: the grid is box drawing (U+2500 block,
# bytes e2 94 xx) and land is braille (U+2800 block, e2 a0 xx). One of the two
# is present in every frame the renderer actually composes.
if ! LC_ALL=C grep -qa -e "$(printf '\342\224')" -e "$(printf '\342\240')" "$out"; then
    echo "$BIN --demo wrote $bytes bytes but no map glyphs; the renderer produced escapes only" >&2
    exit 1
fi

# The map alone is static: it renders whether or not a single packet ever
# arrives. Destination markers do not. A marker exists only for a connection
# the source produced, the resolver geolocated, and the UI drained, so one of
# these glyphs is the whole pipeline reporting for duty:
#   U+2218 ring, U+25CE bullseye, U+25C9 fisheye (e2 88 98 / e2 97 8e / e2 97 89)
# The home marker (U+25CF) is drawn unconditionally and proves nothing.
if ! LC_ALL=C grep -qa -e "$(printf '\342\210\230')" -e "$(printf '\342\227\216')" \
    -e "$(printf '\342\227\211')" "$out"; then
    echo "$BIN --demo drew the map but no destination markers in ${SECONDS_TO_RUN}s; the source or resolver never delivered" >&2
    exit 1
fi

echo "$BIN --demo $* rendered $bytes bytes in ${SECONDS_TO_RUN}s"
