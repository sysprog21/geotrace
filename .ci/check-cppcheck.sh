#!/usr/bin/env bash

# Static analysis over src/. Tests are out of scope: they include .c files
# directly to reach statics, which confuses whole-program reasoning.

set -e -u -o pipefail

mapfile -t SOURCES < <(git ls-files -z -- 'src/*.c' | tr '\0' '\n')

if [ ${#SOURCES[@]} -eq 0 ]; then
    echo "Error: no tracked C sources matched; pathspec is stale" >&2
    exit 1
fi

# cppcheck defines no platform macro of its own, so src/platform.c would take
# its "#error Unsupported platform" branch and the whole file would fail to
# parse. Select the branch the host actually builds.
case "$(uname -s)" in
    Darwin) PLATFORM_DEFINE="-D__APPLE__" ;;
    Linux) PLATFORM_DEFINE="-D__linux__" ;;
    *)
        echo "Error: unsupported platform $(uname -s)" >&2
        exit 1
        ;;
esac

# Hard timeout so a runaway analysis cannot stall CI. --max-configs=1 keeps
# the CI pass fast; deep analysis stays a local exercise.
# HAVE_PCAP/HAVE_LAND_MASK are defined so the live-capture and land-mask
# paths are the ones analyzed, matching a default build.
#
# noValidConfiguration and preprocessorErrorDirective are deliberately NOT
# suppressed: with the defines above forcing branches, a missing pcap.h or
# zlib.h on the runner would leave every file unanalyzed, and suppressing
# those two would report that as a clean run.
timeout 180 cppcheck \
    -Iinclude -Isrc \
    --platform=unix64 \
    --std=c11 \
    --enable=warning \
    --max-configs=1 --error-exitcode=1 --inline-suppr \
    --suppress=checkersReport --suppress=unmatchedSuppression \
    --suppress=missingIncludeSystem \
    --suppress=normalCheckLevelMaxBranches \
    -DHAVE_PCAP=1 -DHAVE_LAND_MASK=1 -DGEOTRACE_VERSION='"ci"' \
    -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE \
    "$PLATFORM_DEFINE" \
    "${SOURCES[@]}"
