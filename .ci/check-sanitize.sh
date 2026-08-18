#!/usr/bin/env bash

# Build and run the unit tests under ASan+UBSan and then under TSan, plus a
# short ASan demo run so the UI/resolver path gets instrumented too.
#
# LeakSanitizer is left on for --demo only. The live-capture path drops
# privileges via setuid, which revokes the ptrace LSan needs on its own
# threads, so it aborts at exit on Linux for reasons unrelated to geotrace.

set -e -u -o pipefail

jobs=$( (nproc || sysctl -n hw.ncpu) 2> /dev/null || echo 2)

export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"

ASAN_CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"

make -j"$jobs" \
    OUT=build/ci-asan \
    EXTRA_CFLAGS="$ASAN_CFLAGS" \
    EXTRA_LDFLAGS="-fsanitize=address,undefined" \
    all tests

# 5 s of synthetic traffic, longer than the plain build's 3 s: an instrumented
# binary on a loaded runner needs more room before the byte floor is a fair
# gate. run-demo.sh requires rendered output, so a run that wedges before the
# first frame fails instead of looking like a clean exit.
# stdout goes to a scratch file there; stderr stays on the terminal because it
# carries the sanitizer report.
.ci/run-demo.sh ./build/ci-asan/geotrace 5

# TSan: the whole point of this tree is a capture thread, a resolver thread,
# and the UI sharing two rings.
make -j"$jobs" \
    OUT=build/ci-tsan \
    EXTRA_CFLAGS="-O1 -g -fsanitize=thread -fno-omit-frame-pointer" \
    EXTRA_LDFLAGS="-fsanitize=thread" \
    all tests

# The unit tests exercise one ring at a time with synthetic producers. Only the
# demo run puts the real source, resolver, and UI threads on the same rings at
# once, which is where an ordering bug would actually live.
#
# 8 s rather than the ASan run's 5: TSan instruments every memory access, and
# the gate now waits on a destination marker, which needs a demo packet to make
# it through the source, the resolver, and a UI frame.
TSAN_OPTIONS="halt_on_error=1" .ci/run-demo.sh ./build/ci-tsan/geotrace 8

echo "Sanitizer checks passed."
