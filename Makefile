# Top-level Makefile
#
# Layout:
#   src/                 .c sources
#   include/geotrace/    public headers
#   tests/               unit test programs
#   scripts/             Python build helpers (bin2c, land mask extractor)
#   mk/                  focused make fragments
#   build/               artifacts (gitignored)

# Skip-deps detection must be set before deps.mk loads.
include mk/common.mk
include mk/toolchain.mk
include mk/deps.mk
include mk/config.mk

# Pin the default goal explicitly. Without this, the very first rule make sees
# becomes the default — and the make-dir template for $(OUT) below would steal
# it, making bare `make` resolve to `make build` (just the build/ directory).
.DEFAULT_GOAL := all

# Required flags — strict C11, all warnings as errors.
CFLAGS  += -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wstrict-prototypes -Werror
CFLAGS  += -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
CFLAGS  += -Iinclude -Isrc

# Default to -O2 -g for `make` (release build with symbols).
CFLAGS  += -O2 -g

# Version stamp — git describe if available.
GEOTRACE_VERSION := $(shell git describe --always --dirty 2>/dev/null || echo unknown)
CFLAGS  += -DGEOTRACE_VERSION=\"$(GEOTRACE_VERSION)\"

# Variant flags appended after base CFLAGS so they take precedence (e.g. -O0
# in `make debug` overrides the -O2 above).
CFLAGS  += $(EXTRA_CFLAGS)
LDFLAGS += $(EXTRA_LDFLAGS)

# Threading
LDFLAGS += -lpthread

# Math (sin/fmod). macOS folds libm into libSystem so -lm is a no-op there;
# glibc requires the explicit link.
ifneq ($(UNAME_S),Darwin)
LDFLAGS += -lm
endif

BIN := $(OUT)/geotrace

# Source enumeration. Sources land here as phases progress.
SRCS := $(wildcard src/*.c)
OBJS := $(patsubst src/%.c,$(OUT)/%.o,$(SRCS))
deps := $(OBJS:%.o=%.o.d)

# Generated sources (e.g., land-mask.c from tools/bin2c).
GENERATED_SRCS :=
ifeq ($(ENABLE_LAND_MASK),1)
GENERATED_SRCS += $(OUT)/land-mask.c
endif
GENERATED_OBJS := $(GENERATED_SRCS:.c=.o)

# Output directory
$(eval $(call make-dir,$(OUT)))

# Compile rule
$(eval $(call compile-rule,OUT,src))

# Link
$(BIN): $(OBJS) $(GENERATED_OBJS) | $(OUT)
	$(VECHO) "  LD\t$@\n"
	$(Q)$(CC) $^ -o $@ $(LDFLAGS)

all: $(BIN)

# Build variants. Pass extra flags through EXTRA_CFLAGS / EXTRA_LDFLAGS rather
# than overriding CFLAGS — that way -Iinclude, -std=c11, etc. are preserved.
debug:
	$(Q)$(MAKE) --no-print-directory \
	    OUT=build/debug \
	    EXTRA_CFLAGS="-O0 -fsanitize=address,undefined -fno-omit-frame-pointer" \
	    EXTRA_LDFLAGS="-fsanitize=address,undefined" all

sanitize:
	$(Q)$(MAKE) --no-print-directory \
	    OUT=build/sanitize \
	    EXTRA_CFLAGS="-O0 -fsanitize=address,undefined -fno-omit-frame-pointer" \
	    EXTRA_LDFLAGS="-fsanitize=address,undefined" all
	$(Q)$(MAKE) --no-print-directory \
	    OUT=build/sanitize-tsan \
	    EXTRA_CFLAGS="-O0 -fsanitize=thread -fno-omit-frame-pointer" \
	    EXTRA_LDFLAGS="-fsanitize=thread" tests

# Build then run. Linux (AF_PACKET) and macOS (BPF) both need root for live
# capture; the binary's cli_ensure_capture_privileges re-execs through sudo
# itself and appends --drop-uid/--drop-gid so the UI runs unprivileged.
#   make run                  # live capture
#   make run ARGS=--demo      # synthetic traffic, no sudo
#   make run ARGS="-i en0 --green"
run: $(BIN)
	$(Q)./$(BIN) $(ARGS)

# Test framework hooks
include mk/tests.mk

# The smoke run goes through .ci/run-demo.sh so `make check` and CI apply the
# same gate: exiting cleanly is not enough, the run has to have rendered
# frames. The binary handles SIGTERM, so a deadlock before the first frame
# exits exactly like a healthy run.
check: all tests
	$(Q)$(call notice, Smoke run: --demo for 3s)
	$(Q).ci/run-demo.sh $(BIN) 3 >/dev/null || { \
	    $(call error_msg, --demo smoke run failed); exit 1; \
	}
	$(Q)$(call notice, [OK])

# Deductive verification (Frama-C/WP) of the ACSL in include/geotrace/util.h
# and src/ring.c. Optional: Frama-C is not a build dependency, so this is not
# wired into `check`. Each file's header comment records what is proved, what is
# assumed, and what is still open.
FRAMA_C ?= frama-c

# One process over all of VERIFY_SRCS: every invocation reparses the whole libc
# first, so a second process is a second parse for nothing.
#
# util.h is all static inline, so it needs a host TU to land in the AST, and
# packet-decode.c is the smallest one that includes it. Exactly one such TU
# belongs here: a second duplicates every inline goal (they reappear with a
# "_0" suffix, failures included), and adding resolver.c cost 100 goals and a
# third of the cold run for no extra coverage, since the inlines are analyzed
# whether or not a listed TU calls them.
VERIFY_SRCS := src/ring.c src/packet-decode.c

VERIFY_FCTS := slot_at,take_locked,ring_put_latest,ring_take,ring_try_take \
               ring_shutdown,ring_size,ring_create \
               geotrace_elapsed_ns,geotrace_abs_int,geotrace_min_int \
               geotrace_max_int,geotrace_clamp_int,geotrace_clamp_double \
               geotrace_clamp01,geotrace_max_float \
               geotrace_copy_cstr,geotrace_copy_span
comma := ,
empty :=
space := $(empty) $(empty)

# Timeout dominates cold runs: every unprovable goal burns it in full, every
# time. Measured here, the slowest goal that does prove takes ~6s, so 15s is
# ~2.5x margin. That margin is machine-dependent -- on a slower or loaded box
# that goal gets cut off, appears in the baseline diff as a new unproved name,
# and fails the build for a reason in the environment. Raise WP_TIMEOUT there
# rather than editing the baseline.
WP_TIMEOUT ?= 15
WP_PAR     ?= $(shell sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)

# WP caches verdicts under .frama-c/, which is why a warm run is several times
# faster; parsing is ~1s, so the rest is prover time. Do not "improve" it with
# -wp-cache-dir: measured markedly slower than the default session cache.

# Frama-C exits 0 with goals unproved, so without this the target would report
# success having proved nothing. The baseline pins the unproved goals by name
# (a new one fails; one that starts proving fails too, so it cannot rot) and the
# proved/total tally (so deleting a contract cannot slip through by removing the
# goal). Names only, never WP's status word -- see verify-run for why that word
# is not portable. Intended changes go through `make verify-baseline`.
WP_BASELINE := .ci/wp-known-unproved.txt

# Noise that is not actionable here, silenced at the source so the run stays
# readable:
#   annot:missing-spec=inactive  memcpy/strlen lack exits+terminates; fixing it
#                                means editing Frama-C's libc.
#   -no-warn-unaligned-pointer   RTE emits \aligned / \valid_function guards WP
#   -rte-no-pointer-call         cannot express, then warns it skipped them.
#                                Nothing here is unaligned or calls a function
#                                pointer, so no check is lost.
# pedantic-assigns stays ON: a contract that forgot its frame is a real defect.
#
# Alt-Ergo alone, and named rather than left to WP's default set. Adding Z3
# closes one more goal (xmalloc's precondition in ring_create) but then BOTH
# provers run every unprovable goal to the full budget: cold 54s to 98s, warm
# 16s to 60s. Wrong side of that trade.
#
# Naming it also makes the baseline reproducible, since WP's default is whatever why3 detected
# on the machine, so a developer box with extra provers installed could reach a
# different verdict than CI and fail the diff for a reason in the environment
# rather than the code.
#
# Deferred (=, not :=) so the WP_PAR probe forks only under `make verify`, not
# on every `make`, `make clean`, and tab-completion.
WPFLAGS = -wp -wp-rte -wp-model Typed+cast -wp-prover alt-ergo \
           -wp-timeout $(WP_TIMEOUT) -wp-par $(WP_PAR) \
           -wp-no-warn-memory-model -kernel-warn-key annot:missing-spec=inactive \
           -no-warn-unaligned-pointer -rte-no-pointer-call

verify-run: | $(OUT)
	$(Q)command -v $(FRAMA_C) >/dev/null || { \
	    $(call error_msg, $(FRAMA_C) not found; opam install frama-c); exit 1; \
	}
	$(Q)$(call notice, verifying $(VERIFY_SRCS) [timeout $(WP_TIMEOUT)s par $(WP_PAR)])
	$(Q)$(FRAMA_C) -cpp-extra-args="-Iinclude" $(VERIFY_SRCS) $(WPFLAGS) \
	    -wp-fct $(subst $(space),$(comma),$(strip $(VERIFY_FCTS))) \
	    >$(OUT)/verify.log 2>&1 || { cat $(OUT)/verify.log; exit 1; }
	@# Filters the terminal copy only; $(OUT)/verify.log keeps every line, so
	@# the full log is what gets read when something went wrong.
	@#
	@# What is filtered: WP models void * as char *, so memcpy on typed fields
	@# reports a pointer mismatch. Same artifact throughout and not fixable
	@# here -- memcpy on a typed field is correct C, and C's implicit void *
	@# conversion warns identically (measured).
	@#
	@# Matched as the whole two-line message: WP prints uncategorized warnings
	@# as a "file:line: Warning:" header plus an indented body, so a
	@# header-shaped pattern would strip the location off every one of them,
	@# including soundness-relevant ones like "Missing decreases clause".
	$(Q)perl -0777 -pe 's/^\[wp\] [^\n]*: Warning: *\n[ ]+Cast with incompatible pointers types[^\n]*\n//mg' \
	    $(OUT)/verify.log
	@# Goal NAME only, never WP's status word. Timeout and Failure both mean
	@# "not proved", but which one appears depends on the budget: at the local
	@# 15s Alt-Ergo is cut off and reports Timeout, while at a larger budget it
	@# reaches a verdict and reports Failure. Pinning the word made the baseline
	@# fail across machines for a difference that carries no information.
	$(Q){ sed -n 's/^\[wp\] \[[A-Za-z]*\] \(typed[a-zA-Z_0-9]*\).*/unproved \1/p' \
	        $(OUT)/verify.log | sort -u; \
	      sed -n 's/^\[wp\] \(Proved goals: *[0-9]* \/ [0-9]*\).*/total \1/p' \
	        $(OUT)/verify.log; \
	    } > $(OUT)/wp-unproved.txt

verify: verify-run
	$(Q)test -f $(WP_BASELINE) || { \
	    $(call error_msg, $(WP_BASELINE) is missing - it must be tracked in git); \
	    $(call error_msg, seed it with: make verify-baseline); \
	    exit 1; \
	}
	$(Q)diff -u $(WP_BASELINE) $(OUT)/wp-unproved.txt || { \
	    $(call error_msg, WP goal status changed vs $(WP_BASELINE)); \
	    $(call error_msg, '-' lines disappeared - a goal now proves$(comma) or a contract was deleted); \
	    $(call error_msg, '+' lines are new - a regression$(comma) or a contract was added); \
	    $(call error_msg, if the change is intended: make verify-baseline); \
	    exit 1; \
	}
	$(Q)$(call notice, WP goal status matches baseline)

# Re-seed the baseline after an intended change. Separate target so that
# refreshing it is always a deliberate act with its own diff to review, never a
# side effect of running the checker.
verify-baseline: verify-run
	$(Q)cp $(OUT)/wp-unproved.txt $(WP_BASELINE)
	$(Q)$(call notice, reseeded $(WP_BASELINE) - review the diff before committing)

# Maintenance targets
clean:
	$(Q)rm -rf $(OUT)

distclean: clean
	$(Q)rm -f compile_commands.json

PREFIX  ?= /usr/local
DESTDIR ?=

install: $(BIN)
	$(Q)install -d $(DESTDIR)$(PREFIX)/bin
	$(Q)install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/geotrace
	$(Q)$(call notice, installed -> $(DESTDIR)$(PREFIX)/bin/geotrace)

# Must match .ci/check-format.sh: clang-format 22 reformats the _Static_assert
# chain in src/world-map.c differently, so a bare `clang-format` writes a tree
# CI rejects. Override when the binary is not on PATH under this name.
CLANG_FORMAT ?= clang-format-20

# ACSL lives in comments, and clang-format rewraps a long "/*@ ... */" by
# inserting a " * " continuation, turning it into a parse error. That happened
# here and only `make verify` caught it, so re-parse afterwards (~1s, skipped
# when Frama-C is absent). Prefer the one-line "//@ assert ..." form near the
# column limit; clang-format leaves "//" alone.
#
# Order-only on $(OUT): the re-parse redirects into $(OUT)/acsl-parse.log, and
# on a clean tree that redirect fails before Frama-C starts, which the "||"
# would then report as a broken annotation.
indent: | $(OUT)
	$(Q)find src include tests -type f \( -name '*.c' -o -name '*.h' \) 2>/dev/null \
	    | xargs -r $(CLANG_FORMAT) -i
	$(Q)command -v $(FRAMA_C) >/dev/null || exit 0; \
	$(FRAMA_C) -cpp-extra-args="-Iinclude -Isrc" $(VERIFY_SRCS) -print >/dev/null 2>$(OUT)/acsl-parse.log \
	    || { $(call error_msg, formatting broke an ACSL annotation:); \
	         grep -E 'annot-error|Failure' $(OUT)/acsl-parse.log | head -4; exit 1; }

# Land mask pipeline: emit a C array from the tracked zlib-compressed blob via
# scripts/bin2c.py. The blob in assets/ is Natural Earth 1:110m land at 360x180.
$(OUT)/land-mask.c: assets/land-mask.bin scripts/bin2c.py | $(OUT)
	$(VECHO) "  BIN2C\t$@\n"
	$(Q)python3 scripts/bin2c.py $< land_mask_zlib $@

# Compile rule for generated sources.
$(OUT)/%.o: $(OUT)/%.c | $(OUT)
	$(VECHO) "  CC\t$@\n"
	$(Q)$(CC) -o $@ $(CFLAGS) -c -MMD -MF $@.d $<

.PHONY: all debug sanitize run tests check verify verify-run verify-baseline clean distclean install indent

# Auto-deps
-include $(deps)
