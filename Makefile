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

indent:
	$(Q)find src include tests -type f \( -name '*.c' -o -name '*.h' \) 2>/dev/null \
	    | xargs -r $(CLANG_FORMAT) -i

# Land mask pipeline: emit a C array from the tracked zlib-compressed blob via
# scripts/bin2c.py. The blob in assets/ is Natural Earth 1:110m land at 360x180.
$(OUT)/land-mask.c: assets/land-mask.bin scripts/bin2c.py | $(OUT)
	$(VECHO) "  BIN2C\t$@\n"
	$(Q)python3 scripts/bin2c.py $< land_mask_zlib $@

# Compile rule for generated sources.
$(OUT)/%.o: $(OUT)/%.c | $(OUT)
	$(VECHO) "  CC\t$@\n"
	$(Q)$(CC) -o $@ $(CFLAGS) -c -MMD -MF $@.d $<

.PHONY: all debug sanitize run tests check clean distclean install indent

# Auto-deps
-include $(deps)
