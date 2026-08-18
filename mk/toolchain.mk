# Toolchain detection for Geotrace
#
# Linux + macOS only. Strict C11 — toolchain must support <stdatomic.h>.

ifndef _GEOTRACE_MK_TOOLCHAIN_INCLUDED
_GEOTRACE_MK_TOOLCHAIN_INCLUDED := 1

# Platform detection
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
    PRINTF := printf
else
    PRINTF := env printf
endif

# Compiler defaults
CC      ?= cc

# Detect compiler family from --version (cached single shell call)
CC_VERSION_OUTPUT := $(shell $(CC) --version 2>&1)
CC_IS_CLANG := $(if $(findstring clang,$(CC_VERSION_OUTPUT)),1,)
CC_IS_GCC   := $(if $(and $(findstring Free Software Foundation,$(CC_VERSION_OUTPUT)),$(if $(CC_IS_CLANG),,1)),1,)

ifeq ("$(CC_IS_CLANG)$(CC_IS_GCC)", "")
$(error Unsupported compiler. Only GCC and Clang are supported.)
endif

# Reject toolchains lacking <stdatomic.h>. Skip on clean to avoid spurious tmpfile work.
ifeq ($(SKIP_DEPS_CHECK),)
# Use octal \043 for `#` so the probe works under both bash (macOS) and dash
# (Debian/Ubuntu /bin/sh): dash's printf preserves unknown escapes like `\#`
# verbatim, which then fails the C parse.
ATOMIC_PROBE := $(shell printf '\043include <stdatomic.h>\nint main(void){_Atomic int x=0;return atomic_load(&x);}\n' \
    | $(CC) -std=c11 -x c -o /dev/null - 2>&1; echo $$?)
ifeq ($(filter 0,$(lastword $(ATOMIC_PROBE))),)
$(error Toolchain lacks <stdatomic.h>. Strict C11 atomics are required.)
endif
endif

# macOS Xcode 15+ warns about duplicate -l options; suppress.
ifeq ($(UNAME_S),Darwin)
    LD_VERSION := $(shell ld -version_details 2>/dev/null | head -n 1)
    ifneq ($(shell echo "$(LD_VERSION)" | grep -E "(15|16|17|18|19|[2-9][0-9])\.[0-9]"),)
        LDFLAGS += -Wl,-no_warn_duplicate_libraries
    endif
    # macOS system headers (libpcap, getifaddrs) use BSD types like u_char that
    # strict _POSIX_C_SOURCE hides. _DARWIN_C_SOURCE re-exposes them.
    CFLAGS += -D_DARWIN_C_SOURCE
endif

# Hardening. Requested explicitly rather than inherited: Ubuntu's GCC turns
# most of this on by default, Apple's clang does not, so without these flags the
# two platforms ship different binaries from the same source. geotrace parses
# attacker-influenced bytes (packet headers, plaintext HTTP from ip-api) and
# spends part of its life as root, so the defaults are not good enough.
#
# _FORTIFY_SOURCE is skipped for unoptimized and sanitizer builds: glibc emits a
# #warning under -O0 that -Werror makes fatal, and clang predefines
# _FORTIFY_SOURCE=0 under -fsanitize=address, so defining it again is a
# -Wmacro-redefined error. Both arrive through EXTRA_CFLAGS, so key off that.
# The -U keeps the definition deterministic where the toolchain already picked a
# level of its own (Ubuntu's GCC defaults to 3), instead of failing on the
# redefinition warning.
HARDEN_CFLAGS := -fstack-protector-strong -fno-strict-aliasing
ifeq ($(strip $(filter -O0 -fsanitize%,$(EXTRA_CFLAGS))),)
    HARDEN_CFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
endif
CFLAGS += $(HARDEN_CFLAGS)

# Full RELRO plus immediate binding. Apple's ld64 has no -z options; its
# equivalents (PIE, chained fixups) are already the default there.
ifneq ($(UNAME_S),Darwin)
    LDFLAGS += -Wl,-z,relro,-z,now
endif

endif # _GEOTRACE_MK_TOOLCHAIN_INCLUDED
