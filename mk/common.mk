# Common build rules and utilities for Geotrace
#
# Verbosity, color helpers, reusable templates. Cribbed from rv32emu.

ifndef _GEOTRACE_MK_COMMON_INCLUDED
_GEOTRACE_MK_COMMON_INCLUDED := 1

# Verbosity Control
# 'make V=1' equals 'make VERBOSE=1'
ifeq ("$(origin V)", "command line")
    VERBOSE = $(V)
endif
ifeq ("$(VERBOSE)","1")
    Q :=
    VECHO = @true
else
    Q := @
    VECHO = @$(PRINTF)
endif

# Colored output
GREEN  = \033[32m
YELLOW = \033[33m
RED    = \033[31m
NC     = \033[0m

notice    = $(PRINTF) "$(GREEN)$(strip $1)$(NC)\n"
warn      = $(PRINTF) "$(YELLOW)$(strip $1)$(NC)\n"
error_msg = $(PRINTF) "$(RED)$(strip $1)$(NC)\n"

# Skip expensive dependency detection on clean targets
SKIP_DEPS_TARGETS := clean distclean format
SKIP_DEPS_CHECK := $(filter $(SKIP_DEPS_TARGETS),$(MAKECMDGOALS))

# Build directory
OUT ?= build

# Reusable templates

# Directory creation template
# Usage: $(eval $(call make-dir,$(OUT)/subdir))
define make-dir
$(1):
	$$(Q)mkdir -p $$@
endef

# Generic object compilation rule
# $(1): output directory variable name (e.g., OUT)
# $(2): source directory (e.g., src)
# $(3): extra CFLAGS (optional)
define compile-rule
$$($(1))/%.o: $(2)/%.c | $$($(1))
	$$(Q)mkdir -p $$(dir $$@)
	$$(VECHO) "  CC\t$$@\n"
	$$(Q)$$(CC) -o $$@ $$(CFLAGS) $(3) -c -MMD -MF $$@.d $$<
endef

# Test framework
# $(1): test name (e.g., ring, ip-filter)
# $(2): list of test object basenames (e.g., test-ring.o)
# $(3): additional object dependencies from src/ (full paths)
#
# Creates per-test SRCDIR/OUTDIR/TARGET/OBJS, compile rules, link rule.
define test-framework
$(1)_TEST_SRCDIR := tests
$(1)_TEST_OUTDIR := $$(OUT)/tests/$(1)
$(1)_TEST_TARGET := $$($(1)_TEST_OUTDIR)/test-$(1)
$(1)_TEST_OBJS   := $$(addprefix $$($(1)_TEST_OUTDIR)/, $(2)) $(3)

$$($(1)_TEST_OUTDIR):
	$$(Q)mkdir -p $$@

$$($(1)_TEST_OUTDIR)/%.o: $$($(1)_TEST_SRCDIR)/%.c | $$($(1)_TEST_OUTDIR)
	$$(VECHO) "  CC\t$$@\n"
	$$(Q)$$(CC) -o $$@ $$(CFLAGS) -c -MMD -MF $$@.d $$<

$$($(1)_TEST_TARGET): $$($(1)_TEST_OBJS)
	$$(VECHO) "  LD\t$$@\n"
	$$(Q)$$(CC) $$^ -o $$@ $$(LDFLAGS)

deps += $$($(1)_TEST_OBJS:%.o=%.o.d)
endef

# Simple test runner: runs binary, checks exit code.
# $(1): test name
define run-test-simple
run-test-$(1): $$($(1)_TEST_TARGET)
	$$(VECHO) "Running test-$(1) ... "
	$$(Q)$$< && $$(call notice, [OK]) || { $$(PRINTF) "Failed.\n"; exit 1; }
endef

endif # _GEOTRACE_MK_COMMON_INCLUDED
