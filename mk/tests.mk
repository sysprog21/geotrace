# Unit tests for Geotrace
#
# One line per test. Each lands a binary under $(OUT)/tests/<name>/ built from
# tests/test-<name>.c plus the src objects it needs.

ifndef _GEOTRACE_MK_TESTS_INCLUDED
_GEOTRACE_MK_TESTS_INCLUDED := 1

TEST_TARGETS :=

# add-test(name, objects)
#   Instantiate the build template, register a runner, and add it to the
#   default test list. Every test used to repeat these three lines behind an
#   $(wildcard tests/test-<name>.c) guard, which was scaffolding from when
#   tests landed phase by phase; all of them are tracked files now.
define add-test
$(call test-framework,$(1),test-$(1).o,$(2))
$(call run-test-simple,$(1))
TEST_TARGETS += run-test-$(1)
endef

# world-map.o needs libm and oom.o, plus the land-mask object when enabled;
# zlib arrives via the global config flags.
WORLD_MAP_DEPS := $(OUT)/world-map.o $(OUT)/oom.o
WORLD_MAP_LIBS := -lm
ifeq ($(ENABLE_LAND_MASK),1)
WORLD_MAP_DEPS += $(OUT)/land-mask.o
endif

# Ring buffer: MPSC stress, eviction, shutdown.
$(eval $(call add-test,ring,$(OUT)/ring.o $(OUT)/oom.o))

# IP filter boundaries. Includes geo.c to reach IPV4_BLOCKED_RANGES and assert
# its own table still matches, so it must not also link geo.o.
$(eval $(call add-test,ip-filter,$(OUT)/oom.o $(OUT)/geo-http.o))

# Equirectangular projection and braille encoding.
$(eval $(call add-test,projection,$(WORLD_MAP_DEPS)))
$(eval $(call add-test,braille,$(WORLD_MAP_DEPS)))
$(projection_TEST_TARGET): LDFLAGS += $(WORLD_MAP_LIBS)
$(braille_TEST_TARGET): LDFLAGS += $(WORLD_MAP_LIBS)

# Input parsers. Includes geo.c and platform.c directly to reach their statics
# rather than widening the public API for tests; links cli.o for the public
# cli_normalize_interfaces, plus its theme.o/oom.o dependencies.
$(eval $(call add-test,parsers,$(OUT)/geo-http.o $(OUT)/cli.o $(OUT)/theme.o $(OUT)/oom.o))

# The sudo re-exec command line. Includes cli.c directly to reach the static
# argv builder, so it must NOT also link cli.o; platform.o is needed for
# platform_iface_append, which cli.c calls.
$(eval $(call add-test,cli,$(OUT)/theme.o $(OUT)/platform.o $(OUT)/oom.o))

# Resolver pipeline stage: cache-only lookups, so no network in the test.
$(eval $(call add-test,resolver,$(OUT)/resolver.o $(OUT)/geo.o $(OUT)/geo-http.o \
                                $(OUT)/ring.o $(OUT)/oom.o))

# BPF program vs IPV4_BLOCKED_RANGES agreement. Needs libpcap to compile the
# filter, so it only exists when live capture is enabled.
ifeq ($(ENABLE_PCAP),1)
$(eval $(call add-test,bpf-filter,$(OUT)/ring.o $(OUT)/oom.o $(OUT)/geo-http.o))
endif

tests: $(TEST_TARGETS)

.PHONY: tests $(TEST_TARGETS)

endif # _GEOTRACE_MK_TESTS_INCLUDED
