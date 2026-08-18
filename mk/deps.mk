# Dependency detection for Geotrace
#
# Wraps pkg-config with a *-config fallback. Skips work on clean targets.

ifndef _GEOTRACE_MK_DEPS_INCLUDED
_GEOTRACE_MK_DEPS_INCLUDED := 1

PKG_CONFIG ?= pkg-config

# dep(type, packages)
#   type: cflags | libs
#   packages: space-separated package names
#
# pkg-config is consulted only when --exists succeeds — otherwise systems
# that ship pkg-config without metadata for a given package (e.g. libpcap on
# some setups) would yield empty flags even though ${pkg}-config is available.
define dep
$(shell \
    for pkg in $(2); do \
        if command -v $(PKG_CONFIG) >/dev/null 2>&1 \
            && $(PKG_CONFIG) --exists $$pkg 2>/dev/null; then \
            $(PKG_CONFIG) --$(1) $$pkg 2>/dev/null; \
        elif command -v $${pkg}-config >/dev/null 2>&1; then \
            $${pkg}-config --$(1) 2>/dev/null; \
        fi; \
    done \
)
endef

# pkg-exists(package) -> "y" or empty
define pkg-exists
$(shell \
    if command -v $(PKG_CONFIG) >/dev/null 2>&1 && $(PKG_CONFIG) --exists $(1) 2>/dev/null; then \
        echo y; \
    elif command -v $(1)-config >/dev/null 2>&1; then \
        echo y; \
    fi \
)
endef

ifeq ($(SKIP_DEPS_CHECK),)
HAVE_PCAP := $(call pkg-exists,libpcap)
HAVE_ZLIB := $(call pkg-exists,zlib)

# macOS ships libpcap as a system library without pkg-config metadata. Probe
# the header directly when pkg-config doesn't know about it.
ifneq ($(HAVE_PCAP),y)
    PCAP_HEADER_PROBE := $(shell printf '\043include <pcap.h>\nint main(void){return 0;}\n' \
        | $(CC) -x c -c -o /dev/null - 2>/dev/null && echo y)
    ifeq ($(PCAP_HEADER_PROBE),y)
        HAVE_PCAP   := y
        PCAP_CFLAGS :=
        PCAP_LIBS   := -lpcap
    endif
endif

ifeq ($(HAVE_PCAP),y)
ifeq ($(PCAP_LIBS),)
    PCAP_CFLAGS := $(call dep,cflags,libpcap)
    PCAP_LIBS   := $(call dep,libs,libpcap)
endif
endif

ifneq ($(HAVE_ZLIB),y)
    # Fallback: zlib usually ships without pkg-config metadata; assume -lz works.
    HAVE_ZLIB := y
    ZLIB_CFLAGS :=
    ZLIB_LIBS   := -lz
else
    ZLIB_CFLAGS := $(call dep,cflags,zlib)
    ZLIB_LIBS   := $(call dep,libs,zlib)
endif
endif

endif # _GEOTRACE_MK_DEPS_INCLUDED
