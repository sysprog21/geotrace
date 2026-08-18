# Build switches for Geotrace
#
# Plain ?= defaults; override on the command line: `make ENABLE_PCAP=0`.
# No Kconfig — we have ~5 switches, not 500.

ifndef _GEOTRACE_MK_CONFIG_INCLUDED
_GEOTRACE_MK_CONFIG_INCLUDED := 1

# Live capture support (requires libpcap).
# Auto-detected from pkg-config; override to force off.
ENABLE_PCAP ?= $(if $(filter y,$(HAVE_PCAP)),1,0)

# Embed land mask via tools/bin2c. Default on.
ENABLE_LAND_MASK ?= 1

ifeq ($(ENABLE_PCAP),1)
    ifneq ($(HAVE_PCAP),y)
        $(error ENABLE_PCAP=1 requires libpcap. Install libpcap-dev or set ENABLE_PCAP=0.)
    endif
    CFLAGS  += -DHAVE_PCAP=1 $(PCAP_CFLAGS)
    LDFLAGS += $(PCAP_LIBS)
else
    CFLAGS  += -DHAVE_PCAP=0
endif

ifeq ($(ENABLE_LAND_MASK),1)
    CFLAGS  += -DHAVE_LAND_MASK=1 $(ZLIB_CFLAGS)
    LDFLAGS += $(ZLIB_LIBS)
else
    CFLAGS  += -DHAVE_LAND_MASK=0
endif

endif # _GEOTRACE_MK_CONFIG_INCLUDED
