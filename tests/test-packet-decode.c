/*
 * test-packet-decode — covers the one decoder in geotrace that reads bytes an
 * outsider chose. Every case here is a frame a hostile or broken sender can put
 * on the wire, so the assertions are about refusing to read out of bounds, not
 * about happy-path field extraction.
 *
 * Worth running under ASan ("make debug") specifically: an over-read past the
 * captured bytes is the failure mode, and only ASan turns that into a crash
 * rather than a silently wrong address. The short_* cases below size their
 * buffers to exactly caplen so ASan has a red zone immediately after.
 */

/* xmalloc, not malloc: an unchecked malloc here means a NULL memset if the
 * allocation ever fails, which EVA flags and which would surface as a confusing
 * crash rather than a test failure.
 */
#include "geotrace/models.h"
#include "geotrace/oom.h"
#include "geotrace/packet-decode.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ETH_HDR 14
#define IPV4_HDR 20

/* Build a minimal Ethernet + IPv4 frame into "buf". Returns total length. */
static size_t build_frame(unsigned char *buf,
                          size_t buf_len,
                          uint8_t version_nibble,
                          uint8_t protocol,
                          uint32_t src_be,
                          uint32_t dst_be)
{
    assert(buf_len >= ETH_HDR + IPV4_HDR);
    memset(buf, 0, buf_len);
    buf[ETH_HDR] = (unsigned char) (version_nibble << 4 | 5); /* IHL 5 */
    buf[ETH_HDR + 9] = protocol;
    memcpy(buf + ETH_HDR + 12, &src_be, 4);
    memcpy(buf + ETH_HDR + 16, &dst_be, 4);
    return ETH_HDR + IPV4_HDR;
}

static void test_accepts_well_formed_ipv4(void)
{
    unsigned char frame[ETH_HDR + IPV4_HDR];
    uint32_t src = 0x01020304, dst = 0x05060708;
    size_t n = build_frame(frame, sizeof(frame), 4, 6 /* TCP */, src, dst);

    packet_event pkt;
    assert(packet_decode_ipv4(frame, n, ETH_HDR, 1500, "en0", &pkt));
    assert(pkt.src_ip_be == src);
    assert(pkt.dst_ip_be == dst);
    assert(pkt.ip_protocol == 6);
    /* wire length, not caplen: a snapped capture must not shrink the size */
    assert(pkt.size == 1500);
    assert(strcmp(pkt.interface, "en0") == 0);
}

static void test_rejects_non_ipv4(void)
{
    unsigned char frame[ETH_HDR + IPV4_HDR];
    packet_event pkt;

    for (uint8_t v = 0; v < 16; v++) {
        if (v == 4)
            continue;
        size_t n = build_frame(frame, sizeof(frame), v, 6, 0, 0);
        assert(!packet_decode_ipv4(frame, n, ETH_HDR, 1500, "en0", &pkt));
    }
}

/* The bounds cases. Each buffer is exactly caplen bytes so that any read past
 * the captured region lands in an ASan red zone instead of adjacent stack.
 */
static void test_rejects_short_frames(void)
{
    packet_event pkt;

    /* caplen strictly below the link header */
    for (size_t caplen = 0; caplen < ETH_HDR; caplen++) {
        unsigned char *buf = caplen ? xmalloc(caplen) : NULL;
        if (caplen)
            memset(buf, 0x45, caplen);
        assert(!packet_decode_ipv4(buf ? buf : (const unsigned char *) "",
                                   caplen, ETH_HDR, 1500, "en0", &pkt));
        free(buf);
    }

    /* caplen exactly the link header: no IP bytes at all. Two checks in the
     * decoder overlap here, so this case passes whether the first one uses "<"
     * or "<="; the minimum-header check is what actually rejects it. Kept
     * because the boundary is worth pinning regardless of which check fires.
     */
    unsigned char *exact = xmalloc(ETH_HDR);
    memset(exact, 0x45, ETH_HDR);
    assert(!packet_decode_ipv4(exact, ETH_HDR, ETH_HDR, 1500, "en0", &pkt));
    free(exact);

    /* Link header present but IPv4 header truncated: 1..19 bytes of IP. */
    for (size_t ip_bytes = 1; ip_bytes < IPV4_HDR; ip_bytes++) {
        size_t caplen = ETH_HDR + ip_bytes;
        unsigned char *buf = xmalloc(caplen);
        memset(buf, 0, caplen);
        buf[ETH_HDR] = 0x45; /* looks like IPv4 so only length can reject it */
        assert(!packet_decode_ipv4(buf, caplen, ETH_HDR, 1500, "en0", &pkt));
        free(buf);
    }
}

/* A link_offset larger than the frame must be rejected, not trusted. The DLT
 * table picks the offset, so a capture on an unexpected link type can present
 * one that overruns a short frame.
 */
static void test_rejects_oversized_link_offset(void)
{
    unsigned char frame[ETH_HDR + IPV4_HDR];
    size_t n = build_frame(frame, sizeof(frame), 4, 6, 0, 0);
    packet_event pkt;

    assert(!packet_decode_ipv4(frame, n, n, 1500, "en0", &pkt));
    assert(!packet_decode_ipv4(frame, n, n + 1, 1500, "en0", &pkt));
    assert(!packet_decode_ipv4(frame, n, SIZE_MAX, 1500, "en0", &pkt));
}

/* DLT_RAW gives offset 0, so the IP header starts at byte 0. */
static void test_zero_link_offset(void)
{
    unsigned char frame[IPV4_HDR];
    memset(frame, 0, sizeof(frame));
    frame[0] = 0x45;
    frame[9] = 17; /* UDP */
    packet_event pkt;

    assert(packet_decode_ipv4(frame, sizeof(frame), 0, 64, "lo0", &pkt));
    assert(pkt.ip_protocol == 17);
    assert(pkt.size == 64);
}

static void test_null_arguments(void)
{
    unsigned char frame[ETH_HDR + IPV4_HDR];
    size_t n = build_frame(frame, sizeof(frame), 4, 6, 0, 0);
    packet_event pkt;

    assert(!packet_decode_ipv4(NULL, n, ETH_HDR, 1500, "en0", &pkt));
    assert(!packet_decode_ipv4(frame, n, ETH_HDR, 1500, "en0", NULL));
    /* A NULL interface is tolerated: the event just carries an empty name. */
    assert(packet_decode_ipv4(frame, n, ETH_HDR, 1500, NULL, &pkt));
    assert(pkt.interface[0] == '\0');
}

/* An interface name longer than the field must truncate, not overflow. */
static void test_long_interface_name_truncates(void)
{
    unsigned char frame[ETH_HDR + IPV4_HDR];
    size_t n = build_frame(frame, sizeof(frame), 4, 6, 0, 0);
    packet_event pkt;
    char longname[GEOTRACE_IFACE_LEN * 4];

    memset(longname, 'x', sizeof(longname) - 1);
    longname[sizeof(longname) - 1] = '\0';

    assert(packet_decode_ipv4(frame, n, ETH_HDR, 1500, longname, &pkt));
    assert(pkt.interface[GEOTRACE_IFACE_LEN - 1] == '\0');
    assert(strlen(pkt.interface) == GEOTRACE_IFACE_LEN - 1);
}

int main(void)
{
    test_accepts_well_formed_ipv4();
    test_rejects_non_ipv4();
    test_rejects_short_frames();
    test_rejects_oversized_link_offset();
    test_zero_link_offset();
    test_null_arguments();
    test_long_interface_name_truncates();

    printf("packet decode tests passed\n");
    return 0;
}
