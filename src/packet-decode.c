#include "geotrace/packet-decode.h"

#include "geotrace/util.h"

#include <string.h>

/* Offsets into the IPv4 header, by RFC 791. Named because "ip + 12" at the
 * memcpy tells a reader nothing.
 */
#define IPV4_MIN_HEADER_LEN 20
#define IPV4_OFF_PROTOCOL 9
#define IPV4_OFF_SRC 12
#define IPV4_OFF_DST 16

bool packet_decode_ipv4(const unsigned char *bytes,
                        size_t caplen,
                        size_t link_offset,
                        uint32_t wire_len,
                        const char *ifname,
                        packet_event *out)
{
    if (!bytes || !out)
        return false;

    /* Rejects both the short frame and the frame that is exactly the link
     * header. The "=" is belt and braces rather than load-bearing: at equality
     * ip_len below is zero and the minimum-header check would reject it anyway.
     * Mutation-testing "<=" to "<" leaves every test passing, which is the
     * evidence for that, not an argument.
     */
    if (caplen <= link_offset)
        return false;

    const unsigned char *ip = bytes + link_offset;
    size_t ip_len = caplen - link_offset;
    if (ip_len < IPV4_MIN_HEADER_LEN)
        return false;

    /* Capture path accepts IPv4 only. Checked after the length test so the
     * version nibble is known to be inside the capture.
     */
    if ((ip[0] >> 4) != 4)
        return false;

    packet_event pkt = {0};
    memcpy(&pkt.src_ip_be, ip + IPV4_OFF_SRC, 4);
    memcpy(&pkt.dst_ip_be, ip + IPV4_OFF_DST, 4);
    pkt.size = wire_len;
    pkt.ip_protocol = ip[IPV4_OFF_PROTOCOL];
    if (ifname)
        geotrace_copy_cstr(pkt.interface, sizeof(pkt.interface), ifname);

    *out = pkt;
    return true;
}
