#ifndef GEOTRACE_PACKET_DECODE_H
#define GEOTRACE_PACKET_DECODE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "geotrace/models.h"

/* IPv4 header decode for the capture path.
 *
 * This is the only place in geotrace that reads bytes an outsider chose. It
 * lives apart from pcap-source.c on purpose: that file is wrapped in "#if
 * HAVE_PCAP" and its handler takes a struct pcap_pkthdr, so nothing could
 * exercise the bounds checks without libpcap present. Here the signature is
 * plain scalars, so tests/test-packet-decode.c drives it directly with
 * hand-built frames.
 *
 * Fills "out" and returns true only for a frame that is long enough to hold a
 * link header plus a 20-byte IPv4 header and whose version nibble is 4. Every
 * other input is rejected without touching "out"; callers must not read "out"
 * on a false return.
 *
 * "wire_len" is the packet's full on-the-wire length and is stored as the event
 * size. It is deliberately not "caplen": the capture snaplen truncates caplen,
 * which would report every full-MTU frame at the snap length.
 *
 * Addresses are copied out in network byte order and converted at the display
 * boundary, not here.
 *
 * "created_at" is left zeroed: the caller stamps it. This keeps the decoder a
 * pure function of its arguments, which is worth more than the one saved line.
 * It also fixes an unsound frame -- clock_gettime's own contract assigns a libc
 * clock global (__fc_time) as well as its output, so "assigns *out" here was
 * narrower than what the function really wrote. Null "bytes", "out" and
 * "ifname" are all admitted, matching what the body actually checks. An earlier
 * revision required a valid "out" instead, on the theory that it would buy
 * proof strength; measurement said otherwise (same goals proved either way) and
 * it put tests/test-packet-decode.c's null-out case in violation of the
 * contract it was meant to be testing, which EVA then flagged. A contract that
 * forbids what the code deliberately handles is just a second, disagreeing
 * specification.
 */
/*@ requires bytes == \null || \valid_read(bytes + (0 .. caplen - 1));
    requires out == \null || \valid(out);
    requires ifname == \null || valid_read_string(ifname);
    requires \separated(out, bytes + (0 .. caplen - 1));
    assigns *out;
 */
bool packet_decode_ipv4(const unsigned char *bytes,
                        size_t caplen,
                        size_t link_offset,
                        uint32_t wire_len,
                        const char *ifname,
                        packet_event *out);

#endif /* GEOTRACE_PACKET_DECODE_H */
