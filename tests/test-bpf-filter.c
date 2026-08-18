/*
 * test-bpf-filter — binds the kernel-side BPF program to the user-side range
 * table.
 *
 * pcap-source.c's BPF_FILTER and geo.c's IPV4_BLOCKED_RANGES encode the same
 * "worth geolocating" decision twice, coupled only by a "keep this in sync"
 * comment. Drift is silent and shows up in production as either missing traffic
 * or wasted geo lookups.
 *
 * This compiles the real filter with pcap_open_dead + pcap_compile, then runs
 * synthetic Ethernet/IPv4 frames through pcap_offline_filter and asserts the
 * verdict matches is_public_ipv4_host for every boundary of every table entry.
 * Adding a range to the table extends the test automatically.
 */

#include "geo.c"
#include "pcap-source.c"

#include <assert.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>

#define ETH_HDR_LEN 14
#define IP_HDR_LEN 20
#define FRAME_LEN (ETH_HDR_LEN + IP_HDR_LEN)

/* Minimal Ethernet + IPv4 frame carrying the requested destination. Only the
 * fields the filter reads have to be right: ethertype, version/IHL, and the
 * destination address.
 */
static void build_frame(unsigned char frame[FRAME_LEN], uint32_t dst_host)
{
    memset(frame, 0, FRAME_LEN);
    frame[12] = 0x08; /* ethertype IPv4 */
    frame[13] = 0x00;

    unsigned char *ip = frame + ETH_HDR_LEN;
    ip[0] = 0x45; /* version 4, IHL 5 */
    ip[2] = 0x00;
    ip[3] = IP_HDR_LEN;
    ip[8] = 64;   /* TTL */
    ip[9] = 6;    /* TCP */
    ip[12] = 203; /* src 203.0.113.9, arbitrary and irrelevant */
    ip[13] = 0;
    ip[14] = 113;
    ip[15] = 9;
    uint32_t be = htonl(dst_host);
    memcpy(ip + 16, &be, 4);
}

static int failures;

static void check_ip(struct bpf_program *prog, uint32_t ip_host)
{
    unsigned char frame[FRAME_LEN];
    build_frame(frame, ip_host);

    struct pcap_pkthdr hdr = {0};
    hdr.caplen = FRAME_LEN;
    hdr.len = FRAME_LEN;

    bool bpf_accepts = pcap_offline_filter(prog, &hdr, frame) != 0;
    bool table_accepts = is_public_ipv4_host(ip_host);

    if (bpf_accepts != table_accepts) {
        fprintf(stderr, "FAIL %u.%u.%u.%u: BPF %s but IPV4_BLOCKED_RANGES %s\n",
                (ip_host >> 24) & 0xFF, (ip_host >> 16) & 0xFF,
                (ip_host >> 8) & 0xFF, ip_host & 0xFF,
                bpf_accepts ? "accepts" : "drops",
                table_accepts ? "accepts" : "drops");
        failures++;
    }
}

int main(void)
{
    pcap_t *dead = pcap_open_dead(DLT_EN10MB, 65535);
    if (!dead) {
        fprintf(stderr, "FAIL: pcap_open_dead\n");
        return 1;
    }

    /* FRAME_LEN has to be a constant expression for the frame array, so bind it
     * to production rather than restating it silently.
     */
    assert(link_offset_for_dlt(DLT_EN10MB) == ETH_HDR_LEN);

    struct bpf_program prog;
    if (pcap_compile(dead, &prog, BPF_FILTER, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        fprintf(stderr, "FAIL: pcap_compile: %s\n", pcap_geterr(dead));
        pcap_close(dead);
        return 1;
    }

    /* Every boundary of every blocked range, plus one address inside it. */
    for (size_t i = 0; i < GEOTRACE_ARRAY_LEN(IPV4_BLOCKED_RANGES); i++) {
        uint32_t start = IPV4_BLOCKED_RANGES[i].start;
        uint32_t end = IPV4_BLOCKED_RANGES[i].end;

        if (start > 0)
            check_ip(&prog, start - 1);
        check_ip(&prog, start);
        check_ip(&prog, start + (end - start) / 2);
        check_ip(&prog, end);
        if (end < 0xFFFFFFFFu)
            check_ip(&prog, end + 1);
    }

    /* The whitelisted holes inside 192.0.0.0/24. */
    for (size_t i = 0; i < GEOTRACE_ARRAY_LEN(IPV4_ALLOWED_EXCEPTIONS); i++)
        check_ip(&prog, IPV4_ALLOWED_EXCEPTIONS[i]);

    /* A few addresses that must plainly pass. */
    static const uint32_t PUBLIC[] = {
        0x01010101u, /* 1.1.1.1 */
        0x08080808u, /* 8.8.8.8 */
        0x09090909u, /* 9.9.9.9 */
        0xD043DEDEu, /* 208.67.222.222 */
    };
    for (size_t i = 0; i < GEOTRACE_ARRAY_LEN(PUBLIC); i++)
        check_ip(&prog, PUBLIC[i]);

    pcap_freecode(&prog);
    pcap_close(dead);

    if (failures) {
        fprintf(stderr,
                "%d mismatch(es): BPF_FILTER in src/pcap-source.c and "
                "IPV4_BLOCKED_RANGES in src/geo.c have drifted\n",
                failures);
        return 1;
    }
    fprintf(stderr, "bpf/table agreement verified\n");
    return 0;
}
