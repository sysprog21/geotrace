/*
 * test-ip-filter — boundary coverage for is_public_ipv4_host / _be.
 *
 * Every blocked range: lower bound, upper bound, one-below-lower,
 * one-above-upper. Every allowed exception: hit, plus its neighbors. Both
 * byte-order entry points return the same answer.
 */

#include "geo.c" /* for IPV4_BLOCKED_RANGES, to assert this table matches */

#include "geotrace/util.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static void check(uint32_t ip_host, bool expect, const char *label)
{
    bool got_host = is_public_ipv4_host(ip_host);
    bool got_be = is_public_ipv4_be(htonl(ip_host));

    if (got_host != expect || got_be != expect) {
        fprintf(stderr, "FAIL: %s (0x%08x) host=%d be=%d expected=%d\n", label,
                ip_host, got_host, got_be, expect);
        exit(1);
    }
}

static void check_range_case(uint32_t ip_host,
                             bool expect,
                             const char *range_label,
                             const char *suffix)
{
    char label[64];
    snprintf(label, sizeof(label), "%s %s", range_label, suffix);
    check(ip_host, expect, label);
}

/* Each entry: { start, end, label }. Deliberately hand-written rather than read
 * out of geo.c: this is the independent statement of the policy, so a corrupted
 * range in geo.c cannot hide behind a test that reads the same bytes.
 * assert_table_matches_source() below enforces that the two agree, which also
 * makes adding a range to geo.c without extending this table a failure rather
 * than silent partial coverage.
 */
static const struct {
    uint32_t start;
    uint32_t end;
    const char *label;
} RANGES[] = {
    {0x00000000, 0x00FFFFFF, "0.0.0.0/8"},
    {0x0A000000, 0x0AFFFFFF, "10.0.0.0/8"},
    {0x64400000, 0x647FFFFF, "100.64.0.0/10"},
    {0x7F000000, 0x7FFFFFFF, "127.0.0.0/8"},
    {0xA9FE0000, 0xA9FEFFFF, "169.254.0.0/16"},
    {0xAC100000, 0xAC1FFFFF, "172.16.0.0/12"},
    {0xC0000000, 0xC00000FF, "192.0.0.0/24"},
    {0xC0000200, 0xC00002FF, "192.0.2.0/24"},
    {0xC0A80000, 0xC0A8FFFF, "192.168.0.0/16"},
    {0xC6120000, 0xC613FFFF, "198.18.0.0/15"},
    {0xC6336400, 0xC63364FF, "198.51.100.0/24"},
    {0xCB007100, 0xCB0071FF, "203.0.113.0/24"},
    {0xE0000000, 0xFFFFFFFF, "224.0.0.0/3"},
};

/* The two tables must describe the same policy, entry for entry. */
static void assert_table_matches_source(void)
{
    if (GEOTRACE_ARRAY_LEN(RANGES) != GEOTRACE_ARRAY_LEN(IPV4_BLOCKED_RANGES)) {
        fprintf(stderr,
                "FAIL: %zu ranges here vs %zu in src/geo.c; the tables have "
                "drifted\n",
                GEOTRACE_ARRAY_LEN(RANGES),
                GEOTRACE_ARRAY_LEN(IPV4_BLOCKED_RANGES));
        exit(1);
    }
    for (size_t i = 0; i < GEOTRACE_ARRAY_LEN(RANGES); i++) {
        if (RANGES[i].start != IPV4_BLOCKED_RANGES[i].start ||
            RANGES[i].end != IPV4_BLOCKED_RANGES[i].end) {
            fprintf(stderr,
                    "FAIL: %s is 0x%08x-0x%08x here but 0x%08x-0x%08x in "
                    "src/geo.c\n",
                    RANGES[i].label, RANGES[i].start, RANGES[i].end,
                    IPV4_BLOCKED_RANGES[i].start, IPV4_BLOCKED_RANGES[i].end);
            exit(1);
        }
    }
}

int main(void)
{
    assert_table_matches_source();
    /* Sample public addresses — should all be public. */
    check(0x08080808u, true, "8.8.8.8");
    check(0x01010101u, true, "1.1.1.1");
    check(0x4A7DE368u, true, "74.125.227.104 (google)");

    /* Range coverage */
    for (size_t i = 0; i < GEOTRACE_ARRAY_LEN(RANGES); i++) {
        check_range_case(RANGES[i].start, false, RANGES[i].label, "start");
        check_range_case(RANGES[i].end, false, RANGES[i].label, "end");

        if (RANGES[i].start > 0) {
            check_range_case(RANGES[i].start - 1, true, RANGES[i].label,
                             "start-1");
        }

        if (RANGES[i].end < 0xFFFFFFFFu) {
            check_range_case(RANGES[i].end + 1, true, RANGES[i].label, "end+1");
        }
    }

    /* Allowed exceptions — public despite the surrounding range. */
    check(0xC0000009u, true, "192.0.0.9 (PCP)");
    check(0xC000000Au, true, "192.0.0.10 (PortMap)");

    /* Just outside the exceptions, still inside the surrounding /24, must be
     * private.
     */
    check(0xC0000008u, false, "192.0.0.8 (in 192.0.0.0/24, not whitelisted)");
    check(0xC000000Bu, false, "192.0.0.11 (in 192.0.0.0/24, not whitelisted)");

    /* Edge of address space */
    check(0xFFFFFFFFu, false, "broadcast");
    check(0x00000000u, false, "0.0.0.0");

    /* Boundary of last range (224.0.0.0/3 ends at 0xFFFFFFFF) — start-1 was
     * tested above.
     */

    fprintf(stderr, "ip-filter tests passed\n");
    return 0;
}
