/*
 * test-resolver — the packet_event to connection_event mapping.
 *
 * Extracting the resolver from main.c was justified partly on testability, so
 * exercise it: drive resolver_main with two rings and a primed cache, with the
 * geo timeout at 0 so geo_lookup never touches the network.
 */

#include "geotrace/geo.h"
#include "geotrace/resolver.h"
#include "geotrace/ring.h"
#include "geotrace/util.h"

#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PRIMED_IP "8.8.8.8"
#define PRIMED_COUNTRY "United States"
#define PRIVATE_IP "192.168.1.7" /* is_public_ipv4 rejects it: no lookup */

static void push(struct ring *r, const char *dst, uint16_t proto)
{
    packet_event p = {0};
    p.src_ip_be = inet_addr("10.0.0.2");
    p.dst_ip_be = inet_addr(dst);
    p.size = 1200;
    p.ip_protocol = proto;
    geotrace_copy_cstr(p.interface, sizeof(p.interface), "en9");
    clock_gettime(CLOCK_MONOTONIC, &p.created_at);
    ring_put_latest(r, &p);
}

/* Block until one connection_event shows up, so the test does not race the
 * resolver thread. The ring is lossy but nothing else is producing here.
 */
static connection_event take(struct ring *r)
{
    connection_event ce;
    for (int spins = 0; spins < 20000; spins++) {
        if (ring_try_take(r, &ce))
            return ce;
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 1000000};
        nanosleep(&ts, NULL);
    }
    fprintf(stderr, "FAIL: resolver produced no event\n");
    exit(1);
}

int main(void)
{
    struct ring *packets = ring_create(64, sizeof(packet_event));
    struct ring *conns = ring_create(64, sizeof(connection_event));
    struct ring *status = ring_create(8, sizeof(status_event));
    struct geo_cache *cache = geo_cache_create(16);

    /* Prime one public address so the cache-hit path is covered without a
     * network round trip.
     */
    geo_result primed = {0};
    primed.valid = true;
    primed.point.lat = 37.3861;
    primed.point.lon = -122.0839;
    geotrace_copy_cstr(primed.country, sizeof(primed.country), PRIMED_COUNTRY);
    geo_cache_put(cache, inet_addr(PRIMED_IP), &primed);

    geotrace_flag stop = GEOTRACE_FLAG_INIT;
    resolver_ctx ctx = {
        .packets_in = packets,
        .connections_out = conns,
        .statuses_out = status,
        .cache = cache,
        .geo_timeout_ms = 0, /* cache only, never dials out */
        .stop = &stop,
    };

    pthread_t tid;
    assert(pthread_create(&tid, NULL, resolver_main, &ctx) == 0);

    /* A resolvable destination keeps its coordinates and country. */
    push(packets, PRIMED_IP, 6);
    connection_event ce = take(conns);
    assert(ce.coords_valid);
    assert(strcmp(ce.country, PRIMED_COUNTRY) == 0);
    assert(strcmp(ce.protocol, "TCP") == 0);
    assert(strcmp(ce.interface, "en9") == 0);
    assert(ce.dst_ip_be == inet_addr(PRIMED_IP));
    assert(ce.size == 1200);

    /* A non-public destination is reported, but unmapped. */
    push(packets, PRIVATE_IP, 17);
    ce = take(conns);
    assert(!ce.coords_valid);
    assert(strcmp(ce.country, "GeoIP miss") == 0);
    assert(strcmp(ce.protocol, "UDP") == 0);

    /* Protocol numbers map to display names; anything unlisted is "?". */
    push(packets, PRIVATE_IP, 1);
    assert(strcmp(take(conns).protocol, "ICMP") == 0);
    push(packets, PRIVATE_IP, 132);
    assert(strcmp(take(conns).protocol, "SCTP") == 0);
    push(packets, PRIVATE_IP, 253);
    assert(strcmp(take(conns).protocol, "?") == 0);

    /* Shutting the input ring down unwinds the thread, and it leaves a closing
     * banner behind for the UI.
     */
    ring_shutdown(packets);
    pthread_join(tid, NULL);

    status_event se;
    assert(ring_try_take(status, &se));
    assert(strcmp(se.message, "Resolver stopped.") == 0);
    assert(se.level == GEOTRACE_STATUS_INFO);

    geo_cache_destroy(cache);
    ring_destroy(packets);
    ring_destroy(conns);
    ring_destroy(status);

    fprintf(stderr, "resolver tests passed\n");
    return 0;
}
