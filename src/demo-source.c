#include "geotrace/source.h"

#include "geotrace/oom.h"
#include "geotrace/util.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Synthetic destinations used by the demo packet source. */
typedef struct {
    const char *dst;
    uint16_t proto; /* IANA protocol number */
    uint32_t base_size;
} demo_entry;

static const demo_entry EXAMPLES[] = {
    {"1.1.1.1", 6, 764},       {"8.8.8.8", 17, 128},
    {"9.9.9.9", 17, 256},      {"208.67.222.222", 6, 1024},
    {"151.101.1.69", 6, 1400}, {"185.199.108.133", 6, 1200},
};

/* Demo source returns a single interface label so the orchestrator can emit a
 * "Listening on demo" banner uniformly.
 */
static const char *DEMO_IFACE_NAMES[] = {"demo", NULL};

typedef struct {
    struct packet_source base;
    pthread_t thread;
    bool running;

    double interval_seconds;
    uint32_t src_ip_be; /* 192.168.1.5 */

    struct ring *out_ring;
    geotrace_flag *stop_flag;
} demo_source;

static const char *const *demo_source_interfaces(struct packet_source *self)
{
    (void) self;
    return DEMO_IFACE_NAMES;
}

static size_t demo_source_iface_count(struct packet_source *self)
{
    (void) self;
    return 1;
}

static void *demo_thread_main(void *arg)
{
    demo_source *d = (demo_source *) arg;
    unsigned rs = (unsigned) ((uintptr_t) time(NULL) ^ (uintptr_t) d);

    /* Sleep in the interval, but check the stop flag at coarse granularity
     * (every 50ms). Avoids leaving the program hanging in nanosleep on Ctrl-C.
     */
    const long interval_ns = (long) (d->interval_seconds * 1e9);
    const long step_ns = 50L * 1000L * 1000L;

    while (!geotrace_flag_is_raised(d->stop_flag)) {
        const demo_entry *e =
            &EXAMPLES[(size_t) rand_r(&rs) % GEOTRACE_ARRAY_LEN(EXAMPLES)];

        packet_event pkt = {0};
        pkt.src_ip_be = d->src_ip_be;
        pkt.dst_ip_be = inet_addr(e->dst);
        pkt.size = e->base_size + (uint32_t) (rand_r(&rs) % 900);
        pkt.ip_protocol = e->proto;
        clock_gettime(CLOCK_MONOTONIC, &pkt.created_at);
        geotrace_copy_cstr(pkt.interface, sizeof(pkt.interface), "demo");

        ring_put_latest(d->out_ring, &pkt);

        long remaining = interval_ns;
        while (remaining > 0 && !geotrace_flag_is_raised(d->stop_flag)) {
            long chunk = remaining < step_ns ? remaining : step_ns;
            struct timespec ts = {.tv_sec = chunk / 1000000000L,
                                  .tv_nsec = chunk % 1000000000L};
            nanosleep(&ts, NULL);
            remaining -= chunk;
        }
    }
    return NULL;
}

static int demo_source_start(struct packet_source *self,
                             struct ring *packets_out,
                             geotrace_flag *stop)
{
    demo_source *d = (demo_source *) self;
    d->out_ring = packets_out;
    d->stop_flag = stop;
    d->running = true;

    if (pthread_create(&d->thread, NULL, demo_thread_main, d) != 0) {
        d->running = false;
        return -1;
    }
    return 0;
}

static void demo_source_stop(struct packet_source *self)
{
    demo_source *d = (demo_source *) self;
    if (!d->running)
        return;

    /* Stop flag should already be raised by the orchestrator before stop() is
     * called, but raise it ourselves defensively in case start() is being torn
     * down on a startup failure.
     */
    if (d->stop_flag)
        geotrace_flag_raise(d->stop_flag);
    pthread_join(d->thread, NULL);
    d->running = false;
}

struct packet_source *demo_source_create(double interval_seconds)
{
    demo_source *d = (demo_source *) xcalloc(1, sizeof(*d));

    d->base.start = demo_source_start;
    d->base.stop = demo_source_stop;
    d->base.interfaces = demo_source_interfaces;
    d->base.interface_count = demo_source_iface_count;

    d->interval_seconds = interval_seconds > 0.0 ? interval_seconds : 0.75;
    d->src_ip_be = inet_addr("192.168.1.5");
    return &d->base;
}

void demo_source_destroy(struct packet_source *s)
{
    if (!s)
        return;
    demo_source *d = (demo_source *) s;
    if (d->running)
        demo_source_stop(s);
    free(d);
}
