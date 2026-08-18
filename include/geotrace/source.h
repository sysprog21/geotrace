#ifndef GEOTRACE_SOURCE_H
#define GEOTRACE_SOURCE_H

#include "geotrace/atomic.h"
#include "geotrace/platform.h"
#include "geotrace/ring.h"

#include <stddef.h>

/* Packet source vtable. Sources push packet_event values onto an MPSC ring
 * supplied by the orchestrator. Sources never touch the status_ring directly —
 * main.c emits "Listening on …" / error banners using interfaces() and
 * start()'s return code.
 */

struct packet_source {
    int (*start)(struct packet_source *self,
                 struct ring *packets_out,
                 geotrace_flag *stop);
    void (*stop)(struct packet_source *self);
    const char *const *(*interfaces)(struct packet_source *self);
    size_t (*interface_count)(struct packet_source *self);

    /* Implementation-specific state lives in the embedding struct. */
};

/* demo source: synthetic events, no external deps */

struct packet_source *demo_source_create(double interval_seconds);
void demo_source_destroy(struct packet_source *s);

/* pcap source: live capture (compile-gated by HAVE_PCAP) */

#if HAVE_PCAP
struct packet_source *pcap_source_create(
    const char ifaces[][GEOTRACE_IFACE_LEN],
    size_t count);
void pcap_source_destroy(struct packet_source *s);
#endif

#endif /* GEOTRACE_SOURCE_H */
