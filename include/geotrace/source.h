#ifndef GEOTRACE_SOURCE_H
#define GEOTRACE_SOURCE_H

#include "geotrace/atomic.h"
#include "geotrace/platform.h"
#include "geotrace/ring.h"

#include <stddef.h>

/* Packet source vtable. Sources push packet_event values onto an MPSC ring
 * supplied by the orchestrator. The orchestrator still owns the "Listening on
 * …" banner and the aggregate start-failed banner, built from interfaces() and
 * start()'s return code.
 *
 * statuses_out carries what that return code cannot express, both of which are
 * per interface rather than per source:
 *   - a capture thread that dies after a successful start (interface
 *     disappears, VPN drops), which nothing else in the process can observe;
 *   - one interface of several failing to open, where start() still returns
 *     success and the stderr message is about to be painted over by the UI.
 * Sources must not use it for anything the orchestrator already reports.
 */

struct packet_source {
    int (*start)(struct packet_source *self,
                 struct ring *packets_out,
                 struct ring *statuses_out,
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
