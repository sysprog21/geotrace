#include "geotrace/source.h"

#if HAVE_PCAP

#include "geotrace/oom.h"
#include "geotrace/packet-decode.h"
#include "geotrace/util.h"

#include <pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Live capture source.
 *
 * One thread per interface, each a producer on the shared packet ring (MPSC).
 * BPF filters down to IPv4 destination addresses outside the reserved ranges,
 * matching is_public_ipv4_be — but the resolver still re-checks because BPF can
 * miss in pathological dlt scenarios.
 *
 * Shutdown:
 *   - Orchestrator raises the atomic stop flag and calls source->stop().
 *   - stop() invokes pcap_breakloop() on every handle from a normal thread,
 *     not from a signal handler.
 *   - Capture threads loop pcap_dispatch with a 100ms timeout so they re-check
 *     the stop flag at least every 100ms even when no packet arrives.
 */

#define PCAP_SNAPLEN 256 /* Enough for the IP header + a few protocol bytes */
#define PCAP_TIMEOUT 100 /* ms — bounds the wakeup latency for shutdown */
#define PCAP_BUFSIZE (1 << 20) /* 1 MiB ring per handle */

/* Kernel prefilter for destinations outside the reserved ranges. The resolver
 * applies is_public_ipv4_be() again as the authoritative gate. The 192.0.0.0/24
 * carve-out preserves the whitelist (PCP/PortMap at 192.0.0.9/10), so this
 * optimization cannot discard an address accepted by the resolver.
 */
static const char BPF_FILTER[] =
    "ip and "
    "not dst net 0.0.0.0/8 and "
    "not dst net 10.0.0.0/8 and "
    "not dst net 100.64.0.0/10 and "
    "not dst net 127.0.0.0/8 and "
    "not dst net 169.254.0.0/16 and "
    "not dst net 172.16.0.0/12 and "
    "(not dst net 192.0.0.0/24 or dst host 192.0.0.9 or dst host 192.0.0.10) "
    "and "
    "not dst net 192.0.2.0/24 and "
    "not dst net 192.168.0.0/16 and "
    "not dst net 198.18.0.0/15 and "
    "not dst net 198.51.100.0/24 and "
    "not dst net 203.0.113.0/24 and "
    "not dst net 224.0.0.0/3";

typedef struct {
    pcap_t *handle;
    pthread_t thread;
    char ifname[GEOTRACE_IFACE_LEN];
    /* Back-pointer to the parent so the callback can reach the ring. */
    struct pcap_source *parent;
    int link_offset; /* bytes to skip to reach the IP header */
} capture_thread;

typedef struct pcap_source {
    struct packet_source base;

    capture_thread *threads;
    size_t thread_count;

    char iface_storage[GEOTRACE_MAX_INTERFACES][GEOTRACE_IFACE_LEN];
    const char *iface_pointers[GEOTRACE_MAX_INTERFACES + 1];
    size_t iface_count;

    struct ring *out_ring;
    struct ring *status_ring;
    geotrace_flag *stop_flag;
} pcap_source_t;

/* Report a per-interface capture failure. Called from a capture thread when it
 * dies, and from start() when one interface of several cannot be opened, so it
 * only touches the status ring, which is MPSC like the packet ring.
 *
 * start()'s return code cannot express either case: it is a single value for
 * the whole set, and a partial start still returns success.
 */
static void report_capture_error(pcap_source_t *p,
                                 const char *ifname,
                                 const char *reason)
{
    if (!p->status_ring)
        return;
    status_event s = {0};
    s.level = GEOTRACE_STATUS_ERROR;
    clock_gettime(CLOCK_MONOTONIC, &s.created_at);

    /* "No capture on" covers both callers. "Capture stopped" would be a lie for
     * an interface that never started in the first place.
     */
    snprintf(s.message, sizeof(s.message), "No capture on %s: %s", ifname,
             reason);
    ring_put_latest(p->status_ring, &s);
}

/* link-layer offset table */

static int link_offset_for_dlt(int dlt)
{
    switch (dlt) {
    case DLT_NULL:
    case DLT_LOOP:
        return 4;
    case DLT_EN10MB:
        return 14;
    case DLT_RAW:
        return 0;
#ifdef DLT_LINUX_SLL
    case DLT_LINUX_SLL:
        return 16;
#endif
#ifdef DLT_LINUX_SLL2
    case DLT_LINUX_SLL2:
        return 20;
#endif
    default:
        /* Unknown — best-effort 0; downstream IP-version check will reject. */
        return 0;
    }
}

/* packet handler */

/* The bounds checking and IPv4 decode live in packet-decode.c so they can be
 * tested without libpcap; see tests/test-packet-decode.c. This handler is left
 * with the pcap-shaped glue only.
 *
 * hdr->len, not hdr->caplen, is passed as the wire length: models.h defines
 * size as the packet's total on-the-wire length, and PCAP_SNAPLEN truncates
 * caplen at 256 bytes, which would silently report every full-MTU frame as a
 * 256-byte one.
 */
static void on_packet(u_char *user,
                      const struct pcap_pkthdr *hdr,
                      const u_char *bytes)
{
    capture_thread *ct = (capture_thread *) user;

    packet_event pkt;
    if (!packet_decode_ipv4(bytes, (size_t) hdr->caplen,
                            (size_t) ct->link_offset, hdr->len, ct->ifname,
                            &pkt))
        return;

    /* Stamped here rather than inside the decoder: see packet-decode.h. */
    clock_gettime(CLOCK_MONOTONIC, &pkt.created_at);

    ring_put_latest(ct->parent->out_ring, &pkt);
}

/* per-interface thread */

static void *capture_thread_main(void *arg)
{
    capture_thread *ct = (capture_thread *) arg;

    while (!geotrace_flag_is_raised(ct->parent->stop_flag)) {
        int n = pcap_dispatch(ct->handle, -1, on_packet, (u_char *) ct);
        if (n < 0) {
            /* pcap_breakloop returns -2, which is the orderly shutdown path.
             * Anything else means this interface is done for (unplugged, VPN
             * torn down, permissions revoked), and this thread is about to
             * exit: tell the UI, since nothing else can observe it.
             */
            if (n == -2)
                break;
            report_capture_error(ct->parent, ct->ifname,
                                 pcap_geterr(ct->handle));
            break;
        }
        /* n == 0 means timeout fired; loop will recheck the stop flag. */
    }
    return NULL;
}

/* vtable */

static const char *const *pcap_source_interfaces(struct packet_source *self)
{
    const pcap_source_t *p = (const pcap_source_t *) self;
    return p->iface_pointers;
}

static size_t pcap_source_iface_count(struct packet_source *self)
{
    const pcap_source_t *p = (const pcap_source_t *) self;
    return p->iface_count;
}

static int open_one(capture_thread *ct, const char *ifname)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *h = pcap_create(ifname, errbuf);
    if (!h) {
        fprintf(stderr, "geotrace: pcap_create(%s): %s\n", ifname, errbuf);
        return -1;
    }
    pcap_set_snaplen(h, PCAP_SNAPLEN);
    pcap_set_promisc(h, 0);
    pcap_set_timeout(h, PCAP_TIMEOUT);
    pcap_set_buffer_size(h, PCAP_BUFSIZE);

    int rc = pcap_activate(h);
    if (rc < 0) {
        fprintf(stderr, "geotrace: pcap_activate(%s): %s\n", ifname,
                pcap_geterr(h));
        pcap_close(h);
        return -1;
    }
    if (rc > 0) {
        fprintf(stderr, "geotrace: pcap_activate(%s) warning: %s\n", ifname,
                pcap_statustostr(rc));
    }

    /* Compile + install BPF program. */
    struct bpf_program prog;
    if (pcap_compile(h, &prog, BPF_FILTER, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        fprintf(stderr, "geotrace: pcap_compile(%s): %s\n", ifname,
                pcap_geterr(h));
        pcap_close(h);
        return -1;
    }
    if (pcap_setfilter(h, &prog) != 0) {
        fprintf(stderr, "geotrace: pcap_setfilter(%s): %s\n", ifname,
                pcap_geterr(h));
        pcap_freecode(&prog);
        pcap_close(h);
        return -1;
    }
    pcap_freecode(&prog);

    ct->handle = h;
    ct->link_offset = link_offset_for_dlt(pcap_datalink(h));
    geotrace_copy_cstr(ct->ifname, sizeof(ct->ifname), ifname);
    return 0;
}

static int pcap_source_start(struct packet_source *self,
                             struct ring *packets_out,
                             struct ring *statuses_out,
                             geotrace_flag *stop)
{
    pcap_source_t *p = (pcap_source_t *) self;
    p->out_ring = packets_out;
    p->status_ring = statuses_out;
    p->stop_flag = stop;

    p->threads =
        (capture_thread *) xcalloc(p->iface_count, sizeof(*p->threads));
    p->thread_count = 0;

    for (size_t i = 0; i < p->iface_count; i++) {
        capture_thread *ct = &p->threads[p->thread_count];
        ct->parent = p;

        if (open_one(ct, p->iface_storage[i]) != 0) {
            /* Best-effort: keep going with remaining interfaces. The
             * orchestrator sees a non-fatal partial start (return 0 if at least
             * one opened, -1 if none opened), so a partial failure would
             * otherwise be visible only on the stderr the UI is about to paint
             * over.
             */
            report_capture_error(p, p->iface_storage[i],
                                 "interface could not be opened");
            continue;
        }
        if (pthread_create(&ct->thread, NULL, capture_thread_main, ct) != 0) {
            pcap_close(ct->handle);
            ct->handle = NULL;
            report_capture_error(p, p->iface_storage[i],
                                 "capture thread could not be started");
            continue;
        }
        p->thread_count++;
    }

    return p->thread_count > 0 ? 0 : -1;
}

static void pcap_source_stop(struct packet_source *self)
{
    pcap_source_t *p = (pcap_source_t *) self;
    if (!p->threads)
        return;

    /* Raise stop defensively so teardown converges even after partial startup.
     */
    if (p->stop_flag)
        geotrace_flag_raise(p->stop_flag);

    for (size_t i = 0; i < p->thread_count; i++) {
        if (p->threads[i].handle)
            pcap_breakloop(p->threads[i].handle);
    }
    for (size_t i = 0; i < p->thread_count; i++) {
        pthread_join(p->threads[i].thread, NULL);
        if (p->threads[i].handle) {
            pcap_close(p->threads[i].handle);
            p->threads[i].handle = NULL;
        }
    }
    free(p->threads);
    p->threads = NULL;
    p->thread_count = 0;
}

struct packet_source *pcap_source_create(
    const char ifaces[][GEOTRACE_IFACE_LEN],
    size_t count)
{
    if (count == 0)
        return NULL;
    if (count > GEOTRACE_MAX_INTERFACES)
        count = GEOTRACE_MAX_INTERFACES;

    pcap_source_t *p = (pcap_source_t *) xcalloc(1, sizeof(*p));

    p->base.start = pcap_source_start;
    p->base.stop = pcap_source_stop;
    p->base.interfaces = pcap_source_interfaces;
    p->base.interface_count = pcap_source_iface_count;

    p->iface_count = count;
    for (size_t i = 0; i < count; i++) {
        geotrace_copy_cstr(p->iface_storage[i], GEOTRACE_IFACE_LEN, ifaces[i]);
        p->iface_pointers[i] = p->iface_storage[i];
    }
    p->iface_pointers[count] = NULL;
    return &p->base;
}

void pcap_source_destroy(struct packet_source *s)
{
    if (!s)
        return;
    pcap_source_t *p = (pcap_source_t *) s;
    if (p->threads)
        pcap_source_stop(s);
    free(p);
}

#endif /* HAVE_PCAP */
