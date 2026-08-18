#ifndef GEOTRACE_RESOLVER_H
#define GEOTRACE_RESOLVER_H

#include "geotrace/atomic.h"
#include "geotrace/geo.h"
#include "geotrace/ring.h"

/* Resolver: the middle pipeline stage. Takes packet_event values off the
 * capture ring, attaches geolocation, and emits connection_event values for the
 * UI plus a shutdown banner on the status ring.
 *
 * Owns no threads. The orchestrator runs resolver_main on its own pthread and
 * keeps the context alive for that thread's lifetime.
 */
typedef struct {
    struct ring *packets_in;
    struct ring *connections_out;
    struct ring *statuses_out;
    struct geo_cache *cache;

    /* Bounds one geo lookup. 0 keeps the resolver on the cache, which is how
     * the orchestrator expresses demo mode without this layer knowing.
     */
    int geo_timeout_ms;
    geotrace_flag *stop;
} resolver_ctx;

/* pthread entry point; "arg" is a resolver_ctx *.
 *
 * Returns when the stop flag is raised or the input ring shuts down.
 */
void *resolver_main(void *arg);

#endif /* GEOTRACE_RESOLVER_H */
