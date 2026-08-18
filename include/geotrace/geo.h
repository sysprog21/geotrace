#ifndef GEOTRACE_GEO_H
#define GEOTRACE_GEO_H

#include "geotrace/models.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* IP filter — single canonical "is this address worth geolocating?" gate. Both
 * the source thread (BPF complement) and the resolver call it.
 *
 * Byte-order contract:
 *   IPV4_BLOCKED_RANGES is sorted in host byte order.
 *   _host takes a host-order uint32_t (ntohl applied at the wire boundary).
 *   _be is a convenience that does the ntohl for you.
 */

bool is_public_ipv4_host(uint32_t ip_host);
bool is_public_ipv4_be(uint32_t ip_be);

/* geo cache + lookup */

struct geo_cache;

/* Create a cache. initial_capacity is rounded up to a power of two and capped
 * at a safely allocatable size. Aborts on OOM.
 */
struct geo_cache *geo_cache_create(size_t initial_capacity);

void geo_cache_destroy(struct geo_cache *c);

/* Lookup with caching.
 *
 * Returns true iff the cache (or live HTTP) produced a valid result and filled
 * *out. On a cached "authoritative no-result" sentinel, returns false with
 * out->valid == false. On transient failure, returns false and does not write
 * the cache.
 *
 * "timeout_ms" bounds each connect and socket-I/O attempt. Use 0 to skip the
 * network and only consult the cache. Invalid arguments produce false.
 */
bool geo_lookup(struct geo_cache *c,
                uint32_t ip_be,
                int timeout_ms,
                geo_result *out);

/* Insert a known result. Used by --demo to preload the table. "result->valid"
 * may be false to install an authoritative-miss sentinel. Null arguments are
 * ignored.
 */
void geo_cache_put(struct geo_cache *c,
                   uint32_t ip_be,
                   const geo_result *result);

#endif /* GEOTRACE_GEO_H */
