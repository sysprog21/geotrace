#include "geotrace/resolver.h"

#include "geotrace/util.h"

#include <stddef.h>
#include <stdint.h>
#include <time.h>

static const char *protocol_name(uint16_t ip_protocol)
{
    switch (ip_protocol) {
    case 1:
        return "ICMP";
    case 6:
        return "TCP";
    case 17:
        return "UDP";
    case 41:
        return "IPv6";
    case 47:
        return "GRE";
    case 50:
        return "ESP";
    case 51:
        return "AH";
    case 132:
        return "SCTP";
    default:
        return "?";
    }
}

void *resolver_main(void *arg)
{
    resolver_ctx *ctx = (resolver_ctx *) arg;
    packet_event pkt;

    while (!geotrace_flag_is_raised(ctx->stop)) {
        if (!ring_take(ctx->packets_in, &pkt))
            break; /* shutdown */

        connection_event ce = {0};
        ce.src_ip_be = pkt.src_ip_be;
        ce.dst_ip_be = pkt.dst_ip_be;
        ce.size = pkt.size;
        ce.ip_protocol = pkt.ip_protocol;
        ce.created_at = pkt.created_at;
        geotrace_copy_cstr(ce.interface, sizeof(ce.interface), pkt.interface);
        geotrace_copy_cstr(ce.protocol, sizeof(ce.protocol),
                           protocol_name(pkt.ip_protocol));

        geo_result r = {0};
        if (geo_lookup(ctx->cache, pkt.dst_ip_be, ctx->geo_timeout_ms, &r)) {
            ce.coords_valid = true;
            ce.coords = r.point;
            geotrace_copy_cstr(ce.country, sizeof(ce.country), r.country);
        } else {
            ce.coords_valid = false;
            geotrace_copy_cstr(ce.country, sizeof(ce.country), "GeoIP miss");
        }
        ring_put_latest(ctx->connections_out, &ce);
    }

    /* Push a final status banner so the UI shows a clean shutdown line. */
    status_event s = {0};
    s.level = GEOTRACE_STATUS_INFO;
    geotrace_copy_cstr(s.message, sizeof(s.message), "Resolver stopped.");
    clock_gettime(CLOCK_MONOTONIC, &s.created_at);
    ring_put_latest(ctx->statuses_out, &s);
    return NULL;
}
