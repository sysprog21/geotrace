#ifndef GEOTRACE_MODELS_H
#define GEOTRACE_MODELS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* Wire-side and UI-side data types. POD only — no hidden allocations, all
 * fixed-size so the ring buffer can copy them by value.
 *
 * created_at uses CLOCK_MONOTONIC. NTP / manual wall-clock changes must not
 * warp event ages. Wall-clock conversion happens only at the display boundary.
 */

#define GEOTRACE_PROTO_LEN 7  /* "ICMPv6" + NUL */
#define GEOTRACE_IP_LEN 16    /* "255.255.255.255" + NUL; IPv4 display text */
#define GEOTRACE_IFACE_LEN 16 /* IFNAMSIZ on Linux is 16 */
#define GEOTRACE_COUNTRY_LEN 48
#define GEOTRACE_CITY_LEN 48
#define GEOTRACE_STATUS_MSGLEN 192

typedef struct {
    double lat;
    double lon;
} geo_point;

typedef struct {
    bool valid; /* false => "no result" sentinel */
    geo_point point;
    char ip[GEOTRACE_IP_LEN];
    char country[GEOTRACE_COUNTRY_LEN];
    char city[GEOTRACE_CITY_LEN];
} geo_result;

/* packet_event — capture thread → resolver. Network-order IP fields stay
 * network-order until the resolver converts. Strings are NUL-terminated POD.
 */
typedef struct {
    uint32_t src_ip_be;   /* network byte order */
    uint32_t dst_ip_be;   /* network byte order */
    uint32_t size;        /* total packet bytes */
    uint16_t ip_protocol; /* IANA protocol number */
    char interface[GEOTRACE_IFACE_LEN];
    struct timespec created_at; /* CLOCK_MONOTONIC */
} packet_event;

/* connection_event — resolver → UI. coords_valid follows from a successful geo
 * lookup; on miss the marker is suppressed but the row still lists.
 */
typedef struct {
    uint32_t src_ip_be;
    uint32_t dst_ip_be;
    uint32_t size;
    uint16_t ip_protocol;
    bool coords_valid;
    geo_point coords;
    char interface[GEOTRACE_IFACE_LEN];
    char country[GEOTRACE_COUNTRY_LEN];
    char protocol[GEOTRACE_PROTO_LEN];
    struct timespec created_at;
} connection_event;

/* status_event — banner messages. Severity: 0 info, 1 warn, 2 error. */
typedef enum {
    GEOTRACE_STATUS_INFO = 0,
    GEOTRACE_STATUS_WARN = 1,
    GEOTRACE_STATUS_ERROR = 2,
} status_level;

typedef struct {
    status_level level;
    struct timespec created_at;
    char message[GEOTRACE_STATUS_MSGLEN];
} status_event;

#endif /* GEOTRACE_MODELS_H */
