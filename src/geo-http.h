#ifndef GEOTRACE_GEO_HTTP_H
#define GEOTRACE_GEO_HTTP_H

#include <stdbool.h>
#include <stddef.h>

#include "geotrace/models.h"

/* HTTP response and JSON parsing for the ip-api.com lookup.
 *
 * Internal to src/, not part of the public API in include/geotrace/. Split out
 * of geo.c because that file was carrying four unrelated concerns (open-
 * addressing cache, socket dialling, HTTP framing, JSON extraction) and this is
 * the one that reads bytes chosen by a remote party. On its own it can be
 * tested without dragging in sockets.
 *
 * Every function here requires a NUL-terminated "response"/"json". The scanners
 * walk forward, so an unterminated buffer reads past the end; geo.c terminates
 * the recv buffer explicitly before calling in. Do not add a call site that
 * passes a non-terminated slice.
 */

/* First byte after the "\r\n\r\n" header terminator, or NULL if absent. */
const char *geo_http_find_body(const char *response);

/* Status code from an "HTTP/1.x NNN ..." status line, or -1 if malformed. All
 * three code characters must be digits: without that a malformed line yields an
 * arbitrary int that would slip through the 4xx/5xx classification.
 */
int geo_http_parse_status_code(const char *response);

/* Extract a JSON string value into "out", always NUL-terminated.
 *
 * Values arrive over plaintext HTTP and are bound for the terminal, so C0 and
 * DEL bytes are folded to spaces here, at the trust boundary; bytes >= 0x80
 * pass through so non-ASCII place names survive. \uXXXX escapes become spaces.
 */
bool geo_json_get_string(const char *json,
                         const char *key,
                         char *out,
                         size_t cap);

bool geo_json_get_double(const char *json, const char *key, double *out);

/* True when the response carries "status":"success". */
bool geo_json_get_status_success(const char *json);

/* Cache decision for an HTTP status, derived without touching a socket so the
 * policy is directly testable.
 */
typedef enum {
    GEO_HTTP_OK = 1,            /* authoritative result, out filled */
    GEO_HTTP_MISS = 0,          /* authoritative miss, out is the sentinel */
    GEO_HTTP_TRANSIENT = -1,    /* retry later */
    GEO_HTTP_RATE_LIMITED = -2, /* 429: stop asking for a while */
} geo_http_result;

/* GEO_HTTP_OK means "status is fine, keep parsing the body"; it is not yet a
 * result. Every other return is final.
 */
geo_http_result geo_http_classify_status(int status, geo_result *out);

/* Authoritative-miss sentinel: zeroes "out" (valid=false) and returns
 * GEO_HTTP_MISS. Shared with geo.c, which reaches the same verdict from a
 * "status":"fail" body rather than from the HTTP status line.
 */
geo_http_result geo_http_auth_miss(geo_result *out);

#endif /* GEOTRACE_GEO_HTTP_H */
