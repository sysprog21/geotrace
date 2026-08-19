#include "geo-http.h"

#include "geotrace/models.h"

#include <ctype.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Find the body — first occurrence of "\r\n\r\n".
 *
 * Returns NULL if no headers.
 */
const char *geo_http_find_body(const char *response)
{
    const char *p = strstr(response, "\r\n\r\n");
    return p ? p + 4 : NULL;
}

/* Parse HTTP/1.1 status code. Expects "HTTP/1.x NNN ..." at the start.
 * Returns -1 unless all three code characters are digits — without that check a
 * malformed status line yields an arbitrary int that slips through the 4xx/5xx
 * classification in http_lookup.
 *
 * A leading '0' is rejected too, so the result is -1 or a real 100..999 code
 * and never something like 42. RFC 9110 has no status below 100, and the
 * header's postcondition states that range; without this check "HTTP/1.1 042 x"
 * returned 42 and made that postcondition false, which is the kind of unsound
 * assumption a verified caller would then inherit. No behaviour changes at the
 * only call site: geo_http_classify_status maps both 42 and -1 to
 * GEO_HTTP_TRANSIENT.
 */
int geo_http_parse_status_code(const char *response)
{
    if (strncmp(response, "HTTP/1.", 7) != 0)
        return -1;

    /* strncmp only vouches for the first 7 bytes, so check the length before
     * indexing: minor version at [7], separating space at [8], code at [9, 11].
     */
    if (strlen(response) < 12)
        return -1;
    if (!isdigit((unsigned char) response[7]) || response[8] != ' ')
        return -1;
    for (int i = 9; i <= 11; i++) {
        if (!isdigit((unsigned char) response[i]))
            return -1;
    }
    if (response[9] == '0')
        return -1;
    return (response[9] - '0') * 100 + (response[10] - '0') * 10 +
           (response[11] - '0');
}

/* minimal JSON value extraction */

/* Invariant: every json_* helper below requires "json" to be NUL-terminated.
 * The scanners walk forward on "*p", so an unterminated buffer would read past
 * the end. The only caller (geo_lookup) explicitly NUL-terminates the recv
 * buffer; do not introduce a call site that passes a non-terminated slice.
 */

/* Skip a JSON string starting at the opening quote; returns the byte after the
 * closing quote, or NULL if the string never closes.
 */
static const char *json_skip_string(const char *p)
{
    if (*p != '"')
        return NULL;
    for (p++; *p; p++) {
        if (*p == '\\') {
            if (!p[1])
                return NULL;
            p++;
            continue;
        }
        if (*p == '"')
            return p + 1;
    }
    return NULL;
}

/* Find a TOP-LEVEL "<key>": and return the start of its value, whitespace
 * skipped. NULL if absent.
 *
 * Walks the object rather than reaching for strstr. strstr matched the key
 * anywhere, so a response of the shape
 *
 *     {"meta":{"lat":99.0},"lat":25.033}
 *
 * yielded 99.0: the nested field won because it came first. ip-api's own
 * replies are flat, but they arrive over plaintext HTTP with no TLS on the free
 * tier, so the bytes are whatever reaches the socket, and these values are the
 * coordinates the map is drawn from. Depth tracking, and only accepting a
 * string in key position, is what makes "top-level" true rather than assumed.
 */
static const char *json_seek_value(const char *json, const char *key)
{
    const char *p = json;
    size_t key_len = strlen(key);
    int depth = 0;
    bool expect_key = false;

    while (*p) {
        if (*p == '{' || *p == '[') {
            depth++;
            expect_key = (*p == '{' && depth == 1);
            p++;
            continue;
        }
        if (*p == '}' || *p == ']') {
            depth--;
            expect_key = false;
            p++;
            continue;
        }
        if (*p == ',') {
            expect_key = (depth == 1);
            p++;
            continue;
        }
        if (*p == '"') {
            const char *after = json_skip_string(p);
            if (!after)
                return NULL;

            /* Only a string in key position at depth 1 can be our key; a value
             * that happens to spell it must not match.
             */
            if (expect_key && depth == 1 &&
                (size_t) (after - p) == key_len + 2 &&
                strncmp(p + 1, key, key_len) == 0) {
                const char *v = after;
                while (*v == ' ' || *v == '\t')
                    v++;
                if (*v != ':')
                    return NULL;
                v++;
                while (*v == ' ' || *v == '\t')
                    v++;
                return v;
            }
            expect_key = false;
            p = after;
            continue;
        }
        p++;
    }
    return NULL;
}

/* Values arrive over plaintext HTTP (ip-api's free tier has no TLS) and are
 * bound for the terminal, so a control byte here would reach the tty verbatim
 * as an escape sequence. Fold C0 and DEL to a space at the trust boundary;
 * bytes >= 0x80 pass through so non-ASCII place names survive.
 */
/*@ assigns \nothing;
    ensures \result == ' ' || \result == c;
 */
static char sanitize_display_byte(char c)
{
    unsigned char u = (unsigned char) c;
    return (u < 0x20 || u == 0x7F) ? ' ' : c;
}

/* Extract a JSON string into out (NUL-terminated).
 *
 * Returns true on success. \uXXXX escapes are represented as spaces; ip-api
 * country/city values used by the UI are normally ASCII, and bounded copies
 * preserve buffer safety.
 */
bool geo_json_get_string(const char *json,
                         const char *key,
                         char *out,
                         size_t cap)
{
    const char *p = json_seek_value(json, key);
    if (!p || *p != '"')
        return false;
    p++;
    size_t i = 0;

    /* i only advances under an "i + 1 < cap" guard, so it never reaches cap;
     * that is what keeps every out[i] write inside the caller's buffer.
     */
    /*@ loop invariant bounded: i == 0 || i < cap;
        loop invariant readable: \valid_read(p);
        loop assigns i, p, out[0 .. cap - 1];
     */
    while (*p && *p != '"') {
        if (*p != '\\' || !p[1]) {
            if (i + 1 < cap)
                out[i++] = sanitize_display_byte(*p);
            p++;
            continue;
        }
        char escaped = p[1];
        if (escaped == 'u') {
            /* Skip \uXXXX as a single space. All four characters must be hex
             * digits; a truncated "\u" near the end of a string (e.g. "\u12")
             * would otherwise let p += 6 walk past the closing quote into the
             * next JSON value.
             *
             * Terminate before bailing: by the time a bad escape is reached the
             * loop has already copied everything before it into "out", so
             * returning straight away would hand back a buffer that was written
             * but never NUL-terminated. Callers that pre-zero their buffer
             * survive that; one that does not gets an unbounded read.
             */
            for (int k = 2; k <= 5; k++) {
                if (!isxdigit((unsigned char) p[k])) {
                    if (cap)
                        out[i < cap ? i : cap - 1] = '\0';
                    return false;
                }
            }
            p += 6;
            if (i + 1 < cap)
                out[i++] = ' ';
            continue;
        }
        char decoded;
        switch (escaped) {
        case 'n':
            decoded = '\n';
            break;
        case 't':
            decoded = '\t';
            break;
        default: /* ", \, /, and any other simple escape — copy verbatim */
            decoded = escaped;
            break;
        }
        if (i + 1 < cap)
            out[i++] = sanitize_display_byte(decoded);
        p += 2;
    }
    if (cap)
        out[i < cap ? i : cap - 1] = '\0';
    return *p == '"';
}

bool geo_json_get_double(const char *json, const char *key, double *out)
{
    const char *p = json_seek_value(json, key);
    if (!p)
        return false;
    char *end = NULL;
    double v = strtod(p, &end);
    if (end == p || !isfinite(v))
        return false;

    /* strtod stops at the first byte it cannot use, so "25abc" would otherwise
     * be accepted as 25 and a malformed coordinate would read as authoritative.
     * The number has to end where a JSON value legally ends.
     */
    if (*end != '\0' && *end != ',' && *end != '}' && *end != ']' &&
        *end != ' ' && *end != '\t' && *end != '\n' && *end != '\r')
        return false;
    *out = v;
    return true;
}

bool geo_json_get_status_success(const char *json)
{
    char buf[16];
    if (!geo_json_get_string(json, "status", buf, sizeof(buf)))
        return false;
    return strcmp(buf, "success") == 0;
}

/* Authoritative-miss sentinel: zeroed result with valid=false. */
geo_http_result geo_http_auth_miss(geo_result *out)
{
    memset(out, 0, sizeof(*out));
    return GEO_HTTP_MISS;
}

/* Map an HTTP status to a cache decision, without touching a socket so the
 * policy is directly testable.
 *
 * GEO_HTTP_OK means "status is fine, keep parsing the body"; it is not yet a
 * result. Every other return is final.
 */
geo_http_result geo_http_classify_status(int status, geo_result *out)
{
    if (status < 0)
        return GEO_HTTP_TRANSIENT;

    /* 429 earns a cooldown. 5xx is transient. 4xx is an authoritative miss: no
     * retry of the same IP will satisfy a 400/404 from ip-api.
     */
    if (status == 429)
        return GEO_HTTP_RATE_LIMITED;
    if (status >= 500)
        return GEO_HTTP_TRANSIENT;
    if (status >= 400)
        return geo_http_auth_miss(out);
    if (status != 200)
        return GEO_HTTP_TRANSIENT;
    return GEO_HTTP_OK;
}
