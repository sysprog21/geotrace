#include "geotrace/geo.h"

#include "geotrace/oom.h"
#include "geotrace/util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* IP filter */

/* Reserved / non-globally-routable ranges in host byte order, sorted by start.
 * Comments use the corresponding CIDR for human review.
 */
static const struct {
    uint32_t start;
    uint32_t end;
} IPV4_BLOCKED_RANGES[] = {
    {0x00000000, 0x00FFFFFF}, /* 0.0.0.0/8       — "this network" */
    {0x0A000000, 0x0AFFFFFF}, /* 10.0.0.0/8      — RFC1918 */
    {0x64400000, 0x647FFFFF}, /* 100.64.0.0/10   — CGNAT */
    {0x7F000000, 0x7FFFFFFF}, /* 127.0.0.0/8     — loopback */
    {0xA9FE0000, 0xA9FEFFFF}, /* 169.254.0.0/16  — link-local */
    {0xAC100000, 0xAC1FFFFF}, /* 172.16.0.0/12   — RFC1918 */
    {0xC0000000, 0xC00000FF}, /* 192.0.0.0/24    — IETF protocol assignments */
    {0xC0000200, 0xC00002FF}, /* 192.0.2.0/24    — TEST-NET-1 */
    {0xC0A80000, 0xC0A8FFFF}, /* 192.168.0.0/16  — RFC1918 */
    {0xC6120000, 0xC613FFFF}, /* 198.18.0.0/15   — benchmark */
    {0xC6336400, 0xC63364FF}, /* 198.51.100.0/24 — TEST-NET-2 */
    {0xCB007100, 0xCB0071FF}, /* 203.0.113.0/24  — TEST-NET-3 */
    {0xE0000000, 0xFFFFFFFF}, /* 224.0.0.0/3     — multicast + reserved */
};

/* Whitelist: known public addresses inside otherwise-blocked /24s. 192.0.0.9
 * and 192.0.0.10 are PCP/PortMap.
 */
static const uint32_t IPV4_ALLOWED_EXCEPTIONS[] = {
    0xC0000009,
    0xC000000A,
};

bool is_public_ipv4_host(uint32_t ip_host)
{
    /* Whitelist short-circuits the range check. Linear scan is fine; it's two
     * entries today.
     */
    for (size_t i = 0; i < GEOTRACE_ARRAY_LEN(IPV4_ALLOWED_EXCEPTIONS); i++) {
        if (ip_host == IPV4_ALLOWED_EXCEPTIONS[i])
            return true;
    }

    /* Binary search for the largest start <= ip_host, then bounds-check end. */
    size_t lo = 0;
    size_t hi = GEOTRACE_ARRAY_LEN(IPV4_BLOCKED_RANGES);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (IPV4_BLOCKED_RANGES[mid].start <= ip_host)
            lo = mid + 1;
        else
            hi = mid;
    }
    /* lo is now the first range with start > ip_host. Candidate is at lo-1. */
    if (lo > 0) {
        size_t cand = lo - 1;
        if (ip_host >= IPV4_BLOCKED_RANGES[cand].start &&
            ip_host <= IPV4_BLOCKED_RANGES[cand].end)
            return false;
    }
    return true;
}

bool is_public_ipv4_be(uint32_t ip_be)
{
    return is_public_ipv4_host(ntohl(ip_be));
}

/* open-addressing cache */

/* No tombstone state: entries are never deleted, only overwritten or rehashed
 * by a grow. Add one only alongside a delete API, and reinstate the probe-skip
 * logic in find_slot at the same time.
 */
typedef enum {
    SLOT_EMPTY = 0,
    SLOT_OCCUPIED = 1,
} slot_state;

typedef struct {
    slot_state state;
    uint32_t key; /* host byte order */
    geo_result value;
} cache_slot;

struct geo_cache {
    pthread_mutex_t mtx;
    cache_slot *slots;
    size_t capacity; /* power of two */
    size_t count;    /* occupied slots */

    /* CLOCK_MONOTONIC second before which no request is attempted, set when
     * ip-api answers 429. Without it every packet to an uncached IP re-issues a
     * request that the service is already refusing, and each one costs the full
     * timeout in the single resolver thread.
     */
    time_t quiet_until;
};

/* ip-api's free tier allows 45 requests/minute and the window resets each
 * minute, so one minute is the shortest wait that reliably clears it.
 */
#define GEO_RATE_LIMIT_QUIET_S 60

/* Shorter cooldown for connect/timeout failures. Without it a down network
 * costs the full per-request timeout on every uncached IP, and the single
 * resolver thread falls permanently behind a packet ring it can never drain.
 * Short enough that a brief blip barely shows, long enough that a sustained
 * outage costs one request per interval instead of one per packet.
 */
#define GEO_TRANSIENT_QUIET_S 5

#define GEO_CACHE_LOAD_NUM 7 /* resize when count * 10 >= capacity * 7 */
#define GEO_CACHE_LOAD_DEN 10
#define GEO_CACHE_MIN_CAP 16

/* Largest power of two that fits a slot allocation in size_t. */
#define GEO_CACHE_MAX_CAP (((size_t) 1) << (sizeof(size_t) * 8 - 2))

static size_t round_up_pow2(size_t n)
{
    if (n < GEO_CACHE_MIN_CAP)
        return GEO_CACHE_MIN_CAP;
    if (n > GEO_CACHE_MAX_CAP)
        return GEO_CACHE_MAX_CAP;
    size_t p = GEO_CACHE_MIN_CAP;
    while (p < n)
        p <<= 1;
    return p;
}

/* MurmurHash3-style finalizer for uniformly spreading sparse IPv4 keys. */
static uint32_t hash_key(uint32_t k)
{
    k ^= k >> 16;
    k *= 0x85ebca6bu;
    k ^= k >> 13;
    k *= 0xc2b2ae35u;
    k ^= k >> 16;
    return k;
}

struct geo_cache *geo_cache_create(size_t initial_capacity)
{
    struct geo_cache *c = (struct geo_cache *) xcalloc(1, sizeof(*c));
    c->capacity = round_up_pow2(initial_capacity);
    c->slots = (cache_slot *) xcalloc(c->capacity, sizeof(*c->slots));
    if (pthread_mutex_init(&c->mtx, NULL) != 0)
        abort();
    return c;
}

void geo_cache_destroy(struct geo_cache *c)
{
    if (!c)
        return;
    pthread_mutex_destroy(&c->mtx);
    free(c->slots);
    free(c);
}

/* Probe sequence: linear, mask = capacity-1 (capacity is power of two).
 *
 * Returns the matching slot, or the first empty slot where the key belongs.
 * NULL only when the table is completely full, which needs resize_locked to
 * have refused a grow at GEO_CACHE_MAX_CAP.
 */
static cache_slot *find_slot(cache_slot *slots, size_t cap, uint32_t key)
{
    size_t mask = cap - 1;
    size_t idx = hash_key(key) & mask;

    for (size_t i = 0; i < cap; i++) {
        cache_slot *s = &slots[(idx + i) & mask];
        if (s->state == SLOT_EMPTY || s->key == key)
            return s;
    }
    return NULL;
}

/* Caller holds the lock.
 *
 * Returns true on success, false when the cache is too large to grow without
 * size_t overflow.
 */
static bool resize_locked(struct geo_cache *c)
{
    /* Prevent capacity wrap and the implicit nmemb*size overflow inside
     * xcalloc. Hitting this branch in practice means a runaway cache; refuse
     * the grow and let needs_resize() keep returning true so the cache stops
     * accepting new authoritative-miss inserts but keeps serving hits.
     */
    if (c->capacity > GEO_CACHE_MAX_CAP / 2)
        return false;
    size_t new_cap = c->capacity << 1;
    if (new_cap > SIZE_MAX / sizeof(cache_slot))
        return false;
    cache_slot *new_slots = (cache_slot *) xcalloc(new_cap, sizeof(*new_slots));

    for (size_t i = 0; i < c->capacity; i++) {
        if (c->slots[i].state != SLOT_OCCUPIED)
            continue;
        cache_slot *dst = find_slot(new_slots, new_cap, c->slots[i].key);
        *dst = c->slots[i];
    }
    free(c->slots);
    c->slots = new_slots;
    c->capacity = new_cap;
    return true;
}

static bool needs_resize(const struct geo_cache *c)
{
    return c->count * GEO_CACHE_LOAD_DEN >= c->capacity * GEO_CACHE_LOAD_NUM;
}

/* Internal insert. Caller holds the lock. */
static void cache_put_locked(struct geo_cache *c,
                             uint32_t key,
                             const geo_result *value)
{
    if (needs_resize(c)) {
        /* Capacity exhaustion is non-fatal: skip caching this insert. The
         * caller will still get the live result.
         */
        if (!resize_locked(c))
            return;
    }
    cache_slot *s = find_slot(c->slots, c->capacity, key);
    if (!s)
        return;
    if (s->state != SLOT_OCCUPIED)
        c->count++;
    s->state = SLOT_OCCUPIED;
    s->key = key;
    s->value = *value;
}

void geo_cache_put(struct geo_cache *c,
                   uint32_t ip_be,
                   const geo_result *result)
{
    if (!c || !result)
        return;
    uint32_t key = ntohl(ip_be);
    pthread_mutex_lock(&c->mtx);
    cache_put_locked(c, key, result);
    pthread_mutex_unlock(&c->mtx);
}

/* ---- HTTP client (raw TCP, ip-api.com is HTTP-only on the free tier) -- */

#define GEO_HOST "ip-api.com"
#define GEO_PORT "80"
#define GEO_RESPONSE_MAX 4096

static struct timeval ms_to_timeval(int timeout_ms)
{
    return (struct timeval) {
        .tv_sec = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
}

/* Wait for a non-blocking connect() to finish, bounded by timeout_ms.
 * Returns 0 on success, -1 on timeout / select error / asynchronous failure.
 */
static int wait_for_connect(int fd, int timeout_ms)
{
    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(fd, &wset);
    struct timeval tv = ms_to_timeval(timeout_ms);

    if (select(fd + 1, NULL, &wset, NULL, &tv) <= 0)
        return -1;

    int err = 0;
    socklen_t el = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err != 0)
        return -1;
    return 0;
}

/* Open one socket and connect to ai with a bounded timeout.
 *
 * Returns the fd on success, -1 on failure (socket has been closed).
 */
static int dial_one(const struct addrinfo *ai, int timeout_ms)
{
    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0)
        return -1;

    /* select(3) with fd_set is defined only for fds < FD_SETSIZE; a larger fd
     * would corrupt the stack via FD_SET. The geo path opens at most one fd at
     * a time so this only trips with an absurd RLIMIT_NOFILE, but the check is
     * cheap.
     */
    if (fd >= FD_SETSIZE)
        goto fail;

    /* Non-blocking is mandatory so connect() returns EINPROGRESS and the
     * select() below can enforce the timeout.
     */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        goto fail;

    int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (rc != 0) {
        if (errno != EINPROGRESS)
            goto fail;
        if (wait_for_connect(fd, timeout_ms) != 0)
            goto fail;
    }

    /* Restore the original (blocking) flags so SO_RCVTIMEO/SO_SNDTIMEO bound
     * the next send()/recv() instead of returning EAGAIN.
     */
    if (fcntl(fd, F_SETFL, flags) < 0)
        goto fail;

    /* The fd is blocking again, so these timeouts are the only thing bounding
     * the send/recv below. If they cannot be installed, fail the dial rather
     * than hand the resolver a socket it can block on forever.
     */
    struct timeval rt = ms_to_timeval(timeout_ms);
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rt, sizeof(rt)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &rt, sizeof(rt)) != 0)
        goto fail;
    return fd;

fail:
    close(fd);
    return -1;
}

/* Connect to host:port with a connect timeout.
 *
 * Returns fd or -1. The fd is temporarily non-blocking during connect, then
 * restored to blocking mode so later send/recv calls use SO_RCVTIMEO.
 */
static int dial(const char *host, const char *port, int timeout_ms)
{
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;

    int fd = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next) {
        fd = dial_one(p, timeout_ms);
        if (fd >= 0)
            break;
    }
    freeaddrinfo(res);
    return fd;
}

static ssize_t send_all(int fd, const char *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        sent += (size_t) n;
    }
    return (ssize_t) sent;
}

/* Read the complete response into buf (NUL-terminated).
 * Returns bytes read, or -1 on error, timeout, or truncation.
 *
 * budget_ms bounds the whole read, not each recv. SO_RCVTIMEO only bounds one
 * call, so a peer trickling a byte per timeout could otherwise hold the single
 * resolver thread for cap * timeout_ms (hours at the default), during which no
 * geo lookups happen at all. The transport is plaintext HTTP, so that peer need
 * not be ip-api.com.
 *
 * Success requires the peer's EOF. The request says "Connection: close", so a
 * complete response always ends in one; anything shorter is a prefix, and
 * parsing a prefix would cache a half-read country name (or a body cut short
 * before the field that would have made it a miss) as if it were
 * authoritative. Reporting -1 sends those to the transient path, where they
 * are retried rather than remembered.
 */
static ssize_t recv_response(int fd, char *buf, size_t cap, int budget_ms)
{
    if (!buf || cap == 0)
        return -1;
    /* FD_SET past FD_SETSIZE writes off the end of fd_set. dial_one already
     * refuses such a descriptor, but the check belongs here too now that this
     * function does its own FD_SET rather than inheriting the caller's
     * guarantee.
     */
    if (fd < 0 || fd >= FD_SETSIZE)
        return -1;

    /* No clock means no budget, and a read with no budget is the unbounded
     * wait this function exists to prevent.
     */
    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
        return -1;

    size_t total = 0;
    bool complete = false;
    while (total + 1 < cap) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
            return -1;
        int64_t remaining_ns =
            (int64_t) budget_ms * 1000000 - geotrace_elapsed_ns(start, now);
        if (remaining_ns <= 0)
            break;

        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(fd, &rset);
        /* Round up so a sub-microsecond remainder cannot produce a zero
         * timeout, which select() reads as "poll and return immediately" and
         * would spin. The casts are explicit because time_t and suseconds_t are
         * 32-bit on 32-bit Linux, where the implicit narrowing would trip
         * -Wconversion; the values are bounded by budget_ms.
         */
        int64_t remaining_us = (remaining_ns + 999) / 1000;
        struct timeval tv = {
            .tv_sec = (time_t) (remaining_us / 1000000),
            .tv_usec = (suseconds_t) (remaining_us % 1000000),
        };
        int ready = select(fd + 1, &rset, NULL, NULL, &tv);
        if (ready == 0)
            break;
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }

        /* MSG_DONTWAIT because a readable indication does not guarantee the
         * recv completes: on a spurious wakeup the blocking call would park
         * for a whole SO_RCVTIMEO past the budget. EAGAIN just sends us back
         * to the deadline check.
         */
        ssize_t n = recv(fd, buf + total, cap - 1 - total, MSG_DONTWAIT);
        if (n == 0) {
            complete = true;
            break;
        }
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            return -1;
        }
        total += (size_t) n;
    }

    if (!complete)
        return -1; /* budget expired, or the response outgrew the buffer */
    buf[total] = '\0';
    return (ssize_t) total;
}

/* Find the body — first occurrence of "\r\n\r\n".
 *
 * Returns NULL if no headers.
 */
static const char *find_body(const char *response)
{
    const char *p = strstr(response, "\r\n\r\n");
    return p ? p + 4 : NULL;
}

/* Parse HTTP/1.1 status code. Expects "HTTP/1.x NNN ..." at the start.
 * Returns -1 unless all three code characters are digits — without that check a
 * malformed status line yields an arbitrary int that slips through the 4xx/5xx
 * classification in http_lookup.
 */
static int parse_status_code(const char *response)
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
    return (response[9] - '0') * 100 + (response[10] - '0') * 10 +
           (response[11] - '0');
}

/* minimal JSON value extraction */

/* Invariant: every json_* helper below requires "json" to be NUL-terminated.
 * The scanners walk forward on "*p", so an unterminated buffer would read past
 * the end. The only caller (geo_lookup) explicitly NUL-terminates the recv
 * buffer; do not introduce a call site that passes a non-terminated slice.
 */

/* Find a top-level "<key>": and return a pointer to the start of the value
 * (whitespace skipped, value type undetermined). NULL if not found. Handles
 * flat ip-api.com JSON; doesn't dive into nested objects.
 */
static const char *json_seek_value(const char *json, const char *key)
{
    char pat[64];
    int n = snprintf(pat, sizeof(pat), "\"%s\"", key);
    if (n <= 0 || (size_t) n >= sizeof(pat))
        return NULL;

    const char *p = strstr(json, pat);
    if (!p)
        return NULL;
    p += (size_t) n;
    while (*p && (*p == ' ' || *p == '\t' || *p == ':'))
        p++;
    return p;
}

/* Values arrive over plaintext HTTP (ip-api's free tier has no TLS) and are
 * bound for the terminal, so a control byte here would reach the tty verbatim
 * as an escape sequence. Fold C0 and DEL to a space at the trust boundary;
 * bytes >= 0x80 pass through so non-ASCII place names survive.
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
static bool json_get_string(const char *json,
                            const char *key,
                            char *out,
                            size_t cap)
{
    const char *p = json_seek_value(json, key);
    if (!p || *p != '"')
        return false;
    p++;
    size_t i = 0;
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
             */
            for (int k = 2; k <= 5; k++) {
                if (!isxdigit((unsigned char) p[k]))
                    return false;
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

static bool json_get_double(const char *json, const char *key, double *out)
{
    const char *p = json_seek_value(json, key);
    if (!p)
        return false;
    char *end = NULL;
    double v = strtod(p, &end);
    if (end == p || !isfinite(v))
        return false;
    *out = v;
    return true;
}

static bool json_get_status_success(const char *json)
{
    char buf[16];
    if (!json_get_string(json, "status", buf, sizeof(buf)))
        return false;
    return strcmp(buf, "success") == 0;
}

/* request/parse helpers */

/* Build the GET request and send it. Returns 0 on success, -1 on error. */
static int send_get(int fd, const char *path)
{
    char request[512];
    int n = snprintf(request, sizeof(request),
                     "GET %s HTTP/1.1\r\n"
                     "Host: " GEO_HOST
                     "\r\n"
                     "User-Agent: geotrace/" GEOTRACE_VERSION
                     "\r\n"
                     "Accept: application/json\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     path);
    if (n <= 0 || (size_t) n >= sizeof(request))
        return -1;
    if (send_all(fd, request, (size_t) n) < 0)
        return -1;
    return 0;
}

/* Result of one HTTP attempt. Negative values are all "do not cache". */
typedef enum {
    GEO_HTTP_OK = 1,            /* authoritative result, out filled */
    GEO_HTTP_MISS = 0,          /* authoritative miss, out is the sentinel */
    GEO_HTTP_TRANSIENT = -1,    /* retry later */
    GEO_HTTP_RATE_LIMITED = -2, /* 429: stop asking for a while */
} geo_http_result;

/* Authoritative-miss sentinel: zeroed result with valid=false. */
static geo_http_result auth_miss(geo_result *out)
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
static geo_http_result classify_status(int status, geo_result *out)
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
        return auth_miss(out);
    if (status != 200)
        return GEO_HTTP_TRANSIENT;
    return GEO_HTTP_OK;
}

static geo_http_result http_lookup(const char *path,
                                   geo_result *out,
                                   int timeout_ms,
                                   const char *fallback_ip_str)
{
    if (timeout_ms <= 0)
        return GEO_HTTP_TRANSIENT;

    int fd = dial(GEO_HOST, GEO_PORT, timeout_ms);
    if (fd < 0)
        return GEO_HTTP_TRANSIENT;

    if (send_get(fd, path) < 0) {
        close(fd);
        return GEO_HTTP_TRANSIENT;
    }

    char buf[GEO_RESPONSE_MAX];
    ssize_t n = recv_response(fd, buf, sizeof(buf), timeout_ms);
    close(fd);
    if (n <= 0)
        return GEO_HTTP_TRANSIENT;

    geo_http_result cls = classify_status(parse_status_code(buf), out);
    if (cls != GEO_HTTP_OK)
        return cls;

    const char *body = find_body(buf);
    if (!body)
        return GEO_HTTP_TRANSIENT;

    /* status: "fail" — authoritative miss. */
    if (!json_get_status_success(body))
        return auth_miss(out);

    double lat, lon;
    if (!json_get_double(body, "lat", &lat) ||
        !json_get_double(body, "lon", &lon) || lat < -90.0 || lat > 90.0 ||
        lon < -180.0 || lon > 180.0)
        return auth_miss(out);

    memset(out, 0, sizeof(*out));
    out->valid = true;
    out->point.lat = lat;
    out->point.lon = lon;

    if (!json_get_string(body, "query", out->ip, sizeof(out->ip)) &&
        fallback_ip_str)
        geotrace_copy_cstr(out->ip, sizeof(out->ip), fallback_ip_str);
    if (!json_get_string(body, "country", out->country, sizeof(out->country)))
        geotrace_copy_cstr(out->country, sizeof(out->country), "Unknown");
    json_get_string(body, "city", out->city, sizeof(out->city));
    return GEO_HTTP_OK;
}

/* public lookup API */

bool geo_lookup(struct geo_cache *c,
                uint32_t ip_be,
                int timeout_ms,
                geo_result *out)
{
    if (!c || !out)
        return false;
    if (!is_public_ipv4_be(ip_be)) {
        memset(out, 0, sizeof(*out));
        return false;
    }

    uint32_t key = ntohl(ip_be);

    /* Cache hit path */
    pthread_mutex_lock(&c->mtx);
    const cache_slot *s = find_slot(c->slots, c->capacity, key);
    if (s && s->state == SLOT_OCCUPIED) {
        *out = s->value;
        pthread_mutex_unlock(&c->mtx);
        return out->valid;
    }
    time_t quiet_until = c->quiet_until;
    pthread_mutex_unlock(&c->mtx);

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        now.tv_sec = 0;

    /* Cache missed and ip-api is still refusing us; skip the request instead of
     * spending the full timeout to be told 429 again.
     */
    if (now.tv_sec < quiet_until) {
        memset(out, 0, sizeof(*out));
        return false;
    }

    /* Live lookup */
    char ip_str[GEOTRACE_IP_LEN];
    struct in_addr addr = {.s_addr = ip_be};
    if (!inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str)))
        geotrace_copy_cstr(ip_str, sizeof(ip_str), "?");

    char path[128];
    snprintf(path, sizeof(path),
             "/json/%s?fields=status,country,city,lat,lon,query", ip_str);

    geo_http_result rc = http_lookup(path, out, timeout_ms, ip_str);
    if (rc < 0) {
        /* Not an answer about this IP, so nothing is cached. This has to come
         * before the cooldown decision: http_lookup returns transient without
         * touching out when it never opened a socket, so falling through to
         * the caching path below would store whatever the caller happened to
         * pass in as though the service had confirmed it.
         */
        memset(out, 0, sizeof(*out));

        /* Arm the cooldown only when a request was actually attempted. A
         * cache-only caller (timeout_ms == 0, which is what demo mode and the
         * tests use) is told transient without a socket ever being opened, and
         * a cooldown for that would report a service problem no one observed.
         */
        if (timeout_ms > 0) {
            /* Length matched to how long the condition usually lasts: a minute
             * for the rate-limit window, seconds for an unreachable service.
             * Timed from now rather than from the pre-request reading, since
             * the attempt itself can burn most of it.
             */
            time_t quiet = rc == GEO_HTTP_RATE_LIMITED ? GEO_RATE_LIMIT_QUIET_S
                                                       : GEO_TRANSIENT_QUIET_S;
            struct timespec after;
            if (clock_gettime(CLOCK_MONOTONIC, &after) != 0)
                after = now;

            pthread_mutex_lock(&c->mtx);
            c->quiet_until = after.tv_sec + quiet;
            pthread_mutex_unlock(&c->mtx);
        }
        return false;
    }

    /* Authoritative miss or success: both are worth caching. */
    pthread_mutex_lock(&c->mtx);
    cache_put_locked(c, key, out);
    pthread_mutex_unlock(&c->mtx);

    return out->valid;
}
