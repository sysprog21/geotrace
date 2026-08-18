/*
 * test-parsers — the input parsers that had no coverage.
 *
 * json_get_string and parse_status_code read bytes that arrive over plaintext
 * HTTP from ip-api.com, so they are the only parsers in the tree handling data
 * an on-path attacker controls. Both are "static", so this test includes the
 * translation units directly rather than widening the public API for testing.
 *
 * The platform row parsers are also static and #ifdef'd per platform; whichever
 * pair is compiled here gets exercised.
 */

#include "geo.c"
#include "platform.c"

#include "geotrace/cli.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* json_get_string */

static void expect_json(const char *json, const char *key, const char *want)
{
    char out[64];
    bool ok = json_get_string(json, key, out, sizeof(out));
    if (!ok || strcmp(out, want) != 0) {
        fprintf(stderr, "FAIL json_get_string(%s, %s): ok=%d got \"%s\"\n",
                json, key, (int) ok, ok ? out : "");
        exit(1);
    }
}

static void expect_json_fail(const char *json, const char *key)
{
    char out[64];
    if (json_get_string(json, key, out, sizeof(out))) {
        fprintf(stderr, "FAIL json_get_string(%s, %s): expected failure\n",
                json, key);
        exit(1);
    }
}

static void test_json_get_string(void)
{
    expect_json("{\"country\":\"Taiwan\"}", "country", "Taiwan");
    expect_json("{\"a\":1,\"city\":\"Taipei\",\"b\":2}", "city", "Taipei");
    expect_json("{\"c\": \"spaced\"}", "c", "spaced");
    expect_json("{\"c\":\"\"}", "c", "");

    /* Simple escapes are copied through; \\n and \\t decode and then fold. */
    expect_json("{\"c\":\"a\\\"b\"}", "c", "a\"b");
    expect_json("{\"c\":\"a\\\\b\"}", "c", "a\\b");
    expect_json("{\"c\":\"a\\/b\"}", "c", "a/b");
    expect_json("{\"c\":\"a\\nb\"}", "c", "a b");
    expect_json("{\"c\":\"a\\tb\"}", "c", "a b");

    /* \\uXXXX collapses to one space. */
    expect_json("{\"c\":\"a\\u00e9b\"}", "c", "a b");

    /* Regression: a truncated \\u used to let the scanner walk past the closing
     * quote into the next value.
     */
    expect_json_fail("{\"c\":\"a\\u12\"}", "c");
    expect_json_fail("{\"c\":\"a\\u\"}", "c");
    expect_json_fail("{\"c\":\"a\\uZZZZ\"}", "c");

    /* Control bytes from the wire must not reach the terminal verbatim. */
    expect_json("{\"c\":\"a\x1b[31mb\"}", "c", "a [31mb");
    expect_json(
        "{\"c\":\"a\x07\x7f"
        "b\"}",
        "c", "a  b");

    /* Bytes >= 0x80 pass through so non-ASCII place names survive. */
    expect_json("{\"c\":\"caf\xc3\xa9\"}", "c", "caf\xc3\xa9");

    expect_json_fail("{\"c\":\"unterminated}", "c");
    expect_json_fail("{\"c\":123}", "c");
    expect_json_fail("{\"c\":\"x\"}", "missing");

    /* Truncation to cap, still NUL-terminated. */
    char small[4];
    assert(json_get_string("{\"c\":\"abcdef\"}", "c", small, sizeof(small)));
    assert(strcmp(small, "abc") == 0);

    /* cap == 0 reaches the copy loop and must not write through out at all. (A
     * non-string value would bail at the type check before getting here.)
     */
    assert(json_get_string("{\"c\":\"abc\"}", "c", NULL, 0));
}

/* parse_status_code */

static void expect_status(const char *line, int want)
{
    int got = parse_status_code(line);
    if (got != want) {
        fprintf(stderr, "FAIL parse_status_code(\"%s\") = %d, want %d\n", line,
                got, want);
        exit(1);
    }
}

static void test_parse_status_code(void)
{
    expect_status("HTTP/1.1 200 OK\r\n\r\n", 200);
    expect_status("HTTP/1.0 404 Not Found\r\n", 404);
    expect_status("HTTP/1.1 429 Too Many Requests\r\n", 429);
    expect_status("HTTP/1.1 500 Internal Server Error\r\n", 500);
    expect_status("HTTP/1.1 999 x", 999);

    /* Short inputs must be rejected before any index into the code field. */
    expect_status("", -1);
    expect_status("HTTP/1.", -1);
    expect_status("HTTP/1.1", -1);
    expect_status("HTTP/1.1 20", -1);

    /* Malformed status lines must not yield an arbitrary integer. */
    expect_status("HTTP/2.0 200 OK", -1);
    expect_status("HTTP/1.X 200 OK", -1);
    expect_status("HTTP/1.1x200 OK", -1);
    expect_status("HTTP/1.1 2O0 OK", -1);
    expect_status("HTTP/1.1 -12 OK", -1);
}

/* classify_status */

static void expect_class(int status, geo_http_result want, bool want_sentinel)
{
    /* Poison the result so an authoritative miss has to zero it itself. */
    geo_result r;
    memset(&r, 0xAA, sizeof(r));

    geo_http_result got = classify_status(status, &r);
    if (got != want) {
        fprintf(stderr, "FAIL classify_status(%d) = %d, want %d\n", status,
                (int) got, (int) want);
        exit(1);
    }
    geo_result zeroed;
    memset(&zeroed, 0, sizeof(zeroed));
    if (want_sentinel && memcmp(&r, &zeroed, sizeof(r)) != 0) {
        /* Compare every byte, not just the fields a caller happens to read:
         * stale coordinates left behind by a partial reset would be cached as
         * an authoritative miss.
         */
        fprintf(stderr, "FAIL classify_status(%d): result not zeroed\n",
                status);
        exit(1);
    }
}

static void test_classify_status(void)
{
    /* 200 means "keep parsing"; the body decides. */
    expect_class(200, GEO_HTTP_OK, false);

    /* 429 is the one status that arms the cooldown. */
    expect_class(429, GEO_HTTP_RATE_LIMITED, false);

    /* 4xx is authoritative: retrying the same IP cannot help, so it caches as
     * the zeroed sentinel.
     */
    expect_class(400, GEO_HTTP_MISS, true);
    expect_class(404, GEO_HTTP_MISS, true);
    expect_class(418, GEO_HTTP_MISS, true);

    /* 5xx and anything unclassifiable are retried later, never cached. */
    expect_class(500, GEO_HTTP_TRANSIENT, false);
    expect_class(503, GEO_HTTP_TRANSIENT, false);
    expect_class(301, GEO_HTTP_TRANSIENT, false);
    expect_class(100, GEO_HTTP_TRANSIENT, false);
    expect_class(-1, GEO_HTTP_TRANSIENT, false); /* parse_status_code failed */
}

/* cli_normalize_interfaces */

static void test_normalize_interfaces(void)
{
    char out[GEOTRACE_MAX_INTERFACES][GEOTRACE_IFACE_LEN];

    assert(cli_normalize_interfaces("en0,en1", out, GEOTRACE_MAX_INTERFACES) ==
           2);
    assert(strcmp(out[0], "en0") == 0 && strcmp(out[1], "en1") == 0);

    /* Trims, drops empties, loopback, and duplicates; honours both separators.
     */
    assert(cli_normalize_interfaces("  en0 , ;lo0,en0;  ,tun5 ", out,
                                    GEOTRACE_MAX_INTERFACES) == 2);
    assert(strcmp(out[0], "en0") == 0 && strcmp(out[1], "tun5") == 0);

    assert(cli_normalize_interfaces("lo", out, GEOTRACE_MAX_INTERFACES) == 0);
    assert(cli_normalize_interfaces("lo0", out, GEOTRACE_MAX_INTERFACES) == 0);
    assert(cli_normalize_interfaces("", out, GEOTRACE_MAX_INTERFACES) == 0);
    assert(cli_normalize_interfaces(",,;;", out, GEOTRACE_MAX_INTERFACES) == 0);
    assert(cli_normalize_interfaces(NULL, out, GEOTRACE_MAX_INTERFACES) == 0);
    assert(cli_normalize_interfaces("en0", out, 0) == 0);

    /* max is respected. */
    assert(cli_normalize_interfaces("a,b,c", out, 2) == 2);

    /* Over-long names truncate rather than overflow. */
    assert(cli_normalize_interfaces("averyveryverylongifname", out,
                                    GEOTRACE_MAX_INTERFACES) == 1);
    assert(strlen(out[0]) == GEOTRACE_IFACE_LEN - 1);
}

/* platform row parsers */

static void test_row_parsers(void)
{
    char buf[GEOTRACE_IFACE_LEN];

#if defined(__linux__)
    char addr[GEOTRACE_IP_LEN];
    assert(pick_after_dev("8.8.8.8 via 10.0.0.1 dev eth0 src 10.0.0.5", buf));
    assert(strcmp(buf, "eth0") == 0);
    assert(pick_after_dev("default dev wlan0 scope link", buf));
    assert(strcmp(buf, "wlan0") == 0);
    assert(!pick_after_dev("no device here", buf));

    assert(pick_ip_brief_line("eth0    UP    192.168.1.42/24", buf, addr));
    assert(strcmp(buf, "eth0") == 0 && strcmp(addr, "192.168.1.42") == 0);
    /* Real "ip -brief -4 addr" rows can carry trailing fields. */
    assert(
        pick_ip_brief_line("eth0  UP  192.168.5.15/24 metric 200", buf, addr));
    assert(strcmp(addr, "192.168.5.15") == 0);
    /* No /mask is still accepted. */
    assert(pick_ip_brief_line("\twlan0 UP 10.0.0.7", buf, addr));
    assert(strcmp(addr, "10.0.0.7") == 0);
    assert(!pick_ip_brief_line("eth1 DOWN", buf, addr));
    assert(!pick_ip_brief_line("", buf, addr));
    assert(!pick_ip_brief_line("   \t ", buf, addr));
#elif defined(__APPLE__)
    assert(pick_macos_interface_label("   interface: en0", buf));
    assert(strcmp(buf, "en0") == 0);
    assert(!pick_macos_interface_label("  gateway: 192.168.0.1", buf));

    assert(pick_netstat_default("default  192.168.0.1  UGScg  en0", buf));
    assert(strcmp(buf, "en0") == 0);
    /* Fewer than four fields, and non-default rows, must not match. */
    assert(!pick_netstat_default("default 192.168.0.1 UGScg", buf));
    assert(!pick_netstat_default("1.2.3.4/32 link#5 UCS en0", buf));
    assert(!pick_netstat_default("", buf));
#endif
}

/* recv_response budget */

/* The window between the two is the whole test: a reader that honours the
 * budget returns at ~BUDGET, one that does not returns when the peer closes at
 * CLOSE. The bound below sits between them with an order of magnitude of slack
 * on each side, so a loaded runner cannot turn either case into the other.
 */
#define TRICKLE_BUDGET_MS 50
#define TRICKLE_CLOSE_MS 1000
#define TRICKLE_MAX_WAIT_MS (TRICKLE_CLOSE_MS / 2)

/* Send one byte, then hold the connection open well past the reader's budget.
 * The hold is what makes the test meaningful: if the reader closes at
 * TRICKLE_CLOSE_MS instead, a reader with no budget at all still returns one
 * byte, just later, and the byte count alone cannot tell the two apart.
 */
static void *trickle_writer(void *arg)
{
    int fd = *(int *) arg;
    char byte = 'x';
    assert(send(fd, &byte, 1, 0) == 1);
    /* Split the sleep: at 1000 ms the whole value lands on tv_nsec as 1e9,
     * which nanosleep rejects with EINVAL, and the writer would then close
     * immediately and hand the reader the EOF this test exists to withhold.
     */
    struct timespec delay = {
        .tv_sec = TRICKLE_CLOSE_MS / 1000,
        .tv_nsec = (TRICKLE_CLOSE_MS % 1000) * 1000000L,
    };
    nanosleep(&delay, NULL);
    close(fd);
    return NULL;
}

/* Send a whole "response" and close, which is what ip-api does for a request
 * carrying "Connection: close".
 */
static void *complete_writer(void *arg)
{
    int fd = *(int *) arg;
    assert(send(fd, "hello", 5, 0) == 5);
    close(fd);
    return NULL;
}

static void test_recv_response_timeout(void)
{
    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    pthread_t tid;
    assert(pthread_create(&tid, NULL, trickle_writer, &fds[1]) == 0);

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    char buf[16];
    ssize_t n = recv_response(fds[0], buf, sizeof(buf), TRICKLE_BUDGET_MS);
    long elapsed_ms = (long) (geotrace_elapsed_ns_now(start) / 1000000);

    /* A prefix is a failure, not a short read: the caller must not parse a
     * response the peer never finished sending.
     */
    assert(n == -1);
    if (elapsed_ms < TRICKLE_BUDGET_MS / 2 ||
        elapsed_ms > TRICKLE_MAX_WAIT_MS) {
        fprintf(stderr,
                "FAIL recv_response returned after %ld ms, want ~%d "
                "(budget) and at most %d (well before the %d peer close)\n",
                elapsed_ms, TRICKLE_BUDGET_MS, TRICKLE_MAX_WAIT_MS,
                TRICKLE_CLOSE_MS);
        exit(1);
    }

    close(fds[0]);
    assert(pthread_join(tid, NULL) == 0);
}

static void test_recv_response_complete(void)
{
    int fds[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    pthread_t tid;
    assert(pthread_create(&tid, NULL, complete_writer, &fds[1]) == 0);

    char buf[16];
    ssize_t n = recv_response(fds[0], buf, sizeof(buf), 2000);
    assert(n == 5);
    assert(strcmp(buf, "hello") == 0);

    close(fds[0]);
    assert(pthread_join(tid, NULL) == 0);
}

/* A lookup that never reached the network must leave the cache alone. This
 * test lives here rather than in test-resolver.c because the count is private
 * to geo.c, and counting is the only way to see the difference: a wrongly
 * cached transient looks exactly like an authoritative miss from outside.
 */
static void test_cache_only_miss_is_not_cached(void)
{
    struct geo_cache *c = geo_cache_create(16);
    geo_result r;
    memset(&r, 0xAA, sizeof(r)); /* a caller that did not zero its result */

    /* timeout_ms == 0: http_lookup returns transient without a socket. */
    assert(!geo_lookup(c, htonl(0x08080808u), 0, &r));
    assert(!r.valid);
    if (c->count != 0) {
        fprintf(stderr, "FAIL cache-only miss stored %zu entries\n", c->count);
        exit(1);
    }

    geo_cache_destroy(c);
}

int main(void)
{
    test_json_get_string();
    test_parse_status_code();
    test_classify_status();
    test_normalize_interfaces();
    test_row_parsers();
    test_recv_response_timeout();
    test_recv_response_complete();
    test_cache_only_miss_is_not_cached();
    fprintf(stderr, "parser tests passed\n");
    return 0;
}
