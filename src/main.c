#include "geotrace/atomic.h"
#include "geotrace/cli.h"
#include "geotrace/geo.h"
#include "geotrace/platform.h"
#include "geotrace/resolver.h"
#include "geotrace/ring.h"
#include "geotrace/source.h"
#include "geotrace/ui.h"
#include "geotrace/util.h"
#include "geotrace/world-map.h"

#include <arpa/inet.h>
#include <errno.h>
#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* global atomics for signal-safe communication */

static geotrace_flag g_stop_requested = GEOTRACE_FLAG_INIT;
static geotrace_flag g_resize_pending = GEOTRACE_FLAG_INIT;

#define PACKET_RING_SIZE 2048
#define CONNECTION_RING_SIZE 1024
#define STATUS_RING_SIZE 128
/* Bounds one ip-api attempt; 0 makes the resolver cache-only. */
#define GEO_TIMEOUT_MS 2500

/* signal handler */

static void on_terminate(int sig)
{
    (void) sig;
    geotrace_flag_raise(&g_stop_requested);

    /* No ring_shutdown here: it locks a mutex, which is not signal-safe. The UI
     * polls via non-blocking ring_try_take, and the resolver is woken by source
     * shutdown during the orderly teardown in quiesce_runtime.
     */
}

static void on_winch(int sig)
{
    (void) sig;
    geotrace_flag_raise(&g_resize_pending);
}

static void install_signals(void)
{
    struct sigaction sa = {0};

    /* Without SA_RESTART so blocked syscalls return EINTR and the loop
     * re-checks the stop flag.
     */
    sa.sa_handler = on_terminate;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    /* SIGWINCH must NOT interrupt syscalls — it's a UI-only signal, and letting
     * it surface as EINTR inside pcap_dispatch's poll() would tear down a
     * perfectly healthy capture thread on every terminal resize.
     */
    sa.sa_handler = on_winch;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGWINCH, &sa, NULL);
    sa.sa_flags = 0;

    /* SIGPIPE ignored — the network/pcap path may write to dead sockets. */
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    /* SIGABRT/SIGSEGV/SIGBUS are claimed by ui.c's install_fatal_handlers
     * instead: they exist only to undo raw mode, so they must not be armed
     * before the terminal is actually in raw mode.
     */
}

/* privilege drop */

static int drop_privileges(uid_t target_uid, gid_t target_gid)
{
    /* Dropping supplementary groups first prevents retained group privileges
     * after setgid/setuid.
     */
    if (setgroups(0, NULL) != 0) {
        fprintf(stderr, "geotrace: setgroups(0, NULL) failed: %s\n",
                strerror(errno));
        return -1;
    }
    if (setgid(target_gid) != 0) {
        fprintf(stderr, "geotrace: setgid(%lu) failed: %s\n",
                (unsigned long) target_gid, strerror(errno));
        return -1;
    }
    if (setuid(target_uid) != 0) {
        fprintf(stderr, "geotrace: setuid(%lu) failed: %s\n",
                (unsigned long) target_uid, strerror(errno));
        return -1;
    }
    /* Sanity: setuid(0) must now fail. */
    if (setuid(0) == 0) {
        fprintf(stderr,
                "geotrace: privilege drop sanity check failed — still root.\n");
        return -1;
    }
    if (errno != EPERM) {
        fprintf(stderr, "geotrace: setuid(0) returned unexpected errno=%d\n",
                errno);
        return -1;
    }
    return 0;
}

static bool resolve_target_user(const cli_options *opts,
                                uid_t *out_uid,
                                gid_t *out_gid)
{
    if (!opts->has_drop_uid || !opts->has_drop_gid)
        return false;
    if (opts->drop_uid == 0 || opts->drop_gid == 0) {
        fprintf(stderr, "geotrace: refusing to drop to UID/GID 0\n");
        return false;
    }
    /* Verify the UID/GID exist in the system database. */
    if (getpwuid(opts->drop_uid) == NULL) {
        fprintf(stderr, "geotrace: --drop-uid=%lu: no such user\n",
                (unsigned long) opts->drop_uid);
        return false;
    }
    if (getgrgid(opts->drop_gid) == NULL) {
        fprintf(stderr, "geotrace: --drop-gid=%lu: no such group\n",
                (unsigned long) opts->drop_gid);
        return false;
    }
    *out_uid = opts->drop_uid;
    *out_gid = opts->drop_gid;
    return true;
}

/* Gate between cli_ensure_capture_privileges and starting the pipeline: we must
 * be root to capture, but must not still be root when the UI runs.
 * Returns false after printing the reason. The policy, with the effective UID
 * passed in rather than read from the process. Splitting it this way is what
 * lets tests reach the root-only branch below: as a single function reading
 * geteuid(), the refusal that matters most here is unreachable from an
 * unprivileged test run, and a test that cannot reach it silently passes when
 * the branch is deleted.
 */
static bool capture_privileges_ok_for(const cli_options *opts, uid_t euid)
{
    if (opts->demo)
        return true;

    if (euid != 0) {
        fprintf(stderr,
                "geotrace: live capture needs root privileges. "
                "Pass --demo for synthetic traffic.\n");
        return false;
    }

    /* The approved entry point (cli_ensure_capture_privileges) always appends
     * --drop-uid/--drop-gid; if those are missing here the user invoked "sudo
     * geotrace" manually. SUDO_UID/SUDO_GID are intentionally not trusted:
     * environment values do not establish the identity to which privileges must
     * be dropped.
     */
    if (!opts->has_drop_uid || !opts->has_drop_gid) {
        fprintf(
            stderr,
            "geotrace: refusing to run the UI as root.\n"
            "         Run unprivileged and let geotrace re-exec via sudo,\n"
            "         or pass --drop-uid=<uid> --drop-gid=<gid> manually.\n");
        return false;
    }
    return true;
}

static bool capture_privileges_ok(const cli_options *opts)
{
    return capture_privileges_ok_for(opts, geteuid());
}

static void destroy_source(bool demo_mode, struct packet_source *source)
{
    if (!source)
        return;
    if (demo_mode)
        demo_source_destroy(source);
#if HAVE_PCAP
    else
        pcap_source_destroy(source);
#endif
}

static void cleanup_runtime(bool demo_mode,
                            struct packet_source *source,
                            struct geo_cache *cache,
                            struct ring *packet_ring,
                            struct ring *connection_ring,
                            struct ring *status_ring)
{
    destroy_source(demo_mode, source);
    geo_cache_destroy(cache);
    ring_destroy(packet_ring);
    ring_destroy(connection_ring);
    ring_destroy(status_ring);
    world_invalidate_cache();
}

/* Raise the global stop flag, drain the source, and shut down every ring so
 * blocked takers exit. Idempotent, and "source" may be NULL, so this is safe to
 * call from early-exit error paths (including one where the source never got
 * constructed) and from the regular teardown after ui_run returns.
 *
 * Main-thread only: ring_shutdown locks a mutex, so this is not async-signal-
 * safe. The signal handler (on_terminate) only sets g_stop_requested and lets
 * the UI poll on the next ring_try_take iteration.
 */
static void quiesce_runtime(struct packet_source *source,
                            struct ring *packet_ring,
                            struct ring *connection_ring,
                            struct ring *status_ring)
{
    geotrace_flag_raise(&g_stop_requested);
    if (source)
        source->stop(source);
    ring_shutdown(packet_ring);
    ring_shutdown(connection_ring);
    ring_shutdown(status_ring);
}

static bool append_csv_name(char *buf,
                            size_t cap,
                            size_t *offset,
                            const char *prefix,
                            const char *name)
{
    if (cap == 0 || *offset >= cap)
        return false;
    int written = snprintf(buf + *offset, cap - *offset, "%s%s", prefix, name);
    if (written < 0)
        return false;
    if ((size_t) written >= cap - *offset) {
        *offset = cap - 1;
        return false;
    }
    *offset += (size_t) written;
    return true;
}

/* demo presets */

typedef struct {
    const char *ip;
    double lat;
    double lon;
    const char *country;
    const char *city;
} demo_geo_entry;

static const demo_geo_entry DEMO_GEO[] = {
    {"1.1.1.1", -33.8688, 151.2093, "Australia", "Sydney"},
    {"8.8.8.8", 37.3861, -122.0839, "United States", "Mountain View"},
    {"9.9.9.9", 47.3769, 8.5417, "Switzerland", "Zurich"},
    {"208.67.222.222", 37.7749, -122.4194, "United States", "San Francisco"},
    {"151.101.1.69", 40.7128, -74.0060, "United States", "New York"},
    {"185.199.108.133", 52.5200, 13.4050, "Germany", "Berlin"},
};

static void prime_demo_cache(struct geo_cache *c)
{
    for (size_t i = 0; i < GEOTRACE_ARRAY_LEN(DEMO_GEO); i++) {
        const demo_geo_entry *e = &DEMO_GEO[i];
        geo_result r = {0};
        r.valid = true;
        r.point.lat = e->lat;
        r.point.lon = e->lon;
        geotrace_copy_cstr(r.ip, sizeof(r.ip), e->ip);
        geotrace_copy_cstr(r.country, sizeof(r.country), e->country);
        geotrace_copy_cstr(r.city, sizeof(r.city), e->city);
        geo_cache_put(c, inet_addr(e->ip), &r);
    }
}

/* main */

static void emit_status(struct ring *statuses,
                        status_level lvl,
                        const char *fmt,
                        ...)
{
    status_event s = {0};
    s.level = lvl;
    clock_gettime(CLOCK_MONOTONIC, &s.created_at);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(s.message, sizeof(s.message), fmt, ap);
    va_end(ap);
    ring_put_latest(statuses, &s);
}

static int run_list_interfaces(void)
{
    interface_info ifs[GEOTRACE_MAX_INTERFACES];
    size_t n = platform_list_ipv4_interfaces(ifs, GEOTRACE_MAX_INTERFACES);
    if (n == 0) {
        printf("No IPv4 interfaces detected.\n");
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        printf("%c %-14s %s\n", ifs[i].selected ? '*' : ' ', ifs[i].name,
               ifs[i].address);
    }
    return 0;
}

/* Render opts->interfaces as "a,b,c" into buf for the sudo re-exec, so the
 * privileged restart keeps the same auto-detected set. Callers decide whether
 * the set is worth forwarding; this only formats it.
 */
static void format_detected_interfaces(char *buf,
                                       size_t cap,
                                       const cli_options *opts)
{
    buf[0] = '\0';
    if (opts->interface_count == 0)
        return;
    size_t off = 0;
    for (size_t i = 0; i < opts->interface_count; i++) {
        if (!append_csv_name(buf, cap, &off, i ? "," : "", opts->interfaces[i]))
            break;
    }
}

/* Construct the packet source.
 *
 * Returns NULL and writes a human-readable error to *err on failure.
 */
static struct packet_source *make_packet_source(const cli_options *opts,
                                                const char **err)
{
    if (opts->demo) {
        struct packet_source *s = demo_source_create(0.75);
        if (!s)
            *err = "geotrace: failed to create packet source\n";
        return s;
    }
#if HAVE_PCAP
    if (opts->interface_count == 0) {
        *err = "geotrace: no capture interfaces detected; pass -i.\n";
        return NULL;
    }

    /* C11 wart: char(*)[N] doesn't implicitly convert to const char(*)[N] (GCC
     * -Wpedantic catches it; C23 lifts the rule). Cast keeps the const-correct
     * API intact.
     */
    struct packet_source *s = pcap_source_create(
        (const char (*)[GEOTRACE_IFACE_LEN]) opts->interfaces,
        opts->interface_count);
    if (!s)
        *err = "geotrace: failed to create packet source\n";
    return s;
#else
    *err = "geotrace: built without libpcap; only --demo is supported.\n";
    return NULL;
#endif
}

/* Build "Listening on a,b,c" (or "Listening on -" when the source returned no
 * names) into buf, and push it through emit_status.
 */
static void emit_listening_banner(struct ring *statuses,
                                  struct packet_source *source)
{
    char line[256];
    size_t n = source->interface_count(source);
    const char *const *names = source->interfaces(source);

    geotrace_copy_cstr(line, sizeof(line),
                       n ? "Listening on" : "Listening on -");
    size_t off = strlen(line);

    for (size_t i = 0; i < n && names[i]; i++) {
        if (!append_csv_name(line, sizeof(line), &off, i ? "," : " ", names[i]))
            break;
    }
    emit_status(statuses, GEOTRACE_STATUS_INFO, "%s", line);
}

/* Modes that print something and leave.
 *
 * Returns true when the process is done, with the exit status in "code"; false
 * means carry on into the capture run.
 */
static bool handle_early_exit(char **argv,
                              const cli_options *opts,
                              cli_status st,
                              int *code)
{
    if (st == CLI_BAD_USAGE) {
        cli_print_help(stderr, argv[0]);
        *code = 2;
        return true;
    }
    if (st == CLI_EXIT_SUCCESS) {
        if (opts->show_help)
            cli_print_help(stdout, argv[0]);
        if (opts->show_version)
            cli_print_version(stdout);
        *code = 0;
        return true;
    }
    if (opts->list_interfaces) {
        *code = run_list_interfaces();
        return true;
    }
    return false;
}

/* Select interfaces, re-exec through sudo if that is how privileges are
 * obtained, and confirm the result is safe to run the UI under.
 *
 * Returns false when the caller should exit non-zero.
 *
 * The ordering here is load-bearing, which is the reason it is one function
 * rather than inline steps: whether the user chose interfaces has to be latched
 * *before* detection overwrites interface_count, because only an auto-detected
 * set needs forwarding across the re-exec. A user-supplied -i is already in the
 * argv handed to execv, and forwarding it twice would let the later occurrence
 * win in getopt.
 */
static bool prepare_capture(int argc, char **argv, cli_options *opts)
{
    const bool user_chose_interfaces = opts->interface_count > 0;
    if (!user_chose_interfaces && !opts->demo) {
        opts->interface_count = platform_detect_interfaces(
            opts->interfaces, GEOTRACE_MAX_INTERFACES);
    }

    char detected_csv[GEOTRACE_MAX_INTERFACES * (GEOTRACE_IFACE_LEN + 1)];
    detected_csv[0] = '\0';
    if (!user_chose_interfaces && !opts->demo)
        format_detected_interfaces(detected_csv, sizeof(detected_csv), opts);

    cli_ensure_capture_privileges(argc, argv, opts, detected_csv);
    /* Execution continues only for root capture, --demo, or --no-auto-sudo. */

    return capture_privileges_ok(opts);
}

int main(int argc, char **argv)
{
    cli_options opts = {0};
    cli_status st = cli_parse(argc, argv, &opts);

    int code = 0;
    if (handle_early_exit(argv, &opts, st, &code))
        return code;

    if (!prepare_capture(argc, argv, &opts))
        return 1;

    install_signals();
    ui_check_terminal();
    world_map_init();

    /* Construct rings. */
    struct ring *packet_ring =
        ring_create(PACKET_RING_SIZE, sizeof(packet_event));
    struct ring *connection_ring =
        ring_create(CONNECTION_RING_SIZE, sizeof(connection_event));
    struct ring *status_ring =
        ring_create(STATUS_RING_SIZE, sizeof(status_event));

    /* Geo */
    struct geo_cache *cache = geo_cache_create(64);
    if (opts.demo)
        prime_demo_cache(cache);

    /* Home is pinned to Taipei. The earlier ip-api.com self-lookup was
     * unreliable in practice — corporate VPNs, NAT egresses, and cloud-routed
     * traffic make the requesting IP geolocate to wherever the egress lives,
     * not where the user is. The project owner is in Taiwan, so the canvas
     * always centers there.
     */
    geo_point home = {25.0330, 121.5654};

    /* Re-center the map on the host so the home marker sits at x = w/2. */
    world_set_center_lon(home.lon);

    /* Source */
    const char *create_error = NULL;
    struct packet_source *source = make_packet_source(&opts, &create_error);
    if (create_error) {
        fputs(create_error, stderr);
        cleanup_runtime(opts.demo, source, cache, packet_ring, connection_ring,
                        status_ring);
        return 1;
    }
    /* Listening banner — orchestrator owns this, sources don't touch status. */
    emit_listening_banner(status_ring, source);

    /* Start source. */
    if (source->start(source, packet_ring, status_ring, &g_stop_requested) !=
        0) {
        emit_status(status_ring, GEOTRACE_STATUS_ERROR,
                    "Source failed to start; UI will run with no data.");
    }

    /* Drop privileges. capture_privileges_ok already established that a
     * non-demo run is root with both drop IDs present.
     */
    if (!opts.demo) {
        uid_t tu;
        gid_t tg;
        if (!resolve_target_user(&opts, &tu, &tg) ||
            drop_privileges(tu, tg) != 0) {
            quiesce_runtime(source, packet_ring, connection_ring, status_ring);
            cleanup_runtime(opts.demo, source, cache, packet_ring,
                            connection_ring, status_ring);
            return 1;
        }
        emit_status(status_ring, GEOTRACE_STATUS_INFO,
                    "Dropped to uid=%lu gid=%lu", (unsigned long) tu,
                    (unsigned long) tg);
    }

    /* Resolver thread. */
    resolver_ctx rctx = {
        .packets_in = packet_ring,
        .connections_out = connection_ring,
        .statuses_out = status_ring,
        .cache = cache,
        .geo_timeout_ms = opts.demo ? 0 : GEO_TIMEOUT_MS,
        .stop = &g_stop_requested,
    };
    pthread_t resolver_tid;
    bool resolver_started = false;
    int prc = pthread_create(&resolver_tid, NULL, resolver_main, &rctx);
    if (prc != 0) {
        emit_status(status_ring, GEOTRACE_STATUS_ERROR,
                    "Resolver thread failed to start (pthread_create=%d); "
                    "geo lookups disabled.",
                    prc);
    } else {
        resolver_started = true;
    }

    /* UI on the main thread. */
    ui_options uopts = {
        .connections = connection_ring,
        .statuses = status_ring,
        .theme = opts.theme,
        .home = home,
        .fps = opts.fps,
    };
    struct ui_context *ui = ui_create(&uopts);
    ui_run(ui, &g_stop_requested, &g_resize_pending);

    /* Shutdown sequence. */
    quiesce_runtime(source, packet_ring, connection_ring, status_ring);
    if (resolver_started)
        pthread_join(resolver_tid, NULL);

    ui_destroy(ui);
    cleanup_runtime(opts.demo, source, cache, packet_ring, connection_ring,
                    status_ring);
    return 0;
}
