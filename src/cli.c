#include "geotrace/cli.h"

#include "geotrace/oom.h"
#include "geotrace/util.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef GEOTRACE_VERSION
#define GEOTRACE_VERSION "unknown"
#endif

/* name/id/argument mode live together so getopt IDs cannot drift from the
 * static long-option table.
 */
#define CLI_LONG_OPTIONS(X)                                \
    X(OPT_DEMO, "demo", no_argument)                       \
    X(OPT_LIST_INTERFACES, "list-interfaces", no_argument) \
    X(OPT_NO_AUTO_SUDO, "no-auto-sudo", no_argument)       \
    X(OPT_FPS, "fps", required_argument)                   \
    X(OPT_DROP_UID, "drop-uid", required_argument)         \
    X(OPT_DROP_GID, "drop-gid", required_argument)         \
    X(OPT_HELP, "help", no_argument)                       \
    X(OPT_VERSION, "version", no_argument)

#define CLI_ALL_LONG_OPTIONS(X) \
    CLI_LONG_OPTIONS(X)         \
    X('i', "interface", required_argument)

/* Long-option ids start above every supported single-character short flag. */
/* clang-format off */
#define CLI_OPTION_ENUM(id, name, has_arg) id,
enum {
    OPT_LONG_BASE = 999,
    CLI_LONG_OPTIONS(CLI_OPTION_ENUM)
    OPT_THEME_BASE, /* sentinel; per-theme entries get OPT_THEME_BASE + index */
};
#undef CLI_OPTION_ENUM
/* clang-format on */

/* helpers */

static bool parse_uint_decimal(const char *s, unsigned long *out)
{
    if (!s || !*s)
        return false;

    /* Strict base-10 parsing, no leading whitespace, no sign, no trailing junk.
     */
    for (const char *p = s; *p; p++) {
        if (!isdigit((unsigned char) *p))
            return false;
    }
    errno = 0;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (errno == ERANGE || !end || *end != '\0')
        return false;
    *out = v;
    return true;
}

/* Parse a positive integer in [1, maxv].
 *
 * Returns true on success. On failure prints "geotrace: <flag> must be
 * 1..<maxv>, got <s>" to stderr.
 */
static bool parse_uid_gid(const char *s,
                          unsigned long maxv,
                          const char *flag,
                          unsigned long *out)
{
    if (parse_uint_decimal(s, out) && *out > 0 && *out <= maxv)
        return true;
    fprintf(stderr, "geotrace: %s must be 1..%lu, got %s\n", flag, maxv, s);
    return false;
}

/* Trim ASCII whitespace from both ends in place.
 *
 * Returns the new pointer (may be past the original start) so the caller can
 * read the trimmed string.
 */
static char *trim_inplace(char *s, size_t *len_inout)
{
    size_t len = *len_inout;
    while (len > 0 && isspace((unsigned char) s[len - 1]))
        len--;
    s[len] = '\0';
    size_t start = 0;
    while (start < len && isspace((unsigned char) s[start]))
        start++;
    *len_inout = len - start;
    return s + start;
}

size_t cli_normalize_interfaces(const char *raw,
                                char out[][GEOTRACE_IFACE_LEN],
                                size_t max)
{
    if (!raw || max == 0)
        return 0;

    size_t count = 0;
    char token[GEOTRACE_IFACE_LEN];
    size_t tlen = 0;

    for (const char *p = raw;; p++) {
        char c = *p;
        if (c != ',' && c != ';' && c != '\0') {
            if (tlen + 1 < GEOTRACE_IFACE_LEN)
                token[tlen++] = c;
            continue;
        }

        /* trim_inplace NUL-terminates in place; the gate drops empties,
         * loopback, and duplicates.
         */
        platform_iface_append(out, &count, max, trim_inplace(token, &tlen));
        tlen = 0;
        if (c == '\0' || count >= max)
            break;
    }

    return count;
}

/* help / version */

void cli_print_version(FILE *fp)
{
    fprintf(fp, "geotrace %s\n", GEOTRACE_VERSION);
}

void cli_print_help(FILE *fp, const char *progname)
{
    fprintf(
        fp,
        "Usage: %s [options]\n"
        "\n"
        "Live terminal map for outgoing IPv4 traffic.\n"
        "\n"
        "Capture options:\n"
        "  -i, --interface=NAME[,NAME]  Interface(s) to sniff "
        "(comma/semicolon).\n"
        "      --demo                   Use synthetic events (no libpcap, no "
        "root).\n"
        "      --list-interfaces        Print detected IPv4 interfaces and "
        "exit.\n"
        "      --no-auto-sudo           Do not re-exec via sudo when root is "
        "needed.\n"
        "      --fps=N                  TUI refresh rate (1..60, default 12).\n"
        "\n"
        "Themes (mutually exclusive):\n",
        progname);

    for (size_t i = 0; i < GEOTRACE_THEME_COUNT; i++) {
        if (GEOTRACE_THEMES[i].cli_flag)
            fprintf(fp, "      --%-22s Use the %s theme.\n",
                    GEOTRACE_THEMES[i].cli_flag, GEOTRACE_THEMES[i].name);
    }

    fprintf(fp,
            "\n"
            "Privilege drop (set internally by sudo re-exec; do not use "
            "manually):\n"
            "      --drop-uid=N             Drop to UID after pcap setup.\n"
            "      --drop-gid=N             Drop to GID after pcap setup.\n"
            "\n"
            "Other:\n"
            "      --version                Print version and exit.\n"
            "  -h, --help                   Print this help and exit.\n");
}

/* option table construction */

/* Build a long_options array from the static fields plus per-theme entries. The
 * allocation includes the NULL terminator required by getopt_long.
 *
 * Caller must free the returned pointer.
 *
 * Static (non-theme) long-option entries. Per-theme entries are appended at
 * runtime since the theme table is the single source of truth for them.
 */
/* clang-format off */
#define CLI_OPTION_ENTRY(id, name, has_arg) {name, has_arg, NULL, id},
static const struct option STATIC_LONG_OPTS[] = {
    CLI_ALL_LONG_OPTIONS(CLI_OPTION_ENTRY)
};
#undef CLI_OPTION_ENTRY
/* clang-format on */

static struct option *build_long_options(void)
{
    const size_t n_static = GEOTRACE_ARRAY_LEN(STATIC_LONG_OPTS);
    size_t n_extra = 0;
    for (size_t i = 0; i < GEOTRACE_THEME_COUNT; i++) {
        if (GEOTRACE_THEMES[i].cli_flag)
            n_extra++;
    }

    /* +1 for the {NULL,0,NULL,0} terminator getopt_long requires. */
    size_t total = n_static + n_extra + 1;
    struct option *opts = (struct option *) xcalloc(total, sizeof(*opts));

    memcpy(opts, STATIC_LONG_OPTS, sizeof(STATIC_LONG_OPTS));
    size_t idx = n_static;

    for (size_t i = 0; i < GEOTRACE_THEME_COUNT; i++) {
        if (!GEOTRACE_THEMES[i].cli_flag)
            continue;
        opts[idx++] = (struct option) {GEOTRACE_THEMES[i].cli_flag, no_argument,
                                       NULL, (int) (OPT_THEME_BASE + i + 1)};
    }

    opts[idx] = (struct option) {NULL, 0, NULL, 0};
    return opts;
}

/* main parser */

cli_status cli_parse(int argc, char **argv, cli_options *out)
{
    memset(out, 0, sizeof(*out));
    out->theme = theme_default();
    out->fps = 12;

    struct option *long_opts = build_long_options();
    int theme_seen = 0;
    int opt;
    int option_index;
    cli_status rc = CLI_OK;

    /* Reset getopt state — important when called more than once (tests). */
    optind = 1;
#ifdef __APPLE__
    optreset = 1;
#endif

    while ((opt = getopt_long(argc, argv, "i:h", long_opts, &option_index)) !=
           -1) {
        switch (opt) {
        case 'h':
        case OPT_HELP:
            out->show_help = true;
            rc = CLI_EXIT_SUCCESS;
            goto done;
        case OPT_VERSION:
            out->show_version = true;
            rc = CLI_EXIT_SUCCESS;
            goto done;
        case OPT_DEMO:
            out->demo = true;
            break;
        case OPT_LIST_INTERFACES:
            out->list_interfaces = true;
            break;
        case OPT_NO_AUTO_SUDO:
            out->no_auto_sudo = true;
            break;
        case OPT_FPS: {
            unsigned long v;
            if (!parse_uint_decimal(optarg, &v) || v == 0 || v > 60) {
                fprintf(stderr, "geotrace: --fps must be 1..60, got %s\n",
                        optarg);
                rc = CLI_BAD_USAGE;
                goto done;
            }
            out->fps = (int) v;
            break;
        }
        case OPT_DROP_UID: {
            /* (uid_t)-1 is the platform-specific upper bound for uid_t. The
             * unsigned-to-unsigned cast keeps -Wsign-conversion quiet.
             */
            unsigned long v;
            if (!parse_uid_gid(optarg, (unsigned long) (uid_t) -1, "--drop-uid",
                               &v)) {
                rc = CLI_BAD_USAGE;
                goto done;
            }
            out->has_drop_uid = true;
            out->drop_uid = (uid_t) v;
            break;
        }
        case OPT_DROP_GID: {
            unsigned long v;
            if (!parse_uid_gid(optarg, (unsigned long) (gid_t) -1, "--drop-gid",
                               &v)) {
                rc = CLI_BAD_USAGE;
                goto done;
            }
            out->has_drop_gid = true;
            out->drop_gid = (gid_t) v;
            break;
        }
        case 'i':
            out->interface_count = cli_normalize_interfaces(
                optarg, out->interfaces, GEOTRACE_MAX_INTERFACES);
            if (out->interface_count == 0) {
                fprintf(stderr,
                        "geotrace: --interface produced no usable names\n");
                rc = CLI_BAD_USAGE;
                goto done;
            }
            break;
        default:
            if (opt >= OPT_THEME_BASE) {
                size_t idx = (size_t) (opt - OPT_THEME_BASE - 1);
                if (idx >= GEOTRACE_THEME_COUNT) {
                    fprintf(
                        stderr,
                        "geotrace: internal: theme index %zu out of range\n",
                        idx);
                    rc = CLI_BAD_USAGE;
                    goto done;
                }
                if (theme_seen) {
                    fprintf(stderr,
                            "geotrace: theme flags are mutually exclusive\n");
                    rc = CLI_BAD_USAGE;
                    goto done;
                }
                out->theme = &GEOTRACE_THEMES[idx];
                theme_seen = 1;
                break;
            }
            /* getopt_long already printed a diagnostic for '?'. */
            rc = CLI_BAD_USAGE;
            goto done;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "geotrace: unexpected positional argument: %s\n",
                argv[optind]);
        rc = CLI_BAD_USAGE;
    }

done:
    free(long_opts);
    return rc;
}

/* ensure_capture_privileges */

/* Candidate sudo locations, ordered by likelihood. Tried in turn via execv —
 * relying on errno==ENOENT to fall through avoids the access(X_OK) → execv
 * TOCTOU window where sudo could be removed between the check and the call.
 */
static const char *const SUDO_CANDIDATES[] = {
    "/usr/bin/sudo",
    "/usr/local/bin/sudo",
    "/opt/homebrew/bin/sudo",
    "/bin/sudo",
    NULL,
};

/* True when the caller supplied a privilege-drop flag of their own, in either
 * spelling ("--drop-uid=N" or "--drop-uid N").
 *
 * These decide who the UI runs as, so the value has to be the one this process
 * computed from getuid(). Refusing a caller-supplied one is what makes that
 * unconditional. Ordering cannot: placing the generated flags last so getopt's
 * last-occurrence rule favours them means appending them after anything the
 * caller wrote, including an argument that is not an option at all.
 */
static bool has_caller_drop_flag(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--drop-uid", 10) == 0 ||
            strncmp(argv[i], "--drop-gid", 10) == 0)
            return true;
    }
    return false;
}

/* Fill new_argv with the re-exec command line:
 *
 *   [placeholder for the sudo path, self,
 *    drop_uid, drop_gid, (optional) iface_arg,
 *    original argv[1..argc-1], NULL]
 *
 * The caller sizes new_argv; reexec_argv_capacity() gives the bound.
 *
 * Everything generated goes before the forwarded argv and nothing is filtered
 * out of it. The caller's words keep their meaning that way: a trailing "--"
 * still terminates options with nothing after it, and a "--" that getopt hands
 * to "-i" as its argument stays attached to it. Dropping "--" instead would
 * turn "-i --" into "-i --drop-uid=1000", handing the flag to the option as a
 * value.
 */
static void build_reexec_argv(char **new_argv,
                              int argc,
                              char **argv,
                              char *self,
                              char *iface_arg,
                              char *drop_uid,
                              char *drop_gid)
{
    size_t idx = 0;
    new_argv[idx++] = NULL; /* placeholder for the sudo path */
    new_argv[idx++] = self;
    new_argv[idx++] = drop_uid;
    new_argv[idx++] = drop_gid;
    if (iface_arg)
        new_argv[idx++] = iface_arg;
    for (int i = 1; i < argc; i++)
        new_argv[idx++] = argv[i];
    new_argv[idx] = NULL;
}

/* Slots build_reexec_argv can use, including the NULL terminator. */
static size_t reexec_argv_capacity(int argc, bool forward_interfaces)
{
    /* sudo + self + drop-uid + drop-gid + NULL */
    size_t extras = 5;
    if (forward_interfaces)
        extras++;
    return extras + (size_t) (argc > 0 ? argc - 1 : 0);
}

void cli_ensure_capture_privileges(int argc,
                                   char **argv,
                                   const cli_options *opts,
                                   const char *extra_interfaces)
{
    if (opts->demo || opts->no_auto_sudo)
        return;
    if (geteuid() == 0)
        return;

    char self[PATH_MAX];
    if (platform_self_path(self, sizeof(self)) != 0) {
        fprintf(stderr,
                "geotrace: cannot resolve own absolute path; pass "
                "--no-auto-sudo.\n");
        return;
    }

    if (has_caller_drop_flag(argc, argv)) {
        fprintf(stderr,
                "geotrace: --drop-uid/--drop-gid are set by the sudo re-exec, "
                "not by hand.\n"
                "         Run unprivileged and let geotrace re-exec, or pass "
                "--no-auto-sudo.\n");
        return;
    }

    /* argv[0] is a placeholder here, patched per execv attempt below. */
    const bool forward_interfaces = extra_interfaces && *extra_interfaces;
    size_t cap = reexec_argv_capacity(argc, forward_interfaces);
    char **new_argv = (char **) xcalloc(cap, sizeof(*new_argv));

    char drop_uid_buf[64];
    char drop_gid_buf[64];
    snprintf(drop_uid_buf, sizeof(drop_uid_buf), "--drop-uid=%lu",
             (unsigned long) getuid());
    snprintf(drop_gid_buf, sizeof(drop_gid_buf), "--drop-gid=%lu",
             (unsigned long) getgid());

    char iface_buf[GEOTRACE_MAX_INTERFACES * (GEOTRACE_IFACE_LEN + 1) + 16];
    iface_buf[0] = '\0';

    if (forward_interfaces) {
        snprintf(iface_buf, sizeof(iface_buf), "--interface=%s",
                 extra_interfaces);
    }

    build_reexec_argv(new_argv, argc, argv, self,
                      forward_interfaces ? iface_buf : NULL, drop_uid_buf,
                      drop_gid_buf);

    fprintf(stderr,
            "geotrace: capture needs root privileges; re-running through "
            "sudo...\n");

    /* Try each candidate; ENOENT means "not installed there", keep going.
     * Anything else (EACCES, ENOEXEC) is a real error — surface it.
     */
    int last_errno = ENOENT;
    for (size_t i = 0; SUDO_CANDIDATES[i]; i++) {
        new_argv[0] = (char *) SUDO_CANDIDATES[i];
        execv(SUDO_CANDIDATES[i], new_argv);
        last_errno = errno;
        if (errno != ENOENT)
            break;
    }

    /* All execv attempts failed. Prefer the last non-ENOENT errno because it
     * identifies an installed but unusable sudo candidate.
     */
    if (last_errno == ENOENT)
        fprintf(
            stderr,
            "geotrace: sudo not found in any of the standard locations.\n"
            "         Install sudo, run as root, or pass --no-auto-sudo.\n");
    else
        fprintf(stderr, "geotrace: execv(sudo) failed: %s\n",
                strerror(last_errno));
    free(new_argv);
}
