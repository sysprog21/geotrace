#ifndef GEOTRACE_CLI_H
#define GEOTRACE_CLI_H

#include "geotrace/platform.h"
#include "geotrace/theme.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

/* Parsed command-line options.
 *
 * theme is always set (defaults to theme_default()). interfaces is empty when
 * the user passed no -i; the orchestrator should call platform_detect on miss.
 */
typedef struct {
    const theme *theme;
    int fps; /* default 12, clamped 1..60 */
    bool demo;
    bool list_interfaces;
    bool no_auto_sudo;
    bool show_help;
    bool show_version;

    bool has_drop_uid;
    bool has_drop_gid;
    uid_t drop_uid;
    gid_t drop_gid;

    char interfaces[GEOTRACE_MAX_INTERFACES][GEOTRACE_IFACE_LEN];
    size_t interface_count;
} cli_options;

typedef enum {
    CLI_OK = 0,
    CLI_EXIT_SUCCESS = 1, /* parsed help/version; caller should exit(0) */
    CLI_BAD_USAGE = 2,    /* malformed argv; caller should exit(2) */
} cli_status;

/* Parse argc/argv into out. Diagnostics go to stderr. */
cli_status cli_parse(int argc, char **argv, cli_options *out);

void cli_print_help(FILE *fp, const char *progname);
void cli_print_version(FILE *fp);

/* Normalize a comma/semicolon-separated interface string into out, dropping
 * empties, lo/lo0, and duplicates.
 *
 * Returns the count written.
 */
size_t cli_normalize_interfaces(const char *raw,
                                char out[][GEOTRACE_IFACE_LEN],
                                size_t max);

/* Re-exec the running binary under sudo when capture privileges are needed.
 * No-op if --demo, --no-auto-sudo, or already root.
 *
 * Appends "--drop-uid=<getuid()>" and "--drop-gid=<getgid()>" so the new
 * process can drop back to the user's identity once pcap handles are open.
 * "extra_interfaces" (when non-NULL and non-empty) is appended as
 * "--interface=..." so the post-sudo run keeps the same set. The caller decides
 * when that applies: pass an empty string when the user's own -i is already in
 * argv, otherwise the forwarded copy and the original would both be parsed.
 *
 * On success this function does not return — execv replaces the process. On
 * failure it prints to stderr and returns; the caller should continue and fail
 * later when pcap_open_live reports EPERM.
 */
void cli_ensure_capture_privileges(int argc,
                                   char **argv,
                                   const cli_options *opts,
                                   const char *extra_interfaces);

#endif /* GEOTRACE_CLI_H */
