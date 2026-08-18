#ifndef GEOTRACE_PLATFORM_H
#define GEOTRACE_PLATFORM_H

#include "geotrace/models.h"

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#define GEOTRACE_MAX_INTERFACES 8

/* Platform-specific glue with a uniform interface for cli.c. Implementations
 * live in src/platform.c with #ifdef branches for Linux and macOS.
 */

typedef struct {
    char name[GEOTRACE_IFACE_LEN];
    char address[GEOTRACE_IP_LEN];
    bool selected; /* would be picked by detect() */
} interface_info;

/* Write the absolute path to the running executable into "buf"
 * (NUL-terminated).
 *
 * Returns 0 on success, -1 on failure.
 */
int platform_self_path(char *buf, size_t buflen);

/* Append "name" to "names", skipping it when empty, loopback (lo / lo0),
 * already present, or the array is full.
 *
 * Returns true when appended. Null pointers, an invalid count, and names that
 * do not fit in GEOTRACE_IFACE_LEN are rejected.
 *
 * Single gate for "is this an interface we would capture on", shared by the
 * platform probes and by the -i parser in cli.c so the two cannot drift.
 */
bool platform_iface_append(char names[][GEOTRACE_IFACE_LEN],
                           size_t *count,
                           size_t max,
                           const char *name);

/* Detect up to "max" capture interfaces (typically VPN + default route).
 * Returns the number written. Excludes lo / lo0.
 */
size_t platform_detect_interfaces(char names[][GEOTRACE_IFACE_LEN], size_t max);

/* List all IPv4 interfaces. "out" must hold at least "max" slots.
 * Returns the number written. Excludes lo / lo0.
 */
size_t platform_list_ipv4_interfaces(interface_info *out, size_t max);

#endif /* GEOTRACE_PLATFORM_H */
