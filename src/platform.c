#include "geotrace/platform.h"
#include "geotrace/util.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <mach-o/dyld.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#if defined(__linux__)
#include <sys/types.h>
#endif

/* Every probe runs through popen(3), i.e. /bin/sh. platform_detect_interfaces
 * is called from main() before the "refusing to run as root" check, so "sudo
 * geotrace" with no -i reaches it with elevated privileges. probe_popen pins
 * PATH rather than trusting the caller's environment or the sudoers secure_path
 * setting; going through it is what makes that unforgettable, so do not call
 * popen(3) directly in this file.
 */
#define PROBE_PATH "PATH=/usr/sbin:/sbin:/usr/bin:/bin "

static FILE *probe_popen(const char *cmd)
{
    char pinned[256];
    int n = snprintf(pinned, sizeof(pinned), PROBE_PATH "%s", cmd);
    if (n < 0 || (size_t) n >= sizeof(pinned))
        return NULL;
    return popen(pinned, "r");
}

/* helpers */

static bool is_loopback(const char *name)
{
    return name && (strcmp(name, "lo") == 0 || strcmp(name, "lo0") == 0);
}

static bool already_listed(const char names[][GEOTRACE_IFACE_LEN],
                           size_t count,
                           const char *name)
{
    for (size_t i = 0; i < count; i++) {
        if (strcmp(names[i], name) == 0)
            return true;
    }
    return false;
}

bool platform_iface_append(char names[][GEOTRACE_IFACE_LEN],
                           size_t *count,
                           size_t max,
                           const char *name)
{
    if (!names || !count || !name || !*name || *count > max)
        return false;
    if (is_loopback(name))
        return false;
    if (*count >= max)
        return false;
    if (strlen(name) >= GEOTRACE_IFACE_LEN)
        return false;
    if (already_listed(names, *count, name))
        return false;
    geotrace_copy_cstr(names[*count], GEOTRACE_IFACE_LEN, name);
    (*count)++;
    return true;
}

/* Walk one whitespace-separated field. On entry *p points at the remainder of
 * the line; on a hit it is advanced past the field and *start / *len describe
 * it.
 *
 * Returns false at end of line. Shared by the per-platform row parsers.
 */
static bool next_field(const char **p, const char **start, size_t *len)
{
    while (**p == ' ' || **p == '\t')
        (*p)++;
    if (!**p)
        return false;
    *start = *p;
    while (**p && **p != ' ' && **p != '\t')
        (*p)++;
    *len = (size_t) (*p - *start);
    return true;
}

static void chomp_line(char *line)
{
    size_t len = strlen(line);
    if (len && line[len - 1] == '\n')
        line[len - 1] = '\0';
}

/* Run "cmd", parse each line through "pick", append the picked name (if any).
 * Returns when max is hit or the command is exhausted.
 *
 * "pick" writes into "out" (size GEOTRACE_IFACE_LEN) and returns true on a
 * useful match.
 */
static void parse_command_lines(const char *cmd,
                                bool (*pick)(const char *line, char *out),
                                char names[][GEOTRACE_IFACE_LEN],
                                size_t *count,
                                size_t max)
{
    FILE *fp = probe_popen(cmd);
    if (!fp)
        return;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        chomp_line(line);
        char picked[GEOTRACE_IFACE_LEN];
        if (pick(line, picked))
            platform_iface_append(names, count, max, picked);
        if (*count >= max)
            break;
    }
    pclose(fp);
}

/* platform_self_path */

int platform_self_path(char *buf, size_t buflen)
{
    if (!buf || buflen == 0)
        return -1;

#if defined(__APPLE__)
    uint32_t size = (uint32_t) buflen;
    if (_NSGetExecutablePath(buf, &size) != 0)
        return -1;

    /* _NSGetExecutablePath may return symlinks or relative components. The sudo
     * re-exec path must use the canonical binary path so privilege escalation
     * cannot target a different executable.
     */
    char resolved[PATH_MAX];
    if (!realpath(buf, resolved))
        return -1;
    if (strlen(resolved) + 1 > buflen)
        return -1;
    geotrace_copy_cstr(buf, buflen, resolved);
    return 0;
#elif defined(__linux__)
    /* readlink does NOT NUL-terminate. A return value equal to the supplied
     * size means the kernel may have truncated; treat that as failure rather
     * than handing a partial path to execv.
     */
    ssize_t n = readlink("/proc/self/exe", buf, buflen - 1);
    if (n < 0 || (size_t) n >= buflen - 1)
        return -1;
    buf[n] = '\0';
    return 0;
#else
#error "Unsupported platform — only Linux and macOS are supported"
#endif
}

/* platform_detect_interfaces */

#if defined(__linux__)
/* "8.8.8.8 via X dev eth0 ..." → eth0 "8.8.8.8 dev eth0 src ..." → eth0 */
static bool pick_after_dev(const char *line, char *out)
{
    const char *p = strstr(line, " dev ");
    if (!p)
        return false;
    p += 4; /* onto the space before the name; next_field skips it */

    const char *start;
    size_t n;
    if (!next_field(&p, &start, &n))
        return false;
    geotrace_copy_span(out, GEOTRACE_IFACE_LEN, start, n);
    return out[0] != '\0';
}
#endif

#if defined(__APPLE__)
/* macOS "route -n get default" line: "  interface: en0" */
static bool pick_macos_interface_label(const char *line, char *out)
{
    const char *p = strstr(line, "interface:");
    if (!p)
        return false;
    p += strlen("interface:");

    /* chomp_line already stripped the trailing newline before the pick callback
     * runs, so whitespace is the only terminator left.
     */
    const char *start;
    size_t n;
    if (!next_field(&p, &start, &n))
        return false;
    geotrace_copy_span(out, GEOTRACE_IFACE_LEN, start, n);
    return out[0] != '\0';
}

/* macOS "netstat -rn -f inet" rows:
 *   Destination Gateway Flags Netif Expire
 * The 4th field on a "default" row is the interface.
 */
static bool pick_netstat_default(const char *line, char *out)
{
    if (strncmp(line, "default", 7) != 0)
        return false;

    const char *p = line, *start;
    size_t n;
    for (int field = 0; next_field(&p, &start, &n); field++) {
        if (field != 3)
            continue;
        geotrace_copy_span(out, GEOTRACE_IFACE_LEN, start, n);
        return out[0] != '\0';
    }
    return false;
}
#endif

size_t platform_detect_interfaces(char names[][GEOTRACE_IFACE_LEN], size_t max)
{
    size_t count = 0;
    if (max == 0)
        return 0;

#if defined(__linux__)
    /* Specific route to 8.8.8.8 (catches VPN/policy routes) */
    parse_command_lines("ip route get 8.8.8.8 2>/dev/null", pick_after_dev,
                        names, &count, max);
    parse_command_lines("ip route show default 2>/dev/null", pick_after_dev,
                        names, &count, max);
#elif defined(__APPLE__)
    parse_command_lines("route -n get default 2>/dev/null",
                        pick_macos_interface_label, names, &count, max);
    parse_command_lines("netstat -rn -f inet 2>/dev/null", pick_netstat_default,
                        names, &count, max);
#endif

    return count;
}

/* platform_list_ipv4_interfaces */

#if defined(__APPLE__)
size_t platform_list_ipv4_interfaces(interface_info *out, size_t max)
{
    if (max == 0)
        return 0;

    char selected[GEOTRACE_MAX_INTERFACES][GEOTRACE_IFACE_LEN];
    size_t selected_count =
        platform_detect_interfaces(selected, GEOTRACE_MAX_INTERFACES);

    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0)
        return 0;

    size_t count = 0;
    for (struct ifaddrs *ifa = list; ifa && count < max; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;
        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (is_loopback(ifa->ifa_name))
            continue;

        struct sockaddr_in *sin = (struct sockaddr_in *) ifa->ifa_addr;
        char ipbuf[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf)))
            continue;

        geotrace_copy_cstr(out[count].name, GEOTRACE_IFACE_LEN, ifa->ifa_name);
        geotrace_copy_cstr(out[count].address, GEOTRACE_IP_LEN, ipbuf);
        out[count].selected =
            already_listed(selected, selected_count, ifa->ifa_name);
        count++;
    }

    freeifaddrs(list);
    return count;
}
#elif defined(__linux__)
/* Parse a line of "ip -brief -4 addr":
 *   eth0  UP  192.168.1.42/24
 * Take fields 0 (name) and 2 (address with mask, strip the suffix).
 */
static bool pick_ip_brief_line(const char *line, char *iface, char *addr)
{
    iface[0] = addr[0] = '\0';

    const char *p = line, *start;
    size_t n;
    for (int field = 0; next_field(&p, &start, &n); field++) {
        if (field == 0) {
            geotrace_copy_span(iface, GEOTRACE_IFACE_LEN, start, n);
        } else if (field == 2) {
            const char *slash = memchr(start, '/', n);
            geotrace_copy_span(addr, GEOTRACE_IP_LEN, start,
                               slash ? (size_t) (slash - start) : n);
            return iface[0] && addr[0];
        }
    }
    return false;
}

size_t platform_list_ipv4_interfaces(interface_info *out, size_t max)
{
    if (max == 0)
        return 0;

    char selected[GEOTRACE_MAX_INTERFACES][GEOTRACE_IFACE_LEN];
    size_t selected_count =
        platform_detect_interfaces(selected, GEOTRACE_MAX_INTERFACES);

    FILE *fp = probe_popen("ip -brief -4 addr 2>/dev/null");
    if (!fp)
        return 0;

    size_t count = 0;
    char line[512];
    while (count < max && fgets(line, sizeof(line), fp)) {
        chomp_line(line);

        char iface[GEOTRACE_IFACE_LEN];
        char addr[GEOTRACE_IP_LEN];
        if (!pick_ip_brief_line(line, iface, addr))
            continue;
        if (is_loopback(iface))
            continue;

        geotrace_copy_cstr(out[count].name, GEOTRACE_IFACE_LEN, iface);
        geotrace_copy_cstr(out[count].address, GEOTRACE_IP_LEN, addr);
        out[count].selected = already_listed(selected, selected_count, iface);
        count++;
    }
    pclose(fp);
    return count;
}
#else
#error "Unsupported platform"
#endif
