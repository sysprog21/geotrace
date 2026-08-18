#ifndef GEOTRACE_UTIL_H
#define GEOTRACE_UTIL_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define GEOTRACE_ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Nanoseconds from start to end. int64_t rather than long because long is 32
 * bits on 32-bit Linux, where it would overflow after two seconds.
 *
 * Every caller wants the same subtraction at a different scale, so the scaling
 * stays at the call site: CLOCK_MONOTONIC deltas here are frame budgets, socket
 * budgets, and marker ages.
 */
static inline int64_t geotrace_elapsed_ns(struct timespec start,
                                          struct timespec end)
{
    return (int64_t) (end.tv_sec - start.tv_sec) * 1000000000 +
           (int64_t) (end.tv_nsec - start.tv_nsec);
}

/* Nanoseconds from start until now, 0 if the clock read fails. */
static inline int64_t geotrace_elapsed_ns_now(struct timespec start)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return geotrace_elapsed_ns(start, now);
}

static inline int geotrace_abs_int(int v)
{
    /* -INT_MIN overflows in signed int. Saturate to INT_MAX — callers use this
     * to bound rendering steps, where one off-by-one beats undefined behavior.
     */
    if (v == INT_MIN)
        return INT_MAX;
    return v < 0 ? -v : v;
}

static inline int geotrace_min_int(int a, int b)
{
    return a < b ? a : b;
}

static inline int geotrace_max_int(int a, int b)
{
    return a > b ? a : b;
}

static inline int geotrace_clamp_int(int v, int lo, int hi)
{
    if (v < lo)
        return lo;
    if (v > hi)
        return hi;
    return v;
}

static inline double geotrace_clamp_double(double v, double lo, double hi)
{
    if (v < lo)
        return lo;
    if (v > hi)
        return hi;
    return v;
}

static inline double geotrace_clamp01(double v)
{
    return geotrace_clamp_double(v, 0.0, 1.0);
}

static inline float geotrace_max_float(float a, float b)
{
    return a > b ? a : b;
}

/* Copy up to dst_size-1 bytes from src and always NUL-terminate when dst_size >
 * 0.
 */
static inline void geotrace_copy_cstr(char *dst,
                                      size_t dst_size,
                                      const char *src)
{
    if (dst_size == 0)
        return;

    size_t len = strlen(src);
    if (len >= dst_size)
        len = dst_size - 1;

    memcpy(dst, src, len);
    dst[len] = '\0';
}

/* Like geotrace_copy_cstr(), but the source may contain embedded NULs or may
 * not be terminated within src_len bytes.
 */
static inline void geotrace_copy_span(char *dst,
                                      size_t dst_size,
                                      const char *src,
                                      size_t src_len)
{
    if (dst_size == 0)
        return;

    if (src_len >= dst_size)
        src_len = dst_size - 1;

    memcpy(dst, src, src_len);
    dst[src_len] = '\0';
}

#endif /* GEOTRACE_UTIL_H */
