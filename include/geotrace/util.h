#ifndef GEOTRACE_UTIL_H
#define GEOTRACE_UTIL_H

#include <limits.h>
#include <stddef.h>
#include <string.h>

#define GEOTRACE_ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))

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
