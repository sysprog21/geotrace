#ifndef GEOTRACE_UTIL_H
#define GEOTRACE_UTIL_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* ACSL contracts below; "make verify" checks them (see src/ring.c for the
 * project's verification notes). These are the bottom of the dependency graph —
 * every other translation unit here includes this header — so their contracts
 * are what the layers above get to assume.
 *
 * All of it discharges but for two goals, both recorded in the baseline that
 * "make verify" diffs against.
 *
 * First, memcpy's valid_src precondition inside geotrace_copy_span. Frama-C's
 * libc states that as valid_read_or_empty(), an opaque predicate WP declines to
 * unfold, so the sub-range step from the caller's \valid_read(src + (0 ..
 * src_len - 1)) never connects. geotrace_copy_cstr's identical memcpy does
 * prove, which is what marks this as a prover limitation rather than a defect.
 *
 * Second, geotrace_copy_cstr's "strlen(dst) <= strlen(src)". Its source bound
 * is itself a strlen, so the post-state strlen(src) has to be reconnected to
 * the length read before the copy, across memcpy's opaque frame. The
 * corresponding "strlen(dst) <= src_len" in geotrace_copy_span, where the bound
 * is an integer parameter, does prove.
 *
 * The separation and destination-bounds obligations, which are the ones that
 * catch real overruns, are proved for both functions.
 */

#define GEOTRACE_ARRAY_LEN(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Nanoseconds from start to end. int64_t rather than long because long is 32
 * bits on 32-bit Linux, where it would overflow after two seconds.
 *
 * Every caller wants the same subtraction at a different scale, so the scaling
 * stays at the call site: CLOCK_MONOTONIC deltas here are frame budgets, socket
 * budgets, and marker ages. The tv_sec bound is what keeps the multiply in
 * range. It is 9223372035, not 9223372036: the seconds term is scaled by 10^9
 * and *then* the nanosecond difference is added, so the looser bound overflows
 * int64_t by up to a second's worth of nanoseconds at the extreme. Either way
 * any pair of CLOCK_MONOTONIC reads under ~292 years apart is safe; the point
 * is that the overflow is a stated caller obligation rather than an accident.
 *
 * The bound is on the mathematical difference, so it rules out overflow of the
 * C subtraction only where time_t is 64 bits — the machdep "make verify" runs
 * under, and every target geotrace builds for. Were time_t 32 bits, the
 * subtraction would wrap at ~68 years, well inside this precondition, and the
 * cast would then widen an already-truncated result.
 */
/*@ requires -9223372035 <= end.tv_sec - start.tv_sec <= 9223372035;
    requires 0 <= start.tv_nsec < 1000000000;
    requires 0 <= end.tv_nsec < 1000000000;
    assigns \nothing;
 */
static inline int64_t geotrace_elapsed_ns(struct timespec start,
                                          struct timespec end)
{
    /* Each operand widened before the subtraction, not after: on a 32-bit
     * time_t the difference itself overflows, and casting the wrapped result
     * would just launder it.
     */
    return ((int64_t) end.tv_sec - (int64_t) start.tv_sec) * 1000000000 +
           ((int64_t) end.tv_nsec - (int64_t) start.tv_nsec);
}

/* Nanoseconds from start until now, 0 if the clock read fails. */
static inline int64_t geotrace_elapsed_ns_now(struct timespec start)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return geotrace_elapsed_ns(start, now);
}

/* No precondition: this is total over int, INT_MIN included, which is the whole
 * point of the saturation below.
 */
/*@ assigns \nothing;
    ensures \result >= 0;
    ensures v != INT_MIN ==> (\result == v || \result == -v);
    ensures v == INT_MIN ==> \result == INT_MAX;
 */
static inline int geotrace_abs_int(int v)
{
    /* -INT_MIN overflows in signed int. Saturate to INT_MAX — callers use this
     * to bound rendering steps, where one off-by-one beats undefined behavior.
     */
    if (v == INT_MIN)
        return INT_MAX;
    return v < 0 ? -v : v;
}

/*@ assigns \nothing;
    ensures \result == (a < b ? a : b);
    ensures \result <= a && \result <= b;
 */
static inline int geotrace_min_int(int a, int b)
{
    return a < b ? a : b;
}

/*@ assigns \nothing;
    ensures \result == (a > b ? a : b);
    ensures \result >= a && \result >= b;
 */
static inline int geotrace_max_int(int a, int b)
{
    return a > b ? a : b;
}

/* The two saturation clauses are not redundant with the range: without them a
 * body that returns hi when v < lo (and vice versa) satisfies this contract.
 */
/*@ requires lo <= hi;
    assigns \nothing;
    ensures lo <= \result <= hi;
    ensures lo <= v <= hi ==> \result == v;
    ensures v < lo ==> \result == lo;
    ensures v > hi ==> \result == hi;
 */
static inline int geotrace_clamp_int(int v, int lo, int hi)
{
    if (v < lo)
        return lo;
    if (v > hi)
        return hi;
    return v;
}

/* The \is_finite precondition is not pedantry: a NaN v fails both comparisons
 * and is returned unchanged, so the clamp silently does nothing. Callers
 * feeding this from parsed or computed coordinates must rule NaN out first.
 */
/*@ requires lo <= hi;
    requires \is_finite(v) && \is_finite(lo) && \is_finite(hi);
    assigns \nothing;
    ensures lo <= \result <= hi;
    ensures lo <= v <= hi ==> \result == v;
    ensures v < lo ==> \result == lo;
    ensures v > hi ==> \result == hi;
 */
static inline double geotrace_clamp_double(double v, double lo, double hi)
{
    if (v < lo)
        return lo;
    if (v > hi)
        return hi;
    return v;
}

/*@ requires \is_finite(v);
    assigns \nothing;
    ensures 0.0 <= \result <= 1.0;
    ensures 0.0 <= v <= 1.0 ==> \result == v;
    ensures v < 0.0 ==> \result == 0.0;
    ensures v > 1.0 ==> \result == 1.0;
 */
static inline double geotrace_clamp01(double v)
{
    return geotrace_clamp_double(v, 0.0, 1.0);
}

/*@ requires \is_finite(a) && \is_finite(b);
    assigns \nothing;
    ensures \result == (a > b ? a : b);
 */
static inline float geotrace_max_float(float a, float b)
{
    return a > b ? a : b;
}

/* Copy up to dst_size-1 bytes from src and always NUL-terminate when dst_size >
 * 0.
 *
 * The \separated precondition is the one that matters: this wraps memcpy, so
 * overlapping dst and src is undefined behaviour, not merely a truncated copy.
 */
/*@ requires dst_size == 0 || \valid(dst + (0 .. dst_size - 1));
    requires dst_size == 0 || valid_read_string(src);
    requires dst_size == 0 ||
             \separated(dst + (0 .. dst_size - 1), src + (0 .. strlen(src)));
    assigns dst[0 .. dst_size - 1];
    ensures dst_size > 0 ==> valid_read_string(dst);
    ensures dst_size > 0 ==> strlen(dst) <= dst_size - 1;
 */
/* No "strlen(dst) <= strlen(src)" clause, though it is true of the body. WP
 * cannot discharge it: the bound is itself a strlen, so the post-state length
 * of src has to be reconnected across memcpy's opaque frame. geotrace_copy_span
 * states the same idea and does prove, because there the bound is an integer
 * parameter rather than a strlen.
 *
 * It is dropped rather than left open because an unproved postcondition is
 * assumed by every caller: it would read as verified while nothing checked it.
 * The two clauses above are the ones that matter anyway -- NUL-termination and
 * no overflow -- and both are proved.
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
/*@ requires dst_size == 0 || \valid(dst + (0 .. dst_size - 1));
    requires dst_size == 0 || \valid_read(src + (0 .. src_len - 1));
    requires dst_size == 0 ||
             \separated(dst + (0 .. dst_size - 1), src + (0 .. src_len - 1));
    assigns dst[0 .. dst_size - 1];
    ensures dst_size > 0 ==> valid_read_string(dst);
    ensures dst_size > 0 ==> strlen(dst) <= dst_size - 1;
    ensures dst_size > 0 ==> strlen(dst) <= src_len;
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
