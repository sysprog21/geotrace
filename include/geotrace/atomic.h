#ifndef GEOTRACE_ATOMIC_H
#define GEOTRACE_ATOMIC_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>

/* Every atomic access in geotrace goes through this header — no .c file spells
 * atomic_* directly. There are exactly two shapes of shared scalar, each with
 * one fixed ordering, so reviewers audit this file instead of chasing every
 * store. Anything that needs a different ordering does not belong behind these
 * types; give it its own declaration and justify it there.
 *
 * geotrace_flag — a cross-thread boolean raised once (or raised and consumed).
 * Writers publish with release, readers observe with acquire, so whatever a
 * writer did before raising the flag is visible to whoever sees it raised.
 *
 * on_terminate() and on_winch() in main.c store from a signal handler. C11
 * §7.14.1.1 permits that only for lock-free atomics, hence the assert — which
 * every Linux and macOS target geotrace supports satisfies. A port to a
 * platform without lock-free int atomics needs a different stop mechanism, not
 * a weaker assert.
 */
typedef _Atomic int geotrace_flag;

#define GEOTRACE_FLAG_INIT 0

_Static_assert(ATOMIC_INT_LOCK_FREE == 2,
               "geotrace_flag must be always-lock-free: signal handlers store "
               "into it");

static inline void geotrace_flag_raise(geotrace_flag *f)
{
    atomic_store_explicit(f, 1, memory_order_release);
}

static inline bool geotrace_flag_is_raised(geotrace_flag *f)
{
    return atomic_load_explicit(f, memory_order_acquire) != 0;
}

/* Read-and-clear, for edge-triggered consumers. SIGWINCH uses this so a resize
 * landing mid-frame is consumed exactly once instead of lost.
 */
static inline bool geotrace_flag_take(geotrace_flag *f)
{
    return atomic_exchange_explicit(f, 0, memory_order_acquire) != 0;
}

/* geotrace_counter — a monotonic diagnostic counter (the ring's dropped /
 * published / peak_size). Relaxed throughout: these guard no payload, so they
 * synchronize only with themselves. They exist so readers with no lock can
 * sample them without racing the abstract machine, not to publish anything.
 * Promoting them to seq_cst buys no correctness and costs real barriers on
 * weakly-ordered ISAs.
 */
typedef _Atomic size_t geotrace_counter;

/* The four helpers below carry ACSL frame contracts so WP can bound what a
 * counter update touches; without them a caller's whole heap is assumed
 * clobbered and every ring invariant dies at the first bump. The bodies are C11
 * atomic intrinsics, which WP's memory models do not interpret — their
 * correctness is an obligation on the C11 memory model, not on WP, so the
 * contracts are stated for callers and the bodies are excluded from proof.
 */

/*@ requires \valid(c);
    assigns *c;
    ensures *c == 0;
 */
static inline void geotrace_counter_init(geotrace_counter *c)
{
    /* xcalloc-zeroed storage is not portably a valid atomic object; atomic_init
     * is the standard spelling.
     */
    atomic_init(c, (size_t) 0);
}

/*@ requires \valid(c);
    assigns *c;
 */
static inline void geotrace_counter_bump(geotrace_counter *c)
{
    atomic_fetch_add_explicit(c, (size_t) 1, memory_order_relaxed);
}

/* \valid_read, not \valid: this only loads, so demanding write access would
 * make the contract stricter than the function.
 */
/*@ requires \valid_read(c);
    assigns \nothing;
 */
static inline size_t geotrace_counter_read(geotrace_counter *c)
{
    return atomic_load_explicit(c, memory_order_relaxed);
}

/* Raise the counter to "v" if "v" is larger, i.e. publish a high-watermark.
 * Takes no lock, so concurrent producers genuinely race on it.
 *
 * The strong form cannot fail spuriously, so every failure means another thread
 * moved the counter and reloaded "prev" with a strictly larger value, which is
 * why the loop terminates. That is a hand argument, not a proof: this function
 * is outside the verified set and the loop carries no invariant or variant, so
 * nothing here checks it. The weak form would emit tighter code on LL/SC ISAs,
 * but this runs only when the watermark actually moves, which after warmup is
 * almost never.
 */
/*@ requires \valid(c);
    assigns *c;
 */
static inline void geotrace_counter_raise_to(geotrace_counter *c, size_t v)
{
    size_t prev = atomic_load_explicit(c, memory_order_relaxed);
    while (v > prev &&
           !atomic_compare_exchange_strong_explicit(
               c, &prev, v, memory_order_relaxed, memory_order_relaxed))
        ;
}

#endif /* GEOTRACE_ATOMIC_H */
