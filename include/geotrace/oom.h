#ifndef GEOTRACE_OOM_H
#define GEOTRACE_OOM_H

#include <stddef.h>
#include <stdint.h> /* SIZE_MAX, referenced by the ACSL contracts below */

/* OOM-aborting wrappers. Hot paths (per-packet) keep their events on the stack
 * and copy them by value through the rings, so these are reserved for
 * setup-time allocations where propagating NULL through every call site would
 * just be noise.
 *
 * On allocation failure or a size multiplication overflow: write a one-line
 * diagnostic to stderr and abort(3). Never returns NULL.
 */

/* These contracts are TRUSTED ASSUMPTIONS about the allocator, and every clause
 * on them is one: src/oom.c is not in VERIFY_SRCS, so WP sees declarations with
 * no body and generates nothing to discharge. Adding or removing a
 * postcondition here changes the goal count by zero. There is no "proved"
 * version of this contract to aspire to, and treating it as a boundary axiom is
 * what Frama-C's own libc does for malloc.
 *
 * An earlier revision deleted the validity postcondition on the grounds that it
 * was an unprovable claim callers silently assumed. That reasoning was wrong on
 * both halves: nothing here is provable either way, and dropping it cost seven
 * real memory-safety obligations in ring_create (the writes through the xcalloc
 * result, the three counter_init preconditions, and mutex_valid), which come
 * back the moment it is stated. Keep it, and keep the label honest. The
 * allocates clauses are not decoration: ACSL defaults a contract without one to
 * "allocates \nothing", which would state that these return a pointer into
 * storage that already existed. That is a stronger claim than saying nothing,
 * and a false one.
 */
/*@ requires size > 0;
    allocates \result;
    assigns \result \from size;
    ensures \valid((char *) \result + (0 .. size - 1));
 */
void *xmalloc(size_t size);

/*@ requires nmemb > 0 && size > 0;
    requires nmemb <= SIZE_MAX / size;
    allocates \result;
    assigns \result \from nmemb, size;
    ensures \valid((char *) \result + (0 .. nmemb * size - 1));
    // calloc zeroes, so the axiom set should say so: without it every field
    // ring_create leaves alone (shutdown) is unconstrained. Stated for
    // faithfulness, not for leverage -- measured, it closes no goal here,
    // because ring_create's blocker is that WP cannot know the xcalloc and
    // xmalloc results do not alias, not what the bytes hold.
    ensures \forall integer i; 0 <= i < nmemb * size ==>
                ((char *) \result)[i] == 0;
 */
void *xcalloc(size_t nmemb, size_t size);

#endif /* GEOTRACE_OOM_H */
