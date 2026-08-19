#include "geotrace/ring.h"

#include "geotrace/atomic.h"
#include "geotrace/oom.h"

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* The mutex on the push/pop paths provides every happens-before relation the
 * consumer needs. The counters below are atomic only so diagnostic readers
 * (status banner, tests, sizing reports) can sample them without taking the
 * mutex; their relaxed ordering is documented once on geotrace_counter.
 */
struct ring {
    pthread_mutex_t mtx;
    pthread_cond_t not_empty;

    /* char, not unsigned char: the slab is only ever allocated, freed, offset
     * by slot_at, and memcpied in both directions -- no byte value is read,
     * compared, or used in arithmetic, so signedness cannot matter. Matching
     * memcpy's own char-based interface also stops WP's Typed model reporting a
     * uint8 / sint8 pointer mismatch at every copy.
     */
    char *slots; /* capacity * elem_size bytes */
    size_t capacity;
    size_t elem_size;

    size_t head; /* next pop index */
    size_t tail; /* next push index */
    size_t count;
    geotrace_counter dropped;   /* evictions, monotonic */
    geotrace_counter published; /* successful pushes, monotonic */
    geotrace_counter peak_size; /* high-watermark of count, monotonic */
    bool shutdown;
};

/* ACSL specification — what "the mutex protects the ring" actually means.
 *
 * WP has no thread model: it cannot prove mutual exclusion, and it cannot prove
 * absence of data races. Those come from the locking discipline, which is
 * reviewed, not proved. What is proved here is the other half of the
 * concurrent-separation-logic argument, and it is the half that hides bugs:
 *
 *   ring_inv is the resource invariant associated with r->mtx. Every entry
 *   point below is specified "requires ring_inv(r) ... ensures ring_inv(r)",
 *   which is exactly the obligation a critical section owes: acquire the lock
 *   and you may assume the invariant; release it and you must have restored it.
 *   Given mutual exclusion, an invariant preserved by every critical section is
 *   preserved globally, whatever the interleaving. That is the whole proof
 *   obligation the interleavings can generate, discharged sequentially.
 *
 * The invariant states head/tail stay in range, count never exceeds capacity,
 * and the wrap relation tail == (head + count) mod capacity holds — written as
 * a conditional subtraction rather than a "%" because head + count < 2*capacity
 * makes the modulus a single branch, which the SMT provers handle in linear
 * arithmetic instead of choking on nested modulo. Memory safety of every memcpy
 * falls out of it: no slot index can leave the allocation.
 *
 * No public entry point below states a \old-relative claim about count, and
 * that is deliberate rather than an omission. WP's \old is the function entry
 * state, which is before the lock is taken, and the post-state is after it is
 * released; another thread may push or drain on either side. Such a claim can
 * therefore be discharged by WP and still be false of the running system —
 * ring_take carried exactly that bug ("returns true implies count dropped by
 * one" is refuted by waking from an empty ring), and ring_try_take's read as
 * "returned false implies the ring was empty", which is the conclusion a
 * concurrent caller most needs not to draw. The relations that do hold live on
 * take_locked, where the caller holds the lock from entry to exit.
 *
 * Trusted, not proved: mutual exclusion itself; the C11 atomic intrinsics
 * behind geotrace_counter (see atomic.h); and the frame of pthread_cond_wait,
 * where in reality another thread mutates the ring and restores the invariant
 * before signalling.
 *
 * Reproduce with "make verify". Every ring_inv preservation goal, every index
 * bound, and every wrap-relation goal is proved: no critical section here can
 * leave count above capacity, drive head or tail out of range, or break the
 * wrap relation. What stays open falls into the groups below. None is a claim
 * about the ring's state machine, and none should be read as verified:
 *
 *   - memcpy's separation precondition in take_locked and ring_put_latest.
 *     Note this is no longer the pointer-type mismatch it once was: the slab is
 *     char now, so WP no longer reports a uint8 / sint8 pointer mismatch at
 * these copies, and the goals stay open regardless.
 *   - ring_create: its own postcondition, exits, terminates, and xmalloc's
 *     precondition. The invariant is still not founded at creation, so this
 *     stays a relative proof: entry points assume ring_inv rather than
 *     inheriting it.
 *   - two of ring_put_latest's assigns parts. WP numbers assigns obligations
 *     per write statement, and the ones that stay open are the memcpy into the
 *     slab, not the counters; every counter part proves.
 *
 * ring_take carries "terminates \false" because it blocks in pthread_cond_wait
 * by design. That is the honest claim rather than a silenced one: the function
 * offers no termination guarantee, so WP is no longer asked to invent one, and
 * the obligation disappears instead of timing out on every run.
 *
 * Two earlier diagnoses in this comment were wrong and are recorded here so
 * they are not repeated. slot_at's postconditions were blamed on the memory
 * model; they fail identically under Typed, Typed+cast and Bytes, because the
 * blocker was nonlinear arithmetic. Stating the no-overflow bound in product
 * form (capacity * elem_size <= SIZE_MAX) instead of division form, plus
 * mul_mono_right and the assert in slot_at, closes both. And the open assigns
 * parts were blamed on the atomic counters, which measurement contradicts.
 */

/*@ predicate slots_valid(struct ring *r) =
      \valid(r->slots + (0 .. r->capacity * r->elem_size - 1));

    predicate slots_separated(struct ring *r) =
      \separated(r, r->slots + (0 .. r->capacity * r->elem_size - 1));

    predicate ring_inv(struct ring *r) =
      \valid(r) &&
      0 < r->capacity &&
      0 < r->elem_size &&
      r->capacity * r->elem_size <= SIZE_MAX &&
      r->head < r->capacity &&
      r->tail < r->capacity &&
      r->count <= r->capacity &&
      r->tail == (r->head + r->count < r->capacity
                      ? r->head + r->count
                      : r->head + r->count - r->capacity) &&
      slots_valid(r) &&
      slots_separated(r);

    lemma mul_mono_right:
      \forall integer a, b, c; 0 <= a <= b ==> 0 <= c ==> a * c <= b * c;

    predicate caller_buffer(struct ring *r, char *p) =
      \separated(p + (0 .. r->elem_size - 1), r,
                 r->slots + (0 .. r->capacity * r->elem_size - 1));
 */

/* No assigns clause: everything this writes lives in storage that did not exist
 * in the pre-state, and WP's Typed model has no way to say "the frame is the
 * object I just allocated". Omitting it lets WP assume the widest frame rather
 * than prove a false "assigns \nothing".
 */
/*@ allocates \result;
    ensures \result == \null ||
            (ring_inv(\result) && \result->capacity == capacity &&
             \result->elem_size == elem_size && \result->head == 0 &&
             \result->tail == 0 && \result->count == 0 &&
             \result->shutdown == \false);
 */
struct ring *ring_create(size_t capacity, size_t elem_size)
{
    if (!capacity || !elem_size)
        return NULL;
    /* Guard the slot allocation against size_t wraparound. */
    if (elem_size > SIZE_MAX / capacity)
        return NULL;

    struct ring *r = (struct ring *) xcalloc(1, sizeof(*r));
    r->capacity = capacity;
    r->elem_size = elem_size;
    r->slots = (char *) xmalloc(capacity * elem_size);

    geotrace_counter_init(&r->dropped);
    geotrace_counter_init(&r->published);
    geotrace_counter_init(&r->peak_size);

    if (pthread_mutex_init(&r->mtx, NULL) != 0)
        abort();
    if (pthread_cond_init(&r->not_empty, NULL) != 0)
        abort();
    return r;
}

void ring_destroy(struct ring *r)
{
    if (!r)
        return;
    pthread_mutex_destroy(&r->mtx);
    pthread_cond_destroy(&r->not_empty);
    free(r->slots);
    free(r);
}

/*@ requires \valid_read(r);
    requires 0 < r->elem_size;
    requires index < r->capacity;
    requires r->capacity * r->elem_size <= SIZE_MAX;
    requires \valid(r->slots + (0 .. r->capacity * r->elem_size - 1));
    assigns \result \from r->slots, r->elem_size, index;
    ensures addr:  \result == r->slots + index * r->elem_size;
    ensures valid: \valid(\result + (0 .. r->elem_size - 1));
 */
static char *slot_at(const struct ring *r, size_t index)
{
    /*@ assert bound: (index + 1) * r->elem_size <=
                      r->capacity * r->elem_size; */
    return r->slots + (index * r->elem_size);
}

/* The lock is held by the caller, so this body is the critical section proper:
 * it may assume the invariant on entry and must restore it on exit.
 */
/*@ requires ring_inv(r);
    // Spelled out rather than reused from ring_inv/caller_buffer: WP hands a
    // named predicate to the provers as an opaque symbol in hypothesis
    // position, and the memcpy bounds and separation goals need these two facts
    // as direct premises. Redundant to a reader, load-bearing to Alt-Ergo.
    requires slots_valid(r);
    requires \valid((char *) out + (0 .. r->elem_size - 1));
    requires \separated((char *) out + (0 .. r->elem_size - 1), r,
                        r->slots + (0 .. r->capacity * r->elem_size - 1));
    assigns r->head, r->count, *((char *) out + (0 .. r->elem_size - 1));
    ensures ring_inv(r);
    ensures \result <==> \old(r->count) > 0;
    ensures \result ==> r->count == \old(r->count) - 1;
    ensures !\result ==> r->count == \old(r->count) && r->head == \old(r->head);
 */
static bool take_locked(struct ring *r, void *out)
{
    if (r->count == 0)
        return false;

    /* Containment of one slot in the slab: the separation and assigns goals for
     * the copy below both need it, and it is the same nonlinear step
     * mul_mono_right exists for.
     */
    //@ assert (r->head + 1) * r->elem_size <= r->capacity * r->elem_size;
    memcpy(out, slot_at(r, r->head), r->elem_size);
    r->head = (r->head + 1) % r->capacity;
    r->count--;
    return true;
}

/*@ requires ring_inv(r);
    requires \valid_read((char *) elem + (0 .. r->elem_size - 1));
    requires caller_buffer(r, (char *) elem);
    assigns r->mtx, r->not_empty, r->head, r->tail, r->count, r->dropped,
            r->published, r->peak_size,
            *(r->slots + (0 .. r->capacity * r->elem_size - 1));
    ensures ring_inv(r);
 */
/* No count relation and no "0 < r->count" here, for the same reason ring_take
 * has none: WP's \old is the function entry state, which is before the lock is
 * taken, and the post-state is after it is released. Another thread may push or
 * drain on either side of this function's critical section, so a claim relating
 * the two is not true of the system even when WP discharges it. The relation
 * that does hold is stated on take_locked, where the lock is held start to end.
 */
bool ring_put_latest(struct ring *r, const void *elem)
{
    bool evicted = false;
    size_t cur;

    pthread_mutex_lock(&r->mtx);

    if (r->count == r->capacity) {
        /* Eviction in the same critical section: drop oldest, then push. */
        r->head = (r->head + 1) % r->capacity;
        r->count--;
        geotrace_counter_bump(&r->dropped);
        evicted = true;
    }

    /* Same two facts the copy in take_locked needs: the slot lies inside the
     * slab, and the caller's buffer is readable for elem_size bytes. Stated as
     * // comments so clang-format cannot rewrap them into invalid ACSL.
     */
    //@ assert (r->tail + 1) * r->elem_size <= r->capacity * r->elem_size;
    //@ assert \valid_read((char *) elem + (0 .. r->elem_size - 1));
    memcpy(slot_at(r, r->tail), elem, r->elem_size);
    r->tail = (r->tail + 1) % r->capacity;
    r->count++;
    geotrace_counter_bump(&r->published);

    cur = r->count;
    pthread_cond_signal(&r->not_empty);
    pthread_mutex_unlock(&r->mtx);

    /* Deliberately outside the mutex, so concurrent producers really do race on
     * the watermark.
     */
    geotrace_counter_raise_to(&r->peak_size, cur);

    return evicted;
}

/* The only entry point here that spans two critical sections: pthread_cond_wait
 * releases the lock and reacquires it, so the state on either side of the wait
 * is not the same state. No \old-relative claim about count survives that —
 * enter with an empty ring, sleep, and the producer that wakes this thread
 * decides what \old would have to be compared against. Only the invariant and
 * the frame are stated. The count relation that does hold is take_locked's, and
 * it is stated there, where the lock is held throughout.
 */
/*@ requires ring_inv(r);
    requires \valid((char *) out + (0 .. r->elem_size - 1));
    requires caller_buffer(r, (char *) out);
    terminates \false;
    assigns r->mtx, r->not_empty, r->head, r->count,
            *((char *) out + (0 .. r->elem_size - 1));
    ensures ring_inv(r);
 */
bool ring_take(struct ring *r, void *out)
{
    pthread_mutex_lock(&r->mtx);

    /* The invariant is what pthread_cond_wait hands back: a producer mutated
     * the ring while this thread slept and restored ring_inv before signalling.
     * That step is the trusted edge of the proof — WP sees only cond_wait's
     * frame, not the other thread.
     */
    /*@ loop invariant ring_inv(r);
        loop assigns r->mtx, r->not_empty;
     */
    while (r->count == 0 && !r->shutdown)
        pthread_cond_wait(&r->not_empty, &r->mtx);

    if (!take_locked(r, out)) {
        /* shutdown && empty */
        pthread_mutex_unlock(&r->mtx);
        return false;
    }

    pthread_mutex_unlock(&r->mtx);
    return true;
}

/*@ requires ring_inv(r);
    requires \valid((char *) out + (0 .. r->elem_size - 1));
    requires caller_buffer(r, (char *) out);
    assigns r->mtx, r->head, r->count,
            *((char *) out + (0 .. r->elem_size - 1));
    ensures ring_inv(r);
 */
/* Same as ring_put_latest above: the \old-relative count claims are gone. The
 * one that was here read as "returned false implies the ring was empty", which
 * is precisely the conclusion a concurrent caller must not draw.
 */
bool ring_try_take(struct ring *r, void *out)
{
    pthread_mutex_lock(&r->mtx);
    if (!take_locked(r, out)) {
        pthread_mutex_unlock(&r->mtx);
        return false;
    }

    pthread_mutex_unlock(&r->mtx);
    return true;
}

/*@ requires ring_inv(r);
    assigns r->mtx, r->not_empty, r->shutdown;
    ensures ring_inv(r);
    ensures r->shutdown == \true;
 */
void ring_shutdown(struct ring *r)
{
    pthread_mutex_lock(&r->mtx);
    r->shutdown = true;
    pthread_cond_broadcast(&r->not_empty);
    pthread_mutex_unlock(&r->mtx);
}

/* "\result == r->count" is gone for the reason given in the header block, the
 * same one that removed the count relations from ring_try_take and
 * ring_put_latest: the lock is released before the return, so the count a
 * caller reads is a sample, not the ring's current size. The capacity bound
 * stays because capacity is fixed at creation and no thread can move it.
 */
/*@ requires ring_inv(r);
    assigns r->mtx;
    ensures ring_inv(r);
    ensures \result <= r->capacity;
 */
size_t ring_size(struct ring *r)
{
    pthread_mutex_lock(&r->mtx);
    size_t n = r->count;
    pthread_mutex_unlock(&r->mtx);
    return n;
}

size_t ring_dropped(struct ring *r)
{
    return geotrace_counter_read(&r->dropped);
}

size_t ring_published(struct ring *r)
{
    return geotrace_counter_read(&r->published);
}

size_t ring_peak_size(struct ring *r)
{
    return geotrace_counter_read(&r->peak_size);
}
