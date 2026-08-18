#ifndef GEOTRACE_RING_H
#define GEOTRACE_RING_H

#include <stdbool.h>
#include <stddef.h>

/* Bounded, lossy MPSC ring buffer.
 *
 * Multiple producer threads, one consumer. Backed by a single mutex and a
 * not_empty condvar — multiple pcap producers preclude an SPSC implementation.
 *
 * Storage model:
 *   Events are stored *by value* in fixed-size slots. Pop copies into
 *   caller-owned storage while holding the lock. The API never hands out
 *   pointers into ring memory, which kills the put_latest UAF/ABA hazard.
 *
 * Lossy semantics:
 *   ring_put_latest() never blocks. On overflow it evicts the oldest slot in
 *   the same critical section as the new write. Returns 1 if eviction occurred.
 *
 * Shutdown:
 *   ring_shutdown() raises an internal flag and broadcasts not_empty. Blocked
 *   ring_take() callers return 0 and unwind.
 */

struct ring;

/* Create a ring with "capacity" slots of "elem_size" bytes each. Aborts on OOM
 * (uses xmalloc).
 */
struct ring *ring_create(size_t capacity, size_t elem_size);

void ring_destroy(struct ring *r);

/* Push by value. Copies elem_size bytes from "elem". On overflow evicts the
 * oldest slot, then writes; returns true.
 * Returns false on a non-evicting write.
 *
 * "elem" must point to elem_size bytes of valid storage; it may be on the stack
 * — the ring copies before unlocking.
 */
bool ring_put_latest(struct ring *r, const void *elem);

/* Blocking pop. Copies elem_size bytes into "out" and returns true.
 * Returns false if the ring was shut down while empty.
 */
bool ring_take(struct ring *r, void *out);

/* Non-blocking pop.
 *
 * Returns true if a slot was copied to "out", false if empty (regardless of
 * shutdown state).
 */
bool ring_try_take(struct ring *r, void *out);

/* Wake all blocked ring_take callers. Idempotent. */
void ring_shutdown(struct ring *r);

/* Diagnostics — for tests and status banners. Hot paths shouldn't poll these.
 * The counters are geotrace_counter values; their ordering rationale lives on
 * that type in atomic.h.
 *
 * "r" is non-const because ring_size acquires the mutex, and because
 * atomic_load_explicit does not accept a const-qualified pointer.
 */
size_t ring_size(struct ring *r);
size_t ring_dropped(struct ring *r);

/* Total successful pushes since creation, including those that evicted an older
 * slot. Monotonic non-decreasing.
 */
size_t ring_published(struct ring *r);

/* Highest value of "count" ever observed after a push, i.e. the peak occupancy
 * watermark. Monotonic non-decreasing; useful for sizing rings in production.
 * Published outside the mutex by geotrace_counter_raise_to().
 */
size_t ring_peak_size(struct ring *r);

#endif /* GEOTRACE_RING_H */
