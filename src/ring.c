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

    unsigned char *slots; /* capacity * elem_size bytes */
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
    r->slots = (unsigned char *) xmalloc(capacity * elem_size);

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

static unsigned char *slot_at(const struct ring *r, size_t index)
{
    return r->slots + (index * r->elem_size);
}

static bool take_locked(struct ring *r, void *out)
{
    if (r->count == 0)
        return false;

    memcpy(out, slot_at(r, r->head), r->elem_size);
    r->head = (r->head + 1) % r->capacity;
    r->count--;
    return true;
}

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

bool ring_take(struct ring *r, void *out)
{
    pthread_mutex_lock(&r->mtx);
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

void ring_shutdown(struct ring *r)
{
    pthread_mutex_lock(&r->mtx);
    r->shutdown = true;
    pthread_cond_broadcast(&r->not_empty);
    pthread_mutex_unlock(&r->mtx);
}

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
