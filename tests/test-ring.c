/*
 * test-ring — covers:
 *   - empty / full / wrap correctness
 *   - put_latest eviction semantics
 *   - shutdown drains blocked takers
 *   - MPSC stress (4 producers + 1 consumer), no corrupt slots and no
 *     per-producer reordering among delivered events
 *
 * Run under TSan ("make sanitize") before declaring this phase done.
 */

#include "geotrace/atomic.h"
#include "geotrace/ring.h"
#include "geotrace/util.h"

#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* basic correctness */

static void test_empty_take_returns_after_shutdown(void)
{
    struct ring *r = ring_create(4, sizeof(int));
    int v = 0xdead;

    /* Non-blocking pop on empty ring */
    assert(!ring_try_take(r, &v));
    assert(v == 0xdead);

    /* Blocking pop returns false after shutdown */
    ring_shutdown(r);
    assert(!ring_take(r, &v));

    ring_destroy(r);
}

static void test_fill_then_drain(void)
{
    struct ring *r = ring_create(4, sizeof(int));
    for (int i = 0; i < 4; i++) {
        bool evicted = ring_put_latest(r, &i);
        assert(!evicted);
    }
    assert(ring_size(r) == 4);

    for (int i = 0; i < 4; i++) {
        int out = -1;
        assert(ring_try_take(r, &out));
        assert(out == i);
    }
    assert(ring_size(r) == 0);
    assert(ring_dropped(r) == 0);

    ring_destroy(r);
}

static void test_wrap_around(void)
{
    struct ring *r = ring_create(3, sizeof(int));
    int v;

    /* Push 2, pop 1, push 2, pop 3 — exercises head/tail wrap. */
    int a = 1, b = 2, c = 3, d = 4;
    assert(!ring_put_latest(r, &a));
    assert(!ring_put_latest(r, &b));

    assert(ring_try_take(r, &v) && v == 1);

    assert(!ring_put_latest(r, &c));
    assert(!ring_put_latest(r, &d));

    assert(ring_size(r) == 3);

    assert(ring_try_take(r, &v) && v == 2);
    assert(ring_try_take(r, &v) && v == 3);
    assert(ring_try_take(r, &v) && v == 4);
    assert(!ring_try_take(r, &v));

    ring_destroy(r);
}

static void test_put_latest_evicts_oldest(void)
{
    struct ring *r = ring_create(3, sizeof(int));
    int v;

    int a = 10, b = 20, c = 30, d = 40, e = 50;
    assert(!ring_put_latest(r, &a));
    assert(!ring_put_latest(r, &b));
    assert(!ring_put_latest(r, &c));
    assert(ring_size(r) == 3);
    assert(ring_published(r) == 3);
    assert(ring_peak_size(r) == 3);

    /* Overflow: oldest (a) evicted, d appended. */
    assert(ring_put_latest(r, &d));
    assert(ring_size(r) == 3);
    assert(ring_dropped(r) == 1);
    assert(ring_published(r) == 4);
    assert(ring_peak_size(r) == 3);

    /* Another overflow: b evicted, e appended. Order should now be c,d,e. */
    assert(ring_put_latest(r, &e));
    assert(ring_dropped(r) == 2);
    assert(ring_published(r) == 5);

    assert(ring_try_take(r, &v) && v == 30);
    assert(ring_try_take(r, &v) && v == 40);
    assert(ring_try_take(r, &v) && v == 50);
    assert(!ring_try_take(r, &v));

    ring_destroy(r);
}

/* shutdown wakes blocked taker */

struct waker_arg {
    struct ring *r;
    bool result;
    int taken;
};

static void *waker_thread(void *arg)
{
    struct waker_arg *w = (struct waker_arg *) arg;
    w->result = ring_take(w->r, &w->taken);
    return NULL;
}

static void test_shutdown_wakes_blocked_take(void)
{
    struct ring *r = ring_create(2, sizeof(int));
    pthread_t tid;
    struct waker_arg w = {.r = r, .result = true, .taken = -1};

    pthread_create(&tid, NULL, waker_thread, &w);

    /* Give the consumer time to enter the wait. Not racy — even if the producer
     * raced ahead, the test still passes via the empty-after-shutdown path.
     */
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 50 * 1000 * 1000};
    nanosleep(&ts, NULL);

    ring_shutdown(r);
    pthread_join(tid, NULL);

    assert(!w.result); /* shutdown caused empty return */
    ring_destroy(r);
}

/* MPSC stress */

#define STRESS_PRODUCERS 4
#define STRESS_PER_THREAD 50000
#define STRESS_CAPACITY 256

typedef struct {
    uint32_t producer;
    uint32_t seq;
} stress_msg;

struct producer_arg {
    struct ring *r;
    uint32_t id;
    geotrace_flag *go;
};

static void *producer_fn(void *arg)
{
    struct producer_arg *p = (struct producer_arg *) arg;

    /* Spin until every producer is ready; this forces concurrent puts. */
    while (!geotrace_flag_is_raised(p->go)) {
        ;
    }

    for (uint32_t i = 0; i < STRESS_PER_THREAD; i++) {
        stress_msg m = {.producer = p->id, .seq = i};
        ring_put_latest(p->r, &m);
    }
    return NULL;
}

static void test_mpsc_stress(void)
{
    struct ring *r = ring_create(STRESS_CAPACITY, sizeof(stress_msg));
    geotrace_flag go = GEOTRACE_FLAG_INIT;
    pthread_t tids[STRESS_PRODUCERS];
    struct producer_arg args[STRESS_PRODUCERS];

    for (uint32_t i = 0; i < STRESS_PRODUCERS; i++) {
        args[i] = (struct producer_arg) {.r = r, .id = i, .go = &go};
        pthread_create(&tids[i], NULL, producer_fn, &args[i]);
    }

    /* Track the last delivered sequence per producer. Drops may create gaps,
     * but delivered values from a single producer must remain strictly
     * increasing.
     */
    uint32_t last_seq[GEOTRACE_ARRAY_LEN(args)];
    for (uint32_t i = 0; i < GEOTRACE_ARRAY_LEN(args); i++)
        last_seq[i] = (uint32_t) -1;

    size_t received = 0;
    size_t expected = (size_t) STRESS_PRODUCERS * STRESS_PER_THREAD;

    geotrace_flag_raise(&go);

    /* Drain until empty. The ring is lossy, so the exact receive count is not
     * fixed; received + dropped must equal expected after producer shutdown.
     */
    bool joined = false;
    while (received + ring_dropped(r) < expected || ring_size(r) > 0) {
        stress_msg m;
        if (ring_try_take(r, &m)) {
            assert(m.producer < STRESS_PRODUCERS);
            uint32_t prev = last_seq[m.producer];
            assert(prev == (uint32_t) -1 || m.seq > prev);
            last_seq[m.producer] = m.seq;
            received++;
            continue;
        }
        if (!joined) {
            for (uint32_t i = 0; i < STRESS_PRODUCERS; i++)
                pthread_join(tids[i], NULL);
            joined = true;
        }
    }

    if (!joined) {
        for (uint32_t i = 0; i < STRESS_PRODUCERS; i++)
            pthread_join(tids[i], NULL);
    }

    size_t dropped = ring_dropped(r);
    assert(received + dropped == expected);

    /* Four producers writing 200k events into 256 slots should exercise the
     * eviction path.
     */
    assert(dropped > 0);

    fprintf(stderr, "[mpsc_stress] received=%zu dropped=%zu (capacity=%d)\n",
            received, dropped, STRESS_CAPACITY);

    ring_destroy(r);
}

int main(void)
{
    test_empty_take_returns_after_shutdown();
    test_fill_then_drain();
    test_wrap_around();
    test_put_latest_evicts_oldest();
    test_shutdown_wakes_blocked_take();
    test_mpsc_stress();
    return 0;
}
