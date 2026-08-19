/*
 * test-runtime-policy — first coverage for src/main.c and src/ui.c.
 *
 * Neither file had a test. Rendering and orchestration are not worth driving
 * from here, so this covers the two things in them that are worth pinning:
 *
 *   - capture_privileges_ok(), which decides whether the UI is allowed to run
 *     as root. It is a security policy, and the interesting case is that it
 *     refuses a manual "sudo geotrace" precisely because SUDO_UID/SUDO_GID are
 *     not trusted. A regression here would silently run the whole UI as root.
 *   - append_csv_name(), which builds the forwarded --interfaces list into a
 *     fixed buffer. Truncation behaviour is the bug surface.
 *   - the pure time and animation helpers in ui.c, where breathe() feeds a
 *     clamp and so must stay finite and in range.
 *
 * main.c defines main(); rename it so this file can supply its own.
 */

#define main geotrace_unused_main
#include "main.c"
#undef main

/* ui.c for its pure time and animation helpers; both files are included as
 * sources so their statics are reachable, so neither main.o nor ui.o is linked.
 */
#include "ui.c"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* capture_privileges_ok */

static void test_demo_never_needs_privileges(void)
{
    cli_options opts = {0};
    opts.demo = true;
    /* True regardless of euid: --demo touches no capture path. */
    assert(capture_privileges_ok(&opts));
}

static void test_root_without_drop_ids_is_refused(void)
{
    /* euid is a parameter, so the root-only branch is reachable from an
     * unprivileged test run. That is the whole reason the policy was split out
     * of capture_privileges_ok(): with geteuid() read inline, this refusal is
     * untestable here and a test would pass even with the branch deleted.
     */
    cli_options opts = {0};

    /* A manual "sudo geotrace" arrives with no drop IDs. Refuse: SUDO_UID and
     * SUDO_GID are environment values and do not establish an identity.
     */
    assert(!capture_privileges_ok_for(&opts, 0));

    opts.has_drop_uid = true;
    opts.drop_uid = 1000;
    assert(!capture_privileges_ok_for(&opts, 0)); /* gid still missing */

    opts.has_drop_gid = true;
    opts.drop_gid = 1000;
    assert(capture_privileges_ok_for(&opts, 0)); /* both present: allowed */

    /* Non-root without --demo is refused regardless of drop IDs. */
    cli_options unpriv = {0};
    assert(!capture_privileges_ok_for(&unpriv, 1000));

    /* --demo is allowed at any euid. */
    cli_options demo = {0};
    demo.demo = true;
    assert(capture_privileges_ok_for(&demo, 0));
    assert(capture_privileges_ok_for(&demo, 1000));
}

/* append_csv_name */

static void test_csv_append_basic(void)
{
    char buf[64] = {0};
    size_t off = 0;

    assert(append_csv_name(buf, sizeof(buf), &off, "", "en0"));
    assert(strcmp(buf, "en0") == 0);
    assert(append_csv_name(buf, sizeof(buf), &off, ",", "tun0"));
    assert(strcmp(buf, "en0,tun0") == 0);
    assert(off == strlen("en0,tun0"));
}

static void test_csv_append_truncates_without_overflow(void)
{
    char buf[8];
    size_t off = 0;

    memset(buf, 'A', sizeof(buf));
    assert(append_csv_name(buf, sizeof(buf), &off, "", "en0"));

    /* Does not fit: must report failure, stay NUL-terminated, and park the
     * offset at the last writable byte rather than past the end.
     */
    assert(!append_csv_name(buf, sizeof(buf), &off, ",", "verylonginterface"));
    assert(off == sizeof(buf) - 1);
    assert(strlen(buf) < sizeof(buf));

    /* A further append on a full buffer is refused, not a second overflow. */
    assert(!append_csv_name(buf, sizeof(buf), &off, ",", "x"));
}

static void test_csv_append_zero_capacity(void)
{
    char buf[1] = {'Z'};
    size_t off = 0;
    assert(!append_csv_name(buf, 0, &off, "", "en0"));
    assert(buf[0] == 'Z'); /* untouched */
}

/* ui.c pure helpers */

static void test_timespec_helpers(void)
{
    struct timespec a = {.tv_sec = 10, .tv_nsec = 0};
    struct timespec b = {.tv_sec = 12, .tv_nsec = 500000000};

    double d = elapsed_seconds(a, b);
    assert(d > 2.49 && d < 2.51);

    /* Monotonic clocks do not go backwards, but a caller that swaps the
     * arguments should get a negative span, not a wrapped huge one.
     */
    assert(elapsed_seconds(b, a) < 0.0);
    assert(timespec_seconds(b) > timespec_seconds(a));
}

static void test_breathe_stays_in_range(void)
{
    /* breathe() feeds a clamp downstream; it must stay finite and within base
     * +/- amp for any phase, including large t.
     */
    const float base = 0.5f, amp = 0.25f;
    for (int i = 0; i < 2000; i++) {
        double t = (double) i * 0.37;
        float v = breathe(t, 2.0, base, amp);
        assert(v == v); /* not NaN */
        assert(v >= base - amp - 0.001f);
        assert(v <= base + amp + 0.001f);
    }
}

int main(void)
{
    test_demo_never_needs_privileges();
    test_root_without_drop_ids_is_refused();
    test_csv_append_basic();
    test_csv_append_truncates_without_overflow();
    test_csv_append_zero_capacity();
    test_timespec_helpers();
    test_breathe_stays_in_range();

    printf("runtime policy tests passed\n");
    return 0;
}
