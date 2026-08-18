/*
 * test-cli — the sudo re-exec command line.
 *
 * build_reexec_argv decides who the privileged process drops to, so its
 * ordering rules are security-relevant rather than cosmetic: the drop flags
 * must come after anything the caller passed, and a bare "--" must not be
 * forwarded ahead of them. Both rules have been broken once already.
 *
 * cli.c is included directly to reach the static builder, so this test does
 * not link cli.o.
 */

#include "cli.c"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define MAX_SLOTS 32

/* Run the builder over a literal argv and return the slot count (excluding the
 * NULL terminator), with the result left in out.
 */
static size_t build(char **out, int argc, char **argv, bool with_iface)
{
    size_t cap = reexec_argv_capacity(argc, with_iface);
    assert(cap <= MAX_SLOTS);

    build_reexec_argv(out, argc, argv, (char *) "/usr/local/bin/geotrace",
                      with_iface ? (char *) "--interface=en0,tun0" : NULL,
                      (char *) "--drop-uid=501", (char *) "--drop-gid=20");

    /* Slot 0 is the sudo path, left NULL for execv to patch, so the terminator
     * search starts at 1.
     */
    assert(out[0] == NULL);
    size_t n = 1;
    while (out[n])
        n++;
    /* The builder must never write past what the capacity promised: n slots
     * plus the terminator.
     */
    assert(n + 1 <= cap);
    return n;
}

static void expect_slot(char **got, size_t i, const char *want)
{
    if (!got[i] || strcmp(got[i], want) != 0) {
        fprintf(stderr, "FAIL slot %zu: got \"%s\", want \"%s\"\n", i,
                got[i] ? got[i] : "(null)", want);
        exit(1);
    }
}

/* The generated flags sit ahead of anything the caller wrote, so nothing the
 * caller wrote can capture them as an argument or terminate options before
 * them.
 */
static void expect_generated_flags_first(char **got)
{
    expect_slot(got, 2, "--drop-uid=501");
    expect_slot(got, 3, "--drop-gid=20");
}

static void test_plain(void)
{
    char *argv[] = {(char *) "geotrace", (char *) "--green"};
    char *got[MAX_SLOTS] = {0};
    size_t n = build(got, 2, argv, false);

    assert(n == 5);
    expect_slot(got, 1, "/usr/local/bin/geotrace");
    expect_generated_flags_first(got);
    expect_slot(got, 4, "--green");
}

/* A caller's own drop flags are refused outright rather than out-ordered:
 * these decide who the UI runs as, and both spellings must be caught.
 */
static void test_caller_drop_flags_refused(void)
{
    char *eq[] = {(char *) "geotrace", (char *) "--drop-uid=0"};
    char *sep[] = {(char *) "geotrace", (char *) "--drop-gid", (char *) "0"};
    char *clean[] = {(char *) "geotrace", (char *) "--demo"};

    assert(has_caller_drop_flag(2, eq));
    assert(has_caller_drop_flag(3, sep));
    assert(!has_caller_drop_flag(2, clean));
    assert(!has_caller_drop_flag(1, clean));
}

/* A trailing "--" keeps its meaning, and nothing generated follows it: after
 * an option terminator the root-side parse would read a flag as a positional
 * argument and refuse to start.
 */
static void test_option_terminator_ends_the_line(void)
{
    char *argv[] = {(char *) "geotrace", (char *) "--demo", (char *) "--"};
    char *got[MAX_SLOTS] = {0};
    size_t n = build(got, 3, argv, false);

    expect_generated_flags_first(got);
    expect_slot(got, n - 1, "--");
}

/* "-i --" is the other reading of the same two characters: getopt takes "--"
 * as the argument to -i. Removing it would hand -i the next word instead, and
 * the next word is a generated flag.
 */
static void test_terminator_as_option_argument(void)
{
    char *argv[] = {(char *) "geotrace", (char *) "-i", (char *) "--"};
    char *got[MAX_SLOTS] = {0};
    size_t n = build(got, 3, argv, false);

    expect_generated_flags_first(got);
    expect_slot(got, n - 2, "-i");
    expect_slot(got, n - 1, "--");
}

/* The auto-detected interface set is forwarded before the drop flags. */
static void test_interface_forwarding(void)
{
    char *argv[] = {(char *) "geotrace"};
    char *got[MAX_SLOTS] = {0};
    size_t n = build(got, 1, argv, true);

    assert(n == 5);
    expect_generated_flags_first(got);
    expect_slot(got, 4, "--interface=en0,tun0");
}

int main(void)
{
    test_plain();
    test_caller_drop_flags_refused();
    test_option_terminator_ends_the_line();
    test_terminator_as_option_argument();
    test_interface_forwarding();
    fprintf(stderr, "cli tests passed\n");
    return 0;
}
