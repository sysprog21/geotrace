#include "geotrace/ui.h"

#include "geotrace/oom.h"
#include "geotrace/util.h"
#include "geotrace/world-map.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <langinfo.h>
#include <locale.h>
#include <math.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* terminal probes */

void ui_check_terminal(void)
{
    setlocale(LC_CTYPE, "");
    const char *codeset = nl_langinfo(CODESET);
    if (!codeset || (strcasecmp(codeset, "UTF-8") != 0 &&
                     strcasecmp(codeset, "UTF8") != 0)) {
        fprintf(stderr,
                "geotrace: terminal codeset is %s (expected UTF-8). "
                "Braille glyphs may render as '?'.\n",
                codeset ? codeset : "unknown");
    }
    const char *colorterm = getenv("COLORTERM");
    if (!colorterm || (strcmp(colorterm, "truecolor") != 0 &&
                       strcmp(colorterm, "24bit") != 0)) {
        fprintf(stderr,
                "geotrace: COLORTERM=%s (expected truecolor). "
                "Colors may be approximated.\n",
                colorterm ? colorterm : "unset");
    }
}

/* termios raw mode */

static struct termios g_saved_term;

/* Reachable from on_fatal, and C11 7.14.1.1p5 lets a signal handler touch only
 * a lock-free atomic or volatile sig_atomic_t. Taking the flag rather than
 * testing it also makes the restore exactly-once, so a fault arriving while the
 * normal path is mid-restore cannot run the teardown twice.
 *
 * g_saved_term itself needs no such treatment: it is written once in
 * enter_raw_mode before install_fatal_handlers arms anything.
 */
static geotrace_flag g_term_saved = GEOTRACE_FLAG_INIT;

static void restore_terminal(void)
{
    if (!geotrace_flag_take(&g_term_saved))
        return;

    tcsetattr(STDOUT_FILENO, TCSANOW, &g_saved_term);
    /* Show cursor + leave alt screen + reset attributes. */
    const char *cleanup = "\x1b[0m\x1b[?25h\x1b[?1049l";
    ssize_t rc = write(STDOUT_FILENO, cleanup, strlen(cleanup));
    (void) rc;
}

/* abort() bypasses atexit (C11 7.22.4.1), and so does a fatal fault, so the
 * xmalloc/pthread_mutex_init abort paths would otherwise strand the user in the
 * alt screen with no echo. restore_terminal is tcsetattr + write, both
 * async-signal-safe.
 *
 * Undoing raw mode is the only job here; deciding what a fatal signal means is
 * not. So the previous disposition is saved and handed the signal back, rather
 * than hard-coding SIG_DFL: in a release build that is SIG_DFL anyway, but
 * "make debug" links AddressSanitizer, which owns SIGSEGV/SIGBUS to print a
 * report. Forcing SIG_DFL there would trade the sanitizer's diagnosis for a
 * tidy terminal, in the one build where crashes are the point.
 */
static const int FATAL_SIGNALS[] = {SIGABRT, SIGSEGV, SIGBUS};
static struct sigaction g_prev_fatal[GEOTRACE_ARRAY_LEN(FATAL_SIGNALS)];

static void on_fatal(int sig)
{
    /* Hand the signal back *before* touching the terminal: if restore_terminal
     * itself faults, the previous owner acts instead of this handler being
     * re-entered.
     */
    for (size_t i = 0; i < GEOTRACE_ARRAY_LEN(FATAL_SIGNALS); i++) {
        if (FATAL_SIGNALS[i] == sig) {
            sigaction(sig, &g_prev_fatal[i], NULL);
            break;
        }
    }
    restore_terminal();
    raise(sig);
}

static void install_fatal_handlers(void)
{
    struct sigaction sa = {0};
    sa.sa_handler = on_fatal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    for (size_t i = 0; i < GEOTRACE_ARRAY_LEN(FATAL_SIGNALS); i++)
        sigaction(FATAL_SIGNALS[i], &sa, &g_prev_fatal[i]);
}

static int enter_raw_mode(void)
{
    if (!isatty(STDOUT_FILENO))
        return -1;
    if (tcgetattr(STDOUT_FILENO, &g_saved_term) != 0)
        return -1;

    struct termios raw = g_saved_term;
    raw.c_lflag &= (tcflag_t) ~(ECHO | ICANON);
    raw.c_iflag &= (tcflag_t) ~(IXON | ICRNL);
    raw.c_oflag &= (tcflag_t) ~OPOST;
    if (tcsetattr(STDOUT_FILENO, TCSANOW, &raw) != 0)
        return -1;
    geotrace_flag_raise(&g_term_saved);

    /* Enter alt screen, hide cursor. */
    const char *enter = "\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H";
    ssize_t rc = write(STDOUT_FILENO, enter, strlen(enter));
    (void) rc;
    atexit(restore_terminal);
    install_fatal_handlers();
    return 0;
}

/* ui context */

/* Marker life cycle, in seconds:
 *   [0, GROW)                 arc draws outward from home to the destination
 *   [GROW, GROW+HOLD)         complete arc, held at full brightness
 *   [GROW+HOLD, TTL)          fades out
 *
 * HOLD is what makes a route readable end to end. Without it the arc reached
 * full length and started dimming in the same frame, so the origin end sank
 * into the background before the eye could follow it. GROW is short so the arc
 * also completes before marker eviction recycles the slot under load.
 */
#define UI_MARKER_TTL 5.0
#define UI_MARKER_GROW 0.9
#define UI_MARKER_HOLD 2.1
#define UI_MARKER_FLASH 0.7

/* Lowest fade a live route reaches. Letting fade reach 0 tore holes in the arc
 * for its last half second: a cell under the renderer's drop threshold does not
 * dim, it vanishes. Taken from world-map.h so the two ends of that contract
 * cannot drift apart.
 */
#define UI_MARKER_FADE_FLOOR WORLD_TRAJECTORY_MIN_FADE
#define UI_MAX_VISIBLE_MARKERS 24
#define UI_LIVE_PREFIX_LEN 6

typedef struct {
    geo_point coords;
    struct timespec started;
} ui_marker;

struct ui_context {
    struct ring *connections;
    struct ring *statuses;
    const theme *theme;
    geo_point home;
    int fps;

    status_event latest_status;
    bool has_status;

    /* Active markers, oldest first, as a ring: eviction and expiry both drop
     * from the front, so both are an index bump instead of a shift. Iterate
     * with marker_at().
     */
    ui_marker markers[UI_MAX_VISIBLE_MARKERS];
    size_t markers_head;
    size_t markers_count;

    /* Frame buffers */
    canvas_cell *cur;
    canvas_cell *prev;
    int width;
    int height;
    size_t buf_capacity;

    /* Counters */
    uint64_t captured;
    uint64_t mapped;
    uint64_t geo_misses;
};

/* helpers */

static double elapsed_seconds(struct timespec start, struct timespec now)
{
    return (double) geotrace_elapsed_ns(start, now) / 1e9;
}

static double timespec_seconds(struct timespec ts)
{
    return (double) ts.tv_sec + (double) ts.tv_nsec / 1e9;
}

/* End of the arc's full-brightness plateau. The destination marker tracks the
 * arc it terminates, so every stage below keys off this rather than off the
 * arrival flash: dimming the marker while its route is still held bright made
 * the two read as unrelated.
 */
#define UI_MARKER_HOLD_END (UI_MARKER_GROW + UI_MARKER_HOLD)

static uint32_t destination_marker_glyph(double age)
{
    if (age < UI_MARKER_GROW * 0.35)
        return 0x2218; /* ring operator, arc still inbound */
    if (age < UI_MARKER_GROW)
        return 0x25CE; /* bullseye, arc nearly there */
    if (age < UI_MARKER_GROW + UI_MARKER_FLASH)
        return 0x25C9; /* fisheye, arrival flash */
    if (age < UI_MARKER_HOLD_END)
        return 0x25CE; /* bullseye, held with the route */
    return 0x00B7;     /* middle dot, fading out with the route */
}

static uint16_t destination_marker_flags(double age)
{
    if (age < UI_MARKER_HOLD_END)
        return CELL_FLAG_BOLD;
    return CELL_FLAG_DIM;
}

static uint32_t destination_marker_color(const theme *th, double age)
{
    if (age < UI_MARKER_GROW)
        return th->destination_marker;
    if (age < UI_MARKER_GROW + UI_MARKER_FLASH)
        return th->destination_arrival;
    if (age < UI_MARKER_HOLD_END)
        return th->destination_marker;

    const double settle_dur = UI_MARKER_TTL - UI_MARKER_HOLD_END;
    double settle = (age - UI_MARKER_HOLD_END) / settle_dur;
    return world_blend_rgb(th->destination_marker, th->muted,
                           (float) geotrace_clamp01(settle));
}

/* Paint rows [y0, y1) with the theme background. */
static void fill_bg(struct ui_context *ui, int y0, int y1)
{
    const canvas_cell bg = {' ', ui->theme->background, 0};
    const size_t w = (size_t) ui->width;
    for (size_t i = (size_t) y0 * w, end = (size_t) y1 * w; i < end; i++)
        ui->cur[i] = bg;
}

/* Strings reaching the canvas are not all ours: interface names, geo results,
 * and anything a status message interpolates originate outside the program.
 * This is the single point where a byte becomes a cell, so folding C0 and DEL
 * here keeps ANSI escapes out of the terminal no matter which producer grew the
 * string.
 */
static uint32_t printable_cp(char c)
{
    unsigned char u = (unsigned char) c;
    return (u < 0x20 || u == 0x7F) ? ' ' : u;
}

static void set_latest_status(struct ui_context *ui, const status_event *ev)
{
    ui->latest_status = *ev;
    ui->has_status = true;
}

/* i is the logical index, 0 = oldest. */
static const ui_marker *marker_at(const struct ui_context *ui, size_t i)
{
    return &ui->markers[(ui->markers_head + i) % UI_MAX_VISIBLE_MARKERS];
}

static void drop_oldest_marker(struct ui_context *ui)
{
    ui->markers_head = (ui->markers_head + 1) % UI_MAX_VISIBLE_MARKERS;
    ui->markers_count--;
}

static void add_marker(struct ui_context *ui, const connection_event *ev)
{
    if (ui->markers_count == UI_MAX_VISIBLE_MARKERS)
        drop_oldest_marker(ui);

    ui_marker *m = &ui->markers[(ui->markers_head + ui->markers_count) %
                                UI_MAX_VISIBLE_MARKERS];
    ui->markers_count++;
    m->coords = ev->coords;
    clock_gettime(CLOCK_MONOTONIC, &m->started);
}

/* Markers are stamped in arrival order, so the expired ones are always a
 * prefix: stop at the first survivor rather than scanning the whole ring.
 */
static void prune_markers(struct ui_context *ui, struct timespec now)
{
    while (ui->markers_count > 0 &&
           elapsed_seconds(marker_at(ui, 0)->started, now) >= UI_MARKER_TTL)
        drop_oldest_marker(ui);
}

/* sin()-driven oscillator over [base - amp, base + amp]. omega is rad/s. */
static float breathe(double t_seconds, double omega, float base, float amp)
{
    return base + amp * (float) sin(t_seconds * omega);
}

static uint32_t status_message_color(const theme *th, status_level level)
{
    switch (level) {
    case GEOTRACE_STATUS_ERROR:
        return th->error;
    case GEOTRACE_STATUS_WARN:
        return th->warning;
    default:
        return th->muted;
    }
}

/* drain rings */

#define UI_MAX_DRAIN_PER_FRAME 256

static void drain_inputs(struct ui_context *ui)
{
    connection_event ev;
    for (int i = 0; i < UI_MAX_DRAIN_PER_FRAME; i++) {
        if (!ring_try_take(ui->connections, &ev))
            break;
        ui->captured++;
        if (ev.coords_valid) {
            ui->mapped++;
            add_marker(ui, &ev);
        } else {
            ui->geo_misses++;
        }
    }

    status_event sev;
    for (int i = 0; i < UI_MAX_DRAIN_PER_FRAME; i++) {
        if (!ring_try_take(ui->statuses, &sev))
            break;
        set_latest_status(ui, &sev);
    }
}

/* terminal size */

static void get_window_size(int *w, int *h)
{
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 &&
        ws.ws_row > 0) {
        *w = ws.ws_col;
        *h = ws.ws_row;
        return;
    }
    /* Fallback. */
    *w = 100;
    *h = 32;
}

static void ensure_buffers(struct ui_context *ui, int w, int h)
{
    size_t needed = (size_t) w * (size_t) h;
    if (needed > ui->buf_capacity) {
        free(ui->cur);
        free(ui->prev);
        ui->cur = (canvas_cell *) xcalloc(needed, sizeof(canvas_cell));
        ui->prev = (canvas_cell *) xcalloc(needed, sizeof(canvas_cell));
        ui->buf_capacity = needed;
    }
    if (ui->width != w || ui->height != h) {
        /* Force a full repaint by zeroing prev. */
        memset(ui->prev, 0, ui->buf_capacity * sizeof(canvas_cell));
        ui->width = w;
        ui->height = h;
        world_invalidate_cache();
    }
}

/* compose layers into ui->cur */

/* Translate the active markers into trajectory[] and rasterize them onto the
 * map area. Each trajectory grows in over UI_MARKER_GROW seconds and then fades
 * to zero by UI_MARKER_TTL.
 */
static void render_marker_trajectories(struct ui_context *ui,
                                       int map_h,
                                       struct timespec now)
{
    if (ui->markers_count == 0)
        return;

    trajectory trajs[UI_MAX_VISIBLE_MARKERS];

    for (size_t i = 0; i < ui->markers_count; i++) {
        const ui_marker *marker = marker_at(ui, i);
        double age = elapsed_seconds(marker->started, now);
        double progress = geotrace_clamp01(age / UI_MARKER_GROW);
        double fade = 1.0;
        const double fade_start = UI_MARKER_GROW + UI_MARKER_HOLD;
        if (age > fade_start) {
            double fade_dur = UI_MARKER_TTL - fade_start;
            double t = geotrace_clamp01((age - fade_start) / fade_dur);
            fade = 1.0 - (1.0 - UI_MARKER_FADE_FLOOR) * t;
        }
        trajs[i].start = ui->home;
        trajs[i].end = marker->coords;
        trajs[i].progress = progress;
        trajs[i].fade = fade;

        /* Stable per-marker shimmer offset. Multiply the start time so routes
         * added a frame apart land far apart in phase space.
         */
        trajs[i].phase_offset = timespec_seconds(marker->started) * 4.7;
    }

    world_render_trajectories(ui->cur, ui->width, map_h, ui->theme, trajs,
                              ui->markers_count, timespec_seconds(now));
}

/* Paint the per-destination marker glyphs on top of the trajectories. */
static void render_marker_glyphs(struct ui_context *ui,
                                 int map_h,
                                 struct timespec now)
{
    for (size_t i = 0; i < ui->markers_count; i++) {
        const ui_marker *marker = marker_at(ui, i);
        double age = elapsed_seconds(marker->started, now);
        world_place_marker(ui->cur, ui->width, map_h, marker->coords.lat,
                           marker->coords.lon, destination_marker_glyph(age),
                           destination_marker_color(ui->theme, age),
                           destination_marker_flags(age));
    }
}

/* Paint the status panel rows [map_h, h) at the bottom of the canvas. Layout:
 *   row map_h     — top border (┬ at the corners, ─ across)
 *   row map_h+1   — "LIVE captured=… mapped=… geo_miss=…"
 *   row map_h+2   — latest status_event message (if any)
 *
 * The "LIVE" prefix pulses between muted and header colors at 1 Hz; this stays
 * visible even on themes where panel_border == header.
 */
static void compose_status(struct ui_context *ui,
                           int map_h,
                           double frame_seconds)
{
    const int w = ui->width;
    const int h = ui->height;
    const theme *th = ui->theme;

    fill_bg(ui, map_h, h);

    /* Top border. */
    for (int x = 0; x < w; x++) {
        uint32_t cp = (x == 0 || x == w - 1) ? 0x252C : 0x2500;
        ui->cur[map_h * w + x] =
            (canvas_cell) {cp, th->panel_border, CELL_FLAG_DIM};
    }

    char status[256];
    snprintf(status, sizeof(status),
             " LIVE  captured=%8llu  mapped=%8llu  geo_miss=%8llu ",
             (unsigned long long) ui->captured, (unsigned long long) ui->mapped,
             (unsigned long long) ui->geo_misses);

    int line_y = (map_h + 1 < h) ? map_h + 1 : map_h;
    /* 2π → 1 Hz pulse (period 1.0 s). */
    const double pulse_omega = 6.283185307179586;
    float pulse = breathe(frame_seconds, pulse_omega, 0.5f, 0.5f);
    uint32_t live_color = world_blend_rgb(th->muted, th->header, pulse);
    for (size_t i = 0; status[i] && (int) i < w; i++) {
        uint32_t color = (i < UI_LIVE_PREFIX_LEN) ? live_color : th->header;
        ui->cur[line_y * w + (int) i] =
            (canvas_cell) {printable_cp(status[i]), color, CELL_FLAG_BOLD};
    }

    if (!ui->has_status || map_h + 2 >= h)
        return;
    const status_event *latest = &ui->latest_status;
    uint32_t color = status_message_color(th, latest->level);
    for (size_t i = 0; latest->message[i] && (int) i < w; i++)
        ui->cur[(map_h + 2) * w + (int) i] =
            (canvas_cell) {printable_cp(latest->message[i]), color, 0};
}

static void compose_frame(struct ui_context *ui, struct timespec now)
{
    int w = ui->width;
    int h = ui->height;

    /* Too small to host the map. Paint blank rather than returning early:
     * leaving stale cells in "cur" would have render_frame diff against the
     * previous window size, and skipping the paint entirely would skip the
     * loop's only write(2), which is how a vanished terminal is detected.
     */
    if (w < 12 || h < 6) {
        fill_bg(ui, 0, h);
        return;
    }

    /* Map area: full width, height - status_rows. Collapse to full height when
     * the terminal is too small to host the panel.
     */
    const int status_rows = 3;
    int map_h = h - status_rows;
    if (map_h < 4)
        map_h = h;

    world_render_base(ui->cur, w, map_h, ui->theme);
    render_marker_trajectories(ui, map_h, now);
    render_marker_glyphs(ui, map_h, now);

    /* Home marker — slow 0.5 Hz breathe, lerping between background and the
     * theme's home_marker. Anchor at 0.55 so it never collapses to the
     * background entirely; the origin should always read as "alive". π rad/s
     * gives a 0.5 Hz cycle (period 2 s).
     */
    double frame_seconds = timespec_seconds(now);
    const double home_omega = 3.141592653589793;
    float home_breath = breathe(frame_seconds, home_omega, 0.55f, 0.45f);
    uint32_t home_color = world_blend_rgb(ui->theme->background,
                                          ui->theme->home_marker, home_breath);
    world_place_marker(ui->cur, w, map_h, ui->home.lat, ui->home.lon, 0x25CF,
                       home_color, CELL_FLAG_BOLD);

    if (map_h < h)
        compose_status(ui, map_h, frame_seconds);
}

/* frame diff + ANSI emission */

static int append_utf8(char *out, size_t cap, uint32_t cp)
{
    if (cp < 0x80) {
        if (cap < 1)
            return 0;
        out[0] = (char) cp;
        return 1;
    }
    if (cp < 0x800) {
        if (cap < 2)
            return 0;
        out[0] = (char) (0xC0 | (cp >> 6));
        out[1] = (char) (0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        if (cap < 3)
            return 0;
        out[0] = (char) (0xE0 | (cp >> 12));
        out[1] = (char) (0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char) (0x80 | (cp & 0x3F));
        return 3;
    }
    if (cap < 4)
        return 0;
    out[0] = (char) (0xF0 | (cp >> 18));
    out[1] = (char) (0x80 | ((cp >> 12) & 0x3F));
    out[2] = (char) (0x80 | ((cp >> 6) & 0x3F));
    out[3] = (char) (0x80 | (cp & 0x3F));
    return 4;
}

static bool cell_eq(canvas_cell a, canvas_cell b)
{
    return a.codepoint == b.codepoint && a.fg_rgb == b.fg_rgb &&
           a.flags == b.flags;
}

#define WRITE_BUF_SZ (1 << 16)

/* Drain buf fully to STDOUT.
 *
 * Returns true on success, false on hard error (caller should treat as terminal
 * gone). Partial writes — common on slow ttys / SSH — are looped; EINTR is
 * retried.
 */
static bool write_all(const char *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(STDOUT_FILENO, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (n == 0)
            return false;
        off += (size_t) n;
    }
    return true;
}

static size_t emit_str(char *buf, size_t cap, const char *s)
{
    size_t n = strlen(s);
    if (n > cap)
        n = cap;
    memcpy(buf, s, n);
    return n;
}

static size_t emit_move(char *buf, size_t cap, int row, int col)
{
    int n = snprintf(buf, cap, "\x1b[%d;%dH", row, col);
    return (n > 0 && (size_t) n < cap) ? (size_t) n : 0;
}

static size_t emit_color(char *buf, size_t cap, uint32_t rgb)
{
    int n = snprintf(buf, cap, "\x1b[38;2;%u;%u;%um",
                     (unsigned) ((rgb >> 16) & 0xFF),
                     (unsigned) ((rgb >> 8) & 0xFF), (unsigned) (rgb & 0xFF));
    return (n > 0 && (size_t) n < cap) ? (size_t) n : 0;
}

/* Worst case per cell: cursor move (~12) + SGR reset/bold/dim (~12) + 24-bit
 * color (~21) + 4-byte UTF-8 = ~49 bytes. 64 leaves headroom.
 */
#define CELL_RESERVE 64

static bool render_frame(struct ui_context *ui)
{
    int w = ui->width;
    int h = ui->height;
    char buf[WRITE_BUF_SZ];
    size_t used = 0;
    int last_x = -2;
    int last_y = -2;
    uint32_t last_color = 0xFFFFFFFFu;
    uint16_t last_flags = 0xFFFFu;

    for (int y = 0; y < h; y++) {
        for (int x = 0; x < w; x++) {
            canvas_cell c = ui->cur[y * w + x];
            canvas_cell p = ui->prev[y * w + x];
            if (cell_eq(c, p))
                continue;

            /* Flush BEFORE writing so every cell starts with full headroom.
             * Doing it after a write would let emit_* truncate silently when
             * the buffer is nearly full, and last_x/last_y would still advance
             * — the diff would then think the cell was painted on the next
             * frame, leaving the terminal stuck in a wrong state.
             */
            if (used > sizeof(buf) - CELL_RESERVE) {
                if (!write_all(buf, used))
                    return false;
                used = 0;
            }

            if (last_y != y || last_x + 1 != x)
                used += emit_move(buf + used, sizeof(buf) - used, y + 1, x + 1);

            uint16_t flags = c.flags;
            if (flags != last_flags) {
                used += emit_str(buf + used, sizeof(buf) - used, "\x1b[0m");
                if (flags & CELL_FLAG_BOLD)
                    used += emit_str(buf + used, sizeof(buf) - used, "\x1b[1m");
                if (flags & CELL_FLAG_DIM)
                    used += emit_str(buf + used, sizeof(buf) - used, "\x1b[2m");
                last_flags = flags;
                last_color = 0xFFFFFFFFu;
            }
            if (c.fg_rgb != last_color) {
                used += emit_color(buf + used, sizeof(buf) - used, c.fg_rgb);
                last_color = c.fg_rgb;
            }
            uint32_t cp = c.codepoint == 0 ? ' ' : c.codepoint;
            int wrote = append_utf8(buf + used, sizeof(buf) - used, cp);
            used += (size_t) wrote;
            last_x = x;
            last_y = y;
        }
    }

    if (used > 0 && !write_all(buf, used))
        return false;

    /* Swap buffers only on a clean flush. On failure leave prev untouched so a
     * subsequent retry (if the caller decides to keep running) re-diffs against
     * the last known-painted frame instead of the half-emitted one.
     */
    canvas_cell *tmp = ui->prev;
    ui->prev = ui->cur;
    ui->cur = tmp;
    return true;
}

/* create / destroy / run */

struct ui_context *ui_create(const ui_options *opts)
{
    if (!opts || !opts->connections || !opts->statuses || !opts->theme)
        return NULL;

    struct ui_context *ui = (struct ui_context *) xcalloc(1, sizeof(*ui));
    ui->connections = opts->connections;
    ui->statuses = opts->statuses;
    ui->theme = opts->theme;
    ui->home = opts->home;
    ui->fps = opts->fps > 0 ? opts->fps : 12;
    if (ui->fps > 60)
        ui->fps = 60;
    return ui;
}

void ui_destroy(struct ui_context *ui)
{
    if (!ui)
        return;
    free(ui->cur);
    free(ui->prev);
    free(ui);
}

void ui_run(struct ui_context *ui, geotrace_flag *stop, geotrace_flag *resize)
{
    if (!ui || !stop || !resize)
        return;

    enter_raw_mode();

    const int64_t frame_ns = 1000000000 / ui->fps;

    while (!geotrace_flag_is_raised(stop)) {
        struct timespec frame_start;
        clock_gettime(CLOCK_MONOTONIC, &frame_start);

        if (geotrace_flag_take(resize))
            world_invalidate_cache();

        int w, h;
        get_window_size(&w, &h);
        ensure_buffers(ui, w, h);

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        drain_inputs(ui);
        prune_markers(ui, now);
        compose_frame(ui, now);

        /* A failed flush means the terminal is gone (EPIPE, EBADF, etc.) —
         * retrying just burns CPU on a dead fd. Bail out and let the caller
         * clean up.
         */
        if (!render_frame(ui))
            break;

        /* Sleep the remainder of the frame, not a whole frame on top of the
         * work: composing and flushing a full-screen frame is a real fraction
         * of the budget, so sleeping frame_ns unconditionally put the actual
         * rate below the requested one, by more the bigger the terminal.
         */
        int64_t remain_ns = frame_ns - geotrace_elapsed_ns_now(frame_start);
        if (remain_ns > 0) {
            /* Split rather than stuffing everything into tv_nsec: at --fps=1 a
             * frame is exactly 1e9 ns, and nanosleep rejects tv_nsec == 1e9
             * with EINVAL, so that frame would never sleep at all.
             */
            struct timespec ts = {
                .tv_sec = (time_t) (remain_ns / 1000000000),
                .tv_nsec = (long) (remain_ns % 1000000000),
            };
            nanosleep(&ts, NULL);
        }
    }

    restore_terminal();
}
