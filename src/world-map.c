#include "geotrace/world-map.h"

#include "geotrace/oom.h"
#include "geotrace/util.h"

#include <math.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if HAVE_LAND_MASK
#include <zlib.h>
#endif

/* land mask: zlib blob → static bit buffer */

#if HAVE_LAND_MASK
extern const unsigned char land_mask_zlib[];
extern const size_t land_mask_zlib_len;

#define MASK_BYTES (WORLD_MASK_WIDTH * WORLD_MASK_HEIGHT / 8)

static unsigned char g_land_mask[MASK_BYTES];

static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;

static void init_land_mask(void)
{
    uLongf out_len = MASK_BYTES;
    int rc =
        uncompress(g_land_mask, &out_len, land_mask_zlib, land_mask_zlib_len);
    if (rc != Z_OK || out_len != MASK_BYTES) {
        /* The blob is repo-owned and bin2c-generated. If it's wrong, the binary
         * is broken at every level.
         */
        abort();
    }
}

void world_map_init(void)
{
    pthread_once(&g_init_once, init_land_mask);
}
#else
void world_map_init(void) {}
#endif

/* Sample the land mask at integer column/row; out-of-range returns false.
 * Callers must have run world_map_init() — world_render_base does, and it is
 * the only path that reaches here. Kept init-free because draw_land calls this
 * once per braille dot.
 */
static bool world_is_land(int x, int y)
{
#if !HAVE_LAND_MASK
    (void) x;
    (void) y;
    return false;
#else
    if (x < 0 || x >= WORLD_MASK_WIDTH || y < 0 || y >= WORLD_MASK_HEIGHT)
        return false;
    int idx = y * WORLD_MASK_WIDTH + x;
    return (g_land_mask[idx / 8] & (1u << (idx % 8))) != 0;
#endif
}

/* projection */

/* Longitude that maps to the horizontal center. Default 0 keeps the original
 * Greenwich-centered layout; world_set_center_lon shifts the whole canvas so a
 * chosen meridian sits at x = w/2. Read-only on the rendering path; the setter
 * takes the cache mutex and invalidates the static base.
 */
static double g_center_lon = 0.0;

static double normalize_centered_lon(double lon)
{
    /* Shift so g_center_lon lands at x = w/2, then wrap to [-180, 180). The
     * shifted>0 carve-out keeps +180 from collapsing onto -180 (the right edge
     * stays distinct from the left).
     */
    double shifted = lon - g_center_lon;
    double normalized = fmod(shifted - WORLD_MIN_LON, 360.0);
    if (normalized < 0.0)
        normalized += 360.0;
    normalized += WORLD_MIN_LON;
    if (normalized == WORLD_MIN_LON && shifted > 0.0)
        normalized = WORLD_MAX_LON;
    return normalized;
}

/* Equirectangular projection into a [w x h] grid. Both the cell grid and the
 * higher-resolution braille-dot grid use this; only the dimensions differ.
 */
static void project_equirectangular(double lat,
                                    double lon,
                                    int w,
                                    int h,
                                    int *ox,
                                    int *oy)
{
    if (w < 1)
        w = 1;
    if (h < 1)
        h = 1;

    if (!isfinite(lat))
        lat = 0.0;
    if (!isfinite(lon))
        lon = 0.0;

    double normalized = normalize_centered_lon(lon);

    if (lat < WORLD_MIN_LAT)
        lat = WORLD_MIN_LAT;
    if (lat > WORLD_MAX_LAT)
        lat = WORLD_MAX_LAT;

    double x = (normalized - WORLD_MIN_LON) / (WORLD_MAX_LON - WORLD_MIN_LON) *
               (double) w;
    double y =
        (WORLD_MAX_LAT - lat) / (WORLD_MAX_LAT - WORLD_MIN_LAT) * (double) h;

    *ox = geotrace_clamp_int((int) x, 0, w - 1);
    *oy = geotrace_clamp_int((int) y, 0, h - 1);
}

void world_geo_to_canvas(double lat, double lon, int w, int h, int *ox, int *oy)
{
    if (!ox || !oy || w <= 0 || h <= 0 || w > WORLD_DIM_MAX ||
        h > WORLD_DIM_MAX)
        return;
    project_equirectangular(lat, lon, w, h, ox, oy);
}

void world_geo_to_virtual(double lat,
                          double lon,
                          int w,
                          int h,
                          int *ox,
                          int *oy)
{
    if (!ox || !oy || w <= 0 || h <= 0 || w > WORLD_DIM_MAX ||
        h > WORLD_DIM_MAX)
        return;
    project_equirectangular(lat, lon, w * WORLD_BRAILLE_DOT_W,
                            h * WORLD_BRAILLE_DOT_H, ox, oy);
}

/* Braille dot-position → pattern-bit mapping. Indexed [row][col] within a
 * single 2x4 braille cell; the value is the bit that lights up that dot. Used
 * by both the static land rasterizer and the trajectory plotter.
 */
static const uint8_t BRAILLE_BITS[WORLD_BRAILLE_DOT_H][WORLD_BRAILLE_DOT_W] = {
    {0x01, 0x08},
    {0x02, 0x10},
    {0x04, 0x20},
    {0x40, 0x80},
};

/* braille encoding */

/* The braille block U+2800..U+28FF lives in the 3-byte UTF-8 range:
 *   U+2800 = 11100010 10100000 10000000 = 0xE2 0xA0 0x80
 *   U+28FF = 11100010 10100011 10111111 = 0xE2 0xA3 0xBF
 *
 * For codepoint c, the encoding is:
 *   byte0 = 0xE0 | ((c >> 12) & 0x0F)         — always 0xE2 for U+2xxx
 *   byte1 = 0x80 | ((c >>  6) & 0x3F)         — 0xA0..0xA3 for U+2800..U+28FF
 *   byte2 = 0x80 | ( c        & 0x3F)         — 0x80..0xBF
 *
 * For braille cells, c = 0x2800 + pattern with pattern in [0,255]:
 *   high = 0x2800 >> 6 = 0xA0  →  byte1 = 0x80 | (0xA0 + (pattern >> 6))
 *                                       = 0xA0 | (pattern >> 6)
 *   byte2 = 0x80 | (pattern & 0x3F)
 */
int braille_encode(uint8_t pattern, char out[4])
{
    if (!out)
        return 0;
    out[0] = (char) 0xE2;
    out[1] = (char) (0xA0u | ((unsigned) pattern >> 6));
    out[2] = (char) (0x80u | ((unsigned) pattern & 0x3Fu));
    out[3] = '\0';
    return 3;
}

/* canvas helpers */

static canvas_cell make_cell(uint32_t cp, uint32_t rgb, uint16_t flags)
{
    canvas_cell c;
    c.codepoint = cp;
    c.fg_rgb = rgb;
    c.flags = flags;
    return c;
}

static void put(canvas_cell *cells, int w, int h, int x, int y, canvas_cell c)
{
    if (x < 0 || x >= w || y < 0 || y >= h)
        return;
    cells[y * w + x] = c;
}

uint32_t world_blend_rgb(uint32_t base, uint32_t tint, float amount)
{
    if (!isfinite(amount))
        amount = 0.0f;
    if (amount < 0.0f)
        amount = 0.0f;
    if (amount > 1.0f)
        amount = 1.0f;

    uint32_t out = 0;
    for (int shift = 0; shift <= 16; shift += 8) {
        uint32_t b = (base >> shift) & 0xFFu;
        uint32_t t = (tint >> shift) & 0xFFu;
        uint32_t ch = (uint32_t) ((1.0f - amount) * (float) b +
                                  amount * (float) t + 0.5f);
        out |= (ch & 0xFFu) << shift;
    }
    return out;
}

/* static base layer (grid + land) */

static void draw_grid(canvas_cell *cells, int w, int h, const theme *th)
{
    /* Verticals every 30° of longitude (skip ±180). */
    for (int lon = -150; lon <= 180; lon += 30) {
        int x, _y;
        world_geo_to_canvas(0.0, (double) lon, w, h, &x, &_y);
        for (int y = 0; y < h; y++)
            put(cells, w, h, x, y, make_cell(0x2502, th->grid, CELL_FLAG_DIM));
    }

    /* Horizontals every 30° of latitude. Writes directly instead of via put()
     * because it has to read the existing cell first to turn a crossing into ┼;
     * y comes from the projection so it is already clamped to [0, h).
     */
    for (int lat = -60; lat <= 90; lat += 30) {
        int _x, y;
        world_geo_to_canvas((double) lat, 0.0, w, h, &_x, &y);
        for (int x = 0; x < w; x++) {
            uint32_t cur = cells[y * w + x].codepoint;
            uint32_t cp = (cur == 0x2502) ? 0x253C : 0x2500;
            cells[y * w + x] = make_cell(cp, th->grid, CELL_FLAG_DIM);
        }
    }
}

/* Build a target_size-index lookup table by sampling source cells at each
 * target cell center.
 */
static void scaled_indices(int *out, int source_size, int target_size)
{
    for (int i = 0; i < source_size; i++) {
        double t = ((double) i + 0.5) / (double) source_size;
        int v = (int) (t * (double) target_size);
        if (v < 0)
            v = 0;
        if (v >= target_size)
            v = target_size - 1;
        out[i] = v;
    }
}

static void draw_land(canvas_cell *cells, int w, int h, const theme *th)
{
    int vw = w * WORLD_BRAILLE_DOT_W;
    int vh = h * WORLD_BRAILLE_DOT_H;

    int *xlk = (int *) xmalloc((size_t) vw * sizeof(int));
    int *ylk = (int *) xmalloc((size_t) vh * sizeof(int));
    scaled_indices(ylk, vh, WORLD_MASK_HEIGHT);

    for (int i = 0; i < vw; i++) {
        double t = ((double) i + 0.5) / (double) vw;
        double normalized = WORLD_MIN_LON + t * (WORLD_MAX_LON - WORLD_MIN_LON);
        double source_lon = normalized + g_center_lon;
        double source_x =
            (source_lon - WORLD_MIN_LON) / (WORLD_MAX_LON - WORLD_MIN_LON);
        source_x -= floor(source_x);

        int v = (int) (source_x * (double) WORLD_MASK_WIDTH);
        if (v < 0)
            v = 0;
        if (v >= WORLD_MASK_WIDTH)
            v = WORLD_MASK_WIDTH - 1;
        xlk[i] = v;
    }

    for (int cy = 0; cy < h; cy++) {
        int vy = cy * WORLD_BRAILLE_DOT_H;
        for (int cx = 0; cx < w; cx++) {
            int vx = cx * WORLD_BRAILLE_DOT_W;
            uint8_t pattern = 0;
            for (int dy = 0; dy < WORLD_BRAILLE_DOT_H; dy++) {
                for (int dx = 0; dx < WORLD_BRAILLE_DOT_W; dx++) {
                    if (world_is_land(xlk[vx + dx], ylk[vy + dy]))
                        pattern |= BRAILLE_BITS[dy][dx];
                }
            }
            if (pattern == 0)
                continue;
            uint32_t color = (pattern == 0xFF) ? th->land : th->coast;
            put(cells, w, h, cx, cy,
                make_cell(WORLD_BRAILLE_BASE + pattern, color, 0));
        }
    }

    free(xlk);
    free(ylk);
}

/* static base cache */

typedef struct {
    int w, h;
    const theme *th;
    canvas_cell *cells;
} base_cache_entry;

static base_cache_entry g_base_cache = {0, 0, NULL, NULL};
static pthread_mutex_t g_cache_mtx = PTHREAD_MUTEX_INITIALIZER;

/* Defined alongside traj_cell further down; released here on invalidate. */
static void free_traj_layer(void);

static void reset_base_cache_locked(void)
{
    free(g_base_cache.cells);
    g_base_cache.cells = NULL;
    g_base_cache.w = 0;
    g_base_cache.h = 0;
    g_base_cache.th = NULL;
}

void world_invalidate_cache(void)
{
    pthread_mutex_lock(&g_cache_mtx);
    reset_base_cache_locked();
    pthread_mutex_unlock(&g_cache_mtx);

    free_traj_layer();
}

void world_set_center_lon(double lon)
{
    if (!isfinite(lon))
        return;
    pthread_mutex_lock(&g_cache_mtx);
    if (g_center_lon == lon) {
        pthread_mutex_unlock(&g_cache_mtx);
        return;
    }
    g_center_lon = lon;
    reset_base_cache_locked();
    pthread_mutex_unlock(&g_cache_mtx);
}

/* Reasonable upper bound for terminal dimensions. Anything beyond this is
 * almost certainly garbage and would risk overflowing int multiplications (w *
 * WORLD_BRAILLE_DOT_W, w * h, etc.) before they're cast to size_t.
 */
void world_render_base(canvas_cell *cells, int w, int h, const theme *th)
{
    if (w <= 0 || h <= 0 || w > WORLD_DIM_MAX || h > WORLD_DIM_MAX || !cells ||
        !th)
        return;
    world_map_init();

    pthread_mutex_lock(&g_cache_mtx);
    if (g_base_cache.cells && g_base_cache.w == w && g_base_cache.h == h &&
        g_base_cache.th == th) {
        memcpy(cells, g_base_cache.cells,
               (size_t) w * (size_t) h * sizeof(*cells));
        pthread_mutex_unlock(&g_cache_mtx);
        return;
    }

    /* Rebuild. */
    free(g_base_cache.cells);
    g_base_cache.cells =
        (canvas_cell *) xcalloc((size_t) w * (size_t) h, sizeof(*cells));
    g_base_cache.w = w;
    g_base_cache.h = h;
    g_base_cache.th = th;

    /* Background fill */
    canvas_cell bg = make_cell(' ', th->background, 0);
    for (int i = 0; i < w * h; i++)
        g_base_cache.cells[i] = bg;

    draw_grid(g_base_cache.cells, w, h, th);
    draw_land(g_base_cache.cells, w, h, th);

    memcpy(cells, g_base_cache.cells, (size_t) w * (size_t) h * sizeof(*cells));
    pthread_mutex_unlock(&g_cache_mtx);
}

/* markers */

void world_place_marker(canvas_cell *cells,
                        int w,
                        int h,
                        double lat,
                        double lon,
                        uint32_t codepoint,
                        uint32_t fg_rgb,
                        uint16_t flags)
{
    if (!cells || w <= 0 || h <= 0 || w > WORLD_DIM_MAX || h > WORLD_DIM_MAX)
        return;
    int x, y;
    world_geo_to_canvas(lat, lon, w, h, &x, &y);
    cells[y * w + x] = make_cell(codepoint, fg_rgb, flags);
}

/* trajectories: great-circle arcs */

/* M_PI is a glibc/_BSD_SOURCE extension; keep a local C11-portable copy. */
static const double GEOTRACE_PI = 3.14159265358979323846;

/* The intensity budget for a body cell, and the threshold it must clear. These
 * used to be three bare literals in two translation units held together by a
 * comment; a tweak to any one of them could silently reopen holes in an arc.
 * The assert below is the enforcement.
 *
 * Dimmest live cell = min fade x tail floor (at the home end) x shimmer trough.
 * Held in permille because _Static_assert needs an integer constant expression
 * (C11 6.6p6), which a floating comparison is not.
 */
#define TRAJ_TAIL_FLOOR_PERMILLE 600
#define TRAJ_SHIMMER_BASE_PERMILLE 900
#define TRAJ_SHIMMER_AMP_PERMILLE 100
#define TRAJ_DROP_CUTOFF_PERMILLE 80

#define TRAJ_TAIL_FLOOR (TRAJ_TAIL_FLOOR_PERMILLE / 1000.0)
#define TRAJ_SHIMMER_BASE (TRAJ_SHIMMER_BASE_PERMILLE / 1000.0)
#define TRAJ_SHIMMER_AMP (TRAJ_SHIMMER_AMP_PERMILLE / 1000.0)
#define TRAJ_DROP_CUTOFF (TRAJ_DROP_CUTOFF_PERMILLE / 1000.0f)

_Static_assert((long) WORLD_TRAJECTORY_MIN_FADE_PERMILLE
                       *TRAJ_TAIL_FLOOR_PERMILLE *(TRAJ_SHIMMER_BASE_PERMILLE -
                                                   TRAJ_SHIMMER_AMP_PERMILLE) >
                   (long) TRAJ_DROP_CUTOFF_PERMILLE * 1000L * 1000L,
               "dimmest live trajectory cell would fall under the drop "
               "threshold: arcs will develop holes instead of dimming");

/* Per-cell braille pattern accumulator + intensity. */
typedef struct {
    uint8_t pattern;
    uint8_t edge; /* 0/1 */
    float intensity;
    uint32_t owner;
} traj_cell;

/* Scratch accumulator for world_render_trajectories, reused across frames.
 * Allocating it per frame meant a calloc plus free of w*h traj_cells at the
 * frame rate. UI-thread only, like the rest of the render path.
 */
static traj_cell *g_traj_layer;
static size_t g_traj_cells;

static void free_traj_layer(void)
{
    free(g_traj_layer);
    g_traj_layer = NULL;
    g_traj_cells = 0;
}

static int unwrap_x(int sx, int ex, int vw)
{
    if (vw <= 1)
        return ex;
    int delta = ex - sx;
    int half = vw / 2;
    if (delta > half)
        return ex - vw;
    if (delta < -half)
        return ex + vw;
    return ex;
}

static double deg_to_rad(double deg)
{
    return deg * GEOTRACE_PI / 180.0;
}

static double rad_to_deg(double rad)
{
    return rad * 180.0 / GEOTRACE_PI;
}

static void geo_to_unit(geo_point p, double out[3])
{
    double lat = deg_to_rad(geotrace_clamp_double(p.lat, -90.0, 90.0));
    double lon = deg_to_rad(p.lon);
    double cos_lat = cos(lat);
    out[0] = cos_lat * cos(lon);
    out[1] = cos_lat * sin(lon);
    out[2] = sin(lat);
}

/* Everything about a great-circle arc that does not depend on t. The endpoints
 * are fixed for the whole of one rasterize_trajectory() call, so the unit
 * vectors and the central angle are computed once instead of per sample —
 * rasterizing a wide arc takes hundreds of samples, and this is the difference
 * between eight transcendental calls per sample and four.
 */
typedef struct {
    geo_point start, end;
    double a[3], b[3];
    double omega;
    double sin_omega;
} gc_arc;

static void gc_arc_init(gc_arc *arc, geo_point start, geo_point end)
{
    arc->start = start;
    arc->end = end;
    geo_to_unit(start, arc->a);
    geo_to_unit(end, arc->b);

    double dot = geotrace_clamp_double(
        arc->a[0] * arc->b[0] + arc->a[1] * arc->b[1] + arc->a[2] * arc->b[2],
        -1.0, 1.0);
    arc->omega = acos(dot);
    arc->sin_omega = sin(arc->omega);
}

static geo_point gc_arc_point(const gc_arc *arc, double t)
{
    /* Coincident or antipodal endpoints leave the slerp weights undefined; fall
     * back to a plain lat/lon lerp.
     */
    if (arc->sin_omega < 1e-9) {
        geo_point p = {
            arc->start.lat + (arc->end.lat - arc->start.lat) * t,
            arc->start.lon + (arc->end.lon - arc->start.lon) * t,
        };
        return p;
    }

    double wa = sin((1.0 - t) * arc->omega) / arc->sin_omega;
    double wb = sin(t * arc->omega) / arc->sin_omega;
    double x = wa * arc->a[0] + wb * arc->b[0];
    double y = wa * arc->a[1] + wb * arc->b[1];
    double z = wa * arc->a[2] + wb * arc->b[2];
    double hyp = sqrt(x * x + y * y);

    geo_point p = {
        rad_to_deg(atan2(z, hyp)),
        rad_to_deg(atan2(y, x)),
    };
    return p;
}

static void plot_dot(traj_cell *layer,
                     int w,
                     int h,
                     int vx,
                     int vy,
                     float intensity,
                     bool edge,
                     uint32_t route_id)
{
    int vw = w * WORLD_BRAILLE_DOT_W;
    int vh = h * WORLD_BRAILLE_DOT_H;
    if (vx < 0 || vx >= vw || vy < 0 || vy >= vh)
        return;
    int cx = vx / WORLD_BRAILLE_DOT_W;
    int cy = vy / WORLD_BRAILLE_DOT_H;
    int idx = cy * w + cx;
    uint8_t bit =
        BRAILLE_BITS[vy % WORLD_BRAILLE_DOT_H][vx % WORLD_BRAILLE_DOT_W];
    if (intensity > 1.0f)
        intensity = 1.0f;
    if (layer[idx].owner != 0 && layer[idx].owner != route_id) {
        bool replace = edge || intensity > layer[idx].intensity + 0.02f;
        if (!replace)
            return;
        layer[idx].pattern = 0;
        layer[idx].edge = 0;
        layer[idx].intensity = 0.0f;
    }
    layer[idx].owner = route_id;
    layer[idx].pattern |= bit;
    layer[idx].intensity = geotrace_max_float(layer[idx].intensity, intensity);
    if (edge)
        layer[idx].edge = 1;
}

/* Pick one trajectory color from the theme's gradient based on intensity.
 * trajectory_trail anchors the faintest visible body cells, then glow and the
 * four brighter levels step up toward the head.
 */
static uint32_t trajectory_color(const theme *th, float intensity, bool edge)
{
    if (edge)
        return th->trajectory_edge;

    /* Interpolated ramp over the theme's six stops. This was a step function,
     * which is what made one arc read as a string of separate fragments:
     * intensity varies smoothly along the stroke, but quantising it to six
     * colours put a hard seam wherever it crossed a threshold, and the shimmer
     * swept those seams back and forth along the route.
     */
    const uint32_t stops[] = {
        th->trajectory_trail,     th->trajectory_glow,
        th->trajectory_levels[0], th->trajectory_levels[1],
        th->trajectory_levels[2], th->trajectory_levels[3],
    };
    const size_t last = GEOTRACE_ARRAY_LEN(stops) - 1;

    float t = (float) geotrace_clamp01((double) intensity) * (float) last;
    size_t i = (size_t) t;
    if (i >= last)
        return stops[last];
    return world_blend_rgb(stops[i], stops[i + 1], t - (float) i);
}

/* Rasterize one trajectory into the layer accumulator. */
static void rasterize_trajectory(traj_cell *layer,
                                 int w,
                                 int h,
                                 const trajectory *T,
                                 uint32_t route_id,
                                 double phase)
{
    if (!isfinite(T->start.lat) || !isfinite(T->start.lon) ||
        !isfinite(T->end.lat) || !isfinite(T->end.lon) ||
        !isfinite(T->progress) || !isfinite(T->fade) || !isfinite(phase))
        return;
    double progress = geotrace_clamp01(T->progress);
    double fade = geotrace_clamp01(T->fade);
    if (progress <= 0.0 || fade <= 0.0)
        return;

    int vw = w * WORLD_BRAILLE_DOT_W;
    int vh = h * WORLD_BRAILLE_DOT_H;

    int sx, sy, ex, ey;
    world_geo_to_virtual(T->start.lat, T->start.lon, w, h, &sx, &sy);
    world_geo_to_virtual(T->end.lat, T->end.lon, w, h, &ex, &ey);
    ex = unwrap_x(sx, ex, vw);

    int distance = geotrace_max_int(
        geotrace_max_int(geotrace_abs_int(ex - sx), geotrace_abs_int(ey - sy)),
        1);
    int samples = geotrace_max_int(16, (int) ((double) distance * 2.5));
    int visible = geotrace_min_int(
        samples + 1,
        geotrace_max_int(1, (int) ceil((double) (samples + 1) * progress)));
    int denom = geotrace_max_int(1, visible - 1);

    gc_arc arc;
    gc_arc_init(&arc, T->start, T->end);

    bool have_prev = false;
    int prev_x = 0, prev_y = 0;
    for (int i = 0; i < visible; i++) {
        double tau = (double) i / (double) samples;
        geo_point p = gc_arc_point(&arc, tau);
        int raw_x, raw_y;
        world_geo_to_virtual(p.lat, p.lon, w, h, &raw_x, &raw_y);

        int unwrapped_x = unwrap_x(have_prev ? prev_x : sx, raw_x, vw);
        int cur_x = unwrapped_x % vw;
        if (cur_x < 0)
            cur_x += vw;
        int cur_y = geotrace_clamp_int(raw_y, 0, vh - 1);

        double pos = (double) i / (double) denom;
        bool edge = (progress < 1.0) && (pos >= 0.965);

        /* Linear tail brightening: ~60% near home, 100% at the head. The head
         * still leads the eye, but the origin stays well clear of the composite
         * cutoff so the route reads as one line from home to destination rather
         * than a detached arc near the far end.
         */
        double tail_falloff = TRAJ_TAIL_FLOOR + (1.0 - TRAJ_TAIL_FLOOR) * pos;

        /* Traveling shimmer: 2 cycles along the arc, advancing at ~2.4 rad/s
         * (one cycle every ~2.6 s). Negative phase so the peak walks from home
         * toward the head, reinforcing the visual direction of travel.
         * T->phase_offset desyncs concurrent routes so they don't pulse in
         * lockstep. ±16% amplitude.
         */
        const double shimmer_cycles = 2.0;
        double shimmer = sin(tau * shimmer_cycles * 2.0 * GEOTRACE_PI -
                             phase * 2.4 + T->phase_offset);
        double shimmer_lift = TRAJ_SHIMMER_BASE + TRAJ_SHIMMER_AMP * shimmer;
        float intensity = (float) (fade * tail_falloff * shimmer_lift);
        float plot_intensity = edge ? 1.0f : intensity;

        plot_dot(layer, w, h, cur_x, cur_y, plot_intensity, edge, route_id);

        /* Fill rounding gaps with a short line between prev and cur. */
        if (have_prev) {
            int dx = unwrapped_x - prev_x;
            int dy = cur_y - prev_y;
            int steps = geotrace_max_int(
                geotrace_max_int(geotrace_abs_int(dx), geotrace_abs_int(dy)),
                1);
            for (int s = 1; s <= steps; s++) {
                int ix = (prev_x + dx * s / steps) % vw;
                if (ix < 0)
                    ix += vw;
                int iy = prev_y + dy * s / steps;
                plot_dot(layer, w, h, ix, iy, plot_intensity, edge, route_id);
            }
        }
        prev_x = unwrapped_x;
        prev_y = cur_y;
        have_prev = true;
    }
}

/* Composite the trajectory layer onto cells, picking colors from the theme's
 * gradient. Keeps faint body cells visible so the trail fades smoothly.
 */
static void composite_trajectory_layer(canvas_cell *cells,
                                       int w,
                                       int h,
                                       const theme *th,
                                       const traj_cell *layer)
{
    for (int idx = 0; idx < w * h; idx++) {
        if (layer[idx].pattern == 0)
            continue;
        bool edge = layer[idx].edge != 0;
        float intensity = layer[idx].intensity;

        /* Drop threshold for a body cell. It must stay clear of the dimmest
         * intensity a live route can reach, which ui.c pins with
         * UI_MARKER_FADE_FLOOR: fade floor 0.3 x tail floor 0.6 x shimmer
         * trough 0.68 = 0.122. Keeping real headroom here means a tweak to
         * either end cannot silently punch holes in an arc again.
         */
        if (!edge && intensity < TRAJ_DROP_CUTOFF)
            continue;

        cells[idx].codepoint = WORLD_BRAILLE_BASE + layer[idx].pattern;
        cells[idx].fg_rgb = trajectory_color(th, intensity, edge);
        cells[idx].flags = (edge || intensity >= 0.56f) ? CELL_FLAG_BOLD : 0;
    }
}

void world_render_trajectories(canvas_cell *cells,
                               int w,
                               int h,
                               const theme *th,
                               const trajectory *trajs,
                               size_t count,
                               double phase)
{
    if (!cells || w <= 0 || h <= 0 || w > WORLD_DIM_MAX || h > WORLD_DIM_MAX ||
        !th || !trajs || count == 0)
        return;

    size_t need = (size_t) w * (size_t) h;
    if (need > g_traj_cells) {
        free(g_traj_layer);
        g_traj_layer = (traj_cell *) xmalloc(need * sizeof(*g_traj_layer));
        g_traj_cells = need;
    }
    traj_cell *layer = g_traj_layer;
    memset(layer, 0, need * sizeof(*layer));

    for (size_t t = 0; t < count; t++)
        rasterize_trajectory(layer, w, h, &trajs[t], (uint32_t) t + 1u, phase);

    composite_trajectory_layer(cells, w, h, th, layer);
}
