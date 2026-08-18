#ifndef GEOTRACE_WORLD_MAP_H
#define GEOTRACE_WORLD_MAP_H

#include "geotrace/models.h"
#include "geotrace/theme.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Terminal world map — projection, braille rasterizer, static layer cache.
 *
 * Constants mirror the repository's generated land-mask assets. The land mask
 * is a 360x180 bit array decoded from a zlib blob embedded by scripts/bin2c.py
 * at build time.
 */

#define WORLD_MASK_WIDTH 360
#define WORLD_MASK_HEIGHT 180
#define WORLD_MIN_LAT (-90.0)
#define WORLD_MAX_LAT 90.0
#define WORLD_MIN_LON (-180.0)
#define WORLD_MAX_LON 180.0
/* Reject dimensions above this bound before size arithmetic or allocation. */
#define WORLD_DIM_MAX 8192

#define WORLD_BRAILLE_DOT_W 2
#define WORLD_BRAILLE_DOT_H 4
#define WORLD_BRAILLE_BASE 0x2800u

/* Cell-style flags. */
#define CELL_FLAG_BOLD 0x01u
#define CELL_FLAG_DIM 0x02u

/* Canvas cell — codepoint + 24-bit RGB + style flags. codepoint == 0 marks an
 * unmodified background cell.
 */
typedef struct {
    uint32_t codepoint;
    uint32_t fg_rgb;
    uint16_t flags;
} canvas_cell;

/* Trajectory request — start/end on the globe, progress and fade in [0,1].
 * phase_offset adds a stable per-route offset (radians) to the shimmer wave so
 * concurrent trajectories don't pulse in lockstep. The caller chooses any
 * monotonic source it likes; the marker's start time works well.
 */
typedef struct {
    geo_point start;
    geo_point end;
    double progress;
    double fade;
    double phase_offset;
} trajectory;

/* Lowest "fade" worth handing this renderer for a route you still want drawn
 * end to end. Below it the dimmest part of the stroke falls under the internal
 * drop threshold and the arc develops holes instead of simply dimming.
 * world-map.c static-asserts the two against each other.
 */
#define WORLD_TRAJECTORY_MIN_FADE_PERMILLE 300
#define WORLD_TRAJECTORY_MIN_FADE (WORLD_TRAJECTORY_MIN_FADE_PERMILLE / 1000.0)

/* one-shot init */

/* Decompress the embedded land mask into a static buffer. Idempotent. Aborts on
 * internal corruption (genuinely fatal).
 */
void world_map_init(void);

/* projection */

/* Set the longitude that maps to the horizontal center of the canvas. The
 * default is 0 (Greenwich-centered). Changing it invalidates the static base
 * cache, since grid lines and the land outline are projection-dependent. Safe
 * to call once at startup before the UI thread runs; concurrent updates are not
 * supported.
 */
void world_set_center_lon(double lon);

/* Equirectangular projection: lat/lon → cell coordinates. Output is clamped to
 * [0, w-1] × [0, h-1].
 */
void world_geo_to_canvas(double lat,
                         double lon,
                         int w,
                         int h,
                         int *out_x,
                         int *out_y);

/* Same projection on the high-resolution braille dot grid (w*2 × h*4). */
void world_geo_to_virtual(double lat,
                          double lon,
                          int w,
                          int h,
                          int *out_x,
                          int *out_y);

/* braille encoding */

/* Encode a braille bit pattern (0x00..0xFF) as a UTF-8 sequence into out.
 * Always writes exactly 3 bytes plus a NUL terminator.
 *
 * Returns 3 on success, or 0 when "out" is NULL.
 */
int braille_encode(uint8_t pattern, char out[4]);

/* canvas rendering */

/* Render the cached static base (grid + land outline) into "cells". "cells"
 * must hold w*h elements. Cache key is (w, h, theme).
 *
 * Subsequent calls with the same (w, h, theme) memcpy from the cache. Resize or
 * theme change rebuilds the cache.
 */
void world_render_base(canvas_cell *cells, int w, int h, const theme *th);

/* Place a marker glyph at lat/lon. */
void world_place_marker(canvas_cell *cells,
                        int w,
                        int h,
                        double lat,
                        double lon,
                        uint32_t codepoint,
                        uint32_t fg_rgb,
                        uint16_t flags);

/* Rasterize trajectories onto the canvas. Each trajectory follows a
 * great-circle arc, projected through world_geo_to_canvas; cells under the arc
 * become braille glyphs with intensity mapped through a continuously
 * interpolated six-stop theme gradient.
 *
 * "phase" is a monotonic seconds value used to drive the brightness peak
 * traveling along each arc; precision is only needed modulo about 4 seconds.
 */
void world_render_trajectories(canvas_cell *cells,
                               int w,
                               int h,
                               const theme *th,
                               const trajectory *trajs,
                               size_t count,
                               double phase);

/* Channel-wise lerp between two 0xRRGGBB colors. amount is clamped to [0,1]. */
uint32_t world_blend_rgb(uint32_t base, uint32_t tint, float amount);

/* Invalidate the static base cache. UI calls this on theme switch or resize. */
void world_invalidate_cache(void);

#endif /* GEOTRACE_WORLD_MAP_H */
