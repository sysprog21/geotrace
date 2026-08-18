/*
 * test-projection — equirectangular projection sanity.
 *
 * Picks a few well-known geographic points and checks they land in the expected
 * canvas cell. Tolerates +/-1 cell to account for integer rounding differences
 * from the Python reference.
 */

#include "geotrace/world-map.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#define MAP_W 100
#define MAP_H 25

static int abs_i(int v)
{
    return v < 0 ? -v : v;
}

static int expected_x_for_lon(double lon)
{
    return (int) ((lon - WORLD_MIN_LON) / 360.0 * MAP_W);
}

static int expected_y_for_lat(double lat)
{
    return (int) ((WORLD_MAX_LAT - lat) / 180.0 * MAP_H);
}

static void check(const char *label,
                  double lat,
                  double lon,
                  int expected_x,
                  int expected_y,
                  int tol)
{
    int x, y;
    world_geo_to_canvas(lat, lon, MAP_W, MAP_H, &x, &y);
    if (abs_i(x - expected_x) > tol || abs_i(y - expected_y) > tol) {
        fprintf(
            stderr,
            "FAIL %s: lat=%.4f lon=%.4f → (%d,%d) expected ~(%d,%d) tol=%d\n",
            label, lat, lon, x, y, expected_x, expected_y, tol);
        exit(1);
    }
}

int main(void)
{
    /* Equator + prime meridian: dead center horizontally, half height. */
    check("(0,0)", 0.0, 0.0, MAP_W / 2, MAP_H / 2, 1);

    /* North pole: top edge, x=center */
    check("north pole", 90.0, 0.0, MAP_W / 2, 0, 1);

    /* South pole: bottom edge */
    check("south pole", -89.999, 0.0, MAP_W / 2, MAP_H - 1, 1);

    /* New York (approx 40.7128, -74.0060) — left half, upper third */
    {
        double lat = 40.7128;
        double lon = -74.0060;
        check("New York", lat, lon, expected_x_for_lon(lon),
              expected_y_for_lat(lat), 1);
    }

    /* Sydney (-33.8688, 151.2093) — right half, lower third */
    {
        double lat = -33.8688;
        double lon = 151.2093;
        check("Sydney", lat, lon, expected_x_for_lon(lon),
              expected_y_for_lat(lat), 1);
    }

    /* Berlin (52.52, 13.405) — slightly right of center, upper quarter */
    {
        double lat = 52.52;
        double lon = 13.405;
        check("Berlin", lat, lon, expected_x_for_lon(lon),
              expected_y_for_lat(lat), 1);
    }

    /* Wraparound: longitude -181 → maps via +179 */
    {
        int x_pos, y_pos;
        int x_neg, y_neg;
        world_geo_to_canvas(0.0, 179.0, MAP_W, MAP_H, &x_pos, &y_pos);
        world_geo_to_canvas(0.0, -181.0, MAP_W, MAP_H, &x_neg, &y_neg);
        if (abs_i(x_pos - x_neg) > 1 || y_pos != y_neg) {
            fprintf(stderr, "FAIL wraparound: 179°→(%d,%d) -181°→(%d,%d)\n",
                    x_pos, y_pos, x_neg, y_neg);
            return 1;
        }
    }

    /* Out-of-range lat clamps to ±90 */
    {
        int x_lo, y_lo, x_hi, y_hi;
        world_geo_to_canvas(-200.0, 0.0, MAP_W, MAP_H, &x_lo, &y_lo);
        world_geo_to_canvas(200.0, 0.0, MAP_W, MAP_H, &x_hi, &y_hi);
        if (y_lo != MAP_H - 1 || y_hi != 0) {
            fprintf(stderr, "FAIL clamp: lat=-200→y=%d  lat=200→y=%d\n", y_lo,
                    y_hi);
            return 1;
        }
    }

    /* Virtual grid is exactly 2× × 4× the cell grid. */
    {
        int x_v, y_v;
        world_geo_to_virtual(0.0, 0.0, MAP_W, MAP_H, &x_v, &y_v);
        int max_v_x = MAP_W * WORLD_BRAILLE_DOT_W - 1;
        int max_v_y = MAP_H * WORLD_BRAILLE_DOT_H - 1;
        if (x_v < 0 || x_v > max_v_x || y_v < 0 || y_v > max_v_y) {
            fprintf(stderr, "FAIL virtual bounds: (%d,%d)\n", x_v, y_v);
            return 1;
        }
    }

    /* Re-centering: with the canvas centered on Taipei (lon=121.5654), the home
     * meridian must land at x = MAP_W/2, the antipode at the edges, and
     * Greenwich must shift to the left half.
     */
    {
        const double cl = 121.5654;
        world_set_center_lon(cl);

        int x, y;
        world_geo_to_canvas(0.0, cl, MAP_W, MAP_H, &x, &y);
        if (abs_i(x - MAP_W / 2) > 1) {
            fprintf(stderr, "FAIL Taipei centering: x=%d expected ~%d\n", x,
                    MAP_W / 2);
            return 1;
        }

        /* Antipode (cl + 180) lands on the right edge via the shifted>0
         * carve-out.
         */
        world_geo_to_canvas(0.0, cl + 180.0, MAP_W, MAP_H, &x, &y);
        if (x != MAP_W - 1) {
            fprintf(stderr, "FAIL antipode (east): x=%d expected %d\n", x,
                    MAP_W - 1);
            return 1;
        }
        /* Same antipode reached from the west wraps to x = 0. */
        world_geo_to_canvas(0.0, cl - 180.0, MAP_W, MAP_H, &x, &y);
        if (x != 0) {
            fprintf(stderr, "FAIL antipode (west): x=%d expected 0\n", x);
            return 1;
        }
        /* Greenwich is 121.5654° west of center → must land left of center. */
        world_geo_to_canvas(0.0, 0.0, MAP_W, MAP_H, &x, &y);
        if (x >= MAP_W / 2) {
            fprintf(stderr,
                    "FAIL Greenwich after Taipei centering: x=%d (expected "
                    "left of %d)\n",
                    x, MAP_W / 2);
            return 1;
        }

        /* Restore default for any future tests. */
        world_set_center_lon(0.0);
    }

    fprintf(stderr, "projection tests passed\n");
    return 0;
}
