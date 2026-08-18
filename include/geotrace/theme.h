#ifndef GEOTRACE_THEME_H
#define GEOTRACE_THEME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Theme registry — single source of truth for available themes. The CLI mutex
 * group is generated from this table; adding a theme touches this one place.
 *
 * Color fields are 0xRRGGBB. The UI consults this table directly during
 * rendering.
 */

typedef struct {
    const char *name;     /* lookup key, e.g. "green" */
    const char *cli_flag; /* e.g. "green" → matches --green */

    uint32_t background;
    uint32_t grid;
    uint32_t land;
    uint32_t coast;
    uint32_t trajectory_edge;
    uint32_t trajectory_glow;
    uint32_t trajectory_trail;
    uint32_t trajectory_levels[4];
    uint32_t home_marker;
    uint32_t destination_marker;
    uint32_t destination_arrival;
    uint32_t panel_border;
    uint32_t header;
    uint32_t muted;
    uint32_t warning;
    uint32_t error;
} theme;

extern const theme GEOTRACE_THEMES[];
extern const size_t GEOTRACE_THEME_COUNT;

/* Default theme — index 0 of the table. */
const theme *theme_default(void);

#endif /* GEOTRACE_THEME_H */
