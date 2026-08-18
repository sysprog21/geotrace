#include "geotrace/theme.h"
#include "geotrace/util.h"

/* Built-in themes. Adding a theme means appending one entry here and letting
 * cli.c derive the corresponding long option from the table.
 */
const theme GEOTRACE_THEMES[] = {
    {
        .name = "default",
        .cli_flag = NULL, /* default has no toggle flag */
        .background = 0x0f172a,
        .grid = 0x1e3a8a,
        .land = 0x2f7d5f,
        .coast = 0x4f8f79,
        .trajectory_edge = 0x00ffff,
        .trajectory_glow = 0x38bdf8,
        .trajectory_trail = 0x5b8ac9,
        .trajectory_levels = {0x7dd3fc, 0x93c5fd, 0xbae6fd, 0xe0f2fe},
        .home_marker = 0xfb7185,
        .destination_marker = 0xfbbf24,
        .destination_arrival = 0x00ffff,
        .panel_border = 0x38bdf8,
        .header = 0x67e8f9,
        .muted = 0x64748b,
        .warning = 0xfbbf24,
        .error = 0xef4444,
    },
    {
        .name = "green",
        .cli_flag = "green",
        .background = 0x000000,
        .grid = 0x0f3d24,
        .land = 0x166534,
        .coast = 0x3f9163,
        .trajectory_edge = 0x00ff41,
        .trajectory_glow = 0x4ade80,
        .trajectory_trail = 0x2f9d5f,
        .trajectory_levels = {0x86efac, 0xbbf7d0, 0xd1fae5, 0xf0fdf4},
        .home_marker = 0xfacc15,
        .destination_marker = 0x00ff41,
        .destination_arrival = 0xbbf7d0,
        .panel_border = 0x00ff41,
        .header = 0x00ff41,
        .muted = 0x4b5563,
        .warning = 0xfacc15,
        .error = 0xef4444,
    },
    {
        .name = "red",
        .cli_flag = "red",
        .background = 0x1a1a1a,
        .grid = 0x5f1a1a,
        .land = 0x57534e,
        .coast = 0xa16565,
        .trajectory_edge = 0xef4444,
        .trajectory_glow = 0xfb7185,
        .trajectory_trail = 0xc46a6a,
        .trajectory_levels = {0xfca5a5, 0xfecaca, 0xfee2e2, 0xfff1f2},
        .home_marker = 0xfbbf24,
        .destination_marker = 0xef4444,
        .destination_arrival = 0xfecaca,
        .panel_border = 0xef4444,
        .header = 0xef4444,
        .muted = 0x737373,
        .warning = 0xfbbf24,
        .error = 0xf87171,
    },
    {
        .name = "violet",
        .cli_flag = "violet",
        .background = 0x1e1b4b,
        .grid = 0x3b1a78,
        .land = 0x5b4f8f,
        .coast = 0x7d72a8,
        .trajectory_edge = 0xa855f7,
        .trajectory_glow = 0xd8b4fe,
        .trajectory_trail = 0x8a7ade,
        .trajectory_levels = {0xe9d5ff, 0xf3e8ff, 0xfae8ff, 0xfdf4ff},
        .home_marker = 0xf0abfc,
        .destination_marker = 0xa855f7,
        .destination_arrival = 0xddd6fe,
        .panel_border = 0xa855f7,
        .header = 0xc084fc,
        .muted = 0xa5b4fc,
        .warning = 0xfbbf24,
        .error = 0xfb7185,
    },
};

const size_t GEOTRACE_THEME_COUNT = GEOTRACE_ARRAY_LEN(GEOTRACE_THEMES);

const theme *theme_default(void)
{
    return &GEOTRACE_THEMES[0];
}
