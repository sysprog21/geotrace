#ifndef GEOTRACE_UI_H
#define GEOTRACE_UI_H

#include "geotrace/atomic.h"
#include "geotrace/models.h"
#include "geotrace/ring.h"
#include "geotrace/theme.h"

#include <stddef.h>

/* Hand-rolled ANSI UI.
 *
 * - Double-buffered: previous frame kept around so the renderer emits only
 *   the cells that changed.
 * - Connections ring + status ring are drained per frame.
 * - SIGWINCH support: a resize_pending atomic, set by the orchestrator's
 *   handler, triggers a re-read of window dimensions and cache invalidation.
 *
 * The orchestrator (main.c) is responsible for installing termios cleanup
 * handlers around ui_run.
 */

struct ui_context;

typedef struct {
    struct ring *connections;
    struct ring *statuses;
    const theme *theme;
    geo_point home;
    int fps; /* clamped 1..60 */
} ui_options;

struct ui_context *ui_create(const ui_options *opts);
void ui_destroy(struct ui_context *ui);

/* Main loop. Returns when stop is raised. */
void ui_run(struct ui_context *ui, geotrace_flag *stop, geotrace_flag *resize);

/* Locale + terminal capability probe. Prints warnings to stderr. Idempotent and
 * side-effect-free beyond the prints.
 */
void ui_check_terminal(void);

#endif /* GEOTRACE_UI_H */
