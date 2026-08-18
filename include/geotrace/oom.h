#ifndef GEOTRACE_OOM_H
#define GEOTRACE_OOM_H

#include <stddef.h>

/* OOM-aborting wrappers. Hot paths (per-packet) keep their events on the stack
 * and copy them by value through the rings, so these are reserved for
 * setup-time allocations where propagating NULL through every call site would
 * just be noise.
 *
 * On allocation failure or a size multiplication overflow: write a one-line
 * diagnostic to stderr and abort(3). Never returns NULL.
 */

void *xmalloc(size_t size);
void *xcalloc(size_t nmemb, size_t size);

#endif /* GEOTRACE_OOM_H */
