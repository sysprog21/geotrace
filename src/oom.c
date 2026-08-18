#include "geotrace/oom.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static void die_oom(const char *what, size_t bytes)
{
    fprintf(stderr, "geotrace: out of memory in %s (%zu bytes)\n", what, bytes);
    abort();
}

void *xmalloc(size_t size)
{
    void *p = malloc(size);
    if (!p && size)
        die_oom("xmalloc", size);
    return p;
}

void *xcalloc(size_t nmemb, size_t size)
{
    if (nmemb != 0 && size > SIZE_MAX / nmemb)
        die_oom("xcalloc overflow", SIZE_MAX);
    void *p = calloc(nmemb, size);
    if (!p && nmemb && size)
        die_oom("xcalloc", nmemb * size);
    return p;
}
