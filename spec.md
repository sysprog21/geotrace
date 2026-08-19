# Geotrace Coding Specification

This document defines coding conventions for the Geotrace project. All
documentation, comments, diagnostics, and identifiers must use American English
(`behavior`, `initialize`, `color`, not `behaviour`, `initialise`, `colour`).

## Scope

Geotrace is a C11 network-traffic visualizer. This spec applies to:

- `src/` — C11 sources (capture, resolver, geo, world map, UI, orchestrator)
- `include/geotrace/` — public headers
- `tests/` — unit-test programs
- `mk/` — GNU make fragments
- `scripts/` — build helpers (`bin2c.py`, `run-with-timeout.sh`)
- `assets/` — tracked binary blobs (e.g., the land-mask bitmap)

Keep `build/` out of commits.

## Language and tooling

- C code targets C11 strict (`-std=c11`). No GNU extensions, no
  `__sync_*`/`__atomic_*` builtins, no compiler-specific intrinsics. If the
  standard does not provide it, write it.
- POSIX only: Linux and macOS. No Windows shims, no `#ifdef _WIN32`.
- Capture goes through libpcap on both platforms (it wraps AF_PACKET on Linux
  and BPF on macOS). Do not open-code either.
- Atomics via `<stdatomic.h>`. Cross-thread scalars are `_Atomic`-qualified
  and accessed through `atomic_load_explicit` / `atomic_store_explicit`.
  Default to `memory_order_seq_cst`; weaken only with a one-line comment
  justifying it.
- `volatile` is not a synchronization primitive. Use atomics or a lock.
- Threading via pthreads, not C11 `<threads.h>` (macOS treats `<threads.h>`
  as optional).
- Build with `make` + `pkg-config`. Required flags:
  `-std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion
  -Wstrict-prototypes -Werror`. Debug builds add
  `-O0 -g -fsanitize=address,undefined`.

Common targets:

```sh
make                # release build
make debug          # ASan + UBSan
make sanitize       # ASan + UBSan build, then TSan tests
make tests          # unit tests
make check          # tests + 3-second --demo smoke run
make indent         # clang-format -i over src/ include/ tests/
```

## Naming conventions

Use `snake_case` for functions, variables, fields, typedefs, and file-local
helpers. Use uppercase for macros and constants.

| Kind | Convention | Examples |
|------|------------|----------|
| Public functions | `<module>_<action>` | `ring_create`, `geo_cache_put`, `cli_parse`, `world_set_center_lon` |
| Static helpers | `<verb>_<noun>` | `prime_demo_cache`, `drop_privileges`, `resolve_target_user` |
| Types | unsuffixed when readable; `_t` suffix when it disambiguates | `geo_point`, `connection_event`, `geotrace_flag`, `pcap_source_t` |
| Opaque types | `struct <name>`, forward-declared in the header | `struct ring`, `struct geo_cache`, `struct packet_source` |
| Macro constants | uppercase, domain prefix | `GEOTRACE_MAX_INTERFACES`, `PACKET_RING_SIZE`, `STATUS_RING_SIZE` |
| Atomic types | declared in `atomic.h` | `geotrace_flag`, `geotrace_counter` |
| Tests | `tests/test-<feature>.c` | `tests/test-ring.c`, `tests/test-ip-filter.c` |

A name should make data direction obvious. For network values, prefer `_be`
(network/big-endian) and `_host` suffixes:

```c
uint32_t ip_be;     /* wire-order, e.g., from libpcap */
uint32_t ip_host;   /* host-order via ntohl, used for cache keys and gates */
```

## Formatting

Formatting is enforced by `.clang-format` (Chromium base, customized). Run
`make indent` rather than hand-aligning. The shape:

- 4-space indent, no tabs (`UseTab: Never`, `IndentWidth: 4`).
- Linux-style braces: function opening braces on a new line; control-structure
  braces on the same line (`BreakBeforeBraces: Linux`).
- Pointer star binds to the variable name: `int *p`, not `int* p`
  (`PointerAlignment: Right`).
- Space after C-style casts: `(uint32_t) v`, not `(uint32_t)v`
  (`SpaceAfterCStyleCast: true`).
- No short single-line `if`/`case`/`for`. Always brace or break the line.
- Up to three blank lines may separate sections (`MaxEmptyLinesToKeep: 3`).
- `case` labels are not extra-indented inside `switch`
  (`IndentCaseLabels: false`).

`.editorconfig` only enforces shell-script settings (`*.sh`); C files defer
entirely to `.clang-format`.

Use early returns for error paths when they keep functions readable. Three
levels of indentation is the working ceiling — restructure before going
deeper.

## Includes

Group includes in this order, separated by one blank line, alphabetized
within each group:

1. The matching public header for the current `.c` file (if any).
2. Other project headers (`"geotrace/<name>.h"`).
3. System headers (`<stdio.h>`, `<pthread.h>`, etc.).

```c
#include "geotrace/cli.h"

#include "geotrace/oom.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
```

Project headers use the `"geotrace/<name>.h"` quoted form. Headers should
include what they use and prefer forward declarations (`struct ring;`,
`struct geo_cache;`) over pulling in full definitions.

## Comments

Use `/* ... */` only. `//` is not used in this codebase.

Quote identifiers, paths, and shell commands inside comments with double
quotes, never with backticks. Backticks are Markdown; in a C comment they are
just noise, and a reader pasting the text into a shell gets command
substitution. This applies to comments only, not to the Markdown files:

```c
/* Append "name" to "names"; "count" must be non-NULL. */   /* correct */
/* Parse a line of "ip -brief -4 addr". */                  /* correct */
```

Comment what is not obvious from the code: invariants, ownership rules,
threading constraints, byte-order boundaries, and the reason for a
non-obvious choice. Do not narrate operations the code already shows.

```c
/* Pop copies the slot under the lock so the API never hands out internal
 * pointers — that closes the put_latest UAF/ABA hazard. */
```

### Comment shape

Single-line comments stay on one line:

```c
/* Home is pinned to Taipei; self-lookup was unreliable through VPN/NAT. */
```

Multi-line comments put the first sentence on the opening line, continue
with ` *`, and keep the closing `*/` on its own line:

```c
/* SIGWINCH must NOT interrupt syscalls — it is a UI-only signal, and the
 * resize handler only flips an atomic flag the UI thread polls.
 */
```

### Section dividers

Translation units use short divider comments to mark sections. Keep them
one line; the `----` run is part of the project pattern, not arbitrary
decoration:

```c
/* ---- privilege drop -------------------------------------------------- */
```

The divider must name a real section. Don't pad with `=` or `─` runs, and
don't use it for groups smaller than ~30 lines.

### Markers

- `NOTE:` — context that prevents a future wrong simplification.
- `WARNING:` — behavior that affects threading, signals, or capture safety.
- `FOLLOW-UP:` — actionable follow-up, with enough context to act on it later.
  Long-lived follow-ups belong in the project backlog, not the source.

Avoid filler words (`Step 1`, `simply`, `just`, restating the next line).

### File banners

Source and header files do not carry per-file copyright or SPDX banners —
top-level `LICENSE` and `README.md` hold license metadata. A short
multi-line comment at the top of a `.c`/`.h` file is fine when it explains
the module's purpose (see `tests/test-ring.c`); it is not required.

## Headers

Use `#ifndef GEOTRACE_<MODULE>_H` guards, not `#pragma once`. The
`geotrace/` prefix avoids collisions if a header is ever consumed under a
broader include path:

```c
#ifndef GEOTRACE_CLI_H
#define GEOTRACE_CLI_H

/* declarations */

#endif /* GEOTRACE_CLI_H */
```

Pair module APIs as `name.c` + `include/geotrace/name.h`. Keep file-local
helpers `static` in the `.c` file.

## Types and byte-order boundaries

Use fixed-width integer types for wire formats, BPF-visible fields, and any
data crossing the network/host boundary:

```c
uint32_t ip_be;        /* wire, network-order */
uint32_t ip_host;      /* host-order via ntohl */
uint16_t port_be;      /* wire */
```

Convert at the wire boundary, once. Do not scatter `ntohl`/`ntohs` calls
through the pipeline. Cache keys, range tables, and `is_public_ipv4`
arguments are host-order.

Use `size_t`, `ssize_t`, `int`, and standard POSIX types for host APIs and
local lengths. `created_at` is `struct timespec` from
`clock_gettime(CLOCK_MONOTONIC)` — wall clock only at the display
boundary, so NTP drift or manual clock changes can't warp event ages.

Strings crossing thread boundaries pass by value via fixed-size buffers
embedded in the event structs (`char ip[INET_ADDRSTRLEN]`,
`char country[64]`). The codebase deliberately avoids pointer-and-length
slices for cross-thread state; that closes the lifetime question entirely.

## Memory and allocation

- Allocate through `xmalloc`/`xcalloc` from `oom.h`. They abort
  on failure; propagating `NULL` through every call site is noise.
- Hot-path packet structs live on the stack or in fixed-size ring slots.
- Do not introduce ad-hoc allocators.

## Concurrency

- One capture thread per interface (MPSC producer), one resolver thread,
  one UI thread.
- Cross-thread scalars are atomic. The single project-wide flag type
  (`geotrace_flag`) lives in `atomic.h` with its accessors and orderings
  documented inline; document any new flag in the same file.
- Rings are bounded and lossy. The producer evicts the oldest slot on
  overflow (`put_latest`). Capture must never block on the UI.
- Each `struct ring` and `struct geo_cache` carries its own mutex. There
  is no nested locking today; if you add nested locking, document the
  acquire order before using it from more than one site.
- Two UI-visible queues, no tagged union: `connection_ring` carries
  resolved events and `status_ring` carries banner messages. The hot path
  never branches on event type.
- Signal handlers do nothing except flip atomics or call `pcap_breakloop`.
  SIGINT/SIGTERM are installed without `SA_RESTART` so blocked syscalls
  return `EINTR`. SIGWINCH is installed *with* `SA_RESTART` (it is
  UI-only). SIGPIPE is ignored.

## Capture and privilege

- libpcap is touched only when live capture is requested. `--demo` builds
  must run on a box without libpcap installed. `#ifdef HAVE_PCAP` is
  driven by `pkg-config` in `mk/deps.mk`.
- `cli_ensure_capture_privileges` re-execs through sudo when needed,
  using an absolute self path (`/proc/self/exe` on Linux,
  `_NSGetExecutablePath` on macOS). It appends
  `--drop-uid=$(getuid)` / `--drop-gid=$(getgid)`; do not trust
  `SUDO_UID` / `SUDO_GID` env (attacker-influenceable).
- Privilege drop runs after `pcap_open_live` and BPF compilation:
  `setgroups(0, NULL)` → `setgid` → `setuid` → `setuid(0)` sanity check.
  Refuse uid/gid 0; verify identities via `getpwuid` / `getgrgid`.

## World map

- Embed the land-mask blob from `assets/land-mask.bin` via
  `scripts/bin2c.py`. Do not use `xxd -i` — its output differs between
  BSD and GNU.
- Static layers (grid + land + coast) are cached by
  `(width, height, theme)`; only the dynamic layer redraws per frame.
  Cache invalidation is driven by a `geotrace_flag` raised in the SIGWINCH
  handler and consumed by the UI thread — never mutate the cache from a
  signal handler.
- `geo_to_canvas` is the single equirectangular projection. Trajectories
  use great-circle arcs and a continuously interpolated ramp over the
  per-theme trajectory stops.
- Adding a theme means extending the theme table — the CLI mutex group
  is derived from it. One source of truth, no "extend two places" wart.

## Tests

Unit tests are plain C programs in `tests/test-<feature>.c` registered via
`mk/tests.mk`. They use `<assert.h>` directly — there is no custom test
harness:

```c
static void test_empty_take_returns_after_shutdown(void)
{
    struct ring *r = ring_create(4, sizeof(int));
    int v = 0xdead;

    assert(!ring_try_take(r, &v));
    assert(v == 0xdead);

    ring_shutdown(r);
    assert(!ring_take(r, &v));

    ring_destroy(r);
}

int main(void)
{
    test_empty_take_returns_after_shutdown();
    /* ... */
    return 0;
}
```

Add new tests by extending `mk/tests.mk` with a `test-framework`
instantiation (crib from the existing entries). Run them under both
`make tests` (release) and `make sanitize` (address, undefined, and thread
sanitizers) before
declaring a feature done.

## File organization

Module ownership in `src/`:

- `main.c` — CLI parsing entry, ring/source/cache lifecycle, signal
  install, privilege drop, UI loop driver.
- `resolver.c` — the middle pipeline stage: packet ring in, geo lookup,
  connection ring out.
- `cli.c` — `getopt_long` parsing, theme mutex, sudo re-exec.
- `platform.c` — interface detection and listing
  (Linux `ip` / macOS `getifaddrs`).
- `geo.c` — `is_public_ipv4`, geo cache, raw-TCP HTTP/1.1 client against
  `ip-api.com`.
- `demo-source.c` / `pcap-source.c` — push-API packet sources behind
  `struct packet_source`.
- `world-map.c` — projection, braille glyph composition, static-layer
  cache, trajectories.
- `ui.c` — `termios` raw mode, double-buffered ANSI render, status
  banner, resize handling.
- `theme.c` — theme table, single source of truth for the CLI mutex
  group.
- `oom.c`, `ring.c` — utilities used everywhere.

Public headers live in `include/geotrace/`; private helpers stay `static`
in the owning `.c` file. Keep new code near the owner of the state it
mutates.

## American English reference

| Correct | Avoid |
|---------|-------|
| behavior | behaviour |
| initialize | initialise |
| serialize | serialise |
| color | colour |
| canceled | cancelled |
| gray | grey |
| dialog | dialogue |
| analog | analogue |
