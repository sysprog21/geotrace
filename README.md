# Geotrace

`Geotrace` visualizes outbound public IPv4 traffic as a terminal-native world map.
It shows where the machine is communicating, how quickly destinations are resolved,
and which routes are active—without a browser or desktop UI.

> [!IMPORTANT]
> Live capture requires root (libpcap uses `AF_PACKET` on Linux and BPF on macOS). Run geotrace as the invoking user and let it re-exec itself through `sudo`; it opens pcap handles with elevated privileges, then drops the process back to the invoking UID/GID before the resolver and UI run. Starting it under `sudo` directly is rejected unless both `--drop-uid` and `--drop-gid` are supplied. Use `--demo` to run without capture privileges. The home marker is fixed at Taipei (25.0330° N, 121.5654° E).

## Features

- Braille world map — 2×4 dot sub-pixel layer, equirectangular projection, embedded Natural Earth 1:110m land mask.
- libpcap capture — one thread per interface, BPF-level filter, MPSC ring into the resolver.
- GeoIP — caching `ip-api.com` client with authoritative-miss caching and a cooldown after rate limiting.
- Privilege drop — pcap handles open as root; the whole process then drops to the invoking UID/GID before the resolver and UI run.
- Great-circle traces — spherical arcs projected onto the terminal map with a continuously interpolated per-theme gradient, from the home pin to remote endpoints.
- Static-layer caching — grid, land, and coastline layers are cached by `(width, height, theme)`; SIGWINCH only sets an atomic resize flag.
- Live counters and status banner — `captured / mapped / geo_miss` plus the latest source/resolver message, drained from a separate `status_ring`.
- Hand-rolled ANSI UI — truecolor, double-buffered with per-cell diff. No ncurses, no Rich, no Textual.

## Build

Requirements
- Linux (tested on Fedora) or macOS.
- libpcap, zlib (linked via `pkg-config`).
- Root privileges for live capture, supplied automatically through the sudo re-exec path; `--demo` runs unprivileged with synthetic events.
- Network access for live GeoIP lookups; `--demo` uses its built-in demo data.


Build dependencies: a C11 compiler, GNU `make`, `pkg-config`, `libpcap`, `zlib`, and Python 3 for `scripts/bin2c.py`, which embeds `assets/land-mask.bin` as a C array during the build.

```bash
make                  # release: -O2 -g, ./build/geotrace
make debug            # ASan + UBSan
make sanitize         # ASan + UBSan build, then ThreadSanitizer tests
make check            # build, unit tests, 3 s --demo smoke
make install          # PREFIX=/usr/local by default
```

## Run

```bash
build/geotrace --demo                 # synthetic events, no root, no libpcap
build/geotrace --list-interfaces      # auto-selected marked with "*"
make run                                # builds, then live capture (re-execs sudo)
make run ARGS="--demo --green"
build/geotrace -i tun0,en0            # force a VPN + default-route pair
build/geotrace --green                # themes: --green / --red / --violet
build/geotrace --no-auto-sudo         # opt out of the sudo re-exec path
build/geotrace --fps=30               # 1..60, default 12
```

## License

`Geotrace` is available under a permissive
[MIT](https://opensource.org/license/mit)-style license.
Use of this source code is governed by a MIT license that can be found
in the [LICENSE](LICENSE) file.
