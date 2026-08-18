# Third-party licensing

notyas is distributed under GPL-3.0-or-later (see `COPYING`). This file accounts for
everything in or around the build that someone else wrote, and states why each piece
is compatible with that outbound license.

## What this repository actually redistributes

Only two kinds of third-party artifact are committed here. Everything else is fetched
at build time by cargo or by esp-idf-sys.

| Artifact | Origin | License |
|---|---|---|
| `tools/fonts/upstream/IBMPlex{Sans-Regular,Sans-SemiBold,Mono-Regular}.ttf` | IBM Plex release files, byte-identical | SIL OFL 1.1 |
| `crates/notyas-fonts/src/gen/*.rs` | Glyph atlases rasterized from those TTFs by `tools/fonts/atlasgen` | SIL OFL 1.1 (Modified Versions, renamed per clause 3) |

`LICENSE-fonts` at the repository root is the authoritative record: it identifies the
upstream releases, documents the subsetting and rasterization that make the atlases
Modified Versions, records the Reserved Font Name rename
(IBM Plex Sans/Mono -> notyas Sans/Mono), and carries the full OFL 1.1 text. The
atlases are the only font data the firmware embeds.

OFL 1.1 permits bundling with, and redistribution alongside, software under any
license, including GPL-3.0-or-later. The fonts remain under OFL; the firmware remains
under GPL-3.0.

The BIP39 English wordlist (`crates/notyas-core/src/wordlist_english.txt`) is the
normative list from the `bitcoin/bips` repository (BIP-0039). It is a specification
data table, not a copyrightable creative work in any sense we rely on; the file's
SHA-256 is pinned at compile time and re-checked at boot precisely because its exact
bytes are what matters.

## Rust dependencies

Nothing is vendored. `Cargo.lock` pins the full graph; cargo fetches it.

As of the 0.1.0 lockfile the graph resolves to 230 third-party packages (all features,
all workspace members, including host-only build and test dependencies). Every one of
them is permissively licensed - the spread is MIT, Apache-2.0, CC0-1.0, BSD-3-Clause,
0BSD, ISC, Zlib, Unlicense, MITNFA, Unicode-3.0 and dual/multi-license combinations of
those. There is no copyleft dependency, and no dependency whose license imposes a
condition GPL-3.0-or-later cannot satisfy.

Two notes on the combinations that are not plain MIT:

- **Apache-2.0** is one-way compatible with GPL-3.0: Apache-2.0 code may be combined
  into a GPLv3 work (not into a GPLv2 one). Every Apache-2.0-only dependency in the
  graph is a host-side build or tooling crate, and all of them are compatible with the
  outbound license either way.
- **`r-efi`** offers `MIT OR Apache-2.0 OR LGPL-2.1-or-later`; the MIT term is taken.
  It reaches the graph through host-side tooling and is not linked into the firmware
  image.

Reproduce the audit at any commit:

```
cargo metadata --format-version 1 --all-features \
  | python -c "import json,sys; [print(p['name'], p['version'], p['license']) for p in json.load(sys.stdin)['packages']]"
```

`tools/build-graph-check.sh` enforces a stricter, security-driven rule on top of the
license question: certain crates (RNG sources, network stacks, closed crypto blobs)
must not appear in the graph at all, per SECURITY.md invariants 1 and 3.

## ESP-IDF and the ESP component registry

The firmware links ESP-IDF v5.5.4 (FreeRTOS, drivers, bootloader), which is
**Apache-2.0** and is downloaded and managed by `esp-idf-sys`/`embuild` rather than
committed here. Apache-2.0 combines into a GPLv3 work.

Display and touch components come from the ESP component registry, pinned in
`firmware/Cargo.toml` and fetched at build time, not vendored. Licenses below are as
read from each component's own `license.txt` in a resolved build tree:

| Component | Publisher | License |
|---|---|---|
| `espressif/esp_lcd_touch_gt911` | Espressif | Apache-2.0 |
| `espressif/esp_lcd_touch` (transitive) | Espressif | Apache-2.0 |
| `espressif/esp_lcd_ek79007` | Espressif | Apache-2.0 |
| `espressif/i2c_bus` (transitive) | Espressif | Apache-2.0 |
| `espressif/cmake_utilities` (transitive, build-time) | Espressif | Apache-2.0 |
| `waveshare/esp_lcd_st7703` | Waveshare | MIT |
| `waveshare/esp_lcd_hx8394` | Waveshare | MIT |
| `waveshare/esp_lcd_ili9881c` | Waveshare | MIT |
| `waveshare/esp_lcd_jd9365_8` | Waveshare | MIT |
| `waveshare/esp_lcd_jd9365_10_1` | Waveshare | MIT |

All are GPL-3.0-compatible. Note that esp-idf-sys package metadata cannot be
feature-gated, so every board build compiles all of these components even though the
cfg-gated Rust in `firmware/src/board/` only ever calls its own board's surface.

The C headers under `firmware/bindings/` are ours: they exist only to widen the bindgen
surface and contain nothing but `#include` lines and comments.

## Hardware documentation

Vendor schematics, factory firmware and BSP sources were **read** during board
bring-up; the facts derived from them (pin numbers, panel timings, register sequences)
are recorded in `docs/research/` and `docs/HARDWARE.md`. No vendor file is
redistributed in this repository.

3D-printable enclosure models are deliberately **not** published here. Third-party
models carry their own terms which may not permit redistribution under GPL-3.0; the
question is deferred to 0.2.0 rather than answered by publishing and hoping.
