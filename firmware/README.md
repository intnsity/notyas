# notyas-firmware

std Rust on ESP-IDF for ESP32-P4 touch-display boards. Milestone 0.1.0-m2:
display and GT911 touch up from Rust - the Butter Paper demo shell renders,
touches are drawn live and logged. Multi-board per docs/BOARDS.md: exactly one
`board-*` cargo feature selects the hardware at compile time (the build IS the
board - no default feature, no runtime detection).

| Board feature | Hardware | Status |
|---|---|---|
| `board-waveshare-4b` | Waveshare ESP32-P4-WiFi6-Touch-LCD-4B, 720x720 DSI | verified on hardware |
| `board-elecrow-5` | Elecrow CrowPanel Advanced 5inch, 800x480 RGB | verified on hardware |
| `board-elecrow-7` / `-9` / `-101` | Elecrow CrowPanel Advanced 1024x600 DSI | UNTESTED scaffolds |

Board modules live in `src/board/<name>.rs` behind one flat surface
(BOARDS.md, normative); everything else is board-agnostic.

## Toolchain (exact versions, proven 2026-08-17)

| Component | Version |
|---|---|
| Rust | nightly-2026-07-27 (rustc 1.99.0-nightly, dc3f85158 2026-07-26) + rust-src |
| Target | riscv32imafc-esp-espidf (Tier 3, -Zbuild-std=std,panic_abort) |
| ESP-IDF | v5.5.4, managed by esp-idf-sys/embuild, installed to C:\Users\<user>\.espressif |
| esp-idf-svc / -hal / -sys | 0.52.1 / 0.46.2 / 0.37.2 |
| embuild | 0.33.3 |
| ldproxy | 0.3.5 |
| espflash | 4.5.0 |
| libclang (bindgen) | libclang.dll from the `libclang` pip wheel (see below) |

Why IDF is v5.5.4 and not v5.5.5: v5.5.5 backports new struct fields
(`sdmmc_host_t.unaligned_multi_block_rw_max_chunk_size`,
`esp_lcd_dsi_bus_config_t.flags`) that break esp-idf-hal 0.46.2's struct
initializers (E0063). v5.5.4 is the newest v5.5.x the pinned crates build
against; revisit when esp-idf-hal > 0.46.2 ships.

Why the nightly is pinned to 2026-07-27 and must NOT be bumped blindly:
rust-lang/rust#158168 (merged 2026-07-29) added `set_perm_nofollow` to std whose
non-Linux fallback references `libc::AT_FDCWD`, which the espidf libc does not
define. Any nightly from 2026-07-29 on fails `-Zbuild-std` with E0425 for this
target until that is fixed upstream.

## Chip revision config (make-or-break)

Both dev boards' silicon is **rev v1.3** - the pre-v3.0 engineering-sample
family. IDF v5.5 defaults to `CONFIG_ESP32P4_REV_MIN_301` (rev >= v3.1), and
the two families are not binary compatible: an image built for v3.x flashes
fine on v1.3 silicon and then prints nothing (ROM banner
`ESP-ROM:esp32p4-eco2-20240710` repeating = boot loop). sdkconfig.base.defaults
therefore pins:

```
CONFIG_ESP32P4_SELECTS_REV_LESS_V3=y   # pre-v3.0 family; caps REV_MAX_FULL at 199
CONFIG_ESP32P4_REV_MIN_100=y           # minimum rev v1.0 (numbering: REV_MIN_FULL = major*100+minor;
                                       # ESP32P4_REV_MIN_1 would mean v0.1, not v1.x)
```

**Release builds for production hardware (rev >= v3.1) must revisit this** -
drop `SELECTS_REV_LESS_V3` and pin `ESP32P4_REV_MIN_301`. One image cannot
serve both families.

## sdkconfig layout

```
firmware/sdkconfig.base.defaults        # shared; nothing board-specific
firmware/boards/<board>/sdkconfig.defaults  # per-board overlay (flash size)
```

build.ps1 passes both (absolute, semicolon-separated) via
`ESP_IDF_SDKCONFIG_DEFAULTS`; later file wins. `.cargo/config.toml` carries a
waveshare-4b default pair so a bare `cargo build` stays safe on the reference
board - build any other board through build.ps1 (see pitfall 8).

## Build / flash / monitor

Prerequisites (one-time):

```powershell
rustup toolchain install nightly-2026-07-27 --component rust-src
cargo install ldproxy espflash --locked   # espflash >= 4.5 for P4
python -m pip install --user libclang     # provides libclang.dll for bindgen
```

git and python must be on PATH; esp-idf-sys downloads and manages ESP-IDF
v5.5.4 plus cmake/ninja/toolchains itself on first build (multi-GB, one-time,
into C:\Users\<user>\.espressif because ESP_IDF_TOOLS_INSTALL_DIR=global).

Then, from anywhere:

```powershell
# Waveshare 4B (COM3):
\\172.16.0.9\bear\code\btc\notyas\tools\build.ps1 -Board waveshare-4b
\\172.16.0.9\bear\code\btc\notyas\tools\flash.ps1 -Board waveshare-4b -Monitor

# Elecrow CrowPanel Advanced 5inch (COM6):
\\172.16.0.9\bear\code\btc\notyas\tools\build.ps1 -Board elecrow-5
\\172.16.0.9\bear\code\btc\notyas\tools\flash.ps1 -Board elecrow-5 -Monitor
```

`-Board` drives the cargo feature, the sdkconfig pair, the per-board
CARGO_TARGET_DIR (C:\nyt-ws, C:\nyt-e5, C:\nyt-e7, C:\nyt-e9, C:\nyt-e101),
espflash `--flash-size` (32mb/16mb) and the default port (COM3/COM6; port
letters drift - override with `-Port COMx`). Per-board target dirs mean
switching boards never needs a clean, and flash.ps1's
newest-bootloader-under-esp-idf-sys search can no longer pick up another
board's bootloader.

Notes the scripts encode:

- Sources build fine directly from the UNC share, but CARGO_TARGET_DIR must be
  a **short local path**. esp-idf-sys hard-fails with "Too long output
  directory" otherwise - Windows path-length limits in the IDF CMake/ninja
  build. Override with NOTYAS_TARGET_DIR (keep it short AND per-board).
- `LIBCLANG_PATH` must point at a dir containing libclang.dll. The esp-clang
  tool embuild installs does not ship one on Windows; the `libclang` pip wheel
  does (`%APPDATA%\Python\Python312\site-packages\clang\native`).
- flash.ps1 flashes the bootloader and partition table produced by the IDF
  build, never espflash's bundled ones - the bundled bootloader is built for
  default (v3.x-family) config and does not boot on this chip.
- Monitor manually: `espflash monitor --port COM3` (115200 baud; Ctrl-C exits).

## What 0.1.0-m2 does

Boot sequence in `src/main.rs` (board-agnostic; hardware in `src/board/`),
in load-bearing order:

1. `esp_idf_svc::sys::link_patches()` + EspLogger init.
2. **Airgap lockdown first**: `board::radio_lockdown()` drives the board's
   C6 kill line low and holds it for the whole power cycle - the radio chip
   sits in reset. Waveshare: GPIO54. Elecrow 5inch: GPIO20 (the C6 EN pullup
   means the C6 ran from power-on until this line; logged, not hidden - see
   BOARDS.md). The board name, flash size, and RADIO_KILL_DOC are logged
   verbatim; scaffold boards additionally log `UNTESTED BOARD CONFIG`.
3. `board::display_init()` - all panel bring-up quirks live per board:
   - waveshare_4b: LDO ch3 2500 mV (DPHY) + ch4 3300 mV; 2-lane DSI at
     480 Mbps; ST7703 via `waveshare/esp_lcd_st7703` (720x720 RGB565, DPI
     38 MHz); backlight enable (GPIO33) held low until first frame.
   - elecrow_5: STC8 backlight blanked over I2C (proves STC8 comms); LDO ch4
     3300 mV (GPIO45-54 bank; ch3 is camera-only - skipped); core-IDF
     `esp_lcd_new_rgb_panel` (800x480 RGB565 DE mode, pclk 25 MHz, pins and
     timings verbatim from Elecrow factory `bsp_display.h`).
   Either way the driver allocates the framebuffer in PSRAM; we draw into it
   directly and publish via `esp_lcd_panel_draw_bitmap`'s no-copy cache-sync
   path (verified for both the DPI and RGB drivers in IDF v5.5.4).
   `display::Display` implements `embedded_graphics::DrawTarget` at the
   board's resolution; the shell lays out from fractions of it.
4. Butter Paper shell painted (tokens in `src/theme.rs`), then
   `board::backlight_set(80)`: LEDC PWM GPIO26 inverted (waveshare) / one
   I2C register write to the STC8 co-MCU at 0x2F reg 0x20 (elecrow-5).
5. `board::touch_init()`:
   - waveshare_4b: manual GT911 reset (GPIO23) + 120 ms wake, probe
     0x5D/0x14, driver gets rst=int=NC (INT unrouted; see pitfall 7).
   - elecrow_5: factory sequence - driver owns RST (GPIO36) and INT
     (GPIO42) and straps the address deterministically to 0x5D.
6. Main loop: poll GT911 every 25 ms; on a new touch point, log
   `touch x=.. y=..` and repaint the status line; heartbeat once per second.

## Captured boot log - Waveshare 4B (COM3, 2026-08-17, multi-board refactor)

Behavior identical to the pre-refactor m2 log (module paths in log tags
changed to `board::waveshare_4b`). GT911 address was 0x14 on this cycle; it
can legitimately be 0x5D on others (pitfall 7).

```
I (30) boot: chip revision: v1.3
I (42) boot.esp32p4: SPI Flash Size : 32MB
I esp_psram: Found 32MB PSRAM device
I esp_psram: Speed: 200MHz
I (1187) notyas_firmware::board::waveshare_4b: C6 radio held in reset (GPIO54 low)
I (1194) notyas_firmware: board: Waveshare ESP32-P4-WiFi6-Touch-LCD-4B | flash 32 MB | radio kill GPIO54
I (1226) notyas_firmware::board::waveshare_4b: LDO channel 3 acquired at 2500 mV (MIPI DPHY)
I (1234) notyas_firmware::board::waveshare_4b: LDO channel 4 acquired at 3300 mV (GPIO39-48 bank)
I (1244) notyas_firmware::board::waveshare_4b: DSI bus up: 2 lanes, 480 Mbps/lane
I (1250) st7703: version: 2.0.0
I (1694) notyas_firmware::board::waveshare_4b: ST7703 panel initialized (720x720 RGB565, DPI 38 MHz)
I (1694) notyas_firmware::board::waveshare_4b: DPI framebuffer at 0x480b0a80 (PSRAM)
I (1716) notyas_firmware::board::waveshare_4b: backlight PWM duty set to 80%
I (1859) notyas_firmware::board::waveshare_4b: GT911 responds at i2c address 0x14
I (1871) notyas_firmware::touch: GT911 initialized: product id "911" ([39, 31, 31, 00]), polled mode, reset GPIO23
I (1880) notyas_firmware: notyas 0.1.0-m2 shell up on Waveshare ESP32-P4-WiFi6-Touch-LCD-4B
I (2903) notyas_firmware: notyas 0.1.0-m2 | IDF v5.5.4 | free heap 32264868 bytes
```

34 s monitored, no watchdog, steady heap, zero errors.

## Captured boot log - Elecrow CrowPanel Advanced 5inch (COM6, 2026-08-17)

Two consecutive boots byte-identical apart from millisecond jitter. Note the
lockdown warning: on this board the C6 EN pullup means the radio co-processor
ran from power-on until app_main's first line (BOARDS.md documents this and
the hardware mitigation for production units).

```
I (30) boot: chip revision: v1.3
I (42) boot.esp32p4: SPI Flash Size : 16MB
I esp_psram: Found 32MB PSRAM device
I esp_psram: Speed: 200MHz
I (1195) notyas_firmware::board::elecrow_5: C6 radio held in reset (GPIO20 low)
W (1201) notyas_firmware::board::elecrow_5: C6 power-on window: C6 EN is pulled up (R77) - the C6 ran from power-on until this line; hardware-held in reset from here on
I (1216) notyas_firmware: board: Elecrow CrowPanel Advanced 5inch ESP32-P4 | flash 16 MB | radio kill GPIO20
I (1257) notyas_firmware::board::elecrow_5: backlight set to 0% (STC8 0x2F reg 0x20)
I (1265) notyas_firmware::board::elecrow_5: LDO channel 4 acquired at 3300 mV (GPIO45-54 bank)
I (1278) notyas_firmware::board::elecrow_5: RGB panel initialized (800x480 RGB565 DE mode, pclk 25 MHz)
I (1282) notyas_firmware::board::elecrow_5: RGB framebuffer at 0x480b0a80 (PSRAM)
I (1302) notyas_firmware::board::elecrow_5: backlight set to 80% (STC8 0x2F reg 0x20)
I (1373) GT911: TouchPad_ID:0x39,0x31,0x31
I (1373) GT911: TouchPad_Config_Version:99
I (1373) notyas_firmware::board::elecrow_5: GT911 at i2c address 0x5D (driver-strapped via INT GPIO42)
I (1379) notyas_firmware::touch: GT911 initialized: product id "911" ([39, 31, 31, 00]), polled mode, reset GPIO36 (driver-managed), int GPIO42
I (1391) notyas_firmware: notyas 0.1.0-m2 shell up on Elecrow CrowPanel Advanced 5inch ESP32-P4
I (2414) notyas_firmware: notyas 0.1.0-m2 | IDF v5.5.4 | free heap 32562936 bytes
```

34 s monitored per boot, no watchdog, steady heap, zero errors. The GT911
address is deterministic here (0x5D, INT-strapped by the driver) - unlike the
Waveshare board's floating-INT coin flip.

## Pitfalls hit while proving this (all encoded in config/scripts now)

1. sdkconfig.defaults silently ignored: esp-idf-sys's root-crate autodiscovery
   runs `cargo metadata` where it cannot find Cargo.toml, so the build used
   stock IDF defaults (rev v3.1+, 2MB flash) and the image crashed with an
   illegal instruction AT the bootloader entry address. Fixed by pinning
   `ESP_IDF_SDKCONFIG_DEFAULTS` in .cargo/config.toml (and per-board in
   build.ps1). If the monitor ever shows a Guru Meditation with PC == the
   `entry` address from the ROM lines, check the generated sdkconfig's
   `ESP32P4_REV_MIN_FULL` first.
2. Stale bootloader copy: `<target>\<profile>\build\bootloader.bin` is not
   always refreshed; flash.ps1 uses the newest one from the esp-idf-sys out
   dir instead - and since the refactor, per-board target dirs make a
   wrong-board bootloader impossible by construction.
3. Long target paths: esp-idf-sys refuses CARGO_TARGET_DIR paths that are too
   long ("Too long output directory") - hence C:\nyt-ws / C:\nyt-e5 / ...
4. Pre-v3 eFuse table differences: `esp_chip_info` is not in the default
   esp-idf-sys binding allowlist, and on the pre-v3 table the wafer major
   version is split into LO(2b)/HI(1b) fields - compose `(HI << 2) | LO`
   exactly like IDF's efuse_ll.h.
5. `[[package.metadata.esp-idf-sys.extra_components]]` silently ignored
   (remote components never downloaded, bindings never generated): embuild
   guesses the workspace dir by walking UP FROM OUT_DIR, which lives under
   CARGO_TARGET_DIR, not next to the sources - so its `cargo metadata` probe
   finds no Cargo.toml and ALL package metadata is dropped. Same root cause
   as pitfall 1, different symptom. Fixed by pinning
   `CARGO_WORKSPACE_DIR = { value = "", relative = true }` in
   .cargo/config.toml. Note: esp-idf-sys does not rerun its build script
   when that env changes - `cargo clean -p esp-idf-sys` once after adding it.
6. Boot-loop abort before app_main after adding the GT911 component:
   `E i2c: CONFLICT! driver_ng is not allowed to be used with this old
   driver`. esp-idf-hal (via esp-idf-svc) links the legacy driver/i2c.h
   symbols, our touch path uses the new i2c_master API, and the legacy
   driver's startup constructor abort()s when both are linked. We never
   install the legacy driver at runtime, so sdkconfig sets
   `CONFIG_I2C_SKIP_LEGACY_CONFLICT_CHECK=y` (IDF's escape hatch for
   exactly this).
7. GT911 init failing intermittently with `touch_gt911_read_cfg: GT911 read
   error!`, address flipping between 0x5D and 0x14 across boots (Waveshare
   only): the GT911 re-latches its I2C address from the INT level at every
   reset release, and INT is unrouted on that board (floats). The
   esp_lcd_touch_gt911 driver pulses reset itself and reads config
   immediately, racing the chip's ~50 ms post-reset wake-up. Fix in
   board/waveshare_4b.rs: reset the chip manually (GPIO23, 10 ms low, then
   120 ms wake-up), probe for whichever address got latched, and hand the
   driver `rst_gpio_num = NC` so it cannot re-reset and re-randomize the
   address. Also: the first coordinate read after reset reports a phantom
   point (observed 481,481) - init does one throwaway read (shared code,
   touch.rs). On the Elecrow boards INT is routed, so the driver-managed
   sequence is deterministic (0x5D) and used as-is.
8. Bare `cargo build --features board-<x>` builds the WAVESHARE sdkconfig
   pair (the safe in-repo default): for any other board the image gets the
   wrong flash-size header. Always build through `tools/build.ps1 -Board` -
   it pins the right pair with absolute paths.
9. esp-idf-sys package metadata cannot be feature-gated: every board build
   compiles all extra components (st7703, gt911, ek79007) and carries the
   full binding surface. Only the selected board's Rust module ever calls
   its own surface; keep this in mind when auditing the C side of an image.
10. One CARGO_TARGET_DIR per board, always. The IDF build dir bakes in the
    merged sdkconfig; reusing a dir across boards resurrects the stale-
    bootloader hazard the per-board dirs were introduced to kill.
