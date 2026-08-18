# notyas-firmware

std Rust on ESP-IDF for ESP32-P4 touch-display boards. Milestone 0.1.0-m3:
the full product is integrated - notyas-core's boot self-test runs before any
peripheral, the real notyas-ui screens replace the m2 demo shell, and the
Verify screen shows only values READ at boot (running-partition SHA256, eFuse
state, radio pad readback - SECURITY.md invariant 5). Multi-board per
docs/BOARDS.md: exactly one `board-*` cargo feature selects the hardware at
compile time (the build IS the board - no default feature, no runtime
detection).

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

## What 0.1.0-m3 does

Boot sequence in `src/main.rs` (board-agnostic; hardware in `src/board/`),
in load-bearing order:

1. `esp_idf_svc::sys::link_patches()` + EspLogger init.
2. **Airgap lockdown first**: `board::radio_lockdown()` drives the board's
   C6 kill line low and holds it for the whole power cycle - the radio chip
   sits in reset. Waveshare: GPIO54 (no EN pullup - the C6 is held down from
   power-on too; docs/research/waveshare-family.md). Elecrow 5inch: GPIO20
   (the C6 EN pullup means the C6 ran from power-on until this line; logged,
   not hidden - see BOARDS.md). The board name, flash size, and
   RADIO_KILL_DOC are logged verbatim; scaffold boards additionally log
   `UNTESTED BOARD CONFIG`.
3. **Boot self-test** (`notyas_core::selftest::run()`), before any
   peripheral: 6 checks over pinned vectors, each logged, 491 ms measured on
   both boards (the PBKDF2 vector dominates). On failure the display still
   comes up and a dedicated failure screen paints the per-check verdicts
   (SECURITY.md invariant 5: hard failure surfaced on screen, not a silent
   brick), then the device parks - it refuses to run the UI over a crypto
   core that failed its own vectors. The failure screen is deliberately NOT
   a notyas-ui screen: it draws with notyas-fonts directly, so it renders
   even when the crate stack under test is what failed.
4. `board::display_init()` - all panel bring-up quirks live per board:
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
   board's resolution; notyas-ui lays out from it.
5. `Ui::new(board::DISPLAY_WIDTH, board::DISPLAY_HEIGHT)` +
   `ui.set_verify_info(verify::build(&selftest))` - `src/verify.rs` reads
   every Verify-screen value at boot: running-app SHA256 through
   `esp_ota_get_running_partition` + `esp_partition_get_sha256` (~290 ms
   over the 2.5 MB image), secure-boot and flash-encryption eFuse state,
   chip revision via `efuse_hal_chip_revision`, the kill line's pad level
   read back, IDF version, board name, firmware semver. Source id reports
   "unavailable" until the release tooling ships it - never a fake value.
6. First frame drawn and published, timed once (it IS the steady-state
   frame time, since every frame is a full repaint): **20 ms draw + <1 ms
   publish at 720x720** (Waveshare), **17 ms + <1 ms at 800x480** (Elecrow).
   Then `board::backlight_set(80)`: LEDC PWM GPIO26 inverted (waveshare) /
   one I2C register write to the STC8 co-MCU at 0x2F reg 0x20 (elecrow-5).
7. `board::touch_init()`:
   - waveshare_4b: manual GT911 reset (GPIO23) + 120 ms wake, probe
     0x5D/0x14, driver gets rst=int=NC (INT unrouted; see pitfall 7).
   - elecrow_5: factory sequence - driver owns RST (GPIO36) and INT
     (GPIO42) and straps the address deterministically to 0x5D.
8. Main loop, every 25 ms: poll the GT911 and synthesize `TouchEvent`s from
   the poll stream (point after none = Down, point after point = Move, none
   after point = Up at the last seen point) -> `ui.touch()` -> full-screen
   `ui.draw()` into the framebuffer -> publish. Down/Up and screen
   transitions are logged (ScreenId carries no data - safe to log);
   heartbeat once per second.

The partition table is the in-repo `firmware/partitions.csv`: a single 4 MB
factory app partition and nothing else (no NVS, no phy_init, no otadata -
SECURITY.md invariant 2), identical on both boards so the running-partition
hash procedure is board-independent. flash.ps1 writes it explicitly (see
pitfall 11).

## Captured boot log - Waveshare 4B (COM3, 2026-08-17, 0.1.0-m3)

GT911 address was 0x14 on this cycle; it can legitimately be 0x5D on others
(pitfall 7). Long verify lines abbreviated with `[...]`.

```
I (30) boot: chip revision: v1.3
I (42) boot.esp32p4: SPI Flash Size : 32MB
I (59) boot:  0 factory          factory app      00 00 00010000 00400000
I esp_psram: Found 32MB PSRAM device
I esp_psram: Speed: 200MHz
I (1707) notyas_firmware::board::waveshare_4b: C6 radio held in reset (GPIO54 low; no EN pullup - C6 held down from power-on)
I (1717) notyas_firmware: board: Waveshare ESP32-P4-WiFi6-Touch-LCD-4B | flash 32 MB | radio kill GPIO54
I (2235) notyas_firmware: selftest: wordlist      pass
I (2235) notyas_firmware: selftest: dice raw      pass
I (2235) notyas_firmware: selftest: dice fixed    pass
I (2238) notyas_firmware: selftest: bip39 seed    pass
I (2243) notyas_firmware: selftest: bip84 account pass
I (2248) notyas_firmware: selftest: bip86 taproot pass
I (2253) notyas_firmware: selftest: 6/6 passed in 491 ms
I (2726) notyas_firmware::board::waveshare_4b: ST7703 panel initialized (720x720 RGB565, DPI 38 MHz)
I (3023) notyas_firmware::verify: app sha256 (running partition, hashed in 291 ms): bce60175fbbeb380e14dd558b78b8fa02f1eff8685803d485cf20aaf74b80322
I (3025) notyas_firmware: verify: fw 0.1.0 | Waveshare ESP32-P4-WiFi6-Touch-LCD-4B | ESP-IDF v5.5.4 | ESP32-P4 rev v1.3
I (3036) notyas_firmware: verify: radio: kill GPIO54 reads LOW (C6 held in reset) | GPIO54 -> ESP32-C6 CHIP_PU (EN) [...]
I (3075) notyas_firmware: verify: secure boot: disabled (dev unit; release units burn Secure Boot v2 RSA-3072) | flash encryption: disabled (dev unit; release units enable XTS-AES)
I (3112) notyas_firmware: frame time: draw 20 ms + publish 0 ms (720x720 full repaint)
I (3112) notyas_firmware::board::waveshare_4b: backlight PWM duty set to 80%
I (3263) notyas_firmware::board::waveshare_4b: GT911 responds at i2c address 0x14
I (3284) notyas_firmware: notyas 0.1.0 ui up on Waveshare ESP32-P4-WiFi6-Touch-LCD-4B
I (4300) notyas_firmware: notyas 0.1.0 | IDF v5.5.4 | free heap 30450584 bytes
I (77714) notyas_firmware: notyas 0.1.0 | IDF v5.5.4 | free heap 30450584 bytes
```

78 s monitored, no watchdog, free heap byte-identical (30450584) across all
72 heartbeats, zero errors.

## Captured boot log - Elecrow CrowPanel Advanced 5inch (COM6, 2026-08-17, 0.1.0-m3)

Note the lockdown warning: on this board the C6 EN pullup means the radio
co-processor ran from power-on until app_main's first line (BOARDS.md
documents this and the hardware mitigation for production units). The
Waveshare board has no such window (no EN pullup).

```
I (30) boot: chip revision: v1.3
I (42) boot.esp32p4: SPI Flash Size : 16MB
I (59) boot:  0 factory          factory app      00 00 00010000 00400000
I esp_psram: Found 32MB PSRAM device
I esp_psram: Speed: 200MHz
I (1667) notyas_firmware::board::elecrow_5: C6 radio held in reset (GPIO20 low)
W (1673) notyas_firmware::board::elecrow_5: C6 power-on window: C6 EN is pulled up (R77) - the C6 ran from power-on until this line; hardware-held in reset from here on
I (1688) notyas_firmware: board: Elecrow CrowPanel Advanced 5inch ESP32-P4 | flash 16 MB | radio kill GPIO20
I (2203) notyas_firmware: selftest: wordlist      pass
I (2221) notyas_firmware: selftest: 6/6 passed in 491 ms
I (2226) notyas_firmware::board::elecrow_5: backlight set to 0% (STC8 0x2F reg 0x20)
I (2246) notyas_firmware::board::elecrow_5: RGB panel initialized (800x480 RGB565 DE mode, pclk 25 MHz)
I (2545) notyas_firmware::verify: app sha256 (running partition, hashed in 287 ms): cc94a2b763e96addca5ec7cc7bc50ee0bebf6d65805f983b68502a97ffe2e960
I (2547) notyas_firmware: verify: fw 0.1.0 | Elecrow CrowPanel Advanced 5inch ESP32-P4 | ESP-IDF v5.5.4 | ESP32-P4 rev v1.3
I (2558) notyas_firmware: verify: radio: kill GPIO20 reads LOW (C6 held in reset) | GPIO20 -> ESP32-C6 CHIP_PU (EN) via R95 [...]
I (2594) notyas_firmware: verify: secure boot: disabled (dev unit; release units burn Secure Boot v2 RSA-3072) | flash encryption: disabled (dev unit; release units enable XTS-AES)
I (2628) notyas_firmware: frame time: draw 17 ms + publish 0 ms (800x480 full repaint)
I (2628) notyas_firmware::board::elecrow_5: backlight set to 80% (STC8 0x2F reg 0x20)
I (2703) notyas_firmware::board::elecrow_5: GT911 at i2c address 0x5D (driver-strapped via INT GPIO42)
I (2721) notyas_firmware: notyas 0.1.0 ui up on Elecrow CrowPanel Advanced 5inch ESP32-P4
I (3759) notyas_firmware: notyas 0.1.0 | IDF v5.5.4 | free heap 30757920 bytes
I (78647) notyas_firmware: notyas 0.1.0 | IDF v5.5.4 | free heap 30757920 bytes
```

78 s monitored, no watchdog, free heap byte-identical (30757920) across all
heartbeats, zero errors. The GT911 address is deterministic here (0x5D,
INT-strapped by the driver) - unlike the Waveshare board's floating-INT
coin flip.

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
11. `espflash flash --partition-table <file>` does NOT write the partition
    table to the device - it only uses it to lay out and validate the app
    image. Proven by flash readback: after a "successful" flash naming the
    new 4 MB table, 0x8000 still held the old 1 MB one and the bootloader
    refused the app ("Image length ... doesn't fit in partition length").
    flash.ps1 therefore converts firmware/partitions.csv to binary
    (`espflash partition-table --to-binary`) and writes it to 0x8000 with
    `espflash write-bin` before every app flash.
12. secp256k1-sys (via notyas-core -> bitcoin) cross-compiles its C library
    with cc-rs, which cannot find the ESP toolchain (esp-idf-sys exports it
    only inside its own build script) and, once pointed at a GCC, produces
    soft-float PIC objects that the static IDF link rejects (`discarded
    output section: '.got.plt'` at final link). build.ps1 exports
    `CC/AR/CFLAGS_riscv32imafc_esp_espidf` pointing at the embuild-installed
    riscv32-esp-elf-gcc with `-march=rv32imafc_zicsr_zifencei -mabi=ilp32f
    -fno-pic`.
13. Static-inline IDF functions are not bindgen-able:
    `esp_secure_boot_enabled()` never appears in the bindings no matter what
    header is included. Read the underlying real API instead
    (`esp_efuse_read_field_bit(ESP_EFUSE_SECURE_BOOT_EN)` - same bit its
    non-virtual arm reads through efuse_ll). bindings/verify.h documents the
    equivalence; the extra_components entry that carries it has NO component
    to build - esp-idf-sys accepts a bindings_header-only entry.
14. `gpio_get_level` on an OUTPUT-mode pin returns a constant 0 regardless
    of the pad's real level (input buffer disabled). Pins whose level is
    reported on the Verify screen (the radio kill line) are claimed as
    GPIO_MODE_INPUT_OUTPUT in `board::claim_output` so the readback is the
    actual pad state - the whole point of reporting it.
