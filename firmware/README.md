# notyas-firmware

std Rust on ESP-IDF for ESP32-P4 touch-display boards. Milestone 0.1.0-m4:
the whole product flow runs on hardware - dice entry -> mnemonic -> optional
passphrase -> derived schemes and receive addresses -> QR display - over a
notyas-core boot self-test that runs before any peripheral, with a Verify
screen that shows only values READ at boot (running-partition SHA256, eFuse
state, radio pad readback - SECURITY.md invariant 5). Multi-board per
docs/BOARDS.md: exactly one `board-*` cargo feature selects the hardware at
compile time (the build IS the board - no default feature, no runtime
detection).

| Board feature | Hardware | Status |
|---|---|---|
| `board-waveshare-4b` | Waveshare ESP32-P4-WiFi6-Touch-LCD-4B, 720x720 DSI | verified on hardware |
| `board-elecrow-5` | Elecrow CrowPanel Advanced 5inch, 800x480 RGB | verified on hardware |
| `board-elecrow-7` / `-9` / `-101` | Elecrow CrowPanel Advanced 1024x600 DSI | UNTESTED scaffolds |
| `board-waveshare-7b` | Waveshare ESP32-P4-WIFI6-Touch-LCD-7B, 1024x600 DSI | UNTESTED scaffold |
| `board-waveshare-5` | Waveshare ESP32-P4-WIFI6-Touch-LCD-5, 720x1280 DSI | UNTESTED scaffold + portrait layout unverified |
| `board-waveshare-7x` / `-8x` / `-101x` | Waveshare Touch-LCD-7/8/10.1 "X", 720x1280 / 800x1280 DSI | UNTESTED scaffolds + portrait layout unverified |

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

Then, from the repository root (the scripts resolve every path relative to
themselves, so an absolute path to them works from any working directory):

```powershell
# Waveshare 4B (COM3):
tools\build.ps1 -Board waveshare-4b
tools\flash.ps1 -Board waveshare-4b -Monitor

# Elecrow CrowPanel Advanced 5inch (COM6):
tools\build.ps1 -Board elecrow-5
tools\flash.ps1 -Board elecrow-5 -Monitor
```

`-Board` drives the cargo feature, the sdkconfig pair, the per-board
CARGO_TARGET_DIR (C:\notyas-build\w, C:\notyas-build\e, C:\notyas-build\e7,
C:\notyas-build\e9, C:\notyas-build\e101, C:\notyas-build\w5, C:\notyas-build\w7b,
C:\notyas-build\w7x, C:\notyas-build\w8x, C:\notyas-build\w101), espflash
`--flash-size` (32mb/16mb) and the default port (COM3/COM6; port letters
drift - override with `-Port COMx`). flash.ps1 does not know the Waveshare
scaffold boards yet (no hardware exists to flash); build.ps1 knows the full
roster. Per-board target dirs mean switching boards never needs a clean, and
flash.ps1's newest-bootloader-under-esp-idf-sys search can no longer pick up
another board's bootloader.

Notes the scripts encode:

- Sources build fine directly from the UNC share, but CARGO_TARGET_DIR must be
  a **short local path**. esp-idf-sys hard-fails with "Too long output
  directory" otherwise - Windows path-length limits in the IDF CMake/ninja
  build. Override with NOTYAS_TARGET_DIR (keep it short AND per-board). Even
  the shortest leaf under C:\notyas-build trips esp-idf-sys's own 88-character
  canonicalized-OUT_DIR check by a few characters (pitfall 3), so build.ps1
  sets ESP_IDF_PATH_ISSUES=warn by default to downgrade that self-check to a
  warning; it does not relax the real filesystem path ceiling underneath it.
- `LIBCLANG_PATH` must point at a dir containing libclang.dll. The esp-clang
  tool embuild installs does not ship one on Windows; the `libclang` pip wheel
  does (`%APPDATA%\Python\Python312\site-packages\clang\native`).
- flash.ps1 flashes the bootloader and partition table produced by the IDF
  build, never espflash's bundled ones - the bundled bootloader is built for
  default (v3.x-family) config and does not boot on this chip.
- Monitor manually: `espflash monitor --port COM3` (115200 baud; Ctrl-C exits).
  A monitor holds the port open, so a flash attempted while one is running
  fails with `Failed to open serial port ... Access is denied` - kill the
  stale `espflash` first (`Get-Process espflash | Stop-Process -Force`).

## What 0.1.0-m4 does

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
   peripheral: 6 checks over pinned vectors, each logged, 493-494 ms
   measured on both boards (the PBKDF2 vector dominates). On failure the
   display still comes up and a dedicated failure screen paints the verdicts
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
   Either way the driver allocates its scan-out framebuffer in PSRAM and
   streams it to the panel continuously. We never draw into that live buffer:
   a repaint starts by clearing to the page background, so drawing in place
   puts half-drawn frames on glass at scan-out rate (the "m3 flicker").
   `display::Display` owns a PSRAM **back buffer**, implements
   `embedded_graphics::DrawTarget` over it at the board's resolution, and
   `flush()` publishes the finished frame with `esp_lcd_panel_draw_bitmap` -
   a row-contiguous memcpy into the driver framebuffer plus the driver's own
   `esp_cache_msync` writeback. The glass therefore only ever shows a
   complete frame. notyas-ui lays out from the `Display`'s size.
5. `Ui::new(board::DISPLAY_WIDTH, board::DISPLAY_HEIGHT)` +
   `ui.set_verify_info(verify::build(&selftest))` - `src/verify.rs` reads
   every Verify-screen value at boot: running-app SHA256 through
   `esp_ota_get_running_partition` + `esp_partition_get_sha256` (~290 ms
   over the 2.5 MB image), secure-boot and flash-encryption eFuse state,
   chip revision via `efuse_hal_chip_revision`, the kill line's pad level
   read back, IDF version, board name, firmware semver. Source id reports
   "unavailable" until the release tooling ships it - never a fake value.
6. First frame drawn and published, timed once. Every repaint is a full
   draw plus a whole-frame publish, so this pair IS the steady-state frame
   cost: **22 ms draw + 0 ms publish at 720x720** (Waveshare, DSI/DPI) and
   **18 ms draw + 9 ms publish at 800x480** (Elecrow, LCDCAM RGB). The
   publish is the back-buffer copy into the driver framebuffer plus its
   cache writeback; the RGB driver's copy path is the slower of the two.
   Then `board::backlight_set(80)`: LEDC PWM GPIO26 inverted (waveshare) /
   one I2C register write to the STC8 co-MCU at 0x2F reg 0x20 (elecrow-5).
7. `board::touch_init()`:
   - waveshare_4b: manual GT911 reset (GPIO23) + 120 ms wake, probe
     0x5D/0x14, driver gets rst=int=NC (INT unrouted; see pitfall 7).
   - elecrow_5: factory sequence - driver owns RST (GPIO36) and INT
     (GPIO42) and straps the address deterministically to 0x5D.
8. Main loop, one pass every 25 ms, in this order:

   ```
   ui.tick()  ->  GT911 poll  ->  ui.touch()  ->  qr request  ->  if dirty { ui.draw(); flush() }
   ```

   - **`ui.tick()` first, and that ordering is load-bearing.** Keyboard
     Done on the passphrase screen does not derive; it parks the seed
     material in notyas-ui's `Deriving` state and returns, so the pass that
     handled the tap paints the interstitial, and the derivation runs at
     the top of the *next* pass. Calling `tick` after `touch` in the same
     pass would paint the result only and leave the passphrase screen
     frozen for the whole computation. `tick` is a no-op returning `false`
     on every other screen. Its duration is logged (`derivation: finished
     in N ms`) - a duration, never any of the material.
   - **GT911 poll -> `TouchEvent`s**, synthesized from consecutive polls:
     point after none = Down, point after point = Move, none after point =
     Up at the last seen point.
   - **QR requests.** notyas-ui is `no_std` and cannot encode a QR, so a
     tap on a QR button comes back out of `ui.touch()` as
     `UiRequest::Qr(target)`. `answer_qr_request` encodes it with
     `notyas_core::qr::matrix` and hands the matrix back through
     `ui.show_qr()` before the same pass repaints, so the modal opens on
     the very frame the tap produced. Only PUBLIC values reach here
     (receive addresses, account xpubs - docs/0.1.0 QR scope); the label is
     logged, the payload never is.
   - **Event-driven repaint.** The UI's pixels are a pure function of its
     state and this loop is the only thing that mutates that state, so a
     synthesized event (or a `tick` that did work) is a complete change
     signal. A Move that reports the same coordinate twice does not count -
     a resting finger would otherwise repaint an identical frame 40x/s.
     An idle device therefore performs **zero** repaints, which the
     heartbeat proves rather than asserts: it carries a monotone repaint
     counter that must not move while nothing is touched.
   - Down/Up and screen/network transitions are logged (`ScreenId` carries
     no data - safe to log). Heartbeat once per second:
     `notyas <ver> | IDF <ver> | free heap <n> bytes | repaints <n>`.

The partition table is the in-repo `firmware/partitions.csv`: a single 4 MB
factory app partition and nothing else (no NVS, no phy_init, no otadata -
SECURITY.md invariant 2), identical on both boards so the running-partition
hash procedure is board-independent. flash.ps1 writes it explicitly (see
pitfall 11).

## Captured boot log - Waveshare 4B (COM3, 2026-08-17, 0.1.0-m4)

GT911 address was 0x14 on this cycle; it can legitimately be 0x5D on others,
and was on the immediately preceding boot of the same image (pitfall 7).
Long verify lines abbreviated with `[...]`.

```
I (30) boot: chip revision: v1.3
I (42) boot.esp32p4: SPI Flash Size : 32MB
I (59) boot:  0 factory          factory app      00 00 00010000 00400000
I esp_psram: Found 32MB PSRAM device
I esp_psram: Speed: 200MHz
I (1699) notyas_firmware::board::waveshare_4b: C6 radio held in reset (GPIO54 low; no EN pullup - C6 held down from power-on)
I (1709) notyas_firmware: board: Waveshare ESP32-P4-WiFi6-Touch-LCD-4B | flash 32 MB | radio kill GPIO54
I (1719) notyas_firmware: airgap: GPIO54 -> ESP32-C6 CHIP_PU (EN), driven low first thing in app_main [...]
I (2230) notyas_firmware: selftest: wordlist      pass
I (2230) notyas_firmware: selftest: dice raw      pass
I (2230) notyas_firmware: selftest: dice fixed    pass
I (2233) notyas_firmware: selftest: bip39 seed    pass
I (2238) notyas_firmware: selftest: bip84 account pass
I (2243) notyas_firmware: selftest: bip86 taproot pass
I (2248) notyas_firmware: selftest: 6/6 passed in 494 ms
I (2253) notyas_firmware::board::waveshare_4b: LDO channel 3 acquired at 2500 mV (MIPI DPHY)
I (2261) notyas_firmware::board::waveshare_4b: LDO channel 4 acquired at 3300 mV (GPIO39-48 bank)
I (2271) notyas_firmware::board::waveshare_4b: DSI bus up: 2 lanes, 480 Mbps/lane
I (2721) notyas_firmware::board::waveshare_4b: ST7703 panel initialized (720x720 RGB565, DPI 38 MHz)
I (2721) notyas_firmware::board::waveshare_4b: DPI framebuffer at 0x48270a80 (PSRAM)
I (3031) notyas_firmware::verify: app sha256 (running partition, hashed in 298 ms): ca188c767c6216a13cfea166e88a452be298f33b3b3e1cc0fddee4ff95c0ebd0
I (3033) notyas_firmware: verify: fw 0.1.0 | Waveshare ESP32-P4-WiFi6-Touch-LCD-4B | ESP-IDF v5.5.4 | ESP32-P4 rev v1.3
I (3044) notyas_firmware: verify: radio: kill GPIO54 reads LOW (C6 held in reset) | GPIO54 -> ESP32-C6 CHIP_PU (EN) [...]
I (3083) notyas_firmware: verify: secure boot: disabled (dev unit; release units burn Secure Boot v2 RSA-3072) | flash encryption: disabled (dev unit; release units enable XTS-AES)
I (3122) notyas_firmware: frame time: draw 22 ms + publish 0 ms (720x720 full repaint)
I (3122) notyas_firmware::board::waveshare_4b: backlight PWM duty set to 80%
I (3273) notyas_firmware::board::waveshare_4b: GT911 responds at i2c address 0x14
I (3285) notyas_firmware::touch: GT911 initialized: product id "911" ([39, 31, 31, 00]), polled mode, reset GPIO23
I (3294) notyas_firmware: notyas 0.1.0 ui up on Waveshare ESP32-P4-WiFi6-Touch-LCD-4B
I (4316) notyas_firmware: notyas 0.1.0 | IDF v5.5.4 | free heap 29328708 bytes | repaints 0
I (133094) notyas_firmware: notyas 0.1.0 | IDF v5.5.4 | free heap 29328708 bytes | repaints 0
```

129 s untouched, no watchdog and no error line, free heap byte-identical
(29328708) across all 128 heartbeats, and **`repaints 0` in every one of
them** - the event-driven repaint invariant, measured rather than asserted.

## Captured boot log - Elecrow CrowPanel Advanced 5inch (COM6, 2026-08-17, 0.1.0-m4)

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
I (1710) notyas_firmware::board::elecrow_5: C6 radio held in reset (GPIO20 low)
W (1716) notyas_firmware::board::elecrow_5: C6 power-on window: C6 EN is pulled up (R77) - the C6 ran from power-on until this line; hardware-held in reset from here on
I (1731) notyas_firmware: board: Elecrow CrowPanel Advanced 5inch ESP32-P4 | flash 16 MB | radio kill GPIO20
I (1741) notyas_firmware: airgap: GPIO20 -> ESP32-C6 CHIP_PU (EN) via R95, driven low first thing in app_main [...]
I (2247) notyas_firmware: selftest: wordlist      pass
I (2247) notyas_firmware: selftest: dice raw      pass
I (2247) notyas_firmware: selftest: dice fixed    pass
I (2251) notyas_firmware: selftest: bip39 seed    pass
I (2256) notyas_firmware: selftest: bip84 account pass
I (2261) notyas_firmware: selftest: bip86 taproot pass
I (2265) notyas_firmware: selftest: 6/6 passed in 493 ms
I (2271) notyas_firmware::board::elecrow_5: backlight set to 0% (STC8 0x2F reg 0x20)
I (2278) notyas_firmware::board::elecrow_5: LDO channel 4 acquired at 3300 mV (GPIO45-54 bank)
I (2291) notyas_firmware::board::elecrow_5: RGB panel initialized (800x480 RGB565 DE mode, pclk 25 MHz)
I (2295) notyas_firmware::board::elecrow_5: RGB framebuffer at 0x48270a80 (PSRAM)
I (2602) notyas_firmware::verify: app sha256 (running partition, hashed in 294 ms): 28cb3fcf39abc4bddb352b5b148a8f70426da4610b49f8f0cd0df1ef5c176b78
I (2604) notyas_firmware: verify: fw 0.1.0 | Elecrow CrowPanel Advanced 5inch ESP32-P4 | ESP-IDF v5.5.4 | ESP32-P4 rev v1.3
I (2615) notyas_firmware: verify: radio: kill GPIO20 reads LOW (C6 held in reset) | GPIO20 -> ESP32-C6 CHIP_PU (EN) via R95 [...]
I (2650) notyas_firmware: verify: secure boot: disabled (dev unit; release units burn Secure Boot v2 RSA-3072) | flash encryption: disabled (dev unit; release units enable XTS-AES)
I (2695) notyas_firmware: frame time: draw 18 ms + publish 9 ms (800x480 full repaint)
I (2695) notyas_firmware::board::elecrow_5: backlight set to 80% (STC8 0x2F reg 0x20)
I (2770) notyas_firmware::board::elecrow_5: GT911 at i2c address 0x5D (driver-strapped via INT GPIO42)
I (2776) notyas_firmware::touch: GT911 initialized: product id "911" ([39, 31, 31, 00]), polled mode, reset GPIO36 (driver-managed), int GPIO42
I (2788) notyas_firmware: notyas 0.1.0 ui up on Elecrow CrowPanel Advanced 5inch ESP32-P4
I (3810) notyas_firmware: notyas 0.1.0 | IDF v5.5.4 | free heap 29914448 bytes | repaints 0
I (123462) notyas_firmware: notyas 0.1.0 | IDF v5.5.4 | free heap 29914448 bytes | repaints 0
```

120 s untouched, no watchdog and no error line, free heap byte-identical
(29914448) across all 119 heartbeats, `repaints 0` throughout. The GT911
address is deterministic here (0x5D, INT-strapped by the driver) - unlike
the Waveshare board's floating-INT coin flip.

The two app hashes differ because they are different images: the board
feature, the sdkconfig overlay and the panel driver all differ, and the
build IS the board.

## Measured on hardware (0.1.0-m4, both boards)

| | Waveshare 4B (720x720) | Elecrow 5inch (800x480) |
|---|---|---|
| boot self-test | 6/6 in 494 ms | 6/6 in 493 ms |
| running-partition SHA256 | 298 ms over 2.5 MB | 294 ms |
| first frame (= any repaint) | 22 ms draw + 0 ms publish | 18 ms draw + 9 ms publish |
| `ui up` at | 3294 ms after reset | 2788 ms after reset |
| Done -> schemes derivation | 827 ms | 827 ms |
| idle heap drift | 0 bytes over 128 heartbeats | 0 bytes over 119 heartbeats |
| idle repaints | 0 | 0 |

The derivation is PBKDF2-HMAC-SHA512 (2048 rounds) plus four BIP32 account
derivations and 5 receive addresses each; it is identical on both boards
because it is pure computation on the same silicon at the same clock. It is
the only operation slow enough to need the `Deriving` interstitial.

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
   long ("Too long output directory") - hence C:\notyas-build\w /
   C:\notyas-build\e / ... - and even those single-letter leaves land 4
   characters over the crate's own 88-character canonicalized-OUT_DIR limit
   (measured 2026-08-21), which is why build.ps1 sets ESP_IDF_PATH_ISSUES=warn.
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
15. `ui.tick()` must run at the TOP of the loop pass, not next to
    `ui.touch()`. Both placements compile and both eventually reach the
    schemes screen, so this fails silently: with `tick` after `touch`, the
    pass that entered `Deriving` also finishes the derivation, the only
    frame ever published is the result, and the interstitial that exists to
    keep the device from looking hung is never painted. The symptom is the
    m4 bug it was meant to fix - the passphrase screen freezes for the
    ~830 ms the derivation takes. The log proves the correct order: the gap
    between `screen: Deriving` and `derivation: finished in N ms` must
    exceed N by about one frame plus one poll interval (~45 ms).
    notyas-ui's `Ui::touch` drains a pending derivation as a safety net, so
    an embedder that omits `tick` entirely is not wedged - it just sits on
    the interstitial until the next touch, which is easy to mistake for
    working.
