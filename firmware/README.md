# notyas-firmware

std Rust on ESP-IDF for the Waveshare ESP32-P4-WiFi6-Touch-LCD-4B. Milestone
0.1.0-m2 (part 1): 720x720 MIPI-DSI display and GT911 touch up from Rust -
the Butter Paper demo shell renders, touches are drawn live and logged.
(m1 proved the toolchain: build, flash, boot, radio lockdown, heartbeat.)

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

The dev board's silicon is **rev v1.3** - the pre-v3.0 engineering-sample
family. IDF v5.5 defaults to `CONFIG_ESP32P4_REV_MIN_301` (rev >= v3.1), and
the two families are not binary compatible: an image built for v3.x flashes
fine on v1.3 silicon and then prints nothing (ROM banner
`ESP-ROM:esp32p4-eco2-20240710` repeating = boot loop). sdkconfig.defaults
therefore pins:

```
CONFIG_ESP32P4_SELECTS_REV_LESS_V3=y   # pre-v3.0 family; caps REV_MAX_FULL at 199
CONFIG_ESP32P4_REV_MIN_100=y           # minimum rev v1.0 (numbering: REV_MIN_FULL = major*100+minor;
                                       # ESP32P4_REV_MIN_1 would mean v0.1, not v1.x)
```

**Release builds for production hardware (rev >= v3.1) must revisit this** -
drop `SELECTS_REV_LESS_V3` and pin `ESP32P4_REV_MIN_301`. One image cannot
serve both families.

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
\\172.16.0.9\bear\code\btc\notyas\tools\build.ps1            # debug build
\\172.16.0.9\bear\code\btc\notyas\tools\flash.ps1 -Monitor   # flash COM3 + monitor
```

Notes the scripts encode:

- Sources build fine directly from the UNC share, but CARGO_TARGET_DIR must be
  a **short local path** (default `C:\nyt`). esp-idf-sys hard-fails with
  "Too long output directory" otherwise - Windows path-length limits in the
  IDF CMake/ninja build.
- `LIBCLANG_PATH` must point at a dir containing libclang.dll. The esp-clang
  tool embuild installs does not ship one on Windows; the `libclang` pip wheel
  does (`%APPDATA%\Python\Python312\site-packages\clang\native`).
- flash.ps1 flashes the bootloader and partition table produced by the IDF
  build, never espflash's bundled ones - the bundled bootloader is built for
  default (v3.x-family) config and does not boot on this chip.
- Monitor manually: `espflash monitor --port COM3` (115200 baud; Ctrl-C exits).

## What 0.1.0-m2 does

Boot sequence in `src/main.rs`, in load-bearing order:

1. `esp_idf_svc::sys::link_patches()` + EspLogger init.
2. **Airgap lockdown first**: GPIO54 (the ESP32-C6 radio module's CHIP_PU
   enable) is driven LOW and held for the whole power cycle - the radio chip
   sits in reset. Logs `C6 radio held in reset (GPIO54 low)`.
3. Backlight enable (GPIO33) claimed and held LOW - the panel stays dark
   until the first real frame is in the framebuffer.
4. Display bring-up (`src/display.rs`):
   - internal LDO channel 3 acquired at 2500 mV (MIPI DPHY power - skipping
     this hangs DSI init) and channel 4 at 3300 mV (GPIO39-48 IO bank);
   - DSI bus, 2 lanes at 480 Mbps/lane; DBI IO channel for panel commands;
   - ST7703 panel via the `waveshare/esp_lcd_st7703` component (v2.0.0),
     720x720 RGB565, DPI clock 38 MHz, LCD reset GPIO27 handled by the
     panel config, `use_dma2d`. The function-like C config macros
     (`ST7703_*_CONFIG`) cannot be bound by bindgen; their values are
     replicated as consts in display.rs.
   - Framebuffer: the DPI driver allocates one 720x720 RGB565 buffer (~1 MB)
     in PSRAM. We draw into it directly (`esp_lcd_dpi_panel_get_frame_buffer`)
     and publish by passing the same pointer back through
     `esp_lcd_panel_draw_bitmap` - the driver recognizes its own framebuffer,
     skips the copy, and only does the required cache writeback. One buffer,
     no memcpy, no hand-rolled cache maintenance. `display::Display`
     implements `embedded_graphics::DrawTarget` (Rgb565) over that buffer.
5. Butter Paper shell painted (tokens in `src/theme.rs`, from
   `\\172.16.0.9\bear\code\YellowBGs.md`): paper-1 page, centered paper-2
   card with 1px hairline border, title/version/status text in the built-in
   mono fonts. Text styles are passed as generic `TextRenderer` parameters so
   the pre-rasterized notyas font atlases (parallel workstream) drop in
   without touching the drawing code. Then backlight on: GPIO33 high + LEDC
   PWM on GPIO26 at 80% (5 kHz, 10-bit, inverted output - same proven config
   as the Waveshare BSP, whose backlight PWM input is active-low).
6. Touch bring-up (`src/touch.rs`): i2c_master bus on SDA GPIO7 / SCL GPIO8
   at 400 kHz; manual GT911 reset on GPIO23 then a 120 ms wake-up wait; probe
   0x5D then 0x14; `espressif/esp_lcd_touch_gt911` component with reset AND
   int set to NC (see pitfall 7); product id read from register 0x8140 and
   logged.
7. Main loop: poll GT911 every 25 ms (INT is unrouted - poll is the only
   option); on a new touch point, log `touch x=.. y=..` and repaint the
   status line; heartbeat banner once per second.

## Captured boot log (COM3, 2026-08-17, display+touch bring-up)

Three consecutive power cycles produced byte-identical init logs (boot on
this path is deterministic to the millisecond). GT911 address was 0x14 on
these cycles; it can legitimately be 0x5D on others (pitfall 7).

```
ESP-ROM:esp32p4-eco2-20240710
rst:0x1 (POWERON),boot:0x30f (SPI_FAST_FLASH_BOOT)
...
I (30) boot: chip revision: v1.3
I (42) boot.esp32p4: SPI Flash Size : 32MB
...
I (296) MSPI Timing: Enter psram timing tuning
I esp_psram: Found 32MB PSRAM device
I esp_psram: Speed: 200MHz
I (501) mmu_psram: .rodata xip on psram
I (558) mmu_psram: .text xip on psram
I (1038) esp_psram: SPI SRAM memory test OK
...
I (1120) esp_psram: Adding pool of 32064K of PSRAM memory to heap allocator
...
I (1206) notyas_firmware: C6 radio held in reset (GPIO54 low)
I (1211) notyas_firmware::display: LDO channel 3 acquired at 2500 mV (MIPI DPHY)
I (1218) notyas_firmware::display: LDO channel 4 acquired at 3300 mV (GPIO39-48 bank)
I (1227) notyas_firmware::display: DSI bus up: 2 lanes, 480 Mbps/lane
I (1232) st7703: version: 2.0.0
I (1676) notyas_firmware::display: ST7703 panel initialized (720x720 RGB565, DPI 38 MHz)
I (1676) notyas_firmware::display: DPI framebuffer at 0x480b0a80 (PSRAM)
I (1695) notyas_firmware::display: backlight PWM duty set to 80%
I (1838) notyas_firmware::touch: GT911 responds at i2c address 0x14
I (1841) GT911: TouchPad_ID:0x39,0x31,0x31
I (1844) GT911: TouchPad_Config_Version:70
I (1849) notyas_firmware::touch: GT911 initialized: product id "911" ([39, 31, 31, 00]), polled mode, reset GPIO23
I (1858) notyas_firmware: notyas 0.1.0-m2 shell up
I (2877) notyas_firmware: notyas 0.1.0-m2 | IDF v5.5.4 | free heap 32264516 bytes
```

45 s monitored with no crash, no watchdog, steady heap. The rev v1.3
silicon accepted the full Waveshare SPIRAM combination (200 MHz + XIP +
L2 256 KB/128 B) on the first try - no bisecting needed.

## Pitfalls hit while proving this (all encoded in config/scripts now)

1. sdkconfig.defaults silently ignored: esp-idf-sys's root-crate autodiscovery
   runs `cargo metadata` where it cannot find Cargo.toml, so the build used
   stock IDF defaults (rev v3.1+, 2MB flash) and the image crashed with an
   illegal instruction AT the bootloader entry address. Fixed by pinning
   `ESP_IDF_SDKCONFIG_DEFAULTS` (relative) in .cargo/config.toml. If the
   monitor ever shows a Guru Meditation with PC == the `entry` address from
   the ROM lines, check the generated sdkconfig's `ESP32P4_REV_MIN_FULL`
   first.
2. Stale bootloader copy: `<target>\<profile>\build\bootloader.bin` is not
   always refreshed; flash.ps1 uses the newest one from the esp-idf-sys out
   dir instead.
3. Long target paths: esp-idf-sys refuses CARGO_TARGET_DIR paths that are too
   long ("Too long output directory") - hence C:\nyt.
4. Pre-v3 eFuse table differences: `esp_chip_info` is not in the default
   esp-idf-sys binding allowlist, and on the pre-v3 table the wafer major
   version is split into LO(2b)/HI(1b) fields - main.rs composes
   `(HI << 2) | LO` exactly like IDF's efuse_ll.h.
5. `[[package.metadata.esp-idf-sys.extra_components]]` silently ignored
   (remote components never downloaded, bindings never generated): embuild
   guesses the workspace dir by walking UP FROM OUT_DIR, which lives under
   CARGO_TARGET_DIR (C:\nyt), not next to the sources - so its
   `cargo metadata` probe finds no Cargo.toml and ALL package metadata is
   dropped. Same root cause as pitfall 1, different symptom. Fixed by
   pinning `CARGO_WORKSPACE_DIR = { value = "", relative = true }` in
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
   error!`, address flipping between 0x5D and 0x14 across boots: the GT911
   re-latches its I2C address from the INT level at every reset release, and
   INT is unrouted on this board (floats). The esp_lcd_touch_gt911 driver
   pulses reset itself and reads config immediately, racing the chip's
   ~50 ms post-reset wake-up. Fix in touch.rs: reset the chip manually
   (GPIO23, 10 ms low, then 120 ms wake-up), probe for whichever address got
   latched, and hand the driver `rst_gpio_num = NC` so it cannot re-reset
   and re-randomize the address. Also: the first coordinate read after reset
   reports a phantom point (observed 481,481) - init does one throwaway
   read.
