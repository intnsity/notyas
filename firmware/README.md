# notyas-firmware

std Rust on ESP-IDF for the Waveshare ESP32-P4-WiFi6-Touch-LCD-4B. Milestone
0.1.0-m1: proves the toolchain end-to-end - builds, flashes, boots on the real
board, locks the radio down, and logs a heartbeat banner on UART0.

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

## What 0.1.0-m1 does

1. `esp_idf_svc::sys::link_patches()` + EspLogger init.
2. **Airgap lockdown first**: GPIO54 (the ESP32-C6 radio module's CHIP_PU
   enable) is driven LOW and held for the whole power cycle - the radio chip
   sits in reset. Logs `C6 radio held in reset (GPIO54 low)`.
3. Once per second: banner `notyas 0.1.0-m1 hello`, IDF version, chip
   revision from eFuse (major.minor), free heap.

## Captured boot log (COM3, 2026-08-17)

The log predates the bigdice32 -> notyas rename; log tags and the banner then
read `bigdice32_firmware` / `BigDice32`. Kept verbatim as captured.

```
ESP-ROM:esp32p4-eco2-20240710
Build:Jul 10 2024
rst:0x1 (POWERON),boot:0x30f (SPI_FAST_FLASH_BOOT)
...
I (27) boot: ESP-IDF v5.5.4 2nd stage bootloader
I (30) boot: chip revision: v1.3
I (42) boot.esp32p4: SPI Flash Size : 32MB
...
I (279) app_init: ESP-IDF:          v5.5.4
I (283) efuse_init: Min chip rev:     v1.0
I (286) efuse_init: Max chip rev:     v1.99
I (290) efuse_init: Chip rev:         v1.3
...
I (377) main_task: Calling app_main()
I (379) bigdice32_firmware: C6 radio held in reset (GPIO54 low)
I (380) bigdice32_firmware: BigDice32 0.1.0-m1 hello
I (380) bigdice32_firmware: IDF v5.5.4 | chip ESP32-P4 rev v1.3 | free heap 596108 bytes
I (1389) bigdice32_firmware: BigDice32 0.1.0-m1 hello
I (1389) bigdice32_firmware: IDF v5.5.4 | chip ESP32-P4 rev v1.3 | free heap 596108 bytes
```

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
