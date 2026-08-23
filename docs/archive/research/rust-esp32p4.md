# Research: Rust on ESP32-P4, ecosystem state (2026-08-17)

Agent-produced report. Decision derived from it: ESP-IDF v5.5.x + std Rust around a
no_std core crate (see docs/ARCHITECTURE.md).

## 1. esp-hal (no_std)

- ESP32-P4 supported on esp-hal `main` only (target `riscv32imafc-unknown-none-elf`);
  no crates.io release includes it. Latest release 1.1.2 (2026-08-05) has no `esp32p4`
  feature; first P4-capable release 1.2.0 milestoned ~2026-08-25. Support is for chip
  **revision v3.x only** ("P4X" mass-production silicon); v1.x boards out of scope.
  Initial support tracking issue #2285 closed done 2026-06-15.
  https://github.com/esp-rs/esp-hal/blob/main/esp-hal/README.md ,
  https://github.com/esp-rs/esp-hal/pull/5400 , https://github.com/esp-rs/esp-hal/issues/3962
- Peripheral status on main: MIPI-DSI driver exists (Partial; PR #5596 merged
  2026-06-08; DBI + DPI + VDMA; no PPA/ISP acceleration). I2C/SPI/UART/GPIO Supported.
  SDMMC Partial (PR #5760, 2026-07-09). USB Partial. SHA/AES/RSA/ECC Partial
  (#5697, #5525); HMAC/DS/ECDSA/Key Manager NOT supported. TRNG Partial with an open
  entropy-quality issue (#5982) - do not use for key material. PSRAM stub. Dual-core
  enabled (#5535). No ADC/LEDC/RMT/MCPWM/camera/ULP.
- Verdict: technically possible on main, but every pillar except basic buses is
  Partial, API-unstable, unreleased, example-free - and our silicon (v1.3) is excluded.

## 2. esp-idf + Rust std

- Target `riscv32imafc-esp-espidf` explicitly lists ESP32-P4 (Tier 3: nightly +
  `-Zbuild-std` + `ldproxy`), min ESP-IDF v5.2.
  https://doc.rust-lang.org/rustc/platform-support/esp-idf.html
- Crates: esp-idf-sys 0.37.2 / esp-idf-hal 0.46.2 / esp-idf-svc 0.52.1 (2026-03-10)
  support esp32p4; 0.37.1 fixed P4 compilation. Crates support ESP-IDF v5.3-v5.5 only
  (v6.0 on unreleased master) - pin **IDF v5.5.5** (2026-07-17).
- P4 mass-production support in IDF since v5.3. Firmware for rev >= v3.0 not
  binary-compatible with older samples.

## 3. Mixed C/Rust

- Canonical: esp-idf-template `cmake` flavor - a directory that is both an IDF
  component and a cargo crate; CMakeLists invokes cargo, links the staticlib.
  https://github.com/esp-rs/esp-idf-template/blob/master/README-cmake.md
- Production P4 proof: esp-smoltcp (Espressif dev-portal blog 2026-06-19) ships a
  no_std Rust staticlib built for riscv32imafc-unknown-none-elf inside IDF components
  on P4, with ld --wrap shims. Key insight: bare-metal target for the staticlib
  sidesteps the Tier-3 std target.
  https://developer.espressif.com/blog/2026/06/rust-smoltcp-network-stack-for-esp-idf/

## 4. UI stack on the 720x720 DSI panel

- Slint: ESP-IDF component v1.17.1 via esp_lcd handles; P4 users exist (issue #10760);
  Espressif demoed Rust+Slint on P4 at 55 fps using PPA. no_std Rust board-support is
  S3-only. https://components.espressif.com/components/slint/slint
- LVGL: first-class C only (P4 EV BSP: LVGL 9.4 ~64 fps). Rust bindings (lvgl 0.6.2)
  stuck at LVGL 8.3, unmaintained since 2023.
- embedded-graphics: buoyant-esp32p4 = embedded-graphics DrawTarget over the esp_lcd
  DSI framebuffer with PPA acceleration (5.5-17x), std Rust on IDF v5.5, tested on DSI
  panels. https://github.com/zebra-pig/buoyant-esp32p4
- Touch: GT911 has a Rust driver (gt911 crate 0.3.0, embedded-hal, async).

## 5. Bitcoin crypto crates

- bitcoin 0.32.x: no_std + alloc; PSBT works in no_std; bare-metal example in-tree
  (~256 KiB heap driven by libsecp context; mitigate with secp-lowmemory /
  preallocated contexts).
  https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/embedded/README.md
- secp256k1 0.31.1 (C libsecp): no_std, alloc-free via preallocated contexts; C
  cross-toolchain painless on RISC-V. k256/secp256kfun (pure Rust): no_std, no heap,
  NCC-audited with a variable-time caveat on some cores. Community default for signers
  is C libsecp; Frostsnap chose pure-Rust to avoid FFI.
- bip39 2.2.2: no_std, zeroize feature. miniscript 13.1.0: no_std (BitBox02 ships it).
- Prior art: Frostsnap (Rust on ESP32-C3, secp256kfun); Blockstream Jade (C on
  ESP-IDF, libwally); BitBox02 (C shell + Rust core: bitcoin, miniscript, bip39);
  Passport Prime (full Rust: KeyOS on Xous, UI in Slint, shipped May 2026). Nobody has
  published rust-bitcoin-on-ESP32 yet; nothing blocks it on RISC-V.

## 6. Bootloader / security on P4

- Secure Boot v2 since IDF v5.3; RSA-3072 / ECDSA-P256/P384. **ECDSA secure boot is
  broken at ROM level on all shipping P4 silicon (<= rev v3.2) - advisory AR2026-006
  (2026-07-28), invalid r/s accepted, no software fix. Use RSA-3072** (also faster:
  ~15 ms vs ~61 ms).
- Flash encryption: XTS-AES-128/256, eFuse or Key Manager keys, anti-SCA pseudo-rounds,
  independent PSRAM encryption.
- Anti-rollback: eFuse 16-bit secure_version (max 16 increments).
- Silicon security: HMAC, RSA-DS, ECDSA-DS peripherals, Key Manager - none in esp-hal,
  all in IDF.
- Reproducible builds: CONFIG_APP_REPRODUCIBLE_BUILD official; pin toolchain via IDF
  Docker image. GPLv3 + Apache-2.0 ESP-IDF is license-clean per FSF (one-directional).
- P4 has **no radio**: no closed WiFi/BT blobs anywhere - IDF layer is all-source
  Apache-2.0 plus mask ROM.

## 7. Windows 11 toolchain

- no_std: stable rustup + riscv32imafc-unknown-none-elf. std: espup --std / EIM
  (winget install Espressif.EIM) for ESP-IDF; Python >= 3.10.
- espflash 4.5.0 (2026-07-09) supports P4 over CH343 COM and native USB-Serial-JTAG.
- probe-rs: P4 added v0.31.0; rev v3.1/v3.2 needs v0.32.0.

## Recommendation matrix (1 poor - 5 excellent)

| Criterion | (a) pure esp-hal no_std | (b) IDF C shell + Rust staticlib | (c) esp-idf std Rust |
|---|---|---|---|
| Display/touch on this chip | 2 | 5 | 4 |
| Crypto library fit | 5 | 4 | 5 |
| Code simplicity | 4 | 2 | 3 |
| Auditability | 5 | 3 | 4 |

Recommendation: no_std IDF-free signing-core crate (route-independent audit heart);
around it, (c) esp-idf std Rust on IDF v5.5.5 today - only route where the exact
display path is production-proven on this chip with the whole app in Rust; P4 has no
radio blobs to taint the C layer. Treat (a) as migration target once esp-hal 1.2.0+
stabilizes DSI/SDMMC/PSRAM (and only on v3.x silicon). Lock in now: RSA-3072 secure
boot, XTS-AES flash encryption (release), CONFIG_APP_REPRODUCIBLE_BUILD, and - for
release hardware - chip rev >= v3.1; dev board (v1.3) builds pin the v1.x revision
family.

Note: secure boot / flash encryption / anti-rollback come from the ESP-IDF second-stage
bootloader regardless of route - even a pure esp-hal app boots behind an IDF-built
bootloader, so IDF never fully leaves the TCB.
