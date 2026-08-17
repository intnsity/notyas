# notyas - Architecture

Version target: 0.1.0. License: GPL-3.0-or-later. Status: decided 2026-08-17 after
hardware/toolchain/feature research; see HARDWARE.md for the board fact sheet.
Renamed from bigdice32 to notyas 2026-08-17.

## What this is

An airgapped bitcoin seed generator and verifier - BigDice (github.com/intnsity/BigDice)
ported to a Waveshare ESP32-P4-WiFi6-Touch-LCD-4B. Dice rolls in, BIP39 mnemonic and
BIP32/44/48/49/84/86 keys out, on a device that has no radio path and whose firmware the
user can verify. It is not (in 0.1.0) a transaction signer: BigDice's feature set is
seed generation, restore/verification, and xpub/address export. PSBT signing via microSD
is the planned 0.2.x milestone (research and format decisions are recorded in
docs/research/ so nothing in 0.1.0 forecloses it).

## Stack decision

**ESP-IDF v5.5.x + std Rust** (`riscv32imafc-esp-espidf`, Tier 3, nightly +
`-Zbuild-std`), wrapped around a **no_std, IDF-free core crate** that carries all
cryptography. Rationale, from the 2026-08 ecosystem survey:

- Pure no_std `esp-hal` is not viable for this device today: P4 support is unreleased
  (git main only), MIPI-DSI/SDMMC/PSRAM are all "Partial", and esp-hal targets rev v3.x
  silicon while our dev board is **rev v1.3**.
- The exact display path we need (esp_lcd MIPI-DSI + ST7703 + GT911) is
  production-proven C, shipped by Espressif and Waveshare, reachable from Rust via
  esp-idf-sys. The P4 has **no radio**, so unlike every other ESP32 there are no closed
  WiFi/BT blobs anywhere in the build - everything above mask ROM is open source
  (Apache-2.0 IDF + our GPL3 code; FSF-confirmed compatible in this direction).
- The migration path to esp-hal no_std stays open because the core crate never touches
  the OS layer.

## Crate layout

```
notyas/
  Cargo.toml            workspace
  crates/
    notyas-core/        #![no_std] + alloc. Ported from the desktop BigDice crate:
                        entropy (SPEC 1-3), bip39 (SPEC 4-8), derive (SPEC 9), qr.
                        No IDF, no std, no clocks, no RNG, no I/O. Host-testable
                        (tests run with std as dev-dependency). This is the audit
                        surface; it must stay byte-for-byte equivalent to desktop
                        BigDice (same SPEC, same vectors).
    firmware/           std Rust on esp-idf. Owns hardware bring-up (display, touch,
                        SD, lockdown), the UI, and calls into notyas-core. Nothing
                        cryptographic lives here.
  docs/                 this file, HARDWARE.md, SECURITY.md, research reports
  tools/                build/flash/verify scripts (PowerShell)
```

## Porting rules for notyas-core

The desktop crate (\\172.16.0.9\bear\code\btc\dice_generator) is the normative source;
its docs/SPEC.md governs. The port changes exactly:

1. `std::` imports -> `core::`/`alloc::`.
2. The two `OnceLock`s (wordlist cache in bip39.rs, secp context in derive.rs) become
   compile-time statics / explicitly passed contexts - the only std-sync surface.
3. `bitcoin` pinned `=0.32.102` with `default-features = false, features = ["alloc"]`
   instead of `["std"]` (same version as desktop).

Everything else - the prefix-free dice code, the 6->0 mapping, raw/fixed modes, the
generalized BIP39 encoder, zeroize discipline, redacting Debug impls - transfers
unchanged, along with the unit tests and the official BIP vectors. Divergence from
desktop BigDice output on identical input is a release-blocking bug.

Dice math note (from the feature research): BigDice RAW mode is iancoleman-compatible by
design and therefore intentionally NOT compatible with Coldcard/SeedSigner
SHA256(rolls) math; BigDice FIXED mode is algorithm-identical to Coldcard/SeedSigner.
The device keeps both modes and the UI labels which external tools each one
cross-checks against. Published test vectors must cover both.

## UI

Hand-rolled screens on `embedded-graphics`, drawing into the esp_lcd DSI framebuffer
(RGB565, PSRAM). No LVGL (Rust bindings are dead at v8), no Slint (closed layout step,
heavier audit surface) - a wallet UI is a dozen static screens and a keypad; a small
bespoke renderer is simpler and fully reviewable.

Theme: Butter Paper (\\172.16.0.9\bear\code\YellowBGs.md), same tokens as desktop
BigDice's gui/theme.rs - warm paper ramp, warm ink, cobalt accent, depth by tint. Fonts:
IBM Plex Sans + IBM Plex Mono (OFL 1.1), pre-rasterized to bitmap glyph atlases at build
time by a host-side tool (no runtime font parsing). Licensing: OFL permits embedding and
redistribution with GPL3 firmware (fonts ship as data + LICENSE-fonts, desktop BigDice
pattern), but "Plex" is a Reserved Font Name - subsetted/converted artifacts are Modified
Versions and must be renamed (e.g. "notyas Sans"/"notyas Mono"), with the OFL text and
attribution in LICENSE-fonts; unmodified upstream TTFs may keep their names. Terminal-
plain layout: full-width cards, hairline rules, no animation.

## Security model (summary - SECURITY.md is normative)

- **Radio dead at three layers**: (1) no esp_hosted / esp_wifi_remote / any WiFi
  component in the build - the driver does not exist in the image; (2) GPIO54 (ESP32-C6
  enable) driven low first thing in app_main and never released - the radio chip is
  held in reset; (3) the C6's SDIO GPIOs are never configured as an SDIO host.
- **Stateless**: seeds and rolls live in RAM only, zeroized on screen exit and
  power-off. NVS is not mounted; no writes to internal flash at runtime.
- **Deterministic**: user dice entropy only. The P4 TRNG is never used for key material
  (also: known entropy-quality issue esp-hal#5982; we do not depend on it at all).
- **Verifiable**: reproducible build (CONFIG_APP_REPRODUCIBLE_BUILD + pinned IDF +
  --locked cargo), GPG-signed release manifests (same key as desktop BigDice), and an
  on-device Verify screen: firmware version, app SHA256, source-id hash, boot self-test
  results (BIP vectors run at boot), and the eFuse/secure-boot status readout.
- **Secure Boot v2 with RSA-3072 only** - ECDSA secure boot is ROM-broken on all
  shipping P4 silicon (Espressif advisory AR2026-006). Flash encryption XTS-AES.
  Both OFF on the dev board during development, ON for release units; the Verify screen
  reports their true eFuse state, never a constant.
- **No secret-keeping claims**: the P4 has no secure element. The device protects by
  being stateless and airgapped, not by resisting physical extraction of a stored
  secret (there is none).

## Build system

- Working tree lives on the NAS share (canonical, git). Builds set CARGO_TARGET_DIR to
  a local disk via tools/build.ps1 (UNC + heavy cmake builds do not mix; sources on
  UNC, artifacts local).
- Rust nightly (pinned in rust-toolchain.toml) + ldproxy + espflash. ESP-IDF v5.5.x
  installed/managed by esp-idf-sys (embuild), version pinned in firmware config.
- **Chip revision**: firmware is built for the pre-v3.0 P4 family (dev board is rev
  v1.3). IDF v5.5 defaults to rev >= 3.1; CONFIG_ESP32P4_REV_MIN must stay pinned to
  the v1.x family or the image builds and does not boot. Release builds for production
  hardware revisit this.
- Versioning: workspace version 0.1.0; git tag per release; rollback = git revert/reset
  to tag. Every milestone lands as a working, flashable commit.

## Milestones

- 0.1.0-m1: toolchain proven - hello-world boots on the device, serial banner, radio
  lockdown verified (C6 held in reset).
- 0.1.0-m2: display + touch up - Butter Paper shell renders, touch keypad works.
- 0.1.0-m3: notyas-core ported, host test suite green, boot self-test on device.
- 0.1.0-m4: full flow - dice entry -> mnemonic -> passphrase -> schemes/addresses ->
  QR display; Verify screen; release 0.1.0.
- 0.2.x (planned): microSD PSBT signing (Coldcard file conventions, UR2 QR-out),
  multisig xpub export, SeedQR display.
