# notyas - Security model (normative)

Every claim here must be mechanically enforced (compile-time, test, or hardware) or it
does not get made. Marketing copy derives from this file, never the reverse.

## Threat model

In scope: remote compromise via radio (eliminated), exfiltration of secrets generated on
the device (minimized: stateless, airgapped), a tampered or substituted firmware image
(detectable: reproducible builds, signed releases, on-device verification), and biased
or insufficient user entropy (surfaced: effective-bits accounting, roll minimums).

Out of scope, stated honestly: physical extraction of secrets from a running, powered
device in an attacker's hands; supply-chain replacement of the hardware itself. The
ESP32-P4 has no secure element and the device stores no secrets, so "tamper-proof
storage" claims are impossible and are not made.

## Invariants

1. **No radio.** The WiFi companion chip (ESP32-C6) is held in reset by a P4 GPIO from
   the first line of app_main, permanently. The kill GPIO is a per-board compile-time
   constant (docs/BOARDS.md, "The airgap invariant, per board", is the source of truth:
   GPIO54 on the Waveshare 4B, GPIO20 on the Elecrow 5inch, GPIO32 on the untested
   Elecrow DSI scaffolds). No esp_hosted, esp_wifi_remote, or any network/WiFi/BT
   component is present in the firmware image; there is no code path that could
   initialize the SDIO link to the C6. Enforced by: build-graph check (a CI grep over
   the linked component list and the Cargo lock, mirroring desktop BigDice's
   dependency-graph tests) + boot-time GPIO state + the Verify screen reporting the
   kill GPIO level.
2. **Stateless.** No seed, roll, passphrase, or derived key is ever written to flash,
   NVS, or SD. NVS is never mounted. RAM copies are zeroized on drop (zeroize crate,
   same discipline and types as desktop BigDice). Power-off is the wipe. Corollary,
   0.1.0: there is no private-key export path at all - QR display covers public
   values only (receive addresses, account xpub/SLIP-132), never a mnemonic, xprv,
   seed or WIF; unlike desktop BigDice there is no reveal gate for private values to
   sit behind. Enforced structurally in notyas-ui and test-asserted.
3. **Deterministic.** Key material derives exclusively from user-supplied dice rolls or
   a typed mnemonic, plus optional passphrase, per the desktop BigDice SPEC. No TRNG,
   no clock, no OS entropy on any derivation path - the property is inherited from
   notyas-core, which has no API for any of those.
4. **Equivalence.** Identical input produces byte-identical output to desktop BigDice
   (and thus to iancoleman in RAW mode, Coldcard/SeedSigner math in FIXED mode).
   Enforced by shared test vectors run in CI on host and as the on-device boot
   self-test.
5. **Verifiable firmware.** Reproducible build (pinned IDF, pinned nightly toolchain,
   --locked, CONFIG_APP_REPRODUCIBLE_BUILD); releases ship SHA256SUMS.txt signed by the
   BigDice GPG key (A1E9 53B2 5C6A 623B 77A1 D522 3AC4 BBCF E51A B37D). The Verify
   screen shows: firmware semver, running-app SHA256 (from the running partition, not a
   compiled-in constant), source-id hash, self-test results, secure-boot and
   flash-encryption eFuse state as actually read.
6. **Secure boot, honestly.** Release hardware: Secure Boot v2 RSA-3072 (ECDSA mode is
   ROM-broken on shipping P4 silicon - Espressif AR2026-006 - and is never used) +
   XTS-AES flash encryption + eFuse anti-rollback. Dev boards run with these off; the
   Verify screen reports the true state either way. The bootloader is built from
   Apache-2.0 ESP-IDF source; the only non-reproducible element below our code is the
   mask ROM, whose behavior the ROM banner and revision readout expose.

## Known accepted risks (documented, not hidden)

- ESP-IDF (FreeRTOS + drivers) is in the TCB. It is fully open source and radio-free on
  the P4, but it is large. Mitigation: the crypto core never calls into it; the
  firmware crate is the only IDF consumer.
- USB is a physical attack surface while connected. 0.1.0 uses USB for power/flash only;
  no USB data functionality is compiled in.
- The GT911 touch controller and ST7703 panel run vendor init sequences (documented
  register writes, no firmware blobs uploaded to them by us).
- Elecrow 5inch board only (board-elecrow-5, verified 2026-08-17):
  - **C6 power-on window.** The C6's EN pin carries a 10K pullup to an always-on rail,
    so the radio co-processor boots its factory esp-hosted slave firmware at every
    power-up and runs until app_main drives the kill GPIO low (order: hundreds of ms).
    The slave idles waiting for an SDIO host and joins no network on its own; the P4
    image contains no driver to talk to it. Logged as a warning at every boot.
    Firmware cannot close this window (ROM + bootloader run first); hardware
    mitigation for production units is removing the pullup/0R (R77/R95) or the C6
    module (BOARDS.md).
  - **STC8 co-MCU.** Backlight control requires one I2C register write (0x2F reg 0x20,
    duty) to an STC8H1K17 running unpublished Elecrow firmware. It has no radio and no
    bus-master role, but it sits on the touch I2C bus and its firmware is
    unverifiable. We send it exactly that one write and read nothing
    security-relevant from it.
  - **Wireless module socket.** The board has a socket for LoRa/nRF24/Zigbee modules.
    The airgap on this board additionally requires the socket to be physically EMPTY;
    firmware never initializes the socket pins and (per the no-probing rule) does not
    try to detect a module. Documented physical precondition, like "keep the device
    in your possession".
