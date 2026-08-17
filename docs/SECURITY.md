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

1. **No radio.** The WiFi companion chip (ESP32-C6) is held in reset by GPIO54 from the
   first lines of app_main, permanently. No esp_hosted, esp_wifi_remote, or any
   network/WiFi/BT component is present in the firmware image; there is no code path
   that could initialize the SDIO link to the C6. Enforced by: build-graph check (a CI
   grep over the linked component list and the Cargo lock, mirroring desktop BigDice's
   dependency-graph tests) + boot-time GPIO state + the Verify screen reporting the
   GPIO54 level.
2. **Stateless.** No seed, roll, passphrase, or derived key is ever written to flash,
   NVS, or SD. NVS is never mounted. RAM copies are zeroized on drop (zeroize crate,
   same discipline and types as desktop BigDice). Power-off is the wipe.
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
