# UI screenshots (generated - do not edit)

Rendered by `tools/uisim` (`cargo run --release` there) from `crates/notyas-ui` at the
primary 720x720 panel geometry. Deterministic: same input -> same PNG bytes; the tool
renders each frame twice and refuses to write on any divergence. Regenerate after any
UI change and commit the diff.

Sample data - all of it public test-vector material, none of it a real seed:

- Dice input: 64 sixes. A six maps to digit 0 (SPEC step 2), so RAW mode yields the
  all-zeros 128-bit entropy of BIP39 test vector #1; the mnemonic shown revealed is the
  well-known "abandon abandon ... about".
- Passphrase: "TREZOR", the official BIP39 test-vector passphrase, so the schemes
  screen shows keys checkable against the published vectors.
- Phrase-entry screen: "zoo zoo ... zoo wrong" (Trezor vector #4, valid checksum).
- Verify screen: placeholder values, each prefixed DUMMY; on hardware the firmware
  fills them from what it actually read.

| File | Screen |
|------|--------|
| 01-home.png | Home menu |
| 02-dice-entry.png | Dice entry, RAW mode, 128 bits collected |
| 03-mnemonic-masked.png | Mnemonic display, masked (fixed 6-bullet runs) |
| 04-reveal-confirm.png | Two-step reveal confirm modal |
| 05-mnemonic-revealed.png | Mnemonic display, revealed |
| 06-passphrase.png | Passphrase entry, both fields masked (fixed 24-bullet run) |
| 07-schemes-bip44.png | Schemes, BIP44 tab (xpub + receive addresses) |
| 08-schemes-bip84.png | Schemes, BIP84 tab |
| 09-verify-device.png | Verify device (DUMMY values) |
| 10-phrase-entry.png | Verify existing seed, typed phrase + checksum advisory |
