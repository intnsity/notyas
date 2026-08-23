# notyas

notyas is an airgapped Bitcoin signer that runs on off-the-shelf ESP32-P4 touch panels.
Roll physical dice or type a mnemonic, and the device derives your seed and public keys.
On a provisioned board it can also save wallets to flash, set a PIN, sign transactions
from a microSD card, and register multisig wallets.

No radio, no network stack, no USB data path. Transactions move on a microSD card, not a
cable. Free software under the GNU GPL, version 3 or later.

![notyas running on the Waveshare ESP32-P4-WiFi6-Touch-LCD-4B](notyas-intro.png)

| | | |
|---|---|---|
| ![Home](docs/screenshots/ui/01-home.png) | ![Dice entry](docs/screenshots/ui/02-dice-entry.png) | ![Receive](docs/screenshots/ui/90-receive.png) |
| Home screen: the menu is the way in | Dice entry: roll history, mode, effective bits | Receive: address with derivation named underneath |
| ![Export](docs/screenshots/ui/08-schemes-bip84.png) | ![Review](docs/screenshots/ui/98-review-overview.png) | ![Refusal](docs/screenshots/ui/134-refusal-unsupported-script.png) |
| Export: descriptor leads, bare xpub follows | Transaction review, page one | A refusal: code, headline, why, what to do |

Screenshots are rendered by the host simulator from the same UI code the device runs.
[docs/TOUR.md](docs/TOUR.md) walks through every screen with recordings.

---

## Status: preview firmware - do not use with real funds

**This is preview firmware. Do not put real funds behind a seed it generates.**

- No independent security audit has been performed. None is claimed.
- No Secure Boot, no flash encryption, no secure element. An attacker with physical access
  and a USB cable can replace the firmware.
- The on-device signing loop has never been driven from the touch panel. What has run on
  hardware was driven through a development console, not the UI you will use.
- The firmware has been tested on 2 of the 10 boards it supports.

Use it against testnet, published test vectors, and a seed you are prepared to throw away.

Full details: [docs/SECURITY.md](docs/SECURITY.md) and [docs/KNOWN-ISSUES.md](docs/KNOWN-ISSUES.md).

---

## What it does

- **Dice-based seed generation** - roll physical dice, device counts entropy in real time.
  Six modes: RAW (prefix-free base-6) and fixed 12/15/18/21/24-word.
- **Mnemonic display and backup** - masked by default, two-step reveal, word-by-word backup
  check that cannot be skipped.
- **Restore from mnemonic** - BIP-39 autocomplete, checksum validation, final-word helper.
- **Optional BIP-39 passphrase** - explicit opt-in, show/hide toggle, NFKD byte counter.
- **Key derivation** - BIP-32/44/48/49/84/86. Output descriptors, account xpubs, SLIP-132
  forms, receive addresses with QR codes.
- **Sealed storage** (provisioned boards) - save wallets to flash under a PIN, survive power
  cycles, anti-phishing words at half-PIN entry, attempt counter with wipe at 15 wrong PINs.
- **Transaction signing** - load a PSBT from microSD, review it page by page, sign with a
  hold gesture, write the signed file back to the card or show it as a QR.
- **Multisig** - import and register k-of-n P2WSH `sortedmulti` wallets, up to 15 cosigners.
  The device proves membership before any screen renders the wallet.
- **Verify device** - firmware version, board, digests, eFuse state, boot self-test, radio-kill
  readback. Every value is read at boot, not compiled in.

[docs/TOUR.md](docs/TOUR.md) walks through all of it with screenshots and recordings.

---

## What it does not do

- **No finalization.** The device outputs a signed PSBT. Your wallet software finalizes and
  broadcasts.
- **No QR camera input.** Transactions arrive on a microSD card only. No supported board has
  a camera.
- **No backup of registrations, labels, or settings.** A wipe destroys them permanently. Your
  recovery words recover the seed and nothing else.
- **No way to change the PIN, change the wipe policy, or remove the PIN from the panel.** These
  operations need a PIN confirmation the UI cannot collect yet. The wipe threshold is fixed at
  15 wrong attempts.
- **Session auto-locks after 120 seconds** with no warning or countdown.
- **BIP-85, BIP-137, SeedQR decode, and coordinator export files** (JSON, Bitcoin Core,
  Electrum, CSV) are implemented and tested in the core library but have no screen.

Full list of limitations and open defects: [docs/KNOWN-ISSUES.md](docs/KNOWN-ISSUES.md).

---

## Supported boards

The firmware is compiled separately for each board. There is no runtime detection - the build
**is** the board.

| Board | Display | Flash | Status |
|---|---|---|---|
| Waveshare ESP32-P4-WiFi6-Touch-LCD-4B | 720x720 | 32 MB | **Verified on hardware** |
| Elecrow CrowPanel Advanced 5inch | 800x480 | 16 MB | **Verified on hardware** |
| Elecrow 7/9/10.1inch | 1024x600 | 16 MB | Untested scaffold |
| Waveshare 5/7B/7X/8X/10.1X | various | 32 MB | Untested scaffold |

"Untested scaffold" means the code compiles and every constant traces to a published vendor
schematic, but no physical unit has ever run it. Full board details:
[docs/BOARDS.md](docs/BOARDS.md).

**Board choice is a security choice.** Elecrow boards pull the radio co-processor's enable line
high through a resistor, so the radio boots its factory firmware for a few hundred milliseconds
at every power-up before notyas drives it low - the device is briefly RF-visible. Waveshare boards
hold the radio in reset from power-on. Details: [docs/SECURITY.md](docs/SECURITY.md).

---

## Getting started

1. **Get a board** - Waveshare 4B or Elecrow 5inch (the two verified boards).
2. **Download the release** - from [releases](https://github.com/intnsity/notyas/releases).
3. **Flash it** - [docs/FLASHING.md](docs/FLASHING.md) walks through it step by step, including
   how to verify the download signature before flashing. No prior microcontroller experience needed.
4. **Press Verify device** - the third button on the home screen. It shows what the board reports
   about itself. Compare the numbers against the `VERIFY.json` from the release.
5. **Make a wallet** - press "New seed (dice)", roll dice, follow the screens. Use testnet.
6. **To save wallets or sign transactions**, provision the board first:
   [docs/PROVISIONING.md](docs/PROVISIONING.md). This burns one eFuse key block and is irreversible.

---

## Setting up your wallet software

**Give your wallet software the output descriptor from the Export tab, not the bare xpub below it.**

The descriptor carries the wallet's root fingerprint and derivation path. A bare xpub does not -
so wallet software has to guess, and it often guesses wrong. BlueWallet defaults bare xpubs to
legacy derivation (`m/44'/0'/0'`), which may not be what you want.

```
wpkh([a1b2c3d4/84h/0h/0h]xpub6CaWStGvcXqSW.../<0;1>/*)#checksum
```

Per scheme: `pkh(...)` for BIP-44, `sh(wpkh(...))` for BIP-49, `wpkh(...)` for BIP-84, `tr(...)`
for BIP-86.

| Wallet | What to expect |
|---|---|
| **BlueWallet** | Reads the descriptor. PSBT export carries `witness_utxo` only, so single-input spends sign but consolidations or Send Max are refused (R-02). |
| **Sparrow** | Attaches full previous transactions. Multi-input spends work. |
| **Electrum** | Attaches full previous transactions. Account-xpub origin paths are resolved. |
| **Bitcoin Core** | Attaches full previous transactions. Import with `importdescriptors`. The one coordinator that has accepted a device-signed file on hardware. |

**No round trip with BlueWallet, Sparrow, or Electrum has been performed on hardware.** What has
been tested is a single Bitcoin Core 29.4 round trip via the development console.

---

## Signing a transaction

1. Put the PSBT on a FAT32 microSD card.
2. On the device: open the wallet, tap "Sign a transaction", pick the file.
3. Read every review page. The hold gesture that signs does not appear until you have seen them
   all. Amounts the file merely states are marked `STATED`.
4. Sign. Every signature is re-verified against a recomputed sighash before the file is released.
5. Write back to the card, or show as a QR (if 1089 bytes or less).
6. Finalize and broadcast in your wallet software.

If the device refuses the file, it shows a full-screen refusal with a code, what happened, why it
matters, and what to do. The most common refusals:

- **R-02** - multi-input spend without full previous transactions. Use coin control to select a
  single coin, or re-export from Sparrow, Electrum, or Bitcoin Core.
- **R-26** - script type not supported. For wrapped-segwit coins, re-export with the redeem
  script included.

Full refusal code table: [docs/REFUSALS.md](docs/REFUSALS.md).

---

## Verifying a release

Every release is signed with this OpenPGP key:

```
A1E9 53B2 5C6A 623B 77A1 D522 3AC4 BBCF E51A B37D
```

Compare the fingerprint against at least two independent sources (keys.openpgp.org, the repo,
the maintainer's GitHub profile). [docs/VERIFYING.md](docs/VERIFYING.md) is the full guide: check
hashes, check the signature, rebuild the firmware in a pinned container, and compare it
byte-for-byte with what was published.

**0.2.3 is the first release with a build artifact.** Earlier tags had release pages with nothing
to download - the release container never built until 0.2.3.

---

## Security model

1. **No radio.** The radio co-processor is held in reset from the first instruction. No WiFi
   component is compiled in.
2. **No plaintext secret leaves RAM.** Seeds are zeroized on lock, screen exit, and power-off.
   Storage is AEAD ciphertext under a PIN-derived key ladder.
3. **Deterministic.** Key material comes from your dice or mnemonic only. No TRNG, no OS entropy.
4. **Equivalence.** Identical input produces byte-identical output to the desktop BigDice crate.
5. **Verifiable firmware.** Every Verify field is read from the running system, not compiled in.
   A field this build cannot read renders `not read`, not a plausible default.
6. **Secure Boot: not yet.** The digest slots render `not burned`. Planned for 0.3.0.
7. **The signing policy engine is the trust boundary.** Ownership is proven by derivation, not
   asserted by fingerprint. Validation runs with no key in scope, so every refusal happens before
   any spending authority exists.

Full threat model and accepted risks: [docs/SECURITY.md](docs/SECURITY.md).

---

## Releases

| Release | What it is |
|---|---|
| [0.2.3](docs/RELEASE-0.2.3.md) | First release with build artifacts. Firmware delta from 0.2.2 is the version string only. |
| 0.2.2 | Legacy P2PKH signing, R-26 for unsupported scripts, BIP-84 as default. No artifact. |
| 0.2.1 | Ownership by derivation, single-input amount rule, Receive screen. No artifact. |
| 0.2.0 | Sealed storage, PIN, signing, multisig, passphrase, device name. The baseline. No artifact. |

Older release runbooks: [docs/archive/](docs/archive/).

---

## License

notyas is free software under the **GNU General Public License, version 3 or later**. See
[COPYING](COPYING). Every crate declares `GPL-3.0-or-later` except `crates/esp-idf-hmac`
(MIT OR Apache-2.0). Embedded fonts are under the SIL OFL 1.1 (IBM Plex, renamed to "notyas
Sans/Mono" per the Reserved Font Name clause). Details: [docs/THIRD-PARTY.md](docs/THIRD-PARTY.md).

Report defects, failed rebuilds, or security problems at
https://github.com/intnsity/notyas/issues. If reporting from the panel, photograph the refusal
screen's details block - it is hidden until you tap "Show details".
