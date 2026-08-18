# PLATFORM.md - ESP32-P4 Rust platform contributions for notyas 0.2.0

Status: wave-2 planning input. Companion documents in this directory:
ARCHITECTURE.md, SECURITY.md, MILESTONES.md, OPEN-QUESTIONS.md (parallel
workflow; the storage/PIN design there governs how shortlist item 1 is used).
PARITY.md maps which Coldcard-parity rows each crate serves; CAMERA.md covers
the QR decode stack these crates plug into.

notyas 0.2.0 will need lower-level platform pieces that do not exist in the
Rust ecosystem today. This document is the exists/gap/skip survey and the ranked
contribution shortlist.

**Read section 6 first.** It was written on the premise that those pieces would be
extracted as standalone, published crates. The project owner answered the licensing
question on 2026-08-17 - GPL-3.0-or-later for everything - and under that answer nothing
is extracted and nothing is published to crates.io. The gap analysis in sections 1-4 is
unaffected and still correct; what changes is the FORM the contribution takes, and
section 6 restates every shortlist item under the answer. The survey below still reads
as though crates were the destination; that framing is superseded, not the findings.

## 1. Survey: security silicon (HMAC / DS / ECDSA / Key Manager / eFuse)

Ground truth on hardware and C drivers:

- P4 silicon has HMAC, RSA-DS, ECDSA, AES, SHA and eFuse blocks. The `esp32p4`
  PAC v0.2.0 (svd2rust) exposes register blocks for all of these, but not the
  Key Manager (absent from the SVD as of 0.2.0).
  https://docs.rs/esp32p4/latest/esp32p4/
- ESP-IDF ships P4 drivers for HMAC, ECDSA-DS and RSA-DS in the peripherals
  API reference.
  https://docs.espressif.com/projects/esp-idf/en/latest/esp32p4/api-reference/peripherals/index.html
- Key Manager: no dedicated P4 API page in stable docs (the P4 `key_mgr.html`
  URL 404s), but the P4 flash-encryption guide documents Key-Manager-based
  flash keys and `esp_key_mgr_*` exists in IDF (full API page published for the
  C5: AES / ECDH0 deployment modes, key purposes, activate/deactivate).
  Treat P4 `esp_key_mgr` as present but thinly documented; verify against IDF
  v5.5 headers during implementation.
  https://docs.espressif.com/projects/esp-idf/en/stable/esp32p4/security/flash-encryption.html ,
  https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/api-reference/peripherals/key_manager.html ,
  https://docs.espressif.com/projects/esp-idf/en/stable/esp32p4/security/security.html

Rust coverage today (gap confirmed):

- esp-idf-sys's default bindgen header includes `esp_efuse.h` and `nvs.h` but
  not `esp_hmac.h`, `esp_ds.h`, or `esp_key_mgr.h` - no raw bindings out of
  the box. https://github.com/esp-rs/esp-idf-sys (src/include/esp-idf/bindings.h)
- The escape hatch is first-class: `[[package.metadata.esp-idf-sys.extra_components]]`
  with `bindings_header` generates bindings for any extra IDF headers, so a
  wrapper crate is cheap - no fork of esp-idf-sys needed.
  https://github.com/esp-rs/esp-idf-sys/blob/master/BUILD-OPTIONS.md
- esp-hal has HMAC drivers only for S2/S3/C3/C6/H2, not P4; this repo's
  docs/research/rust-esp32p4.md records HMAC/DS/ECDSA/Key Manager as
  unsupported for P4 in esp-hal.
  https://docs.rs/esp-hal/latest/src/esp_hal/hmac.rs.html ,
  https://github.com/esp-rs/esp-hal
- esp-idf-hal wraps gpio/i2c/spi and similar but none of these security
  peripherals. https://lib.rs/crates/esp-idf-hal

Prior art for a sealed-storage layer (designs, not portable code - see the
licensing section):

- Blockstream Jade (C, ESP32): encrypted keychain blob in NVS, single-byte
  attempt counter decremented via `storage_decrement_counter()`, blob erased at
  zero; atomicity via `nvs_commit()`; PIN key strengthened by their
  blind-oracle pinserver - a network dependency an airgapped device cannot
  copy. https://github.com/Blockstream/Jade (main/storage.c) ,
  https://help.blockstream.com/hc/en-us/articles/9639949755673-How-does-Blockstream-Jade-s-oracle-enforced-PIN-protection-work
- Trezor (C): NORCOW append-only copy-on-write flash log for wear leveling and
  power-loss safety; PIN scheme built on an encrypted data key plus a PIN
  verification code, with a fault-injection-hardened counter (their earlier
  32-word counter design was documented as FI-vulnerable - a lesson worth
  importing). https://docs.trezor.io/trezor-firmware/storage/index.html ,
  https://github.com/trezor/trezor-firmware/blob/main/storage/norcow.c

Verdict: gap worth filling, and the highest-value contribution available.
Nothing in Rust today gives an ESP32 project "seal a secret under PIN plus a
silicon-bound key with attempt limiting." Honest constraint to document
(corrected 2026-08-17 from ESP-SEAL.md 7.2 - the earlier wording here credited
flash encryption with rollback resistance it does not provide): with no secure
element and (on most P4 boards) external flash, the counter has to live in a
PLAINTEXT partition, because bit-clear counters are incompatible with XTS write
granularity. XTS-AES flash encryption therefore does not raise the cost of a
counter rollback at all. What is actually detected is a ledger-only rollback,
by a mount-time witness check against the records and by device-keyed guard
patterns; a consistent full-flash snapshot and restore is undetectable and needs
no key. The claim to make is "the attempt counter converts unlimited offline
guesses into N guesses per full-flash restore cycle" - the same trust model as
other non-secure-element-class devices. State it; do not oversell it.

## 2. Survey: display / input

- `buoyant-esp32p4` already exists: hardware-accelerated (PPA + MIPI-DSI)
  render target for Buoyant on P4 over ESP-IDF v5.5, with an embedded-graphics
  DrawTarget fallback. Our esp_lcd-DSI DrawTarget glue substantially overlaps
  it. https://github.com/zebra-pig/buoyant-esp32p4 ,
  https://github.com/riley-williams/buoyant
- GT911 touch: two maintained embedded-hal drivers exist - `gt911`
  (Apache-2.0, blocking + async) and `gt9x` (no_std, blocking + async).
  https://crates.io/crates/gt911 , https://github.com/jnshuiji/gt9x

Verdict: skip as new crates. Anything our display path has that
`buoyant-esp32p4` lacks (double-buffer publish discipline, tear-free swap on
esp_lcd DPI, silicon-revision quirks) goes upstream as PRs/issues; GT911 quirks
(0x5D/0x14 address probe, INT-less polled mode) likewise belong upstream in
`gt911`/`gt9x` rather than in a competing crate.

## 3. Survey: bitcoin formats

- **UR / fountain codes: exists, use.** `ur` (dspicher/ur-rs) 0.5.2, MIT,
  no_std, fountain encode and decode, active; `foundation-ur` 0.4.0 (MIT,
  static-allocation-friendly) and `foundation-urtypes` 0.5.0 (registry types)
  from Foundation's foundation-rs monorepo. No contribution needed. Note:
  foundation-rs as a whole mixes GPL-3 and MIT crates - check per-crate SPDX
  before depending. https://lib.rs/crates/ur , https://github.com/dspicher/ur-rs ,
  https://crates.io/crates/foundation-ur ,
  https://github.com/Foundation-Devices/foundation-rs
- **BBQr: exists with a partial gap.** `bbqr` 0.6.0 (SatoshiPortal, MIT)
  does encode + decode + compression; std-oriented, which is fine for notyas
  (std on ESP-IDF). The gap is a no_std-friendly decode for esp-hal-class
  targets - best delivered as an upstream feature PR, not a new crate.
  https://bbqr.org/ , https://github.com/coinkite/BBQr ,
  https://crates.io/crates/bbqr , https://github.com/SatoshiPortal/bbqr-rust
- **SeedQR / CompactSeedQR: verified gap.** No Rust crate found. Spec and
  published test vectors live in the SeedSigner repo; existing implementations
  are Python and Go. Tiny surface (11-bit index packing, checksum handling),
  high reuse across wallet projects.
  https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md ,
  https://pkg.go.dev/seedhammer.com/seedqr
- **BSMS (BIP-129): verified gap with named downstream demand.** No Rust
  implementation found; the reference implementation is Coinkite's Python, and
  BDK has an open feature request explicitly discussing a separate crate
  (bdk_wallet issue 170). Serves the PARITY.md BSMS row.
  https://github.com/bitcoin/bips/blob/master/bip-0129.mediawiki ,
  https://github.com/coinkite/bsms-bitcoin-secure-multisig-setup ,
  https://github.com/bitcoindevkit/bdk_wallet/issues/170 ,
  https://coldcard.com/docs/bsms/

## 4. Survey: fonts / deterministic builds

- Font atlases: crowded space - `mplusfonts` (swash-powered proc-macro bitmap
  fonts), `embedded_font`, `bitmap-font`, `embedded-graphics-unicodefonts`.
  Our host-side Plex atlas tool adds little over `mplusfonts` as a public
  crate. Skip; ship in-repo under GPL3 (OFL Reserved-Font-Name renaming
  already handled). https://lib.rs/crates/mplusfonts ,
  https://crates.io/crates/embedded_font
- Deterministic builds: ESP-IDF documents reproducible builds for the C side
  and Jade maintains a working reproducible pipeline, but no published,
  verified recipe exists for Rust + esp-idf-sys + `-Zbuild-std` (path
  remapping, lockfiles, IDF component pinning - this repo already pins via
  components_esp32p4.lock). The contribution is a document plus CI example,
  not a crate - small, real, and directly supporting a verify-your-firmware
  device. https://github.com/Blockstream/Jade/blob/master/REPRODUCIBLE.md

## 5. Ranked contribution shortlist

1. **esp-seal** (working name) - sealed secret storage for ESP32: seal/unseal
   a blob under a PIN, KDF bound to the eFuse-keyed HMAC peripheral (Key
   Manager where present), AEAD-encrypted blob, fault-hardened attempt counter
   with erase-at-zero, power-loss-safe two-phase commit (NVS-atomic or
   NORCOW-style log), explicit documented trust model. Effort: L. Nothing
   comparable exists; benefits every wallet or secret-holding ESP32 product in
   Rust. Prior art: Jade storage.c and the Trezor storage design docs
   (section 1). This is the crate under the 0.2.0 storage layer specified in
   this directory's SECURITY.md/ARCHITECTURE.md where present.
2. **esp-idf-hmac / esp-idf-ds / esp-idf-key-mgr safe wrappers** - thin safe
   Rust over the IDF drivers via the `extra_components`/`bindings_header`
   mechanism; the prerequisite layer for item 1 and independently useful;
   candidate for upstreaming into esp-idf-hal. Effort: S-M. Gap verified
   (section 1).
3. **seedqr** - no_std SeedQR + CompactSeedQR encode/decode validated against
   SeedSigner's published test vectors. Effort: S. No Rust implementation
   exists; used by the CAMERA.md scan-in scope and by any SeedSigner-adjacent
   tooling.
4. **bsms** - BIP-129 signer + coordinator rounds (token KDF, encryption,
   descriptor record parse/emit) with Coinkite test vectors. Effort: M. No
   Rust implementation exists; BDK has an open request.
5. **no_std BBQr decode** - preferably an upstream no_std feature PR to
   `bbqr` rather than a new crate. Effort: S. Partial gap.
6. **Reproducible Rust-on-ESP-IDF recipe** - documentation plus CI example
   (path remap, -Zbuild-std pinning, IDF component locks), modeled on Jade's
   REPRODUCIBLE.md. Effort: S. Documentation contribution, not a crate.

Skips, with reasons: UR/fountain (`ur`, `foundation-ur` cover it - MIT,
no_std, maintained); GT911 driver (`gt911`, `gt9x` exist - upstream quirks
instead); DSI DrawTarget crate (`buoyant-esp32p4` exists - contribute patches);
font atlas tool (`mplusfonts`/`embedded_font` cover the space).

## 6. Licensing - DECIDED 2026-08-17 by the project owner (OPEN-QUESTIONS Q8)

**Answer: GPL-3.0-or-later, everywhere.** The firmware, every notyas crate, the
tools, and anything that might otherwise have been extracted. For wallet firmware,
copyleft prevents closed forks of code that handles user keys, and the adoption cost
on the low-level pieces is accepted deliberately. Nothing is published to crates.io.

**What follows, and it reshapes section 5 above.** ESP-SEAL.md 9.1 stated the
consequence in advance and it now applies: under a GPL answer `esp-seal` should not be
extracted at all, because a GPL3 "platform contribution" that the permissively licensed
ESP32/Rust ecosystem will not depend on is worse than an honest internal module. So:

- **Item 1 (esp-seal):** stays a module inside notyas-wallet (Q44). The contribution
  becomes ESP-SEAL.md itself, published in-repo: the byte-exact on-flash format, the
  state machine, the power-loss analysis and the attack analysis. Any project can read
  it and reimplement freely. That is a real contribution and it is the honest
  description of what 0.2.0 delivers.
- **Item 2 (esp-idf-hmac / -ds / -key-mgr):** in-tree. The verified gap is still real,
  but "candidate for upstreaming into esp-idf-hal" is withdrawn - esp-idf-hal is
  MIT/Apache and will not take a GPL dependency. Residual value is ours: it is the
  silicon leg under every storage row, and the `extra_components` / `bindings_header`
  recipe is documentable independently of licence.
- **Item 3 (seedqr):** in-tree. Still the only Rust implementation, still needed by
  m11's scan-in; under the ratified Q17 its ENCODE half is test-vector-only, because
  SeedQR display-out is declined.
- **Item 4 (bsms):** in-tree if built at all (Q15). BDK's open request is no longer a
  reason to build it, because BDK is permissive.
- **Item 5 (no_std BBQr decode):** the only shortlist item that is an upstream PR to
  someone else's permissive project rather than a crate of ours, so our patch would go
  out under MIT. **That needs the owner's sign-off and is OPEN-QUESTIONS Q51.**
- **Item 6 (reproducible Rust-on-ESP-IDF recipe):** unaffected, and now the strongest
  remaining contribution. A document's licence is no barrier to anyone reading it, and
  no published recipe exists for the Rust + esp-idf-sys + `-Zbuild-std` stack.

**Two constraints survive unchanged.** Trezor's and Jade's code are copyleft, so only
their published DESIGNS may inform a clean-room implementation - being GPL ourselves
does not license a port. And font data is the one carve-out: IBM Plex and the generated
atlases are SIL OFL 1.1 with the Reserved Font Name renaming, per LICENSE-fonts, and
that distinction must survive any blanket "everything is GPL" statement.

**One constraint is now moot:** R6's warning that `foundation-urtypes`
(GPL-3.0-or-later) must never be pulled into a permissive crate binds nothing, because
there is no permissive crate. The placement it produced - UR and transport encoding
inside notyas-wallet - is still right and should not be undone.

---

### 6.1 The tradeoff as it was weighed (retained for the record, no longer open)

The firmware is GPL-3.0-or-later. For the extracted crates there were two
coherent options:

- **(a) GPL3 crates.** Preserves reciprocity on the crates themselves.
  Practical cost: the permissively licensed ecosystems these crates would
  serve (esp-hal and the esp-idf-* stack are MIT/Apache-2.0; `ur`, `bbqr`,
  `gt911` are MIT/Apache) generally do not take GPL dependencies, which caps
  adoption - and adoption is the point of extracting them.
- **(b) Dual MIT OR Apache-2.0 crates.** The Rust-ecosystem norm; maximizes
  reuse (Foundation relicensed their API crates this way for exactly that
  reason: https://foundation.xyz/developers ,
  https://github.com/Foundation-Devices/foundation-rs), and the GPL3 firmware
  can consume them freely. Cost: forfeits copyleft on the crates themselves.

Constraint under either option: Trezor's storage code and Jade's code are
copyleft, so neither can be ported into an MIT/Apache crate - only their
published designs can inform a clean-room Rust implementation. A per-crate
split was also possible (e.g. permissive for the interop formats seedqr/bsms
where ecosystem uptake matters most, GPL3 for esp-seal); ESP-SEAL.md 9.1 argued that
particular split was backwards, because esp-seal has the largest audience outside
Bitcoin of anything on the shortlist. All of it is settled by the answer at the top of
this section: (a), for everything.

Repo files consulted: docs/ARCHITECTURE.md, docs/research/rust-esp32p4.md,
firmware/src/display.rs, firmware/src/touch.rs.

Input to: MILESTONES.md reconciliation
