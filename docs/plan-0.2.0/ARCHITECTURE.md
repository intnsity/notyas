# notyas 0.2.0 - Architecture plan

Status: PLAN, written 2026-08-17 from four research inputs (storage deep-dive, signing
stack deep-dive, UX deep-dive, codebase readiness audit). Not yet reviewed; nothing
here is committed until the red-team pass. docs/SECURITY.md remains normative for
invariants; this plan proposes the 0.2.0 amendments in plan-0.2.0/SECURITY.md.

0.2.0 scope: PIN-protected seed STORAGE, PSBT SIGNING, wallet management, MULTISIG
management. 0.1.0's stateless generator remains a first-class, unmodified mode: a user
who never saves a wallet gets exactly today's behavior, and a device with a blank
wallet partition is behaviorally a 0.1.0 device with a "Save" offer.

---

## 1. Crate layout

```
notyas/
  Cargo.toml            root WORKSPACE (new - the audit found each crate has its own
                        lock; 0.2.0 lands one workspace + CI so crates cannot drift)
  crates/
    notyas-core/        UNCHANGED ROLE: #![no_std]+alloc, IDF-free, RNG-free, I/O-free.
                        entropy/bip39/derive/qr, byte-equivalent to desktop BigDice.
                        0.2.0 EXTENDS it with a signing-capable key API (section 5.1).
                        Gains NO new dependencies: no miniscript, no AEAD, no KDF.
    notyas-wallet/      NEW: #![no_std]+alloc, IDF-free, RNG-free, I/O-free.
                        Everything 0.2.0 adds that the ecosystem does not provide:
                        seal/unseal (PIN KDF ladder + AEAD), two-slot storage record
                        format (behind a Storage trait the firmware implements),
                        wallet registry, unlock session, PSBT policy engine, change
                        verification, multisig registration store, airgap transport
                        encoding (PSBT file encodings, UR2 chunking). Host-testable,
                        power-loss-fuzzable on host.
    notyas-ui/          state machine, extended per section 7 (per-screen modules,
                        tick(), new screens); still no_std-testable, secrets still
                        exactly-one-state-alive.
    notyas-fonts/       unchanged.
  firmware/             std/esp-idf. Gains: flash Storage-trait driver, HMAC-eFuse
                        binding call, SD subsystem (FATFS mount lifecycle), tick-driven
                        repaint, extended UiRequest handling. Still nothing
                        cryptographic beyond calling into the crates.
  tools/                build/flash/fonts/uisim + new: corpus tools, differential
                        harness, release runbook additions.
```

### Responsibility boundary of notyas-wallet vs vetted primitives

House rule: vetted primitives reused, policy and state machines ours. Concretely
(sources: signing deep-dive sections 1 and 5):

Reused, never reimplemented:

| Concern | Crate (no_std+alloc config) |
|---|---|
| PSBT v0 parse/serialize/fee/extract, sighash (all script types), ECDSA + Schnorr signing, taproot tweak, BIP-32 | `bitcoin = "=0.32.102"`, `default-features=false, features=["alloc","base64"]` (base64 added for Coldcard-convention PSBT text files) |
| Descriptor parse/checksum/derive/script_pubkey, PSBT finalize + interpreter sanity re-check | `miniscript = "13.1"`, `default-features=false` (no_std in 13.x is default-features-off; the named `no-std` feature was the 12.x convention and no longer exists - verified against crates.io 13.1.0 metadata 2026-08-17. Depends on bitcoin ^0.32.6 - fits the =0.32.102 pin) |
| curve ops | `secp256k1` transitively via bitcoin (RFC6979 ECDSA, BIP-340 Schnorr) |
| PIN stretch | RustCrypto `argon2`, `default-features=false` REQUIRED - its default `password-hash`/`rand` features pull rand_core, which invariant 1's build-graph ban rejects (no_std, no-alloc capable; https://github.com/RustCrypto/password-hashes/tree/master/argon2) |
| AEAD | RustCrypto `chacha20poly1305`, `default-features=false, features=["alloc"]` REQUIRED - `getrandom` is one of its DEFAULT features and would trip the RNG ban |
| KDF plumbing | RustCrypto `hkdf`, `hmac`, `sha2` (sha2/hmac already in-graph) |
| UR2 fountain encoding | `foundation-ur` + `foundation-urtypes`, both `default-features=false` (std is a DEFAULT feature of foundation-ur - must be disabled; maintained by a hardware-wallet vendor; https://docs.rs/foundation-ur/latest/foundation_ur/) |
| wipe-on-drop | `zeroize` (in-graph) |

License audit of every new dependency against our GPL-3.0-or-later (red-team
addition, verified against crates.io metadata 2026-08-17): `bitcoin` CC0-1.0,
`miniscript` CC0-1.0, `argon2`/`chacha20poly1305`/`hkdf`/`hmac`/`sha2`/`zeroize`
MIT OR Apache-2.0, `foundation-ur` MIT, `foundation-urtypes` GPL-3.0-or-later.
All compatible with GPL3 firmware; foundation-urtypes is itself GPL and therefore
binds the combined work to GPL3 terms we already carry. No license blocker.

Explicitly NOT adopted, with reasons recorded from the signing research: BDK
(std-only, coordinator-shaped - we take its "change = what the internal keychain
derives" idea as ~50 lines over miniscript, not the dependency;
https://docs.rs/crate/bdk_wallet/latest/features), `rust-psbt`/PSBT v2 (pre-1.0, v0 is
the coordinator interop baseline - Sparrow/Electrum/Specter/Core all speak v0;
https://github.com/rust-bitcoin/rust-psbt), the `bip39`/`slip132` crates (notyas-core
equivalents are SPEC-normative), the `ur` crate (std-default;
https://docs.rs/crate/ur/latest/features), `secp256kfun` (not vetted-primitives).

Owned by notyas-wallet because no crate provides it (the ecosystem gap): the signing
policy engine and its checklist (section 5.3), descriptor-exact change detection with
gap bounds, the wallet/multisig registration store and its verification rules, the
seal/unseal construction and storage record format, session/secret lifecycle, and
emission rules (finalize-when-complete, encoding-matches-input, UR chunk parameters).

miniscript placement: inside notyas-wallet, never in notyas-core. notyas-core stays
the small BigDice-equivalent audit surface; notyas-wallet is the second, larger audit
surface with its own vector suites. One new crate, not three - a separate descriptor
crate or UR crate would be shallow modules wrapping single dependencies.

Precedent for the shape: Frostsnap ships production ESP32 signer firmware as exactly
this split - a pure no_std core state-machine crate under a thin device driver
(https://github.com/frostsnap/frostsnap).

---

## 2. Storage architecture

### 2.1 Chosen scheme: device-bound sealed storage (candidate A with candidate B's framing)

From the storage deep-dive's ranked candidates, 0.2.0 ships candidate A - Argon2id +
HMAC-eFuse + AEAD in a hand-rolled two-slot raw partition - presented and defaulted
per candidate B (deterministic-wipe posture, passphrase-first UX). Rejected
alternatives, and why:

- Blind oracle (Jade's model, https://blog.blockstream.com/jade-virtual-secure-element/):
  the only scheme that truly defeats offline brute force after theft, but it requires
  a networked helper device at every unlock, which breaks notyas's single-device,
  radio-dead identity. Deferred as a possible opt-in mode (OPEN-QUESTIONS Q9), never
  the thing that lets us claim "secure storage" by default.
- Key Manager / SRAM-PUF keys: documented as ESP32-P4 chip revision >= v3.0 only
  (https://docs.espressif.com/projects/esp-idf/en/stable/esp32p4/api-reference/peripherals/key_manager.html);
  both bench units are rev v1.3 (BOARDS.md). Not designed around; revisit if
  production silicon is confirmed >= v3.0 (OPEN-QUESTIONS Q1).
- NVS (incl. HMAC-scheme NVS encryption): would kill the "NVS is never mounted"
  invariant, pull a large C key-value surface into the TCB, and its key management
  fights the PIN-sealing design. The raw two-slot format is small, host-fuzzable,
  and keeps invariant 2's sentence literally true.
- SD card as seed vault: rejected outright - removable media defeats any
  device-bound counter and violates the SD-stays-untrusted doctrine. SD encrypted
  BACKUP export (Krux/Passport style) is a separate, honestly-labeled feature
  (OPEN-QUESTIONS Q8).

### 2.2 The key ladder

All primitives vetted; construction ours. PIN means "PIN or passphrase" throughout -
the entry surface accepts full alphanumeric (OPEN-QUESTIONS Q4, ratified: minimum 6
characters, no maximum below 64).

```
pin_norm    = NFKD(pin)                                   # same normalization discipline as BIP39
prestretch  = Argon2id(pin_norm, kdf_salt, m, t, p=1)     # memory-hard; params pinned after m1
                                                          #   on-device benchmark (see 2.3)
bound       = HMAC-SHA256_efuse(prestretch)               # P4 HMAC peripheral, key in a
                                                          #   read-protected eFuse block: software
                                                          #   never sees the key, so every guess
                                                          #   must run on this physical device
okm         = HKDF-SHA256(ikm=bound,
                salt=kdf_salt,
                info="notyas-seal-v1" || slot_id || wipe_epoch || seal_seq)
                                                          # wipe_epoch REQUIRED: without it, a
                                                          #   wipe that loses seal_seq state and a
                                                          #   re-save under the same PIN could
                                                          #   repeat a (key, nonce) pair against a
                                                          #   pre-wipe flash snapshot (keystream
                                                          #   reuse). Epoch is one-way; see 2.5.
key, nonce  = okm[0..32], okm[32..44]
ct          = ChaCha20-Poly1305.seal(key, nonce,
                aad=record_header, pt=wallet_record)      # AEAD tag = wrong-PIN detector
                                                          #   (Trezor PVC intent, stronger primitive)
```

- HMAC-eFuse step: `ESP_EFUSE_KEY_PURPOSE_HMAC_UP` key. **Burned by the HOST with
  `espefuse.py` as a provisioning step before first boot, then write- and
  read-protected - NOT burned at first save (amended 2026-08-17 by the ratified
  OPEN-QUESTIONS Q45; release firmware contains no eFuse-burn code at all, and a blank
  unprovisioned device refuses to format rather than burning anything).** After
  read-protection the key can be made "completely inaccessible for any resources outside
  the cryptographic modules".
  P4-specific citation (red-team fix - the earlier draft cited the ESP32-S3 page):
  the ESP32-P4 HMAC peripheral with eFuse keys and `esp_hmac_calculate()` is
  documented for IDF v5.5 at
  https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/peripherals/hmac.html
  (verified 2026-08-17: HMAC_UP purpose value 8, keys in eFuse blocks 0-5, no chip
  revision constraint documented - unlike the Key Manager, which needs rev >= v3.0).
  This is the notyas analog of the BitBox02's per-guess SE round-trip
  (https://bitbox.swiss/bitbox02/security-features/), minus fault-injection
  resistance - stated honestly in SECURITY.md.
- Argon2id is the second wall: if a fault-injection lab extracts the eFuse key (the
  ESP32 family track record says assume eventually possible -
  https://www.usenix.org/system/files/woot24-delvaux.pdf,
  https://courk.cc/esp32-c3-c6-fault-injection), the attack collapses to offline
  memory-hard guessing whose cost is set by PIN/passphrase entropy. The UI therefore
  nudges toward passphrases and shows an entropy estimate at PIN creation.
- ChaCha20-Poly1305 authenticated decryption means a wrong PIN fails the tag; there is
  no oracle distinguishing "wrong PIN" from "corrupt record" beyond the counter's
  decrement (which happens before the attempt - fail-closed, Trezor discipline,
  https://docs.trezor.io/trezor-firmware/storage/index.html).

The wallet_record plaintext holds: BIP39 entropy bytes (not the 64-byte seed - keeps
mnemonic re-display and re-verification possible), label, network, creation metadata,
backup-verified flag, and the wallet's registered-descriptor references. All metadata
is inside the AEAD: a pre-PIN flash dump reveals only that sealed slots exist.

### 2.3 KDF parameters (to be measured, not guessed)

No published Argon2-on-ESP32 numbers exist; PSRAM random-access latency will dominate
(https://www.pschatzmann.ch/home/2022/05/30/esp32-and-psram/). Milestone m1 benchmarks
on the rev v1.3 board: starting point m=64 MiB in PSRAM, t=3, p=1, target 0.5-2 s per
unlock; fallback m=16 MiB in internal SRAM at higher t if PSRAM is pathological.
Benchmark caveat (red-team): on the P4, enabling flash encryption ALSO encrypts all
external-PSRAM traffic with the same XTS machinery, non-optionally
(https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/security/flash-encryption.html),
so release units pay an extra latency cost the bare dev board does not. The m1
benchmark must therefore measure with flash+PSRAM encryption enabled (a sacrificial
dev unit or the eFuse-emulation path), or the pinned parameters will overshoot the
unlock-time target on release hardware. Side benefit, stated honestly: on release
units the Argon2 working memory is encrypted at rest in PSRAM; on dev boards it is
plaintext PSRAM (in-package die, still probe-resistant in practice, no claim made).
Parameters are then pinned in SPEC + known-answer vectors, and the boot self-test runs
a reduced-cost pinned vector (full-cost KDF does not fit the 1 s self-test budget -
documented in the self-test source).

### 2.4 Randomness policy: fully deterministic (decision)

The audit flags this as the blocking decision. Chosen: option (b) - NO RNG anywhere,
uniqueness by construction, keeping SECURITY.md invariant 3 mechanically checkable
("notyas-core and notyas-wallet have no RNG API" extends the existing dependency-graph
test to the new crate; getrandom/rand* stay banned from the whole graph).

- kdf_salt = SHA256("notyas-salt-v1" || device_binding || slot_id), where
  device_binding = HMAC_efuse("notyas-device-id") computed at runtime. The salt's only
  job is defeating cross-device precomputation; an attacker who can read the salt
  from flash necessarily also holds the device (and post-FI holds device_binding), so
  a stored-random salt would add nothing - Trezor's own docs make the same
  attacker-has-the-salt assumption (https://docs.trezor.io/trezor-firmware/storage/index.html).
- AEAD nonce reuse is prevented structurally, not randomly: seal_seq is a
  device-global monotonic sequence number, bumped on every seal, never decremented;
  on mount seal_seq = max(counter high-water, max over valid record seqs) + 1, and
  wipe_epoch (one-way, in the HKDF info) covers the wipe-erases-everything case -
  see 2.5. Every write derives a fresh (key, nonce) pair through HKDF info binding,
  so identical plaintexts re-sealed produce unrelated ciphertexts and no
  plaintext-equality leak exists.
- The distrusted P4 TRNG (esp-hal#5982, ARCHITECTURE.md 0.1.0) is not used, not even
  for salts - rejected option (a) because it would trade a checkable invariant for a
  hardware-quality claim we explicitly do not trust.
- Schnorr aux-rand: with `default-features=false` (no `rand`), BIP-340 signing takes
  the deterministic no-aux-rand path. BIP-340 explicitly permits this; the cost is a
  weaker side-channel AND fault-attack posture, the gain is signature determinism,
  which feeds invariant 4 (byte-identical signatures vs pinned vectors). Decision
  recorded in SPEC; RFC6979 ECDSA is deterministic by definition.
- Fault honesty (red-team addition): deterministic nonces are the textbook target for
  fault-injection key extraction (glitch the message hash, obtain two signatures with
  the same nonce over different messages, solve for the key). Mitigations, layered:
  (1) the post-sign gate (5.3 check 10) re-verifies every signature against a sighash
  recomputed independently from the validated PSBT, so a faulted-digest signature is
  caught before it leaves the device - this check is a security control, not a
  formality, and must not share the signing code path's digest computation; (2) a
  glitched-signer attack requires the fault lab that tier 2/3 of SECURITY.md already
  concedes. The tradeoff is accepted with both eyes open, not silently.

### 2.5 Attempt counter, wipe, duress

- Counter: Trezor-style paired one-way bit-clear logs (pin_entry_log /
  pin_success_log) interleaved with guard bits derived from a per-device guard key -
  a single glitch must corrupt data and guard patterns together
  (https://docs.trezor.io/trezor-firmware/storage/index.html).
  Decrement BEFORE the unseal attempt; clear on success.
- Counter placement (red-team correction): bit-clear logs CANNOT live inside the
  `encrypted` wallets partition. XTS-encrypted partitions require 16-byte-aligned,
  16-byte-minimum writes and cannot re-program individual bits of already-written
  flash (https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/security/flash-encryption.html)
  - progressive 1->0 bit programming is exactly what the Trezor scheme is built on.
  The counters therefore live in a dedicated PLAINTEXT `counters` partition (see
  2.7). This loses nothing real: the counter holds no secret (attempt bits, guard
  bits, seal_seq high-water, wipe_epoch), the guard patterns are keyed by a
  device-bound HMAC-eFuse-derived guard key so a forged counter image is detectable
  short of full key extraction, and SECURITY.md tier 3 already concedes that any
  flash-level attacker can snapshot/restore the counter regardless of encryption.
  Chosen over the alternative (A/B 16-byte counter records inside the encrypted
  partition) because bit-clear + guard bits gives real mid-decrement glitch
  robustness, which the A/B variant does not.
- seal_seq and wipe_epoch: seal_seq high-water lives in the counters partition;
  every sealed record also carries its own seq in the AAD header. On mount:
  seal_seq = max(counter high-water, max over valid record seqs) + 1 - so a torn
  counter write can never cause seq reuse while records exist. wipe_epoch is a
  one-way bit-clear field in the same partition, bumped by every wipe, and is an
  input to the HKDF info (2.2), so even a post-wipe re-save under the same PIN and
  slot can never repeat a (key, nonce) pair. Residual, stated honestly: an attacker
  who restores a FULL pre-wipe flash snapshot (records + counters) and returns the
  device unnoticed is the evil-maid/snapshot tier SECURITY.md already concedes.
- Wipe-on-N: default N=10 consecutive failures, range 3..=25 (OPEN-QUESTIONS Q5,
  ratified) -> erase both seed-record slots and bump a wipe-epoch marker. Because notyas
  is deterministic, the SEED is re-derivable from the user's dice rolls or words, which
  is why N can be aggressive. **Stated precisely, because the loose version is false:
  multisig registrations, labels and device settings are NOT re-derivable from a
  mnemonic and a wipe destroys them permanently.** The wipe screens must say so, and
  Q14 owns whether a backup exists to recover them.
- Honest limits, stated in SECURITY.md, and stated precisely because the loose
  version overstates the protection (corrected 2026-08-17 from ESP-SEAL.md 7.2): the
  counter lives in flash the CPU can address, and the `counters` partition is
  **PLAINTEXT**. Flash encryption therefore does **not** raise the cost of a counter
  rollback - there is no key to break in that partition, only bytes to copy back. Two
  sub-cases, and only one of them is detected:
  - **Ledger-only rollback** (restore an old counter image, keep the current records)
    IS detected. Mount runs a witness check: a record whose `seal_seq` outranks the
    ledger's high-water, or a blank ledger beside a non-blank records region, is
    tamper and the device must refuse rather than silently re-initialise - which is
    what would otherwise make a counter reset free. The device-keyed guard patterns
    prevent forging a fresh cell without the eFuse key.
  - **Full-flash snapshot and restore** (both partitions, consistently) is **not
    detectable and not preventable, and needs no key at all**: the attacker writes
    the same ciphertext bytes back.

  The honest claim, which replaces the bare phrase "attempt limited" everywhere it
  appears: **the attempt counter converts unlimited offline guesses into N guesses
  per full-flash restore cycle.** Against a thief with a hot-air station and a
  programmer that is a real slowdown of several orders of magnitude. It is not a
  wall, and nothing on rev v1.3 P4 silicon can make it one, because the chip has no
  monotonic counter the CPU cannot reach. This is precisely the gap a secure element
  would fill (https://bitbox.swiss/bitbox02/threat-model/); we do not paper over it.
- Duress PIN (OPEN-QUESTIONS Q2, now with a red-team caveat): a second PIN whose
  ladder unseals a decoy slot set; no stored marker says which PIN is which
  (Coldcard trick-PIN precedent,
  https://blog.coinkite.com/understanding-mk4-security-model/). CAVEAT: "which PIN"
  is hidden, but "how many wallets exist" is NOT - slot occupancy is visible in a
  pre-PIN flash dump, and the Verify screen as drafted reports "N sealed slots".
  A coercer who sees 3 occupied slots and is shown 1 decoy wallet knows they are
  being played. Real deniability requires all slots to be ciphertext-filled at all
  times (device-bound pseudorandom filler in unused slots) and a degraded Verify
  storage readout. That is a design decision with an honesty cost - moved to Q2
  with full analysis; the "indistinguishable by construction" claim is NOT made
  until Q2 is decided.

### 2.6 Storage medium and record format

Raw dedicated partition, hand-rolled two-slot A/B commit, format owned by
notyas-wallet behind a Storage trait (`read_sector/erase_sector/write_sector` +
geometry), firmware implements it over `esp_partition_*`. Norcow is the reference
design (https://docs.trezor.io/trezor-firmware/storage/index.html).

- Record commit: write the inactive slot fully (header, seal_seq, kdf params, salt
  inputs, ct, AEAD tag), verify readback, then the slot with the higher valid
  seal_seq is authoritative - a torn write corrupts at most the slot being written;
  no separate pointer flip needed because seq comparison IS the commit point.
- Counter writes live in the separate plaintext `counters` partition (2.5), so a
  counter update can never tear a seed record - and never has to obey the encrypted
  partition's 16-byte write granularity.
- Fixed slot budget inside the 256 KiB wallets partition: 8 wallet slot pairs
  (4 KiB sectors), 8 registry record pairs (multisig descriptors), 1 header pair.
  Capacity honest and displayed ("8 wallets max"), Coldcard-style bounded registry.
- Stale-ciphertext rule (red-team addition): any operation that re-seals under a new
  key - PIN change re-sealing every record, wallet delete, wipe - MUST erase the now
  -stale inactive slot of each pair after the new record is committed and verified.
  Two-slot A/B otherwise leaves the previous ciphertext (sealed under the OLD PIN)
  readable in the inactive slot; a user who changed their PIN because it was
  compromised deserves the old-PIN ciphertext actually gone. Erase-after-commit
  order keeps power-loss safety: a cut before the erase leaves a valid new record
  plus a stale-but-superseded old one, cleaned up on next mount (host fuzzer covers
  this path too).
- Host test: simulated flash truncating/corrupting the write stream at every byte
  offset and after every erase; property: mount yields the previous record or the new
  one, never garbage, never a panic (audit section 5.3).

### 2.7 Partition table evolution

**SUPERSEDED 2026-08-17 by the ratified OPEN-QUESTIONS Q7 (reconciliation R2). The
offsets below are the frozen ones; the original 0x410000 / 0x450000 layout is gone
because a growing app would have relocated them and destroyed every sealed record on
upgrade.**

```
# Name,    Type, SubType, Offset,   Size,     Flags
factory,   app,  factory, 0x10000,  0xDF0000
wallets,   data, 0x40,    0xE00000, 256K,     encrypted
counters,  data, 0x41,    0xE40000, 16K
```

- The app is declared at its collision bound (0xE00000 - 0x10000 = 0xDF0000 =
  13.94 MiB) rather than at a nominal size, so the frozen table never needs a later
  edit and `partition-table.bin` stays a byte-stable published artifact. App-size
  discipline is an explicit CI budget constant (fail above 8 MiB, warn above 6 MiB),
  not the partition size field. Table ends at 0xE44000 = 14.27 MiB, inside board B's
  16 MB with 1.73 MiB spare, unchanged on board A's 32 MB.

- `counters` (red-team addition, see 2.5): plaintext by necessity - Trezor-style
  bit-clear attempt logs are incompatible with XTS-encrypted partitions' 16-byte
  write granularity. Holds no secret: attempt/guard bit logs, seal_seq high-water,
  wipe_epoch. Two sector pairs (counter pair + epoch/header pair) inside 16 KiB.

- App offset unchanged: the Verify screen's running-partition SHA256 procedure stays
  board-independent (BOARDS.md flash section).
- `encrypted` flag: covered by XTS-AES on release units
  (https://docs.espressif.com/projects/esp-idf/en/stable/esp32p4/security/flash-encryption.html).
  Dev boards (encryption off) store wallets protected by the PIN ladder only - stated
  in SECURITY.md.
- No OTA, decision recorded: an airgapped signer updates by USB reflash (espflash);
  SD-borne update would be an attack surface. eFuse anti-rollback
  (secure_version) works with the factory-only layout and ships on release units.
  Fits 16 MB; smallest board stays the binding constraint.
- eFuse key-block budget (6 blocks): 1 secure-boot digest, 1 flash-encryption XTS
  key, 1 HMAC_UP storage key; 3 spare. Recorded so future features budget
  deliberately.

---

## 3. Wallet management

- One device PIN (not per-wallet), Coldcard/Passport model: PIN gates the device;
  wallets are slots under it. Anti-phishing words at half-PIN entry are derived
  HMAC_efuse(pin_prefix) -> 2 BIP39 words (Coldcard pattern,
  https://coldcard.com/anti-phishing-words) - device-authenticates-to-user before the
  user finishes authenticating to it. Limitation, stated honestly (Coldcard shares
  it): an evil maid with temporary device access can enumerate prefixes, record the
  words, and build a look-alike device that replays them - the words defeat device
  SWAP by a party who never held your device, not substitution by one who did. The
  words reveal nothing about the remaining PIN digits, and half-PIN word display
  does not consume an attempt-counter decrement (only a full wrong PIN does).
- Create: 0.1.0 dice flow -> mnemonic -> passphrase -> MANDATORY backup verification
  quiz (BitBox02 pattern: every word, 5 candidates,
  https://support.bitbox.swiss/en_US/recovery-words-seed/how-to-view-recovery-words-bitbox02)
  -> explicit fork "Save (PIN-protected)" vs "Use once, keep nothing".
- Restore: 0.1.0 reverse mode + word-completion keyboard + final-word calculator;
  fingerprint echoed before save (a wrong passphrase is a different wallet - surface
  the fingerprint).
- Session: unlocking produces a WalletSession (notyas-wallet type) owning the
  Zeroizing entropy/derived keys; wiped on lock, screen timeout, or power-off. It is
  the first secret that outlives a screen; its wipe points are explicit and tested.
- Delete: typed-name confirmation; wipes the slot pair; states on-screen exactly what
  is destroyed and that the user's own backup is the only way back.

## 4. Multisig management

- Canonical stored form: descriptor string with checksum (wsh(sortedmulti(...)),
  multipath `<0;1>`), parsed/validated by miniscript. The Coldcard .txt format is an
  accepted import dialect converted to a descriptor on ingest
  (https://coldcard.com/docs/multisig/). BSMS (BIP-129) deferred - spec complete,
  adoption thin (https://github.com/bitcoin/bips/blob/master/bip-0129.mediawiki);
  descriptor import + first-address cross-check covers the need (OPEN-QUESTIONS Q6).
- Import verification (the 2021 Coldcard xpub-substitution lesson,
  https://benma.github.io/2021/02/09/coldcard-multisig-vulnerability.html): device
  verifies OUR key is a member (derives it and compares), shows M, N, script type,
  every cosigner fingerprint + xpub for confirmation, then displays the wallet's
  first receive address for cross-device comparison (manual BSMS round-2).
- Storage: registry records sealed with the same AEAD ladder (PIN-gated by
  construction, integrity = AEAD tag), bound to the owning wallet slot. The stored
  registration is what multisig change verification derives from - never the PSBT's
  claimed cosigners.
- Scope: P2WSH sortedmulti (BIP-48) in 0.2.0; taproot multisig deferred
  (OPEN-QUESTIONS Q7). Export "our xpub for a new multisig" (BIP48, SLIP-132 forms)
  via QR + SD.

---

## 5. Signing pipeline

### 5.1 notyas-core signing API (extension)

Per the audit, derive.rs cannot sign today (string-only outputs, private SecretXpriv,
no arbitrary-path API). Additions, keeping the wipe discipline:

- `derive_path(seed, &DerivationPath) -> SecretSigningKey` - arbitrary depth, mixed
  hardened/normal, for PSBT-supplied paths (bounded by the policy engine, not here).
- `SecretSigningKey`: zeroize-on-drop wrapper exposing exactly what `Psbt::sign`'s
  `GetKey` needs plus Schnorr keypair with taproot tweak; redacting Debug.
- `root_fingerprint_typed() -> bitcoin::bip32::Fingerprint`.
- Boot self-test gains a pinned PSBT-sign known-answer check (sighash + ECDSA +
  Schnorr through the real stack) and published BIP-143/BIP-341 sighash vectors as
  unit tests.

Signing itself uses `Psbt::sign` + `SighashCache` - never a hand-rolled sighash
(https://docs.rs/bitcoin/0.32.7/bitcoin/psbt/struct.Psbt.html).

Signature-equivalence honesty (red-team correction to the draft's invariant-4
wording): byte-identical signatures against Bitcoin Core are NOT generally
achievable and must not be claimed. Core signs BIP-341 with random aux-rand (its
Schnorr output differs run to run by design), and Core grinds ECDSA nonces for
low-R signatures (71-byte DER) while plain RFC6979 does not. What IS claimable and
tested: (a) byte-identical signatures against pinned known-answer vectors (BIP-340
official vectors are no-aux-deterministic; BIP-143/BIP-341 sighash vectors); (b) a
differential suite where Core VERIFIES and ACCEPTS our signatures
(walletprocesspsbt + testmempoolaccept on regtest) and where sighash intermediates
match byte-for-byte. Whether we adopt low-R grinding ourselves (Core-identical
ECDSA bytes, predictable tx size, slightly slower signing) is OPEN-QUESTIONS Q13.

### 5.2 Flow

```
SD in -> parse/decode (bin|base64|hex autodetect)
      -> notyas-wallet policy engine: evaluate(psbt, wallet, policy)
             -> Reject(reason)  -> refusal screen (plain words, what to do next)
             -> Approval{review rows, warnings}
      -> UI review: per-output pages, fee page, full traversal enforced
      -> hold-to-sign -> derive keys per input (session) -> Psbt::sign
      -> policy re-asserted post-sign; miniscript finalize IF our sigs complete
         every input (interpreter sanity re-check runs either way as a gate)
      -> emit: <name>-signed.psbt (encoding matches input) [+ <name>-final.txn]
         to SD; and/or animated UR2 crypto-psbt QR out
```

PSBT v0 only; v2 is parse-and-reject with a clear message (interop reality: every
target coordinator emits v0). No camera: QR is out-only; SD is the in-channel - which
also absorbs the size cost of requiring full previous transactions (below).

### 5.3 The validation checklist and which layer enforces it

Every historical signer attack in the research maps to a check; every check maps to a
layer (RB = rust-bitcoin, MS = miniscript, NW = notyas-wallet policy engine) and to a
regression-corpus case (MILESTONES m5 gate):

| # | Check | Attack it answers | Layer |
|---|---|---|---|
| 1 | Input ownership: derive-and-compare scripts from claimed key origins; path sanity bounds (purpose whitelist, depth, hardened shape) | Coldcard change-path ransom 2019 (https://coinkite.com/historical-disclosures) | NW over RB |
| 2 | Full prev-tx (`non_witness_utxo`) REQUIRED for every segwit-v0/legacy input; txid + amount cross-check. `witness_utxo` alone acceptable for taproot only (BIP-341 commits to all prevouts) | BIP-143 fee attack, Trezor 2020 (https://blog.trezor.io/details-of-firmware-updates-for-trezor-one-version-1-9-1-and-trezor-model-t-version-2-3-1-1eba8f60f2dd) | NW |
| 3 | Change = our descriptor derives exactly that script_pubkey at an internal-keychain index within gap bound; no script heuristics | Coldcard multisig change confusion 2019 | MS derive + NW loop |
| 4 | Multisig outputs rebuilt from the REGISTERED descriptor only; membership, M/N/format/derivation match | Coldcard xpub substitution 2021 (https://benma.github.io/2021/02/09/coldcard-multisig-vulnerability.html) | NW over MS |
| 5 | Network isolation: coin_type and address network must match wallet's declared network | Coldcard isolation bypass 2020 (https://benma.github.io/2020/11/24/coldcard-isolation-bypass.html) | NW |
| 6 | Fee: computed from validated prevouts; reject negative; warn/cap absolute + sat/vB + percent-of-send | fee burn | RB arithmetic, NW thresholds |
| 7 | Sighash whitelist: SIGHASH_ALL / SIGHASH_DEFAULT only, with NO override (ratified Q24: no Settings toggle ever disables a refusal; the earlier "expert-gated otherwise" is struck) | output swap after signing | NW (RB would honor any type) |
| 8 | Taproot: correct output-key tweak; script-path leaves only from registered descriptor; reject unknown annex | key leak / unknown-leaf signing | RB tweak, NW/MS whitelist |
| 9 | Global sanity: no duplicate inputs, no already-finalized inputs, every input classified (ours/not-ours) and shown, unknown fields preserved untouched, never trusted | malformed/hostile PSBTs | RB parse + NW |
| 10 | Post-sign gate: miniscript finalize interpreter re-verifies sigs/timelocks/preimages before anything leaves the device | any policy-engine bug | MS |

The engine is a pure function producing review rows + warnings BEFORE any key is
derived, re-asserted immediately before signing; UI renders its output verbatim
(one pipeline, many renderers - the report.rs rationale extended to signing).

### 5.4 Airgap transport

- SD (primary, in+out): Coldcard conventions - accept .psbt bin/base64/hex
  autodetected; write `<name>-signed.psbt` in the input's encoding; `-final.txn` when
  finalizable (https://coldcard.com/docs/ready-to-sign/). Mount on demand, unmount
  before returning to wallet screens; FATFS torn writes lose only re-creatable
  artifacts, never secrets (stated in SECURITY.md). Accepted PSBT size capped (RAM
  bound), parse errors in plain language.
- QR out (no camera = no QR in): `ur:crypto-psbt` (emit legacy type name for
  ecosystem compat; https://developer.blockchaincommons.com/ur/psbts/), fountain
  encoding via foundation-ur, default max_fragment_len 200 bytes, ~5-8 fps, pause /
  speed / density controls + frame counter (SeedSigner/Sparrow lessons). Static QR
  path (0.1.0 qr.rs) reused for the frames; the firmware main loop gains the
  tick-driven repaint this needs (section 7).

---

## 6. Firmware infrastructure

- Storage driver: Storage-trait impl over `esp_partition_erase_range/write/read`
  against the `wallets` partition; HMAC peripheral call
  (`esp_hmac_calculate`) wrapped in one small module; eFuse STATE READOUT only, surfaced
  on the Verify screen as actually read and able to render "not provisioned" - the burn
  itself is a host step and no burn code ships (ratified Q45).
- SD: per-board `sd_init()/sd_deinit()` joins the board surface (Elecrow 5 is 1-bit
  SDMMC, Waveshare 4-bit - BOARDS.md 124-127; scaffold boards inherit UNTESTED
  status); IDF FATFS/VFS mount-on-demand lifecycle tied to the signing/export flows.
- Main loop: `Ui::tick(elapsed_ms) -> needs_repaint` drives hold-to-confirm progress,
  UR2 frame advance, and session auto-lock timeout. The 0.1.0 "idle device performs
  zero repaints" claim is reworded to "zero repaints outside an active animation".
- 0.1.0 bug fixed first (m1): firmware currently discards `UiRequest` and compiles
  notyas-core without the `qr` feature - QR buttons are dead on hardware. Wired
  before UR2 builds on it.
- USB: unchanged - power/flash only; the PSBT path deliberately does not use it.

## 7. UI architecture

Per the audit's verdict: KEEP the closed State enum (exactly-one-state-alive,
drop-equals-zeroize, no dyn dispatch in the input path); restructure dispatch into
per-screen modules each exporting `layout/regions/draw/activate`, enum match reduced
to one-line delegation; promote the modal pattern into one shared component with the
three danger grades (confirm / hold / typed-name). `UiRequest` grows into the full
embedder protocol (ListSdFiles, ReadPsbt, WriteSignedPsbt, UnsealWallet,
PersistWallet, ...) keeping storage I/O and sealing on the std side and the state
machine pure. Touch layer: add tick + press age for hold-to-confirm; fix the
horizontal-slop defect (sideways swipe across a button must cancel the tap). Screen
inventory and flows: plan-0.2.0/UX.md.

## 8. Migration and 0.1.0 compatibility

- Stateless mode is a first-class peer, not a fallback: no PIN set -> no storage
  mounted, no writes, flows byte-identical to 0.1.0; "Use once, keep nothing" is an
  explicit branch in the create flow. SECURITY.md states the stateless-device
  properties survive verbatim for a device with a blank wallet partition.
- A 0.1.0 device reflashed to 0.2.0 sees a blank (erased) wallets partition and
  behaves statelessly until the user opts in. No data migration exists or is needed.
- Every write to flash or SD is announced on-screen before it happens (the
  statelessness border is visible - UX commandment 6).
- Equivalence invariant extends (wording corrected per 5.1): identical PSBT +
  identical wallet produces byte-identical signatures to PINNED VECTORS, and
  signatures that Bitcoin Core verifies and accepts (walletprocesspsbt +
  testmempoolaccept differential in CI). Byte-equality against Core's own output is
  claimed only if Q13 adopts low-R grinding, and then for ECDSA only - never for
  Schnorr (Core randomizes aux-rand).
