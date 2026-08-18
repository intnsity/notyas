# notyas 0.2.0 - Security model rewrite (plan)

Status: PLAN. This is the proposed 0.2.0 text for docs/SECURITY.md, written as the
amendment the codebase audit demands: 0.2.0 breaks the 0.1.0 identity "the device
stores no secrets" in four places, and each break is restated honestly here rather
than papered over. The governing rule is unchanged: every claim must be mechanically
enforced (compile-time, test, or hardware) or it does not get made; marketing derives
from this file, never the reverse.

---

## Threat model (0.2.0 restatement)

In scope: remote compromise via radio (eliminated - unchanged); exfiltration of
secrets generated on the device (minimized: airgapped; stateless unless the user
opts in); a tampered or substituted firmware image (detectable: reproducible builds,
signed releases, on-device verification); biased or insufficient user entropy
(surfaced: effective-bits accounting); NEW: theft of a device holding a stored
wallet, including flash extraction and offline attack of the sealed record; NEW: a
malicious or compromised coordinator feeding hostile PSBTs, descriptors, or file
content through SD/QR (mitigated: the on-device policy engine and review UI are the
trust boundary).

Out of scope, stated honestly: a determined fault-injection attacker holding the
device (see "An attacker with the device" below); supply-chain replacement of the
hardware itself.

## An attacker with the device (new section, normative)

The ESP32-P4 has no secure element. What that means, exactly:

- There is no key store hardened against fault injection, no monotonic counter the
  CPU cannot reach, and no rate limit enforced outside the attacker-controllable
  processor. Those are precisely the three properties a real secure element provides
  (https://bitbox.swiss/bitbox02/security-features/,
  https://bitbox.swiss/bitbox02/threat-model/).
- The ESP32 family has a uniform published history of eventually falling to fault
  injection: original ESP32 (CVE-2019-15894, CVE-2020-13629), ESP32 V3 (single EM
  glitch defeats all security features - USENIX WOOT 2024,
  https://www.usenix.org/system/files/woot24-delvaux.pdf), ESP32-C3/C6 boot-ROM
  crowbar glitch (https://courk.cc/esp32-c3-c6-fault-injection). No P4-specific
  result is published; we treat the P4 as NOT proven resistant.

The stored-wallet guarantee is therefore tiered, and the tiers are the claim:

1. Bench attacker (theft, desolder, flash dump): gets XTS-AES-encrypted flash
   (release units) containing an AEAD-sealed record. Each PIN guess requires the
   physical device, because the sealing key ladder passes through the P4 HMAC
   peripheral whose key lives in a read-protected eFuse block software cannot read
   (P4-specific, IDF v5.5, verified 2026-08-17:
   https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/peripherals/hmac.html).
   On-device guessing meets the attempt counter: 10 consecutive failures (default)
   destroy the sealed record.
2. Fault-injection lab: assume the eFuse HMAC key and a flash image are eventually
   extracted. The attack then collapses to offline Argon2id-stretched guessing of
   the PIN/passphrase. A 6-digit PIN falls in days-to-weeks of memory-hard grinding;
   an alphanumeric passphrase does not. The wall is the user's PIN/passphrase
   entropy, and the UI says so at PIN creation.
3. The attempt counter is advisory against tier 2, and the honest statement of what
   it buys is: **it converts unlimited offline guesses into N guesses per full-flash
   restore cycle.** The counter lives in flash the CPU can address, in a **plaintext**
   partition - bit-clear counters are incompatible with XTS write granularity, so
   they cannot be encrypted - which means flash encryption does **not** raise the cost
   of a counter rollback. There is no key to break there; the attacker copies bytes
   back. Ledger-only rollback (old counter image, current records) IS detected and
   refused at mount, because a record outranking the ledger's high-water, or a blank
   ledger beside a non-blank records region, is tamper rather than a fresh device.
   A consistent full-flash snapshot and restore is neither detectable nor preventable
   and needs no key. Against a thief with a hot-air station and a programmer, N per
   restore cycle is a real slowdown of several orders of magnitude, not a wall, and
   nothing on rev v1.3 silicon can make it one: the chip has no monotonic counter the
   CPU cannot reach. "Tamper-proof storage" is not claimed and never will be on this
   hardware.

Deterministic-wipe posture: because every notyas wallet is re-derivable from the
user's own dice rolls or mnemonic backup, the stored wallet is a convenience cache,
not the only copy. A stolen device races the user, who can move funds from backup
the moment the device goes missing; a wiped device is an inconvenience, not a loss.
This posture is why the wipe counter defaults aggressive and why the passphrase-first
UX is the real security control.

## Invariants (0.2.0)

1. **No radio.** Unchanged from 0.1.0, verbatim, including the per-board kill
   mechanisms in BOARDS.md, the build-graph exclusion, and the Verify-screen
   readout. 0.2.0 additionally lands the build-graph CI check that 0.1.0's text
   promised but the repo never implemented (audit finding), extended to the new
   dependency edges (miniscript, argon2, chacha20poly1305, hkdf, foundation-ur) and
   still banning getrandom/rand*/ring/socket/http crates from the whole graph.

2a. **No plaintext secret ever leaves RAM.** Seeds are persisted only as AEAD
   ciphertext under the PIN-derived key ladder, only on explicit user opt-in, only
   to the dedicated `wallets` partition. The app and bootloader partitions are never
   written at runtime. NVS is never mounted (the wallet partition is a raw two-slot
   record format owned by notyas-wallet). RAM copies are zeroized on lock, screen
   exit, session timeout, and power-off; power-off wipes everything except the
   sealed blob. A device with no stored wallet retains the 0.1.0 stateless property
   verbatim: nothing is ever written to flash.

   **Corollary on QR display, carried forward from 0.1.0 invariant 2 (restored here
   2026-08-17: the split into 2a/2b had dropped it from both halves, which R19
   specifically promised would not happen).** QR display covers PUBLIC values only -
   receive addresses, account xpub/SLIP-132, descriptors, signed PSBTs and final
   transactions - and never a mnemonic, xprv, seed or WIF. SeedQR display-out is
   declined for 0.2.0 (OPEN-QUESTIONS Q17, ratified), so there is no exception to state
   and no secret-QR screen class. Scan-IN of a SeedQR is unaffected: this rule is about
   output. Enforced structurally in notyas-ui and test-asserted.

2b. **What the device writes is enumerated and public.** Flash: the wallets
   partition (sealed records, sealed multisig registrations - ciphertext only) and
   the plaintext counters partition (attempt/guard bit logs, seal_seq high-water,
   wipe_epoch - no secret content; plaintext by necessity, because bit-clear
   counters are incompatible with XTS write granularity - ARCHITECTURE 2.5). SD:
   `*-signed.psbt`, `*-final.txn`, exported xpubs/descriptors [, encrypted backups
   if OPEN-QUESTIONS Q14 accepts them - explicitly labeled ciphertext. The reference
   was written as "Q8" in the wave-1 numbering; the question is Q14, not the licensing
   question]. No key material, no PIN
   material, no logs reach SD. Privacy note, stated honestly: exported xpubs and
   descriptors are not secrets but reveal the wallet's entire address history to
   whoever reads the card - the export screens say so. Every write to flash or SD
   is announced on-screen before it happens.

3. **Deterministic.** Key material derives exclusively from user-supplied dice rolls
   or a typed mnemonic, plus optional passphrase. No TRNG, no clock, no OS entropy
   on any derivation path OR in the storage sealing path: salts and nonces are
   derived, unique-by-construction values (device-bound HMAC + monotonic seal
   sequence), not random ones. Enforcement stays mechanical: notyas-core and
   notyas-wallet have no RNG API, and the dependency-graph test proves no RNG crate
   is reachable. The distrusted P4 TRNG (esp-hal#5982) is used for nothing.
   Schnorr signatures use the deterministic no-aux-rand BIP-340 path; ECDSA is
   RFC6979. (Tradeoff recorded: deterministic nonces weaken side-channel AND
   fault-injection posture - glitched-digest nonce reuse is the textbook attack -
   and are chosen deliberately for verifiability. Mitigation: the post-sign
   interpreter gate re-verifies every signature against an independently recomputed
   sighash before it leaves the device; the remaining fault surface is the lab
   attacker tiers 2-3 already concede. ARCHITECTURE 2.4.)

4. **Equivalence.** Extended: identical input produces byte-identical output to
   desktop BigDice (unchanged), AND identical PSBT + identical wallet produces
   byte-identical signatures to PINNED VECTORS (BIP-340 official vectors,
   BIP-143/BIP-341 sighash vectors, pinned signing known-answer check in the boot
   self-test) plus signatures Bitcoin Core verifies and accepts (walletprocesspsbt
   + testmempoolaccept differential in CI). **Split by algorithm, now that
   OPEN-QUESTIONS Q3 is ratified in favour of low-R grinding: for ECDSA, byte-equality
   against Core's own emitted signatures IS claimed and IS tested, because notyas grinds
   low-R exactly as Core does (`sign_ecdsa_low_r`), which also makes the 71-byte
   signature size and therefore the displayed vsize and fee exact. For Schnorr it is NOT
   claimed and never will be: Core randomizes BIP-341 aux-rand, so byte-equality is
   impossible under any implementation choice; the claim there is the pinned BIP-340
   vectors plus Core verifies and accepts.** (See ARCHITECTURE 5.1.)

5. **Verifiable firmware.** Unchanged mechanism (reproducible build, signed
   SHA256SUMS, Verify screen). Verify screen additionally reports: storage state,
   eFuse HMAC-key and anti-rollback state as actually read, and the wallet
   partition's presence - never constants. Storage-state granularity is pending Q2:
   "blank / N sealed slots" is the honest default, but reporting N is incompatible
   with duress-wallet deniability (a coercer reads the true count off the Verify
   screen). If Q2 ships duress, the readout degrades to "storage: present/blank"
   and this invariant's text records why.

6. **Secure boot, honestly.** Unchanged (Secure Boot v2 RSA-3072 only - ECDSA mode
   ROM-broken per AR2026-006 - XTS-AES flash encryption, eFuse anti-rollback, all ON
   for release units, true state on the Verify screen). Amended rank: with a stored
   secret, flash encryption is now a PRIMARY control, not belt-and-braces. Dev
   boards run with it off; a dev board's stored wallet is protected by the PIN
   ladder only, and the Verify screen shows exactly that.

7. **The signing policy engine is the trust boundary (new).** No PSBT input is
   signed unless: claimed key origins re-derive to the input's actual script; every
   segwit-v0/legacy input carries its full previous transaction with matching txid
   and amount (BIP-143 fee-attack defense); outputs are classified and change is
   proven by exact descriptor derivation (multisig change from the on-device
   registration only, never from PSBT-supplied xpubs); network matches; sighash
   type is whitelisted; fee is computed, shown, and bounded. After signing,
   miniscript's interpreter re-verifies the result before anything leaves the
   device. Each check is pinned to a historical attack in ARCHITECTURE.md 5.3 and
   to a corpus case in CI.

## Duress and wipe stance

- Wipe-on-N (default 10, range 3..=25 - OPEN-QUESTIONS Q5, ratified) destroys the
  sealed records and bumps a one-way epoch marker. The user is told at setup that the
  mnemonic/dice backup is the recovery path - the device never claims to be the only
  copy. **Two honesty requirements on that copy, both from Q5's ratification.** First,
  the mnemonic recovers the SEED and nothing else: multisig registrations, labels and
  device settings are not re-derivable and a wipe destroys them permanently, so the
  wipe screens must name what is lost rather than implying the seed covers it (the
  deliberate-erase screen already does; the accidental one did not). Second, a power cut
  taken between the attempt-cell program and the success-cell write CONSUMES an attempt
  even when the PIN was correct - that is deliberate and fail-closed, because otherwise
  power-cutting is a free oracle - so on a portable device the counter can advance with
  no wrong PIN entered, and the wrong-PIN policy screen must say so.
- Duress PIN (if Q2 accepted): opens a decoy wallet set; no stored marker says
  which PIN is which. Red-team correction: this alone is NOT "indistinguishable by
  construction" - slot occupancy is visible pre-PIN and the Verify screen's slot
  count would expose how many wallets exist. Full deniability requires
  always-filled slot ciphertext padding and a degraded Verify storage readout;
  the decision and its honesty cost live in Q2, and no indistinguishability claim
  is made unless Q2 accepts that package.
- Anti-phishing words at half-PIN entry authenticate the device to the user
  (https://coldcard.com/anti-phishing-words). Known limit (Coldcard shares it): an
  evil maid who held the device can enumerate and replay the words on a look-alike;
  the words defeat swap-by-a-stranger, not substitution by someone who had your
  device. Half-PIN display costs no attempt-counter decrement.

## Known accepted risks (0.2.0 additions)

- ESP-IDF in the TCB, GT911/ST7703 vendor init, Elecrow C6 power-on window, STC8
  co-MCU, empty-socket requirement: all unchanged from 0.1.0.
- USB remains power/flash only; the PSBT path deliberately does not use USB.
- FATFS on SD is not power-loss safe. Accepted: a torn SD write loses a re-creatable
  artifact (a signed PSBT can be re-signed), never a secret. The wallet partition
  does not use FATFS.
- The IDF FATFS/VFS/SDMMC stack is new C attack surface parsing untrusted media.
  Mitigations: mounted on demand only, unmounted outside signing/export flows,
  accepted file size capped, PSBT parsing itself in Rust (rust-bitcoin), filenames
  rendered with a restricted charset.
- The HMAC-eFuse binding means a dead P4 with an intact flash chip is NOT
  recoverable by moving the flash to another board - by design. The user's backup
  is the recovery path; setup says so.
- Argon2id parameters are a measured compromise on rev v1.3 silicon (m1 benchmark);
  they bound, not eliminate, offline guessing after a successful key extraction.
