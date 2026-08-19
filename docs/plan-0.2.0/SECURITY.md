# notyas 0.2.0 - Security model rewrite (plan)

Status: PLAN, and as of the m13 claims audit (2026-08-18) it is the WORKING half of the
pair. `docs/SECURITY.md` now carries the shipped 0.2.0 text and is the normative
document; this file keeps the reasoning, the citations to the research documents and the
tier analysis that the shipped text compresses. Where the two disagree, the shipped one
wins and this one is the defect.

Written as the amendment the codebase audit demands: 0.2.0 breaks the 0.1.0 identity "the
device stores no secrets" in four places, and each break is restated honestly here rather
than papered over. The governing rule is unchanged: every claim must be mechanically
enforced (compile-time, test, or hardware) or it does not get made; marketing derives
from this file, never the reverse.

**Corrections landed by the m13 claims audit are marked `[m13]` inline.** Each replaced a
sentence that claimed a mechanism the tree does not contain; `docs/claims-audit-0.2.0.md`
records the claim, the verdict and the file:line behind each one.

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

**Before the tiers, one thing 0.2.0 does not have, because every tier reads differently
without it.** Secure Boot v2 is NOT burned on 0.2.0 release units (OPEN-QUESTIONS Q32,
deferred to 0.3.0), and eFuse anti-rollback goes with it. Three consequences, all
factual:

- **An attacker who has held the device can replace the firmware.** There is no signature
  check in the boot path to stop them, and no anti-rollback to stop them installing an
  older image.
- **The Verify screen therefore cannot vouch for itself.** VERIFY.md section 9 is explicit
  that secure boot is the only check on that screen which does not depend on the firmware
  being honest: every other row - the running-app digest, the eFuse readout, the storage
  state, the boot counter - is a value the firmware reports about itself. On a 0.2.0 unit,
  the Verify screen tells you what the running firmware says about itself. **If you did
  not build and flash that firmware yourself from a reproduced image, the screen cannot
  prove it is the firmware you think it is.**
- **The reproducible-build chain is the answer and it is unchanged**, but it has to be
  exercised by the owner, on their own machine, rather than certified by the device. That
  is a real difference in who does the work, not a rewording.

This is a stated limitation of the release, not an oversight, and the release notes carry
it in these terms.

**The cable is the cheap version of that attack and is worth naming separately, because
"no USB data functionality is compiled in" reads as a defense and is not one.** The P4's
USB-Serial-JTAG peripheral exposes a JTAG debug port on the same D+/D- pins that carry
power and flashing, with no external adapter: Espressif's own guide calls it *"the
quickest and most convenient way to start with JTAG debugging ... through a USB cable
connected to the D+/D- USB pins of ESP32-P4. No need for an external JTAG adapter"*
(ESP-IDF v5.5, esp32p4, JTAG Debugging -> Configure ESP32-P4 Built-in JTAG Interface).
The statement about the application is true and beside the point: the peripheral is
silicon, live from power-on, and nothing an application omits can decline it. On a 0.2.0
unit `DIS_USB_JTAG`, `DIS_PAD_JTAG`, `DIS_DOWNLOAD_MODE` and
`DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE` are all unburned. The only burn 0.2.0 asks for is the
HMAC key the sealed storage binds to; Q63 scoped "no eFuse burned" to the secure-boot set,
and nothing in that scoping touches JTAG or download mode. So:

- **OpenOCD over that one cable halts both cores and reads internal RAM and PSRAM**, where
  the unsealed seed, the derived xprv and the PIN as typed live for the length of a
  session. Zeroize-on-drop bounds each value's lifetime; it does nothing against a
  debugger that halts the CPU while the value is in scope and in use. Because this reads
  the live secret, none of the three tiers below applies to it: no PIN ladder, no attempt
  counter, no Argon2id cost stands between the attacker and the plaintext.
- **ROM download mode is open on the same cable**, so the app partition can be rewritten
  without opening the case or touching the flash chip. Without Secure Boot v2 the
  replacement image runs. That is the firmware substitution above, at the price of one
  cable and a few minutes.

One thing the port carries in the other direction, for completeness: the IDF secondary
console (`CONFIG_ESP_CONSOLE_SECONDARY_USB_SERIAL_JTAG`) is in the image by default, so
the boot log leaves the device on USB whenever it is plugged into a host. Output only - no
CDC-ACM, MSC, HID or TinyUSB device path is linked into any artifact, asserted per image
by `tools/ci/check-airgap.sh` - and no key, seed or PIN material reaches it in a release
build, because the only call sites printing PIN material are the HIL console's, which
`build.rs` refuses in a release profile and `tools/ci/check-release-symbols.sh` asserts
absent (Q41). Named here because "power/flash only" does not describe it.

The window is exactly: device powered, physically reachable, cable attachable - evil maid,
border inspection, repair shop. Not remote, not network, and not applicable to a
powered-off device in your possession; a stateless (State 1) unit has nothing in RAM
between sessions to read. What it does mean is that **an unlocked session in a place the
owner does not control is the exposed state**, and no software change in 0.2.0 moves that
line.

**Burning those eFuses is deliberately NOT proposed here.** It is the same one-way cliff
and the same key-ownership question as Secure Boot v2, it is a 0.3.0 decision, and
SECUREBOOT.md owns it (section 10, the burn sequence and what each step forecloses). This
section states the exposure and the window; it does not settle the remedy.

**The tiers below describe a device that has stored something. Two of the three supported
device states have no stored secret at all, and that is worth stating before the tiers
rather than leaving as an omission** (PIN-MODES.md is authoritative for the states):

- **State 1, stateless (the default, and a first-class mode).** No PIN, nothing written to
  flash, seed in RAM for the session and gone at power-off. This is the 0.1.0 model and it
  remains a legitimate way to own this device. **There is no stored-secret threat surface
  to describe: nothing to brute-force and nothing to extract.** Every tier below is empty
  in this state.
- **State 2, PIN set with wipe on (the default once anything is saved).** The tiers below
  apply, with N = 15.
- **State 3, PIN set with wipe off.** The tiers below apply with the attempt limit removed;
  see the wipe stance for what that costs and why it is nevertheless the user's to choose.

The stored-wallet guarantee is tiered, and the tiers are the claim:

1. Bench attacker (theft, desolder, flash dump): gets an AEAD-sealed record. Each PIN
   guess requires the physical device, because the sealing key ladder passes through the
   P4 HMAC peripheral whose key lives in a read-protected eFuse block software cannot read
   (P4-specific, IDF v5.5, verified 2026-08-17:
   https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/peripherals/hmac.html).
   On-device guessing meets the attempt counter: **15 consecutive failures (default)
   destroy the sealed record.**
   **Two honest qualifications, both new in the 2026-08-18 re-scope.** First, **0.2.0
   burns no flash-encryption key** (SECUREBOOT.md; Q63), so the flash is NOT XTS-AES
   encrypted and the sealed record is protected by the PIN ladder alone. The `wallets`
   partition's `encrypted` flag is inert without the burn, and the Verify screen reports
   exactly that rather than implying protection that is not there. Second, the attempt
   counter can be turned OFF by the user (invariant 5's wipe policy) - see the wipe stance
   below, because that is the difference between 15 guesses and unlimited ones.
2. Fault-injection lab: assume the eFuse HMAC key and a flash image are eventually
   extracted. The attack then collapses to offline Argon2id-stretched guessing of
   the PIN/passphrase, and the wall is entirely the user's entropy. **The PIN floor is 4
   characters (Q4), and 4 digits does not survive this tier**: 10,000 candidates at the
   pinned Argon2id cost is hours, not years. 6 digits is days to weeks; an alphanumeric
   passphrase does not fall. This is stated without hedging here and is shown as an
   entropy meter at PIN creation, with the wording "a digits-only PIN protects against
   theft, not against a funded lab".
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

Deterministic-wipe posture, **corrected 2026-08-18 because the original sentence was
false and the thing that would have made it true is no longer in 0.2.0**: the SEED is
re-derivable from the user's own dice rolls or mnemonic backup, so a wiped seed is an
inconvenience rather than a loss, and a stolen device races a user who can move funds from
backup the moment it goes missing. **The rest of the device's state is not re-derivable
from anything.** Multisig registrations, labels and settings exist only on the device, and
with encrypted backup deferred to 0.3.0 (Q14) there is no recovery path for them at all in
0.2.0. A wipe destroys them permanently. Every wipe surface names them individually rather
than implying the mnemonic covers everything. This posture is why the wipe counter defaults
aggressive and why the passphrase-first UX is the real security control.

## Invariants (0.2.0)

1. **No radio.** Unchanged from 0.1.0, verbatim, including the per-board kill
   mechanisms in BOARDS.md, the build-graph exclusion, and the Verify-screen
   readout. 0.2.0 additionally lands the build-graph CI check that 0.1.0's text
   promised but the repo never implemented (audit finding), extended to the new
   dependency edges (argon2, chacha20poly1305, hkdf, foundation-ur) and
   still banning getrandom/rand*/ring/socket/http crates from the whole graph.
   **[m13] Two narrowings.** First, the check reads Cargo lockfiles and resolved
   dependency subtrees; it does NOT grep the linked ESP-IDF component list, which is
   pinned by `firmware/components_esp32p4.lock` and reviewed at release. 0.1.0's text
   claimed the component-list grep and no such check exists, so the claim is now stated
   as the pinned list plus a review. Second, `miniscript` is not in the dependency graph
   at all: descriptor construction and `sortedmulti` parsing are hand-written in
   notyas-core, so it is not one of the new edges the ban list covers.

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
   wipe_epoch, the wipe-policy log - no secret content; plaintext by necessity, because
   bit-clear counters are incompatible with XTS write granularity - ARCHITECTURE 2.5).
   **[m13] The `media` partition is struck from this enumeration.** R2/R23 and Q7 describe
   a frozen table with `media` at 0xC00000 and the data partitions at 0xE00000/0xE40000;
   the table the release actually flashes (`firmware/partitions.csv`) declares
   factory/wallets/counters only, at 0x10000/0x410000/0x450000, and no `media` partition
   exists. An enumeration of what the device writes may not name a partition that is not
   in the table. The geometry discrepancy itself is an m1 defect, raised in the audit
   record, not something this document can fix. SD:
   `*-signed.psbt`, `*-final.txn`, exported xpubs and descriptors. **Nothing else.
   Encrypted backups were the one conditional item in this list and Q14 deferred them
   whole to 0.3.0, so this enumeration is now unconditional and 2b needs no amendment.**
   No key material, no PIN material, no logs reach SD. Privacy note, stated honestly: exported xpubs and
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
   gate re-verifies every signature THIS DEVICE produced against a sighash recomputed
   from the PSBT alone before it leaves the device; the remaining fault surface is the lab
   attacker tiers 2-3 already concede. ARCHITECTURE 2.4. **[m13] The gate is
   `notyas_core::psbt::signer::verify_signatures`, not a miniscript interpreter** - see
   invariant 7.)

4. **Equivalence.** Extended: identical input produces byte-identical output to
   desktop BigDice (unchanged), AND identical PSBT + identical wallet produces
   byte-identical signatures to PINNED VECTORS (BIP-340 official vectors,
   BIP-143/BIP-341 sighash vectors, pinned signing known-answer check in the boot
   self-test). **[m13] The `walletprocesspsbt` + `testmempoolaccept` differential is NOT
   in CI** - no CI job runs `bitcoind`, and the corpus fixtures are built from a fixed
   in-tree seed rather than captured from Core. It is a release-time procedure, and the
   claim is now stated as one. What IS mechanical is the pinned-vector suite, including
   the low-R corpus whose expectations come from an independent RFC 6979 implementation
   that reproduces both of Core's published signatures byte for byte. **Split by
   algorithm, now that
   OPEN-QUESTIONS Q3 is ratified in favour of low-R grinding: for ECDSA, byte-equality
   against Core's own emitted signatures IS claimed and IS tested, because notyas grinds
   low-R exactly as Core does (`sign_ecdsa_low_r`), which also makes the 71-byte
   signature size and therefore the displayed vsize and fee exact. For Schnorr it is NOT
   claimed and never will be: Core randomizes BIP-341 aux-rand, so byte-equality is
   impossible under any implementation choice; the claim there is the pinned BIP-340
   vectors plus Core verifies and accepts.** (See ARCHITECTURE 5.1.)

5. **Verifiable firmware, and a storage readout that is deliberately coarse.**
   Mechanism unchanged (reproducible build, signed SHA256SUMS, Verify screen). The Verify
   screen reports eFuse HMAC-key state, the secure-boot digest slots, the running-app and
   partition digests and the storage state as actually read - never constants.
   **Storage-state granularity is settled by Q2(a) and it is a permanent honesty cost paid
   by every user:** the readout is `present` or `blank`, never a count of sealed wallets,
   permanently and whether or not that user ever enables a duress PIN. **[m13]** Two other
   values are reachable and neither is a count: `not provisioned` (no eFuse key) and
   `unreadable (kind)` (both superblock sides fail to resolve). Reporting the true
   count would let a coercer read off the Verify screen how many wallets exist, which is
   the leak a duress feature cannot survive. The full wallet list is shown after a
   successful unlock, where it is post-PIN and leaks nothing. **What makes the coarse
   readout meaningful rather than merely vague** is that unused slots always hold
   device-derived filler ciphertext (`Occupancy::AlwaysFilled`), so "present" is the true
   state of every formatted device and an attacker without the eFuse key cannot tell
   filler from a real record. The claim stops exactly there: it is not a claim about an
   attacker who has extracted the key, and not a claim that behaviour under a duress PIN
   is indistinguishable at every UI surface.

   **Wipe policy is user-settable, and the settings screen states the cost at the moment
   of the change.** The default is 15 attempts; the user may change N within 3..=25 or
   disable the wipe entirely, from an unlocked session only. The mechanism that makes
   "from an unlocked session only" a real constraint rather than a UI convention is
   specified in OPEN-QUESTIONS Q5.1-Q5.3 and summarised in the wipe stance below.

6. **Secure boot, honestly - and in 0.2.0 the honest answer is that it is not there.**
   Secure Boot v2 is **not burned** on 0.2.0 release units, eFuse anti-rollback is not
   set, and **no flash-encryption key is burned either** (Q32 deferred to 0.3.0;
   SECUREBOOT.md, which is authoritative and targets 0.3.0). The device stays reflashable,
   which is what keeps the reproducible-build claim usable by the person it is for.
   **The one eFuse 0.2.0 uses is the HMAC_UP key the sealed storage binds to** (Q45).
   **[m13] Q63 is answered (a) and closed:** "no eFuse burned" means no secure-boot-related
   eFuse - no digest, no anti-rollback, no flash-encryption key - and the HMAC_UP
   provisioning proceeds as designed. It is burned host-side with `espefuse.py` by whoever
   provisions the board, which is why no claim resembling a vendor genuine-check may be
   made anywhere: such a check would prove only that the device knows a key someone
   provisioned (COMPETITIVE.md 9.9).
   **A 0.2.0 unit's stored wallet is therefore protected by the PIN ladder, and the Verify
   screen shows exactly that** - the same posture dev boards have always had, now stated
   as the release posture rather than as a development caveat. The three secure-boot digest
   slots render `not burned`, which is the true and important answer rather than a hidden
   section.

   When it returns in 0.3.0 the parameters are already fixed and are not re-litigated:
   Secure Boot v2 RSA-3072 only, never ECDSA (ROM-broken per AR2026-006), with the
   key-ownership question (ours, the user's, or both channels) settled by Q32 first,
   because it decides whether an owner of this device can build and run their own
   firmware.

7. **The signing policy engine is the trust boundary (new).** No PSBT input is
   signed unless: claimed key origins re-derive to the input's actual script; every
   segwit-v0/legacy input carries its full previous transaction with matching txid
   and amount (BIP-143 fee-attack defense); outputs are classified and change is
   proven by exact descriptor derivation (multisig change from the on-device
   registration only, never from PSBT-supplied xpubs); network matches; sighash
   type is whitelisted; fee is computed and shown. **[m13] Two narrowings.** Change is
   proven only from an on-device multisig registration; single-sig change proof (check 3)
   is assigned to notyas-wallet and is not implemented, so a single-sig output claiming to
   be ours classifies as `ClaimedButUnproven` and counts as a payment - conservative, and
   the review copy must not call it change. And no maximum-fee ceiling exists in the tree:
   the fee is computed together with whether this device's own signatures would enforce it,
   which is what the review screen renders. After signing, every
   signature this device produced is re-verified against a sighash recomputed from the
   PSBT alone before anything leaves the device. Each check is pinned to a historical
   attack in ARCHITECTURE.md 5.3 and to a corpus case in CI.
   **[m13] The post-sign gate is not miniscript's interpreter.** `miniscript` is not a
   dependency of any crate in this workspace and does not appear in `Cargo.lock`;
   `notyas_core::psbt::signer::verify_signatures` is what runs, and it shares
   rust-bitcoin's digest implementation with the signing path, so it is a fault and
   caller-bug detector rather than an independent second implementation. Two consequences
   are now stated rather than implied: the independence the original sentence promised
   does not exist in 0.2.0, and the gate verifies only the signatures this device made,
   deliberately, because verifying a cosigner's entries would let anyone veto the file.

## Duress and wipe stance

- **Wipe-on-N (default 15, range 3..=25, user-settable, and disableable** -
  OPEN-QUESTIONS Q5, owner-answered 2026-08-18) destroys the sealed records and bumps a
  one-way epoch marker. The user is told at setup that the mnemonic/dice backup is the
  recovery path for the SEED, and equally plainly that it is not a recovery path for
  anything else. **Three honesty requirements on that copy.** First, the mnemonic recovers
  the seed and nothing else: multisig registrations, labels and device settings are not
  re-derivable, 0.2.0 ships no backup at all (Q14), and a wipe destroys them permanently -
  so every wipe screen names them, and the accidental path must not disclose less than the
  deliberate one. Second, a power cut taken between the attempt-cell program and the
  success-cell write CONSUMES an attempt even when the PIN was correct - deliberate and
  fail-closed, because otherwise power-cutting is a free oracle - so on a portable device
  the counter can advance with no wrong PIN entered, and the wrong-PIN policy screen says
  so. Third, every number in that copy is a format string, because N is runtime state now.
- **Turning the wipe off is a real weakening, and the device says so where it happens.**
  With wipe enabled, an attacker holding the device gets N guesses. With it disabled they
  get all of them, at one guess per Argon2id stretch. **[m13] The rate is the pinned cost,
  1827 ms measured (MEASUREMENTS.md m1), not the "roughly one per second" this paragraph
  used to assume** - so a 4-digit PIN is a few hours rather than under three, and half that
  by an attacker running their own firmware on both P4 cores -
  which in 0.2.0 needs no key, because Secure Boot is not burned. The settings screen
  states the keyspace, the measured per-guess cost and the resulting time **for the PIN
  actually set**, at the moment of the change, and offers the longer-PIN path as an action
  rather than only accept or cancel. **A longer PIN is NOT required** - the owner decided
  that the device states the trade and does not withhold the setting (PIN-MODES.md, Q62) -
  which puts the entire burden on that copy being accurate and specific.
- **What stops an attacker turning the wipe off before guessing.** A policy change needs
  the PIN: both writes that constitute it - a guarded ledger cell and a re-sealed canary -
  require an unlocked session plus a fresh PIN confirmation, and every attempt to obtain
  one spends an attempt against the counter being attacked. Offline editing cannot do it
  either, because the ledger cell's guard and the superblock mirror's MAC both descend
  from the read-protected eFuse key, so forged bytes are malformed and malformed resolves
  to the strict default of wipe ON. Erasing the policy log does not help: an empty log
  falls back to the format-time policy, which has wipe enabled. **What is NOT defended,
  stated rather than implied: a consistent full-flash snapshot and restore restores the
  policy along with everything else. If the snapshot was taken while wipe was disabled,
  restoring it buys unlimited guesses permanently, and turning wipe back on afterwards
  does not repair it.** A device on which wipe has ever been disabled must be treated as
  having no attempt limit from the earliest snapshot an attacker might hold.
- **Removing the PIN means reverting to 0.1.0 stateless operation and destroying every
  stored wallet.** There is no "stored wallets with no PIN" state, and the reason is
  structural rather than a policy choice: the sealing key is derived from the PIN, so with
  no PIN there is no key and no sealed storage. The confirmation names what is destroyed -
  every wallet, every multisig registration, all labels and settings, the anti-phishing
  words - with counts read from the store rather than a generic phrase, behind the
  strongest confirmation the device has. **It must not be described as a security
  downgrade** (PIN-MODES.md): it is a data-loss event, and the device it produces stores
  nothing, which is the safest state this hardware has. Two "off" switches, opposite
  risks; describing them the same way would teach the wrong instinct about both.
- **Duress PIN (Q2(a), owner-answered 2026-08-18):** opens a decoy wallet set; no stored
  marker says which PIN is which. The feature is OFF by default. **The deniability package
  it depends on is not optional and is not off by default** - unused slots always hold
  device-derived filler ciphertext for every user, and the Verify storage readout is
  permanently coarse for every user - because a package only some devices have is itself
  the tell. That is a cost every user pays to protect a minority under coercion; it was
  chosen deliberately and it is stated rather than buried. The red-team correction that
  produced it stands: a duress PIN alone would NOT be "indistinguishable by construction",
  because slot occupancy is visible pre-PIN. The claim actually made is the narrower one in
  invariant 5, and nothing beyond it is claimed.
- Anti-phishing words at half-PIN entry authenticate the device to the user
  (https://coldcard.com/anti-phishing-words). Because the HMAC key sits in a
  read-protected eFuse block, the words genuinely detect a swapped BOARD. **[m13] They do
  NOT detect replaced firmware on the same board** (COMPETITIVE.md 9.10): any firmware
  running on that board can compute them, and with Secure Boot not burned, firmware
  replacement is precisely the attack in play. The words catch a different device, not
  different software on the same device, and the copy has to say so. Second known limit
  (Coldcard shares it): an evil maid who held the device can enumerate and replay the
  words on a look-alike; the words defeat swap-by-a-stranger, not substitution by someone
  who had your device. Half-PIN display costs no attempt-counter decrement.

## Known accepted risks (0.2.0 additions)

- ESP-IDF in the TCB, GT911/ST7703 vendor init, STC8 co-MCU, empty-socket requirement:
  all unchanged from 0.1.0.
- **The Elecrow C6 power-on window is NOT unchanged from 0.1.0 - the 0.1.0 description of
  it was wrong.** The factory esp-hosted slave does not idle waiting for an SDIO host: its
  init path is unconditional (`esp_hosted_coprocessor.c` calls `connect_sta()` inside a
  `#if 1`, reaching `esp_wifi_set_mode(WIFI_MODE_STA)` and `esp_wifi_start()`; `slave_bt.c`
  enables the BT controller under `CONFIG_BT_ENABLED`), so a WiFi MAC and a BT controller
  are live inside the case at every power-up until app_main drives the kill GPIO low, and
  a C6 holding credentials attempts to associate. Nothing of the user's can leave - no P4
  driver, no secret that early - but the unit is RF-visible and MAC-identifiable at every
  power-on. Firmware cannot close it; the mitigations are physical (remove R77, or the C6
  module). Every supported Waveshare board carries a C6-MINI module with no EN pullup and
  therefore has no window at all, which makes a Waveshare unit the airgap-preferred choice
  among the boards 0.2.0 supports; the predictor is the C6 part, not the vendor, and
  BOARDS.md carries the full rule and the two bare-chip Waveshare exceptions. BOARDS.md
  and SECURITY.md carry the corrected text.
- **USB is power/flash only at the application layer, and that is not the whole claim.**
  The PSBT path deliberately does not use USB and no USB data functionality is compiled
  in; the USB-Serial-JTAG peripheral still offers a debug port and ROM download mode on
  the same pins. See "An attacker with the device" above - that is the claim, this is the
  pointer.
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
- Argon2id parameters are a measured compromise on rev v1.x silicon (m1 benchmark;
  Q9 ships v1.x deliberately, with the Key-Manager-backed ladder scheduled for 0.3.x on
  the same record format); they bound, not eliminate, offline guessing after a successful
  key extraction.
- **No Secure Boot v2 and no anti-rollback on 0.2.0 release units** (Q32, deferred). An
  attacker who has held the device can flash a modified image, and the Verify screen
  cannot contradict them because it is produced by the firmware under suspicion. The
  reproducible-build chain is the mitigation and it requires the owner to build and flash.
  Accepted for this release and stated in the release notes rather than left to inference.
- **The release signing key is held on a general-purpose machine**, not a hardware token
  (Q30, deferred). A verifier's trust in SHA256SUMS.txt is exactly as good as that key's
  custody, so the custody regime is documented rather than assumed.
- **The reproducibility claim has no third-party corroboration in 0.2.0** (Q31, deferred).
  The recipe is published so anyone can check it, and a matching independent build is
  invited rather than presented as already existing.
- **No backup of any kind ships in 0.2.0** (Q14, deferred). Multisig registrations, labels
  and settings are unrecoverable after a wipe. This is the largest single gap in the
  release and every wipe surface names it.
