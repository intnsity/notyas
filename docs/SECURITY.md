# notyas - Security model (normative)

Applies to 0.2.0. The 0.1.0 text this replaces is in git history at tag `v0.1.0`; it
described a device that stores nothing, and 0.2.0 breaks that identity on purpose.

Every claim in this file is mechanically enforced - by a build gate, by a type, by a
test, or by hardware - or it is not made. Marketing copy derives from this file, never
the reverse. `docs/claims-audit-0.2.0.md` records the mechanism and the file:line behind
each claim, so the rule can be re-checked rather than re-argued.

## The release identity

Every notyas release artifact is signed with this OpenPGP key, and nothing else is a
notyas release:

```
A1E9 53B2 5C6A 623B 77A1 D522 3AC4 BBCF E51A B37D
```

rsa4096, created 2026-08-15, held by intnsity. The public key is committed at
`docs/keys/A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D.asc` and the verification procedure
is `docs/VERIFYING.md`.

Stated HERE, in the normative file, rather than only in the release runbook, for the
reason the rest of this document exists: a verifier who wants to know which key is
authentic must be able to find that answer in the file whose claims are mechanically
enforced. `tools/ci/check-ratified.sh` asserts this fingerprint appears in this file, and
`tools/release.sh` refuses to run its preflight without it.

An earlier document named a retired rsa3072 identity. That key is not a notyas release
key and a signature from it verifies nothing.

## What 0.2.0 does not have

Stated first, because a lean release invites the reader to assume the missing parts are
present. Eight things a reader of a hardware-wallet security page would reasonably expect
are absent here, and four of them change what everything else in this file is worth.

1. **No Secure Boot v2.** No signature check runs in the boot path. An attacker who has
   held the device can flash a modified image (OPEN-QUESTIONS Q32, deferred to 0.3.0).
2. **No eFuse anti-rollback.** It protects a signature chain that does not exist without
   secure boot, so it travels with Q32.
3. **No flash encryption.** No XTS-AES key is burned (Q63). The `wallets` partition is
   NOT encrypted at rest; its `encrypted` partition flag is inert without the burn. The
   stored records are protected by the PIN ladder alone.
4. **No hardware-held signing key.** The ESP32-P4 has no secure element. Key material is
   derived in RAM and, if the user opts in, stored as AEAD ciphertext in flash. There is
   no chip on this board that can refuse to release a key.
5. **No third-party attestation.** The reproducibility claim is ours alone: the recipe is
   published and a matching independent build is invited, not already in hand (Q31). The
   release signing key lives on a general-purpose machine, not a hardware token (Q30).
6. **No backup of any kind.** Multisig registrations, labels and settings exist only on
   the device and are unrecoverable after a wipe (Q14). This is the largest single gap in
   the release.
7. **No BSMS (BIP-129) and no taproot multisig.** Descriptor import plus the mandatory
   first-address cross-check covers multisig setup; taproot multisig interop is not stable
   across the coordinators this device targets (Q15, Q16).
8. **No JTAG or download-mode lockdown.** `DIS_USB_JTAG`, `DIS_PAD_JTAG`,
   `DIS_DOWNLOAD_MODE` and `DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE` are not burned; 0.2.0 burns
   the HMAC key and nothing else. The P4's USB-Serial-JTAG peripheral therefore offers a
   debug port and ROM download mode over the ordinary USB cable on any unit an attacker
   can power, whatever the application does or does not compile in.

The consequence of 1 and 3 together is the next section, and it governs the rest of the
file. Item 8 is what makes item 1 cheap rather than merely possible, and has its own
section below.

## The self-reporting boundary

**Every value on the Verify screen is read and reported by the firmware being verified.**
Without Secure Boot, that firmware is not itself checked by anything on the device.
Firmware that has been replaced controls every step of the chain: it can print the digest
of the image it replaced, print `Secure boot enabled` on a blank device, print any eFuse
state, any storage state, any boot count. There is no arrangement of software running on
the suspect processor that closes this, because the thing doing the reporting is the thing
in question (plan-0.2.0/VERIFY.md section 9). **And on a 0.2.0 unit the substitution is
cheap**: ROM download mode is open over the ordinary USB cable (see "The powered device"
below), so replacing the firmware needs neither the case opened nor the flash desoldered.

What the screen is genuinely good for is unchanged and is not small: detecting accidental
corruption and incomplete flashes, comparing one unit against another, and comparing a
unit against a digest the owner produced themselves from a reproduced build. The
reproducible-build chain is the answer to firmware substitution, and in 0.2.0 it is
exercised by the owner on their own machine rather than certified by the device. That is a
real difference in who does the work, not a rewording.

**If you did not build and flash this firmware yourself from a reproduced image, the
Verify screen tells you what the running firmware says about itself and nothing more.**

## Threat model

In scope: remote compromise via radio (eliminated); exfiltration of secrets generated on
the device (minimized: airgapped, and stateless unless the user opts in); a tampered or
substituted firmware image (detectable off-device: reproducible builds and published
digests, with the limits above); biased or insufficient user entropy (surfaced:
effective-bits accounting and roll minimums); theft of a device holding a stored wallet,
including flash extraction and offline attack of the sealed record; a malicious or
compromised coordinator feeding hostile PSBTs or descriptors (mitigated: the on-device
policy engine and the review UI are the trust boundary).

Out of scope, stated honestly: a determined fault-injection attacker holding the device;
supply-chain replacement of the hardware itself; in 0.2.0, an attacker who has held the
device and replaced its firmware, because nothing on the device checks the firmware; and,
also in 0.2.0, an attacker who gets the device powered and attaches a USB cable, because
the debug and download paths that would have to be closed are eFuse burns this release
does not make. That last one has its own section, "The powered device", because it is the
cheapest attack on the list and the easiest to assume away.

**No vendor genuine-check exists and none will be built on this hardware.** The eFuse
HMAC key is provisioned by whoever flashes the device, not by a factory, so a
challenge-response ceremony would prove only "this device knows a key someone
provisioned" - which an attacker who flashes their own firmware and burns their own key
reproduces exactly. Reproducible builds plus a firmware digest the owner compares against
their own build are the honest substitute.

## The three device states

PIN-MODES.md is authoritative. Two of the three have no stored secret at all, which is
worth stating before any tier of stored-secret analysis.

- **State 1, stateless (the default, and a first-class mode).** No PIN, nothing written to
  flash, seed in RAM for the session and gone at power-off. This is the 0.1.0 model and it
  remains a legitimate way to own this device. There is nothing to brute-force and nothing
  to extract; every tier below is empty.
- **State 2, PIN set with the wipe on (the default once anything is saved).** The tiers
  apply, with N = 15 by default.
- **State 3, PIN set with the wipe off.** The tiers apply with the attempt limit removed.
  See the wipe stance for what that costs and why it is nevertheless the user's to choose.

## The stored-wallet guarantee, tiered

The tiers are the claim. Nothing broader is claimed anywhere.

1. **Bench attacker (theft, desolder, flash dump).** Gets an AEAD-sealed record. Each PIN
   guess requires this physical board, because the sealing key ladder passes through the
   P4 HMAC peripheral whose key lives in a read-protected eFuse block that software cannot
   read. On-device guessing meets the attempt counter: 15 consecutive failures by default
   destroy the sealed records. **The flash is not encrypted** (see "What 0.2.0 does not
   have"), so the PIN ladder is the whole of the protection, and the attempt counter is
   user-disableable.
2. **Fault-injection lab.** Assume the eFuse key and a flash image are eventually
   extracted; the ESP32 family has a uniform published history of falling to fault
   injection and no P4-specific result exists, so the P4 is treated as NOT proven
   resistant. The attack then collapses to offline Argon2id-stretched guessing, and the
   wall is entirely the user's entropy. The PIN floor is 4 characters and **4 digits does
   not survive this tier**: 10,000 candidates at the pinned Argon2id cost is hours, not
   years. 6 digits is days to weeks; an alphanumeric passphrase does not fall. The device
   states this at PIN creation, in those terms.
3. **What the attempt counter actually buys.** It converts unlimited offline guesses into
   N guesses per full-flash restore cycle. The counter lives in a plaintext partition -
   bit-clear counters are incompatible with XTS write granularity, so they could not be
   encrypted even on a unit that had flash encryption - and there is no key to break
   there: the attacker copies bytes back. Ledger-only rollback (an old counter image
   beside current records) IS detected and refused at mount. A consistent full-flash
   snapshot and restore is neither detectable nor preventable and needs no key. Against a
   thief with a hot-air station and a programmer, N per restore cycle is a real slowdown of
   several orders of magnitude, not a wall. **"Tamper-proof storage" is not claimed and
   never will be on this hardware.**

**Deterministic-wipe posture.** The SEED is re-derivable from the user's own dice rolls or
mnemonic backup, so a wiped seed is an inconvenience rather than a loss, and a stolen
device races an owner who can move funds from backup. **The rest of the device's state is
not re-derivable from anything.** Multisig registrations, labels and settings exist only
on the device, 0.2.0 ships no backup, and a wipe destroys them permanently. Every wipe
surface names them individually rather than implying the mnemonic covers everything.

## The powered device: USB, JTAG and ROM download mode

The tiers above describe an attacker who took the flash chip. This section describes the
cheap attack, and on a 0.2.0 unit it is the one that matters: **an attacker who gets the
device powered and plugs in one USB cable.**

The ESP32-P4's USB-Serial-JTAG peripheral puts a JTAG debug port on the same D+/D- pins
that carry power and flashing, with no external adapter and nothing for software to
enable - Espressif's own documentation presents it as the quickest and most convenient way
to start JTAG debugging on this chip. **That no USB data functionality is compiled in is
true and beside the point.** The peripheral is silicon; it is live from power-on, before
any code of ours runs, and an application cannot decline it.

What that buys an attacker on a 0.2.0 unit, where no JTAG or download-mode eFuse is
burned:

- **OpenOCD over that one cable halts both cores and reads internal RAM and PSRAM.** For
  the length of an unlocked session, that memory holds the unsealed seed, the derived
  xprv and the PIN as typed. Zeroize-on-drop bounds how long each value exists; it does
  nothing against a debugger that halts the CPU while the value is in scope and in use.
  This is a read of the live secret, so it does not meet the PIN ladder, the attempt
  counter or the Argon2id cost - none of tier 1 to 3 above applies to it.
- **ROM download mode is open on the same cable**, so the app partition can be rewritten
  without opening the case. Without Secure Boot v2, the replacement image runs. That is
  the firmware substitution of the self-reporting boundary, reduced to one cable.

**One thing the port carries in the other direction, for completeness.** The IDF
secondary console (`CONFIG_ESP_CONSOLE_SECONDARY_USB_SERIAL_JTAG`) is in the image by
default, so the boot log leaves the device on the USB port whenever it is plugged into a
host. That direction is output only: no CDC-ACM, MSC, HID or TinyUSB device path is linked
into any artifact, which `tools/ci/check-airgap.sh` asserts positively per image rather
than by absence of evidence. No key, seed or PIN material reaches that log in a release
build - the only call sites that print PIN material belong to the HIL console, which
`build.rs` refuses to compile in a release profile and `tools/ci/check-release-symbols.sh`
asserts absent from a shipped binary (Q41). It is still a data emission over a port
described elsewhere as power-and-flash, so it is named here.

**The window is precisely: device powered, physically reachable, cable attachable.** Evil
maid, a border inspection, a repair shop - the situations where the device leaves your
hands in a state where it can be powered up. It is not a remote attack and not a network
attack, it does not apply to a powered-off device in your possession, and against a
stateless unit (State 1) between sessions there is nothing in RAM to read. What it does
mean is that **an unlocked session in a place you do not control is the exposed state**,
and no software change in this release moves that line.

The eFuses that would close these paths - `DIS_USB_JTAG`, `DIS_PAD_JTAG`,
`DIS_DOWNLOAD_MODE`, `DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE` - are not burned on 0.2.0 units;
the one eFuse this release burns is the HMAC key the sealed storage binds to. **Burning
them is not proposed here.** It is the same one-way cliff and the same key-ownership
question as Secure Boot v2, it is a 0.3.0 decision, and plan-0.2.0/SECUREBOOT.md owns it
(section 10, the burn sequence and what each step forecloses). This section states the
exposure and stops there.

## Invariants

1. **No radio.** The WiFi companion chip (ESP32-C6) is driven into reset by a P4 GPIO
   before anything else in `app_main`, and the line is never released. The kill GPIO is a
   per-board compile-time constant; docs/BOARDS.md ("The airgap invariant, per board") is
   the source of truth. No esp_hosted, esp_wifi_remote or any network/WiFi/BT component is
   present in the firmware image, and there is no code path that could initialize the SDIO
   link to the C6. Enforced by: `tools/build-graph-check.sh` (CI job `invariants`), which
   bans `rand`, `rand_core`, `getrandom`, `ring` and the network crates across every
   lockfile and, with no exemption at all, across the resolved dependency subtree of each
   crate that links into the image; plus the boot-time GPIO drive and the Verify screen's
   readback of the kill line's live level. The ESP-IDF managed-component set is pinned by
   `firmware/components_esp32p4.lock` and reviewed at release; that half is a pinned list
   and a review, not a CI grep.

   **Scope of this invariant, stated because the heading is stronger than the mechanism.**
   It covers the P4 image for the whole power cycle, and the C6 from the first instruction
   of `app_main` onward. It does NOT cover the hundreds of ms before `app_main` on a board
   whose C6 EN is pulled up, where the C6 runs its own factory firmware and brings a WiFi
   MAC and a Bluetooth controller up on its own initiative. That is the C6 power-on window
   under "Known accepted risks", and it is the honest boundary of "no radio" on an Elecrow
   unit. On every supported Waveshare board C6 EN carries no pullup and the window does
   not exist, so the heading is literal there.

2a. **No plaintext secret ever leaves RAM.** Seeds are persisted only as AEAD ciphertext
   under the PIN-derived key ladder, only on explicit user opt-in, only to the dedicated
   `wallets` partition. The app and bootloader partitions are never written at runtime. NVS
   is never mounted and is not in the partition table. RAM copies are zeroized on lock,
   screen exit, session timeout and power-off. A device with no stored wallet retains the
   0.1.0 stateless property verbatim: nothing is ever written to flash. Enforced by: a
   compile-time drop-equals-zeroize check in notyas-ui that names every secret-bearing
   field of every screen against its type, so replacing one with a plain `String` stops the
   crate compiling; `Zeroizing`/`ZeroizeOnDrop` types through notyas-core and
   notyas-wallet; and the partition table itself, which declares nowhere else to write.

   **The one exception, stated rather than buried (0.2.0).** A device that has never
   stored a wallet but HAS saved a public setting - a device name, or the network toggle -
   has written to flash: to the `settings` partition, and only there. That region holds no
   secret and no secret-derived value; it exists because the lock screen draws the device
   name BEFORE any PIN, so the value cannot live in a store that is unreadable until the
   unlock it is displayed in front of. It is plaintext, unauthenticated, and rewritten by
   the user at will, and the admission rule for anything ever added to it is that "an
   attacker sets this to any value of their choosing" must be an acceptable outcome - which
   is why the wipe policy, attempts-left, `min_pin_len`, the boot counter, acknowledgement
   timestamps and anything about wallet occupancy are excluded from it by name
   (`crates/notyas-wallet/src/settings.rs`). A device that has saved neither a wallet nor a
   setting still writes nothing at all, and that remains provable by a flash readback.

   **Corollary on QR display, carried forward from 0.1.0.** QR display covers PUBLIC
   values only - receive addresses, account xpub/SLIP-132, descriptors, signed PSBTs and
   final transactions - and never a mnemonic, xprv, seed or WIF. SeedQR display-out is
   declined for 0.2.0 (Q17), so there is no exception to state and no secret-QR screen
   class; scan-IN of a SeedQR is a separate direction and is unaffected. Enforced
   structurally: the request type carries a label and a payload string, the only code paths
   that construct one are the export screen's three QR buttons (address, account xpub,
   SLIP-132 key), and the UI tests assert what those buttons emit.

2b. **What the device may write is enumerated, public, and closed.** Flash: the `wallets`
   partition (sealed records and sealed multisig registrations, ciphertext only), the
   plaintext `counters` partition (attempt and guard bit-logs, seal_seq high-water,
   wipe_epoch, the wipe-policy log - no secret content, plaintext by necessity because
   bit-clear counters are incompatible with XTS write granularity), and the plaintext
   `settings` partition (device name and network choice - public preferences the user
   explicitly saves, read before any PIN, listed exhaustively in 2a). SD, when the SD
   subsystem ships: `*-signed.psbt`, `*-final.txn`, exported xpubs and descriptors.
   **Nothing else, and nothing conditional** - encrypted backups were the one conditional
   item and Q14 deferred them whole. No key material, no PIN material and no logs reach SD.
   Privacy note, stated honestly: exported xpubs and descriptors are not secrets but reveal
   a wallet's entire address history to whoever reads the card, and the export screens say
   so. Every write to flash or SD is announced on-screen before it happens; that one is a
   UI requirement carried by the screen specifications, not a mechanism the storage engine
   can enforce.

3. **Deterministic.** Key material derives exclusively from user-supplied dice rolls or a
   typed mnemonic, plus an optional passphrase. No TRNG, no clock and no OS entropy on any
   derivation path OR in the storage sealing path: salts and nonces are derived,
   unique-by-construction values (an eFuse-keyed device binding plus a monotonic seal
   sequence), never random ones. The distrusted P4 TRNG (esp-hal#5982) is used for nothing.
   Schnorr signatures use the deterministic no-aux-rand BIP-340 path; ECDSA is RFC 6979
   with Bitcoin Core's low-R grinding. Enforced by: no RNG API existing in notyas-core or
   notyas-wallet, and the build-graph check proving no RNG crate is reachable from either.
   (Tradeoff recorded: deterministic nonces weaken the side-channel and fault-injection
   posture - glitched-digest nonce reuse is the textbook attack - and are chosen
   deliberately for verifiability. Mitigation: the post-sign gate re-verifies every
   signature this device produced against a sighash recomputed from the PSBT alone before
   anything leaves the device; the remaining fault surface is the lab attacker tiers 2 and
   3 already concede.)

4. **Equivalence.** Identical input produces byte-identical output to desktop BigDice, and
   identical PSBT plus identical wallet produces signatures that match pinned published
   vectors. Enforced by: shared test vectors run in CI on the host and a curated subset run
   as the on-device boot self-test, against BIP-39, BIP-32/44/49/84/86, BIP-143 (native and
   wrapped segwit), BIP-340 (the published signing vectors, aux_rand all zero) and BIP-341
   (key-path spending), each vector naming its upstream source in the file that pins it.
   **Split by algorithm.** For ECDSA, byte-equality against Bitcoin Core's own emitted
   signatures IS claimed and IS tested, because notyas grinds low-R exactly as Core does,
   which also makes the 71-byte signature size and therefore the displayed vsize and fee
   exact; the pinned expectations are Core's two published deterministic vectors plus a
   grinding corpus reproduced by an independent RFC 6979 implementation that reproduces
   both of Core's and both of BIP-143's byte for byte. For Schnorr, byte-equality with Core
   is NOT claimed and never will be: Core randomizes BIP-341 aux-rand, so it is impossible
   under any implementation choice; the claim there is the pinned BIP-340 vectors. A live
   `walletprocesspsbt` + `testmempoolaccept` differential against a running Bitcoin Core is
   a release-time procedure, not a CI job, and is not claimed as one.

5. **Verifiable firmware, and a storage readout that is deliberately coarse.** The Verify
   screen reports the eFuse HMAC-key state, the three secure-boot digest slots, the
   flash-encryption and download-mode fields, the running-app and partition digests, the
   boot count and the storage state **as actually read from the running system, never as
   compiled-in constants**; a field this build cannot read renders `not read`, never a
   plausible default. There is no summary verdict on that screen, by design: a verdict
   computed there would be the firmware grading itself. Read the self-reporting boundary
   above for what that is worth without Secure Boot.

   **Storage-state granularity is a permanent honesty cost paid by every user:** the
   readout is `present` or `blank` and never a count of sealed wallets, whether or not that
   user ever enables a duress PIN. The only other values it can take are `not provisioned`
   and `unreadable`, neither of which is a count. Reporting the true count would let a
   coercer read off the Verify screen how many wallets exist, which is the leak a duress
   feature cannot survive. The full wallet list is shown after a successful unlock, where
   it is post-PIN and leaks nothing. What makes the coarse readout meaningful rather than
   merely vague is that unused slots always hold device-derived filler ciphertext, so
   `present` is the true state of every formatted device and an attacker without the eFuse
   key cannot tell filler from a real record. The claim stops exactly there: it is not a
   claim about an attacker who has extracted the key, and not a claim that behaviour under
   a duress PIN is indistinguishable at every UI surface.

   **The wrong-PIN wipe policy is user-settable, from an unlocked session only.** The
   default is 15 attempts; the user may change N within 3..=25 or disable the wipe
   entirely. The bounds are format constants, the encoded policy is authenticated inside
   the AEAD, and a malformed or absent policy resolves to the strict default of wipe ON.

6. **Secure boot, honestly - and in 0.2.0 the honest answer is that it is not there.**
   Secure Boot v2 is not burned on 0.2.0 units, eFuse anti-rollback is not set, and no
   flash-encryption key is burned (Q32 deferred to 0.3.0; Q63 settled the scope of "no
   eFuse burned" to mean no secure-boot-related eFuse). The device stays reflashable, which
   is what keeps the reproducible-build claim usable by the person it is for. **The one
   eFuse 0.2.0 uses is the HMAC key the sealed storage binds to**, burned host-side with
   `espefuse.py` by whoever provisions the board, before the firmware first runs. A device
   that has not been through that ceremony has no key, stores nothing, and says so as its
   own state rather than as a hardware fault. The three secure-boot digest slots render
   `not burned`, which is the true and important answer rather than a hidden section.

   When Secure Boot returns in 0.3.0 the parameters are already fixed: Secure Boot v2
   RSA-3072 only, never ECDSA (ROM-broken on shipping P4 silicon, Espressif AR2026-006),
   with the key-ownership question settled first, because it decides whether an owner of
   this device can build and run their own firmware.

7. **The signing policy engine is the trust boundary.** No PSBT input is signed unless:
   claimed key origins re-derive to the input's actual script; every segwit-v0 and legacy
   input carries its full previous transaction with matching txid and amount (the BIP-143
   fee-attack defense); the network matches; the sighash type is whitelisted; and the
   structural limits on size, counts and derivation depth hold. Outputs are classified,
   and **change is proven rather than believed**: an output is change only when a
   registration this device holds rebuilds that exact script on its change keychain at the
   claimed leaf. An output that merely carries our fingerprint and cannot be proven counts
   as a payment everywhere money is counted, which is the change-confusion attack refused
   by construction. The fee is computed from the prevouts, together with whether it is a
   number this device's own signatures would actually enforce, so a claimed amount is
   never rendered as a measured one. Validation is a pure function of the PSBT and a
   context, with no key in scope, and it refuses with one named reason rather than a list.
   After signing, every signature this device produced is re-verified against a sighash
   recomputed from the PSBT alone before the file leaves the device; that gate shares
   rust-bitcoin's digest implementation with the signing path, so it detects a fault or a
   caller bug rather than standing in for an independent second implementation. Each check
   is pinned to a historical attack in plan-0.2.0/ARCHITECTURE.md 5.3 and to a case in the
   regression corpus that CI runs. A maximum-fee ceiling is a review-layer check and is not
   claimed here.

## Duress and wipe stance

- **Wipe-on-N** (default 15, range 3..=25, user-settable and disableable) destroys the
  sealed records and bumps a one-way epoch marker. The user is told at setup that the
  mnemonic or dice backup is the recovery path for the SEED, and equally plainly that it is
  not a recovery path for anything else: multisig registrations, labels and settings are
  destroyed permanently, and every wipe surface names them. A power cut taken between the
  attempt-cell program and the success-cell write CONSUMES an attempt even when the PIN was
  correct - deliberate and fail-closed, because otherwise power-cutting is a free oracle -
  so on a portable device the counter can advance with no wrong PIN entered, and the
  wrong-PIN policy screen says so.
- **Turning the wipe off is a real weakening, and the device says so where it happens.**
  With the wipe enabled an attacker holding the device gets N guesses; with it disabled
  they get all of them, at one guess per Argon2id stretch - the pinned cost is 1.8 s, so a
  4-digit PIN is a few hours, and half that for an attacker running their own firmware on
  both P4 cores, which in 0.2.0 needs no key because Secure Boot is not burned. The
  settings screen states
  the keyspace, the measured per-guess cost and the resulting time for the PIN actually set,
  at the moment of the change, and offers the longer-PIN path as an action. A longer PIN is
  not required: the device states the trade and does not withhold the setting.
- **What stops an attacker turning the wipe off before guessing.** A policy change needs
  the PIN: both writes that constitute it require an unlocked session plus a fresh PIN
  confirmation, and every attempt to obtain one spends an attempt against the counter being
  attacked. Offline editing cannot do it either, because the ledger cell's guard and the
  superblock mirror's MAC both descend from the read-protected eFuse key, so forged bytes
  are malformed, and malformed resolves to wipe ON. Erasing the policy log does not help: an
  empty log falls back to the format-time policy, which has the wipe enabled. **What is NOT
  defended, stated rather than implied: a consistent full-flash snapshot and restore
  restores the policy along with everything else.** If the snapshot was taken while the wipe
  was disabled, restoring it buys unlimited guesses permanently, and turning the wipe back
  on afterwards does not repair it. A device on which the wipe has ever been disabled must
  be treated as having no attempt limit from the earliest snapshot an attacker might hold.
- **Removing the PIN means reverting to stateless operation and destroying every stored
  wallet.** There is no "stored wallets with no PIN" state, and the reason is structural
  rather than a policy choice: the sealing key is derived from the PIN, so with no PIN there
  is no key and no sealed storage. The confirmation names what is destroyed - every wallet,
  every multisig registration, all labels and settings, the anti-phishing words - with
  counts read from the store rather than a generic phrase. It is a data-loss event, not a
  security downgrade: the device it produces stores nothing, which is the safest state this
  hardware has.
- **Duress PIN:** opens a decoy wallet set, with no stored marker saying which PIN is which.
  The feature is OFF by default. The record format carries it unconditionally - four PIN
  identities, index 0 primary - so nothing about the decision reaches the on-flash bytes;
  the enrolment and classification UX is the half that decides whether a given release
  exposes it. The deniability package it depends on is not optional and
  is not off by default - unused slots always hold device-derived filler ciphertext for
  every user, and the Verify storage readout is permanently coarse for every user - because
  a package only some devices have is itself the tell. A duress PIN alone would NOT be
  "indistinguishable by construction", because slot occupancy is visible pre-PIN; the claim
  actually made is the narrower one in invariant 5, and nothing beyond it is claimed.
- **Anti-phishing words** at half-PIN entry authenticate the DEVICE to the user, and they
  are derived from the read-protected eFuse key, so they genuinely detect a swapped board.
  **They do not detect replaced firmware on the same board**: any firmware running on that
  board can compute them, and without Secure Boot firmware replacement is precisely the
  attack in play - on a 0.2.0 unit it needs one USB cable and open ROM download mode (see
  "The powered device"), not a workshop. The words catch a different device, not different
  software on the same device. A second known limit, shared with Coldcard: an evil maid who held the device can
  enumerate and replay the words on a look-alike. Displaying them costs no attempt-counter
  decrement.

## Known accepted risks (documented, not hidden)

- **ESP-IDF (FreeRTOS plus drivers) is in the TCB.** It is fully open source and radio-free
  on the P4, but it is large. Mitigation: the crypto core never calls into it; the firmware
  crate is the only IDF consumer.
- **USB is a physical attack surface, and the part that matters is not the application.**
  The PSBT path deliberately does not use USB and no USB data functionality is compiled
  in. That disposes of USB as an application input and of nothing else: the P4's
  USB-Serial-JTAG peripheral offers a debug port and ROM download mode on the same pins
  regardless of what the application contains. "The powered device: USB, JTAG and ROM
  download mode" above is the claim; this bullet is only the pointer to it.
- **The GT911 touch controller and ST7703 panel run vendor init sequences** (documented
  register writes; no firmware blobs are uploaded to them by us).
- **The vendored libsecp256k1 is C code in the TCB.** It is the same library desktop
  BigDice and Bitcoin Core rely on, and equivalence with it is the point of invariant 4.
- **Argon2id parameters are a measured compromise on rev v1.x silicon** (16 MiB, t=1, p=1;
  1827 ms measured on both bench boards). They bound, not eliminate, offline guessing after
  a successful key extraction. The Key-Manager-backed ladder needs newer silicon and is
  scheduled for 0.3.x on the same record format.
- **The HMAC-eFuse binding means a dead P4 with an intact flash chip is NOT recoverable** by
  moving the flash to another board. That is by design; the user's own backup is the
  recovery path and setup says so.
- **FATFS on SD is not power-loss safe.** Accepted: a torn SD write loses a re-creatable
  artifact (a signed PSBT can be re-signed), never a secret. The wallet partition does not
  use FATFS. The IDF FATFS/VFS/SDMMC stack is also new C attack surface parsing untrusted
  media; mitigations are mount-on-demand, unmount outside signing and export flows, a cap on
  accepted file size, PSBT parsing itself in Rust, and filenames rendered with a restricted
  charset.
- **The release signing key is held on a general-purpose machine**, not a hardware token
  (Q30). A verifier's trust in `SHA256SUMS.txt` is exactly as good as that key's custody, so
  the custody regime is documented rather than assumed.
- **Board choice is itself a security choice, and the supported boards are not equal.**
  Every Waveshare board module in docs/BOARDS.md carries a C6-MINI module whose EN has no
  pullup (1 uF to GND only, schematic-verified), so its radio is held down from power-on
  and no window exists at all. Every Elecrow board module pulls EN up and has the window
  described next. **Of the hardware 0.2.0 supports, a Waveshare unit is therefore the
  airgap-preferred choice.** The running firmware already states which case the board in
  your hand is, at every boot: the Waveshare modules log the radio as held down from
  power-on at info level, the Elecrow modules log the power-on window as a warning. The
  predictor is the C6 part rather than the vendor - a C6-MINI module has no EN pullup, a
  bare ESP32-C6FH8 does, and the two Waveshare P4 boards built on the bare chip
  (Touch-LCD-3.5, WIFI6-DEV-KIT) do boot their radio at power-on. Neither is a supported
  board here; docs/BOARDS.md carries the full rule so the shorthand is not generalized.
- **Elecrow 5inch board only** (board-elecrow-5, verified 2026-08-17):
  - **C6 power-on window: a live radio inside the case at every power-up.** The C6's EN
    pin carries a 10K pullup (R77) to an always-on rail, so the radio co-processor boots
    its factory esp-hosted `network_adapter` firmware at every power-up and runs until
    `app_main` drives the kill GPIO low (order: hundreds of ms, ROM and bootloader
    included). **That firmware does not idle during the window; its init path is
    unconditional.** `esp_hosted_coprocessor.c` calls `connect_sta()` inside a `#if 1`,
    which runs `esp_hosted_wifi_init`, `esp_wifi_set_mode(WIFI_MODE_STA)` and
    `esp_wifi_start()`; `slave_bt.c` calls `esp_bt_controller_init` and
    `esp_bt_controller_enable` under `CONFIG_BT_ENABLED`. So a WiFi MAC and a Bluetooth
    controller are alive inside the case for the whole window, at every power-on, and if
    that C6's NVS holds saved credentials it attempts to associate. **The device is
    RF-visible and MAC-identifiable at every power-on.** What does not happen is
    exfiltration of anything of the user's: the P4 image contains no driver for the SDIO
    link, and that early in the boot no secret exists on the P4 to send. The exposure is
    presence and identity, not user data - which is still not what an airgap is bought
    for, so it is stated rather than characterized as harmless. Logged as a warning at
    every boot. **Firmware cannot close this window**: ROM and the second-stage bootloader
    run before any code of ours, so no build option, sdkconfig setting or boot ordering
    helps. The only real mitigations are physical: remove R77, the EN pullup, so the C6
    never comes out of reset (the P4 still holds the line low through R95), or remove the
    C6 module outright. **Do not remove R95 on its own** - that cuts the kill line while
    leaving the pullup in place, which extends the window from hundreds of ms to the
    entire session.
  - **STC8 co-MCU.** Backlight control requires one I2C register write to an STC8H1K17
    running unpublished Elecrow firmware. It has no radio and no bus-master role, but it
    sits on the touch I2C bus and its firmware is unverifiable. We send it exactly that one
    write and read nothing security-relevant from it.
  - **Wireless module socket.** The board has a socket for LoRa/nRF24/Zigbee modules. The
    airgap on this board additionally requires the socket to be physically EMPTY; firmware
    never initializes the socket pins and does not try to detect a module. A documented
    physical precondition, like "keep the device in your possession".
