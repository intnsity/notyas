# notyas 0.2.0 - Open questions (one deduplicated decision list)

Status: RECONCILED 2026-08-17. Merges wave-1's thirteen questions, wave-2's
(camera path, crate licensing, parity class-c/d tiering) and the red team's two
escalations into one numbered list. Wave-1 numbers no longer apply; the old number
is noted on each item so earlier references stay traceable.

**Q1-Q8 block milestone 1.** Nothing downstream can start until they are answered,
because each one pins either a document that must precede the code or a byte-level
format that cannot change once a user has sealed a wallet. Q9-Q50 can be answered at
their milestone. **Q22 is already RESOLVED by the user** (the BIP39 passphrase is
never stored) and is kept in place with its resolution, because its two consequences
are implementation requirements. **One exception inside the blocking set: Q2 is no
longer a format decision** - ESP-SEAL.md 3.6 showed the duress filler needs no format
change, so Q2 decides behaviour only and its real deadline is m4b. It stays numbered
where it is; see its blast radius.

Wave-3 design documents (WALLET-API.md, ESP-SEAL.md, CORPUS.md, REPRODUCIBLE.md,
UX-SCREENS.md, BACKUP-FEATURES.md, CAMERA-HW.md) raise their own `OPEN:` items. Those
are folded in here as Q22 and up, attributed to the source document. Decisions those
documents took internally are theirs to keep and are not re-litigated here. **All of
them have now been swept; the list is complete as of 2026-08-17.**

How to answer: reply with the question number and a letter, or "as recommended".
Anything not overruled is taken as the recommendation and written into SPEC at m1.

---

# BLOCKING - answer these to start m1

## Q1. Ratify fully deterministic sealing (no RNG anywhere) [was Q4]

**Decision:** keep the sealing path RNG-free (derived salts, monotonic `seal_seq`
plus one-way `wipe_epoch` for nonce uniqueness, deterministic no-aux-rand BIP-340),
or allow the P4 TRNG for salts.

**Recommendation: ratify RNG-free as written (ARCHITECTURE 2.4).** It keeps
SECURITY.md invariant 3 mechanically checkable by the build-graph test, and the P4
TRNG is already distrusted (esp-hal#5982). Accepted cost, recorded: deterministic
nonces are the textbook fault-injection target, mitigated by the post-sign gate that
re-verifies every signature against an independently recomputed sighash.

**Blast radius:** the highest-leverage decision in the plan. Overruling it rewrites
SECURITY.md invariant 3, the record format, the whole m3 KDF ladder, and the
build-graph ban list.

## Q2. Duress PIN: which package, if any [was Q2; red team changed its shape]

**Decision:** the red team showed "indistinguishable by construction" was false as
drafted - slot occupancy is visible in a pre-PIN flash dump, and the Verify screen
would report the true wallet count to anyone holding the device.

- (a) Ship duress WITH the full package: unused slots always ciphertext-filled with
  device-bound pseudorandom filler (HMAC-eFuse-derived, no RNG); Verify storage
  readout degraded to "present / blank" permanently and for ALL users; delete and
  wipe rewrite filler rather than leaving erased-flash signatures.
- (b) Ship duress WITHOUT the package, documented as "the coercer can see how many
  wallets exist; duress only hides which PIN opens what".
- (c) Drop duress from 0.2.0 and keep the honest "N sealed slots" Verify readout.

**Recommendation: (a), off by default.** Filler slots and the degraded readout are
cheap, and a duress feature that leaks the wallet count is worse than none - it
invites the coercion it cannot survive. A wipe-PIN variant stays deferred either way
(it invites accidental self-harm).

**Blast radius (REVISED 2026-08-17 by ESP-SEAL.md 3.6 - this supersedes R11 as
originally written; see MILESTONES R11):** Q2 decides BEHAVIOUR only, and can be
answered AFTER the storage format is frozen. The reconciliation's earlier finding
that duress blocks m3 assumed filler slots were a format change. ESP-SEAL.md 3.6
shows they are not: a filler slot is a genuine AEAD record sealed under a
*device-derived* key (`HKDF(filler_root, kdf_salt, RecordInfo)`), carrying the same
header shape, the same `pin_gen` identity 0, and consuming `seal_seq` values like any
other record. The device therefore tells empty from occupied with one HKDF and one
AEAD open per slot and no PIN, while an attacker without the eFuse key cannot. The
format is byte-identical under `Occupancy::AlwaysFilled` and `Occupancy::Sparse`;
only the CONTENT of an unoccupied slot differs. **The ESP-SEAL analysis wins because
it is the concrete format, not a summary of one** - the reconciliation reasoned from
ARCHITECTURE 2.5's prose, which had no filler construction in it yet, and a mechanism
that exists at zero marginal format cost beats an inference that it could not.
What remains: Q2 still sets SECURITY.md invariant 5's wording, the permanent
degradation of the Verify storage readout for ALL users, the m4b capacity line ("3 of
8 slots" only survives under (b)/(c)), and Q37. **Deadline: m4b, not m3.** It stays
in the blocking set because it is cheap to settle at m1 and three screens depend on
it, but it no longer gates the format freeze and answering it late costs no
migration.

## Q3. ECDSA low-R grinding and the scope of the equivalence claim [was Q13]

**Decision:** the draft's "byte-identical signatures to Bitcoin Core" was impossible:
Core randomizes BIP-341 aux-rand, and grinds ECDSA nonces for low-R (71-byte DER)
while plain RFC6979 does not.

- (a) Adopt low-R grinding (`secp256k1::sign_ecdsa_low_r`): Core-identical ECDSA
  bytes, predictable 71-byte signatures and therefore exact vsize and fee
  prediction, byte-level differential testing against Core.
- (b) Stay on stock RFC6979 through `Psbt::sign`: simpler code path, equivalence
  claim reduces to "pinned vectors plus Core verifies and accepts".

**Recommendation: (a).** Predictable signature size matters on a device that shows a
fee it must stand behind, and byte-level ECDSA differential testing is a materially
stronger CI gate. Schnorr byte-equality versus Core is impossible under either
option and is never claimed.

**Blast radius:** BLOCKS m2 (the signing API shape and its known-answer vectors, not
just the SPEC text - R12) and the wording of SECURITY.md invariant 4.

## Q4. PIN format and floor [was Q5]

**Decision:** what the entry surface accepts and enforces.

**Recommendation: minimum 6 digits, full alphanumeric supported and actively nudged**
(entropy meter at creation, wording: "a digits-only PIN protects against theft, not
against a funded lab"), no maximum below 64 characters.

**Blast radius:** m1 SPEC text, the m3 KDF ladder's normalization (NFKD) and cost
target, and screens 2 and 4. Post-fault-injection, offline guessing is bounded only
by this entropy, so it is also a SECURITY.md tier-2 claim.

## Q5. Wipe-after-N default [was Q3]

**Recommendation: N=10, configurable no lower than 3 and no higher than 25.** The
setup screen states the policy and that the user's own backup is the recovery path.
Aggressive is affordable because every notyas wallet is re-derivable.

**Blast radius:** the m3 counter bit-log format (the bit budget is sized to N) and
m4a's wipe gate.

## Q6. Camera in 0.2.0, or 0.3.0? [wave 2, CAMERA.md]

**Decision:** CAMERA.md ranks CSI + OV5647 (Pi-camera-class, the module a SeedSigner
already uses) first, SD-only second, and rejects USB-UVC outright.

- (a) Camera in 0.2.0 as milestone m11: board A only (board B cannot take a Pi-class
  module), compile-time feature off by default. Moves the class-c QR-scan rows
  (seed scan, PSBT scan-in, QR scanner module) to class b.
- (b) Camera in 0.3.0. 0.2.0 stays SD-in / QR-out, which Coldcard's microSD flow
  proves is a legitimate airgap on its own.

**Recommendation: run the spike inside m1 either way** (half a day: plug the user's
module into J1, run the esp-video `capture_stream` example), then **(a) if the spike
passes.** A working camera closes the single biggest gap versus the Coldcard Q, and
the parity bar is the product bar.

**CAMERA-HW.md 6.2 raises the same question and its answer is merged here rather than
duplicated. It refines (a) into "(a) but droppable":** land camera in 0.2.0, sequence
it LAST, and let it slip without blocking the release. Every camera parity row has a
working SD equivalent, so nothing in 0.2.0 is blocked on it; meanwhile the riskiest
part is the cheapest part (the bench replug experiment), so buying the answer early
costs a couple of hours. Its proposed ordering splits m11 into six steps - m-camera-0
(the replug experiment, which is m1's spike), m-camera-1 (the `board::shared_i2c_bus()`
refactor, cheap, independent, and worth landing with the early infrastructure work),
and m-camera-2..5 (esp_video integration, PPA plus rqrr decode, the ingress validator
and fuzz harness, then the scan session in the UI) at the end of the list, each
individually droppable. **Adopting this changes nothing about the yes/no; it changes
where m11 sits and makes partial delivery legitimate.** If the answer is (a), also
answer Q47, and place m-camera-1 in the early infrastructure work rather than in m11.

**Blast radius:** BLOCKS m1 because `esp_video` + `esp_cam_sensor` change the
app-size budget the partition freeze depends on (Q7), and because the m6 sign-flow
UX should not be frozen as "no camera exists" if one is coming. Independent of the
answer, m6's PSBT load path takes a source abstraction so m11 is additive. Under the
CAMERA-HW refinement it also reshapes m11 into staged, individually droppable steps
and pulls the I2C-bus refactor earlier.

## Q7. Freeze the storage geometry [new, from reconciliation R2]

**Decision:** ARCH 2.7 puts `wallets` at 0x410000, right behind a 4 MB app. 0.2.0
adds miniscript, argon2, the AEAD stack, FATFS and possibly esp_video; when the app
outgrows 4 MB the data partitions move, and moving them destroys every sealed record
on upgrade.

**Recommendation: freeze this table now, identical on both boards, permanently.**

```
factory,   app,  factory, 0x10000,  8M
wallets,   data, 0x40,    0xE00000, 256K, encrypted
counters,  data, 0x41,    0xE40000, 16K
```

Fits board B's 16 MB (ends at 14.27 MB) and leaves 13.94 MB of app headroom before a
collision; app offset 0x10000 unchanged, so the Verify screen's SHA256 procedure
stays board-independent. Slot budget inside 256 KiB stays as designed: 8 wallet slot
pairs, 8 registry record pairs, 1 header pair - so "8 wallets max" is displayed
honestly. Raise the capacity now if 8 is too few; it cannot be raised later without
a format migration.

**Blast radius:** BLOCKS m1 (it is m1's deliverable) and every stored record for the
life of the product. Interacts with Q6 (a camera build is a bigger app) and Q2
(filler slots consume the same budget).

## Q8. Licensing for the extracted crates [wave 2, PLATFORM.md section 6;
ESP-SEAL.md 9.1 merged in, not duplicated]

**Decision:** the firmware is GPL-3.0-or-later. Pick ONE licence line for the crates
we extract (`esp-idf-hmac`, the `esp-seal` family - `esp-seal`, `esp-seal-idf`,
`esp-seal-sim`, the future `esp-seal-hal` - `seedqr`, maybe `bsms`):

- (a) GPL-3.0-or-later: preserves reciprocity, but the ecosystems these crates serve
  (esp-hal, esp-idf-*, `ur`, `bbqr`, `gt911`) are MIT/Apache and generally will not
  take a GPL dependency - which caps the adoption that is the whole point of
  extracting them.
- (b) Dual MIT OR Apache-2.0: the Rust norm, maximum reuse, GPL3 firmware consumes
  them freely; forfeits copyleft on the crates.
- (c) Per-crate split.

**Recommendation: (c) with a simple rule - permissive (MIT OR Apache-2.0) for
everything meant for the wider ecosystem (`esp-idf-hmac`, the `esp-seal` family,
`seedqr`, `bsms`), with the published esp-seal test vectors under CC0-1.0 so any
implementation may validate against them, and GPL-3.0-or-later for notyas-core,
notyas-wallet, notyas-ui and the firmware.** The reciprocity that matters is on the
wallet itself, not on a KDF wrapper. Two hard constraints, either way: Trezor's and
Jade's code are copyleft, so only their published designs may inform a clean-room
implementation; and `foundation-urtypes` is GPL-3.0-or-later, so all UR/transport
code must stay inside notyas-wallet and never inside a permissive crate (R6). The
CC0 vector rule is the same argument Q39 makes for the PSBT corpus.

**ESP-SEAL.md 9.1 sharpens this for the largest crate on the list, and its argument
is adopted here rather than raised as a separate question.** PLATFORM.md floats a
split of "permissive for the interop formats, GPL3 for esp-seal". ESP-SEAL.md argues
that is exactly backwards: esp-seal is the shortlist item with the largest audience
OUTSIDE Bitcoin - every ESP32 product that holds a secret is a potential user, not
just wallets - and the thing worth protecting is the design, which this planning set
publishes either way. The implementation is on the order of three thousand lines of
well-trodden construction over vetted primitives; copyleft on those lines protects
little and costs the crate its reason to exist.

**Consequence that makes this decision-shaped, and that the answer must cover:** if
GPL-3.0-or-later wins for esp-seal, the crate should NOT be extracted at all. It
should stay a module inside notyas-wallet, because a GPL3 "platform contribution" no
platform can adopt is worse than an honest internal module. So answering Q8 also
answers whether `crates/esp-seal*` ever exists, and it therefore governs Q44 (the
crate boundary) and Q46 (publish location and timing). Answer Q8 first.

**Blast radius:** blocks the first publication (m3h, which starts alongside m2) AND
the first commit of any extracted crate, because the SPDX header has to be right from
that commit; determines whether esp-seal is a crate or a module (Q44, Q46); and
determines whether notyas-wallet can ever be published as a reusable Bitcoin wallet
library. Relicensing after publication requires every contributor's consent, so this
is effectively irreversible.

---

# NON-BLOCKING - decide at the milestone named

## Q9. Production silicon revision and the Key Manager [was Q1] - decide before m13

Both bench units are rev v1.3; the ESP32-P4 Key Manager (HUK / SRAM-PUF-bound keys)
needs rev >= v3.0. 0.2.0 designs for v1.x via the HMAC-eFuse path and works on both.
**Recommendation:** confirm the revision of production hardware before release units
are provisioned; if >= v3.0, schedule a Key-Manager-backed ladder as 0.3.x (stronger
key story, same record format). **Blast radius:** m13's provisioning runbook; no
0.2.0 code depends on the answer.

## Q10. Ratify the class-d reject list [wave 2] - decide by m9

MILESTONES section 7.3 rejects: PSBT over USB host protocol, USB virtual disk,
BIP-85 password typing over USB HID, HSM Mode / CKBunker, paper wallets, WIF store,
Delta Mode, Secure Notes and Passwords, and the trick-PIN brick variants.
**Recommendation:** ratify all nine rejections. The four USB rows are one decision -
they all reopen the data port the airgap posture closes - and rejecting them is a
positioning statement, not a gap. **Blast radius:** parity messaging and the m13
documentation; no engineering depends on a yes.

## Q11. How loudly must class-c equivalents be shipped? [wave 2] - decide by m10

Every hardware-impossible row has a named equivalent (MILESTONES 7.2). Question: do
those equivalents need on-device UI text ("this device has no NFC; show the QR to
your phone instead"), or is the documentation enough?
**Recommendation:** on-device text only where a user would otherwise hunt for a
missing feature (NFC transfers, camera scan-in when the camera is absent, battery),
documentation for the rest. **Blast radius:** m10 and m13 screen copy.

## Q12. Stateless signing [was Q11] - decide by m6

Should a user be able to load a seed transiently (dice or mnemonic entry) and sign a
PSBT with it, SeedSigner style, with storage never touched?
**Recommendation: yes.** It falls out of the session design (a session need not come
from a sealed slot) and preserves the 0.1.0 identity for storage-averse users.
Stated limit: stateless multisig cannot verify cosigners against a registration, so
multisig change claims are refused by default with an expert override.
**Blast radius:** m6 session plumbing and the blank-device home screen; small.

## Q13. Fee thresholds [was Q12] - decide by m6

**Recommendation:** warn above 5% of send value or 500 sat/vB; hard-block only on a
negative fee and rust-bitcoin's absurd-fee guard; always show absolute sats, sat/vB
and percent. Constants live in notyas-wallet, adjustable in Settings behind an
expert gate. (Coldcard defaults to a 10% cap.) **Blast radius:** m6 policy
constants and one review screen.

## Q14. Encrypted SD backup, device clone, Key Teleport equivalent [was Q8;
reopened by BACKUP-FEATURES.md OPEN-B1] - by m9

Wave 1 deferred all three because they write encrypted key material to microSD, which
SECURITY invariant 2b forbids. BACKUP-FEATURES.md raises a fact that reasoning did
not have: **multisig registrations and settings are state no mnemonic can
re-derive.** Under wipe-on-N (Q5) or a lost device, they are simply gone. That splits
the question in two:

- **(a) Seedless backup** - registrations, labels, settings, no seed material.
  **Recommendation: ship in 0.2.0 (m9), encrypted.** This does not need an invariant
  amendment: its contents are the same class of data as the xpub and descriptor
  exports invariant 2b already permits, carrying the same privacy warning, and it
  closes a real hole where a wipe destroys unrecoverable state.
- **(b) Seed-bearing backup, plus device clone and a Key Teleport equivalent.**
  **This reconciliation's recommendation: not in 0.2.0** - the mandatory
  backup-verify quiz plus deterministic re-derivation is the backup story, and a
  second sealed copy of the seed on removable media dilutes it.
  **BACKUP-FEATURES.md OPEN-B1 recommends the opposite**: ship it behind an advanced
  gate as the second of two profiles. Both positions are honest; the user picks. If
  (b) is accepted, SECURITY invariant 2b must be amended explicitly, not quietly, and
  every such file must be labeled "this file's security is exactly this passphrase".

Either way, state honestly: with (b) declined, notyas has NO Key Teleport equivalent
in 0.2.0, and PARITY.md's claimed equivalent (an encrypted state file over microSD)
does not exist (R10). If (b) is declined, the wipe-on-N setup screen must also say
that a wipe destroys multisig registrations.
**Blast radius:** invariant 2b's text, three parity rows, m9 scope, the wipe-screen
copy, and the m13 claims audit.

## Q15. BSMS (BIP-129) tier, and the `bsms` crate [was Q6] - decide by m7

Spec complete, adoption thin; Coldcard implements it on its EDGE branch.
**Recommendation:** no on-device BSMS in 0.2.0 - descriptor import plus the
mandatory first-address cross-device comparison covers the security need. Build the
`bsms` crate at m12 only if m7 finishes with capacity; BDK has an open request for
one, so the contribution has a named consumer either way.
**Blast radius:** m7 scope and one platform contribution.

## Q16. Taproot multisig timing [was Q7] - decide by m7

**Recommendation:** 0.2.0 multisig is P2WSH `sortedmulti` (BIP-48) only; taproot
single-sig (BIP-86) is fully supported for signing; tapscript, multi-leaf and MuSig2
revisit at 0.3.x. Interop across Sparrow/Specter/Coldcard is not there yet, and
upstream Coldcard has it on EDGE only. **Blast radius:** m6/m7 scope; the descriptor
model is designed to accept taproot descriptors later without a format change.

## Q17. SeedQR display-out [reconciliation R19; BACKUP-FEATURES.md OPEN-B3, which
that document's section 6.1 and its B22/B23 rows also call OPEN-B5 - one item, two
labels, no missing question] - by m9

A SeedQR encodes a mnemonic. 0.1.0's invariant 2 corollary is that QR display covers
public values only - never a mnemonic, xprv, seed or WIF. SeedSigner ships SeedQR
display; Coldcard does not. Scan-IN is uncontroversial and ships with the camera
(m11); the question is display-OUT.

- **(a) Decline display-out.** *This reconciliation's recommendation.* Shipping it
  means amending the one invariant that makes the whole QR path safe to trust, for a
  backup format the user can already produce off-device from the displayed words. The
  parity rows are then documented as deliberately declined, not pending - a
  defensible position for a device with a 720x720 mnemonic display.
- **(b) Accept it as a bounded exception, with the "secret-QR screen class" package**
  that BACKUP-FEATURES.md OPEN-B3 specifies: explicit warning gate, hold-to-reveal,
  auto-blank, and a reachability test proving no other screen can reach it. Under
  (b), the invariant is amended to "no QR renders a secret except from the secret-QR
  screen class, which is gated, held and auto-blanked", and that sentence must be
  mechanically enforced by the reachability test or it is not made.

**Blast radius:** SECURITY.md invariant 2's corollary; m9 scope; BACKUP-FEATURES rows
B22-B24; three PARITY rows.

## Q18. BBQr alongside UR2 for QR output [wave 2] - decide by m8

**Recommendation: yes if the `bbqr` crate clears the dependency ledger** (no RNG, no
network, pinned, license compatible). UR2 stays the default; BBQr is Coldcard-family
interop and costs one encoder. **Blast radius:** m8 scope and one dependency edge.

## Q19. Login extras: MicroSD 2FA, Login Countdown, Kill Key - decide by m13

**Recommendation:** Kill Key yes (real when implemented as storage-key zeroization);
escalating wrong-PIN delay yes (m4a); configurable long Login Countdown no (5 min to
28 days invites self-lockout and only deters an attacker using the UI); MicroSD 2FA
no for 0.2.0 (card-serial binding adds a bricking failure mode for modest gain).
**Blast radius:** three parity rows; m4a/m13 UI.

## Q20. Blind-oracle unlock mode [was Q9] - revisit post-0.2.0

The only known way to give a no-secure-element device real offline-brute-force
resistance, but every unlock needs a network-connected helper, against the
single-device airgap identity.
**Recommendation:** not in 0.2.0; documented in SECURITY.md as a known alternative
with its tradeoff. Revisit only on user demand; a self-hosted oracle over QR
transport would be the shape. **Blast radius:** documentation only.

## Q21. Anti-phishing words and the lock-screen word [was Q10] - ratify at m4a

Both need only HMAC-eFuse plus UI work. **Recommendation: ship both** (words at
half-PIN, user-chosen lock-screen word). Two limits to state on screen: an evil maid
who held the device can enumerate and replay the words on a look-alike, so they
defeat swap-by-a-stranger, not substitution by someone who had your device; and the
words exist only after the eFuse key is provisioned at first save, so a blank
stateless device has none (R20). Half-PIN display costs no attempt-counter
decrement. **Blast radius:** m4a screens 2 and 16.

---

# FROM THE WAVE-3 DESIGN DOCUMENTS

These arrived with the API-level documents after the wave-1/wave-2 merge. Each keeps
its source document's recommendation; none duplicates Q1-Q21.

## Q22. Does a sealed record store the BIP39 passphrase? [WALLET-API.md W1]
### RESOLVED 2026-08-17 by the user - kept visible because the reasoning is load-bearing

**Decision: the BIP39 passphrase is NEVER stored on the device.** User's words: "we
can leave out storing the bip39 passphrase but warn users it will not be stored and
they need a backup." This matches Coldcard, and it is what makes a passphrase wallet
hidden: the passphrase is typed per session and exists only in RAM.

Two consequences are requirements, not options, and both are acceptance criteria on
the milestones that own passphrase wallets (m3 for the field, m4b/m9 for the copy):

1. **Keep `passphrase_check`** (WALLET-API.md W1's recommendation). A BIP39
   passphrase produces a DIFFERENT wallet, so a silent typo on re-entry yields an
   empty wallet with no error and the user concludes their funds vanished. With a
   stored verification fingerprint the device says "this passphrase does not match
   the one this wallet was created with" instead of silently deriving a stranger's
   empty wallet. Requirements on the field: it is a KDF-separated value (derived
   through a distinct HKDF info label, never the seed and never anything from which
   the passphrase or any key can be recovered); it lives INSIDE the sealed record, so
   it is reachable only after a correct PIN unlock and hands an offline attacker no
   passphrase oracle; and a mismatch is a WARNING the user can override, never a hard
   block, because entering a different passphrase to reach a different wallet is a
   legitimate action.
2. **The not-stored warning is a placement requirement, not one line of copy.** It
   must appear at (i) passphrase entry during wallet creation, before the wallet is
   saved; (ii) the post-creation backup screen; and (iii) any restore or unlock flow
   that asks for a passphrase. Required substance, house voice, plain and factual:
   the passphrase is not stored on this device; anyone restoring this wallet needs
   BOTH the seed words AND the passphrase; a seed backup alone will not recover a
   passphrase-protected wallet; the device cannot help recover a forgotten
   passphrase. **Recorded recommendation: a one-time explicit acknowledgment before
   the first passphrase wallet is saved**, so the warning cannot be skipped by muscle
   memory.

UX-SCREENS.md must carry the exact placement and copy for all three points. If it
does not, that is a gap to patch, tracked in INDEX.md.

**Blast radius (why this had to be settled early):** `passphrase_check` is a
RECORD-FORMAT field, so it had to land before m3 freezes the layout; it also touches
m4b's unlock flow, m9's Lock Down Seed (the one feature that deliberately folds a
passphrase into stored entropy), and the Q2 filler-slot sizing.

## Q23. Change gap bounds, and does the device persist an index high-water?
[WALLET-API.md W2] - by m6

An airgapped device has no chain view, so change-index plausibility needs an anchor:
(a) the highest index among this PSBT's own inputs for that descriptor, plus a
forward window; or (b) additionally a per-wallet high-water persisted in the record.
**Recommendation: (a) only, with forward 200 and a ceiling of 100000.** (b) means a
flash write on every signature - wear, latency, and a write the user did not ask for,
against UX commandment 6 - to tighten a case that is already handled with a warning
rather than a refusal. Re-check both constants against real coordinator behavior at
m6. **Blast radius:** m6 policy engine; (b) would also make it a record-format change,
which is the main reason to decide it now rather than later.

## Q24. Expert overrides: what may a Settings toggle change?
[WALLET-API.md W3; UX-SCREENS.md "Expert overrides"] - by m6

**Recommendation: draw the line at warnings versus refusals.**
- No override ever disables a REFUSAL. SIGHASH_ALL/DEFAULT-only, "stateless mode
  refuses multisig change claims", ownership re-derivation and the post-sign gate are
  hard rules. The enum variants exist so the future is expressible, but no Settings
  screen turns them on. A setting that disables the check which stops output
  substitution is a setting an attacker will talk a user into enabling, and the device
  cannot detect that conversation. This narrows Q12's suggested override.
- An expert toggle MAY adjust WARNING thresholds (fee percentage and sat/vB per Q13,
  lookalike-address sensitivity per Q42) with each override individually named and no
  master bypass, which is what UX-SCREENS.md's S-44 specifies. Accepted on that
  boundary: refusing to build any gate at all pushes determined users toward patched
  firmware, which is worse.
**Blast radius:** m6 policy surface and the Settings screen; the warning/refusal line
is also the sentence SECURITY.md invariant 7 has to keep true.

## Q25. Accepted PSBT size cap [WALLET-API.md W4] - by m6

The cap bounds RAM on a device whose PSRAM also holds a 720x720 framebuffer and the
Argon2 arena, while requiring full previous transactions makes real PSBTs large.
**Recommendation: 1 MiB accepted file, re-measured and re-pinned at m6** against the
worst realistic case (a many-input consolidation carrying full prev-txs). The refusal
must say "this transaction is too large for the device: N inputs" and suggest
splitting. **Blast radius:** m6 limits and one refusal screen; interacts with the m1
Argon2 memory parameters.

## Q26. `-final.txn` byte format [WALLET-API.md W5] - by m6

**Recommendation: hex text of the raw transaction (Coldcard's own behavior), with the
exact bytes confirmed against a real Coldcard output file before the writer ships.**
Getting this wrong is a silent interop failure, so it is a corpus item, not a code
comment. **Blast radius:** m6 emission and coordinator interop.

## Q27. esptool or espflash as the normative image producer? [REPRODUCIBLE.md] - m12

espflash has open defects around image production, and esptool is the reference
implementation shipped inside the pinned IDF image.
**Recommendation: compare both outputs once during the reproducibility bring-up; if
they differ at all, esptool becomes the normative release producer** and espflash
stays the developer flashing tool - one fewer independently versioned tool in the
trusted path. Either way, pin the version exactly and record it in BUILDINFO.
**Blast radius:** m12's recipe and tools/flash.ps1's role; no firmware change.

## Q28. Vendor the ESP-IDF managed components? [REPRODUCIBLE.md] - m12

`components_esp32p4.lock` pins seven remote components by version and hash, but the
registry has to still exist in five years.
**Recommendation: do not vendor for 0.2.0** - the hashes already make substitution
detectable, which is the security property - **but publish
`components-<tag>.tar.gz` alongside the release artifacts as an archival mirror,
with its hash in the signed SHA256SUMS.txt.** Cheap insurance against registry rot.
**Blast radius:** m12 artifact set; revisit if a component publisher ever yanks.

## Q29. Publish a Nix flake as a second pinning mechanism? [REPRODUCIBLE.md] - m12

**Recommendation: no for 0.2.0.** A flake pins the full closure more strongly than a
Docker digest and appeals to a subset of verifiers, but ESP-IDF under Nix is a real
maintenance burden. Revisit if a contributor owns it. **Blast radius:** none if no.

## Q30. Release signing-key hygiene [REPRODUCIBLE.md] - procure now, gate at m13

**Recommendation: yes - move the release key to a hardware token (OpenPGP card /
YubiKey) before 0.2.0 ships, generate a revocation certificate, and hold it
offline.** A wallet vendor's release key sitting on a general-purpose disk is the
weakest link in the entire verification chain this plan builds. Lead time on
hardware means deciding this late is deciding it badly.
**Blast radius:** m13's release gate and every future signed tag; the key identity
itself (A1E9 53B2 5C6A 623B 77A1 D522 3AC4 BBCF E51A B37D) does not change.

## Q31. Multi-party attestation [REPRODUCIBLE.md] - m13

Reproducibility only pays off when someone else actually rebuilds.
**Recommendation: recruit at least one independent builder to publish their own
signed SHA256SUMS.txt for the 0.2.0 tag, and add an `attestations/` directory that
collects them.** Coldcard's credibility here comes from third parties publicly
matching builds, not from the vendor's own claim. **Blast radius:** release timing
(a human has to be lined up in advance) and the repo layout.

## Q32. Whose secure-boot key? [REPRODUCIBLE.md] - m13

SECURITY.md invariant 6 says release hardware runs Secure Boot v2 RSA-3072 but does
not say whose key.
- (a) We sign and burn our digest: locks the user out of running their own builds,
  which contradicts a GPL3 verify-it-yourself device.
- (b) Ship unsigned images plus a documented procedure for the USER to generate and
  burn their own secure-boot key: preserves user control at the cost of a one-way
  eFuse step they perform themselves.
- (c) Both, as separate download channels.

**Recommendation: (b) as the default, with (a) only if assembled units are ever
sold.** Reproducibility interaction to state explicitly: a vendor-signed image can
never be byte-reproduced by anyone without the key, so under (a) the UNSIGNED image
must also be published and be the object of the reproducibility claim - exactly how
Jade frames it. **Blast radius:** SECURITY.md invariant 6's text, m13's provisioning
runbook, and what "verified boot" means for a user who builds their own firmware.

## Q33. Seed XOR part-generation default [BACKUP-FEATURES.md OPEN-B2] - by m9

Dice-generated parts give information-theoretic secrecy at 50-99 rolls per part;
Coldcard's deterministic mode is reproducible and interop-testable but downgrades the
guarantee to preimage resistance.
**Recommendation: dice default, deterministic as the clearly labeled second option,
both shipped** - the stronger guarantee is the default and interop is still
reachable. **Blast radius:** m9 scope and one screen's copy.

## Q34. Publish the backup container format as a public spec?
[BACKUP-FEATURES.md OPEN-B4] - by m12

**Recommendation: yes for the format document** - a backup format nobody else can
read is lock-in by omission, and the in-repo reference decoder is a release gate
either way. Whether the decoder also ships as a published crate follows Q8's
licensing answer. Applies only if Q14 ships a backup at all.
**Blast radius:** m12 documentation; no firmware change.

## Q35. PIN pad shuffle domain [UX-SCREENS.md] - by m4a

The randomized keypad permutation derives from the device-bound HMAC ladder with its
own HKDF info string. **Recommendation: accept as specified.** It keeps invariant 3
mechanically checkable, and a display permutation needs unpredictability to an
observer between attempts, not cryptographic unpredictability.
**Blast radius:** one derivation label in m4a; none elsewhere.

## Q36. Deliver-screen escape hatch [UX-SCREENS.md] - by m6

S-38 keeps the user in the delivery flow until one delivery succeeds, then offers
"Discard signed transaction" after two failures.
**Recommendation: accept.** The alternative is a power cycle, which discards it
anyway without informed consent. Reject only if you would rather the device never
offer to discard a signature it already produced. **Blast radius:** one screen.

## Q37. Wrong-PIN policy visibility [UX-SCREENS.md] - decide with Q2

S-44 shows the current wipe threshold; Q5 sets its default.
**Recommendation: show the threshold, and hide the slot count if Q2 chooses the
deniability package** - the two are separable, and three screens (S-01, S-03, S-46)
degrade together if the count goes. Decide Q2 first. **Blast radius:** three screens
and SECURITY invariant 5's wording.

## Q38. Address-list truncation [UX-SCREENS.md] - by m10

S-22 truncates addresses in the navigation list and states "never check an address
from this list"; the stricter alternative is indices and paths only.
**Recommendation: keep the truncated preview.** Users navigate by the characters they
already know, and the verification screen is one tap away and never truncates. Reject
if you want a zero-truncation product with no exception to explain.
**Blast radius:** one screen; UX commandment 1's phrasing.

## Q39. Corpus licensing and publication [CORPUS.md corpus-1] - by m12

**Recommendation: keep the harness GPL-3.0-or-later, license the VECTOR FILES
permissively (CC0 or MIT) with their own SPDX headers, and upstream selected cases to
HWI and Coldcard's psbt_faker.** Test vectors gain their value from adoption - the
same argument Q8 makes for the extracted crates - and a vector carries no
implementation to protect. **Blast radius:** repo licensing headers; a genuine
community contribution at no engineering cost.

## Q40. Does CI get a bitcoind? [CORPUS.md corpus-2] - by m6

**Recommendation: a pinned container, run on pull requests that touch notyas-core or
notyas-wallet plus nightly, not on every push.** The fast lane stays fast. The
operational cost is real, but a signer whose acceptance testing is manual will
eventually ship a transaction the network rejects. **Blast radius:** CI cost and one
maintained image; m6's differential gate depends on it.

## Q41. The HIL test-mode console [CORPUS.md corpus-3] - by m4a

Repeatable hardware testing wants a serial console that can inject touch events and
dump the screen model - which is an attack surface if it ever ships.
**Recommendation: accept the proposed package** - build-feature gated, off by
default, "HIL BUILD" banner on the Verify screen, and a release gate asserting the
symbols are absent from the shipped binary. Every mitigation is mechanical rather
than procedural. Without it, hardware verification stays a person with a camera and a
checklist. **Blast radius:** firmware build features and one m13 release gate.

## Q42. Lookalike-address warning [CORPUS.md corpus-4] - by m6

Compare each external output address against our own derived addresses in the gap
window and warn on a prefix/suffix near-match ("this address resembles your own
address at index 7").
**Recommendation: implement it in m6.** It costs a handful of string comparisons over
addresses the device already derives, and it counters a documented active attack that
showing the full address only partially addresses, because users still compare ends.
Sensitivity is a warning threshold, so Q24's expert gate may tune it; it can never be
turned into a refusal. **Blast radius:** m6 policy engine and the review screen.

## Q43. HIL hardware purchases [CORPUS.md corpus-5] - now

**Recommendation: buy the USB-controlled relay or FET for the power-cut rig now** -
m4a's "power cut taken mid-decrement" gate cannot be faked - and treat the SD-mux as
optional, since the SD steps are few and already batched into the release run.
**Blast radius:** a small purchase with lead time; it gates m4a's exit.

## Q44. esp-seal vs notyas-wallet: where does the sealing layer live?
[ESP-SEAL.md 2.4] - answer at m1, lands at m3

ARCHITECTURE.md section 1's crate table assigns "seal/unseal (PIN KDF ladder + AEAD),
two-slot storage record format" to notyas-wallet. ESP-SEAL.md proposes those move into
`esp-seal` and that notyas-wallet depend on it, keeping only the payload schema:
esp-seal stores opaque bytes and knows nothing about BIP39, descriptors or wallets.

**Recommendation: adopt the split - notyas-wallet delegates sealing to esp-seal.** It
is the whole point of extracting the crate (a sealing layer that cannot be used
without a Bitcoin wallet crate is not a platform contribution) and it shrinks
notyas-wallet's audit surface to the payload schema, the registry semantics, the
session type and policy. Cost: one more crate boundary and a version-pin discipline
between the two. If rejected, everything in ESP-SEAL.md still applies verbatim as a
module layout inside notyas-wallet - the design does not change, only its address.

**Overlap to resolve before anyone writes code, so it is not built twice:**
WALLET-API.md 1.2 and 2.3 define a notyas-wallet `seal` module that currently claims
the key ladder outright ("the ladder of ARCHITECTURE.md 2.2 as three functions -
`device_id`, `stretch`, `seal`/`open` - over two platform traits", owning the Argon2id
parameters, the HKDF info construction, the AAD framing and the ChaCha20-Poly1305
call), and a `store` module that claims the two-slot A/B commit, the counters area
and `seal_seq`/`wipe_epoch` reconciliation. ESP-SEAL.md claims exactly the same
ground. Under the recommendation, WALLET-API.md's `seal` module becomes a thin
re-export/adapter over `esp-seal` and its `store` module keeps only the record schema
and the wallet-level vault API; the ladder constants (`SEAL_LABEL`, `SALT_LABEL`,
`DEVICE_ID_MESSAGE`, `KdfParams`) move to esp-seal and notyas-wallet pins them. Under
the rejection, ESP-SEAL.md's sections 2-5 are read as the implementation of
WALLET-API.md's `seal` + `store`. Either way, **one implementation, and whichever
document loses says so explicitly before m3 opens.**

**Blast radius:** ARCHITECTURE.md section 1's crate table, WALLET-API.md's module
table and its `seal`/`store` sections, m3's crate list and the m3 dependency ledger.
Gated by Q8: under a GPL-3.0-or-later answer there is no separate crate to delegate
to and this question resolves to "module inside notyas-wallet" by default.

## Q45. In-app eFuse provisioning, or factory-only? [ESP-SEAL.md 4.3] - by m3h,
gates m4a, runbook at m13

ARCHITECTURE 2.2 says the device HMAC key is "burned at first save". ESP-SEAL.md
proposes a host-side factory step with `espefuse.py` instead, and **no eFuse-burn
code in release firmware at all**.

**Recommendation: factory provisioning, no burn code in the release image.** Two
load-bearing reasons. First, invariant 3: notyas has no RNG, and a device-unique key
must be unpredictable, so it has to come from outside - the host CSPRNG is a trust
dependency we can name and audit, while the P4 TRNG is already declared distrusted
(esp-hal#5982). Second, firmware that cannot burn eFuses cannot brick a board through
a bug and offers no burn path for a glitch to steer. It also matches how the release
runbook already treats secure boot and flash encryption. Cost: a user who builds their
own firmware from source must run one extra documented command to provision - which is
acceptable for a device whose whole story is "verify your firmware".

Mechanics that follow from a yes: `esp-seal-idf` still ships a `Provisioner` behind a
non-default `provisioning` feature (a general-purpose crate must serve products that
provision in the field), notyas release builds do not enable it, and the build-graph
check asserts that. Power-loss handling is specified in ESP-SEAL.md 4.3.

**Blast radius:** amends ARCHITECTURE 2.2's "burned at first save"; adds one
build-graph assertion at m3h; changes m4a's first-save path (a blank unprovisioned
device refuses to format rather than burning); adds a provisioning step to m13's
release runbook and to the build-from-source instructions. No record-format impact.

## Q46. Where esp-seal lives and when it is published [ESP-SEAL.md 9.1] - m12

In-tree under `crates/esp-seal*` during 0.2.0, or a separate repository from day one.

**Recommendation: develop in-tree through m3 and m4a while the API is still moving,
then extract to its own repository and publish at the 0.2.0 release (m12), with notyas
pinning an exact version.** Extracting early costs a two-repo edit cycle during the
phase with the most churn; extracting late costs nothing, because the licence headers
and the crate boundary are correct from the first commit either way. This is the same
shape as reconciliation R4 (the sealing layer is written first and in-tree,
extraction-ready, and published after hardware proves it).

**Hard sequencing constraint: the Q8 licence answer must land BEFORE the first commit
of this code, regardless of when publication happens**, because relicensing once
external contributions arrive requires every contributor's consent. Also note Q8's
consequence: under a GPL-3.0-or-later answer there is no extraction at all and this
question is moot.

**Blast radius:** repo layout at m12, one version pin in notyas-wallet, and the m12
publication gate. Also depends on measurement M9 (crate-name availability on
crates.io), which is cheap and embarrassing to discover late.

## Q47. Per-board policy for camera support: separate artifact, or one build?
[CAMERA-HW.md 6.2] - answer with Q6 at m1, lands at m11

The camera works on one of the two hardware-verified boards. Board A (Waveshare 4B)
takes a 15-pin Pi-class OV5647 on J1; board B (Elecrow 5inch) has a MIPI-CSI path that
is not the same path - 24-pin FPC, sensor I2C on a separate 1.8 V-shifted bus, reset
driven by the STC8 co-MCU, and a factory target of SC2336 - and nobody on this bench
owns that module. BOARDS.md's governing rule is "the build IS the board", and it has
no precedent for a feature only one board can have.

**Recommendation: camera is a BUILD VARIANT, not a runtime capability**, in three
parts. (1) A cargo feature `camera`, valid only with a board feature whose module
declares camera hardware, enforced by `compile_error!` in `board/mod.rs` exactly like
the existing exactly-one-board check, producing a separately hashed artifact
(`notyas-0.2.0-waveshare-4b-camera.bin` beside `notyas-0.2.0-waveshare-4b.bin`). Two
artifacts for one board is the honest representation of two hardware configurations.
(2) The support statement is per board AND per variant in the BOARDS.md table, with
the UNTESTED-scaffold discipline: hardware-verified or not shipped; the Elecrow row
says "camera: not supported (24-pin SC2336 path, no hardware on bench)". (3) Parity
language follows the artifact - camera-dependent rows are class b **on the camera
variant** and stay class c on the base unit, and no row claims a capability the base
artifact does not have.

**Consequence to accept, and it contradicts an existing m11 exit gate - resolve it
with this answer:** esp-idf-sys metadata cannot be feature-gated, so the esp_video C
sources sit in every build's component tree; the per-board sdkconfig overlay turns
them off and a link-map gate proves nothing camera-related reaches the image. That is
verification of absence, not absence. **MILESTONES m11 currently gates on "the
camera-off build's image SHA256 is unchanged by the feature's presence in the tree",
which this says is not achievable as stated.** Under the recommendation that gate
becomes the link-map assertion plus a pinned hash for each named artifact, and the
release notes say which property is being claimed.

**Blast radius:** the release artifact set and its naming, BOARDS.md's support table,
PARITY.md's class assignment for four rows, m11's exit gate as written, and m12's
reproducible-build matrix (one more artifact to rebuild bit-identically).

## Q48. Does the camera variant accept SeedQR scan-in, and behind what friction?
[CAMERA-HW.md 6.4] - by m11

**Recommendation: yes, gated behind the same friction as manual mnemonic entry, and
never a default-visible action on the scan screen.** Scanning a seed is genuinely
useful - it is what SeedSigner users already have - and the risk is the risk of typing
one in, plus the fact that a camera pointed at a paper backup is a camera pointed at a
paper backup. The 0.1.0 structural rule that no private value ever leaves the device
is about OUTPUT and an input path does not touch it.

**This does not reopen Q17.** Q17 is display-OUT and already records scan-IN as
uncontroversial and shipping with the camera. What is actually being decided here is
the friction and the placement: whether seed scanning is reachable only from the seed
import flow, or appears as an option on the general scan screen. Answer it with Q17 so
the two halves of SeedQR are settled together.

**Blast radius:** the m11 scan-screen action list and the m9 `seedqr` crate's caller;
one UX-SCREENS entry. No format or invariant impact.

## Q49. Camera viewfinder preview on or off by default? [CAMERA-HW.md 6.4] - by m11

**Recommendation: on.** It costs one PPA pass, it is the only camera-activity
indicator this hardware has (there is no hardware activity LED on the CSI path), and a
scan without a viewfinder is unattributable when it fails - the user cannot tell aim
from focus from decode. **Blast radius:** one screen and a small per-frame cost
already measured in CAMERA-HW 3.6.

## Q50. Buy a Waveshare OV5647 reference module? [CAMERA-HW.md 1.7 / 6.4] - now

**Recommendation: yes, about 10 USD, ordered before the m1 camera spike if lead time
allows.** The bench's existing SeedSigner-class module is plausibly a 25 MHz clone
against drivers that assume 24 MHz, which makes every derived rate 4.17% high and
garbled frames an expected outcome of the spike rather than a defeat. A known-good
Espressif-driver-clean module turns every future "is it the camera or the firmware"
question into a two-minute swap, and it is the module the documentation should
recommend to users who do not already own a SeedSigner. Same shape as Q43: a small
purchase whose only real cost is lead time.
**Blast radius:** a small purchase; it de-risks the m1 spike that Q6 depends on.

---

## Disposition notes

- Red team (2026-08-17): everything fixable was fixed directly in the plan texts.
  Only two items needed a human: the duress deniability package (Q2) and the signing
  equivalence scope (Q3). Both are in the blocking set.
- Reconciliation (2026-08-17): four questions changed scope or moved earlier - Q2
  now blocks the record format at m3, Q3 blocks m2's API, Q6 blocks the m1 partition
  freeze, and two new questions were raised by cross-checking the documents against
  each other (Q7 storage geometry, Q17 SeedQR display-out). Wave-1 questions Q1-Q13
  all survive here under new numbers; nothing was dropped.
- Wave-1 to reconciled number map: Q1->Q9, Q2->Q2, Q3->Q5, Q4->Q1, Q5->Q4, Q6->Q15,
  Q7->Q16, Q8->Q14, Q9->Q20, Q10->Q21, Q11->Q12, Q12->Q13, Q13->Q3.
- Wave-3 map: WALLET-API.md W1->Q22 (RESOLVED), W2->Q23, W3->Q24, W4->Q25, W5->Q26;
  REPRODUCIBLE.md's six OPEN items -> Q27-Q32; BACKUP-FEATURES.md OPEN-B1 -> folded
  into Q14 (not duplicated), OPEN-B2 -> Q33, OPEN-B3 -> folded into Q17 as option
  (b), OPEN-B4 -> Q34.
- UX-SCREENS.md and CORPUS.md map: shuffle domain -> Q35, deliver escape hatch ->
  Q36, wrong-PIN visibility -> Q37, address truncation -> Q38, expert overrides ->
  folded into Q24 (with the warning-versus-refusal line drawn there); corpus-1 -> Q39,
  corpus-2 -> Q40, corpus-3 -> Q41, corpus-4 -> Q42, corpus-5 -> Q43.
- ESP-SEAL.md map (swept 2026-08-17, after the reconciliation): 2.4 crate boundary ->
  Q44; 4.3 in-app provisioning -> Q45; 9.1 licence -> **folded into Q8** (not
  duplicated: Q8 already owned extracted-crate licensing, and ESP-SEAL's argument and
  its "if GPL3, do not extract at all" consequence are merged into it); 9.1 publish
  location and timing -> Q46. ESP-SEAL.md's three escalations were applied to the plan
  texts rather than raised as questions, because they are correctness fixes: the
  attempt-counter honesty fix (ARCHITECTURE 2.5, SECURITY.md tier 3), measurement M6
  as an m1 exit gate (MILESTONES m1), and the R11 sequencing relief recorded in Q2's
  blast radius above.
- CAMERA-HW.md map (swept 2026-08-17, same pass; the document landed as commit
  f5aa401 while the ESP-SEAL sweep was in progress): 6.2 per-board camera policy ->
  Q47; 6.2 "does 0.2.0 ship camera at all" -> **folded into Q6** (not duplicated: Q6
  already owned the ship-or-slip decision, and CAMERA-HW's refinement - land it, but
  sequence it last and make it droppable, with m11 split into m-camera-0..5 - is
  merged into Q6's recommendation); 6.4 SeedQR scan-in friction -> Q48, cross-linked
  to Q17 and explicitly not reopening it; 6.4 default preview -> Q49; 1.7 and 6.4 both
  ask to buy a reference OV5647 module, which is one item -> Q50. CAMERA-HW.md's
  DECISION items (the shared-I2C-bus refactor, the 25 MHz clock-mismatch triage rule,
  the abort criteria, USB-UVC rejection) are its own and are not re-litigated. One
  conflict is recorded inside Q47 rather than settled silently: m11's "the camera-off
  build's image SHA256 is unchanged by the feature's presence in the tree" is not
  achievable, because esp-idf-sys metadata cannot be feature-gated.
- Sweep status (2026-08-17): **complete.** Every open item present in docs/plan-0.2.0/
  is folded in, including the ones that do not use the literal `OPEN:` prefix
  (BACKUP-FEATURES.md uses `OPEN-Bn`, CORPUS.md uses `OPEN: (corpus-n)`). No document
  in this directory is now owed a sweep. INDEX.md tracks the status.
- Where a wave-3 document recommends the opposite of this reconciliation, both
  positions are stated in the question rather than one being silently dropped:
  Q14 (BACKUP-FEATURES wants seed-bearing backup in 0.2.0) and Q17 (BACKUP-FEATURES
  wants SeedQR display behind a secret-QR screen class).
