# notyas 0.2.0 - Open questions (one deduplicated decision list)

Status: RECONCILED 2026-08-17. Merges wave-1's thirteen questions, wave-2's
(camera path, crate licensing, parity class-c/d tiering) and the red team's two
escalations into one numbered list. Wave-1 numbers no longer apply; the old number
is noted on each item so earlier references stay traceable.

**Q1-Q8 block milestone 1.** Nothing downstream can start until they are answered,
because each one pins either a document that must precede the code or a byte-level
format that cannot change once a user has sealed a wallet. Q9-Q34 can be answered at
their milestone. **Q22 is already RESOLVED by the user** (the BIP39 passphrase is
never stored) and is kept in place with its resolution, because its two consequences
are implementation requirements.

Wave-3 design documents (WALLET-API.md, and ESP-SEAL.md / CORPUS.md / REPRODUCIBLE.md
/ UX-SCREENS.md / CAMERA-HW.md / BACKUP-FEATURES.md as they land) raise their own
`OPEN:` items. Those are folded in here as Q22 and up, attributed to the source
document. Decisions those documents took internally are theirs to keep and are not
re-litigated here.

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

**Blast radius:** BLOCKS m3, not just m13 (reconciliation R11). Filler slots are a
record-format property; adding them after m4a ships changes the on-flash format under
existing users. Also sets SECURITY.md invariant 5's wording and the m4b capacity line
("3 of 8 slots" only survives under (b)/(c)).

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

**Blast radius:** BLOCKS m1 because `esp_video` + `esp_cam_sensor` change the
app-size budget the partition freeze depends on (Q7), and because the m6 sign-flow
UX should not be frozen as "no camera exists" if one is coming. Independent of the
answer, m6's PSBT load path takes a source abstraction so m11 is additive.

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

## Q8. Licensing for the extracted crates [wave 2, PLATFORM.md section 6]

**Decision:** the firmware is GPL-3.0-or-later. The crates we extract
(`esp-idf-hmac`, `esp-seal`, `seedqr`, maybe `bsms`) can be:

- (a) GPL-3.0-or-later: preserves reciprocity, but the ecosystems these crates serve
  (esp-hal, esp-idf-*, `ur`, `bbqr`, `gt911`) are MIT/Apache and generally will not
  take a GPL dependency - which caps the adoption that is the whole point of
  extracting them.
- (b) Dual MIT OR Apache-2.0: the Rust norm, maximum reuse, GPL3 firmware consumes
  them freely; forfeits copyleft on the crates.
- (c) Per-crate split.

**Recommendation: (c) with a simple rule - permissive (MIT OR Apache-2.0) for
everything meant for the wider ecosystem (`esp-idf-hmac`, `esp-seal`, `seedqr`,
`bsms`), GPL-3.0-or-later for notyas-core, notyas-wallet, notyas-ui and the
firmware.** The reciprocity that matters is on the wallet itself, not on a KDF
wrapper. Two hard constraints, either way: Trezor's and Jade's code are copyleft, so
only their published designs may inform a clean-room implementation; and
`foundation-urtypes` is GPL-3.0-or-later, so all UR/transport code must stay inside
notyas-wallet and never inside a permissive crate (R6).

**Blast radius:** blocks the first publication (m3h, which starts alongside m2), and
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

## Q17. SeedQR display-out [reconciliation R19; BACKUP-FEATURES.md OPEN-B3] - by m9

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

## Q24. Expert overrides for the sighash whitelist and stateless multisig?
[WALLET-API.md W3] - by m6

**Recommendation: neither ships in 0.2.0.** SIGHASH_ALL/DEFAULT-only and
"stateless mode refuses multisig change claims" are hard rules; the enum variants
exist so the future is expressible, but no Settings screen turns them on. A setting
that disables the check which stops output substitution is a setting an attacker will
talk a user into enabling, and the device cannot detect that conversation. Note this
narrows Q12's suggestion of an expert override for stateless multisig.
**Blast radius:** m6 policy surface and the Settings screen; reversible later.

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
- Sweep status (2026-08-17): every open item present in docs/plan-0.2.0/ at
  reconciliation time is folded in, including the ones that do not use the literal
  `OPEN:` prefix (BACKUP-FEATURES.md uses `OPEN-Bn`). Still absent and therefore
  still owed a sweep: ESP-SEAL.md, CORPUS.md, UX-SCREENS.md, CAMERA-HW.md. INDEX.md
  tracks which are outstanding.
- Where a wave-3 document recommends the opposite of this reconciliation, both
  positions are stated in the question rather than one being silently dropped:
  Q14 (BACKUP-FEATURES wants seed-bearing backup in 0.2.0) and Q17 (BACKUP-FEATURES
  wants SeedQR display behind a secret-QR screen class).
