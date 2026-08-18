# notyas 0.2.0 planning set - index and status

**Reconciled 2026-08-17.** These documents were written in three waves and then
reconciled into one execution-ready plan. A later reviewer should treat them as
reconciled and NOT re-derive them: the contradictions between waves have been found,
decided, and recorded, and re-opening them without new information will just churn.

Two files carry the reconciliation:

- **MILESTONES.md** - the single dependency-ordered roadmap. Where any other file in
  this directory disagrees with it on scope, ordering, or dependency, MILESTONES.md
  wins as of the reconciliation date. Its section 8 (R1-R20) is the register of every
  contradiction found and how it was resolved, with reasoning.
- **OPEN-QUESTIONS.md** - the single decision list. Wave-1's thirteen questions,
  wave-2's three, and the red team's two escalations are merged, deduplicated and
  renumbered, and the wave-3 documents' own open items are folded in behind them
  (currently through Q46). Q1-Q8 block milestone 1, with one revision: **Q2 is
  behaviour-only since the ESP-SEAL.md sweep** and its real deadline is m4b, though it
  keeps its number and its place in the blocking set.

Everything else is a normative input that MILESTONES.md and OPEN-QUESTIONS.md read.

---

## Reading order

1. **OPEN-QUESTIONS.md** - eight blocking decisions. Nothing starts until they are
   answered; this is the file the user reads to unblock execution.
2. **MILESTONES.md** - what gets built, in what order, on which board, and what
   physical demonstration closes each milestone. Section 8 explains every place the
   waves disagreed.
3. **ARCHITECTURE.md** - the technical design: crate layout, the key ladder, the
   storage record format, the signing pipeline and its 10-check validation table.
4. **SECURITY.md** (this directory) - the proposed 0.2.0 security model, written as
   an honest amendment to the 0.1.0 one. Read `docs/SECURITY.md` first if you have
   not: it is still the normative file until m13 lands this text over it.
5. **UX.md** - the ten commandments, the top-level flow, and all 16 screens.
6. **WALLET-API.md** - the notyas-wallet crate as concrete Rust: types, traits,
   errors, the validation pipeline, test strategy. **Authoritative for the wallet
   crate.** Read after ARCHITECTURE.md; it makes that design buildable.
7. **ESP-SEAL.md** - the sealed-storage layer as a crate design: the platform traits
   WALLET-API.md defines (Storage, DeviceBinding, KdfScratch) over esp_partition and
   the P4 HMAC peripheral, the byte-exact on-flash record and ledger format, the
   mount/unlock/seal/wipe state machine, and the attack analysis behind the honest
   attempt-counter claim. **Authoritative for the sealed-storage layer and its
   on-flash format, which gate all storage work.** Read immediately after
   WALLET-API.md: that document says what notyas-wallet exposes, this one says what
   the layer beneath it actually writes to flash.
8. **UX-SCREENS.md** - the per-screen build spec every UI milestone implements
   (UX.md stays the design rationale behind it).
9. **CORPUS.md** - the adversarial PSBT corpus: cases, expected verdicts, expected
   rendered text. **Defines m6's and m7's exit criteria.**
10. **REPRODUCIBLE.md** - the reproducible-build recipe and verification procedure.
    **Gates the release milestones (m12, m13).**
11. **CAMERA-HW.md** - camera hardware and software integration spec: the J1 CSI
    connector and the replug experiment that answers m1's spike, the esp_video /
    esp_cam_sensor / PPA / rqrr pipeline, the ingress validator, the per-board
    support split, and the staged m-camera-0..5 ordering. **Authoritative for camera
    bring-up.** Read after CAMERA.md (14), which is the ranking it takes as settled.
12. **BACKUP-FEATURES.md** - backup, restore and device-lifecycle feature detail
    (m9, and the scope of OPEN-QUESTIONS Q14).
13. **PARITY.md** - the Coldcard Mk4/Q feature matrix. Reference, not a plan; read it
    when you need to know why a feature is or is not in a milestone.
14. **CAMERA.md** - camera input paths, ranked. Feeds OPEN-QUESTIONS Q6.
15. **PLATFORM.md** - the ESP32-P4 Rust ecosystem survey and the contribution
    shortlist. Feeds milestones m3h, m9 and m12.

Authority rule between this set and MILESTONES.md: where a companion document and
MILESTONES.md disagree on WHAT is built, the companion wins; where they disagree on
WHEN, or on what closes a milestone, MILESTONES.md wins. MILESTONES section 1.1 maps
each companion to the milestones it governs.

For the 0.1.0 baseline these all amend: `docs/SECURITY.md` (invariants),
`docs/ARCHITECTURE.md`, `docs/BOARDS.md` (boards, flash, partition policy, the
per-board airgap statement), `docs/HARDWARE.md`, `docs/research/`.

---

## File status

| File | Wave | Role | Status |
|---|---|---|---|
| INDEX.md | 3 | this file | current |
| MILESTONES.md | 1 + 2, reconciled | **authoritative roadmap** | RECONCILED 2026-08-17, supersedes the wave-1 draft |
| OPEN-QUESTIONS.md | 1 + 2, reconciled | **authoritative decision list** | RECONCILED 2026-08-17, renumbered - see the map below |
| ARCHITECTURE.md | 1, red-teamed | technical design | current, with the exceptions in "Errata" below |
| SECURITY.md | 1, red-teamed | proposed 0.2.0 security model | current, lands as docs/SECURITY.md at m13 |
| UX.md | 1, red-teamed | screens and flows | current, with the camera-wording exception below |
| PARITY.md | 2 | Coldcard feature matrix | reference; count erratum below; all rows assigned in MILESTONES section 7 |
| CAMERA.md | 2 | camera paths, ranked | proposal, pending OPEN-QUESTIONS Q6 |
| PLATFORM.md | 2 | contribution shortlist | current; its licensing question is now OPEN-QUESTIONS Q8 |
| WALLET-API.md | 3 | notyas-wallet API design (authoritative for the crate) | PRESENT at reconciliation (commit 7a67983); its OPEN: W1-W5 folded in as Q22-Q26 |
| REPRODUCIBLE.md | 3 | reproducible-build recipe, release gate | PRESENT; its six OPEN items folded in as Q27-Q32 |
| BACKUP-FEATURES.md | 3 | backup/restore/seed-lifecycle detail | PRESENT; OPEN-B1 folded into Q14, B2 -> Q33, B3 folded into Q17, B4 -> Q34 |
| UX-SCREENS.md | 3 | per-screen build spec | PRESENT; its five open items -> Q35-Q38 and Q24; one gap to patch, below |
| CORPUS.md | 3 | adversarial PSBT corpus, m6/m7 exit criteria | PRESENT; corpus-1..5 -> Q39-Q43 |
| ESP-SEAL.md | 3 | firmware platform traits, sealed-storage layer; **authoritative for the sealed-storage layer and the on-flash format** | PRESENT (commit ed031c1); **SWEPT 2026-08-17** - four OPEN items: 2.4 -> Q44, 4.3 -> Q45, 9.1 licence folded into Q8, 9.1 publish timing -> Q46; three escalations applied to the plan texts, see below |
| CAMERA-HW.md | 3 | camera hardware and software integration spec behind CAMERA.md's decision | PRESENT (commit f5aa401); **SWEPT 2026-08-17** - 6.2 per-board policy -> Q47, 6.2 ship-or-slip folded into Q6, 6.4 SeedQR scan-in -> Q48, 6.4 default preview -> Q49, 1.7/6.4 reference-module purchase (one item, stated twice) -> Q50 |

**Sweep status (2026-08-17): COMPLETE. No document in this directory is owed a
sweep.** Every open item present here is in OPEN-QUESTIONS.md, including those that do
not use the literal `OPEN:` prefix (BACKUP-FEATURES.md uses `OPEN-Bn`, CORPUS.md uses
`OPEN: (corpus-n)`). Swept at reconciliation: WALLET-API.md, REPRODUCIBLE.md,
BACKUP-FEATURES.md, UX-SCREENS.md, CORPUS.md. Swept afterwards, in the final
integration pass: ESP-SEAL.md and CAMERA-HW.md, both of which landed after the
reconciliation. The list now runs to **Q50**. If a further design document lands,
continue the numbering from there, attribute the source document, keep its
recommendation, and give each item a blast radius and an owning milestone; apply
correctness fixes to the plan texts directly rather than raising them as questions.

**ESP-SEAL.md's three escalations were correctness fixes, not questions, and are
applied in place (2026-08-17):**

1. **Attempt-counter honesty.** ARCHITECTURE.md 2.5, this directory's SECURITY.md
   tier 3, PLATFORM.md section 1 and MILESTONES R8 all credited XTS-AES flash
   encryption with raising the cost of a counter rollback. It does not: the `counters`
   partition is PLAINTEXT, because bit-clear counters are incompatible with XTS write
   granularity, so there is no key in the way. All four now carry the honest claim -
   **the attempt counter converts unlimited offline guesses into N guesses per
   full-flash restore cycle** - together with the split that makes it true: a
   ledger-only rollback IS detected at mount (a record outranking the ledger
   high-water, or a blank ledger beside a non-blank records region, must refuse),
   while a consistent full-flash snapshot and restore is undetectable and needs no
   key.
2. **Measurement M6 is an m1 exit gate.** The ledger programs up to 32 cells into one
   256-byte page, and SPI NOR parts specify a maximum partial-page-program count. If
   the real limit is lower, the on-flash format is invalid. MILESTONES m1 now requires
   the datasheets for the parts actually fitted (JEDEC ID read on the bench first -
   board B's schematic says Winbond W25Q128JVSIQ while the probed unit is a GigaDevice
   GD25Q128) plus a soak test, before the format is frozen, with format re-design as
   the stated consequence.
3. **Q2 no longer blocks m3.** Reconciliation finding R11 said the duress package was
   a record-format change. ESP-SEAL.md 3.6 shows filler slots are genuine AEAD records
   under a device-derived key, so the format is byte-identical whether the mode is on
   or off. R11 is revised in MILESTONES section 8 with the original text kept and the
   correction reasoned; Q2's blast radius in OPEN-QUESTIONS.md now says behaviour-only,
   deadline m4b.

**Gap found in UX-SCREENS.md, to patch (not a re-decision):** OPEN-QUESTIONS Q22 is
RESOLVED - the BIP39 passphrase is never stored - and its warning has three required
placements. UX-SCREENS.md as landed covers the "a different passphrase is a different
wallet" framing and echoes the fingerprint on S-15/S-18/S-19, which is the right
instinct, but it does not carry the not-stored substance anywhere: that the passphrase
is not stored on this device, that restoring needs BOTH the seed words and the
passphrase, that a seed backup alone will not recover the wallet, and that the device
cannot help recover a forgotten passphrase. Missing specifically: (i) that text at the
S-15 passphrase entry before the wallet is saved, (ii) the same at the post-creation
backup screen, (iii) the same in every restore and unlock flow that asks for a
passphrase, (iv) the one-time explicit acknowledgment before the first passphrase
wallet is saved, and (v) the overridable `passphrase_check` mismatch warning at
unlock. Patch UX-SCREENS.md with the copy; MILESTONES m4b already carries all five as
acceptance criteria.

**Recorded disagreements between documents, left for the user rather than silently
settled:** Q14 (BACKUP-FEATURES.md recommends shipping seed-bearing encrypted backup
in 0.2.0; this reconciliation recommends only the seedless profile) and Q17
(BACKUP-FEATURES.md recommends SeedQR display behind a gated secret-QR screen class;
this reconciliation recommends declining display-out). Both questions state both
positions. Two more came out of the final integration sweep, and both are recorded
inside the question that owns them rather than settled here:

- **ESP-SEAL.md 2.4 versus WALLET-API.md 1.2/2.3** - both claim the key ladder and the
  record engine. Q44 states the overlap in detail (which constants move, what
  WALLET-API's `seal` and `store` modules keep under each answer) so the ladder is not
  implemented twice. Whichever document loses says so explicitly before m3 opens.
- **CAMERA-HW.md 6.2 versus MILESTONES m11's exit gate** - m11 gates on the camera-off
  image SHA256 being unchanged by the feature's presence in the tree; CAMERA-HW shows
  that is not achievable, because esp-idf-sys metadata cannot be feature-gated and the
  esp_video C sources are therefore in every build's component tree. Q47 carries the
  conflict and the proposed replacement gate (a link-map assertion plus a pinned hash
  per named artifact).

Wave 1 (ARCHITECTURE, SECURITY, UX, MILESTONES, OPEN-QUESTIONS) was written, then
adversarially reviewed. The red team found real defects and they are fixed in place:
post-wipe nonce reuse (fixed by putting a one-way `wipe_epoch` in the HKDF info); the
attempt counter being unable to live in an XTS-encrypted partition (fixed by a
separate plaintext `counters` partition); stale old-PIN ciphertext surviving a PIN
change in the inactive A/B slot (fixed by erase-after-commit); an HMAC claim cited
from the ESP32-S3 page instead of the P4 one (re-cited); and three dependencies whose
DEFAULT features would have smuggled an RNG into the graph (pinned
`default-features=false`). It also downgraded two false claims: "indistinguishable
duress" and "byte-identical signatures to Bitcoin Core". Those two became decisions
and are now OPEN-QUESTIONS Q2 and Q3.

Wave 2 added PARITY.md, CAMERA.md and PLATFORM.md. Wave 3 is this reconciliation plus
the API-level documents.

If a file listed above is missing from the directory, it has not landed yet. The
reconciliation itself does not depend on its contents, but the milestone it governs
cannot close without it (MILESTONES section 1.1), and its `OPEN:` items still owe a
sweep into OPEN-QUESTIONS.md.

---

## Errata: where a document is superseded

Each entry names the reconciliation decision in MILESTONES.md section 8 that governs.
The rest of each document stands.

**ARCHITECTURE.md**

- 2.7 partition offsets (`wallets` at 0x410000 behind a 4 MB app) - superseded by
  **R2**: factory grows to 8M and the data partitions move to fixed high offsets
  (0xE00000 / 0xE40000) so app growth can never relocate a user's sealed records.
  Everything else in 2.7 stands.
- 5.2 / 5.4 "No camera: QR is out-only" - superseded by **R3**: the camera is an
  optional, board-A-only, compile-time-off milestone (m11) preceded by a spike inside
  m1. The wording becomes "no camera on this board/build".
- 5.3's pointer to "MILESTONES m5" for the regression corpus - superseded by **R13**:
  the corpus gate is m6, multisig cases m7.
- Section 1's dependency table stands and is restated as the authoritative dependency
  ledger in MILESTONES section 6, extended with the wave-2 crates (`bbqr`, `rqrr`).
- Section 1's CRATE table assigns "seal/unseal (PIN KDF ladder + AEAD), two-slot
  storage record format" to notyas-wallet - contested by ESP-SEAL.md 2.4, which moves
  it into `esp-seal`. Now **OPEN-QUESTIONS Q44**, which also flags the overlap with
  WALLET-API.md's `seal` and `store` modules so the ladder is not implemented twice.
- 2.2's "the HMAC key is burned at first save" - contested by ESP-SEAL.md 4.3, which
  proposes host-side factory provisioning with `espefuse.py` and NO eFuse-burn code in
  release firmware. Now **OPEN-QUESTIONS Q45**.
- 2.4's `kdf_salt` including `slot_id` - refined by ESP-SEAL.md 4.1 (a DECISION, not a
  question): the salt drops `slot_id` and slot separation moves entirely into the HKDF
  info, so an unlock costs one Argon2id run rather than one per slot.
- 2.5's honest-limits bullet - **rewritten in place 2026-08-17**, not superseded. It
  credited flash encryption with raising the cost of a counter rollback; the `counters`
  partition is plaintext, so it does not. See the escalation note above.
- 2.6's slot map is refined by ESP-SEAL.md 3.2: 8 payload plus 8 registry pairs
  confirmed, plus 4 canary pairs and a superblock pair, with registry sides two sectors.

**SECURITY.md (this directory)**

- Tier 3's attempt-counter paragraph was **rewritten in place 2026-08-17** for the
  same honesty fix as ARCHITECTURE 2.5 (escalation 1 above). Nothing else is
  superseded. Two additions are required at m13, both recorded as
  decisions: invariant 2's 0.1.0 corollary ("there is no private-key export path at
  all") must be restated in 0.2.0 terms rather than dropped (**R19**), and invariant
  1's per-board "the SDIO host is never configured on the C6 pins" survives the SD
  subsystem verbatim, re-verified with pin numbers at m5 (**R16**).

**UX.md**

- Screen 9's "No camera exists, stated in the UI rather than hidden" - superseded by
  **R3** (same wording change as ARCHITECTURE).
- Screen 3's capacity line and screen 1's "storage state (blank / N wallets)" are
  contingent on OPEN-QUESTIONS Q2: option (a) degrades both to "present / blank".

**PARITY.md**

- Summary counts - **R7**: "61 feature rows" counts sections 1-6 only; the matrix has
  72 rows. A recount gives a=31, b=21, c=14, d=6 by primary class, against the
  summary's 30/17/12/6. Assignment in MILESTONES section 7 is by row title, so
  nothing operational changes.
- Section 2 preamble ("PIN-as-key-material ... offline-hard but not attempt-limited")
  - **R8**: the design does attempt-limit, because the ladder passes through the
  eFuse-keyed HMAC peripheral and wipe-on-N destroys the record. The honest limit
  (advisory against a fault-injection lab) is unchanged.
- "master-seed-keyed AES" as the pattern for class-b storage rows - **R9**:
  everything seals under the device PIN ladder; there is no master-seed key path.
- Encrypted backups and Clone device marked class a, and Key Teleport's stated
  equivalent - **R10**: all three write key material to SD, which SECURITY invariant
  2b forbids and OPEN-QUESTIONS Q14 defers. notyas has no Key Teleport equivalent in
  0.2.0 and must not claim one.

**CAMERA.md**

- Section 6's recommendation of the `ur` crate - superseded by **R5**: one UR
  implementation, `foundation-ur` + `foundation-urtypes`, both with default features
  off (the `ur` crate is std by default).
- SeedQR is scan-in only; display-out is not shipped (**R19**, OPEN-QUESTIONS Q17).

**PLATFORM.md**

- Item 1's framing of `esp-seal` as the crate the storage layer is built on -
  refined by **R4**: the sealing LAYER is written first and in-tree (m3,
  extraction-ready, no ESP-IDF types at its boundary); the crate is PUBLISHED after
  hardware proves it (m12). The real prerequisite is item 2, the HMAC wrapper (m3h).
- Section 6's licensing question is now OPEN-QUESTIONS Q8, with the added constraint
  that `foundation-urtypes` is GPL-3.0-or-later, so UR/transport code can never live
  in a permissive crate (**R6**). Section 6's floated split - "permissive for the
  interop formats, GPL3 for esp-seal" - is argued backwards by ESP-SEAL.md 9.1 and
  that argument is merged into Q8 rather than raised separately: esp-seal has the
  largest audience outside Bitcoin of anything on the shortlist. Q8 also now carries
  ESP-SEAL's consequence - under a GPL3 answer the crate is not extracted at all.
- Item 1's "attempt-counter rollback resistance ultimately rests on secure boot +
  XTS-AES flash encryption + the eFuse-bound HMAC key" - **rewritten in place
  2026-08-17**. The counters partition is plaintext, so flash encryption contributes
  nothing to rollback resistance (escalation 1 above).

**Wave-1 milestone draft**

- Old m9 (hardening closeout) is now m13. Ids m1, m2, m3, m4a, m4b, m5, m6, m7 and m8
  keep their meaning exactly, so existing references stay valid. New: m3h (HMAC
  wrapper), m9 and m10 (parity packs), m11 (camera), m12 (reproducible builds and
  crate publication).

---

## Question renumbering map

Wave-1 and wave-3 documents cite the old numbers Q1-Q13. Translate with this table;
OPEN-QUESTIONS.md carries the same map.

| Old | New | Question |
|---|---|---|
| Q1 | Q9 | Production silicon revision / Key Manager |
| Q2 | **Q2** | Duress deniability package |
| Q3 | Q5 | Wipe-after-N default |
| Q4 | **Q1** | Randomness policy ratification |
| Q5 | Q4 | PIN format and floor |
| Q6 | Q15 | BSMS tier |
| Q7 | Q16 | Taproot multisig timing |
| Q8 | Q14 | Encrypted SD backup / clone |
| Q9 | Q20 | Blind-oracle unlock mode |
| Q10 | Q21 | Anti-phishing words and lock-screen word |
| Q11 | Q12 | Stateless signing |
| Q12 | Q13 | Fee thresholds |
| Q13 | **Q3** | ECDSA low-R grinding / equivalence scope |
| - | Q6 | Camera in 0.2.0 (wave 2) |
| - | Q7 | Storage geometry freeze (reconciliation) |
| - | Q8 | Extracted-crate licensing (wave 2) |
| - | Q10, Q11 | Class-d reject list, class-c equivalent tier (wave 2) |
| - | Q17 | SeedQR display-out (reconciliation) |
| - | Q18, Q19 | BBQr output, login extras |
| W1 | Q22 | Passphrase in the sealed record (WALLET-API.md) - **RESOLVED: never stored** |
| W2 | Q23 | Change gap bounds (WALLET-API.md) |
| W3 | Q24 | Expert overrides (WALLET-API.md) |
| W4 | Q25 | PSBT size cap (WALLET-API.md) |
| W5 | Q26 | `-final.txn` byte format (WALLET-API.md) |
| - | Q27-Q32 | esptool vs espflash, vendoring components, Nix flake, signing-key hygiene, multi-party attestation, secure-boot key ownership (REPRODUCIBLE.md) |
| OPEN-B1 | folded into Q14 | Encrypted backup, split into seedless and seed-bearing (BACKUP-FEATURES.md) |
| OPEN-B2 | Q33 | Seed XOR part-generation default (BACKUP-FEATURES.md) |
| OPEN-B3 | folded into Q17 as option (b) | SeedQR display behind a secret-QR screen class (BACKUP-FEATURES.md). **Label slip inside that document, found in the final sweep:** its section 6.1 calls this same item `OPEN-B5` and rows B22/B23 and sections 5 and 8 cite `OPEN-B5`, but section 9 defines only B1-B4 and defines this one as B3. There is no fifth open item - `OPEN-B5` is an alias for `OPEN-B3` and the substance is fully recorded in Q17. Fix the label the next time that document is edited. |
| OPEN-B4 | Q34 | Publish the backup container format (BACKUP-FEATURES.md) |
| - | Q35-Q38 | PIN pad shuffle domain, deliver escape hatch, wrong-PIN visibility, address truncation (UX-SCREENS.md) |
| - | folded into Q24 | Expert overrides - the warning-versus-refusal line (UX-SCREENS.md) |
| corpus-1..5 | Q39-Q43 | Corpus licensing, bitcoind in CI, HIL console, lookalike warning, HIL hardware (CORPUS.md) |
| ESP-SEAL 2.4 | Q44 | esp-seal vs notyas-wallet crate boundary; also flags the WALLET-API `seal`/`store` overlap |
| ESP-SEAL 4.3 | Q45 | In-app eFuse provisioning versus host-side factory provisioning |
| ESP-SEAL 9.1 (licence) | folded into Q8 | esp-seal's licence, with the "if GPL3, do not extract at all" consequence |
| ESP-SEAL 9.1 (publish) | Q46 | Where esp-seal lives and when it is published |
| CAMERA-HW 6.2 (policy) | Q47 | Per-board camera policy: separate build variant and artifact |
| CAMERA-HW 6.2 (ship) | folded into Q6 | Ship camera in 0.2.0 or slip; refines Q6 to "land it, sequence last, droppable" |
| CAMERA-HW 6.4 (SeedQR) | Q48 | SeedQR scan-in friction and placement; does NOT reopen Q17 |
| CAMERA-HW 6.4 (preview) | Q49 | Viewfinder preview on by default |
| CAMERA-HW 1.7 / 6.4 | Q50 | Buy a known-good OV5647 reference module |

WALLET-API.md's internal decisions D1-D11 are its own and are not re-opened here.

---

## Ground rules these documents share

- **0.2.0 is the public release.** 0.1.0 ships now as a source-only preview.
  Reproducible builds and GPG-signed per-board artifacts are 0.2.0 deliverables.
- **Full Coldcard parity is the product bar.** Every PARITY.md row is implemented,
  shipped as a documented equivalent, or deferred with a stated reason.
- **Mechanically enforced or not claimed.** Every security sentence must be backed by
  a compile-time check, a test, or hardware. Marketing derives from SECURITY.md, never
  the reverse.
- **Vetted primitives, our policy.** Rust wherever it fits, including notyas-wallet as
  a real wallet library - but no hand-rolled crypto, ever.
- **The smallest board is the binding constraint.** Anything that must fit, fits in
  16 MB of flash and runs on both verified boards.
- **GPL-3.0-or-later** for the firmware and the notyas crates; the extracted platform
  crates are OPEN-QUESTIONS Q8.
