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
  renumbered. Q1-Q8 block milestone 1.

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
7. **ESP-SEAL.md** - the firmware side of the platform traits WALLET-API.md defines
   (Storage, DeviceBinding, KdfScratch) over esp_partition and the P4 HMAC
   peripheral. **Authoritative for the sealed-storage layer, which gates all storage
   work.**
8. **UX-SCREENS.md** - the per-screen build spec every UI milestone implements
   (UX.md stays the design rationale behind it).
9. **CORPUS.md** - the adversarial PSBT corpus: cases, expected verdicts, expected
   rendered text. **Defines m6's and m7's exit criteria.**
10. **REPRODUCIBLE.md** - the reproducible-build recipe and verification procedure.
    **Gates the release milestones (m12, m13).**
11. **CAMERA-HW.md** - camera hardware bring-up detail behind CAMERA.md's decision.
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
| ESP-SEAL.md | 3 | firmware platform traits, sealed-storage layer | PENDING - open-item sweep still owed |
| UX-SCREENS.md | 3 | per-screen build spec | PENDING - open-item sweep still owed, plus the Q22 check below |
| CORPUS.md | 3 | adversarial PSBT corpus, m6/m7 exit criteria | PENDING - open-item sweep still owed |
| CAMERA-HW.md | 3 | camera bring-up detail | PENDING - open-item sweep still owed |

**Outstanding sweep (as of 2026-08-17):** every open item present in this directory at
reconciliation time is in OPEN-QUESTIONS.md, including those that do not use the
literal `OPEN:` prefix (BACKUP-FEATURES.md uses `OPEN-Bn`). The four PENDING documents
above had not landed; when each arrives, its open items must be folded into
OPEN-QUESTIONS.md (continue numbering from Q34, attribute the source document, keep
its recommendation) and its row updated to PRESENT. A document listed here as PENDING
that is now on disk means the sweep is owed.

**Gap to patch when UX-SCREENS.md lands:** OPEN-QUESTIONS Q22 is RESOLVED (the BIP39
passphrase is never stored), and its warning must appear at three specific places -
passphrase entry during creation before the wallet is saved, the post-creation backup
screen, and every restore or unlock flow that asks for a passphrase - plus a one-time
acknowledgment before the first passphrase wallet is saved. UX-SCREENS.md had not
landed at reconciliation time, so nobody has verified it carries all three placements
and the exact copy. Verify on arrival; if any placement is missing, that is a patch to
UX-SCREENS.md, not a re-decision.

**Recorded disagreements between documents, left for the user rather than silently
settled:** Q14 (BACKUP-FEATURES.md recommends shipping seed-bearing encrypted backup
in 0.2.0; this reconciliation recommends only the seedless profile) and Q17
(BACKUP-FEATURES.md recommends SeedQR display behind a gated secret-QR screen class;
this reconciliation recommends declining display-out). Both questions state both
positions.

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

**SECURITY.md (this directory)**

- Nothing is superseded. Two additions are required at m13, both recorded as
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
  in a permissive crate (**R6**).

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
| OPEN-B3 | folded into Q17 as option (b) | SeedQR display behind a secret-QR screen class (BACKUP-FEATURES.md) |
| OPEN-B4 | Q34 | Publish the backup container format (BACKUP-FEATURES.md) |

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
