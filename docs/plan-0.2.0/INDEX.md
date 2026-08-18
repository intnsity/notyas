# notyas 0.2.0 planning set - index and status

**OWNER-ANSWERED AND RE-SCOPED 2026-08-18.** These documents were written in four waves,
reconciled into one execution-ready plan on 2026-08-17, and re-scoped on 2026-08-18 when
the project owner answered the last ten open questions. A later reviewer should treat them
as settled and NOT re-derive them: the contradictions between waves have been found,
decided and recorded, and re-opening them without new information will just churn.

Two files carry the plan:

- **MILESTONES.md** - the single dependency-ordered roadmap, **RE-SCOPED 2026-08-18**.
  Where any other file in this directory disagrees with it on scope, ordering, or
  dependency, MILESTONES.md wins as of the re-scope date. Its section 8 (R1-R30) is the
  register of every contradiction found and how it was resolved, with reasoning; R26-R30
  belong to the re-scope and are listed first.
- **OPEN-QUESTIONS.md** - the single decision list. Wave-1's thirteen questions, wave-2's
  three, the red team's two escalations and the wave-3 and wave-4 documents' own open
  items are merged, deduplicated and renumbered through Q61, and **all sixty-one are now
  settled.** The file opens with an OWNER DECISIONS section carrying **two** genuinely new
  questions, both raised by the owner's own answers; then a DEFERRED TO 0.3.0 section; then
  the ratified record, ordered by milestone.

**What the 2026-08-18 answers did, in one paragraph.** Seven things left 0.2.0 for 0.3.0:
encrypted backups (Q14), BSMS (Q15), the release-key hardware token (Q30), independent
builder attestation (Q31), secure-boot key ownership and therefore Secure Boot v2 itself
(Q32), the backup format publication (Q34), and the HIL power-cut rig (Q43). Three things
changed shape: licensing became a per-crate split (Q8), the wipe policy became
user-settable and therefore a format change inside the m3 freeze (Q5), and the storage
geometry gained a 2 MiB reserved `media` region (Q7). The camera stayed, with every gate
that needs physical hardware marked **[HW-CAMERA]** (Q6, Q50). One milestone id was retired
rather than renumbered (m9, R26), so every m10-m13 reference in this set stays valid.

**Read this before anything else in the set.** Deferring Q32 means **0.2.0 ships without
Secure Boot v2 burned**, and VERIFY.md is explicit that secure boot is the only check on
the Verify screen that does not depend on the firmware being honest. On a 0.2.0 unit the
Verify screen reports what the running firmware says about itself; if you did not build
and flash that firmware yourself from a reproduced image, the screen cannot prove it is
the firmware you think it is. This is written into SECURITY.md tier 1 and invariant 6,
into m13's release documentation and into VERIFYING.md, as a stated limitation of the
release rather than as an open item.

**Two documents landed in this directory alongside the re-scope, and both are
authoritative inside their subject.** **PIN-MODES.md** (owner-directed) owns PIN, wipe and
stateless BEHAVIOUR - the three device states, when the PIN is introduced, which modal
appears where, and the copy rules; OPEN-QUESTIONS Q5 defers to it on behaviour and owns
the on-flash format and the authentication mechanism beneath it, recording in Q5.1 the one
place the two texts differed and why. **SECUREBOOT.md** owns Secure Boot v2, the
key-ownership decision that was Q32, the burn order and the runbook; it targets 0.3.0 and
confirms that 0.2.0 burns no secure-boot, anti-rollback or flash-encryption fuse.

**Blocking set: one item, and it is sharp.** Q62 is already answered (PIN-MODES.md: no
PIN-length requirement to disable wipe) and is re-presented once with the arithmetic
before it closes. **Q63 is genuinely open and must be answered before m3 closes:**
SECUREBOOT.md says 0.2.0 burns "no eFuse on any device, at any point", while the ratified
Q45 provisions an HMAC_UP key that the entire sealed-storage design binds to. Under the
narrow reading - no SECURE-BOOT fuse - everything proceeds and one sentence needs
narrowing. Under the literal reading, 0.2.0 stores nothing at all and m3, m4a and m4b lose
most of their purpose. That is a scope question, not a wording one, so it was raised
rather than resolved unilaterally.

Everything else is a normative input that MILESTONES.md and OPEN-QUESTIONS.md read.

---

## Reading order

1. **OPEN-QUESTIONS.md** - the decision list. Its OWNER DECISIONS section holds the two
   questions still open (Q62, the PIN length required to disable wipe; Q63, what flash
   encryption 0.2.0 burns now that Secure Boot is deferred) and is the only part the
   project owner needs to read; neither blocks anything before m4b. Its DEFERRED TO 0.3.0
   section records what left the release and what each departure costs. Its RATIFIED
   DECISIONS section holds the rest, ordered by milestone, and doubles as an
   implementation reference and as the audit record for why the device behaves as it does.
2. **MILESTONES.md** - what gets built, in what order, on which board, what physical
   demonstration closes each milestone, and - added at the re-scope - what each milestone
   must NOT break. Section 8 explains every place the waves disagreed.
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
11. **VERIFY.md** - the "Verify device" capability: everything the device can honestly
    report about itself, and the boundary past which no amount of reporting helps because
    the report is produced by the software under suspicion. Owns screen S-46's row set,
    frozen field order and CI assertions, the firmware-chain and reserved-space digests,
    the eFuse posture, and the boot counter. **Authoritative for S-46 and for the
    device-verification readout.** Read after UX-SCREENS.md, which still owns the screen
    inventory and the component vocabulary this document uses.
12. **CAMERA-HW.md** - camera hardware and software integration spec: the J1 CSI
    connector and the replug experiment that answers m1's spike, the esp_video /
    esp_cam_sensor / PPA / rqrr pipeline, the ingress validator, the per-board
    support split, and the staged m-camera-0..5 ordering. **Authoritative for camera
    bring-up.** Read after CAMERA.md (15), which is the ranking it takes as settled.
13. **BACKUP-FEATURES.md** - backup, restore and device-lifecycle feature detail.
    **A 0.3.0 input as of 2026-08-18**: Q14 deferred backup whole and m9 is retired, so
    this document governs nothing in 0.2.0. Read it when 0.3.0 opens, not before.
13b. **PIN-MODES.md** - owner-directed, and **authoritative for PIN, wipe and stateless
    BEHAVIOUR**: the three device states, when the PIN is introduced, the two "off"
    switches and why they carry opposite risks, and the modal copy rules. Read it with
    OPEN-QUESTIONS Q5, which owns the on-flash format and the authentication mechanism
    beneath it.
13c. **SECUREBOOT.md** - **authoritative for Secure Boot v2**, the two-key distinction,
    key ownership (the former Q32), the flash-geometry constraint, anti-rollback, the burn
    order and the runbook. Targets 0.3.0. Read its opening before assuming anything about
    what 0.2.0 burns, and read Q63 before ordering a burn.
14. **PARITY.md** - the Coldcard Mk4/Q feature matrix. Reference, not a plan; read it
    when you need to know why a feature is or is not in a milestone.
15. **CAMERA.md** - camera input paths, ranked. Feeds OPEN-QUESTIONS Q6.
16. **PLATFORM.md** - the ESP32-P4 Rust ecosystem survey and the contribution
    shortlist. Feeds milestones m3h and m12. Its shortlist is restated under the
    per-crate licence split in Q46's table; two items regained an external-adoption claim
    that the blanket GPL answer had withdrawn.

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
| PIN-MODES.md | 4 | **authoritative for PIN / wipe / stateless behaviour** | PRESENT (owner-directed 2026-08-17). Supersedes conflicting text in ARCHITECTURE 2.x, UX-SCREENS S-06/S-08/S-44 and OPEN-QUESTIONS Q4/Q5 on BEHAVIOUR. It answers Q62 (no PIN-length requirement to disable wipe). Q5 owns the format beneath it; Q5.1 records where the two differed |
| SECUREBOOT.md | 4 | **authoritative for Secure Boot v2 and the former Q32** | PRESENT. Targets 0.3.0. Confirms 0.2.0 burns no secure-boot, anti-rollback or flash-encryption fuse. **One sentence in it ("no eFuse burned on any device, at any point") collides with the ratified Q45 HMAC provisioning and is raised as Q63** |
| MILESTONES.md | 1 + 2, reconciled | **authoritative roadmap** | RECONCILED 2026-08-17, supersedes the wave-1 draft |
| OPEN-QUESTIONS.md | 1 + 2, reconciled | **authoritative decision list** | RECONCILED 2026-08-17, renumbered - see the map below |
| ARCHITECTURE.md | 1, red-teamed | technical design | current, with the exceptions in "Errata" below |
| SECURITY.md | 1, red-teamed | proposed 0.2.0 security model | current, lands as docs/SECURITY.md at m13 |
| UX.md | 1, red-teamed | screens and flows | current, with the camera-wording exception below |
| PARITY.md | 2 | Coldcard feature matrix | reference; count erratum below; all rows assigned in MILESTONES section 7 |
| CAMERA.md | 2 | camera paths, ranked | proposal, pending OPEN-QUESTIONS Q6 |
| PLATFORM.md | 2 | contribution shortlist | current; its licensing question is ANSWERED - OPEN-QUESTIONS Q8, GPL-3.0-or-later everywhere. Section 6 is retained as the record of the tradeoff and marked decided; the shortlist is restated under that answer in Q46 |
| WALLET-API.md | 3 | notyas-wallet API design (authoritative for the crate) | PRESENT at reconciliation (commit 7a67983); its OPEN: W1-W5 folded in as Q22-Q26 |
| REPRODUCIBLE.md | 3 | reproducible-build recipe, release gate | PRESENT; its six OPEN items folded in as Q27-Q32 |
| BACKUP-FEATURES.md | 3 | backup/restore/seed-lifecycle detail | PRESENT; OPEN-B1 folded into Q14, B2 -> Q33, B3 folded into Q17, B4 -> Q34. **Governs NO 0.2.0 milestone as of 2026-08-18**: Q14 deferred backup whole to 0.3.0 and m9 is retired. Retained as the 0.3.0 input, with its positions intact |
| UX-SCREENS.md | 3 | per-screen build spec | PRESENT; its five open items -> Q35-Q38 and Q24; one gap to patch, below |
| CORPUS.md | 3 | adversarial PSBT corpus, m6/m7 exit criteria | PRESENT; corpus-1..5 -> Q39-Q43 |
| ESP-SEAL.md | 3 | firmware platform traits, sealed-storage layer; **authoritative for the sealed-storage layer and the on-flash format** | PRESENT (commit ed031c1); **SWEPT 2026-08-17** - four OPEN items: 2.4 -> Q44, 4.3 -> Q45, 9.1 licence folded into Q8, 9.1 publish timing -> Q46; three escalations applied to the plan texts, see below. **All four settled 2026-08-17**: the crate is NOT extracted, the layer is a notyas-wallet module, and this document stays authoritative for its design |
| CAMERA-HW.md | 3 | camera hardware and software integration spec behind CAMERA.md's decision | PRESENT (commit f5aa401); **SWEPT 2026-08-17** - 6.2 per-board policy -> Q47, 6.2 ship-or-slip folded into Q6, 6.4 SeedQR scan-in -> Q48, 6.4 default preview -> Q49, 1.7/6.4 reference-module purchase (one item, stated twice) -> Q50 |
| VERIFY.md | 4 | the Verify-device capability; **authoritative for screen S-46 and the device-verification readout** | PRESENT; **SWEPT 2026-08-17** - its ten section-14 items -> Q52-Q61, all ratified, none reaching the owner. Three correctness fixes applied in place rather than raised as questions: the superseded partition geometry throughout (R23), the image-tail arithmetic in its scan example, and a boot counter that would have falsified SECURITY invariant 2a on blank devices (R24). Its overlap with UX-SCREENS' own S-46 entry is settled in VERIFY.md's favour for content (R25) |

**Sweep status (2026-08-17): COMPLETE through VERIFY.md. No document in this directory is
owed a sweep.** Every open item present here is in OPEN-QUESTIONS.md, including those that
do not use the literal `OPEN:` prefix (BACKUP-FEATURES.md uses `OPEN-Bn`, CORPUS.md uses
`OPEN: (corpus-n)`). Swept at reconciliation: WALLET-API.md, REPRODUCIBLE.md,
BACKUP-FEATURES.md, UX-SCREENS.md, CORPUS.md. Swept afterwards, in the final
integration pass: ESP-SEAL.md and CAMERA-HW.md, both of which landed after the
reconciliation. Swept last: VERIFY.md, which landed after that. **The list now runs to
Q63.** Q51 (outbound contributions under a receiving project's licence) is answered YES;
Q52-Q61 are VERIFY.md's ten items, all ratified; **Q62 and Q63 were raised on 2026-08-18
by the owner's own answers and are the only open items.** If a further design document
lands, continue the numbering from **Q64**, attribute the source document, keep its
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

**Recorded disagreements between documents. Three of the four are now settled by the
2026-08-17 ratification; the fourth is still the owner's.**

- **Q14** (BACKUP-FEATURES.md recommends shipping seed-bearing encrypted backup in
  0.2.0; the reconciliation recommends only the seedless profile) - **SETTLED
  2026-08-18: neither ships.** The owner deferred backup whole to 0.3.0. Both positions
  are preserved in the question for when it returns. The consequence is recorded rather
  than absorbed: multisig registrations, labels and settings have no recovery path in
  0.2.0, so every wipe surface must name them.
- **Q17** (BACKUP-FEATURES.md recommends SeedQR display behind a gated secret-QR screen
  class; the reconciliation recommends declining display-out) - **SETTLED: display-out
  is declined.** BACKUP-FEATURES rows B22-B24 are dropped, B14's "and QR" clause is
  struck, and the invariant-2 QR corollary that plan-0.2.0/SECURITY.md had silently
  dropped is restored to invariant 2a.
- **ESP-SEAL.md 2.4 versus WALLET-API.md 1.2/2.3** - both claimed the key ladder and the
  record engine. **SETTLED in WALLET-API.md's favour by Q44**, as a consequence of the
  owner's GPL-3.0-or-later answer to Q8: there is no extracted `esp-seal` crate, the
  sealing layer is a module inside notyas-wallet, WALLET-API.md's `seal` and `store`
  modules keep the ground they claim, and ESP-SEAL.md remains the authoritative DESIGN
  document for that module (format, state machine, power-loss guarantees, attack
  analysis). One implementation, one address.
- **VERIFY.md versus UX-SCREENS.md on screen S-46** - both specified it, and they
  disagreed on more than detail: UX-SCREENS rendered the flash-encryption row as a
  `WARNING` carrying an advice sentence, which VERIFY.md's design contract rule 2 forbids
  outright. **SETTLED in VERIFY.md's favour for content (R25).** VERIFY.md owns S-46's row
  set, frozen field order, geometry and CI assertions; UX-SCREENS keeps the screen
  inventory, the component library and the copy vocabulary, and its S-46 sketch is marked
  superseded in detail. The dev-board caveat the struck WARNING carried is real and moves
  to the "Save (PIN-protected)" fork and the wipe-policy sub-screen, where a warning can
  still change a decision.
- **CAMERA-HW.md 6.2 versus MILESTONES m11's exit gate** - **SETTLED by Q47.** m11 gated on
  the camera-off image SHA256 being unchanged by the feature's presence in the tree;
  CAMERA-HW shows that is not achievable, because esp-idf-sys metadata cannot be
  feature-gated and the esp_video C sources are therefore in every build's component
  tree. Q47 carries the
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
the API-level documents (WALLET-API, ESP-SEAL, UX-SCREENS, CORPUS, REPRODUCIBLE,
BACKUP-FEATURES, CAMERA-HW). Wave 4 is VERIFY.md, swept the same day it landed.

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
  **R2** and by **Q7 as amended 2026-08-18**: the data partitions sit at fixed high
  offsets (0xE00000 / 0xE40000) so app growth can never relocate a user's sealed records;
  a **2 MiB reserved `media` partition at 0xC00000** holds room for camera and video
  assets and is taken out of the app's declared span rather than the tail, so no existing
  offset moves and board B's 1.73 MiB unmapped tail is untouched; and `factory` is declared
  at its collision bound, now `0xBF0000`, so the frozen table never needs a future edit and
  `partition-table.bin` stays a stable published artifact. App-size discipline is an
  explicit CI budget constant (fail above 8 MiB, warn above 6 MiB), a policy number rather
  than a compatibility surface. Everything else in 2.7 stands.
- 5.2 / 5.4 "No camera: QR is out-only" - superseded by **R3**: the camera is an
  optional, board-A-only, compile-time-off milestone (m11) preceded by a spike inside
  m1. The wording becomes "no camera on this board/build".
- 5.3's pointer to "MILESTONES m5" for the regression corpus - superseded by **R13**:
  the corpus gate is m6, multisig cases m7.
- Section 1's dependency table stands and is restated as the authoritative dependency
  ledger in MILESTONES section 6, extended with the wave-2 crates (`bbqr`, `rqrr`).
- Section 1's CRATE table assigns "seal/unseal (PIN KDF ladder + AEAD), two-slot
  storage record format" to notyas-wallet - **this STANDS.** ESP-SEAL.md 2.4 contested
  it and Q44 settled it in notyas-wallet's favour: under the owner's GPL-3.0-or-later
  answer to Q8 there is no extracted `esp-seal` crate, so no crate row is added to the
  table. ESP-SEAL.md remains the authoritative design of that module.
- 2.2's "the HMAC key is burned at first save" - **superseded by the ratified Q45**:
  host-side factory provisioning with `espefuse.py`, and NO eFuse-burn code in release
  firmware. Amended in place 2026-08-17, along with section 4's firmware work list
  ("eFuse burn/read-protect in the provisioning path" becomes state readout).
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
  same honesty fix as ARCHITECTURE 2.5 (escalation 1 above).
- **Invariant 2's QR corollary was missing and is restored 2026-08-17.** 0.1.0's
  invariant 2 carries "QR display covers public values only ... never a mnemonic, xprv,
  seed or WIF"; this directory's split into 2a and 2b dropped it from both halves, which
  is precisely what R19 promised would not happen. The ratified Q17 declines SeedQR
  display-out, so the rule it depends on is now stated in 2a.
- **Invariant 4 no longer needs its conditional** - the ratified Q3 adopts low-R
  grinding, so ECDSA byte-equality with Bitcoin Core is claimed and tested; Schnorr
  equality against Core's own output remains impossible and is never claimed.
- **Invariant 2b's "encrypted backups if Q8 is accepted"** used the wave-1 numbering; the
  question is Q14, not the licensing question. Corrected in place.
- Still required at m13: invariant 1's per-board "the SDIO host is never configured on
  the C6 pins" survives the SD subsystem verbatim, re-verified with pin numbers at m5
  (**R16**).

**UX.md**

- Screen 9's "No camera exists, stated in the UI rather than hidden" - superseded by
  **R3** (same wording change as ARCHITECTURE).
- Screen 3's capacity line and screen 1's "storage state (blank / N wallets)" are
  **SETTLED 2026-08-18 by Q2(a) and both degrade to "present / blank"** - permanently, for
  every user, whether or not they ever enable a duress PIN. The static maximum ("holds up
  to 8 wallets") may still be shown, because a constant is not a leak; the count in use may
  not, on any pre-PIN surface or on the Verify screen. After a successful unlock the real
  wallet list is shown as before.
- Screen 16's wrong-PIN policy sub-screen (S-44) **becomes a live editor** under Q5: N is
  settable, the wipe can be turned off with the arithmetic stated at the moment of the
  change, and a PIN-removal flow sits beside it that reverts the device to 0.1.0 stateless
  operation and destroys every stored wallet. UX.md's screen text predates all of this.

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
- SeedQR is scan-in only; display-out is not shipped (**R19**, OPEN-QUESTIONS Q17, ratified 2026-08-17).

**PLATFORM.md**

- **Section 6's licensing question is ANSWERED (Q8, by the owner, 2026-08-18): a
  per-crate split, not a blanket.** The 2026-08-17 blanket GPL answer is superseded, and
  the consequences it produced were re-argued rather than left standing on a reason that
  had evaporated. Section 6 is retained as the record of the tradeoff and is marked
  decided in place. **R6's GPL-contagion constraint through `foundation-urtypes` is NOT
  moot and the 2026-08-17 "moot" marking is withdrawn**: the split creates two permissive
  crates for it to contaminate, so UR and transport encoding stay inside notyas-wallet and
  the rule is now CI-enforced.
- **Item 1 (`esp-seal`) is still not extracted and still not published** - re-decided on
  its merits under the split (Q44), for two new reasons: the sealing layer handles key
  material and encodes the security policy, so it would be GPL anyway, and extraction is
  scope this release cannot afford. R4's sequencing argument survives untouched. The
  contribution is ESP-SEAL.md itself, published in-repo, now including the settable-policy
  design of Q5.1-Q5.4.
- **The rest of the shortlist is restated under the split in Q46's table:** item 2
  (`esp-idf-hmac`) is **MIT OR Apache-2.0** and **regains** its upstream-into-esp-idf-hal
  claim, published at 0.3.0; item 3 (`seedqr`) is **MIT OR Apache-2.0**, published at
  0.3.0, and its encode half stays test-vector-only under Q17; item 4 (`bsms`) is
  permissive and **regains BDK as a named consumer**, but is not built at all in 0.2.0
  (Q15); item 5 (the no_std BBQr decode) is **permitted** under Q51's yes and is 0.3.0
  work; item 6 (the reproducible Rust-on-ESP-IDF recipe) is unaffected, ships at m12, and
  is the strongest contribution 0.2.0 makes - with its copyable artifacts permissively
  licensed so a reader can lift them without a licence audit.
- **The font carve-out is unaffected and must stay stated separately:** IBM Plex TTFs and
  the generated atlases are SIL OFL 1.1, with the Reserved Font Name renaming to "notyas
  Sans" / "notyas Mono" recorded in LICENSE-fonts. "Everything is GPL-3.0-or-later" is
  about code, not fonts.
- Item 1's "attempt-counter rollback resistance ultimately rests on secure boot +
  XTS-AES flash encryption + the eFuse-bound HMAC key" - **rewritten in place
  2026-08-17**. The counters partition is plaintext, so flash encryption contributes
  nothing to rollback resistance (escalation 1 above).

**VERIFY.md**

- The partition offsets throughout - `wallets` at 0x410000, `counters` at 0x450000, a 4 MiB
  app, an 11.7 MiB unmapped tail - were the SUPERSEDED ARCHITECTURE 2.7 layout. **Corrected
  in place 2026-08-17 to the frozen Q7 geometry, in sixteen places** (flash map, scan
  example, cost table, `counters` location, raw-digest ranges, both wireframes). See
  MILESTONES **R23** for the part that is not a find-and-replace: the freeze moves almost
  all of the must-be-blank space into the app tail, which is the region the merged-image
  caveat covers, so board B's fully trustworthy scan region is 1.73 MiB rather than
  11.7 MiB. The document now says so.
- The reserved-space scan example computed each image's tail from the image LENGTH rather
  than from `base + length`. Corrected with the arithmetic shown.
- Section 6's boot counter would have written to flash on every power-up, falsifying
  SECURITY invariant 2a for blank devices. **Corrected in place**: no write and a
  `not counted` row until the ledger is formatted (MILESTONES **R24**, ratified Q61).
- Section 13's milestone mapping is adopted as written and is folded into MILESTONES'
  milestone bodies; the V1-V3 measurements join m1's harness.

**UX-SCREENS.md**

- S-46's entry is **superseded in detail by VERIFY.md** and marked so in place; its
  `WARNING`-with-advice edge state for flash encryption is struck (**R25**). The rest of the
  document stands, including its ownership of the screen inventory, the component library
  and the copy vocabulary.
- Still owed, from the earlier sweep and unchanged: the Q22 passphrase-not-stored copy at
  the five placements listed above.

**Wave-1 milestone draft**

- Old m9 (hardening closeout) is now m13. Ids m1, m2, m3, m4a, m4b, m5, m6, m7 and m8
  keep their meaning exactly, so existing references stay valid. New: m3h (HMAC
  wrapper), m10 (addresses and exports), m11 (camera), m12 (reproducible builds).
- **m9 is RETIRED as of 2026-08-18 (R26) and the id is not reused.** Its contents were
  redistributed - seed import to m4b, the stateless session to m6, the `seedqr` decoder to
  m11 - and BIP-85, Seed XOR, Lock Down Seed and the encrypted backup left 0.2.0. A
  reference to m9 anywhere in this set resolves to the retirement note in MILESTONES
  section 4, which carries the redistribution table. Retiring rather than renumbering
  keeps every m10-m13 reference valid.
- **m12 is no longer "and crate publication".** Under Q46 nothing publishes to crates.io
  in 0.2.0; the contribution is REPRODUCIBLE.md's recipe and ESP-SEAL.md's format.

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
| - | Q8 | Licensing (wave 2) - **ANSWERED by the owner 2026-08-18: a per-crate split, monorepo. Supersedes the 2026-08-17 blanket GPL answer** |
| - | Q62 | **NEW 2026-08-18.** Must disabling wipe-on-N require a PIN longer than the 4-digit floor? Raised by the Q4 + Q5 interaction |
| - | Q63 | **NEW 2026-08-18.** What flash-encryption mode do release units burn, now that Secure Boot is deferred? Forced by the Q32 answer |
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
| ESP-SEAL 2.4 | Q44 | esp-seal vs notyas-wallet crate boundary - **settled: notyas-wallet module, no crate; the WALLET-API `seal`/`store` overlap resolves in WALLET-API's favour** |
| ESP-SEAL 4.3 | Q45 | In-app eFuse provisioning versus host-side factory provisioning - **settled: host-side factory, no burn code in release firmware** |
| Q8's consequence | Q51 | Raised 2026-08-17, **ANSWERED YES 2026-08-18.** We may contribute the no_std BBQr decode upstream, and the adversarial PSBT vectors to HWI / psbt_faker, under those projects' permissive licences. The work itself is 0.3.0; only the permission was needed now |
| ESP-SEAL 9.1 (licence) | folded into Q8 | esp-seal's licence - **GPL-3.0-or-later, and its own stated consequence therefore applies: do not extract at all** |
| ESP-SEAL 9.1 (publish) | Q46 | Where esp-seal lives and when it is published - **settled: in-tree for the life of 0.2.0, never published; the contribution becomes the design document** |
| CAMERA-HW 6.2 (policy) | Q47 | Per-board camera policy: separate build variant and artifact |
| CAMERA-HW 6.2 (ship) | folded into Q6 | Ship camera in 0.2.0 or slip; refines Q6 to "land it, sequence last, droppable" |
| CAMERA-HW 6.4 (SeedQR) | Q48 | SeedQR scan-in friction and placement; does NOT reopen Q17 |
| CAMERA-HW 6.4 (preview) | Q49 | Viewfinder preview on by default |
| CAMERA-HW 1.7 / 6.4 | Q50 | Buy a known-good OV5647 reference module |
| VERIFY 7.3 | Q52 | Publish a per-board verification manifest artifact - **ratified: accept**; field set frozen at m1, artifact at m12 |
| VERIFY 6.2 | Q53 | Boot-log cell budget and placement - **ratified: reserved region, sized by M6**; inside the m3 format freeze |
| VERIFY 11.5 | Q54 | Three new `RegionId` values - **ratified: accept** |
| VERIFY 11.4 | Q55 | S-46's exemption from reflow rule 1 - **ratified: accept** |
| VERIFY 7.4 | Q56 | `wallets` raw digest pre-PIN - **ratified conditionally**: pre-PIN only under Q2(a); a mechanical consequence of Q2, like Q37 |
| VERIFY 3.3 / 3.4 | Q57 | Reserved-space scan at boot? - **ratified: on demand** |
| VERIFY 5.1 | Q58 | Print all three secure-boot key digest slots - **ratified: yes, unconditionally**; does not pre-empt the owner's Q32 |
| VERIFY 4.3 | Q59 | A mask-ROM digest - **ratified: no**; report the ROM version fields only |
| VERIFY 4.6 | Q60 | Ship the flash unique-ID row? - **ratified: measurement-gated on m1's new V3 run** |
| VERIFY 6 / 14 | Q61 | Boot counter on a failed self-test - **ratified: yes, and it does not exist on a blank device** (R24) |

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
- **Licensing is a per-crate split, in one monorepo** (Q8, owner-answered 2026-08-18,
  superseding the 2026-08-17 blanket GPL answer). The principle: **GPL-3.0-or-later if the
  crate is the product, handles user key material, or encodes this project's security
  policy; MIT OR Apache-2.0 if it is a generic platform or format building block whose
  only value is adoption by a permissive ecosystem and which holds no secret and makes no
  policy decision; CC0-1.0 for test vectors, which are data; SIL OFL 1.1 for font data,
  which is neither.** In practice: firmware, notyas-core, notyas-wallet, notyas-ui,
  notyas-fonts code and the tools are GPL; `esp-idf-hmac` and `seedqr` (and `bsms` when it
  is built at 0.3.0) are MIT OR Apache-2.0; the PSBT vector files are CC0-1.0 while their
  harness stays GPL; IBM Plex and the generated atlases are OFL per LICENSE-fonts and are
  **explicitly excluded from every crate-level licence statement**. Nothing publishes to
  crates.io during 0.2.0. The full table is in Q8; a CI job enforces both the headers and
  the rule that no permissive crate has a GPL dependency.
- **0.2.0 is a LEAN release.** Anything not needed for a working storage, signing and
  multisig wallet is 0.3.0 (owner instruction, 2026-08-18). Coldcard parity remains the
  project bar and becomes a 0.3.0 release bar; MILESTONES section 7.4 is the honest
  measure of what the lean release costs.
- **0.2.0 has no Secure Boot.** See the statement above; it changes what the Verify screen
  can prove and it is documented rather than implied.
