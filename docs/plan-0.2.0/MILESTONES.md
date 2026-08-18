# notyas 0.2.0 - Milestones (THE roadmap)

Status: RECONCILED 2026-08-17, and swept again the same day for VERIFY.md. This file
supersedes the wave-1 milestone draft and folds in wave 2 (PARITY.md, CAMERA.md,
PLATFORM.md) and the wave-3 design documents. Where any other document in
docs/plan-0.2.0/ disagrees with this file on scope, ordering, or dependency, this
file wins as of the reconciliation date; the resolutions and their reasoning are
recorded in section 8 (R1-R25). The VERIFY.md sweep added no milestone and moved no
dependency: it added measurements V1-V3 and two freezes to m1, a cell array to m3's format
freeze, the eFuse readout surface to m3h, the boot counter to m4a, screen S-46 to m4b, a QR
export to m8, one artifact to m12, and the self-reporting wording to m13 - plus findings
R23, R24 and R25. docs/SECURITY.md (0.1.0) stays normative for invariants
until plan-0.2.0/SECURITY.md lands at m13.

**RE-SCOPED 2026-08-18** on the project owner's answers to the last ten open questions.
The re-scope removed work rather than reordering it: no milestone moved, no dependency
changed, one milestone id (m9) was retired rather than renumbered so every m10-m13
reference stays valid, and section 7.4's deferred list absorbed everything that left. What
changed inside the milestones is recorded per block and in findings R26-R30.

Release framing (owner directive, encoded here so no milestone re-litigates it):

- 0.1.0 ships NOW as a source-only preview: signed-if-possible, not reproducible,
  no public binary campaign.
- **0.2.0 is the public release, and it is a LEAN one.** Scope: seed storage + PSBT
  signing + multisig + wallet management, and the things those four require. Nothing
  else. Reproducible builds and GPG-signed per-board artifacts are a 0.2.0 deliverable
  (m12/m13), not a later nicety.
- **Scope discipline is the governing rule for this release.** The owner's 2026-08-18
  instruction is explicit: anything not needed for a working storage, signing and
  multisig wallet goes to 0.3.0. Where a milestone is in doubt about a feature the answer
  is 0.3.0, and the row goes to section 7.4 with a reason rather than into the scope.
- **Coldcard parity is still the product bar, and it is now a 0.3.0 bar.** Every
  PARITY.md row is still assigned - implemented, shipped as a documented equivalent, or
  deferred with a stated reason - and no row is silently dropped. What changed is that
  section 7.4 got substantially longer, which is where that stays honest instead of
  hidden.
- Rust wherever it fits, including notyas-wallet as a real Bitcoin wallet library -
  but vetted primitives are reused, never reimplemented. No hand-rolled crypto.
- **Licensing is a per-crate split (ratified Q8), not a blanket:** GPL-3.0-or-later for
  the firmware and everything that touches key material, MIT OR Apache-2.0 for the
  generic low-level pieces (`esp-idf-hmac`, `seedqr`), CC0-1.0 for test vectors, SIL OFL
  1.1 for font data. One monorepo, and nothing is published to crates.io during 0.2.0.
- First-class wallet UI/UX is a gate, not a garnish: m4b and m10 exist because a
  signer nobody can operate confidently is not a signer.

**Two release-level facts every milestone is written against, stated here so nothing
downstream implies otherwise:**

1. **0.2.0 ships without Secure Boot v2 burned** (owner deferral of Q32; eFuse
   anti-rollback goes with it, because it protects a signature chain that does not
   exist). VERIFY.md section 9 is explicit that secure boot is the only check on the
   Verify screen which does not depend on the firmware being honest, so on a 0.2.0
   release unit every value that screen prints is self-reported by software an attacker
   may have replaced. The reproducible-build chain remains the answer, and it must be
   exercised by the owner on their own machine rather than certified by the device. This
   lands in SECURITY.md tier 1 and invariant 6, in VERIFYING.md and in the release
   announcement. Q63 decides what, if anything, is burned instead.
2. **The camera is in scope, and the owner does not yet have a module.** Every exit gate
   below that needs physical camera hardware is marked **[HW-CAMERA]**. Such a gate is met
   the day the module arrives and never before, and **no non-camera milestone depends on
   one**. Everything else about the camera - the cargo feature and its `compile_error!`
   guard, the artifact split, the ingress validator and its fuzzer, the `seedqr` decoder,
   the autodetect classifier, the scan UI - is built and tested with no hardware present.

---

## 1. How to read a milestone

Every milestone lands as a working, flashable commit, independently verifiable on
hardware (0.1.0 house rule). Each block states:

- **Depends on** - hard predecessors. Anything not listed can run concurrently.
- **Runs on** - board A (Waveshare 4B, COM3, 720x720, 32 MB flash, 4-bit SD,
  Pi-compatible CSI at J1), board B (Elecrow CrowPanel 5inch, COM6, 800x480, 16 MB
  flash, 1-bit SD, STC8 co-MCU, C6 power-on window, no Pi camera), or host.
- **Scope** - what is built.
- **Crates / areas** - what the diff touches.
- **Exit gate (hardware)** - the physical demonstration that closes the milestone.
  Host-only milestones still carry an on-device gate: fit and behavior on target
  silicon is the thing being proven. A clause marked **[HW-CAMERA]** needs a physical
  camera module and is met when one arrives; nothing else waits on it.
- **Must not break** - added 2026-08-18. The properties this milestone's diff is not
  allowed to regress, named specifically enough to be testable. This field exists because
  a lean release is built by adding to a working device, and the failure mode of a lean
  release is a milestone that quietly costs something the previous one proved. Every entry
  is either already covered by a test or names the test that must exist.
- **Parity rows closed** - PARITY.md rows this milestone satisfies.
- **Implements** - the research or red-team finding it discharges.

**Two standing "must not break" items apply to every milestone below and are not repeated
in each block:** the build-graph check stays green (no RNG, no network crate, no banned
feature reaching the image), and a blank device stays byte-for-byte stateless (SECURITY
invariant 2a, proven by a flash readback diff, not by inspection).

### 1.1 Companion specifications (who is authoritative for what)

This file owns ordering, scope boundaries and exit gates. The build-level detail lives
in the wave-3 documents, and each one is the authority inside its milestone:

| Document | Authority for | Milestones it governs |
|---|---|---|
| WALLET-API.md | the notyas-wallet crate: types, traits, error taxonomy, the validation pipeline, test strategy | m3, m4a, m6, m7, m8 |
| ESP-SEAL.md | the firmware side of the platform traits (Storage, DeviceBinding, KdfScratch) over esp_partition and the P4 HMAC peripheral - the sealed-storage layer that gates all storage work | m3h, m3, m4a, m12 |
| CORPUS.md | the adversarial PSBT corpus: cases, expected verdicts, expected rendered text - the signing milestone's exit criteria are defined there | m6, m7 |
| UX-SCREENS.md | the per-screen build spec every UI milestone implements | m4a, m4b, m6, m10, m11 |
| REPRODUCIBLE.md | the reproducible-build recipe and its verification procedure - the release gate | m12, m13 |
| CAMERA-HW.md | camera hardware bring-up detail behind CAMERA.md's decision | m11 (including m-camera-0, the spike, which left m1 in the 2026-08-18 re-scope) |
| BACKUP-FEATURES.md | backup, restore and device-lifecycle feature detail | **no 0.2.0 milestone.** Q14 deferred whole to 0.3.0; this document is retained as the 0.3.0 input and governs nothing in this release |
| PIN-MODES.md | **PIN, wipe and stateless BEHAVIOUR**: the three device states, when the PIN is introduced, which modal appears where, and the copy rules. Owner-directed and authoritative; Q5 owns the on-flash format and the authentication mechanism beneath it | m4a, m4b, m13 |
| SECUREBOOT.md | **Secure Boot v2**: the signature scheme, the two-key distinction, key ownership (the former Q32), the flash-geometry constraint, anti-rollback, the burn order and the runbook. Targets 0.3.0; owns the 0.2.0 preparatory slice | m1 (measurements SB1/SB2), m3h, m13 |
| VERIFY.md | the "Verify device" capability: what the device reads about itself, the firmware-chain and reserved-space digests, the eFuse posture, the boot counter, and screen S-46's row set, frozen field order and CI assertions | m1 (decisions and the V1-V3 measurements), m3h, m4a, m4b, m8, m12, m13 |

Rule: where a companion document and this file disagree on WHAT is built, the
companion wins; where they disagree on WHEN or on what closes a milestone, this file
wins. If a companion document listed here is absent from the directory, it has not
landed yet and its milestone cannot close.

---

## 2. Ordering: storage before signing (retained from the red-team pass)

Justification from the dependency graph, unchanged and still correct:

1. The randomness and sealing decisions block the SECURITY.md rewrite, which the
   project rule says must precede any claim the code implies.
2. The unlock session and PIN flow are the substrate every signing screen assumes -
   a signer without a wallet context has nothing to verify change against.
3. Multisig registration, required for safe multisig signing per the 2021 Coldcard
   xpub-substitution attack, is itself storage.
4. The Argon2id benchmark (m1) is a prerequisite for pinning any storage constant.

Signing depends on storage; storage depends on nothing signing provides. The red
team's m4 split is retained and hardened: **m4a proves the storage stack on hardware
with the minimum UI; m4b builds the wallet-management UX on a proven substrate.**
Bundling the flash driver, eFuse provisioning, a notyas-ui restructure, and six new
screens into one hardware step is unbisectable when the first on-device unlock
misbehaves.

---

## 3. Parallelism map (two dev boards, one flashable image each)

Strictly serial spine (never overlap these):

```
m1 -> m3 -> m4a -> m4b
            m4a -> m6 -> m7
            m5  -> m6
            m6  -> m8
```

- m3 cannot start until m1 pins the KDF parameters and the partition offsets.
- m4a cannot start until m3's ladder and record format pass host proof, and until
  m3h can call the HMAC peripheral.
- m6 cannot start until m4a (a session to sign with) and m5 (a file to sign) exist.
- m7 cannot start until m6: multisig change verification is a policy-engine check,
  not a separate engine.
- m13 is last by construction: it re-audits every claim against what shipped.

Concurrent lanes, and which board each needs:

| Lane | Milestones | Board | Notes |
|---|---|---|---|
| A - silicon | m1 benchmark, m3h, m4a, m5 | board B first | Board B is the sacrificial unit: the eFuse HMAC burn and the flash-encryption-on benchmark happen there. |
| B - pure Rust | m2, m3, the m11 host work (`seedqr` decoder, ingress validator, fuzzers) | host | No board needed until the on-device KAT gate. The camera's host half sits in this lane, not in lane D, which is what lets it proceed with no module. |
| C - UI/UX | m4b, m10 screens | board A + uisim | 720x720 and 800x480 golden images both required before any UI milestone closes. |
| D - camera hardware | m-camera-0, m-camera-2, and m11's `[HW-CAMERA]` gates | board A only, **and only once a module exists** | Board B physically cannot take a Pi-class module (CAMERA.md 2.3). This lane is currently **blocked on a purchase** (Q50) and blocks nothing else. |

Safe concurrency, explicitly:

- m2 (notyas-core signing API, host) runs alongside m3 (notyas-wallet sealing, host)
  and m3h (HMAC wrapper, board B). Three people, no contention.
- m4b (UI on board A + uisim) runs alongside m5 (SD bring-up on board B). Both then
  cross-verify on the other board before closing.
- m8 (UR2 QR-out, board A, needs a webcam and Sparrow) runs alongside m10's non-signing
  screens and m11's host-side work.
- m11's HOST half (the `seedqr` decoder, the ingress validator, both fuzz harnesses, the
  autodetect classifier, the artifact split and the link-map gate) runs at any time in
  lane B with no hardware at all. Only lane D waits on the module.
- **Retired: lane B previously listed "m9 math". Milestone m9 no longer exists** (R26);
  the seed-math work it carried left 0.2.0 and the rest was absorbed by m4b, m6 and m11.

Hard serialization on hardware resources, stated so two agents do not collide:

- **One eFuse budget per board (6 key blocks).** One HMAC_UP key is burned and
  read-protected per board, by the HOST with `espefuse.py` ahead of m4a (ratified Q45 -
  release firmware contains no burn code). That is permanent. Do it on board B first;
  board A stays clean until the procedure is written down and repeated. Retry budget,
  worth knowing before the first burn: one block for the secure-boot digest, one for the
  flash-encryption XTS key, one for the HMAC key, three spare - and Secure Boot v2 can
  occupy up to three digest slots if multiple signing keys are enrolled, so it is three
  retries with one signing key and one with three. Ordering is load-bearing and belongs
  in the runbook: HMAC provisioning BEFORE flash encryption and secure boot, because
  Release-mode flash encryption disables the UART download path `espefuse.py` uses.
  **Re-scope note 2026-08-18: with Secure Boot deferred (Q32) the retry budget improves to
  four spare blocks, and the burn-ordering rule survives anyway** - it is a property of the
  UART download path, not of secure boot, and 0.3.0 will need it unchanged.
- **The only eFuse burn in 0.2.0 is the HMAC_UP key.** Secure Boot v2 and eFuse
  anti-rollback are deferred to 0.3.0 with Q32; flash encryption's fate is Q63 and is
  decided at m13. The m1 benchmark still measures the encryption cost using virtual-eFuse
  / development mode on board B, because the Argon2 parameters must be pinned against the
  worst case whether or not 0.2.0 units ship with encryption on. Board A is never burned
  for a measurement.
- Switching boards never requires a clean (per-board CARGO_TARGET_DIR, BOARDS.md),
  but two agents must not flash the same COM port concurrently.

---

## 4. The milestones

### 0.2.0-m1 - Foundations, ratified decisions, frozen storage geometry

- **Depends on:** nothing. **The blocking set is empty and every question that ever
  gated this milestone is now settled** (2026-08-18): Q1, Q2, Q3, Q4, Q5, Q6, Q7, Q8, Q9,
  Q44 and Q47 are all decided. The two questions that remain open project-wide, Q62 and
  Q63, gate a settings-screen branch at m4b and a runbook line at m13 respectively, and
  neither touches m1 or the format freeze.
- **Runs on:** board A and board B (partition table boot check), board B (benchmark).
  **The camera spike is no longer part of this milestone** - it moved to m11 as
  m-camera-0 when the owner's Q6 answer made physical camera work hardware-gated (R27).
- **Scope:**
  - Write the settled decisions into SPEC and the plan texts: randomness policy
    (Q1 / ARCH 2.4), signing equivalence and low-R grinding (Q3), **PIN floor of 4
    characters (Q4)**, **wipe-after-N default 15, range 3..=25, user-settable, with the
    copy, the power-cut disclosure and the PIN-removal semantics it carries (Q5)**, the
    camera's hardware-gated scope (Q6), **the frozen partition geometry including the
    2 MiB `media` reserve (Q7)**, the camera build variant (Q47), the sealing layer's
    address (Q44), **the per-crate licence split (Q8)**, **the duress deniability package
    with `Occupancy::AlwaysFilled` as the only shipped mode (Q2)**, and **rev v1.x silicon
    with the HMAC-eFuse ladder as designed (Q9)**. One sub-item remains implementation
    design and is settled at its own milestone rather than here: the scope of the
    stateless multisig refusal (m6, recommended answer recorded in Q12).
  - **Licence hygiene, new at the 2026-08-18 re-scope and cheapest here.** Set every SPDX
    header to the Q8 table from the first commit of each file, add the per-path licence
    map to `COPYING`, and add the CI job that enforces both: every `.rs`, `.toml`, `.ps1`
    and `.sh` carries an `SPDX-License-Identifier` matching its path's row, the font paths
    (`crates/notyas-fonts/src/gen/`, `tools/fonts/upstream/`) are on an explicit exclusion
    list so no crate-level statement can be read as covering them, and **no crate declared
    MIT OR Apache-2.0 has a GPL crate anywhere in its dependency tree** - which is what
    keeps reconciliation finding R6 honoured after everyone has forgotten it exists.
  - Workspace and CI: the root workspace and the unified Cargo.lock already landed
    in 0.1.0 (commit b0f9452), as did tools/build-graph-check.sh (commit d151b2e).
    m1 does NOT rebuild them; it EXTENDS the ban list and the graph walk to every
    dependency edge 0.2.0 adds (section 6 ledger) and wires both into CI at both
    board geometries. See R1.
  - Freeze the storage geometry (R2). New partitions.csv, identical on both boards,
    inside 16 MB:

    ```
    # Name,    Type, SubType, Offset,   Size,     Flags
    factory,   app,  factory, 0x10000,  0xBF0000
    media,     data, 0x42,    0xC00000, 0x200000, encrypted
    wallets,   data, 0x40,    0xE00000, 256K,     encrypted
    counters,  data, 0x41,    0xE40000, 16K
    ```

    Data partitions sit at fixed high offsets so app growth can never relocate a
    user's sealed records: **the whole table is a permanent compatibility surface and
    is frozen here.** The app is declared at its collision bound - 0xC00000 - 0x10000 =
    0xBF0000 = 11.94 MB - rather than at a nominal 8M, precisely so that the frozen
    table never needs a later edit: ESP-IDF enforces the size field, so an 8M
    declaration would have to be raised to use the space, and `partition-table.bin` is
    a published byte-identical release artifact whose hash verifiers are told is
    stable (REPRODUCIBLE.md 3.5). **App-size discipline lives in CI as an explicit budget
    constant: fail above 8 MiB, warn above 6 MiB.** That is a policy number, freely
    revisable because it is not a compatibility surface. The table ends at 0xE44000 =
    14.27 MB, inside board B's 16 MB with **1.73 MB spare, unchanged**, and unchanged on
    board A's 32 MB. App offset 0x10000 is unchanged, so the Verify screen's
    running-partition SHA256 procedure stays board-independent. No `nvs`, `otadata` or
    `phy_init`, as in 0.1.0 - and the m11 link-map gate additionally asserts
    `nvs_flash_init` and `nvs_open` are absent from the image, because 0.2.0 adds
    components (FATFS, possibly `esp_cam_sensor`) that could pull NVS in and fail at
    runtime on a device with no recovery path.

    **The 2 MiB `media` partition is new at the 2026-08-18 re-scope** (owner requirement:
    leave room for video if it is ever needed) and three things about it are gates rather
    than notes. **It is taken out of the app's declared span, not out of the tail**, so
    `wallets` at 0xE00000 and `counters` at 0xE40000 do not move and board B's 1.73 MiB
    unmapped tail - which R23 identifies as the fully trustworthy region of the
    reserved-space scan on an encrypted unit flashed from a merged image - is untouched.
    **It carries the `encrypted` flag** because the flag cannot be added after the freeze
    and the thing most likely to be staged there is a camera frame, which under Q48 can
    contain a SeedQR, which is a mnemonic. **And 0.2.0 writes nothing to it**: it reads
    all-`0xff`, its SHA256 is a Verify row, CI asserts no image symbol references it, and
    any non-blank content on a release unit is a finding. It is sized for camera assets
    and one staged still, explicitly not for footage - the whole reserve holds under two
    seconds of 640x480 MJPEG, and NOR flash is the wrong medium for streaming writes when
    the device has a microSD slot. See OPEN-QUESTIONS Q7 for the full arithmetic and the
    sizing argument.
  - Fix the two known 0.1.0 defects: uisim stale VerifyInfo; firmware discarding
    UiRequest with notyas-core's `qr` feature off (QR buttons are dead on hardware).
    Wire UiRequest::Qr end to end - m8 builds on it.
  - Argon2id benchmark harness (feature-flagged firmware path): m=64 MiB in PSRAM
    vs m=16 MiB in internal SRAM at several t, target 0.5-2 s per unlock. MUST
    include a measurement with flash+PSRAM encryption enabled, because the P4
    encrypts external-PSRAM traffic with the same XTS machinery whenever flash
    encryption is on and release units pay that cost (ARCH 2.3). All boards are
    P4NRW32 with 32 MB PSRAM, so 64 MiB working memory is not the constraint;
    latency is. Commit the numbers; pin the parameters.
  - **Measurement M6 - NOR partial-page program limit on the actual flash parts
    (ESP-SEAL.md 8.3). This is an m1 exit gate, not a nice-to-have, because it can
    invalidate the on-flash format.** The ledger's bit-clear attempt counter programs
    **up to 32 cells into a single 256-byte page** between erases. SPI NOR parts
    specify a maximum number of partial-page programs to the same page between erase
    cycles, and if the real limit is below 32 the cell size or the page layout has to
    change - which is a format change, so it must be known BEFORE the format is
    frozen. Two steps, both required:
    1. **Read the datasheets for the parts actually fitted.** Board A (Waveshare) is
       a 32 MB GD25Q256-class part - `docs/research/hardware.md` records "QSPI to
       external 32 MB NOR flash" (capacity only, no part number), and
       `docs/research/waveshare-family.md` identifies the family part as
       GD25Q256EYIGR. Board B (Elecrow) is 16 MB, and
       `docs/research/elecrow-board.md` records a vendor swap that matters here: the
       schematic specifies Winbond W25Q128JVSIQ while the probed unit reports
       GigaDevice `c8/4018` = GD25Q128. **Read the JEDEC ID off each unit on the
       bench first and read the datasheet for what is actually there**, not for what
       the schematic says - both vendors' parts are in circulation for board B, and
       their partial-program specs are not guaranteed to agree.
    2. **Run an empirical soak test.** Program cells one at a time into a single page
       of the `counters` partition, reading back after every program, until read-back
       diverges or the design's 32 is comfortably exceeded; repeat across several
       pages and both boards. Datasheet numbers here are conservative and sometimes
       silent, so the soak is what the format is frozen against.
    **Consequence if the limit is exceeded:** the ledger cell layout is re-designed
    (larger cells, fewer per page, or one cell per page) before m3 writes a line of
    the format, and the m1 geometry freeze is re-taken with the new layout. Commit
    the datasheet citations and the soak results next to the Argon2 numbers.
  - The remaining ESP-SEAL.md 8.3 measurements ride the same harness and are
    committed with it: M3 (`esp_hmac_calculate` latency - mount does up to ~40 MAC
    operations), M4 (4 KiB erase and 256-byte page program times - sizes the
    power-loss window), M5 (64 MiB PSRAM zeroization time), M7 (the P4's
    Development-mode flash-encryption re-flash count eFuse field - how many times the
    sacrificial board can be re-flashed) and M8 (full cold-boot-to-session unlock wall
    time). **M9 (`esp-seal` crate-name availability on crates.io) is withdrawn**: under
    the ratified Q8/Q44/Q46 there is no crate to name. M1 and M2 are the
    Argon2id and PSRAM-bandwidth runs above. Only M6 is an exit gate; the rest are
    "committed numbers, no invented values".
  - **Three more measurements from VERIFY.md 13, on the same harness and the same bench
    session.** **V1** - app, bootloader and partition-table hash times at boot on both
    boards (0.1.0 already logs the app number; this commits it). **V2** - raw
    read-and-hash throughput over the whole part on both fitted flash chips, which sizes
    the reserved-space scan. **V3** - whether `esp_flash_read_unique_chip_id()` returns a
    plausible, stable, non-zero value on each fitted part, taken at the same moment as the
    M6 JEDEC-ID read because it is the same bench operation. V3 is a gate on one screen row
    only, not on the milestone: the ratified Q60 ships the flash unique-ID row if V3 passes
    on both boards and renders `not supported` otherwise.
  - **Two freezes VERIFY.md needs taken here, both because m12's artifact set depends on
    them and neither because of UI work:** the composite `firmware_digest` construction
    (VERIFY.md 2.4) and the field set of the per-board verification manifest
    `notyas-<ver>-<board>-VERIFY.json` (VERIFY.md 7.3, ratified Q52). No Verify-screen UI is
    built at m1 - that is m4b - but a manifest whose fields are decided after the release
    recipe is written is a manifest that arrives too late to be reproduced.
  - **M6 gains a THIRD consumer at the 2026-08-18 re-scope, which raises what it decides
    again.** The `counters` partition now holds three bit-clear cell arrays under the same
    partial-page limit: the attempt ledger, the boot counter (Q53), and the new
    `policy_log` that makes the wipe policy settable (Q5.1). M6's measured number sizes
    all three. **If it comes back below 32 cells per 256-byte page, all three are
    re-laid-out together before m3 writes a line of the format**, and the geometry freeze
    is re-taken with the new layout.
  - **The camera spike has LEFT this milestone** (R27). It needs a module the owner does
    not yet have, and holding m1 open for a purchase would stall the entire spine. It is
    m-camera-0 inside m11, marked [HW-CAMERA]. Two things it was carrying stay here
    because neither needs hardware:
    - **The app-size measurement.** Record `app.bin`'s byte count for a notyas build with
      the `camera` feature ON and for the base build, and commit both beside the Argon2
      numbers. This is a build, not a bench run. Nobody has ever measured it, and the old
      claim that the camera gated the partition freeze was asserted on a number that did
      not exist. For scale, 0.1.0's debug build's flash-loadable sections total roughly
      2.5 MiB.
    - **m-camera-1, the `board::shared_i2c_bus()` refactor** (CAMERA-HW.md 6.2): cheap,
      hardware-independent, and worth landing with the early infrastructure work.
  - Reproducible-build groundwork: keep CONFIG_APP_REPRODUCIBLE_BUILD, add path
    remapping and toolchain pinning to build.ps1 (the full two-machine proof is
    m12's gate).
- **Crates / areas:** root workspace, CI, tools/build-graph-check.sh, tools/build.ps1,
  tools/flash.ps1, firmware/partitions.csv, firmware (benchmark path), tools/uisim,
  docs/BOARDS.md flash section, `COPYING` and every SPDX header.
- **Exit gate (hardware):** both boards boot the new partition table and report the
  new geometry on the Verify screen, **including the `media` partition's span and its
  all-`0xff` digest**; the QR modal is reachable and renders on both
  boards (photo evidence in the milestone note); benchmark numbers committed
  including the encryption-on run; **M6 answered on both boards - JEDEC ID read off
  each fitted part, the matching datasheet's partial-page-program limit cited, and a
  soak test showing 32 cell programs into one 256-byte page read back intact; if the
  limit is below 32, the attempt ledger, the boot log AND the policy log are re-laid-out
  together and the geometry freeze re-taken before m1 closes**; V1, V2 and V3 committed
  beside the Argon2 numbers, with V3's verdict recorded as ship-or-`not supported` for the
  flash unique-ID row; the `firmware_digest` construction and the VERIFY.json field set
  frozen in the plan texts; CI red on a planted `rand` dependency; **CI red on a planted
  SPDX mismatch and on a planted GPL dependency inside a permissive crate**. No camera
  clause: the spike is m11's (R27).
- **Must not break:** 0.1.0's boot path and its Verify-screen values (the geometry change
  must not alter the running-app SHA256 procedure, which is why the app offset stays at
  0x10000); the existing uisim golden images at both geometries; `tools/build.ps1` and
  `tools/flash.ps1` for either board; the 0.1.0 stateless flash readback (nothing this
  milestone adds may write to flash on a blank device, and the benchmark harness is
  feature-gated out of release builds).
- **Parity rows closed:** none directly (foundation). Unblocks every storage row.
- **Implements:** audit repo hygiene; storage research 3.2 ("never ship a guessed
  KDF cost"); red-team counter-partition finding (ARCH 2.5/2.7); reconciliation R1, R2,
  R3, R7, and R26-R30.

### 0.2.0-m2 - notyas-core signing API

- **Depends on:** m1 (Q3 decides whether the ECDSA path grinds low-R; the API shape
  differs).
- **Runs on:** host; gate on board A and board B.
- **Scope:** `derive_path()` over an arbitrary DerivationPath (mixed hardened and
  normal, arbitrary depth; bounded by the policy engine, not here);
  `SecretSigningKey` (zeroize-on-drop, redacting Debug, GetKey-compatible, Schnorr
  keypair with taproot tweak); typed `root_fingerprint()`; BIP-143 and BIP-341
  sighash vector tests; pinned PSBT-sign known-answer check in selftest.rs and in
  the on-device boot self-test. If Q3 adopts low-R grinding, the ECDSA path calls
  secp256k1's `sign_ecdsa_low_r` instead of Psbt::sign's stock loop and the KAT
  vectors are regenerated accordingly. No policy logic here: notyas-core signs what
  it is told; refusing is notyas-wallet's job. Sighash is never hand-rolled -
  `SighashCache` only.
- **Crates / areas:** notyas-core only.
- **Exit gate (hardware):** sighash and signing KATs green on host AND in the boot
  self-test on both boards (this is the gate: RISC-V, no_std, real stack budget);
  no_std proof build still passes; **zero new dependencies in notyas-core** enforced
  by the build-graph check.
- **Must not break:** the 0.1.0 dice-to-mnemonic path and its byte-identical-to-BigDice
  equivalence (invariant 4's first half is a shipped claim with shipped tests); the no_std
  proof build; notyas-core's zero-dependency posture; the boot self-test's 1 s budget,
  which this milestone adds KATs to.
- **Parity rows closed:** none alone; prerequisite for every section-3 row.
- **Implements:** signing research 1; audit gap-list item 6; red-team correction to
  invariant 4 (equivalence is against pinned vectors plus Core-accepts, never
  byte-equality with Core's own Schnorr output).

### 0.2.0-m3h - esp-idf-hmac: safe Rust over the P4 security peripherals

- **Depends on:** m1. **Licence, changed at the 2026-08-18 re-scope: `esp-idf-hmac` is
  MIT OR Apache-2.0** (Q8's split), set in its SPDX header and `Cargo.toml` from the first
  commit. It is an in-tree workspace member and **is not published during 0.2.0** (Q46);
  publication is 0.3.0 work and costs nothing to defer because the licence - the
  expensive-to-change part - is already right. Two constraints follow from the permissive
  licence and are enforced by m1's CI job: **no GPL crate may enter its dependency tree**
  (so no `foundation-*`, per the revived R6), and it must hold no key material and make no
  policy decision - it calls a peripheral whose key lives in an eFuse, and that is all.
- **Runs on:** board B, then board A.
- **Scope:** first platform contribution (PLATFORM.md shortlist item 2). A thin,
  safe crate over ESP-IDF's `esp_hmac.h` (and optionally `esp_ds.h`,
  `esp_key_mgr.h`) using esp-idf-sys's `extra_components` / `bindings_header`
  mechanism - no fork of esp-idf-sys. Verified gap: esp-idf-sys's default bindgen
  header does not include these; esp-hal has HMAC for S2/S3/C3/C6/H2 but not P4.
  Surface: calculate HMAC-SHA256 with an eFuse key of purpose HMAC_UP, query key
  state, and a documented provisioning helper for burn plus read-protect that is
  loud about being irreversible - **behind a non-default `provisioning` feature that
  notyas release builds never enable, with the build-graph check asserting that
  (ratified Q45). The build-graph check's SPECIFICATION is extended here from a
  banned-crate walk to feature-state assertions, because a crate walk cannot enforce a
  feature being off; ESP-SEAL.md already describes the right check and REPRODUCIBLE.md
  and this document did not.** Key Manager support is compiled out on rev < v3.0
  silicon and is not designed around (Q9).
  **Also here, because this is the module whose whole purpose is safe Rust over these
  peripherals: the eFuse posture READOUT surface VERIFY.md section 5 needs** - key-block
  purposes, `RD_DIS`/`WR_DIS`, `esp_secure_boot_read_key_digests()` (all three slots and
  their revocation bits, ratified Q58), the download-mode and JTAG field group, and the
  anti-rollback pair. `KeyProvenance` (ESP-SEAL.md 4.x) is the same readout in miniature, so
  building the two separately would be two implementations of one thing. Extending
  `firmware/bindings/verify.h` is the only mechanism available for any of it (VERIFY.md 1),
  and the `ESP_EFUSE_*` symbols are revision-family dependent: they must be re-checked
  against the post-v3 table if Q9 moves production silicon, which is a standing requirement
  rather than a one-off.
- **Crates / areas:** in-tree workspace member (Q46: never extracted, never published),
  firmware (consumer).
- **Exit gate (hardware):** on board B, `esp_hmac_calculate()` over a known key in a
  NOT-yet-read-protected eFuse block returns the expected HMAC-SHA256 for published
  test vectors; then the same key is read-protected and the same call still returns
  the same value while software can no longer read the key (proven by attempting the
  read and getting the protected result). Repeated on board A. Provisioning
  procedure written down before board A is touched.
- **Must not break:** the eFuse readout must never render a compiled-in constant (the
  Verify screen's whole credibility rests on it reading true state, and this is the
  milestone that could quietly substitute a default); the `provisioning` feature stays off
  in every release build, asserted by the extended build-graph check, not by convention;
  no ESP-IDF type crosses into notyas-wallet through this crate. **Also: the readout must
  render `not burned` for the three secure-boot digest slots rather than hiding the
  section**, because on 0.2.0 units that is the true and important answer (Q32).
- **Parity rows closed:** none directly; it is the silicon leg under every
  storage row.
- **Implements:** PLATFORM.md section 1 gap; ARCH 2.2 HMAC-eFuse step with the
  red-team's P4-specific citation (IDF v5.5 P4 HMAC peripheral, HMAC_UP purpose 8,
  eFuse blocks 0-5, no chip-revision constraint - unlike the Key Manager).

### 0.2.0-m3 - notyas-wallet sealing and storage engine (host-proven)

- **Depends on:** m1 (KDF parameters, partition geometry, the M6 partial-page result,
  Q5's N and its policy format). Not on m3h: the HMAC step is trait-injected and stubbed
  on host.
- **Settled input (Q2, OWNER-ANSWERED 2026-08-18): `Occupancy::AlwaysFilled` is the only
  mode notyas ships.** The mode switch is still built - ESP-SEAL.md is a general layer and
  `Sparse` remains valid for other embedders - but the product pins AlwaysFilled for every
  user, always, because the filler only hides the wallet count if everyone has it. This
  costs no format change (revised R11) and it is not the duress feature, which is a second
  PIN identity and ships off by default at m13.
- **Settled input (Q5, OWNER-ANSWERED 2026-08-18): the wipe policy is user-settable, which
  IS a format change and lands here.** Full specification in OPEN-QUESTIONS Q5.1-Q5.4. Four
  concrete additions to the on-flash format, all inside this freeze and none deferrable
  past it:
  1. **`policy_log`**, a guarded bit-clear cell array in the `counters` partition
     (16-byte cells: 8 bytes of policy plus an 8-byte `guard_key` MAC), allocated from the
     ledger sector's reserved region and the second reserved sector pair, alongside Q53's
     boot log. **It is the AUTHORITY for the effective policy** - not the superblock -
     because that is what makes a superblock-only rollback unable to weaken the policy.
  2. **Two superblock fields**, `policy_gen` (u32, into the MBZ words at 0x32) and
     `min_pin_len` (u8), joining the existing `wipe_after` and `occupancy` bytes. This
     copy is a MIRROR for fast mount reads and for the Verify screen, covered by
     `body_digest`/`header_mac`, and it is never the authority: if it disagrees with the
     ledger, the ledger wins and mount rewrites it.
  3. **Eight bytes of the canary plaintext** carry a WITNESS copy of the policy, inside
     the AEAD, so a policy in force can be proven to have been authorised by someone who
     knew the PIN. The unlock-time reconciliation table in Q5.1 is an acceptance
     criterion, including the one-generation-behind repair case.
  4. **`failures_base: u32` in the ledger head** (MBZ region at 0x40), making
     `failures = failures_base + len(attempt_entry) - len(attempt_success)`. This exists
     because with wipe DISABLED a failure streak is no longer bounded by the wipe, so the
     128-cell attempt log can overflow with no success to rotate it. With the base carried
     forward, rotation on failure is safe and is not a counter reset. **On a wipe-enabled
     device the value is always 0 and behaviour is byte-for-byte unchanged**, which is the
     property the fuzzer must assert.
- **Settled input (Q22, RESOLVED 2026-08-17):** the record NEVER stores the BIP39
  passphrase. It DOES carry `passphrase_check`, a KDF-separated fingerprint of the
  passphrase-applied root derived under its own HKDF info label - never the seed and
  never anything from which the passphrase or a key can be recovered. It sits inside
  the AEAD, so it is reachable only after a correct PIN unlock and gives an offline
  attacker no passphrase oracle. A mismatch at unlock is a WARNING the user can
  override, never a hard block: entering a different passphrase to reach a different
  wallet is legitimate use.
- **Runs on:** host; gate on board A and board B.
- **Scope:** the new crate and the whole sealing construction.
  - Storage trait (`read_sector` / `erase_sector` / `write_sector` + geometry),
    firmware-implemented later.
  - Two-slot A/B record format; separate plaintext counter region with Trezor-style
    paired one-way bit-clear logs interleaved with guard bits derived from a
    device-bound guard key. **The boot log is one of those cell arrays and is allocated
    HERE, not at m4a** (ratified Q53): it takes its cells from the ledger sector's reserved
    region and the second reserved sector pair rather than shrinking `attempt_entry`,
    `attempt_success` or `pin_gen_log`, adds two head words (`acknowledged_at` and its own
    `log_id`), and is sized against m1's measured M6 limit. Adding it after the freeze would
    be a format change under existing users, and shrinking the attempt log to make room
    would weaken the tail reserve that makes Q5's ceiling of 25 a frozen constant. Counters CANNOT live in the encrypted partition:
    XTS-encrypted partitions require 16-byte-aligned, 16-byte-minimum writes and
    cannot re-program individual bits, which is exactly what the bit-clear scheme
    needs (red-team correction, ARCH 2.5).
  - Full key ladder with known-answer vectors: Argon2id (default-features off) ->
    HMAC-eFuse (trait) -> HKDF-SHA256 with `wipe_epoch` and `seal_seq` in the info
    -> ChaCha20-Poly1305 (default-features off; `getrandom` is one of its DEFAULT
    features and would trip the RNG ban).
  - Nonce uniqueness by construction: seal_seq is device-global monotonic;
    `wipe_epoch` is one-way and in the HKDF info, so a post-wipe re-save under the
    same PIN and slot can never repeat a (key, nonce) pair. On mount,
    seal_seq = max(counter high-water, max valid record seq) + 1.
  - Stale-ciphertext rule: PIN change, wallet delete, and wipe MUST erase the
    now-stale inactive slot of each pair after the new record is committed and
    verified. Erase-after-commit keeps power-loss safety and the fuzzer covers the
    window.
  - Build the filler mechanism unconditionally, and make its USE a runtime mode.
    An unoccupied slot under `Occupancy::AlwaysFilled` holds a genuine AEAD record
    sealed under a device-derived key (`HKDF(filler_root, kdf_salt, RecordInfo)`,
    no RNG), with the same header shape, `pin_gen` identity 0, and a consumed
    `seal_seq` so sequence gaps do not betray occupancy either; under
    `Occupancy::Sparse` an unoccupied slot is simply erased on both sides. **The
    on-flash format is byte-identical between the two modes** (ESP-SEAL.md 3.6), so
    Q2 selects a mode and does not change the format - which is why Q2 no longer
    blocks m3 (revised R11). Delete and wipe rewrite filler rather than leaving
    erased-flash signatures whenever the mode is on.
  - **`Vault::set_policy`, the SET-POLICY operation** (Q5.2's Y1-Y7). Preconditions:
    an Unlocked session AND a fresh `Session::confirm_pin`, which touches no flash and
    consumes no attempt; range validation; a refusal to lower N below the failures already
    accumulated; a refusal to change occupancy; and the Q62 PIN-length precondition on
    disabling wipe, wired as a parameter so either answer is expressible without a code
    change. The commit is one `policy_log` cell program, reusing the existing single-cell
    commit story rather than inventing a second one.
  - **`Vault::remove_pin`** (Q5.5), which is a WIPE followed by leaving the store
    unformatted. There is no "stored wallets without a PIN" state and the API must not
    imply one: the sealing key is derived from the PIN, so with no PIN there is no key.
    The operation returns the list of what it destroyed so the UI can name each item
    rather than summarise.
  - Host power-loss fuzzer: truncate and corrupt the write stream at every byte
    offset and after every erase. Property: mount yields the previous record or the
    new one, never garbage, never a panic - including the PIN-change
    erase-after-commit window **and the SET-POLICY window, where the additional property
    is that the effective policy after any cut is either the old one or the new one and
    is never weaker than both**.
  - The sealing module keeps a clean platform boundary: no ESP-IDF types cross it. The
    reason is not extraction (Q44/Q46: it is never extracted) but testability -
    the host simulator and the fuzz harness need to substitute the Storage,
    DeviceBinding and KdfScratch traits, and that is worth the discipline on its own.
- **Build specs:** WALLET-API.md is authoritative for the crate's types, traits and
  error taxonomy; ESP-SEAL.md is authoritative for the platform-trait contracts this
  crate is written against, and takes the byte layout of `policy_log`, the two superblock
  fields, the canary witness bytes and `failures_base`. m3 cannot close while either is
  absent.
- **Crates / areas:** notyas-wallet (new), GPL-3.0-or-later - it handles key material and
  encodes the security policy, both criteria in Q8's principle at once.
- **Exit gate (hardware):** host fuzz property holds over the full corpus and KDF/AEAD
  KATs are green; **the policy-rollback tests pass - a superblock-only rollback to an
  older mirror does not weaken the effective policy, a forged `policy_log` cell is
  rejected as malformed and resolves to the strict default, and an erased `policy_log`
  falls back to the format-time policy with wipe ON**; AND a feature-flagged firmware test
  command runs the same seal/unseal KAT on both boards with the stubbed HMAC and prints
  PASS - this proves the Argon2 working set actually fits and completes on target within
  the pinned budget, which no host test can prove. miniscript is deliberately NOT in the
  graph yet (it enters at m6), keeping this milestone's audit surface minimal.
- **Must not break:** the nonce-uniqueness invariant, asserted globally by the fuzzer and
  not by argument (the policy work adds writes to the same `counters` partition and must
  not perturb `seal_seq` or `wipe_epoch` accounting); the wipe commit point staying a
  single epoch-cell program; the tail reserve that makes N <= 25 a frozen constant, which
  the new arrays take from the reserved region and never from `attempt_entry`; and
  behaviour on a wipe-ENABLED device being byte-for-byte identical to the pre-policy
  design, which is what `failures_base = 0` buys and what a differential test must show.
- **Parity rows closed:** none alone; it is the layer under all 21 class-b rows.
- **Implements:** storage research candidate A; Trezor norcow and counter design;
  red-team findings on post-wipe nonce reuse, counter placement, and stale old-PIN
  ciphertext; PLATFORM.md shortlist item 1 (as in-tree code; the contribution is
  ESP-SEAL.md, published at m12).

### 0.2.0-m4a - Storage on hardware and PIN unlock (minimal UI)

- **Depends on:** m3, m3h.
- **Runs on:** board B first, then board A. (Under the ratified Q45 the eFuse burn is a
  HOST step performed once per board with `espefuse.py` before this milestone's firmware
  runs, not something the firmware does. It is still permanent, so board B still goes
  first.)
- **Scope:** firmware Storage-trait driver over `esp_partition_*` for the wallets and
  counters partitions; HMAC peripheral binding with a Verify-screen readout of the TRUE
  eFuse state (the key is provisioned by the host, ratified Q45, and the Verify row must
  be able to render "not provisioned"); a blank UNPROVISIONED device refuses to format
  rather than burning anything, which needs `StoreState::Unprovisioned` and its refusal
  screen; `Ui::tick()` plus hold-to-confirm plus the
  horizontal-slop fix (a sideways swipe across a button must cancel the tap);
  minimal functional screens 2 and 16 only (randomized-pad PIN entry with
  anti-phishing words, lock screen); a bare-bones save/unlock path grafted onto the
  existing create flow; the WalletSession type with lock, timeout, and power-off
  wipe; the extended UiRequest protocol (UnsealWallet, PersistWallet, ...) keeping
  all I/O and sealing on the std side.
  Note: anti-phishing words derive from the eFuse key, so they exist only after
  provisioning. A blank stateless device has none, and no screen may imply otherwise
  (R20).
  **Also here (VERIFY.md 6, ratified Q61): the boot counter and the owner-set
  acknowledgement mark**, written into the ledger cells m3 allocated. Two rules are
  acceptance criteria, not implementation detail. The counter increments BEFORE the boot
  self-test runs, so a boot that ends at S-02 is still counted and failures are not a free
  way to advance it. And nothing is written at all while `StoreState` is `Unprovisioned` or
  `Blank` - the row renders `not counted`, never `0` - because SECURITY invariant 2a keeps
  the 0.1.0 stateless property verbatim for a device with no stored wallet, and a
  convenience row does not get to falsify it (R24). Pressing `[ Mark as seen ]` is a flash
  write and carries a `C12 WriteNotice` band; it is post-PIN only, because a coercer who can
  press it erases the gap the counter exists to show.
- **Build specs:** UX-SCREENS.md for screens 2 and 16; ESP-SEAL.md for the driver and
  the provisioning path; VERIFY.md section 6 for the boot counter and the acknowledgement
  mark, and 7.4 for the pre-PIN field set; CORPUS.md for the hardware-in-the-loop procedure.
- **Test method (changed 2026-08-18: Q43's rig is deferred, the gate is not).** The
  power-cut gate below is performed BY HAND: power pulled at the USB connector or a bench
  inline switch, at a scripted delay after the attempt-cell program begins, **repeated at
  least twenty times across the window**, with the ledger state read back over the HIL
  console after each cut and recorded in the milestone note. That is weaker than a
  USB-controlled relay in exactly one way and the note must say so: the timing is not
  repeatable to the millisecond, so the window is SAMPLED rather than swept. The rig moves
  to 0.3.0, where the sweep becomes exhaustive. The HIL test-mode console still ships
  build-feature-gated and off by default, with a release gate asserting its symbols are
  absent from the shipped binary (Q41) - and it is now load-bearing, because it is how the
  manual cuts are read back.
- **Crates / areas:** firmware, notyas-wallet (session), notyas-ui (minimal).
- **Exit gate (hardware), on both boards:** create a wallet, power cycle, unlock;
  wrong PIN decrements the counter and the decrement survives a reboot AND a power
  cut taken mid-decrement; **wipe-on-N at the default N = 15 destroys the records and bumps
  the epoch**; a PIN change leaves no stale old-PIN ciphertext (proven by raw flash
  readback, not by code inspection); the stateless path still writes nothing (proven by a
  flash readback diff on a dev board); the Verify screen reports the real eFuse HMAC-key
  state, not a constant. **Two additions from the settable policy (Q5):** a SET-POLICY
  change survives a power cut taken at each of its seven steps with the effective policy
  never weaker than both the old and the new value, and a device with wipe DISABLED
  survives 128+ consecutive failed attempts without overflowing the attempt log or losing
  the accumulated count (the `failures_base` rotation path).
- **Must not break:** SECURITY invariant 2a's stateless property on a blank or
  unprovisioned device - this is the milestone that adds a boot counter and a policy log
  to the same partition, and both must write nothing before the ledger is formatted (R24);
  the 0.1.0 golden touch flows and the masking pixel tests (two different mnemonics must
  still render byte-identical masked frames); the boot budget, which the counter's single
  early bit-clear program must not measurably move; and the rule that no screen implies
  anti-phishing words exist on an unprovisioned device (R20).
- **Parity rows closed:** two-part main PIN (b), anti-phishing words (b),
  scramble keypad (a), secure logout (a), 13-attempt brick (c - documented
  equivalent: wipe-on-N plus the device-bound ladder), wrong-PIN actions (c - same),
  Nuke Device (c - crypto-erase equivalent, device stays reusable), login countdown
  (b, partial: escalating delay only).
- **Implements:** storage research 3.3; audit firmware infrastructure 1-2; the
  red-team m4 split.

### 0.2.0-m4b - Wallet management UI

- **Depends on:** m4a.
- **Runs on:** board A and board B (both geometries are a gate), plus uisim.
- **Scope:** per-screen module restructure of notyas-ui (each screen exports
  layout/regions/draw/activate; the enum match becomes one-line delegation; the
  closed State enum, exactly-one-state-alive and drop-equals-zeroize are KEPT); the
  shared danger-modal component with three grades (confirm / hold / typed-name);
  screens 3, 5, 7, 15 (wallet list, backup-verify quiz, wallet home, danger modals);
  create and restore flows gain the mandatory backup-verify gate and the explicit
  "Save (PIN-protected)" vs "Use once, keep nothing" fork; delete with typed-name
  confirmation. **Seed import by word entry lands here** - it was always this milestone's
  restore flow, and it is the only part of the retired m9 that 0.2.0 still needs (R26).
  **The capacity line is settled and shrinks (Q2(a)):** the device shows the static
  maximum ("holds up to 8 wallets") and NEVER the count in use on any pre-PIN surface or
  on the Verify screen, which read `present` or `blank`. After a successful unlock the
  wallet list shows the real wallets, because that is post-PIN and leaks nothing to a
  coercer who does not have the PIN.
- **Also in scope, new at the 2026-08-18 re-scope: the S-44 wrong-PIN policy sub-screen
  becomes a live editor, and a PIN-removal flow lands beside it** (owner's Q5 answer).
  Four things are acceptance criteria rather than copy suggestions:
  1. **The threshold is always shown** (Q37) and every number on the screen is a format
     string, because N is now runtime state.
  2. **The power-cut disclosure is on the screen**: an interrupted verification consumes
     an attempt even when the PIN was correct, so on a portable device the counter can
     advance with no wrong PIN entered.
  3. **Disabling wipe states the arithmetic at the moment of the change, not in a manual.**
     The screen computes the warning from the user's ACTUAL PIN length - never a generic
     sentence - naming the keyspace, the measured per-guess cost from m1 and the resulting
     exhaustive-search time, then requires a typed confirmation and **offers the
     longer-PIN path as an action rather than only accept or cancel** (PIN-MODES.md). **No
     PIN-length precondition is enforced**: the owner decided the device states the trade
     and does not withhold the setting (Q62). The floor is still implemented as a
     parameter defaulting to "none", so revisiting it is a constant rather than a rewrite.
  4. **PIN removal names what it destroys, individually** (Q5.5, PIN-MODES.md): every
     stored wallet, every multisig registration (not re-derivable, and with Q14 deferred
     there is no backup), all labels and settings, and the anti-phishing words, with
     **counts read from the store** rather than a generic phrase. It is presented as what
     it is - reverting the device to 0.1.0 stateless operation - and never as "turning off
     the PIN", because the sealing key IS the PIN and there is no third state. **It must
     not be worded as a security downgrade**: the device it produces stores nothing, which
     is the safest state the hardware has, and the copy that says otherwise teaches the
     wrong instinct about the setting next to it.
- **Also in scope: the S-46 Verify-device rebuild**, which is the largest single screen
  0.2.0 adds and is specified end to end in VERIFY.md sections 10-11: the three row kinds,
  the six frozen sections, the frozen field order, the viewport pager, the identity /
  firmware / flash rows, the on-demand reserved-space scan with its C3 Busy screen (Q57),
  and the CI assertions in 11.7. Its design contract is binding and is what makes the screen
  worth having: raw values shown in full, no verdicts or advice beside a value, and a field
  order that does not move between builds so two units can be compared side by side rather
  than read. **Settled inputs, no longer conditional:** storage rows read `present` /
  `blank` only, permanently and for all users (Q2(a)); the `wallets` raw digest IS
  permitted pre-PIN and joins the pre-PIN identity field set with its CI golden list
  (Q56); the secure-boot section prints all three digest slots as `not burned` on a 0.2.0
  unit, which is the true and important answer (Q32/Q58); the `media` partition gets a
  span and digest row; S-46 keeps full body width at 800x480 (Q55); three new `RegionId`
  values land (Q54).
- **Build specs:** UX-SCREENS.md is the per-screen build spec and owns the screen inventory,
  the component library and the copy vocabulary; **VERIFY.md is authoritative for S-46's
  content, row set, field order and CI assertions**, and UX-SCREENS' own S-46 sketch is
  superseded in detail (R25). UX.md remains the design rationale behind both.
- **Acceptance criteria carried from Q22 (RESOLVED):** the "your passphrase is not
  stored" warning appears at all three placements - passphrase entry during creation
  (before the wallet is saved), the post-creation backup screen, and every restore or
  unlock flow that asks for a passphrase - with the required substance in plain
  words: the passphrase is not stored on this device; restoring this wallet needs
  BOTH the seed words AND the passphrase; a seed backup alone will not recover it;
  the device cannot help recover a forgotten passphrase. A one-time explicit
  acknowledgment gates the first passphrase wallet save, so the warning cannot be
  skipped by muscle memory. The `passphrase_check` mismatch renders as an
  overridable warning, and a UI test asserts both the warning text and the override
  path.
- **Crates / areas:** notyas-ui, firmware, tools/uisim.
- **Exit gate (hardware):** full create -> verify-backup -> save -> lock -> unlock ->
  delete walk on BOTH boards; UI flow tests driven through touch+tick at both
  geometries; masking pixel tests extended to PIN and session screens (two different
  mnemonics must render byte-identical masked frames); uisim tour renders every new
  screen; S-46 renders its frozen field order at both geometries with identical hex line
  breaks, every value read from the running system (a planted compiled-in constant fails
  CI), and the reserved-space scan completing on both boards within VERIFY.md 2.5's
  expectation or the discrepancy explained. **Three additions from the re-scope:** the
  wipe-policy editor round-trips (set N, power cycle, the new N is in force and is what
  the screen shows); disabling wipe shows the arithmetic for the PIN actually set and
  requires the typed-name modal; and PIN removal destroys everything it named, proven by a
  raw flash readback showing the store unformatted and the device stateless again.
- **Must not break:** no pre-PIN surface may regain a wallet COUNT, which is the whole
  cost Q2(a) paid for and is the easiest thing in this milestone to reintroduce by
  accident - a CI assertion over the pre-PIN field set is the enforcement, not review; the
  masking pixel tests; the closed State enum with exactly-one-state-alive and
  drop-equals-zeroize, which the per-screen restructure must preserve rather than relax;
  and VERIFY.md's rule 2, which forbids a verdict or advice sentence beside a value on
  S-46 (R25) - the wipe-policy caveat belongs on S-44 where it can change behaviour, not
  on the instrument panel.
- **Parity rows closed:** Seed Vault (b - as PIN-ladder-sealed slots, see R9),
  device nickname / home XFP / idle timeout (a), calculator login (a, if kept),
  View Identity (a), Destroy Seed (a), Selftest and maintenance menu (a/b),
  import seed by word entry (a), BIP-39 passphrase (a).
- **Implements:** UX research screens 2-7/15/16; audit UI section 4.

### 0.2.0-m5 - SD subsystem

- **Depends on:** m1. Independent of m3/m4a - can run in parallel on the other board.
- **Runs on:** board B (1-bit SDMMC) and board A (4-bit SDMMC).
- **Scope:** per-board `sd_init()` / `sd_deinit()` joins the board surface; FATFS/VFS
  mount-on-demand lifecycle tied to the signing and export flows; the file-picker
  screen chrome (screen 9's shell; its PSBT-specific behavior is m6 - R15); accepted
  file-size caps; SD export of xpubs and descriptors from the existing export
  screens; the "Verify external address" file input path (screen 8).
  Airgap cross-check to re-assert here (R16): the microSD pins are disjoint from
  each board's C6 SDIO bank - board A uses SDMMC slot 0 on GPIO39-42/43/44 with a
  power gate on 45 while the C6 sits on 14-19; board B uses 1-bit on GPIO39/43/44
  while the C6 sits on 49-54. SECURITY.md invariant 1's per-board sentence ("the
  SDIO host is never configured on <C6 pins>") therefore survives m5 verbatim, and
  the milestone note must say so with the pin numbers.
- **Crates / areas:** firmware (board surface), notyas-ui.
- **Exit gate (hardware), on both boards:** insert a card, list files, read a file,
  write a file, remove the card at any idle moment with no consequence; the mount is
  never held outside an SD flow (asserted in code and tested); the C6-pin
  non-overlap re-verified against the running pin configuration; the FATFS
  accepted-risk text landed in the SECURITY plan text.
- **Must not break:** SECURITY invariant 1's per-board "the SDIO host is never configured
  on the C6 pins", re-verified against the RUNNING pin configuration with the numbers in
  the milestone note (R16) - this is the milestone with the only plausible way to break it;
  the mount never being held outside an SD flow, asserted in code and tested; and the
  0.1.0 idle-repaint claim, which the file picker's chrome must not violate.
- **Parity rows closed:** microSD file transport underlying section 3 and 4 rows;
  dual-microSD-slots (c - documented equivalent: the `-signed` filename convention
  on one slot).
- **Implements:** features.md airgap-IO research; audit firmware infrastructure 3.

### 0.2.0-m6 - PSBT engine and single-sig signing end to end

- **Depends on:** m2, m4a, m5. Q23-Q26 (change gap bounds, expert overrides, PSBT size
  cap, `-final.txn` byte format) are all ratified; the only thing left to settle inside
  this milestone is the SCOPE of the stateless multisig refusal, whose recommended answer
  - the broader one, because without a registration the input's witness-script membership
  is unverifiable too - is recorded in Q12.
- **Absorbed from the retired m9 (R26): the stateless / temporary seed session.** A
  session need not come from a sealed slot, so a seed loaded transiently by dice or
  mnemonic entry can sign a PSBT with storage never touched (Q12). It belongs here rather
  than in a seed-lifecycle milestone because everything it exists for is signing.
  **Stateless multisig claims are REFUSED with no expert override** - Q24 makes that a
  hard rule and SECURITY invariant 7 is written without exceptions.
- **Runs on:** board A and board B.
- **Scope:** miniscript enters the dependency graph with its vetting note;
  the notyas-wallet policy engine implementing ARCHITECTURE 5.3 checks 1-3 and 5-10
  (multisig check 4 lands in m7); descriptor-exact change detection with gap bounds;
  the adversarial PSBT corpus (output substitution, fee inflation, change-path
  ransom, wrong network, sighash games, duplicate and already-finalized inputs,
  missing prev-tx, oversized and truncated files, non-address outputs); the
  differential signing suite against Bitcoin Core `walletprocesspsbt` plus
  `testmempoolaccept` on regtest; screens 9-11 (load, review, deliver-to-SD);
  hold-to-sign; refusal screens with their exact text asserted in CI.
  The load screen takes its PSBT from a **source abstraction** (SD today, QR-in
  later) so m11 is an added source, not a rewrite of the flow (R3).
  Review-screen requirements that are gates, not polish: full address in mono
  chunked to the end, one page per output, non-address outputs rendered explicitly,
  nLockTime and RBF surfaced, the >10-output overview page, no sign affordance until
  the last page has been visited, and the lookalike-address warning (compare each
  external output against our own derived addresses in the gap window - Q42), which
  counters an active attack that showing the full address only partly mitigates.
  Expert settings may tune WARNING thresholds and may never disable a REFUSAL (Q24).
  **Fee policy is pinned to concrete numbers (Q13, researched 2026-08-18):** warn at
  >= 5% of the amount SENT (Coldcard's warn line, but with the amount actually leaving the
  wallet as the denominator rather than `total_value_out`, so a self-transfer with a large
  fee still warns), warn at >= 500 sat/vB (4x tighter than Trezor's 2,000 sat/vB confirm
  line), warn at >= 100,000 sat absolute (which is what the other two axes both miss on a
  consolidation), and REFUSE only on a negative fee and on >= 25,000 sat/vB, the latter
  pinned to rust-bitcoin's own `Psbt::DEFAULT_MAX_FEE_RATE` so the device can never sign
  something its own dependency will refuse to extract. **Coldcard's hard 10% refusal is
  deliberately not adopted**: it is wrong when sweeping a nearly-dust UTXO, and Coldcard
  itself makes it disable-able, which under Q24 is an override on a refusal and therefore
  forbidden. All three values are always displayed whether or not a threshold fires.
- **Build specs:** WALLET-API.md (policy engine, verdicts, limits), CORPUS.md (the
  corpus cases and their expected verdicts and rendered text - m6's exit criteria are
  defined there, not here), UX-SCREENS.md (screens 9-11).
- **Crates / areas:** notyas-wallet, notyas-ui, firmware.
- **Exit gate (hardware):** every corpus case triggers its exact expected verdict and
  rendered text; the differential suite is byte-identical to pinned vectors and
  Core-verified/accepted on regtest (byte-equality against Core's own ECDSA output
  only if Q3 adopted low-R grinding, and never for Schnorr); a full Sparrow SD round
  trip on testnet across all four script types on both boards, including a
  deliberately hostile PSBT refused with the right screen; the post-sign miniscript
  interpreter gate demonstrably wired (mutation test: corrupt a signature, the gate
  catches it) and using a sighash recomputed independently of the signing path.
- **Must not break:** SECURITY invariant 7, which is written without exceptions and is the
  sentence this milestone is most able to falsify - no Settings toggle may reach a
  refusal, and the corpus asserts the exact refusal text rather than merely a non-zero
  exit; the post-sign gate using a sighash recomputed independently of the signing path
  (sharing that code would make the mitigation circular, which is the whole point of it
  existing under the deterministic-nonce tradeoff); the m4a unlock and session behaviour,
  which this milestone consumes and must not alter; and the PSBT size cap actually
  bounding RAM against the 720x720 framebuffer plus the Argon2 arena.
- **Parity rows closed:** PSBT signing via microSD (a), batch signing (a),
  output/input explorer (a), on-device finalization (a), max fee guard / sighash
  checks (a), taproot send-to-P2TR (a), taproot keyspend BIP-86 (b, partial - see
  section 7 for the tapscript/MuSig2 deferral), PSBT via NFC (c - QR plus SD
  equivalent), testnet4/regtest toggle (a), temporary and stateless seeds (a, absorbed
  from m9).
- **Implements:** signing research sections 2 and 5; every historical signer attack
  in ARCH 5.3; red-team fault-injection mitigation (the post-sign gate is a security
  control, not a formality).

### 0.2.0-m7 - Multisig (P2WSH sortedmulti)

- **Depends on:** m6, m4a.
- **Runs on:** board A and board B.
- **Scope:** sealed registry records bound to the owning wallet slot; descriptor and
  Coldcard `.txt` import with membership, M-of-N, script-type and derivation
  verification; screen 12; multisig change verification (check 4) wired into the
  policy engine, deriving from the STORED registration and never from PSBT-supplied
  xpubs; multisig address verification in the explorer; BIP-48 xpub export packaging;
  first-receive-address display for manual cross-device comparison (the poor
  person's BSMS round 2).
- **Crates / areas:** notyas-wallet, notyas-ui, firmware.
- **Exit gate (hardware):** the corpus gains the xpub-substitution and
  multisig-change-confusion cases and both are refused; on hardware, register a
  2-of-3 P2WSH with Sparrow plus two other signers on testnet, verify the first
  receive address cross-device, sign as one cosigner (partial PSBT emitted, other
  signatures preserved), then sign as the completing cosigner (finalized,
  `-final.txn` written); registry delete requires the typed name.
- **Must not break:** the m6 single-sig corpus, every case of which must still produce its
  exact verdict once check 4 joins the pipeline; the rule that multisig change is derived
  from the STORED registration and never from PSBT-supplied xpubs, which is the 2021
  attack and is invariant 7's hardest clause; and the stateless refusal, which multisig
  support makes newly tempting to soften.
- **Scope note (2026-08-18):** BSMS is not built at all, not even speculatively at m12
  (Q15 deferred whole). The first-receive-address cross-device comparison is the shipped
  answer and it is mandatory rather than advisory, which is what makes the deferral
  defensible.
- **Parity rows closed:** multisig registration (b), trust policy knobs (a), export
  XPUB / create airgapped (a), descriptor export (a).
- **Implements:** signing research 3; the benma disclosures (2021 xpub substitution,
  2020 isolation bypass) and the 2019 Coldcard change-confusion defenses.

### 0.2.0-m8 - Animated QR out (UR2, plus BBQr interop)

- **Depends on:** m6 (something to emit), m1 (the UiRequest::Qr fix).
- **Runs on:** board A and board B, plus a webcam and Sparrow.
- **Scope:** `foundation-ur` integration emitting `ur:crypto-psbt` (the legacy type
  name, for ecosystem compatibility); tick-driven frame advance in the main loop;
  pause, three speed steps, density steps and an `i/j` frame counter on screen 11;
  default max fragment 200 bytes; encoder round-trip tests against reference vectors;
  reuse of the 0.1.0 static QR path for frame rendering. BBQr output alongside UR2
  for Coldcard-family interop, subject to the `bbqr` crate clearing the dependency
  ledger (section 6). The final network transaction is also offered as a QR so a
  phone can broadcast it - this is the honest equivalent of Coldcard's NFC PushTX.
  One UR implementation only: `foundation-ur`, not `ur` (R5).
  Once the QR player exists, S-46's `[ Show as QR ]` rides it: the complete Verify readout
  as a `notyas-verify/1` payload, so the values can be captured and compared off-device
  instead of transcribed (VERIFY.md 7.2). It is an export affordance, not a new capability -
  the screen still presents and never judges.
- **Crates / areas:** notyas-wallet (chunking parameters), notyas-ui, firmware.
- **Exit gate (hardware):** host round-trip against reference decoder vectors;
  Sparrow webcam-scans a signed multisig PSBT off BOTH boards at default and lowest
  density; the "idle device performs zero repaints outside an active animation"
  claim re-proven on hardware.
- **Must not break:** the "idle device performs zero repaints outside an active
  animation" claim, which a tick-driven frame advance is the obvious way to violate and
  which the gate re-proves on hardware; invariant 2a's QR corollary - QR display covers
  PUBLIC values only, never a mnemonic, xprv, seed or WIF (Q17 declines SeedQR
  display-out, and this is the milestone with a QR encoder in hand); and the static QR
  path 0.1.0 already ships, which the animated player reuses rather than replaces.
- **Parity rows closed:** PSBT via QR/BBQr - display leg (b); NFC PushTX (c -
  QR-for-phone equivalent); QR display density improvement over the Q's 320x240 (a,
  exceeded).
- **Implements:** signing research 4 (transport sizing); UX commandment 9;
  CAMERA.md's decode-stack survey on the encode side.

### 0.2.0-m9 - RETIRED 2026-08-18 (id kept, not renumbered)

**This milestone no longer exists.** The owner's 2026-08-18 scope instruction removed most
of what it carried, and what survived belonged in milestones that already existed. **The id
is retired rather than reused or renumbered, so every existing reference to m10, m11, m12
and m13 stays valid** (R26).

Where its contents went:

| Was in m9 | Now |
|---|---|
| Seed import by word entry, BIP-39 passphrase flows | **m4b** - they were always that milestone's restore flow |
| Temporary and stateless seeds | **m6** - everything they exist for is signing |
| `seedqr` decoder | **m11** - the only consumer, and it is decode-only in 0.2.0 |
| BIP-85 derived seeds | **0.3.0** (section 7.4) |
| Seed XOR split, recombine and the Q33 dice default | **0.3.0** (section 7.4) |
| Lock Down Seed | **0.3.0** (section 7.4) |
| Seedless encrypted backup | **0.3.0** with Q14, deferred whole |

**One consequence must not be lost with the milestone.** m9 was where the wipe-copy
honesty requirement was going to be satisfied by a backup. There is now no backup at all
in 0.2.0, so the requirement lands entirely on copy: every wipe surface names multisig
registrations, labels and settings as destroyed and not recoverable (m4b's S-44 and S-06,
m13's S-48/S-48b). See Q5 correction 1 and Q14.

### 0.2.0-m10 - Addresses and exports

- **Depends on:** m7 (multisig-aware address verification), m5 (SD export).
- **Runs on:** board A and board B.
- **Scope:** the "works with your software" and anti-phishing surface, **trimmed at the
  2026-08-18 re-scope to what a working wallet cannot do without** (R28):
  - Address explorer completion: change-address tab, per-address QR, explicit
    derivation path, CSV export of a bounded address range. **The detached signature on
    that CSV moves to 0.3.0 with message signing**, since it is the same machinery.
  - Verify Address Ownership: given an address (typed, or read from an SD text
    file), search singlesig and multisig accounts within a bounded gap and answer
    "yours at m/84'/0'/0'/0/N" or "NOT MINE". **Kept**: it is the anti-phishing control
    that makes a receive address safe to use, which is part of a working wallet rather
    than a parity nicety.
  - Watch-only wallet exports: named formats (Sparrow, Bitcoin Core
    `importdescriptors`, Electrum, Nunchuk) plus generic JSON, over SD and QR.
    **Kept**: without these the wallet cannot be used with any coordinator, which makes
    them load-bearing rather than optional.
  - **Moved to 0.3.0:** BIP-137 message signing and its on-device verification, and
    BIP-322 signing with proof-of-reserves PSBTs. Neither is needed to hold, verify or
    spend coins, and BIP-322 in particular is a second signing surface with its own
    review-UI problem. Section 7.4 carries both with this reason.
  - Class-c on-device text is exactly two lines under the refined Q11: camera absent and
    battery. **NFC is documentation only** - nobody expects NFC on this device, so a line
    saying it is missing answers a question nobody asked and dilutes the two that matter.
- **Crates / areas:** notyas-wallet, notyas-ui, firmware.
- **Exit gate (hardware):** on both boards, export a watch-only file that Sparrow and
  Bitcoin Core each import without editing; verify a known-owned and a known-foreign
  address with the right verdicts; the address explorer's QR renders a receive address
  that a phone wallet scans and resolves to the same string shown on screen.
- **Must not break:** UX commandment 1 - the full address is always shown, chunked, to
  the end, and the truncated navigation list keeps its "never check an address from this
  list" statement (Q38); invariant 2a's QR corollary, since this milestone adds
  per-address QR rendering; and the bounded-gap discipline on the ownership search, which
  must refuse rather than scan unboundedly.
- **Parity rows closed:** address explorer (a), verify address ownership (b),
  export watch-only wallet (a), view identity (a).
- **Implements:** PARITY.md section 5; UX commandment 1 (address poisoning is why
  the full address is always shown, chunked, to the end).

### 0.2.0-m11 - Camera scan-in (board A only; hardware gates deferred until a module exists)

- **Depends on:** m6 (a PSBT source abstraction to plug into) and, for the host half,
  nothing else. Q6, Q47, Q48 and Q49 are all settled; Q50 is a purchase the owner has
  agreed to make. **m1's spike is no longer a predecessor - it moved INTO this milestone
  as m-camera-0** (R27), because holding the whole spine open for a module purchase was
  never a good trade.
- **Split into two halves, and this is the operative structure of the re-scope.**
  - **The HOST half needs no hardware and proceeds now, in lane B:** the cargo `camera`
    feature and its `compile_error!` board guard, the separately named artifact and its
    link-map gate (Q47), the `seedqr` decoder absorbed from the retired m9, the autodetect
    classifier including the CompactSeedQR fix Q48 requires, the ingress validator, and
    both fuzz harnesses (the validator's and - per Q48 condition 2 - the seedqr decoder's,
    which is brand-new code doing 11-bit unpacking on attacker-supplied bytes).
  - **The HARDWARE half is every step that needs a module** and is marked [HW-CAMERA]
    below: m-camera-0 (the replug experiment), m-camera-2 (esp_video bring-up), and the
    on-device parts of m-camera-3..5.
- **Runs on:** board A only, **and only once a module exists**. Board B physically cannot
  take a Pi-class module; its camera is Elecrow's 24-pin SC2336, deferred to 0.3.0
  (CAMERA.md 2.3). The mating part for board A is a 15-pin, 1.0 mm pitch Pi-compatible
  OV5647 module (Q50); an IMX219/IMX708 or a 22-pin CM4 ribbon will not work.
- **If the module does not arrive before the release freeze**, 0.2.0 ships the camera
  variant BUILT and NOT hardware-verified, BOARDS.md's support column says exactly that,
  and the artifact carries the statement. It is neither silently dropped nor silently
  claimed. This is the standing "hardware-verified or not claimed" rule applied to a
  variant rather than a board.
- **Scope:** CSI capture bring-up with `esp_cam_sensor` + `esp_video` on the
  Waveshare 4B J1 connector with an OV5647 Pi-camera-class module; ISP Y-plane
  grayscale straight into `rqrr`; static scan-in of SeedQR/CompactSeedQR, plain word
  lists, descriptors and addresses; animated scan-in of UR `crypto-psbt` (and BBQr
  if the crate clears the ledger); a viewfinder screen with an honest per-board
  support statement. Compile-time feature, OFF by default, and under Q47 a separately
  named and separately hashed build VARIANT rather than a runtime capability; the base
  artifact is proven camera-free by the link-map gate, not by a hash comparison
  against itself.
  USB-UVC is rejected in all builds: it turns the signer's only data port into a
  parser of untrusted device descriptors (USBFuzz, USENIX Security 2020), and
  neither board can even power a webcam without an external hub.
- **Build specs:** CAMERA-HW.md for the bring-up detail behind CAMERA.md's decision;
  UX-SCREENS.md for the viewfinder and scan screens.
- **Crates / areas:** firmware (new board-surface entry `camera_init`), notyas-ui,
  notyas-wallet (source abstraction), `seedqr` (**MIT OR Apache-2.0**, per Q8; decode is
  what 0.2.0 uses and the encode half stays test-vector-only under Q17), `rqrr`.
- **Exit gate, split by what it needs:**
  - **Meetable today, no module required:** the base artifact is provably free of camera
    code by the LINK-MAP assertion below; both fuzz harnesses run clean over their
    corpora; the autodetect classifier correctly types every payload class including
    CompactSeedQR (byte mode, 16 or 32 raw bytes with embedded `0x00`, which the original
    all-digits rule could not classify - Q48 condition 1); the `seedqr` decoder matches
    SeedSigner's published vectors; the per-board and per-variant support statement lands
    in BOARDS.md and on the Verify screen.
  - **[HW-CAMERA] m-camera-0:** the replug experiment - module into J1, esp-video
    `capture_stream`, pass or fail recorded with the module part number. If frames are
    garbled, apply CAMERA-HW.md's 25 MHz clock-mismatch triage rule before concluding
    anything about the driver.
  - **[HW-CAMERA]** on board A, scan a CompactSeedQR and restore the expected
    fingerprint.
  - **[HW-CAMERA]** on board A, scan an animated UR `crypto-psbt` emitted by Sparrow at
    Sparrow's default density and sign it.
  **The absence gate, settled by the ratified Q47.** It cannot be a hash comparison:
  esp-idf-sys metadata cannot be feature-gated, so the esp_video C sources sit in every
  build's component tree and only the per-board sdkconfig overlay turns them off. The
  gate is therefore a LINK-MAP assertion that no camera symbol reaches the image, plus a
  pinned hash for each separately named artifact. **That is verification of absence
  rather than absence, and the release notes must say which property is being claimed.**
  The same link-map job additionally asserts `nvs_flash_init` and `nvs_open` are absent
  (ratified Q7), which turns the never-mount-NVS invariant from prose into a linker
  check. Two loose ends this creates: REPRODUCIBLE.md 3.5's artifact set has no camera
  variant row and no occurrence of the word "camera" at all, and BOARDS.md's support
  table needs the per-variant column. Both land with this milestone.
- **Must not break:** the structural rule that **a camera cannot approve anything** - no
  scanned payload may set a flag, skip a review page, shorten a hold or change a setting,
  which is the answer to the entire "scan this QR to configure your device" attack shape;
  the base artifact's byte-identical reproducibility, which the variant must not perturb;
  a scanned seed following exactly the same path as a typed one, with no shortcut for
  having arrived by camera (Q48); and the m6 sign flow, which gains a source and is not
  rewritten (R3).
- **Parity rows closed (only if the [HW-CAMERA] gates are met):** scan seed via QR
  (c -> b), PSBT via QR scan-in (c -> b), QR scanner module (c -> b), verify-address input
  ergonomics (b). Key Teleport receive stays deferred - it needs protocol work beyond
  capture. **If the module does not arrive, all four stay class c with the documented
  gap**, which is the state 0.2.0 would otherwise have shipped in anyway.
- **Implements:** CAMERA.md rank 1 (CSI + OV5647), its USB-UVC rejection, and its
  section 7 scope proposal.

### 0.2.0-m12 - Reproducible builds, and the documents that are the contribution

- **Depends on:** m4a (the sealing layer proven on hardware), m3h. **No longer depends on
  m9**, which is retired (R26). Under the split licence (Q8) and Q46's re-decision, this
  milestone's contribution scope is **documents and a recipe, not crates**: `esp-idf-hmac`
  and `seedqr` carry permissive headers from their first commit but are published at
  0.3.0, because a `cargo publish` is cheap to defer and a maintenance obligation to
  strangers during a release is not.
- **Runs on:** two independent build machines; boards for the artifact check.
- **Scope:**
  - Reproducible build proven: the per-board images rebuild bit-identically on a
    second machine from a clean checkout (pinned IDF, pinned nightly, `--locked`,
    `-Zbuild-std` pinning, path remapping, `components_esp32p4.lock`). Published as
    the **Reproducible Rust-on-ESP-IDF recipe** (PLATFORM.md item 6), modeled on
    Jade's REPRODUCIBLE.md - the first public one for the Rust + esp-idf-sys stack.
    This directory's REPRODUCIBLE.md is the authoritative recipe and verification
    procedure; m12 and m13 cannot close while it is absent.
  - **The per-board verification manifest** `notyas-<ver>-<board>-VERIFY.json` (ratified
    Q52): emitted by the container build, listed in the signed SHA256SUMS.txt, and itself
    rebuilt bit-identically on the second machine - a published artifact that is not
    reproduced is a hole in the chain this milestone exists to close. It carries the image
    offsets, lengths and both digests per member of the trusted path, which is what makes
    the device's numbers checkable at all and what settles the content-digest versus
    file-digest confusion REPRODUCIBLE.md 4.3 names as the likeliest support question.
    REPRODUCIBLE.md 3.5's artifact table takes this row and the ratified Q47 camera-variant
    row in the same edit.
  - **Nothing is published to crates.io during 0.2.0** (Q46). The sealing layer stays a
    module inside notyas-wallet and is never extracted (Q44, re-decided on its merits
    under the split licence); `esp-idf-hmac` and `seedqr` are in-tree, permissively
    licensed and publishable, and publish at 0.3.0; `bsms` is not built at all (Q15).
  - **ESP-SEAL.md is published as the contribution instead**, in-repo: the byte-exact
    on-flash format, the mount/unlock/seal/wipe state machine, the power-loss analysis,
    the honest attempt-counter trust model, the attack analysis, and - new at the
    2026-08-18 re-scope - **the settable-policy design of Q5.1-Q5.4**, which is the part
    of the format most likely to be useful to someone else and the part where getting the
    authentication wrong is easiest. Any project can read it and reimplement freely; a
    document does not impose its licence on an independent implementation of the ideas it
    describes. Clean-room constraint unchanged: Trezor's and Jade's code are copyleft and
    are never ported.
  - The adversarial PSBT vector files ship **CC0-1.0 with per-file SPDX headers** (a
    `.psbt` cannot carry one inline, so each is paired with a sidecar or a per-directory
    `REUSE.toml` entry); **the harness and generator stay GPL-3.0-or-later**, because they
    encode our verdict policy (Q39, completed). **The offer of selected cases upstream to
    HWI and psbt_faker is permitted (Q51, answered yes) and is 0.3.0 work**, as is the
    no_std BBQr decode PR. The permission is recorded now so neither is blocked on a
    second conversation later.
  - **The reproducible-build recipe's copyable artifacts - the container definition and
    the CI workflow - are MIT OR Apache-2.0**, because their entire purpose is to be
    lifted into someone else's repository and a snippet a reader must license-audit before
    pasting is a recipe nobody follows.
- **Crates / areas:** tools, CI, docs. No crate publications in 0.2.0 (Q46).
- **Exit gate (hardware):** a second machine reproduces every named artifact
  bit-for-bit, including the camera variant (Q47) and the VERIFY.json manifest; the
  reproduced image flashes and boots with the same Verify-screen SHA256 on both boards;
  REPRODUCIBLE.md and ESP-SEAL.md are complete enough that an outside reader could follow
  the recipe and reimplement the format without asking a question.
- **Must not break:** `partition-table.bin`'s published hash, which is frozen at m1 and
  which verifiers are told is a stable first sanity check; the pinned toolchain and IDF
  versions, which are the reproducibility claim rather than an implementation detail; and
  the rule that every published artifact is also a reproduced artifact - adding a
  published file without adding it to the rebuild matrix is a hole in the exact chain this
  milestone exists to close.
- **Parity rows closed:** tamper-evident supply chain (b/d - the notyas answer is
  reproducible builds plus user-flashable firmware, not a bag number); firmware
  upgrade verification (b, partial - completed at m13).
- **Implements:** PLATFORM.md shortlist items 1 and 6 in full; items 2, 3 and 5 as
  licence-and-header work whose publication lands at 0.3.0; the owner directive to ship
  genuine community contributions.

### 0.2.0-m13 - Hardening closeout and the 0.2.0 public release

- **Depends on:** everything.
- **Runs on:** board A and board B, plus release units.
- **Scope:**
  - Duress PIN and the Kill Key (Q2(a), owner-answered). The record-format half shipped
    at m3 and `Occupancy::AlwaysFilled` is already the only mode; this is the
    PIN-classification and UX half, and the duress PIN itself is **OFF by default**. The
    permanent cost - degraded storage readout for every user, duress or not - is already
    paid at m4b and must not be walked back here.
  - The plan texts land as the real documents: docs/SECURITY.md, docs/ARCHITECTURE.md
    and docs/BOARDS.md rewritten from plan-0.2.0/, then re-audited claim by claim
    against what is mechanically enforced. Required honest amendments to the 0.1.0
    text, stated as amendments and not silently: invariant 2 splits into 2a/2b
    (stateless becomes opt-in), and its corollary "no private-key export path at
    all" is restated as "no key material is ever written to flash in plaintext, to
    SD, or into any QR; derived private values appear only on screen behind the
    existing reveal gates" (R19).
  - Extended boot self-test: seal/unseal KAT and a reduced-cost KDF KAT with the
    cost rationale documented in the source (the full-cost KDF does not fit the 1 s
    self-test budget).
  - Verify screen finalized against VERIFY.md: storage state as `present` / `blank`
    (Q2(a)), HMAC-key state as actually read, **all three secure-boot digest slots
    rendering `not burned`, which on a 0.2.0 unit is the true and important answer**, the
    per-board and per-variant camera support statement, and the final frozen field order.
    VERIFY.md section 9's self-reporting wording - what this screen can and cannot prove,
    given that it is produced by the software under suspicion - lands verbatim in
    docs/SECURITY.md and VERIFYING.md; it is the sentence that keeps the screen honest, it
    is not optional, and **with Secure Boot deferred it carries more weight than it was
    written to carry**, because secure boot was the one row that did not depend on the
    firmware being honest.
  - **Release-unit runbook, reduced to a single burn.** **Secure Boot v2, eFuse
    anti-rollback and flash encryption are all NOT burned in 0.2.0** (Q32 deferred;
    SECUREBOOT.md, which is authoritative and targets 0.3.0). The only eFuse burn is
    HMAC-key provisioning, host-side with `espefuse.py` (Q45), with a dry run on a
    sacrificial unit - **and whether even that survives SECUREBOOT.md's "no eFuse burned
    at any point" wording is the one open question in the set (Q63), which must be
    answered before m3 closes rather than at m13, because m4a orders the first burn.** The
    burn ORDER rule is still written down even though one burn remains, because 0.3.0
    needs it unchanged: HMAC key before flash encryption and secure boot, since
    Release-mode flash encryption disables the UART download path `espefuse.py` uses.
    **The pre-existing three-way conflict - m13's runbook, REPRODUCIBLE.md's out-of-scope
    statement, and ARCHITECTURE's USB-reflash update story - closes here rather than being
    left standing** (R29). SECUREBOOT.md's preparatory slice (measurements SB1 and SB2,
    both build-only, neither touching a fuse) rides m1's harness.
  - **Release documentation states three limitations in plain terms, none of them
    buried** (R30): Secure Boot v2 is not burned and what that costs the Verify screen;
    the reproducibility claim is currently ours alone, with no third-party attestation
    (Q31) and an invitation to produce one; and the signing key is held on a
    general-purpose machine rather than a hardware token (Q30), which is exactly how good
    a verifier's trust in SHA256SUMS.txt can be.
  - Release: per-board `notyas-0.2.0-<board>.bin` plus the camera variant if its
    [HW-CAMERA] gates were met, one signed SHA256SUMS.txt (BigDice GPG key A1E9 53B2 5C6A
    623B 77A1 D522 3AC4 BBCF E51A B37D), reproducibility instructions, the per-path
    licence map, and the public announcement.
- **Crates / areas:** all; docs; tools.
- **Exit gate (hardware):** full CI matrix green; on-device self-test green on both
  boards with storage populated AND blank; a red-team pass over SECURITY.md
  claim-by-claim ("mechanically enforced or not made"); release artifacts reproduce
  on a second machine and the reproduced binary is the one signed; the 0.1.0-parity
  check - a blank 0.2.0 device walks the 0.1.0 golden flows byte-identically; a
  release unit completes the (now single-burn) runbook and still passes every gate.
  **Added by the re-scope: a claims audit that specifically hunts for any sentence
  implying Secure Boot, anti-rollback, a hardware-held signing key, third-party
  attestation, a backup, BSMS or taproot multisig exists in 0.2.0.** Those are the seven
  things a reader would most reasonably assume from the surrounding documents, and each
  one is now false.
- **Must not break:** every claim in SECURITY.md must be mechanically enforced or removed
  - that is the standing rule and m13 is where it is finally checked rather than
  promised; the 0.1.0 golden flows on a blank device; the reproducibility of the exact
  binary that gets signed (signing a different build than the one reproduced would void
  the whole chain); and the honest-limits language, which the re-scope makes it tempting
  to soften on a release that lost several protections.
- **Parity rows closed:** trick PINs / duress wallet (b), kill key (b),
  bless-firmware LEDs (c - Verify screen equivalent), dual secure elements (c - the
  tiered honesty statement), AAA battery (c - USB power bank), NFC and kill-trace (c -
  the radio is absent), USB kill-trace (b - firmware never enumerates USB data).
  **Removed from this list by the re-scope and moved to 7.4:** downgrade protection and
  firmware-upgrade-signed-only, both of which needed the Secure Boot burn Q32 deferred.
- **Implements:** storage research blocking follow-ups 1-3; audit section 5 items
  5-7; every red-team correction, closed out and re-verified.

---

## 5. Dependency graph at a glance

```
m1 ---+--> m2 ------------------+
      |                          \
      +--> m3h --+                +--> m6 --> m7 --> m10 --+
      |          \               /       \                  \
      +--> m3 ----+--> m4a --+--+         +--> m8 ----------+--> m12 --> m13
      |                       \          /                  /
      +--> m5 ----------------+--> (m6) /                  /
      |                       \                           /
      |                        +--> m4b                  /
      |                                                 /
      +-----------------------------> m11 (host half) -+
                                       m11 [HW-CAMERA] half: blocked on a module,
                                       blocks nothing
```

Serial by necessity: m1 -> m3 -> m4a -> {m4b, m6}; m6 -> m7 -> m10; m6 -> m8;
everything -> m12 -> m13. Everything else is schedulable in parallel per section 3.

**Two changes from the 2026-08-18 re-scope, both visible in the graph.** m9 is gone, so
m4b no longer feeds a seed-math milestone and m12 no longer waits on one. And m11 split:
its host half hangs off m1 and m6 like any other work, while its hardware half is a
dangling gate that no path runs through - which is precisely the property that lets 0.2.0
finish without a camera module.

---

## 6. Dependency ledger (the RNG ban is a build-graph check, not a promise)

Every crate below must be no_std-viable where it sits in a no_std crate, and must
enter the graph with the stated features or CI fails. `getrandom`, `rand`,
`rand_core`, `ring` and any network crate stay banned graph-wide (SECURITY.md
invariant 1 and 3), which is exactly why three of these need `default-features=false`.

| Crate | Enters at | Required features | Why the default is unsafe for us | License |
|---|---|---|---|---|
| `bitcoin = "=0.32.102"` | m2 | `default-features=false, features=["alloc","base64"]` | default pulls std and `rand`-adjacent surface | CC0-1.0 |
| `secp256k1` (via bitcoin) | m2 | no `rand`, no `global-context` | the `rand` feature would trip the ban; note the vendored libsecp256k1 is C in the TCB, stated honestly | CC0-1.0 |
| `argon2` | m3 | `default-features=false` | default `password-hash`/`rand` features pull `rand_core` | MIT OR Apache-2.0 |
| `chacha20poly1305` | m3 | `default-features=false, features=["alloc"]` | **`getrandom` is a DEFAULT feature** | MIT OR Apache-2.0 |
| `hkdf`, `hmac`, `sha2` | m3 | `default-features=false` | already in-graph, keep them that way | MIT OR Apache-2.0 |
| `zeroize` | in-graph | - | - | MIT OR Apache-2.0 |
| `miniscript = "13.1"` | m6 | `default-features=false` (no_std is default-off in 13.x; the named `no-std` feature was the 12.x convention) | default pulls std | CC0-1.0 |
| `foundation-ur` | m8 | `default-features=false` | **`std` is a DEFAULT feature** | MIT |
| `foundation-urtypes` | m8 | `default-features=false` | same | **GPL-3.0-or-later** - see R6, which is REVIVED |
| `bbqr` | m8/m11 if adopted | vet at admission | std-oriented; must clear the ban list and be pinned | MIT |
| `rqrr` | m11 if adopted | vet at admission | std-oriented; firmware is std on ESP-IDF, but it must not pull an RNG | MIT OR Apache-2.0 |

**Placement constraint, revived 2026-08-18 and enforced by m1's CI job.** R6 was marked
moot under the blanket GPL answer. Under the per-crate split it binds again:
`foundation-urtypes` is GPL-3.0-or-later, so **UR and transport encoding stay inside
notyas-wallet (GPL), and neither `esp-idf-hmac` nor `seedqr` - both MIT OR Apache-2.0 -
may take a `foundation-*` dependency.** The check is mechanical (no GPL crate in a
permissive crate's tree), because a placement rule held only by a paragraph is a rule that
lasts until the next refactor.

Rejected with reasons on file: BDK (std-only, coordinator-shaped - its
"change = what the internal keychain derives" idea is ~50 lines over miniscript, not
a dependency), PSBT v2 / `rust-psbt` (pre-1.0; v0 is what every target coordinator
speaks), the `bip39`/`slip132` crates (notyas-core equivalents are SPEC-normative),
the `ur` crate (std by default; `foundation-ur` covers it - R5), `secp256kfun`,
`zbar`, USB-UVC host stacks.

---

## 7. Parity coverage: every class-b, class-c and class-d row has a home

Recount note (R7): PARITY.md's summary says "61 feature rows"; that is sections 1-6
only. Section 7 adds 11 more, so the matrix is **72 rows**. A row-by-row recount
during reconciliation gives a=31, b=21, c=14, d=6 counting each row under its
primary class - close to but not identical with the summary's 30/17/12/6. The
assignment below is by row title, not by count, so the discrepancy changes nothing
operationally; PARITY.md's tally is an erratum, not a scope change.

### 7.1 Class-b rows (needs redesign) - all 21 assigned

| Row | Milestone | Redesign |
|---|---|---|
| Seed Vault | m4b | Multi-slot registry sealed under the device PIN ladder, NOT keyed by a master seed (R9). Count never shown pre-PIN under Q2(a) |
| Lock Down Seed | **0.3.0** (7.4) | Destructive re-seal of the slot with the passphrase-derived secret. Not needed to hold, verify or spend |
| Two-part main PIN | m4a | Prefix/suffix UX; enforcement is the KDF ladder plus the counter, not hardware |
| Anti-phishing words | m4a | HMAC-eFuse derived; exists only post-provisioning (R20); replay limit stated |
| Trick PINs (duress wallet leg) | m3 mechanism + m13 UX | Q2 selects the occupancy mode and the readout, not the format (revised R11); brick/wipe variants and Delta Mode rejected (7.3) |
| Login Countdown | m4a (escalating delay) | Long configurable countdown deferred: self-lockout risk, weak without an SE |
| Kill Key | m13 | Real when implemented as storage-key zeroization |
| MicroSD 2FA | deferred to 0.2.x | Card-serial binding adds a bricking failure mode for modest gain |
| PSBT via QR/BBQr (display) | m8 | UR2 primary, BBQr for Coldcard-family interop |
| Taproot keyspend | m6 | BIP-86 single-sig signing; tapscript/MuSig2 deferred (7.4) |
| Miniscript spending | m6 partial | miniscript is in-graph for descriptors; arbitrary policy spending deferred (7.4) |
| Multisig registration | m7 | Sealed registry; descriptor and Coldcard .txt dialects |
| BSMS (BIP-129) | **0.3.0, and no crate is built** | Descriptor import plus the MANDATORY first-address cross-check covers the need. The earlier "crate at m12 if capacity" conditional was removed by the owner's 2026-08-18 scope answer (Q15) |
| CCC co-signing | deferred to 0.3.x | Velocity policy needs a trusted clock and counter the P4 lacks; TOTP leg is NFC |
| Verify Address Ownership | m10 | Bounded search; typed or SD input, camera makes it smooth at m11 |
| Secure Notes and Passwords | rejected for 0.2.0 | A signing device is not a password manager (7.3) |
| Firmware upgrade (signed only) | **0.3.0** (7.4) | Needs the Secure Boot v2 burn that Q32's deferral removed. 0.2.0's answer is the user-buildable reproducible chain, documented as what it is: a check the owner performs, not one the device enforces |
| Downgrade protection | **0.3.0** (7.4) | eFuse anti-rollback protects a signature chain that does not exist without secure boot, so it travels with Q32 |
| USB kill-trace | m13 | Firmware never enumerates USB data; the board mod is documented |
| Tamper-evident supply chain | m12 | Reproducible builds plus user-flashable firmware replace the bag |
| SSSP policy signing | deferred to 0.3.x | Same reason as CCC |

### 7.2 Class-c rows (hardware-impossible) - equivalent and where it ships

| Row | Equivalent | Ships at |
|---|---|---|
| TRNG seed generation | Dice-only entropy with published verification math | shipped in 0.1.0, restated at m13 |
| Scan seed via QR | Manual entry; becomes class b only if m11's [HW-CAMERA] gates are met | m11 if a module arrives, otherwise the documented gap at m13 |
| Key Teleport | **No equivalent in 0.2.0.** PARITY.md names "encrypted state file over microSD", but SECURITY invariant 2b forbids key material on SD and Q14 defers encrypted backup - so the honest statement is "not available; move the mnemonic yourself" (R10) | documented at m13 |
| 13-attempt brick | Device-bound ladder plus wipe-on-N, labeled best-effort | m4a |
| Wrong-PIN actions | Same as above | m4a |
| PSBT via NFC | SD plus QR | m6/m8 |
| NFC PushTX | Final transaction as a QR a phone scans and broadcasts | m8 |
| Bless Firmware LEDs | Verify screen: eFuse state, running-app SHA256, self-test, plus reproducible builds. **Weaker in 0.2.0 than this row implies and the m13 claims audit must say so:** without Secure Boot (Q32) the screen is self-reported by the firmware under suspicion, where Coldcard's LED is driven by a separate security chip | m12/m13 |
| Nuke Device | Crypto-erase of the sealed records; device stays reusable | m4a/m4b |
| QR scanner module | m11 if adopted, otherwise the documented gap | m11 |
| Dual microSD slots | `-signed` filename convention on one slot | m5 |
| AAA battery | USB power bank, power only | m13 doc |
| NFC and NFC kill-trace | The radio is absent from the build and the C6 is held in reset - a stronger form of the same idea | shipped |
| Dual secure elements | The tiered honesty statement in SECURITY.md; no secure-element-class claim is ever made | m13 |

### 7.3 Class-d rows (judgment) - decided here, ratify at Q10

| Row | Verdict | Reason |
|---|---|---|
| PSBT via USB host protocol | **Reject, permanently** | Reopens the data port the airgap posture closes |
| PSBT via USB virtual disk (MSC) | **Reject, permanently** | Same |
| BIP-85 passwords via USB HID | **Reject the HID leg permanently.** BIP-85 itself moved to 0.3.0 in the re-scope, so nothing about passwords ships in 0.2.0 | Same |
| HSM Mode / CKBunker | **Reject, permanently** | Requires an always-connected host; the opposite posture |
| Paper wallets | **Reject** | Discouraged by Coldcard's own docs; and it is a private-key export path |
| WIF Store | **Reject** | Encourages loose-key handling; no demand |
| Delta Mode | **Reject** | Deeply secure-element-integrated upstream; software re-implementation is theater |
| Secure Notes and Passwords | **Reject for 0.2.0** | Scope; revisit only if users ask |
| Trick-PIN brick variants | **Reject**; keep only the wipe variant | A firmware "brick" without hardware backing is a lie |

### 7.4 Deferred beyond 0.2.0 (recorded so nothing forecloses them, and so nothing is silently dropped)

**Rewritten 2026-08-18. This list is now the honest measure of what the lean release
costs**, and it is the checklist the m13 claims audit reads. Grouped by why each item
left, because the reasons are not interchangeable.

**Deferred by the owner's 2026-08-18 scope instruction** (needed for parity, not needed
for a working storage, signing and multisig wallet):

| Item | Was | Reason |
|---|---|---|
| Encrypted backup, both profiles | m9 (seedless) / Q14(b) (seed-bearing) | Deferred whole. **Consequence: multisig registrations, labels and settings have no recovery path for the life of 0.2.0**, which every wipe surface must state |
| Device clone, Key Teleport equivalent | Q14(b) | Travels with the backup; PARITY's "encrypted state file over microSD" equivalent does not exist and must not be claimed (R10) |
| Publish the backup container format | Q34 | Moot with no backup |
| BSMS (BIP-129), on-device and as a crate | Q15 | Descriptor import plus the mandatory first-address cross-check covers the need |
| BIP-85 derived seeds | m9 | Pure parity; nothing depends on it |
| Seed XOR split and recombine, and the Q33 dice default | m9 | Pure parity, and up to 297 dice rolls of UX to build and test. The Q33 decision is kept settled for 0.3.0 |
| Lock Down Seed | m9 | Pure parity |
| BIP-137 message signing and verification | m10 | Not needed to hold, verify or spend coins |
| BIP-322 and proof-of-reserves PSBTs | m10 | A second signing surface with its own review-UI problem |
| Detached signature on the address-range CSV export | m10 | Same machinery as message signing; goes with it |
| Release signing key on a hardware token | Q30 | Costs money and lead time. 0.2.0 signs from disk and **says so in the release notes** |
| Independent builder attestation | Q31 | Needs a named outside person. 0.2.0's reproducibility claim is ours alone and **says so** |
| HIL power-cut rig | Q43 | m4a's power-cut gate is performed by hand and the milestone note records that the window is sampled, not swept |
| Upstream PRs (no_std BBQr decode; PSBT vectors to HWI / psbt_faker) | m12 | **Permission granted** (Q51, yes); only the work is deferred |
| crates.io publication of `esp-idf-hmac` and `seedqr` | m12 | Licences are set now (the irreversible part); publishing is a maintenance obligation deferred to 0.3.0 |

**Deferred because Secure Boot is not burned in 0.2.0** (Q32; each of these needs it and
none can be faked):

| Item | Reason |
|---|---|
| Secure Boot v2 RSA-3072 burn | Owner deferral. Never ECDSA when it returns - AR2026-006 |
| eFuse anti-rollback / downgrade protection | Protects a signature chain that does not exist without secure boot |
| Firmware-upgrade-signed-only enforcement | Same. 0.2.0's answer is the reproducible chain the OWNER checks, not one the device enforces |
| A Verify screen whose values do not depend on the firmware being honest | The one property secure boot supplied. Stated in SECURITY.md and VERIFYING.md rather than glossed |

**Deferred on technical grounds, unchanged from the 2026-08-17 list:** blind-oracle unlock
mode (needs a networked helper, against the single-device identity); taproot multisig and
MuSig2 (interop is not stable across our target coordinators, Q16); arbitrary miniscript
policy spending (descriptor-registration and review-rendering UX is a product in itself);
SeedQR display-out (declined outright by Q17, not merely deferred - it would amend the
no-secret-in-a-QR rule, R19); MicroSD 2FA (bricking failure mode for modest gain); CCC and
SSSP policy signing (need a trusted clock and counter the P4 lacks); Elecrow SC2336 camera
(no module on the bench and a different path entirely); Key Manager key ladder (needs rev
>= v3.0 silicon, and Q9 ships v1.x deliberately); PSBT v2 (parse-and-reject with a clear
message in 0.2.0).

**Contingent, not deferred:** the camera itself is IN 0.2.0. Only its hardware
verification waits, on a module the owner has agreed to buy (Q6, Q50).

---

## 8. Reconciliation decisions (contradictions found and how they were resolved)

**R26 to R30 were added by the 2026-08-18 re-scope and are listed first because they are
the ones a reader of the older text will trip over.**

**R26 - milestone m9 is retired, and the id is NOT reused.** The owner's scope instruction
removed BIP-85, Seed XOR, Lock Down Seed and the encrypted backup; seed import by words
was always m4b's restore flow, the stateless session belongs with signing at m6, and the
`seedqr` decoder belongs with its only consumer at m11. Nothing was left. Resolution: the
block is replaced by a redistribution table and the id is retired rather than renumbered,
because renumbering would invalidate every existing reference to m10, m11, m12 and m13
across seven documents to save one integer. A retired id is a stale reference that
resolves to an explanation; a renumbered id is a stale reference that resolves to the
wrong milestone.

**R27 - the camera spike left m1.** m1's exit gate required the spike's result, and the
spike requires a module the owner does not own. Holding the entire serial spine open for a
purchase is not a trade worth making, and the spike's only claimed dependency - the
partition freeze - was already withdrawn as unsupported when Q6 was ratified. Resolution:
the spike is m-camera-0 inside m11 and is marked [HW-CAMERA]; the one deliverable that
needed no hardware, the `app.bin` size measurement with the `camera` feature on, stays in
m1 as a build measurement. The general rule this establishes: **a milestone on the serial
spine may not carry a gate that depends on hardware nobody has yet.**

**R28 - "parity is the product bar" and "ship a lean 0.2.0" cannot both be unqualified.**
The release framing said full Coldcard parity was the product bar; the owner's 2026-08-18
instruction says anything not needed for a working storage, signing and multisig wallet
goes to 0.3.0. Resolution: the parity bar survives as a PROJECT bar and becomes a 0.3.0
release bar; the rule that every row is implemented, equivalent-and-documented, or
deferred with a stated reason is unchanged and is what keeps the deferral honest. Section
7.4 is rewritten as the measure of what the lean release costs, and m13's claims audit
reads it. The failure mode this guards against is a release whose documentation was
written for the feature set that was planned rather than the one that shipped.

**R29 - four documents disagreed about eFuse burning, and the Q32 deferral forced the
issue.** REPRODUCIBLE.md scopes eFuse burning OUT of 0.2.0; m13's runbook scoped four
burns IN; ARCHITECTURE's "an airgapped signer updates by USB reflash" is incompatible with
Release-mode flash encryption, which permanently disables the UART download path; and
SECUREBOOT.md, which landed alongside this re-scope, says 0.2.0 burns "no eFuse on any
device, at any point". Resolution, in two parts. **Settled:** no secure-boot digest, no
anti-rollback and no flash-encryption key are burned in 0.2.0. That is SECUREBOOT.md's
position, it matches the recommendation, and it is the only option that keeps the device
reflashable and therefore keeps the reproducible-build story usable by the person it is
for. **Open, and it is the one live question in the set:** whether "no eFuse at any point"
was meant to include the HMAC_UP key of Q45, which the entire sealed-storage design binds
to. If it was, 0.2.0 stores nothing at all and m3, m4a and m4b lose most of their purpose;
if it was not - almost certainly the case, since that document's subject is secure boot -
one sentence there needs narrowing. Raised as Q63 rather than fixed unilaterally, because
SECUREBOOT.md is another document's subject and the sweeping reading, if deliberate, is a
scope decision far larger than a wording fix. **It must be answered before m3 closes**,
since m4a orders the first burn.

**R30 - a lean release invites overclaiming, so the release documentation carries three
explicit limitations.** Seven things a reader would reasonably assume exist do not:
Secure Boot, anti-rollback, a hardware-held signing key, third-party attestation, any
backup, BSMS, and taproot multisig. Three of those are properties of the RELEASE rather
than absent features, so they are stated in the release notes rather than merely omitted
from a feature list: Secure Boot is not burned and what that costs the Verify screen; the
reproducibility claim is ours alone; the signing key is on a general-purpose machine.
Resolution: m13's claims audit hunts specifically for sentences implying any of the seven,
and the three statements are release-note content rather than a footnote in a design
document nobody reads.

---

**R1 - m1 rebuilds work that already shipped.** The wave-1 m1 lists "root Cargo
workspace + CI" and "implement the build-graph check for real" as new work. Both
landed in 0.1.0 (commits b0f9452 and d151b2e). Resolution: m1 EXTENDS the existing
check to the new dependency edges (section 6 ledger) and wires it into CI; it does
not recreate either.

**R2 - the partition table could strand user wallets.** ARCH 2.7 places `wallets` at
0x410000, immediately after a 4 MB app. 0.2.0 adds miniscript, argon2, an AEAD
stack, FATFS and possibly esp_video; the app will outgrow 4 MB, and moving it moves
the data partitions, which destroys every sealed record on upgrade. Resolution:
the data partitions move to a fixed high offset (0xE00000 /
0xE40000), frozen permanently at m1, and - per Q7 - `factory` is declared
at its collision bound rather than at a nominal 8M, so the frozen table never
needs a later edit and `partition-table.bin` stays a stable published artifact. App-size
discipline moves to an explicit CI budget constant (fail above 8 MiB, warn above 6 MiB).
**Amended 2026-08-18: a 2 MiB reserved `media` partition at 0xC00000 now sits between the
app and `wallets`, so the app's collision bound is 0xBF0000 (11.94 MB) rather than
0xDF0000.** It was taken out of the app's span, not the tail, so `wallets` and `counters`
do not move and board B still has 1.73 MB spare - which matters beyond arithmetic, because
that tail is the fully trustworthy region of VERIFY.md's reserved-space scan (R23).
ARCH 2.7's offsets are superseded; its reasoning (counters plaintext and separate, app
offset unchanged, no OTA, 6-block eFuse budget) is retained.

**R3 - "no camera" versus CAMERA.md rank 1.** ARCH 5.2/5.4 and UX screen 9 assert
flatly that no camera exists and QR is out-only; CAMERA.md recommends CSI + OV5647
for 0.2.0 and the user owns a compatible module. Resolution: the camera is an
optional, board-A-only, compile-time-off milestone (m11), preceded by a half-day
spike inside m1 so the answer is known before the app-size budget and the sign-flow
UX are frozen. m6's load path takes a source abstraction so m11 adds a source rather
than rewriting the flow. The UI wording changes from "no camera exists" to "no
camera on this board/build". USB-UVC stays rejected in every build.

**R4 - who owns sealing, notyas-wallet or esp-seal. SUPERSEDED 2026-08-17 by the
ratified Q44/Q46: there is no `esp-seal` crate and nothing is published.** The original
finding and its resolution are kept because the sequencing argument is still sound and
still governs m3 versus m12.

*Original:* ARCH says notyas-wallet owns seal/unseal and warns against shallow wrapper
crates; PLATFORM says esp-seal "is the crate under the 0.2.0 storage layer" and gates
storage work. Resolution: the sealing LAYER gates all storage work and is written first
(m3), in-tree, extraction-ready, with no ESP-IDF type crossing its boundary; the
PUBLICATION of `esp-seal` trails hardware proof and lands at m12. The genuine
prerequisite is the HMAC wrapper (m3h), which really does gate the on-hardware ladder.
Publishing an unproven security crate to satisfy an ordering diagram would be a
disservice to the ecosystem the contribution is meant to serve.

*What survives:* the layer is still written first, in-tree, at m3, with a clean platform
boundary - now for testability rather than for extraction. What is withdrawn is the
extraction and the m12 publication. ARCH's position (notyas-wallet owns seal/unseal)
wins outright, and ESP-SEAL.md stays the authoritative design of that module.

**R5 - two UR implementations.** ARCH adopts `foundation-ur` and explicitly rejects
`ur` (std by default); CAMERA.md section 6 recommends `ur`. Resolution:
`foundation-ur` + `foundation-urtypes`, one implementation, both with
default-features off. CAMERA.md's recommendation is superseded.

**R6 - GPL contagion through foundation-urtypes. REVIVED 2026-08-18; the 2026-08-17
"moot" marking is WITHDRAWN.** `foundation-urtypes` is GPL-3.0-or-later, so any crate
depending on it must be GPL. The original resolution kept UR and transport encoding inside
notyas-wallet so that no permissively licensed crate could depend on it. That constraint
was briefly moot under the blanket GPL answer, because there was no permissive crate to
contaminate. **The owner's 2026-08-18 split-licensing answer creates two of them -
`esp-idf-hmac` and `seedqr`, both MIT OR Apache-2.0 - so the constraint binds again.**
Resolution: UR and transport encoding stay inside notyas-wallet, neither permissive crate
may take a `foundation-*` dependency, and the rule is enforced mechanically by m1's CI job
(no GPL crate in a permissive crate's dependency tree) rather than by this paragraph. This
is the clearest example in the set of why a "moot" marking is dangerous: the constraint did
not go away, its precondition did, and the precondition came back.

**R7 - PARITY.md's row and class counts.** "61 feature rows" counts sections 1-6
only; the matrix has 72 rows. The class tally 30/17/12/6 recounts as 31/21/14/6.
Resolution: recorded as an erratum; assignment in section 7 is by row title.

**R8 - PARITY understates the PIN design.** PARITY section 2's preamble says the
notyas equivalent is "PIN-as-key-material, offline-hard but not attempt-limited".
The wave-1 design DOES attempt-limit, because the ladder passes through the
eFuse-keyed HMAC peripheral, so each guess needs the physical device, and wipe-on-N
destroys the record. Resolution: plan-0.2.0/SECURITY.md's tiered statement governs;
PARITY's preamble is superseded on this point. The honest limit is unchanged in
substance and sharpened in wording (ESP-SEAL.md 7.2): the counter is advisory against
a fault-injection lab, and the claim to make is "N guesses per full-flash restore
cycle", never a bare "attempt limited". The `counters` partition is plaintext, so
flash encryption adds nothing to rollback resistance.

**R9 - master-seed-keyed encryption.** PARITY maps class-b storage rows onto
Coldcard's "AES keyed by the master seed" pattern. notyas has no single master seed
on a multi-wallet device, and everything is sealed under the device PIN ladder.
Resolution: the ladder is the only encryption key path; the Seed Vault row maps to
the multi-slot registry.

**R10 - class-a rows that the security model forbids.** PARITY marks encrypted
backups and device clone as class a ("directly portable"). Both write encrypted key
material to SD, which SECURITY invariant 2b forbids and OPEN-QUESTIONS Q14 defers.
Resolution: both are deferred beyond 0.2.0, and PARITY's stated equivalent for Key
Teleport ("encrypted state file over microSD") does not exist in 0.2.0 and must not
be claimed.

**R11 - duress is a BEHAVIOUR decision, and the format carries it either way.**
REVISED 2026-08-17 against ESP-SEAL.md 3.6; the original text is kept below because
the correction is the interesting part.

*Original finding:* wave 1 schedules duress in the final milestone while its
deniability package requires all slots to be ciphertext-filled at all times, so adding
filler slots after m4a ships would change the on-flash format under existing users -
therefore Q2 blocks m3.

*Correction, and it wins:* filler needs no format change. ESP-SEAL.md 3.6 makes an
unoccupied slot a genuine AEAD record sealed under a **device-derived** key rather
than a PIN-derived one - `HKDF(filler_root, kdf_salt, RecordInfo)` over a zero
plaintext - carrying the same 80-byte header shape, the same `pin_gen` identity 0, and
consuming a `seal_seq` like any other record. Two consequences do the work: the device
distinguishes filler from a real record without a PIN, at one HKDF and one AEAD open
per slot, so "empty" is never confused with "wrong PIN"; and an attacker without the
eFuse key cannot make that distinction at all. The format under
`Occupancy::AlwaysFilled` and under `Occupancy::Sparse` is byte-identical - only the
CONTENT of an unoccupied slot differs.

*Which analysis wins, and why:* the ESP-SEAL analysis. The reconciliation reasoned
from ARCHITECTURE 2.5's prose, which described duress before any filler construction
existed and could only infer that "all slots ciphertext-filled" must be a format
property. ESP-SEAL.md is the concrete format, and it exhibits the mechanism at zero
marginal format cost. A demonstrated mechanism beats an inference that no such
mechanism exists.

*Resolution:* m3 implements the filler mechanism unconditionally and exposes the
occupancy mode as runtime state, so nothing about Q2's answer reaches the on-flash
bytes. Q2 decides behaviour - whether the mode is on, whether the Verify storage
readout degrades permanently for all users, and the PIN-classification and UX half at
m13 - and its real deadline is **m4b**, the milestone that ships the capacity line and
the readout. It stays in the blocking set only because it is cheap to settle at m1 and
three screens (S-01, S-03, S-46) and Q37 depend on it; answering it after the format
freeze costs no migration. R11's original scheduling claim is withdrawn.

**R12 - low-R grinding reaches further than SPEC text.** Wave 1 treats Q13 as an
invariant-4 wording question. Adopting `sign_ecdsa_low_r` means not using
`Psbt::sign`'s stock loop. Resolution: the question blocks m2's API shape and its
KAT vectors, not just m1's documentation.

**R13 - stale milestone cross-references.** ARCH 5.3 points the regression corpus at
"MILESTONES m5", which is the SD subsystem. Resolution: the corpus gate is m6, and
the multisig cases are m7.

**R14 - Q10 references "m4".** m4 no longer exists. Resolution: anti-phishing words
and the lock-screen word land in m4a.

**R15 - screen 9 is claimed by two milestones.** Resolution: m5 builds the file
picker chrome and the mount lifecycle; m6 builds the PSBT-specific load behavior,
refusal screens, and the source abstraction.

**R16 - does SD bring-up break invariant 1?** Invariant 1's per-board text says the
SDIO host is never configured on the C6 pins. Checked: board A uses SDMMC slot 0 on
GPIO39-42/43/44 (power gate 45) while its C6 sits on 14-19; board B uses 1-bit SD on
GPIO39/43/44 while its C6 sits on 49-54. Disjoint on both. Resolution: invariant 1
survives m5 verbatim; m5's gate re-asserts the pin numbers so a future board that
overlaps forces an honest amendment instead of a silent one.

**R17 - `encrypted` partition flag on dev boards.** The flag is inert without flash
encryption burned, so dev-board wallets are protected by the PIN ladder alone.
Already stated in the plan SECURITY text; m1's boot check must not be read as
evidence that encryption is active.

**R18 - Argon2 memory versus the 16 MB board.** The 16/32 MB difference is FLASH.
All boards are ESP32-P4NRW32 with 32 MB PSRAM, so a 64 MiB Argon2 working set is a
latency question, not a capacity one, on both boards. Cross-check passes.

**R19 - SeedQR display-out versus the no-secret-in-a-QR rule. SETTLED 2026-08-17 by the
ratified Q17: display-out is declined.** BACKUP-FEATURES rows B22-B24 are dropped, B14's
"and QR" clause is struck, PARITY's SeedQR row is documented as scan-in only, and - the
part that had actually gone wrong - the invariant-2 QR corollary, which this directory's
SECURITY.md had dropped from both 2a and 2b while R19 promised it would be restated
rather than quietly dropped, is restored to invariant 2a. Original finding below. 0.1.0 invariant 2's
corollary is that QR display covers public values only, never a mnemonic. A SeedQR
is a QR of a mnemonic. Resolution: notyas ships SeedQR scan-IN (m11) and the
`seedqr` crate (m9/m12), but not display-out. m13's SECURITY rewrite restates the
corollary in 0.2.0 terms rather than quietly dropping it. BACKUP-FEATURES.md
(OPEN-B3) recommends the opposite - accept it behind a gated, hold-to-reveal,
auto-blanking "secret-QR screen class" with a reachability test. Both positions are
recorded at OPEN-QUESTIONS Q17 and the user decides; neither is silently adopted.

**R21 - unrecoverable state versus "your mnemonic is the backup". RESOLVED 2026-08-18 in
the direction the finding warned about: NEITHER backup ships, so the copy requirement is
the whole mitigation.** Wave 1 deferred all SD backup on the grounds that every notyas
wallet is re-derivable. BACKUP-FEATURES.md pointed out that multisig registrations and
settings are NOT re-derivable from a mnemonic, so a wipe destroys them permanently. The
question split into a seedless profile (no invariant amendment needed, proposed for m9)
and a seed-bearing one (needs an explicit amendment), and the owner deferred both to 0.3.0
with Q14. **R21's closing sentence therefore becomes load-bearing rather than a
fallback:** the wipe screens must say what a wipe destroys, naming multisig registrations,
labels and settings individually, on the S-06 setup line, the S-44 policy sub-screen, the
post-wipe S-48b text and the deliberate-erase S-48 screen. The accidental path must not
disclose less than the deliberate one, which is how it stood before this was caught.

**R22 - the BIP39 passphrase is never stored (user decision, 2026-08-17).** The
record carries only a KDF-separated `passphrase_check` fingerprint, inside the AEAD.
The consequences are acceptance criteria, not copy suggestions: three warning
placements at m4b and a one-time acknowledgment before the first passphrase wallet is
saved (OPEN-QUESTIONS Q22).

**R23 - VERIFY.md was written against the superseded partition geometry.** Found in the
VERIFY.md sweep, 2026-08-17. That document's flash map, its reserved-space scan example, its
cost table, its `counters` location, its raw-digest ranges and both of its wireframes used
`wallets` at 0x410000, `counters` at 0x450000, a 4 MiB app and an 11.7 MiB unmapped tail -
the layout the ratified Q7 replaced. Sixteen places. Resolution: corrected in place to the
frozen offsets, because MILESTONES and Q7 win on geometry and ARCHITECTURE 2.7 already
carried the frozen table.

*Why this was more than a find-and-replace, and the part worth remembering:* the freeze moves
where the blank space **is**. Declaring the app at its collision bound turns the app tail into
almost all of the must-be-blank space (about 12.8 MiB for a 1.8 MiB image) and shrinks board
B's unmapped tail from 11.7 MiB to 1.73 MiB. VERIFY.md's own merged-image caveat says a
`merged.bin` flash writes `0xff` padding that becomes ciphertext on an encrypted unit - and
that caveat covers exactly the app tail. So on a release board B flashed from a merged image,
the scan's fully trustworthy region is 1.73 MiB rather than 11.7 MiB. The document now states
that plainly, with the three mitigations that keep it useful (flash the artifacts separately;
unencrypted units are unaffected; the per-span report shows which case you are in) and one
prohibition: the scan must not quietly exclude the app tail to avoid false positives, which
would trade a legible caveat for an invisible blind spot. A second, independent arithmetic
error in the same example - image tails computed from the image LENGTH rather than from
`base + length` - was fixed at the same time.

**R24 - a boot counter would have falsified SECURITY invariant 2a.** Found in the VERIFY.md
sweep. VERIFY.md section 6 adds a power-on counter in the plaintext `counters` ledger and its
section 14 recommends incrementing it early in every boot. Invariant 2a says of a device with
no stored wallet that "nothing is ever written to flash" - the 0.1.0 stateless property,
retained verbatim and mechanically enforced. A counter incrementing on every power-up writes
to flash on blank and unprovisioned devices, so the two cannot both stand. Resolution: the
invariant wins, and it is not close - this project's governing rule is that a claim is
mechanically enforced or not made, and trading a headline invariant for a convenience row is
the wrong direction. Counting begins when the ledger is formatted, which is the same moment
the device stops being stateless for every other reason; before that the row renders
`not counted`, never `0`. Ratified as Q61(ii). The feature keeps its value: it answers "has
anyone powered this on since I set it up", and the question it cannot answer - since the
factory - is not answerable on this hardware by any means.

**R25 - two documents specified screen S-46, and one of them opined.** Found in the VERIFY.md
sweep. VERIFY.md declares itself the owner document for S-46 and specifies a design contract
whose rule 2 forbids verdicts, risk language and advice sentences beside a value; UX-SCREENS'
S-46 entry carried an edge state rendering the flash-encryption row as a `WARNING` with
"disabled - a stored wallet on this board is protected by the PIN only". Resolution: the
contract wins for this screen's content. A screen whose purpose is to let an owner read raw
values loses that purpose the moment it starts interpreting them, and VERIFY.md's field order
and colour rules are CI-asserted while a prose caveat is not. UX-SCREENS keeps the screen
inventory, the component library and the copy vocabulary; its S-46 sketch is marked superseded
in detail and the WARNING edge state is struck. The caveat itself is real and moves rather
than disappearing: a dev board's stored wallet IS protected by the PIN ladder alone, and that
belongs at the moment of decision - the "Save (PIN-protected)" fork and the wipe-policy
sub-screen - where it can change behaviour, not on an instrument panel the user opened to read
hex.

**R20 - anti-phishing words before provisioning. AMENDED 2026-08-17 by the ratified
Q45.** The words derive from the eFuse key, which is burned **by the host with
`espefuse.py` before the device ships or before a self-builder first boots it**, not at
first save. A blank UNPROVISIONED device therefore has no words, and no screen or doc
may imply it does. Two other derivations sit on the same key and inherit the same
problem, which R20 as written did not name: the randomized PIN-pad permutation and the
backup quiz's distractor set. An unprovisioned device cannot render its own PIN screen,
so the refusal has to be an explicit state (`StoreState::Unprovisioned`) with its own
screen, not a generic hardware fault.

---

## 9. What "done" means for 0.2.0

The release is done when:

1. **Every milestone gate above is green on both verified boards**, with one stated
   exception: gates marked [HW-CAMERA] may be outstanding, in which case BOARDS.md and the
   artifact both say `camera: built, not hardware-verified` and the four camera parity rows
   stay class c. No other gate may be outstanding, and no gate may be waived.
2. **A working wallet does the whole loop on real hardware**, which is the actual bar the
   re-scope was aimed at: create or import a seed, save it under a PIN, power cycle,
   unlock, register a 2-of-3 P2WSH multisig, verify the first receive address against
   another signer, load a PSBT from SD, review it, sign it, and hand the result to a
   coordinator that accepts it. If that loop has a gap, the release is not done regardless
   of what else is green.
3. **Every PARITY.md row is implemented, equivalent-and-documented, or deferred with the
   reason in section 7** - and section 7.4 is now long, which is exactly why the m13
   claims audit reads it rather than trusting the feature list.
4. **Every SECURITY.md claim is mechanically enforced or removed**, checked claim by
   claim, with the seven things a reader would wrongly assume (R30) specifically hunted
   for rather than passively absent.
5. **Both board images reproduce bit-for-bit on a second machine and the reproduced
   binaries are the signed ones** - including the VERIFY.json manifest and the camera
   variant, because a published artifact that is not reproduced is a hole in the chain.
6. **The published design documents stand on their own** for someone who has never seen
   this repository: REPRODUCIBLE.md's recipe, and ESP-SEAL.md's format, trust model and
   settable-policy design.

Two clauses are withdrawn and are recorded rather than deleted, so nobody restores them
from memory. "The published crates build from crates.io for someone who has never seen
this repository" is gone: nothing publishes in 0.2.0 (Q46). And "a release unit completes
all four eFuse burns" is gone: there is one burn (Q32, Q63).
