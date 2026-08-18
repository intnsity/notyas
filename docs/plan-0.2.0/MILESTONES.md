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

Release framing (user directive, encoded here so no milestone re-litigates it):

- 0.1.0 ships NOW as a source-only preview: signed-if-possible, not reproducible,
  no public binary campaign.
- **0.2.0 is the public release.** Scope: seed storage + PSBT signing + multisig +
  wallet management. Reproducible builds and GPG-signed per-board artifacts are a
  0.2.0 deliverable (m12/m13), not a later nicety.
- Full Coldcard (Mk4 + Q) feature parity is the product bar. Every PARITY.md row is
  assigned to a milestone, ships as a documented equivalent, or is deferred with a
  stated reason in section 7. No row is silently dropped.
- Rust wherever it fits, including notyas-wallet as a real Bitcoin wallet library -
  but vetted primitives are reused, never reimplemented. No hand-rolled crypto.
- Genuine platform contributions ship (m3h, m12), GPL-3.0-or-later firmware.
- First-class wallet UI/UX is a gate, not a garnish: m4b and m10 exist because a
  signer nobody can operate confidently is not a signer.

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
  silicon is the thing being proven.
- **Parity rows closed** - PARITY.md rows this milestone satisfies.
- **Implements** - the research or red-team finding it discharges.

### 1.1 Companion specifications (who is authoritative for what)

This file owns ordering, scope boundaries and exit gates. The build-level detail lives
in the wave-3 documents, and each one is the authority inside its milestone:

| Document | Authority for | Milestones it governs |
|---|---|---|
| WALLET-API.md | the notyas-wallet crate: types, traits, error taxonomy, the validation pipeline, test strategy | m3, m4a, m6, m7, m8 |
| ESP-SEAL.md | the firmware side of the platform traits (Storage, DeviceBinding, KdfScratch) over esp_partition and the P4 HMAC peripheral - the sealed-storage layer that gates all storage work | m3h, m3, m4a, m12 |
| CORPUS.md | the adversarial PSBT corpus: cases, expected verdicts, expected rendered text - the signing milestone's exit criteria are defined there | m6, m7 |
| UX-SCREENS.md | the per-screen build spec every UI milestone implements | m4a, m4b, m6, m9, m10, m11 |
| REPRODUCIBLE.md | the reproducible-build recipe and its verification procedure - the release gate | m12, m13 |
| CAMERA-HW.md | camera hardware bring-up detail behind CAMERA.md's decision | m1 spike, m11 |
| BACKUP-FEATURES.md | backup, restore and device-lifecycle feature detail | m9, and Q14's scope |
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
| A - silicon | m1 benchmark, m3h, m4a, m5 | board B first | Board B is the sacrificial unit: eFuse burns and the flash-encryption-on benchmark happen there. |
| B - pure Rust | m2, m3, m9 math, seedqr | host | No board needed until the on-device KAT gate. |
| C - UI/UX | m4b, m10 screens | board A + uisim | 720x720 and 800x480 golden images both required before any UI milestone closes. |
| D - camera | m1 spike, m11 | board A only | Board B physically cannot take a Pi-class module (CAMERA.md 2.3). |

Safe concurrency, explicitly:

- m2 (notyas-core signing API, host) runs alongside m3 (notyas-wallet sealing, host)
  and m3h (HMAC wrapper, board B). Three people, no contention.
- m4b (UI on board A + uisim) runs alongside m5 (SD bring-up on board B). Both then
  cross-verify on the other board before closing.
- m8 (UR2 QR-out, board A, needs a webcam and Sparrow) runs alongside m9 (seed-math
  parity, host) and m10's non-signing screens.
- m11 (camera) is board A only and never blocks anything else; it is additive.

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
- **Flash encryption and secure boot burns are m13-only and release-unit-only.**
  The m1 benchmark measures the encryption cost using virtual-eFuse / development
  mode on board B, not by burning board A.
- Switching boards never requires a clean (per-board CARGO_TARGET_DIR, BOARDS.md),
  but two agents must not flash the same COM port concurrently.

---

## 4. The milestones

### 0.2.0-m1 - Foundations, ratified decisions, frozen storage geometry

- **Depends on:** nothing that is still open. **The blocking set is empty as of
  2026-08-17**: Q1, Q3, Q4, Q5, Q6, Q7, Q44 and Q47 are ratified, Q8 was answered by the
  owner (GPL-3.0-or-later, everywhere), and Q2's deadline is m4b because the duress
  package needs no format change (revised R11). This milestone can now close on
  engineering alone.
- **Runs on:** board A and board B (partition table boot check), board B
  (benchmark, camera spike is board A).
- **Scope:**
  - Write the ratified decisions into SPEC and the plan texts: randomness policy
    (Q1 / ARCH 2.4), signing equivalence and low-R grinding (Q3), PIN floor (Q4),
    wipe-after-N (Q5, default 10, range 3..=25, with the copy and power-cut disclosure
    requirements it carries), camera in-or-out (Q6), the frozen partition geometry
    (Q7), the camera build variant (Q47), and the sealing layer's address (Q44 - a
    notyas-wallet module, no extracted crate). Two sub-items that Q5 and Q12 left as
    implementation design must be settled at their milestones, not here: whether
    wipe-after-N is runtime-mutable or format-time-only (m3, inside the format freeze)
    and the scope of the stateless multisig refusal (m6). Q2 is still the owner's and
    is behaviour-only; nothing here waits on it.
  - Workspace and CI: the root workspace and the unified Cargo.lock already landed
    in 0.1.0 (commit b0f9452), as did tools/build-graph-check.sh (commit d151b2e).
    m1 does NOT rebuild them; it EXTENDS the ban list and the graph walk to every
    dependency edge 0.2.0 adds (section 6 ledger) and wires both into CI at both
    board geometries. See R1.
  - Freeze the storage geometry (R2). New partitions.csv, identical on both boards,
    inside 16 MB:

    ```
    # Name,    Type, SubType, Offset,   Size,     Flags
    factory,   app,  factory, 0x10000,  0xDF0000
    wallets,   data, 0x40,    0xE00000, 256K,     encrypted
    counters,  data, 0x41,    0xE40000, 16K
    ```

    Data partitions move to a fixed high offset so app growth can never relocate a
    user's sealed records: **the whole table is a permanent compatibility surface and
    is frozen here.** The app is declared at its collision bound, 0xE00000 - 0x10000 =
    0xDF0000 = 13.94 MB, rather than at a nominal 8M, precisely so that the frozen
    table never needs a later edit: ESP-IDF enforces the size field, so an 8M
    declaration would have to be raised to use the space, and `partition-table.bin` is
    a published byte-identical release artifact whose hash verifiers are told is
    stable (REPRODUCIBLE.md 3.5). **App-size discipline moves out of the geometry and
    into CI as an explicit budget constant: fail above 8 MiB, warn above 6 MiB.** That
    is a policy number, freely revisable because it is not a compatibility surface,
    and it separates the two things the old 8M field conflated. Ends at 0xE44000 =
    14.27 MB, inside board B's 16 MB with 1.73 MB spare, unchanged on board A's 32 MB.
    App offset 0x10000 is unchanged, so the Verify screen's running-partition SHA256
    procedure stays board-independent. No `nvs`, `otadata` or `phy_init`, as in 0.1.0 -
    and the m11 link-map gate additionally asserts `nvs_flash_init` and `nvs_open` are
    absent from the image, because 0.2.0 adds components (FATFS, possibly
    `esp_cam_sensor`) that could pull NVS in and fail at runtime on a device with no
    recovery path. See OPEN-QUESTIONS Q7 for the full reasoning.
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
  - **M6 gains a second consumer, which raises what it decides.** The boot counter is a
    bit-clear cell array in the same `counters` partition and under the same partial-page
    limit as the attempt ledger (ratified Q53), so M6's measured number now sizes both. If
    it comes back below 32, both arrays are re-laid-out together before m3 opens.
  - Camera decision spike (board A, half a day, CAMERA.md section 5): plug the
    user's SeedSigner OV5647 module into J1, run the esp-video `capture_stream`
    example, record pass/fail. This is the cheapest possible answer to Q6. **Two
    corrections from the Q6 ratification.** It no longer gates the partition freeze -
    the camera only ever affected the app partition's SIZE field, and under the
    ratified Q7 that field is no longer a compatibility surface. And the spike gains a
    second deliverable, because nobody has ever measured the thing the old dependency
    was asserted on: **record `app.bin`'s byte count for the `capture_stream` build
    and for a notyas build with the `camera` feature on**, and commit it beside the
    Argon2 numbers. For scale, the current 0.1.0 debug build's flash-loadable sections
    total roughly 2.5 MiB.
  - **m-camera-1, the `board::shared_i2c_bus()` refactor** (CAMERA-HW.md 6.2, adopted
    by the ratified Q6): cheap, independent of the camera answer, and landed here with
    the early infrastructure work rather than inside m11.
  - Reproducible-build groundwork: keep CONFIG_APP_REPRODUCIBLE_BUILD, add path
    remapping and toolchain pinning to build.ps1 (the full two-machine proof is
    m12's gate).
- **Crates / areas:** root workspace, CI, tools/build-graph-check.sh, tools/build.ps1,
  tools/flash.ps1, firmware/partitions.csv, firmware (benchmark path), tools/uisim,
  docs/BOARDS.md flash section.
- **Exit gate (hardware):** both boards boot the new partition table and report the
  new geometry on the Verify screen; the QR modal is reachable and renders on both
  boards (photo evidence in the milestone note); benchmark numbers committed
  including the encryption-on run; **M6 answered on both boards - JEDEC ID read off
  each fitted part, the matching datasheet's partial-page-program limit cited, and a
  soak test showing 32 cell programs into one 256-byte page read back intact; if the
  limit is below 32, the ledger cell layout AND the boot-log cell layout are re-designed
  together and the geometry freeze re-taken before m1 closes**; the camera spike result
  committed as pass or fail with the module part number; V1, V2 and V3 committed beside the
  Argon2 numbers, with V3's verdict recorded as ship-or-`not supported` for the flash
  unique-ID row; the `firmware_digest` construction and the VERIFY.json field set frozen in
  the plan texts; CI red on a planted `rand` dependency.
- **Parity rows closed:** none directly (foundation). Unblocks every storage row.
- **Implements:** audit repo hygiene; storage research 3.2 ("never ship a guessed
  KDF cost"); red-team counter-partition finding (ARCH 2.5/2.7); CAMERA.md decision
  request; reconciliation R1, R2, R3, R7.

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
- **Parity rows closed:** none alone; prerequisite for every section-3 row.
- **Implements:** signing research 1; audit gap-list item 6; red-team correction to
  invariant 4 (equivalence is against pinned vectors plus Core-accepts, never
  byte-equality with Core's own Schnorr output).

### 0.2.0-m3h - esp-idf-hmac: safe Rust over the P4 security peripherals

- **Depends on:** m1. (Q8 is answered: GPL-3.0-or-later, and under Q46 nothing is
  published, so this is an in-tree module rather than a crate. The SPDX header is
  GPL-3.0-or-later from the first commit.)
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
- **Parity rows closed:** none directly; it is the silicon leg under every
  storage row.
- **Implements:** PLATFORM.md section 1 gap; ARCH 2.2 HMAC-eFuse step with the
  red-team's P4-specific citation (IDF v5.5 P4 HMAC peripheral, HMAC_UP purpose 8,
  eFuse blocks 0-5, no chip-revision constraint - unlike the Key Manager).

### 0.2.0-m3 - notyas-wallet sealing and storage engine (host-proven)

- **Depends on:** m1 (KDF parameters, partition geometry, the M6 partial-page result,
  Q5 wipe-N). **Not on Q2** - the filler mechanism is built either way and Q2 only
  picks the mode at runtime (revised R11). Not on m3h either: the HMAC step is
  trait-injected and stubbed on host.
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
  - Host power-loss fuzzer: truncate and corrupt the write stream at every byte
    offset and after every erase. Property: mount yields the previous record or the
    new one, never garbage, never a panic - including the PIN-change
    erase-after-commit window.
  - The sealing module keeps a clean platform boundary: no ESP-IDF types cross it. The
    reason is no longer extraction (Q44/Q46: it is never extracted) but testability -
    the host simulator and the fuzz harness need to substitute the Storage,
    DeviceBinding and KdfScratch traits, and that is worth the discipline on its own.
- **Build specs:** WALLET-API.md is authoritative for the crate's types, traits and
  error taxonomy; ESP-SEAL.md is authoritative for the platform-trait contracts this
  crate is written against. m3 cannot close while either is absent.
- **Crates / areas:** notyas-wallet (new).
- **Exit gate (hardware):** host fuzz property holds over the full corpus and KDF/AEAD
  KATs are green; AND a feature-flagged firmware test command runs the same
  seal/unseal KAT on both boards with the stubbed HMAC and prints PASS - this proves
  the Argon2 working set actually fits and completes on target within the pinned
  budget, which no host test can prove. miniscript is deliberately NOT in the graph
  yet (it enters at m6), keeping this milestone's audit surface minimal.
- **Parity rows closed:** none alone; it is the layer under all 21 class-b rows.
- **Implements:** storage research candidate A; Trezor norcow and counter design;
  red-team findings on post-wipe nonce reuse, counter placement, and stale old-PIN
  ciphertext; PLATFORM.md shortlist item 1 (as in-tree code, published at m12).

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
- **Test rig (lead time, order at m1):** the power-cut gate below needs a
  USB-controlled relay or FET; it cannot be faked (Q43). The HIL test-mode console
  ships build-feature-gated and off by default, with a release gate asserting its
  symbols are absent from the shipped binary (Q41).
- **Crates / areas:** firmware, notyas-wallet (session), notyas-ui (minimal).
- **Exit gate (hardware), on both boards:** create a wallet, power cycle, unlock;
  wrong PIN decrements the counter and the decrement survives a reboot AND a power
  cut taken mid-decrement; wipe-on-N destroys the records and bumps the epoch; a PIN
  change leaves no stale old-PIN ciphertext (proven by raw flash readback, not by
  code inspection); the stateless path still writes nothing (proven by a flash
  readback diff on a dev board); the Verify screen reports the real eFuse HMAC-key
  state, not a constant.
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
  confirmation; capacity line ("3 of 8 slots"), subject to Q2's Verify-readout
  decision.
- **Also in scope: the S-46 Verify-device rebuild**, which is the largest single screen
  0.2.0 adds and is specified end to end in VERIFY.md sections 10-11: the three row kinds,
  the six frozen sections, the frozen field order, the viewport pager, the identity /
  firmware / flash rows, the on-demand reserved-space scan with its C3 Busy screen (Q57),
  and the CI assertions in 11.7. Its design contract is binding and is what makes the screen
  worth having: raw values shown in full, no verdicts or advice beside a value, and a field
  order that does not move between builds so two units can be compared side by side rather
  than read. Storage-row granularity follows whichever Q2 package is ratified; the `wallets`
  raw digest is pre-PIN only under Q2(a) (Q56); S-46 keeps full body width at 800x480 (Q55);
  three new `RegionId` values land (Q54).
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
  expectation or the discrepancy explained.
- **Parity rows closed:** Seed Vault (b - as PIN-ladder-sealed slots, see R9),
  device nickname / home XFP / idle timeout (a), calculator login (a, if kept),
  View Identity (a), Destroy Seed (a), Selftest and maintenance menu (a/b).
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
- **Parity rows closed:** microSD file transport underlying section 3 and 4 rows;
  dual-microSD-slots (c - documented equivalent: the `-signed` filename convention
  on one slot).
- **Implements:** features.md airgap-IO research; audit firmware infrastructure 3.

### 0.2.0-m6 - PSBT engine and single-sig signing end to end

- **Depends on:** m2, m4a, m5, plus the answers to Q23-Q26 (change gap bounds, expert
  overrides, PSBT size cap, `-final.txn` byte format).
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
- **Parity rows closed:** PSBT signing via microSD (a), batch signing (a),
  output/input explorer (a), on-device finalization (a), max fee guard / sighash
  checks (a), taproot send-to-P2TR (a), taproot keyspend BIP-86 (b, partial - see
  section 7 for the tapscript/MuSig2 deferral), PSBT via NFC (c - QR plus SD
  equivalent), testnet4/regtest toggle (a).
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
- **Parity rows closed:** PSBT via QR/BBQr - display leg (b); NFC PushTX (c -
  QR-for-phone equivalent); QR display density improvement over the Q's 320x240 (a,
  exceeded).
- **Implements:** signing research 4 (transport sizing); UX commandment 9;
  CAMERA.md's decode-stack survey on the encode side.

### 0.2.0-m9 - Parity pack A: seed math and seed lifecycle

- **Depends on:** m4b (storage-backed seed operations need the wallet UI).
  Independent of m6-m8; can run concurrently on host and board B.
- **Runs on:** host, then board A and board B.
- **Scope:** the pure-math Coldcard features that notyas can match exactly, all in
  notyas-core with published test vectors:
  - BIP-85 derived seeds (12/18/24 words, WIF, xprv, hex, passwords index 0-9999+),
    usable in-device as a temporary seed. Password derivation displays on screen and
    as a QR of a NON-secret only where applicable; the USB-HID typing leg is
    rejected permanently (section 7).
  - Seed XOR split and recombine (2-4 parts, each a valid-checksum mnemonic).
  - Temporary and stateless seeds: a session need not come from a sealed slot
    (ratified Q12). Stateless multisig claims are REFUSED, with **no expert override** -
    Q24 makes that a hard rule and SECURITY invariant 7 is written without exceptions.
    (This line previously said "with an expert override", contradicting section 4's own
    m6 statement; corrected 2026-08-17.) The SCOPE of that refusal - all stateless
    multisig signing, or only change claims - is the one sub-item Q12 left open, is
    settled at m6, and the recommended answer is the broader one, because without a
    registration the input's witness-script membership is unverifiable too.
  - Lock Down Seed: destructively replace the stored record with the
    passphrase-derived secret.
  - Seed XOR part generation defaults to dice, with the deterministic mode as a
    clearly labeled second option (Q33).
  - `seedqr` crate (PLATFORM.md item 3): no_std SeedQR and CompactSeedQR encode and
    decode against SeedSigner's published vectors. Built here because m11's scan-in
    needs it. **Display-out of a SeedQR is NOT shipped under this plan's
    recommendation** - a QR that encodes a mnemonic contradicts the 0.1.0 invariant-2
    corollary that no QR ever carries a secret, and no 0.2.0 feature is worth
    silently amending that (R19). BACKUP-FEATURES.md argues for shipping it behind a
    gated "secret-QR screen class"; the user chooses at OPEN-QUESTIONS Q17, and if
    (b) is chosen the reachability test becomes a gate of this milestone.
  - **Contingent on Q14(a):** the seedless encrypted backup (multisig registrations,
    labels, settings - no seed material), which exists because those are the only
    device state a mnemonic cannot re-derive. If Q14(a) is declined, the wipe-on-N
    setup screen must instead state that a wipe destroys multisig registrations.
  - Passphrase wallets carry the Q22 warning placements and the overridable
    `passphrase_check` mismatch warning wherever this milestone adds a flow that
    asks for a passphrase.
- **Build specs:** BACKUP-FEATURES.md for the backup, restore and seed-lifecycle
  detail; UX-SCREENS.md for the screens.
- **Crates / areas:** notyas-core, notyas-wallet, notyas-ui, new `seedqr` crate.
- **Exit gate (hardware):** BIP-85 and Seed XOR vectors green in the on-device boot
  self-test on both boards; a derived BIP-85 child seed opens as a temporary session
  and signs a testnet PSBT; a Seed XOR round trip recombines to the original
  fingerprint on-device; `seedqr` vectors green on host.
- **Parity rows closed:** BIP-85 derived seeds (a), Seed XOR (a), temporary seeds
  (a), import seed by word entry (a), BIP-39 passphrase (a), Lock Down Seed (b),
  View/Destroy seed words (a), TRNG seed generation (c - dice-only equivalent with
  published verification math).
- **Implements:** PARITY.md section 1; PLATFORM.md item 3; OPEN-QUESTIONS Q12.

### 0.2.0-m10 - Parity pack B: addresses, messages, exports

- **Depends on:** m7 (multisig-aware address verification), m5 (SD export).
- **Runs on:** board A and board B.
- **Scope:** the "works with your software" and anti-phishing surface:
  - Address explorer completion: change-address tab, per-address QR, explicit
    derivation path, CSV export of a bounded address range with a detached
    signature.
  - Verify Address Ownership: given an address (typed, or read from an SD text
    file), search singlesig and multisig accounts within a bounded gap and answer
    "yours at m/84'/0'/0'/0/N" or "NOT MINE".
  - Message signing (BIP-137 with RFC2440 armor) from an SD file or on-device entry,
    plus on-device verification of a signature file.
  - BIP-322 signing and proof-of-reserves PSBTs.
  - Watch-only wallet exports: named formats (Sparrow, Bitcoin Core
    `importdescriptors`, Electrum, Nunchuk) plus generic JSON, over SD and QR.
- **Crates / areas:** notyas-wallet, notyas-ui, firmware.
- **Exit gate (hardware):** on both boards, export a watch-only file that Sparrow and
  Bitcoin Core each import without editing; verify a known-owned and a known-foreign
  address with the right verdicts; sign a message and verify the armored output with
  an independent tool; a BIP-322 signature verified by an independent verifier.
- **Parity rows closed:** address explorer (a), verify address ownership (b),
  message signing (a), BIP-322 (a), export watch-only wallet (a), view identity (a).
- **Implements:** PARITY.md section 5; UX commandment 1 (address poisoning is why
  the full address is always shown, chunked, to the end).

### 0.2.0-m11 - Camera scan-in (OPTIONAL, board A only)

- **Depends on:** m1's spike result and the Q6 answer (which, under CAMERA-HW.md 6.2's
  refinement, also decides whether this milestone is delivered as one unit or as the
  individually droppable steps m-camera-2..5, with m-camera-0 being m1's spike and
  m-camera-1 - the `board::shared_i2c_bus()` refactor - pulled forward into the early
  infrastructure work); Q47 (per-board policy and the artifact split); Q48, Q49 and
  Q50 at their points inside this milestone; m6 (a PSBT source abstraction to plug
  into); m9 (`seedqr`).
- **Runs on:** board A only. Board B physically cannot take a Pi-class module; its
  camera is Elecrow's 24-pin SC2336, deferred to 0.3.0 (CAMERA.md 2.3).
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
  notyas-wallet (source abstraction), `rqrr`.
- **Exit gate (hardware):** on board A with the user's SeedSigner module, scan a
  CompactSeedQR and restore the expected fingerprint; scan an animated UR
  `crypto-psbt` emitted by Sparrow at Sparrow's default density and sign it; the
  camera-off image is provably free of camera code by the LINK-MAP assertion below;
  the per-board support statement lands in BOARDS.md and on the Verify screen.
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
- **Parity rows closed (only if this milestone ships):** scan seed via QR (c -> b),
  PSBT via QR scan-in (c -> b), QR scanner module (c -> b), verify-address input
  ergonomics (b), Key Teleport receive (still deferred - it needs protocol work
  beyond capture).
- **Implements:** CAMERA.md rank 1 (CSI + OV5647), its USB-UVC rejection, and its
  section 7 scope proposal.

### 0.2.0-m12 - Reproducible builds and platform contributions published

- **Depends on:** m4a (the sealing layer proven on hardware), m3h, m9 (`seedqr`). Q8 is
  answered (GPL-3.0-or-later) and Q46 withdraws publication, so this milestone's
  contribution scope is documents, not crates.
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
  - **Nothing is published to crates.io.** Q8 was answered GPL-3.0-or-later for
    everything, and Q44/Q46 follow from it: the sealing layer stays a module inside
    notyas-wallet, `esp-idf-hmac`, `seedqr` and `bsms` stay in-tree, and no crate is
    extracted. R4's "published after hardware proves it" sequencing is overtaken -
    there is nothing to publish.
  - **ESP-SEAL.md is published as the contribution instead**, in-repo under
    GPL-3.0-or-later: the byte-exact on-flash format, the mount/unlock/seal/wipe state
    machine, the power-loss analysis, the honest attempt-counter trust model and the
    attack analysis. Any project can read it and reimplement freely; a document does
    not impose its licence on an independent implementation of the ideas it describes.
    ESP-SEAL.md 9.1 argued the value was in the design rather than in three thousand
    lines of well-trodden construction, and this is that position carried through.
    Clean-room constraint unchanged: Trezor's and Jade's code are copyleft and are
    never ported.
  - `bsms` (BIP-129): build only if m7 left capacity, in-tree; on-device BSMS stays
    deferred either way (Q15). BDK's open request is no longer a reason to build it,
    because BDK is permissive and cannot take a GPL dependency.
  - The adversarial PSBT vector files: the harness and generator stay GPL-3.0-or-later
    (Q39). **The vector files' own licence and the offer of selected cases upstream to
    HWI and psbt_faker are OPEN-QUESTIONS Q51, for the owner** - both mean putting our
    work out under someone else's permissive terms, which is the same call Q8 was.
    Default if Q51 lapses: GPL-3.0-or-later in-repo, no upstreaming.
  - **The no_std BBQr decode is also Q51**, for the same reason: it is an upstream
    feature PR to SatoshiPortal's MIT crate rather than a crate of ours.
- **Crates / areas:** tools, CI, docs. No new published crates (Q46).
- **Exit gate (hardware):** a second machine reproduces every named artifact
  bit-for-bit, including the camera variant (Q47); the reproduced image flashes and
  boots with the same Verify-screen SHA256 on both boards; REPRODUCIBLE.md and
  ESP-SEAL.md are complete enough that an outside reader could follow the recipe and
  reimplement the format without asking a question.
- **Parity rows closed:** tamper-evident supply chain (b/d - the notyas answer is
  reproducible builds plus user-flashable firmware, not a bag number); firmware
  upgrade verification (b, partial - completed at m13).
- **Implements:** PLATFORM.md shortlist items 1, 2, 3, 5, 6; the user directive to
  ship genuine community contributions.

### 0.2.0-m13 - Hardening closeout and the 0.2.0 public release

- **Depends on:** everything.
- **Runs on:** board A and board B, plus release units.
- **Scope:**
  - Duress PIN and the Kill Key, per whichever Q2 package was ratified at m1 (the
    record-format half already shipped in m3; this is the PIN-classification and UX
    half), OFF by default.
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
  - Verify screen finalized against VERIFY.md: storage state (granularity per Q2),
    anti-rollback and HMAC-key state as actually read, per-board camera support statement,
    and the final frozen field order. This is the first time most of the eFuse section is
    anything but `disabled`, so the whole section is validated against a real release unit
    AFTER the burn runbook rather than inferred from dev boards. VERIFY.md section 9's
    self-reporting wording - what this screen can and cannot prove, given that it is produced
    by the software under suspicion - lands verbatim in docs/SECURITY.md and VERIFYING.md;
    it is the sentence that keeps the screen honest and it is not optional.
  - Release-unit runbook: eFuse HMAC-key provisioning, XTS-AES flash encryption,
    Secure Boot v2 RSA-3072 (never ECDSA - AR2026-006), anti-rollback, in a fixed
    order of burns with a dry run on a sacrificial unit.
  - Release: per-board `notyas-0.2.0-<board>.bin`, one signed SHA256SUMS.txt (BigDice
    GPG key A1E9 53B2 5C6A 623B 77A1 D522 3AC4 BBCF E51A B37D), reproducibility
    instructions, GPL-3.0-or-later, and the public announcement.
- **Crates / areas:** all; docs; tools.
- **Exit gate (hardware):** full CI matrix green; on-device self-test green on both
  boards with storage populated AND blank; a red-team pass over SECURITY.md
  claim-by-claim ("mechanically enforced or not made"); release artifacts reproduce
  on a second machine and the reproduced binary is the one signed; the 0.1.0-parity
  check - a blank 0.2.0 device walks the 0.1.0 golden flows byte-identically; a
  release unit completes the burn runbook and still passes every gate.
- **Parity rows closed:** trick PINs / duress wallet (b), kill key (b), downgrade
  protection (b), firmware upgrade signed-only (b), bless-firmware LEDs (c - Verify
  screen equivalent), dual secure elements (c - the tiered honesty statement),
  AAA battery (c - USB power bank), NFC and kill-trace (c - the radio is absent),
  USB kill-trace (b - firmware never enumerates USB data).
- **Implements:** storage research blocking follow-ups 1-3; audit section 5 items
  5-7; every red-team correction, closed out and re-verified.

---

## 5. Dependency graph at a glance

```
m1 ---+--> m2 ------------------+
      |                          \
      +--> m3h --+                +--> m6 --> m7 --> m10
      |          \               /       \
      +--> m3 ----+--> m4a --+--+         +--> m8
      |                       \
      +--> m5 ----------------+--> (m6)
      |                       \
      |                        +--> m4b --> m9 --+
      |                                           \
      +--> (camera spike) ------------> m11 -------+--> m12 --> m13
```

Serial by necessity: m1 -> m3 -> m4a -> {m4b, m6}; m6 -> m7 -> m10; m6 -> m8;
everything -> m12 -> m13. Everything else is schedulable in parallel per section 3.

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
| `foundation-urtypes` | m8 | `default-features=false` | same | **GPL-3.0-or-later** - see R6 |
| `bbqr` | m8/m11 if adopted | vet at admission | std-oriented; must clear the ban list and be pinned | MIT |
| `rqrr` | m11 if adopted | vet at admission | std-oriented; firmware is std on ESP-IDF, but it must not pull an RNG | MIT OR Apache-2.0 |

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
| Seed Vault | m4b / m9 | Multi-slot registry sealed under the device PIN ladder, NOT keyed by a master seed (R9) |
| Lock Down Seed | m9 | Destructive re-seal of the slot with the passphrase-derived secret |
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
| BSMS (BIP-129) | deferred; crate at m12 | Descriptor import plus mandatory first-address cross-check covers the need (Q15) |
| CCC co-signing | deferred to 0.3.x | Velocity policy needs a trusted clock and counter the P4 lacks; TOTP leg is NFC |
| Verify Address Ownership | m10 | Bounded search; typed or SD input, camera makes it smooth at m11 |
| Secure Notes and Passwords | rejected for 0.2.0 | A signing device is not a password manager (7.3) |
| Firmware upgrade (signed only) | m13 | Secure Boot v2 RSA-3072 plus the user-buildable chain, both documented |
| Downgrade protection | m13 | eFuse anti-rollback on release units |
| USB kill-trace | m13 | Firmware never enumerates USB data; the board mod is documented |
| Tamper-evident supply chain | m12 | Reproducible builds plus user-flashable firmware replace the bag |
| SSSP policy signing | deferred to 0.3.x | Same reason as CCC |

### 7.2 Class-c rows (hardware-impossible) - equivalent and where it ships

| Row | Equivalent | Ships at |
|---|---|---|
| TRNG seed generation | Dice-only entropy with published verification math | shipped in 0.1.0, restated m9 |
| Scan seed via QR | Manual entry; becomes class b if m11 ships | m11 or documented gap at m13 |
| Key Teleport | **No equivalent in 0.2.0.** PARITY.md names "encrypted state file over microSD", but SECURITY invariant 2b forbids key material on SD and Q14 defers encrypted backup - so the honest statement is "not available; move the mnemonic yourself" (R10) | documented at m13 |
| 13-attempt brick | Device-bound ladder plus wipe-on-N, labeled best-effort | m4a |
| Wrong-PIN actions | Same as above | m4a |
| PSBT via NFC | SD plus QR | m6/m8 |
| NFC PushTX | Final transaction as a QR a phone scans and broadcasts | m8 |
| Bless Firmware LEDs | Verify screen: eFuse state, running-app SHA256, self-test, plus reproducible builds | m12/m13 |
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
| BIP-85 passwords via USB HID | **Reject the HID leg**; password derivation ships at m9 | Same |
| HSM Mode / CKBunker | **Reject, permanently** | Requires an always-connected host; the opposite posture |
| Paper wallets | **Reject** | Discouraged by Coldcard's own docs; and it is a private-key export path |
| WIF Store | **Reject** | Encourages loose-key handling; no demand |
| Delta Mode | **Reject** | Deeply secure-element-integrated upstream; software re-implementation is theater |
| Secure Notes and Passwords | **Reject for 0.2.0** | Scope; revisit only if users ask |
| Trick-PIN brick variants | **Reject**; keep only the wipe variant | A firmware "brick" without hardware backing is a lie |

### 7.4 Deferred beyond 0.2.0 (recorded so nothing forecloses them)

Blind-oracle unlock mode (needs a networked helper - against the single-device
identity); BSMS on-device ceremony; taproot multisig and MuSig2 (interop is not
stable across our target coordinators); arbitrary miniscript policy spending
(descriptor-registration and review-rendering UX is a product in itself);
seed-bearing SD backup and device clone (blocked by invariant 2b until Q14 says
otherwise; the SEEDLESS backup is proposed for m9 instead - R21); SeedQR display-out
(blocked by the no-secret-in-a-QR rule unless Q17 accepts the gated exception, R19);
MicroSD 2FA; CCC and SSSP policy signing; Elecrow SC2336 camera; Key Manager
key ladder (needs rev >= v3.0 silicon, Q9); PSBT v2 (parse-and-reject with a clear
message in 0.2.0).

---

## 8. Reconciliation decisions (contradictions found and how they were resolved)

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
0xE40000), frozen permanently at m1, and - per the ratified Q7 - `factory` is declared
at its collision bound 0xDF0000 rather than at a nominal 8M, so the frozen table never
needs a later edit and `partition-table.bin` stays a stable published artifact. App-size
discipline moves to an explicit CI budget constant (fail above 8 MiB, warn above 6 MiB).
Fits 16 MB with 1.73 MB to spare and gives the app 13.94 MB; unchanged on 32 MB. ARCH 2.7's offsets are superseded; its
reasoning (counters plaintext and separate, app offset unchanged, no OTA, 6-block
eFuse budget) is retained.

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

**R6 - GPL contagion through foundation-urtypes. MOOT since Q8 was answered
(2026-08-17).** `foundation-urtypes` is GPL-3.0-or-later, so any crate depending on it
must be GPL. The original resolution kept UR and transport encoding inside
notyas-wallet so that no extracted, permissively licensed crate could depend on it.
Under Q8's answer - GPL-3.0-or-later everywhere, nothing extracted - there is no
permissive crate to contaminate and the constraint binds nothing. Kept on the register
because the placement it produced is still the right one and should not be undone by
someone who notices the constraint is gone.

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

**R21 - unrecoverable state versus "your mnemonic is the backup".** Wave 1 defers all
SD backup on the grounds that every notyas wallet is re-derivable. BACKUP-FEATURES.md
points out that multisig registrations and settings are NOT re-derivable from a
mnemonic, so wipe-on-N destroys them permanently. Resolution: the question splits.
A SEEDLESS encrypted backup (registrations, labels, settings) needs no invariant
amendment - its contents are the class of data invariant 2b already permits to leave
the device - and is recommended for m9. A SEED-BEARING backup still requires an
explicit amendment and stays this plan's "no for 0.2.0", with BACKUP-FEATURES.md's
counter-recommendation recorded. Both live at OPEN-QUESTIONS Q14. If neither ships,
the wipe screen must say what a wipe destroys.

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

The release is done when: every milestone gate above is green on both verified
boards; every PARITY.md row is implemented, equivalent-and-documented, or deferred
with the reason in section 7; every SECURITY.md claim is mechanically enforced or
removed; both board images reproduce bit-for-bit on a second machine and the
reproduced binaries are the signed ones; and the published design documents -
REPRODUCIBLE.md's recipe and ESP-SEAL.md's format and trust model - stand on their own
for someone who has never seen this repository. (The old clause "the published crates
build from crates.io" is withdrawn: under Q8, Q44 and Q46 there are no published
crates.)
