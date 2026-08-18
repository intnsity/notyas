# notyas 0.2.0 - Milestones (THE roadmap)

Status: RECONCILED 2026-08-17. This file supersedes the wave-1 milestone draft and
folds in wave 2 (PARITY.md, CAMERA.md, PLATFORM.md). Where any other document in
docs/plan-0.2.0/ disagrees with this file on scope, ordering, or dependency, this
file wins as of the reconciliation date; the resolutions and their reasoning are
recorded in section 8. docs/SECURITY.md (0.1.0) stays normative for invariants
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

- **One eFuse budget per board (6 key blocks).** m4a burns one HMAC_UP key and
  read-protects it. That is permanent. Do it on board B first; board A stays clean
  until m4a's procedure is written down and repeated.
- **Flash encryption and secure boot burns are m13-only and release-unit-only.**
  The m1 benchmark measures the encryption cost using virtual-eFuse / development
  mode on board B, not by burning board A.
- Switching boards never requires a clean (per-board CARGO_TARGET_DIR, BOARDS.md),
  but two agents must not flash the same COM port concurrently.

---

## 4. The milestones

### 0.2.0-m1 - Foundations, ratified decisions, frozen storage geometry

- **Depends on:** the blocking answers in OPEN-QUESTIONS.md (Q1-Q7). This milestone
  cannot close on engineering alone.
- **Runs on:** board A and board B (partition table boot check), board B
  (benchmark, camera spike is board A).
- **Scope:**
  - Ratify OPEN-QUESTIONS Q1-Q7 with the user and write the decisions into SPEC and
    the plan texts: randomness policy (ARCH 2.4), duress package (Q2 - it changes
    the m3 record format, see R11), signing equivalence and low-R grinding (Q3),
    PIN floor (Q4), wipe-after-N (Q5), camera in-or-out (Q6), partition offsets (Q7).
  - Workspace and CI: the root workspace and the unified Cargo.lock already landed
    in 0.1.0 (commit b0f9452), as did tools/build-graph-check.sh (commit d151b2e).
    m1 does NOT rebuild them; it EXTENDS the ban list and the graph walk to every
    dependency edge 0.2.0 adds (section 6 ledger) and wires both into CI at both
    board geometries. See R1.
  - Freeze the storage geometry (R2). New partitions.csv, identical on both boards,
    inside 16 MB:

    ```
    # Name,    Type, SubType, Offset,   Size, Flags
    factory,   app,  factory, 0x10000,  8M
    wallets,   data, 0x40,    0xE00000, 256K, encrypted
    counters,  data, 0x41,    0xE40000, 16K
    ```

    App partition grows 4M -> 8M (miniscript, argon2, the AEAD stack and the SD/FATFS
    subsystem all land in 0.2.0). Data partitions move to a fixed high offset so app
    growth can never relocate a user's sealed records: **these offsets are a
    permanent compatibility surface and are frozen here.** Headroom check: the app
    may grow to 0xE00000 - 0x10000 = 13.94 MB before it collides; CI asserts image
    size against the partition size. Ends at 0xE44000 = 14.27 MB, inside board B's
    16 MB, unchanged on board A's 32 MB. App offset 0x10000 is unchanged, so the
    Verify screen's running-partition SHA256 procedure stays board-independent.
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
  - Camera decision spike (board A, half a day, CAMERA.md section 5): plug the
    user's SeedSigner OV5647 module into J1, run the esp-video `capture_stream`
    example, record pass/fail. This is the cheapest possible answer to Q6 and it
    must be answered before m1 closes because esp_video/esp_cam_sensor affect the
    app-size budget the partition freeze depends on.
  - Reproducible-build groundwork: keep CONFIG_APP_REPRODUCIBLE_BUILD, add path
    remapping and toolchain pinning to build.ps1 (the full two-machine proof is
    m12's gate).
- **Crates / areas:** root workspace, CI, tools/build-graph-check.sh, tools/build.ps1,
  tools/flash.ps1, firmware/partitions.csv, firmware (benchmark path), tools/uisim,
  docs/BOARDS.md flash section.
- **Exit gate (hardware):** both boards boot the new partition table and report the
  new geometry on the Verify screen; the QR modal is reachable and renders on both
  boards (photo evidence in the milestone note); benchmark numbers committed
  including the encryption-on run; the camera spike result committed as pass or
  fail with the module part number; CI red on a planted `rand` dependency.
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

- **Depends on:** m1 (Q8 licensing decides the crate's SPDX before first publish).
- **Runs on:** board B, then board A.
- **Scope:** first platform contribution (PLATFORM.md shortlist item 2). A thin,
  safe crate over ESP-IDF's `esp_hmac.h` (and optionally `esp_ds.h`,
  `esp_key_mgr.h`) using esp-idf-sys's `extra_components` / `bindings_header`
  mechanism - no fork of esp-idf-sys. Verified gap: esp-idf-sys's default bindgen
  header does not include these; esp-hal has HMAC for S2/S3/C3/C6/H2 but not P4.
  Surface: calculate HMAC-SHA256 with an eFuse key of purpose HMAC_UP, query key
  state, and a documented provisioning helper for burn plus read-protect that is
  loud about being irreversible. Key Manager support is compiled out on rev < v3.0
  silicon and is not designed around (Q9).
- **Crates / areas:** new out-of-tree crate (workspace member during development),
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

- **Depends on:** m1 (KDF parameters, partition geometry, Q2 duress package, Q5
  wipe-N). Not on m3h: the HMAC step is trait-injected and stubbed on host.
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
    device-bound guard key. Counters CANNOT live in the encrypted partition:
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
  - If Q2 chooses the deniability package: unused slots hold device-bound
    pseudorandom filler (HMAC-eFuse-derived stream, no RNG), and delete/wipe rewrite
    filler rather than leaving erased-flash signatures. This is a RECORD-FORMAT
    decision, which is why Q2 blocks m3 and not m13 (R11).
  - Host power-loss fuzzer: truncate and corrupt the write stream at every byte
    offset and after every erase. Property: mount yields the previous record or the
    new one, never garbage, never a panic - including the PIN-change
    erase-after-commit window.
  - The sealing module is written extraction-ready: no ESP-IDF types cross its
    boundary, so m12 can publish it as `esp-seal` without a rewrite (R4).
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
- **Runs on:** board B first (eFuse burn), then board A.
- **Scope:** firmware Storage-trait driver over `esp_partition_*` for the wallets and
  counters partitions; HMAC peripheral binding and eFuse key provisioning with a
  Verify-screen readout of the TRUE state; `Ui::tick()` plus hold-to-confirm plus the
  horizontal-slop fix (a sideways swipe across a button must cancel the tap);
  minimal functional screens 2 and 16 only (randomized-pad PIN entry with
  anti-phishing words, lock screen); a bare-bones save/unlock path grafted onto the
  existing create flow; the WalletSession type with lock, timeout, and power-off
  wipe; the extended UiRequest protocol (UnsealWallet, PersistWallet, ...) keeping
  all I/O and sealing on the std side.
  Note: anti-phishing words derive from the eFuse key, so they exist only after
  provisioning. A blank stateless device has none, and no screen may imply otherwise
  (R20).
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
- **Build specs:** UX-SCREENS.md is the per-screen build spec; UX.md remains the
  design rationale behind it.
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
  screen.
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
  the last page has been visited.
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
    (OPEN-QUESTIONS Q12). Stateless multisig change is refused by default with an
    expert override, because there is no registration to verify against.
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

- **Depends on:** m1's spike result and the Q6 answer; m6 (a PSBT source
  abstraction to plug into); m9 (`seedqr`).
- **Runs on:** board A only. Board B physically cannot take a Pi-class module; its
  camera is Elecrow's 24-pin SC2336, deferred to 0.3.0 (CAMERA.md 2.3).
- **Scope:** CSI capture bring-up with `esp_cam_sensor` + `esp_video` on the
  Waveshare 4B J1 connector with an OV5647 Pi-camera-class module; ISP Y-plane
  grayscale straight into `rqrr`; static scan-in of SeedQR/CompactSeedQR, plain word
  lists, descriptors and addresses; animated scan-in of UR `crypto-psbt` (and BBQr
  if the crate clears the ledger); a viewfinder screen with an honest per-board
  support statement. Compile-time feature, OFF by default; a build without it must
  be byte-identical to the no-camera build.
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
  camera-off build's image SHA256 is unchanged by the feature's presence in the
  tree; the per-board support statement lands in BOARDS.md and on the Verify screen.
- **Parity rows closed (only if this milestone ships):** scan seed via QR (c -> b),
  PSBT via QR scan-in (c -> b), QR scanner module (c -> b), verify-address input
  ergonomics (b), Key Teleport receive (still deferred - it needs protocol work
  beyond capture).
- **Implements:** CAMERA.md rank 1 (CSI + OV5647), its USB-UVC rejection, and its
  section 7 scope proposal.

### 0.2.0-m12 - Reproducible builds and platform contributions published

- **Depends on:** m4a (esp-seal proven on hardware), m3h, m9 (`seedqr`), Q8
  (licensing).
- **Runs on:** two independent build machines; boards for the artifact check.
- **Scope:**
  - Reproducible build proven: the per-board images rebuild bit-identically on a
    second machine from a clean checkout (pinned IDF, pinned nightly, `--locked`,
    `-Zbuild-std` pinning, path remapping, `components_esp32p4.lock`). Published as
    the **Reproducible Rust-on-ESP-IDF recipe** (PLATFORM.md item 6), modeled on
    Jade's REPRODUCIBLE.md - the first public one for the Rust + esp-idf-sys stack.
    This directory's REPRODUCIBLE.md is the authoritative recipe and verification
    procedure; m12 and m13 cannot close while it is absent.
  - `esp-seal` published: the extraction of notyas-wallet's proven sealing module
    (PIN-sealed blob, eFuse-bound KDF, AEAD, fault-hardened attempt counter,
    power-loss-safe commit) with its trust model documented honestly. Published
    AFTER m4a proved it on silicon, not before (R4). Clean-room from published
    designs only: Trezor's and Jade's code are copyleft and are never ported.
  - `esp-idf-hmac` published (from m3h), offered upstream to esp-idf-hal.
  - `seedqr` published (from m9).
  - `bbqr` no_std decode contributed upstream as a feature PR rather than a
    competing crate, if m8/m11 needed it.
  - `bsms` (BIP-129) crate: build only if m7 left capacity; on-device BSMS stays
    deferred either way (OPEN-QUESTIONS Q15).
- **Crates / areas:** new published crates, tools, CI, docs.
- **Exit gate (hardware):** a second machine reproduces both board images
  bit-for-bit; the reproduced image flashes and boots with the same Verify-screen
  SHA256 on both boards; every published crate builds from crates.io into a fresh
  project and its examples run on board B.
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
  - Verify screen finalized: storage state (granularity per Q2), anti-rollback and
    HMAC-key state as actually read, per-board camera support statement.
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
| Trick PINs (duress wallet leg) | m3 format + m13 UX | Q2 package decides deniability; brick/wipe variants and Delta Mode rejected (7.3) |
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
factory grows to 8M and the data partitions move to a fixed high offset
(0xE00000 / 0xE40000), frozen permanently at m1. Fits 16 MB with 1.7 MB to spare and
13.94 MB of app headroom; unchanged on 32 MB. ARCH 2.7's offsets are superseded; its
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

**R4 - who owns sealing, notyas-wallet or esp-seal.** ARCH says notyas-wallet owns
seal/unseal and warns against shallow wrapper crates; PLATFORM says esp-seal "is the
crate under the 0.2.0 storage layer" and gates storage work. Resolution: the sealing
LAYER gates all storage work and is written first (m3), in-tree, extraction-ready,
with no ESP-IDF type crossing its boundary; the PUBLICATION of `esp-seal` trails
hardware proof and lands at m12. The genuine prerequisite is the HMAC wrapper
(m3h), which really does gate the on-hardware ladder. Publishing an unproven
security crate to satisfy an ordering diagram would be a disservice to the
ecosystem the contribution is meant to serve.

**R5 - two UR implementations.** ARCH adopts `foundation-ur` and explicitly rejects
`ur` (std by default); CAMERA.md section 6 recommends `ur`. Resolution:
`foundation-ur` + `foundation-urtypes`, one implementation, both with
default-features off. CAMERA.md's recommendation is superseded.

**R6 - GPL contagion through foundation-urtypes.** `foundation-urtypes` is
GPL-3.0-or-later. Any crate depending on it must be GPL. Resolution: all UR and
transport encoding stays inside notyas-wallet (GPL-3.0-or-later firmware), and no
extracted, permissively licensed crate may depend on it. This constrains Q8 rather
than being blocked by it.

**R7 - PARITY.md's row and class counts.** "61 feature rows" counts sections 1-6
only; the matrix has 72 rows. The class tally 30/17/12/6 recounts as 31/21/14/6.
Resolution: recorded as an erratum; assignment in section 7 is by row title.

**R8 - PARITY understates the PIN design.** PARITY section 2's preamble says the
notyas equivalent is "PIN-as-key-material, offline-hard but not attempt-limited".
The wave-1 design DOES attempt-limit, because the ladder passes through the
eFuse-keyed HMAC peripheral, so each guess needs the physical device, and wipe-on-N
destroys the record. Resolution: plan-0.2.0/SECURITY.md's tiered statement governs;
PARITY's preamble is superseded on this point. The honest limit is unchanged: the
counter is advisory against a fault-injection lab.

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

**R11 - duress is a record-format decision, not a late feature.** Wave 1 schedules
duress in the final milestone while its deniability package requires all slots to be
ciphertext-filled at all times. Adding filler slots after m4a ships would change the
on-flash format under existing users. Resolution: Q2 must be answered at m1; the
filler-slot format lands in m3; only the PIN-classification and UX half lands at m13.

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

**R19 - SeedQR display-out versus the no-secret-in-a-QR rule.** 0.1.0 invariant 2's
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

**R20 - anti-phishing words before provisioning.** The words derive from the eFuse
key, which is burned at first save. A blank stateless device therefore has no words,
and no screen or doc may imply it does.

---

## 9. What "done" means for 0.2.0

The release is done when: every milestone gate above is green on both verified
boards; every PARITY.md row is implemented, equivalent-and-documented, or deferred
with the reason in section 7; every SECURITY.md claim is mechanically enforced or
removed; both board images reproduce bit-for-bit on a second machine and the
reproduced binaries are the signed ones; and the published crates build from
crates.io for someone who has never seen this repository.
