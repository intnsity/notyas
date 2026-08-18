# notyas 0.2.0 - Milestones

Status: PLAN. Dependency-ordered; every milestone lands as a working, flashable
commit independently verifiable on hardware (0.1.0 house rule). Each lists scope,
crates touched, the test gate that must be green before the milestone closes, and
which research finding it implements.

**Ordering decision: storage before signing.** Justification from the dependency
graph: (1) the randomness/sealing decisions block the SECURITY.md rewrite, which the
project rule says must precede any claim the code implies; (2) the unlock session and
PIN flow are the substrate every signing screen assumes (a signer without a wallet
context has nothing to verify change against); (3) multisig registration - required
for safe multisig signing per the 2021 Coldcard attack - is itself storage; (4) the
Argon2id benchmark (m1) is a prerequisite for pinning any storage constant. Signing
depends on storage; storage depends on nothing signing provides. The audit's
dependency-ordered gap list reaches the same order.

---

## 0.2.0-m1: Foundations and decisions closed

Scope:
- Ratify OPEN-QUESTIONS decisions with the user; pin randomness policy (ARCH 2.4)
  and storage scheme (ARCH 2.1) into docs/SECURITY.md + SPEC.
- Root Cargo workspace + CI: build all crates at both geometries, run all tests,
  implement the SECURITY.md invariant-1 build-graph check for real (dependency-graph
  walk banning RNG/network crates, asserting secp256k1 present), covering the new
  dependency edges.
- Fix the two known 0.1.0 defects: uisim stale VerifyInfo (tools/uisim); firmware
  discarding UiRequest + notyas-core `qr` feature off (QR buttons dead on
  hardware) - wire UiRequest::Qr end to end.
- partitions.csv: add `wallets, data, 0x40, 0x410000, 256K, encrypted` AND
  `counters, data, 0x41, 0x450000, 16K` (plaintext - bit-clear counters are
  incompatible with XTS write granularity, ARCH 2.5/2.7); update flash.ps1 and the
  BOARDS.md flash section; verify both boards boot with the new table.
- On-device Argon2id benchmark harness (throwaway firmware path or feature flag):
  measure m=64 MiB PSRAM vs m=16 MiB SRAM at several t; MUST include a measurement
  with flash+PSRAM encryption enabled (P4 encrypts PSRAM traffic whenever flash
  encryption is on - ARCH 2.3), since that is what release units pay; record
  numbers in docs/plan-0.2.0/ and pin chosen parameters.

Crates: root workspace, firmware, notyas-ui (none-to-minor), tools.
Test gate: CI green on workspace; build-graph check fails on a planted rand dep;
QR modal reachable on hardware (photo evidence in the milestone note); benchmark
numbers committed.
Implements: audit "repo hygiene" + "blocking follow-up 2" (storage research 3.2:
never ship a guessed KDF cost).

## 0.2.0-m2: notyas-core signing API

Scope: `derive_path()` over arbitrary DerivationPath; `SecretSigningKey`
(zeroize-on-drop, redacting Debug, GetKey-compatible, Schnorr keypair + taproot
tweak); typed `root_fingerprint`; BIP-143/BIP-341 sighash vector tests; pinned
PSBT-sign known-answer check added to selftest.rs and the on-device boot self-test.
No policy logic here - notyas-core signs what it is told; refusing is
notyas-wallet's job.

Crates: notyas-core (only).
Test gate: sighash vectors green; sign-KAT green on host and on both verified
boards' Verify screens; no_std proof build still passes; zero new dependencies in
notyas-core.
Implements: signing research 1 (Psbt::sign / SighashCache as the only sighash path)
+ audit gap list item 6.

## 0.2.0-m3: notyas-wallet sealing + storage engine (host-proven)

Scope: new crate skeleton; Storage trait; two-slot record format + counter bit-log
with guard bits (in the separate plaintext counters region - ARCH 2.5); the full key
ladder (Argon2id -> HMAC-eFuse (trait-injected so host tests stub it) -> HKDF with
wipe_epoch in the info -> ChaCha20-Poly1305) with known-answer vectors; seal/unseal,
wrong-PIN, PIN-change re-seal WITH stale-inactive-slot erase (ARCH 2.6), wipe-on-N,
seal_seq monotonicity across wipe (epoch bump proven to change the key), host
power-loss fuzzer (truncate/corrupt at every offset; property: mount yields previous
or new record, never garbage, never a panic - including the erase-after-commit
window of a PIN change).

Crates: notyas-wallet.
Test gate: power-loss fuzz property holds over the full corpus; KDF/AEAD KATs green;
dependency-graph check green with the new crates; miniscript NOT yet in-graph
(enters in m6 - keeps this milestone's audit surface minimal).
Implements: storage research candidate A construction + Trezor norcow counter
design (https://docs.trezor.io/trezor-firmware/storage/index.html).

## 0.2.0-m4a: Storage on hardware + PIN unlock (minimal UI)

(Red-team split: the former m4 bundled the storage driver, eFuse provisioning, a
full notyas-ui restructure, and six new screens into one hardware-verification
step - too much to bisect when the first on-device unlock misbehaves. m4a proves
the storage stack on hardware with the minimum UI; m4b builds the real wallet
management UX on top of a proven substrate.)

Scope: firmware Storage-trait driver over esp_partition (wallets + counters
partitions); HMAC peripheral binding + eFuse key provisioning path (with
Verify-screen true-state readout); Ui::tick() + hold-to-confirm + horizontal-slop
fix; minimal functional screens 2 and 16 only (PIN entry with randomized pad +
anti-phishing words, lock screen); a bare-bones save/unlock path grafted onto the
existing create flow; session type with lock/timeout wipe; extended UiRequest
protocol (UnsealWallet/PersistWallet/...).

Crates: firmware, notyas-wallet (session), notyas-ui (minimal).
Test gate: on hardware - create wallet, power cycle, unlock, wrong-PIN counter
decrements and survives reboot AND power-cut mid-decrement, wipe-on-N destroys the
records and bumps the epoch, PIN change leaves no stale-PIN ciphertext (flash
readback), stateless path still writes nothing (verified by flash readback diff on
a dev board).
Implements: storage research 3.3 + audit firmware infrastructure 1-2.

## 0.2.0-m4b: Wallet management UI

Scope: per-screen module restructure of notyas-ui; shared danger-modal component;
screens 3, 5, 7, 15 (wallet list, backup verify quiz, wallet home, danger modals);
create/restore flows gain the mandatory backup-verify gate and the Save / Use-once
fork; delete with typed-name confirmation.

Crates: notyas-ui, firmware, tools/uisim (tour).
Test gate: UI flow tests driven through touch+tick at both geometries; masking
pixel tests extended to PIN and session screens; uisim tour renders the new
screens; on hardware - full create -> verify-backup -> save -> lock -> unlock ->
delete walk on both verified boards.
Implements: UX research screens 2-7/15/16 + audit UI sections 4.

## 0.2.0-m5: SD subsystem

Scope: per-board sd_init()/sd_deinit() (Elecrow 1-bit, Waveshare 4-bit pin research;
scaffolds stay UNTESTED); FATFS mount-on-demand lifecycle; file picker screen (9);
file size caps; SD export of xpubs/descriptors from the existing export screens;
"Verify external address" file input (8).

Crates: firmware (board surface), notyas-ui.
Test gate: on both verified boards - insert card, list files, read a file, write a
file, remove card at any idle moment without consequence; mount never held outside
an SD flow (asserted in code + tested); accepted-risk text landed in SECURITY.md
(FATFS not power-loss safe).
Implements: features.md airgap-IO research + audit firmware infrastructure 3.

## 0.2.0-m6: PSBT engine + single-sig signing end to end

Scope: miniscript enters the graph (vetting note recorded); policy engine
implementing ARCHITECTURE 5.3 checks 1-3 and 5-10 (multisig check 4 lands in m7);
change detection via descriptor derivation with gap bounds; adversarial PSBT corpus
(output substitution, fee inflation, change-path ransom, wrong network, sighash
games, duplicate/finalized inputs, missing prev-tx, oversized/truncated);
differential signing suite vs Bitcoin Core walletprocesspsbt on regtest; screens
9-11 (load, review, deliver-to-SD); hold-to-sign; refusal screens with asserted
text.

Crates: notyas-wallet, notyas-ui, firmware.
Test gate: every corpus case triggers its exact expected verdict and rendered text;
differential suite - byte-identical to pinned vectors, Core-verified/accepted on
regtest (byte-equality vs Core's own output only per Q13, ECDSA only); on
hardware - full Sparrow SD round
trip on testnet (all four script types), including a deliberately hostile PSBT
refused with the right screen; post-sign miniscript interpreter gate demonstrably
wired (mutation test: break a sig, gate catches it).
Implements: signing research sections 2 + 5 (the checklist and the notyas-wallet
gap list).

## 0.2.0-m7: Multisig

Scope: registry records (sealed storage, from m3/m4a); descriptor + Coldcard .txt
import with membership/M/N/format/derivation verification; screen 12; multisig
change verification (check 4) wired into the policy engine; multisig address
verification in the explorer; BIP48 xpub export packaging.

Crates: notyas-wallet, notyas-ui, firmware.
Test gate: corpus gains the xpub-substitution and multisig-change-confusion attack
cases (both must be refused); on hardware - register a 2-of-3 P2WSH with Sparrow +
two other signers on testnet, verify first receive address cross-device, sign as
one cosigner (partial PSBT emitted, other sigs preserved), sign as the completing
cosigner (finalized, -final.txn written); delete requires typed name.
Implements: signing research 3 + the benma/Coldcard disclosure defenses.

## 0.2.0-m8: UR2 animated QR-out

Scope: foundation-ur integration (crypto-psbt type name for ecosystem compat);
tick-driven frame advance in the main loop; pause/speed/density controls + frame
counter on screen 11; fragment default 200 bytes; encoder round-trip tests against
reference vectors; static-QR path reuse.

Crates: notyas-wallet (chunking params), notyas-ui, firmware.
Test gate: host round-trip vs reference decoder vectors; on hardware - Sparrow
webcam-scans a signed multisig PSBT off both verified boards at default and lowest
density; "idle device performs zero repaints outside active animation" re-proven.
Implements: signing research 4 (transport sizing) + UX commandment 9.

## 0.2.0-m9: Hardening closeout and release

Scope: duress PIN + any accepted OPEN-QUESTIONS extras; SECURITY.md/ARCHITECTURE.md/
BOARDS.md final rewrites land (from plan texts, re-audited against what is
mechanically enforced); extended boot self-test (seal/unseal KAT, reduced-cost KDF
KAT with documented rationale); Verify screen storage/anti-rollback/HMAC-key
readouts; release-unit runbook: eFuse HMAC key provisioning, flash encryption,
secure boot, anti-rollback order-of-burns; reproducible-build check across the
workspace; signed release per board.

Crates: all; docs; tools.
Test gate: full CI matrix green; on-device self-test green on both verified boards
with storage populated and blank; a red-team pass over SECURITY.md claim-by-claim
("mechanically enforced or not made"); release artifacts reproduce on a second
machine; 0.1.0-parity check - a blank device walks the 0.1.0 golden flows
byte-identically.
Implements: storage research blocking follow-ups 1-3 closure + audit section 5
items 5-7.

---

Deferred beyond 0.2.0 (recorded so nothing forecloses them): blind-oracle unlock
mode, BSMS ceremony, taproot multisig, SeedQR display, message signing, PSBT v2,
encrypted SD backup (unless Q8 accepted), Key Manager path (rev >= v3.0 silicon).
