# notyas 0.2.0 - release runbook

Owner-facing. This is the ordered list of gates between "the milestones are done" and
"the release is public", what ships, what deliberately does not, and the limitations the
release notes have to state rather than let a buyer discover.

The verifier-facing counterpart is `docs/VERIFYING.md`: what a stranger does with the
artifacts this runbook produces. Anything promised there has to be true here, and the two
documents are meant to be read together before a tag is cut.

`tools/release.sh` is the executable form of section 2. It refuses to run a stage
until the previous stage has passed at the current commit, so the order below is enforced
rather than remembered. It runs no hardware gate and signs nothing on its own.

```
tools/release.sh              # the stage plan, and where this release stands
```

---

## 0. What a 0.2.0 unit can, cannot, and has not been shown to do

This section is first because it is the one that decides whether a stranger's expectations
are met. Everything in it was checked against the tree on 2026-08-19 by following each
control from the panel down to the firmware arm that answers it. It describes a device
flashed from a release artifact - not a bench unit running a `hil-console` build, which is a
different image with different capabilities (K10).

Three lists, not two. The third is the one an owner is most likely to collapse into one of
the others, and collapsing it in either direction produces a false release note.

**A 0.2.0 unit can:**

- Generate a recovery phrase from dice, at 12, 15, 18, 21 or 24 words, with the entropy
  accounting on the screen while the rolls are entered.
- Restore a phrase by typing it, with BIP-39 autocomplete, a checksum verdict, and the
  final-word helper.
- Apply a BIP-39 passphrase, which is never stored and never leaves the screen that took it.
- Prove the backup, word by word, before anything else is offered.
- Show the derived public material: the account xpub for each supported scheme, the SLIP-132
  rendering where one exists, receive addresses, and a QR code for each.
- Report on itself: firmware digests, eFuse security state, the running partition, and the
  boot counter, on the Verify device screen.
- Choose mainnet or testnet for the next derivation.
- **Set a first PIN and seal a wallet into flash**, on an eFuse-provisioned board. S-06 and
  S-07 raise `UiRequest::SetPin`; `answer_set_pin` (`firmware/src/main.rs:1263`) formats the
  sealed store, and `answer_persist_wallet` seals the wallet into the lowest free slot.
- **Unlock a stored wallet after a power cycle** and open it, with the anti-phishing words
  at half-PIN entry, an attempt counter, and a wallet list.
- **Mount and browse a microSD card**, from the sign-source screen and the multisig import
  screen (`UiRequest::ListCard` into `flow::list_card` into `firmware/src/sd/`).
- **Load a PSBT off the card, review it, and sign it.** The file is read under a size cap,
  decoded, and put through the ten-check pipeline with no signing key in scope; the hold
  control exists only once every review page has been visited
  (`crates/notyas-ui/src/screens/review.rs:1417`), and `flow::sign_tx` answers it.
- **Write the signed transaction back to the card** under a name the panel showed before the
  write, with a collision asked about rather than resolved, or discard it
  (`flow::write_signed`, `flow::discard_signed`).
- **Import, verify, register and delete a k-of-n P2WSH `sortedmulti` wallet** from a
  descriptor or a Coldcard setup file on the card. Membership is proven from the seed before
  any screen renders the wallet (`flow::read_and_verify`), and an approved registration is
  sealed into the registry.

The eight requests that used to be answered with a refusal - `ListCard`, `LoadPsbt`,
`SignTx`, `WriteSigned`, `DiscardSigned`, `ImportRegistration`, `ApproveRegistration`,
`DeleteRegistration` - are routed into `crate::sd` and `crate::signing` by
`firmware/src/flow/mod.rs`, which holds one wallet open across the screens that need it.
`RefusalCode::NotInThisBuild` now has no firmware caller at all.

**A 0.2.0 unit cannot:**

- **Sign from a keep-in-session wallet.** Sign and Multisig are offered only on a wallet
  that came out of a slot, because the only seed the firmware ever holds is one it unsealed
  (`crates/notyas-ui/src/screens/wallet.rs:181`). A stateless signing entry does not exist.
- **Store, and therefore sign, on a board that has not been eFuse-provisioned.** A release
  image accepts one key provenance, `EfuseReadProtected` (`firmware/src/store/mod.rs:67`).
  An unprovisioned board is the 0.1.0 stateless seed tool and public-key exporter, exactly
  as before.
- **Delete a stored wallet** (`firmware/src/main.rs:725`), **commit a wipe-policy change**
  (`:740`), **change the PIN** (`:762`) or **remove the PIN** (`:778`). Four screens exist
  for operations the firmware refuses: erasing a record has no published route through
  `Store`, and the other three re-seal or destroy sealed records and need a fresh PIN
  confirmation this UI cannot collect. K15 and K16 carry the detail; only one of the four
  refusals reaches the user in words.
- **Finalize a transaction.** `sd::plan` is called with `finalized: false` and nothing in
  this workspace finalizes a PSBT. A coordinator does that.
- **Take a transaction in over anything but the card.** No supported board has a camera, and
  the UR2 and BBQr codecs have no screen.
- **Receive a card at all on a Waveshare 4B in its OEM chassis or in the desk stand this
  repository ships** (K6). The board runs plate-off for 0.2.0, and the release notes have to
  say so.
- **Scan the reserved flash spans** on the Verify screen: no reader in this build, so the
  row answers `not read` (K22).
- **Taproot multisig, BSMS, backup of any kind, BIP-85, BIP-137 message signing, SeedQR
  decode.**

**A 0.2.0 unit has not been shown to:**

- **Do any of the card, review, signing or registration work from the panel of a device.**
  That path is wired and compiled; the engines under it and the screens over it are
  host-tested, `firmware/src/flow/model.rs` is host-tested as the device links it
  (`firmware/hostcheck/tests/review_model.rs`), and the plumbing between them -
  `firmware/src/flow/mod.rs`, which touches the store, the card and ESP-IDF - can only be
  covered by a hardware run. No one has done that run. The end-to-end loop that has run on hardware was driven through the development
  console, on a `hil-console,unsafe-emulated-key` build, on the board that is not
  eFuse-provisioned (`docs/clause2-evidence.md`) - it shares the engine with the panel path
  and none of the screen wiring.
- **Do it on the only unit where it could be done.** Of the two verified boards only the
  Elecrow 5inch is eFuse-provisioned, and the panel signing path needs a provisioned board.
- **Report single-sig change correctly on hardware.** The hardware run found the firmware
  calling `psbt::inspect` where it needed `inspect_with_accounts`, so half of validation
  check 3 never ran on the device and single-sig change was counted as money leaving. Fixed
  at `firmware/src/signing.rs:358-363` with host tests behind it, and not re-run on
  hardware.

So: **0.2.0 as an artifact is a signer, and no unit has yet been watched signing from its
own panel.** On a provisioned board it creates or restores a seed, seals it under a PIN,
survives a power cycle, registers a multisig, reads a PSBT off a card, reviews it, signs it
and writes the result back. On an unprovisioned board it is the 0.1.0 stateless seed tool.
Neither sentence is optional in a release note, and the second category above is the one
that decides how the first is worded: the code path is real and the hardware evidence for
that path is one console-driven run plus a host suite.

Two consequences for the rest of this runbook. First, the pre-handover gauntlet in section
2D and the exit gates in 2C are now startable - `MILESTONES.md` section 9 clause 2 requires
the whole loop including SD ingress and signed delivery, and that loop now has an on-device
path, so the gate is a run to perform rather than a gap to disclose. Second, section 5 below
still is not optional prose: items 8 through 12 there are what a buyer would otherwise
assume the other way.

---

## 1. Before anything else

**The release identity.** notyas releases are signed with the OpenPGP RSA-4096 key
`intnsity`, created 2026-08-15:

```
A1E9 53B2 5C6A 623B 77A1 D522 3AC4 BBCF E51A B37D
```

This is the maintainer's single release identity: desktop BigDice signs with the same key,
and `docs/plan-0.2.0/SECUREBOOT.md` section 4 and `docs/plan-0.2.0/REPRODUCIBLE.md` 5.2
both say so. What must never be offered as this key is the RSA-3072 `intnsity-esp`
identity, generated 2026-08-18 and retired on 2026-08-19 with its secret half destroyed.
SECUREBOOT.md section 4 is the authority on why a GPG key can never be a secure-boot key,
and it is also where the third key that must not be confused with either of these, the
future Secure Boot v2 signing key, is described. A document that still calls the release
identity RSA-3072 sends a verifier to a key that signs nothing; `tools/ci/check-ratified.sh`
`[KEY]` is the detector for that, and gate B5 runs it on the release path.

Before tagging, every release-facing document must name the notyas key, and the public
half must be exported to
`docs/keys/A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D.asc`, because `docs/VERIFYING.md`
sends the reader there as one of the independent sources they compare against.
`tools/release.sh preflight` checks both mechanically.

**The version.** `firmware/Cargo.toml` is the single source of the version. It lands in
the app descriptor, therefore in every artifact name, in `VERIFY.json`, and on the device
Verify screen. It must read `0.2.0` before the tag is cut, and the tag is `v0.2.0`.

**The documents that ship.** `README.md`, `docs/SECURITY.md`, `docs/ARCHITECTURE.md`,
`docs/BOARDS.md`, `docs/VERIFYING.md`, `docs/PROVISIONING.md`, `docs/KNOWN-ISSUES.md` and
this file. The claims audit in section 2E is what makes them shippable.

---

## 1b. Pushing: what must NOT go up

The GitHub repository was deleted and recreated on 2026-08-19 after a tool identity
appeared in its contributor list and could not be removed. 0.1.0 went with it, by
decision: **only 0.2.0 is published to the new repository.** That makes the push itself a
step with its own failure mode, so it gets its own list.

**Never `git push --tags`.** The local tag set still carries the whole 0.1.0 lineage -
`v0.1.0`, `v0.1.0-m1`, `v0.1.0-m3`, `v0.1.0-m4` and `origin-v0.1.0` - plus in-progress
milestone tags `v0.2.0-m1`, `v0.2.0-m3` and `plan-0.2.0-reconciled`. A bare `--tags`
restores every one of them to the new repository and undoes the decision. Push the single
release tag by name:

```
git push origin main
git push origin v0.2.0
```

**The rollback refs are safe but check anyway.** `refs/rollback/*` are outside
`refs/heads` and `refs/tags`, so no ordinary push sends them. `git push --mirror` DOES,
and would publish the entire local ref namespace including the 0.1.0 rollback points.
Do not use it on this repository.

**Verify authorship before the push, not after.** The check is mechanical and covers both
halves - the prose and the identity, because GitHub builds its contributor list from the
author and co-author fields rather than from commit messages:

```
bash tools/ci/check-commit-messages.sh HEAD
git log --all --format="%an <%ae>%n%cn <%ce>" | sort -u
```

The second command is the one that matters here and it must list only
`intnsity <at@intnsity.com>`, `intnsity <85849955+intnsity@users.noreply.github.com>` and
`GitHub <noreply@github.com>`. It was clean across all 126 commits on 2026-08-19.

**A clean history is necessary and not sufficient.** The contributor entry that caused the
deletion was not in any commit - the local history was and is clean. Check the GitHub side
before and after the push: Settings -> Integrations / GitHub Apps for any installed app,
Settings -> Collaborators, and the Insights -> Contributors graph once commits land. An
installed app can appear regardless of what the git history says.

## 2. The gate list, in order

Ordering is the substance of this section, so the reason for it is stated first:

1. **Cheap before expensive.** A pin mismatch found in six seconds is the same finding as
   one found after an hour of container build.
2. **Everything before the tag.** A signed tag is a public claim about a commit. Moving
   one is a history rewrite, and this project has paid for one of those already.
3. **The tag before the build.** Artifacts are a function of the committed tree, so the
   tag names the tree they came from rather than being applied afterwards to whatever
   produced a good-looking result.
4. **Reproduction before signature.** Signing a build nobody reproduced voids the whole
   chain `docs/VERIFYING.md` asks a stranger to walk: the signature would attest to bytes
   whose provenance nobody checked. This is MILESTONES section 9 item 5 and it is the one
   ordering rule with no exception.
5. **Signature before publication, on a machine that is not a CI runner.** The release key
   does not touch hosted infrastructure (`REPRODUCIBLE.md` 6.3). CI computes hashes; a
   human signs them.
6. **Re-checked at the irreversible boundary.** A stamp binds a stage to a commit; it
   cannot bind a tag object or a file on disk to the one that was checked. Stage J
   verifies the tag, the signature and every artifact hash once more in the seconds
   before the push, because that is the last moment any of it can be found wrong.

### A. Freeze

| # | Gate | How |
| --- | --- | --- |
| A1 | Version bumped to 0.2.0 in `firmware/Cargo.toml` | edit, commit |
| A2 | Working tree clean, no untracked files | `git status --porcelain` empty. The container build takes `git archive` of HEAD, so an untracked file is invisible to it and would silently not ship |
| A3 | `v0.2.0` does not already exist | `tools/release.sh preflight` |
| A4 | The release key is named consistently and exported to `docs/keys/` | `tools/release.sh preflight` |
| A5 | `docs/KNOWN-ISSUES.md` is current, with each open entry marked blocking or not | by hand |
| A6 | A `riscv32-esp-elf-nm` is reachable, on PATH or under `~/.espressif` | `tools/release.sh preflight` |

`tools/release.sh preflight` covers A2 to A4 and A6 mechanically and fails with the exact
fix for each. A6 is the one row that only warns: it is a note here and fatal in stage G,
where the Q41 gate and its self-test read the linked ELF with that `nm`. It is asked this
early because there is nothing to be gained from learning it after a container build and
a tag.

### B. Host gates (mechanical, no hardware)

`tools/release.sh gates`, cheapest first. Every one of these also runs in CI on every
push; running them again at the release commit is the point, not duplication.

| # | Gate | Command | What it proves |
| --- | --- | --- | --- |
| B1 | Dash hygiene | `tools/ci/check-dashes.sh` | ASCII hyphens only, tracked and untracked |
| B2 | Commit hygiene | `tools/ci/check-commit-messages.sh HEAD` | no forbidden token in the message |
| B3 | Build graph | `tools/build-graph-check.sh` | SECURITY invariants 1 and 3: no RNG source, no network stack, no closed crypto blob anywhere in the graph, and secp256k1 genuinely present |
| B4 | Supply chain | `tools/ci/check-supply-chain.sh` | every dependency resolves to crates.io with a checksum, nothing patched or path-escaped |
| B5 | Ratified decisions | `tools/ci/check-ratified.sh` | the tree agrees with every owner decision it can be checked against, `[KEY]` included: that the release identity is the rsa4096 fingerprint `tools/release.sh` signs with, and that every document in its `KEY_DOCS` names it |
| B6 | Airgap, source tier | `tools/ci/check-airgap.sh --source-only` | the tree asks for no radio, and the kill GPIO is driven low first |
| B7 | Reproducible-build pins | `tools/ci/check-repro-pins.sh` | the four files that must agree about the toolchain do agree |
| B8 | Screenshots | `tools/ci/check-screenshots.sh` | the committed renders are what the UI produces today |
| B9 | Host suite | `cargo test --locked` | every vector suite, host side |
| B10 | Lints | `cargo clippy --locked --all-targets --all-features -- -D warnings` | clean under the crates' own deny lists |
| B11 | Power-loss fuzzer | `cargo test --locked --release -p notyas-wallet --test powerloss -- --ignored --nocapture` | the m3 storage exit gate: a cut at every step boundary of every storage operation |
| B12 | Third-party cross-check | `tools/ci/check-xverify.sh --require` | every derivation and signature this release makes is accepted by Bitcoin Core and embit, the one bar nothing inside this tree can answer (MILESTONES section 9 clause 2) |
| B13 | no_std | `cargo check --locked -p <crate> --target riscv32imac-unknown-none-elf` for core, ui and wallet | no crate quietly acquired std |

B5 exits 2, not 1, when an assertion cannot be evaluated at all - a renamed constant, a
moved block. `tools/release.sh gates` treats that as a failed gate, which is the point:
an assertion nobody can evaluate is a decision nobody is checking.

B12 and B13 are the two that a bench may not be able to run. B12 needs `bitcoind`,
`bitcoin-cli` and a python that can import embit, and is probed first
(`check-xverify.sh --probe`) so that a machine without a node reports it UNAVAILABLE
rather than blocking outright. B13 needs the RISC-V target and `riscv64-unknown-elf-gcc`
for secp256k1-sys, which the Windows bench does not have. `tools/release.sh gates` reports
either as unavailable rather than skipping it, and will not stamp the stage until you name
where it did run (`--ci-evidence 'ci run <url>, green at <commit>'`). An unrun gate is not
a passed gate.

The airgap IMAGE tier is deliberately not here. It needs a release ELF, so it runs in
stage G against the artifact that ships, which is the only tier that proves invariant 1
about the thing a user receives.

**What CI runs and this stage does not.** Stated because the sentence above ("every one of
these also runs in CI") reads easily as the converse, which is false. On 2026-08-19 five
gates existed in `.github/workflows/ci.yml` with no invocation anywhere in
`tools/release.sh`: `check-advisories.sh` (a published advisory against the pinned
lockfile), `check-hil-fence.sh` (executes the two build-script refusals that keep the HIL
console and the emulated device key out of a product image - the source-side half of what
stage G proves about the artifact), `check-heap-residue.sh`, and `selftest-commit-identity.sh`
(the proof that B2 can fail, exactly as `selftest-release-symbols.sh` is the proof that
stage G's Q41 gate can). `tools/ci/check-target-dir.sh` is invoked by neither. Until they
are wired here, the release path takes them on trust from a green CI run at the same
commit, and `--ci-evidence` does not cover them because they never report as unavailable:
they are never asked.

### C. Milestone exit gates (both boards, owner)

Each milestone in `docs/plan-0.2.0/MILESTONES.md` carries its own exit gate, quoted and
evidenced in its closing commit or in `MEASUREMENTS.md`. All of them must be green on
**both** verified boards, with one stated exception: gates marked `[HW-CAMERA]` may be
outstanding, in which case `docs/BOARDS.md` and the artifact both say
`camera: built, not hardware-verified` and the four camera parity rows stay class c. No
other gate may be outstanding and no gate may be waived (MILESTONES section 9 item 1).

| Milestone | Subject |
| --- | --- |
| m1 | Foundations, ratified decisions, frozen storage geometry |
| m2 | notyas-core signing API |
| m3h | esp-idf-hmac over the P4 security peripherals |
| m3 | Sealing and storage engine, host-proven |
| m4a | Storage on hardware and PIN unlock |
| m4b | Wallet management UI |
| m5 | SD subsystem |
| m6 | PSBT engine and single-sig signing end to end |
| m7 | Multisig, P2WSH sortedmulti |
| m8 | Animated QR out, UR2 plus BBQr interop |
| m10 | Addresses and exports |
| m11 | Camera scan-in, board A only, `[HW-CAMERA]` |
| m12 | Reproducible builds |
| m13 | Hardening closeout and this release |

Also from `docs/QA.md`, per milestone: the previous milestone's gates re-run and still
green (item 5), and a rollback ref at the closing commit (item 6).

### D. Pre-handover gauntlet (owner, both boards)

`docs/QA.md`, "Pre-handover gauntlet", in full. Summarised here so the runbook is
self-contained, but that document is the authority:

- **Flows, end to end:** stateless dice to QR with a flash readback proving nothing
  persisted; first save, power cycle, unlock; wrong PIN to the threshold minus one then a
  correct PIN; PIN change with a power cut mid-change; both wipe paths with flash readback;
  PIN off; a single-sig PSBT from SD verified against an independent verifier and accepted
  by a coordinator; a multisig PSBT with and without its registration; every adversarial
  corpus case refused with the right code; the Verify screen against an independent
  reading of the same facts.
- **Robustness:** power cut at every step boundary of every storage operation, malformed
  and oversized PSBTs, absent or removed SD card, every screen at both resolutions with the
  longest plausible content, and the one hour idle soak with zero repaints.
- **Consistency with the documents:** every SECURITY.md invariant mechanically enforced or
  struck; every PARITY.md row implemented, equivalent or deferred with its reason visible;
  every number the UI states about itself recomputed independently.

Plus the whole-loop test that MILESTONES section 9 item 2 makes the actual bar: create or
import a seed, save it under a PIN, power cycle, unlock, register a 2 of 3 P2WSH multisig,
verify the first receive address against another signer, load a PSBT from SD, review it,
sign it, and have a coordinator accept the result. If that loop has a gap, the release is
not done regardless of what else is green.

**As of 2026-08-19 that loop has an on-device path at every point, and has not been run
over one.** Setting a PIN, opening a card, reviewing and signing a PSBT and registering a
multisig are each answered by real firmware - `answer_set_pin` and the eight arms
`firmware/src/flow/mod.rs` serves - so the gate is now a run somebody performs rather than a
gap somebody discloses. Until that run happens on the eFuse-provisioned board, the bar is
not met, and it is not met for a different reason than before: not "there is no path" but
"the path has not been walked". Section 0's third list is the current statement of what that
leaves unproven.

The run needs the provisioned Elecrow unit specifically. A `hil-console` build does not
satisfy this gate: it is a different image, and driving the engine from a console proves the
engine and not the product (K10).

And the release-unit runbook: a unit walks `docs/PROVISIONING.md`, one eFuse burn, and
still passes every gate afterwards.

### E. Claims audit (owner, and the second half of m13)

Every shipped document is read claim by claim against what is mechanically enforced. The
specific hunt, from the m13 exit gate, is for any sentence implying that any of these
exists in 0.2.0. All seven are false:

1. Secure Boot v2
2. eFuse anti-rollback
3. a hardware-held signing key
4. third-party attestation of the reproducible build
5. a backup mechanism
6. BSMS
7. taproot multisig

Two known amendments belong here rather than being made silently: SECURITY invariant 2
splits into 2a and 2b, because stateless becomes opt-in once storage exists, and its
0.1.0 corollary "there is no private-key export path at all" is restated as "no key
material is ever written to flash in plaintext, to SD, or into any QR; derived private
values appear only on screen behind the existing reveal gates".

`tools/release.sh hardware --ack` records that C, D and E were done, by whom and when. It
records an acknowledgement, not a result: nothing in this repository can observe them.

### F. Tag

```
tools/release.sh tag
```

Signed annotated tag `v0.2.0` at the release commit, made with the release key explicitly
rather than with whatever the machine's default signing key is, then verified against the
PINNED FINGERPRINT with `git verify-tag --raw` and a `VALIDSIG` match - never with plain
`git tag -v`, which prints the tag MESSAGE the signer chose and would say "Good signature"
for an impostor whose message quotes the real fingerprint. The tag authenticates the source
revision independently of wherever the artifacts end up hosted, which is why
`docs/VERIFYING.md` tells a verifier to check it.

### G. Build

```
tools/release.sh build
```

Builds the release container and runs `tools/repro/build.sh` inside it once per board.
Nothing about the image is produced outside that container: a file some other command
produced is not a release artifact, however identical it looks. Then, against what came
out, in this order:

- `selftest-release-symbols.sh`, once, BEFORE any per-board verdict. It synthesises RISC-V
  ELFs carrying the console's symbols, its UART entry points and its string literals -
  including stripped ones - and asserts that `check-release-symbols.sh` rejects every one
  of them and clears a console-free image. A gate that has only ever passed is
  indistinguishable from a gate that cannot fail, and this is the run that tells the two
  apart. A failure stops the stage on the spot: an "ok" printed by a broken gate is worse
  than no gate, so no per-board Q41 verdict is produced after one.
- `verify-manifest.py check --manifest <board> --dir <artifacts>` per board, which is the
  same command `docs/VERIFYING.md` hands the verifier.
- `check-airgap.sh --image <board>.elf` per board. This is the tier that proves SECURITY
  invariant 1 about the shipped image rather than about the tree that asked for it: the
  IDF link line carries the WiFi and lwIP archives on every build, and whether any member
  survives `--gc-sections` is a property of the ELF alone.
- `check-release-symbols.sh --image <board>.elf` per board: **Q41**, that the HIL test
  console is absent from the image that ships. It reads the linked ELF rather than the
  build configuration, because `firmware/build.rs` and `firmware/src/hil.rs` state what
  was ASKED for and three such fences have already been broken by profile shapes a build
  script could not see. There is no probe-first path and no skip: a missing `nm`, an
  unrecognisable file, a stripped image and an image it cannot find are all failures.
  Nowhere else has this artifact, so this gate cannot be deferred to CI evidence the way
  B12 and B13 can. The stamp records the verdict, the tool that made it and the commit.
- `sha256sum -c SHA256SUMS.txt`, plus a count check, so that no file in the output
  directory escaped being hashed.

Both symbol steps need `riscv32-esp-elf-nm` (and, for the self-test, that toolchain's
`gcc` and `strip`). They cannot run in `.github/workflows/ci.yml` - its own header records
that nothing about a linked image is checked there - which is why they belong to this
stage and to no other.

### H. Reproduce

```
tools/release.sh reproduce --attestation /path/to/second-machine/SHA256SUMS.txt
```

Two halves, and the second is the one that matters:

1. `tools/repro/check-repro.sh` builds each board twice on this machine, from two
   different host paths, at different times, handing the second run a deliberately hostile
   environment, and compares every byte.
2. A **second machine** builds the same tag and its `SHA256SUMS.txt` is compared against
   ours. MILESTONES section 9 item 5 makes this a condition of the release being done.

If the second machine has not run, `--no-second-machine` records that fact and the release
notes must then say plainly that the two-machine gate did not happen for this tag.
`docs/VERIFYING.md` tells readers to look for exactly that statement, so silence there is
a broken promise rather than an omission.

A difference between two machines is the finding this entire process exists to produce.
Do not sign anything; triage with `docs/VERIFYING.md` section 9 item 3.

### I. Sign

```
tools/release.sh sign
```

Re-hashes every artifact before signing, because the gap between building and signing is
exactly where a compromised host would act and closing it costs a second. Produces the
detached armored signature over `SHA256SUMS.txt` with the release key, then verifies it
the way a stranger will. Refuses to run inside CI.

### J. Publish

```
tools/release.sh publish --confirm
```

First re-establishes, in seconds, the three facts the push makes public: that `v0.2.0`
still points at HEAD, that it still verifies under the release key, and that
`SHA256SUMS.txt.asc` verifies over a hash list every artifact on disk still matches.
Nothing above binds those to the stages that checked them, so they are checked again here.

Then pushes the current branch (`git push origin HEAD`, so run it on `main` - see 1b, and
never `--tags`) and the tag by name, and prints the manual remainder: create the release
from the tag, attach every file listed in `SHA256SUMS.txt` and nothing that is not (an
unlisted file is an unsigned file), paste the release notes, and publish the key.

### K. Post-publish: walk it as a stranger

Take `docs/VERIFYING.md` on a machine that has never held this repository, download only
from the release page, and do the whole thing: hashes, signature, container rebuild, byte
comparison, flash, provision, compare the device against the manifest. Everything before
this point was checked by someone who knew the answer.

---

## 3. What ships

Per board, for `waveshare-4b` and `elecrow-5`:

| Artifact | What it is |
| --- | --- |
| `notyas-0.2.0-<board>-app.bin` | the application, flashed at 0x10000 |
| `notyas-0.2.0-<board>-bootloader.bin` | second stage bootloader, 0x2000, differs per board because the flash size is in the header |
| `notyas-0.2.0-<board>-partition-table.bin` | 0x8000, identical across boards |
| `notyas-0.2.0-<board>-merged.bin` | the three above plus 0xff padding, for one flash command |
| `notyas-0.2.0-<board>.elf` | unstripped release ELF, so a verifier who finds a difference can triage it |
| `notyas-0.2.0-<board>-sdkconfig.txt` | the merged sdkconfig actually used |
| `notyas-0.2.0-<board>-BUILDINFO.txt` | toolchain versions, input hashes, environment |
| `notyas-0.2.0-<board>-VERIFY.json` | the verification manifest: both digests and the length of each member of the boot chain, the composite `firmware_digest`, and the parsed partition table |

Plus, once: `notyas-0.2.0-src.tar.gz`, `notyas-0.2.0-components.tar.gz`,
`SHA256SUMS.txt`, and `SHA256SUMS.txt.asc`.

**0.2.0 ships binaries. 0.1.0 did not, and the reason it did not is the reason it can
now.** The 0.1.0 README states the policy plainly: releases were source only and unsigned,
because shipping unsigned binaries for a Bitcoin wallet invites substitution attacks.
Nothing about that judgement has changed; what changed is that the two things it was
waiting for now exist. There is a signature over the hash list, so a substituted download
does not verify, and there is a reproducible build, so the signature attests to bytes
anyone can independently regenerate from the published source. Publishing binaries without
both would still be wrong, and publishing them with both is the point of m12.

Two limits on that, which belong in the release notes rather than here alone: the signing
key sits on a general-purpose machine (Q30), and no third party has yet published their
own hash list for a notyas tag (Q31).

---

## 4. What deliberately does not ship

| Not shipped | Why |
| --- | --- |
| Secure Boot v2 signed images, and any secure-boot eFuse burn | Q32 deferred to 0.3.0. `docs/plan-0.2.0/SECUREBOOT.md` owns the design and the burn order; nothing in 0.2.0 burns a digest slot |
| Flash encryption | same decision. Release-mode flash encryption also disables the UART download path `espefuse` needs, so it has to land after HMAC provisioning, not before |
| eFuse anti-rollback | same decision; `secure_version` is carried in the manifest but no fuse enforces it |
| Any eFuse burn beyond one HMAC key | ratified Q63(a). Exactly one burn per device, host side, `docs/PROVISIONING.md` |
| Artifacts for the eight scaffold boards | they are compile-checked and have never run on hardware. Source only, and `docs/BOARDS.md` says which is which |
| The camera variant `waveshare-4b-camera` | only if m11's `[HW-CAMERA]` gates were met on real hardware. If they were not, no artifact, and the camera parity rows stay class c |
| Anything on crates.io | Q46. No crate in this workspace publishes in 0.2.0 |
| A backup mechanism, BSMS, taproot multisig | not implemented. Named here because a reader of the surrounding documents could reasonably assume otherwise |
| A hardware-token-held signing key | Q30 remains open, and it is the weakest link in the chain the verification documents build |
| Third-party build attestation | Q31 remains open. The invitation to produce one is in `docs/VERIFYING.md` |

**This table is about decisions, and it is not the whole of what a unit cannot do.** A row
here means the work was scoped out on purpose. Two other categories exist and section 0 owns
both: operations whose screens are on the panel and whose firmware arm refuses them - delete
a wallet, change the PIN, remove the PIN, commit a wipe policy - and subsystems that are
finished, host-tested and reached by no screen, which after the m6 wiring is a much shorter
list than it was: the UR2 and BBQr transport codecs, SeedQR decode, BIP-85 and BIP-137
message signing. Reading section 4 alone would leave a reader believing that everything
absent from it is present in the artifact, which is the error this note exists to prevent.

---

## 5. Known limitations a buyer must read

These belong in the release notes verbatim, not behind a link.

1. **No Secure Boot v2 and no flash encryption.** The consequence is specific and it is
   the most important sentence in the release: on a 0.2.0 unit the Verify screen reports
   what the running firmware says about itself, and if the reader did not build and flash
   that firmware themselves from a reproduced image, the screen cannot prove it is the
   firmware they think it is. `docs/VERIFYING.md` is the way out, and it is the reason
   that document leads with the same sentence.
2. **No independent security audit.** None has been performed and none is claimed.
3. **Two boards.** Everything else in `docs/BOARDS.md` is a source-verified scaffold that
   has never run.
4. **No secure element.** The ESP32-P4 has none and notyas adds none. Physical extraction
   from a running, powered device in an attacker's hands is out of scope, as is
   supply-chain replacement of the hardware itself.
5. **One eFuse burn is required before the device can store anything**, it is
   irreversible, and it is performed by the owner on the host, not by the firmware
   (`docs/PROVISIONING.md`).
6. **The signing key is on a general-purpose computer** (Q30), and **no third party has
   attested the reproducible build** (Q31).
7. **The open entries in `docs/KNOWN-ISSUES.md`**, each with its blocking verdict:
   K1 (a documented m3 gate command reports FAILED on success), K3 (the HIL console
   cannot erase a store it refused to mount, behind a non-default feature and therefore not
   in the shipped image), K4 (the m4a power-cut window is sampled rather than swept). K2
   is a development-host defect with no exposure in the artifact and is recorded for
   completeness.
8. **Signing, the card and multisig registration have never been driven from the panel of
   a device.** The path is wired, compiled and covered by the host suite. The only
   end-to-end hardware run to date was driven through the development console, on a
   `hil-console,unsafe-emulated-key` build, on the board that is not eFuse-provisioned
   (`docs/clause2-evidence.md`). A buyer is entitled to know that the first person to sign
   a real transaction from the touch UI may be them.
9. **Signing requires an eFuse-provisioned board and a stored wallet.** A release image
   accepts only `EfuseReadProtected` key provenance, so an unprovisioned unit has no store,
   no PIN and no Sign action; and even on a provisioned unit, a wallet kept in session
   rather than sealed cannot sign, because the firmware never holds that seed. An
   unprovisioned board is a seed tool and public-key exporter, which is a legitimate way to
   own the hardware and is not what "signer" means.
10. **Four operations have screens and no implementation**: delete a stored wallet (K15),
    change the PIN and commit a wipe-policy change (K16), and remove the PIN. All four are
    refused in `firmware/src/main.rs`, three of them without words on the panel. A user who
    walks the delete flow, including its typed-name consent, watches the wallet survive.
11. **A PSBT cannot reach a Waveshare 4B in the enclosure this repository ships** (K6): the
    microSD slot is behind the backing plate, and the desk stand in `3dp/` does not open it.
    That board runs plate-off for 0.2.0. **The Verify screen's reserved-space scan always
    answers `not read`**, because this build has no reader for it (K22).
12. **A cross-check this project published before 2026-08-19 was not independent.**
    `tools/psbtgen verify`'s segwit-v0 path recomputed the BIP-143 digest by calling the
    same `notyas_core::sign` function the device signs with, so a defect in that function
    would have cancelled out and been reported as agreement. Every green segwit-v0 ECDSA
    result that tool produced before that date is the signer agreeing with itself, and no
    claim of independent segwit-v0 verification made before then holds. It is fixed - the
    ECDSA path now goes straight to rust-bitcoin's `SighashCache`
    (`tools/psbtgen/src/verify.rs:1300-1336`) - and the taproot path always went straight to
    `taproot_key_spend_signature_hash`, so it was independent throughout and is unaffected.
    The judgement in `docs/clause2-evidence.md` that never depended on this is Bitcoin Core
    29.4 finalizing the device-signed file.

Items 8 through 12 are the ones a buyer is most likely to have assumed the other way, and
section 0 states them together at the top of this document for that reason.

---

## 6. The interop change every cosigner user must be told about

**A PSBT that was accepted earlier on 2026-08-18 is now refused, deliberately, and this
belongs in the release notes rather than in a support thread.**

### What changed

The device refuses a PSBT when both of the following are true:

- it would sign at least one input whose signature does not commit to every input amount
  in the transaction, which means any segwit v0 input (BIP-143 covers its own input's
  amount and nothing else, under every sighash flag it has); and
- any input in the file states its amount without proving it, which means a
  `witness_utxo` with no `non_witness_utxo`.

The refusal is `UnprovenAmountBesideOurSignature` under check 2, previous transactions,
and it names both ends of the pair, because either end is one a sender can fix.

**A cosigner's already finalized input is not exempt.** Being finalized says nothing about
an amount, so a finalized input that carries only a `witness_utxo`, sitting beside a
segwit v0 input of ours, is exactly the refused case. That combination is the one most
likely to surprise a coordinator, which is why it is called out by name here.

### Why

This is BIP-174's own line 415 footnote enforced rather than quoted: the previous
transaction is required "to ensure that the amounts of other inputs are not being tampered
with". The demonstration in the test suite is a two-round probe. Each round presents one
proven 1 BTC coin of ours and one claimed 20,000 sat coin, so each round's arithmetic
lands on the ordinary 10,000 sat fee that every other fixture declares. The two rounds
share one unsigned transaction, so the signatures combine, and the two coins really behind
that transaction are 1 BTC each against a payment of 1.0001 BTC. The loss is 0.9999 BTC
and it is invisible in every number either review screen could have shown, which is why
this is a refusal and not a warning.

### What still works

- A cosigner's finalized input that carries its previous transaction.
- A taproot spend of ours beside a claimed amount: BIP-341 hashes every input amount into
  the digest under SIGHASH_DEFAULT, so our own signature makes those amounts binding. That
  holds only while the sighash whitelist stays at SIGHASH_DEFAULT for taproot, and the
  test suite fails loudly if it is ever widened to an ANYONECANPAY flag.
- A file this device signs nothing in: with no signature of ours, there is nothing for a
  substituted amount to ride on.
- The published BIP-174 vectors, for the same reason. Two of them are refused, but for a
  different and older reason: vectors 2 and 7 state no amount at all for their single
  input, so there is no fee to show, and that refusal predates this change.

### What a coordinator has to do

Include the full previous transaction (`non_witness_utxo`) for every input, not only for
the ones this device signs. Coordinators that omit it for segwit inputs to save space will
produce files this device refuses. That is the cost, it is known, and it buys the closure
of a demonstrated one-coin loss.

---

## 7. Release notes skeleton

Paste into the GitHub release, in this order, and do not reorder it so the good news comes
first:

1. One paragraph on what 0.2.0 is, written from section 0 of this document and not from
   the milestone list. It must name what the unit does - dice and typed-word seed
   generation, an optional passphrase, the backup check, public-key and address export
   with QR, the device-verification screen, sealed storage under a PIN, multisig
   registration, and PSBT review and signing over microSD - and in the same paragraph it
   must name the two conditions on that and the one thing missing behind it: signing needs
   an eFuse-provisioned board and a stored wallet, and nobody has yet driven the signing
   loop from a device's panel. Claiming the capability without the second half is the
   specific way this paragraph can be false while every clause in it is true. So is the
   opposite error - the previous draft of this runbook described the unit as unable to
   sign at all, which stopped being true when m6 landed.
2. **Read this first**: section 5 of this document, items 1 to 12, in full.
3. The interop change: section 6, at least "what changed", "why" and "what a coordinator
   has to do".
4. Verification: point at `docs/VERIFYING.md` and give the key fingerprint inline.
5. Reproducibility status: the exact line `tools/release.sh sign` prints, which is either
   that a second machine matched or that the two-machine run did not happen for this tag.
6. Provisioning: one eFuse burn, irreversible, `docs/PROVISIONING.md`. State the burn's
   purpose accurately - it binds the sealing key ladder to the silicon - and do not pair it
   with a promise about what the device does afterwards. The accurate pairing is the other
   way round: without the burn a unit runs, derives and exports, and stores nothing and
   signs nothing; with it, storing and signing become reachable (section 0).
7. The artifact list and which board slug is which.

---

## 8. If a defect surfaces after publication

1. **Do not delete or move the tag.** It has been downloaded and it is what a verifier
   compares against. Publish a fix as a new version.
2. **Say so on the release page immediately**, at the top of the notes, naming what is
   wrong and what a holder should do about it. A quiet fix in a later version is how a
   user with funds behind the defect finds out last.
3. **If the defect is in the signing or verification chain** rather than in the firmware
   (a wrong hash list, a signature over the wrong artifacts, a key confusion), treat the
   artifacts as unverifiable and say so plainly: unpublish them, publish corrected ones,
   and never quietly replace a file that a hash list already covers.
4. **Add it to `docs/KNOWN-ISSUES.md`** with its found-date, its blocking verdict and what
   closing it requires, whether or not it is fixed in the same breath.
