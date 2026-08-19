# PUBLISH-0.2.0.md - the exact sequence for publishing notyas 0.2.0

Operator-facing and copy-pasteable. Every command below runs in **Git Bash** from the
repository root. This file is the ordered transcript; `docs/RELEASE-0.2.0.md` is the
reasoning behind each gate, `tools/release.sh` is the enforcement, and `docs/VERIFYING.md`
is what a stranger does with the result.

---

## 0. Read this before you open a terminal

**One machine runs all eight stages.** `tools/release.sh` stamps each stage into
`out/release/0.2.0/stamps/`, which is gitignored and local, and every stage refuses to
start until the previous stage has a stamp **at the current commit** on the same disk.
There is no way to run `tag` on one host and `build` on another. So pick the host first,
and it must have all four of:

| Needs | Used by | Present on this workstation |
| --- | --- | --- |
| the release **secret** key `A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D` | `tag`, `sign` | **NO** - `gpg --list-secret-keys` reports "No secret key", and the public half is not in this keyring either |
| `docker` | `build`, `reproduce` | **NO** - not on PATH |
| `riscv32-esp-elf-nm`, plus that toolchain's `gcc` and `strip` | `build` (Q41 gate and its self-test) | yes, under `~/.espressif/tools/riscv32-esp-elf/esp-14.2.0_20260121/` |
| push access to `origin` | `publish` | yes |

**This workstation cannot cut the release.** It holds neither the secret key nor Docker.
Run the whole sequence on the machine that holds the release key, and install Docker there
if it is not present. Do not attempt to split the sequence: `tools/release.sh publish`
calls `stamp_require preflight gates hardware tag build reproduce sign`, and a stamp made
on another host is not on this host at all.

If that machine is not x86-64 Linux, the container build in `build` and `reproduce` runs
under emulation and takes several times as long. `docs/VERIFYING.md` section 2 says the
same thing to verifiers.

**The release identity**, RSA-4096, created 2026-08-15:

```
A1E9 53B2 5C6A 623B 77A1 D522 3AC4 BBCF E51A B37D
```

The RSA-3072 `intnsity-esp` key of 2026-08-18 is retired and its secret half destroyed. It
signs nothing, ever. `tools/ci/check-ratified.sh` is the detector for a document that
confuses the two, and the `gates` stage runs it.

**Never `git push --tags`, never `git push --mirror`.** The local tag set still carries
`v0.1.0`, `v0.1.0-m1`, `v0.1.0-m3`, `v0.1.0-m4`, `origin-v0.1.0`, `v0.2.0-m1`, `v0.2.0-m3`
and `plan-0.2.0-reconciled`. A bare `--tags` restores the entire 0.1.0 lineage that was
deliberately removed when the repository was recreated; `--mirror` additionally publishes
`refs/rollback/*`. Push the branch, then the single tag by name. That is what
`tools/release.sh publish` does, and it is the only form to use by hand.

---

## 1. Preconditions

Run these in order. Each has an expected result; do not proceed past a mismatch.

### 1.1 Authorship, before anything else

First, because the repository was deleted and recreated on 2026-08-19 after a tool identity
appeared in the contributor list and could not be removed. GitHub builds that list from the
author and committer fields, not from commit messages.

```sh
git log --all --format="%an <%ae>%n%cn <%ce>" | sort -u
```

Expected, exactly these three lines and nothing else:

```
GitHub <noreply@github.com>
intnsity <85849955+intnsity@users.noreply.github.com>
intnsity <at@intnsity.com>
```

Any fourth line stops the release. Do not push and then clean up: a contributor entry that
has reached GitHub is what cost the previous repository.

The prose half, separately:

```sh
bash tools/ci/check-commit-messages.sh HEAD
```

Expected: exit 0, no findings. A bare ref means the whole history, which is what a release
wants rather than just the tip.

### 1.2 The branch and the working tree

```sh
git rev-parse --abbrev-ref HEAD     # expected: main
git status --porcelain              # expected: NO OUTPUT AT ALL
```

`git push origin HEAD` in the publish stage pushes the current branch, so be on `main`.

The empty `git status` is not a formality. The container build takes `git archive` of HEAD,
so an untracked file is invisible to it: the release would silently lack a file you can see
on disk. `tools/release.sh preflight` fails on any output here.

> **State on 2026-08-19:** the tree at `C:\notyas` is **dirty** - dozens of modified files
> and at least one deletion (`crates/notyas-ui/src/screens.rs`). The release commit has not
> been made. Commit or discard everything before starting; the hooks in `.git/hooks`
> (`pre-commit`, `commit-msg`) enforce authorship and dash hygiene on the way in, and they
> are not to be bypassed.

### 1.3 The tag does not exist yet

```sh
git rev-parse -q --verify refs/tags/v0.2.0 ; echo "exit $?"
```

Expected: no output, `exit 1`. If it prints a hash, the tag already exists - see section 4.

### 1.4 The version

```sh
grep -m1 '^version' firmware/Cargo.toml    # expected: version = "0.2.0"
```

`firmware/Cargo.toml` is the single source: that value lands in the app descriptor, in
every artifact name, in `VERIFY.json`, and on the device Verify screen.

### 1.5 The key, on this machine and in the tree

```sh
gpg --list-secret-keys A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D
```

Expected on the signing machine: one `sec rsa4096 2026-08-15` block. "No secret key" means
you are on the wrong machine - stop here, not at stage `tag`.

```sh
gpg --show-keys --with-fingerprint docs/keys/A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D.asc
```

Expected: exactly one primary key, `rsa4096`, created `2026-08-15`, fingerprint
`A1E9 53B2 5C6A 623B 77A1 D522 3AC4 BBCF E51A B37D`. `--show-keys` parses without
importing, so nothing touches the keyring. This is the copy `docs/VERIFYING.md` sends a
stranger to; a file is named by whoever wrote it, so the key inside it is the claim.

### 1.6 The gates, green

```sh
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
bash tools/ci/check-ratified.sh
bash tools/ci/check-dashes.sh
bash tools/ci/check-hil-fence.sh
bash tools/ci/check-target-dir.sh
```

Expected: exit 0 from each. Last verified: 1034 host tests passing with 0 failures,
graphics gate 6/6, clippy clean, `check-ratified`, `check-dashes` and `check-hil-fence`
all PASS.

> **`check-target-dir.sh` currently FAILS**, on a stale `C:\notyas\target` tree left behind
> by an earlier `check-screenshots.sh` run. It is red for a real reason and it is **not**
> invoked by `tools/release.sh` or by CI, so nothing downstream will stop for it. Remove
> the tree yourself before starting:
>
> ```sh
> rm -rf /c/notyas/target
> bash tools/ci/check-target-dir.sh    # expected: exit 0, silent
> ```

Both boards build:

```powershell
.\tools\build.ps1 -Board waveshare-4b --features unsafe-emulated-key,hil-console
.\tools\build.ps1 -Board elecrow-5 --features hil-console
```

Those are bench builds, not release artifacts. A release artifact is only ever what comes
out of the container in stage `build`.

### 1.7 No stale cross-check verdict

```sh
ls out/xverify/
```

Expected: empty, or no such directory.

> **State on 2026-08-19:** `out/xverify/attestation.json` exists with **no**
> `attestation.json.run` binding beside it. On a machine without `bitcoind` and embit the
> `gates` stage refuses on exactly this. Read it, then remove it:
>
> ```sh
> rm -f out/xverify/attestation.json out/xverify/attestation.json.run
> ```

### 1.8 The stage plan

```sh
tools/release.sh
```

Prints the version, the tag, HEAD, the artifact directory, the release key, and each of the
eight stages as `not run`, `passed at HEAD` or `STALE`. Run it whenever you lose your
place. It changes nothing.

---

## 2. The stages, in order

Every stage is idempotent and re-runnable. A stage writes its stamp only if everything it
checked passed, and **a stamp made at a different commit does not count** - amending
anything sends you back to the stage that covered it.

### Stage 1 - `preflight`

```sh
tools/release.sh preflight
```

Checks that the tree is clean, that `v0.2.0` does not exist, that the version parses, that
all four of `docs/VERIFYING.md docs/RELEASE-0.2.0.md docs/SECURITY.md
docs/plan-0.2.0/REPRODUCIBLE.md` name the release fingerprint, and that
`docs/keys/<fpr>.asc` really holds one RSA-4096 key created 2026-08-15 which is neither
revoked nor expired. It notes, rather than fails, a missing secret key or
`riscv32-esp-elf-nm`.

Refuses: a dirty tree, an existing tag, a document naming the wrong key, a key file holding
a different key, more than one key in that file, or a revoked or expired one.

### Stage 2 - `gates`

```sh
tools/release.sh gates
```

The mechanical gates, cheapest first: dash hygiene, commit-message hygiene, the build graph
(SECURITY invariants 1 and 3), supply chain, ratified decisions, the two self-tests that
prove the signature check and the cross-check binding can say **no**, the airgap source
tier, repro pins, screenshots, `cargo test --locked`, clippy at `-D warnings`, the
power-loss fuzzer, the third-party cross-check against Bitcoin Core and embit, and the
three `no_std` bare-metal checks.

Refuses: any red gate - a gate is never waived and there is no override flag. It also
refuses to stamp when a gate could not run here. `check-xverify` needs `bitcoind`,
`bitcoin-cli` and a python that can import embit; the `no_std` checks need the
`riscv32imac-unknown-none-elf` target and `riscv64-unknown-elf-gcc`. Neither is on a
Windows bench. An unavailable gate is not a passed gate, so name where it did run:

```sh
tools/release.sh gates --ci-evidence "ci run https://github.com/intnsity/notyas/actions/runs/<id>, green at $(git rev-parse HEAD)"
```

Take that URL from the CI run at **this exact commit**, and confirm the run is green before
quoting it.

### Stage 3 - `hardware`

```sh
tools/release.sh hardware --ack "gauntlet green on waveshare-4b and elecrow-5, 2026-08-__, notes in docs/QA.md"
```

Records an acknowledgement of the five things no script here can observe: every milestone
exit gate on both boards, the `docs/QA.md` pre-handover gauntlet, the whole-loop test, a
release unit walking `docs/PROVISIONING.md`, and the claims audit. Do the work before you
type the sentence.

Refuses: a missing `--ack`.

### Stage 4 - `tag`

```sh
tools/release.sh tag
```

Creates the signed annotated tag `v0.2.0` at HEAD, with `-u` pinning the release key
explicitly rather than trusting the machine's default signing key, then verifies it with
`git verify-tag --raw` and a `VALIDSIG` match against the pinned fingerprint. Never
`git tag -v`, which prints the tag **message** the signer chose.

Refuses: an existing `v0.2.0`, no `gpg`, no secret key on this machine, or a tag that came
out signed by anything other than the release key.

This is the first irreversible-shaped step, and it is still local. See section 3.

### Stage 5 - `build`

```sh
tools/release.sh build
```

Builds the release container, then runs `tools/repro/build.sh` inside it once per board -
`waveshare-4b` and `elecrow-5` - into `out/release/0.2.0/artifacts/`. It wipes that
directory first, because a leftover from an earlier attempt would be hashed into
`SHA256SUMS.txt`. Then, against what came out: the Q41 self-test **once, first** (it
synthesises console-bearing RISC-V ELFs, stripped ones included, and asserts the gate
rejects each of them); then per board `verify-manifest.py check`, the airgap **image** tier,
and `check-release-symbols.sh --image`, which is Q41 - that the HIL test console is absent
from the image that ships; then `sha256sum -c` plus the count equality that catches a file
nobody hashed.

Refuses: no `docker`, a tag that no longer points at HEAD, a missing `riscv32-esp-elf-nm`,
a Q41 self-test that does not fail when it should (that stops the stage on the spot - an
"ok" printed by a broken gate is worse than no gate), any per-board finding, or a file in
the artifact directory that `SHA256SUMS.txt` does not name.

Hours, not minutes.

### Stage 6 - `reproduce`

```sh
tools/release.sh reproduce --attestation /path/to/second-machine/SHA256SUMS.txt
```

Two halves. `tools/repro/check-repro.sh` builds each board twice on this machine, from two
different host paths, at different times, the second run handed a deliberately hostile
environment, and compares every byte. Then the second machine's hash list is reduced to
`<hash> <basename>` and diffed against ours.

If no second machine ran:

```sh
tools/release.sh reproduce --no-second-machine
```

That is a recorded choice, not a silent one: the release notes must then say plainly that
the two-machine run did not happen for this tag, because `docs/VERIFYING.md` tells readers
to look for exactly that statement.

Refuses: a missing attestation file, and - the important one - any byte difference between
the two machines. **That difference is the finding this whole process exists to produce.**
Do not sign anything; triage with `docs/VERIFYING.md` section 9 item 3.

The second-machine question is settled before the double build, so you learn you have no
attestation in a second rather than after hours of building.

### Stage 7 - `sign`

```sh
tools/release.sh sign
```

Re-hashes every artifact **before** signing - the gap between building and signing is
exactly where a compromised host would act - then writes the detached armored signature
`SHA256SUMS.txt.asc` with the release key and verifies it the way a stranger will, against
the pinned fingerprint. Prints the one reproducibility line the release notes must carry.

Refuses: running inside CI (`$CI` set - the release key does not touch hosted
infrastructure), no `gpg`, no secret key, a `SHA256SUMS.txt` that no longer describes the
directory, or a signature that turns out to be from some other key.

Copy the printed `reproducibility:` line now; it goes into the release notes verbatim.

### Stage 8 - `publish`

```sh
tools/release.sh publish --confirm
```

Before touching the network it re-establishes **every** fact the push makes public, because
a stamp binds a stage to a commit and cannot bind a tag object or a file on disk to the one
that was checked: that `v0.2.0` still points at HEAD; that it still verifies under the
release key; that `docs/keys/<fpr>.asc` **as committed at HEAD** still holds that key; that
`SHA256SUMS.txt.asc` verifies over the hash list; every check stage `build` made against
the artifact directory, in full; and that the cross-check verdict in `out/xverify` is the
one this run's `gates` stage produced, or that there is none.

Then, and only then:

```sh
git push origin HEAD
git push origin v0.2.0
```

Refuses: no `--confirm`, a moved tag, a bad signature on either object, a key file in the
commit that is not the release key, an artifact directory that has changed since `build`,
or a cross-check verdict this run did not write.

---

## 3. The irreversible points, named

**I1. `tools/release.sh tag` creates the tag.** Local, and still reversible:
`git tag -d v0.2.0` undoes it completely as long as it has not been pushed. This is the
last point at which anything can be undone cleanly.

**I2. `git push origin HEAD`, inside `publish`.** The commit becomes public. Nothing after
this is undoable in the sense that matters - people can already have fetched it.

**I3. `git push origin v0.2.0`, one line later.** The tag becomes public. From here the tag
is a permanent public claim: `docs/RELEASE-0.2.0.md` section 8 rule 1 is **do not delete or
move the tag** - publish a fix as a new version instead.

**The gap between I2 and I3 is real.** The two pushes sit adjacent with nothing between
them, so if the tag push fails - dropped connection, expired credential, rejected ref - the
commit is already public and untagged. That state is recoverable, and the wrong reaction is
worse than the state:

```sh
# 1. Find out what actually landed.
git ls-remote --heads origin main
git ls-remote --tags  origin v0.2.0     # NO output means the tag push failed

# 2. Fix the cause (credentials, network), then push the single tag by name.
#    NOT --tags. NOT --mirror. Nothing else needs re-pushing.
git push origin v0.2.0

# 3. Confirm.
git ls-remote --tags origin v0.2.0      # one line ending in refs/tags/v0.2.0
```

Do not delete the local tag, do not re-tag, and do not amend the pushed commit to start
over: the tag is already correct and already verified against the fingerprint, and amending
would invalidate every stamp and orphan a public commit. Re-running
`tools/release.sh publish --confirm` is equally safe - it re-runs every check and both
pushes, and the branch push is then a no-op.

If `git ls-remote --tags origin v0.2.0` shows a tag whose object differs from your local
one, stop and force nothing. Something else pushed a `v0.2.0`.

**I4. Publishing the GitHub release.** The artifacts become downloadable and people begin
verifying against them. Create it as a draft first - section 5.

**I5. eFuse provisioning burns** are one-way per unit and belong to `docs/PROVISIONING.md`,
not to this file. Nothing in this runbook burns anything.

---

## 4. When a stage refuses

| Message | Cause | Fix |
| --- | --- | --- |
| `stage 'X' passed at <sha> but HEAD is now <sha>` | you committed, amended or rebased after stage X | re-run from stage X. This is the stamp doing its job |
| `working tree has uncommitted or untracked files` | anything in `git status --porcelain` | commit it or remove it. `git archive` cannot see untracked files, so the release would not contain them |
| `v0.2.0 already exists` | a previous attempt tagged | if it has **not** been pushed: `git tag -d v0.2.0` and continue. If it **has** been pushed: stop. Do not move a published tag; release the fix as a new version |
| `the release secret key ... is not on this machine` | wrong host | move to the machine holding the secret key and start from `preflight` there. Stamps do not travel |
| `gates: N gate(s) failed` | a red gate | fix it. A gate is never waived |
| `name where they did run` after `gates` | `check-xverify` or the `no_std` checks could not run here | re-run with `--ci-evidence 'ci run <url>, green at <commit>'`, quoting a green CI run at this exact commit |
| `out/xverify holds a cross-check verdict this release run did not produce` | a stale or unbound `attestation.json` - the current state of this tree | `rm -f out/xverify/attestation.json out/xverify/attestation.json.run`, then re-run `gates` |
| `the gates stamp records no cross-check run id` | the stamp was written by an older `release.sh` | re-run `tools/release.sh gates` |
| `docker is not on PATH` | wrong host, or Docker not installed | the container build is the normative one. A host build is not a release artifact, however identical it looks |
| `the Q41 gate did not reject an image carrying the HIL console` | `selftest-release-symbols.sh` failed, usually a missing `riscv32-esp-elf` `gcc`, `strip` or `nm` | fix the toolchain. Until the self-test passes, a clean Q41 report proves nothing |
| `SHA256SUMS.txt does not list these files, and they are here` | a file appeared in the artifact directory after the build | find out what wrote it. Do not delete it and move on without knowing, then re-run `build` |
| `the second machine's artifacts differ` | the reproducibility claim is false for this tag | STOP. Triage with `docs/VERIFYING.md` section 9 item 3. Sign nothing |
| `refusing to sign inside CI` | `$CI` is set in the environment | sign on a human's machine. Clear `CI` only if you are certain this is not a runner |
| `signed by <fpr>, which is not the release key` | gpg used a different key | run `gpg --list-secret-keys` and find out which. Delete the tag or the signature and redo it with the right key. Plain `gpg --verify` would have exited 0 here and printed "Good signature" - that is precisely why this check reads the status stream |
| `publication is the irreversible half` | `--confirm` missing | re-run with `--confirm` once the artifacts and the notes are ready to be public |

---

## 5. After the push

`tools/release.sh publish` prints this list; it is repeated here with the commands.

**5.1 Check the GitHub side for identities git cannot show you.** The contributor entry
that caused the deletion was never in any commit, so a clean history is necessary and not
sufficient:

- **Settings -> Integrations / GitHub Apps** - any installed app. This is the specific
  thing to look at.
- **Settings -> Collaborators**.
- **Insights -> Contributors**, once the commits have landed and the graph has built.

**5.2 Create the release as a draft**, from the tag, attaching every file in the artifact
directory and nothing else. That directory was asserted to hold exactly the files
`SHA256SUMS.txt` names, plus the list and its signature: an unlisted file is an unsigned
file.

```sh
ls out/release/0.2.0/artifacts/
gh release create v0.2.0 --draft --title "notyas 0.2.0" \
  --notes-file /path/to/release-notes.md \
  out/release/0.2.0/artifacts/*
```

The notes follow the skeleton in `docs/RELEASE-0.2.0.md` section 7, in that order: what
0.2.0 is **and does not do**, in the same paragraph; section 5 items 1 to 11 in full; the
interop change from section 6; the fingerprint inline plus a pointer to
`docs/VERIFYING.md`; the exact `reproducibility:` line stage `sign` printed; the
provisioning burn; the artifact list and which board slug is which.

Review the draft's asset list against the hash list, then publish:

```sh
gh release view v0.2.0 --json assets --jq '.assets[].name' | sort
awk '{sub(/^[0-9a-f]+ +\*?/, ""); print}' out/release/0.2.0/artifacts/SHA256SUMS.txt | sort
gh release edit v0.2.0 --draft=false
```

The two listings must agree except for `SHA256SUMS.txt` and `SHA256SUMS.txt.asc`, which are
in the release and not in the list.

**5.3 Publish the key in a second place.** `docs/keys/<fpr>.asc` ships with the push;
confirm the same key is on keys.openpgp.org, so a verifier comparing the fingerprint has
two independent sources rather than one server.

```sh
gpg --keyserver keys.openpgp.org --recv-keys A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D
```

---

## 6. Post-publish verification: what a stranger runs

Run this yourself first, on a machine that has never held this repository, downloading only
from the release page. Everything before this point was checked by someone who knew the
answer. What follows is the abbreviated form of `docs/VERIFYING.md` steps 2 to 4; hand
strangers that document, not this one.

```sh
mkdir /tmp/notyas-check && cd /tmp/notyas-check
gh release download v0.2.0 --repo intnsity/notyas
```

**Hashes.** Proves only that the bytes match what the page served.

```sh
sha256sum -c SHA256SUMS.txt --ignore-missing
```

Expected: `OK` on every line.

**Signature - pinned, not merely "good".** `gpg --verify` exits 0 for **any** key in the
keyring, and its `Good signature from intnsity` line is reading a uid the signer chose for
themselves. The forty hex digits are the only part an impostor cannot copy.

```sh
gpg --keyserver keys.openpgp.org --recv-keys A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D

gpg --status-fd 1 --verify SHA256SUMS.txt.asc SHA256SUMS.txt 2>/dev/null \
  | grep '^\[GNUPG:\] VALIDSIG .*A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D'
```

Expected: **one line**, exit 0. No output means the release key did not sign it, whatever
name gpg printed above.

```sh
gpg --status-fd 1 --verify SHA256SUMS.txt.asc SHA256SUMS.txt 2>/dev/null \
  | grep -E '^\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG)'
```

Expected: **no output** - the opposite of the check above. A revoked or expired key still
produces a `VALIDSIG` and still exits 0, alongside one of these five lines saying so.

**The tag.** Authenticates the source revision independently of wherever the artifacts are
hosted. `git tag -v` prints the tag **message**, which the signer wrote and which an
impostor can fill with the real fingerprint, so ask git for gpg's status stream instead.
`-c gpg.format=openpgp` pins the scheme, so a machine configured for ssh signing cannot
answer in a format that carries no fingerprint to compare.

```sh
git clone https://github.com/intnsity/notyas && cd notyas
git -c gpg.format=openpgp verify-tag --raw v0.2.0 2>&1 \
  | grep 'VALIDSIG .*A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D'
```

Expected: one line, exit 0.

**The key file in the tree**, as the second independent source:

```sh
gpg --show-keys --with-fingerprint docs/keys/A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D.asc
```

Expected: one primary key, `rsa4096`, `2026-08-15`, that fingerprint.

**Rebuild.** The step that makes the others worth doing: 30 to 90 minutes on x86-64 Linux
with Docker.

```sh
git checkout v0.2.0
docker build -t notyas-repro:0.2.0 -f tools/repro/Dockerfile .
docker run --rm -v "$PWD":/mnt/src:ro -v "$PWD/out":/out notyas-repro:0.2.0 waveshare-4b
cd out && sha256sum -c <(grep waveshare-4b /tmp/notyas-check/SHA256SUMS.txt)
cmp notyas-0.2.0-waveshare-4b-app.bin /tmp/notyas-check/notyas-0.2.0-waveshare-4b-app.bin
```

Then walk `docs/VERIFYING.md` steps 5 to 8 with a board in hand: flash what you built,
provision, and compare the device readout against the manifest. Section 9 of that document
is what to do when something does not match.
