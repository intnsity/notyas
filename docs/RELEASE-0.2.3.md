# notyas 0.2.3 - release runbook

Owner-facing. 0.2.3 is the packaging repair for 0.2.2. The firmware delta from `v0.2.2`
(`16dfff2`) is the version string and nothing else; everything a unit does, refuses and
displays is what 0.2.2 decided, and the three decisions in `docs/archive/RELEASE-0.2.2.md` remain
authoritative. What changed is the machinery that turns a tagged commit into a signed
artifact, which until this release had never once run to completion.

Nothing in section 0 of `docs/archive/RELEASE-0.2.0.md` about what a unit can, cannot, and has not
been shown to do is superseded, and neither is anything in `docs/archive/RELEASE-0.2.1.md` or
`docs/archive/RELEASE-0.2.2.md`. Read all four; this one is the shortest because it changes the
least about the product.

The verifier-facing counterpart is `docs/VERIFYING.md`, unchanged by this release. The gate
list and process are `tools/release.sh`; nothing about the order of gates changed for 0.2.3,
only the version they run against and the runbook they point at.

```
tools/release.sh              # the stage plan, and where this release stands
```

---

## 0. What 0.2.3 is, and what happened to 0.2.2

`v0.2.2` was tagged, signed and pushed on 2026-08-21 at `16dfff2`. Its host gates were
green: 1309 tests across 54 suites, `clippy -D warnings` clean, the dash and ratified gates
clean. Its two-board hardware pass had run. And **no `v0.2.2` artifact exists**, because the
release container could not be built - `tools/repro/Dockerfile` failed at step 5 of 7, on
GitHub Actions and on every local host, every time it had ever been attempted. There is
therefore no `notyas-0.2.2-waveshare-4b-app.bin`, no `merged.bin`, no `SHA256SUMS.txt` and
no signature over one. The GitHub release page for `v0.2.2` carries no downloadable image.

**The tag stays exactly where it is.** It is the honest record of a firmware release whose
packaging did not work, and rewriting it would replace a true statement with a tidy one.
0.2.3 is the repair, published the ordinary way, and the sentence a holder needs is short:
if you want a 0.2.2 image there is none, and 0.2.3 is the same firmware with a version
string that says so.

This is the first release of notyas for which a reproducible-build artifact has ever been
produced. That is a milestone and it is also a warning: the machinery downstream of the
container - `reproduce`, `sign`, `publish` and their binding checks - is running for the
first time on this release too. Section 5 says which parts have been rehearsed and which
have not.

---

## 1. The root cause, named

Two defects, one hiding the other. Both are in the container recipe, neither is in the
firmware, and neither could have been found by any host gate.

**The first stopped the build.** `tools/repro/Dockerfile` line 64 sourced ESP-IDF's
`export.sh` inside a `RUN` step and then called `idf_tools.py`:

```
RUN . $IDF_PATH/export.sh \
 && python $IDF_PATH/tools/idf_tools.py install esp-clang
```

`export.sh` has to work out where ESP-IDF lives before it can activate it. In ESP-IDF v5.5
it tries `$BASH_SOURCE`, then `$ZSH_VERSION`, and only then falls back to the `IDF_PATH`
already in the environment - and it accepts that fallback on one condition: that the file
`/.dockerenv` exists. Docker's engine creates `/.dockerenv` in every container it starts,
which is why this command succeeds under `docker run`. BuildKit, which executes `RUN` steps,
does not create it in its build sandbox. So under `docker build` the detection chain runs
off the end, the script's idea of where ESP-IDF lives stays at `.`, the working directory is
`/`, there is no `./tools/idf.py` there, and the step dies with the message that names the
symptom and not the cause:

```
Could not automatically detect IDF_PATH from script location.
```

`/bin/sh` being dash rather than bash is a necessary condition and not the cause: dash
sources the same script successfully under `docker run`, because there `/.dockerenv` is
present. The distinguishing fact between the two contexts is that one file. Proved by
tracing the same command in both: under `docker build` the `[ -f /.dockerenv ]` test
evaluates false and takes the error branch; under `docker run` it evaluates true, prints
"Using the IDF_PATH found in the environment as docker environment detected", and proceeds
to a full activation. A two-line Dockerfile with no notyas layers at all fails identically,
which rules out anything the earlier layers leave behind.

**The second would have shipped a broken pin.** `idf_tools.py install esp-clang` installs
Espressif's clang COMPILER package. Since the upstream split that package carries no
`libclang.so` at all - only `libLTO.so`. The libclang that `bindgen` loads lives in a
separate ESP-IDF tool, `esp-clang-libs`, described upstream as the "Standalone Clang shared
libraries distribution". So every workaround that keeps `export.sh` and installs only
`esp-clang` makes the error stop without installing the library the step exists to pin. That
miss would then have been swallowed at run time by a third defect, in `build.sh`: its
libclang discovery took `dirname` of an empty `find` result, and `dirname ""` prints `.`,
which is a directory, which passes the `[ -d ]` guard. The `die` that exists precisely to
catch a missing libclang could never fire; `LIBCLANG_PATH=.` would have been exported and
the failure would have surfaced as something unreadable deep inside the cargo build.

**What changed, in four places.**

- `tools/repro/Dockerfile`: the `export.sh` line becomes a direct
  `RUN python3 $IDF_PATH/tools/idf_tools.py install esp-clang esp-clang-libs`. No activation
  in a build layer - `idf_tools.py` needs only `IDF_PATH` and `IDF_TOOLS_PATH`, both of which
  the pinned base image sets as image ENV, and this is how ESP-IDF's own `install.sh` invokes
  it. Activation stays `build.sh`'s job at run time, where it happens under bash in a real
  container and both detection paths work. Both halves of the split clang distribution are
  installed, so `libclang.so` lands where `build.sh` looks for it.
- `tools/repro/build.sh`, libclang discovery: the empty `find` result is caught before
  `dirname` sees it, so a missing libclang dies with a message naming `esp-clang-libs`
  instead of silently exporting `LIBCLANG_PATH=.`.
- `tools/repro/build.sh`, the merged image: `esptool` was being handed espflash's spelling of
  the flash size. The board table carries `32mb` because that is what `espflash save-image`
  takes; `esptool`'s `--flash-size` choice list is uppercase and rejects anything else at
  argument parsing, under both the modern and the legacy subcommand spelling. The esptool
  spelling is now derived from the board table's rather than duplicated in it. This defect
  was found by running the container to completion for the first time, one step past where
  the Dockerfile had always stopped.
- `tools/ci/check-heap-residue.sh`: builds `notyas-ui` with `--features notyas-core/qr`, the
  feature every real consumer of that crate already unifies in. See section 3.

`tools/repro/toolchain.lock` also changed: its seven pending pins are filled with the values
the first completed container run printed. They were pending because no container run had
ever existed to read them off.

---

## 2. What the fix is not

Recorded because each of these stops the error and none of them is the right change, and a
future reader deserves the reasoning rather than the conclusion.

- **`IDF_PATH_FORCE=1` before sourcing.** It is the escape hatch the error message itself
  advertises, it reads as suppressing a safety check, it depends on `export.sh` internals
  that upstream has already rewritten once, and it still installs only `esp-clang` - so the
  build goes green while the library the step exists to pin never lands.
- **`SHELL ["/bin/bash", "-c"]`, or wrapping the line in `bash -c`.** Works, via
  `$BASH_SOURCE`. But it keeps an activation this step does not need, spends the time in a
  layer whose exported environment is thrown away, changes shell semantics for every later
  `RUN` in a file strangers are meant to copy, and ships no `libclang.so` either.
- **`cd $IDF_PATH` first.** Works only through the incidental fallback where the script's
  idea of where ESP-IDF lives is `.` and the working directory happens to be right, which is
  the error message's advice to an interactive human rather than a statement a recipe should
  make. Same missing library.

The chosen line states a true dependency a stranger can check: `idf_tools.py` needs the two
paths the pinned image already sets, and nothing else.

---

## 3. The gate that had stopped running

`tools/ci/check-heap-residue.sh` compiles `notyas-ui` on its own and runs three
`SECURITY.md`-backed assertions about secrets in freed heap blocks. It had been exiting 1
since the Receive screen started calling `notyas_core::qr::matrix` directly: `notyas-ui`
takes `notyas-core` with `default-features = false`, `qr` is one of those features, and every
other build in the tree - the firmware included - has some other consumer unify it back on.
The one gate that compiles the crate alone saw the truth and reported it to nobody, because
a red gate inside a red job is invisible. `ci.yml`'s test job has been failing on every push
for that reason.

0.2.3 fixes the gate and not the architecture: the gate now names the feature its consumers
already supply. `docs/KNOWN-ISSUES.md` K32 carries both halves, and the architectural half -
the Receive screen should raise `UiRequest::Qr` like every other QR on this device rather
than reaching into the core for an encoder - stays open on purpose. 0.2.3's firmware delta is
deliberately the version string alone, and rewiring a screen belongs in a release that
re-runs the hardware gauntlet over changed UI code.

This matters to the release and not only to hygiene: `tools/release.sh gates` accepts a
citation of a green CI run for a gate that cannot run on the bench, and a citation of a run
that was never green is worth nothing.

---

## 4. What a verifier can now do that they could not before

Everything `docs/VERIFYING.md` describes. Until this release the document was accurate about
the intent and unusable in fact, because there were no artifacts to verify and the container
it tells a reader to build could not be built. From 0.2.3 a stranger can run

```
docker build -t notyas-repro -f tools/repro/Dockerfile .
docker run --rm -v "$PWD":/mnt/src:ro -v "$PWD/out":/out notyas-repro waveshare-4b
```

and compare their bytes against the published `SHA256SUMS.txt`. That is the claim the whole
document set rests on and 0.2.3 is the first release for which it is true.

---

## 5. Where this release stands

1. DONE - the container recipe builds all seven steps, and `tools/repro/build.sh` runs to
   `done: <board>` producing a full artifact set. First proved on 2026-08-23.
2. DONE - `tools/repro/toolchain.lock` filled from that run; zero pending pins.
3. DONE - the version bump across the five workspace crates and `Cargo.lock`, the uisim
   goldens and `docs/screenshots/ui/` re-approved for the frames that render the version
   string.
4. DONE - the heap-residue gate compiles and runs again, so `ci.yml` can go green and be
   cited.
5. DONE - the pre-tag rehearsal: both boards built through the container at the candidate
   tree, both `VERIFY.json` manifests checked, and `tools/repro/check-repro.sh` run so that
   the double-build byte comparison has executed before anything was tagged. `v0.2.2` was
   tagged before this pipeline had ever run, which is how a version was spent on a release
   that could not be packaged; the rehearsal is the standing answer to that.
6. OWNER - the hardware evidence decision, below.
7. OWNER - tag, sign, publish.

**Hardware evidence for a version-string-only release.** The image bytes change, because the
version string is in them and on two screens. The gauntlet that 0.2.2 passed was run over
firmware that is otherwise identical. This is the owner's call and this document does not
make it. The recommended floor, and what `tools/release.sh hardware --ack` should say if the
owner agrees with it: carry the 0.2.2 two-board gauntlet at `16dfff2` forward by citation,
and add a per-board smoke of the actual 0.2.3 image - flash, boot, unlock, and read the
Verify screen - so that the artifact being signed is one that has been observed to run on
both boards. The `--ack` text quotes what the owner actually observed, whatever they decide;
flashing is the owner's act alone.

Until step 6 has an answer this document describes what 0.2.3 is, not what any built image
has been shown to do.

---

## 6. What ships

Per board, for `waveshare-4b` and `elecrow-5`, named `0.2.3` in place of `0.2.2`:
`notyas-0.2.3-<board>-app.bin`, `-bootloader.bin`, `-partition-table.bin`, `-merged.bin`,
`.elf`, `-sdkconfig.txt`, `-BUILDINFO.txt`, `-VERIFY.json`; plus, once,
`notyas-0.2.3-src.tar.gz`, `notyas-0.2.3-components.tar.gz`, `SHA256SUMS.txt` and
`SHA256SUMS.txt.asc`. See `docs/archive/RELEASE-0.2.0.md` section 3 for what each file is; nothing
about the artifact set itself changed. Unlike 0.2.2, these files exist.

The base image digest, which is the pin that matters more than the tag and which
`tools/repro/Dockerfile` says to re-read at release time
(`docker buildx imagetools inspect espressif/idf:v5.5.4`):

```
espressif/idf:v5.5.4@sha256:b9f2d6ea1c19e0c9f7959bdb74a9e3c775642f9d0f3b841937c5fa3363db892b
```

---

## 7. What deliberately does not ship

Unchanged from `docs/archive/RELEASE-0.2.0.md` section 4, `docs/archive/RELEASE-0.2.1.md` section 3 and
`docs/archive/RELEASE-0.2.2.md` section 7: no Secure Boot v2, no flash encryption, no eFuse
anti-rollback, no eFuse burn beyond the one HMAC key, no artifacts for the eight scaffold
boards, no crates.io publication, no backup mechanism, no BSMS, no taproot multisig, no
hardware-held signing key, no third-party build attestation, no persistent
outpoint-to-amount cache, no P2SH or P2SH-P2WSH multisig, no legacy signing under any
sighash flag but SIGHASH_ALL, and no scheme selector on the Receive screen.

Also not in 0.2.3, specifically because this release is a packaging repair: no firmware
change of any kind beyond the version string. The refusal-copy audit, K32's architectural
half and K33 all stay where they are.

---

## 8. Known limitations a buyer must read

All twelve items in `docs/archive/RELEASE-0.2.0.md` section 5, item 13 in
`docs/archive/RELEASE-0.2.1.md` section 4, and items 14 to 16 in `docs/archive/RELEASE-0.2.2.md` section 8
still apply unchanged. Nothing is added: 0.2.3 changes no behaviour, so it creates no new
limitation.

One fact belongs here that is not a limitation of the firmware:

- **There is no 0.2.2 image.** `v0.2.2` is a real tag over real, gated, hardware-tested
  firmware, and its release page has no artifacts because the container that produces them
  could not be built. If you are looking for a 0.2.2 download, 0.2.3 is the same firmware
  packaged. `docs/KNOWN-ISSUES.md` K34 records it.

---

## 9. Verification

Signed with the same key as every notyas release, unchanged since 0.2.0:

```
A1E9 53B2 5C6A 623B 77A1 D522 3AC4 BBCF E51A B37D
```

See `docs/VERIFYING.md` for how to check it, and
`docs/keys/A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D.asc` for the published public half.

---

## 10. Release notes skeleton

Paste into the GitHub release, in this order:

1. One paragraph: 0.2.3 is a packaging repair. The firmware is 0.2.2 with a version string
   that says 0.2.3; `docs/archive/RELEASE-0.2.2.md` is still the authority on what changed in the
   product, and `docs/archive/RELEASE-0.2.0.md` section 0 on the whole feature set.
2. That `v0.2.2` has no artifacts, and why, with the mechanism named rather than gestured
   at: the release container's step 5 sourced ESP-IDF's `export.sh` inside a `docker build`
   step; that script trusts `IDF_PATH` from the environment only when it sees `/.dockerenv`,
   which a running container has and BuildKit's build sandbox does not. The `v0.2.2` tag
   stays as the record. Section 1 above is the long form.
3. Section 8: the buyer-facing limitation list, which is 0.2.2's unchanged plus the "there
   is no 0.2.2 image" note.
4. Verification: point at `docs/VERIFYING.md` and give the key fingerprint inline (section 9
   above).
5. Reproducibility status: the exact line `tools/release.sh sign` prints for this tag - and
   note that this is the first notyas release for which a container-produced artifact
   exists at all.
6. The artifact list (section 6 above) and which board slug is which.

---

## 11. If a defect surfaces after publication

Same policy as `docs/archive/RELEASE-0.2.0.md` section 8: do not delete or move the tag; disclose on
the release page immediately, naming what is wrong and what a holder should do; treat the
signing/verification chain as unverifiable and republish rather than silently replace if the
defect is there; record it in `docs/KNOWN-ISSUES.md` with its found-date, its blocking
verdict, and what closing it requires.
