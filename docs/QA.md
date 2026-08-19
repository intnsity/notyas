# notyas - verification regime

How work is verified before it is called done. This governs 0.2.0 development and the
handover to the project owner. Written 2026-08-17.

The standard is not "the tests pass". It is that the owner, testing the device by hand,
should not be the one to find a defect.

## Per-milestone gate

No milestone is closed until all of these are true and recorded where the next person
looking will find them - see "Where evidence lives" below:

1. **Host suite green.** Every crate: `cargo test`, plus `cargo clippy --all-targets
   -D warnings`. Counts reported, not asserted vaguely.
2. **no_std still holds.** `cargo check --target riscv32imac-unknown-none-elf` for every
   crate that claims no_std. A crate that quietly acquires std is a regression even if
   nothing fails.
3. **Both boards.** Built and flashed to the Waveshare 4B and the Elecrow 5, not one.
   Boot self-test passes, no watchdog or Guru over a 60 s idle hold, heap stable, idle
   repaints zero.
4. **The milestone's own exit gate** from MILESTONES.md, quoted and evidenced.
5. **Nothing else broke.** The previous milestone's gates re-run and still green. A
   passing new feature on top of a broken old one is not progress.
6. **Rollback point.** A local ref at the closing commit, so any regression can be
   bisected against a known-good state without disturbing the published repository.
7. **Commit hygiene.** No attribution trailer, no tool-attribution reference of any
   kind, no dash characters. Enforced by CI, checked before push regardless.

### Graphics gate

The UI has its own gate, `tools/uisim/tests/gate.rs`, which rides `cargo test` (tools/uisim
is a default workspace member, so `cargo test --locked` already runs it). Three
obligations, and exactly one of them is approvable:

**(a) Bounds - never approvable.** No frame draws outside its panel, and no frame leaves a
panel pixel unpainted. Measured by `tools/uisim/src/panel.rs`, which records what a display
would discard rather than dropping it: the old framebuffer discarded off-panel pixels
silently, which is why an 800x480 panel shipped a screen drawing one line of text through
another with every test green. `cargo run -p uisim -- render <frame> --panel WxH` writes a
picture of what escaped, with the panel edge marked.

**(b) Coverage - never approvable.** Every `ScreenId`, in every state
`catalog::required_variants` declares it has, on every entry of `notyas_ui::layout::PANELS`
(five distinct panels across ten board features), renders and lands on the screen it claims
to be. `required_variants` is an exhaustive match, so a new screen does not compile until
its states are named.

**(c) Pixels - approvable, deliberately.** Every frame's digest, ink box, ink count and
region digest match `tools/uisim/goldens.txt`. The only thing that writes that file is
`cargo run -p uisim -- approve`, which runs (a) and (b) FIRST and refuses to write if
either fails - so a developer can approve a layout change and can never approve a frame
that draws off the panel or a screen state that stopped rendering. The commit carrying the
goldens.txt diff is the approval record; the reviewer reads which frames moved and by how
much in the ink, px and reg columns. `cargo run -p uisim -- diff` renders a before/after
image for the committed pictures.

`tools/ci/check-screenshots.sh` keeps the role the gate does not cover: cross-machine byte
determinism of docs/screenshots/ui.

## Where evidence lives

Three places, and choosing between them is not a matter of taste. A result a reader could
misread from the number alone needs a file of its own; a result that speaks for itself
does not.

- **The commit message.** A count, a duration, a pass or fail for a gate whose command is
  already written down elsewhere. Sufficient when the number cannot be misread and nothing
  was excluded from it.
- **MEASUREMENTS.md.** Numbers whose series is the point: heap free, frame times, image
  sizes, Argon2 duration per board.
- **A standing evidence file under docs/.** Any result that needs its exclusions, its
  sample and its own weaknesses stated beside it to be read correctly. Two exist, and they
  are the pattern for the rest:
  - `docs/m4a-power-cut-evidence.md` - the hardware power-cut gate: what was run, what was
    not, which rows were excluded and why, and the sampled-not-swept weakness in the words
    the milestone note has to repeat.
  - `docs/claims-audit-0.2.0.md` - every SECURITY.md and PARITY.md claim with its
    mechanism cited by path and by symbol, its verdict and its strength, so the m13 gate
    can be re-run rather than re-argued.

What a file of that kind owes, learned from writing those two:

1. **Point at the raw records.** The per-cut CSVs, the console transcripts, the digests. A
   summary nobody can get behind is an assertion wearing a table.
2. **Say what was not run.** An exit gate with three modes and one mode of evidence is
   partially evidenced, and the file says that in those words rather than reporting the
   part that was done as though it were the whole.
3. **Keep excluded rows visible with their reason.** Two harness errors excluded from a
   pass count are part of the record, not noise removed from it.
4. **Distinguish a check that passed from a check that had no data.** The power-cut
   summariser does this by construction, which is what stops an unmeasured property
   reading as a passing one.
5. **State the weakness in the file, not only in the head of whoever ran it.** Where a
   sentence has to appear verbatim in the milestone note, the file says which sentence.

An evidence file is written while the run happens. One reconstructed afterwards is a
report about somebody's memory of a run.

Open defects go to `docs/KNOWN-ISSUES.md` as they are found, each with a blocking verdict
and the argument for it, and closed ones stay there with their resolution.

## What does not count as verification

- An agent's own assertion that its work is correct. Claims are re-checked against the
  artefact: the test output, the serial log, the rendered screenshot, the flash readback.
- A tool's own PASS. The power-cut harness deliberately prints none: it records
  observations and flags anomalies, and a person reads those against the exit criteria. A
  tool that both performs a test and grades it is the likeliest place for a case it had no
  data for to come out the other side as a pass.
- A host-rendered screenshot standing in for device behaviour, or a device photograph
  standing in for a colour reference. Each answers only its own question. A photograph
  of a screen has already produced one false bug report in this project.
- "It compiles" for anything touching flash layout, the key ladder, or the signing path.
- A rendered screenshot that a human looked at, as verification of a LAYOUT. It is
  evidence about the one panel and the one state it was taken in, and layout defects live
  in the states and panels nobody photographed. That assumption is precisely what let the
  800x480 panel ship a screen drawing text through text: the frame existed nowhere, so
  nothing was wrong with any picture anybody had. A layout is verified by the graphics
  gate above, which renders every declared state on every shipped panel and refuses a
  frame that leaves the glass.


## Pre-handover gauntlet

Before 0.2.0 is handed to the owner for acceptance testing, it must survive this. Each
item is run on both boards unless noted.

**Flows, walked end to end by hand or by scripted region-tap:**
- Stateless: dice -> mnemonic -> passphrase -> addresses -> QR, power off, nothing
  persisted (verified by flash readback, not by trusting the UI).
- First save: PIN creation, backup quiz, wallet saved, power cycle, unlock, wallet
  intact and identical.
- Wrong PIN to the wipe threshold minus one, then a correct PIN: counter resets.
- PIN change, power-cut mid-change: old PIN still works, no stale ciphertext in flash.
- Wipe: both the deliberate path and the threshold path; flash readback confirms
  destruction.
- PIN off: stored wallets destroyed, device returns to stateless, confirmation modal
  named the true counts.
- Sign a single-sig PSBT from SD, verify the signature against an independent verifier,
  write back, and confirm the coordinator accepts it.
- Sign a multisig PSBT with the registration present; then with it absent, and confirm
  the refusal is shown with a reason a person can act on.
- A PSBT whose cosigner input carries only a `witness_utxo` beside a segwit v0 input of
  ours: refused, with both ends of the pair named. This one is walked by hand as well as
  by corpus because it is the interop change coordinators will meet
  (docs/RELEASE-0.2.0.md section 6).
- Every adversarial corpus case: each must be refused, with the right refusal code.
- Verify screen: values match an independent reading of the same facts.

**Robustness:**
- Power cut at every step boundary of every storage operation (the fuzzer, on host,
  plus spot checks on hardware).
- Malformed and oversized PSBTs, truncated SD files, absent card, card removed mid-read.
- Every screen at both resolutions, checked for overlap and out-of-bounds regions, with
  the longest plausible content in every field.
- Long-run soak: leave the device on an idle screen for an hour, confirm zero repaints,
  stable heap, and a responsive first touch afterwards.

**Consistency with the documents:**
- Every SECURITY.md invariant either mechanically enforced or struck. An invariant that
  is merely intended is a false claim.
- Every PARITY.md row implemented, documented as an equivalent, or deferred with its
  reason visible.
- Every number the UI states about itself (roll counts, bit strengths, fees, attempt
  counters) recomputed independently and compared.

## Handover

The owner receives: the flashable images, a list of what was verified and how, the
residual known issues with severity, and the specific things worth their attention that
automated checks cannot judge - wording, layout, and whether a flow feels right. Known
issues are stated up front. Discovering a defect the orchestrator already knew about
would be worse than the defect.

Every open entry in docs/KNOWN-ISSUES.md carries its blocking verdict argued rather than
asserted, because "does not block the release" and "leave it alone" are different
sentences, and which one applies is the owner's call to make with the reasoning in front
of them.
