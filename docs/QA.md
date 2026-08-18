# notyas - verification regime

How work is verified before it is called done. This governs 0.2.0 development and the
handover to the project owner. Written 2026-08-17.

The standard is not "the tests pass". It is that the owner, testing the device by hand,
should not be the one to find a defect.

## Per-milestone gate

No milestone is closed until all of these are true and recorded in its commit message or
in MEASUREMENTS.md:

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
7. **Commit hygiene.** No attribution trailer, no assistant or LLM reference, no dash
   characters. Enforced by CI, checked before push regardless.

## What does not count as verification

- An agent's own assertion that its work is correct. Claims are re-checked against the
  artefact: the test output, the serial log, the rendered screenshot, the flash readback.
- A host-rendered screenshot standing in for device behaviour, or a device photograph
  standing in for a colour reference. Each answers only its own question. A photograph
  of a screen has already produced one false bug report in this project.
- "It compiles" for anything touching flash layout, the key ladder, or the signing path.

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
