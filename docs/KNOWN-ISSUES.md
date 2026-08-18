# notyas 0.2.0 - known issues

Open defects and rough edges found during development, tracked here so the handover
states them up front rather than letting the owner discover them. Each entry says what
it is, how it was found, whether it blocks release, and what closing it requires.

Closed entries stay, with their resolution, because the reasoning is often the useful
part.

---

## OPEN

### K1. The documented m3 exit-gate command reports FAILED when the gate passes

**Found:** orchestrator verification, 2026-08-18, running the exit gate independently
rather than accepting the milestone report.

The m3 exit gate is documented as `cargo test -p notyas-wallet --release -- --ignored`.
That flag runs the two exhaustive power-loss fuzz corpora, which pass (196 s, zero
findings, independently confirmed). It ALSO runs three `ignore`-fenced doc examples in
`src/lib.rs:42`, `src/sim.rs:31` and `src/sim.rs:927`, which are illustrative API
sketches referencing undefined bindings and therefore fail to compile. The command exits
101 and prints `FAILED`.

Severity: does not affect shipped behaviour, and the fuzzer result is sound. But a gate
command that reports failure on success is worse than no gate - the next person to run
it either stops trusting it or stops running it.

Closing it: make the three examples compile, with hidden setup lines so they are checked
against the real API on every test run and cannot drift, which is strictly better than
the current state where a doc example may silently contradict the code. Failing that,
fence them as `text` so they make no promise. Deferred only to avoid editing `lib.rs`
while a parallel agent is adding modules to it.

---

## CLOSED

(none yet)
