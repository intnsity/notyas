# m4a power-cut gate - evidence record

Date: 2026-08-18. Board B (Elecrow CrowPanel Advanced 5inch, COM6, 16 MB, MAC
`e8:f6:0a:e1:a4:9e`), eFuse-provisioned, store formatted against the real HMAC_UP key.

**Result: 20 valid power cuts, every one landing inside a live seal. No epoch change, no
sequence regression, no failed remount.** The store committed 7,424 sequence units across
the run and mounted cleanly after every cut.

## What was tested

MILESTONES.md m4a requires the power-cut gate to be performed by hand, "power pulled at
the USB connector or a bench inline switch, at a scripted delay after the attempt-cell
program begins, repeated at least twenty times across the window, with the ledger state
read back over the HIL console after each cut and recorded in the milestone note."

This record covers the `seal` mode: a cut taken while `soak` is writing records. The
`pin` mode (cut during change-PIN, the operation with the most steps) and the `attempt`
mode (cut mid-decrement of the attempt counter) are separate runs and are NOT covered
here. The m4a exit gate is not complete until those are also run.

## Numbers

| Measure | Value |
|---|---|
| Valid device cuts | 20 |
| Harness errors, recorded and excluded | 2 |
| Cuts landing inside a live seal | 20 of 20 |
| In-flight seal index range | 3 to 1999, 18 distinct values |
| Epoch changes | 0 of 20 comparable |
| `next_seq` regressions | 0 of 19 comparable |
| Failed to remount after cut | 0 |
| Sequence units committed across the run | 7,424 |

One row of the 20 carries no `next_seq` pair, because it predates a fix to the console
field parser, so the sequence property is evidenced by 19 cuts rather than 20. That is
stated rather than rounded up.

The two harness errors were serial-port failures in the test rig, not device findings: a
freshly re-powered board can re-enumerate its USB bridge after a handle has already been
opened against it, and the first write then fails with "the port is closed". They are
recorded as flagged rows in the evidence CSVs and are excluded from the pass count. The
harness now retries the reopen and treats a failed cut as a flagged row rather than
aborting the run.

## What the numbers mean

- **No epoch change** across every cut is the important one. The epoch bumps on a wipe,
  so an unchanged epoch says no cut was mistaken for a tamper event or an attempt-counter
  exhaustion. A store that wiped itself on power loss would be catastrophic and invisible
  until a user lost a wallet.
- **No `next_seq` regression** means no committed record was lost. The counter only moves
  forward, so a cut mid-write either completes the record or leaves the previous state
  intact - never a torn record that reads as valid.
- **Every cut landed inside a seal.** A cut that arrives between operations interrupts
  nothing and proves nothing. All 20 interrupted an announced `about_to_seal`, which is
  what makes them evidence.

## Stated weakness, which belongs in the milestone note verbatim

The cut window was SAMPLED, not swept. Q43's USB-controlled relay is deferred to 0.3.0,
so cuts were made by hand at the connector. The harness selects when to ASK for a cut,
but the operator's pull lands some seconds later, so the in-flight index at cut time is
observed rather than chosen. Coverage of the commit window is therefore a sample whose
distribution nobody controlled, and a rare torn-write window could sit entirely between
the sampled points. The 18 distinct indices from 3 to 1999 show the sample is spread
rather than clustered, which is the most that can be claimed without the relay.

## Reproducing

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\hil\power-cut-gate.ps1 `
    -Port COM6 -Mode seal -Cuts 20 -Pin 1234
powershell -NoProfile -ExecutionPolicy Bypass -File tools\hil\summarize-cuts.ps1
```

The harness detects the cut and the reseat by watching the serial port disappear and
return, so the operator only pulls and reseats. It deliberately does not print PASS: it
records observations and flags anomalies, and a human reads the result against the exit
criteria. `summarize-cuts.ps1` distinguishes a check that passed from a check that had no
data, so an unmeasured property cannot read as a passing one.

## Evidence

Raw per-cut records, console transcripts and machine-readable summaries:

```
C:\nb\hil\powercut-seal-20260818-122655\   1 cut  (validation run)
C:\nb\hil\powercut-seal-20260818-180333\   2 cuts
C:\nb\hil\powercut-seal-20260818-180618\   3 cuts + 2 harness errors
C:\nb\hil\powercut-seal-20260818-181142\  14 cuts
```

Each directory holds `cuts.csv`, `cuts.json` and `console.log`. The evidence is on local
disk and is not mirrored to the NAS, because it is machine-specific test output rather
than repository content.

## Not yet done

- `-Mode pin` and `-Mode attempt` runs. Until those are recorded, the m4a exit gate is
  partially evidenced, not closed.
- The SET-POLICY seven-step cut sequence and the wipe-disabled 128-attempt overflow case,
  both named in the m4a exit gate.
- Board A has not been power-cut tested. It is unprovisioned by design
  (`KeyProvenance::Emulated`), so its store path differs and the gate must be re-run there
  or explicitly scoped out with a reason.
