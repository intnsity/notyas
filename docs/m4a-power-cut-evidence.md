# m4a power-cut gate - evidence record

One file per gate. Each mode of `tools/hil/power-cut-gate.ps1` gets its OWN section here
and its numbers are never folded into another mode's: a mode with no data must not average
into one that has some (KNOWN-ISSUES K5). A section that still holds `[FILL: ...]` markers
is an unrun mode, not a passing one.

Rig, common to every run below. Board B (Elecrow CrowPanel Advanced 5inch, COM6, 16 MB,
MAC `e8:f6:0a:e1:a4:9e`), eFuse-provisioned, store formatted against the real HMAC_UP key,
firmware built with the `hil-console` feature. Cuts are made by hand at the USB connector.
The harness detects the cut and the reseat by watching the serial port disappear and
return, so the operator only pulls and reseats.

## Status at a glance

| Mode | What it cuts | State | Evidence |
|---|---|---|---|
| `seal` | a record seal inside `soak` | recorded 2026-08-18, 20 valid cuts | `C:\nb\hil\powercut-seal-*` |
| `pin` | change-PIN, the operation with the most steps | `[FILL: recorded <date>, N valid cuts / not run]` | `C:\nb\hil\powercut-pin-[FILL: stamp]` |
| `attempt` | a wrong-PIN unlock, at the attempt cell | `[FILL: recorded <date>, N valid cuts / not run]` | `C:\nb\hil\powercut-attempt-[FILL: stamp]` |
| `policy` | SET-POLICY, at each of its seven steps | blocked on firmware, nothing cut | `BLOCKED.txt` if attempted |
| overflow soak | nothing is cut; 128+ wrong PINs with the wipe off | blocked on the same firmware gap | `C:\nb\hil\overflow-*` |

The harness never prints PASS. It records observations and flags anomalies, and a human
reads the result against the m4a exit criteria. `summarize-cuts.ps1` distinguishes a check
that passed from a check that had NO DATA, so an unmeasured property cannot read as a
passing one - "NOT CHECKED" in a summary is an unverified property and the milestone note
must not claim it.

---

## Mode `seal` - recorded 2026-08-18

**Result: 20 valid power cuts, every one landing inside a live seal. No epoch change, no
sequence regression, no failed remount.** The store committed 7,424 sequence units across
the run and mounted cleanly after every cut.

### What was tested

MILESTONES.md m4a requires the power-cut gate to be performed by hand, "power pulled at
the USB connector or a bench inline switch, at a scripted delay after the attempt-cell
program begins, repeated at least twenty times across the window, with the ledger state
read back over the HIL console after each cut and recorded in the milestone note."

This section covers the `seal` mode: a cut taken while `soak` is writing records. It says
nothing about change-PIN or the attempt counter, which are the sections below.

### Numbers

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

### What the numbers mean

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

### Evidence

```
C:\nb\hil\powercut-seal-20260818-122655\   1 cut  (validation run)
C:\nb\hil\powercut-seal-20260818-180333\   2 cuts
C:\nb\hil\powercut-seal-20260818-180618\   3 cuts + 2 harness errors
C:\nb\hil\powercut-seal-20260818-181142\  14 cuts
```

---

## Mode `pin` - cut during change-PIN

Run: `.\tools\hil\power-cut-gate.ps1 -Port COM6 -Mode pin`
Evidence: `C:\nb\hil\powercut-pin-[FILL: stamp]\`
Date: `[FILL: date]`.  Cuts requested: `[FILL: n]`.  Delay window: 40 to 6000 ms.

**Result: [FILL: one sentence, in the shape of "N valid cuts, exactly one PIN opened the
device after every one of them, and the slot digest was unchanged across all N" - or the
finding, if there is one].**

### What the cut is testing

Change-PIN (`Vault::change_pin`, ESP-SEAL.md 4.6 C1-C6) re-stretches the new PIN, then
re-seals EVERY record of the identity - payloads, registry, filler and the canary - under
a new key at a new generation, writing each to the slot's other side while the old side
stays intact. None of that is visible to a mount. One ledger cell at C5 commits the new
generation into the current set, and only then does C6 erase the retired sides. A value is
never in the current set until its own cell is programmed, and `scan_pin_gen_log` ignores a
malformed cell entirely, so a torn commit cell leaves the generation uncommitted rather
than half-committed.

The property, therefore: **before the commit cell the old PIN opens the device and nothing
is lost; after it the new PIN opens the device and the stale sides are erased. There is no
window in which neither works, and none in which both do.** The mode exists to test that
claim against a real power cut over the real `esp_partition` driver, at the operation with
the most steps and so the most boundaries for a cut to land between.

This is why the harness tries BOTH PINs after every cut, in a fixed order, each from a
locked device. Asking only about the PIN it expects to work cannot see the failure that
matters most.

### What a failure looks like, and what it costs an owner

| Observation | Flag | What it means for the owner |
|---|---|---|
| Neither PIN opens the device | `no_pin_opens` | The store is unreachable. The owner is locked out of their own wallet permanently and recovers only from a seed backup they may not have. Availability failure, and the worst outcome in this table. The harness STOPS the run on it. |
| Both PINs open the device | `both_pins_open` | Two live sealing keys for one store. The retired PIN still opens the records after the owner deliberately changed it, so a disclosed or coerced old PIN keeps working. Security failure. |
| The slot digest moved | `payload_digest_changed` | A record was altered or lost by the cut. Wallet data destroyed. |
| The slot read before and not after | `record_unreadable_after_cut` | The same class seen from the other side: the re-seal landed somewhere unreadable. |
| The epoch moved | `epoch_changed:a->b` | A cut was mistaken for a wipe trigger. Every record is gone. |

`next_seq` MOVING during this mode is expected, not a fault: every change-PIN re-seals the
records and each re-seal consumes sequence units. Only a regression is a finding.

### The record - every column `cuts.csv` carries for this mode

Common columns in file order, then the mode's own. Fill from the CSV; leave a cell empty
only where the CSV is empty, and say so rather than tidying it.

| Column | What it is | Fill |
|---|---|---|
| `cut` | 1-based cut number | `[FILL]` |
| `mode` | `pin` | `pin` |
| `delay_ms` | the scripted delay before the beep, sampled from the window | `[FILL: range]` |
| `cut_detected` | True when the port vanished; False is a MISSED cut, not a pass | `[FILL: n of n]` |
| `cut_at_ms` | when the port vanished, measured from the start of the workload | `[FILL: range]` |
| `last_inflight` | the last `HIL\|pinsoak\|about_to_change\|i=N\|to=PIN` line before the cut; empty means the cut interrupted nothing | `[FILL: i= range, distinct values]` |
| `mount_before` / `mount_after` | the boot line carrying mount, provenance or state | `[FILL: any row where mount_after is empty]` |
| `epoch_before` / `epoch_after` | wipe epoch either side | `[FILL: changes, expect 0]` |
| `next_seq_before` / `next_seq_after` | ledger sequence either side | `[FILL: regressions, expect 0]` |
| `failures_before` / `failures_after` | the wrong-PIN count either side | `[FILL]` |
| `boot_count_after` | the boot counter after the cut; rises by one per power cycle | `[FILL: first -> last]` |
| `pin_before` | the PIN the harness knew to be current before the cut | `[FILL]` |
| `pin_a_opens` / `pin_b_opens` | did PIN A (1234) / PIN B (5678) open a locked device afterwards | `[FILL]` |
| `pin_after` | the resolved answer: the opening PIN, or `BOTH`, or `NEITHER` | `[FILL: distribution]` |
| `payload_ok_before` / `payload_len_before` / `payload_sha_before` | slot 1 read under the pre-cut PIN | `[FILL]` |
| `payload_ok_after` / `payload_len_after` / `payload_sha_after` | slot 1 read under whichever PIN opened | `[FILL]` |
| `flags` | anomalies for this row; `harness-error: ...` rows are rig failures, not device findings, and are excluded from the pass count | `[FILL: flagged rows, verbatim]` |

### The summary, pasted verbatim

```
[FILL: paste the whole output of
 powershell -NoProfile -ExecutionPolicy Bypass -File tools\hil\summarize-cuts.ps1 `
     -RunDir C:\nb\hil\powercut-pin-<stamp>
 here, unedited]
```

### Which checks can come back with no data

Each of these prints NOT CHECKED when its columns are empty. NOT CHECKED is not a pass,
and any that appears must be repeated in the "Not yet done" list at the foot of this file.

- **Which PIN opens** - no data if no row recorded a post-cut PIN probe. That is the whole
  gate for this mode; without it the run has measured nothing that `seal` had not already.
- **Record survival** - no data if no row carried a payload digest on BOTH sides. "No
  record may be lost" is then unverified.
- **Epoch stability** and **ledger monotonicity** - no data if no row carried both values.
- **Readback** - reported only when a slot read before a cut and not after.

### The stale-ciphertext half, which this table does not prove

The same exit-gate clause asks that "a PIN change leaves no stale old-PIN ciphertext,
proven by raw flash readback, not by code inspection". The PIN probe above does not prove
it: it proves the retired PIN no longer OPENS the device, which is a different statement
from the retired ciphertext no longer BEING there. C6 erases the losing sides after the
commit, and mount runs the same cleanup path to finish an interrupted change, so the bytes
are expected to be gone - but expected is not measured.

Every cut ran `scan`, so `console.log` carries
`HIL|scan|region=Records|nonblank_total=N|per_sector=...` on both sides of each cut. That
is the coarse readback: a retired side that still held ciphertext shows as a sector whose
non-blank count did not fall.

- Per-sector non-blank counts, retired side, after the last cut: `[FILL: from console.log]`
- Byte-exact confirmation of one retired side: `dump rec <offset> <len>` over that side,
  confirming every byte is 0xff. The harness does NOT send this, so it is a manual step:
  `[FILL: the dump line, or "not done" - and if not done, this clause stays open]`

### Verdict against the exit gate

`[FILL: one paragraph. State what the run measured, in the numbers above, and what it did
not. If any check came back NOT CHECKED, say which property is still unverified.]`

---

## Mode `attempt` - cut during a wrong-PIN unlock

Run: `.\tools\hil\power-cut-gate.ps1 -Port COM6 -Mode attempt`
Evidence: `C:\nb\hil\powercut-attempt-[FILL: stamp]\`
Date: `[FILL: date]`.  Cuts requested: `[FILL: n]`.  Delay window: 0 to 700 ms after the
beep, which is the pause before the wrong PIN is sent rather than a delay into it.

**Result: [FILL: one sentence, in the shape of "N valid cuts, the count never went
backwards, no completed attempt went uncharged" - or the finding].**

### What the cut is testing

`Vault::unlock` is ordered so that the counter is charged before the VERIFICATION, not
before the COMPUTATION. U1 pre-checks cost nothing. U2/U3 spend about 1.9 s in Argon2id and
write nothing. U4 programs one attempt-entry cell, with a read-back verify. Only then does
U5 attempt to open the canaries. An attacker who cuts power during the stretch has paid the
full cost and learned nothing, and cannot obtain an uncounted verification, because the
verification is strictly after the charge.

The property: **a wrong-PIN attempt that reached the verification has been paid for, and
the payment survives the power cut.** `failures = failures_base + len(attempt_entry) -
len(attempt_success)`, and the ledger scan rules resolve every ambiguity toward a HIGHER
count: the entry log counts a malformed cell as consumed, while the success log truncates
at the first malformed one. A torn cell can only ever raise the apparent failure count.

### Is a lost decrement a security failure or an availability failure

**This design fails in the availability direction, deliberately, and the run is confirming
it fails that way on hardware and not the other.**

- **Security direction, where an attacker gains guesses.** For this to happen a cut would
  have to leave the entry log SHORTER than the number of verifications performed. Two
  things stand against it: the charge is programmed before the verification, so a cut that
  loses the cell also loses the verification it would have paid for; and a torn cell scans
  as consumed rather than as absent. The observables that would show this direction had
  failed anyway are `failures_after < failures_before` (`failures_went_backwards`), and the
  sharp one - `unlock_completed_before_cut` True with the count unmoved
  (`completed_attempt_not_counted`), which means the device performed a verification, said
  so on the console, and did not charge for it. Either is blocking. A thief who can produce
  one at will has unlimited on-device guesses, one power cut at a time, which is the
  classic attack against exactly this mechanism.
- **Availability direction, where the owner loses guesses.** This one is REACHABLE by
  design and is the accepted cost. A cut after U4 and before the verification charges the
  owner for an attempt that never happened. An interrupted SUCCESSFUL unlock leaves entry =
  success + 1 until U7's catch-up runs on the next success. A torn cell scans as consumed.
  All three cost the owner attempts, and with the wipe enabled at N = 15 enough of them
  destroy the records. The design accepts that: an owner who repeatedly cuts power
  mid-unlock can walk their own device toward a wipe, and the alternative - resolving
  ambiguity toward a lower count - hands the attacker the free guess instead.

So for the owner, a lost count here is at worst a wallet they must restore from their seed
backup. A lost count in the other direction would be a wallet an attacker gets to brute
force. This run is checking that the ordering holds on real flash.

### What this mode cannot prove on hardware, and why that is not a weak run

The counted region is microseconds wide at the very end of a two second operation. A
hand-timed pull essentially never lands inside it, so a `cut_phase` column full of
`uncounted_stretch` is the EXPECTED result. What the hardware honestly evidences is that
the count survives a cut ANYWHERE in the unlock and never goes backwards, over the real
`esp_partition` driver and the real HMAC key - which no host test can claim. The exhaustive
sweep of the U4 boundary is the host fuzzer, at `Op::UnlockBad` and `Op::UnlockToWipe`:

```
cargo test -p notyas-wallet --release -- --ignored     (tests/powerloss.rs)
```

Host fuzzer result backing this section: `[FILL: date and outcome, or "not re-run for this
record"]`.

### The record - every column `cuts.csv` carries for this mode

| Column | What it is | Fill |
|---|---|---|
| `cut` | 1-based cut number | `[FILL]` |
| `mode` | `attempt` | `attempt` |
| `delay_ms` | pause between the beep and the wrong-PIN command, so the operator's reaction lands INSIDE the unlock | `[FILL: range]` |
| `cut_detected` | True when the port vanished | `[FILL: n of n]` |
| `cut_at_ms` | when the port vanished, from the start of the workload | `[FILL: range]` |
| `last_inflight` | the last `HIL\|unlock\|` line seen. Read this one carefully: that line is the unlock's ANSWER, so a non-empty value means the cut arrived after the operation ended, not inside it | `[FILL: n non-empty]` |
| `mount_before` / `mount_after` | boot line carrying mount, provenance or state | `[FILL: any empty mount_after]` |
| `epoch_before` / `epoch_after` | wipe epoch either side; a change means a cut triggered a wipe | `[FILL: changes, expect 0]` |
| `next_seq_before` / `next_seq_after` | ledger sequence. An unlock seals no records, so a STATIC value is expected here and is not a missing measurement | `[FILL]` |
| `failures_before` | the count after the harness cleared it with a correct unlock, so normally 0 | `[FILL]` |
| `failures_after` | the count read after the cut, BEFORE the harness clears it again | `[FILL]` |
| `boot_count_after` | boot counter; rises by one per cut and cross-checks that a real power cycle happened | `[FILL: first -> last]` |
| `bad_pin` | the wrong PIN typed, which must parse or it never reaches the counter | `9999` |
| `stretch_ms` | THIS board's measured Argon2id cost on the preceding correct unlock, not a constant from MEASUREMENTS.md | `[FILL: range]` |
| `unlock_completed_before_cut` | True when the console had already answered the unlock when the power went | `[FILL: n True]` |
| `cut_phase` | `uncounted_stretch`, `at_or_after_the_counted_region`, `after_the_attempt_completed`, or `unknown`. An inference from `cut_at_ms` against `stretch_ms`, not something the device said | `[FILL: distribution]` |
| `attempts_left_before` / `attempts_left_after` | remaining attempts. `none` means the wipe is DISABLED, which is a fact and not missing data; empty means the field was not parsed | `[FILL]` |
| `failures_after_clear` | the count after the correct PIN cleared it; anything but 0 means success did not clear the counter | `[FILL: expect 0]` |
| `flags` | anomalies for this row | `[FILL: flagged rows, verbatim]` |

### The summary, pasted verbatim

```
[FILL: paste the whole output of
 powershell -NoProfile -ExecutionPolicy Bypass -File tools\hil\summarize-cuts.ps1 `
     -RunDir C:\nb\hil\powercut-attempt-<stamp>
 here, unedited]
```

Two lines of that summary are easy to misread, so read them against this:

- **"Landed in an unlock : N"** counts rows whose `last_inflight` holds an `HIL|unlock|`
  line. Because that line is the unlock's answer and not an announcement before it, a HIGH
  number here means many cuts arrived AFTER the attempt finished. Where the cuts actually
  fell is the `Where the cuts fell` line, from `cut_phase`.
- **"In-flight index range"** will not appear at all for this mode. The unlock reply
  carries no `i=` field, so there is no index to range over. Its absence is structural, not
  a gap in the data.

### Which checks can come back with no data

- **Count continuity** - NOT CHECKED if no row carried the count on both sides. That is the
  whole gate for this mode.
- **Completed attempts** - reports "no cases to judge" when no cut arrived after the unlock
  had answered. That is an empty check, not a passing one, and it is a likely outcome: the
  harness beeps first precisely to get the pull inside the unlock rather than after it.
- **Success clears** - printed only when `failures_after_clear` carried a number.
- **Epoch stability** and **ledger monotonicity** - as above.

### Verdict against the exit gate

`[FILL: one paragraph. Say whether the count ever went backwards, whether any completed
attempt went uncharged, and which of the checks above had no cases to judge.]`

---

## What these two runs close, and what stays open

The m4a exit gate, clause by clause, in MILESTONES.md's order.

| Exit-gate clause | Closed by these runs? |
|---|---|
| create a wallet, power cycle, unlock | Partly, and incidentally. Every cut is a power cycle followed by an unlock on a provisioned board, so the power-cycle-and-unlock half is exercised `[FILL: n]` times across the two runs. The create-a-wallet half is not part of either run. |
| wrong PIN decrements the counter, and the decrement survives a reboot AND a power cut taken mid-decrement | The power-cut half: YES, by the `attempt` run, with the honest limit stated in that section - the hardware evidences survival of a cut anywhere in the unlock, and the exhaustive sweep of the U4 boundary is the host fuzzer. The reboot half is separately evidenced by the overflow soak's `-RebootAt`, which cannot run yet (below). |
| wipe-on-N at the default N = 15 destroys the records and bumps the epoch | NO. Neither run goes near it. The harness deliberately refuses to walk a provisioned board into a wipe: it stops when `failures` is within `-WipeMargin` (default 3) of `wipe_after`. Board B is the only eFuse-provisioned unit and its store is where all of this evidence comes from. This clause needs its own decision about which board to spend. |
| a PIN change leaves no stale old-PIN ciphertext, proven by raw flash readback | Partly, by the `pin` run, and only if the manual `dump rec` step in that section was done. The PIN probe proves the old PIN does not open the device; it does not prove the old ciphertext is gone. |
| the stateless path still writes nothing, proven by a flash readback diff on a dev board | NO. Not a power-cut run at all. |
| the Verify screen reports the real eFuse HMAC-key state, not a constant | NO. Not a power-cut run at all. |
| SET-POLICY survives a cut at each of its seven steps with the effective policy never weaker than both values | NO, and not by choice. `-Mode policy` needs three console surfaces this firmware does not have: `setpolicy <wipe_after\|off> <min_pin_len> <pin>`, `policysoak` announcing `about_to_step\|i=N\|step=Y1..Y7`, and `min_pin_len` on the status line. `Vault::set_policy` has no route from the device at all - `firmware/src/main.rs` refuses `UiRequest::SetWipePolicy` for that reason. The harness probes `help` and writes `BLOCKED.txt` without cutting anything, which is the correct record: a firmware gap, not a test result. |
| a device with wipe DISABLED survives 128+ consecutive failed attempts without overflowing the attempt log or losing the accumulated count | NO, blocked on the same gap. Reaching the wipe-disabled state needs `set_policy`, and nothing on the device can commit one. `tools/hil/attempt-overflow-gate.ps1` refuses to send a single wrong PIN unless the device reports `wipe_after=0`, because on a wipe-enabled board that run would destroy every record at attempt 15. Host coverage today is the fuzzer's `Op::RotationOnFailure`, which is a real proof over simulated flash and not the same claim. |
| ...on BOTH boards | NO. See below. |

So: these two runs close the two modes KNOWN-ISSUES K5 names as runnable, and they leave K5
itself open. K5 also names the SET-POLICY sequence and the 128-attempt overflow, and both
are blocked on one firmware gap rather than on bench time. K5 is therefore updated after
these runs, not closed.

## Board A has never been power-cut tested

Every cut recorded in this file was taken on board B. Board A has not been cut once, in any
mode. It is unprovisioned by design - `KeyProvenance::Emulated`, no eFuse HMAC key burned -
so its store path is not the same code path board B exercises, and the gate's own wording
is "on both boards".

There are exactly two acceptable outcomes and this file carries one of them before release:

1. **Re-run the gate on board A.** That means provisioning it first, which is a permanent
   eFuse burn on the second of two boards.
2. **Scope it out, with the reason written down here.** `[FILL: the reason, if this is the
   choice. It has to say what board A's emulated-key path shares with board B's real-key
   path and what it does not, and why a cut on the shared part is evidence for both. A
   scope-out that only says "no time" is a waiver, and MILESTONES.md section 9 item 1 does
   not permit a waived gate.]`

Chosen: `[FILL: 1 or 2, and the date]`.

## Stated weakness, which belongs in the milestone note verbatim, for every mode above

The cut window was SAMPLED, not swept. Q43's USB-controlled relay is deferred to 0.3.0, so
cuts were made by hand at the connector. The harness selects when to ASK for a cut, but the
operator's pull lands some seconds later, so the in-flight index at cut time is observed
rather than chosen. Coverage of the commit window is therefore a sample whose distribution
nobody controlled, and a rare torn-write window could sit entirely between the sampled
points.

For `seal`, the 18 distinct indices from 3 to 1999 show the sample is spread rather than
clustered, which is the most that can be claimed without the relay. The equivalent for
`pin` is `[FILL: the i= range and distinct count from last_inflight]`. For `attempt` there
is no index to report, and the spread is the `cut_phase` distribution instead: `[FILL]`.

## Reproducing

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\hil\power-cut-gate.ps1 `
    -Port COM6 -Mode seal    -Cuts 20 -Pin 1234
powershell -NoProfile -ExecutionPolicy Bypass -File tools\hil\power-cut-gate.ps1 `
    -Port COM6 -Mode pin     -Cuts 20 -Pin 1234 -PinB 5678
powershell -NoProfile -ExecutionPolicy Bypass -File tools\hil\power-cut-gate.ps1 `
    -Port COM6 -Mode attempt -Cuts 20 -Pin 1234 -BadPin 9999
powershell -NoProfile -ExecutionPolicy Bypass -File tools\hil\summarize-cuts.ps1
```

`-DryRun` prints the per-cut procedure and the mode's evidence columns without touching the
board. `tools/hil/RUNBOOK.md` is the operator's copy. Each run directory holds `cuts.csv`,
`cuts.json` and `console.log`, plus `BLOCKED.txt` when the firmware could not drive the
mode. The evidence is on local disk and is not mirrored to the NAS, because it is
machine-specific test output rather than repository content - the harness refuses a UNC
`-OutDir` for that reason.

## Not yet done

- The `pin` and `attempt` sections of this file, until their `[FILL: ...]` markers are gone.
  `[FILL: delete this line once both are filled]`
- Any check the summariser reported as NOT CHECKED: `[FILL: list them, or "none"]`.
- The manual `dump rec` readback of a retired slot side, which is what turns "the old PIN
  does not open the device" into "no stale old-PIN ciphertext remains".
- The SET-POLICY seven-step cut sequence and the wipe-disabled 128-attempt overflow case.
  Both are blocked on the same firmware gap: no route to `Vault::set_policy` from the
  device.
- wipe-on-N at N = 15 on hardware, which no power-cut mode performs and which costs the
  store of whichever board runs it.
- Board A, per the section above.
