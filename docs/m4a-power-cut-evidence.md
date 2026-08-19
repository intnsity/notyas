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
| `pin` | change-PIN, the operation with the most steps | recorded 2026-08-19, 20 valid cuts | `C:\nb\hil\powercut-pin-20260819-144312` |
| `attempt` | a wrong-PIN unlock, at the attempt cell | recorded 2026-08-19, 20 valid cuts | `C:\nb\hil\powercut-attempt-20260819-145849` |
| `policy` | SET-POLICY, at each of its seven steps | blocked on firmware, nothing cut | `BLOCKED.txt` if attempted |
| overflow soak | nothing is cut; 128+ wrong PINs with the wipe off | blocked on the same firmware gap | `C:\nb\hil\overflow-*` |

The harness never prints PASS. It records observations and flags anomalies, and a human
reads the result against the m4a exit criteria. `summarize-cuts.ps1` distinguishes a check
that passed from a check that had NO DATA, so an unmeasured property cannot read as a
passing one - "NOT CHECKED" in a summary is an unverified property and the milestone note
must not claim it. No check in either 2026-08-19 run came back NOT CHECKED.

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
Evidence: `C:\nb\hil\powercut-pin-20260819-144312\`
Date: 2026-08-19, 14:43 to 14:56.  Cuts requested: 20.  Delay window: 40 to 6000 ms.

**Result: 20 valid cuts, exactly one PIN opened the device after every one of them - never
both, never neither - and the slot digest was byte-identical across all 20.** No epoch
change, no `next_seq` regression, no failed remount, no flagged row, no harness error.

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

None of the five was observed. The `flags` column is empty on all 20 rows.

`next_seq` MOVING during this mode is expected, not a fault: every change-PIN re-seals the
records and each re-seal consumes sequence units. Only a regression is a finding.

### The record - every column `cuts.csv` carries for this mode

Common columns in file order, then the mode's own. Read from the CSV, not from the
summariser.

| Column | What it is | Observed |
|---|---|---|
| `cut` | 1-based cut number | 1 to 20 |
| `mode` | `pin` | `pin` |
| `delay_ms` | the scripted delay before the beep, sampled from the window | 355 to 5,693 ms, inside the 40..6000 window |
| `cut_detected` | True when the port vanished; False is a MISSED cut, not a pass | True on 20 of 20 |
| `cut_at_ms` | when the port vanished, measured from the start of the workload | 1,860 to 33,019 ms |
| `last_inflight` | the last `HIL\|pinsoak\|about_to_change\|i=N\|to=PIN` line before the cut; empty means the cut interrupted nothing | non-empty on 20 of 20. `i=0` on 8 cuts, `i=1` on 11, `i=7` on 1 |
| `mount_before` / `mount_after` | the boot line carrying mount, provenance or state | non-empty on 20 of 20. Every `mount_after` reports `provenance=eFuse HMAC_UP key, read-protected` and `state=formatted, 1 PIN identity/identities` |
| `epoch_before` / `epoch_after` | wipe epoch either side | `0 -> 0` on all 20. Zero changes |
| `next_seq_before` / `next_seq_after` | ledger sequence either side | 8,960 rising to 16,896. Zero regressions. 7,936 sequence units committed across the run |
| `failures_before` / `failures_after` | the wrong-PIN count either side | 0 on both sides of all 20 rows |
| `boot_count_after` | the boot counter after the cut; rises by one per power cycle | 50 -> 69, consecutive with no skipped value: exactly one power cycle per cut |
| `pin_before` | the PIN the harness knew to be current before the cut | `5678` on 18 rows, `1234` on 2 (cuts 1 and 6) |
| `pin_a_opens` / `pin_b_opens` | did PIN A (1234) / PIN B (5678) open a locked device afterwards | exactly one True per row on all 20. `pin_b_opens` True on 19, `pin_a_opens` True on 1 (cut 5) |
| `pin_after` | the resolved answer: the opening PIN, or `BOTH`, or `NEITHER` | `5678` x19, `1234` x1. Zero `BOTH`, zero `NEITHER` |
| `payload_ok_before` / `payload_len_before` / `payload_sha_before` | slot 1 read under the pre-cut PIN | True / 16 / `5cf581511c7aefdc1b116bcbf1f5524c37ce6b6c5241792a1a39eae46e6e19a6` on all 20 |
| `payload_ok_after` / `payload_len_after` / `payload_sha_after` | slot 1 read under whichever PIN opened | identical to the before triple on all 20 rows, and the same digest on every row of the run |
| `flags` | anomalies for this row; `harness-error: ...` rows are rig failures, not device findings, and are excluded from the pass count | empty on all 20. Zero flagged rows, zero harness errors |

Two rows are worth reading rather than averaging.

- **Cut 13** is the only one whose `next_seq` did not move (12,544 on both sides). The cut
  landed early enough in that change-PIN that nothing had been committed yet. That is the
  uncommitted-generation case behaving exactly as C5 describes, and `5678` still opened the
  device afterwards.
- **Cut 5** is the single row where `1234` opened. Its in-flight line was
  `about_to_change|i=1|to=1234`, so the commit cell had already been programmed when the
  power went. The one row that differs is the row that is supposed to differ, and it
  differs in the direction the design predicts.

The `pinsoak` workload announced 58 change-PIN operations across the run: 20 were
interrupted by a cut and 38 ran to completion. Only one round reached `i=7`, which is why
the in-flight index spans 0 to 7 but holds just three distinct values at cut time.

Independent cross-check on the unlock traffic: 80 `unlock` commands were issued over the
run and the device accepted 60 and refused 20. That is exactly 4 per round - the pre-cut
read, the two post-cut PIN probes, and the post-cut read - with exactly one refusal per
round. A round in which both probes had been accepted, or both refused, would show up here
as well as in `pin_after`, and none did.

### The summary, pasted verbatim

```
m4a power-cut gate, mode 'pin' - C:/nb/hil/powercut-pin-20260819-144312
========================================================================

Cuts requested        : 20
Cuts detected         : 20
Landed in a PIN change : 20   (a cut with no in-flight line interrupted nothing)
In-flight index range : 0 to 7 across 3 distinct values
Rows carrying flags   : 0

Against the m4a exit criteria:

  Remount after cut   : all 20 cuts remounted and answered status.
  Epoch stability     : no epoch change across 20 comparable cut(s). No cut triggered a wipe.
  Ledger monotonicity : next_seq never went backwards across 20 comparable cut(s). No committed record was lost.
  Boot counter        : Some(50) -> Some(69) across the run, surviving every cut.

The change-PIN gate, which is what this mode exists to answer:

  Which PIN opens     : exactly one PIN opened the device after each of 20 probed cut(s).
                        distribution: 5678 x19, 1234 x1
  Record survival     : the slot's SHA-256 was identical before and after across
                        20 cut(s). The record was re-sealed under the surviving
                        PIN with its bytes unchanged.

  Note: the stale-ciphertext half of the same exit-gate clause - "a PIN change
  leaves no stale old-PIN ciphertext" - is proven from the raw flash, not from
  this table. Each cut ran `scan`; read the retired side of the re-sealed slot in
  console.log and confirm it counts zero non-0xff bytes.

Stated weakness, which belongs in the milestone note verbatim:

  The cut window was SAMPLED, not swept. Q43's USB-controlled relay is deferred
  to 0.3.0, so cuts were made by hand at the connector. The harness selects when
  to ASK for a cut, but the operator's pull lands some seconds later, so the
  in-flight index at cut time is observed rather than chosen. Coverage of the
  commit window is therefore a sample whose distribution nobody controlled, and
  a rare torn-write window could sit entirely between the sampled points.

Evidence: C:\nb\hil\powercut-pin-20260819-144312\cuts.csv

VERDICT: EVERY CRITERION CHECKED, NONE BLOCKING, exit 0
         That is a statement about the data, not about the gate. Read the numbers
         above against the m4a exit criteria and decide that yourself.
```

The summariser's closing note above says to read the retired side out of `console.log`
rather than out of its table. That was done, for both runs; it is the "Retired-side
residue" section near the foot of this file.

### Which checks can come back with no data

Each of these prints NOT CHECKED when its columns are empty. NOT CHECKED is not a pass,
and any that appears must be repeated in the "Not yet done" list at the foot of this file.
**None of them appeared in this run.**

- **Which PIN opens** - no data if no row recorded a post-cut PIN probe. That is the whole
  gate for this mode; without it the run has measured nothing that `seal` had not already.
  20 of 20 rows carried a probe.
- **Record survival** - no data if no row carried a payload digest on BOTH sides. "No
  record may be lost" is then unverified. 20 of 20 rows carried both.
- **Epoch stability** and **ledger monotonicity** - no data if no row carried both values.
  20 of 20 rows carried both, for both checks.
- **Readback** - reported only when a slot read before a cut and not after. No such row.

### Verdict against the exit gate

The run measured, over 20 hand-made power cuts on real hardware, that a cut inside
change-PIN always leaves exactly one PIN able to open the device: 19 times the pre-commit
PIN, once the post-commit PIN, never both and never neither. It measured that the one user
record present survived all 20 cuts with a byte-identical SHA-256, that the epoch never
moved, that `next_seq` never regressed across 7,936 committed sequence units, and that the
device remounted and answered `status` after every cut. Every check the summariser can run
returned data, none returned NOT CHECKED, and no row carried a flag. The stale-ciphertext
half of the same exit-gate clause is answered separately and from the raw flash, in the
"Retired-side residue" section below. The sample is 20 pulls, not a sweep, and its index
spread is the weakest of the three modes - see the stated weakness at the foot of this file.

---

## Mode `attempt` - cut during a wrong-PIN unlock

Run: `.\tools\hil\power-cut-gate.ps1 -Port COM6 -Mode attempt`
Evidence: `C:\nb\hil\powercut-attempt-20260819-145849\`
Date: 2026-08-19, 14:58 to 15:13.  Cuts requested: 20.  Delay window: 0 to 700 ms after the
beep, which is the pause before the wrong PIN is sent rather than a delay into it.

**Result: 20 valid cuts, the count never went backwards, and no completed attempt went
uncharged.** The count rose by exactly one on the 12 cuts that arrived after the unlock had
answered and stayed put on the 8 that arrived during the stretch - none lost, none charged
twice - and the correct PIN reset it to 0 after all 20. No epoch change, no `next_seq`
movement, no failed remount, no flagged row, no harness error.

### What the cut is testing

`Vault::unlock` is ordered so that the counter is charged before the VERIFICATION, not
before the COMPUTATION. U1 pre-checks cost nothing. U2/U3 spend the Argon2id stretch and
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

**This design fails in the availability direction, deliberately, and the run confirms it
failed that way on hardware and not the other.**

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
  classic attack against exactly this mechanism. **Observed: zero of each, over 20 cuts.**
  All 12 rows carrying `unlock_completed_before_cut` True also carried `failures_after=1`.
- **Availability direction, where the owner loses guesses.** This one is REACHABLE by
  design and is the accepted cost. A cut after U4 and before the verification charges the
  owner for an attempt that never happened. An interrupted SUCCESSFUL unlock leaves entry =
  success + 1 until U7's catch-up runs on the next success. A torn cell scans as consumed.
  All three cost the owner attempts, and with the wipe enabled at N = 15 enough of them
  destroy the records. The design accepts that: an owner who repeatedly cuts power
  mid-unlock can walk their own device toward a wipe, and the alternative - resolving
  ambiguity toward a lower count - hands the attacker the free guess instead. **No row of
  this run landed in that window either**, which is not the same as it being unreachable;
  see the next section for why hardware cannot reach it.

So for the owner, a lost count here is at worst a wallet they must restore from their seed
backup. A lost count in the other direction would be a wallet an attacker gets to brute
force. This run checked that the ordering holds on real flash, and it did.

### What this mode cannot prove on hardware, and why that is not a weak run

This is the most honest thing in the record, so it is stated before the numbers rather than
after them.

**Attempt mode CANNOT sweep the counted region, and no amount of bench time will change
that.** `Vault::unlock` spends the whole Argon2id stretch before it programs the attempt
cell - deliberately, so that a cut during the stretch buys the attacker no uncounted
verification. On this board that stretch measured **2,343 to 2,351 ms across the 20 rounds,
mean 2,346 ms** (`stretch_ms`, taken from each round's own preceding correct unlock rather
than from a constant). The counted region - between the U4 program and the U5 verification
- is microseconds wide at the very end of a two-and-a-third-second operation. A hand-timed
pull will essentially never land inside it.

So a `cut_phase` column dominated by `uncounted_stretch` is the EXPECTED result and not a
weak run, and this run's split - `uncounted_stretch` x8, `after_the_attempt_completed` x12,
`at_or_after_the_counted_region` x0 - is what a hand-timed sample of that operation looks
like. The two phases that were sampled are the two an owner or a thief can actually reach
by hand, and both behaved correctly on every cut.

The exhaustive sweep of the U4 boundary is the host fuzzer - `Op::UnlockBad` and
`Op::UnlockToWipe`, both members of `Op::CORPUS` in `crates/notyas-wallet/src/fuzz.rs`,
driven by the `#[ignore]`d exit-gate test `the_full_corpus_holds` in
`crates/notyas-wallet/tests/powerloss.rs`, which cuts at every step boundary in every cut
mode:

```
cargo test --locked --release -p notyas-wallet --test powerloss -- --ignored --nocapture
```

Host fuzzer result backing this section: run 2026-08-19 on this workstation and recorded in
docs/release-readiness-0.2.0.md section 2.1 - PASS, 43,107 + 24,834 cases, 67,941 cuts
fired, 348,065 seals observed, 0 findings, 207.85 s. It was not re-run as part of this
hardware session.

What the hardware adds, and what no host test can claim, is that the property holds over
the real `esp_partition` driver, the real P4 HMAC peripheral and the real read-protected
eFuse key, across real power loss with real flash-cell physics. What the host fuzzer adds,
and what no hardware run can claim, is that every step boundary was visited. Neither
substitutes for the other, and this record does not let either stand in for the other.

### The record - every column `cuts.csv` carries for this mode

| Column | What it is | Observed |
|---|---|---|
| `cut` | 1-based cut number | 1 to 20 |
| `mode` | `attempt` | `attempt` |
| `delay_ms` | pause between the beep and the wrong-PIN command, so the operator's reaction lands INSIDE the unlock | 24 to 669 ms, inside the 0..700 window |
| `cut_detected` | True when the port vanished | True on 20 of 20 |
| `cut_at_ms` | when the port vanished, from the start of the workload | 344 to 86,960 ms. The long tail is operator reaction time, not device behaviour |
| `last_inflight` | the last `HIL\|unlock\|` line seen. Read this one carefully: that line is the unlock's ANSWER, so a non-empty value means the cut arrived after the operation ended, not inside it | non-empty on 12 of 20, empty on 8. Every non-empty one reads `ok=false\|err=Refused(WrongPin { attempts_remaining: Some(14) })\|failures_after=1` |
| `mount_before` / `mount_after` | boot line carrying mount, provenance or state | non-empty on 20 of 20 |
| `epoch_before` / `epoch_after` | wipe epoch either side; a change means a cut triggered a wipe | `0 -> 0` on all 20. Zero changes |
| `next_seq_before` / `next_seq_after` | ledger sequence. An unlock seals no records, so a STATIC value is expected here and is not a missing measurement | 16,896 on both sides of all 20 rows. Perfectly static, as designed, and equal to the value the `pin` run finished on |
| `failures_before` | the count after the harness cleared it with a correct unlock, so normally 0 | 0 on all 20 |
| `failures_after` | the count read after the cut, BEFORE the harness clears it again | 1 on 12 rows, 0 on 8. Never above 1, never below `failures_before` |
| `boot_count_after` | boot counter; rises by one per cut and cross-checks that a real power cycle happened | 70, then 72 through 90. See the note below: 71 is absent |
| `bad_pin` | the wrong PIN typed, which must parse or it never reaches the counter | `9999` on all 20 |
| `stretch_ms` | THIS board's measured Argon2id cost on the preceding correct unlock, not a constant from MEASUREMENTS.md | 2,343 to 2,351 ms, mean 2,346 |
| `unlock_completed_before_cut` | True when the console had already answered the unlock when the power went | True on 12, False on 8. The 12 True rows are exactly the 12 rows whose count rose |
| `cut_phase` | `uncounted_stretch`, `at_or_after_the_counted_region`, `after_the_attempt_completed`, or `unknown`. An inference from `cut_at_ms` against `stretch_ms`, not something the device said | `uncounted_stretch` x8, `after_the_attempt_completed` x12, and zero of the other two |
| `attempts_left_before` / `attempts_left_after` | remaining attempts. `none` means the wipe is DISABLED, which is a fact and not missing data; empty means the field was not parsed | `15 -> 14` on the 12 charged rows, `15 -> 15` on the 8 uncharged. `wipe_after=15` on every status line, so the wipe was ENABLED throughout and the run never came near it |
| `failures_after_clear` | the count after the correct PIN cleared it; anything but 0 means success did not clear the counter | 0 on all 20 |
| `flags` | anomalies for this row | empty on all 20. Zero flagged rows, zero harness errors |

**The boot counter skips 71, and that is in the record rather than smoothed away.**
`boot_count_after` reads 70 after cut 1 and 72 after cut 2, then rises by exactly one per
cut to 90. The endpoints 70 -> 90 span 20 increments across 20 cuts, but one of those
increments was not a cut: one extra power cycle happened between cut 1 and cut 2 that the
harness did not record. The `scan` evidence below independently agrees with that reading.
It affects no measured property - the epoch did not move, `next_seq` did not move, and the
count was cleared to 0 at the top of every round - but the counter is not a clean
one-per-cut sequence across this run and the record should not imply that it is.

Independent cross-check on the unlock traffic: 60 `unlock` commands were issued, which is
3 per round - the correct unlock that measures `stretch_ms`, the wrong PIN, and the correct
unlock that clears. All 40 correct unlocks were accepted. Of the 20 wrong PINs, 12 produced
a `HIL|unlock|ok=false` answer before the power went and 8 did not, matching
`unlock_completed_before_cut` row for row.

### Ledger-level corroboration, from the 20 `scan` lines

The records-region half of these scans is in the "Retired-side residue" section below,
which reads both runs together. The ledger half belongs here:

- **1,062 rising monotonically to 2,020 non-blank bytes**, and the per-round growth
  partitions cleanly along the counted/uncounted split. Eleven of the twelve charged rounds
  grew the ledger by exactly 56 bytes and one by 55; five of the seven measurable uncharged
  rounds grew it by exactly 40 and one by 39. That 16-byte separation is visible in the raw
  flash and it agrees with `failures_after` on every row without exception. The two rows one
  byte short are consistent with a programmed cell whose value happens to contain an 0xff
  byte, since the scan counts non-0xff bytes rather than cells - that is an explanation
  offered, not something this run measured.
- The one remaining outlier is round 2's growth of 48 rather than 40: eight bytes more,
  which is exactly one 8-byte `BOOT_LOG` cell (`crates/notyas-wallet/src/format.rs`). It
  falls on the same round as the missing boot count 71. Two independent measurements
  agreeing on one unrecorded power cycle is a better account than either alone, and it is
  recorded here rather than dropped.

### The summary, pasted verbatim

```
m4a power-cut gate, mode 'attempt' - C:/nb/hil/powercut-attempt-20260819-145849
========================================================================

Cuts requested        : 20
Cuts detected         : 20
Landed in an unlock   : 12   (a cut with no in-flight line interrupted nothing)
Rows carrying flags   : 0

Against the m4a exit criteria:

  Remount after cut   : all 20 cuts remounted and answered status.
  Epoch stability     : no epoch change across 20 comparable cut(s). No cut triggered a wipe.
  Ledger monotonicity : next_seq never went backwards across 20 comparable cut(s). No committed record was lost.
  Boot counter        : Some(70) -> Some(90) across the run, surviving every cut.

The attempt-counter gate, which is what this mode exists to answer:

  Count continuity    : across 20 comparable cut(s), the count rose by one on
                        12 and stayed put on 8.
                        No count was lost and none was charged twice.
  Completed attempts  : 12 cut(s) arrived after the unlock had answered, and
                        every one of them still carried its count afterwards.
  Success clears      : the correct PIN reset the count to 0 after all 20 cut(s).
  Where the cuts fell : uncounted_stretch x8, after_the_attempt_completed x12

  WHAT THIS MODE DOES NOT PROVE, and the reason it cannot. Vault::unlock spends
  about 1.9 s in Argon2id before it programs the attempt cell - deliberately, so a
  cut during the stretch buys no uncounted verification. The counted region is
  therefore microseconds wide at the very end of a two second operation, and a
  hand-timed pull will almost never land inside it: a `cut_phase` column full of
  uncounted_stretch is the expected result, not a weak run. The exhaustive sweep of
  that boundary is the host fuzzer, notyas-wallet tests/powerloss.rs, at Op::UnlockBad
  and Op::UnlockToWipe:  cargo test -p notyas-wallet --release -- --ignored
  What the hardware adds is that the same property holds over the real esp_partition
  driver and the real HMAC key, which no host test can claim.

Stated weakness, which belongs in the milestone note verbatim:

  The cut window was SAMPLED, not swept. Q43's USB-controlled relay is deferred
  to 0.3.0, so cuts were made by hand at the connector. The harness selects when
  to ASK for a cut, but the operator's pull lands some seconds later, so the
  in-flight index at cut time is observed rather than chosen. Coverage of the
  commit window is therefore a sample whose distribution nobody controlled, and
  a rare torn-write window could sit entirely between the sampled points.

Evidence: C:\nb\hil\powercut-attempt-20260819-145849\cuts.csv

VERDICT: EVERY CRITERION CHECKED, NONE BLOCKING, exit 0
         That is a statement about the data, not about the gate. Read the numbers
         above against the m4a exit criteria and decide that yourself.
```

Three lines of that summary are easy to misread, so read them against this.

- **"Landed in an unlock : 12"** counts rows whose `last_inflight` holds an `HIL|unlock|`
  line. Because that line is the unlock's answer and not an announcement before it, a HIGH
  number here means many cuts arrived AFTER the attempt finished. Where the cuts actually
  fell is the `Where the cuts fell` line, from `cut_phase`.
- **"In-flight index range"** does not appear at all for this mode. The unlock reply carries
  no `i=` field, so there is no index to range over. Its absence is structural, not a gap in
  the data.
- **"about 1.9 s in Argon2id"** is the summariser's fixed prose, not a measurement. This
  board's measured cost is in the `stretch_ms` column and it is 2,343 to 2,351 ms, mean
  2,346. The argument that sentence makes is unaffected and if anything gets stronger - the
  counted region sits at the end of a longer operation than the prose assumes - but 1.9 s is
  not this run's number and is not used as one anywhere else in this record.

### Which checks can come back with no data

**None of them did in this run.**

- **Count continuity** - NOT CHECKED if no row carried the count on both sides. That is the
  whole gate for this mode. 20 of 20 rows carried both.
- **Completed attempts** - reports "no cases to judge" when no cut arrived after the unlock
  had answered. That is an empty check, not a passing one, and it is a likely outcome: the
  harness beeps first precisely to get the pull inside the unlock rather than after it. This
  run had 12 cases to judge and all 12 were charged.
- **Success clears** - printed only when `failures_after_clear` carried a number. All 20
  carried 0.
- **Epoch stability** and **ledger monotonicity** - as above; 20 of 20 comparable.

### Verdict against the exit gate

The count never went backwards on any of the 20 cuts, and no completed attempt went
uncharged: all 12 cuts that arrived after the device had answered the unlock carried
`failures_after = 1`, and all 8 that arrived during the stretch carried 0, which is the
correct answer for a cut that reached no verification. The correct PIN cleared the count to
0 after every one of the 20. The epoch never moved, `next_seq` never moved, every cut
remounted, and no row carried a flag. No check had no cases to judge.

What this does NOT establish is behaviour inside the counted region itself, because zero
cuts landed there and, for the reason set out above, essentially none ever will by hand.
The hardware evidence is that the count survives a cut anywhere an operator can reach it;
the exhaustive boundary sweep is the host fuzzer, which passed on 2026-08-19 with 0 findings
over 67,941 cuts. This section claims the first and cites the second, and does not let
either read as the other. The sample is 20 pulls, not a sweep - see the stated weakness at
the foot of this file.

---

## Retired-side residue, read from the raw flash

The exit-gate item "a PIN change leaves no stale old-PIN ciphertext, proven by raw flash
readback, not by code inspection" is settled by the `scan` lines already in the two
2026-08-19 run logs. `summarize-cuts.ps1` refuses to answer it because its table has no
sector-to-slot mapping; the mapping is fixed by the format, so the raw counts can be read
against it.

### The mapping, from the code rather than from the shape of the data

`Layout::V1` (`crates/notyas-wallet/src/config.rs`) gives a 64-sector records region at
4,096 bytes per sector, with `canary_slots: 4`, `payload_slots: 8`, `registry_slots: 8`,
`payload_slot_sectors: 1` and `registry_slot_sectors: 2`. `SlotId::first_sector`
(`crates/notyas-wallet/src/slot.rs`) lays those out in class order with both sides
adjacent, which is the frozen map of ESP-SEAL.md 3.2:

| Sectors | Slots | Sectors per side |
|---|---|---|
| 0..1 | superblock, 1 slot | 1 |
| 2..9 | canaries, 4 slots | 1 |
| 10..25 | payloads, 8 slots | 1 |
| 26..57 | registries, 8 slots | 2 |
| 58..63 | reserved, erased | - |

21 slots, 42 sides, 58 mapped sectors and a 6-sector reserved tail.

`hil::scan` (`firmware/src/hil.rs`) streams `PartitionFlash::scan_raw` - the raw
pre-decode image of the region, not the logical view - and emits one count of non-`0xff`
bytes per 4,096-byte sector, in region order. So entry *n* is sector *n*, a count of 0 means
all 4,096 bytes of that sector read `0xff`, and side B of a slot is the entry (or entry
pair) immediately after side A. That is a raw flash readback, which is what the clause asks
for.

### What all 40 scans say

Across the 20 records scans of `powercut-pin-20260819-144312` and the 20 of
`powercut-attempt-20260819-145849` - 840 slot observations:

- **Zero slots, in any scan, had both sides non-blank.** Not one of the 840.
- **18 of the 21 slots carried exactly one live side in every scan**, and its retired side
  counted zero non-`0xff` bytes: the superblock, one canary, all 8 payloads and all 8
  registries.
- **The other 3 slots were blank on BOTH sides in all 40 scans.** These are the three
  unprovisioned canary slots: the layout reserves one canary per identity and `Layout::V1`
  allows 4, while the status line on every mount of both runs reads `state=formatted, 1 PIN
  identity/identities`. Zero live sides is the correct state for a slot that was never
  written, and it is called out rather than folded into the "exactly one live side" count.
- **The reserved tail, sectors 58 to 63, read blank in all 40 scans.**
- In all 40 scans the per-sector counts sum exactly to the reported `nonblank_total`, so
  the scan is internally consistent and nothing was dropped in transport.

### The control that makes the alternation mean something

The `pin` run's 20 scans hold exactly **two** live-side signatures across the 21 slots, and
they are complements of each other on all 20 record slots:

```
A B - - -  A A B B B B B B  B B B B B B B B     x12
A A - - -  B B A A A A A A  A A A A A A A A     x8
     superblock, canaries | payloads | registries
```

Every occupied canary, payload and registry slot flips sides between the two, which is the
change-PIN re-seal itself showing up in the raw flash. The superblock does not flip, and
should not: a change-PIN re-seals the records, not the superblock.

The `attempt` run, which changes no PIN, holds **one** signature for all 20 of its scans -
identical to the `pin` run's 12-count signature above. That is the control that says the
alternation in the `pin` run is the PIN change and not scan noise, drift, or an artefact of
the reboot.

### Scope, so the claim is not read wider than the evidence

The scan is issued after the board reboots, remounts and unlocks, so what is proven is the
SETTLED state: once the device comes back up, no retired side holds ciphertext, whether the
cut landed before or after the change-PIN commit cell. It is not an observation of the
window between C3 and C6, where `StaleSide::DeferToCommit` intentionally leaves both sides
written until the commit cell lands. That window is closed by C6's cleanup, or by mount M9
after a cut, and these scans are what shows the close actually happens on hardware. Catching
that window open would need a scan taken before mount runs cleanup, which the console cannot
do, because the console only exists after mount.

That limit is inherent to reading the flash over the device's own console and is not a gap a
further run would fill. What would fill it is an external programmer reading the flash with
the board held in reset, which this rig does not have.

---

## What these two runs close, and what stays open

The m4a exit gate, clause by clause, in MILESTONES.md's order.

| Exit-gate clause | Closed by these runs? |
|---|---|
| create a wallet, power cycle, unlock | Partly, and incidentally. Every cut is a power cycle followed by an unlock on a provisioned board, so the power-cycle-and-unlock half is exercised 40 times across the two runs, with 140 `unlock` commands issued and every accept and refuse landing where the harness expected it. The create-a-wallet half is not part of either run. |
| wrong PIN decrements the counter, and the decrement survives a reboot AND a power cut taken mid-decrement | The power-cut half: YES, by the `attempt` run, with the honest limit stated in that section - the hardware evidences survival of a cut anywhere in the unlock an operator can reach, and the exhaustive sweep of the U4 boundary is the host fuzzer. The reboot half is separately evidenced by the overflow soak's `-RebootAt`, which cannot run yet (below). |
| wipe-on-N at the default N = 15 destroys the records and bumps the epoch | NO. Neither run goes near it. `wipe_after=15` on every status line of both runs and `attempts_left` never fell below 14. The harness deliberately refuses to walk a provisioned board into a wipe: it stops when `failures` is within `-WipeMargin` (default 3) of `wipe_after`. Board B is the only eFuse-provisioned unit and its store is where all of this evidence comes from. This clause needs its own decision about which board to spend. |
| a PIN change leaves no stale old-PIN ciphertext, proven by raw flash readback | YES, for the settled post-mount state, by the "Retired-side residue" section: 840 slot observations from raw `scan_raw` reads across both runs, zero of them with two live sides, every retired side at zero non-`0xff` bytes, and the no-PIN-change run as the control. It is a raw flash readback and not code inspection, which is the standard the clause sets. It does not observe the intentional C3-to-C6 both-sides-written window, which the console cannot reach; that limit is stated in the section. |
| the stateless path still writes nothing, proven by a flash readback diff on a dev board | NO. Not a power-cut run at all. |
| the Verify screen reports the real eFuse HMAC-key state, not a constant | NO. Not a power-cut run at all. Both runs' status lines do report `provenance=eFuse HMAC_UP key, read-protected` read from the device rather than a constant, on all 40 post-cut mounts, but that is the console surface and not the Verify screen the clause names. |
| SET-POLICY survives a cut at each of its seven steps with the effective policy never weaker than both values | **NO, and still not done - re-checked against today's firmware rather than carried over.** The `help` output captured in this run's `console.log` lists 24 commands and neither `setpolicy` nor `policysoak` is among them, and `firmware/src/main.rs` still refuses `UiRequest::SetWipePolicy`, because committing a policy re-seals the store under the PIN and the session holds a derived key rather than the PIN itself. `-Mode policy` also needs `min_pin_len` on the status line, which today's status line does not carry. The harness probes `help` and writes `BLOCKED.txt` without cutting anything, which is the correct record: a firmware gap, not a test result. |
| a device with wipe DISABLED survives 128+ consecutive failed attempts without overflowing the attempt log or losing the accumulated count | **NO, and still not done**, blocked on the same gap. Reaching the wipe-disabled state needs `set_policy`, and nothing on the device can commit one; both runs confirm the board is fixed at `wipe_after=15`. `tools/hil/attempt-overflow-gate.ps1` refuses to send a single wrong PIN unless the device reports `wipe_after=0`, because on a wipe-enabled board that run would destroy every record at attempt 15. Host coverage today is the fuzzer's `Op::RotationOnFailure`, a member of `Op::CORPUS`, which is a real proof over simulated flash and not the same claim. |
| ...on BOTH boards | NO. See below. |

So: these two runs close the two modes KNOWN-ISSUES K5 names as runnable, and they close
them without a single flagged row, a single NOT CHECKED check, a single harness error or a
finding in either direction. Between them they also close the stale-ciphertext clause, which
K5 did not expect them to reach. Three clean runs of three modes is the strongest storage
evidence this project holds and this record does not undersell it.

It also does not close K5. K5 additionally names the SET-POLICY seven-step sequence and the
wipe-disabled 128-attempt overflow; both were re-checked against today's firmware and both
are still blocked on one firmware gap rather than on bench time. Board A is still untested.
K5 is therefore narrowed by these runs, not closed.

## Board A has never been power-cut tested

Every cut recorded in this file was taken on board B. Board A has not been cut once, in any
mode. It is unprovisioned by design - `KeyProvenance::Emulated`, no eFuse HMAC key burned -
so its store path is not the same code path board B exercises, and the gate's own wording
is "on both boards".

The technical shape of the difference, since the decision has to be made against it rather
than against a guess. The two boards diverge inside one function, `DeviceMac::hmac` in
`firmware/src/store/mac.rs`: board B routes it to the P4 HMAC peripheral over a
read-protected eFuse key, board A to `soft_hmac` over a compiled-in development constant
behind the `unsafe-emulated-key` feature. Both return 32 bytes, and everything the
power-cut gate actually measures sits downstream of that return - the KDF ladder, the record
format, the A/B side selection, the ledger cell logs, the `esp_partition` write path and
mount's cleanup pass all consume the MAC output and cannot observe where it came from. What
board A would exercise that board B does not is the peripheral-versus-software boundary
itself, including whether an in-flight HMAC peripheral operation behaves differently across
power loss than a software one, plus the different display geometry, which the storage path
does not touch. Board A also cannot run the gate as it stands: an unprovisioned store
refuses to format, so reaching a cuttable state means burning its eFuse, which is permanent
and on the second of two boards.

There are exactly two acceptable outcomes and this file carries one of them before release:

1. **Re-run the gate on board A.** That means provisioning it first, which is a permanent
   eFuse burn on the second of two boards.
2. **Scope it out, with the reason written down here.** The paragraph above is the material
   such a scope-out has to be argued from, and it is deliberately not written as the
   argument: it states what the two paths share and what they do not, and it stops short of
   asserting that a cut on the shared part is sufficient evidence for both. That assertion
   is the owner's to make or refuse, because it is the assertion that spends or saves the
   second board. A scope-out that only says "no time" is a waiver, and MILESTONES.md
   section 9 item 1 does not permit a waived gate.

Chosen: **not yet chosen, as of 2026-08-19.** This is the one item in this record that is an
open owner decision rather than an open measurement, and it holds the gate open until it is
made.

## Stated weakness, which belongs in the milestone note verbatim, for every mode above

The cut window was SAMPLED, not swept. Q43's USB-controlled relay is deferred to 0.3.0, so
cuts were made by hand at the connector. The harness selects when to ASK for a cut, but the
operator's pull lands some seconds later, so the in-flight index at cut time is observed
rather than chosen. Coverage of the commit window is therefore a sample whose distribution
nobody controlled, and a rare torn-write window could sit entirely between the sampled
points.

For `seal`, the 18 distinct indices from 3 to 1999 show the sample is spread rather than
clustered, which is the most that can be claimed without the relay.

For `pin`, the spread is the weakest of the three and this record does not dress it up. The
in-flight index at cut time was `i=0` on 8 cuts, `i=1` on 11 and `i=7` on 1: a range of 0 to
7 but only three distinct values, and 19 of 20 cuts landed in the first two change-PIN
operations of their round, out of 58 announced. Operator reaction time, not the harness,
decided that nearly every pull arrived early in a round. What the run does spread well is
the other axis - `delay_ms` covered 355 to 5,693 ms of the 40..6000 window and `cut_at_ms`
ran 1,860 to 33,019 ms - so the cuts landed at varied points WITHIN a change-PIN even though
they landed on much the same change-PIN each time. The gate's claim is about where a cut
falls inside the C1-C6 sequence, and that axis is genuinely sampled; the index axis is close
to clustered and is reported as such rather than as 20 independent samples.

For `attempt` there is no index to report, and the spread is the `cut_phase` distribution
instead: `uncounted_stretch` x8, `after_the_attempt_completed` x12, and zero in the counted
region. That distribution is not a sampling failure - it is the predicted consequence of a
2.35-second stretch guarding a microsecond-wide counted region, set out in that mode's own
section. The relay will not fix it either; only the host fuzzer sweeps it.

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
mode. The evidence is on local disk and is not mirrored elsewhere, because it is
machine-specific test output rather than repository content - the harness refuses a UNC
`-OutDir` for that reason.

## Not yet done

- The SET-POLICY seven-step cut sequence and the wipe-disabled 128-attempt overflow case.
  Re-checked against today's firmware, and both still blocked on the same gap: no route to
  `Vault::set_policy` from the device, so no `setpolicy` console command, no `policysoak`
  announcement and no `min_pin_len` on the status line.
- wipe-on-N at N = 15 on hardware, which no power-cut mode performs and which costs the
  store of whichever board runs it.
- Board A, per the section above - and specifically the choice between re-running and
  scoping out, which is unmade.
- An external-programmer read of the records region with the board held in reset, which is
  the only way to observe the C3-to-C6 both-sides-written window that the on-device console
  cannot reach. This is a rig capability the bench does not have, not a run that was skipped.

Nothing on this list is a check that returned NOT CHECKED. Every check the two 2026-08-19
runs could run, ran and returned data; the items above are measurements that were never
attempted, not measurements that came back empty.
