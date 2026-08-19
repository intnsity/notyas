# notyas HIL runbook - the outstanding hardware gates

Everything you type, in order, for the m4a hardware gates that are still open, with what a
good result looks like and what a bad one means.

You pull and reseat one connector. The harness does the rest: it drives the console, times
the cut by watching the serial port disappear, waits for the reseat, reads the state back,
and writes a per-cut record. It never prints PASS - a tool that does is a tool that gets
believed when it should not be. It records, flags, and leaves the verdict to you.

Nothing here flashes a board or touches an eFuse. Provisioning is a host step and is
already done (ratified Q45).

## The two boards

| | Board A | Board B |
|---|---|---|
| Unit | Waveshare ESP32-P4-WiFi6-Touch-LCD-4B | Elecrow CrowPanel Advanced 5inch |
| Port | COM3 | COM6 |
| Panel | 720x720 | 800x480 |
| Device key | emulated (`unsafe-emulated-key`) | eFuse BLOCK_KEY5, HMAC_UP, read-protected |
| PIN | as set on that unit | 1234 |
| Store | dev | formatted against the real key |

Board B is where the storage and device-binding evidence comes from. Board A's emulated key
cannot substitute for it: its provenance is `KeyProvenance::Emulated`, so the ladder it
seals under is not the one a product device uses.

Board B is the only eFuse-provisioned unit on the bench. **Nothing in this runbook may put
it into a wipe.** The harness enforces that (see "The wipe rail"), but the rule is yours,
not the tool's.

## Before the first run

The board must be running a `hil-console` image. A product image has no console and every
command below fails silently in the same way.

```
# Board B (real key, no emulation feature)
powershell -NoProfile -ExecutionPolicy Bypass -File tools\build.ps1 -Board elecrow-5 --features hil-console

# Board A (emulated key)
powershell -NoProfile -ExecutionPolicy Bypass -File tools\build.ps1 -Board waveshare-4b --features hil-console,unsafe-emulated-key
```

Smoke check before you spend an evening on cuts. Open the port in any serial terminal at
115200 and type `status`, then `help`. Two things to read:

- `provenance=EfuseReadProtected` on board B. If it says `Emulated`, you are on the wrong
  image or the wrong board and every result would be about the wrong ladder.
- `wipe_after=15`, `failures=0`. If `failures` is not 0, unlock once with the correct PIN
  to clear it before starting. A run that begins at `failures=12` will stop itself three
  cuts later, which is correct behaviour and a waste of your evening.

Every harness below takes `-DryRun`, which sends nothing to the board and prints exactly
what the run would do. Use it once per mode to confirm the port and the PIN before the
first pull.

**The gates below are in the order to run them.** They are independent, but a `pin` run can
leave the board on PIN 5678 and every other command in this file defaults to 1234, so the
counter gate goes first and you never have to remember which PIN the board is on.

## Gate 1 - board B, cut during the attempt counter

The gate: a wrong PIN decrements the counter, and the decrement survives both a reboot and
a cut taken during it.

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\hil\power-cut-gate.ps1 `
    -Port COM6 -Mode attempt -Cuts 20 -Pin 1234 -BadPin 9999
```

Budget about 30 minutes. This mode beeps FIRST and then sends the wrong PIN, which is
backwards from the other modes and deliberate: the operation is a single unlock of about
1.9 s, so a beep partway through it leaves no time to pull. Pull on the beep. Per cut the
harness first unlocks with the correct PIN - that clears the counter to a known 0 and
measures this board's real stretch cost - then locks, then sends the wrong one.

**Good result.** `failures_after` is either `failures_before` or `failures_before + 1` on
every row, never less; every row that shows `unlock_completed_before_cut=True` shows the
count incremented; `failures_after_clear` is 0 everywhere. The summary reads:

```
  Count continuity    : ... No count was lost and none was charged twice.
  Completed attempts  : N cut(s) arrived after the unlock had answered, and
                        every one of them still carried its count afterwards.
```

**Bad results.**

- `failures_went_backwards` - a count that existed before the cut is gone after it. That is
  a free guess for whoever pulled the power. Blocking.
- `completed_attempt_not_counted` - the console had already answered the unlock when the
  power went, and the count did not move. The device performed a verification and did not
  charge for it, which is exactly what the counter exists to prevent. Blocking.
- `failures_counted_more_than_once` - one attempt charged twice. Not a security hole, but
  it walks a real user toward a wipe they did not earn.
- `success_did_not_clear` - a correct PIN did not reset the count.

**What this gate does not prove, and why it cannot.** `Vault::unlock` spends the whole
~1.9 s of Argon2id BEFORE it programs the attempt cell, by design: an attacker who cuts
during the stretch has paid the cost and learned nothing. So the counted region is
microseconds wide at the very end of a two second operation, and a hand-timed pull will
essentially never land inside it. A `cut_phase` column full of `uncounted_stretch` is the
expected result of a correct run, not a weak one. The exhaustive sweep of that boundary is
the host fuzzer:

```
cargo test -p notyas-wallet --release -- --ignored --nocapture
```

`tests/powerloss.rs` cuts at every step boundary of `Op::UnlockBad` and `Op::UnlockToWipe`
with eleven invariants asserted after each. What the hardware run adds is that the same
property holds over the real `esp_partition` driver and the real HMAC key, which no host
test can claim. Say both in the milestone note; either one alone overstates.

## Gate 2 - board B, cut during change-PIN

Change-PIN is the operation with the most steps, and the only one whose commit point moves
a whole identity's records. The gate: after a cut, EXACTLY ONE of the two PINs opens the
device, and no record is lost.

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\hil\power-cut-gate.ps1 `
    -Port COM6 -Mode pin -Cuts 20 -Pin 1234 -PinB 5678 -Slot 1
```

Budget about 45 minutes for 20 cuts. Per cut the harness unlocks with whichever PIN is
current, reads slot 1 for its SHA-256, starts `pinsoak`, then beeps. Pull the connector on
the beep, wait for it to log the cut, and reseat when it says so. After the reseat it tries
PIN 1234, then PIN 5678, then re-reads slot 1 under whichever opened.

**Good result.** Every row has `pin_after` set to one PIN or the other, `payload_sha_after`
equal to `payload_sha_before`, and an empty `flags` column. The summary reads:

```
  Which PIN opens     : exactly one PIN opened the device after each of 20 probed cut(s).
  Record survival     : the slot's SHA-256 was identical before and after across 20 cut(s).
```

**Bad results, and what each one means.**

- `both_pins_open` - the cut left two valid sealing keys on one store. Blocking. Stop and
  keep the board as it is; the ledger's pin-generation cells are the evidence.
- `no_pin_opens` - the store is unreachable with either PIN. Blocking, and the harness ends
  the run itself: further cuts would spend attempts against the wipe threshold with no way
  to clear them. Do not keep typing PINs at it.
- `payload_digest_changed` - a record's bytes moved across a PIN change. That is record
  loss or corruption, not a re-seal. Blocking.
- `record_unreadable_after_cut` - the slot read before the cut and not after.

**Where this leaves the board.** A `pin` run ends on whichever PIN the last change
committed. Read the `pin_after` column of the last row of `cuts.csv`. If it says 5678, pass
`-Pin 5678` to anything you run on this board afterwards, or set it back with a serial
terminal:

```
unlock 5678
changepin 1234
```

**The other half of the same exit-gate clause** - "a PIN change leaves no stale old-PIN
ciphertext" - is proven from the flash, not from the CSV. Every cut runs `scan`, which
prints per-sector non-0xff byte counts for both regions. Open `console.log`, find a `scan`
after a cut, and confirm the retired side of the re-sealed slot counts zero. That is the
readback the milestone asks for; code inspection does not satisfy it.

## Gate 3 - board A

Board A has never been power-cut tested. The m4a exit gate says "on both boards", so this
is either run there or explicitly scoped out with a reason written down. Its store path
genuinely differs - `KeyProvenance::Emulated` rather than `EfuseReadProtected` - so the
result is not implied by board B's.

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\hil\power-cut-gate.ps1 `
    -Port COM3 -Mode seal -Cuts 20 -Pin <board A PIN>
powershell -NoProfile -ExecutionPolicy Bypass -File tools\hil\power-cut-gate.ps1 `
    -Port COM3 -Mode pin  -Cuts 20 -Pin <board A PIN> -PinB 5678
```

If you scope it out instead, the reason belongs in `docs/m4a-power-cut-evidence.md` and in
the milestone note, in the same sentence as the claim it qualifies.

## What this runbook does not cover

The m4a exit gate has items that are not power-cut gates and have no harness here. They are
listed so their absence from this file is not read as their being done, and their status is
whatever the milestone note says, not whatever this paragraph guesses:

- wipe-on-N at the default N = 15 destroying the records and bumping the epoch;
- the stateless path writing nothing, proven by a flash readback diff on a dev board;
- the Verify screen reporting the real eFuse HMAC-key state rather than a constant, which
  on an unprovisioned board must be able to render "not provisioned" (R20).

If you do walk the wipe threshold on board B, walk it LAST. It destroys every record on the
only eFuse-provisioned unit on the bench by design - that is what the gate asks for - and
every other gate in this file needs those records to still be there.

## What is blocked, and why

Two items named in the m4a exit gate cannot be run on hardware today. Neither is blocked on
bench time; both are blocked on a firmware surface that does not exist.

### The SET-POLICY seven-step cut sequence

The gate: "a SET-POLICY change survives a power cut taken at each of its seven steps with
the effective policy never weaker than both the old and the new value."

`Vault::set_policy` is implemented and its seven steps are Y1 to Y7 in
`crates/notyas-wallet/src/vault.rs`, with the commit at Y4. Nothing on the device can reach
it. `firmware/src/store/mod.rs` publishes no route, `firmware/src/main.rs` refuses
`UiRequest::SetWipePolicy` and says why in its own comment (the policy is authenticated
inside the AEAD, so committing it is a re-seal and needs the PIN, which that request does
not carry), and `firmware/src/hil.rs` has no `setpolicy` command.

The harness is written and waiting. It probes `help` before the first cut and refuses with
a `BLOCKED.txt` rather than cutting into a console that rejects every line:

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\hil\power-cut-gate.ps1 `
    -Port COM6 -Mode policy -DryRun
```

The console contract it drives, which is what the firmware has to add:

```
setpolicy <wipe_after|off> <min_pin_len> <pin>
    -> HIL|setpolicy|ok=true|wipe_after=N|min_pin_len=N|policy_gen=N

policysoak <wipe_a> <wipe_b> <min_pin_len> <pin> <n>
    -> HIL|policysoak|about_to_step|i=N|step=Y1..Y7|wipe_after=N
       One line BEFORE each of the seven steps, exactly as `soak` announces each seal.
       Without the announcement a cut cannot be attributed to a step, and "a cut at each
       of its seven steps" stays unevidenced no matter how many cuts are taken.

status: add min_pin_len to the existing line.
       It carries wipe_after and policy_gen but not the floor, so the half of SET-POLICY
       that moves the floor cannot be read back at all.
```

When that lands, the run is 21 cuts and the summary reports coverage of Y1 to Y7 rather
than a count, because the step is observed and not chosen: a run of 40 cuts that never
touched Y6 has not closed this gate.

Note for whoever adds it: the harness never asks for a PIN floor above 4 (ratified Q4), and
`disable_wipe_min_pin_len` is `None` in the product config (ratified Q62). `setpolicy` must
not introduce a floor of its own.

### The wipe-disabled 128-attempt overflow

The gate: "a device with wipe DISABLED survives 128+ consecutive failed attempts without
overflowing the attempt log or losing the accumulated count (the `failures_base` rotation
path)."

Same blocker. Reaching the wipe-disabled state needs `set_policy`, and nothing on the
device can commit one. The gate has its own harness because nothing is cut - it is a soak,
and once it starts it needs no one at the bench:

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\hil\attempt-overflow-gate.ps1 `
    -Port COM6 -DryRun
```

It refuses to send a single wrong PIN unless the device reports `wipe_after=0`. That check
is the most important line in the file: on a wipe-enabled board this run destroys every
record at attempt 15. When the firmware can disable the wipe, the real run is

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\hil\attempt-overflow-gate.ps1 `
    -Port COM6 -Attempts 136 -RebootAt 64 -Pin 1234
```

about six minutes plus one power cycle at attempt 64, which evidences the reboot half of
the counter gate in the same run. What it watches is one column: the failure count must
rise by exactly one per attempt, including across the 128-cell boundary where the ledger
rotates and the running count moves into `failures_base`. A count that returned to zero
there would make every guess after it free.

Until then, what covers this is the host fuzzer's `Op::RotationOnFailure`, in the same
`--ignored` run as above. That is a real proof over the simulated flash and it is not the
same claim as hardware.

## After every run

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\hil\summarize-cuts.ps1
```

With no arguments it summarises the newest run under `C:\nb\hil` that actually recorded
something. Pass `-RunDir C:\nb\hil\powercut-pin-<stamp>` for a specific one.

The summary prints the common criteria (remount, epoch stability, ledger monotonicity, boot
counter) and then a section written in the columns of whichever mode ran. It distinguishes
a check that passed from a check that had no data: "NOT CHECKED" is printed wherever a
column was empty, and it is not a pass. If you see it, the property is unverified and the
milestone note must not claim it.

Evidence lands in `C:\nb\hil\powercut-<mode>-<stamp>\`, or `overflow-<stamp>\` for the
attempt-overflow gate, whose per-attempt records are `attempts.csv`:

- `cuts.csv` - one row per cut, the machine-readable record
- `cuts.json` - the same rows
- `console.log` - the full transcript, every line sent and received
- `BLOCKED.txt` - present only when the firmware could not drive that mode

It is local by design. The harness refuses a UNC `-OutDir`: the tree on the NAS is
canonical, and machine-specific test output does not belong in it.

Paste the summary into `docs/m4a-power-cut-evidence.md` as its OWN section for that mode,
never folded into the seal numbers: a mode with no data must not average into one that has
some (KNOWN-ISSUES K5). Include the "Stated weakness" paragraph verbatim. The window was
SAMPLED by hand and not swept - Q43's relay is deferred to 0.3.0 - and a reader who sees
only the pass rate would reasonably assume otherwise.

K5 is the open entry these runs close, and it is the only entry in `docs/KNOWN-ISSUES.md`
that blocks 0.2.0 on its own. It will not be closed by the `pin` and `attempt` runs alone:
it names the SET-POLICY sequence and the 128-attempt overflow too, and both are blocked on
the firmware surface described above.

## The wipe rail

`pin` and `attempt` type wrong PINs at a real provisioned board, so before every cut the
harness reads `failures` and `wipe_after` and stops the run if the count is within
`-WipeMargin` (default 3) of the threshold. It prints:

```
STOP: failures=N is within 3 of wipe_after=15.
```

That is the harness working, not a fault. Unlock once with the correct PIN to clear the
count and start a new run. Do not raise the margin to push through it; on board B the thing
on the other side of that number is every record on the only provisioned unit you have.

## When something goes wrong

| What you see | What it means | What to do |
|---|---|---|
| `WARN: port never vanished` | The pull was not detected inside ten minutes. | The row is recorded as MISSED and is not counted as a cut. Continue. |
| `CUT n FAILED (harness error, not a device finding)` | Serial-port transient, usually a board re-enumerating after re-power. | Recorded as a flagged row, excluded from the pass count. The run continues by itself. |
| `readback attempt 1 of 3 failed` | The port opened and then died on first use. | It retries twice more. Only a third failure gives up on that cut. |
| `waiting for COM6 - reseat the connector` | The port has not come back. | Reseat it. There is a five minute window. |
| `neither PIN opened the device` | Blocking finding, and the run ends. | Leave the board alone and read `console.log` before touching it. |
| Console answers nothing at all | Wrong image (no `hil-console`) or wrong port. | Check `status` in a terminal before spending another pull. |

A flagged row is not a failed gate and a harness error is not a device finding. Both are
recorded rather than hidden, and both are excluded from the counts, because a run that
quietly dropped its bad rows would be the one number nobody could check.

## The release loop, which is a different bar

`tools/hil/end-to-end-loop.ps1` drives MILESTONES section 9 clause 2 - seed, save, power
cycle, unlock, register a 2-of-3 P2WSH, verify an address, load a PSBT from SD, review,
sign, coordinator accepts. It probes the device's command surface first and names the steps
that are not drivable yet, so it is worth running now to see exactly what is missing:

```
powershell -NoProfile -ExecutionPolicy Bypass -File tools\hil\end-to-end-loop.ps1 -Port COM6
```

Supply `-Descriptor` and `-PsbtHex` from a coordinator when the loop is complete, never from
this device: the point of those steps is agreement with software that did not create them.
