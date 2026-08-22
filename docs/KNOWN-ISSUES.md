# notyas 0.2.0 - known issues

Open defects and rough edges found during development, tracked here so the handover states
them up front rather than letting the owner discover them. Each entry says what it is, how it
was found, whether it blocks release, and what closing it requires.

Closed entries stay, with their resolution, because the reasoning is often the useful part.

**Read the 2026-08-19 revision note before anything else.** This file previously opened with a
release block that no longer holds. K13 said a shipped image could not set a PIN, K17 said the
signing path was absent from the touch UI, and K18 and K19 said the microSD subsystem and
multisig registration were reachable by nothing. All four closed on 2026-08-19 and are in the
CLOSED section below with what fixed them and where. Every remaining entry was re-verified
against the tree the same day, and each carries a dated line saying so, because an entry
nobody has re-read is indistinguishable from an entry that is still true.

**What that revision did NOT do is make the release ready, and the shape of the remaining
problem changed rather than shrank.** Most of the old group leaned on K13: a defect behind an
unreachable door costs nothing until the door opens. The door is open, so K14, K15, K16 and
K20 are now defects a stranger meets, and three of them are release-blocking for that reason
alone by rules those entries had already written down for themselves. Against that, the whole
of the new surface is unproven on silicon: everything that landed on 2026-08-19 has host tests
and clippy and a graphics gate, and not one line of it has run on a board (K24).

The blocking set as this revision stands is **K5, K14, K16, K24, K25 and K26**: two
power-cut modes that ran and were never written up plus two more that no build can perform; a
save whose refusal is silent; a delete and a change-PIN that consent the user and do nothing;
a product path with no hardware evidence at all; an external cross-check that has never
executed; and a release runbook that still describes the product as it was before that day's
work. The one-paragraph statement of what the release can and cannot do is
`docs/RELEASE-0.2.0.md` section 0, and per K26 it is currently wrong.

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

**Re-verified 2026-08-19.** Still true, and demonstrated rather than read: `cargo test -p
notyas-wallet --release --doc -- --ignored` fails to compile all three examples and reports
`test result: FAILED. 0 passed; 3 failed`. The line numbers have drifted with the file - the
examples are at `src/lib.rs:53`, `src/sim.rs:31` and `src/sim.rs:927` today - which is itself
an argument for making them compile: a fenced example nothing checks is free to rot in place.

### K2. The development host leaks kernel handles and exhausted its memory

**Found:** the machine itself, 2026-08-18. The System process (PID 4) had accumulated
16,705,584 File handles over seven days of uptime, holding 78.4 GB of paged plus nonpaged
pool on a 95.2 GB machine. Explorer, dwm and SearchHost died at 04:20:33 with "could not
allocate additional memory", NTFS dismounted seven volumes, and the machine shut down
unexpectedly at 08:55:40. Diagnosed after the fact from the event logs and from live
sampling after the reboot.

This is a defect in the development workstation, not in notyas. No firmware, no crate in
this workspace, and no released artifact is implicated. The leaking allocations are kernel
pool held by a driver calling ZwCreateFile with no matching ZwClose; no user-mode process
can hold kernel pool, so cargo, rustc and the test suites are excluded by construction -
they were blamed first and the attribution was wrong. The candidates are the SMB redirector
stack, Windows Defender's WdFilter, the two Malwarebytes minifilters, and two SenseShield
DRM drivers. The whole SMB and filesystem stack on this host was replaced by KB5123304 and
KB5120708 on 2026-08-11, and the machine died 6 d 4 h 45 m after first booting onto it.
Root cause is OPEN: the machine was rebooted before the leaked file was named, and a reboot
returns the pool to the free list and destroys the evidence.

The project's exposure is that the working tree is canonical on an SMB share, so this
project's own file I/O is the workload most correlated with the failure. That correlation
is a hypothesis, not a finding - see docs/OPS-HOST.md, which carries the full incident
record, the ranked candidates with their decisive checks, and the emergency procedure.

Does it block 0.2.0? No, and the argument is worth stating rather than asserting. A release
gate asks whether the shipped artifact is defective. Nothing here touches the firmware
image, the reproducible build, the signing path or any invariant in SECURITY.md; the same
source builds byte-identically on any host and the QA.md gauntlet is unaffected. An
intermittent host fault would only block release if it could corrupt an artifact silently,
and it cannot: it exhausts memory and kills processes, which fails builds loudly rather
than producing a bad image, and every release artifact is verified by hash against a
reproducible rebuild regardless.

What it does block is development throughput, and it has already destroyed one work
session, which is why it is tracked here rather than left as an operational footnote. It
also carries a real risk to the release schedule rather than to the release itself: if it
recurs mid-gauntlet it costs a day, and any build that dies to it must be re-run from clean
rather than trusted.

Closing it: name the file the leaked handles point at, during a live leak and before any
reboot, then map its path prefix to the owning driver. The tooling is in `tools/ops/` and
the procedure is section 4 of docs/OPS-HOST.md. Two prerequisites are not yet met: nothing
is currently watching, since PoolWatch is not registered as a scheduled task, and it has
never been confirmed that the handle table returns usable object pointers even to a
privileged caller on this build. Both are cheap to settle while the machine is healthy, and
both are open questions Q4 and Q5 in that runbook. Until the driver is named, the standing
mitigations - build artifacts pinned off the share, the CI target-dir gate, the build-graph
prune - reduce the correlated workload but prove nothing about the cause.

**Re-verified 2026-08-19.** Unchanged, and the first prerequisite is still unmet.
`poolwatch/poolwatch.csv` holds one sample, taken at 02:26 UTC today, still in its six-sample
warm-up, and nothing has written to it since - so PoolWatch ran once by hand and is still not a
scheduled task. `Get-ScheduledTask` matches no PoolWatch entry. Nothing is watching, so a
leak that recurs before something starts will destroy its own evidence at the reboot,
exactly as it did the first time.

### K3. The HIL console cannot erase a store it refused to mount

**Found:** 2026-08-18, re-provisioning board B after the `BLOCK_KEY5` HMAC_UP burn. The
board carried a store formatted earlier against the emulated key, the burn changed the
device binding, and the one console command that exists for exactly that situation could
not be reached.

`Vault::mount` refuses a store whose recorded `device_tag` is not this device's
(`crates/notyas-wallet/src/vault.rs:420`, `MountError::Foreign`). `Store::bring_up`
propagates that as `BringUpError::Mount` and `firmware/src/main.rs` turns it into
`store = None`, which is deliberate - a device that cannot mount its store must still run
the stateless flow. The console dispatcher then holds `&mut Option<Store>` and its store
arm rejects EVERY store command with `err=store_unavailable` when that option is `None`
(`firmware/src/hil.rs:221`). So `erase`, `status` and `scan` all disappear at precisely the
moment they are the only commands worth having. The mount refusal is correct and must
stay; the defect is that the console's own recovery path is unreachable exactly when it is
needed.

The sharp part is that two of those three commands never touch the store. `erase` opens its
own `PartitionFlash`, calls `erase_all` on both regions, and discards its parameter with
`let _ = s;` (`firmware/src/hil.rs:298`); `scan` has the same shape (`hil.rs:409`). They are
gated on a value they do not read. Recovery on the bench was therefore a host-side erase of
the `wallets` and `counters` partitions with esptool followed by `format` - written up in
docs/PROVISIONING.md, since the next person to burn a board will land in the same state.

Does it block 0.2.0? No, and the argument is more useful than the verdict. A release gate
asks whether the shipped artifact is defective, and this code is not in it: the HIL console
sits behind the non-default `hil-console` feature (`firmware/Cargo.toml`, `default = []`),
so a release build does not compile it. Q41's belt-and-braces symbol gate is declared in
that same file as `tools/ci/check-release-symbols.sh`, and that script does not exist yet -
a gap in the release runbook rather than in this defect, since the feature flag alone
already keeps the console out of the artifact. Nothing a user receives behaves differently.
What this is instead is a defect in the instrument that reads back m4a's power-cut gate -
the gate most likely of anything in the plan to leave a store that will not mount - and the
cost of meeting it there is a host erase per occurrence plus the real risk that an operator
fifteen cuts deep reads an unmountable store as a harness fault and keeps going. "Does not
block release" is not the same sentence as "leave it": the fix is smaller than the
workaround it replaces, and it should land before the twenty cuts, not after.

One thing this entry deliberately does not answer: the product has the same shape of gap. A
device whose store mounts `Foreign` falls back to the stateless flow with every store
surface gone, and no UX-SCREENS.md screen offers a recovery from it. Whether 0.2.0 needs
one is an m4b scope question for the owner, not a defect report.

Closing it: move `erase` and `scan` out of the store-gated arm, since neither reads the
store, and give `status` a mount-refused form that prints the provenance and the refusal
class in place of the vault's fields - that is the diagnostic a person actually needs when
the mount fails. Note that `Vault::mount` consumes its backends and returns `Err`, so
`Store` cannot simply hold a refused vault; the console keeping its own `PartitionFlash`
for these commands is the smaller change and is what those two already do.

**Re-verified 2026-08-19.** Still true. `firmware/src/hil.rs` now names this entry in the
dispatcher itself: the release-loop commands (`network`, `wallet`, `paste`, `register`,
`registrations`, `address`, `psbtload`, `psbtinspect`, `psbtsign`) were deliberately placed
OUTSIDE the store-gated arm with a comment citing K3 as the reason. `status`, `erase`, `scan`
and the rest are still inside it and still vanish on a store that will not mount. The pattern
was learned and the original three were not moved.

### K4. The m4a power-cut window is sampled at a human-timed instant, not swept

**Found:** 2026-08-18, from the manual power-cut harness itself
(`tools/hil/power-cut-gate.ps1`) while preparing the m4a gate. The gate's twenty-plus cuts
have not been performed - they need the board owner present - so this is a property of the
method, established before the run rather than discovered during it.

Q43 deferred the relay rig and MILESTONES m4a already says the window is SAMPLED rather
than swept because manual timing is not repeatable to the millisecond. Using the harness
sharpens that into something stronger: **the delay parameter does not select when the cut
happens at all.** The harness waits its scripted delay, beeps, and prints PULL POWER NOW;
the operator's hand arrives seconds later and the board keeps working throughout. The
parameter selects when we ASK. The instant of the cut is whatever reaction time makes it,
and the delay records nothing about it.

That is why the harness does not trust the delay for its evidence. `Watch-UntilCut` reads
the console continuously until the port disappears and keeps the LAST `about_to_` line the
board emitted, so each cut is attributed to the operation genuinely in flight when power
went away rather than to the one in flight when the prompt printed. Port disappearance is
the authoritative cut signal, and a cut whose port never vanishes is recorded MISSED rather
than counted. The per-cut evidence is therefore sound - every cut says truthfully which
step it landed on. What is not sound is any claim about coverage: the SET of steps hit is
whatever twenty human reactions happen to produce, and nothing makes it uniform, and
nothing makes it exhaustive.

Does it block 0.2.0? No. The gate is twenty-plus cuts with ledger read-back after each, and
Q43 ratified it in exactly that form with exactly this weakness named. This entry exists so
the weakness is not quietly forgotten between the ratification and the run. The obligation
it does carry is honesty in the milestone note: it must say SAMPLED, it must not claim
window coverage, and it should record the observed distribution of in-flight steps so a
reader can see which ones were actually hit rather than trusting that twenty cuts covered
the window.

Closing it: the Q43 relay rig in 0.3.0. A commanded cut at a programmed offset with
millisecond repeatability is what turns twenty samples into a sweep. Nothing available on
this bench closes it before then, and no amount of extra manual cuts substitutes - more
samples from the same distribution are still samples.

**Re-verified 2026-08-19.** Unchanged as a property of the method, and now it applies to three
completed modes rather than to a plan: `seal`, `pin` and `attempt` have all been run by hand at
the connector (K5). Sixty cuts from an uncontrolled distribution are still sixty samples.

### K5. Two power-cut modes remain: policy and overflow soak, both blocked on K16

**Found:** 2026-08-19, reading `docs/m4a-power-cut-evidence.md` back against the harness
output after the `pin` and `attempt` runs. The previous version of this entry said those two
modes had not been run. That is no longer true, and what replaced it is a different and
narrower problem.

The `seal` mode stands where it did: 20 valid cuts on board B on 2026-08-18, every one
landing inside a live seal, zero epoch changes, zero `next_seq` regressions, zero failed
remounts, 7,424 sequence units committed. That section of the evidence file is complete and
is the strongest storage evidence this project holds. What follows is about the other four
cases.

**What ran.** Board B took 20 valid cuts in `-Mode pin` and 20 in `-Mode attempt` on
2026-08-19, in the harness output directories `docs/m4a-power-cut-evidence.md` names. Read
back from those `cuts.csv` files:

- `pin` (a cut inside change-PIN): 20 of 20 cuts detected by port disappearance, no MISSED
  rows, no `harness-error` flags. Exactly one PIN opened the device after every single cut -
  19 of them the new PIN and 1 the old - so the answer was never `NEITHER` (a store that
  opens to nothing, the failure this mode exists to hunt) and never `BOTH` (an old-PIN
  ciphertext still live). Zero epoch changes. Slot 1's payload read back `ok=True` under
  whichever PIN opened, on every row.
- `attempt` (a cut mid-decrement of the attempt counter): 20 of 20 detected, zero flags,
  zero epoch changes. No regression of any kind: the 12 cuts that landed after the attempt
  had completed were all charged (`attempts_left` 15 to 14), and the 8 that landed in the
  uncounted stretch left the budget at 15 with the attempt uncompleted, which is the correct
  pair of behaviours and the one an attacker would want reversed. `next_seq` was static
  across all 20, which an unlock is supposed to leave.

On the substance those are clean runs of the two operations this entry named as the two with
the most steps to land between and the worst outcome if a cut lands badly.

**What is wrong is the record.** `docs/m4a-power-cut-evidence.md` carries one meta-reference to the `[FILL: ...]` pattern (in its intro text), not 57 unfilled sections as previously stated. The `pin` and `attempt` sections were filled in from the CSVs the harness produced. What remains open is the policy mode and overflow soak, both blocked on K16.
"a section that still holds `[FILL: ...]` markers is an unrun mode, not a passing one" - so by
its own construction the evidence record currently states that these modes did not run. A
gate is the record, not the memory of the bench: a reader in six months has the file and not
the session, and MILESTONES.md section 9 item 1 forbids an outstanding gate. Numbers held in
a CSV nobody has read into the document are not evidence anybody can check.

**What still cannot run at all, and why it is not bench time.** `-Mode policy` (the SET-POLICY
seven-step cut sequence) and the wipe-disabled 128-attempt overflow soak are both blocked on
the same firmware gap, not on the operator. Both need a device that can commit a policy;
nothing on this device can, because `Store` publishes no route to `Vault::set_policy` and
`firmware/src/main.rs:740` refuses `UiRequest::SetWipePolicy` for that reason (K16). The
harness behaves correctly about it - `-Mode policy` probes `help`, finds the console surface
absent and writes `BLOCKED.txt` without cutting anything, and
`tools/hil/attempt-overflow-gate.ps1` refuses to send a single wrong PIN unless the device
reports `wipe_after=0`, because on a wipe-enabled board that run would destroy every record
at attempt 15. So two of the five m4a cases are held open by a UI-and-store gap rather than
by a rig.

**Board A has still never been cut**, in any mode. It is unprovisioned by design
(`KeyProvenance::Emulated`), so its store path is not the one board B exercises, and the
gate's own wording is "on both boards". The evidence file offers exactly two acceptable
outcomes - re-run the gate there after provisioning it, or scope it out with the reason
written down - and records neither.

**Does it block 0.2.0? Yes.** Three things are outstanding and each would carry the verdict
on its own: an evidence record that says its own runs did not happen, two ratified cases that
no build of this firmware can perform, and a board the gate names that has never been cut.
MILESTONES.md section 9 item 1 settles it without needing this entry's opinion - no gate may
be outstanding and none may be waived.

**Closing it,** in the order the work actually goes:

1. Write the `pin` and `attempt` sections from the CSVs the harness already produced. This is
   the cheapest release-blocking item on the whole list and needs no hardware.
2. Give the console the `setpolicy`, `policysoak` and `min_pin_len` surfaces `-Mode policy`
   probes for, which is K16's fix seen from the bench side, then run that mode and the
   overflow soak.
3. Decide board A, in writing, and note that a scope-out has to say what the emulated-key path
   shares with the real-key path and what it does not. "No time" is a waiver and section 9
   item 1 does not permit one.

K4 still applies to every cut in every mode: the window is sampled, not swept, and more cuts
from the same distribution are still samples.

### K6. The Waveshare 4B cannot receive a PSBT in any enclosure this repository ships

**Found:** 2026-08-19, recorded in docs/BOARDS.md after the desk stand in `3dp/` was
actually printed and offered up to the board, rather than assumed from its listing.

0.2.0 is SD-only - the camera moved to 0.3.0 - so the microSD slot is the single ingress
path a PSBT has. The Waveshare 4B OEM white chassis exposes two USB-C ports and nothing
else; the slot sits behind the backing plate, unreachable as shipped. The printed desk
stand, `3dp/Makerworld-Screen-Stand-4inch+P4+Desk+Stand.3mf`, leaves it equally
unreachable. So the repository ships an enclosure asset that is incompatible with the only
ingress the release has: not a missing part, a present part pointing the wrong way.

The awkward part is that this runs opposite to the security ranking. The 4B is the better
airgap board - its C6 EN carries no pullup, so the radio is held down from power-on where
the Elecrow board has a window (K9) - it is the 4-bit SD host, and it is the only board
with the CSI connector 0.3.0 wants. The board that is right on every other axis is the one
whose 0.2.0 ingress is behind a plate.

Does it block 0.2.0? No, and "the firmware is fine" is not the whole of why. The release
artifact is a firmware image, and a 4B with the backing plate off signs perfectly - both
bench boards are bare, which is how this went unnoticed for so long. What it does block is
any sentence claiming a 4B in its OEM chassis is a usable signer, and this repository
comes close to making that sentence by shipping a stand for that board with no caveat. A
user who prints the stand, assembles it and only then discovers there is nowhere to insert
a card has been misled by an asset in this tree. That is a documentation defect fixable
today, and it is worth being blunt that it is ours rather than the vendor's.

Closing it: a replacement back plate cut from the vendor 2D drawing set
(`3dp/ESP32-P4-WIFI6-Touch-LCD-4B-2D.zip`, which exists in the repo precisely as the input
for one) that opens the slot. Until that exists, the honest interim is one line beside the
`3dp/` assets and in the release notes saying the 4B runs plate-off for 0.2.0. One more
gap is cheap to close and belongs with it: whether the Elecrow 5's slot is reachable in
its own chassis is still blank in BOARDS.md, and a blank in that column is how this was
missed the first time.

**Re-verified 2026-08-19.** Unchanged. `3dp/` still holds the desk stand and the vendor 2D
drawing set and no back plate. `docs/BOARDS.md:147` still reads "Elecrow CrowPanel 5inch:
accessibility not yet recorded here", so the blank that let this be missed on the first board
is still blank on the second.

### K7. A revealed recovery phrase stays on the glass and in two plaintext PSRAM buffers

**Found:** 2026-08-18, reading the display path against the reveal flow during the claims
audit. Not a bench failure - nothing misbehaved.

Every screen draws into a heap back buffer (`firmware/src/display.rs`, `Display::back`,
one `Vec<u16>` of width x height, in PSRAM via the spiram malloc pool) and `Display::flush`
hands the finished frame to `esp_lcd_panel_draw_bitmap`, which memcpys it into the
driver's own PSRAM scan-out framebuffer. That design is correct and it is what closed the
m3 flicker: the glass never shows a half-drawn frame. Its consequence is that the pixels
of the words exist twice, in plaintext, in external DRAM, and nothing takes them back. The
main loop repaints on input rather than on a timer - the zero-idle-repaint property the
heartbeat proves - so the frame stays exactly as drawn until somebody touches something.
The idle timer that would otherwise lock the device only reaches for a `Store`
(`firmware/src/main.rs`, `s.touch()` under `store.as_mut()`), and the stateless flow that
generates a phrase has no store, therefore no PIN, therefore no auto-lock at all. The
words stay lit until a touch or a power cut.

The sharp part is that the invariant which looks like it should catch this does not.
Invariant 2a's compile-time check (`crates/notyas-ui/src/screens/mod.rs`, `WipesOnDrop`)
names every secret-bearing FIELD of every screen and stops the crate compiling if one
becomes a plain `String`, so the mnemonic's characters are zeroized on drop. Its rendering
is not a field of anything. Zeroizing the string while leaving its picture in two buffers
satisfies the letter of "RAM copies are zeroized" and misses what an attacker would
actually read.

Does it block 0.2.0? No, and the argument has to survive the obvious objection that a
wallet displaying a seed phrase is doing its job. It is: the words exist to be written
down, a person is standing in front of the screen, and no PIN can exist on a stateless
device by construction, because the sealing key is derived from the PIN and with no PIN
there is no sealed store to gate. What is genuinely new is residency after the reading is
finished. A device left on the reveal screen shows the phrase to whoever walks past, and
the two buffers hold it after the user has stopped looking. PSRAM is not scrubbed by a
warm reset either, so the bytes survive into the next boot until the panel driver
allocates and clears its framebuffer - which only helps an attacker who can run their own
code on the board, and without Secure Boot they can (K8). Both ends of that pair are
already conceded: the threat model assumes a device you keep in your possession, and the
shipped text says plainly that an attacker who has held the device can flash a modified
image. So this is a disclosed limitation with a cheap mitigation, not a defect that stops
a release - and the mitigation should still land, because the user-visible half of it is
one screen affordance.

Closing it: an explicit dismissal on the reveal screen ("I have written these down")
instead of leaving the words up until an arbitrary touch, and a scrub in the same act -
clear the back buffer to the page background and flush once, so both copies are
overwritten where the string is already zeroized. Leaving the screen normally repaints
both buffers anyway, so the interval the dismissal closes is the one that matters. The
generalisable form is to extend the `WipesOnDrop` idea so a screen that declares itself
secret-bearing owes a scrub as well as a zeroize, which puts the rendering under the same
compile-time discipline as the field. Until then the handover note carries it in words:
power the device off when you have finished writing the phrase down.

**Re-verified 2026-08-19.** Unchanged. `crates/notyas-ui/src/screens/mnemonic.rs` still has no
dismissal region and no scrub: `revealed` is set to true and nothing sets it back. There is no
`scrub` anywhere in `firmware/src/display.rs`.

### K8. USB is a live JTAG and ROM-download surface, with no Secure Boot behind it

**Found:** 2026-08-18, from the device's own eFuse readout during the claims audit
(`firmware/src/readout.rs`, the `Download`, `Jtag` and `RomLog` groups, rendered on the
Verify screen through `firmware/src/verify.rs:141-152`). Read from silicon and rendered as
read, not inferred from a document.

The bits say what they say. `dis_pad_jtag`, `dis_usb_jtag` and `soft_dis_jtag` are
unburned, so USB-Serial-JTAG is a working debug port on the same connector that supplies
power. `dis_download_mode`, `dis_usb_serial_jtag_download_mode` and
`dis_usb_otg_download_mode` are unburned, so ROM download mode answers on that cable too.
With no Secure Boot v2 (stated absence N1) and no flash encryption (N3), the practical
sentence is: anyone who holds the device for a few minutes with a USB cable can read the
flash out and write different firmware in, and nothing on the device notices or refuses.

Does it block 0.2.0? No, and this is the clearest case in the set of a ratified decision
rather than a defect. Q32 and Q63 decided that 0.2.0 ships without Secure Boot v2 and
without flash encryption, with the single eFuse burn being the HMAC_UP key, and everything
above follows from that decision arithmetically rather than from anything anybody built
wrong. The release gate asks whether the artifact contradicts what the project claims
about it. It does not: the shipped SECURITY.md text states N1 in the negative and in the
open, the flash-not-encrypted line says the PIN ladder is the whole of the protection, and
the Verify screen reads these very bits live instead of asserting a posture. A disclosed
absence that the device itself reports honestly is a limitation to publish, not a defect
to fix.

It is here rather than left in the accepted-risk list because it changes how two other
entries read. It is what turns K7's PSRAM residency from a theoretical read into a
reachable one, and it is why the HIL console's absence has to be proven against the linked
ELF rather than promised by a build flag (K10). It also bounds every readout claim:
without Secure Boot, nothing on the device checks the firmware doing the reading, so the
eFuse bits above are exactly as trustworthy as the image that printed them and no more.

Closing it: not in 0.2.0, and not in firmware at all. It needs Secure Boot v2 with a key
this project can custody and rotate, flash encryption, and only then the JTAG and
download-mode disables burned in the same provisioning pass. The order is the whole of it,
and it is why these cannot be picked off individually: burning the JTAG disables alone
leaves ROM download mode answering on the same cable, so the flash stays readable and
writable and the only thing lost is the owner's bench. Every one of these burns is
one-way. Scheduled with the 0.3.x provisioning work, where the key-custody question (Q30)
has to be answered first, because a secure-boot key that cannot be rotated is worse than
none.

**Re-verified 2026-08-19.** Unchanged, and it is a ratified decision rather than a defect, so
re-verification here means only that the decision has not been quietly reversed: no eFuse burn
beyond HMAC_UP is performed or planned for 0.2.0.

### K9. The Elecrow 5's radio co-processor runs Wi-Fi STA and BT at every power-up

**Found:** 2026-08-17, traced on the schematic and confirmed against the factory
sdkconfig; re-checked in the 2026-08-18 claims audit, which is where the airgap wording
was corrected to match it.

C6 EN carries a 10K pullup (R77) to an always-on 3V3 rail. The P4 drives the kill line
(GPIO20 through R95) low as the first thing `app_main` does and never releases it - but
ROM and the second-stage bootloader run before `app_main`, so for the order of hundreds of
milliseconds at every power-up the C6 is out of reset running its factory esp-hosted slave
firmware, which brings up the Wi-Fi station interface and the BT controller. The Waveshare
4B has no such window: its C6 EN sheet carries a 1 uF cap to GND and no pullup, so that
radio is held down from power-on and could only run if the P4 drove the line high, which
this firmware never does.

What the window is, stated at both ends so neither exaggeration survives: the slave
firmware idles waiting for an SDIO host and joins no network on its own, the P4 image
contains no driver capable of talking to it (`esp_hosted` and `esp_wifi_remote` are absent
from the pinned component list and banned lockfile-wide by `tools/build-graph-check.sh`),
and the SDIO pins are never configured. The radios are powered and initialised, not
associated and not carrying anything of ours. That is a smaller thing than "the device has
Wi-Fi" and a larger thing than "no radio", and the second phrasing was in the documents
until the audit removed it.

Does it block 0.2.0? No, and the argument is about which claim is under test. Invariant 1
says no radio; on this board that is true from `app_main` onward and false for the few
hundred milliseconds before it. Firmware cannot close the gap, because the code that would
close it has not started running yet, so no change to this release can alter the fact. The
real choice is between disclosing the board and dropping it, and it is disclosed: at every
boot in the log (`firmware/src/board/elecrow_5.rs:83-86`), in SECURITY.md's accepted
risks, in BOARDS.md, and now here. A radio that is powered but unassociated for a fraction
of a second during a boot the owner is watching, on a device holding no key material until
the user types some in, is a risk a reader can weigh for themselves. An undocumented one
would not be.

What it does bind is the language: nothing in this release may say this board has no radio
without the window in the same sentence. Note also what the pair of boards honestly looks
like now - one has a documented radio window, the other has a card slot behind a plate
(K6) - and 0.2.0 ships both facts stated rather than a preference implied by silence.

Closing it: hardware, per unit, and it is the recommended prep for a production Elecrow
unit rather than a firmware change - remove the EN pullup, or remove the C6 module
outright, which turns the window into the Waveshare's held-down-from-power-on behaviour.
One physical precondition on this board stays open regardless and cannot be closed in
software: the LoRa/nRF24/Zigbee socket (J9/J11) must be empty, firmware never initialises
those pins, and per the no-probing rule it does not try to detect a module.

**Re-verified 2026-08-19.** Unchanged, in the code and in the wording.
`firmware/src/board/elecrow_5.rs` still logs the window at every boot, and no document in this
release says either board has no radio without the window in the same sentence.

### K10. The HIL console formats, seals, erases and signs with no PIN, and only the build fences it

**Found:** 2026-08-18, reading `firmware/src/hil.rs` against the release-symbol gate while
the artifact-tier gates were being assembled.

The dispatcher reaches `format`, `erase`, `seal`, `wipe`, `changepin`, `soak` and, since
0.2.0's release-loop additions, `register`, `address`, `psbtload`, `psbtinspect` and
`psbtsign` from a bare line on UART0 (`firmware/src/hil.rs:335-365`). `unlock` takes a PIN
because the store's key ladder needs one; nothing else asks for one, and `psbtsign` produces
a real signature from the wallet in memory on request. An image with this console compiled in
is a signer that signs on command over a serial port with no authentication at all. That is
deliberate - m4a's exit gate cannot be evidenced any other way, and neither could clause 2
(`docs/clause2-evidence.md`) - and the console is careful in the other direction: its stated
invariant is that it prints what the operator supplied and what is public, never a derived
key, seed, session secret or xprv.

Three fences, deliberately of three kinds. `firmware/build.rs` refuses the feature in an image
built without debug assertions, which stops the artifact existing at all. `hil.rs` carries the
same rule as a `compile_error!` under `cfg(not(debug_assertions))`, which holds even if the
build script is skipped, stubbed or wired to succeed.
`tools/ci/check-release-symbols.sh` reads the linked ELF with `nm`, and it is the only one of
the three whose subject is the file somebody downloads. The first two are promises about a
build; the third is a finding about an image.

**Does it block 0.2.0? No,** and the wiring complaint this entry used to carry is now stale.
**Re-verified 2026-08-19:** `tools/release.sh` runs `check-release-symbols.sh --image` per
board ELF (`release.sh:647`) and `check-airgap.sh --image` beside it (`release.sh:624`), and
it will not accept either until `tools/ci/selftest-release-symbols.sh` has demonstrated that
the checker REJECTS an image that does carry the console - the stage dies with "a clean report
from tools/ci/check-release-symbols.sh proves nothing" otherwise (`release.sh:585-607`). That
selftest is the part worth naming: a gate that has only ever been run against images it
passes is a gate nobody has proven can fail. `docs/RELEASE-0.2.0.md` section G lists the check
per board. CI still does not invoke it, and that is now a stated scope rather than an
oversight: `.github/workflows/ci.yml:16-20` says in its own header that nothing about a LINKED
IMAGE can run there and names this script and the image tier of `check-airgap.sh` as the two
things it therefore does not verify. The gate is wired where its subject exists.

Two residuals stand, and the second grew today. `nm` sees symbols, so a clean run proves that
no symbol of the console survived the link, not that no inlined instruction did, which is
exactly why it does not retire `build.rs`'s refusal. And the bench discipline is now sharper
than it was: a debug image carrying this console, flashed to a board holding a wallet with
money on it, is a remote-controlled signer on a cable, and as of 2026-08-19 the product path
signs too - so the difference between a bench board and an owner's board is no longer visible
from the outside of the case. Every board on this bench is a provisioned test unit, and that
is the only reason this reads as a footnote rather than as an incident.

Closing it: write the discipline where the person flashing will meet it - a board that has
ever held a real wallet does not run a `hil-console` image - and keep the three fences and the
selftest exactly as they are. `docs/PROVISIONING.md` is the file that meets that person, and
it is outside this pass's remit, so the edit is handed over rather than applied.

### K14. A refused save is still silent, and a shipped device can now genuinely refuse

**Found:** 2026-08-19, same pass as K13, following the create flow to its end. Rewritten the
same day: one half of it was fixed and the other half got worse.

**The half that is fixed.** S-19 Keep-or-save no longer offers a save on a device that cannot
perform one. `ForkState::activate` now matches
`RegionId::SaveToDevice if !env.lock.status.has_pin() && self.report.is_some()` and pushes
`State::SetPin` (`crates/notyas-ui/src/screens/fork.rs:255-257`), and the card's own copy
changes with the status - `SAVE_CARD_NEW_PIN` instead of `SAVE_CARD` when there is no PIN
(`fork.rs:216`). So the first save is where the first PIN is set, which is what
`PIN-MODES.md` asks for in as many words, and the dead-end this entry described is gone.

**The half that is not, and is now live.** `Ui::persist_result`
(`crates/notyas-ui/src/ui.rs:525`) still begins `if !sealed { return; }` - the failure verdict
is discarded. `NameState` still has no failure installer and no error state; a grep of
`crates/notyas-ui/src/screens/name.rs` for a refusal path finds only the keyboard's character
filter. The screen redraws identically and the only record is a `log::error!` on a UART nobody
is watching.

What changed is that the refusals are now reachable. `answer_persist_wallet`
(`firmware/src/main.rs:859`) reports `false` for a full device, a slot that filled underneath
the flow, a record too large for a slot, a fingerprint that will not parse, and a session that
expired mid-flow - and its own comment lists them. Before 2026-08-19 only the last could fire,
on a device where the whole flow was unreachable anyway (K13). Now a shipped image can format
the store, fill its eight slots, and answer a user's ninth save with nothing at all.

The comment above `persist_result` says a failure "leaves the naming screen exactly as it was,
so a retry does not cost the user their typing". That is a correct description of a retry
affordance and an incorrect one of a verdict channel: the screen it leaves untouched never
told the user there was anything to retry.

This is the worst-shaped defect in this file, because the reasonable reading of a save button
that produces no error is that the wallet was saved. A user who believes an eighth wallet is
on the device and has stopped keeping the paper backup is the concrete loss.

**Does it block 0.2.0? Yes.** The argument no longer leans on K13: it is a silent failure on a
control a shipped device reaches, at the moment the device is being trusted with a seed.

Closing it: give `NameState` a failure state and render it, so `persist_result(false)` has
somewhere to land, and delete the early return. The gating half is done and needs nothing
further. The pattern to copy is the one this UI already keeps elsewhere - the capacity
treatment at `crates/notyas-ui/src/screens/wallets.rs`, where an unavailable control is drawn
`Disabled` with its reason beside it.

### K15. Delete wallet takes a two-stage typed-name consent and then does nothing

**Found:** 2026-08-19, same pass.

The wallet home draws `Delete this wallet` (`crates/notyas-ui/src/screens/wallet.rs`) and
gates it behind the full C4d sequence: a consequence sheet, then a sheet that requires the
wallet's name typed in full. Consent complete, it navigates to the wallet list and raises
`UiRequest::DeleteWallet(slot)`.

The firmware arm (`firmware/src/main.rs:725-738`) refuses. `Store` publishes no route to
`Vault::clear`, so nothing is erased, and the arm re-installs the wallet list rather than
writing an empty record - which is the right call, since a blank record would read as occupied
and decode as nothing. The refusal reaches a `log::error!` and nowhere else. What the user
sees is the wallet they just typed the name of, still in the list.

The arm's own comment argues that the surviving wallet "is the evidence either way - the user
watches the wallet survive instead of being told it is gone". That is true and it is not
sufficient: a user who tapped Delete, read two sheets and typed a name has been given no
statement about why the device disagreed with them, and the unchanged list is equally
consistent with a redraw that has not happened yet.

This is the one destructive control whose refusal is safe. It is recorded because it is drawn,
fully consented and inert - not because anything is lost.

**Does it block 0.2.0? It did, as of 2026-08-19,** and by this entry's own previously stated
rule rather than by a new opinion: it said "it blocks any release in which the store is
reachable", and the store became reachable when the PIN-create screen landed (K13, now
closed). A shipped unit walked a user through the heaviest consent grade this design has and
then ignored the answer.

**Closed 2026-08-19.** The erase route was built exactly as this entry prescribed, plus the
step the owner asked for on hardware:

- `Store::clear_payload` publishes the route to `Vault::clear`. The refusal's reasoning about
  never writing an empty record is unchanged and unnecessary: under `Occupancy::AlwaysFilled`
  `clear` writes device FILLER sealed under the key ladder's filler root, and `slot_state`
  tries that root first and answers `Empty`, so no wallet-record encoder is involved and no
  half-record exists at any instant.
- `firmware/src/wallet/erase.rs` owns the order - registrations before the record, so a power
  cut can never leave a registry record naming a slot that has been freed - and READS THE SLOT
  BACK before anything may be called a delete. Its four outcomes are what the screens render.
- `Op::Clear` in the power-loss fuzzer now runs over a slot holding a real record rather than
  over filler, and is in the default subset as well as the exit gate: 27,921 cases over the
  shipped geometry and 50,037 over the full corpus, 0 findings.
- S-47b (`crates/notyas-ui/src/screens/erase.rs`) stands between the typed-name sheet and the
  write: it announces what is written before it happens, and offers the recovery words one
  last time through S-13's reveal gate.
- Every ending reaches the user. `Ui::wallet_deleted` carries `Gone`, `Refused` or `Damaged`,
  and the wallet list draws the sentence in a band - success ink for a completed delete,
  danger ink for anything else.

### K16. The touch UI cannot commit policy/PIN mutations; the HIL console now can

**Found:** 2026-08-19, same pass. Re-verified and re-scoped the same day.

Three of the four sealed-store mutations are refused in every build of the image, each for a
stated reason at the site (`firmware/src/main.rs:740-790`):

- `SetWipePolicy` - committing a policy is `Vault::set_policy`, which takes the PIN because
  the policy is authenticated inside the AEAD and the commit is a re-seal. The request carries
  a threshold and no PIN. **Reported**: the arm calls `ui.policy_result(false)` and re-installs
  the policy still in force, and the policy screen renders the verdict.
- `ChangePin` - `Store::change_pin` exists and re-seals every record correctly; it needs a new
  PIN. **Not reported**: `UiRequest` documents no failure channel for this request, so the
  refusal is a log line and the screens are re-fed the state they already had. The user taps
  the row and nothing happens.
- `RemovePin` - `Vault::remove_pin` destroys every sealed record and needs a fresh PIN
  confirmation for the same reason. **Reported**: `ui.pin_removed(false)` is a failure line
  the settings screen renders.

**What changed on 2026-08-19 is the reason behind `ChangePin`, not the behaviour.** A
PIN-collection screen now exists - S-06/S-07, `crates/notyas-ui/src/screens/setpin.rs` - but
it is deliberately reachable only where `StoreStatus::has_pin` is false, and the surface a
provisioned device has is PIN ENTRY, which raises `UnsealWallet`. The arm's own comment now
says exactly this. The gating is correct and should stay: a change-PIN re-keys every stored
wallet, and half of that operation must not be startable. So the row is still a control that
leads nowhere without saying so, and the wipe-policy editor is still a live editor over a
value that can be read and never written.

**Does it block 0.2.0? Yes,** on two independent grounds, and the second is the one that got
missed while K13 was open.

First, the silent half, by the same rule K15 turns on: this entry already said the silent
refusal "must not survive a release in which the store is reachable", and the store became
reachable when the PIN-create screen landed. `PIN-MODES.md` requires the wipe-off sheet to
offer change-PIN as a PATH, and that path now leads nowhere on a device a stranger owns.

Second, and larger: **this firmware gap is what holds two ratified hardware gates open.**
`-Mode policy` (the SET-POLICY seven-step cut sequence) and the wipe-disabled 128-attempt
overflow soak both require a device that can commit a policy, and neither can run until one
exists (K5). That makes this a blocker on the m4a exit gate and not only a UI defect, which is
a heavier verdict than the entry carried when it was written.

Closing it: the two policy operations need `Store` to publish routes to `Vault::set_policy`
and `Vault::remove_pin` that take a freshly confirmed PIN - which is the S-06/S-07 screen
again, invoked in a second place with a different precondition. `ChangePin` needs a failure
channel on `Ui` before it needs anything else, because a refusal a user cannot see is worse
than a control that is absent. And the console needs the `setpolicy`, `policysoak` and
`min_pin_len` surfaces `tools/hil/power-cut-gate.ps1 -Mode policy` probes for, or K5's two
blocked cases stay blocked however the UI is fixed.

### K20. The session auto-locks after 120 seconds with no warning, no countdown and no setting

**Found:** 2026-08-19, same pass. Verdict and consequences updated the same day, after the
store became reachable and the signing path landed.

`AUTO_LOCK_MS` is 120,000 (`firmware/src/store/mod.rs`, restating
`notyas_wallet::DEFAULT_AUTO_LOCK_MS`). The main loop ages the session from the wall clock and
any touch restarts the timer (`firmware/src/main.rs:372-381`), which is the right mechanism: a
pass that spent 1.8 s inside a derivation ages the session by 1.8 s.

What is missing is every part the user sees. **Re-verified 2026-08-19:**
`Store::idle_remaining_ms` is documented "for the UI" and `grep -rn idle_remaining_ms firmware
crates` still returns exactly one line, its own definition - no caller anywhere in the tree.
`LockInfo` carries no remaining-time field, no screen renders one, and the settings row
catalogue is still `[Row::Network, Row::WipePolicy, Row::VerifyDevice]`
(`crates/notyas-ui/src/screens/settings.rs:134`) with no timeout row. `UX-SCREENS.md` lists
S-49 Auto-lock warning in its screen table; nothing implements it. When the timer expires the
screen stack is cleared and the device is on the lock screen, with no preceding warning frame
and no explanation on arrival.

**Two things changed today and both make it sharper.** A shipped device now opens sessions, so
this is behaviour a stranger meets rather than a defect behind an unreachable door. And the
auto-lock now takes more with it than a screen stack: `firmware/src/main.rs:381` calls
`close_flow(&mut flow, "the session timed out")`, which drops the open wallet, the loaded PSBT,
the review and any signed bytes. That is the correct thing for it to do - an auto-lock that
left a wallet open would leave a live seed and a signed transaction behind a lock screen - but
it means a user who is 100 seconds into a paged transaction review - checking a destination
address character by character is exactly the task S-30..S-36 exist for - loses the review
silently, with no warning frame and no way to ask for more time. Two minutes
was already short for reading an eight-slot wallet list or comparing a fingerprint against a
coordinator; it is shorter than the task the device now exists to perform.

**Does it block 0.2.0?** No, and the direction is why: nothing is lost that cannot be redone,
the failure is toward locking rather than away from it, and a signed transaction is never left
behind. But the argument that used to carry this verdict - that no shipped device opens a
session - is gone, and the entry should not be read as unchanged.

Closing it: a warning frame at a fixed remaining time, fed by the accessor that already exists,
and a timeout row in the settings catalogue. The timeout is per-session runtime state rather
than sealed policy, so a row for it re-seals nothing and does not need the PIN - which also
means it is the one settings row that can be made to work without K16.

### K21. The ratified simple-mode dice door is written and unwired

**Found:** 2026-08-19, same pass.

`crates/notyas-ui/src/screens/door.rs` implements `docs/plan-0.2.0/SIMPLE-MODE.md`: the pre-PIN
card on S-03 that pushes the dice flow, plus the whole two-column S-03 rearrangement the card
forced, with its own fit tests at both geometries. It is complete, it is correct about its
invariants - it records nothing, opens no store and raises no `UiRequest` - and it is dead.
`crates/notyas-ui/src/screens/mod.rs:120` declares the module; grep for `door::` across
`crates/`, `firmware/` and `tools/` returns no call site. The file carries
`#![allow(dead_code)]` with a comment naming the call sites that have not landed: `lock.rs`'s
`layout`, `regions` and `draw`.

The user-visible consequence is the one the design document predicted: on a device with a
stored wallet, the dice-only flow sits behind a PIN even though nothing on it reads the store,
writes it, or derives anything from the PIN. That was a hypothetical state when this was
written, because K13 meant no shipped device could hold a wallet. It is a real one now.

**Does it block 0.2.0?** No.

Closing it: three call sites in `crates/notyas-ui/src/screens/lock.rs`, and remove the
module-level `allow(dead_code)`.

**Re-verified 2026-08-19, and it is still an orphan.** `grep -rn 'door::' crates firmware
tools` returns nothing; `crates/notyas-ui/src/screens/mod.rs:128` declares the module and no
other file names it; `#![allow(dead_code)]` is still at `door.rs:45`; and
`crates/notyas-ui/src/screens/lock.rs` contains no occurrence of the string `door`. It is the
only module in the workspace in this state - every other `allow(dead_code)` in
`crates/notyas-ui/` is on a single item or is `cfg_attr(not(test), ...)`. What HAS changed is
the cost of leaving it: a shipped device can now hold a wallet (K13, closed), so the state the
door was written for - a PIN standing in front of a dice flow that reads no store - is now a
state a real user reaches. The entry stays open and the verdict does not change.

### K22. The Verify screen's reserved-space scan has no reader in this build

**Found:** 2026-08-19, same pass.

`VERIFY.md` 3.3's raw read of every must-be-blank flash span is offered on S-46 as a `Scan`
button, and the button is offered unconditionally
(`crates/notyas-ui/src/screens/verify.rs:751-768`). The firmware arm
(`firmware/src/main.rs:553-565`) logs a warning and answers `ReservedSpace::NotRead`. The screen
leaves its Busy frame and the row reads `not read`.

The copy is honest - `NotRead` is a different statement from `NotScanned` and from a scan that
found nothing, and the arm's comment is explicit that "it looked and found nothing" would be a
sentence this device has not earned. What is not honest by itself is a button that can never
produce any other answer: the reason belongs beside the control, not only in a source comment.

**Does it block 0.2.0?** No. It is reachable on a shipped image - S-46 is reachable from Home -
so unlike most of this group it is a defect a stranger will actually meet.

Closing it: implement the raw span read that `firmware/src/readout.rs` scopes, or state beside
the row that this build cannot perform the scan and draw the button `Disabled` with that
reason, which is the rule the rest of the UI keeps.

**Re-verified 2026-08-19.** Unchanged. `firmware/src/main.rs:695-707` still logs a warning and
answers `ReservedSpace::NotRead`, and the `Scan` button is still offered unconditionally. This
remains the defect on this list most likely to be met by a stranger, because S-46 is reachable
from Home with no PIN.

### K23. C4 specifies four confirmation grades and the component implements three

**Found:** 2026-08-19, implementation-readiness pass over the ratified screen spec
(`docs/plan-0.2.0/UX-SCREENS.md` C4).

C4 names four grades and chooses between them by consequence: **C4a** yellow card for the
reversible (overwriting a file on the card, discarding entered rolls, leaving a review),
**C4b** red card for the destructive but recoverable from backup, **C4c** hold-to-confirm
for the irreversible in effect, **C4d** typed-name for the unrecoverable on this device.
`crates/notyas-ui/src/danger.rs` has three: `DangerGrade::{Confirm, Hold, Typed}`, and its
own constructors name them C4b, C4c and C4d - `Danger::confirm` is documented "C4b:
destructive, recoverable from the backup the consequence names". C4a has no variant.

The consequence is not a missing feature, it is a wrong one. Every C4a site in the tree is
built with `Danger::confirm`, and `Danger::draw` paints one grammar for all three grades:
the header band is `DANGER_TINT` inside a `DANGER` frame and the confirm button is
`ButtonKind::Danger`, unconditionally. So a reversible confirmation wears the card the
spec reserves for destruction. The two live examples are the deliver screen's overwrite
sheet (`screens/deliver.rs::overwrite_sheet`, which UX-SCREENS S-38 names in as many words
as a "C4a overwrite confirm") and the review's leave sheet
(`screens/review.rs::leave_sheet`, "Leave this review?", which destroys nothing at all and
which C4a lists by name as one of its three examples).

C4's whole argument is that a user learns to read the grade. A red card on a reversible
action spends that vocabulary on nothing, and the screen where it is spent is the one the
user has been trained to click through - which makes the next red card, the one that
matters, cheaper to dismiss.

**Does it block 0.2.0?** No, and the direction matters: the error is more friction than
specified, never less. No grade renders WEAKER than C4 asks for, and every sheet that
reaches a user today is genuinely at C4b or above by consequence, so nothing destructive is
under-guarded.

Closing it is a decision and not a patch, and this entry deliberately does not make it. One
of two: give C4a its own variant in `danger.rs` - a `WARNING` frame and a non-`Danger`
confirm button, everything else shared - and point the reversible sites at it; or amend
UX-SCREENS C4 to three grades and re-classify the C4a sites as C4b with the reasoning
written down. No fourth variant has been invented on the strength of this entry. Whichever
is chosen, `overwrite_sheet` and `leave_sheet` are the two call sites to re-check, and
S-38's "C4a overwrite confirm" line has to end up agreeing with whatever `danger.rs` draws.

**Re-verified 2026-08-19.** Unchanged, and the specification now agrees that it is unchanged:
`docs/plan-0.2.0/UX-SCREENS.md` C4 carries an "Implementation gap, noted 2026-08-19" paragraph
pointing back at this entry. `crates/notyas-ui/src/danger.rs` still has three variants. The two
named call sites are still `Danger::confirm` (`screens/deliver.rs:249,261` and
`screens/review.rs:716`), and the decision this entry declines to make has still not been made.

### K24. Nothing on the product path has ever run on hardware

**Found:** 2026-08-19, looking for the read-back that K13 named as its own closing condition
and finding that it does not exist - then finding that the same is true of every other step of
the loop the release bar names.

Everything that landed on 2026-08-19 is code and host tests.
`crates/notyas-ui/src/screens/setpin.rs` (1,094 lines), `sdcard.rs` (2,148), `review.rs`
(2,407), `deliver.rs` (950), `multisig.rs` (3,617) and `firmware/src/flow/` (1,788) are new or
newly wired, and the host suites are green:
`cargo test -p notyas-core -p notyas-ui -p notyas-wallet -p psbtgen` passes 976 tests on
2026-08-19, clippy is clean, and the graphics gate is 6 of 6. **None of it has been executed on
a board.**

What that means step by step, against MILESTONES.md section 9 clause 2:

- **No device has set a PIN from the touch UI.** K13 closed on code, and K13's own text says
  "this entry closes on that read-back, not when `SetPin` compiles - a store that formats but
  whose records do not survive a power cycle is the failure mode this milestone has already had
  once." The read-back has not been performed. The `format` evidence in
  `docs/clause2-evidence.md` is a `hil-console` `format <pin>` command, which is a different
  call site reaching the same `Store::format`.
- **No device has saved, power-cycled and re-opened a wallet from the touch UI.**
- **No device has read or written a microSD card in any build.** `firmware/src/sd/` is wired to
  the product path now, and the only PSBT ingress ever exercised on silicon is a hex string on
  a serial console (K28).
- **No device has reviewed or signed a transaction from the touch UI.** The one hardware
  signature in the record came from `psbtsign` on the console.
- **No device has registered a multisig from the touch UI**, and no device has signed the
  2-of-3 that clause 2 names, on any interface.

The only end-to-end hardware evidence this project holds is `docs/clause2-evidence.md`, and
every step of it was driven over the `hil-console` serial interface on an image that the
release artifact provably is not - which is exactly what `check-release-symbols.sh` and
`check-hil-fence.sh` passing means. That run is real and it is evidence about the engine. It is
not evidence about the product, and the two are now different code paths that meet only at
`Store::format`, `signing::review`, `Review::sign` and `sd::deliver`.

**Does it block 0.2.0? Yes,** and it is the entry most likely to be argued with, so the
argument is worth stating. Clause 2 is not "the loop is implemented"; it is "a working wallet
does the whole loop on real hardware", and it is the one clause that can fail the release on
its own. A device whose signing path has only ever run against a host renderer has an untested
display driver, an untested touch layer, an untested SD host, an untested PSRAM allocation
under a 2,400-line screen, and an untested interaction between all of those and a 120-second
auto-lock that drops the review (K20). Every one of those is a class of failure the host suites
cannot see by construction.

Closing it: one full pass on each board with a release-shaped image - set a PIN, save a wallet,
power cycle, unlock, read the wallet back, register the 2-of-3, verify the address, load a PSBT
off a card, review it, hold to sign, write the signed file back, and hand it to Bitcoin Core -
recorded the way `docs/m4a-power-cut-evidence.md` records a gate rather than as a session
memory. `tools/hil/end-to-end-loop.ps1` exists and drives the console, so it evidences the
wrong path; the product pass is a human with a card and a camera. Until then, no release-facing
document may say 0.2.0 signs on hardware without naming this entry in the same paragraph.

### K25. The external cross-check against Bitcoin Core and embit has never run

**Found:** 2026-08-19, reading `out/xverify/attestation.json` while checking what in
`docs/clause2-evidence.md` is genuinely independent of this tree.

`tools/xverify/` exists to put Bitcoin Core and embit on the other side of every derivation,
address and signature this tree produces - 21 cases, 9 of them negative - and
`tools/ci/check-xverify.sh --require` is release gate B12 in `docs/RELEASE-0.2.0.md` section 2,
described there as "the one bar nothing inside this tree can answer". It has never produced a
pass. The attestation file records the whole of the current state:

    "status": "skipped", "verified": false, "cases_verified": 0, "cases_expected": 21,
    "harness_exit_code": 3, "conclusion": "NOT VERIFIED - the cross-check could not run"

with `missing` naming all three prerequisites: no `bitcoind`, no `bitcoin-cli`, and a Python
3.12.5 interpreter that cannot `import embit`. The gate's behaviour is exactly right - it
refuses to report a pass it did not earn, and `check-xverify.sh` was written specifically so
that 0 cases verified cannot read as 0 failures - so this entry is not a defect in the harness.

What it means for the release is that the external evidence this project holds is one manual
`analyzepsbt` and `finalizepsbt` invocation of Bitcoin Core 29.4, against one single-sig PSBT,
recorded in `docs/clause2-evidence.md`. That is genuine and it is one file. Nothing external
has ever checked an address this device derives, a descriptor checksum it computes, a taproot
signature, a multisig signature, or any of the nine negative cases. The other cross-check in
that document, `tools/psbtgen`, is in-tree and links `notyas-core`, so it is a self-consistency
check rather than an independent opinion - which is now stated there in as many words.

**Does it block 0.2.0? Yes.** MILESTONES.md section 9 item 1 permits no outstanding gate and no
waived one, B12 is a gate, and `docs/RELEASE-0.2.0.md` describes it as answering the one
question the tree cannot answer about itself. A signer whose address derivation has never been
checked by a second implementation is the specific failure that costs a user their coins
silently: wrong addresses do not throw, they just cannot be spent from.

Closing it: install Bitcoin Core 29.4 at the pinned digest and `pip install embit` into the
interpreter `NOTYAS_XVERIFY_PYTHON` points at, then run `check-xverify.sh --require` and keep
`out/xverify/attestation.json` with the release artifacts. The harness binds its attestation to
a tree digest, so the run has to happen at the commit that ships. This is installation work
rather than engineering work, which is an argument for doing it rather than deferring it.

### K26. The release-facing documents still describe the product as it was before 2026-08-19

**Found:** 2026-08-19, cross-checking this file's own entries against the documents that cite
them, after K13, K17, K18 and K19 were retired.

`docs/RELEASE-0.2.0.md` section 0 is the section a stranger reads first, and it says a 0.2.0
unit cannot sign a transaction (citing K17), cannot read or write a microSD card (K18), cannot
set a PIN and therefore cannot store anything (K13), and cannot register a multisig wallet
(K19). All four of those sentences were true when they were written and none of them is true
now. Section 6 and section 4 carry the same claims in shorter form, at `RELEASE-0.2.0.md:302`,
`:497` and `:533-545`. `docs/claims-audit-0.2.0.md` section 6 and its findings table carry them
at `:569`, `:578`, `:614` and `:629-635`. `docs/release-readiness-0.2.0.md` section 5 states
"zero of the six wallet-operation steps are drivable from the device UI" and "zero occurrences
of psbt in all of crates/notyas-ui/src", both of which the tree now contradicts. `README.md`
was already recorded as wrong in the other direction, telling a reader the device does not
store a seed or touch a PSBT.

So the repository currently ships two mutually exclusive accounts of what it is, and the one a
buyer reads first is the wrong one. That is a worse failure than either being out of date on
its own: a reader who checks two documents and finds them disagreeing cannot tell which to
trust, and the honest-limitations posture the whole document set is built on is exactly what
gets spent.

**Does it block 0.2.0? Yes.** Release notes that misdescribe the artifact are a release defect
by the same rule that makes K11's interop regression a disclosable one: the gate asks whether
the artifact contradicts what the project claims about it, and here the claims contradict each
other before the artifact is even consulted. `tools/ci/check-ratified.sh` passed on 2026-08-19 with
34 assertions and 0 violations, which is worth noting precisely because it did not catch this -
the gate checks ratified decisions, not currency, so nothing automated is watching for a
document that has fallen behind the tree.

Closing it: one editing pass over `docs/RELEASE-0.2.0.md` sections 0, 4 and 6,
`docs/claims-audit-0.2.0.md` section 6, `docs/release-readiness-0.2.0.md` section 5 and
`README.md`, rewriting each against the tree rather than against this file - and every rewritten
sentence has to distinguish "the product path can do this" from "a board has been observed
doing this", because as of today those are different claims for every step of the loop (K24).
Those files are outside this pass's remit, so the finding is recorded rather than applied.

### K27. The airgapped transport codecs are complete, compiled, and reached by nothing

**Found:** 2026-08-19. This is the remainder of K18 after the microSD half of that entry closed;
it is filed separately because closing K18 did not touch it and because a reader looking for the
QR path should not have to find it inside a retired entry.

`crates/notyas-wallet/src/transport/` carries `ur.rs`, `bbqr.rs`, `bytewords.rs`, `fountain.rs`,
`playback.rs` and `checksum.rs`. `grep -rn 'transport::' firmware/src crates/notyas-ui/src`
returns nothing: no firmware file and no UI file references any of it. The code is finished and
host-tested and no build of this device can reach it.

Unlike the SD subsystem this is not an unwired path to a shipped feature - it is a path to a
feature 0.2.0 does not have. 0.2.0 is SD-only by decision and the camera moved to 0.3.0, so
animated-QR ingress has nowhere to arrive from, and QR EGRESS of a signed transaction is a real
0.2.0-shaped use that no screen offers. The device does render QR codes, for xpubs and
addresses, through a different path (`UiRequest::Qr`).

**Does it block 0.2.0? No.** Nothing claims it. `docs/RELEASE-0.2.0.md` section 4 lists what is
not shipped and the release notes should name the QR transport there if they do not already, so
that a reader who finds `bbqr.rs` in the tree is not left inferring a feature from a filename.

Closing it: 0.3.0's camera work consumes the ingress half. The egress half - offering a signed
PSBT as an animated QR beside the SD write on S-38 - is a smaller piece and could land
first, and the decision about whether it belongs in 0.2.x is the owner's rather than this
entry's.

### K28. The HIL console cannot read a PSBT off a card

**Found:** 2026-08-19, tracing why `docs/clause2-evidence.md` loaded its PSBT as console hex
rather than from the microSD slot the release is built around.

`psbtload sd <path>` is advertised in the console's own help (`firmware/src/hil.rs:504`) and its
implementation is a stub that refuses:

    fn read_sd_file(path: &str) -> Result<Vec<u8>, String> {
        Err("sd_unsupported_in_this_build_no_firmware_src_sd_module_at_compile_time".to_string())
    }

at `firmware/src/hil.rs:1897-1899`. The error string was accurate when it was written and is not
any more: `firmware/src/sd/` compiles into every build and is now on the product path through
`firmware/src/flow/`. The comment above the stub already says the fix is "one call in
`read_sd_file`".

Three consequences, and the third is why this is worth an entry rather than a footnote. The
console advertises a command that cannot work, which is the same defect shape as K22 one layer
down. The only PSBT ingress ever exercised on hardware, in any build, is a hex string typed over
a serial port. And the bench therefore has no way to cross-check the SD path at all: if the
product path mounts a card wrongly, reads a truncated file, or mis-orders a directory listing,
there is no second interface on the device that would disagree with it - the console would have
been that interface, and it is blind.

**Does it block 0.2.0? No.** The console is not in the artifact (K10), and nothing a user
receives behaves differently. It is a defect in the instrument, and it is the instrument K24's
hardware pass would otherwise lean on: the fastest honest way to get card evidence off a
board is usually the console, and here that route is closed.

Closing it: wire `read_sd_file` to `crate::sd::with_card` and the bounded read in
`notyas_wallet::sd`, which is the same call the flow layer already makes, and either fix or
withdraw the help line until it is done.

### K29. Receive and Export hand out legacy addresses this device cannot spend from

**Found:** 2026-08-22, from a user report that a spend of his own coins was refused. Tracing
where the coins came from found the device itself, not his wallet software.

Every wallet on this device derives all four schemes with no user choice, and `Scheme::ALL`
puts BIP-44 first (`crates/notyas-core/src/derive.rs:106`). Three screens take that order at
face value:

- Receive shows exactly one scheme and picks it with `report.schemes.first()?`
  (`crates/notyas-ui/src/screens/receive.rs:39`), so the addresses it offers for deposit are
  `1...` legacy P2PKH, for every wallet, with no warning anywhere. The word "legacy" appears
  in `notyas-ui`'s user-facing copy exactly once, as a review-row label
  (`crates/notyas-ui/src/screens/review.rs:263`), and never on Receive.
- Export opens preselected on the BIP44 tab (`crates/notyas-ui/src/screens/schemes.rs:123`,
  `tab: 0`), again for every wallet.
- On every tab the first and most prominent block is the bare account xpub
  (`schemes.rs:407`). BIP-44 and BIP-86 have no SLIP-132 form (`derive.rs:148`), so both
  render as a plain `xpub...`, and BlueWallet's documented default builds a LEGACY
  `m/44'/0'/0'` wallet from any bare xpub. The origin-carrying descriptor - the artifact the
  screen's own `DESCRIPTOR_HELP` tells the reader to use - is the LAST block, below five
  address rows (`schemes.rs:460`). The layout contradicts its own help text.

Meanwhile the signer cannot spend any of it: `ScriptKind::is_single_sig` excludes P2pkh
(`crates/notyas-core/src/psbt/checks.rs:846`), `whitelisted_sighashes(P2pkh)` is empty, and
`sign::SpendKind` has no legacy arm. So the device derives, displays, exports and solicits
deposits for a scheme it will then refuse to spend, and `export::descriptor` even emits a
`pkh()` descriptor for it (`crates/notyas-core/src/export.rs:256`).

The demonstration is the user's own file: a PSBT with one legacy P2PKH input at
`m/44'/0'/0'/0/0` of this device's own seed, full previous transaction present, refused at
load. The device proves the input is its own by derivation and then refuses to sign it. The
refusal he was shown, and the false multisig alarm it wore, is K31.

Funds are not lost - the recovery phrase re-derives `m/44'` in any standard wallet - but the
device can never move them, while actively inviting more of them. BIP-49 and BIP-86 are
spendable end to end; only BIP-44 is stranded.

**Does it block 0.2.2? Yes**, and it is what 0.2.2 is for. `docs/RELEASE-0.2.2.md` sections 1
and 4 carry the two halves: implement P2PKH signing, which the design record already
ratified (`ARCHITECTURE.md:550`, `WALLET-API.md:1325` and `:1330`, `CORPUS.md:274`,
`MILESTONES.md:877`), and change the Receive and Export defaults so legacy becomes something
a user asks for rather than something the device hands out. Closing this entry needs both,
plus the two-board hardware pass in that document's section 5.

### K30. Ten more refusal rows render copy that is false for a situation they cover

**Found:** 2026-08-22, by auditing every `CheckFailure` row after K31 was traced. K31 was the
worst row of a set, not a lone defect: the codes are assigned per CHECK, and a check groups
failures that do not share a remedy.

`RefusalCode` carries three frozen sentences and the engine supplies a fourth
(`crates/notyas-ui/src/lib.rs`, `firmware/src/flow/model.rs::code_for`). Where a check covers
two unrelated situations, at most one of them can own the copy. The rows, worst first:

| Failure | Code shown | Why it is wrong for that row |
|---|---|---|
| `MultisigStatelessUnverifiable` | R-04 Cosigner keys do not match | No comparison happened: the registry is empty. This is the FIRST screen a real multisig user meets, before registering, and it accuses him of a key mismatch. The honest instruction is "register this wallet on this device first". |
| `ClaimedKeyNotInScript` | R-01 These inputs are not from this wallet | Fires when an account of OURS locks the exact script and the file lies about which key sits there - the code's own doc calls it tamper evidence. The screen says the opposite and sends the user to open a wallet that cannot exist. |
| `PrevoutIndexOutOfRange`, `PrevTxidMismatch`, `PrevAmountMismatch`, `PrevScriptMismatch` | R-02 Missing the previous transaction | The previous transaction is PRESENT and contradicts the input's own claim. The headline states the one thing that is not true, and the remedy tells the user to attach what the file already has. `PrevAmountMismatch` is the 2020 Trezor fee-attack tripwire. |
| `MultisigWitnessScriptMissing` | R-04 Cosigner keys do not match | A required BIP-174 field is absent; nothing matched or mismatched. The remedy is to re-export with `witness_script` included, not to compare registrations. |
| `AmbiguousOwnershipClaim` | R-01 These inputs are not from this wallet | The input names THIS device twice, so it may be exactly from this wallet. Only the coordinator can fix a duplicate-origin file; "open that wallet" cannot. |
| `PathTooShallow`, `PathTooDeep`, `PathHardenedShapeInvalid`, `PathOutsidePurposeWhitelist` | R-01 These inputs are not from this wallet | The file names OUR fingerprint at a path shape no wallet should produce (the 2019 Coldcard ransom defence). There is no other wallet to open, and foreign ownership is asserted by a check that never determined it. |
| `RedeemScriptDoesNotMatchInput` | R-01 These inputs are not from this wallet | A P2SH input of ours whose redeem script does not hash to its own scriptPubKey: corruption or tampering on a coin that IS ours. |
| `InputAlreadyFinalized` | R-09 This file is malformed | The common benign trigger is re-loading a file the coordinator already finalized, which is a perfectly well-formed file. The honest sentence is "this transaction is already complete". |
| `TaprootInternalKeyMissing`, `TaprootInternalKeyMismatch`, `TaprootTweakMismatch` | R-08 Unexpected taproot data | For the first, the data is MISSING rather than unexpected and "rebuild the transaction without it" names no "it". The two mismatches are tamper-shaped and get the same impossible instruction. |
| `SignFailure::OriginDoesNotDeriveScript`, `SignFailure::Derivation` | R-01 These inputs are not from this wallet | The derive-and-compare tripwire ("every forged origin ends here") shown as a wrong-wallet mixup. The appended "Nothing was signed and nothing was written." is the one load-bearing sentence. |

Three adjacent faults outside `CheckFailure` have the same shape: a card I/O failure
(`Fault::Unreadable`) renders under "This file is malformed" with the steering-attack matters
line; a sealed-store write failure with no card involved renders under R-25 "Card write
failed" whose body says "The file on the card is incomplete."; and a multisig REGISTRATION
that this release does not store (`ScriptTypeNotP2wsh`, a legitimate P2SH-P2WSH or taproot
multisig) is called malformed and told to "re-export the transaction", which misnames a
wallet description as a transaction.

Carried here as well, from 0.2.2: **the engine sentence under an R-26 band still opens "Check
4 (multisig binding)"**, because the ten-check numbering is ratified and the sentence is the
engine's own words. The band above it says nothing about multisig, so the two disagree in
front of the user.

**Does it block 0.2.2? No.** Every refusal in this table refuses the right file for the right
reason; what is wrong is what the user is told to do next. R-26 was lifted out of the set
because it fires on an ordinary spend of the user's own coins, which none of these do.

Closing it: one decision per row about what the honest sentence is, then the codes to carry
them. Not a bulk rewrite - frozen copy that gets rewritten in bulk is copy nobody has read -
and `crates/notyas-ui/src/screens/refusal.rs`'s `CODES` array is hand-listed, so any code
added for this must be added there too or it is uncovered by the section gate.

---

## CLOSED

### K11. A cosigner's unproven amount beside our segwit v0 input could hand a whole coin to the miner

**Found:** 2026-08-18, by the adversarial corpus rather than by a user or a coordinator.
The demonstration is a two-round probe in the test suite: each round presents one proven
1 BTC coin of ours and one claimed 20,000 sat coin, so each round's arithmetic lands on
the ordinary 10,000 sat fee every other fixture declares. The two rounds share one
unsigned transaction, so the signatures combine, and the two coins really behind that
transaction are 1 BTC each against a payment of 1.0001 BTC. The loss is 0.9999 BTC, paid
to the miner as fee, and it is invisible in every number either review screen could have
shown.

**Resolved:** 2026-08-18. The device now refuses the file at check 2, previous
transactions, with `UnprovenAmountBesideOurSignature`, when both halves of the pair are
present: it would sign at least one input whose signature does not commit to every input
amount in the transaction (any segwit v0 input, since BIP-143 covers its own input's
amount and nothing else under every sighash flag it has), and any input in the file states
an amount without proving it (a `witness_utxo` with no `non_witness_utxo`). The refusal
names both ends, because either end is one a sender can fix. This is BIP-174's own
footnote enforced rather than quoted: the previous transaction is required "to ensure that
the amounts of other inputs are not being tampered with".

A cosigner's already finalized input is not exempt, and that is the part that will
surprise people: being finalized says nothing about an amount, so a finalized input
carrying only a `witness_utxo`, sitting beside a segwit v0 input of ours, is exactly the
refused case. Taproot is untouched - BIP-341 hashes every input amount into the digest
under SIGHASH_DEFAULT, so our own signature makes those amounts binding, and the test
suite fails loudly if the taproot sighash whitelist is ever widened to an ANYONECANPAY
flag. A file this device signs nothing in is also untouched: with no signature of ours,
there is nothing for a substituted amount to ride on.

Did it block 0.2.0? It would have, and it no longer does. The residual is not a defect but
an interop regression, and it is real: a PSBT this device accepted earlier on 2026-08-18
is now refused, and coordinators that omit `non_witness_utxo` for segwit inputs to save
space will produce files it refuses. A silently narrowed acceptance set is how a signer
earns a reputation for being broken, so the regression is disclosed rather than
discovered - docs/RELEASE-0.2.0.md section 6 states it, names the finalized-input case
specifically, and says what a coordinator has to do about it. That disclosure is the
condition on which this entry is closed; the refusal itself is not negotiable, because it
buys the closure of a demonstrated one-coin loss.

**Narrowed:** 2026-08-22, in 0.2.1. The refusal above still stands wherever both halves of
the pair are present, with exactly one case removed from it: a transaction with a single
input. There is no other amount in such a file to substitute, and no second signature
anywhere for a later round to combine a harvested one with, so the two-round probe that
opened this entry has nothing to work with. The interop regression narrows with it - a
single-input spend from a coordinator that omits `non_witness_utxo`, which is every
BlueWallet spend, is now accepted, and its fee is shown as an exact figure rather than a
lower bound. Two or more inputs stays refused, and the reason is that no stateless rule
can admit it: a coordinator can prove one input's amount and merely claim another's,
rotating which is which between rounds, so every file he presents carries a single
unproven amount and still yields one valid signature per round, and S-35 leaves this
device nothing with which to notice the second presentation. `docs/RELEASE-0.2.1.md`
section 0 states the narrowed rule, what it admits, what it still refuses, and the remedy.

### K12. Board B stopped enumerating over USB after a camera module was inserted reversed

**Found:** 2026-08-18, on the bench. An OV2640 module was seated into FPC3 end-for-end
reversed. Afterwards board B's CH340K UART bridge no longer enumerated on the host - COM6
simply absent - which is indistinguishable at first sight from a dead board.

**Resolved:** same session, by removing the module. Enumeration returned completely, and
the two things that would have been expensive to lose were intact: the eFuse contents read
back as before, and the sealed store still mounted and read back its ledger, so the m4a
seal evidence taken on this board stands.

Did it block 0.2.0? No, on two independent grounds. It was operator error against a
connector this release does not use - 0.2.0 is SD-only and the camera moved to 0.3.0 - and
the board recovered fully, so there is no damaged unit and no artifact implicated. It is
kept because the reasoning is the useful part. First, the failure mode presented as a dead
board at the worst possible moment in the schedule, and the correct diagnosis was
mechanical and reversible; anyone meeting a P4 board that has stopped enumerating should
look at what was last plugged into it before concluding anything about the silicon.
Second, it is unsought evidence that an eFuse burn and a sealed store survive an
electrical insult of this class, which says something real about the durability of the
HMAC device binding that no test would have been written to ask.

Closing it further: nothing in 0.2.0. What actually happened electrically was not
established - the FPC connector is not keyed against a reversed insertion, and whether the
reversed module shorted or back-powered the 5 V side is a question for a meter, not for a
guess in a release week. When the camera lands in 0.3.0, m11's bring-up notes should carry
the orientation, this incident, and the answer.

### K13. A shipped 0.2.0 image cannot set a PIN, so it cannot store a wallet at all

**Found:** 2026-08-19, walking the shipped UI against the ratified screen spec and then
following each dead end down into the firmware.

The sealed store is formatted by `Store::format(&Pin, label)`
(`firmware/src/store/mod.rs:358`). The only two call sites in the tree are in the
hardware-in-the-loop console: `firmware/src/hil.rs:571` (the `format <pin>` command) and
`hil.rs:984` (a known-answer self-check). That console is behind the non-default
`hil-console` feature and is refused outright in a product image by three independent
fences - `firmware/build.rs:185`, the `compile_error!` at `firmware/src/hil.rs:97`, and the
symbol gate `tools/ci/check-release-symbols.sh` read against the linked ELF. All three are
correct and must stay. The consequence is that **nothing in a shipped image can format the
store.**

The touch UI cannot do it either, and this is a second, independent gap rather than the same
one twice. Of the `UiRequest` variants, `PersistWallet` carries a `WalletDraft` with no PIN
field, `ChangePin` and `RemovePin` carry no value at all, and `UnsealWallet(Secret)` carries
a PIN only to try an EXISTING one. `PinState` (`crates/notyas-ui/src/screens/pin.rs:47`) has
one mode - entry - with no create, no confirm and no repeat field.

What follows mechanically, while the store cannot be formatted, is the whole rest of the
product. `StoreStatus::has_pin` (`crates/notyas-ui/src/lib.rs:913`) is true only for
`Locked` and `Unlocked`, both of which require `StoreState::Formatted`
(`firmware/src/store/mod.rs:349-353`). `Ui::lock` (`crates/notyas-ui/src/ui.rs:432`) returns
`false` and does nothing when `has_pin` is false, and `Ui::floor` (`ui.rs:686`) resolves to
the stateless Home for every other status. On a device flashed from a release artifact the
lock screen, PIN entry, the wallet list, the wallet home, Settings and the wipe-policy
editor are therefore not merely empty - they are unreachable, for the life of the device.

Note that `docs/PROVISIONING.md:129` already documents the real procedure and is accurate:
after the eFuse burn, "power-cycle the board and run `format <pin>` on the HIL console".
That is a bench procedure on a non-shipped image. It is the only procedure there is.

**Did it block 0.2.0? Yes, until 2026-08-19.** Everything else in this file was a defect in
a device that works; this was the difference between the product described in `README.md`
and `docs/SECURITY.md` - a device that stores up to eight wallets behind a PIN - and the
product in the artifact, which was a stateless seed tool and public-key exporter. No wording
change made those the same device. The choice was between shipping with the store reachable
and documenting the artifact as what it was; `docs/RELEASE-0.2.0.md` section 0 took the
second option, and per K26 it still reads that way and is now wrong.

Closing it takes four pieces, of which the vocabulary above is the first: the S-06/S-07
screen and its `State` variant; a route that raises `SetPin` where `has_pin` is false; a
`firmware/src/main.rs` arm carrying the PIN to a `Store::format` route published on the
product path; and a power-cycle read-back proving that a wallet saved under that PIN comes
back. **This entry closes on that read-back, not when `SetPin` compiles** - a store that
formats but whose records do not survive a power cycle is the failure mode this milestone
has already had once.

The store side is done and proven - `Vault::format` is covered by the lifecycle and tamper
suites and by the power-loss corpus - so this is UI work and one firmware arm, not new
cryptography. The three build fences around `hil-console` must not be touched, and `SetPin`
must stay distinct from `ChangePin`: the first creates the ledger and the superblock, the
second re-seals records that already exist under a key that already exists, and they fail in
different ways.

**Resolved 2026-08-19.** A shipped image can set a PIN. The screen is
`crates/notyas-ui/src/screens/setpin.rs` (S-06/S-07, `SetPinState`), wired at
`crates/notyas-ui/src/screens/mod.rs:398` as `State::SetPin` and at `:448` as
`ScreenId::PinCreate`; the route that reaches it is
`crates/notyas-ui/src/screens/fork.rs:255-257`, where the S-19 save card pushes the create
screen when `StoreStatus::has_pin` is false; `setpin.rs:547` raises
`UiRequest::SetPin(Secret)` (`crates/notyas-ui/src/lib.rs:768`) after the same PIN has been
typed twice; and `firmware/src/main.rs:682` dispatches it to `answer_set_pin`
(`main.rs:1263`), which parses the PIN and calls `Store::format(&pin, b"notyas")` on the
product path, answering `ui.pin_created(true|false)` on every arm. The `b"notyas"` superblock
label distinguishes a store the product formatted from one the console did (`b"hil"`), which
is a question an auditor can now ask of any device.

The three `hil-console` fences were not touched, and `SetPin` stayed distinct from
`ChangePin`: the first creates the ledger and the superblock where none exists, the second
re-seals records under a key that already exists, and the create screen is reachable only
where `has_pin` is false.

**The read-back this entry demanded has NOT been performed, and it moved rather than
vanished.** K13's own closing text says it closes on a power-cycle read-back and not on
`SetPin` compiling. No board has run any of this. That obligation, and the same obligation for
every other step of the loop, is now K24 - it is a hardware-evidence gap rather than a missing
feature, which is why this entry closes and that one opens.

### K17. The whole signing path is absent from the touch UI

**Found:** 2026-08-19, same pass. This is the widest gap in the repository between what is
built and what is reachable.

The engine is real and it is the most heavily tested code here.
`crates/notyas-core/src/psbt/` decodes, inspects, signs and encodes. `firmware/src/signing.rs`
is the single-entry pipeline over it: `Review` is constructible only by `review` and `Signed`
only by `Review::sign`, the inspection carries the SHA-256 of the bytes it read and signing
recomputes it, and `ReviewedFee` makes it impossible to render an unprovable fee the way a
proven one is rendered. The host suites pass. Re-run them rather than trusting a count -
they grow - with `cargo test -p notyas-core --lib` and `cargo test -p notyas-core --test
psbt_vectors --test multisig_vectors --test address_vectors`; all four were green on
2026-08-19 (331 lib, then 4, 6 and 18).

Nothing on the device reaches any of it. `firmware/src/signing.rs` has exactly one consumer
in the tree, `firmware/src/hil.rs`, which is the console excluded from every product image
(K13, K10). `ScreenId` has no PSBT screen, so there is no S-27..S-39; `RegionId` carries no
signing region; `UiRequest` carries no signing request. Searching all of
`crates/notyas-ui/src/` for a signing screen returns nothing.

A 0.2.0 unit therefore cannot sign a transaction. It can generate and restore seeds and show
public keys, and the signer inside it is reachable only from a serial console a shipped image
does not contain.

**Did it block 0.2.0? Yes**, against `MILESTONES.md` section 9 clause 2, which requires the
whole loop including loading a PSBT and delivering a signed one. It no longer does, on
reachability; the clause-2 obligation it names is not discharged by that, because no board
has run the path (K24).

Closing it: the m6 review and signing screens. No engine work is outstanding.

**Resolved 2026-08-19.** The signing path is on the device. `ScreenId` now carries
`SignSource`, `FilePicker`, `Working`, `Refusal`, `ReviewTransaction`, `Signing` and `Deliver`
(`crates/notyas-ui/src/lib.rs:327-363`), implemented by
`crates/notyas-ui/src/screens/sdcard.rs`, `review.rs`, `deliver.rs` and `refusal.rs`. The
wallet home offers it: `RegionId::ActSign` is pushed on a stored wallet holding its derivation
(`crates/notyas-ui/src/screens/wallet.rs:182`) and opens `SignSourceState`
(`wallet.rs:327`). `UiRequest` carries `ListCard`, `LoadPsbt`, `SignTx`, `WriteSigned` and
`DiscardSigned`, answered by `firmware/src/flow/`, which is the new module holding the one
long-lived wallet on the device and stating its lifetime once: opened by `OpenWallet`, closed
by `Flow::close` on a lock, on the auto-lock, and when the panel leaves the wallet's screens.
`firmware/src/signing.rs` now has a second consumer, and it is the product one.

Two things that were true when this entry was written stayed true and are worth carrying
forward. No engine work was outstanding, and none was done - `Review` is still constructible
only by `review` and `Signed` only by `Review::sign`. And the review's own defect found by the
clause 2 run closed in the same pass: `signing::review` now passes
`derive::device_accounts` into `psbt::inspect_with_accounts`, so check 3 proves single-sig
change instead of labelling it a payment (`docs/clause2-evidence.md`).

What this closure does not include is any hardware evidence. Nothing in this list has run on a
board; see K24.

### K18. The microSD subsystem is complete, compiled, and reached by nothing

**Found:** 2026-08-19, same pass.

`firmware/src/sd/` (`mod.rs`, `mount.rs`, `fs.rs`, `pins.rs`) and
`crates/notyas-wallet/src/sd.rs` are finished: the bounded decision layer is host-tested
against a hostile simulated card, the GPIO sets are proven disjoint from the C6 radio pins at
compile time, and the delivery sequence's power-cut behaviour is stated.

`firmware/src/main.rs:55` declares `mod sd;` and never names it again - grep for `sd::` in
`main.rs` returns nothing, and the console does not use it either. The module's own header
says so plainly: "Why every item here is currently dead code - the screens that call it are
m4b's and m6's, and neither is in this workstream's fence."

The same is true of the airgapped transport codecs. `crates/notyas-wallet/src/transport/`
carries `ur.rs`, `bbqr.rs`, `bytewords.rs`, `fountain.rs`, `playback.rs` and `checksum.rs`,
and no firmware or UI file references `transport::`.

With K17 this is the ingress and the egress of the signing loop: 0.2.0 is SD-only by decision
(the camera moved to 0.3.0), the SD code exists, and no screen opens a card.

**Did it block 0.2.0?** It was the same block as K17 rather than a second one - the loop needs
both halves and neither was wired. It is recorded separately because closing K17's screens does
not by itself wire this, and because `docs/claims-audit-0.2.0.md` section 6 previously recorded
m5 as "not started", which is no longer true and would send the next reader hunting for absent
code rather than unwired code.

Closing it: the m6 file picker and delivery screens call `Catalog::scan`, `read`, `plan` and
`deliver`, all of which already exist.

**Resolved 2026-08-19**, for the microSD half, which is what this entry's title claims.
`firmware/src/flow/mod.rs` is the consumer: it imports `crate::sd::{self, Card, CardError,
FsError}` and `notyas_wallet::sd::{Catalog, Filter, Kind, Location, Name, OnCollision}` and
answers `ListCard` with `Catalog::scan`, `LoadPsbt` with a bounded read, `WriteSigned` with
`sd::deliver` and the S-38 collision question, all behind `sd::with_card` so the card guard is
dropped however the call ends. `firmware/src/main.rs` names `sd::assert_idle()` and
`sd::mounts()` directly. The module header's own note - "the screens that call it are m4b's
and m6's, and neither is in this workstream's fence" - is now out of date in the good
direction.

The other half of this entry did not close and has been refiled as **K27**: the airgapped
transport codecs in `crates/notyas-wallet/src/transport/` are still referenced by no firmware
or UI file.

No board has read or written a card, in this build or any other, and the console's own SD
route is still a stub (K28). This entry closes on reachability, which is what it claimed; the
hardware evidence is K24.

### K19. Multisig registration has no UI

**Found:** 2026-08-19, same pass.

The registry is real on the storage side: registry slots are part of the frozen layout
(`firmware/src/store/mod.rs:518`), a wallet's registrations are re-derived and re-proved
against the live seed at open time and a record that fails to prove out is reported as a fault
(`firmware/src/main.rs:768-784`), and `notyas-core`'s `multisig_vectors` suite passes. The UI
can COUNT registrations - `WalletInfo::registrations`, and the destruction sheets name them
individually with counts read from the store (`crates/notyas-ui/src/lib.rs:794-800`).

There is no screen that creates one. No `ScreenId`, no `RegionId` and no `UiRequest` reaches
registration, so on a device the count is always zero and every sentence the UI writes about
registrations is about a set that can only be empty.

**Did it block 0.2.0?** No. `docs/RELEASE-0.2.0.md` section 4 already lists BSMS and taproot
multisig as not shipped; this entry adds that ordinary multisig REGISTRATION is also not
reachable on the device, which a reader of the wipe-policy and PIN-removal copy would
otherwise reasonably assume exists.

Closing it: the m7 registration screens, or a line in the release notes stating the absence.
The second is cheap and should land either way.

**Resolved 2026-08-19.** Multisig registration has a UI.
`crates/notyas-ui/src/screens/multisig.rs` implements S-41 import, S-42 review and approve, and
S-43 detail and delete, wired as `ScreenId::{MultisigList, MultisigImport, MultisigDetail}`
(`crates/notyas-ui/src/lib.rs:365-370`) and reached from the wallet home through
`RegionId::ActMultisig` (`crates/notyas-ui/src/screens/wallet.rs:189,337`). The requests are
`ImportRegistration`, `ApproveRegistration { replace }` and `DeleteRegistration(u8)`, answered
in `firmware/src/flow/` against `multisig::verify`, `Wallet::register` and `Wallet::deregister`.
The destruction sheet is a C4d typed-name at `multisig.rs:1987` and the duplicate-replace
question a confirm sheet at `:1972`, so the count the UI has always been able to read is now a
count it can change.

The registration is still re-derived and re-proved against the live seed at open time, and a
record that fails to prove out is still reported as a fault - the storage side this entry
described as "real" was not weakened to make the UI reachable.

No registration has been created on a board, and the 2-of-3 that MILESTONES clause 2 names has
never been signed on hardware on any interface; both are K24.

### K31. A single-sig spend of the user's own coins was refused as a cosigner-substitution attack

**Found:** 2026-08-22, by a user, on a device holding his own wallet. He loaded a PSBT and
was told his cosigner keys did not match and to compare the registration on all his devices.
He has no multisig wallet, no cosigners and no registration on the device. He was right and
the device was wrong.

The demonstration is his file, decoded off the card: one input, one output. The input is a
legacy P2PKH prevout with the full previous transaction present, so its amount is proven
rather than claimed, and its `bip32_derivation` names `m/44'/0'/0'/0/0` with a public key
whose hash160 is exactly the pubkey hash in the input's own script. The device derived that
leaf, rebuilt the script, and PROVED the input was its own (`Ownership::Proven` ->
`Claim::Ours`, `crates/notyas-core/src/psbt/checks.rs:2218`) before showing him a multisig
attack alarm.

The chain, every link of it correct in isolation (the two firmware line numbers are omitted
because the fix below moves them):

    checks.rs:1456   P2pkh is outside is_single_sig  -> ClaimedInputNotSingleSig
    checks.rs:630    that variant is filed under     -> Check::MultisigBinding (check 4)
    model.rs         code_for(check 4) mapped to     -> RefusalCode::CosignerMismatch
    notyas-ui        which rendered                  -> "R-04 Cosigner keys do not match"
                                                       "A substituted cosigner key sends your
                                                        coins to someone else's multisig."
                                                       "Compare the registration on all your
                                                        devices."

Exactly one sentence on the screen was true, and it was the engine's own: "input 0 is a
legacy address, which is not a script this device spends". Everything the UI wrote around it
described an attack that had not happened, and the instruction named an action he could not
perform.

Reproduced on hardware before any edit, over the HIL console, against a wallet that does NOT
own the coin: the same file inspects clean and refuses honestly at check 1, "none of these
inputs belongs to this wallet". The false alarm appears only once ownership PROVES, which is
half of why it survived every gate. The other half is what the gates assert: the one fixture
for this row (`p2sh_psbt_claiming_our_key`) checks the engine's `CheckFailure` and its check
number and never the copy a screen builds from them, the `RefusalCode` table test asserted
exactly the ratified check-to-code mapping that produced the wrong screen, and the ratified
legacy corpus group (CORPUS.md P3) was never built - `P2pkh` appears in no test in
`crates/notyas-core/tests/`. Nothing in the suite had ever read the sentence a user would.

The refusal itself was load-bearing and stays. At `ccc85c7` there is no legacy signing path
(`sign::SpendKind` has four arms, none legacy) and the post-sign gate computes a BIP-143
digest for any prevout that is not P2WSH, so admitting the input without building that path
would have moved the same refusal to after he held to sign and shown him R-01 instead. What
was defective was the copy, not the decision.

**Resolved:** 2026-08-22. `ClaimedInputNotSingleSig` has its own refusal code, R-26 "Not a
script this device signs", with a body that names no multisig, no cosigner and no
registration, and an instruction the reader can act on. The lift is one arm in
`firmware/src/flow/model.rs::check_refusal` matched before the fallback to the `Check`-based
table, which is the same per-variant lift that file already performs for `PsbtTooLarge` and
`PsbtVersionUnsupported`. No `Check` numbering, no `CheckFailure` variant, no `Display`
string and no security check changed: R-04 is still what every genuine multisig failure
carries - `MultisigStatelessUnverifiable`, `MultisigNotRegistered`,
`MultisigWitnessScriptMissing`, `MultisigWitnessScriptMismatch` - and the check-to-code table
pin in `firmware/hostcheck/tests/review_model.rs` is untouched and green. Both directions are
pinned by new tests in that file, and a uisim frame puts the new band on both panels.

Two residuals, both deliberate and both recorded rather than quietly carried:

- The "What happened" line under the band is the engine's sentence and still opens "Check 4
  (multisig binding)", because the ten-check numbering is ratified (`ARCHITECTURE.md` 5.3)
  and that line is what a bug report is photographed from. It is tracked in K30 with the rest
  of the copy audit.
- `crates/notyas-ui/src/screens/refusal.rs` holds a hand-listed `CODES` array that the
  "every code fills the sections it claims to" gate iterates. R-26 is not in it, so that gate
  does not cover the new code; its three strings are pinned in `review_model.rs` instead.
  Adding it to `CODES` is a one-line change and belongs with the next edit to that file.

What this entry does NOT close is why his coins were on a legacy address in the first place,
or that the device still cannot spend them: that is K29, and `docs/RELEASE-0.2.2.md` sections
1 and 4 carry the decision.
