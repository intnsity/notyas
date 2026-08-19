# notyas 0.2.0 - known issues

Open defects and rough edges found during development, tracked here so the handover
states them up front rather than letting the owner discover them. Each entry says what
it is, how it was found, whether it blocks release, and what closing it requires.

Closed entries stay, with their resolution, because the reasoning is often the useful
part.

**K13 to K22 are one group and should be read as one.** They are the result of walking the
shipped UI against the ratified screen spec on 2026-08-19 and following each dead end down
into the firmware. K13 is the root: no shipped image can set a PIN, so no shipped image can
store a wallet, so the entire post-PIN surface is unreachable. Most of the rest are defects
in code that a shipped image therefore never reaches - which makes them cheap today and
release-blocking the moment K13 closes. K14, K17 and K18 stand on their own. The
one-paragraph statement of what the release can and cannot do is
`docs/RELEASE-0.2.0.md` section 0, and it is the section a stranger reads first.

Three findings from an earlier pass of that walk are **not** in this file because they were
fixed while it was being written, and they are named here so that they are not re-reported:
the touch-UI save path now seals a real `WalletRecord` through `Wallet::seal_into_free_slot`
rather than writing a raw phrase; all eight payload slots are usable, with the slot chosen
by the store rather than hardcoded; and Settings is now reachable from the wallet list, with
Verify device and the network choice as rows on it. Each was re-checked in the tree on
2026-08-19 before being struck.

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

### K5. The m4a power-cut gate has evidenced one of its three modes

**Found:** 2026-08-18, from the gate's own evidence record, docs/m4a-power-cut-evidence.md,
written as the run happened rather than reconstructed afterwards.

Twenty valid cuts on board B, every one landing inside a live seal, zero epoch changes,
zero `next_seq` regressions, zero failed remounts, 7,424 sequence units committed across
the run. That is the strongest storage evidence this project holds, and it covers
`-Mode seal` and nothing else. The m4a exit gate also names `-Mode pin` (a cut inside
change-PIN, the operation with the most steps and therefore the most boundaries to land
between), `-Mode attempt` (a cut mid-decrement of the attempt counter), the SET-POLICY
seven-step cut sequence, and the wipe-disabled 128-attempt overflow case. None of those
has been run. Board A has not been cut at all: it is unprovisioned by design
(`KeyProvenance::Emulated`) so its store path differs, and the gate must either be re-run
there or scoped out with the reason written down.

Does it block 0.2.0? Yes, and it is the only open entry here that does. The distinction
that carries the verdict is between a property measured and found sound and a property not
measured. Sealing is measured. Change-PIN and the attempt counter are not, and they are
the two operations where a cut has the most steps to land between and the worst outcome if
it lands badly: a torn change-PIN can leave a store that opens to neither PIN, and an
attempt counter that regresses across a power cut hands a thief unlimited on-device
guesses one reset at a time, which is the classic attack against exactly this mechanism.
The seal run says nothing about either, and saying nothing is not the same as saying they
are fine. MILESTONES.md section 9 item 1 settles the rest: no other gate may be
outstanding and no gate may be waived, so an unrun mode of a ratified gate blocks the
release by the release's own rule rather than by this entry's opinion.

Closing it: two more harness runs and the two named cases, on the harness that produced
the seal record - `power-cut-gate.ps1 -Port COM6 -Mode pin`, then `-Mode attempt`, each
read back with `summarize-cuts.ps1` and appended to docs/m4a-power-cut-evidence.md as its
own section rather than folded into the seal numbers, since a mode with no data must not
average into one that has some. This is bench time with the board owner present, not a
code change: nothing in the tree has to move. K4 still applies to every one of those cuts
and more of them will not fix it - the window is sampled either way.

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

### K10. The HIL console formats, seals, erases and signs with no PIN, and only the build fences it

**Found:** 2026-08-18, reading `firmware/src/hil.rs` against the release-symbol gate while
the artifact-tier gates were being assembled.

The dispatcher reaches `format`, `erase`, `seal`, `wipe`, `changepin`, `soak` and, since
0.2.0's release-loop additions, `register`, `address`, `psbtload`, `psbtinspect` and
`psbtsign` from a bare line on UART0 (`firmware/src/hil.rs:294-329`). `unlock` takes a PIN
because the store's key ladder needs one; nothing else asks for one, and `psbtsign`
produces a real signature from the wallet in memory on request. An image with this console
compiled in is a signer that signs on command over a serial port with no authentication at
all. That is deliberate - m4a's exit gate cannot be evidenced any other way - and the
console is careful in the other direction: its stated invariant is that it prints what the
operator supplied and what is public, never a derived key, seed, session secret or xprv.

Three fences, deliberately of three kinds. `firmware/build.rs` refuses the feature in an
image built without debug assertions, which stops the artifact existing at all. `hil.rs`
carries the same rule as a `compile_error!` under `cfg(not(debug_assertions))`, which
holds even if the build script is skipped, stubbed or wired to succeed.
`tools/ci/check-release-symbols.sh` reads the linked ELF with `nm`, and it is the only one
of the three whose subject is the file somebody downloads. The first two are promises
about a build; the third is a finding about an image.

Does it block 0.2.0? No. The feature is off by default (`default = []`), a release build
does not compile it, and the artifact-tier fence now exists - K3's note that the script was
missing is no longer current. Two things still deserve saying rather than filing as
settled. First, that script is not wired to anything: no workflow under
`.github/workflows/` invokes it, and the artifact-tier gate list in docs/RELEASE-0.2.0.md
section G runs `check-airgap.sh --image` per board without it. A gate that exists and is
never invoked is indistinguishable from no gate for any release that forgets to type it.
Second, the script is honest about its own reach: `nm` sees symbols, so a clean run proves
that no symbol of the console survived the link, not that no inlined instruction did,
which is exactly why it does not retire `build.rs`'s refusal.

The residual is bench discipline rather than artifact content, and it is real. A debug
image carrying this console, flashed to a board holding a wallet with money on it, is a
remote-controlled signer on a cable. Every board on this bench is a provisioned test unit,
and that is the only reason this reads as a footnote rather than as an incident.

Closing it: wire the gate in at both tiers - CI on every push, and the release runbook's
artifact section against the ELF that actually shipped - and write the discipline where
the person flashing will meet it, namely that a board which has ever held a real wallet
does not run a `hil-console` image. Both files are outside this pass's remit, so the exact
edits are handed over rather than applied.

---

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

**A fix for exactly this is landing as this entry is written, and is partly in the tree.**
`ScreenId::PinCreate` (S-06/S-07) and `UiRequest::SetPin(Secret)` now exist in
`crates/notyas-ui/src/lib.rs`, with the request documented as raised "only by S-06/S-07,
only where `StoreStatus::has_pin` is false, and only after the same PIN has been typed
twice". What does NOT yet exist, checked in the tree at the time of writing: no `State`
variant for the screen and no module implementing it, so `ScreenId::PinCreate` names a
screen nothing can be; no route anywhere raises `SetPin`; and `firmware/src/main.rs` has no
`SetPin` arm, so the answering match is not exhaustive. Re-check with
`grep -rn SetPin firmware/src crates/notyas-ui/src` rather than trusting this paragraph -
it is a snapshot of work in flight, and the finding below is what survives it either way.

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

**Does it block 0.2.0? Yes.** Everything else in this file is a defect in a device that
works; this is the difference between the product described in `README.md` and
`docs/SECURITY.md` - a device that stores up to eight wallets behind a PIN - and the product
in the artifact, which is a stateless seed tool and public-key exporter. No wording change
makes those the same device. Either the release ships with the store reachable, or the
release documents itself as what it is; `docs/RELEASE-0.2.0.md` section 0 now does the
second so that the choice is explicit rather than implied.

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

### K14. The save path offers itself on a device that cannot save, and its failure is silent

**Found:** 2026-08-19, same pass as K13, following the create flow to its end.

S-19 Keep-or-save draws both cards unconditionally: `ForkState::activate`
(`crates/notyas-ui/src/screens/fork.rs:215-221`) routes `SaveToDevice` into the naming
screen with no test of `StoreStatus`, and neither `fork.rs` nor `name.rs` reads the store
status at all. So a user on a device with no PIN - which per K13 is every shipped device -
is invited to save, types a name, acknowledges the passphrase warning, and taps the save
button.

`UiRequest::PersistWallet` then reaches `answer_persist_wallet`
(`firmware/src/main.rs:673`), which needs an open session to seal and does not have one, so
it calls `ui.persist_result(false)`. `Ui::persist_result` (`crates/notyas-ui/src/ui.rs:509`)
begins `if !sealed { return; }` - the failure verdict is discarded. `NameState` has no
failure installer and no error state. The screen redraws identically. Nothing on the panel
changes, and the only record is a `log::error!` on a UART nobody is watching.

The comment above `persist_result` says a failure "leaves the naming screen exactly as it
was, so a retry does not cost the user their typing". That is a correct description of a
retry affordance and an incorrect one of a verdict channel: the screen it leaves untouched
never told the user there was anything to retry.

This is the worst-shaped defect in this file, because the reasonable reading of a save
button that produces no error is that the wallet was saved. It is separable from K13 and
must be fixed even after K13 is closed: a full device, a slot that filled underneath the
flow, a record too large for a slot and an expired session are all real refusals that
`seal_draft` can return on a working device (`main.rs:707-717`).

**Does it block 0.2.0? Yes**, on the same argument as K13 and independently of it.

Closing it: give `NameState` a failure state and render it, so `persist_result(false)` has
somewhere to land; and gate the S-19 save card on `StoreStatus::has_pin`, drawn `Disabled`
with its reason beside it, which is the rule the rest of this UI already keeps (see the
capacity treatment at `crates/notyas-ui/src/screens/wallets.rs:216-234`).

### K15. Delete wallet takes a two-stage typed-name consent and then does nothing

**Found:** 2026-08-19, same pass.

The wallet home draws `Delete this wallet` (`crates/notyas-ui/src/screens/wallet.rs:369`)
and gates it behind the full C4d sequence: a consequence sheet, then a sheet that requires
the wallet's name typed in full. Consent complete, it navigates to the wallet list and
raises `UiRequest::DeleteWallet(slot)` (`wallet.rs:321-330`).

The firmware arm (`firmware/src/main.rs:583-597`) refuses. `Store` publishes no route to
`Vault::clear`, so nothing is erased, and the arm re-installs the wallet list rather than
writing an empty record - which is the right call, since a blank record would read as
occupied and decode as nothing. The refusal reaches a `log::error!` and nowhere else. What
the user sees is the wallet they just typed the name of, still in the list.

The arm's own comment argues that the surviving wallet "is the evidence either way - the
user watches the wallet survive instead of being told it is gone". That is true and it is
not sufficient: a user who tapped Delete, read two sheets and typed a name has been given no
statement about why the device disagreed with them, and the unchanged list is equally
consistent with a redraw that has not happened yet.

This is the one destructive control whose refusal is safe. It is recorded because it is
drawn, fully consented and inert - not because anything is lost.

**Does it block 0.2.0?** Not on its own: per K13 the wallet home is unreachable in a shipped
image. It blocks any release in which the store is reachable.

Closing it: publish an erase route on `Store` that reaches `Vault::clear`, and give the
wallet list a refusal line for the case where it cannot.

### K16. Change PIN and the wrong-PIN policy cannot be committed, and one of the two refusals is silent

**Found:** 2026-08-19, same pass.

Three of the four sealed-store mutations are refused in every build of the image, each for a
stated reason at the site (`firmware/src/main.rs:598-645`):

- `SetWipePolicy` - committing a policy is `Vault::set_policy`, which takes the PIN because
  the policy is authenticated inside the AEAD and the commit is a re-seal. The request
  carries a threshold and no PIN. **Reported**: the arm calls `ui.policy_result(false)` and
  re-installs the policy still in force, and the policy screen renders the verdict.
- `ChangePin` - `Store::change_pin` exists and re-seals every record correctly; it needs a
  new PIN, which per K13 no screen can collect. **Not reported**: `UiRequest` documents no
  failure channel for this request, so the refusal is a log line and the screens are re-fed
  the state they already had. The user taps the row and nothing happens.
- `RemovePin` - `Vault::remove_pin` destroys every sealed record and needs a fresh PIN
  confirmation for the same reason. **Reported**: `ui.pin_removed(false)` is a failure line
  the settings screen renders.

The wipe-policy editor is therefore a live editor over a value that can be read and never
written, and the change-PIN action that `PIN-MODES.md` requires the wipe-off sheet to offer
as a PATH is a control that leads nowhere without saying so.

**Does it block 0.2.0?** Not on its own, for the K13 reason. The silent half is the part
that must not survive a release in which the store is reachable.

Closing it: the two policy operations need `Store` to publish routes to `Vault::set_policy`
and `Vault::remove_pin` that take a freshly confirmed PIN, which is the same PIN-collection
screen K13 needs. `ChangePin` needs a failure channel on `Ui` before it needs anything else,
because a refusal a user cannot see is worse than a control that is absent.

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

**Does it block 0.2.0? Yes**, against `MILESTONES.md` section 9 clause 2, which requires the
whole loop including loading a PSBT and delivering a signed one. It is recorded here so that
no release-facing document describes 0.2.0 as a signer without this sentence beside it.

Closing it: the m6 review and signing screens. No engine work is outstanding.

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

**Does it block 0.2.0?** It is the same block as K17 rather than a second one - the loop needs
both halves and neither is wired. It is recorded separately because closing K17's screens does
not by itself wire this, and because `docs/claims-audit-0.2.0.md` section 6 previously recorded
m5 as "not started", which is no longer true and would send the next reader hunting for absent
code rather than unwired code.

Closing it: the m6 file picker and delivery screens call `Catalog::scan`, `read`, `plan` and
`deliver`, all of which already exist.

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

**Does it block 0.2.0?** No. `docs/RELEASE-0.2.0.md` section 4 already lists BSMS and taproot
multisig as not shipped; this entry adds that ordinary multisig REGISTRATION is also not
reachable on the device, which a reader of the wipe-policy and PIN-removal copy would
otherwise reasonably assume exists.

Closing it: the m7 registration screens, or a line in the release notes stating the absence.
The second is cheap and should land either way.

### K20. The session auto-locks after 120 seconds with no warning, no countdown and no setting

**Found:** 2026-08-19, same pass.

`AUTO_LOCK_MS` is 120,000 (`firmware/src/store/mod.rs:81`, restating
`notyas_wallet::DEFAULT_AUTO_LOCK_MS`). The main loop ages the session from the wall clock and
any touch restarts the timer (`firmware/src/main.rs:368-377` and `406-412`), which is the right
mechanism: a pass that spent 1.8 s inside a derivation ages the session by 1.8 s.

What is missing is every part the user sees. `Store::idle_remaining_ms`
(`firmware/src/store/mod.rs:424`) is documented "for the UI" and has **no caller anywhere in
the tree**. `LockInfo` carries no remaining-time field, no screen renders one, and the settings
row catalogue is `[Network, WipePolicy, VerifyDevice]`
(`crates/notyas-ui/src/screens/settings.rs:134`) with no timeout row. When the timer expires the
screen stack is cleared and the device is on the lock screen, with no preceding warning frame
and no explanation on arrival.

Two minutes is short for the tasks this surface is for. Reading an eight-slot wallet list,
comparing a fingerprint against a coordinator, or reading a receive address off the glass are
all things a careful user does slowly, and a device that blanks mid-task teaches them to tap
the panel periodically for no stated reason.

**Does it block 0.2.0?** No - per K13 no shipped device opens a session. It is a defect in the
surface behind K13 and has to close with it.

Closing it: a warning frame at a fixed remaining time, fed by the accessor that already exists,
and a timeout row in the settings catalogue. The timeout is per-session runtime state rather
than sealed policy, so a row for it re-seals nothing and does not need the PIN.

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
writes it, or derives anything from the PIN. Per K13 no shipped device is in that state, so
today the door's absence costs nothing.

**Does it block 0.2.0?** No.

Closing it: three call sites in `crates/notyas-ui/src/screens/lock.rs`, and remove the
module-level `allow(dead_code)`.

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
