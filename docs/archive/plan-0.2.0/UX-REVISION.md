## Answer

The PIN/lock work is not just carrying nine defects, it is carrying three that are **spec-level, not implementation-level**, and fixing those first collapses most of the list. Specifically: `Metrics::bar` produces 51 px bar chips at 800x480, so `Back` itself already violates the 60 px floor and the Verify chip is a symptom, not the bug; S-04's documented 800x480 reflow is geometrically impossible (it asks for ~519 px of stacked pad + separation + button inside a 377 px body, in a 220 px rail that cannot hold a 3-wide 80 px pad); and the "of 15 tries" literal is one instance of a class the code cannot express (`attempts_remaining() -> Option<u8>`, `wipe_after` runtime 3..=25 or 0). Below, `A` items fix a defect and raise the bar, `B` is improvement inside scope, `C` needs owner sign-off.

Two contradictions block build and need a ruling before S-06 is written (see D1, D2).

---

## A. Defect fixes that also raise the bar (do these first)

### A1. `Metrics::bar` floor - the root cause of the 51 px Verify chip
**Changes:** `crates/notyas-ui/src/layout.rs` (`Metrics::new`), every bar-resident region.

At 800x480 `Metrics::new` yields `pad=26, gap=13, btn=64, bar=64`; `screens::back_rect` is `Rect::new(13, 6, 128, 51)`. Every bar chip inherits `bar - gap = 51`. Change `bar` from `btn` to `btn.max(TOUCH_MIN + gap)`, giving `bar=73` at 800x480 and **`bar=80` unchanged at 720x720** (`max(80, 72)`), so the primary panel takes zero regression. Body height goes 377 -> 368, which still clears the 4-row PIN pad (350). Do not fix this per-chip: a hit rect drawn larger than its painted band would collide with the existing region-overlap test and would violate the crate's own "never draw an affordance nothing hit-tests" rule in reverse.

**Derivation:** novel (a geometry bug), but the enforcement half is Coldcard Q's shipped phantom-keypress defect - a target floor that is a comment rather than a test is not a floor.
**Scope:** inside 0.2.0. `TOUCH_MIN`/`KEYPAD_KEY_MIN`/`LIST_ROW_MIN`/`SEPARATION_MIN` are specified in UX-SCREENS 0.3 and do not yet exist in `layout.rs`; add them here.

### A2. Make R-TOUCH universal in `check_regions`, now, before 0.2.0 adds 60 regions
**Changes:** `crates/notyas-ui/tests/ui.rs:155`.

Today the size assertion covers only `RegionId::Digit(_)` (80 px) and `Suggest(_)` (60 px). Everything else - `Back`, `Lock`, `PinSubmit`, `VerifyQr`, `StayUnlocked` - is unchecked at both geometries. Assert `>= TOUCH_MIN` for every region with exactly one allow-listed exception (keyboard letter keys at their audited 40 px floor), named in the test with its reason. This is what makes A1 stay fixed and it retires the whole class the Verify chip belongs to.

**Derivation:** UX-SCREENS 0.3 R-TOUCH, currently written but unenforced.
**Scope:** inside 0.2.0 (section 6 already implies the test).

### A3. Rebuild S-04's 800x480 reflow on the dice split, not on a rail
**Changes:** UX-SCREENS S-04 reflow note + reflow rule 1; new `pin_layout` in `screens.rs`.

The spec's rail is `clamp(w/4, 220, 300)` = 220 at 800 px wide. A 3-wide 80 px pad needs `3*80 + 2*KEYPAD_GAP` = 260. And the spec puts `Unlock` *under* the pad with `SEPARATION_MIN` (96) clear: `350 + 96 + 64 = 510` into a 368 px body. Both are impossible; this is why `PinSubmit` lands off-screen.

Reuse `dice_layout`'s proven split verbatim: info column `(body.w - gap) * 9/20` = 330, pad column 405, `key_w = (405 - 2*KEYPAD_GAP)/3 = 128`, `key_h = (368 - 3*KEYPAD_GAP)/4 = 84`. Left column carries dot row, device-words panel, attempt line, and `PinSubmit` at its foot (330 >= the spec's 260 minimum). Amend reflow rule 1 to add a keypad-aware floor so the rail can never again be specified narrower than the keys it must hold.

Also correct the separation requirement while it is being written: R-SEPARATION is defined for Danger and hold actions, and `Unlock` is neither. The real hazard is mistapping `Unlock` instead of a digit and burning an attempt. Replace the rule with the enforceable one: `PinSubmit` shares no edge with any key rect, and it is `Disabled` below the floor with its reason rendered beside it.

**Derivation:** notyas's own dice screen (0.1.0 already solved this exact problem).
**Scope:** inside 0.2.0.

### A4. Keypad control keys: relabel and freeze their slots
**Changes:** S-04 pad, `PinBackspace`, `PinAlpha`.

Label the key `Backspace`, per S-04's own region table - "Back" collides with the bar's `< Back` and the copy vocabulary (UX-SCREENS 3.1) assigns "Back" to exactly one concept. Then close the ambiguity the wireframe leaves: the 3x4 grid has 12 slots and only 10 digits. **Freeze slot 12 (bottom-right) to `PinBackspace`, put the commit key in slot 10 (bottom-left) - the slot reserved for `PinAlpha`, which 0.2.0 declares and never emits - and print the digits in fixed phone order over slots 1-9 and 11: 1-2-3 / 4-5-6 / 7-8-9 with the 0 in slot 11.**

**Amended 2026-08-19.** As first written this item shuffled the ten digits over those slots and froze the two controls so that a key which moved per attempt could not make the user hunt. The project owner reversed the shuffle after using it on hardware (OPEN-QUESTIONS Q35, reversed), so nothing on the pad moves any more and the freeze needs the other half of its justification, which is the half that survives: one of those two keys spends an attempt when it is hit, so it must not sit where a finger aiming for a digit lands. The 0 keeps the bottom-centre slot for the same reason it always had - that is where every keypad ever built puts it.

**Derivation:** the telephone and cash-machine keypad, which is what the reversal bought and what the shipped grid must therefore match exactly. The Trezor/Keystone precedent this item originally derived from - shuffle the digits, never the controls - was followed until 2026-08-19; what is left of it here is that the control keys stay out of the digit block.
**Scope:** inside 0.2.0 (a clarification C10 carried before implementation; its shuffle half is superseded by Q35's reversal).

### A5. Every number on a PIN screen is read from the store - and the wipe-off state gets real copy
**Changes:** S-04 attempt line, S-06 policy line, S-44 wrong-PIN policy row.

`Vault::attempts_remaining()` returns `Option<u8>`; `policy.wipe_after` is 0 (disabled) or 3..=25. Three renderings, no literals:

- `Some(n)`, n > 3: `"{n} of {N} tries left"`, N from `policy.wipe_after`.
- `Some(n)`, n <= 3: `WARNING` ink plus the full sentence S-04 already specifies.
- `None`: **not** "unlimited". State the mechanism: `"Wrong PINs are counted. This device does not erase itself. Guessing is limited only by how long each try takes."` No device in the survey ships State 3 at all, so nobody has copy for it, and a blank or omitted line here would be the one place the product hides a genuinely weakened configuration.

Back it with a CI rule (extends the section 6 string inventory): no screen literal contains a bare integer adjacent to `tries`, `wallets`, `slots`, or `registrations`. That retires the "of 15" defect as a class rather than as an instance.

**Derivation:** Coldcard surfaces remaining tries but not its ceiling per-attempt; Keystone documents neither. The store-sourced N is notyas's own PIN-MODES commitment made mechanical.
**Scope:** inside 0.2.0.

### A6. The PIN length cap announces itself, and it counts bytes
**Changes:** S-04 / S-06 / S-07 hint line.

`Pin::MAX_BYTES = 64` and `Pin::from_normalized_bytes` refuses above it. The cap is currently silent; the dot row simply stops growing, which reads as a dead panel. On the first ignored key: `"Maximum length reached."` in `WARNING`, dot row unchanged (so the user sees the key did nothing), hint clears on the next backspace. Cap on **bytes**, matching the crate, so a PIN can never type successfully and then be refused at seal.

**Derivation:** the crate's own contract; the anti-pattern is Krux 25.09/25.10 accepting an input in the wrong role rather than rejecting it visibly.
**Scope:** inside 0.2.0.

### A7. Two-phase Busy on unlock - the highest-value copy fix in the whole list
**Changes:** C3, the Unlocking StoreBusy instance.

`Vault::unlock` (`crates/notyas-wallet/src/vault.rs:962`) ticks the attempt entry into flash **before** the KDF runs, deliberately, so a power cut is not a free guess. So "Unlocking" is not one operation; it is a flash write followed by a computation, and the two have opposite trailing lines. C3's rule is exactly one trailing line and only when true, so one frame cannot be honest.

Paint two frames:

1. `Counting this attempt` / `"Writing the attempt counter."` / indeterminate / `"Do not power off."` (true: a write is in flight)
2. `Checking PIN` / `"Argon2id, then the sealed record."` / indeterminate elapsed seconds at 1 Hz / `"This cannot be cancelled."` (true: nothing is being written)

This deletes the "Do not power off" leak into Unlocking that the defect list names, gives StoreBusy the progress element it lacks, and it makes S-44's promised sentence - *"If the device loses power while checking a PIN, that attempt still counts. Otherwise power-cutting would be a free way to guess."* - something the user watches happen instead of something the settings screen claims. No device in the survey renders the cost of an attempt at the moment it is paid; post-Mk3 Coldcard imposes ~4 s per attempt with no rendered story about it at all.

For the other store operations: `Re-encrypting wallets` and `Erasing stored wallets` are determinate over slots ("slot 2 of 3") with `"Do not power off."`; `Saving wallet` likewise.

**Derivation:** C3's own honesty rule, applied to a two-phase operation. The determinate-vs-elapsed split is C3; the two-phase split is novel.
**Scope:** inside 0.2.0.

### A8. Split every unlock-path failure into its own screen, and promote `Provenance`
**Changes:** UX-SCREENS 3.2 refusal table, S-04 edge states.

`UnlockError` (`crates/notyas-wallet/src/error.rs:198`) has nine distinct arms and the screens collapse them. Each needs a C7 three-part refusal with a stable code:

| Arm | Treatment |
|---|---|
| `WrongPin { attempts_remaining }` | stays on S-04, A5's copy |
| `Wiped { epoch }` | S-48b. **Counts must be captured before `wipe_inner` runs** - after it, the store cannot say what it erased, and S-48b's whole value is naming the 3 wallets and 2 registrations that are gone |
| `Locked` | distinct, and it is a *rare good story*: the store is at zero and awaiting its wipe, reachable only by a power cut in the window between the last counted failure and the erase. Copy: `"The last wrong PIN was counted, but the erase did not finish before power was lost. It is finishing now."` -> the mount-time `wipe_is_due()` path -> S-48b |
| `Provenance(KeyProvenance)` | **new refusal, R-34, and the strongest screen on the unlock path.** This fires when the eFuse key does not match the one that sealed the store: the storage in front of you was sealed by different silicon. That is board-substitution detection that does not depend on the user remembering a lock word, and it is materially stronger than the lock word, whose documented limit is that anyone who held the device can read it. Treat it as a first-class screen, not an "internal error" |
| `Tamper(TamperKind)` | R-35, fail-closed, no attempt consumed - say so, because "this did not cost you a try" is the first thing a user needs |
| `Corrupt` / `NotFormatted` / `Scratch` / `Hardware { attempt_consumed }` | R-32 (exists), R-36, R-37; `Hardware` renders the `attempt_consumed` flag as a sentence, since it is the one error that honestly cannot say |

**Derivation:** C7; the anti-pattern is Jade's generic "Internal Error" (correct only inside a deliberate duress path) and Krux's tamper check that detects and then merely powers off. Promoting `Provenance` is novel.
**Scope:** inside 0.2.0 for the screens; the error arms already exist.

### A9. Build S-05, and correct its load-bearing sentence before it ships
**Changes:** new C3 variant; S-05 copy; a delay schedule that does not exist anywhere in `notyas-wallet` yet (grep for `delay`/`backoff` returns nothing).

Three decisions to make now rather than after:

- **The delay is a pure function of the persisted failure count**, computed at mount. There is no trusted clock on this device. Therefore the spec's line `"Powering off does not skip the wait."` is **not true** - power-cycling restarts the wait at full length, it does not resume it. The true sentence is `"Powering off restarts this wait."`, which is a stronger claim and an accurate one. C3's own rule is that the trailing line ships only if it is true; shipping the near-miss is exactly the failure mode this revision pass exists to prevent.
- **Cap the doubling, and print the cap.** Doubling from 1 s with `wipe_after` at its 25 ceiling reaches 2^24 s at the last attempt - the device denies itself service months before the wipe fires. Cap at 60 s with wipe enabled and state it: `"The wait doubles after each wrong PIN, up to 60 seconds."` Nobody in the survey documents their cap.
- **With wipe disabled (State 3) the delay is the only defence**, so it needs a different cap - recommend 15 minutes - and that number belongs in PIN-MODES' disable-wipe arithmetic. Right now that modal says 10,000 guesses at Argon2id speed; with a 15-minute floor per guess it is 10,000 guesses at 104 days. That completes the most honest piece of copy in the plan and makes State 3 defensible rather than merely permitted.

**Derivation:** Trezor has the exponential curve, notyas renders it as a countdown (already a lead). The anti-pattern is Krux 26.04.0, whose backoff resets on reboot and never persists a lockout - notyas's counter-anchored version is immune, and the corrected sentence is what says so.
**Scope:** the screen is inside 0.2.0. The delay schedule and the State 3 cap are a small **spec addition** (D3 below).

### A10. `PinAlpha` must not silently discard C10's protection
**Changes:** S-04 / S-06, C9, C10.

Tapping `abc` swaps the digit pad for the standard C9 keyboard, which lights the pressed key. The one protection C10 still has evaporates and nothing on screen says so. One change, and one withdrawal:

- When C9 is serving a PIN field, **C10's rule carries over**: press feedback is drawn on the dot row, never on the key. This is a per-field mode on the keyboard, not a new component. After Q35's reversal this is the whole of what C10 protects, so it is not optional and the keyboard is the only place it could have been dropped by accident.
- **Withdrawn 2026-08-19:** the line `"Letter keys are not shuffled."` As first written it warned that the keyboard lost a protection the digit pad had. The digit pad no longer has it (Q35, reversed), so the sentence would state a difference that does not exist and imply a defence on the pad the product has stopped making. A line that is not true does not ship - C3's own rule.

**Derivation:** novel. Coldcard Q has a physical keyboard; no surveyed device offers an on-screen alphanumeric PIN, so no one has had to state this boundary. It is also the C10 principle stated correctly - feedback is deliberately non-local, which is transferable to any keyboard.
**Scope:** inside 0.2.0 (both are already-specified components).

### A11. `PolicyRefusal::PinTooShortToDisableWipe` is used as the general length floor
**Changes:** `crates/notyas-wallet/src/error.rs:139`, call sites `vault.rs:751` and `vault.rs:1193`.

Those two call sites are `format` (first PIN) and `change_pin`. Both refuse a short PIN with a variant whose name - and therefore whose rendered copy - says "too short to disable wipe", which is not what the user was doing. Add `PolicyRefusal::PinTooShort { min_len }` and keep the existing variant for `set_policy`'s wipe-disable path (`vault.rs:1406`), which is the only place it is accurate.

**Derivation:** direct instance of the Trezor Suite anti-pattern - mislabelling identity on the one screen where the label is the whole message (issues #2578, #3207, #7927, #8029).
**Scope:** inside 0.2.0, and it must land before S-06's copy is CI-frozen.

### A12. The wrong-PIN policy row must show why a lower N is refused
**Changes:** S-44 wrong-PIN policy sub-screen.

`Vault::set_policy` (`vault.rs:1395`) refuses `wipe_after <= failures`, because lowering N below the failures already accumulated would wipe the device on the spot. The sub-screen must render the accumulated failure count and draw the out-of-range choices `Disabled` **with their reason beside them**: `"You have 4 counted wrong PINs. Choosing 3 would erase this device now."` Never a silent dead row.

**Derivation:** C4d's disabled-with-reason contract. The mechanism is novel - the field either hardcodes N or never exposes it.
**Scope:** inside 0.2.0.

---

## B. Pure improvement inside scope

### B1. Freeze the device-words panel to a labelled prefix
**S-04.** The words derive from whatever prefix was typed (correctly, so they cannot become a prefix oracle). But if the user shows words at 4 characters and then types a fifth, the panel now describes something other than what is on screen. Label it - `"Words for the first 4 characters"` - hold it frozen, and offer `[ Recheck ]` to recompute at the current length. Also change `PinShowWords`'s enable rule from "words not yet shown" to "words not shown for the current length", or the affordance vanishes exactly when it becomes stale.
**Derivation:** Passport shows words after 4 digits; Coldcard's two-part PIN makes the boundary explicit by construction. notyas's continuous field needs the label to get the same property. **Scope:** inside.

### B2. State the anti-phishing boundary in one line
**S-04.** `"These words come from a key burned into this chip. They change if the board changes. They do not change if the software changes."` The eFuse key is not software-readable, so the words genuinely detect a swapped board - stronger than PARITY.md's cautious note - but any firmware on that board computes them, and without secure boot in 0.2.0 firmware replacement is precisely the live attack. Three sentences, no warning band, matching VERIFY 9.4's provenance-note voice.
**Derivation:** novel as on-screen copy. Every vendor that ships anti-phishing words overstates them by omission. **Scope:** inside (one string).

### B3. Render the two digests as two comparands, not one wall
**S-46 / S-03.** VERIFY 3.3 already computes (A) `firmware_digest` and (C) the mutable-region digests. Present them as two independently readable rows with their own labels, so the reader gets separate answers to "did my firmware change" and "did my stored data change" without diffing hex. Contract rule 2 is untouched - no verdicts, just two labelled values instead of one.
**Derivation:** Krux TC Flash Hash's split pair, which is the one part of that feature worth taking (its bypass is not). **Scope:** inside; the data exists.

### B4. Give the pre-PIN Verify affordance a real target
**S-03.** Pre-PIN there is no `Lock` chip (VERIFY 11.5), so the bar's right slot is empty and the chip does not need to be a chip. Make it a full-width bottom action on the lock screen. It fixes the 60 px problem independently of A1 and it makes the single most important pre-PIN affordance in the product look like one.
**Derivation:** commandment 4 / Coldcard's principle that the genuineness affordance never competes for space with the thing under suspicion. **Scope:** inside.

### B5. Suppress auto-lock on the PIN screens
**S-49.** The suppression list names review, hold, busy and QR playback but not S-04/S-05/S-06/S-07. Auto-locking a locked device is incoherent; auto-locking mid-PIN-create discards a half-entered PIN. Add all four.
**Derivation:** S-49's own reasoning. **Scope:** inside.

### B6. Write the Busy-before-block harness against real timings
UX-SCREENS section 6 names it; MEASUREMENTS.md has the numbers. Assert that no `Ui::tick` work item exceeding 150 ms is reachable from a non-Busy state, with the store's Argon2id and seal/unseal costs as the seed cases. Without it the 150 ms law is a comment.
**Scope:** inside.

### B7. Make the post-wipe erase observable
**S-48b.** Add a grid of the wallets partition's blocks, erased versus occupied, after the erase completes. A destructive operation the user cannot see is one they cannot trust; the store already knows slot occupancy, so this is drawing, not new data.
**Derivation:** Krux's Flash Map, which is the single best "prove the erase touched what it claimed" affordance in the survey. **Scope:** inside for S-48b only.

---

## C. Scope additions needing owner approval

### C1. The receipt chip, scoped to two screens
One chip, one label, one position, on the screens that assert a verification value. Tapping writes `receipt-<kind>-<seq>.txt` to SD and offers the same bytes as a QR: plain ASCII, no secret material, stating algorithm, domain strings, entropy mode label (RAW/FIXED), path, script type, and the comparand claimed. A `notyas-verify` CLI, reproducible-built and hashed in the same signed manifest as the firmware, prints MATCH or MISMATCH.

**For 0.2.0, restrict to the two screens where all the data already exists:** the mnemonic screen (dice receipt) and S-46 (verify receipt). Everything else follows in 0.3 without re-teaching the ritual.

**Derivation:** SeedSigner's `tools/mnemonic.py` (the identical production code path, standalone) and Coldcard's published dice construction, generalized. Both exist for entropy only; nobody has it as a uniform affordance.
**Cost:** 2-3 days firmware (the receipt format and the chip, on 2 screens), 2 days for the CLI, ~1 day of manifest wiring on top of m12's existing reproducible-build work. The chip's position must be fixed now even if only two screens carry it, or the ritual never becomes one.

### C2. Dice-screen integrity affordances
**S-12.** A roll-distribution histogram and the on-screen SHA256 of the filtered roll string. Pure UI over data already in hand. The histogram is the only mechanic in the survey that catches a loaded die; the hash lets a user re-derive offline without transcribing 99 rolls. This is the identity-defining screen of the product and Krux currently out-features it.
**Derivation:** Krux ("Stats for Nerds", entropy SHA-256 display).
**Cost:** ~1 day. Recommend approving - it is the cheapest item on this page with a visible competitive delta.

### C3. Record hardware identity off-device, once, at PIN creation
**New screen between S-07 and the first save.** One screen showing MAC, die unique ID, flash JEDEC ID and flash unique ID, with a QR (all public values, all readable over USB by anyone holding the device, so no invariant is touched), and one instruction: write these down somewhere that is not this device. A substituted unit then has to lie about them rather than merely display them - and lying requires modified firmware, which is the case secure boot addresses.
**Derivation:** VERIFY 9.2 item 3 makes this the screen's third genuine capability, but nothing in the flow ever prompts the user to establish the baseline it depends on. Nobody in the field prompts for it.
**Cost:** ~1 day (S-46 already reads every value). Strongly recommended: without it, one third of the Verify screen's documented value is unreachable in practice.

### C4. Touch-panel dead-zone self-test
A sweep test as a Settings row and optionally an S-01 step. The panel is the only input path, and a mis-registered tap during dice entry silently changes the seed with nothing downstream to catch it.
**Derivation:** Krux ships a sweep; Coldcard Q shipped phantom-keypress defects.
**Cost:** ~1 day.

### C5. Calculator-login disguise - decide now, build later
UX-SCREENS section 7 defers it and PARITY calls it class b/d. It is the only covert-duress affordance in the field that survives an inspector picking the device up, and a 720x720 touch panel makes it cheaper for notyas than it was for Coinkite. **Recommend keeping it deferred to 0.3 but not deleting it**, because it interacts with S-01 and S-03 and its shape should be reserved now.
**Cost if pulled in:** 4-5 days plus its own review surface. Not recommended for 0.2.0.

---

## D. Blocking decisions - these gate the build, not the polish

**D1. The PIN floor contradicts itself three ways.** `WalletConfig` default is `min_pin_len: 4` (`crates/notyas-wallet/src/config.rs:254`); PIN-MODES.md ratifies 4 explicitly ("The 4-digit floor applies in every state", and its guess-count arithmetic is written for a 4-digit PIN); UX-SCREENS S-04 and S-06 both gate on `length >= 6` and carry the CI-frozen literal `"A PIN is at least 6 characters."` One of these ships wrong. PIN-MODES is the authoritative document by its own header, so the default reading is 4 - but the copy, the enable rules and the crate config must be changed together and the owner should confirm which.

**D2. S-01's storage row and S-46's pre-PIN field set are circularly defined.** VERIFY 7.4 caps S-46's pre-PIN granularity at "exactly the granularity S-01's boot row and S-03's footer show"; S-01 defers to Q2. Q2 (duress) is open. The boot row, the lock footer and the pre-PIN golden list cannot be frozen until Q2 lands, and the pre-PIN golden list is a CI assertion. Resolve Q2 before writing the golden list, or write it against Q2(a) and accept a rewrite.

**D3. The retry-delay schedule does not exist.** No `delay` or `backoff` anywhere in `notyas-wallet`. A9 needs a ratified curve, a cap with wipe on, and a different cap with wipe off. This is a small spec addition but S-05 cannot be built without it.

---

## E. Ratified specs corrected after implementation

### E1. The type scale gains a sixth face, because S-21's cards are geometrically impossible at five (2026-08-19)
**Changes:** UX-SCREENS 0.5 (amended in place), `crates/notyas-fonts/src/gen/sans_regular_24.rs` (new atlas), `canvas::CAPTION`, `screens/wallet.rs`, `screens/deliver.rs`, `LICENSE-fonts`.

Reported from hardware: on the 800x480 Elecrow every wallet action card showed its title
and no second line. The cause is arithmetic and no amount of copy editing reaches it. Four
cards under the identity card, each at or above the 60 px touch floor, are 88 px tall and 62
px inside; `HEADING` over `BODY` is 84 px of line box; the 720x720 panel is the same failure
with 71 px. The five committed faces have no smaller Sans - the only 28 px atlas is
monospace, which 0.5 forbids for prose - so two lines of type could not be drawn in that
card at any ratified size.

Nothing was omitted quietly: the draw loop already skipped a line it could not hold, which
is why the bounds gate stayed green - the card clips to its own rectangle, so an overrun is
truncated INSIDE the panel where only a person holding the device sees it. Three surfaces
were in that state (S-21's cards, S-38's status card, S-41's unreadable registry row) and
each now carries a measured-fit assertion; the S-21 test additionally asserts that NOTHING
is omitted, so the skip can never become the mechanism again.

**Resolution.** Add `CAPTION` (Sans Regular 24, line box 31 px) for the lines inside a
control whose height the finger and the panel own, and amend 0.5's "hints differ by ink,
not size" with the boundary it was always missing - it governs pages, and a card is not a
page. Both of a card's lines take the new size together and keep separating by ink. Copy
that was merely long was shortened instead of shrunk, per surface, and nothing a user
compares against another device changed size.

**Derivation:** notyas's own rule that an affordance is never drawn where nothing can be
read; the fix is the smallest exception that keeps it.
**Scope:** inside 0.2.0. Cost ~17.9 KiB of flash against ~419-594 KB of app-partition
headroom.

---

## The three things that would make a reviewer call this the best interaction design in open source hardware wallets

**1. One receipt ritual, learned once, applied everywhere (C1).** Every device in the survey asks to be trusted somewhere and hides that fact in a different place, and each teaches five unrelated verification ceremonies that users perform zero or one times. notyas's honest structural weakness - firmware attestation with no secure element, conceded in VERIFY 9.1 - converts into the organizing principle: nothing the device says ever has to be taken on faith, because every assertion leaves as a portable receipt an open tool re-derives. Two screens in 0.2.0 is enough to establish the ritual; the position of the chip is the part that must be fixed now.

**2. The two-phase unlock Busy (A7).** The device shows you the irreversible side effect of a PIN attempt at the instant it is paid - `Counting this attempt`, write in flight, do not power off - and only then `Checking PIN`, nothing being written, cannot be cancelled. It is one extra painted frame. It turns the plan's most subtle security property (bump-before-attempt, so a power cut is not a free guess) from a settings-screen claim into something the user watches happen, and it retires the "Do not power off" lie that most embedded UI ships permanently. Nobody in the field renders the cost of an attempt as it is being paid.

**3. Every number read from the store, and every failure given its own screen (A5, A8, A12).** No literal count anywhere on a PIN screen, enforced by a CI rule rather than by review; the wipe-disabled state given honest copy instead of silence; `Locked` distinguished from `Wiped` with the true story of the power cut that produced it; and `KeyProvenance` promoted from an error arm to a first-class refusal that tells an owner their storage was sealed by different silicon - board-substitution detection that does not ask the user to have memorized anything. The field's failures here are all of a kind: Specter-DIY's counter shows a number that is not the number of chances, Keystone never documents its threshold, Jade's generic error confuses a wallet-erase PIN with a duress PIN. Making the whole unlock path's arithmetic and vocabulary structurally incapable of lying is the thing a knowledgeable reviewer will test first, and it is achievable entirely inside 0.2.0 scope.