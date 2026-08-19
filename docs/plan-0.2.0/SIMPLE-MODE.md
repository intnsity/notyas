# notyas 0.2.0 - the dice door

Status: PLAN (buildable spec). Owner request of 2026-08-18: "add a simple mode toggle
for users on the home screen which is dice generation only - or have a button to show
them how to access no wallet dice roll only - and the user can also do more complicated
wallet things."

This file answers that request and is buildable on its own. It is subordinate to
`PIN-MODES.md` (the three device states), `SECURITY.md` (invariants), and
`UX-SCREENS.md` (screen inventory, component library, copy vocabulary). Where it
appears to conflict with any of those, this file has a bug.

Companion reading: `UX-PATTERNS.md` section 1, `UX-REVISION.md` A1/A9/B4/B5,
`COMPETITIVE.md` sections 9 and 10.

---

## 0. The answer in one paragraph

Build a **door**, not a toggle, and put it on the **lock screen**. The feature the
owner is asking for is not a new mode: it is 0.1.0, which 0.2.0 has quietly put behind
a PIN for anybody who ever saves a wallet. The whole delivery is one tappable card on
`S-03`, one new on-screen sentence, one corrected sentence, and a handful of navigation
rules. It adds **zero new screens**, **zero new components**, and **two new string
literals**. A persistent toggle is not merely more expensive: on a device with nothing
stored it is unimplementable without breaking `SECURITY.md` invariant 2a, and that
alone settles the question. Ship the door in 0.2.0; decline the toggle permanently.

---

## 1. What the request actually is

`COMPETITIVE.md` section 10 leads its claims list with "three explicit device states
with a real path back to stateless". `PIN-MODES.md` State 1 is "Supported permanently
and as a first-class mode, not a degraded one." `UX.md` commandment 6 is
"Statelessness is a feature with a border".

Against those three commitments, here is the 0.2.0 device as currently specified. A
user who has saved one wallet now boots into `S-01` -> `S-03` lock -> `S-04` PIN ->
`S-10` wallet list. Everything 0.1.0 did is still reachable - `S-10` -> `New wallet` ->
`S-11` -> `S-12` dice -> ... -> `S-19` -> "Use once, keep nothing" - but it is reachable
**only after typing a secret that the flow itself does not need**. Nothing in the dice
path reads the store, writes the store, or derives anything from the PIN.

That is the defect. It is not that the dice product became unreachable; it is that it
became gated on a credential it has no use for. State 1 is described in `PIN-MODES.md`
as a way to own the device; in 0.2.0 as specified, once you leave State 1 you cannot
visit it again without erasing the device.

The door restores it. That framing matters for everything below, because it decides
what the feature may cost: a restoration of shipped behaviour may not invent screens,
invent vocabulary, or invent state.

---

## 2. Question 1 - a door, not a toggle

**DECISION: a door.** A one-way entry into the dice-only flow, which ends and returns
to where it started. No preference is recorded anywhere, ever.

### 2.1 The invariant decides it before taste does

`SECURITY.md` invariant 2a, verbatim: *"A device with no stored wallet retains the
0.1.0 stateless property verbatim: nothing is ever written to flash."*

A persistent toggle is stored state. On a blank device there is nowhere legal to put
it:

- The wallets partition is not formatted until the first save (`ESP-SEAL.md` 4.x, the
  `F1..F5` format sequence). A blank device has no superblock and no slot to write.
- `ESP-SEAL.md` 3.5's superblock body is a fixed, fully specified plaintext record with
  every field accounted for and `MBZ` padding. A UI preference is not in it, and adding
  one would put a statement about the user's habits into the one deliberately
  unencrypted structure on the device.
- NVS is never mounted (invariant 2a, same sentence).

So a persistent toggle can exist only on a device that has already saved a wallet.
That inverts the feature: the setting that is supposed to make the dice-only product
easy to reach would be available exclusively to users who have left the dice-only
product. There is no version of the toggle that serves the person it is for.

### 2.2 Three supporting arguments, each from an existing document

1. **`UX-PATTERNS.md` 1, adopt item 3** already rejects the shape by name: *"Present
   the two ways to own the device as a fork at the point of consequence, not a settings
   toggle at setup."* The fork exists and is `S-19`. A toggle at setup is the pattern
   that section chose against after surveying six devices.

2. **`PIN-MODES.md` derives the device state from what is stored, not from a
   preference.** The three states are distinguishable by facts on the flash. A stored
   "prefers dice-only" flag would add a fourth axis that no other document models, that
   the boot path would have to read, and that `S-01`'s storage row and `S-46`'s field
   set would then have to decide whether to display. That is complexity bought for a
   convenience, which is the trade `A Philosophy of Software Design` and this project's
   own bar both refuse.

3. **`COMPETITIVE.md` 9.14 and 9.15** reject disclosure controls over content
   (Electrum's "Advanced" toggle) and reject trading verification detail for a cleaner
   screen (Nunchuk's simplification ceiling). `UX-PATTERNS.md` 1, avoid item 2 rejects
   "tiering that keeps the name and drops the differentiator" (Jade Core). A persistent
   mode is a tier, and a tier is the thing three separate passes over the field have
   already told this project not to build.

### 2.3 The toggle is declined, not deferred

Recording it as a 0.3.0 item would leave it to be re-proposed. It should be closed:

- On a blank device it is illegal (2.1).
- On a stored device it is legal - it can live inside the sealed record, readable only
  after unlock, which is where a preference about the post-unlock landing screen
  belongs. But the only thing it could then do is change what an **unlock** lands on,
  which is a different feature from the one that was asked for, and it splits the
  post-unlock home in two for no gain the door does not already deliver.
- The door already gives a user who wants dice-only every boot a one-tap path from the
  first screen they see. A preference would save that one tap and cost a stored fact
  about the owner's habits.

If the owner still wants a landing preference later, it is a new question ("where does
unlock land"), not this one, and it should be raised as such.

### 2.4 What "door" means precisely

- **One-way.** It enters the dice flow and does not change the state of anything.
- **Pre-PIN.** It costs no PIN attempt, opens no store, and reads no wallet.
- **Returning.** It ends by returning to `S-03`, the screen it was entered from.
- **Not a state.** The device is `StoreStatus::Locked` for the whole of it. Nothing on
  the device knows the door was used, before, during or after.
- **Not exclusive.** It is one affordance among the two already on `S-03`; it does not
  replace, hide or reorder unlocking.

---

## 3. Question 2 - what is behind the door

### 3.1 The flow

Every screen below already exists in `UX-SCREENS.md`. The door introduces no new one.

```
  S-03 Lock
    |
    |  [ New seed (dice) ]        <- the door, pushed (not entered)
    v
  S-12 Dice entry          rolls, RAW/FIXED label, strength meter
    v
  S-13 Mnemonic display    reveal gate, fixed-run mask
    v
  S-15 Passphrase          opt-in, off by default
    v
  S-16 Deriving            C3 busy, determinate
    v
  S-17 Backup check        every word, five candidates
    v
  S-19 Keep or save   -----[ Save to this device ]---> S-04 PIN --> S-20 --> S-21
    |
    |  [ Use once, keep nothing ]
    v
  S-26 Export public keys  0.1.0's schemes screen: xpub, descriptor, addresses
    |
    |  [ Done ] -> exit modal -> lock
    v
  S-03 Lock
```

### 3.2 In and out, with the reason for each

| Item | In the door? | Why |
|---|---|---|
| Dice entry (`S-12`) | **In** | It is the door. |
| Entropy accounting (`S-12`'s meter, "Need 128 bits - about 77 more rolls", the RAW / FIXED compatibility label) | **In** | Already on the screen, unchanged. `UX-PATTERNS.md` 2.3 requires the mode label stay visible because it is what makes the off-device check possible at all. |
| Mnemonic display with the reveal gate (`S-13`) | **In** | It is the output. |
| Backup check quiz (`S-17`) | **In, mandatory** | Commandment 3: "No backup exists until it is verified". `S-17`'s own edge-state note says every word every time. It matters **more** here, not less: on this path the user's dice log and handwritten words are the only copy that will ever exist. Making it optional for the door would be inventing a second, weaker rule for the path where the rule matters most. |
| BIP-39 passphrase (`S-15`) | **In, unchanged** | Three reasons. It shipped in 0.1.0, and the door's whole justification is that it restores 0.1.0 rather than a reduced version of it. It is already opt-in with a single toggle, so a user who does not want it pays one tap. Removing it would fork the create flow into a door variant and a wallet variant, which costs a screen state, a test matrix and a divergence, to save that one tap. |
| Address preview / public keys (`S-26`) | **In, as the terminal** | 0.1.0's dice flow ended on the schemes screen. Ending the door earlier would be a regression against the shipped product it exists to restore. It is also the only screen on the path that lets a user check the result against an off-device tool, which is `UX-PATTERNS.md`'s single highest-leverage decision applied at the one place the data already exists. |
| Final-word calculator (`crates/notyas-core/src/mnemonic_tools.rs`, `C9`'s "Valid last words" strip) | **Out, by construction** | It is a completion strip on `S-14` word entry (`UX-SCREENS.md` C9, S-14). The door has no word entry, so there is nothing to decide: the calculator is not on the path. Its coin-flip and `EntropyAccount` surface belongs to the hand-picked-mnemonic path (`COMPETITIVE.md` G8), which is a separate feature with its own screen. |
| Restore from words (`S-14`) | **Out** | The owner asked for "dice roll only", and every item added costs the simplicity that is the point. A user with existing words is not stuck: unlock and use `S-10` -> "Restore from words". Cheap to reverse if wanted later - see section 10. |
| Stateless signing (`S-40`) | **Out** | See 3.3, rule 5. This is the one exclusion with a security reason rather than a scope reason. |
| Saving a wallet | **In, via `S-19`** | Question 3's discovery direction. It routes through the PIN, which is exactly where a write belongs. |
| Multisig, receive-address browsing, wallet settings (`S-21` and below) | **Out** | They are per-wallet surfaces and there is no wallet. `S-26` is the correct terminal, as it was in 0.1.0. |

### 3.3 Rules the door adds

These are the whole behavioural delta. Each is stated as an invariant because each is
the kind of thing that decays silently.

1. **The store is never opened on the door path.** No mount, no unseal, no attempt
   counter tick, no wipe-epoch read. The door consumes no PIN attempt and cannot
   contribute to a wipe. This is checkable: on the door path the UI issues no
   `UiRequest` that touches the store.

2. **`StoreStatus` does not change.** It is `Locked` on entry, throughout, and on exit.
   The pre-PIN visibility rule in `VERIFY.md` 7.4 therefore holds unchanged: the door
   shows nothing a person holding the device could not already obtain, and it says
   nothing about the wallets on this unit. Q2(a) is unaffected - the door renders
   identically on a device with one wallet and a device with eight.

3. **The door does not arm auto-lock.** Auto-lock (`S-49`) exists to drop a **stored
   wallet session** so an unattended unlocked device cannot be used against stored
   coins. The door opens no such session; the device stays locked. The only secret in
   RAM is one the user is actively creating and can only lose. Arming auto-lock here
   would destroy a half-finished 99-roll entry to protect nobody, and it would be new
   behaviour 0.1.0 never had. `UX-REVISION.md` B5 already established that auto-locking
   a locked device is incoherent.

4. **The door is `push`ed, not `enter`ed.** `S-03`'s existing `HomeVerifyDevice` is
   pushed for exactly this reason (`screens/lock.rs`: "Pushed, so Back returns here").
   The door follows it. This matters: `Ui::floor()` currently returns `State::Home`
   (the stateless home, `S-09`) whenever the device is not `Unlocked`, so an empty
   stack on a locked device would land the user on a screen that says "Nothing is
   stored on this device." That sentence would be false. Pushing keeps the stack
   non-empty; see section 9, defect D2, for the assertion that should make it stay
   true.

5. **No signing from the door in 0.2.0.** `S-40` stateless signing enters from `S-09`
   on a blank device and stays there. The reason is not scope, it is refusal quality:
   `R-01`'s wrong-wallet routing - which `UX-PATTERNS.md` 7.3 calls "the single
   highest-value refusal in the plan because it rescues a guaranteed first-timer dead
   end" - names the stored wallet whose fingerprint matches the PSBT's inputs. That
   comparison requires reading stored fingerprints, which requires an unlock. A
   pre-PIN stateless signer would therefore give a strictly worse refusal than the
   unlocked one, on the device population most likely to hit it. Shipping a degraded
   refusal path to save an unlock is the wrong trade.

6. **A transient seed may cross the unlock boundary, in one direction only.** When
   `S-19`'s "Save to this device" is taken from the door, `S-04` is **pushed** over
   `S-19`, so the seed stays in the `S-19` state on the stack and is never copied. A
   successful unlock pops to `S-19` and continues to `S-20`. A failed or abandoned
   unlock pops to `S-19` with the seed intact. Back from `S-04` to `S-03` drops the
   stack and wipes it, as every stack clear already does
   (`ui.rs::reset`: "each stack entry owns its screen's secrets"). No new copy of the
   seed exists at any point, and no seed is ever moved onto the `Ui`.

---

## 4. Question 3 - the two directions, and no dead end in either

### 4.1 Dice user discovers the wallet features

At `S-19`, which is where they already are and where the choice already lives. The two
cards are equally weighted, side by side, with the storage consequence spelled out in
each - `UX-PATTERNS.md` 1's "fork at the point of consequence". The user has just
finished the backup check and has the words in front of them; that is the moment the
save is worth explaining, and it is the moment `S-19` was designed for.

On the door path the Save card gains one line saying the PIN comes next (section 5.2).
Tapping it leads to `S-04`, then `S-20`, then `S-21`. Nothing is lost and nothing is
retyped.

The wallet features are also visible before that, without being pushed: `S-03` itself
shows a locked device with a name and a lock word, so a door user has seen from the
first screen that this device does more.

### 4.2 Wallet user does not trip over the door

- The door is one card in the lower part of `S-03`, below the identity block and below
  the "Locked / Touch to unlock" line. Reaching for the PIN means touching the body,
  which is still the whole screen minus the two explicit affordances.
- It changes nothing about unlocking. Same tap, same pad, same attempt accounting.
- Its body line answers the wallet owner's only question in the same sentence a dice
  user reads for the opposite reason: "Your stored wallets stay locked."
- A wallet user who wants a dice-only run without leaving their unlocked session still
  has the original route: `S-10` -> "New wallet" -> `S-11` -> "Roll dice" -> ... ->
  `S-19` -> "Use once, keep nothing". Unchanged.

### 4.3 Neither direction terminates

| From | To | Path |
|---|---|---|
| Door -> stored wallet | `S-19` Save card -> `S-04` -> `S-20` -> `S-21` | Seed carried, nothing retyped |
| Door -> exit | `S-26` `Done` -> exit modal -> `S-03` | Nothing written |
| Locked wallet device -> door | `S-03` card | One tap, no PIN |
| Unlocked device -> dice-only run | `S-10` -> `S-11` -> `S-12` -> `S-19` -> Use once | Unchanged from spec |
| Blank device -> everything | `S-09` | Unchanged; `S-09` **is** the door on a blank device |

---

## 5. Question 4 - the copy

### 5.1 The rule this copy is written against

`PIN-MODES.md` states the discipline in one direction: turning the PIN off is a
data-loss event and the modal "must NOT claim the device is becoming less secure. It is
becoming a device that stores nothing, which is the safest state available. Saying
otherwise is false and teaches the wrong instinct."

The door needs the same discipline pointing the other way. **The wallet path must not
be worded as the real product and the dice path must not be worded as the introductory
one.** Concretely, that means the copy may state only mechanism - what runs, what is
written, what stays locked - and may never rank the two paths, in either direction. No
"just", no "only" in a diminishing sense, no "full", no "advanced", no "get started",
no "for beginners". Note that this also forbids the flattering version: the door must
not say the dice path is safer either, because at the moment of the tap the user has
not made a trade, and `UX-SCREENS.md` 0.4 bans security adjectives as claims outright.

### 5.2 The whole string delta

**Two new literals. One corrected literal. Everything else is reuse.**

New:

| Where | Literal |
|---|---|
| `S-03` door card, body | `"No PIN. Nothing is written. Your stored wallets stay locked."` |
| `S-19` Save card, third line, door path only | `"This device is locked. Saving asks for your PIN first."` |

Corrected:

| Where | From | To |
|---|---|---|
| `S-03` unlock hint | `"Touch anywhere to unlock"` | `"Touch to unlock"` |

Reused verbatim, no new string:

| Where | Literal | Source |
|---|---|---|
| `S-03` door card, heading | `"New seed (dice)"` | `S-09` / 0.1.0 `screens/home.rs` |
| `S-26` door terminal, status line | `"Nothing is written to this device."` | `S-40` |
| `S-26` door terminal, bar action | `"Done"` | `UX-SCREENS.md` 3.1, "Finish a flow" |
| Exit modal on `Done` | `"Go back?"` / `"Going back will clear your current work from this screen."` / `"You can re-enter your dice rolls or seed words to start again."` / `"Cancel"` / `"Go back"` | `ui.rs::EXIT_MODAL` |
| `S-19` both cards | unchanged | `screens/fork.rs` |
| `S-19` footer | `"Either way, your dice rolls or seed words are the backup."` | `screens/fork.rs` |

That the delta is this small is the argument, not a coincidence. If simple mode needed
its own vocabulary, it would be a second product. It is not; it is this product with
one fewer precondition, so it borrows the words this product already uses.

### 5.3 Justification, string by string

**`"New seed (dice)"` (reused).** `UX-SCREENS.md` 3.1: "One label per concept across
the product." The concept is identical to `S-09`'s button and so is the intent, so a
second label for it would fork the vocabulary for no gain. The parenthetical is not
decoration: it is what makes the label accurate for a card that goes straight to `S-12`
and skips `S-11`'s method fork, which the door does deliberately because a dice-only
door has no method to choose. Rejected alternative: `"New seed from dice"` - clearer in
isolation, but a near-duplicate of an existing label is exactly what 3.1 forbids.

**`"No PIN. Nothing is written. Your stored wallets stay locked."` (new).** Three
mechanical facts, in the order the two audiences need them.

- *"No PIN."* States the precondition that is absent. Not "no PIN required", not "no
  PIN needed" - the shorter form is a statement about the device, which is the present
  tense `UX-SCREENS.md` 0.4 asks for, and it fits the line budget in section 6.2.
- *"Nothing is written."* This is the load-bearing sentence and it is deliberately the
  same claim, in the same words, as `S-19`'s Use-once card ("Nothing is written.") and
  `S-40`'s notice ("Nothing is written to this device."). `UX-SCREENS.md` 3.3 item 8
  establishes the pattern: a device-level fact should read the same everywhere it
  appears, so it reads as a property of the device rather than as per-screen
  boilerplate.
- *"Your stored wallets stay locked."* Addresses the wallet owner in the same sentence
  the dice user reads. It is a mechanism statement, not a reassurance: the door does
  not unlock anything, so the wallets are locked, and the sentence says so. It is also
  the only place the door acknowledges stored wallets exist, and it does so without
  saying how many, which keeps Q2(a) intact.
- Not present, deliberately: any adjective. No "safe", no "secure", no "private", per
  `UX-SCREENS.md` 0.4 and section 6's banned-word inventory.

**`"Touch to unlock"` (corrected).** "Anywhere" stops being true the moment the body
carries a second affordance, and `UX-REVISION.md` B4 already puts a real target on
`S-03` independently of this work. `UX-REVISION.md` A9 settled the principle on `S-05`:
a near-true line is worse than a shorter true one, and "shipping the near-miss is
exactly the failure mode this revision pass exists to prevent". The `"Locked"` heading
above it is unchanged.

**`"This device is locked. Saving asks for your PIN first."` (new).** Direct precedent:
`S-20` already specifies "If no PIN exists yet, tapping Save routes through S-06/S-07
first and the button label reads 'Set a PIN and save'." This is the symmetric case, and
it uses the same shape - state the device condition, then state what the next tap does.
Second person for the instruction, present tense for the device state
(`UX-SCREENS.md` 0.4). It is a third line on the existing card, not a warning band: no
danger is present, only a step the user has not seen yet.

**The exit modal (reused).** `ui.rs::EXIT_MODAL` already says the right thing - work on
this screen will be cleared, and dice rolls or seed words bring it back. Writing a
door-specific farewell would add a string to say what an existing string says.

### 5.4 The words that must never appear on screen

Add to `UX-SCREENS.md` section 6's string-inventory banned list, as whole words,
case-insensitive: `simple`, `beginner`, `basic`, `advanced`, `easy`, `expert mode`,
`full mode`, `wallet mode`, `dice mode`. Verified 2026-08-18 against
`crates/notyas-*/src`: none of these occurs in any current on-screen literal, so the
rule can land with the door and cost nothing.

The rule exists because this is the failure mode the feature invites. The moment a
string calls one path "simple", the other becomes "not simple", and the product has
told the user that the configuration `PIN-MODES.md` calls "the safest state the
hardware can be in" is the one for people who cannot handle the real thing. The name
"simple mode" is fine in this document, in the milestone tracker and in a commit
message. It must not reach the panel or the release notes.

---

## 6. Question 5 - which screens change

### 6.1 The change table

| Screen | Change | Kind |
|---|---|---|
| `S-03` Lock screen | Gains the door card, one corrected line, a revised body arrangement at both geometries | **Modified** |
| `S-19` Keep or save | Save card gains a third line and a route to `S-04` when the device is locked | **Variant of an existing screen** |
| `S-26` Export public keys | On the door path, the bar's right slot carries `Done`; a status line reuses `S-40`'s sentence | **Variant of an existing screen** |
| `S-12` Dice entry | On the door path only, the bar's right slot carries the existing `NetToggle` | **One region, existing component** |
| `S-09`, `S-13`, `S-15`, `S-16`, `S-17`, `S-20`, `S-21`, `S-40`, `S-44` | None | Unchanged |
| Any new screen | None | Zero |

New `RegionId` variants: **none**. The door reuses `HomeNewSeed`. Justification:
`UX-SCREENS.md` section 4's naming rule is that "a variant names the *meaning* of the
tap, never the widget or its position". The meaning is "start a dice seed run" and the
destination is `S-12`; the caller screen already determines the return target and the
session class, which is screen state, not region identity. Adding
`LockDiceDoor` would grow the enum by one variant per entry point, which is the rule's
opposite.

### 6.2 `S-03` Lock screen, full spec

**Purpose.** Unchanged: say which device this is, before the user gives it a PIN. Now
also: offer the one thing this device can do that needs no PIN.

**Enter / Exit.** Unchanged, plus: `HomeNewSeed` -> `S-12`, **pushed**.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
|                                              [   Verify device   ]    |
+----------------------------------------------------------------------+
|                                                                       |
|                            notyas                                     |
|                         "kitchen-desk"                                |
|                                                                       |
|                +-------------------------------+                      |
|                |          your word            |                      |
|                |            ANVIL              |                      |
|                +-------------------------------+                      |
|                                                                       |
|                            Locked                                     |
|                       Touch to unlock                                 |
|                                                                       |
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  |  New seed (dice)                                                |  |
|  |  No PIN. Nothing is written. Your stored wallets stay locked.   |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|                  version 0.2.0 - storage present                      |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** A genuine rearrangement, not a compression. The body splits into
two columns of `(body.w - gap) / 2`. Left column, top-aligned: `notyas`, the nickname,
the lock-word panel. Right column, top-aligned: `Locked`, `Touch to unlock`, then the
door card bottom-anchored above the footer. The footer stays full width and unchanged
(reflow rule 5).

```
+----------------------------------------------------------------------------+
|                                                    [   Verify device   ]    |
+----------------------------------------------------------------------------+
|                                                                             |
|              notyas                    |            Locked                  |
|           "kitchen-desk"               |       Touch to unlock              |
|                                        |                                    |
|      +---------------------+           |  +------------------------------+  |
|      |     your word       |           |  |  New seed (dice)             |  |
|      |       ANVIL         |           |  |  No PIN. Nothing is written. |  |
|      +---------------------+           |  |  Your stored wallets stay    |  |
|                                        |  |  locked.                     |  |
|                                        |  +------------------------------+  |
|                     version 0.2.0 - storage present                         |
+----------------------------------------------------------------------------+
```

**Height budget.** State it because the screen is already tight and the door has to fit
into what is left. With `Metrics` as built today (`layout.rs::new`) plus
`UX-REVISION.md` A1's `bar` floor:

| Panel | `bar` | `body.h` | Footer band | Usable above footer |
|---|---|---|---|---|
| 720x720 | 80 | 604 | `LINE` + `pad` | 550 |
| 800x480 | 73 (A1) | 368 | `LINE` + `pad` | 314 |

The door card is `HEADING` (42) + two wrapped `BODY` lines (84) + 24 padding = 150 px
at 720x720, where the card spans the content width and the 60-character body wraps to
two lines. At 800x480 the same body wraps to three lines in a half-width column, so the
card is 192 px.

Two layout changes make it fit, and both are stated as rules rather than as constants:

1. **Portrait identity offset.** The identity block's top offset becomes `body.h / 16`
   (from `body.h / 8`). This is the only change to the existing portrait arrangement.
2. **Compression order, if a future string or font makes it not fit.** First collapse
   the lock-word panel to one line (caption and word on the same row, `LINE + 24`
   rather than `2 * LINE + 24`); then reduce the identity block's top offset to `gap`.
   Never drop content and never shrink the card (reflow rule 4).

**Regions.**

| RegionId | Label | Min size | Enabled when |
|---|---|---|---|
| `HomeVerifyDevice` | "Verify device" | bar chip, >= `TOUCH_MIN` after A1 | always |
| `HomeNewSeed` | door card | content width x >= 150 (portrait); column width x >= 150 (landscape) | always |
| `LockWake` | none (the body) | remainder of the body | always |

**Hit-test order and the wake rectangle.** `regions()` pushes the verify chip, then the
door card, then `LockWake`. The crate's region test forbids **any** overlap between
returned rectangles, so `LockWake` must be computed to exclude the card rather than
relying on first-match:

- Portrait: one `LockWake` rect, `Rect::new(0, bar, w, card.y - gap - bar)`.
- Landscape: **two** `LockWake` rects, both carrying the same `RegionId` - the left
  column for its full height above the footer, and the right column above the card.
  Two rectangles with one meaning is exactly what section 4's naming rule permits, the
  two do not overlap so the region test passes, and the region-parity test compares
  `RegionId` sets, which are equal. Without this, the lock word - the element the user
  is meant to read before typing - would sit in a dead zone on the landscape panel.

**Copy.** Section 5.2. `"Locked"` unchanged, `"Touch anywhere to unlock"` becomes
`"Touch to unlock"`, footer unchanged (`storage_word` still yields Q2(a)'s
`present` / `blank`, never a count).

**Masked / shown.** Nothing secret, unchanged. The door adds no field, so
`VERIFY.md` 7.4's pre-PIN governing test is satisfied trivially: the card states
nothing about this unit at all.

**Edge states.**

- `StoreStatus::Unreadable` (both slots fail their integrity check, `S-01` continues to
  `S-03`): the door is **present and fully functional**. This is worth naming as a
  property rather than an edge case - on a device whose storage is damaged, the entire
  dice product still works, because it never touches storage. `R-32` remains the
  answer for the unlock path.
- `StoreStatus::NotProvisioned` (no eFuse key): `S-03` is not reachable, so neither is
  the door. This is load-bearing, not incidental: `S-17`'s distractor generation
  derives from `HMAC_efuse`, and `UX-SCREENS.md` section 8 flags that this "cannot run
  on an unprovisioned device and that path needs specified behaviour". Because
  `StoreStatus::Locked` implies a provisioned key, the door is immune to that open
  path by placement. The blank-device path (`S-09`) still needs its own answer, which
  is that open item's business and not this one's.
- No lock word set: unchanged, the existing panel edge state renders and the door is
  unaffected.

### 6.3 `S-19` Keep or save, door variant

Only the Save card changes, and only when `StoreStatus::Locked`.

```
  +-----------------------------------------------------------------+
  |  Save to this device                                            |
  |  Stored encrypted in a wallet slot. The PIN is the key.         |
  |  You can open it after every power-on without retyping words.   |
  |  This device is locked. Saving asks for your PIN first.         |
  +-----------------------------------------------------------------+
```

- `SaveToDevice` **pushes** `State::Pin` and asks for nothing: the pad is fixed phone
  order (Q35, reversed 2026-08-19) and `UiRequest::PinPad` no longer exists, so PIN
  entry is complete the moment it is entered.
- The PIN screen carries a purpose: unlock-to-save rather than plain unlock. On
  success it pops to `S-19` and immediately advances to `S-20`, rather than resetting
  to `S-10`. The seed never leaves the `S-19` state on the stack (rule 3.3.6).
- On `Back` from `S-04`, the stack clears to `S-03` through the normal path and the
  seed is wiped by the stack drop. No special case.
- Wrong PIN, delay, and wipe behave exactly as they do on any other unlock. The door
  did not change the attempt accounting; only this card, taken deliberately, enters it.
- The Use-once card, the fingerprint line and the footer sentence are unchanged.
- `S-19`'s existing no-free-slot edge state still applies once the store is open: the
  Save card is `Disabled` with "All 8 slots are used. Delete a wallet first." Because
  slot occupancy cannot be known before the unlock, on the door path the card is
  **enabled** and the disabled state is discovered after the PIN, at which point the
  user is on `S-19` with the seed intact and the reason rendered. That is the honest
  ordering: the device does not pretend to know the store's contents from behind a lock,
  which is the same Q2(a) discipline that keeps the count off `S-01` and `S-03`.

### 6.4 `S-26` Export public keys, door terminal

- The bar's right slot (C1) carries `Done`.
- A status line above the actions reads `"Nothing is written to this device."`,
  reusing `S-40`'s literal.
- `Done` raises the exit-confirmation modal, because a derived secret is alive
  (`UX-SCREENS.md` 0.7). The modal is `EXIT_MODAL`, verbatim.
- Confirming the modal performs the UI half of a lock: clear the whole navigation
  stack and show `S-03`. This is the one behavioural addition the modal needs - today
  its confirm always `pop()`s one screen. Give it a two-arm kind (`Back` -> `pop`,
  `End` -> `reset(lock)`) rather than a second modal; the copy is identical and the
  destination is not.
- The card write action (`ExportToSd`) and the QR actions are unchanged and remain
  available - they emit public values only, which is `S-26`'s existing contract.

### 6.5 `S-12` Dice entry, door origin

One region, so a testnet user is not left without a path.

- The bar's right slot carries the existing `NetToggle`, on the door path only.
- Reason: `screens/home.rs` states it plainly - "the network is a pipeline input", and
  everything derived downstream reflects the choice. On every other path the toggle
  lives on the home screen the flow started from. The door has no home screen, so
  without this the door is mainnet-only and a testnet user has to unlock to do a
  thing that needs no unlock, which is the dead end this whole document exists to
  remove.
- Placement on `S-12` rather than on `S-03`: the control belongs where the choice is
  consumed, and `S-03` is a pre-PIN surface where every added control is a liability.
- Everything else about `S-12` is unchanged, including the 80 px key floor, the
  RAW / FIXED control, the strength meter and every string.

### 6.6 State-machine rules, collected

For the implementer, in one place:

1. `S-03` `HomeNewSeed` -> `Outcome::push(State::Dice(DiceState::new()))`.
2. The dice flow's existing `push` / `enter` behaviour is unchanged.
3. `S-19` `SaveToDevice` with `StoreStatus::Locked` ->
   `Outcome::push(State::Pin(PinState::to_save()))`. No request rides with it: the pad
   is fixed (Q35, reversed 2026-08-19) and `UiRequest::PinPad` was deleted with the
   shuffle. `S-19` `SaveToDevice` with no PIN at all is a separate arm and already
   ships - it pushes `State::SetPin` (S-06/S-07).
4. A successful unlock from `PinState::to_save()` pops to `S-19` and advances to
   `S-20`; every other successful unlock resets to `S-10` as today.
5. `S-26` `Done` -> `Nav::ConfirmEnd`; the modal's confirm clears the stack and shows
   `S-03`.
6. No path from the door reaches `S-40`, `S-21`, `S-27` or any store-touching request.

---

## 7. Question 6 - release call

**The door ships in 0.2.0. The persistent toggle ships never.** No hedge.

### Why the door lands now

- **Cost.** One card, one reused region, two new literals, one corrected literal, one
  layout rule per geometry, one two-arm modal kind, one PIN purpose. Every screen it
  reaches is already on the 0.2.0 critical path and is being built regardless.
- **It is a restoration, not a feature.** 0.1.0's entire function is currently gated on
  a credential it does not use. Shipping 0.2.0 that way, and fixing it in 0.3.0, means
  shipping a release in which the product's original identity is the one thing the
  release made harder to reach.
- **It is load-bearing for a claim already in the release material.**
  `COMPETITIVE.md` 10 leads with "three explicit device states with a real path back to
  stateless" and `PIN-MODES.md` calls State 1 "first-class, not degraded". Those are
  defensible today only in the sense that a user can erase the device to get back. The
  door makes the claim true in the ordinary sense, and `COMPETITIVE.md`'s own m13
  claims audit is the thing that will test it.
- **It is the cheapest visible differentiator left on the list.** Nothing in
  `COMPETITIVE.md` section 8's tiers costs this little. No surveyed device offers any
  route to its stateless behaviour from a locked screen, because no surveyed device has
  stateless behaviour and storage both.

### The honest cost

The door is not free of risk, and the risk is `S-03`'s layout. Section 9 records that
`S-03` already overflows at 800x480 today; the door cannot land until that is fixed,
and fixing it changes the committed golden screenshots for that screen at both
geometries. Budget the layout work, not the copy work.

### Why the toggle does not go to 0.3.0

Section 2.3. It is illegal on the device population that wants it and redundant on the
population that could store it. Recording it as deferred invites it back; record it as
closed, with the reasoning, so the next reader does not re-derive the question.

---

## 8. What CI asserts

All at both geometries (`UX-SCREENS.md` section 6, `MILESTONES.md` m4b gates).

- **Region hygiene on `S-03`.** `R-TOUCH` for the door card (>= `TOUCH_MIN`, and in
  practice >= 150 px tall), no overlap between the card, the verify chip and either
  `LockWake` rectangle, nothing out of bounds, at 720x720 and 800x480. This is the test
  that would have caught the existing overflow in section 9.
- **Region parity.** `regions()` on `S-03` returns the same `RegionId` set at both
  geometries, including the landscape case where `LockWake` is emitted twice.
- **Reachability.** A test that taps `HomeNewSeed` from `S-03` and walks the whole door
  to `S-26`, then `Done`, then confirms the modal, and asserts the final screen is
  `ScreenId::Lock`. `tools/uisim` drives the same walk so the door's screens appear in
  `docs/screenshots/ui` at both geometries.
- **The store is untouched.** Over the whole door walk, assert that no `UiRequest`
  requiring the store is emitted and that `StoreStatus` is `Locked` at every step. This
  is rule 3.3.1 made mechanical rather than editorial.
- **Seed survival across the unlock hop.** Tap `SaveToDevice` from a door `S-19`,
  deliver a successful unlock, assert the next screen is `S-20` and the fingerprint it
  shows equals the one `S-19` showed. Then the negative: `Back` from `S-04` lands on
  `S-03` and no state above the floor survives.
- **String inventory.** The two new literals are ASCII, contain no banned word, and are
  in the inventory table. The banned list gains section 5.4's words as whole-word,
  case-insensitive entries.
- **The corrected literal.** Assert `"Touch anywhere to unlock"` appears nowhere in the
  tree, so the near-true version cannot come back through a merge.
- **Golden screenshots.** `tools/ci/check-screenshots.sh` regenerates and demands
  byte-identical output; `S-03` at both geometries and the door's `S-26` terminal are
  part of the set.
- **`tools/ci/check-dashes.sh`** covers this document and every string it specifies.

---

## 9. Defects this work surfaces

Both are pre-existing and neither is caused by the door, but the door cannot land
cleanly over them. Recording them here so they are fixed deliberately rather than
discovered during layout.

**D1. `S-03` already overflows at 800x480.** With `Metrics::new(800, 480)` as built
today (`pad` 26, `gap` 13, `btn` 64, `bar` 64), `screens/lock.rs` lays the body out
top-down from `body.y + body.h / 8` = 124: title to 181, nickname to 236, lock-word
panel to 357, `"Locked"` at 370..412, `"Touch anywhere to unlock"` at 425..467. The
footer is drawn at `m.h - m.pad - LINE` = 412..454. The unlock hint and the footer
overlap by 42 px, and the hint runs 13 px past the panel's usable bottom. Neither is
caught today because both are measured text, not regions, and the region test only sees
regions. The two-column landscape arrangement in 6.2 fixes it; it must land with, or
before, the door. Recommend adding a text-extent assertion for `S-03` alongside the
region assertions, since this class is otherwise invisible to CI.

**D2. `Ui::floor()` returns the stateless home on a locked device.**
`ui.rs::floor()` is `Wallets` when `Unlocked` and `Home` otherwise, so an empty
navigation stack on a locked device would render `S-09`, whose first line is "Nothing
is stored on this device." On a device with a PIN that sentence is false. Today the
path is unreachable because `S-03` is the only floor a locked device ever has and
`LockWake` uses `enter`, not `push`. The door adds a second pushed branch from `S-03`,
which makes the invariant load-bearing rather than incidental. Fix: give `floor()` a
`Locked` arm returning `State::Lock`, and assert it - `floor()` is documented in the
crate as the single answer to "where does Back go when there is nothing behind it", and
a wrong answer there is a false statement about storage, which is the one class of
error this product cannot ship.

---

## 10. Non-goals, and where this goes next

Named so nobody re-derives the omission.

- **A persistent preference of any kind.** Closed, not deferred. Section 2.3.
- **A second home screen, a mode selector, or any screen whose job is to choose
  between the two paths.** The paths are not alternatives to be chosen between; they
  are one flow with one fork at `S-19`.
- **Stateless signing from behind the lock.** Section 3.3, rule 5. Reconsider only if
  `R-01`'s wrong-wallet routing gains a form that works without reading stored
  fingerprints, which it currently cannot.
- **Restore-from-words behind the door (0.3.0 extension point).** It is one additional
  card on `S-03` and zero new screens, because `S-14` and its final-word helper already
  exist. Deliberately out of 0.2.0 because the owner asked for dice-only and because
  each added item costs the simplicity the door exists to provide. Cheap to add, which
  is the reason it is safe to leave out now.
- **A dice receipt on the door path.** `UX-REVISION.md` C1 scopes the receipt chip to
  the mnemonic screen and `S-46` for 0.2.0. If C1 is approved, the door inherits it on
  `S-13` at no extra cost and the door becomes the shortest path in the product from
  power-on to a verifiable, re-derivable artifact. Worth noting when C1 is decided.
- **`S-12` integrity affordances** (`COMPETITIVE.md` G5 / `UX-REVISION.md` C2: the
  roll-distribution histogram and the on-screen SHA256 of the filtered roll string).
  Not a door dependency, but the door makes them more valuable, because the door makes
  `S-12` the first interactive screen many users reach.

---

## 11. Open items for the owner

1. **`S-03` landscape arrangement.** Section 6.2 specifies a two-column body. It is the
   arrangement that fits the budget, but it changes the look of the lock screen on
   board B more than any other change in this document. Confirm, or ask for the
   alternative (single column with the lock-word panel collapsed to one line), which
   fits with less slack and keeps the portrait arrangement's shape.
2. **`NetToggle` on the door's `S-12`** (section 6.5). One region, and the only
   alternative is a mainnet-only door. Confirm it belongs on `S-12` rather than on
   `S-03`.
3. **Restore-from-words behind the door** (section 10). Recommended out for 0.2.0.
   Confirm.
4. **`INDEX.md` entry.** This document is not yet indexed; the fence for this work was
   a single file. Add a row when convenient.
