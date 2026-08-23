# UX-SCREENS.md - notyas 0.2.0 screen specification

Status: PLAN (buildable spec). Companion to `UX.md`, which holds the research, the
flow diagrams and the ten commandments; this file is the thing you build from. Where
the two disagree, UX.md's commandments win and this file has a bug.

Scope: every screen 0.2.0 ships, the reusable components they are made of, the exact
words on them, and the states that are not the happy path. Read with
`plan-0.2.0/ARCHITECTURE.md` (sections 3-5 and 7), `plan-0.2.0/SECURITY.md`
(invariants 2a/2b/7), `PARITY.md` and the 0.1.0 code in `crates/notyas-ui`.

Not in this file: milestone sequencing (`MILESTONES.md`), the embedder protocol shape
(`WALLET-API.md`), open decisions for the user (`OPEN-QUESTIONS.md`). Items marked
`OPEN:` here are mirrored there by the reconciliation pass; items marked `DECISION:`
are calls made in this document with the reasoning attached.

---

## 0. How to read this spec

### 0.1 The layout law (inherited, non-negotiable)

`crates/notyas-ui/src/layout.rs` computes every rectangle from `Metrics`, which is
computed from the display size passed to `Ui::new`. There are no absolute pixel
positions in the crate and 0.2.0 does not introduce any. Two exceptions exist and are
principled: **touch minimums are physical** (fingers do not scale with the panel) and
**QR module scale is an integer** (scanners do not read fractional modules).

Every wireframe below is therefore an *arrangement*, not a coordinate list. The
wireframes are drawn at 720x720 on a fixed character grid:

```
  1 column = 10 px horizontally      (72 columns = 720 px)
  1 row    = 20 px vertically        (36 rows    = 720 px)
```

Each screen states its reflow at 800x480 in words, because that panel is not a scaled
720x720: it is 240 px shorter and 80 px wider, which is exactly the geometry
`Metrics::landscape()` already tests for (`w * 4 >= h * 5`; 800x480 is landscape,
720x720 is not).

### 0.2 Per-screen template

Every screen entry has the same seven parts, in this order:

1. **Purpose** - one sentence, what the user is doing here.
2. **Enter / Exit** - which states lead in, which lead out, and what Back means.
3. **Wireframe (720x720)** and **Reflow (800x480)**.
4. **Regions** - table of `RegionId`, label, minimum touch size, enabled-when.
5. **Copy** - the literal strings. If it is in quotes here, it is in the binary.
6. **Masked / shown** - what is hidden, what is not, and why.
7. **Edge states** - empty, too long, wrong, refused, mid-operation, torn.

### 0.3 Touch and safety constants (new, in `layout.rs`)

```rust
/// Every interactive region's minimum edge, in physical px. Commandment 7.
pub const TOUCH_MIN: i32 = 60;
/// Keypad keys (dice, PIN): 80 px is ~8.9 mm on the 229 PPI panel.
/// 0.1.0's DICE_KEY_MIN generalized; keep the old name as an alias so the
/// 0.1.0 layout tests keep compiling.
pub const KEYPAD_KEY_MIN: i32 = 80;
/// List/card row height floor: a row is a wide target, so height is the constraint.
pub const LIST_ROW_MIN: i32 = 88;
/// Minimum clear space between a destructive confirm and its cancel.
pub const SEPARATION_MIN: i32 = 96;
```

Three mechanical rules, each a CI test at both geometries:

- **R-TOUCH**: no region returned by `Ui::regions()` on any state has an edge below
  `TOUCH_MIN`. (0.1.0 already asserts this for the dice pad; 0.2.0 asserts it for
  every state, including keyboard keys, which keep their documented 40 px floor as
  the single audited exception - a letter key is a self-correcting target, a Sign
  button is not.)
- **R-SEPARATION**: on any screen carrying a `Danger` or hold-to-confirm action, the
  gap between that region and the nearest cancel/back region is >= `SEPARATION_MIN`.
- **R-NOTHROUGH** (no double-tap-through): when screen B replaces screen A without
  an intervening user action (an automatic advance, e.g. quiz word N -> N+1, review
  page -> page, refusal -> next), B's primary action rect must not overlap A's
  primary action rect. Where the natural layout would collide, B moves its primary
  action to the opposite side of the action row for that transition only.

### 0.4 Voice

Plain, factual, short. Rules that are actually enforceable in review:

- Never "Are you sure?". Name the consequence: "Delete 'savings'? The wallet slot is
  erased. Your dice rolls or seed words are the only way back."
- Never a security adjective as a claim ("secure", "safe", "protected", "military").
  State the mechanism instead: "Stored encrypted. The PIN is the key."
- Refusals say what happened, why the device refused, and what to do next, in that
  order, in three sentences or fewer per part.
- Second person for instructions, present tense for device state. "Insert a card."
  / "No card detected."
- Numbers are never rounded in a verification context. Fees, amounts, indices and
  counts are exact.
- ASCII only on screen. The one non-ASCII glyph in the build is U+2022 BULLET
  (`theme::BULLET`), used for masking and for revealed spaces.

### 0.5 Type and unit conventions

| Content | Font role | Rule |
|---|---|---|
| Screen titles | `TITLE` (Sans SemiBold 44) | Home/lock only; other screens use the bar |
| Bar titles, buttons, section heads | `HEADING` (Sans SemiBold 32) | |
| Prose, hints, labels | `BODY` (Sans Regular 32) | hints differ by ink, not size |
| Mnemonic words, digits, wallet names in verification context | `MONO` (Mono Regular 32) | |
| Addresses, xpubs, txids, hex, descriptors, fingerprints | `MONO_SMALL` (Mono Regular 28) | never Sans, ever |
| The lines inside a control that cannot grow | `CAPTION` (Sans Regular 24) | title and hint together, separated by ink; never prose, never a comparand |

**Amended 2026-08-19 - the `CAPTION` role.** The five faces above were the whole palette
until the owner tested S-21 on the 800x480 Elecrow and found every wallet action card
drawing its title and nothing else. The arithmetic, not a preference: four cards have to
fit under the identity card and stay above the 60 px touch floor, which gives each one 88
px of height and 62 px inside it, and `HEADING` over `BODY` is 42 + 42 = 84 px of line box.
No copy edit reaches that - the shortest possible two rows at the ratified sizes are still
84 px - and the 720x720 panel is the same failure with 71 px. The card had been silently
dropping the line that says what the tap costs.

"Hints differ by ink, not size" holds wherever the PAGE owns the height, and every screen
in this document is such a page. It cannot hold inside a control whose height the finger
and the panel own, and that is the whole of this exception: Sans Regular 24, line box 31
px, so a card's title and its hint both fit in 62 px and still separate by ink exactly as
the rule says.

What it is NOT: a smaller body size, or room for more words. Prose stays `BODY`; a screen
with too much text gets less text, and the two strings that overran their cards on the way
here were shortened rather than set smaller ("registered wallets, import a descriptor" ->
"registrations, import one"). And nothing a user compares against another device shrinks -
fingerprints, addresses, xpubs, derivation paths, txids and the device words stay
`MONO`/`MONO_SMALL` at their existing sizes, where a misread character costs money.

Applied at 0.2.0 to S-21's action cards (both lines) and to S-38's status-card detail line,
whose sentence is parked OPEN below pending the finalizer decision and could therefore be
refitted but not reworded. Atlas: `crates/notyas-fonts/src/gen/sans_regular_24.rs`, 17144 B
of bitmap plus a 1164 B glyph table, about 17.9 KiB of flash; rostered in `LICENSE-fonts`.

**Amounts.** BTC, mono, always eight decimals, fractional part grouped 2-3-3 with
spaces (satcomma, spaces rather than commas because a comma is a decimal separator in
half the world): `0.01 234 567 BTC`. Sources: satcomma proposal
(https://bitcoinmagazine.com/culture/satcomma-standard-look-at-bitcoin-this) and the
Bitcoin Design Guide units page
(https://bitcoin.design/guide/designing-products/units-and-symbols/). Fees
additionally show plain sats and sat/vB, since those are the numbers a user compares
against their coordinator.

**Addresses and long keys.** Mono, chunked in groups of 4 separated by a single
space, wrapped by whole groups, never truncated, never ellipsized, never shown
prefix+suffix. Commandment 1: attackers grind lookalikes matching up to 20 hex
characters (https://arxiv.org/abs/2501.16681), so a prefix/suffix check is not a
check. The only permitted abbreviation anywhere in the product is the 8-hex-character
master fingerprint, which is a full value, not a truncation.

**Derivation paths.** Mono, apostrophe for hardened (`m/84'/0'/0'/0/7`), matching
what 0.1.0 already renders and what coordinators print.

### 0.6 The masking law (inherited from 0.1.0, extended)

Two rules, and the difference is who chose the secret.

- **Derived secret -> fixed-run mask.** `theme::mask_word()`, six bullets, identical
  for every word of every mnemonic. Length is information the user never supplied.
  Applies to: mnemonic words, quiz answers before reveal, any derived key material.
- **Typed input -> one bullet per character.** `canvas::field`. The user knows what
  they typed; a fixed run on a field being edited reads as a rendering bug.
  Applies to: passphrase, PIN, typed-name confirmations (unmasked - see below).

0.2.0 additions:

- **PIN uses the typed-input rule** (one bullet per digit) with **no length counter**.
  Honest note, stated here because it is a real tradeoff: a shoulder surfer learns
  the PIN's *length* from the dot count. Every hardware wallet on the market accepts
  this, because hiding your own progress from yourself causes far more entry errors
  than the length leak costs. What the pad used to add - a shuffle, so that the
  positions an observer watched meant nothing on the next attempt - was reversed on
  2026-08-19 (Q35), so nothing on this screen protects the digits from someone who can
  see the hand. That is the trade the owner took, and it is recorded in Q35 in full.
- **Typed-name confirmations are never masked.** The whole point is that the user
  reads back the name of the thing being destroyed.
- **No QR is ever generated from a masked or derived-secret value.** 0.1.0's QR scope
  note holds verbatim: QR targets are public values by construction (addresses,
  xpubs, descriptors, signed PSBTs).
- **Pixel test extension**: two different wallets, same screen, same state must
  produce byte-identical frames wherever a secret is masked. Extended in 0.2.0 to the
  PIN screens, the quiz (pre-reveal), the wallet list (names are user-chosen, so the
  list is NOT covered - see S-10 edge states) and every busy interstitial.

### 0.7 Screen state and secret lifetime

The `State` enum stays closed and exactly-one-state-alive; `Drop` is still the wipe
(`ARCHITECTURE.md` 7). Two 0.2.0 consequences the screens must respect:

- A `WalletSession` outlives screens. It is owned by the `Ui`, not by a `State`, and
  is dropped on: Lock, auto-lock timeout, wipe, delete-of-the-open-wallet, and any
  transition back to the lock screen. Every screen that can be reached with a session
  open shows the **Lock** affordance in the bar (S-21 onward).
- Screens that hold a *screen-local* secret (mnemonic, passphrase, quiz answers)
  keep the 0.1.0 exit-confirmation modal on Back.

---

## 1. Component library

Twelve components. Every screen in section 2 is assembled from these; a screen that
needs a thirteenth needs a design review first.

### C1. TopBar

The 0.1.0 bar (`screens::bar`), extended with a right-hand slot.

```
+----------------------------------------------------------------------+
| < Back   Review transaction                       [ 3 / 7 ]  [ Lock ] |
+----------------------------------------------------------------------+
```

- Left: `Back` ghost button (`RegionId::Back`), or nothing on screens with no back
  (0.1.0's `draw_bar_no_back` rule: never draw an affordance nothing hit-tests).
- Centre-left: title, `HEADING`, `INK_PRIMARY` on `PAPER_2`.
- Right slot, in priority order (at most two chips fit at 800x480):
  1. page counter `[ i / n ]`, mono, non-interactive, on paged screens;
  2. `Lock` (`RegionId::Lock`), secondary chip, on every session screen.
- Height `Metrics::bar`; the hairline under it is `BORDER`.

Back semantics table (applies everywhere; a screen only documents deviations):

| Situation | Back does |
|---|---|
| Read-only screen | pops to the prior state immediately |
| Screen holding a screen-local secret | opens the 0.1.0 exit modal first |
| Mid-review of a PSBT | opens a confirm: "Leave this transaction? Nothing is signed." |
| Mid-quiz | opens a confirm: "Leave backup check? You will start from word 1." |
| Busy (C3) | not present; the operation is not cancellable, or it offers Stop |

### C2. ListView

One scrollable column of rows. Used by: wallet list, address list, SD file picker,
multisig registry, settings.

```
+----------------------------------------------------------------------+
| savings                                              single-sig  >    |
| a1b2c3d4  m/84'/0'/0'                            backup verified      |
+----------------------------------------------------------------------+
```

- Row height >= `LIST_ROW_MIN` (88), hairline separated, `PAPER_2` on `PAPER_1`,
  pressed state `PAPER_TINT`.
- Row anatomy: line 1 primary (`HEADING`) + right-aligned type badge; line 2
  secondary (`MONO_SMALL`, `INK_SECONDARY`) + right-aligned status badge.
- Rows are `RegionId::ListRow(u8)` (index within the visible page).
- **Scrolls** if the list is homogeneous reference material (addresses, files);
  **pages** if the rows must each be considered (never used in 0.2.0 - all lists are
  reference material). See C6.
- Long list: drag-scroll (0.1.0's `scroll_by`) plus, when content exceeds two
  viewports, an explicit `[ Older ]` / `[ Newer ]` pair - drag alone is undiscoverable
  on a device with no scrollbar. Address lists use index paging instead (S-22).
- **Empty state is a first-class row**, never a blank panel: an inset well with one
  factual line and, where an action exists, one primary button (see each screen).

### C3. Busy (the interstitial pattern)

0.1.0 learned this the hard way: a blocking derivation with no painted frame is
indistinguishable from a crash. The generalization of `ScreenId::Deriving`.

**Law (enforceable in review):** any operation that can block the input loop for more
than 150 ms paints a Busy frame *and publishes it to the panel* before the work
starts. The frame is painted by the state transition; the work runs in
`Ui::tick(elapsed_ms)`.

```
+----------------------------------------------------------------------+
|          Deriving                                                     |
+----------------------------------------------------------------------+
|                                                                       |
|             +------------------------------------------+             |
|             |            Deriving keys                 |             |
|             |                                          |             |
|             |  2048 rounds of PBKDF2, then every       |             |
|             |  scheme.                                 |             |
|             |                                          |             |
|             |  [########################          ]    |             |
|             |  step 3 of 4 - 6 s elapsed               |             |
|             |                                          |             |
|             |  This cannot be cancelled.               |             |
|             +------------------------------------------+             |
|                                                                       |
+----------------------------------------------------------------------+
```

Contents, in order:

1. Gerund heading: what is happening ("Deriving keys", "Reading card", "Checking
   transaction", "Signing", "Writing to card", "Searching addresses").
2. One or two mechanical lines: what the device is actually doing. No reassurance.
3. Progress, one of exactly two kinds:
   - **Determinate** where the work has countable units: a filled trough (reuse
     `canvas::strength_meter` geometry with `ACCENT` fill) plus "step i of n".
     Countable in 0.2.0: scheme derivation (4 schemes), signing (i of n inputs),
     address search (i of 1528), QR encoding (i of n fragments), quiz progress.
   - **Indeterminate**: elapsed seconds, ticking at 1 Hz ("14 s elapsed"). Never a
     fake percentage, never a spinner the repaint model cannot animate honestly.
4. Exactly one of these trailing lines:
   - `"This cannot be cancelled."` - single blocking primitive (KDF, seal/unseal).
   - `"Do not remove the card."` - a write is in flight. Only then.
   - `"Do not power off."` - a flash write is in flight. Only then. 0.1.0 says this
     during pure computation, which is false and trains people to ignore it;
     **DECISION:** the derivation Busy screen drops "Do not power off" and says
     "This cannot be cancelled" instead. Power loss during pure computation costs
     nothing but the computation.
   - `[ Stop ]` (`RegionId::BusyStop`, secondary, >= TOUCH_MIN) where the loop can
     check between units: address search, batch signing between PSBTs, QR playback.
     A stopped operation returns to the screen that launched it with a status line
     ("Search stopped at index 412 of 1528."), never to a blank state.
5. No Back in the bar. No other regions. A Busy screen with a live Back is a lie
   about what the loop can do.

**Repaint budget**: Busy is the only screen class allowed to repaint on a timer, and
it repaints at most 1 Hz (plus once per completed unit). The QR player (C11) and
hold-to-confirm (C4c) are the other two animated surfaces; everything else keeps the
0.1.0 "zero repaints outside an active animation" property.

### C4. Confirmation grades

One component (`ui::modal`), three grades, one visual grammar. Grade is chosen by
consequence, per commandment 2.

**C4a. Yellow card - reversible.** Overwriting an SD file, discarding entered rolls,
leaving a review. Panel `PAPER_3`, 2 px `WARNING` frame, title + one or two lines,
`[ Cancel ]` ghost left, `[ <verb> ]` primary right, gap >= `SEPARATION_MIN`.

**C4b. Red card - destructive but recoverable-by-backup.** Wiping session state,
early wipe, removing a multisig registration. Same shape, 2 px `DANGER` frame,
`Danger` confirm button, and a mandatory consequence line naming what is destroyed
and what the recovery path is.

**C4c. Hold-to-confirm - irreversible-in-effect.** Signing, factory wipe. The button
is not tappable; it fills over 1500 ms while held.

```
+----------------------------------------------+
|  Hold to sign                                |
|  [############################        ]      |
|  Keep holding - 0.6 s of 1.5 s               |
+----------------------------------------------+
```

- Region `RegionId::HoldConfirm`, minimum 120 px tall and >= 60% of body width.
- Fill is `ACCENT` for sign, `DANGER` for wipe, over `PAPER_0` trough.
- Release before completion: fill resets to zero immediately, the label returns to
  "Hold to sign", and a `INK_SECONDARY` line reads "Released - nothing was signed."
  (or "- nothing was erased."). No modal, no scolding.
- Drag off the region while holding: same as release.
- Driven by `Ui::tick(elapsed_ms)` plus press age from the touch layer; requires the
  horizontal-slop fix listed in `ARCHITECTURE.md` 7.
- **DECISION:** hold duration is a constant, not a setting. A user-shortenable hold
  is a user-shortenable safety interlock.

**Implementation gap, noted 2026-08-19.** `crates/notyas-ui/src/danger.rs` implements
three of these four grades - `DangerGrade::{Confirm, Hold, Typed}`, mapped by their own
constructors to C4b, C4c and C4d. C4a has no variant, so every reversible confirmation in
the tree is built at C4b and wears the red card. Recorded as K23 in `docs/KNOWN-ISSUES.md`,
which also states why closing it is a decision rather than a patch. No fourth variant has
been invented here.

**C4d. Typed-name - destructive and unrecoverable-on-device.** Delete wallet, factory
wipe, PIN change confirmation of the old-ciphertext erase.

```
+----------------------------------------------------------------------+
| Delete wallet "savings"                                               |
|                                                                       |
| This erases the stored wallet slot and its multisig registrations.    |
| Your dice rolls or seed words are the only way back.                  |
|                                                                       |
| Type the wallet name to confirm:                                      |
| +------------------------------------------------------------------+ |
| | savin_                                                           | |
| +------------------------------------------------------------------+ |
| (unmasked, exact match, case sensitive)                               |
|                                                                       |
| [ Cancel ]                                       [ Delete wallet ]    |
+----------------------------------------------------------------------+
```

- The confirm button is `Disabled` until the typed text matches exactly, and the
  disabled state carries its reason beside it - never a silent dead button (0.1.0's
  `ButtonKind::Disabled` contract): "Name does not match yet."
- Field is `canvas::field` with `masked: false`.
- Keyboard is the existing on-screen keyboard, letters page first.
- For device-level destruction where there is no name to type, the required word is
  `WIPE` (uppercase, stated on screen).

### C5. PagedReview

The enforced-traversal pattern. Used by: PSBT review, multisig cosigner review,
oversized address/xpub review, backup quiz (a degenerate case).

- Content is split into an ordered page set computed once when the review opens. The
  set never changes mid-review (a re-parse restarts the review from page 1).
- Bar shows `[ i / n ]`. Bottom action row: `[ < Prev ]` ghost, `[ Next > ]` primary.
- The terminal action (Sign, Approve, Done) **does not exist as a region** until
  every page has been visited. Until then the last page shows a `Disabled` button
  with its reason: "Review all 7 pages first - 2 not yet seen."
- Visited-set is per-review state, not per-page-index arithmetic: jumping back and
  forth is fine, skipping is not.
- No timer ever advances a page. No swipe-to-page (a swipe is indistinguishable from
  a scroll on a resistive-feeling capacitive panel and users overshoot); paging is
  buttons only. Vertical drag inside a page scrolls that page's overflow.
- **DECISION:** page order is fixed and semantic - overview (if any), inputs,
  outputs, fee, warnings - never sorted by amount or by "interesting first".
  A stable order is what lets a user compare two runs of the same transaction.

### C6. Scrolling vs paging (the convention)

| Content kind | Mechanism | Why |
|---|---|---|
| Must be *considered* item by item | Paged (C5) | traversal is enforceable |
| Reference lists (files, addresses, settings) | Drag-scroll + explicit pager when > 2 viewports | fast to skim, nothing to enforce |
| A single value too tall for the viewport (xpub, descriptor, quiz word list) | Drag-scroll within the page | it is one thing, not many |
| A single *verification* value too long for the viewport at minimum legible size | Split into "part i of n" pages with traversal enforced | an unread address is an unverified address |

Scroll affordance: when a screen's content exceeds its viewport, the last visible
line is followed by a `INK_MUTED` hairline and a centred `MONO_SMALL` "more below"
marker; when scrolled, "more above". 0.1.0 has no marker and users on the schemes
screen do not know there is more - fixed here.

### C7. Refusal

The screen the signing pipeline shows when it will not proceed. Commandment 10: same
design care as a success screen.

```
+----------------------------------------------------------------------+
| < Back   Refused                                                      |
+----------------------------------------------------------------------+
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  |  Missing the previous transaction                       R-02    |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|  What happened                                                        |
|  Input 2 states an amount but does not include the transaction        |
|  that amount came from.                                               |
|                                                                       |
|  Why this matters                                                     |
|  Without it the amount cannot be checked. A wrong amount is how a     |
|  signer is tricked into paying its whole balance as a fee.            |
|                                                                       |
|  What to do                                                           |
|  Re-export this transaction from your wallet software with full       |
|  previous transactions included, then load it again.                  |
|                                                                       |
|  [ Show details ]                                    [ Back to sign ] |
+----------------------------------------------------------------------+
```

- Header band: `DANGER_TINT` fill, `DANGER` hairline, headline `HEADING` in
  `INK_PRIMARY`, refusal code right-aligned `MONO_SMALL` `INK_SECONDARY`.
- Three fixed sections: **What happened** (facts about this file), **Why this
  matters** (the attack or fault it defends against, one or two sentences), **What to
  do** (the user's next action). Any refusal that cannot fill all three is
  under-specified and does not ship.
- `[ Show details ]` (`RegionId::RefusalDetails`) toggles a mono block with the
  machine facts: input/output index, txid, claimed path, script type, the policy
  check number from `ARCHITECTURE.md` 5.3. This is what gets photographed for a bug
  report, so it is mono, complete, and it never contains key material.
- Refusal codes are stable across releases and asserted in CI with their exact text
  (`MILESTONES.md` m6 gate). Table in section 3.2.
- A refusal is never a modal. It is a screen, because it needs the space and because
  a modal invites dismiss-without-reading.

### C8. MonoValue (the full-value block)

One caption plus one long value, plus optional QR button. Evolves 0.1.0's `qr_block`.

- Value chunked in 4s, wrapped by whole groups, `MONO_SMALL` by default and `MONO`
  when the value is the *subject* of the screen (address detail, cosigner review).
- Group index gutter when the value exceeds two lines: each line is prefixed with the
  character offset of its first group in `INK_MUTED` mono (`00`, `24`, `48`). This is
  what makes "read it back to me" possible over the phone and what makes two devices
  comparable line by line.
- `[ QR ]` button (96x56, existing) top-right of the block when the value is public.
- Never truncates. If it does not fit, the screen scrolls (C6) or pages (C5); the
  block itself has no ellipsis path at all.

```
  Receive address                        m/84'/0'/0'/0/7        [ QR ]
  00  bc1q xy2k gdyg jrsq tzq2 n0yr f249 3p83
  32  kkfj hx0w lh
```

### C9. Keyboard + word completion

0.1.0's four-page ASCII keyboard, unchanged, plus the existing BIP39 suggestion strip
(`RegionId::Suggest(u8)`, four chips). 0.2.0 additions:

- **Final-word helper** on restore: when 11 (or 23) valid words are entered, the strip
  switches to showing only checksum-valid candidates for the last word, with the
  heading "Valid last words". This is a public-wordlist computation over the user's
  own input, the same category as the existing prefix completion.
- **Word counter** in the well header: "word 7 of 12" (`MONO_SMALL`, `INK_SECONDARY`).
- Keys keep the audited 40 px row floor; Done/Backspace/Shift keep >= `TOUCH_MIN`.

### C10. Keypad (fixed phone order)

The PIN pad, used by S-04 and by S-06/S-07. Ten digit keys plus backspace plus a
commit key.

- **Layout is fixed and identical everywhere**: 1-2-3 / 4-5-6 / 7-8-9 with 0 centred
  on the last row, the arrangement every telephone and cash machine has taught. It is
  a constant in the UI crate, not a value the embedder supplies, so a device draws it
  correctly with nothing installed and the two PIN screens cannot disagree about where
  a digit is.
- **The two cells flanking the 0 are controls, never digits** - commit on the left,
  backspace on the right - and they never move. A key that spends an attempt, or that
  formats the device, must not sit where a finger aims for a digit.
- **Touch-down highlight must not reveal position**: the pressed state is drawn on
  the *dot row*, not on the key. The key itself does not change appearance on press.
  This is the one place in the product where a control gives no local press feedback,
  and it is deliberate. It survives the reversal below on a different argument than
  the one it was written with: on a fixed pad a lit 80 px cell IS the digit, legible
  across a room, in a window reflection and in a camera frame where the hand covers
  the glyph but not the border.
- Keys >= `KEYPAD_KEY_MIN` (80 px) each.
- Digits are `MONO`.

**REVERSED 2026-08-19 (OPEN-QUESTIONS Q35).** As specified and as shipped at m4a, this
control reshuffled the ten digits on every entry attempt - never per keystroke, because a
pad that moves under the finger causes mistaps - from `HMAC_efuse(domain ||
attempt_counter || seal_seq)` truncated to a Fisher-Yates index stream, which kept
invariant 3 (no RNG anywhere) mechanically checkable. The project owner used it on
hardware and reversed it, accepting in writing that a fixed pad means one clear look at
the hand yields the PIN. Q35 records the trade, what was given up and why the decision was
his to make. The whole derivation was then deleted - the request, the setter, the vault
method and its HKDF info string - because a derivation nothing uses is a claim the source
no longer supports.

### C11. QrPlayer (animated)

Used only for delivering signed PSBTs and large exports (`ur:crypto-psbt`).

```
+----------------------------------------------------------------------+
| < Back   Signed transaction                          [ frame 7 / 24 ] |
+----------------------------------------------------------------------+
|                    +----------------------------+                    |
|                    |                            |                    |
|                    |        (QR symbol)         |                    |
|                    |                            |                    |
|                    +----------------------------+                    |
|                                                                       |
|  [ Pause ]   [ Slower ]  [ Faster ]   [ Smaller ]  [ Bigger ]         |
|  6 frames/s - 200 bytes per frame - fountain encoded, loops forever   |
|                                                                       |
|  [ Also write to card ]                              [ Done ]         |
+----------------------------------------------------------------------+
```

- Symbol drawn at the largest integer module scale that fits, 4-module quiet zone
  (0.1.0's QR modal math, reused verbatim).
- Controls: pause/resume, three speed steps (3 / 6 / 12 fps), three density steps
  (100 / 200 / 400 bytes per fragment). Every control >= `TOUCH_MIN` and labelled
  with words, not icons.
- Status line states the current fps, fragment size, and that the sequence is a
  fountain code that repeats indefinitely - because the single most common support
  question is "I missed a frame".
- Frame counter in the bar right slot.
- Repaint is tick-driven; pausing stops repaints entirely (the "zero repaints outside
  an active animation" claim survives).
- A single-frame payload (small PSBT, an xpub) renders as a static symbol with no
  controls and the status line "single frame".

### C12. WriteNotice

Invariant 2b: every write to flash or SD is announced on screen *before* it happens.
An inline band, not a modal, placed directly above the action that triggers the write.

```
  +------------------------------------------------------------------+
  |  This writes to the card: psbt-signed.psbt (2.4 kB)               |
  |  Nothing secret is written. Anyone with the card can read it.     |
  +------------------------------------------------------------------+
```

- `PAPER_0` fill, `BORDER_STRONG` hairline, `MONO_SMALL` for the artifact name.
- Flash variant: "This writes to the device: wallet slot 2 (encrypted). The PIN is
  the key."
- Second line always states the confidentiality of the artifact in plain terms.
  Exported xpubs get: "This is not a secret key, but it reveals every address this
  wallet will ever use to anyone who reads the card."

---

## 2. Screens

Numbering `S-nn` is this document's; the parenthesised number maps to `UX.md`
section 3's inventory. (E) evolves a 0.1.0 screen, (N) is new.

### 2.0 Inventory

| # | Screen | Kind | Components |
|---|---|---|---|
| S-01 | Boot / self-test | E | C3 |
| S-02 | Self-test failed | N | - |
| S-03 | Lock screen | N | - |
| S-04 | PIN entry | N | C1, C10 |
| S-05 | PIN delay | N | C3 |
| S-06 | PIN create | N | C10 |
| S-07 | PIN confirm | N | C10 |
| S-08 | Change PIN | N | C10, C12, C3 |
| S-09 | Stateless home | E | - |
| S-10 | Wallet list | N | C1, C2 |
| S-11 | New wallet: method | N | C2 |
| S-12 | Dice entry | E | - |
| S-13 | Mnemonic display | E | C4b |
| S-14 | Restore: word entry | E | C9 |
| S-15 | Passphrase | E | C9 |
| S-16 | Deriving | E | C3 |
| S-17 | Backup check (quiz) | N | C5 |
| S-18 | Restore result / fingerprint | N | C8 |
| S-19 | Keep or save | N | C2 |
| S-20 | Name and save | N | C9, C12 |
| S-21 | Wallet home | N | C1, C2 |
| S-21b | Passphrase unlock | N | C3, C9 |
| S-22 | Receive / address list | E | C2 |
| S-23 | Address detail | E/N | C8 |
| S-24 | Check an address (input) | N | C9 |
| S-25 | Check an address (result) | N | C8 |
| S-26 | Export public keys | E | C8, C12 |
| S-27 | Sign: source | N | - |
| S-28 | SD file picker | N | C2 |
| S-29 | Refusal | N | C7 |
| S-30 | Review: overview | N | C5 |
| S-31 | Review: input page | N | C5, C8 |
| S-32 | Review: output page | N | C5, C8 |
| S-33 | Review: unusual output | N | C5 |
| S-34 | Review: fee / locktime | N | C5 |
| S-35 | Review: warnings | N | C5, C4c |
| S-36 | Hold to sign | N | C4c |
| S-37 | Signing | N | C3 |
| S-38 | Deliver | N | C12, C4a |
| S-39 | Signed QR | N | C11 |
| S-40 | Stateless signing entry | N | C2, C4b |
| S-41 | Multisig registry | N | C2 |
| S-42 | Multisig import review | N | C5, C8 |
| S-43 | Multisig detail | N | C2, C4d |
| S-44 | Settings | N | C2 |
| S-45 | Wallet settings | N | C2, C4d |
| S-46 | Verify device | E | C6 |
| S-47 | Delete wallet | N | C4d |
| S-48 | Erase this device | N | C4d, C4c |
| S-49 | Auto-lock warning | N | C4a |

### 2.1 Boot, lock and PIN

---

#### S-01 Boot / self-test (E, UX 1)

**Purpose.** Show the device proving itself before it is used, and land on the right
home screen for the storage state.

**Enter / Exit.** Power on -> S-01. Exits automatically on success: to S-09 (stateless
home) when no PIN is set, to S-03 (lock) when storage holds a PIN. On failure ->
S-02, which is terminal.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
|                                                                       |
|                            notyas                                     |
|                          version 0.2.0                                |
|                                                                       |
|      +-----------------------------------------------------------+    |
|      | BIP-39 vectors ................................ pass      |    |
|      | BIP-32 vectors ................................ pass      |    |
|      | Signing known-answer .......................... pass      |    |
|      | Seal / unseal known-answer .................... pass      |    |
|      | Radio held in reset (GPIO54 low) .............. pass      |    |
|      | Storage ....................................... 2 wallets |    |
|      +-----------------------------------------------------------+    |
|                                                                       |
|                     [#################          ]                     |
|                     checking 4 of 6                                   |
|                                                                       |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Same single column; the check list is the only content and it
fits. If a future check list overflows, it scrolls (C6) - it must never be truncated,
because "the check you did not see" is exactly the one that matters.

**Regions.** None while running (C3 rules: no Back on a Busy screen). This screen is
a Busy variant with a determinate meter.

**Copy.** Rows are `<check name> <leader dots> <result>`; results are `pass`,
`FAIL`, or a value (`2 wallets`, `blank`). Storage row text: `"blank"`,
`"1 wallet"`, `"N wallets"` - subject to `OPEN-QUESTIONS` Q2: if duress ships, this
degrades to `"present"` / `"blank"` and this spec's S-01 and S-46 change together.

**Masked / shown.** Nothing secret is on this screen. Wallet *names* are not shown at
boot (pre-PIN); only the count.

**Edge states.**
- A check fails -> the row turns `DANGER`, the run continues to the end (a user
  deserves the whole picture), then S-02.
- Storage present but unreadable (both slots invalid) -> row reads
  `"storage: unreadable"` in `WARNING` and boot continues to S-03; the PIN screen
  then surfaces R-32 (section 3.2) rather than pretending there is a wallet.
- Boot on a scaffold board -> an extra `WARNING` band under the list: "This board is
  not hardware-verified. Displays and touch may be wrong." (0.1.0 behaviour kept.)

---

#### S-02 Self-test failed (N)

**Purpose.** Stop. A device that failed its own arithmetic must not be used to hold
money, and must say so in a way that cannot be tapped away.

**Enter / Exit.** From S-01 on any `FAIL`. **There is no exit.** No region on this
screen leads anywhere except S-46-style detail; recovery is a power cycle or a
reflash. This is the only screen in the product with no forward path.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  |                        SELF-TEST FAILED                         |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|  Do not use this device to hold bitcoin.                              |
|                                                                       |
|  Failed check                                                         |
|  BIP-32 vectors: derived key does not match the published test        |
|  vector at m/0'/1.                                                    |
|                                                                       |
|  What this means                                                      |
|  This firmware computes keys incorrectly on this hardware. Any        |
|  address it shows could be wrong, and any signature could be          |
|  invalid.                                                             |
|                                                                       |
|  What to do                                                           |
|  Power off. Re-flash a verified firmware image and check its SHA256   |
|  against the signed release list. If it fails again, the hardware     |
|  is at fault.                                                         |
|                                                                       |
|  App SHA256                                                           |
|  3f9a...  (full 64 hex, mono, wrapped)                                |
|                                                                       |
|  [ Show all checks ]                                                  |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Two columns: verdict + failed check left, what-to-do + hashes
right. The header band stays full width.

**Regions.**

| RegionId | Label | Min size | Enabled when |
|---|---|---|---|
| `SelfTestDetails` | "Show all checks" | 200x`TOUCH_MIN` | always |

**Copy.** Header is the only all-caps string in the product; it is a stop sign and
it earns the shout. "Do not use this device to hold bitcoin." is verbatim.

**Masked / shown.** Full app SHA256 shown (it is the identity of the broken build and
the thing a bug report needs). No storage contents are read or shown; a failed
self-test never unlocks anything.

**Edge states.** Multiple failures: the headline names the count ("3 checks failed"),
the body lists each with its own three-part explanation, and the page scrolls.

---

#### S-03 Lock screen (N, UX 16)

**Purpose.** Say which device this is, before the user gives it a PIN.

**Enter / Exit.** From S-01 (storage present), from Lock anywhere, from auto-lock
timeout. Touch anywhere -> S-04.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
|                                                                       |
|                                                                       |
|                            notyas                                     |
|                                                                       |
|                          "kitchen-desk"                               |
|                                                                       |
|                            Locked                                     |
|                                                                       |
|                                                                       |
|                    Touch anywhere to unlock                           |
|                                                                       |
|                 version 0.2.0 - 2 wallets stored                      |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Identical, vertically compressed. One centred column on every
shipped panel: the second arrangement this screen used to need existed only to fit the
lock-word panel beside the identity, and went with the panel (Q64, 2026-08-19).

**Regions.**

| RegionId | Label | Min size | Enabled when |
|---|---|---|---|
| `LockWake` | (whole screen) | full screen | always |
| `HomeVerifyDevice` | "Verify device" (bar chip, top right) | 200x`TOUCH_MIN` | always |

Verify device is reachable *before* PIN entry, deliberately: commandment 4 says the
device authenticates itself first, and a user who suspects a swap must be able to
check the firmware hash without typing a digit into it.

**Copy.** The device NAME is user-chosen (Settings row -> S-44a), shown in quotes,
mono. "Locked". "Touch anywhere to unlock". Footer: version and storage state.

**One pre-PIN string, and it makes no claim (Q64, 2026-08-19).** This screen used to
show two user-set strings: the name, and a "lock word" whose panel told the user it let
them tell this device from a fake. The word is deleted. Anything drawn here is readable
by whoever is holding the device, including whoever would build the counterfeit, so no
string on this screen may be described as anti-swap evidence - the claim belongs to
S-04's derived word pair, which a counterfeit cannot compute, and is taught by S-04a.
The name is a label and is drawn as one.

**Masked / shown.** The name is shown in the clear. It is not a secret and the screen
does not treat it as one; what an attacker learns from it is the name.

**Edge states.**
- No name set (the state every device ships in): the row reads "no name set", with no
  instruction and no promise attached to it.
- Storage unreadable: footer reads "storage unreadable" in `WARNING`.
- Q2 duress accepted: footer degrades to "storage present" (see S-01).

---

#### S-04 PIN entry (N, UX 2)

**Purpose.** Authenticate the user, after the device has authenticated itself.

**Enter / Exit.** From S-03. Correct PIN -> C3 Busy ("Unlocking") -> S-10 wallet list.
Wrong PIN -> stays here with the counter decremented and, above a threshold, S-05.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Enter PIN                                                    |
+----------------------------------------------------------------------+
|                                                                       |
|         * * * * o o o o o o o o                                       |
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  |  Device words:  ANVIL  MERCURY                                  |  |
|  |  Wrong words? Stop. This may not be your device.                |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|  +----------+  +----------+  +----------+                             |
|  |    7     |  |    2     |  |    9     |                             |
|  +----------+  +----------+  +----------+                             |
|  +----------+  +----------+  +----------+                             |
|  |    4     |  |    0     |  |    6     |                             |
|  +----------+  +----------+  +----------+                             |
|  +----------+  +----------+  +----------+                             |
|  |    1     |  |    8     |  |    3     |                             |
|  +----------+  +----------+  +----------+                             |
|  +----------+  +----------+  +----------+                             |
|  |   abc    |  |    5     |  | Backspace|                             |
|  +----------+  +----------+  +----------+                             |
|                                                                       |
|  9 of 10 tries left                          [      Unlock      ]     |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Landscape split: dot row, device-words panel and attempt line in
the left column; the 3x4 pad in the right column at `KEYPAD_KEY_MIN`. Unlock sits
under the pad, `SEPARATION_MIN` clear of the last key row.

**Regions.**

| RegionId | Label | Min size | Enabled when |
|---|---|---|---|
| `PinKey(u8)` (x10) | digit, fixed phone order | 80x80 | always |
| `PinBackspace` | "Backspace" | 80x80 | length > 0 |
| `PinAlpha` | "abc" | 80x80 | always (switches to C9 keyboard for alphanumeric PINs) |
| `PinShowWords` | "Show device words" | 260x`TOUCH_MIN` | length >= 4, words not yet shown |
| `PinSubmit` | "Unlock" | 260x`Metrics::btn` | length >= 6 (Q5 floor) |
| `Back` | "< Back" | bar | always -> S-03 |

**Copy.**
- Bar title "Enter PIN" (unlock) / "Enter PIN" (confirm-before-destructive), never
  "Please enter your PIN".
- Words panel before the prefix is long enough: `[ Show device words ]` with the hint
  "Available after 4 digits. Seeing them costs no attempt."
- Words panel after: "Device words: ANVIL MERCURY" and, on the second line,
  "Wrong words? Stop. This may not be your device."
- Attempt line: "9 of 10 tries left". At <= 3: `WARNING` ink and the fuller sentence
  "3 tries left. At 0 the device erases its stored wallets; your dice rolls or seed
  words are the only way back."
- Wrong PIN: the dot row clears and a `DANGER` line appears under it - "Wrong PIN."
  The pad does not change; it never does (C10, reversed 2026-08-19).
- Submit disabled reason: "A PIN is at least N characters.", where N is the live
  floor the store formats at - never a literal (Q4 ratified 4; Q37 requires every
  number on a PIN screen to be a format over runtime policy).

**Masked / shown.** One bullet per typed character, unmasked count implied (see 0.6).
There is no reveal toggle on the PIN field - a PIN is short, retypeable, and shoulder
surfing is the threat this screen exists for. The device words are shown in the clear
by design.

**Edge states.**
- Length cap 64 characters (Q5); at the cap, further keys are ignored and the hint
  reads "Maximum length reached."
- Words requested with a prefix that is not any real prefix: the device shows words
  anyway (derived from whatever was typed). It must, or the words themselves become
  an oracle for prefix correctness. Hint line unchanged.
- Attempt counter reaching 0: C3 Busy ("Erasing stored wallets") then S-48b, the
  post-wipe screen: "Stored wallets erased after N wrong PINs. This device is blank.
  Restore your coins from your dice rolls or seed words. Your multisig registrations,
  labels and settings are gone and cannot be re-derived." with a single `[ Continue ]`
  to S-09. **Amended 2026-08-17 by the ratified Q5:** the accidental-wipe screen
  previously disclosed less than the deliberate-erase screen S-48, which already names
  registrations; that was backwards, and N is a format string, not a literal 10.
- Storage unreadable (R-32): the pad is replaced by a C7 refusal, because typing a
  PIN into unreadable storage cannot succeed.
- Mid-unseal power loss: next boot's S-01 storage row reports what survived; the A/B
  slot design means at worst the older slot is authoritative and the newer write is
  discarded. Nothing on this screen needs to know.

---

#### S-05 PIN delay (N)

**Purpose.** Render the escalating retry delay as a countdown rather than a frozen
device.

**Enter / Exit.** From S-04 after a wrong PIN when the delay policy says wait. Exits
to S-04 when the countdown reaches zero.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
|          Wrong PIN                                                    |
+----------------------------------------------------------------------+
|                                                                       |
|            +-------------------------------------------+             |
|            |            Wrong PIN                      |             |
|            |                                           |             |
|            |        Try again in  0:47                 |             |
|            |                                           |             |
|            |  The wait doubles after each wrong PIN.   |             |
|            |  8 of 10 tries left.                      |             |
|            |                                           |             |
|            |  Powering off does not skip the wait.     |             |
|            +-------------------------------------------+             |
|                                                                       |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Same centred card, narrower.

**Regions.** None. This is a C3 Busy variant with a counting-down timer and no Stop.

**Copy.** As above; the countdown is `MONO`, `m:ss`. The last line is only shown if it
is true - i.e. if the delay is anchored to the persisted counter rather than to
uptime. **DECISION:** anchor it to the counter (bump-before-attempt, cleared on
success), so the sentence is true; a delay a power cycle skips is theatre.

**Edge states.** Power cycle mid-delay -> S-01 -> S-03 -> S-04 shows the remaining
delay again on the next wrong-PIN-free entry attempt only if the policy is unelapsed;
the counter itself is authoritative.

---

#### S-06 PIN create (N)

**Purpose.** Set the device PIN, with an honest statement of what it does and does not
protect against.

**Enter / Exit.** From S-19 (save-a-wallet fork) when no PIN exists, or from Settings.
Next -> S-07.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Set a PIN                                        [ 1 / 2 ]   |
+----------------------------------------------------------------------+
|                                                                       |
|  This PIN encrypts the wallets stored on this device. There is no     |
|  copy of it and no reset.                                             |
|                                                                       |
|         * * * * * * o o o o o o                                       |
|         [############                    ]  digits only               |
|                                                                       |
|  A digits-only PIN protects against theft, not against a funded       |
|  lab. Letters and symbols make offline guessing far harder.           |
|                                                                       |
|                  ( keypad, as S-04, + [ abc ] )                       |
|                                                                       |
|  After 10 wrong PINs the device erases its stored wallets.            |
|                                                                       |
|                                              [      Next      ]       |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Explanation and meter left, pad right; the policy line moves
under the explanation column.

**Built 2026-08-19. Three deviations from the wireframe above, each deliberate.**

1. **No strength meter and no `digits only` caption.** The bar the wireframe draws has
   exactly one band on the pad that ships: this build has ten digit keys and no
   alphanumeric page (`PinAlpha` is declared and never emitted), so every PIN a user can
   type scores the same and a meter would move for no reason a user could act on. The
   honesty the caption was for is carried by the sentence that stayed - "A digits-only PIN
   protects against theft, not against a funded lab." The meter comes back with the
   keyboard page, not before.
2. **No `PinPolicyInfo` region.** There is no sub-screen behind it, and a drawn button
   nothing hit-tests is a button that lies. The wipe policy is stated as a sentence
   formatted from the store's live `wipe_after` (Q37) rather than from the literal 10 the
   wireframe carries.
3. **The pad is fixed phone order, not S-04's shuffle.** S-04's shuffle was itself
   reversed on 2026-08-19 (C10, Q35). "As S-04" therefore still holds and is what makes
   it hold: a create screen that shuffled while the unlock screen did not would teach one
   layout and then ask for the PIN on another.

The floor is read from the store (`LockInfo::min_pin_len`, 4 by the ratified PIN-MODES
answer), not from the 6 this section's edge states still name - see the note there.

**Not built, and an owner decision rather than an omission:** the anti-phishing words are
never shown at creation, so a user has no chance to learn them at the moment the PIN is
set. The wireframe has no words panel, so the screen follows the spec - but this is the
natural place to memorise them, and the first place they appear today is S-04, where the
user is being asked to check them against a memory they were never given.

**Regions.** As S-04's pad, plus:

| RegionId | Label | Min size | Enabled when |
|---|---|---|---|
| `PinNext` | "Next" | 260x`btn` | length >= 6 |
| `PinPolicyInfo` | "What happens after 10 wrong PINs" | 320x`TOUCH_MIN` | always |

**Copy.** Strength meter labels: `digits only` / `mixed` / `long mixed`, and the
`Strength` band colours from `theme.rs` reused (weak/ok/strong semantics are the same
idea: how hard is this to guess). Note the meter here measures *character-class and
length*, not entropy of a secret the device chose - the caption says "digits only",
never a bit count, because a bit count for a human-chosen PIN would be a lie.

**Masked / shown.** Bullets per character, as S-04. No reveal toggle (see S-07 for
why the confirm step exists instead).

**Edge states.**
- Below the store's floor: Next disabled, reason "A PIN is at least N characters.",
  where N is the live floor the store formats at, never a literal (Q4, Q37).
- All-same-digit or trivially sequential PIN (`111111`, `123456`): allowed, with a
  `WARNING` line "This PIN is one of the first an attacker tries." **DECISION:**
  warn, do not block. A blocklist teaches attackers the blocklist and infuriates
  users who understand their threat model.
- Cap 64 characters.

---

#### S-07 PIN confirm (N)

**Purpose.** Catch the typo before it becomes a wallet nobody can open.

**Enter / Exit.** From S-06. Match -> the pending action (save wallet / change PIN).
Mismatch -> back to S-06 step 1 with both entries cleared.

**Wireframe (720x720).** Identical to S-06 with the bar reading `[ 2 / 2 ]`, the
heading line replaced by "Type the same PIN again.", no strength meter, and the
button labelled `[ Set PIN ]`.

**Regions.** As S-06, with `PinConfirm` in place of `PinNext`.

**Copy.** On mismatch: a `DANGER` line "Those did not match. Start again." and an
automatic return to step 1 after the user's next tap (never an auto-timer).

**Masked / shown.** As S-06.

**Edge states.** Back from step 2 clears both entries (returning with step 1 intact
would let a shoulder surfer resume someone else's half-typed PIN).

---

#### S-08 Change PIN (N)

**Purpose.** Replace the PIN and re-seal every stored record under the new one, with
the stale ciphertext erased rather than left behind.

**Enter / Exit.** From S-44. S-04 (old PIN, full attempt-counter semantics) ->
S-06/S-07 (new PIN) -> this screen -> C3 ("Re-encrypting wallets", determinate, "slot
2 of 3", "Do not power off.") -> S-44 with a status band.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Change PIN                                                   |
+----------------------------------------------------------------------+
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  |  This writes to the device: 3 wallet slots and 2 multisig       |  |
|  |  registrations are re-encrypted with the new PIN, and the old   |  |
|  |  copies are erased.                                             |  |
|  |  Do not power off while this runs.                              |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|  If power is lost part way, the old PIN still opens this device.      |
|  Nothing is lost either way.                                          |
|                                                                       |
|  [ Cancel ]                                    [   Change PIN    ]    |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Notice card left, the reassurance line and buttons right.

**Regions.** `DangerCancel`, `DangerConfirm` (labelled "Change PIN"), separated by
>= `SEPARATION_MIN`.

**Copy.** The torn-write sentence is stated up front because it is the question a
careful user asks before starting, and the A/B slot design makes the honest answer a
good one (`ARCHITECTURE.md` 2.6).

**Masked / shown.** No PIN material on this screen; both PINs were entered elsewhere.

**Edge states.**
- Failure part way: C7 R-33 variant - "2 of 3 slots were re-encrypted. The old PIN
  still opens this device. Retry." Retry resumes from the first slot still on the old
  key; the operation is idempotent per slot by design.
- Verification pass after re-seal: every re-sealed record is read back and unsealed
  under the new key before the old slot is erased. If a readback fails, the old slot
  is kept and the screen says so.

---

### 2.2 Home, wallets and creation

---

#### S-09 Stateless home (E, 0.1.0 Home)

**Purpose.** The 0.1.0 home, unchanged in character: a device with nothing stored.

**Enter / Exit.** From S-01 when no PIN is set, from S-48b after a wipe. Exits to the
create flow, restore flow, verify screen, or (Q11) the stateless signing flow.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
|                                                    [ Mainnet|Testnet ]|
|                                                                       |
|                            notyas                                     |
|                          version 0.2.0                                |
|                                                                       |
|              Nothing is stored on this device.                        |
|                                                                       |
|                                                                       |
|             [        New seed (dice)             ]                    |
|             [        Restore from words          ]                    |
|             [        Sign a transaction          ]                    |
|             [        Verify device               ]                    |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** 0.1.0's arrangement holds: buttons at three-quarter width,
bottom-anchored; the fourth button fits because `Metrics::btn` floors at 64.

**Regions.** `HomeNewSeed`, `HomeRestore` (0.1.0's `HomeVerifySeed`, relabelled -
see copy), `HomeSignStateless` (Q11), `HomeVerifyDevice`, `NetToggle`. All
`3/4 * content.w` x `Metrics::btn`.

**Copy.** "Nothing is stored on this device." is the honest one-line statement of the
stateless property and it stays. **DECISION:** 0.1.0's "Verify existing seed" becomes
"Restore from words", because in 0.2.0 the same flow can end in a saved wallet and
"verify" then misdescribes it; the verify-only use is unchanged (end at the schemes
screen, save nothing).

**Masked / shown.** Nothing secret.

**Edge states.** Q11 rejected -> the Sign button is absent (not disabled: a stateless
device with no wallet has nothing to sign with, and a disabled button implies a
missing prerequisite the user could satisfy).

---

#### S-10 Wallet list (N, UX 3)

**Purpose.** Choose a wallet. The device's real home once anything is stored.

**Enter / Exit.** From S-04 (unlock). Row -> S-21 wallet home. `New`/`Restore` ->
S-11. `Lock` -> S-03. Settings -> S-44.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| Wallets                                        [ Settings ] [ Lock ]  |
+----------------------------------------------------------------------+
|  +-----------------------------------------------------------------+  |
|  | savings                                            single-sig   |  |
|  | a1b2c3d4   m/84'/0'/0'                        backup verified   |  |
|  +-----------------------------------------------------------------+  |
|  | vault 2of3                                            multisig  |  |
|  | 9f3e17aa   m/48'/0'/0'/2'                     backup verified   |  |
|  +-----------------------------------------------------------------+  |
|  | testing                                            single-sig   |  |
|  | 44b0c1de   m/84'/1'/0'  TESTNET               BACKUP UNCHECKED  |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|  3 of 8 slots used                                                    |
|                                                                       |
|  [      New wallet      ]          [    Restore from words    ]       |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Two-column card grid (rows are short); the action pair sits in
a right-hand rail if three or more wallets are stored, otherwise under the list.

**Regions.**

| RegionId | Label | Min size | Enabled when |
|---|---|---|---|
| `ListRow(u8)` | wallet row | full width x `LIST_ROW_MIN` | always |
| `WalletNew` | "New wallet" | 280x`btn` | free slot exists |
| `WalletRestore` | "Restore from words" | 280x`btn` | free slot exists |
| `SettingsOpen` | "Settings" | 180x`TOUCH_MIN` | always |
| `Lock` | "Lock" | 140x`TOUCH_MIN` | always |
| `ListPagePrev` / `ListPageNext` | "Newer"/"Older" | 160x`TOUCH_MIN` | > 1 page |

**Copy.** Badges: `single-sig`, `multisig`, `TESTNET` (uppercase, `WARNING` ink,
because signing on the wrong network is a real error class), `backup verified`
(`SUCCESS`), `BACKUP UNCHECKED` (`WARNING`, uppercase). Capacity line "3 of 8 slots
used". No balances anywhere - an airgapped device has no chain view, and a stale
balance would be worse than none.

Empty state (all slots free, but a PIN exists - e.g. post-delete):

```
  +-----------------------------------------------------------------+
  |  No wallets stored.                                             |
  |  Create one from dice, or restore from your seed words.         |
  +-----------------------------------------------------------------+
```

**Masked / shown.** Wallet names and fingerprints are shown - they are the identity
surface and hiding them defeats the screen. Note therefore that the masking pixel test
does **not** cover this screen: two different wallet sets legitimately render
different frames. What is asserted instead is that no *derived* value beyond the
fingerprint and account path appears here.

**Edge states.**
- All slots used: both action buttons `Disabled` with the reason "All 8 slots are
  used. Delete a wallet to free one."
- A slot whose record fails its AEAD tag: the row renders as
  `"slot 4 - unreadable"` in `DANGER` with the sub-line "This record does not
  decrypt with this PIN. It may be damaged." and tapping it opens R-32.
- Names are user input: rendered in `MONO` (so lookalike characters are visible),
  truncated to the row width with the full name shown on the wallet home; the name
  field itself is capped at 24 characters (S-20).

---

#### S-11 New wallet: method (N)

**Purpose.** Fork the creation flow, and make the entropy source an explicit choice.

**Enter / Exit.** From S-10 or S-09. -> S-12 (dice), S-14 (words). Back -> caller.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   New wallet                                                   |
+----------------------------------------------------------------------+
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  |  Roll dice                                                      |  |
|  |  You roll, the device computes. No random numbers from this     |  |
|  |  hardware are used for keys.                                    |  |
|  +-----------------------------------------------------------------+  |
|  +-----------------------------------------------------------------+  |
|  |  Type existing seed words                                       |  |
|  |  12, 15, 18, 21 or 24 words. Checksum is verified as you type.  |  |
|  +-----------------------------------------------------------------+  |
|  +-----------------------------------------------------------------+  |
|  |  Scan a seed QR                              not available      |  |
|  |  This device has no camera.                                     |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Two cards per row; the unavailable card sits alone on row two.

**Regions.** `NewFromDice`, `NewFromWords` (both full-width, height >= 2 lines +
padding, min 120 px). The camera card is **not** a region - nothing hit-tests it (the
0.1.0 rule about not drawing untappable affordances is respected by drawing it as an
informational card, visually distinct from the two action cards: `PAPER_0` fill, muted
ink, no cobalt).

**Copy.** As drawn. The camera card exists because "why can't I scan?" is the single
most-asked question a camera-less signer gets, and hiding the answer does not stop
the question (CAMERA.md).

**Masked / shown.** Nothing secret.

**Edge states.** None; this screen has no failure mode.

---

#### S-12 Dice entry (E, 0.1.0 DiceEntry)

**Purpose.** Unchanged from 0.1.0: collect roll digits, show effective entropy.

**Enter / Exit.** From S-11 -> S-13 on Done. Back -> S-11 (exit modal, since rolls are
secret material).

**Wireframe.** 0.1.0's, verbatim (see `docs/screenshots/ui/02-dice-entry.png`).
0.2.0 changes nothing about the layout, the RAW/12/15/18/21/24 control, the strength
meter, or the wording.

**Regions.** 0.1.0's: `Digit(1..=6)`, `DiceBackspace`, `Mode(u8)`, `DiceDone`, `Back`.
Unchanged, including the 80 px key floor.

**Copy.** Unchanged, including "Raw dice bits: iancoleman", "Need 128 bits - about 77
more rolls", "Ready: 12 words".

**Masked / shown.** Rolls are shown (typed input, and the user must be able to audit
their own roll history). Unchanged.

**Edge states.** Unchanged from 0.1.0 (below-minimum entropy warns and Done stays
available with a `WARNING` band - the device does not refuse the user's own choice,
it states the consequence).

---

#### S-13 Mnemonic display (E, 0.1.0 MnemonicDisplay)

**Purpose.** Unchanged: show the derived words behind a reveal gate.

**Enter / Exit.** From S-12 or S-14. Next -> S-15 (passphrase). Back -> exit modal.

**Wireframe.** 0.1.0's masked grid + reveal modal, verbatim. 0.2.0 adds one line under
the grid when the flow is heading for storage:

```
  Write these down now. The next screen checks every word.
```

**Regions.** 0.1.0's `Reveal`, `Next`, `Back`, plus modal regions. Unchanged.

**Copy.** 0.1.0's reveal modal is unchanged word for word ("Show seed words?" / "The
seed words will appear on this screen in plain text." / ...). The new line above is
the only addition, and it is only shown on the create path (not on the
verify-existing-seed path, where the user already has the words).

**Masked / shown.** Fixed-run mask (six bullets) per word until revealed. Unchanged,
including the pixel test that two different mnemonics render byte-identical masked
frames.

**Edge states.** Unchanged.

---

#### S-14 Restore: word entry (E, 0.1.0 PhraseEntry)

**Purpose.** Type an existing mnemonic. 0.1.0's screen plus the final-word helper.

**Enter / Exit.** From S-11 / S-09. Done -> S-15. Back -> exit modal.

**Wireframe (720x720).** 0.1.0's well + suggestion strip + keyboard, with the well
header carrying the word counter, and the strip switching to checksum-valid last
words at 11/14/17/20/23 words:

```
| word 12 of 12 - last word                                             |
| +------------------------------------------------------------------+ |
| | abandon ability able about above absent absorb abstract absurd    | |
| | abuse access accident                                             | |
| +------------------------------------------------------------------+ |
| Valid last words:  [ art ] [ chase ] [ jelly ] [ void ]   +8 more     |
```

**Reflow (800x480).** 0.1.0's landscape arrangement (well left, keyboard right)
unchanged; the strip sits above the keyboard in both geometries.

**Regions.** 0.1.0's `Key(char)`, `Shift`, `PageDigits/Letters/Symbols`, `Space`,
`KeyBackspace`, `KeyDone`, `Suggest(0..=3)`, plus `SuggestMore` (new, shows the full
candidate list in a scrollable sheet when more than four valid last words exist).

**Copy.** "word N of M", "Valid last words:", "+8 more". Errors:
- unknown word: the word is inked `DANGER` in the well and the strip reads "Not a
  BIP-39 word." (0.1.0 behaviour, restated).
- checksum fails at a complete word count: `DANGER` line "These 12 words do not form
  a valid seed. Check the last word and the spelling of each word." Done stays
  disabled with that reason.

**Masked / shown.** 0.1.0 shows typed words in the clear. Unchanged: the user is
copying from their own backup and an unseen typo is the worse failure. (This is the
same reasoning as the passphrase reveal toggle, and it is the input-masking rule, not
the derived-secret rule.)

**Edge states.**
- Word counts other than 12/15/18/21/24: Done disabled, reason "A seed is 12, 15, 18,
  21 or 24 words. You have 13."
- Buffer cap `PHRASE_MAX` (1024 bytes) unchanged; at the cap, keys are ignored and the
  hint says so.

---

#### S-15 Passphrase (E, 0.1.0 PassphraseEntry)

**Purpose.** Unchanged: optional BIP-39 passphrase with the explicit opt-in, the two
fields, the Show toggle.

**Enter / Exit.** From S-13/S-14 -> S-16 (Deriving) on Done.

**Wireframe.** 0.1.0's, verbatim. 0.2.0 adds the fingerprint echo *after* derivation
(S-18/S-19 carry it), per ARCHITECTURE 3: "a wrong passphrase is a different wallet".

**Regions.** 0.1.0's `PassToggle`, `PassShow`, `PassEntry`, `PassConfirm`, keyboard,
`KeyDone`. Unchanged.

**Copy.** Unchanged. One addition under the fields when the flow is heading for
storage: "A different passphrase is a different wallet. The next screens show the
fingerprint so you can check you got the one you meant."

**Masked / shown.** One bullet per character, Show toggle reveals (with spaces drawn
as muted bullets). Unchanged, including the mismatch handling.

**Edge states.** Unchanged (`PASS_MAX` 256 bytes; mismatch blocks Done with a reason).

**Second entry point, added 2026-08-19 with the Q22 amendment.** S-21's `Add a passphrase`
action opens this same screen with the words of a wallet that is already stored. In that
purpose a passphrase is not optional - off would re-derive the wallet the user is looking
at - so there is no toggle, and the first page is the explanation instead of the Q22 block:
"This does not change "{name}": these words plus a passphrase are a different wallet, with
its own fingerprint and addresses." Q22 is not repeated there because the flow it starts
passes through both remaining placements: S-19 states it (ii) and S-20's save is GATED on
the acknowledgement (iii). What comes out the far end is a NEW record in a NEW slot, which
is the BIP-39 truth made unmistakable by the wallet list's own structure - two rows, two
fingerprints - rather than by prose.

**Q22 placement (i), as amended.** "Not stored here unless you choose to store it. Your
seed words alone restore a DIFFERENT wallet - write this passphrase down and keep it
apart." Three BODY lines, which is what the 800x480 fork screen has under two equal cards;
the fuller wording is on the storage sheet, which is placement (iv).

---

#### S-16 Deriving (E, 0.1.0 Deriving) - C3 instance

**Purpose.** The interstitial that made 0.1.0 usable. Now determinate.

**Enter / Exit.** From S-15 -> S-17 (create path, quiz next) or S-26 (verify-existing
path, straight to schemes/export).

**Wireframe.** C3, with heading "Deriving keys", body "2048 rounds of PBKDF2, then
every scheme.", meter "step i of 4", trailing line "This cannot be cancelled."

**Regions.** None.

**Copy.** See C3. The 0.1.0 line "Do not power off." is removed here (C3 DECISION).

**Masked / shown.** Nothing. The screen must render identically for every seed - it is
covered by the masking pixel test.

**Edge states.** Derivation failure (a core bug) falls back to the prior screen, as
0.1.0 does, and shows a `DANGER` band there: "Key derivation failed. Nothing was
saved. Run Verify device and report this."

---

#### S-17 Backup check (N, UX 5)

**Purpose.** Prove the user actually recorded the words. No backup exists until it is
verified (commandment 3).

**Enter / Exit.** From S-16 on the create path. Completion -> S-19 (the save fork).
Back -> confirm ("Leave backup check? You will start from word 1.") -> S-13.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Check your backup                            [ 7 / 12 ]      |
+----------------------------------------------------------------------+
|                                                                       |
|  Which word did you write down as word 7?                             |
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  |                        crouch                                   |  |
|  +-----------------------------------------------------------------+  |
|  +-----------------------------------------------------------------+  |
|  |                        crowd                                    |  |
|  +-----------------------------------------------------------------+  |
|  +-----------------------------------------------------------------+  |
|  |                        cruel                                    |  |
|  +-----------------------------------------------------------------+  |
|  +-----------------------------------------------------------------+  |
|  |                        crumble                                  |  |
|  +-----------------------------------------------------------------+  |
|  +-----------------------------------------------------------------+  |
|  |                        crunch                                   |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|  [############################################              ]         |
|  6 of 12 words checked                                                |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Candidates in two columns of two plus one full-width, each still
>= `LIST_ROW_MIN`; question and meter across the top.

**Regions.**

| RegionId | Label | Min size | Enabled when |
|---|---|---|---|
| `QuizChoice(u8)` 0..=4 | candidate word | full width x `LIST_ROW_MIN` | always |
| `Back` | "< Back" | bar | always (confirms) |

**Copy.**
- Question: "Which word did you write down as word 7?"
- Wrong answer: the tapped row goes `DANGER_TINT` with `DANGER` ink, and a line
  appears: "That is not word 7. Read your backup again - this word restarts." The
  next tap anywhere re-poses the same word with a fresh candidate set. **DECISION:**
  a wrong answer restarts *that word*, not the whole quiz (BitBox02 behaviour); a
  full restart punishes a fat finger with 24 re-taps and trains people to rush.
- Progress: "6 of 12 words checked".

**Candidate generation (spec, because it is a security control).** Five candidates:
the correct word plus four distractors drawn deterministically from the BIP-39
wordlist, weighted toward confusables - same 4-letter prefix first (BIP-39's
uniqueness rule makes these the real transcription risk), then edit-distance 1, then
random-by-derived-index. The distractor set derives from
`HMAC_efuse(quiz_domain || word_index || mnemonic_position)` so it is deterministic
per device and per attempt without an RNG (invariant 3). Candidates are presented in
derived-permutation order; the correct answer's position must be uniform across the
quiz, and a CI test asserts that over the wordlist the correct answer lands in each
of the five slots with equal frequency.

**Masked / shown.** The candidate words are shown - they must be. The *correct* word
is not distinguishable in any rendering artifact (same ink, same fill, same order
distribution), which is a pixel-level test: for a fixed device and index, swapping
which candidate is correct must permute rows only, never change styling.

**Edge states.**
- 24-word seeds: 24 questions. No skipping, no sampling. **DECISION:** every word,
  every time (commandment 3). It takes about two minutes and it is the only moment
  the device can catch a transcription error while the words are still on the table.
- Dry-run re-check later (Settings > wallet > "Check backup again"): the same screen,
  but the device already holds the seed, so it answers only "matches" / "does not
  match" and exposes nothing (Trezor dry-run pattern). Entry there is by typing the
  words (S-14), not by tapping candidates.
- Interrupted (power loss): nothing is stored until S-20, so the flow restarts at
  S-12/S-14. The words were never written to flash. Said plainly on S-19.

---

#### S-18 Restore result / fingerprint (N)

**Purpose.** Make the user own the identity of the wallet they just restored. A wrong
passphrase, or a mistyped word that still checksums, is a *different wallet* - and the
fingerprint is where that becomes visible (`ARCHITECTURE.md` 3).

**Enter / Exit.** From S-16 on the restore path. -> S-19 (keep or save). Back -> S-15
(passphrase) via the exit modal, because the passphrase is the usual culprit.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Restored                                                     |
+----------------------------------------------------------------------+
|                                                                       |
|  Fingerprint                                                          |
|  +-----------------------------------------------------------------+  |
|  |                          a1b2c3d4                               |  |
|  +-----------------------------------------------------------------+  |
|  24 words          passphrase ON          mainnet                     |
|                                                                       |
|  Check this fingerprint against your wallet software before you       |
|  use this wallet. A different passphrase gives a different            |
|  fingerprint and a different set of addresses.                        |
|                                                                       |
|  First receive address     m/84'/0'/0'/0/0                            |
|  00  bc1q  xy2k  gdyg  jrsq  tzq2                                     |
|  20  n0yr  f249  3p83  kkfj  hx0w                                     |
|  40  lh                                                               |
|                                                                       |
|  [ Change passphrase ]                           [   Continue   ]     |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Fingerprint card and facts left, first address right; actions
across the bottom.

**Regions.**

| RegionId | Label | Min size | Enabled when |
|---|---|---|---|
| `Back` / `PassEntry` | "Change passphrase" | 280x`btn` | always |
| `ReviewNext` | "Continue" | 280x`btn` | always |

**Copy.** The fingerprint is rendered at `TITLE` size in mono - it is the subject of
the screen, not a footnote. The first address is included because a fingerprint alone
is not something most users have to hand, while an address usually is.

**Masked / shown.** Fingerprint and first address shown (both public). The words are
not re-shown here; getting back to them means the reveal gate on S-13.

**Edge states.**
- Fingerprint matches a wallet already stored: a `WARNING` band - "This is the same
  wallet as 'savings' (a1b2c3d4), already stored on this device." with the save option
  on S-19 relabelled "Save as a second copy".
- Passphrase off: the facts line reads "passphrase OFF" and the explanation sentence
  changes to "Adding a passphrase would give a different fingerprint and a different
  set of addresses."

---

#### S-19 Keep or save (N)

**Purpose.** The fork that keeps statelessness first-class (commandment 6).

**Enter / Exit.** From S-17 (or S-16 on the restore path). -> S-20 (save) or S-21
(session-only wallet home) / S-26 (export only).

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Backup checked                                               |
+----------------------------------------------------------------------+
|                                                                       |
|  All 12 words checked.       fingerprint  a1b2c3d4   passphrase ON    |
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  |  Save to this device                                            |  |
|  |  Stored encrypted in a wallet slot. The PIN is the key.         |  |
|  |  You can open it after every power-on without retyping words.   |  |
|  +-----------------------------------------------------------------+  |
|  +-----------------------------------------------------------------+  |
|  |  Use once, keep nothing                                         |  |
|  |  Nothing is written. When this device powers off or locks, the  |  |
|  |  seed is gone and you retype the words to use it again.         |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|  Either way, your dice rolls or seed words are the backup.            |
|                                                                       |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Cards side by side; the fingerprint line moves into the bar's
subtitle position.

**Regions.** `SaveToDevice`, `UseOnce` - full-width cards, min 140 px tall.

**Copy.** As drawn. The fingerprint is `MONO`, 8 hex, always shown here and on every
subsequent wallet screen - it is how the user notices a passphrase typo.

**Masked / shown.** Fingerprint shown (public). No words on this screen.

**Edge states.** No free slot: the Save card is `Disabled` with the reason "All 8
slots are used. Delete a wallet first." and Use-once remains available.

---

#### S-20 Name and save (N)

**Purpose.** Name the wallet, announce the flash write, gate it behind the PIN.

**Enter / Exit.** From S-19. -> C3 Busy ("Encrypting and saving") -> S-21. Back -> S-19.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Save wallet                                                  |
+----------------------------------------------------------------------+
|                                                                       |
|  Name                                          fingerprint a1b2c3d4   |
|  +-----------------------------------------------------------------+  |
|  | savings_                                                        |  |
|  +-----------------------------------------------------------------+  |
|  Letters, digits, spaces, - and _ . Up to 24 characters.              |
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  |  This writes to the device: wallet slot 3 (encrypted).          |  |
|  |  The PIN is the key. Wrong PIN 10 times erases it.              |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|             ( keyboard )                                              |
|                                                                       |
|                                              [     Save wallet    ]   |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Field and notice left, keyboard right.

**Regions.** `NameField`, keyboard regions, `ConfirmSave` (>= 280x`btn`).

**Copy.** The C12 WriteNotice text is verbatim above. Save button label "Save wallet",
always. **Corrected 2026-08-19 as built:** the second label never ships, because this
screen is not where a device without a PIN meets the PIN step. S-06's own Enter/Exit line
puts that step on S-19 ("From S-19 ... when no PIN exists"), and PIN-MODES puts the moment
at the choice to save rather than at the naming of what is saved - so by the time S-20 is
reached the device always has a PIN and there is no second case for the label to cover.
The fork's Save card carries the warning instead: on a device with no PIN it reads "Sets a
PIN first. The PIN is the key.", which is where a user still has the choice in front of
them.

**Masked / shown.** Name unmasked (typed, and it is a label, not a secret).

**Edge states.**
- Empty name: Save disabled, reason "Give the wallet a name."
- Duplicate name: allowed with a `WARNING` line "Another wallet is also called
  'savings'. Fingerprints tell them apart." **DECISION:** warn, do not block -
  duplicate names are the user's business, and the fingerprint is the real identity.
- Illegal character typed: ignored at the keyboard level, hint flashes the allowed set.
- Write fails (flash error, both slots bad): C7 refusal R-33 with "The wallet was not
  saved. Nothing was changed." and a Retry.
- Power loss mid-write: A/B slot commit means the older slot stays authoritative; the
  next boot reports the true state and the user re-saves. Stated in the WriteNotice?
  No - stated on the S-01 storage row if it happens. The notice stays short.

---

#### S-21 Wallet home (N, UX 7)

**Purpose.** The per-wallet hub: identity first, then the four things you can do.

**Enter / Exit.** From S-10 (open) or S-19/S-20. Every action leads out; Back -> S-10;
Lock -> S-03 (drops the session).

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   savings                                              [ Lock ]|
+----------------------------------------------------------------------+
|  +-----------------------------------------------------------------+  |
|  |  savings                                       single-sig       |  |
|  |  fingerprint  a1b2c3d4        native segwit    m/84'/0'/0'      |  |
|  |  mainnet        backup verified 2026-08-14     session only     |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  |  Receive                    show and check addresses            |  |
|  +-----------------------------------------------------------------+  |
|  +-----------------------------------------------------------------+  |
|  |  Sign a transaction         read a PSBT from the card           |  |
|  +-----------------------------------------------------------------+  |
|  +-----------------------------------------------------------------+  |
|  |  Export public keys         xpub, descriptor, QR or card        |  |
|  +-----------------------------------------------------------------+  |
|  +-----------------------------------------------------------------+  |
|  |  Multisig                   2 registrations                     |  |
|  +-----------------------------------------------------------------+  |
|  +-----------------------------------------------------------------+  |
|  |  Wallet settings            rename, re-check backup, delete     |  |
|  +-----------------------------------------------------------------+  |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Identity card full width; action cards in two columns of two
plus one, each >= `LIST_ROW_MIN`.

**Regions.** `ActReceive`, `ActSign`, `ActExport`, `ActMultisig`, `ActWalletSettings`,
`ActPassphraseStore`, `ActPassphraseDerive`, `WalletDelete`, `Lock`, `Back`.

**Copy.** Identity card fields as drawn. `session only` appears in place of the
storage line when the wallet came from Use-once. Multisig card's secondary text is the
count, or "not set up" when zero.

**The passphrase row (amended Q22, 2026-08-19).** The identity card's passphrase field is
exactly one of three strings and never a switch: `no passphrase`, `passphrase required`,
`passphrase stored`. The words ON and off are banned from it and a copy gate asserts they
appear in no frame. The reason is not style: "off" implies a passphrase this wallet could
be given, and a passphrase is not a setting of a wallet - the same words under a different
passphrase are a DIFFERENT wallet, with a different fingerprint and different addresses.
The one thing here that IS a setting is whether this device remembers it, and
`passphrase stored` is the state that names it. The build before this one hardcoded the
field to false and rendered `passphrase off` on wallets that demonstrably had one.

**Two passphrase actions, offered exclusively.**

- **`Remember the passphrase` / `Forget the passphrase`** (`ActPassphraseStore`), on a
  STORED wallet that has a passphrase and is open with its keys - which is the same thing
  as saying the session is holding the passphrase, so storing never asks the user to
  retype and never stores anything unverified. Turning ON is one C4b sheet carrying
  dangers (a) and (c). Turning OFF is a C4b consequence followed by a C4c hold, on the
  delete sequence's own precedent: the grade this action earns is the hold, and a hold bar
  leaves 64 px of prose on the 800x480 panel, which is one line. The row re-renders from
  the record READ BACK after the write, never from the intent.
- **`Add a passphrase`** (`ActPassphraseDerive`), on a wallet with NO passphrase. It
  CREATES a second wallet from the same words - a new record, a new slot, its own label -
  and changes nothing about this one. Its first page says so before a keyboard appears.

**Reflow, amended.** A stored wallet with its keys, a registry and a passphrase action
carries five cards, and 190 px under the identity card on the 800x480 panel holds two at
the `LIST_ROW_MIN` floor. The body SCROLLS, identity card included - it is content, not a
header - with the `more below` / `more above` chips C2 requires and S-30, S-38, S-42 and
C7 already draw. What does not give way is the touch floor or the number of actions.

**Masked / shown.** Fingerprint, script type, account path shown (all public). No key
material, no words, no reveal path from here - viewing the words again is under
Wallet settings and goes through the reveal gate (S-13's modal).

**Edge states.**
- Session-only wallet: an extra `WARNING` line "Not stored. Locking or powering off
  loses this wallet until you retype the words."
- Backup unchecked (restore path where the user declined the quiz): status reads
  `BACKUP UNCHECKED` and Wallet settings offers "Check backup now".

---

#### S-21b Passphrase unlock (N, 0.2.0)

**Purpose.** Ask for the BIP-39 passphrase of a wallet that already exists, at the moment
the user taps its row. Until 0.2.0 this screen did not exist and a passphrase wallet could
therefore be created once and never opened again (see the Q22 amendment, 2026-08-19).

**Enter / Exit.** From S-10, when the embedder answers `OpenWallet` with
`Ui::wallet_needs_passphrase` - which is NOT a failure and is never rendered as one:
nothing went wrong, and the device is asking for the half of the seed it does not hold.
Done -> C3 Busy -> S-21 on success (the unlock screen is REPLACED, so Back never returns
to a passphrase field) or back to this screen with the refusal. Back -> S-10, nothing
opened.

**Three phases, each with a way out.**

1. **Typing.** One field, one Show toggle, the byte counter, the keyboard. NO confirm
   field: the record carries the fingerprint the seed must produce, so a typo is caught by
   the device rather than by retyping, which is the whole difference from S-15.
2. **Busy (C3).** Published BEFORE the derivation starts. No Back and nothing tappable -
   the work is synchronous and cannot be cancelled, so a Back here would be a button that
   lies. Both answers leave the phase, which is what makes it impossible to wedge.
3. **Refused.** What happened, in derivation facts, with `Try again`.

**Copy.** Bar: the wallet's name. Busy: "Opening this wallet... / Deriving keys from your
words and passphrase. / This takes a few seconds. Do not power off." Counter:
"{n} bytes (NFKD) - Done opens it". Q22 placement (iii), in the line this phase has room
for: "Not stored on this device." - unconditional here, because this screen is only ever
up for a wallet whose passphrase the device does NOT hold.

**The refusal, which is a security property and not a message.** "Every passphrase opens
some wallet. That one opens wallet {derived}. This record is wallet {expected}, so nothing
was opened. Spelling, capitals and spaces all count - check them and try again." The
device never says "wrong", "incorrect" or "invalid" about a passphrase: BIP-39 has no
invalid passphrases, only different wallets. Both fingerprints are public - one is in the
record, the other is a function of what the user just typed. What is NEVER rendered is the
fingerprint the words derive with an EMPTY passphrase: that is an existence proof for a
hidden wallet, and the firmware discards it rather than sending it here.

**Retry gate.** Attempts 1 and 2 are immediate. From the third, `Try again` is drawn
disabled with "Wait {n}s before the next try." beside it, starting at 5 s and doubling to
a 300 s cap. The counter is per wallet slot, lives on the `Ui`, survives backing out to
S-10 and survives a lock - a counter a tap could reset would be decoration - and is
cleared by a successful open or a power cycle. It closes the on-panel oracle only; a flash
dump plus the PIN lets the same guessing run offline at PBKDF2 speed, which only passphrase
strength answers.

**Regions.** `PassEntry`, `PassShow`, `PassUnlock` (Try again), the keyboard, `Back`.

**Masked / shown.** Typed INPUT masking, one bullet per character, with the Show toggle
S-15 has and for the same reason: an unseen typo is a wallet that does not open.

---

### 2.3 Addresses

---

#### S-22 Receive / address list (E, UX 8)

**Purpose.** Browse this wallet's addresses by index, on the device's own screen.

**Enter / Exit.** From S-21. Row -> S-23. Back -> S-21.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Receive - savings                                    [ Lock ]|
+----------------------------------------------------------------------+
|  [   Receive   |    Change   ]              m/84'/0'/0'               |
|                                                                       |
|  0   bc1q xy2k gdyg jrsq tzq2 n0yr f249 3p83 kkfj hx0w lh       >     |
|  1   bc1q ar0s rrr7 xfkv y5l6 43lc dpuc dqvm zzmp ehc9 gj       >     |
|  2   bc1q w508 d6qe jxtd g4y5 r3za rvar y0c5 xw7k xpjz sx       >     |
|  3   bc1q rp33 g0q5 c5tx sp9a rysr x4k6 zdkf s4nc e4xj 0gd      >     |
|  4   bc1q c7sl rfxk knqc q2je vvvk dgvr t808 852d fjhn ...      >     |
|                                                                       |
|  [ Earlier ]   showing 0 - 4    [ Later ]      [ Jump to index ]      |
|                                                                       |
|  [ Check an address I was given ]                                     |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Rows are wider, so each address fits on one line at
`MONO_SMALL`; the pager and the check-an-address action move to a right rail.

**Regions.**

| RegionId | Label | Min size | Enabled when |
|---|---|---|---|
| `Tab(0/1)` | "Receive" / "Change" | half width x 56 | always |
| `AddrRow(u8)` | address row | full width x `LIST_ROW_MIN` | always |
| `ListPagePrev` / `ListPageNext` | "Earlier" / "Later" | 180x`TOUCH_MIN` | index > 0 / always |
| `AddrJump` | "Jump to index" | 240x`TOUCH_MIN` | always |
| `VerifyAddrOpen` | "Check an address I was given" | full width x `btn` | always |

**Copy.** Note the list rows are the **only** place an address is allowed to be
visually truncated, and only in the list, never in a verification context - the row
ends with a literal `...` and the row's purpose is navigation, not verification. The
screen says so once, under the list: "Open an address to see all of it. Never check an
address from this list."

**Masked / shown.** Addresses are public. Change addresses are shown on their own tab
with a caption "These are the addresses your own change comes back to."

**Edge states.**
- Multisig wallet without a registration: the list is replaced by an empty-state well
  "No multisig registration for this wallet. Import one before showing addresses." with
  a button to S-41. A multisig address the device cannot derive from a registration is
  not an address it should display.
- Jump-to-index beyond the gap bound: accepted, with a `WARNING` line "Index 5000 is
  far past your used range. Coordinators may not watch this address."

---

#### S-23 Address detail (E/N, UX 8)

**Purpose.** The anti-poisoning screen: the full address, at the largest legible size,
with nothing else competing for attention.

**Enter / Exit.** From S-22 row. Back -> S-22.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Address 7                                            [ Lock ]|
+----------------------------------------------------------------------+
|  m/84'/0'/0'/0/7                                          receive     |
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  | 00   bc1q  xy2k  gdyg  jrsq  tzq2                               |  |
|  | 20   n0yr  f249  3p83  kkfj  hx0w                               |  |
|  | 40   lh                                                         |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|                    +--------------------------+                       |
|                    |                          |                       |
|                    |       (QR symbol)        |                       |
|                    |                          |                       |
|                    +--------------------------+                       |
|                                                                       |
|  Compare every group with the address in your wallet software.        |
|                                                                       |
|  [ < Address 6 ]                                    [ Address 8 > ]   |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Address block left (four groups per line), QR right at the
largest integer scale that fits the column; the prev/next pair spans the bottom.

**Regions.** `AddrPrev`, `AddrNext` (>= 200x`TOUCH_MIN`, at opposite edges),
`Back`, `Lock`. The QR is not interactive (it is already the biggest it can be).

**Copy.** "Compare every group with the address in your wallet software." - the one
instruction that matters, stated once, near the data. The offset gutter (`00`, `20`,
`40`) is the character index of each line's first character.

**Masked / shown.** Fully shown, always. Never truncated, never prefix/suffix. This is
commandment 1's screen.

**Edge states.**
- Taproot / long addresses at 800x480: if the block plus a legible QR do not both fit,
  the QR moves behind a `[ QR ]` button and the address keeps the space. The address
  is the point; the QR is a convenience.
- If the address at `MONO` does not fit the viewport at all (a pathological future
  script type), it becomes a C5 two-page review with traversal enforced before the
  next/prev buttons enable.
- Change tab: the header chip reads `change` in `WARNING` ink, and a line is added:
  "This is a change address. Do not give it out as a receive address."

---

#### S-24 / S-25 Check an address (N, UX 8)

**Purpose.** Answer "is this address mine?" without the user trusting their computer -
the Coldcard verify-ownership pattern
(https://coldcard.com/docs/verify-address-ownership/).

**Enter / Exit.** From S-22. S-24 (input) -> C3 Busy ("Searching addresses", i of
1528, Stop available) -> S-25 (result). Back -> S-22.

**Wireframe S-24 (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Check an address                                     [ Lock ]|
+----------------------------------------------------------------------+
|  Type the address, or read it from a text file on the card.           |
|  +-----------------------------------------------------------------+  |
|  | bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh_                     |  |
|  +-----------------------------------------------------------------+  |
|  42 characters                                                        |
|                                                                       |
|             ( keyboard, lowercase + digits )                          |
|                                                                       |
|  [ Read from card ]                                  [    Check    ]  |
+----------------------------------------------------------------------+
```

**Wireframe S-25 (720x720), both verdicts.**

```
+----------------------------------------------------------------------+
| < Back   Result                                                       |
+----------------------------------------------------------------------+
|  +-----------------------------------------------------------------+  |
|  |  This address is yours                                          |  |
|  +-----------------------------------------------------------------+  |
|  Found at m/84'/0'/0'/0/7  (receive index 7)                          |
|  00  bc1q  xy2k  gdyg  jrsq  tzq2                                     |
|  20  n0yr  f249  3p83  kkfj  hx0w                                     |
|  40  lh                                                               |
|  Searched 1528 addresses across receive and change.                   |
|                          - or -                                       |
|  +-----------------------------------------------------------------+  |
|  |  NOT FOUND                                                      |  |
|  +-----------------------------------------------------------------+  |
|  This address is not in the first 1528 addresses of this wallet.      |
|  If someone told you it was yours, do not send to it.                 |
|  Searched: receive 0-763, change 0-763, wallet a1b2c3d4.              |
+----------------------------------------------------------------------+
```

**Regions.** S-24: `VerifyAddrField`, keyboard, `VerifyAddrFromSd`, `VerifyAddrCheck`.
S-25: `Back`, `VerifyAddrAgain` ("Check another").

**Copy.** Verdict band: `SUCCESS` fill-tint for "This address is yours",
`DANGER_TINT` for "NOT FOUND". "NOT FOUND" is uppercase; it is the answer that should
stop a transaction.

**Masked / shown.** Everything shown; addresses are public.

**Edge states.**
- Malformed address: refusal inline (not a C7 screen) - "That is not a valid bitcoin
  address. Check the characters." with the offending position marked if the bech32
  checksum locates it.
- Wrong network: "This is a testnet address. This wallet is mainnet." (never "not
  yours", which would be a misleading answer).
- Multisig wallet: search runs against the registration; without one, the button is
  disabled with the reason "Import the multisig registration first."
- Search stopped by the user: result screen reads "Search stopped at 412 of 1528.
  No match so far. This is not an answer." - the honest non-verdict.

---

#### S-26 Export public keys (E, 0.1.0 Schemes)

**Purpose.** 0.1.0's schemes screen, now per-wallet and with file export.

**Enter / Exit.** From S-21 or the end of a verify-existing-seed run. Back -> caller.

**Wireframe.** 0.1.0's tabbed layout (BIP44/49/84/86), unchanged, with two additions:
a C12 WriteNotice above the new `[ Save to card ]` action, and a descriptor block
under the xpub block.

```
| [ BIP44 | BIP49 | BIP84 | BIP86 ]                                     |
| fingerprint a1b2c3d4 - passphrase ON                                  |
| Account m/84'/0'/0'                                                   |
| Account xpub                                              [ QR ]      |
| 00  zpub 6rFR 7y4Q 2Aij ...                                           |
| Descriptor                                                [ QR ]      |
| 00  wpkh([a1b2c3d4/84h/0h/0h]xpub.../<0;1>/*)#checksum                |
| Receive addresses                                                     |
| ...                                                                   |
| This writes to the card: savings-84-a1b2c3d4.json                     |
| Not a secret key, but it reveals every address this wallet will       |
| ever use to anyone who reads the card.                                |
| [ Save to card ]                                                      |
```

**Regions.** 0.1.0's `Tab(u8)`, `QrXpub`, `QrSlip132`, `QrAddress(u8)`, plus
`QrDescriptor`, `ExportToSd`.

**Copy.** The privacy sentence is invariant 2b's requirement, verbatim.

**Masked / shown.** Public values only, as 0.1.0. No xpriv path exists anywhere.

**Edge states.** No card: `Save to card` disabled with "No card detected." plus a
`[ Check again ]`. Existing file of the same name: C4a yellow card "A file with that
name is on the card. Overwrite it?" with `[ Cancel ]` / `[ Overwrite ]`.

---

### 2.4 Signing

---

#### S-27 Sign: source (N, UX 9)

**Purpose.** Get an unsigned transaction into the device, and say plainly why there is
only one way in.

**Enter / Exit.** From S-21. -> S-28 (picker) or straight to C3 ("Reading card") when
exactly one PSBT is present. Back -> S-21.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Sign - savings                                       [ Lock ]|
+----------------------------------------------------------------------+
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  |  Ready to sign                                                  |  |
|  |  psbt-2026-08-17.psbt        2.4 kB      found on the card      |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|  [ Choose a different file ]                                          |
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  |  Transactions come in on the card only. This device has no      |  |
|  |  camera, so it cannot scan one. Signed transactions go out by   |  |
|  |  card or by QR.                                                 |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Same, one column; the explanation card sits right of the ready
card.

**Regions.** `SignReady` (the auto-detected file card, full width, >= 120 px),
`SignPickFile`, `Back`.

**Copy.** "Ready to sign" mirrors the Coldcard convention users already know
(https://coldcard.com/docs/ready-to-sign/). The camera sentence is not an apology; it
is the transport contract.

**Edge states.**
- No card: the ready card is replaced by "No card detected. Insert a card with a
  .psbt file." plus `[ Check again ]`.
- No PSBT on the card: "No .psbt files on this card." plus `[ Show all files ]`
  (S-28 with the filter off, so a mis-extensioned file is findable).
- More than one PSBT: skip straight to S-28.
- Card removed between detect and read: C7 refusal R-23.

---

#### S-28 SD file picker (N)

**Purpose.** Choose a file when auto-detect is not enough.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Files on card                                        [ Lock ]|
+----------------------------------------------------------------------+
|  [  PSBT only  |  All files  ]                                        |
|  +-----------------------------------------------------------------+  |
|  | psbt-2026-08-17.psbt                    2.4 kB   17 Aug 14:02   |  |
|  | spend-vault.psbt                       11.8 kB   16 Aug 09:41   |  |
|  | multisig-vault.txt                      0.4 kB   02 Aug 18:22   |  |
|  +-----------------------------------------------------------------+  |
|  3 files                                          [ Check again ]     |
+----------------------------------------------------------------------+
```

**Regions.** `Tab(0/1)`, `ListRow(u8)` (>= `LIST_ROW_MIN`), `FileRefresh`,
`ListPagePrev/Next`, `Back`.

**Copy.** Sizes in kB with one decimal; timestamps from the FAT directory entry, shown
as-is with no timezone claim. Empty: "No files on this card."

**Edge states.** File larger than the accepted cap: the row is `Disabled`-styled with
"too large (max 512 kB)" in `WARNING` (cap value from the RAM bound in
`ARCHITECTURE.md` 5.4). Directory nesting: **DECISION:** the picker lists the card
root and one level of directories, no deeper; deep trees on an airgapped device's
5-row list are a navigation trap. Unreadable card -> C7 R-23.

---

#### S-29 Refusal (N, C7 instance, UX 9/10)

Covered by component C7 and the code table in 3.2. It is listed as a screen because it
has its own state, its own Back semantics (returns to S-27, never into the review),
and its own CI corpus.

**Edge state worth naming**: a refusal that arrives *after* review has started (the
post-sign gate, R-10) returns to S-21, not S-27, and says so: "Nothing was signed and
nothing was written."

---

#### S-30 Review: overview (N, UX 10)

**Purpose.** Prime the user for what they are about to page through. Fatigue is real;
abbreviation is how output substitution wins, so we prime and never truncate.

**Enter / Exit.** From C3 ("Checking transaction"). -> S-31. Back -> C4a confirm ->
S-27.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Review                                       [ 1 / 10 ]      |
+----------------------------------------------------------------------+
|  +-----------------------------------------------------------------+  |
|  |  Leaving this wallet        0.12 345 678 BTC                    |  |
|  |  Fee                        0.00 004 210 BTC                    |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|  3 inputs        0.13 000 000 BTC     all from savings (a1b2c3d4)     |
|  4 outputs       2 external, 2 change (verified)                      |
|  Network         mainnet                                              |
|  Warnings        1                                                    |
|                                                                       |
|  You will see every input and every output on its own page.           |
|  The Sign button appears after the last page.                         |
|                                                                       |
|                                             [       Next >       ]    |
+----------------------------------------------------------------------+
```

**Page count. Corrected 2026-08-19 against the implementation.** The traversal is
`1 + n_in + n_out + 2` - the overview, one page per input, one page per output, then the
fee page and the warnings page. `TxReview::pages` is the single definition of it and
computes `3 + inputs.len() + outputs.len()`; the bar's `[ i / n ]`, the visited set that
gates the hold and the Next target all read that one function, so they cannot disagree by
one. The worked example carried through S-30..S-35 is 3 inputs and 4 outputs, which is 10
pages and not 9, and the fee page is 9 rather than 8. Every counter in those six screens
was renumbered on that basis, along with the disabled-hold reason on S-35. The per-page
indices were already right; only the denominator and the fee's own index were wrong.

**Reflow (800x480).** Summary card left, the four-row fact table right; action row
across the bottom.

**Regions.** `ReviewNext` (>= 280x`btn`, right), `Back`.

**Copy.** "Leaving this wallet" rather than "Amount": on a signer, the number a user
must internalise is the net outflow, not the sum of outputs. Change is excluded from
it by definition and the label says which wallet.

**Masked / shown.** Everything shown. Nothing on a review screen is ever masked.

**Edge states.**
- More than 10 outputs: the fact table gains "Large transaction - 32 outputs" in
  `WARNING`, and the page count reflects the full traversal. No sampling.
- All inputs foreign (should have refused earlier): unreachable by construction; if it
  happens it is R-01 before this screen.
- Consolidation (no external outputs): the header reads "Leaving this wallet
  0.00 000 000 BTC" and a line adds "This transaction sends everything back to
  itself, minus the fee."

---

#### S-31 Review: input page (N)

**Purpose.** Show what is being spent, so the fee arithmetic is auditable.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Input 2 of 3                                 [ 3 / 10 ]      |
+----------------------------------------------------------------------+
|  Amount            0.05 000 000 BTC                                   |
|  From              m/84'/0'/0'/0/4        yours (a1b2c3d4)            |
|  Address                                                              |
|  00  bc1q  ar0s  rrr7  xfkv  y5l6                                     |
|  20  43lc  dpuc  dqvm  zzmp  ehc9  gj                                 |
|  Previous transaction                                                 |
|  00  9f2c  1a44  ...  (64 hex, full)                                  |
|  Checked: amount and txid match the full previous transaction.        |
|                                                                       |
|  [ < Prev ]                                          [   Next >   ]   |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Facts left, mono values right; the value column scrolls if the
prev-tx txid plus address exceed the column.

**Regions.** `ReviewPrev`, `ReviewNext`, `Back`.

**Copy.** The "Checked:" line names the check that passed, because a user should be
able to see which defences ran (`ARCHITECTURE.md` 5.3 check 2). If an input is not
ours (mixed-ownership PSBT), the From line reads "not from this wallet" in `WARNING`
and the page adds "This input is not yours. It will not be signed here."

**Edge states.** Taproot input with `witness_utxo` only: "Checked: amount is committed
to by the signature (taproot)." - the honest variant, since BIP-341 commits to all
prevouts. Non-taproot with `witness_utxo` only: never reaches this screen (R-02).

---

#### S-32 Review: output page (N)

**Purpose.** The screen the whole device exists for.

**Wireframe (720x720), external output.**

```
+----------------------------------------------------------------------+
| < Back   Output 1 of 4                                [ 5 / 10 ]      |
+----------------------------------------------------------------------+
|  +-----------------------------------------------------------------+  |
|  |  EXTERNAL - leaving your wallet                                 |  |
|  +-----------------------------------------------------------------+  |
|  Amount            0.12 345 678 BTC                                   |
|                                                                       |
|  Address                                                              |
|  +-----------------------------------------------------------------+  |
|  | 00   bc1q  w508  d6qe  jxtd  g4y5                               |  |
|  | 20   r3za  rvar  y0c5  xw7k  xpjz                               |  |
|  | 40   sx                                                         |  |
|  +-----------------------------------------------------------------+  |
|  Compare every group with the address you were given.                 |
|                                                                       |
|  [ < Prev ]                                          [   Next >   ]   |
+----------------------------------------------------------------------+
```

**Wireframe (720x720), change output.**

```
|  +-----------------------------------------------------------------+  |
|  |  CHANGE - coming back to you (verified)                         |  |
|  +-----------------------------------------------------------------+  |
|  Amount            0.00 650 112 BTC                                   |
|  Path              m/84'/0'/0'/1/12                                   |
|  Checked: this device derived this exact address from your wallet.    |
|  (address block, same as above)                                       |
```

**Multisig variant** adds, under the badge:

```
|  2 of 3 - vault 2of3 registration                                     |
|  cosigners  a1b2c3d4 (this device)  9f3e17aa  0c55ab21                |
```

**Reflow (800x480).** Badge full width; amount and metadata left, address block right
at four groups per line.

**Regions.** `ReviewPrev`, `ReviewNext`, `Back`. The badge is not interactive.

**Copy.** Badge strings are fixed and are the vocabulary of the whole review:

| Badge | Ink / fill | Meaning |
|---|---|---|
| `EXTERNAL - leaving your wallet` | `DANGER` on `DANGER_TINT` | not ours; scrutinise |
| `CHANGE - coming back to you (verified)` | `SUCCESS` on paper-0 | derived from our descriptor |
| `CHANGE - CLAIMED, NOT VERIFIED` | `DANGER` on `DANGER_TINT` | PSBT says change, we could not prove it |
| `OURS - another address of this wallet` | `ACCENT` on `ACCENT_TINT` | ours but not the change keychain |
| `DATA - not spendable` | `WARNING` on paper-0 | OP_RETURN |
| `UNKNOWN SCRIPT` | `DANGER` on `DANGER_TINT` | not classifiable |

**Masked / shown.** Nothing masked. Ever.

**Edge states.**
- `CHANGE - CLAIMED, NOT VERIFIED` renders as a page, and that page can never be signed.
  **Corrected 2026-08-19 against the implementation.** This entry read "is a refusal
  condition, full stop (R-03). It never renders as a signable page", and the shipped
  engine contradicts the first clause. `notyas-core`'s `inspect` does not fail on an
  unproven change claim: it returns `OutputRole::ClaimedButUnproven` inside a clean
  `Inspection`, `OutputRole::is_change` answers false for it, and the output is therefore
  counted as money LEAVING in every total the screen computes - `firmware/src/hil.rs`
  logs it as `CLAIMED_BUT_UNPROVEN` on a successful inspection. Dropping its page would
  remove an output from a traversal whose entire purpose is that no output goes unseen,
  which is a worse failure than the one the old wording was guarding against.
- The security intent is unchanged, and the mechanism carrying it moved rather than
  vanished. R-03 is raised where the CONSENT is, not where the parsing is: the hold does
  not exist while any output carries this role (`ReviewState::blocker`, re-asked at
  `activate` so a caller that bypasses `regions` cannot get past it), the last page states
  "This transaction cannot be signed here.", and there is no override anywhere on the path
  (ratified Q24 - the 2026-08-17 correction that deleted the "Hold to sign anyway" action
  stands, and there is still no such mode). The badge is `DANGER` on `DANGER_TINT` and
  outranks the script's own shape in the badge precedence, and the word CHANGE never
  appears on it without CLAIMED, NOT VERIFIED beside it. The page says the claim was made
  and not believed, which is strictly more than a bare refusal screen said.
- Stateless multisig (Q12): change cannot be verified without a registration, so the
  claim is refused. **There is no override badge and no override mode**, for the same
  reason: SECURITY invariant 7 is written without exceptions, and a setting that
  disables the check which stops output substitution is a setting an attacker will talk
  a user into enabling.
- Dust output: `WARNING` line "Below the dust limit. Some nodes will not relay this."

---

#### S-33 Review: unusual output (N)

**Purpose.** Render non-address outputs honestly instead of skipping or faking them.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Output 3 of 4                                [ 7 / 10 ]      |
+----------------------------------------------------------------------+
|  +-----------------------------------------------------------------+  |
|  |  DATA - not spendable                                           |  |
|  +-----------------------------------------------------------------+  |
|  Amount            0.00 000 000 BTC                                   |
|  Script type       OP_RETURN                                          |
|  Payload (34 bytes, hex)                                              |
|  00  6a20 1f3c 8b21 ...                                               |
|  As text (printable characters only)                                  |
|  "hello world..............."                                         |
|                                                                       |
|  This output carries data, not coins. Nobody can spend it.            |
|  [ < Prev ]                                          [   Next >   ]   |
+----------------------------------------------------------------------+
```

**Copy.** The "As text" rendering shows printable ASCII and a period for every other
byte, with the count stated - never a decoded string that could contain control
characters or spoof the UI.

**Edge states.** Unknown script type: badge `UNKNOWN SCRIPT`, the script rendered as
disassembly if `rust-bitcoin` can, hex if not, plus "This device cannot tell who can
spend this output." A page and a warning, never a refusal.

**Corrected 2026-08-19 against the implementation.** This paragraph said "A transaction
containing one is refused (R-09 family)", and both halves were wrong. No `CheckFailure`
refuses an unclassifiable output: `ScriptKind::Other` is a legal payment in `notyas-core`,
and the ten checks constrain the scripts this device SIGNS - an input of ours that is not
P2WPKH, P2SH-P2WPKH, P2TR key-path or a registered P2WSH is `ClaimedInputNotSingleSig` -
while saying nothing about where a transaction may pay. R-09 is "This file is malformed",
which an unrecognised output script is not.

The correction is the right design and not only the accurate one. Refusing every script
this device does not recognise would hard-code an expiry date into the product: the next
output type Bitcoin adopts would make every wallet that used it unsignable here, on a
device whose claim is that it can be verified rather than trusted, and the user would have
no way to tell a new standard from an attack. So the output gets its own page like any
other, the badge is `DANGER` on `DANGER_TINT` and outranks the role - "who can spend this"
is unanswered, and no role means anything without it - the amount counts as money leaving
in every total, and S-35 carries the warning "Output 3 pays a script this device cannot
classify. / Nobody here can tell you who will be able to spend it." The user decides, with
the fact in front of them, whether that is acceptable. **There is no expert override; the
2026-08-17 Q24 correction stands, and there is now nothing to override, because there is
no refusal.**

---

#### S-34 Review: fee, locktime, RBF (N)

**Purpose.** The other number attackers manipulate.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Fee                                          [ 9 / 10 ]      |
+----------------------------------------------------------------------+
|  Fee               0.00 004 210 BTC                                   |
|                    4210 sats                                          |
|                    18.6 sat/vB   (226 vB, estimated)                  |
|                    3.4% of the amount leaving                         |
|                                                                       |
|  Fee is computed by this device from the inputs it checked, not       |
|  taken from the file.                                                 |
|                                                                       |
|  Locktime          not set                                            |
|  Replaceable       yes (RBF signalled)                                |
|                                                                       |
|  [ < Prev ]                                          [   Next >   ]   |
+----------------------------------------------------------------------+
```

**Copy.** Over threshold (Q12: > 5% of send, or > 500 sat/vB), the fee block gets a
`WARNING` band: "This fee is 12.4% of what you are sending. Check it against your
wallet software." Negative fee is R-06, never a page.

Locktime set: "Locktime  block 812,000 - this transaction is not valid before that
block." or the timestamp form. Non-final sequences without RBF: "Replaceable  no".

**Edge states. Corrected 2026-08-19 against the implementation.** The wireframe printed a
bare "(226 vB)" and this paragraph reserved the word "estimated" for multisig with unknown
final witness sizes. Both understated it: a vsize quoted BEFORE signing is an estimate for
every ECDSA input, multisig or not. `notyas-core` grinds low-R (`sign_ecdsa_low_r`,
ratified Q3), which BOUNDS an ECDSA signature at `MAX_ECDSA_SIGNATURE_LEN` = 71 bytes
rather than fixing it there - R and S are DER-minimal, so a leading zero byte in either
(roughly one signature in 64) encodes a byte shorter and the broadcast transaction lands
smaller than the number on this page. The only input whose witness size is known before it
is signed is taproot key-path under SIGHASH_DEFAULT, where BIP-341 fixes the Schnorr
signature at 64 bytes with no encoding left to vary.

So the row reads "(226 vB, estimated)" whenever any input this device will sign is ECDSA,
and drops the qualifier only when every one of them is taproot key-path.
`TxReview::vsize_exact` is exactly that predicate; its doc comment names only the multisig
case today and is listed as an outside-fence correction. The reason is the one the old
paragraph gave and it is worth keeping: an exact-looking number that shifts after signing
erodes trust in every other number on the screen.

---

#### S-35 Review: warnings (N)

**Purpose.** Collect everything that is legal but notable, in one place, before the
hold.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Warnings                                     [ 10 / 10 ]     |
+----------------------------------------------------------------------+
|  +-----------------------------------------------------------------+  |
|  |  1. Fee is 12.4% of the amount leaving.                         |  |
|  |     0.00 004 210 BTC on 0.00 034 000 BTC sent.                  |  |
|  +-----------------------------------------------------------------+  |
|  +-----------------------------------------------------------------+  |
|  |  2. Outputs 2 and 4 pay the same address.                       |  |
|  |     This transaction pays it twice; check that is intended.     |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|  These are not errors. Read them, then sign or go back.               |
|                                                                       |
|  [ < Prev ]                                    [   Hold to sign   ]   |
+----------------------------------------------------------------------+
```

**Regions.** `ReviewPrev`, `HoldConfirm` (C4c), `Back`. The hold region appears only
here and only when the visited-set is complete; otherwise a `Disabled` button reads
"Review all 10 pages first - 2 not yet seen."

**Copy.** Warnings are numbered, each two lines: what, and why it matters. No
warning may be a bare noun phrase.

**Corrected 2026-08-19 against the implementation.** The second example read "Output 2
pays an address this wallet has already paid. / Reuse links your payments together." That
is not a warning this device can raise. Reuse against a wallet's PAST is a statement about
transaction history, and an airgapped signer has none - it holds a seed, wallet slots and
multisig registrations, and it sees exactly one PSBT at a time, with no chain, no index and
no network. A warning the firmware cannot evaluate either never fires or is fabricated, and
both are worse than its absence: a page of warnings a user learns to distrust is the page
the whole review builds towards.

Scoped to what one `Inspection` decides, the reuse-shaped warnings are two:

- **Two outputs in THIS transaction paying the same script.** "Outputs 2 and 4 pay the
  same address. / This transaction pays it twice; check that is intended." Decided by
  comparing `OutputFacts::script_pubkey` within the file, which is all the device holds.
- **A self-send.** An output whose role is `OwnNotChange` - ours, on the RECEIVE keychain,
  and so not netted out of the amount leaving: "Output 3 pays an address of this wallet. /
  It is not change, so the amount leaving counts it as money sent."

The rule that generalises, and the one to apply to any warning added later: every warning
on this page is a predicate over a single `Inspection`. The fee thresholds, the dust limit,
the locktime, the unproven-amount caveat and the unknown-field count all qualify. Anything
needing history, a price, a clock or a network does not, and does not belong here.

**Edge states.** No warnings: the page still exists (so the page count is stable and
the hold is always in the same place) and reads "No warnings." plus the same hold.

---

#### S-36 Hold to sign (C4c instance, on S-35)

Specified as part of C4c. On completion -> S-37.

Copy: idle "Hold to sign", holding "Keep holding - 0.6 s of 1.5 s", released
"Released - nothing was signed.", complete -> immediate transition (no success flash;
the next screen is the feedback).

---

#### S-37 Signing (C3 instance)

Heading "Signing", body "Deriving keys for each input, then signing.", determinate
meter "input 2 of 3", trailing "This cannot be cancelled." Post-sign verification runs
inside this screen and, if it fails, exits to C7 R-10.

---

#### S-38 Deliver (N, UX 11)

**Purpose.** Get the signed transaction out, with two independent exits so no flow can
end with a signed PSBT stranded in RAM.

**Enter / Exit.** From S-37. -> S-39 (QR), or writes and stays here with a result
band. Done -> S-21.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
|          Signed                                                       |
+----------------------------------------------------------------------+
|  +-----------------------------------------------------------------+  |
|  |  Signed - 3 of 3 inputs                                         |  |
|  |  This transaction is complete and ready to broadcast.           |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  |  This writes to the card:                                       |  |
|  |    psbt-2026-08-17-signed.psbt   (2.6 kB)                       |  |
|  |  Nothing secret is written.                                     |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|  [    Write to card    ]                     [    Show as QR     ]    |
|                                                                       |
|  Written. Remove the card.                                            |
|                                            [        Done        ]     |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Status card across the top, the two exits side by side beneath,
result band under them.

**Regions.** `DeliverSd`, `DeliverQr`, `DeliverDone`, `DeliverRetry` (appears only
after a failure). No Back: Back from a signed-but-undelivered transaction is exactly
the loss this screen exists to prevent; the only way out is Done, and Done is
`Disabled` until at least one delivery has succeeded, with the reason "Write to card
or show the QR first." **DECISION:** allow an override after two failed attempts -
`[ Discard signed transaction ]` as a C4b red card - because a user with a dead card
slot and no scanner must still be able to leave, and a device that traps them will be
power-cycled anyway (which is the same outcome, minus the informed consent).

**Copy.** Partial signature (multisig, not yet complete): the status card reads
"Signed 1 of 2 required signatures - this transaction still needs another cosigner."

**What 0.2.0 writes. Corrected 2026-08-19 against the implementation.** Q26 specified a
second file beside the signed PSBT, `psbt-2026-08-17-final.txn`, carrying the extracted
network transaction. 0.2.0 does not write it, and the wireframe above has been cut to what
it does write. `notyas-core` has no finalizer and no `extract_tx`: `psbt::sign` adds
`partial_sigs` and `tap_key_sig` and nothing else, and `firmware/src/signing.rs`'s `Signed`
hands back exactly one artifact, `psbt::encode(signed.psbt())`. So a delivery writes ONE
file, the signed PSBT, which is what every coordinator this device targets accepts and
finalizes for itself.

The `.txn` file is **awaiting a finalizer**, not dropped, and what it waits on is named so
nobody re-derives the absence: witness assembly per script type plus an extractor in
`notyas-core`, then a second `Artifact` and the write plan behind it. `FileKind::Txn`
already exists in the picker's vocabulary and stays. Until a finalizer ships, no screen may
print a `.txn` name.

One copy item follows from this and is left **OPEN** rather than rewritten here: the status
card's "This transaction is complete and ready to broadcast." is true of the SIGNATURES and
not of the file, since a signed PSBT still has to be finalized by the coordinator. Reword
it with the finalizer decision, not before it.

**Edge states.**
- Card missing at write time: R-23 inline (band, not a screen) "No card detected."
  with `[ Check again ]`; the QR exit stays available. **Corrected 2026-08-19: this cited
  R-24, which is "No PSBT files on this card" - the read-time code for a card carrying no
  transaction. The sentence quoted here was already R-23's, so the code was the only thing
  wrong.**
- Write failed part way: R-25 "Card write failed. The file may be incomplete - delete
  it before reusing the name." plus Retry and the QR exit.
- Existing file with the target name: C4a overwrite confirm.
- Card removed mid-write: same as write failure. FATFS is not power-loss safe and
  `SECURITY.md` says so; the artifact is re-creatable, which is why this is a
  yellow-card situation and not a red one.

---

#### S-39 Signed QR (C11 instance, UX 11)

Specified as component C11. Additional copy for this instance: the bar title is
"Signed transaction", the footer states "Scan with your wallet software. The sequence
repeats until you tap Done." `[ Also write to card ]` returns to S-38's write path.

**Edge state.** A PSBT too large for a comfortable frame count (> ~60 fragments at
default density) opens with a `WARNING` line: "This is a large transaction - 74
frames. Writing to the card is faster and more reliable." Density controls remain
available; we inform, we do not block.

---

#### S-40 Stateless signing entry (N, Q11)

**Purpose.** Sign with a seed the device never stores - the SeedSigner posture, kept
first-class for storage-averse users (`OPEN-QUESTIONS` Q11).

**Enter / Exit.** From S-09 ("Sign a transaction" on a blank device). -> S-14/S-12
(seed entry) -> S-15 -> S-16 -> here -> S-27 with a session-only wallet. Lock, power
off, or Done at the end of delivery drops the session.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Sign without saving                                          |
+----------------------------------------------------------------------+
|                                                                       |
|  fingerprint  a1b2c3d4        24 words        passphrase ON           |
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  |  Nothing is written to this device.                             |  |
|  |  When it locks or powers off, you retype the words to sign      |  |
|  |  again.                                                         |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  |  Multisig change cannot be checked in this mode. There is no    |  |
|  |  stored registration to check it against, so a multisig         |  |
|  |  transaction with change will be refused.                       |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|                                              [ Load a transaction ]   |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** The two notice cards sit side by side; the action spans the
bottom.

**Regions.** `ActSign` ("Load a transaction", >= 300x`btn`), `Back`.

**Copy.** The multisig limitation is stated before the user invests effort, not at the
refusal (R-31). Stateless multisig claims are refused, and **there is no expert override
that changes that** - the second card previously promised one and no longer does
(corrected 2026-08-17 by the ratified Q24). One wording item is still open at m6, per
Q12: whether the refusal covers all stateless multisig signing or only change claims.
The recommended answer is the broader one - without a registration the input's
witness-script membership is unverifiable too - in which case this copy must say
"multisig cannot be signed in this mode" rather than implying a change-free workaround.

**Masked / shown.** Fingerprint shown; no words, no key material.

**Edge states.**
- Auto-lock during a stateless session: suppressed during review/hold/QR as everywhere
  else, but on the wallet screens it applies and the warning band (S-49) adds "This
  wallet is not stored - locking loses it."
- Q11 rejected: this screen and `HomeSignStateless` do not exist, and S-09 has three
  buttons.

---

### 2.5 Multisig

---

#### S-41 Multisig registry (N, UX 12)

**Purpose.** List what this wallet is registered in, and import more.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Multisig - savings                                   [ Lock ]|
+----------------------------------------------------------------------+
|  +-----------------------------------------------------------------+  |
|  | vault 2of3                                    2 of 3   P2WSH    |  |
|  | m/48'/0'/0'/2'   this device: a1b2c3d4        registered        |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|  [ Import from card ]                    [ Export our xpub (BIP48) ]  |
+----------------------------------------------------------------------+
```

**Regions.** `ListRow(u8)`, `MsImport`, `MsExportXpub`, `Back`, `Lock`.

**Copy.** Empty state: "No multisig registrations. Import a descriptor or a Coldcard
multisig file from the card, or export this wallet's xpub so a coordinator can build
one."

**Edge states.** Registration whose record fails its tag: row in `DANGER`, "unreadable
- delete and import again".

---

#### S-42 Multisig import review (N, C5 instance)

**Purpose.** Defend against the 2021 xpub-substitution class
(https://benma.github.io/2021/02/09/coldcard-multisig-vulnerability.html): the user
must see every cosigner, and the device must state that it found itself.

**Enter / Exit.** From S-41 -> C3 ("Reading card") -> here. Approve -> C3
("Saving registration") -> S-43. Reject/Back -> S-41.

**Wireframe (720x720), page 1.**

```
+----------------------------------------------------------------------+
| < Back   Import multisig                              [ 1 / 5 ]       |
+----------------------------------------------------------------------+
|  Name              vault 2of3                                         |
|  Policy            2 of 3        sortedmulti                          |
|  Script            P2WSH (native segwit)                              |
|  Derivation        m/48'/0'/0'/2'                                     |
|  Network           mainnet                                            |
|                                                                       |
|  +-----------------------------------------------------------------+  |
|  |  This device is cosigner 1 of 3 (a1b2c3d4).                     |  |
|  |  Checked: the key at this path on this device is in the set.    |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|  You will see each cosigner key in full on the next pages.            |
|                                             [       Next >       ]    |
+----------------------------------------------------------------------+
```

**Pages 2-4**: one cosigner each - fingerprint, path, full xpub in a C8 block with the
offset gutter, and "this device" marked on ours. **Page 5**: the first receive address
this registration produces, full, chunked, with "Compare this address on your other
signing devices before you use this wallet." and the approve action.

**Regions.** `ReviewPrev`, `ReviewNext`, `MsApprove` (page 5 only, after full
traversal), `MsReject`, `Back`.

**Copy.** Membership failure (our key is not in the set) is a refusal, not a page:
R-04, "This device is not one of the cosigners." with "Why this matters: importing a
wallet you cannot sign for is how a substituted key gets accepted."

**Masked / shown.** Everything shown: xpubs are public, and the entire point is
comparison.

**Edge states.**
- Coldcard `.txt` dialect: converted on ingest, and page 1 states "Imported from a
  Coldcard multisig file and converted to a descriptor." with the resulting descriptor
  viewable on page 5.
- Duplicate registration: C4a "This registration is already stored. Replace it?"
- More than 8 cosigners: pages grow; traversal is still enforced. No cap below 15.

---

#### S-43 Multisig detail (N)

**Purpose.** Re-inspect, re-export, cross-check, delete.

**Wireframe (720x720).** Page 1 of S-42's content, plus an action list: `[ Show all
cosigners ]` (re-enters the paged review, read-only), `[ Show first address ]`,
`[ Export to card ]`, `[ Export as QR ]`, `[ Delete registration ]` (C4d, typed name).

**Regions.** `MsCosigners`, `MsFirstAddress`, `MsExportSd`, `MsExportQr`, `MsDelete`.

**Copy.** Delete confirmation: "Delete registration 'vault 2of3'? This wallet can no
longer verify change or addresses for it until you import it again. Your keys are not
affected."

---

### 2.6 Settings, verification, danger

---

#### S-44 Settings (N, UX 14)

**Purpose.** Device-level settings, honestly labelled, with the dangerous ones last.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Settings                                             [ Lock ]|
+----------------------------------------------------------------------+
|  | Device name                                  "kitchen-desk"   >  |  |
|  | Lock word                                    ANVIL            >  |  |
|  | Screen brightness                            70%              >  |  |
|  | Lock after                                   2 minutes        >  |  |
|  | QR defaults                                  6 fps, 200 B     >  |  |
|  | Change PIN                                                    >  |  |
|  | Wrong-PIN policy                             erase after 10   >  |  |
|  | Expert options                               off              >  |  |
|  | Verify device                                                 >  |  |
|  +-----------------------------------------------------------------+  |
|  | Erase this device                                             >  |  |
|  +-----------------------------------------------------------------+  |
+----------------------------------------------------------------------+
```

**Regions.** `SetRow(u8)` per row (>= `LIST_ROW_MIN`), `Back`, `Lock`. The erase row
is visually separated by a full gap and drawn with `DANGER` ink on `DANGER_TINT`.

**Copy per sub-screen** (each is a C2 list of choices or a small form; they share one
layout and are not specified individually beyond their copy):

- **Device name** (S-44a): keyboard entry, first row of the list. The screen explains
  what the name is - "Shown on the lock screen, before any PIN is typed. Anyone holding
  the device can read it." - and what it is not: "It tells your devices apart. It is not
  proof - the device words on the PIN screen are that." It refuses non-ASCII, an
  all-digit string, a BIP-39 word, and anything too wide for the narrowest shipped
  panel. Empty is legal and means unnamed. There is no lock-word screen (Q64).
- **Screen brightness**: five steps, applied live.
- **Lock after**: 1 / 2 / 5 / 15 minutes / never. "Never" carries "The session stays
  open until you power off or tap Lock."
- **QR defaults**: fps and fragment size, matching C11's steps.
- **Change PIN**: S-04 (old) -> S-06/S-07 (new) -> C3 ("Re-encrypting wallets") with
  the WriteNotice "Every stored wallet is re-encrypted with the new PIN and the old
  copies are erased." Failure mid-way leaves the old PIN authoritative (A/B slots) and
  says so.
- **Wrong-PIN policy**: shows the current N and its bounds (Q5, ratified: 3..=25,
  default 10), with "After N wrong PINs the device erases its stored wallets. Your dice
  rolls or seed words bring back your coins, but your multisig registrations and
  settings are gone." Two additions required by Q5's ratification: the copy is a format
  string over N, not the hardcoded "10" it is elsewhere in this document; and the screen
  must state that an interrupted verification costs an attempt - "If the device loses
  power while checking a PIN, that attempt still counts. Otherwise power-cutting would
  be a free way to guess." Whether N is editable here at all depends on the m3 decision
  Q5 left open (superblock rewrite path versus format-time-only); if it is
  format-time-only this row is read-only and says so.
- **Expert options**: a single toggle gating the WARNING thresholds only - the fee
  percentage and sat/vB (Q13) and the lookalike-address sensitivity (Q42). Copy:
  "Expert options change when this device warns you. They cannot turn off a check that
  makes the device refuse." Each threshold inside is individually named; there is no
  master bypass and there is no sign-anyway. **Corrected 2026-08-17 by the ratified
  Q24: this copy previously read "Expert options let you sign transactions this device
  would otherwise refuse", which is exactly what Q24 forbids, on the very screen Q24
  cited approvingly.** In the policy types, `warn_percent_of_send` and `warn_sat_per_vb`
  are settable from here; `sighash` and `hard_max_percent` are not.
- **Firmware**: read-only rows inside Verify device (S-46): version, running SHA256,
  and "Firmware is updated by USB reflash from a computer. This device never updates
  itself."

**Edge states.** Stateless device (no PIN): PIN, wrong-PIN policy and erase rows are
absent, not disabled - there is nothing to configure. The screen says "This device has
nothing stored. Settings that protect stored wallets appear once you save one."

---

#### S-45 Wallet settings (N)

**Purpose.** Everything that belongs to one wallet rather than to the device.

**Enter / Exit.** From S-21. Rows lead to their own screens; Back -> S-21.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   savings - settings                                   [ Lock ]|
+----------------------------------------------------------------------+
|  | Rename                                       "savings"        >  |  |
|  | Show seed words                              reveal gate      >  |  |
|  | Check backup again                           last: 14 Aug     >  |  |
|  | Account number                               0                >  |  |
|  | Script type                                  native segwit    >  |  |
|  +-----------------------------------------------------------------+  |
|  | Delete this wallet                                            >  |  |
|  +-----------------------------------------------------------------+  |
+----------------------------------------------------------------------+
```

**Reflow (800x480).** Single column; the list is short enough at both geometries.

**Regions.** `SetRow(u8)` per row (>= `LIST_ROW_MIN`), the delete row separated by a
full gap and drawn `DANGER` on `DANGER_TINT`.

**Copy per row.**
- **Rename**: keyboard, same rules as S-20. "Renaming does not change the wallet's
  keys or its fingerprint."
- **Show seed words**: goes through S-13's reveal modal verbatim. The row's secondary
  text is "reveal gate", so the consequence is visible before the tap.
- **Check backup again**: the Trezor-style dry run - the user types the words (S-14)
  and the device answers "These words match this wallet." or "These words do not match
  this wallet." and nothing else. It never displays the stored words during a check,
  which is the whole point of a dry run. On a match it updates the "backup verified"
  date; on a mismatch it does not clear it, and says "The stored wallet is unchanged.
  Check which backup you read from."
- **Account number / Script type**: read-only in 0.2.0, shown because they are part of
  the wallet's identity; changing them is creating a different wallet, and the row's
  detail screen says exactly that.
- **Delete this wallet**: S-47 (C4d).

**Masked / shown.** Nothing revealed without passing S-13's gate. The dry-run check
never renders a stored word.

**Edge states.** Session-only wallet: the rows that write (rename, backup date) are
absent, and a band reads "This wallet is not stored, so there is nothing to change
here. Save it first."

---

#### S-46 Verify device (E, 0.1.0 VerifyDevice)

**SUPERSEDED IN DETAIL 2026-08-17 by `VERIFY.md`, which is the owner document for this
screen.** This entry keeps S-46 in the inventory and keeps its component vocabulary; the
row set, the six frozen sections, the frozen field order, the row kinds, the geometry and
the CI assertions are `VERIFY.md` sections 10-11. The sketch below is retained as the
0.1.0-plus-storage baseline it was, not as the build spec. Read `VERIFY.md` before
implementing anything here. (Authority rule, `MILESTONES.md` 1.1: the companion wins on
WHAT is built inside its domain; this file still owns the inventory, the component library
and the copy vocabulary that document uses.)

**Purpose.** 0.1.0's screen, extended with storage and eFuse truth.

**Wireframe.** 0.1.0's scrolling key/value list, plus rows:

```
| Storage                     2 wallets, 6 free slots                   |
| Wallet partition            present, 64 kB                            |
| HMAC eFuse key              burned, read-protected                    |
| Anti-rollback               enabled, version 2                        |
| Flash encryption            enabled (release)                         |
| Secure boot                 enabled, RSA-3072                         |
```

**Copy.** Values are what the firmware actually read - never a constant, never a
reassuring default. Absent readings render "not read" (0.1.0's honest placeholder).

**Edge states.** Q2 (duress) accepted: the storage row degrades to "present" / "blank" and
a footnote states why the count is not shown.

**Struck 2026-08-17, and the reason is worth keeping.** This entry previously said: "Dev
board with flash encryption off: the row is `WARNING` with 'disabled - a stored wallet on
this board is protected by the PIN only.'" `VERIFY.md`'s design contract rule 2 forbids
exactly that - no verdicts, no risk language, no advice sentence beside a value; `Flash
encryption   disabled` is the whole row, and the only semantic colour that survives on this
screen is the self-test `FAIL` row and the radio-kill row, where the word carries the
meaning. The contract wins, because a screen whose purpose is to let an owner read raw
values loses that purpose the moment it starts interpreting them, and because the field
order and colour rules are CI-asserted while a prose caveat is not.

The caveat itself is real and is not dropped - it moves to where it is actionable. A dev
board's stored wallet IS protected by the PIN ladder alone (`SECURITY.md` invariant 6), and
the place to say so is the moment the user chooses to store one: the "Save (PIN-protected)"
fork in the create and restore flows, and the wipe-policy sub-screen. A warning at the point
of decision changes behaviour; a warning on an instrument panel the user opened to read
hex does not.

---

#### S-47 Delete wallet (C4d instance)

Full copy in C4d. Reached from wallet settings. On confirm -> C3 ("Erasing wallet
slot") -> S-10 with a status band "Deleted 'savings'."

**Edge states.** Deleting the open wallet drops the session first. Deleting the last
wallet lands on S-10's empty state, not S-09 (a PIN still exists).

---

#### S-48 Erase this device (C4d instance)

**Purpose.** Crypto-erase everything: wallet slots, registrations, settings, PIN.

**Wireframe (720x720).**

```
+----------------------------------------------------------------------+
| < Back   Erase this device                                            |
+----------------------------------------------------------------------+
|  +-----------------------------------------------------------------+  |
|  |  This erases all 3 wallets, 2 multisig registrations, the PIN   |  |
|  |  and all settings. The device returns to blank.                 |  |
|  |  Your dice rolls or seed words are the only way back.           |  |
|  +-----------------------------------------------------------------+  |
|                                                                       |
|  Type WIPE to confirm:                                                |
|  +-----------------------------------------------------------------+  |
|  | WIP_                                                            |  |
|  +-----------------------------------------------------------------+  |
|             ( keyboard )                                              |
|                                                                       |
|  [ Cancel ]                        [ Hold to erase  (disabled) ]      |
+----------------------------------------------------------------------+
```

Two grades stacked deliberately: typed word **and** hold (C4c with `DANGER` fill).
This is the only action in the product that requires both, because it is the only one
that destroys every stored artifact at once.

**S-48b post-wipe screen**: "This device is blank. 3 wallets, 2 registrations and the
PIN were erased. Restore from your dice rolls or seed words." with `[ Continue ]`
to S-09.

---

#### S-49 Auto-lock (N)

**Purpose.** Warn before the session is dropped, so a user reading an address is not
ambushed.

**Wireframe.** A C4a-shaped band at the bottom of whatever screen is showing (not a
modal - it must not block the content being read):

```
  +------------------------------------------------------------------+
  |  Locking in 20 s.                              [ Stay unlocked ]  |
  +------------------------------------------------------------------+
```

**Regions.** `StayUnlocked` (>= 240x`TOUCH_MIN`).

**Edge states.** Never appears during a review, a hold, a busy operation, or QR
playback: those screens suppress auto-lock entirely and the timer restarts when they
exit. A device that locks mid-signature-review would be its own denial of service.

---

## 3. Copy reference

### 3.1 Button labels (the whole vocabulary)

Verbs, never "OK". One label per concept across the product.

| Concept | Label |
|---|---|
| Advance a review | `Next >` |
| Retreat a review | `< Prev` |
| Leave a screen | `< Back` |
| Finish a flow | `Done` |
| Commit a write | `Save wallet`, `Write to card`, `Set PIN`, `Approve` |
| Destroy | `Delete wallet`, `Erase this device`, `Delete registration` |
| Sign | `Hold to sign` |
| Re-attempt | `Retry`, `Check again` |
| Show more | `Show details`, `Show all cosigners`, `Show all files` |
| Escape hatch | `Show as QR`, `Choose a different file` |

### 3.2 Refusal codes and their exact text

Codes are stable, printed on the refusal screen, and asserted in CI with the
rendered text (`MILESTONES.md` m6/m7 gates). Numbers 01-10 track the policy checks in
`ARCHITECTURE.md` 5.3 one-to-one; 20+ sit outside that numbering. Most of the 20s are
transport and device conditions, and the rest are refusals LIFTED out of a check group
because the group's copy is about a different situation: R-21 and R-22 (a version and a size
a user must not be told two different things about depending on which bound caught the file)
and R-26 (a script type this device does not sign, which is not a cosigner mismatch and must
not wear R-04's words). A lift changes which sentences are shown and nothing else - the
check that refused, its number, and the engine's own "what happened" line are unchanged.

| Code | Headline | What happened (template) | Why this matters | What to do |
|---|---|---|---|---|
| R-01 | These inputs are not from this wallet | "None of the 2 inputs derive from savings (a1b2c3d4)." + when a stored wallet matches: "These inputs belong to 'vault 2of3' (9f3e17aa)." | "Signing needs the wallet that owns the coins." | "Open that wallet and load the file again." / "Check you loaded the right file." |
| R-02 | Missing the previous transaction | "Input 2 states an amount but does not include the transaction it came from." | "Without it the amount cannot be checked. A wrong amount is how a signer is tricked into paying its balance as a fee." | "Re-export with full previous transactions included, then load it again." |
| R-03 | Change output not proven | "Output 2 is marked as change, but this device could not derive that address from your wallet at the path the file claims." | "This is exactly what an attacker does to redirect your change." | "Do not sign. Check the transaction in your wallet software." |
| R-04 | Cosigner keys do not match | "The keys in this transaction do not match the stored registration for 'vault 2of3'." | "A substituted cosigner key sends your coins to someone else's multisig." | "Compare the registration on all your devices. Import it again if it changed legitimately." |
| R-05 | Wrong network | "This transaction is for testnet. The open wallet is mainnet." | "Signing across networks can expose keys that were meant to stay separate." | "Open the testnet wallet, or load a mainnet transaction." |
| R-06 | Fee is impossible | "The outputs are worth more than the inputs. This transaction cannot be valid." | "A negative fee means the file is corrupt or hostile." | "Rebuild the transaction in your wallet software." |
| R-07 | Unsupported signature type | "Input 1 asks to be signed with SIGHASH_NONE." | "notyas signs SIGHASH_ALL only. Other types let the outputs be changed after you sign." | "Rebuild the transaction with the default signature type." |
| R-08 | Unexpected taproot data | "Input 1 carries a taproot annex this device does not understand." | "Signing data the device cannot interpret is signing a blank cheque." | "Rebuild the transaction without it." |
| R-09 | This file is malformed | (variant per case: "Input 3 appears twice." / "Input 1 is already finalized." / "The file ends part way through an input.") | "A signer that accepts malformed input is a signer that can be steered." | "Re-export the transaction and load it again." |
| R-10 | Signature check failed | "The device produced a signature that did not verify against its own recomputed hash." | "This is a device fault, not a problem with your transaction. Nothing was signed and nothing was written." | "Run Verify device and report this with the details below." |
| R-20 | This file is not a PSBT | "psbt-2026-08-17.psbt does not start with a PSBT header." | "The device reads PSBT files only." | "Check the file, or choose a different one." |
| R-21 | PSBT version 2 is not supported | "This file is a version 2 PSBT." | "This device reads version 0, which is what wallet software produces today." | "Export as a version 0 PSBT." |
| R-22 | File is too large | "spend-vault.psbt is 1.4 MB. The limit is 512 kB." | "The device holds the whole transaction in memory to check it." | "Split the transaction, or use fewer inputs." |
| R-23 | No card detected | "No card is in the slot, or it cannot be read." | - | "Insert a FAT32-formatted card and try again." |
| R-24 | No PSBT files on this card | "The card has 12 files and none of them is a .psbt." | - | "Copy the transaction onto the card, or show all files." |
| R-25 | Card write failed | "Writing psbt-signed.psbt stopped after 1.2 kB." | "The file on the card is incomplete." | "Delete that file, then retry - or show the signed transaction as a QR instead." |
| R-26 | Not a script this device signs | "Input 0 is a legacy address, which is not a script this device spends." | "This device signs only script types it can verify end to end. Anything else is refused rather than signed blind." | "Spend these coins from a wallet that supports this script type. If this is a wrapped-segwit coin, re-export the transaction with its redeem script included." |
| R-30 | No wallet is open | "This action needs an unlocked wallet." | - | "Open a wallet from the list." |
| R-31 | Multisig needs a registration | "This wallet has no stored multisig registration, so change cannot be verified." | "Without the registration the device cannot tell your change from an attacker's address." | "Import the registration, or sign from the stored wallet that has it." |
| R-32 | Storage is unreadable | "Both copies of wallet slot 4 failed their integrity check." | "The record is damaged or was written by a different device." | "Restore from your dice rolls or seed words. Erasing the device clears the damaged slot." |
| R-33 | The wallet was not saved | "Writing the wallet slot failed. Nothing was changed." | - | "Retry. If it keeps failing, run Verify device." |

### 3.3 Notable copy decisions

1. **"Leaving this wallet"** as the headline amount on the review overview, rather
   than "Amount" or "Total". It is the number that answers "how much am I spending?"
   and it excludes change by construction.
2. **No word "confirm" on a destructive button.** The button says what it does
   (`Delete wallet`), so a screenshot of the moment of consent is self-describing.
3. **"NOT FOUND", "SELF-TEST FAILED", "BACKUP UNCHECKED"** are the only uppercase
   strings. Uppercase is reserved for states that should stop a user, and the badge
   vocabulary in S-32 uses it for the same reason.
4. **Refusals never say "invalid"** on its own. "Invalid" tells a user nothing; every
   refusal names the specific field and the specific consequence.
5. **The device never apologises and never reassures.** No "Sorry", no "Don't worry",
   no "Successfully". A write either happened ("Written. Remove the card.") or did not.
6. **"This device has no camera"** is stated where a user looks for scanning (S-11,
   S-27), not buried in documentation.
7. **Security claims are mechanism statements.** "Stored encrypted. The PIN is the
   key." and "A digits-only PIN protects against theft, not against a funded lab."
   (Q5's wording, kept verbatim.) Nothing on screen calls anything "secure".
8. **The backup sentence is one sentence, everywhere it appears**: "Your dice rolls
   or seed words are the only way back." It appears on every destructive screen, word
   for word, so it reads as a device-level fact rather than per-screen boilerplate.
9. **Two failures share a code only when one instruction answers both.** R-26 exists
   because `ClaimedInputNotSingleSig` used to render R-04: a single-sig spend of the user's
   own legacy coins was described as a cosigner-substitution attack, and he was told to
   compare registrations he did not have (`docs/KNOWN-ISSUES.md` K31, 2026-08-22). R-04
   stays reserved for a genuine mismatch in a cosigner SET, which is the 2021 substitution
   attack's own code and the one refusal on this device that has to be believed the instant
   it appears; spending its credibility on a script-type refusal is how it stops being
   believed. The residual is recorded rather than hidden: the engine's "what happened" line
   under an R-26 band still names check 4, because the check numbering above is ratified and
   that line is the engine's own words.

---

## 4. RegionId additions

The 0.2.0 additions to `RegionId`, grouped as the enum should be ordered. All existing
0.1.0 variants stay, unchanged in name and meaning.

```rust
// --- shared chrome ---
Lock, SettingsOpen,
ListRow(u8), ListPagePrev, ListPageNext,
ReviewPrev, ReviewNext,
HoldConfirm, BusyStop, RefusalDetails, SelfTestDetails,
StayUnlocked,

// --- lock / PIN ---
LockWake, PinKey(u8), PinBackspace, PinAlpha, PinShowWords,
PinSubmit, PinNext, PinConfirm, PinPolicyInfo,

// --- wallets ---
WalletNew, WalletRestore, NewFromDice, NewFromWords,
QuizChoice(u8), SaveToDevice, UseOnce, NameField, ConfirmSave,
HomeRestore, HomeSignStateless,

// --- wallet home ---
ActReceive, ActSign, ActExport, ActMultisig, ActWalletSettings,

// --- addresses ---
AddrRow(u8), AddrPrev, AddrNext, AddrJump,
VerifyAddrOpen, VerifyAddrField, VerifyAddrFromSd, VerifyAddrCheck, VerifyAddrAgain,
QrDescriptor, ExportToSd,

// --- signing ---
SignReady, SignPickFile, FileRefresh,
DeliverSd, DeliverQr, DeliverDone, DeliverRetry, DeliverDiscard,
QrPlayPause, QrSlower, QrFaster, QrDenser, QrSparser,

// --- multisig ---
MsImport, MsExportXpub, MsApprove, MsReject, MsCosigners,
MsFirstAddress, MsExportSd, MsExportQr, MsDelete,

// --- settings / danger ---
SetRow(u8), SetChoice(u8), DangerConfirm, DangerCancel,
```

Naming rules: a variant names the *meaning* of the tap, never the widget or its
position (0.1.0's rule); indexed variants index the visible page, not the underlying
collection, so hit-testing never depends on scroll state.

---

## 5. Reflow rules (720x720 vs 800x480)

The rules, in priority order. Every screen's reflow note above is an application of
these; a screen that needs a rule of its own is a design smell.

1. **Landscape splits into content + rail.** When `Metrics::landscape()`, screens with
   a dominant content block and a small action set place the actions in a right-hand
   rail of width `clamp(w/4, 220, 300)`; the content keeps the rest. Applies to: PIN
   (pad in the rail), review pages (Prev/Next in the rail), wallet home (action cards
   in two columns), deliver.
2. **Keypads move beside, never shrink.** Dice and PIN keys keep
   `KEYPAD_KEY_MIN`; if the stacked arrangement cannot hold them, the layout splits
   into columns (0.1.0's dice screen already does exactly this).
3. **Verification data gets the width.** In any split, the mono block takes the wider
   column. At 800x480 an address reaches four groups per line and the block gets
   shorter; that is the panel's one advantage and the layout takes it.
4. **Nothing is dropped, only relocated.** No screen may hide a region on the shorter
   panel. If content does not fit, it scrolls (reference) or pages (verification) -
   never disappears. The region-parity test asserts `regions()` returns the same
   `RegionId` set at both geometries for every state.
5. **The badge, the warning band and the header are always full width.** They are
   read first and they must not compete with a column boundary.
6. **Portrait scaffolds** (unverified boards) inherit the 720x720 arrangement and keep
   their boot warning; no separate design work.

---

## 6. What CI asserts about these screens

The spec is only real if it is tested. These are the tests this document implies, all
at both geometries:

- **R-TOUCH / R-SEPARATION / R-NOTHROUGH** (section 0.3) over every state.
- **Region parity**: identical `RegionId` sets across geometries per state.
- **Masking equality**: byte-identical frames for different secrets on every masked
  screen (0.1.0's mnemonic test, extended to PIN, quiz-pre-reveal, all busy screens).
- **Quiz fairness**: correct-answer slot distribution uniform over the wordlist; the
  correct candidate is not distinguishable by any style attribute.
- **Traversal enforcement**: for every review, the terminal action's `RegionId` is
  absent from `regions()` until the visited-set is complete (fuzzed page orders).
- **Refusal corpus**: every adversarial PSBT in the corpus renders its exact expected
  headline, code, and all three body sections; every code in section 3.2 has at least
  one corpus case.
- **No-truncation**: for every screen that renders an address, xpub or descriptor,
  the rendered character sequence (recovered from the draw calls) equals the source
  string, modulo the chunking spaces. The address *list* (S-22) is the single
  allow-listed exception and is asserted to be excluded from verification contexts.
- **Busy-before-block**: a harness asserts that no `Ui::tick` work item exceeding
  150 ms is reachable from a state that is not a Busy variant.
- **String inventory**: every literal on screen is in a single table, checked ASCII-only
  (except `theme::BULLET`) and checked against a banned-words list ("secure", "safe",
  "simply", "just", "please", "sorry", "successfully", "oops").

---

## 7. Deliberately not screens in 0.2.0

Named so nobody has to re-derive the omission:

- **Message signing (BIP-137 / BIP-322)** - `PARITY.md` class a, but it is a separate
  review-and-consent surface with its own refusal cases; 0.2.x.
- **BIP-85, Seed XOR, seed vault, BIP-39 passphrase saved to card** - class a/b math,
  no 0.2.0 milestone.
- **Encrypted SD backup** - Q8 says no for 0.2.0.
- **Duress PIN screens** - Q2 is a blocker; if accepted, it changes S-01, S-03, S-46
  (storage readout degrades) and adds nothing else visible, which is the point.
- **Calculator login, trick PINs, login countdown** - `PARITY.md` class b/d, deferred.
- **Any screen that scans** - no camera (CAMERA.md).

---

## 8. Open items - ALL RESOLVED 2026-08-17

Every item in this section was ratified in OPEN-QUESTIONS.md's 2026-08-17 pass. The
recommendations are kept verbatim below because they are the reasoning behind the
decision; the outcome of each is stated first.

- **PIN pad shuffle domain -> Q35, accepted as specified.** One added requirement from
  Q45: this derivation runs on the eFuse key, so it cannot run on an unprovisioned
  device and that path needs specified behaviour.
  **REVERSED 2026-08-19.** The pad is fixed phone order and nothing is derived for it,
  so the Q45 requirement above no longer applies to this item. The recommendation kept
  below is the record of a decision that was made, held for two days, and then
  overturned by the project owner - see Q35 and C10 for what was traded.
- **Deliver escape hatch -> Q36, accepted.**
- **Wrong-PIN policy visibility -> Q37, ratified in the form that holds under every Q2
  outcome:** the threshold is always shown; the slot count's visibility is Q2's to
  decide and is not a separate question.
- **Address list truncation -> Q38, truncated preview kept.**
- **Expert overrides -> Q24, and the recommendation below was ACCEPTED ONLY IN PART.**
  The gate is ratified for WARNING thresholds. It is refused for "sign-anyway": no
  override may disable a refusal. S-44's copy and the S-31 / S-33 / S-40 override
  branches have been corrected above.


`OPEN:` **PIN pad shuffle domain.** The randomized keypad permutation derives from the
device-bound HMAC ladder with its own HKDF info string (C10). Recommendation: accept
as specified - it keeps invariant 3 (no RNG anywhere) mechanically checkable, and a
display permutation does not need cryptographic unpredictability, only
unpredictability to an observer between attempts.

`OPEN:` **Deliver escape hatch.** S-38 traps the user until one delivery succeeds,
then offers `[ Discard signed transaction ]` (C4b) after two failures. Recommendation:
accept - the alternative is a power cycle, which discards it anyway without informed
consent. Reject only if you would rather the device never offers to discard a
signature it has already produced.

`OPEN:` **Wrong-PIN policy visibility.** S-44 shows the current wipe threshold and
Q3 sets its default. If Q2 (duress) is accepted, showing the threshold is fine but
showing the *slot count* is not (S-01, S-03, S-46 all degrade together).
Recommendation: decide Q2 first; this spec is written for the non-duress default and
flags all three touch points.

`OPEN:` **Address list truncation.** S-22 truncates addresses in the navigation list
and states "never check an address from this list". The stricter alternative is a list
of indices and paths only, with no address text at all. Recommendation: keep the
truncated preview - users navigate by the first characters they already know, and the
verification screen (S-23) is one tap away and never truncates. Reject if you want a
zero-truncation product with no exceptions to explain.

`OPEN:` **Expert overrides.** S-44 gates fee thresholds and sign-anyway on a single
"Expert options" toggle, with each override individually named inside and no master
bypass. Recommendation: accept. Q12 already puts fee constants behind an expert gate;
this is the same gate, and refusing to build one pushes determined users toward
patched firmware, which is worse.
