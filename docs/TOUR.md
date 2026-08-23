# A tour of notyas

What using the device looks like, function by function. Every picture and every recording
on this page is rendered by the host simulator (`tools/uisim`) from the same
`crates/notyas-ui` code the device runs, at the geometries the two verified boards have.
Nothing here is a photograph and nothing here is drawn by hand; the still frames are
regenerated and byte-diffed on every CI run
([docs/screenshots/ui/](screenshots/ui/README.md)). Where a control or a state is named in
quotes, that is the string the firmware contains today.

Sample data throughout is public test-vector material: 64 sixes, which is BIP-39 test
vector #1, and placeholder device values each prefixed DUMMY. None of it is a usable seed.

1. [Two ways in](#two-ways-in)
2. [Making a wallet](#making-a-wallet)
3. [Getting a receive address](#getting-a-receive-address)
4. [Exporting to a coordinator](#exporting-to-a-coordinator)
5. [Reviewing and signing a transaction](#reviewing-and-signing-a-transaction)
6. [Checking the device is the one you left](#checking-the-device-is-the-one-you-left)
7. [Managing what is stored on it](#managing-what-is-stored-on-it)
8. [What a refusal looks like](#what-a-refusal-looks-like)

---

## Two ways in

A device with nothing saved opens on a menu: "New seed (dice)", "Verify existing seed" and
"Verify device", with a mainnet/testnet toggle above them. Nothing is written unless you
choose to write it. A device that has saved a wallet opens "Locked", and the PIN is the way
in: a wrong PIN costs an attempt, and at the configured threshold the device erases what it
has stored.

| | | |
|---|---|---|
| ![A device with nothing saved](screenshots/ui/01-home.png) | ![Locked](screenshots/ui/16-lock.png) | ![The wallet list](screenshots/ui/136-wallet-list-one.png) |
| A device with nothing saved: the menu is the way in | A device that has saved a wallet opens "Locked" | After the PIN: "Wallets", and what the device is holding |

The lock screen prints the name its owner gave the device, the version, and whether the
internal store holds anything. It says nothing about how many wallets there are, and it
never prints an attempt count. "Verify device" is reachable from it without typing a digit,
which is the point: a user who suspects a swapped device can check the firmware hash first.
A device nobody has named says so rather than leaving the row blank.

| | | |
|---|---|---|
| ![No name set](screenshots/ui/16b-lock-no-name.png) | ![PIN entry](screenshots/ui/17-pin-entry.png) | ![The device words](screenshots/ui/18-pin-device-words.png) |
| A device nobody has named yet | The pad. It is the same 3x4 keypad on every panel | At half entry: two words derived from the eFuse key |

Those two words are the anti-phishing check: the device works them out from the first four
digits you typed and a secret only it holds. Its own words for what that buys are "No copy
of this device can work them out. Check them BEFORE you type the rest of your PIN." The
first time they appear after a power-up it says that over the pad and waits.

| | | |
|---|---|---|
| ![What the words are](screenshots/ui/18a-device-words-explained.png) | ![A wrong PIN](screenshots/ui/19-pin-wrong.png) | ![The last attempt](screenshots/ui/142-pin-last-attempt.png) |
| Raised once per power-up, over the pad, and acknowledged | A wrong PIN, and what it cost | One attempt left before the stored wallets go |

The way back out is the "Lock device" chip in the top bar of the wallet list, the wallet
menu and settings. It drops the session and lands on "Locked" again, which is the return
leg no still frame presents as one.

![The round trip](media/unlock-and-lock.gif)

*Locked, the pad, the device words, a wrong PIN, "Wallets", the same dice screen the other
entrance reaches, and "Lock device" back to where it started.*

Both entrances run the same screens once you are past them, and both end at the same
question. That question is the next section.

A card on the lock screen that would reach dice entry without a PIN is specified in
[docs/archive/plan-0.2.0/SIMPLE-MODE.md](archive/plan-0.2.0/SIMPLE-MODE.md) and is not in this build:
`crates/notyas-ui/src/screens/door.rs` is written and has no call sites, and
`crates/notyas-ui/src/screens/lock.rs` still pushes the PIN pad and the Verify chip and
nothing else. There is no picture of it here because there is nothing to photograph. Two
details of that plan are also stale against the tree, and are flagged rather than repeated:
its wireframes draw a lock-screen word panel that was deleted on 2026-08-19, and its flow
diagram ends a dice-only run on the export screen where the shipped run ends on the session
wallet home.

---

## Making a wallet

Roll dice, or type a mnemonic you already have. The dice screen keeps a roll history and a
running count of effective bits, in six modes: RAW, which is a prefix-free variable-length
base-6 code, and fixed 12/15/18/21/24-word. The words that come out are masked, and a
two-step confirm stands between them and the screen.

| | | |
|---|---|---|
| ![Dice entry](screenshots/ui/02-dice-entry.png) | ![Masked](screenshots/ui/03-mnemonic-masked.png) | ![The reveal confirm](screenshots/ui/04-reveal-confirm.png) |
| Roll history, mode strip, effective bits | Masked by default, in fixed six-bullet runs | Two steps between the words and the panel |

![Rolling a seed](media/dice-entropy.gif)

*The meter following the rolls actually entered, then the words.*

Restoring works the other way round: type the phrase, with BIP-39 autocomplete, a checksum
verdict, and a helper that finishes the last word once eleven are in - at that point only
128 of the 2048 words can be the twelfth.

| | | |
|---|---|---|
| ![Typing a phrase](screenshots/ui/11-phrase-entry.png) | ![Autocomplete](screenshots/ui/15-phrase-autocomplete.png) | ![The final word](screenshots/ui/65-final-word-helper.png) |
| A checksum verdict under what you typed | The completion strip at full width | Eleven words in, the screen finishes the phrase |

Then the optional BIP-39 passphrase, which is opt-in and has a Show/Hide toggle and an NFKD
byte counter, and then the backup check. The check is word by word, it is asked on both
paths, and it cannot be skipped: no backup exists until it is verified.

| | | |
|---|---|---|
| ![The passphrase](screenshots/ui/06-passphrase.png) | ![Show on](screenshots/ui/13-passphrase-shown.png) | ![The backup check](screenshots/ui/40-backup-check.png) |
| One bullet per typed character, with a byte count | The literal input, spaces as muted bullets | Word by word, on both paths, never skipped |

**The fork is the only place anything is written**, and it comes after the backup check
with the words already behind you. What the Save card promises depends on the device you
are holding: one that has no PIN is told saving sets one, one that already has a PIN is
told the PIN is the key.

| | |
|---|---|
| ![The fork, no PIN yet](screenshots/ui/41-keep-or-save.png) | ![The fork, PIN already set](screenshots/ui/159-keep-or-save-with-pin.png) |
| "Sets a PIN first. The PIN is the key." | "Stored encrypted. The PIN is the key." |

"Use once, keep nothing" ends on a "Session wallet" that hands out public keys and
addresses and is gone at power-off. Its own words are "Not stored. Locking or powering off
loses this wallet until you retype the words."

"Save to this device" on a device with no PIN goes to the PIN screen first. It asks twice;
a second entry that differs drops both and returns to step one with the reason on it.
Nothing is written until the two match.

| | | |
|---|---|---|
| ![Set a PIN](screenshots/ui/138-pin-create.png) | ![Again](screenshots/ui/140-pin-create-again.png) | ![They differed](screenshots/ui/141-pin-create-mismatch.png) |
| Where the device stops storing nothing | The second entry. Nothing written yet | Both entries dropped, and the reason stated |

| | | |
|---|---|---|
| ![Name it](screenshots/ui/42-name-a-wallet.png) | ![What the save writes](screenshots/ui/43-save-wallet.png) | ![Session wallet](screenshots/ui/44-wallet-home-session.png) |
| Naming the wallet about to be sealed | Stated before the seal, not after | The other leg: not stored, and gone at power-off |

![The first save](media/first-pin.gif)

*A device that has written nothing, through the dice, the words, the backup check and the
fork, to a PIN set twice and a wallet in a slot. It ends on a device that now boots
"Locked".*

---

## Getting a receive address

One address at a time, with its QR and the derivation named underneath it, a Next button,
and a Save to SD that writes `receive-address.txt` through the same staged, read-back,
collision-checked write path every other card write uses.

| |
|---|
| ![Receive](screenshots/ui/90-receive.png) |
| The address, the QR, and `BIP-84 native segwit - m/84'/0'/0'/0/0` under it |

---

## Exporting to a coordinator

One tab per scheme, opening on BIP-84. Each tab leads with the origin-carrying output
descriptor, then the bare account xpub, then the SLIP-132 form where the scheme has one,
then the address rows. Every block has a QR button and every payload is a public value.
Which block to hand your coordinator, and why the choice matters, is
["Hand your coordinator the descriptor"](../README.md#1-hand-your-coordinator-the-descriptor-not-the-bare-xpub)
in the README, and [docs/START-HERE.md](START-HERE.md) states it in plain language.

| | | |
|---|---|---|
| ![BIP-84](screenshots/ui/08-schemes-bip84.png) | ![BIP-44](screenshots/ui/07-schemes-bip44.png) | ![A QR](screenshots/ui/09-schemes-qr.png) |
| Descriptor, xpub, the SLIP-132 zpub, addresses | The legacy tab, for a coordinator that wants it | The descriptor as a symbol to scan |

This is the densest screen in the product, and
[the same tab at 800x480](screenshots/ui/156-schemes-bip84-800x480.png) is what the shorter
panel makes of it: the same arrangement, with the tab strip, the identity line and the
account path above a descriptor whose tail is already past the fold.

![A stored wallet](media/wallet-details.gif)

*A stored wallet: its identity row, receive, export, the descriptor QR, and the delete at
the foot.*

---

## Reviewing and signing a transaction

The transaction comes in on a microSD card and goes out the same way. The device lists what
is on the card, names the file, and does not read it until you ask - inserting a card is not
enough to make this device parse a stranger's file. The file is then validated through the
ten-check pipeline **with no signing key in scope**, so every refusal happens before any
spending authority exists.

| | | |
|---|---|---|
| ![The card](screenshots/ui/91-sign-source.png) | ![The picker](screenshots/ui/93-file-picker.png) | ![Checking](screenshots/ui/94-checking-transaction.png) |
| One transaction on the card, named and not yet read | A picker that never looks inside a file | Validated with no key in scope |

The review is paged, one rendering per page, and the pages that carry the security argument
each have two forms. An input amount is either proven by a full previous transaction or
merely stated by the file. A change output is either verified against this device's own
derivation or only claimed. A fee is either enforced by proven amounts or a lower bound,
in which case every number derived from it says AT LEAST.

| | | |
|---|---|---|
| ![Overview](screenshots/ui/98-review-overview.png) | ![Proven](screenshots/ui/99-review-input-proven.png) | ![Stated](screenshots/ui/100-review-input-stated.png) |
| Page one: what the transaction does | An amount a previous transaction proves | An amount the file states and nothing proves |
| ![Claimed change](screenshots/ui/102-review-claimed-change.png) | ![An enforced fee](screenshots/ui/103-review-fee.png) | ![A stated fee](screenshots/ui/154-review-fee-stated.png) |
| The change-confusion attack, where it is caught | A fee the proven amounts enforce | A fee the file claims, with AT LEAST throughout |

The hold that signs does not exist until every page has been visited, and on a transaction
carrying an unproven change claim it does not appear even then. Reading everything is not a
way past it.

| | |
|---|---|
| ![The hold armed](screenshots/ui/104-review-warnings.png) | ![The hold withheld](screenshots/ui/155-review-warnings-gated.png) |
| Every page seen, and the hold armed | Every page seen, and the hold still absent |

Every signature the device produces is re-verified against a sighash recomputed from the
PSBT alone before the file is released. The result goes back to the card under a name the
panel showed first, or out as one static QR if it is 1089 bytes or less. A name collision
is asked about rather than resolved, and a discard is offered only after a second failed
write, because it destroys the only copy this device holds.

| | | |
|---|---|---|
| ![Signing](screenshots/ui/109-signing.png) | ![Signed](screenshots/ui/110-deliver.png) | ![Written](screenshots/ui/112-deliver-written.png) |
| Each signature re-checked before release | The file it will write, named before the write | Written. The overlapping text on this one is a real defect, K35, not a rendering artefact of this page |
| ![Still short a cosigner](screenshots/ui/111-deliver-partial.png) | ![A collision](screenshots/ui/152-deliver-overwrite.png) | ![A discard](screenshots/ui/153-deliver-discard.png) |
| Signed by this device, not finished | Nothing written; the sheet names the file | After a second failed write, the one way out |

![Signing a PSBT](media/psbt-signing.gif)

*The file off the card, all ten review pages, the hold, and the written file. The last frame
shows the Deliver screen drawing its status card over the scroll footer: that is K35, open, and
it is what the device does today rather than something this recording got wrong.*

Multisig follows the same shape, and adds one step this device will not skip: it proves it
is a member of the cosigner set, from the seed, before any screen renders the wallet.

| | | |
|---|---|---|
| ![The registry](screenshots/ui/72-multisig-empty.png) | ![What it says](screenshots/ui/76-multisig-import.png) | ![Not a member](screenshots/ui/83-multisig-not-a-member.png) |
| Empty, with the card as the way to fill it | The descriptor's facts, before any of it is stored | A set that does not name this device, with no Approve |
| ![A cosigner](screenshots/ui/80-multisig-cosigner.png) | ![Approve](screenshots/ui/81-multisig-approve.png) | ![Stored](screenshots/ui/86-multisig-saved.png) |
| One cosigner at a time | The first receive address, then a live Approve | The quorum, the policy, and what it binds |

---

## Checking the device is the one you left

"Verify device" reads the board at boot and reports on itself: firmware version, board, IDF
and silicon revision, the SHA-256 of the running app partition, a source-id hash, the boot
self-test result, the radio-kill pad readback, the eFuse HMAC-key state, the three
secure-boot digest slots, flash-encryption and download-mode fields, a boot count, and a
deliberately coarse storage state. None of those is a compiled-in constant.

It is reachable before a PIN is typed, deliberately. What it shows pre-PIN is a strict
subset of what it shows with a session open.

| | | |
|---|---|---|
| ![Before a PIN](screenshots/ui/10-verify-device.png) | ![The digests](screenshots/ui/21-verify-digests.png) | ![With a session](screenshots/ui/22-verify-device-unlocked.png) |
| Reachable without typing a digit into the device | The app-partition digest and the source id | The full set of rows |

It can also scan the space beyond the app partition and acknowledge the boot count, which
is the one write this screen offers and states its cost on the same row as the button.

| | | |
|---|---|---|
| ![Reserved space](screenshots/ui/24-verify-reserved-space.png) | ![Scanning](screenshots/ui/23-verify-scanning.png) | ![The boot mark](screenshots/ui/25-verify-acknowledge.png) |
| Before the scan is asked for | Block by block | The write, on the same row as what it costs |

![Verify device](media/device-fingerprint.gif)

*The paged readout, the reserved-space scan, and the boot mark.*

**What this does not do** is prove the firmware is the firmware you think it is. Nothing on
the device checks the firmware; every value here is the running build reporting on itself.
It detects corruption, and it lets you compare a unit against a digest you produced
yourself. "The self-reporting boundary" in [docs/SECURITY.md](SECURITY.md) is the full
statement.

---

## Managing what is stored on it

The wallet list is what every unlock lands on. A device that has just had its first save
holds one wallet; a slot that did not decrypt is a different row shape rather than a wallet
with blank fields.

| | | |
|---|---|---|
| ![Nothing stored](screenshots/ui/137-wallet-list-empty.png) | ![One](screenshots/ui/136-wallet-list-one.png) | ![Three and a damaged slot](screenshots/ui/45-wallet-list.png) |
| A PIN set and nothing stored yet | The day after the first save | Three wallets and a slot that did not decrypt |

**The wallet menu changes shape, and the rule is worth knowing before you meet it.** The
same screen offers two actions, three or seven depending on what the device is actually
holding. Export and Receive need only the derivation that is on the screen. Sign and
Multisig are offered only on a wallet that came out of a slot, because the only seed the
firmware ever holds is one it unsealed - a keep-in-session wallet hands the screens a
derivation and hands the firmware no seed. The gate is in
`crates/notyas-ui/src/screens/wallet.rs`, and a stateless signing entry does not exist.

| | | |
|---|---|---|
| ![Session](screenshots/ui/44-wallet-home-session.png) | ![Stored](screenshots/ui/46-wallet-home-stored.png) | ![Stored, unsealed](screenshots/ui/117-wallet-home-signable.png) |
| A session wallet: two actions | A stored wallet, no derivation in hand: three | Out of a slot with its derivation: seven, and Sign |

A stored wallet can show its recovery words, behind the same two-step gate a fresh set
costs, and it can be deleted - behind a consequence sheet, its own name typed back, and one
last offer of those words before the record that holds them is overwritten.

| | | |
|---|---|---|
| ![What it destroys](screenshots/ui/47-delete-consequence.png) | ![Typed back](screenshots/ui/48-delete-typed-name.png) | ![The words, offered first](screenshots/ui/119-erase-offer.png) |
| Stated before anything is typed | The wallet's own name, case included | Two answers, and neither is the sheet's confirm |
| ![Masked](screenshots/ui/143-stored-words-masked.png) | ![Revealed](screenshots/ui/144-stored-words-revealed.png) | ![A passphrase asked for](screenshots/ui/121-passphrase-unlock.png) |
| A stored wallet's words, same masking law | Same gate, same modal, same words | A record with no stored passphrase asks at unlock |

![Deleting a wallet](media/erase-a-wallet.gif)

*The consequence, the typed name, the words offered before the erase, and the list
afterwards.*

Settings holds the device name, the network, the wrong-PIN policy, Verify device, "Format
SD card", and one destructive row pinned to the foot. It opens on "Scroll for more
settings.", so the card row is below the fold until you drag to it.

| | | |
|---|---|---|
| ![Settings](screenshots/ui/53-settings.png) | ![The foot of the list](screenshots/ui/157-settings-scrolled.png) | ![The device name](screenshots/ui/53a-device-name.png) |
| As it opens, with the pinned row under it | Where "Format SD card" is | What the lock screen prints |
| ![The policy](screenshots/ui/54-wipe-policy.png) | ![Turning it off](screenshots/ui/56-wipe-off-arithmetic.png) | ![Remove the PIN](screenshots/ui/58-remove-pin-consequence.png) |
| Erase after 15 wrong PINs, by default | The cost of guessing this PIN on this board | Counted from the wallets this device holds |

Three sealed-store operations are refused in every build: committing a wipe-policy change,
changing the PIN, and removing the PIN. Each one re-seals or destroys sealed records and
needs a fresh confirmation of the PIN, which this UI cannot collect. The screens are there
and the operations are not, so the consequence to plan around is that the wrong-PIN wipe is
fixed at fifteen attempts and cannot be raised, lowered or switched off.
[docs/KNOWN-ISSUES.md](KNOWN-ISSUES.md) tracks it.

![Settings](media/settings.gif)

*The device name, the network, the wrong-PIN policy, and the one red row.*

Formatting a card is the one operation here that destroys data the device does not own. It
is offered for exactly one fault, a card this firmware cannot read, and refused for every
other reason a card will not work. The refusal that carries the argument is the one where
the firmware itself cannot read cards at all: every card then looks unreadable, and
formatting one would erase somebody's data to work around a build setting. Four of the six
pictures below are of a card the device has not touched.

| | | |
|---|---|---|
| ![The offer](screenshots/ui/145-format-card.png) | ![What it destroys](screenshots/ui/147-format-consequence.png) | ![The capacity typed back](screenshots/ui/148-format-typed.png) |
| Named with its capacity and what it holds | Stated before any typing | "32GB" costs a digit page and a shifted letter page |
| ![Writing](screenshots/ui/151-formatting-card.png) | ![Done](screenshots/ui/149-format-done.png) | ![Refused](screenshots/ui/150-format-refused-firmware.png) |
| The one frame where "Do not remove the card" is load-bearing | Reported in the device's own words | The refusal that stops the worst outcome this feature has |

![Formatting a card](media/format-card.gif)

*The row at the foot of settings, the probe, the consequence, the typed capacity, the
write, and the result.*

---

## What a refusal looks like

A refusal is a full screen, not a toast: a code, a headline, "What happened" in the engine's
own words, "Why this matters", and "What to do". The action line exists on every code, so a
refusal cannot render without one. A machine-fact block is behind a control rather than on
the screen, because a review screen full of hex teaches a user to skim.

| | | |
|---|---|---|
| ![A refusal](screenshots/ui/95-refusal.png) | ![The details](screenshots/ui/116-refusal-details.png) | ![Not a script it signs](screenshots/ui/134-refusal-unsupported-script.png) |
| A code, a headline, why it matters, what to do | The block a bug report is photographed from | R-26, with no cosigner named anywhere on it |

Which refusals you are most likely to meet, and what to do about each, is
[docs/REFUSALS.md](REFUSALS.md) for the codes and the README's
["Two things that will bite you"](../README.md#two-things-that-will-bite-you) for the
reasoning behind the two that surprise people.

---

Every committed picture, with what it shows and the catalogue frame that produced it, is
[docs/screenshots/ui/INDEX.md](screenshots/ui/INDEX.md).
