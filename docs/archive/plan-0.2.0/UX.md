# notyas 0.2.0 - UX plan

Status: PLAN. Derived from the UX deep-dive (Coldcard Q, Passport, Jade, BitBox02,
Keystone, Trezor, Krux/SeedSigner walkthroughs + address-poisoning literature).
Constraints honored: 720x720 and 800x480 (and unverified portrait scaffolds) from the
single Layout mechanism; Butter Paper theme; notyas Sans for UI, notyas Mono for ALL
verification data; touch targets >= 60 px; no animation except QR frames and
hold-progress. ASCII only on-screen where mono verification data is shown.

---

## 1. The ten commandments

1. The device screen is the truth. Never require trust in the coordinator for an
   address, amount, or fee - and never show less than the FULL address, mono,
   chunked in groups of 4, paged to the end. Address poisoning defeats
   prefix+suffix checking: attackers grind lookalikes matching up to 20 hex chars
   (https://arxiv.org/abs/2501.16681).
2. Friction is graded to consequence: tap to navigate, page-to-the-end to review,
   hold to sign, type-the-name to destroy. One visual danger grammar everywhere.
3. No backup exists until it is verified: every word, 5 candidates, at creation
   (BitBox02 pattern) - and re-verifiable forever after without exposure (Trezor
   dry-run pattern).
4. The device authenticates itself to the user before the user authenticates to it:
   anti-phishing words at half-PIN (https://coldcard.com/anti-phishing-words);
   Verify screen always one tap away.
5. Fixed phone-order PIN pad - 1-2-3 / 4-5-6 / 7-8-9 over a 0, the same on every
   attempt; never echo digits; the touch-down highlight is drawn on the dot row, never
   on the key. The per-attempt shuffle this commandment used to require (Trezor/Keystone
   pattern) was built, used on hardware, and reversed by the project owner on 2026-08-19
   (Q35), knowing that fixed positions let one look at the hand yield the PIN. The
   non-local highlight stays, and matters more for it.
6. Statelessness is a feature with a border: "use once, keep nothing" stays a
   first-class path, and every write to flash or SD is announced on-screen before
   it happens.
7. Every touch target >= 60 px; confirm and cancel never adjacent and never where a
   previous tap landed (no double-tap-through).
8. A wrong passphrase is a different wallet: always echo the resulting fingerprint
   and make the user own it.
9. QRs are for the scanner, not the spec: max module size, quiet zone, pause /
   speed / density controls, frame counter - and SD writeback always available when
   QR fails (SeedSigner/Sparrow lessons).
10. Plain words over jargon at every failure: what happened, why the device refused,
    what to do next. Refusal screens get the same design care as success screens.

---

## 2. Top-level flow

```
 power on
    |
 [1 Boot/Self-test] -- storage blank -----------------> [0.1.0-style home:
    |                                                    Generate | Restore | Verify]
 storage has wallets                                       |  ("Save" offered at the
    |                                                      |   end of either flow;
    |                                                      |   if Q11 is accepted the
    |                                                      |   blank home also offers
    |                                                      |   "Sign (stateless)" so
    |                                                      |   signing is discoverable
    |                                                      |   without saving a wallet)
 [16 Lock screen] -> touch
    |
 [2 PIN entry] --(half-PIN: anti-phishing words shown)--> wrong words? STOP
    |  ok                       \
    |                            wrong PIN -> counter decremented, escalating delay,
    |                                         wipe at N (screen states remaining tries)
 [3 Wallet list] ---- New ----> [4 Create wallet wizard]
    |                 Restore -> [6 Restore wallet]
    | open
 [7 Wallet home] -+-> [8 Receive / Address explorer]
                  +-> [9 Sign: load PSBT] -> [10 Review] -> hold -> [11 Deliver]
                  +-> [13 Export xpub]
                  +-> [12 Multisig registry]
                  +-> [14 Settings] / [15 Danger modals as needed]
                  \-> Lock (always visible, top right)
```

Create-wallet fork (commandment 6):

```
 [4 dice/entropy] -> [4 mnemonic display, paged] -> [4 passphrase (optional),
     fingerprint echoed] -> [5 Backup verify quiz - MANDATORY]
        -> "Save to device (PIN-protected)"   <- announced flash write
        -> "Use once, keep nothing"           <- 0.1.0 behavior, first-class
```

Signing flow (the flagship):

```
 [9] SD inserted -> auto-detect *.psbt (Coldcard "Ready to Sign") | file picker
     parse fail -> refusal screen, plain words ("this file is not a PSBT",
                   "missing input data - refusing to sign")
 [10] policy engine result rendered:
      header: net amount leaving the wallet
      -> one PAGE PER OUTPUT ("output 2 of 3"): full address mono/chunked,
         amount, tag = EXTERNAL | CHANGE (verified) | OWN
         multisig: k-of-M sigs present, cosigner fingerprints
      -> fee page: sats + sat/vB + % of send; warning treatment over threshold
      -> warnings page(s), if any
      NO sign affordance until the last page has been visited
 [hold-to-sign] 1.5 s, progress ring, release cancels
 [11] write *-signed.psbt (+ *-final.txn if finalizable) to SD, encoding matches
      input; and/or animated UR2 QR with pause/speed/density + frame i/j;
      end state: "Done - remove card"
```

---

## 3. Screen inventory

(E) = evolves a 0.1.0 screen, (N) = new. Evolution notes name what carries over.

1. (E) **Boot / Self-test** - 0.1.0 screen + new lines: storage state (blank / N
   wallets), signing known-answer check result, seal/unseal self-check result.
2. (N) **PIN entry** - fixed phone-order 10-key pad (1-2-3 / 4-5-6 / 7-8-9 over a 0,
   not shuffled - Q35, reversed 2026-08-19), 6+ digits or switch to full keyboard for
   passphrase-PIN; masked dots (fixed-length mask
   discipline from 0.1.0); anti-phishing words after the PIN prefix with "words
   wrong? STOP - this may not be your device"; remaining-attempts line; escalating
   delay rendered as a countdown, not a frozen screen.
3. (N) **Wallet list (home)** - one card per stored wallet: name, fingerprint
   (mono), type badge (single-sig/multisig + script type), backup-verified badge.
   No balances by design (airgapped device has no chain view - the fingerprint IS
   the identity surface). Actions: Open, New, Restore. Capacity line ("3 of 8
   slots").
4. (E) **Create wallet wizard** - 0.1.0 dice entry, mnemonic display, and
   passphrase screens re-used verbatim as wizard steps; adds: entropy-mode labels
   (RAW = iancoleman-compatible / FIXED = Coldcard-SeedSigner-compatible,
   unchanged), mandatory Backup Verify gate, then the Save / Use-once fork. Save
   path announces the flash write and requires the device PIN (set on first save).
5. (N) **Backup verify** - BitBox02-style quiz: every word position, 5 candidates
   including confusable neighbors; wrong answer restarts that word; completion
   stored with the wallet ("backup verified <date>"). Reachable later from wallet
   settings as a dry-run re-check (re-enter words; device answers match/no-match
   only, exposing nothing).
6. (E) **Restore wallet** - 0.1.0 reverse mode + word-completion QWERTY (live
   prefix filter to valid BIP39 words) + final-word checksum calculator;
   fingerprint shown for confirmation before the Save / Use-once fork.
7. (N) **Wallet home (per wallet)** - identity card (name, fingerprint, script
   type, derivation); full-width action cards: Receive, Sign, Export xpub,
   Multisig, Settings. Lock always visible top-right (wipes session, back to PIN).
8. (E) **Receive / Address explorer** - evolves the 0.1.0 address screens: paged
   index list; detail = FULL address, mono, 4-char chunks, larger scale, static QR,
   explicit path "m/84'/0'/0'/0/N"; change-address tab; "Verify external address":
   read an address from SD text file or typed entry, device answers "yours at index
   N" or "NOT MINE" (Coldcard verify-ownership pattern,
   https://coldcard.com/docs/verify-address-ownership/). Works for multisig via the
   registration.
9. (N) **Sign - load PSBT** - SD source: auto-detect + file picker fallback;
   refusal screens per commandment 10. No camera exists: QR is out-only, stated in
   the UI rather than hidden. Wrong-wallet routing (red-team addition): a PSBT
   whose inputs match none of the OPEN wallet's keys is a guaranteed first-timer
   dead end; because one device PIN gates all slots, the refusal screen names the
   stored wallet that DOES match ("these inputs belong to 'savings' (a1b2c3d4) -
   open it to sign") when fingerprint comparison finds one, instead of a bare
   "nothing to sign".
10. (N) **Sign - review** - as diagrammed above. Paged, not scrolled (paging makes
    "I saw all of it" enforceable); page counter always visible; no timer ever
    auto-advances. Red-team additions: (a) non-address outputs (OP_RETURN / data /
    unknown script types) get an explicit page rendering the script type and raw
    payload in mono - never silently skipped, never coerced into an address shape;
    (b) nLockTime and RBF signaling are shown on the fee page whenever nLockTime
    is nonzero or sequences are non-final ("this transaction is not valid before
    block N"); (c) fatigue control for batch transactions: above 10 outputs, an
    overview page first (count, total EXTERNAL amount, count of verified CHANGE
    outputs) - the per-output pages still follow and full traversal is still
    required, the overview only primes what to expect. Fatigue is real but
    abbreviation is how output-substitution wins; we prime, we do not truncate.
11. (N) **Sign - deliver** - SD writeback + animated UR2 QR (pause, 3 speed steps,
    density steps, frame i/j); "Done - remove card". Failure path (red-team
    addition): an SD write that fails (card pulled, full, write error) is announced
    in plain words with Retry and "show as QR instead" - the signed PSBT is still
    in RAM and the QR path is the guaranteed exit, mirroring commandment 9's
    SD-when-QR-fails in the other direction. No flow may end with a signed PSBT
    silently lost.
12. (N) **Multisig registry** - list; import descriptor (or Coldcard .txt) from SD;
    review screen: M-of-N, script type, derivation, EVERY cosigner fingerprint +
    xpub paged in mono with our key highlighted and membership-verified; approve
    stores it (announced write); detail: re-export (SD/QR), first-address display
    for cross-device comparison, Verify Address; delete requires typed wallet name.
    "Export our xpub for a new multisig" (BIP48) lives here.
13. (E) **Export xpub** - 0.1.0 scheme/xpub screens per-wallet: SLIP-132 forms, QR
    + SD export, key-origin (fingerprint + path) always shown.
14. (N) **Settings** - brightness, QR defaults, auto-lock timeout, wipe-counter
    policy display, PIN change (re-seals all records and erases the stale old-PIN
    ciphertext slots - ARCHITECTURE 2.6), firmware update instructions
    (USB reflash only - show current version + running SHA256), and the 0.1.0
    Verify screen retained verbatim plus storage/anti-rollback/HMAC-eFuse state.
15. (N) **Danger modals** - ONE shared component, three grades: (a) yellow-card
    confirm (reversible: overwrite SD file) - buttons spatially separated; (b)
    hold-to-confirm (sign, early wipe) - 1.5 s, progress, release cancels; (c)
    typed-name confirmation (delete wallet, factory reset) - states exactly what is
    destroyed and that the user's backup is the only way back.
16. (N) **Lock screen** - device name + "locked" + user-chosen display word (swap
    detection before PIN); touch anywhere -> PIN entry.

Landscape 800x480 adaptation per the existing Layout rule: review screens split into
left content card + right action rail; keypads sit right of entry lists; 720x720
stacks vertically. Same widgets, derived arrangement, golden-image tests at both
geometries (and the portrait scaffolds keep their UNVERIFIED boot warning).

---

## 4. Per-screen evolution principles vs 0.1.0

- Nothing 0.1.0 renders changes meaning: dice entry, mnemonic display/masking,
  passphrase, scheme/xpub, Verify keep their behavior and their pixel-level masking
  tests; they gain wizard framing and per-wallet context only.
- The masking disciplines (fixed-length masks, redacting debug, no-QR-from-secret
  screens) extend to every new screen; the existing "two mnemonics render
  byte-identical masked frames" test style is applied to PIN entry and session
  screens.
- New interaction primitives are exactly three: the PIN keypad (fixed phone order
  since Q35's reversal), hold-to-confirm (tick-driven), animated QR (tick-driven).
  Everything else composes 0.1.0 widgets.
- Refusal screens are first-class deliverables with their own corpus-driven tests:
  every policy-engine rejection reason has a screen with the exact rendered text
  asserted in CI.
