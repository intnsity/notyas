# notyas 0.2.1 - release runbook

Owner-facing. 0.2.1 is a point release on top of 0.2.0 (`b6cceba`, tagged `v0.2.0`). It
carries one behavioral change - the amount-proof rule below - plus the fixes and interface
corrections that change made necessary. Nothing in section 0 of `docs/RELEASE-0.2.0.md`
about what a unit can, cannot, and has not been shown to do is superseded except where this
document says so explicitly. Read both.

The verifier-facing counterpart is `docs/VERIFYING.md`, unchanged by this release. The
gate list and process are `tools/release.sh`; nothing about the order of gates changed for
0.2.1, only the version they run against.

```
tools/release.sh              # the stage plan, and where this release stands
```

---

## 0. The amount-proof rule: what changed, what it admits, what it still refuses

**Before 0.2.1**, check 2 (previous transactions) refused any file where a signature of
this device's does not itself commit to every input amount (any segwit v0 input, under
every sighash flag this device admits) while any input anywhere in the file states its
amount without proving it (a `witness_utxo` with no `non_witness_utxo`). That refusal was
correct and it is documented in `docs/RELEASE-0.2.0.md` section 6: it closed a demonstrated
one-coin loss, and its cost was disclosed as an interop regression rather than discovered
by a coordinator.

That cost fell hardest on one shape: a BlueWallet watch-only wallet spending a single
UTXO. BlueWallet's PSBT export carries `witness_utxo` only, never
`non_witness_utxo`, so every such spend - the ordinary case, not an edge case - hit the
same refusal as the two-round attack the rule exists to stop. 0.2.1 narrows the rule to
admit that shape specifically, without reopening the attack.

**The rule now**: a segwit v0 input's amount may rest on `witness_utxo` alone, and this
device will still sign over it, in exactly one additional case: the unsigned transaction
has a single input. (Taproot is unaffected either way - BIP-341's `sha_amounts` already
makes every claimed amount binding under SIGHASH_DEFAULT, so it never needed the previous
transaction and still does not.)

**Why one input, specifically, is safe and two is not.** BIP-143 binds only its own
input's amount. In a single-input transaction there is no second amount anywhere for a
signature to lie about, and no second signature anywhere for a future round to combine
with - the transaction is the whole story. In a two-or-more-input transaction, a
coordinator can prove one input's amount and merely claim another's, get a valid signature
over the input it proved, then present a second file with the roles swapped and get a
second valid signature - each round shows an ordinary, acceptable fee, and the two
signatures combine into one transaction that pays far more in fees than either round ever
displayed. This device has no record of a previous round (ratified rule S-35: no chain, no
clock, no price, no history), so it cannot notice the rotation from either presentation
alone. Only the single-input case forecloses this statelessly, which is why the rule is
keyed on the transaction's input count rather than on how many amounts one file happens to
leave unproven.

**What is now accepted that was not:**
- A BlueWallet spend whose transaction has exactly one input - the user's reported case,
  and the common one. The change output proves as change, the fee is enforced (shown as an
  exact figure, not a lower bound), and no "amount not checked" warning is raised, because
  nothing on the page is left resting on the file's word once the device's own signature
  makes it binding.
- Any other single-input file in the same shape, regardless of which wallet produced it.

**What is still refused, and why:**
- **Every BlueWallet spend with two or more inputs** - a consolidation, or "Send Max" from
  a wallet holding more than one UTXO - is still refused. This is not an oversight; it is
  the direct consequence of ratified rule S-35. No stateless rule can admit a multi-input
  file with an unproven amount without reopening the rotation attack above, and this
  device deliberately keeps no history with which to catch a rotation across two
  presentations of "the same" transaction.
- **The remedy** is coin control - select a single UTXO to spend from, so the exported
  PSBT has one input - or rebuilding the transaction in wallet software that attaches full
  previous transactions to every input: Sparrow, Electrum, or Bitcoin Core. Any of the
  three produces a file this device signs today, on any board, with no change to this
  device's behavior.
- A cosigner's already-finalized input is still not exempt from the multi-input refusal:
  being finalized says nothing about its amount.

This does not reopen `docs/KNOWN-ISSUES.md` K11. K11's two-round demonstration is a
two-input transaction; the rotation it describes requires a second signature somewhere in
the file for a later round to combine with, which a single-input transaction never has.
The single-input admission is a distinct, narrower case, proven safe against the same
attack before being ratified - see "Verification" below.

**Interface changes that follow from the rule, all consistent with the above:**
- The per-input caveat row on the review screen, for an amount that rests on the file's
  word alone but that this device's own signature makes binding, no longer reads "(taproot)" - it
  now reads "Checked: if this amount is wrong, the signature this device adds is worthless
  and this transaction cannot confirm," which is true of both the taproot case and the new
  single-input case. The amount itself keeps its `STATED` prefix either way: the number
  still came from the file rather than from the previous transaction, and a third
  qualifier on the commonest spend there is would be exactly the qualifier fatigue this
  screen's header warns against. The Script type and Address rows for such an input carry
  the same `STATED` prefix as the amount above them, for the same reason: BIP-143 hashes
  the scriptCode it is given, not the scriptPubKey, so this device cannot distinguish a
  native segwit coin from its P2SH-wrapped form on `witness_utxo` alone, and the qualifier
  says so rather than implying a certainty the device does not have.
- The `MissingPrevTx` refusal a multi-input BlueWallet spend still raises now names the
  remedy that wallet can actually perform. The old copy read "Re-export with full previous
  transactions included, then load it again" - advice a watch-only BlueWallet import
  cannot follow, since it has no previous transactions to attach. The panel now reads:
  "Spend a single coin - use coin control to select one - or re-export from software that
  includes full previous transactions (Sparrow, Electrum, Bitcoin Core), then load it
  again."

**Verification.** The rule was adversarially tested before being ratified, including
against a broader relaxation (any file with at most one unproven amount, regardless of
input count) that was rejected specifically because it re-admits the rotation attack: a
coordinator that always leaves exactly one amount unproven per round, rotating which
input that is, clears such a rule every time while still harvesting one combinable
signature per round. That variant was implemented in an isolated copy of the crate and
broken with a two-round test before being rejected. The rule actually shipped -
single-input transactions only - was implemented against the same isolated copy and the
same attack, and refuses it in both rounds. The full host suite - 1277 tests as of this
tag, zero failures - includes permanent negative pins for both the rotation attack and the
plain two-round consolidation attack, so a future change that reopens either fails loudly
rather than silently.

---

## 1. Everything else this release changes

None of the following is a security-relevant behavior change; they are corrections and
fixes that either accompanied the amount-proof rule or were found while preparing this
release.

- **Save-to-SD now goes through the same collision-checked write path as every other card
  write.** The receive-address save previously deleted an existing same-named file
  unconditionally, wrote the new one with no read-back, and reported success on the write
  call alone. It now stages, reads back, and asks before overwriting - the same discipline
  `sd::deliver` already gives the signed-PSBT write - and the Save button is drawn
  unconditionally, since neither shipped board has a card-detect line and there was never
  a state in which the button should have been hidden.
- **The stored-wallet list's scroll indicator is now a marker on the edge that has content
  past it**, matching the marker the review flow already uses, rather than a text hint
  appended to the capacity line. The previous hint text is gone; nothing about which
  wallets are shown or how many fit changed.
- **A session wallet's keys are the only copy that exists**, and Back on that screen still
  confirms before discarding them. A *stored* wallet's keys survive in flash regardless of
  what this screen is holding, so Back on a stored wallet - even one whose keys happen to
  already be unsealed - no longer raises the same confirmation over nothing at risk.

---

## 2. What ships

Per board, for `waveshare-4b` and `elecrow-5`, named `0.2.1` in place of `0.2.0`:
`notyas-0.2.1-<board>-app.bin`, `-bootloader.bin`, `-partition-table.bin`, `-merged.bin`,
`.elf`, `-sdkconfig.txt`, `-BUILDINFO.txt`, `-VERIFY.json`; plus, once,
`notyas-0.2.1-src.tar.gz`, `notyas-0.2.1-components.tar.gz`, `SHA256SUMS.txt` and
`SHA256SUMS.txt.asc`. See `docs/RELEASE-0.2.0.md` section 3 for what each file is; nothing
about the artifact set itself changed.

---

## 3. What deliberately does not ship

Unchanged from `docs/RELEASE-0.2.0.md` section 4: no Secure Boot v2, no flash encryption,
no eFuse anti-rollback, no eFuse burn beyond the one HMAC key, no artifacts for the eight
scaffold boards, no crates.io publication, no backup mechanism, no BSMS, no taproot
multisig, no hardware-held signing key, no third-party build attestation. Also not in
0.2.1: the Coldcard-style persistent outpoint-to-amount cache that would be the only route
to admitting a multi-input BlueWallet spend. It was proposed and explicitly rejected for
this change - it needs its own design pass, its own storage (the counters partition
cannot express it and the settings charter excludes anything an attacker must be able to
influence), and it conflicts with ratified rule S-35. It is not a rider on this rule
change; the multi-input remedy for now is coin control or a coordinator that attaches
previous transactions.

---

## 4. Known limitations a buyer must read

All twelve items in `docs/RELEASE-0.2.0.md` section 5 still apply unchanged. Add:

13. **A BlueWallet spend with two or more inputs is refused**, on purpose, for the reason
    given in section 0 above. The remedy is coin control or rebuilding the transaction in
    Sparrow, Electrum, or Bitcoin Core.

`docs/KNOWN-ISSUES.md` K11 ("a cosigner's unproven amount beside our segwit v0 input could
hand a whole coin to the miner") stays resolved as recorded there; 0.2.1 narrows the
resolution's edge for the single-input case without touching the multi-input refusal that
entry is about.

---

## 5. Verification

Signed with the same key as every notyas release, unchanged since 0.2.0:

```
A1E9 53B2 5C6A 623B 77A1 D522 3AC4 BBCF E51A B37D
```

See `docs/VERIFYING.md` for how to check it, and `docs/keys/A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D.asc`
for the published public half.

---

## 6. Release notes skeleton

Paste into the GitHub release, in this order:

1. One paragraph: 0.2.1 is a point release on 0.2.0 that admits a common, previously
   refused BlueWallet spend shape (single input) without weakening the check that refused
   it, and fixes an SD-card write path and a UI affordance along the way. It does not
   change what a unit can do beyond that; `docs/RELEASE-0.2.0.md` section 0 is still the
   authority on the whole feature set.
2. Section 0 of this document in full: what changed, what is newly accepted, what is still
   refused and why, and the remedy.
3. Section 1 of this document: the SD-save fix, the wallet-list marker, the session-wallet
   Back fix.
4. Verification: point at `docs/VERIFYING.md` and give the key fingerprint inline (section
   5 above).
5. Reproducibility status: the exact line `tools/release.sh sign` prints for this tag.
6. The artifact list (section 2 above) and which board slug is which.

---

## 7. If a defect surfaces after publication

Same policy as `docs/RELEASE-0.2.0.md` section 8: do not delete or move the tag; disclose
on the release page immediately, naming what is wrong and what a holder should do; treat
the signing/verification chain as unverifiable and republish rather than silently replace
if the defect is there; record it in `docs/KNOWN-ISSUES.md` with its found-date, its
blocking verdict, and what closing it requires.
