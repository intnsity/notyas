# notyas 0.2.2 - release runbook

Owner-facing. 0.2.2 is a point release on top of 0.2.1 (`ccc85c7`). It answers one field
report - a spend of the device's own coins refused with a multisig cosigner alarm - and it
carries three separate decisions, recorded here before the code that implements them, on
`tools/ci/check-ratified.sh`'s own rule: the tree is wrong until the owner says otherwise,
and a deliberate change of mind is made by editing the documents FIRST.

Nothing in section 0 of `docs/RELEASE-0.2.0.md` about what a unit can, cannot, and has not
been shown to do is superseded except where this document or `docs/RELEASE-0.2.1.md` says
so explicitly. Read all three.

The verifier-facing counterpart is `docs/VERIFYING.md`, unchanged by this release. The gate
list and process are `tools/release.sh`; nothing about the order of gates changed for 0.2.2,
only the version they run against.

```
tools/release.sh              # the stage plan, and where this release stands
```

---

## 0. The report, and what the device actually did

A user loaded a PSBT from a card and was told his cosigner keys did not match. He has no
multisig wallet, no cosigners and no registration on the device. He said so, and he was
right.

**The file, decoded from his card.** One input, one output. The input is a legacy P2PKH
prevout, and the full previous transaction is present, so its amount is proven rather than
claimed. The input's `bip32_derivation` names the path `m/44'/0'/0'/0/0` and a public key
whose hash160 is exactly the pubkey hash inside the input's own script; the master
fingerprint written beside it is `00000000`, which is what a watch-only wallet built from a
bare account key writes when it has no fingerprint to write. The output is P2WPKH. The file
is well formed, internally consistent, and it spends a coin of the device's own BIP-44
account.

**What the device did with it.** It derived the leaf, rebuilt the script, and proved the
input was its own. Then it refused, because the script kind is P2PKH and P2PKH is outside
`ScriptKind::is_single_sig` (`crates/notyas-core/src/psbt/checks.rs:846`), and refusals at
that site are filed under check 4, multisig binding (`checks.rs:630`). The screen that
followed was:

```
R-04   Cosigner keys do not match
What happened     Check 4 (multisig binding): input 0 is a legacy address,
                  which is not a script this device spends.
Why this matters  A substituted cosigner key sends your coins to someone
                  else's multisig.
What to do        Compare the registration on all your devices. Import it
                  again if it changed legitimately.
```

Exactly one line of that is true, and it is the engine's own: the input is a legacy address.
There is no multisig in the file, no cosigner to substitute, and no registration to compare.
The instruction names an action the user cannot perform and would not help if he could.

**The refusal itself was correct.** At `ccc85c7` this device has no legacy signing path at
all: `sign::SpendKind` has four arms and none of them is legacy, and the post-sign gate
computes a BIP-143 digest for any prevout that is not P2WSH. Admitting the input without
building that path would have moved the refusal to after the user held to sign, and would
have shown him R-01 instead. What was wrong was the copy, not the decision to refuse.

**Reproduced on hardware** over the HIL console before any edit, against a wallet that does
NOT own the coin: the same file inspects clean and refuses honestly at check 1, "none of
these inputs belongs to this wallet". The false alarm appears only once ownership PROVES,
which is the shape that made it hard to see and is why the reproduction is recorded here.

---

## 1. Decision 1: this device signs legacy P2PKH, and the record always said so

0.2.2 implements P2PKH signing. That is not a new decision. It is the ratified one, and the
tree deviated from it without any documented change of mind. Five citations, each checked
against the file rather than repeated from a report:

- `docs/plan-0.2.0/ARCHITECTURE.md:550`, checklist 5.3, check 2: "Full prev-tx
  (`non_witness_utxo`) REQUIRED for every segwit-v0/legacy input; txid + amount
  cross-check. `witness_utxo` alone acceptable for taproot only". An admission rule for
  legacy inputs is not something a device that refuses every legacy input needs.
- `docs/plan-0.2.0/WALLET-API.md:1325`, gate 3, repeats it: "`non_witness_utxo` present for
  every legacy and segwit-v0 input; its txid equals the outpoint's txid; its output amount
  equals the claimed amount".
- `docs/plan-0.2.0/WALLET-API.md:1330`, gate 8: "every input we would sign uses SIGHASH_ALL
  (legacy/segwit-v0) or SIGHASH_DEFAULT (taproot)". Legacy is named among the inputs "we
  would sign".
- `docs/plan-0.2.0/CORPUS.md:274`, positive group P3: "P3 single-sig P2PKH | 1-in/2-out |
  legacy sighash path, and the strictest `non_witness_utxo` requirement". That is a legacy
  PSBT the device is required to SIGN, in the document m6 names as its exit criteria.
  (CORPUS.md also uses the label P3 at line 53, for an unrelated property in the coverage
  register; the corpus group is the one at line 274.)
- `docs/plan-0.2.0/MILESTONES.md:877`, the m6 exit gate: "a full Sparrow SD round trip on
  testnet across all four script types on both boards".

Nothing strikes any of it. `OPEN-QUESTIONS.md`, `KNOWN-ISSUES.md`, `RELEASE-0.2.1.md` and
`QA.md` record no decision to drop legacy, and `tools/ci/check-ratified.sh` makes no
assertion about script types at all. The contrary position exists only in code comments -
`checks.rs:845` ("The three that answer yes are exactly BIP84, BIP49 and BIP86 key-path"),
`checks.rs:1826` and `checks.rs:1848` ("this device does not sign legacy") - which is
precisely the class of unratified deviation `check-ratified.sh` was written for, after a
build shipped with a PIN floor the owner had never agreed to.

It also matters because the device does not merely tolerate BIP-44, it hands it out.
`Scheme::ALL` puts Bip44 first (`crates/notyas-core/src/derive.rs:106`), the Receive card
shows whatever `schemes.first()` returns (`crates/notyas-ui/src/screens/receive.rs:39`), the
export screen opens on the BIP44 tab (`crates/notyas-ui/src/screens/schemes.rs:123`), and
`export::descriptor` emits a `pkh()` descriptor for it
(`crates/notyas-core/src/export.rs:256`). A device that solicits deposits to an address it
cannot spend from is a trap regardless of what any document says; see section 4.

The coins are not lost either way - the recovery phrase re-derives `m/44'` in any standard
wallet - but the only on-device route out of a legacy coin is legacy signing, so refusing to
build it would strand the user's existing coins behind a seed export, which is the exact
harm this product exists to prevent.

---

## 2. The legacy amount rule, stated rather than inherited

**The rule.** A legacy (pre-BIP-143) signature commits to NO input amount, not even its
own. The 0.2.1 single-input exemption (`docs/RELEASE-0.2.1.md` section 0, scoped to segwit
v0) therefore NEVER applies to a legacy input: every legacy input's amount must be proven by
a txid-checked full previous transaction, or the file is refused.
`binds_the_whole_transaction(P2pkh)` is false and stays false.

**Why it is written down here instead of being left to follow from the code.** 0.2.1 bought
a narrow escape from check 2 for a single-input transaction, and the reason that escape is
safe is that a BIP-143 signature binds its own input's amount, so a transaction with one
input has no amount anywhere for a file to lie about. A legacy digest does not even do that
much: it hashes the scriptCode and the outputs and never the value. Legacy is therefore
STRICTLY WEAKER than the case the exemption was reasoned about, and a future reader who sees
"single input, so the amount is bound" without seeing this paragraph could extend the
exemption to legacy by analogy and reopen a fee attack on the commonest shape there is.

**What this costs in code: nothing.** The rule is already enforced, by the exhaustive match
`binds_the_whole_transaction` was deliberately written as. Admitting P2PKH into
`is_single_sig` does not touch it:

- a single-input legacy file with a claimed amount passes the per-input carve-out at
  `checks.rs:1450` (the transaction has one input) and is then refused
  `UnprovenAmountBesideOurSignature` by the whole-file half, because
  `our_signatures_bind_every_amount` falls through to the single-input escape and
  `binds_the_whole_transaction(P2pkh, [0x01])` is false;
- a multi-input legacy file with a claimed amount is refused `MissingPreviousTransaction` at
  the carve-out itself.

Both are intended, both get permanent pins in the suite, and one of them is demonstrated on
hardware before the release is cut. The rule's own half is already pinned, and the pins
predate this release: `the_sighash_whitelist_gates_the_single_input_escape` asserts
`!binds_the_whole_transaction(P2pkh, [0x01])` directly - under SIGHASH_ALL, which is the one
flag legacy will ever be signed under - and
`the_admitted_sighash_set_is_the_one_the_amount_rule_rests_on` enumerates the admitted flag
set kind by kind, so section 1's change to P2PKH's arm cannot be made without that test being
edited deliberately.

A legacy input therefore enters under the STRICTEST amount regime in the device: stricter
than segwit v0, which has the single-input allowance, and stricter than taproot, which needs
no previous transaction at all.

**What must not be edited to make legacy signing work, and was not.** The single-input
exemption (`checks.rs:1450`), `our_signatures_bind_every_amount`,
`amounts_our_signatures_do_not_cover` and `commits_to_every_amount` are untouched by this
release. The P2PKH arm of `binds_the_whole_transaction` stays `false`; only its comment
changes, because two of the three reasons it gave for that answer stop being true when the
signer gains a legacy arm, and the surviving one - a legacy digest carries no amount at all -
is the whole reason by itself.

Legacy signing enters under SIGHASH_ALL only, with ownership proven by derivation and with
an independent post-sign verification arm, exactly as every other script type does. No
security check is loosened by this release.

---

## 3. Decision 2: a script this device does not sign gets its own refusal (R-26)

`ClaimedInputNotSingleSig` was wearing R-04's copy because it is filed under check 4, and
R-04's copy is about one specific attack: the 2021 cosigner substitution
(`https://benma.github.io/2021/02/09/coldcard-multisig-vulnerability.html`). Applying it to
a single-sig input is not a small wording error. It accuses a coordinator of an attack that
did not happen, it sends the reader to compare registrations he may not have, and it spends
the credibility of the one refusal on the device that has to be believed instantly if it
ever does fire.

The new code, outside the ratified R-01..R-10 numbering exactly as R-20..R-25 are:

| Code | Headline | Why this matters | What to do |
|---|---|---|---|
| R-26 | Not a script this device signs | "This device signs only script types it can verify end to end. Anything else is refused rather than signed blind." | "Spend these coins from a wallet that supports this script type. If this is a wrapped-segwit coin, re-export the transaction with its redeem script included." |

The headline names no multisig, no cosigner and no registration, because none of the
situations that reach this code involve any.

**What reaches it.** Every `ClaimedInputNotSingleSig`, which is an input claiming this
device's key whose script is none of the kinds the signer builds. After section 1 lands that
is P2SH, OP_RETURN and Other; until then it is also P2PKH. The P2SH row is worth naming: it
covers both a genuine P2SH multisig, which this release still does not sign (Q7), and a
BIP-49 wrapped-segwit coin OF OURS whose redeem script the coordinator omitted from the file
- a file defect the sender can fix, which is why the second sentence of "what to do" is
there.

**The mapping is presentation only.** `Check` numbering is unchanged, no `CheckFailure`
variant or its `Display` string is changed, and no security check is touched. The lift is
one arm in `firmware/src/flow/model.rs::check_refusal`, matched before the fallback to the
`Check`-based table, which is the same per-variant lift that file already performs for
`PsbtTooLarge` and `PsbtVersionUnsupported`. Genuine multisig failures -
`MultisigStatelessUnverifiable`, `MultisigNotRegistered`, `MultisigWitnessScriptMissing`,
`MultisigWitnessScriptMismatch` - still map to R-04, and the check-to-code table pin in
`firmware/hostcheck/tests/review_model.rs` is untouched.

**Accepted residual, recorded rather than fixed.** The "What happened" line under the band
is the engine's own sentence and still opens "Check 4 (multisig binding)", because the
ten-check numbering is ratified (`ARCHITECTURE.md` 5.3) and that sentence is what a bug
report is photographed from. A user who reads it will see the words "multisig binding" under
a headline that says nothing about multisig. That is a smaller wrong than the one being
fixed, and closing it means either renaming a ratified check or letting the UI rewrite
engine text - both larger decisions than this release is making. Deferred to the copy audit
tracked in `docs/KNOWN-ISSUES.md`.

**The rest of that audit.** R-26 is the worst row of a set. Ten more refusal rows render
copy that is false or misdirected for at least one situation they cover - a previous
transaction that is PRESENT and contradicts its input, reported as "Missing the previous
transaction"; a tamper tripwire reported as a calm wrong-wallet mixup; an ordinary
pre-registration multisig onboarding step reported as a key mismatch - and card and
registration faults borrow file-flavoured copy the same way. They are tracked in
`docs/KNOWN-ISSUES.md` and are not in this release: each needs its own decision about what
the honest sentence is, and a bulk rewrite of frozen copy is how a set of individually
considered strings becomes a set nobody has read.

---

## 4. Decision 3: the funnel that put the coins there

The user's coins are on legacy leaves of the device's own BIP-44 account because the device
put them there. Three defaults compound:

- **Receive shows one scheme and takes the first one.** `receive.rs:39` is
  `report.schemes.first()?` and `Scheme::ALL[0]` is Bip44 (`derive.rs:106`), so the Receive
  card hands out `1...` addresses for every wallet on the device.
- **Export opens on the legacy tab.** `schemes.rs:123` sets `tab: 0`, regardless of anything
  about the wallet.
- **The first, most prominent block on every tab is the bare account xpub**
  (`schemes.rs:407`), while the origin-carrying descriptor - the artifact the screen's own
  help text tells the reader to use - is the last block, below five address rows
  (`schemes.rs:460`). BIP-44 and BIP-86 have no SLIP-132 form (`derive.rs:148`), so both
  export as a plain `xpub...`, and BlueWallet's documented default builds a LEGACY
  `m/44'/0'/0'` wallet from any bare xpub. The screen's layout contradicts its own
  `DESCRIPTOR_HELP`.

0.2.2 changes the defaults: Receive selects BIP-84 and falls back to the first scheme only
if a report carries no BIP-84 entry; Export opens on the BIP-84 tab; and the export blocks
are reordered so the descriptor leads, captioned as the recommended artifact, with the bare
account xpub last and captioned as advanced. The bare key keeps being emitted - some
coordinators want it, and removing it would break an established workflow - but it stops
being the default gesture. `export::descriptor` keeps emitting `pkh()` for BIP-44, because
section 1 makes the device able to sign what that QR invites.

A returning user's remembered "Address #0" changes from a `1...` address to a `bc1q...`
address as a result. That is intended and is stated in section 8. Legacy addresses stay
visible under Export > BIP44, and coins already received on them become spendable by this
device for the first time under section 1.

---

## 5. Where this release stands

The three decisions above are ratified by this document. They land in five steps, in this
order, each one revertable on its own and each one proved before the next begins:

1. this document, the `KNOWN-ISSUES` entries, and the R-26 rows in `UX-SCREENS.md`, plus
   the legacy amount rule in `WALLET-API.md` - the ratification act, which changes no
   behaviour;
2. R-26 itself: one arm in `model.rs`, one code in `notyas-ui`, host tests both ways, and
   the uisim frame that puts the new band on both panels;
3. legacy admission in `checks.rs`, and the legacy digest, signer arm and post-sign gate
   branch in `sign.rs` and `psbt/signer.rs`, with the amount-rule pins from section 2;
4. the Receive and Export defaults from section 4;
5. the two-board hardware pass, which is the release gate: the corpus legacy case signed and
   verified on hardware, the claimed-amount negative refused on hardware, and a P2SH input
   claiming our key still refused at check 4 - evidence the refusal was not loosened for the
   kinds that remain unsignable.

A tag is cut only after step 5. Until then this document describes what 0.2.2 is, not what
any built image does.

---

## 6. What ships

Per board, for `waveshare-4b` and `elecrow-5`, named `0.2.2` in place of `0.2.1`:
`notyas-0.2.2-<board>-app.bin`, `-bootloader.bin`, `-partition-table.bin`, `-merged.bin`,
`.elf`, `-sdkconfig.txt`, `-BUILDINFO.txt`, `-VERIFY.json`; plus, once,
`notyas-0.2.2-src.tar.gz`, `notyas-0.2.2-components.tar.gz`, `SHA256SUMS.txt` and
`SHA256SUMS.txt.asc`. See `docs/RELEASE-0.2.0.md` section 3 for what each file is; nothing
about the artifact set itself changed.

---

## 7. What deliberately does not ship

Unchanged from `docs/RELEASE-0.2.0.md` section 4 and `docs/RELEASE-0.2.1.md` section 3: no
Secure Boot v2, no flash encryption, no eFuse anti-rollback, no eFuse burn beyond the one
HMAC key, no artifacts for the eight scaffold boards, no crates.io publication, no backup
mechanism, no BSMS, no taproot multisig, no hardware-held signing key, no third-party build
attestation, and no persistent outpoint-to-amount cache. Also not in 0.2.2:

- **P2SH multisig and P2SH-P2WSH multisig.** Still refused, now with R-26 instead of R-04.
  Q7 has not moved.
- **Legacy under any sighash flag but SIGHASH_ALL.** The whitelist for P2PKH is `[0x01]` and
  nothing else, on the same ground as every other kind (Q24: no override ever disables a
  refusal).
- **The rest of the refusal-copy audit.** Section 3 names it; `docs/KNOWN-ISSUES.md` tracks
  it row by row.
- **A scheme selector on the Receive screen.** Receive still shows exactly one scheme; 0.2.2
  changes which one. Viewing or verifying an address of any other scheme is Export's job,
  which is where the per-scheme address rows already are.

---

## 8. Known limitations a buyer must read

All twelve items in `docs/RELEASE-0.2.0.md` section 5 and item 13 in
`docs/RELEASE-0.2.1.md` section 4 still apply unchanged. Add:

14. **Receive now offers a native segwit address where 0.2.1 offered a legacy one.** A
    device upgraded from 0.2.1 shows `bc1q...` as Address #0 for the same wallet that showed
    `1...` before. No key, path or wallet changed, and nothing was lost: the legacy
    addresses are still derived, still listed under Export > BIP44, and coins on them are
    spendable by this device from 0.2.2 onward. Anything already handed out keeps working.
15. **A P2SH input is refused with R-26**, including a wrapped-segwit input of yours whose
    redeem script the coordinator left out of the file. For that case the remedy is in the
    refusal text: re-export the transaction with the redeem script included. For genuine
    P2SH multisig there is no remedy in this release; it is not a script type this device
    signs.

---

## 9. Verification

Signed with the same key as every notyas release, unchanged since 0.2.0:

```
A1E9 53B2 5C6A 623B 77A1 D522 3AC4 BBCF E51A B37D
```

See `docs/VERIFYING.md` for how to check it, and
`docs/keys/A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D.asc` for the published public half.

---

## 10. Release notes skeleton

Paste into the GitHub release, in this order:

1. One paragraph: 0.2.2 is a point release on 0.2.1 that completes legacy P2PKH signing,
   which the design record always specified and the code never implemented; replaces a false
   multisig-attack refusal with an honest one; and stops the Receive and Export screens
   defaulting every user to legacy. It does not change what a unit can do beyond that;
   `docs/RELEASE-0.2.0.md` section 0 is still the authority on the whole feature set.
2. Section 2 of this document in full: the legacy amount rule, which is the security
   statement of this release and the sentence a reviewer should check the code against.
3. Sections 1, 3 and 4: the three fixes, with what each was and what it becomes.
4. Section 8: the two new buyer-facing limitations.
5. Verification: point at `docs/VERIFYING.md` and give the key fingerprint inline (section 9
   above).
6. Reproducibility status: the exact line `tools/release.sh sign` prints for this tag.
7. The artifact list (section 6 above) and which board slug is which.

---

## 11. If a defect surfaces after publication

Same policy as `docs/RELEASE-0.2.0.md` section 8: do not delete or move the tag; disclose on
the release page immediately, naming what is wrong and what a holder should do; treat the
signing/verification chain as unverifiable and republish rather than silently replace if the
defect is there; record it in `docs/KNOWN-ISSUES.md` with its found-date, its blocking
verdict, and what closing it requires.
