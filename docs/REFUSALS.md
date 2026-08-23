# Refusal codes

When notyas will not sign a file, it says so on a full screen rather than in a toast, and
the screen carries five things: a code, a headline, **What happened** in the validation
engine's own words, **Why this matters**, and **What to do**. This document is the table of
codes, so a code photographed off a panel can be looked up without reading Rust.

The words below are transcribed from `RefusalCode` in `crates/notyas-ui/src/lib.rs`, which
is where they are defined. If this document and the panel ever disagree, the panel is right
and this file is stale.

## How the numbering works

- **R-01 to R-10** are the ten ratified validation checks, in the order
  `docs/plan-0.2.0/ARCHITECTURE.md` section 5.3 numbers them. The mapping from a check to
  its code is `code_for` in `firmware/src/flow/model.rs` and it is one-to-one.
- **R-20 to R-26** sit outside that numbering, for faults that are not check failures: the
  file was never a PSBT, the card is not there, the write failed, or the script is not one
  this device signs.
- **R-00** is "this build cannot do that", for a screen that raises a request this firmware
  has no implementation behind.

Three failures are lifted out of their check group before the table is consulted, because
the group's copy answers a different situation than the failure is in: a file over the
structural cap and an unsupported PSBT version report the same code they would have got
from the decoder, and a script this device does not sign gets R-26 rather than R-04. The
lift is presentation only. The check that refused, its number, and the engine's own sentence
are unchanged, which is why the **What happened** line under an R-26 band still opens
"Check 4 (multisig binding)".

## The table

**What to do** is a `&'static str` on every code, so a refusal cannot render without an
action. **Why this matters** is optional and is absent on exactly two codes, R-23 and R-24,
because there is no attack behind an empty card slot and a fabricated sentence there would
teach a user to skim the section that elsewhere carries the whole warning. Both properties
are asserted for all eighteen codes by
`every_code_fills_the_sections_it_claims_to` in `crates/notyas-ui/src/screens/refusal.rs`.

### The ten validation checks

| Code | Headline | Why this matters | What to do |
|---|---|---|---|
| **R-01** | These inputs are not from this wallet | Signing needs the wallet that owns the coins. | Open that wallet and load the file again. |
| **R-02** | Missing the previous transaction | Without it, nothing proves what these coins are worth. Telling a signer a false amount is how it is tricked into paying its balance as a fee, and with more than one input this device cannot rule that out. | Spend a single coin - use coin control to select one - or re-export from software that includes full previous transactions (Sparrow, Electrum, Bitcoin Core), then load it again. |
| **R-03** | Change output not proven | This is exactly what an attacker does to redirect your change. | Do not sign. Check the transaction in your wallet software. |
| **R-04** | Cosigner keys do not match | A substituted cosigner key sends your coins to someone else's multisig. | Compare the registration on all your devices. Import it again if it changed legitimately. |
| **R-05** | Wrong network | Signing across networks can expose keys that were meant to stay separate. | Open the testnet wallet, or load a mainnet transaction. |
| **R-06** | Fee is impossible | A negative fee means the file is corrupt or hostile. | Rebuild the transaction in your wallet software. |
| **R-07** | Unsupported signature type | notyas signs SIGHASH_ALL only. Other types let the outputs be changed after you sign. | Rebuild the transaction with the default signature type. |
| **R-08** | Unexpected taproot data | Signing data the device cannot interpret is signing a blank cheque. | Rebuild the transaction without it. |
| **R-09** | This file is malformed | A signer that accepts malformed input is a signer that can be steered. | Re-export the transaction and load it again. |
| **R-10** | Signature check failed | This is a device fault, not a problem with your transaction. Nothing was signed and nothing was written. | Run Verify device and report this with the details below. |

R-10 is the post-sign gate: every signature the device produced is re-verified against a
sighash recomputed from the PSBT alone before the file is released. A refusal that arrives
after the hold gesture returns you to the wallet home rather than to the file picker, and it
says that nothing moved, because "load a different file" is the wrong instruction to give
somebody whose device just failed its own check.

### Faults that are not check failures

| Code | Headline | Why this matters | What to do |
|---|---|---|---|
| **R-20** | This file is not a PSBT | The device reads PSBT files only. | Check the file, or choose a different one. |
| **R-21** | PSBT version 2 is not supported | This device reads version 0, which is what wallet software produces today. | Export as a version 0 PSBT. |
| **R-22** | File is too large | The device holds the whole transaction in memory to check it. | Split the transaction, or use fewer inputs. |
| **R-23** | No card detected | (none, by design) | Insert a FAT32-formatted card and try again. |
| **R-24** | No PSBT files on this card | (none, by design) | Copy the transaction onto the card, or show all files. |
| **R-25** | Card write failed | The file on the card is incomplete. | Delete that file, then retry - or show the signed transaction as a QR instead. |
| **R-26** | Not a script this device signs | This device signs only script types it can verify end to end. Anything else is refused rather than signed blind. | Spend these coins from a wallet that supports this script type. If this is a wrapped-segwit coin, re-export the transaction with its redeem script included. |
| **R-00** | This build cannot do that | A device that quietly does nothing teaches you that an operation succeeded. | Update to a firmware release that carries this screen. |

## The two you are most likely to meet

**R-02, on a multi-input spend.** This is not a malfunction. A segwit v0 input may rest on
the file's word about what the coin is worth only when the unsigned transaction has a single
input; with two or more inputs every amount must be proven by a full previous transaction.
The attack it forecloses, and why no stateless device can admit the multi-input case, is
`docs/RELEASE-0.2.1.md` section 0. In practice it means a BlueWallet consolidation or Send
Max is refused and a single-coin BlueWallet spend is not, and the remedy is coin control or
rebuilding in Sparrow, Electrum or Bitcoin Core.

**R-26, on a P2SH input.** After legacy P2PKH signing landed, what still reaches R-26 is
P2SH, OP_RETURN and anything unrecognised. For genuine P2SH multisig and P2SH-P2WSH multisig
there is no remedy in this release; they are not script types this device signs. For a
wrapped-segwit coin of yours whose redeem script the coordinator omitted, the remedy is the
second sentence of the code's own "what to do": re-export with the redeem script included.

R-26 exists because that failure used to wear R-04's copy. A user spending his own legacy
coins was told a cosigner key had been substituted and to compare registrations he did not
have. R-04 is now reserved for a genuine mismatch in a cosigner set, which is the one
refusal on this device that has to be believed instantly if it ever fires. The whole report
is `docs/RELEASE-0.2.2.md` sections 0 and 3.

## Copy that is known to be wrong

The refusal vocabulary is not finished, and the defects are tracked rather than glossed in
`docs/KNOWN-ISSUES.md`.

Ten rows render text that is false or misdirected for at least one situation they cover: a
previous transaction that is **present** and contradicts its input is reported as "Missing
the previous transaction"; a tamper tripwire is reported as a calm wrong-wallet mixup; an
ordinary pre-registration multisig onboarding step is reported as a key mismatch. Card and
registration faults borrow file-flavoured copy the same way. Every one of them refuses the
right file for the right reason. What is wrong is what the user is told to do next.

Separately, the **What happened** sentence under an R-26 band still opens "Check 4 (multisig
binding)" under a headline that says nothing about multisig. That sentence is the engine's
own and it is what a bug report is photographed from, and the ten-check numbering is
ratified, so changing it means either renaming a ratified check or letting the UI rewrite
engine text. Both are larger decisions than that release made.

## The details block

Every refusal screen carries a `[ Show details ]` control, hidden until you ask for it. It
reveals the machine facts: input indexes, outpoints, the claimed derivation path, the script
type, and the check number. That is the block to photograph for a bug report. It never
contains key material.

Report at https://github.com/intnsity/notyas/issues.

## Where the rules behind these codes are written

- `docs/SECURITY.md` invariant 7 - the signing policy engine as the trust boundary.
- `docs/RELEASE-0.2.1.md` section 0 - the amount-proof rule, the rotation attack it stops,
  and the broader relaxation that was implemented and rejected.
- `docs/RELEASE-0.2.2.md` section 2 - the legacy amount rule; section 3 - R-26.
- `docs/plan-0.2.0/ARCHITECTURE.md` section 5.3 - the ten checks, each pinned to the
  historical attack it defends against.
- `crates/notyas-core/src/psbt/checks.rs` - the checks themselves, with the negative test
  pins that stop a future change reopening any of them.
