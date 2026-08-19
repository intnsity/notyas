# psbtgen

The release-bar harness for MILESTONES.md section 9 clause 2.

Clause 2 is the only clause that can fail the 0.2.0 release on its own: a working wallet
has to do the whole loop on real hardware - load a PSBT from SD, review it, sign it, and
hand the result to a coordinator that accepts it. Nothing in this tree could previously
build a file for the device to load, or judge what came back. This tool is both ends of
that loop.

It never touches hardware. It opens no serial port, flashes nothing, and knows nothing
about COM ports. A human carries the card.

## The four subcommands

```
psbtgen generate [--out DIR]     write the artifact set (default DIR: psbtgen-out)
psbtgen sign FILE [--out FILE]   sign on the host with notyas-core, as the device would
psbtgen verify FILE              would a coordinator accept this signed PSBT?
psbtgen selftest                 run the verifier against files whose answer is known
```

`FILE` may be a binary `.psbt` or a file of hex, and may be `-` for stdin, because both
transport routes exist: the card carries the binary and the serial console carries the hex.

Exit status is the interface: `0` accepted, `1` refused, `2` the tool could not run, `3`
the file is not one psbtgen generated and so cannot be judged at all.

## generate

Writes, to the output directory:

| file | what it is |
|---|---|
| `README.txt` | the operator's card: the mnemonic, the passphrase, the master fingerprint, every expected address, every amount and fee, and the procedure |
| `single.psbt` | a P2WPKH spend from the device's BIP-84 account: a payment output and a change output that re-derives |
| `multisig.psbt` | a spend from a 2-of-3 P2WSH `sortedmulti` wallet the device is a member of |
| `multisig.txt` | that wallet's canonical, checksummed descriptor, for the device to register |

and prints the same PSBTs as hex on stdout, one line each, for pasting over the serial
console.

Every seed in the harness is a published BIP-39 English test vector from
`https://github.com/trezor/python-mnemonic/blob/master/vectors.json` - the file BIP-39
normatively points at, and the same file `crates/notyas-core/tests/vectors/` already
carries - under that file's stated passphrase, `TREZOR`. The tool asserts on startup that
`bip39::seed` reproduces each published seed, so a mistyped word or a regression in the
crate's PBKDF2 stops it before it can emit an artifact.

Both PSBTs carry the FULL previous transaction for the input they spend. That is
ARCHITECTURE.md check 2, and it is the rule that closed the amount-substitution attack: a
segwit v0 signature commits to the amount the signer was TOLD, so an unproven amount is a
fee the user never approved. The engine refuses to sign beside one, and a fixture that
worked around that would be asking the device an easier question than the real one.

Nothing generated here is broadcastable: the funding transactions do not exist on any
chain.

## verify

The half that turns a demo into evidence. For a signed file it:

0. works out WHICH generated case the file claims to be, and compares the whole transaction
   with the copy this tool kept: every output's amount and script, the input set, the
   sequences, the version and the locktime. Any difference is a refusal that names it -
   "output 0 pays 120000 sat to bc1q...van, and the approved 'single' case pays 120000 sat
   to bc1q...rex";
1. resolves every input's previous output, preferring the full previous transaction, and
   checks that the transaction supplied is the one the input actually spends;
2. decides which inputs are the device's from the harness seed and the registered wallet -
   never from what the file claims;
3. recomputes each of those inputs' sighash with `SighashCache` and verifies the signature
   with `secp256k1` (`p2wpkh_signature_hash` / `p2wsh_signature_hash` + `verify_ecdsa`,
   `taproot_key_spend_signature_hash` + `verify_schnorr`);
4. completes the 2-of-3 with the cosigner seeds the harness holds - verifying every leg
   already on the input before counting it towards the threshold - finalizes every input
   and extracts the transaction;
5. checks the extracted transaction's shape and prints the fee it really pays beside the
   fee the card promised.

Step 3 shares nothing with the device's own post-sign gate except the `bitcoin` crate: the
device recomputes its digest through `notyas_core::sign`, and this side goes straight to
`SighashCache` and `Secp256k1` with amounts it resolved itself. A bug that made the signer
agree with its own verifier would still be caught.

A refusal always names the input and the reason, and carries a stable one-word code
(`case-diverges`, `amount-unproven`, `signature-missing`, `signature-invalid`,
`witness-unverified`, `incomplete`, ...) that a script can match on.

### What ACCEPTED means

**psbtgen only prices a transaction it assembled itself, out of signatures it verified
itself.** Any `final_script_witness` or `final_script_sig` the file arrives with is removed
before anything is judged; every input then has to earn a witness back on this side, from
signatures checked here against digests recomputed here. An input that cannot is
`witness-unverified` and the file is refused.

The rule exists because without it every check above was conditional on the file's own
account of which inputs were worth checking. Ownership is decided from `bip32_derivation`
and `tap_key_origins` - hints the file carries - so a file that simply omitted them got no
checks at all: absent origin means "not ours", "not ours" means no signature check and no
finalization, and the witness the file brought passed straight through into the extracted
transaction. Such a file was reported ACCEPTED with exit 0, a txid and a fee rate, over a
witness of arbitrary bytes. That is also the normal shape of a finalized PSBT, since
BIP-174 says a finalizer removes exactly those fields.

The same argument covers the other half of a multisig: a leg counts towards the threshold
only if it verifies here, not because a `partial_sigs` entry exists under a key the witness
script names.

### Step 0, and why it is step 0

A signature is evidence about the transaction it covers and about nothing else. "The
signature verifies" therefore cannot answer the question this tool exists for - whether the
device signed what it displayed - because a transaction paying an attacker carries a
signature that verifies just as well as one paying the payee on the card. Until this step
existed, a file whose payment output had been rewritten and then signed was reported
ACCEPTED with exit 0: the file was looked up by unsigned txid, the edit changed the txid,
the lookup found nothing, and finding nothing meant nothing was compared.

The case is identified by its INPUT set rather than by its outputs or its txid. The prevouts
are the part such a file cannot change - a stolen signature is only spendable against the
outpoints it commits to - while the outputs are precisely what it does change.

### The third answer

A file psbtgen did not generate is `UNRECOGNISED`, exit `3`: not accepted, and not refused
either. There is no approved copy of it here, so nothing in this tool can say whether its
destinations are the ones a human agreed to; its signatures and its shape are still checked
and reported, and that is a strictly smaller statement than acceptance.

That is a real limitation and it is worth stating plainly: **this verifier can only judge
transactions it issued.** It is a release-bar harness, not a general coordinator. A general
one would need the approved intent to come from somewhere else - a policy, a watch-only
wallet, a second channel the operator confirmed - and the honest thing for this tool to do
about a file from outside its own set is to say so in a status a script can act on, rather
than to fall back on internal consistency and call that a pass.

## selftest

A verifier nobody has tried to fool is a rubber stamp. `selftest` runs the verifier
against fifteen cases whose answers are already known: five PSBTs from
`notyas_core::psbt::fixture` (which is where the taproot and P2SH-wrapped cases come from,
along with a batch whose other party has not signed yet), the two generated artifacts, and
eight files that must not be accepted:

| the file | the answer |
|---|---|
| the payment output swapped for another address, then signed | `case-diverges` |
| a spend of a UTXO this harness never generated | `UNRECOGNISED`, exit 3 |
| a signature with one bit flipped | `signature-invalid` |
| a witness the file finished for itself, over stripped origins | `witness-unverified` |
| the signature removed | `signature-missing` |
| the previous transaction stripped after signing | `amount-unproven` |
| an output edited after signing | `signature-invalid` |
| a forged second leg on the 2-of-3 | `signature-invalid` |

`cargo test -p psbtgen` runs that list and, beside it, `src/negatives.rs`: one test per way
a signature can be invalid - a bit flipped in `r`, `s` raised above the half order (BIP-62
rule 5, enforced by `secp256k1_ecdsa_verify`), a signature by another key, a valid signature
over another transaction, `SIGHASH_NONE`, a truncated DER blob (rejected by the decoder, one
layer before the verifier), a witness the file finished for itself, and a forged multisig
leg.

The first is the one the rest of this tool is built around: everything internal about it is
impeccable - the device signed the transaction that is in the file, the signature verifies,
the fee is the fee - and the money goes to an address nobody approved.

The same corpus runs as an ordinary `#[test]`, so `cargo test` at the workspace root
covers it.

## Why notyas-core carries a `testkit` feature

`psbt::fixture` was `#[cfg(test)]`, which made it reachable from nothing but the crate's
own test binary. `testkit` makes it reachable from here, exactly as notyas-wallet's
identically named feature does for its simulator. It adds no dependency and no code to the
device image - `cargo tree` over notyas-core's default feature set is byte-identical with
and without it, and `tools/build-graph-check.sh` asserts the default graph the firmware
links. It must never be enabled in a firmware build: the fixtures carry a fixed seed.

## Running the loop

```
psbtgen generate --out card
# copy card/ to a microSD card, follow card/README.txt on the device
psbtgen verify card/single-signed.psbt
psbtgen verify card/multisig-signed.psbt
```

Verify the files that came back from the device, in the directory the card was generated
into. A `3` means the file being verified is not one of that set - a stale copy, the wrong
card, or a file from somewhere else - and not that the device did anything wrong.

`psbtgen sign` is the host stand-in for the device. It is not a substitute for the hardware
loop and must never be reported as one; what it is for is proving an artifact is signable
before an operator carries a card to a bench, and giving a device disagreement something to
be measured against.
