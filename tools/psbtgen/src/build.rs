// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the device is handed, and why every field of it is there.
//!
//! Two cases, because two are what clause 2's loop needs to be believed: a single-sig
//! P2WPKH spend, which is the plain path, and a 2-of-3 P2WSH `sortedmulti` spend, which is
//! the path where a wrong answer costs somebody else's money too.
//!
//! Both are built to satisfy the engine rather than to slip past it. In particular both
//! carry the FULL previous transaction on every input they spend, not just a `witness_utxo`.
//! That is ARCHITECTURE.md check 2, and the reason it is not negotiable is a demonstrated
//! attack: a coordinator that states an input's amount without proving it can make a
//! hardware wallet display a 1 BTC fee as a 0.001 BTC fee, because a segwit v0 signature
//! commits to the amount the SIGNER was told, not to the amount the chain holds. The
//! engine refuses to sign beside an unproven amount, so a fixture that worked around that
//! rule - by omitting the previous transaction and letting the file assert the value -
//! would be testing a device that had been asked an easier question than the real one.
//!
//! Everything below is a pure function of the harness wallet, so `generate` and `verify`
//! rebuild bit-identical cases from the same constants. That is what lets the verifier say
//! "this is the transaction I asked for, and here is the fee you were promised" instead of
//! only "these signatures verify".
//!
//! [`refused_cases`] is the other half of the set: three shapes 0.2.1's signer cannot sign
//! at all, built the same way and to the same standard, because the shape that needs a
//! hardware refusal to prove itself is exactly as real a fixture as the shape that needs a
//! hardware signature. `cases` and its two names above are untouched by that addition - a
//! generated case that signs today must go on signing exactly as it always has.

use notyas_core::bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use notyas_core::bitcoin::hashes::{sha256, Hash as _};
use notyas_core::bitcoin::psbt::{Psbt, PsbtSighashType};
use notyas_core::bitcoin::secp256k1::PublicKey;
use notyas_core::bitcoin::{
    absolute, transaction, Address, Amount, EcdsaSighashType, OutPoint, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use notyas_core::derive::secp;
use notyas_core::multisig::{Keychain, Registration};

use crate::harness::{self, Harness};

/// The single-sig case: what the funding transaction pays us, what we pay out, and the fee.
///
/// Round numbers, and a fee that is plausible for the transaction's real size (about
/// 11 sat/vB at the vsize the extracted transaction turns out to have). A fee nobody would
/// send is a fee an operator cannot sanity-check on the review screen, which is half of
/// what the screen is for.
const SINGLE_PREVOUT: Amount = Amount::from_sat(200_000);
const SINGLE_PAYMENT: Amount = Amount::from_sat(120_000);
const SINGLE_FEE: Amount = Amount::from_sat(1_500);

/// The multisig case. Larger, because a 2-of-3 P2WSH input is a much bigger witness and a
/// fee that ignored that would look wrong beside the single-sig one.
const MULTI_PREVOUT: Amount = Amount::from_sat(500_000);
const MULTI_PAYMENT: Amount = Amount::from_sat(300_000);
const MULTI_FEE: Amount = Amount::from_sat(2_200);

/// Which output of the funding transaction is ours.
///
/// One, not zero, deliberately. A coordinator, a wallet or a verifier that ignores the
/// outpoint's `vout` and reads `output[0]` gets a different script and a different amount
/// here, so the off-by-one that would pass unnoticed against a one-output funding
/// transaction fails loudly against this one.
const OUR_VOUT: u32 = 1;

/// What the funding transaction's other output is worth. Never spent by anything here; it
/// exists so that [`OUR_VOUT`] is a real choice rather than a formality.
const DECOY_VALUE: Amount = Amount::from_sat(31_337);

/// The procedure the card prints. A raw literal so the indentation on the card is the
/// indentation written here, and so a line can be reworded without re-deriving how the
/// escapes line up.
const PROCEDURE: &str = r#"PROCEDURE
---------
  1. Load the words and the passphrase on the device. Confirm the master fingerprint
     above before going any further: a mistyped passphrase changes every value below,
     and this is the one line that shows it immediately.
  2. Confirm the first receive address of each case on the device. Those addresses were
     computed here from the seed and not read back from the device, so agreement is
     evidence and disagreement is a finding.
  3. Import multisig.txt as a wallet. The device must show the same 2-of-3.
  4. For each .psbt: load it from the card, review it, and check the payment address,
     the change address and the FEE against the lines above. A fee the device reports
     differently from this file is the failure this whole set exists to catch.
  5. Sign. The device writes <name>-signed.psbt beside the original.
  6. Copy the signed files back to the host and run

         psbtgen verify <name>-signed.psbt

     which compares the WHOLE transaction that came back with the one generated here -
     every output, every amount, every script - then re-derives every amount from the
     previous transactions, recomputes every sighash, verifies every signature, completes
     the multisig with the cosigner seeds this harness holds, extracts the transaction
     and prints the fee it really pays. A device that displayed one destination and
     signed another is refused here, by name, rather than passed as a signature that
     verifies.
  7. Read the exit status: 0 accepted, 1 refused, 3 the file is not one of this set.
     Verify the files that came back from THIS card; a file from anywhere else has no
     approved copy here to be compared against, and is reported unrecognised rather than
     accepted.
"#;

/// A generated case: the file the device is given, plus everything an operator or a
/// verifier needs in order to judge what comes back.
#[derive(Debug)]
pub struct Case {
    /// Short name, used by refusals and by the verifier when it recognises a file.
    pub name: &'static str,
    /// The file name on the card.
    pub file: &'static str,
    /// One line for the operator: what the device is being asked to do.
    pub what: &'static str,
    pub psbt: Psbt,
    pub payment: Amount,
    pub change: Amount,
    /// The fee the review screen must show, and the fee the broadcast transaction must pay.
    /// The verifier prints the real one beside this one, because the whole point of the
    /// amount rule is that they are the same number.
    pub fee: Amount,
    pub payment_address: Address,
    pub change_address: Address,
    /// The wallet's first receive address, computed here from the harness seed and printed
    /// on the card so the device's own display can be checked against a value it had no
    /// part in producing.
    pub first_receive_address: Address,
}

impl Case {
    /// The unsigned transaction's txid, for the operator's card.
    ///
    /// Signatures are witness data, so this value survives signing unchanged and a signed
    /// file that still bears it is the same transaction. It is NOT how the verifier decides
    /// what a file is: a txid that no longer matches says only "something changed", and the
    /// answer that matters is which output moved. See `verify::Expectation`.
    pub fn unsigned_txid(&self) -> Txid {
        self.psbt.unsigned_tx.compute_txid()
    }
}

/// Both cases, in the order the card lists them.
pub fn cases(harness: &Harness) -> Vec<Case> {
    vec![singlesig_case(harness), multisig_case(harness)]
}

/// A P2WPKH spend of one output the device's BIP-84 account owns.
fn singlesig_case(harness: &Harness) -> Case {
    let device = &harness.device;
    let input_script = device.singlesig_script(Keychain::Receive, 0);
    let change_address = device.singlesig_address(Keychain::Change, 0);
    let prev = funding(
        "notyas psbtgen single",
        &harness.decoy_script(),
        &input_script,
        SINGLE_PREVOUT,
    );
    let change = SINGLE_PREVOUT - SINGLE_PAYMENT - SINGLE_FEE;

    let unsigned = spend(
        &prev,
        &[
            TxOut {
                value: SINGLE_PAYMENT,
                script_pubkey: harness.payee_script(),
            },
            TxOut {
                value: change,
                script_pubkey: change_address.script_pubkey(),
            },
        ],
    );
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("a freshly built unsigned tx is clean");

    // The input. `witness_utxo` is what a signer reads; `non_witness_utxo` is what PROVES
    // it, and the engine will not sign beside an amount that rests on the first alone.
    psbt.inputs[0].witness_utxo = Some(prev.output[OUR_VOUT as usize].clone());
    psbt.inputs[0].non_witness_utxo = Some(prev);
    // Explicit SIGHASH_ALL rather than an absent field. Both are accepted by check 7; the
    // explicit form is what real coordinators send, so it is the one worth exercising.
    psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::All));
    let key = device.key_at(&harness::singlesig_path(Keychain::Receive, 0));
    psbt.inputs[0].bip32_derivation.insert(
        key.public_key().0,
        (
            device.fingerprint(),
            harness::singlesig_path(Keychain::Receive, 0),
        ),
    );

    // The change output carries its origin, which is what makes it re-derivable rather than
    // merely asserted: anyone holding the account xpub can rebuild this exact script from
    // the path below and check it against the scriptPubKey. notyas-core deliberately stops
    // short of calling a single-sig output change (that proof needs a descriptor and a gap
    // bound, and belongs to notyas-wallet), so on the device this shows as a claim the
    // engine has not itself proved - and the address on the card is how an operator closes
    // that gap by eye.
    let change_key = device.key_at(&harness::singlesig_path(Keychain::Change, 0));
    psbt.outputs[1].bip32_derivation.insert(
        change_key.public_key().0,
        (
            device.fingerprint(),
            harness::singlesig_path(Keychain::Change, 0),
        ),
    );

    Case {
        name: "single",
        file: "single.psbt",
        what: "spend 120000 sat from the BIP-84 account, 78500 sat back to change",
        psbt,
        payment: SINGLE_PAYMENT,
        change,
        fee: SINGLE_FEE,
        payment_address: harness.payee(),
        change_address,
        first_receive_address: device.singlesig_address(Keychain::Receive, 0),
    }
}

/// A 2-of-3 P2WSH `sortedmulti` spend, from a wallet the device is a registered member of.
fn multisig_case(harness: &Harness) -> Case {
    let registration = harness.registration();
    let input_script = registration
        .script_pubkey(Keychain::Receive, 0)
        .expect("the registered wallet builds its own receive leaf 0");
    let witness_script = registration
        .witness_script(Keychain::Receive, 0)
        .expect("the registered wallet builds its own receive leaf 0");
    let change_address = registration
        .address(Keychain::Change, 0)
        .expect("the registered wallet builds its own change leaf 0");
    let prev = funding(
        "notyas psbtgen multisig",
        &harness.decoy_script(),
        &input_script,
        MULTI_PREVOUT,
    );
    let change = MULTI_PREVOUT - MULTI_PAYMENT - MULTI_FEE;

    let unsigned = spend(
        &prev,
        &[
            TxOut {
                value: MULTI_PAYMENT,
                script_pubkey: harness.payee_script(),
            },
            TxOut {
                value: change,
                script_pubkey: change_address.script_pubkey(),
            },
        ],
    );
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("a freshly built unsigned tx is clean");

    psbt.inputs[0].witness_utxo = Some(prev.output[OUR_VOUT as usize].clone());
    psbt.inputs[0].non_witness_utxo = Some(prev);
    psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::All));
    psbt.inputs[0].witness_script = Some(witness_script);
    for (key, source) in leaf_derivations(registration, Keychain::Receive, 0) {
        psbt.inputs[0].bip32_derivation.insert(key, source);
    }

    // Every cosigner's origin on the change output too. For a multisig output this is a
    // provable claim rather than an assertion: the device rebuilds the script from the
    // REGISTRATION it verified at import time and compares, which is ARCHITECTURE.md
    // check 4 and is what defeats the 2019 change-confusion attack. A device that shows
    // this output as anything other than change is a finding.
    for (key, source) in leaf_derivations(registration, Keychain::Change, 0) {
        psbt.outputs[1].bip32_derivation.insert(key, source);
    }

    Case {
        name: "multisig",
        file: "multisig.psbt",
        what: "spend 300000 sat from the 2-of-3, 197800 sat back to multisig change",
        psbt,
        payment: MULTI_PAYMENT,
        change,
        fee: MULTI_FEE,
        payment_address: harness.payee(),
        change_address,
        first_receive_address: registration
            .first_receive_address()
            .expect("the registered wallet builds its own first receive address"),
    }
}

/// The `legacy` and `legacy-claimed` cases' fixed amounts.
const LEGACY_PREVOUT: Amount = Amount::from_sat(150_000);
const LEGACY_PAYMENT: Amount = Amount::from_sat(90_000);
const LEGACY_FEE: Amount = Amount::from_sat(1_800);

/// The `p2sh-ours` negative's fixed amounts. Its own constants, not `LEGACY_*`: reusing
/// those would make an unrelated coincidence between two cases' fees look like a deliberate
/// one to a reader of the card.
const P2SH_OURS_PREVOUT: Amount = Amount::from_sat(80_000);
const P2SH_OURS_PAYMENT: Amount = Amount::from_sat(50_000);
const P2SH_OURS_FEE: Amount = Amount::from_sat(900);

/// Three cases 0.2.1's signer cannot sign, built to the same standard [`cases`] is: a full
/// previous transaction, a genuine ownership claim at a sane path, nothing this fixture
/// invented to make the refusal easier to provoke than the real one is. Kept apart from
/// [`cases`] rather than folded into it because they answer a different question -
/// `verify::Coordinator` only ever judges a file that reached a signature, and none of
/// these three do; `selftest` asserts each against `notyas_core::psbt::inspect` directly.
/// See that module for the expected `CheckFailure` and why it is the same one, check 4, for
/// all three.
pub fn refused_cases(harness: &Harness) -> Vec<Case> {
    vec![
        legacy_case(harness),
        legacy_claimed_case(harness),
        p2sh_ours_case(harness),
    ]
}

/// CORPUS.md P3: a single-sig P2PKH spend, "legacy sighash path, and the strictest
/// `non_witness_utxo` requirement". Ratified in 0.2.0 and never built, because until this
/// wave nothing in this tree could prove what a device does with it: the signer has no
/// legacy arm (0.2.1), so this file is REFUSED today, at ARCHITECTURE.md check 4
/// (`ClaimedInputNotSingleSig`) - the same check, wearing the same wrong name (R-04,
/// "cosigner keys do not match") that this wave's docs and its refusal-code lift are about.
/// It stays that way until legacy signing lands; see `selftest`, which pins today's verdict
/// so that change is a test going from red to green rather than a claim nobody checked.
///
/// The input is unconditionally proven: CORPUS.md's "strictest requirement" is that a
/// legacy input never relies on `witness_utxo` alone, because a pre-segwit signature
/// commits to no amount at all and so has no BIP-143 digest to make a false one costly. See
/// `legacy_claimed_case`, the negative that pulls this proof and must stay refused even
/// after legacy signing lands.
fn legacy_case(harness: &Harness) -> Case {
    let device = &harness.device;
    let input_script = device.legacy_script(Keychain::Receive, 0);
    let change_address = device.legacy_address(Keychain::Change, 0);
    let prev = funding(
        "notyas psbtgen legacy",
        &harness.decoy_script(),
        &input_script,
        LEGACY_PREVOUT,
    );
    let change = LEGACY_PREVOUT - LEGACY_PAYMENT - LEGACY_FEE;

    let unsigned = spend(
        &prev,
        &[
            TxOut {
                value: LEGACY_PAYMENT,
                script_pubkey: harness.payee_script(),
            },
            TxOut {
                value: change,
                script_pubkey: change_address.script_pubkey(),
            },
        ],
    );
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("a freshly built unsigned tx is clean");

    psbt.inputs[0].non_witness_utxo = Some(prev);
    psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::All));
    let key = device.key_at(&harness::legacy_path(Keychain::Receive, 0));
    psbt.inputs[0].bip32_derivation.insert(
        key.public_key().0,
        (device.fingerprint(), harness::legacy_path(Keychain::Receive, 0)),
    );

    let change_key = device.key_at(&harness::legacy_path(Keychain::Change, 0));
    psbt.outputs[1].bip32_derivation.insert(
        change_key.public_key().0,
        (device.fingerprint(), harness::legacy_path(Keychain::Change, 0)),
    );

    Case {
        name: "legacy",
        file: "legacy.psbt",
        what: "spend 90000 sat from the BIP-44 account, 58200 sat back to change - \
               CORPUS.md P3; REFUSED today (check 4, no legacy signer yet), must ACCEPT \
               once legacy signing lands",
        psbt,
        payment: LEGACY_PAYMENT,
        change,
        fee: LEGACY_FEE,
        payment_address: harness.payee(),
        change_address,
        first_receive_address: device.legacy_address(Keychain::Receive, 0),
    }
}

/// `legacy_case`'s file with its ownership proof pulled and a bare claim left standing:
/// `non_witness_utxo` removed, `witness_utxo` supplied in its place. Everything else -
/// version, locktime, every input and every output - is untouched, so this is the exact
/// experiment CORPUS.md's "strictest requirement" is about: the only variable that moves is
/// how the amount is known.
///
/// REFUSED today for the same reason `legacy_case` is (check 4 fires before amount proof is
/// even considered, for a single-input file). The two diverge only once legacy signing
/// lands: `legacy_case` starts signing, and this file MUST NOT, because a legacy signature
/// commits to no amount at all and so can never take the single-input exemption
/// ARCHITECTURE.md check 2 grants a segwit v0 spend of one input. Pinning that divergence in
/// advance - one file that starts passing, an adjacent one built to fail the same way
/// forever - is this case's whole purpose.
fn legacy_claimed_case(harness: &Harness) -> Case {
    let legacy = legacy_case(harness);
    let mut psbt = legacy.psbt.clone();
    let prev = psbt.inputs[0]
        .non_witness_utxo
        .take()
        .expect("legacy_case always carries its own previous transaction");
    psbt.inputs[0].witness_utxo = Some(prev.output[OUR_VOUT as usize].clone());
    Case {
        name: "legacy-claimed",
        file: "legacy-claimed.psbt",
        what: "the 'legacy' spend with its previous transaction stripped and a witness_utxo \
               claim left in its place - REFUSED today, and must STAY refused after legacy \
               signing lands: a legacy signature proves no amount",
        psbt,
        ..legacy
    }
}

/// A P2SH input the harness wallet's own BIP-49 leaf genuinely unlocks - the scriptPubKey is
/// exactly what that leaf's P2WPKH program wraps into - claimed without the one field
/// (`redeem_script`) a device needs to tell this apart from a P2SH of any other shape.
/// Mirrors `notyas_core::psbt::fixture::p2sh_psbt_claiming_our_key`, which reaches the same
/// refusal from the opposite direction - an artificial non-P2WPKH redeem script supplied,
/// rather than none supplied at all - but bound to the HARNESS wallet's key, so it is a file
/// a human can actually load: a device holding this seed proves the claim, the same way it
/// would for `legacy`.
///
/// REFUSED today at the same check 4 as `legacy` (a P2SH with no redeem script classifies as
/// `ScriptKind::P2sh`, which `is_single_sig` also answers no for). Unlike `legacy`, this stays
/// refused after legacy signing lands - admitting P2PKH does nothing for a script this
/// device can never classify at all - which is what makes it the one file on the card that
/// can still provoke the lifted refusal band (R-26, once T4 lands) on a product image.
fn p2sh_ours_case(harness: &Harness) -> Case {
    let device = &harness.device;
    let input_script = device.nested_script(Keychain::Receive, 0);
    let change_address = device.nested_address(Keychain::Change, 0);
    let prev = funding(
        "notyas psbtgen p2sh-ours",
        &harness.decoy_script(),
        &input_script,
        P2SH_OURS_PREVOUT,
    );
    let change = P2SH_OURS_PREVOUT - P2SH_OURS_PAYMENT - P2SH_OURS_FEE;

    let unsigned = spend(
        &prev,
        &[
            TxOut {
                value: P2SH_OURS_PAYMENT,
                script_pubkey: harness.payee_script(),
            },
            TxOut {
                value: change,
                script_pubkey: change_address.script_pubkey(),
            },
        ],
    );
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("a freshly built unsigned tx is clean");

    // Proven, and no redeem script - deliberately: the amount is not the defect this case
    // is for, and leaving it claimed-only would let a reader wonder whether check 2 or
    // check 4 is what actually refused this file. Only check 4 does.
    psbt.inputs[0].non_witness_utxo = Some(prev);
    psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::All));
    let key = device.key_at(&harness::nested_path(Keychain::Receive, 0));
    psbt.inputs[0].bip32_derivation.insert(
        key.public_key().0,
        (device.fingerprint(), harness::nested_path(Keychain::Receive, 0)),
    );

    Case {
        name: "p2sh-ours",
        file: "p2sh-ours.psbt",
        what: "a P2SH input at the harness wallet's own BIP-49 key, redeem_script withheld - \
               REFUSED (check 4), and stays refused even after legacy signing lands",
        psbt,
        payment: P2SH_OURS_PAYMENT,
        change,
        fee: P2SH_OURS_FEE,
        payment_address: harness.payee(),
        change_address,
        first_receive_address: device.nested_address(Keychain::Receive, 0),
    }
}

/// The transaction that paid the wallet, in full.
///
/// Its own input spends an outpoint derived from `label` by SHA-256. That outpoint does not
/// exist on any chain and is not supposed to: what check 2 needs is a previous transaction
/// whose txid is the one the spend names and whose output at `vout` is the script and the
/// amount being claimed, and all three of those are real here. Deriving the txid from a
/// label rather than fixing a constant keeps the two cases distinct and keeps every run of
/// this tool byte-identical.
fn funding(label: &str, decoy: &ScriptBuf, ours: &ScriptBuf, value: Amount) -> Transaction {
    let seed_txid = Txid::from_byte_array(sha256::Hash::hash(label.as_bytes()).to_byte_array());
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: seed_txid,
                vout: 7,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: DECOY_VALUE,
                script_pubkey: decoy.clone(),
            },
            TxOut {
                value,
                script_pubkey: ours.clone(),
            },
        ],
    }
}

/// One input spending `prev`'s [`OUR_VOUT`], the given outputs, RBF signalled.
fn spend(prev: &Transaction, outputs: &[TxOut]) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev.compute_txid(),
                vout: OUR_VOUT,
            },
            script_sig: ScriptBuf::new(),
            // Signalling replaceability is what a coordinator that expects to bump a fee
            // does, and it is the value the review screen reports as "replaceable".
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: outputs.to_vec(),
    }
}

/// The `(pubkey, (fingerprint, path))` entry every cosigner of `registration` has at one
/// leaf: exactly what a coordinator attaches so each member can find its own key.
///
/// Derived from the registration's stored xpubs, not from any seed, because that is all a
/// coordinator holds - and it is the whole reason a PSBT can be handed to a member who
/// keeps its seed on an airgapped device.
pub fn leaf_derivations(
    registration: &Registration,
    keychain: Keychain,
    index: u32,
) -> Vec<(PublicKey, (Fingerprint, DerivationPath))> {
    let chain = harness::chain_of(keychain);
    registration
        .cosigners()
        .iter()
        .map(|cosigner| {
            let child = cosigner
                .xpub
                .derive_pub(
                    secp(),
                    &[
                        ChildNumber::from_normal_idx(chain).expect("a keychain index is normal"),
                        ChildNumber::from_normal_idx(index).expect("a leaf index is normal"),
                    ],
                )
                .expect("a cosigner leaf derives");
            (
                child.public_key,
                (
                    cosigner.fingerprint,
                    harness::multisig_leaf_path(keychain, index),
                ),
            )
        })
        .collect()
}

/// A file the operator copies to the card.
#[derive(Debug)]
pub struct Artifact {
    pub file: String,
    pub bytes: Vec<u8>,
    /// Whether stdout should render the bytes as hex (a PSBT, for the serial route) or
    /// leave them as the text they already are.
    pub binary: bool,
}

/// Everything `generate` writes: the two PSBTs, the descriptor to register, and the card
/// that tells an operator what to do with them and what the answers must be.
pub fn artifacts(harness: &Harness, cases: &[Case]) -> Vec<Artifact> {
    let mut out = vec![Artifact {
        file: "README.txt".to_string(),
        bytes: card(harness, cases).into_bytes(),
        binary: false,
    }];
    out.push(Artifact {
        file: "multisig.txt".to_string(),
        // The canonical checksummed descriptor. `.txt` is the extension the device's card
        // reader offers as a wallet import (notyas_wallet::sd), and the checksum is what
        // makes a corrupted transfer a refusal rather than a different wallet.
        bytes: format!("{}\n", harness.descriptor()).into_bytes(),
        binary: false,
    });
    for case in cases {
        out.push(Artifact {
            file: case.file.to_string(),
            bytes: case.psbt.serialize(),
            binary: true,
        });
    }
    out
}

/// The human half of the artifact set: the procedure, and every value the device must
/// agree with.
fn card(harness: &Harness, cases: &[Case]) -> String {
    let device = &harness.device;
    let mut s = String::new();
    s.push_str("notyas device test set (psbtgen)\n");
    s.push_str("================================\n\n");
    s.push_str(
        "Every value below is derived from published BIP-39 test vectors, so it can be\n\
         rebuilt from the specification and does not have to be taken on trust. Nothing\n\
         here is broadcastable: the funding transactions do not exist on any chain.\n\n",
    );

    s.push_str("SEED TO LOAD ON THE DEVICE\n");
    s.push_str("--------------------------\n");
    s.push_str(&format!("  words       {}\n", device.vector.mnemonic));
    s.push_str(&format!("  passphrase  {}\n", harness::PASSPHRASE));
    s.push_str(&format!(
        "  source      trezor/python-mnemonic vectors.json, english[{}] (entropy {})\n",
        device.vector.upstream_index, device.vector.entropy
    ));
    s.push_str(&format!(
        "  fingerprint {}   <- check this first; a wrong passphrase shows up here\n\n",
        device.fingerprint()
    ));

    s.push_str("WALLET TO REGISTER (multisig.txt)\n");
    s.push_str("---------------------------------\n");
    s.push_str(&format!("  {}\n\n", harness.descriptor()));

    for case in cases {
        s.push_str(&format!("CASE: {} ({})\n", case.name, case.file));
        s.push_str(&"-".repeat(40));
        s.push('\n');
        s.push_str(&format!("  what            {}\n", case.what));
        s.push_str(&format!(
            "  first receive   {}\n",
            case.first_receive_address
        ));
        s.push_str(&format!(
            "  pays            {} sat to {}\n",
            case.payment.to_sat(),
            case.payment_address
        ));
        s.push_str(&format!(
            "  change          {} sat to {}\n",
            case.change.to_sat(),
            case.change_address
        ));
        s.push_str(&format!("  fee             {} sat\n", case.fee.to_sat()));
        s.push_str(&format!("  unsigned txid   {}\n\n", case.unsigned_txid()));
    }

    s.push_str(PROCEDURE);
    s
}
