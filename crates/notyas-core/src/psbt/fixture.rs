// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Test-only PSBTs, built from one fixed seed.
//!
//! Every hostile case in this module is the corresponding clean case with exactly one
//! thing changed. That is deliberate: a negative test built from its own hand-written file
//! proves only that some file is refused, while a one-field mutation of a file that
//! otherwise passes proves that the named check is the thing doing the refusing.
//!
//! The seed is a constant, not entropy: these fixtures are also the known-answer base for
//! the signing tests, and a signature over a random key proves nothing that can be pinned.

use alloc::vec;
use alloc::vec::Vec;

use bitcoin::bip32::{DerivationPath, Fingerprint};
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::{
    absolute, transaction, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, WScriptHash, Witness,
};

use super::{Context, StructuralLimits};
use crate::multisig::{Keychain, Registration};
use crate::sign::{derive_path, SecretSigningKey};

/// What the fixture input is worth.
pub const PREVOUT_SAT: u64 = 100_000;
/// What the fixture transaction pays in fee: prevout minus the single output.
pub const FEE_SAT: u64 = 10_000;

/// The one seed every fixture derives from.
pub const SEED: [u8; 64] = [0x2a; 64];
pub const NETWORK: Network = Network::Bitcoin;

pub const P2PKH_PATH: &str = "m/44'/0'/0'/0/0";
pub const P2WPKH_PATH: &str = "m/84'/0'/0'/0/0";
pub const P2SH_P2WPKH_PATH: &str = "m/49'/0'/0'/0/0";
pub const P2TR_PATH: &str = "m/86'/0'/0'/0/0";

pub fn fingerprint() -> Fingerprint {
    crate::derive::master_fingerprint(&SEED, NETWORK)
}

/// The stateless context: no multisig wallet registered. Every m6 fixture is inspected
/// through this one, which is what keeps the single-sig corpus a test of the single-sig
/// path and nothing else.
pub fn context() -> Context<'static> {
    context_with(&[])
}

/// The same context with a registry in scope, for the m7 cases.
pub fn context_with(registry: &[Registration]) -> Context<'_> {
    Context {
        network: NETWORK,
        fingerprint: fingerprint(),
        limits: StructuralLimits::DEFAULT,
        registry,
    }
}

pub fn path(s: &str) -> DerivationPath {
    s.parse().expect("fixture path")
}

pub fn key_at(s: &str) -> SecretSigningKey {
    derive_path(&SEED, NETWORK, &path(s)).expect("fixture derivation")
}

/// Where the fixture transaction sends its money: a key of ours from a different account,
/// with no derivation information attached, so it reads as somebody else's address.
fn external_script() -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&key_at("m/84'/0'/9'/0/0").public_key().wpubkey_hash())
}

/// One input spending `spk`, one output, RBF signalled.
fn skeleton(spk: &ScriptBuf) -> (Transaction, Psbt) {
    let prev = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(PREVOUT_SAT),
            script_pubkey: spk.clone(),
        }],
    };
    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(PREVOUT_SAT - FEE_SAT),
            script_pubkey: external_script(),
        }],
    };
    let psbt = Psbt::from_unsigned_tx(unsigned).expect("fixture psbt");
    (prev, psbt)
}

/// The segwit-v0 shape: full previous transaction plus the witness utxo, which is what a
/// well behaved coordinator sends.
fn segwit_v0_skeleton(spk: &ScriptBuf) -> Psbt {
    let (prev, mut psbt) = skeleton(spk);
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(PREVOUT_SAT),
        script_pubkey: spk.clone(),
    });
    psbt.inputs[0].non_witness_utxo = Some(prev);
    psbt
}

/// The legacy shape: the full previous transaction and NOTHING beside it.
///
/// Deliberately not [`segwit_v0_skeleton`] with one field dropped. A pre-BIP-143 signature
/// commits to no amount at all, so a `witness_utxo` on a legacy input is a number the signed
/// bytes could never contradict, and this device requires the txid-checked previous
/// transaction for every legacy input without exception - the strictest amount regime it
/// has. `docs/RELEASE-0.2.2.md` section 2 is the rule; the two negatives below are what
/// happens to a file that leaves it out.
fn legacy_skeleton(spk: &ScriptBuf) -> Psbt {
    let (prev, mut psbt) = skeleton(spk);
    psbt.inputs[0].non_witness_utxo = Some(prev);
    psbt
}

/// The scriptPubKey a BIP-44 leaf of [`SEED`] is locked to: `76a914{hash160(pubkey)}88ac`.
///
/// Built through [`ScriptBuf::new_p2pkh`] rather than through `crate::address`, so that a
/// fixture proven ours by derivation is proving that `Account::leaf` and this file agree
/// rather than that one of them is consistent with itself.
fn legacy_script(p: &str) -> ScriptBuf {
    ScriptBuf::new_p2pkh(&key_at(p).public_key().pubkey_hash())
}

// ---------------------------------------------------------------------------------------
// Clean cases
// ---------------------------------------------------------------------------------------

/// CORPUS group P3, ratified in 0.2.0 and first built in 0.2.2: a single-sig P2PKH spend of
/// this device's own BIP-44 account, carrying the previous transaction that proves what the
/// coin is worth.
///
/// This is the shape of the file that provoked the field report - a bare account xpub
/// exported from this device, imported by a wallet that reads any bare xpub as
/// `m/44'/0'/0'`, spending a coin from the scheme `Scheme::ALL` puts FIRST and the receive
/// screen hands out by default. The device derived the leaf, rebuilt this exact script,
/// proved the input was its own, and then refused it as a multisig cosigner mismatch.
pub fn p2pkh_psbt() -> Psbt {
    let pk = key_at(P2PKH_PATH).public_key();
    let mut psbt = legacy_skeleton(&legacy_script(P2PKH_PATH));
    psbt.inputs[0]
        .bip32_derivation
        .insert(pk.0, (fingerprint(), path(P2PKH_PATH)));
    psbt
}

pub fn p2wpkh_psbt() -> Psbt {
    let key = key_at(P2WPKH_PATH);
    let pk = key.public_key();
    let spk = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
    let mut psbt = segwit_v0_skeleton(&spk);
    psbt.inputs[0]
        .bip32_derivation
        .insert(pk.0, (fingerprint(), path(P2WPKH_PATH)));
    psbt
}

pub fn p2sh_p2wpkh_psbt() -> Psbt {
    let key = key_at(P2SH_P2WPKH_PATH);
    let pk = key.public_key();
    let redeem = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
    let spk = ScriptBuf::new_p2sh(&redeem.script_hash());
    let mut psbt = segwit_v0_skeleton(&spk);
    psbt.inputs[0].redeem_script = Some(redeem);
    psbt.inputs[0]
        .bip32_derivation
        .insert(pk.0, (fingerprint(), path(P2SH_P2WPKH_PATH)));
    psbt
}

/// Taproot, carrying only `witness_utxo`: BIP-341 commits to every prevout, so the full
/// previous transaction is not required and this is what coordinators send.
pub fn p2tr_psbt() -> Psbt {
    let key = key_at(P2TR_PATH);
    let internal = key.internal_key();
    let spk = ScriptBuf::new_p2tr_tweaked(key.output_key(None));
    let (_, mut psbt) = skeleton(&spk);
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(PREVOUT_SAT),
        script_pubkey: spk,
    });
    psbt.inputs[0].tap_internal_key = Some(internal);
    psbt.inputs[0]
        .tap_key_origins
        .insert(internal, (vec![], (fingerprint(), path(P2TR_PATH))));
    psbt
}

// ---------------------------------------------------------------------------------------
// One-field mutations
// ---------------------------------------------------------------------------------------

/// The same outpoint twice: two signatures over one UTXO if nothing stops it.
pub fn duplicate_input_psbt() -> Psbt {
    let base = p2wpkh_psbt();
    let mut tx = base.unsigned_tx.clone();
    tx.input.push(tx.input[0].clone());
    let mut psbt = Psbt::from_unsigned_tx(tx).expect("fixture psbt");
    psbt.inputs[0] = base.inputs[0].clone();
    psbt.inputs[1] = base.inputs[0].clone();
    psbt
}

/// A P2WPKH input of ours whose origin claims `p`. The script is built from the key that
/// path actually derives, so the only thing wrong with the file is the shape of the path.
pub fn psbt_with_input_path(p: &str) -> Psbt {
    let derivation = path(p);
    let key = derive_path(&SEED, NETWORK, &derivation).expect("fixture derivation");
    let pk = key.public_key();
    let spk = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
    let mut psbt = segwit_v0_skeleton(&spk);
    psbt.inputs[0]
        .bip32_derivation
        .insert(pk.0, (fingerprint(), derivation));
    psbt
}

/// The origin names one of our keys and the script commits to another. Both are ours, so
/// this is not a forged fingerprint; it is a coordinator pointing at the wrong key, which
/// is what a derive-and-compare exists to catch.
pub fn psbt_claiming_the_wrong_key() -> Psbt {
    let mut psbt = p2wpkh_psbt();
    let other = key_at("m/84'/0'/0'/0/1").public_key();
    psbt.inputs[0].bip32_derivation.clear();
    psbt.inputs[0]
        .bip32_derivation
        .insert(other.0, (fingerprint(), path(P2WPKH_PATH)));
    psbt
}

pub fn psbt_with_two_of_our_claims() -> Psbt {
    let mut psbt = p2wpkh_psbt();
    let other = key_at("m/84'/0'/0'/0/1").public_key();
    psbt.inputs[0]
        .bip32_derivation
        .insert(other.0, (fingerprint(), path("m/84'/0'/0'/0/1")));
    psbt
}

/// THE PIN UNDER THE LEGACY AMOUNT RULE: [`p2pkh_psbt`] with its proof pulled and a bare
/// `witness_utxo` in its place, on a transaction with exactly ONE input.
///
/// One input is the shape 0.2.1 bought an escape for, and the escape must not reach here.
/// The reason it is safe for segwit v0 is that a BIP-143 signature binds its own input's
/// amount, so a one-input transaction has no amount anywhere left to lie about. A legacy
/// digest does not bind even that: it hashes the scriptCode and the outputs and never the
/// value, so it is STRICTLY WEAKER than the case the exemption was reasoned about. A reader
/// who extends the exemption to legacy by analogy reopens a fee attack on the commonest
/// input shape there is, and this file is what stops him.
pub fn p2pkh_psbt_without_its_prev_tx() -> Psbt {
    let mut psbt = p2pkh_psbt();
    psbt.inputs[0].non_witness_utxo = None;
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(PREVOUT_SAT),
        script_pubkey: legacy_script(P2PKH_PATH),
    });
    psbt
}

/// Two legacy inputs of ours and one previous transaction between them: the same rule at
/// the other end of the carve-out, where the input count alone refuses the file before any
/// reasoning about signatures happens.
pub fn two_p2pkh_inputs_one_amount_claimed_psbt() -> Psbt {
    const SECOND: &str = "m/44'/0'/0'/0/1";
    let spk_a = legacy_script(P2PKH_PATH);
    let spk_b = legacy_script(SECOND);
    let prev_a = funding_of(&spk_a, 3, PREVOUT_SAT);
    let prev_b = funding_of(&spk_b, 4, PREVOUT_SAT);
    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            spending(prev_a.compute_txid()),
            spending(prev_b.compute_txid()),
        ],
        output: vec![TxOut {
            value: Amount::from_sat(2 * PREVOUT_SAT - FEE_SAT),
            script_pubkey: external_script(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("fixture psbt");
    psbt.inputs[0].non_witness_utxo = Some(prev_a);
    psbt.inputs[0]
        .bip32_derivation
        .insert(key_at(P2PKH_PATH).public_key().0, (fingerprint(), path(P2PKH_PATH)));
    // The second input states its worth and proves nothing.
    psbt.inputs[1].witness_utxo = Some(TxOut {
        value: Amount::from_sat(PREVOUT_SAT),
        script_pubkey: spk_b,
    });
    psbt.inputs[1]
        .bip32_derivation
        .insert(key_at(SECOND).public_key().0, (fingerprint(), path(SECOND)));
    psbt
}

/// The origin names one of our keys and the legacy script commits to another. Both are
/// ours, so nothing here is a forged fingerprint; it is a coordinator pointing at the wrong
/// leaf, and `76a914{hash160(pubkey)}88ac` is the only thing that can tell.
pub fn p2pkh_psbt_claiming_the_wrong_key() -> Psbt {
    let mut psbt = p2pkh_psbt();
    let other = key_at("m/44'/0'/0'/0/1").public_key();
    psbt.inputs[0].bip32_derivation.clear();
    psbt.inputs[0]
        .bip32_derivation
        .insert(other.0, (fingerprint(), path(P2PKH_PATH)));
    psbt
}

/// [`p2pkh_psbt`] with the sighash type it would be signed under written out explicitly.
///
/// A coordinator may state `PSBT_IN_SIGHASH_TYPE` or leave it absent, and the two say the
/// same thing about a legacy input: absent means SIGHASH_ALL. This file exists because this
/// device does not yet agree that they say the same thing - see the test that reads it.
pub fn p2pkh_psbt_declaring_sighash_all() -> Psbt {
    let mut psbt = p2pkh_psbt();
    psbt.inputs[0].sighash_type =
        Some(bitcoin::psbt::PsbtSighashType::from(bitcoin::EcdsaSighashType::All));
    psbt
}

/// A segwit input of OURS beside a legacy input belonging to somebody else, both amounts
/// proven.
///
/// The shape every multi-party round arrives in, with the other party on a script family
/// this device happens to sign. A foreign input's script kind has never been this device's
/// business, because such an input is shown and never signed, and refusing the transaction
/// over one would burn a round for everyone in it. Admitting P2PKH must not change that in
/// either direction.
pub fn ours_and_a_foreign_legacy_input_psbt() -> Psbt {
    let ours = key_at(P2WPKH_PATH).public_key();
    let spk_a = ScriptBuf::new_p2wpkh(&ours.wpubkey_hash());
    // A legacy coin of an account this device does not derive, carrying no origin at all.
    let spk_b = legacy_script("m/44'/0'/9'/0/0");
    let prev_a = funding_of(&spk_a, 5, PREVOUT_SAT);
    let prev_b = funding_of(&spk_b, 6, PREVOUT_SAT);
    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            spending(prev_a.compute_txid()),
            spending(prev_b.compute_txid()),
        ],
        output: vec![TxOut {
            value: Amount::from_sat(2 * PREVOUT_SAT - FEE_SAT),
            script_pubkey: external_script(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("fixture psbt");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(PREVOUT_SAT),
        script_pubkey: spk_a,
    });
    psbt.inputs[0].non_witness_utxo = Some(prev_a);
    psbt.inputs[0]
        .bip32_derivation
        .insert(ours.0, (fingerprint(), path(P2WPKH_PATH)));
    psbt.inputs[1].non_witness_utxo = Some(prev_b);
    psbt
}

/// A genuine BIP-49 coin OF OURS whose `redeem_script` the coordinator left out.
///
/// Distinct from [`p2sh_psbt_claiming_our_key`], which supplies a redeem script of the wrong
/// shape: this is the file defect a sender can actually fix, and it is the one that reaches
/// the refusal from the direction a real coordinator produces. Without the field nothing can
/// tell this apart from a P2SH of any other shape - guessing is what ARCH check 3 forbids -
/// so it classifies as [`super::ScriptKind::P2sh`] and stays refused after legacy signing
/// lands. It is the shape R-26 is written for.
pub fn p2sh_psbt_with_no_redeem_script() -> Psbt {
    let pk = key_at(P2SH_P2WPKH_PATH).public_key();
    let redeem = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
    let spk = ScriptBuf::new_p2sh(&redeem.script_hash());
    let mut psbt = segwit_v0_skeleton(&spk);
    psbt.inputs[0]
        .bip32_derivation
        .insert(pk.0, (fingerprint(), path(P2SH_P2WPKH_PATH)));
    psbt
}

/// A P2WSH input whose map names our key and whose script no registration builds.
pub fn p2wsh_psbt_claiming_our_key() -> Psbt {
    let key = key_at(P2WPKH_PATH);
    let pk = key.public_key();
    let witness_script = ScriptBuf::from_bytes(vec![0x51, 0x21]);
    let spk = ScriptBuf::new_p2wsh(&WScriptHash::hash(witness_script.as_bytes()));
    let mut psbt = segwit_v0_skeleton(&spk);
    psbt.inputs[0].witness_script = Some(witness_script);
    psbt.inputs[0]
        .bip32_derivation
        .insert(pk.0, (fingerprint(), path(P2WPKH_PATH)));
    psbt
}

// ---------------------------------------------------------------------------------------
// Multisig (0.2.0-m7)
// ---------------------------------------------------------------------------------------

/// The BIP-48 P2WSH origin every fixture cosigner sits on.
pub const BIP48_ORIGIN: &str = "m/48\'/0\'/0\'/2\'";

/// Two cosigners that are not us, derived from fixed seeds so the wallet is reproducible.
/// Their seeds never enter a fixture PSBT: only their xpubs do, exactly as a real import
/// would carry them.
const COSIGNER_SEEDS: [[u8; 64]; 2] = [[0x11; 64], [0x22; 64]];

fn cosigner_key_expression(seed: &[u8; 64]) -> alloc::string::String {
    let fingerprint = crate::derive::master_fingerprint(seed, NETWORK);
    let xpub = account_xpub(seed);
    alloc::format!("[{fingerprint}/48h/0h/0h/2h]{xpub}/<0;1>/*")
}

/// A cosigner's BIP-48 account xpub. Goes through the public signing API rather than a
/// private helper so the fixture cannot drift from what the crate actually derives.
fn account_xpub(seed: &[u8; 64]) -> bitcoin::bip32::Xpub {
    let secp = crate::derive::secp();
    let master =
        bitcoin::bip32::Xpriv::new_master(NETWORK, seed).expect("fixture seed is a valid master");
    let account = master
        .derive_priv(secp, &path(BIP48_ORIGIN))
        .expect("fixture BIP-48 origin derives");
    bitcoin::bip32::Xpub::from_priv(secp, &account)
}

/// The 2-of-3 P2WSH sortedmulti wallet the m7 fixtures spend from, as a descriptor.
///
/// Written WITHOUT a checksum on purpose: the canonical checksummed form is what
/// `Pending::verify` produces, and a fixture that hand-wrote one would be pinning this
/// module's arithmetic against itself.
pub fn wallet_descriptor() -> alloc::string::String {
    alloc::format!(
        "wsh(sortedmulti(2,{},{},{}))",
        cosigner_key_expression(&SEED),
        cosigner_key_expression(&COSIGNER_SEEDS[0]),
        cosigner_key_expression(&COSIGNER_SEEDS[1])
    )
}

/// The same wallet, registered: parsed, and proven ours by derivation from [`SEED`].
pub fn registration() -> Registration {
    crate::multisig::parse(&wallet_descriptor())
        .expect("fixture descriptor parses")
        .verify(&SEED, NETWORK)
        .expect("fixture wallet has this seed as a member")
}

/// The derivation path of one leaf of the fixture wallet, in the spelling a PSBT uses.
pub fn multisig_leaf_path(keychain: Keychain, index: u32) -> DerivationPath {
    let chain = match keychain {
        Keychain::Receive => 0,
        Keychain::Change => 1,
    };
    path(&alloc::format!("{BIP48_ORIGIN}/{chain}/{index}"))
}

/// A PSBT spending one leaf of the registered 2-of-3, paying an external address.
///
/// This is the shape a coordinator hands a cosigner: full previous transaction, the witness
/// script, and one `bip32_derivation` entry per cosigner. Only ours names our fingerprint.
pub fn multisig_psbt() -> Psbt {
    multisig_psbt_at(Keychain::Receive, 0)
}

pub fn multisig_psbt_at(keychain: Keychain, index: u32) -> Psbt {
    let registration = registration();
    let witness_script = registration
        .witness_script(keychain, index)
        .expect("fixture leaf derives");
    let spk = registration
        .script_pubkey(keychain, index)
        .expect("fixture leaf derives");
    let mut psbt = segwit_v0_skeleton(&spk);
    psbt.inputs[0].witness_script = Some(witness_script);

    let chain = match keychain {
        Keychain::Receive => 0u32,
        Keychain::Change => 1u32,
    };
    for cosigner in registration.cosigners() {
        let child = cosigner
            .xpub
            .derive_pub(
                crate::derive::secp(),
                &[
                    bitcoin::bip32::ChildNumber::from_normal_idx(chain).expect("chain index"),
                    bitcoin::bip32::ChildNumber::from_normal_idx(index).expect("leaf index"),
                ],
            )
            .expect("cosigner leaf derives");
        psbt.inputs[0].bip32_derivation.insert(
            child.public_key,
            (
                cosigner.fingerprint,
                multisig_leaf_path(keychain, index),
            ),
        );
    }
    psbt
}

/// The same spend with a second output that the registered wallet really does build on its
/// change keychain, labelled as such. The honest case the attack below is a mutation of.
pub fn multisig_psbt_with_real_change() -> Psbt {
    let registration = registration();
    let spk = registration
        .script_pubkey(Keychain::Change, 4)
        .expect("fixture change leaf derives");
    attach_claim(multisig_psbt(), spk, Keychain::Change, 4)
}

/// A second output on the wallet's own RECEIVE keychain: ours, provable, and not this
/// transaction's change.
pub fn multisig_psbt_with_receive_claim() -> Psbt {
    let registration = registration();
    let spk = registration
        .script_pubkey(Keychain::Receive, 4)
        .expect("fixture receive leaf derives");
    attach_claim(multisig_psbt(), spk, Keychain::Receive, 4)
}

/// The 2019 change-confusion attack: an output paying a script the wallet does NOT build,
/// carrying a `bip32_derivation` that claims our fingerprint on the change keychain.
///
/// Every field a heuristic would look at says change - our fingerprint, an internal path, a
/// P2WSH script of the right shape, an index well inside any gap bound - and the one thing
/// that decides says otherwise: the registered wallet does not build that script at that
/// leaf.
pub fn multisig_psbt_with_forged_change() -> Psbt {
    let attacker = ScriptBuf::new_p2wsh(&WScriptHash::hash(b"an address the attacker owns"));
    attach_claim(multisig_psbt(), attacker, Keychain::Change, 4)
}

/// A P2SH input claiming our key whose redeem script is not a P2WPKH program: the script
/// type m7 leaves exactly where m6 left it (OPEN-QUESTIONS Q7).
pub fn p2sh_psbt_claiming_our_key() -> Psbt {
    let key = key_at(P2WPKH_PATH);
    let pk = key.public_key();
    let redeem = ScriptBuf::from_bytes(vec![0x51]);
    let spk = ScriptBuf::new_p2sh(&redeem.script_hash());
    let mut psbt = segwit_v0_skeleton(&spk);
    psbt.inputs[0].redeem_script = Some(redeem);
    psbt.inputs[0]
        .bip32_derivation
        .insert(pk.0, (fingerprint(), path(P2WPKH_PATH)));
    psbt
}

fn attach_claim(mut psbt: Psbt, spk: ScriptBuf, keychain: Keychain, index: u32) -> Psbt {
    let registration = registration();
    let chain = match keychain {
        Keychain::Receive => 0u32,
        Keychain::Change => 1u32,
    };
    let mut tx = psbt.unsigned_tx.clone();
    // Split the existing output rather than adding value, so the fee stays what the other
    // fixtures declare and the difference between the two change cases is the script alone.
    let split = tx.output[0].value / 2;
    tx.output[0].value -= split;
    tx.output.push(TxOut {
        value: split,
        script_pubkey: spk,
    });
    let inputs = psbt.inputs.clone();
    let first_output = psbt.outputs[0].clone();
    psbt = Psbt::from_unsigned_tx(tx).expect("fixture psbt");
    psbt.inputs = inputs;
    psbt.outputs[0] = first_output;

    let ours = registration.ours();
    let key = registration
        .our_key_at(keychain, index)
        .expect("claimed leaf derives");
    psbt.outputs[1].bip32_derivation.insert(
        key.0,
        (
            ours.fingerprint,
            path(&alloc::format!("{BIP48_ORIGIN}/{chain}/{index}")),
        ),
    );
    psbt
}

/// Our taproot key, claimed as the signer of a script leaf rather than of the key path.
pub fn p2tr_psbt_with_a_leaf_claim() -> Psbt {
    let mut psbt = p2tr_psbt();
    let internal = key_at(P2TR_PATH).internal_key();
    let leaf = bitcoin::taproot::TapLeafHash::from_byte_array([7u8; 32]);
    psbt.inputs[0]
        .tap_key_origins
        .insert(internal, (vec![leaf], (fingerprint(), path(P2TR_PATH))));
    psbt
}

/// A finalized witness whose last element is an annex (BIP-341 reserves a leading 0x50).
pub fn psbt_with_an_annex() -> Psbt {
    let mut psbt = p2wpkh_psbt();
    let mut witness = Witness::new();
    witness.push([1u8; 64]);
    witness.push([0x50u8, 0xaa, 0xbb]);
    psbt.inputs[0].final_script_witness = Some(witness);
    psbt
}

/// Two inputs of ours in one transaction, spending different prevouts, so the signing loop
/// is exercised over more than one input and the sighash cache over more than one digest.
pub fn two_input_psbt() -> Psbt {
    let first = key_at("m/84'/0'/0'/0/0").public_key();
    let second = key_at("m/84'/0'/0'/0/1").public_key();
    let spk_a = ScriptBuf::new_p2wpkh(&first.wpubkey_hash());
    let spk_b = ScriptBuf::new_p2wpkh(&second.wpubkey_hash());

    let prev_a = funding_of(&spk_a, 1, PREVOUT_SAT);
    let prev_b = funding_of(&spk_b, 2, PREVOUT_SAT);
    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: alloc::vec![
            spending(prev_a.compute_txid()),
            spending(prev_b.compute_txid()),
        ],
        output: vec![TxOut {
            value: Amount::from_sat(2 * PREVOUT_SAT - FEE_SAT),
            script_pubkey: external_script(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("fixture psbt");
    for (i, (spk, pk, p)) in [
        (spk_a, first, "m/84'/0'/0'/0/0"),
        (spk_b, second, "m/84'/0'/0'/0/1"),
    ]
    .into_iter()
    .enumerate()
    {
        psbt.inputs[i].witness_utxo = Some(TxOut {
            value: Amount::from_sat(PREVOUT_SAT),
            script_pubkey: spk,
        });
        psbt.inputs[i].bip32_derivation.insert(pk.0, (fingerprint(), path(p)));
    }
    psbt.inputs[0].non_witness_utxo = Some(prev_a);
    psbt.inputs[1].non_witness_utxo = Some(prev_b);
    psbt
}

/// The two-input spend with the second input's ownership claim taken away: input 0 is
/// ours, input 1 is a cosigner's. Every multi-party flow arrives in this shape, and it is
/// the base every "somebody else did that to their own input" case below mutates.
pub fn ours_and_a_foreign_input_psbt() -> Psbt {
    let mut psbt = two_input_psbt();
    psbt.inputs[1].bip32_derivation.clear();
    psbt
}

/// The same, with the cosigner's own input finalized: what Bitcoin Core hands back from
/// `walletprocesspsbt`, which finalizes every input it can before it returns.
pub fn foreign_input_finalized_psbt() -> Psbt {
    let mut psbt = ours_and_a_foreign_input_psbt();
    psbt.inputs[1].final_script_witness = Some(Witness::from_slice(&[
        [0x30u8; 71].as_slice(),
        [0x02u8; 33].as_slice(),
    ]));
    psbt
}

/// The same, with the cosigner's input carrying only `witness_utxo`: an amount stated
/// without the previous transaction that would prove it, beside a segwit-v0 input of ours.
///
/// The minimal shape of [`amount_substitution_round`], and the file this crate accepted for
/// part of 2026-08-18 on the argument that the amount was one it never signed over. It is
/// not: with the origin on the other input deleted the same way, "never signs over" is a
/// property of the round rather than of the coin, and two rounds combine.
pub fn foreign_input_without_its_prev_tx_psbt() -> Psbt {
    let mut psbt = ours_and_a_foreign_input_psbt();
    psbt.inputs[1].non_witness_utxo = None;
    psbt
}

/// A funding transaction distinguished by `nonce`, so two of them have different txids.
///
/// `value` is a parameter rather than [`PREVOUT_SAT`] because the amount-substitution
/// probe needs coins large enough for the loss it demonstrates to be the point.
fn funding_of(spk: &ScriptBuf, nonce: u32, value: u64) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::from_consensus(nonce),
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: spk.clone(),
        }],
    }
}

fn spending(txid: bitcoin::Txid) -> TxIn {
    TxIn {
        previous_output: OutPoint { txid, vout: 0 },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    }
}

// ---------------------------------------------------------------------------------------
// The amount-substitution probe
// ---------------------------------------------------------------------------------------

/// What each of the two probe coins is really worth: 1 BTC.
pub const PROBE_COIN_SAT: u64 = 100_000_000;
/// What the round that does NOT prove a coin claims it is worth instead.
pub const PROBE_CLAIMED_SAT: u64 = 20_000;
/// The single payment both rounds make: 1.0001 BTC.
///
/// Chosen so that each round's own arithmetic - one proven coin plus one claimed 20000 -
/// lands on exactly [`FEE_SAT`], the ordinary fee every other fixture here declares. That
/// is the whole point of the probe: the number the screen shows is the number a user
/// expects to see.
pub const PROBE_PAYMENT_SAT: u64 = PROBE_COIN_SAT + PROBE_CLAIMED_SAT - FEE_SAT;

/// One round of the probe that BIP-174's line 415 footnote exists to stop.
///
/// Both inputs are ours. `proven` is the one this round presents honestly - full previous
/// transaction, witness utxo, and the `bip32_derivation` that makes it ours - and the
/// other is the same coin of ours stripped of its origin, so that the file presents it as
/// a stranger's, and restated as [`PROBE_CLAIMED_SAT`] through `witness_utxo` alone.
///
/// Ownership here is decided by metadata a coordinator writes, so deleting an origin costs
/// the coordinator nothing and turns the amount behind it into a free lie. Run for
/// `proven = 0` and `proven = 1` against the SAME unsigned transaction, the two rounds
/// each harvest one BIP-143 signature made over that input's real 1 BTC, and combine into
/// a transaction that pays [`PROBE_PAYMENT_SAT`] out of 2 BTC. Every number either screen
/// could show says the fee is [`FEE_SAT`].
pub fn amount_substitution_round(proven: usize) -> Psbt {
    assert!(proven < 2, "the probe has two inputs");
    let keys = ["m/84'/0'/0'/0/0", "m/84'/0'/0'/0/1"];
    let spks: Vec<ScriptBuf> = keys
        .iter()
        .map(|p| ScriptBuf::new_p2wpkh(&key_at(p).public_key().wpubkey_hash()))
        .collect();
    let prevs: Vec<Transaction> = spks
        .iter()
        .enumerate()
        .map(|(i, spk)| funding_of(spk, i as u32 + 1, PROBE_COIN_SAT))
        .collect();

    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: prevs.iter().map(|p| spending(p.compute_txid())).collect(),
        output: vec![TxOut {
            value: Amount::from_sat(PROBE_PAYMENT_SAT),
            script_pubkey: external_script(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("fixture psbt");

    for i in 0..2 {
        if i == proven {
            psbt.inputs[i].witness_utxo = Some(TxOut {
                value: Amount::from_sat(PROBE_COIN_SAT),
                script_pubkey: spks[i].clone(),
            });
            psbt.inputs[i].non_witness_utxo = Some(prevs[i].clone());
            psbt.inputs[i].bip32_derivation.insert(
                key_at(keys[i]).public_key().0,
                (fingerprint(), path(keys[i])),
            );
        } else {
            // No origin and no previous transaction: a coin of ours, presented as somebody
            // else's, at whatever the coordinator felt like writing.
            psbt.inputs[i].witness_utxo = Some(TxOut {
                value: Amount::from_sat(PROBE_CLAIMED_SAT),
                script_pubkey: spks[i].clone(),
            });
        }
    }
    psbt
}

/// The probe with the unproven input taproot instead of segwit v0, and OURS.
///
/// The rule this fixture holds the line on is about the digest, not about who owns what:
/// a BIP-341 key-path signature of ours hashes `sha_amounts` over every input, so the
/// claimed amount beside it is bound by the signature this device is about to make and
/// substituting it produces a transaction that cannot confirm. Input 0 is a taproot coin
/// of ours carrying only `witness_utxo`, input 1 is a cosigner's, also unproven.
pub fn taproot_spend_beside_an_unproven_input_psbt() -> Psbt {
    let ours = key_at(P2TR_PATH);
    let spk_a = ScriptBuf::new_p2tr_tweaked(ours.output_key(None));
    let spk_b = ScriptBuf::new_p2wpkh(&key_at("m/84'/0'/0'/0/1").public_key().wpubkey_hash());
    let prev_a = funding_of(&spk_a, 1, PREVOUT_SAT);
    let prev_b = funding_of(&spk_b, 2, PREVOUT_SAT);

    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: alloc::vec![
            spending(prev_a.compute_txid()),
            spending(prev_b.compute_txid()),
        ],
        output: vec![TxOut {
            value: Amount::from_sat(2 * PREVOUT_SAT - FEE_SAT),
            script_pubkey: external_script(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("fixture psbt");
    for (i, spk) in [spk_a.clone(), spk_b].into_iter().enumerate() {
        psbt.inputs[i].witness_utxo = Some(TxOut {
            value: Amount::from_sat(PREVOUT_SAT),
            script_pubkey: spk,
        });
    }
    let internal = ours.internal_key();
    psbt.inputs[0].tap_internal_key = Some(internal);
    psbt.inputs[0]
        .tap_key_origins
        .insert(internal, (vec![], (fingerprint(), path(P2TR_PATH))));
    psbt
}

/// Two inputs, neither of them ours, one of them stating an amount nothing proves: the
/// review-only file, which this device signs nothing in and must still be able to read.
pub fn no_input_of_ours_one_unproven_psbt() -> Psbt {
    let mut psbt = amount_substitution_round(0);
    psbt.inputs[0].bip32_derivation.clear();
    psbt
}

// ---------------------------------------------------------------------------------------
// Batch signing (0.2.0-G10)
// ---------------------------------------------------------------------------------------

/// The key the batch fixtures spend their non-ours input from. A key of ours from a
/// distant account, carried into the file WITHOUT its origin, so the file presents it as a
/// stranger's coin - the same device a coordinator uses to hand over somebody else's input.
const BATCH_STRANGER_PATH: &str = "m/84'/0'/8'/0/0";

/// `ours` P2WPKH inputs of this device's own in one transaction, each spending its own
/// funding transaction, paying one external output.
///
/// The shape a coordinator hands over for a consolidation, and the reason batch signing is
/// a feature rather than a loop: one approval buys `ours` signatures, so every property the
/// single-input fixtures pin has to survive being asked `ours` times at once.
pub fn batch_psbt(ours: u32) -> Psbt {
    batch_of(ours, false)
}

/// The same batch with one further input that is not ours and states its amount through
/// `witness_utxo` alone.
///
/// The poisoned batch: every input of ours is proven, the file is otherwise ordinary, and
/// the one amount nothing proves sits beside `ours` BIP-143 signatures that each cover
/// their own input's amount and no other. Burying it among many good inputs is the only
/// thing this fixture adds to [`foreign_input_without_its_prev_tx_psbt`], and it is the
/// thing a batch could plausibly have been used to hide.
pub fn batch_psbt_with_an_unproven_input(ours: u32) -> Psbt {
    batch_of(ours, true)
}

fn batch_of(ours: u32, unproven_tail: bool) -> Psbt {
    assert!(ours >= 1, "a batch signs at least one input");
    let paths: Vec<alloc::string::String> = (0..ours)
        .map(|i| alloc::format!("m/84'/0'/0'/0/{i}"))
        .collect();
    let spks: Vec<ScriptBuf> = paths
        .iter()
        .map(|p| ScriptBuf::new_p2wpkh(&key_at(p).public_key().wpubkey_hash()))
        .collect();
    // Distinct nonces, so no two inputs of the batch spend the same outpoint and the
    // duplicate-input refusal is not what a batch test ends up measuring.
    let prevs: Vec<Transaction> = spks
        .iter()
        .enumerate()
        .map(|(i, spk)| funding_of(spk, i as u32 + 1, PREVOUT_SAT))
        .collect();
    let stranger_spk =
        ScriptBuf::new_p2wpkh(&key_at(BATCH_STRANGER_PATH).public_key().wpubkey_hash());
    let stranger_prev = funding_of(&stranger_spk, ours + 1, PREVOUT_SAT);

    let mut input: Vec<TxIn> = prevs.iter().map(|p| spending(p.compute_txid())).collect();
    if unproven_tail {
        input.push(spending(stranger_prev.compute_txid()));
    }
    // Every input is worth the same, so the fee is [`FEE_SAT`] whatever `ours` is: a batch
    // test that changed the fee as it grew would be measuring two things at once.
    let funded = input.len() as u64 * PREVOUT_SAT;
    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input,
        output: vec![TxOut {
            value: Amount::from_sat(funded - FEE_SAT),
            script_pubkey: external_script(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("fixture psbt");

    for i in 0..ours as usize {
        psbt.inputs[i].witness_utxo = Some(TxOut {
            value: Amount::from_sat(PREVOUT_SAT),
            script_pubkey: spks[i].clone(),
        });
        psbt.inputs[i].non_witness_utxo = Some(prevs[i].clone());
        psbt.inputs[i].bip32_derivation.insert(
            key_at(&paths[i]).public_key().0,
            (fingerprint(), path(&paths[i])),
        );
    }
    if unproven_tail {
        // No origin and no previous transaction: not ours, and worth whatever the file says.
        psbt.inputs[ours as usize].witness_utxo = Some(TxOut {
            value: Amount::from_sat(PREVOUT_SAT),
            script_pubkey: stranger_spk,
        });
    }
    psbt
}

// ---------------------------------------------------------------------------------------
// BlueWallet watch-only import (0.2.0, 2026-08-21)
// ---------------------------------------------------------------------------------------
//
// The corpus behind the field report: a BlueWallet watch-only wallet built from a bare
// zpub this device exported, signing an ordinary spend and handing the PSBT back for this
// device to co-sign. BlueWallet's construction is one specific, narrow shape, and BIP-174
// forbids none of it:
//
//   - PSBT_IN_WITNESS_UTXO only, never PSBT_IN_NON_WITNESS_UTXO, for a segwit v0 input.
//     BlueWallet reads BIP-143 the way most coordinators this device has been reported
//     against do: the witness already signs the amount, so the amount needs no second
//     proof. `checks.rs` disagrees - see [`CheckFailure::MissingPreviousTransaction`] - and
//     that disagreement is the whole of the bug this corpus reproduces.
//   - PSBT_IN_BIP32_DERIVATION with the FULL five-component path (m/84'/0'/0'/{0,1}/i) and
//     a master fingerprint of all zero bytes: BlueWallet's literal default when a
//     watch-only import carries no fingerprint of its own, written rather than omitted.
//   - PSBT version 0, no PSBT_IN_SIGHASH_TYPE field, and the file delivered to the SD card
//     as base64 TEXT under a `.psbt` extension - never the binary BIP-174 grammar.
//
// Every fixture below is [`bluewallet_watch_only_psbt`] with exactly one thing changed, for
// the reason this module's own doc gives at the top of the file: a hostile file built from
// scratch proves only that some file is refused, and a one-field mutation of a file that
// otherwise matches BlueWallet's real construction proves which fact about it decided the
// verdict.

/// Where fixture A's change lands: BIP-84's change keychain, leaf 0.
pub const P2WPKH_CHANGE_PATH: &str = "m/84'/0'/0'/1/0";

/// What fixture A's single coin pays out: a payment leaving the wallet and change coming
/// back to it, summing with [`BW_FEE_SAT`] to [`PREVOUT_SAT`] exactly as every other
/// fixture's fee arithmetic does.
pub const BW_PAYMENT_SAT: u64 = 60_000;
pub const BW_CHANGE_SAT: u64 = 30_000;
pub const BW_FEE_SAT: u64 = PREVOUT_SAT - BW_PAYMENT_SAT - BW_CHANGE_SAT;

/// Every single-sig account this device holds, exactly as `firmware/src/signing.rs` puts
/// them in scope before calling [`super::inspect_with_accounts`].
///
/// The corpus is read against THIS wherever the question is what the device actually does,
/// because ownership is now decided by deriving from an account rather than by reading a
/// fingerprint out of the file ([`super::checks::Claim`]), and a test that puts one
/// hand-picked account in scope is testing a configuration no session has.
pub fn device_accounts() -> Vec<crate::derive::Account> {
    crate::derive::device_accounts(&SEED, NETWORK)
}

/// The wallet's one BIP-84 account, exactly as a session that had imported this device's
/// xpub would hold it. Its OWN xpub fingerprint - not the master's - is what Electrum
/// writes into `bip32_derivation` when it has only an account xpub in hand; see
/// [`bluewallet_electrum_relative_path_psbt`].
pub fn account_bip84() -> crate::derive::Account {
    crate::derive::Account::derive(
        &SEED,
        NETWORK,
        crate::derive::Scheme::Bip84,
        crate::derive::ChildIndex::ZERO,
    )
    .expect("bip84 is a single-sig scheme")
}

/// Fixture A: one P2WPKH input of ours, `witness_utxo` only, claimed at fingerprint
/// 00000000 with the full path - exactly what BlueWallet writes for a watch-only wallet it
/// holds no master fingerprint for - paying one external output and one change output back
/// to [`P2WPKH_CHANGE_PATH`], the change output's claim carrying the same zero
/// fingerprint.
pub fn bluewallet_watch_only_psbt() -> Psbt {
    bluewallet_psbt_with_fingerprint(Fingerprint::default())
}

/// Fixture B: fixture A with the wallet's real master fingerprint in both
/// `bip32_derivation` claims instead of BlueWallet's zero default.
///
/// The one-field difference from fixture A isolates what the zero fingerprint costs on its
/// own: `claim_for_input` already treats 00000000 as an ownership claim
/// (`our_fingerprint`'s own doc says so), so if this fixture fails the same way fixture A
/// does, the fingerprint was never the reason BlueWallet's file was refused.
pub fn bluewallet_watch_only_master_fingerprint_psbt() -> Psbt {
    bluewallet_psbt_with_fingerprint(fingerprint())
}

fn bluewallet_psbt_with_fingerprint(fp: Fingerprint) -> Psbt {
    let key = key_at(P2WPKH_PATH);
    let pk = key.public_key();
    let spk = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
    let prev = funding_of(&spk, 1, PREVOUT_SAT);

    let change_key = key_at(P2WPKH_CHANGE_PATH);
    let change_pk = change_key.public_key();
    let change_spk = ScriptBuf::new_p2wpkh(&change_pk.wpubkey_hash());

    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![spending(prev.compute_txid())],
        output: vec![
            TxOut {
                value: Amount::from_sat(BW_PAYMENT_SAT),
                script_pubkey: external_script(),
            },
            TxOut {
                value: Amount::from_sat(BW_CHANGE_SAT),
                script_pubkey: change_spk,
            },
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("fixture psbt");
    // witness_utxo only: BlueWallet's construction never supplies non_witness_utxo.
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(PREVOUT_SAT),
        script_pubkey: spk,
    });
    psbt.inputs[0]
        .bip32_derivation
        .insert(pk.0, (fp, path(P2WPKH_PATH)));
    psbt.outputs[1]
        .bip32_derivation
        .insert(change_pk.0, (fp, path(P2WPKH_CHANGE_PATH)));
    psbt
}

/// Fixture C: two inputs, both ours, both `witness_utxo` only, both claimed at fingerprint
/// 00000000 - a BlueWallet consolidation rather than a single-coin spend.
///
/// This is the shape [`super::checks::amounts_our_signatures_do_not_cover`] is about: two
/// BIP-143 signatures, each committing to its own input's amount and nothing about the
/// other's, standing beside TWO amounts nothing but the file itself asserts. Loosening
/// [`CheckFailure::MissingPreviousTransaction`] for a single input does not answer this
/// fixture; the pairwise rule still has to.
pub fn bluewallet_two_inputs_psbt() -> Psbt {
    let paths = [P2WPKH_PATH, "m/84'/0'/0'/0/1"];
    let spks: Vec<ScriptBuf> = paths
        .iter()
        .map(|p| ScriptBuf::new_p2wpkh(&key_at(p).public_key().wpubkey_hash()))
        .collect();
    let prevs: Vec<Transaction> = spks
        .iter()
        .enumerate()
        .map(|(i, spk)| funding_of(spk, i as u32 + 1, PREVOUT_SAT))
        .collect();
    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: prevs.iter().map(|p| spending(p.compute_txid())).collect(),
        output: vec![TxOut {
            value: Amount::from_sat(2 * PREVOUT_SAT - BW_FEE_SAT),
            script_pubkey: external_script(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("fixture psbt");
    for (i, (spk, p)) in spks.iter().zip(paths.iter()).enumerate() {
        psbt.inputs[i].witness_utxo = Some(TxOut {
            value: Amount::from_sat(PREVOUT_SAT),
            script_pubkey: spk.clone(),
        });
        psbt.inputs[i]
            .bip32_derivation
            .insert(key_at(p).public_key().0, (Fingerprint::default(), path(p)));
    }
    psbt
}

/// Fixture D: fixture A with input 0's claimed key substituted for a different key of
/// ours, at the SAME path and the SAME zero fingerprint. The `witness_utxo` still commits
/// to the honest key's hash; only the map's account of which key that is has been changed.
///
/// Refused, naming the input ([`CheckFailure::ClaimedKeyNotInScript`]), by the derivation:
/// an account in scope rebuilds the leaf this origin names, finds that the script it locks
/// IS this input's script, and finds a different key stated at it. Our coin, described by a
/// file that is lying about it.
///
/// The weaker comparison catches this fixture too - the claimed key does not hash to the
/// script, so `key_matches_script` refuses whenever the origin is addressed to this device
/// by name. It is weaker because a forgery that states the right key FOR THE WRONG COIN
/// passes it; that file is
/// [`bluewallet_origin_over_a_stranger_input_psbt`] and only the derivation sees it.
pub fn bluewallet_key_substitution_psbt() -> Psbt {
    let mut psbt = bluewallet_watch_only_psbt();
    let wrong = key_at("m/84'/0'/0'/0/1").public_key();
    psbt.inputs[0].bip32_derivation.clear();
    psbt.inputs[0]
        .bip32_derivation
        .insert(wrong.0, (Fingerprint::default(), path(P2WPKH_PATH)));
    psbt
}

/// Fixture D at the wallet's REAL master fingerprint rather than BlueWallet's zero default.
///
/// The one-field difference separates two statements a file can make: fixture D names no
/// device, so with no wallet in scope there is nothing to contradict and the input is simply
/// Foreign; this one names THIS device, so it is a false statement about us whatever is in
/// scope, and it is refused either way - by the derivation where an account can answer, and
/// by `key_matches_script`'s file-against-itself comparison where none can.
pub fn key_substitution_at_our_fingerprint_psbt() -> Psbt {
    let mut psbt = bluewallet_watch_only_psbt();
    let wrong = key_at("m/84'/0'/0'/0/1").public_key();
    psbt.inputs[0].bip32_derivation.clear();
    psbt.inputs[0]
        .bip32_derivation
        .insert(wrong.0, (fingerprint(), path(P2WPKH_PATH)));
    psbt
}

/// Fixture E: fixture A with the change output's script replaced by one an attacker
/// controls, while its `bip32_derivation` still claims our zero fingerprint at our real
/// change path [`P2WPKH_CHANGE_PATH`] - the 2019 change-confusion attack, restated in
/// BlueWallet's shape.
///
/// This output is not change: [`P2WPKH_CHANGE_PATH`] derives a script that is not the one
/// it pays, so [`super::checks::prove_account_output`] has nothing to prove and the role is
/// [`super::checks::OutputRole::ClaimedButUnproven`] - counted as money leaving, and blocked
/// at the hold. The input half of this file is fixture A's and passes on its own merits,
/// which is what makes this fixture a pin on the output-level defence rather than on an
/// input-level refusal standing in front of it.
pub fn bluewallet_forged_change_psbt() -> Psbt {
    let attacker = key_at("m/84'/0'/7'/0/3").public_key();
    let attacker_spk = ScriptBuf::new_p2wpkh(&attacker.wpubkey_hash());

    let mut psbt = bluewallet_watch_only_psbt();
    let mut tx = psbt.unsigned_tx.clone();
    tx.output[1].script_pubkey = attacker_spk;
    let inputs = psbt.inputs.clone();
    let mut outputs = psbt.outputs.clone();
    psbt = Psbt::from_unsigned_tx(tx).expect("fixture psbt");
    psbt.inputs = inputs;
    // The claim still names OUR change path - only the script it is paired with is wrong.
    outputs[1].bip32_derivation.clear();
    outputs[1]
        .bip32_derivation
        .insert(attacker.0, (Fingerprint::default(), path(P2WPKH_CHANGE_PATH)));
    psbt.outputs = outputs;
    psbt
}

/// Fixture F: two inputs, one ours (`witness_utxo` only, claimed at fingerprint 00000000)
/// and one a cosigner's (`witness_utxo` only, no `bip32_derivation` at all) - what a
/// multi-party round looks like carried in BlueWallet's construction.
///
/// BIP-174 is explicit that a foreign input is not an error: this device shows it and signs
/// only its own. Two `witness_utxo`-only inputs are refused by check 2 before ownership can
/// matter, so what this fixture pins is that the refusal names OUR input and not the
/// cosigner's - refusing the whole file over a coin this device was never asked to sign is
/// the failure mode. [`bluewallet_mixed_ownership_proven_psbt`] is the same two coins with
/// the amount question answered, where the ownership rule is what is left.
pub fn bluewallet_mixed_ownership_psbt() -> Psbt {
    let our_key = key_at(P2WPKH_PATH).public_key();
    let our_spk = ScriptBuf::new_p2wpkh(&our_key.wpubkey_hash());
    // A key of ours from a different account, carried in WITHOUT derivation info, which is
    // what a cosigner's coin looks like from here - the same device `external_script` uses.
    let foreign_key = key_at("m/84'/0'/9'/0/1").public_key();
    let foreign_spk = ScriptBuf::new_p2wpkh(&foreign_key.wpubkey_hash());

    let prev_ours = funding_of(&our_spk, 1, PREVOUT_SAT);
    let prev_foreign = funding_of(&foreign_spk, 2, PREVOUT_SAT);
    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            spending(prev_ours.compute_txid()),
            spending(prev_foreign.compute_txid()),
        ],
        output: vec![TxOut {
            value: Amount::from_sat(2 * PREVOUT_SAT - BW_FEE_SAT),
            script_pubkey: external_script(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("fixture psbt");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(PREVOUT_SAT),
        script_pubkey: our_spk,
    });
    psbt.inputs[0]
        .bip32_derivation
        .insert(our_key.0, (Fingerprint::default(), path(P2WPKH_PATH)));
    psbt.inputs[1].witness_utxo = Some(TxOut {
        value: Amount::from_sat(PREVOUT_SAT),
        script_pubkey: foreign_spk,
    });
    psbt
}

/// Fixture F with both amounts proven: the file BIP-174 line 415 is actually about.
///
/// [`bluewallet_mixed_ownership_psbt`] carries the amount question and the ownership
/// question at once, and check 2 answers first, so it can only ever pin which input the
/// refusal names. This is the same two coins with their full previous transactions
/// attached, which takes the amount rule out of the way and leaves the ownership rule
/// alone: input 0's origin derives to input 0's script under an account of ours and is
/// signed, input 1 carries no origin at all and is passed through untouched.
pub fn bluewallet_mixed_ownership_proven_psbt() -> Psbt {
    let our_key = key_at(P2WPKH_PATH).public_key();
    let our_spk = ScriptBuf::new_p2wpkh(&our_key.wpubkey_hash());
    let foreign_key = key_at("m/84'/0'/9'/0/1").public_key();
    let foreign_spk = ScriptBuf::new_p2wpkh(&foreign_key.wpubkey_hash());

    let prev_ours = funding_of(&our_spk, 1, PREVOUT_SAT);
    let prev_foreign = funding_of(&foreign_spk, 2, PREVOUT_SAT);
    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            spending(prev_ours.compute_txid()),
            spending(prev_foreign.compute_txid()),
        ],
        output: vec![TxOut {
            value: Amount::from_sat(2 * PREVOUT_SAT - BW_FEE_SAT),
            script_pubkey: external_script(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("fixture psbt");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(PREVOUT_SAT),
        script_pubkey: our_spk,
    });
    psbt.inputs[0].non_witness_utxo = Some(prev_ours);
    psbt.inputs[0]
        .bip32_derivation
        .insert(our_key.0, (Fingerprint::default(), path(P2WPKH_PATH)));
    psbt.inputs[1].witness_utxo = Some(TxOut {
        value: Amount::from_sat(PREVOUT_SAT),
        script_pubkey: foreign_spk,
    });
    psbt.inputs[1].non_witness_utxo = Some(prev_foreign);
    psbt
}

/// Fixture A's input replaced by a STRANGER's coin - a stranger's key and the script that
/// key really locks - still carrying an origin that names this wallet at one of its own
/// leaves.
///
/// The forgery [`super::checks::key_matches_script`] cannot see, and the reason the
/// derivation had to move to inspect time. The origin and the script agree with each other
/// perfectly, so every comparison that reads only the file passes; what they agree ABOUT is
/// a coin this wallet does not hold, and only re-deriving the leaf they name says so. Before
/// 2026-08-21 this input reached the approval screen inside the batch the user was asked to
/// authorise.
pub fn bluewallet_origin_over_a_stranger_input_psbt() -> Psbt {
    let stranger = key_at("m/84'/0'/9'/0/1").public_key();
    let spk = ScriptBuf::new_p2wpkh(&stranger.wpubkey_hash());
    let prev = funding_of(&spk, 1, PREVOUT_SAT);
    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![spending(prev.compute_txid())],
        output: vec![TxOut {
            value: Amount::from_sat(PREVOUT_SAT - BW_FEE_SAT),
            script_pubkey: external_script(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("fixture psbt");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(PREVOUT_SAT),
        script_pubkey: spk,
    });
    psbt.inputs[0].non_witness_utxo = Some(prev);
    // Our own fingerprint at our own change leaf, over somebody else's coin.
    psbt.inputs[0]
        .bip32_derivation
        .insert(stranger.0, (fingerprint(), path(P2WPKH_CHANGE_PATH)));
    psbt
}

/// One of OUR OWN scripts in a `witness_utxo`, with no origin at all beside it.
///
/// A `witness_utxo` is the file's word about what an input is worth AND about what it is
/// locked to, and neither is a derivation. A signer that read the script out of one and
/// called that ownership would be taking the coordinator's word for which coin it is
/// spending - which is what the 500-address sweep removed on 2026-08-21 did, and what made
/// [`laundered_foreign_input_psbt`] a free amplifier.
pub fn our_script_without_an_origin_psbt() -> Psbt {
    let ours = key_at("m/84'/0'/0'/0/5").public_key();
    let spk = ScriptBuf::new_p2wpkh(&ours.wpubkey_hash());
    let prev = funding_of(&spk, 2, PREVOUT_SAT);
    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![spending(prev.compute_txid())],
        output: vec![TxOut {
            value: Amount::from_sat(PREVOUT_SAT - BW_FEE_SAT),
            script_pubkey: external_script(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("fixture psbt");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(PREVOUT_SAT),
        script_pubkey: spk,
    });
    psbt
}

/// A cosigner's input carrying an origin this device cannot use: the zero fingerprint at a
/// purpose no wallet of ours has, beside an input of ours that is perfectly good.
///
/// The file-wide refusal this pins the absence of was real until 2026-08-21: `path_sanity`
/// ran on any origin the zero fingerprint routed to this device, and its `Err` was
/// propagated with `?`, so four zero bytes and a made-up path on SOMEBODY ELSE'S input
/// refused a file this device had every reason to sign. Anyone in a multi-party round can
/// write both fields.
pub fn foreign_input_at_a_path_we_dislike_psbt() -> Psbt {
    let mut psbt = bluewallet_mixed_ownership_proven_psbt();
    let foreign_key = key_at("m/84'/0'/9'/0/1").public_key();
    psbt.inputs[1].bip32_derivation.insert(
        foreign_key.0,
        // Purpose 1' is outside the whitelist, and the coin type is a test chain: two
        // separate reasons this device would once have burned the file.
        (Fingerprint::default(), path("m/1'/1'/0'/0/0")),
    );
    psbt
}

/// Fixture A with its change output's origin moved to a path this device would never use.
///
/// The output side of the same defect. `classify_output` propagated `path_sanity`'s `Err`
/// too, so one unusable origin on one output refused the whole file - and an output is the
/// one place nothing this device signs is at stake, so the strongest honest answer was
/// always [`super::checks::OutputRole::ClaimedButUnproven`]: the claim was made and not
/// believed, the money counts as leaving, and `ReviewState::blocker` stops the hold.
pub fn change_claim_at_a_path_we_dislike_psbt() -> Psbt {
    let mut psbt = bluewallet_watch_only_psbt();
    let change_pk = key_at(P2WPKH_CHANGE_PATH).public_key();
    psbt.outputs[1].bip32_derivation.clear();
    psbt.outputs[1]
        .bip32_derivation
        .insert(change_pk.0, (Fingerprint::default(), path("m/84'/1'/0'/1/0")));
    psbt
}

/// Fixture G: the Electrum convention rather than BlueWallet's. `bip32_derivation` carries
/// the ACCOUNT xpub's own fingerprint - what [`account_bip84`] exports - and a
/// two-component path RELATIVE to that account (`change/index`) instead of the full
/// five-component path from the master. Electrum writes exactly this when it has only an
/// account xpub in hand and no master fingerprint to prepend.
///
/// Until 2026-08-21 this claim was read as a full path from the master and handed to
/// `path_sanity`, which demands three hardened steps before the first unhardened one - a
/// relative path has none, so the file was refused for its SPELLING of a path while the
/// coin it named was the wallet's own. `OwnWallets::prove` implements Electrum's own
/// branch instead: nothing resolves from the master, so the LAST TWO components are read as
/// `(change, index)` and derived under each account in scope, and the same key-and-script
/// comparison every other route ends in decides it.
///
/// What the fixture pins is that the resolution is a derivation and not a courtesy: with no
/// account in scope nothing can answer and the input is Foreign, and with one in scope the
/// claim is proven and the path that travels to [`super::sign`] is OURS - the five-component
/// path a master key can actually be walked along - rather than the file's two components.
///
/// It carries CHANGE, and until 2026-08-22 it did not. That omission is why nothing caught
/// the hole [`electrum_relative_path_stolen_change_psbt`] demonstrates: an Electrum file's
/// output map is spelled the same way its input map is, and a corpus whose only Electrum
/// file paid one external address never asked check 3 what it made of that spelling.
pub fn bluewallet_electrum_relative_path_psbt() -> Psbt {
    let key = key_at(P2WPKH_PATH);
    let pk = key.public_key();
    let spk = ScriptBuf::new_p2wpkh(&pk.wpubkey_hash());
    let prev = funding_of(&spk, 1, PREVOUT_SAT);

    let change_pk = key_at(P2WPKH_CHANGE_PATH).public_key();
    let change_spk = ScriptBuf::new_p2wpkh(&change_pk.wpubkey_hash());

    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![spending(prev.compute_txid())],
        output: vec![
            TxOut {
                value: Amount::from_sat(BW_PAYMENT_SAT),
                script_pubkey: external_script(),
            },
            TxOut {
                value: Amount::from_sat(BW_CHANGE_SAT),
                script_pubkey: change_spk,
            },
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("fixture psbt");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(PREVOUT_SAT),
        script_pubkey: spk,
    });
    let account_fp = account_bip84().xpub().fingerprint();
    psbt.inputs[0]
        .bip32_derivation
        .insert(pk.0, (account_fp, path("0/0")));
    // The same spelling on the output side, because it is the same wallet writing it: the
    // account xpub's own fingerprint and `change/index` relative to it.
    psbt.outputs[1]
        .bip32_derivation
        .insert(change_pk.0, (account_fp, path("1/0")));
    psbt
}

/// Fixture G with its change output swapped for an address the coordinator controls, and
/// its origin rewritten to match so that the file agrees with itself.
///
/// THE SUBSTITUTION, in the one spelling that had no coverage. Byte for byte this is
/// [`bluewallet_electrum_relative_path_psbt`] with output 1 changed and nothing else: same
/// input, same payment, same amounts, so the fee arithmetic and every total a screen can
/// compute are identical between the two files. The only thing that separates them is
/// whether an account of ours rebuilds the script output 1 pays at the leaf its origin
/// names - which is precisely what check 3 is - and until 2026-08-22 `classify_output`
/// never asked, because an account-xpub fingerprint was not a fingerprint it routed. Both
/// files reviewed and signed identically. That is the whole of the defect.
pub fn electrum_relative_path_stolen_change_psbt() -> Psbt {
    let attacker = key_at("m/84'/0'/7'/0/3").public_key();
    let attacker_spk = ScriptBuf::new_p2wpkh(&attacker.wpubkey_hash());

    let mut psbt = bluewallet_electrum_relative_path_psbt();
    let mut tx = psbt.unsigned_tx.clone();
    tx.output[1].script_pubkey = attacker_spk;
    let inputs = psbt.inputs.clone();
    let mut outputs = psbt.outputs.clone();
    psbt = Psbt::from_unsigned_tx(tx).expect("fixture psbt");
    psbt.inputs = inputs;
    // Self-consistent, which is the hard case: the key stated is the key that really locks
    // the attacker's script, so nothing that reads only the file has anything to object to.
    let account_fp = account_bip84().xpub().fingerprint();
    outputs[1].bip32_derivation.clear();
    outputs[1]
        .bip32_derivation
        .insert(attacker.0, (account_fp, path("1/0")));
    psbt.outputs = outputs;
    psbt
}

/// Fixture G with fixture D's substitution: the relative path is honest and the key stated
/// at that leaf is not the key that is there.
///
/// Electrum's convention makes the file's path shorter, never softer. This exists so that
/// "the path does not resolve from the master" cannot become a way around the comparison
/// every other route ends in.
pub fn electrum_relative_path_wrong_key_psbt() -> Psbt {
    let mut psbt = bluewallet_electrum_relative_path_psbt();
    let account_fp = account_bip84().xpub().fingerprint();
    let wrong = key_at("m/84'/0'/0'/0/1").public_key();
    psbt.inputs[0].bip32_derivation.clear();
    psbt.inputs[0]
        .bip32_derivation
        .insert(wrong.0, (account_fp, path("0/0")));
    psbt
}

/// [`bluewallet_mixed_ownership_proven_psbt`] with a SECOND party's change claim written
/// onto the output both parties are paying: an origin at `fp`, on a BIP-84 path under an
/// account index this device does not hold, over a script this device does not build.
///
/// The shape a multi-party round arrives in, and the one thing about it that matters is
/// that any party to the round can write this field on any output. What the device may
/// conclude from it therefore depends entirely on WHO the field names, which is the split
/// the two wrappers below exist to pin.
fn mixed_round_with_an_unprovable_output_claim(fp: Fingerprint) -> Psbt {
    let mut psbt = bluewallet_mixed_ownership_proven_psbt();
    // Their key at their own leaf, which is neither our key nor a script any account of
    // ours rebuilds - so nothing here can ever be proven, whatever fingerprint it wears.
    let theirs = key_at("m/84'/0'/9'/0/3").public_key();
    psbt.outputs[0]
        .bip32_derivation
        .insert(theirs.0, (fp, path("m/84'/0'/9'/0/3")));
    psbt
}

/// The second party's claim at BlueWallet's zero fingerprint: four bytes that name nobody.
///
/// THE REGRESSION, and it burned the round for everyone in it. Between 2026-08-21 and
/// 2026-08-22 `classify_output` read a zero fingerprint as a claim about THIS device, so an
/// origin it could not discharge became [`super::checks::OutputRole::ClaimedButUnproven`]
/// and `ReviewState::blocker` refused to arm the hold, with no override. One field, writable
/// by any party to the round and requiring no knowledge of our fingerprint, against a file
/// this device had every reason to sign.
pub fn mixed_round_with_an_assumed_output_claim_psbt() -> Psbt {
    mixed_round_with_an_unprovable_output_claim(Fingerprint::default())
}

/// The same claim at OUR master fingerprint: a statement about this device, and a false one.
///
/// The other half of the split, and the reason the zero-fingerprint half is not simply a
/// hole. Here the file has named us and failed to back it, so
/// [`super::checks::OutputRole::ClaimedButUnproven`] is the honest answer and the hold stays
/// blocked. Nobody writes this by accident, and a coordinator that does has to know our
/// fingerprint to write it.
pub fn mixed_round_with_a_named_output_claim_psbt() -> Psbt {
    mixed_round_with_an_unprovable_output_claim(fingerprint())
}

/// Standard base64 (RFC 4648), padded, encoding only. Hand rolled rather than pulled in as
/// a dependency: [`bluewallet_base64_text`] encodes one small fixture PSBT, and reaching
/// for a crate to do that is not proportionate for code this binary carries nowhere else.
fn base64_encode(data: &[u8]) -> alloc::string::String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = alloc::string::String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(ALPHABET[usize::try_from((n >> 18) & 0x3f).unwrap()] as char);
        out.push(ALPHABET[usize::try_from((n >> 12) & 0x3f).unwrap()] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[usize::try_from((n >> 6) & 0x3f).unwrap()] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[usize::try_from(n & 0x3f).unwrap()] as char
        } else {
            '='
        });
    }
    out
}

/// Fixture H: fixture A, encoded exactly as BlueWallet writes it to the SD card - base64
/// TEXT under a `.psbt` extension, with a trailing newline - rather than the binary
/// BIP-174 grammar [`super::codec::decode`] expects.
///
/// This is what the device actually reads off the card. [`super::codec::decode`] does not
/// autodetect base64 by design (its own doc says why: that is a transport concern, one
/// layer up, and teaching the parser three ways to reach the same bytes is not a
/// simplification). This fixture exists to pin the boundary: base64 text fails the magic
/// check on its own ([`super::codec::Malformed::NotAPsbt`]), and unwrapping it by hand
/// recovers exactly fixture A's bytes, refused for exactly fixture A's reason.
pub fn bluewallet_base64_text() -> Vec<u8> {
    let psbt = bluewallet_watch_only_psbt();
    let bytes = super::codec::encode(&psbt);
    let mut text = base64_encode(&bytes).into_bytes();
    text.push(b'\n');
    text
}

// ---------------------------------------------------------------------------------------
// The amount-rotation probe (0.2.1)
// ---------------------------------------------------------------------------------------
//
// [`amount_substitution_round`] above leaves TWO amounts unproven in one file, one of them
// dressed as a stranger's coin. That shape is refused by the pairwise rule, and it is not
// the hardest one: a coordinator does not have to leave two amounts unproven at all. He
// PROVES one and CLAIMS the other, and rotates which is which between rounds. Every file he
// presents then carries exactly one unproven amount, and every round still yields one valid
// harvestable signature - the one on the input he proved, made over that input's true
// amount. Two rounds over one unsigned transaction combine.
//
// That is why the single-input escape is keyed on the count of TRANSACTION inputs and never
// on a count of the inputs a file says are ours. The fixtures below are the two rotations
// the rule has to survive, and `checks.rs` pins both of them permanently.

/// The two coins of ours the rotation probe spends, both P2WPKH, both really 1 BTC.
const ROTATION_PATHS: [&str; 2] = ["m/84'/0'/0'/0/0", "m/84'/0'/0'/0/1"];

/// The unsigned transaction both rotation rounds share, plus the scripts and the funding
/// transactions behind it.
///
/// One skeleton for both rounds, because two rounds that did not share an unsigned
/// transaction would not combine and the probe would prove nothing. Fixed nonces on the
/// fundings, so the outpoints - and therefore the transaction - are the same whichever
/// round builds it.
fn rotation_skeleton() -> (Vec<ScriptBuf>, Vec<Transaction>, Psbt) {
    let spks: Vec<ScriptBuf> = ROTATION_PATHS
        .iter()
        .map(|p| ScriptBuf::new_p2wpkh(&key_at(p).public_key().wpubkey_hash()))
        .collect();
    let prevs: Vec<Transaction> = spks
        .iter()
        .enumerate()
        .map(|(i, spk)| funding_of(spk, i as u32 + 1, PROBE_COIN_SAT))
        .collect();
    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: prevs.iter().map(|p| spending(p.compute_txid())).collect(),
        output: vec![TxOut {
            value: Amount::from_sat(PROBE_PAYMENT_SAT),
            script_pubkey: external_script(),
        }],
    };
    let psbt = Psbt::from_unsigned_tx(unsigned).expect("fixture psbt");
    (spks, prevs, psbt)
}

/// One round of the rotation, with EXACTLY ONE unproven amount in the file.
///
/// Both inputs are ours and both say so, at BlueWallet's zero fingerprint. `proven` carries
/// its full previous transaction, so its amount is true and a signature over it is valid
/// against the real chain; the other carries `witness_utxo` alone, understated to
/// [`PROBE_CLAIMED_SAT`]. Each round's own arithmetic therefore lands on [`FEE_SAT`], the
/// ordinary fee, and each round hands the coordinator one signature he can keep.
///
/// Run for `proven = 0` and `proven = 1`: the two signatures he keeps are over the SAME
/// unsigned transaction and each was made over its input's real 1 BTC, so they combine into
/// a transaction that pays 0.9999 BTC of a 2 BTC wallet to miners after two screens that
/// each said 10000 sat. This is the shape any "at most one unproven amount" relaxation
/// readmits, which is why it is a permanent negative pin rather than a probe.
pub fn amount_rotation_round(proven: usize) -> Psbt {
    assert!(proven < 2, "the rotation has two inputs");
    let (spks, prevs, mut psbt) = rotation_skeleton();
    for i in 0..2 {
        let claimed = if i == proven {
            PROBE_COIN_SAT
        } else {
            PROBE_CLAIMED_SAT
        };
        psbt.inputs[i].witness_utxo = Some(TxOut {
            value: Amount::from_sat(claimed),
            script_pubkey: spks[i].clone(),
        });
        if i == proven {
            psbt.inputs[i].non_witness_utxo = Some(prevs[i].clone());
        }
        // Both inputs claim this wallet: nothing is disguised as a stranger's coin here,
        // which is what separates this probe from `amount_substitution_round`.
        psbt.inputs[i].bip32_derivation.insert(
            key_at(ROTATION_PATHS[i]).public_key().0,
            (Fingerprint::default(), path(ROTATION_PATHS[i])),
        );
    }
    psbt
}

/// The plainer rotation: both inputs ours, NEITHER carrying its previous transaction, and
/// `truthful` the one whose stated amount happens to be the real one this round.
///
/// [`bluewallet_two_inputs_psbt`] is this file with both amounts stated honestly. Rotating
/// which one is honest costs the coordinator nothing, because nothing in either file proves
/// either amount, and it buys him the same two-round harvest.
pub fn all_ours_claimed_round(truthful: usize) -> Psbt {
    assert!(truthful < 2, "the rotation has two inputs");
    let (spks, _, mut psbt) = rotation_skeleton();
    for i in 0..2 {
        let claimed = if i == truthful {
            PROBE_COIN_SAT
        } else {
            PROBE_CLAIMED_SAT
        };
        psbt.inputs[i].witness_utxo = Some(TxOut {
            value: Amount::from_sat(claimed),
            script_pubkey: spks[i].clone(),
        });
        psbt.inputs[i].bip32_derivation.insert(
            key_at(ROTATION_PATHS[i]).public_key().0,
            (Fingerprint::default(), path(ROTATION_PATHS[i])),
        );
    }
    psbt
}

/// Ownership laundering: input 0 is ours and fully proven, input 1 carries no origin at all
/// and an unproven amount, and its `witness_utxo.script_pubkey` is one of OUR OWN receive
/// addresses - a script the coordinator reads straight out of an xpub he already has.
///
/// The attacker's amplifier, and the reason the single-input escape counts TRANSACTION
/// inputs. Under the 500-address sweep this crate ran until 2026-08-21, that one script
/// bought him a relabelling of input 1 to `Ours`, which moved the file from "one unproven
/// foreign amount beside our signature" into "one unproven amount on an input we sign" -
/// the shape a rule keyed on our own count would admit.
///
/// The sweep is gone and ownership needs an ORIGIN to derive against, so the laundering now
/// buys nothing at all: input 1 is Foreign in every configuration and the file is refused by
/// the pairwise half of check 2. Kept as a permanent pin on both statements - that a
/// `witness_utxo` script is the coordinator's word and not evidence, and that the escape was
/// never keyed on a count the coordinator chooses.
pub fn laundered_foreign_input_psbt() -> Psbt {
    let ours = key_at(P2WPKH_PATH).public_key();
    let our_spk = ScriptBuf::new_p2wpkh(&ours.wpubkey_hash());
    // Leaf 5 of the SAME account's receive keychain: a script `account_bip84` derives, and
    // therefore one the scan matches, carried in without the origin that would say so.
    let laundered = key_at("m/84'/0'/0'/0/5").public_key();
    let laundered_spk = ScriptBuf::new_p2wpkh(&laundered.wpubkey_hash());

    let prev_ours = funding_of(&our_spk, 1, PREVOUT_SAT);
    let prev_laundered = funding_of(&laundered_spk, 2, PREVOUT_SAT);
    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            spending(prev_ours.compute_txid()),
            spending(prev_laundered.compute_txid()),
        ],
        output: vec![TxOut {
            value: Amount::from_sat(2 * PREVOUT_SAT - FEE_SAT),
            script_pubkey: external_script(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("fixture psbt");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(PREVOUT_SAT),
        script_pubkey: our_spk,
    });
    psbt.inputs[0].non_witness_utxo = Some(prev_ours);
    psbt.inputs[0]
        .bip32_derivation
        .insert(ours.0, (fingerprint(), path(P2WPKH_PATH)));
    psbt.inputs[1].witness_utxo = Some(TxOut {
        value: Amount::from_sat(PREVOUT_SAT),
        script_pubkey: laundered_spk,
    });
    psbt
}

/// One input, `witness_utxo` alone, no origin and no script this wallet derives: a
/// stranger's single-input transaction, readable and unsignable.
///
/// The single-input escape upgrades an unproven amount only when the input is one we sign,
/// because the argument behind it is that OUR signature invalidates itself over a false
/// amount. Nothing of ours signs here, so nothing binds the number and the fee stays a
/// lower bound.
pub fn single_input_foreign_unproven_psbt() -> Psbt {
    // A distant account, so no account a session puts in scope derives this script even
    // if the file had carried an origin naming one - which it does not.
    let stranger = key_at("m/84'/0'/9'/0/1").public_key();
    let spk = ScriptBuf::new_p2wpkh(&stranger.wpubkey_hash());
    let prev = funding_of(&spk, 1, PREVOUT_SAT);
    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![spending(prev.compute_txid())],
        output: vec![TxOut {
            value: Amount::from_sat(PREVOUT_SAT - FEE_SAT),
            script_pubkey: external_script(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("fixture psbt");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(PREVOUT_SAT),
        script_pubkey: spk,
    });
    psbt
}

/// Two taproot inputs of ours, both carrying `witness_utxo` alone - what a coordinator
/// sends for an ordinary taproot spend, and a file with more than one input.
///
/// The regression base for the taproot half of the rule: nothing about taproot's security
/// changes when the single-input escape lands, because BIP-341 already binds every one of
/// these amounts through `sha_amounts`. What changes is only how the facts read.
pub fn taproot_two_input_psbt() -> Psbt {
    let paths = [P2TR_PATH, "m/86'/0'/0'/0/1"];
    let keys: Vec<crate::sign::SecretSigningKey> = paths.iter().map(|p| key_at(p)).collect();
    let spks: Vec<ScriptBuf> = keys
        .iter()
        .map(|k| ScriptBuf::new_p2tr_tweaked(k.output_key(None)))
        .collect();
    let prevs: Vec<Transaction> = spks
        .iter()
        .enumerate()
        .map(|(i, spk)| funding_of(spk, i as u32 + 1, PREVOUT_SAT))
        .collect();
    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: prevs.iter().map(|p| spending(p.compute_txid())).collect(),
        output: vec![TxOut {
            value: Amount::from_sat(2 * PREVOUT_SAT - FEE_SAT),
            script_pubkey: external_script(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned).expect("fixture psbt");
    for (i, (spk, key)) in spks.iter().zip(keys.iter()).enumerate() {
        psbt.inputs[i].witness_utxo = Some(TxOut {
            value: Amount::from_sat(PREVOUT_SAT),
            script_pubkey: spk.clone(),
        });
        let internal = key.internal_key();
        psbt.inputs[i].tap_internal_key = Some(internal);
        psbt.inputs[i]
            .tap_key_origins
            .insert(internal, (vec![], (fingerprint(), path(paths[i]))));
    }
    psbt
}
