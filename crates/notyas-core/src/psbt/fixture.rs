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

// ---------------------------------------------------------------------------------------
// Clean cases
// ---------------------------------------------------------------------------------------

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
