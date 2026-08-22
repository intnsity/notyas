// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The coordinator's half of clause 2: would this signed file actually be accepted?
//!
//! A signer that says "signed" is not evidence. The question the release bar asks is
//! whether the thing that came back is a transaction a coordinator would take, and that is
//! a different question with a different set of ways to fail. This module answers it the
//! only way that counts, by doing what a coordinator does:
//!
//!   0. Work out WHICH approved transaction this file claims to be, and compare the whole
//!      of it to the copy this tool kept: every output's amount and script, the input set,
//!      the sequences, the version and the locktime. A signature is only evidence about the
//!      transaction it covers, so "the signature verifies" answers nothing about whether
//!      that transaction is the one the operator was shown and approved. This step is the
//!      only one that can catch a device that displayed one destination and signed another,
//!      which is the failure the whole harness exists for.
//!   1. Resolve every input's previous output, preferring the FULL previous transaction and
//!      checking that its txid is the one the spend actually names. An amount that rests on
//!      a `witness_utxo` alone is an amount nobody proved.
//!   2. Work out, from the harness seed and the registered wallet - never from what the
//!      file claims - which inputs the device was supposed to sign.
//!   3. Recompute each of those inputs' sighash from the transaction and the proven
//!      amounts, with `SighashCache`, and verify the signature the file carries against the
//!      public key the script commits to, with secp256k1.
//!   4. Complete the multisig from the cosigner seeds this harness holds, checking every
//!      leg already on the input before counting it, finalize every input, and extract the
//!      transaction.
//!   5. Check the extracted transaction's shape against the consensus and standardness
//!      rules that can be decided without a chain, and print the fee it really pays beside
//!      the fee the operator was promised.
//!
//! Underneath all five is one rule, and it is what the word ACCEPTED here means: the only
//! transaction this tool extracts, prices and reports is one it assembled itself, out of
//! signatures it verified itself. Any witness the file arrives with is removed before
//! anything is judged, and an input this side cannot then authorise is a refusal that says
//! so. Without that rule the checks above are conditional on the file's own account of
//! which inputs are worth checking, and a file that simply omitted the account got none of
//! them: `bip32_derivation` absent means "not ours", "not ours" means no signature check
//! and no finalization, and the witness the file brought went into the extracted
//! transaction untouched. See [`Verification::new`].
//!
//! Step 3 deliberately shares NOTHING with the device's own post-sign gate beyond the
//! `bitcoin` crate itself. The device recomputes its digest through `notyas_core::sign`;
//! this module goes straight to `SighashCache` and `Secp256k1` with the amounts it resolved
//! itself. A bug that made the signer and its own verifier agree with each other would
//! still be caught here, which is the entire reason this file exists rather than a call to
//! `psbt::verify_signatures`.
//!
//! Step 5 is why the fee is printed twice. The amount rule closed an attack whose whole
//! payload was a fee: the user approves 0.001 BTC of fee and the chain pays 1 BTC, because
//! the signature commits to an amount the coordinator stated rather than one it proved. So
//! "the signatures verify" is not the finish line - "the fee you approved is the fee this
//! transaction pays" is, and that number is only knowable after extraction.
//!
//! Step 0 has a third answer, and it is deliberate. A file this coordinator never generated
//! is neither accepted nor refused: there is no approved copy to compare it against, so
//! nothing here can say whether its destinations are the ones a human agreed to. Reporting
//! that as acceptance is the defect this module was rewritten to remove; reporting it as a
//! refusal would blame a device for a file somebody merely pointed at the wrong verifier.
//! It gets its own verdict and its own exit status, and the honest statement of this tool's
//! limit: it can only judge transactions it issued.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use notyas_core::bitcoin::bip32::{DerivationPath, Fingerprint};
use notyas_core::bitcoin::blockdata::script::Instruction;
use notyas_core::bitcoin::ecdsa;
use notyas_core::bitcoin::hashes::Hash as _;
use notyas_core::bitcoin::key::{CompressedPublicKey, TweakedPublicKey};
use notyas_core::bitcoin::psbt::{Input, Psbt};
use notyas_core::bitcoin::script::{Builder, PushBytesBuf};
use notyas_core::bitcoin::secp256k1::{Message, PublicKey, Secp256k1};
use notyas_core::bitcoin::sighash::{
    EcdsaSighashType, Prevouts, SegwitV0Sighash, SighashCache, TapSighashType,
};
use notyas_core::bitcoin::taproot;
use notyas_core::bitcoin::{
    Address, Amount, Network, OutPoint, Script, ScriptBuf, Transaction, TxOut, Txid, Weight,
    Witness,
};
use notyas_core::multisig::{self, Registration};
use notyas_core::psbt::fixture;
use notyas_core::sign::{self, SignHash, Signature};

use crate::build::{self, Case};
use crate::harness::Harness;
use crate::Verdict;

/// The standard weight ceiling for a relayable transaction (`MAX_STANDARD_TX_WEIGHT`).
/// Consensus allows a whole block, but nothing this harness produces should come near
/// either number, so the tighter of the two is the useful one to check against.
const MAX_STANDARD_WEIGHT: Weight = Weight::from_wu(400_000);

/// BIP-141: a transaction whose non-witness serialization is 64 bytes is rejected, because
/// such a thing can be confused with a merkle node. Anything smaller cannot be well formed
/// at all.
const MIN_BASE_SIZE: usize = 65;

/// A wallet whose seed this side of the airgap holds.
#[derive(Debug)]
pub struct Signer {
    pub label: String,
    pub seed: [u8; 64],
    pub fingerprint: Fingerprint,
}

impl Signer {
    fn new(label: &str, seed: [u8; 64], network: Network) -> Signer {
        Signer {
            label: label.to_string(),
            seed,
            fingerprint: notyas_core::derive::master_fingerprint(&seed, network),
        }
    }
}

/// A transaction this coordinator issued: the approved copy, and the fee promised for it.
///
/// The whole unsigned transaction is kept, not just its txid. A txid answers exactly one
/// question - "is this byte for byte the file I handed out" - and answers it with a yes or
/// a silence. The question that matters when a device displays one destination and signs
/// another is "what changed", and only a copy of what was approved can answer that. Keeping
/// the txid alone is how this tool once accepted a transaction nobody had approved: the
/// edited file simply failed the lookup, and a failed lookup meant nothing was compared.
#[derive(Debug)]
pub struct Expectation {
    pub name: String,
    pub tx: Transaction,
    /// The fee the operator's card promised. `None` for a corpus that was never handed to
    /// an operator and so promised nothing - the fee is then reported, not judged.
    pub fee: Option<Amount>,
}

impl Expectation {
    fn txid(&self) -> Txid {
        self.tx.compute_txid()
    }

    /// How many of this case's inputs `tx` spends.
    ///
    /// The input set is the identity test, and it is the inputs rather than the outputs on
    /// purpose: the prevouts are the part an attacker cannot move. A device signature is
    /// only worth stealing against the outpoints it commits to, so a file built to redirect
    /// an approved spend keeps every one of them and edits the outputs instead. Recognising
    /// a case by its outputs would therefore stop recognising it in exactly the case this
    /// step exists for.
    fn overlap(&self, tx: &Transaction) -> usize {
        let approved: BTreeSet<OutPoint> =
            self.tx.input.iter().map(|i| i.previous_output).collect();
        tx.input
            .iter()
            .filter(|i| approved.contains(&i.previous_output))
            .count()
    }

    /// Every way `tx` differs from what was approved, one line each, naming the change.
    ///
    /// Covers precisely the fields the txid commits to - version, locktime, and every
    /// input's and output's contents - so this list is empty if and only if the two
    /// transactions are identical. That equivalence is what lets the caller treat an empty
    /// list as "unchanged" rather than as "nothing I know how to look at".
    fn divergences(&self, tx: &Transaction, network: Network) -> Vec<String> {
        let case = &self.name;
        let mut changes = Vec::new();

        if tx.version != self.tx.version {
            changes.push(format!(
                "the transaction version is {}, and the approved '{case}' case is version {}",
                tx.version.0, self.tx.version.0
            ));
        }
        if tx.lock_time != self.tx.lock_time {
            changes.push(format!(
                "the locktime is {}, and the approved '{case}' case has {}",
                tx.lock_time, self.tx.lock_time
            ));
        }

        if tx.input.len() != self.tx.input.len() {
            changes.push(format!(
                "it spends {} input(s), and the approved '{case}' case spends {}",
                tx.input.len(),
                self.tx.input.len()
            ));
        }
        for index in 0..tx.input.len().max(self.tx.input.len()) {
            match (tx.input.get(index), self.tx.input.get(index)) {
                (Some(found), Some(approved)) => {
                    if found.previous_output != approved.previous_output {
                        changes.push(format!(
                            "input {index} spends {}, and the approved '{case}' case spends {}",
                            found.previous_output, approved.previous_output
                        ));
                    }
                    if found.sequence != approved.sequence {
                        // A changed sequence is a changed transaction even when every
                        // amount is untouched: it decides replaceability and any relative
                        // timelock, both of which the review screen reports.
                        changes.push(format!(
                            "input {index} has sequence {:#010x}, and the approved '{case}' \
                             case sets {:#010x}",
                            found.sequence.0, approved.sequence.0
                        ));
                    }
                    if found.script_sig != approved.script_sig {
                        changes.push(format!(
                            "input {index} carries a scriptSig of {} byte(s), and the approved \
                             '{case}' case carries {}",
                            found.script_sig.len(),
                            approved.script_sig.len()
                        ));
                    }
                }
                (Some(found), None) => changes.push(format!(
                    "input {index} spends {}, and the approved '{case}' case has no input {index}",
                    found.previous_output
                )),
                (None, Some(approved)) => changes.push(format!(
                    "the approved '{case}' case spends {} at input {index}, and this file drops it",
                    approved.previous_output
                )),
                // Unreachable: the index is below at least one of the two lengths.
                (None, None) => {}
            }
        }

        if tx.output.len() != self.tx.output.len() {
            changes.push(format!(
                "it has {} output(s), and the approved '{case}' case has {}",
                tx.output.len(),
                self.tx.output.len()
            ));
        }
        for index in 0..tx.output.len().max(self.tx.output.len()) {
            match (tx.output.get(index), self.tx.output.get(index)) {
                (Some(found), Some(approved)) => {
                    if found != approved {
                        // Both sides in full, and the destination as an address rather than
                        // a script: the number an operator can act on is the one they can
                        // read off the card and off the device's review screen.
                        changes.push(format!(
                            "output {index} pays {} sat to {}, and the approved '{case}' case \
                             pays {} sat to {}",
                            found.value.to_sat(),
                            destination(&found.script_pubkey, network),
                            approved.value.to_sat(),
                            destination(&approved.script_pubkey, network)
                        ));
                    }
                }
                (Some(found), None) => changes.push(format!(
                    "output {index} pays {} sat to {}, and the approved '{case}' case has no \
                     output {index}",
                    found.value.to_sat(),
                    destination(&found.script_pubkey, network)
                )),
                (None, Some(approved)) => changes.push(format!(
                    "the approved '{case}' case pays {} sat to {} at output {index}, and this \
                     file drops it",
                    approved.value.to_sat(),
                    destination(&approved.script_pubkey, network)
                )),
                // Unreachable, as above.
                (None, None) => {}
            }
        }
        changes
    }
}

/// What this file turned out to be, once it was compared with what was approved.
#[derive(Debug)]
pub enum Recognition {
    /// The approved case, unchanged. Everything after this step is about the signatures.
    Approved(String),
    /// The approved case's inputs, and a transaction that is no longer the approved one.
    /// Every change is also a refusal, so this can never end in acceptance.
    Altered { case: String, changes: Vec<String> },
    /// Nothing this coordinator issued. Neither accepted nor refused: see the module
    /// header. The verdict is [`Verdict::Unrecognised`] and the exit status is its own.
    Unknown,
}

/// The coordinator: who it can recognise, who it can sign for, and what it asked for.
#[derive(Debug)]
pub struct Coordinator {
    /// The wallet under test. Its signatures are the ones being judged; a missing or wrong
    /// one is a refusal, never something this side quietly fixes.
    pub device: Signer,
    /// Wallets this side holds too. Used only to COMPLETE a multisig spend the device has
    /// already signed one leg of, which is exactly what a coordinator does before
    /// broadcast. Never used to stand in for a device signature.
    pub cosigners: Vec<Signer>,
    pub registry: Vec<Registration>,
    pub network: Network,
    /// The transactions this coordinator issued. Never empty: a coordinator that holds no
    /// approved copy of anything can only ever check a file against itself, and this tool's
    /// one defining bug was doing exactly that. Both constructors below supply a corpus.
    expectations: Vec<Expectation>,
}

impl Coordinator {
    /// The coordinator for the generated artifact set.
    pub fn for_harness(harness: &Harness) -> Coordinator {
        let network = crate::harness::NETWORK;
        let expectations = build::cases(harness)
            .iter()
            .map(|case: &Case| Expectation {
                name: case.name.to_string(),
                tx: case.psbt.unsigned_tx.clone(),
                fee: Some(case.fee),
            })
            .collect();
        Coordinator {
            device: Signer::new("device", *harness.device.seed(), network),
            cosigners: harness
                .cosigners
                .iter()
                .map(|w| Signer::new(w.label, *w.seed(), network))
                .collect(),
            registry: vec![harness.registration().clone()],
            network,
            expectations,
        }
    }

    /// The coordinator for `notyas_core::psbt::fixture`'s corpus.
    ///
    /// No cosigners: the fixture wallet's other two seeds are private to that module, which
    /// is the honest situation for a coordinator holding one member of a 2-of-3 and is
    /// worth exercising for that reason alone - it is the case where the right answer is
    /// "the signature is good, and this file still needs another one".
    ///
    /// Its approved corpus is the fixture PSBTs themselves, which is not a formality. A
    /// fixture's unsigned transaction IS the approved intent for that fixture, so holding
    /// it here means the whole-transaction comparison covers this corpus too, and - more to
    /// the point - it means there is no such thing as a coordinator with nothing to compare
    /// against. That state was the bug. Leaving it representable would leave a path back to
    /// it for whoever adds the third coordinator.
    ///
    /// No fee: none of these was ever printed on an operator's card, so there is no
    /// approved figure and the fee is reported rather than judged.
    pub fn for_fixture() -> Coordinator {
        let expectations = [
            ("fixture p2wpkh", fixture::p2wpkh_psbt()),
            ("fixture p2sh-p2wpkh", fixture::p2sh_p2wpkh_psbt()),
            ("fixture taproot", fixture::p2tr_psbt()),
            ("fixture 2-of-3", fixture::multisig_psbt()),
            ("fixture batch", fixture::ours_and_a_foreign_input_psbt()),
        ]
        .into_iter()
        .map(|(name, psbt)| Expectation {
            name: name.to_string(),
            tx: psbt.unsigned_tx,
            fee: None,
        })
        .collect();
        Coordinator {
            device: Signer::new("fixture", fixture::SEED, fixture::NETWORK),
            cosigners: Vec::new(),
            registry: vec![fixture::registration()],
            network: fixture::NETWORK,
            expectations,
        }
    }

    /// Judge a signed PSBT.
    pub fn verify(&self, psbt: &Psbt) -> Outcome {
        Verification::new(self, psbt).run()
    }
}

/// What an input turned out to be, once ownership was decided from the seed rather than
/// from the file.
#[derive(Debug)]
enum Ownership {
    /// Not ours. Nothing is expected of it, and the coordinator would be getting its
    /// signature from somewhere else.
    Foreign,
    /// A pre-segwit coin. The key hash sits in the scriptPubKey itself, with no witness
    /// program and no redeem script in between, and the digest that authorises it commits
    /// to no amount at all - which is why the amount an input like this pays has to be
    /// proven by a previous transaction rather than asserted by the file.
    P2pkh {
        pubkey: CompressedPublicKey,
    },
    P2wpkh {
        pubkey: CompressedPublicKey,
    },
    P2shP2wpkh {
        pubkey: CompressedPublicKey,
        redeem_script: ScriptBuf,
    },
    P2wsh {
        our_key: CompressedPublicKey,
        witness_script: ScriptBuf,
    },
    P2trKeyPath {
        output_key: TweakedPublicKey,
    },
}

/// Every way this tool refuses. Each names the input it is about and says what is wrong in
/// a sentence, because a refusal that cannot be acted on is only a slower way of saying no.
#[derive(Debug)]
pub enum Refusal {
    /// The file spends an approved case's inputs, and is not that case any more. One per
    /// change, so a refusal names the destination or the amount that moved rather than only
    /// announcing that something did.
    CaseDiverges {
        case: String,
        change: String,
    },
    NoPrevout {
        index: usize,
    },
    PrevTxIsNotTheOneNamed {
        index: usize,
        named: Txid,
        supplied: Txid,
    },
    PrevTxTooShort {
        index: usize,
        vout: u32,
        outputs: usize,
    },
    ProvenAmountContradicted {
        index: usize,
        proven: Amount,
        claimed: Amount,
    },
    AmountUnproven {
        index: usize,
        claimed: Amount,
    },
    ClaimedButNotOurs {
        index: usize,
        path: DerivationPath,
    },
    SignatureMissing {
        index: usize,
        key: String,
    },
    SighashNotWhitelisted {
        index: usize,
        found: String,
    },
    SighashUncomputable {
        index: usize,
        reason: String,
    },
    SignatureDoesNotVerify {
        index: usize,
        key: String,
        digest: String,
    },
    /// The file arrived with a witness already on this input and this tool could not
    /// re-derive it from signatures it checked itself. See [`Verification::new`].
    WitnessNotVerified {
        index: usize,
    },
    Incomplete {
        index: usize,
        have: usize,
        need: usize,
        missing: Vec<String>,
    },
    ExtractionFailed {
        reason: String,
    },
    ConsensusShape {
        reason: String,
    },
    FeeIsNotWhatWasApproved {
        expected: Amount,
        actual: Amount,
    },
}

impl Refusal {
    /// A stable one-word name for this kind of refusal.
    ///
    /// The prose in `Display` is for a person and is expected to be reworded; this is what
    /// `selftest` asserts against and what a script can grep for, so the two jobs do not
    /// fight over one string.
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::CaseDiverges { .. } => "case-diverges",
            Refusal::NoPrevout { .. } => "no-prevout",
            Refusal::PrevTxIsNotTheOneNamed { .. } => "wrong-prev-tx",
            Refusal::PrevTxTooShort { .. } => "prev-tx-too-short",
            Refusal::ProvenAmountContradicted { .. } => "amount-contradicted",
            Refusal::AmountUnproven { .. } => "amount-unproven",
            Refusal::ClaimedButNotOurs { .. } => "claimed-but-not-ours",
            Refusal::SignatureMissing { .. } => "signature-missing",
            Refusal::SighashNotWhitelisted { .. } => "sighash-not-whitelisted",
            Refusal::SighashUncomputable { .. } => "sighash-uncomputable",
            Refusal::SignatureDoesNotVerify { .. } => "signature-invalid",
            Refusal::WitnessNotVerified { .. } => "witness-unverified",
            Refusal::Incomplete { .. } => "incomplete",
            Refusal::ExtractionFailed { .. } => "extraction-failed",
            Refusal::ConsensusShape { .. } => "consensus-shape",
            Refusal::FeeIsNotWhatWasApproved { .. } => "fee-differs",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::CaseDiverges { case, change } => write!(
                f,
                "this is not the '{case}' case that was approved: {change}"
            ),
            Refusal::NoPrevout { index } => write!(
                f,
                "input {index}: neither a previous transaction nor a witness utxo, so its \
                 amount and its script are unknown"
            ),
            Refusal::PrevTxIsNotTheOneNamed {
                index,
                named,
                supplied,
            } => write!(
                f,
                "input {index}: the supplied previous transaction is {supplied}, but the \
                 input spends {named}"
            ),
            Refusal::PrevTxTooShort {
                index,
                vout,
                outputs,
            } => write!(
                f,
                "input {index}: spends output {vout} of a previous transaction that has \
                 {outputs}"
            ),
            Refusal::ProvenAmountContradicted {
                index,
                proven,
                claimed,
            } => write!(
                f,
                "input {index}: the previous transaction proves {proven} but the witness \
                 utxo claims {claimed}; a signature made under the claim would pay the \
                 difference as fee"
            ),
            Refusal::AmountUnproven { index, claimed } => write!(
                f,
                "input {index}: signed for {claimed} on the file's word alone - no previous \
                 transaction was supplied, so the fee shown to the user is not the fee this \
                 transaction pays"
            ),
            Refusal::ClaimedButNotOurs { index, path } => write!(
                f,
                "input {index}: an origin names our fingerprint at {path}, but that path \
                 does not derive the key the input's script commits to"
            ),
            Refusal::SignatureMissing { index, key } => write!(
                f,
                "input {index}: no signature for {key}, which is the key this device was \
                 supposed to sign with"
            ),
            Refusal::SighashNotWhitelisted { index, found } => write!(
                f,
                "input {index}: signed under sighash {found}; only SIGHASH_ALL (and \
                 SIGHASH_DEFAULT for taproot) commits to every output"
            ),
            Refusal::SighashUncomputable { index, reason } => {
                write!(f, "input {index}: the sighash cannot be recomputed: {reason}")
            }
            Refusal::SignatureDoesNotVerify { index, key, digest } => write!(
                f,
                "input {index}: the signature for {key} does not verify against the digest \
                 this transaction really commits to ({digest})"
            ),
            Refusal::WitnessNotVerified { index } => write!(
                f,
                "input {index}: the file supplied a finished witness for it, and nothing in \
                 that witness was verified here - psbtgen only prices a transaction it \
                 assembled itself out of signatures it checked, so it cannot say whether \
                 this input is authorised"
            ),
            Refusal::Incomplete {
                index,
                have,
                need,
                missing,
            } => write!(
                f,
                "input {index}: {have} of {need} required signatures; still missing {}",
                missing.join(", ")
            ),
            Refusal::ExtractionFailed { reason } => {
                write!(f, "the transaction does not extract: {reason}")
            }
            Refusal::ConsensusShape { reason } => {
                write!(f, "the extracted transaction is not well formed: {reason}")
            }
            Refusal::FeeIsNotWhatWasApproved { expected, actual } => write!(
                f,
                "the fee is {actual}, and the file the device was given promised {expected}"
            ),
        }
    }
}

/// One input, as the verifier came to understand it.
#[derive(Debug)]
pub struct InputVerdict {
    pub index: usize,
    pub outpoint: OutPoint,
    pub value: Amount,
    /// Whether the amount rests on a full previous transaction rather than on a claim.
    pub proven: bool,
    pub kind: &'static str,
    pub ours: bool,
    /// The device's signature verified against a digest recomputed here.
    pub verified: bool,
}

/// The extracted transaction and the numbers that decide whether it is worth broadcasting.
#[derive(Debug)]
pub struct Extracted {
    pub txid: Txid,
    pub weight: Weight,
    pub vsize: usize,
    pub fee_rate: f64,
    pub raw: Vec<u8>,
}

/// The verdict.
#[derive(Debug)]
pub struct Outcome {
    /// Which approved case this file turned out to be, and whether it still is that case.
    pub recognition: Recognition,
    pub inputs: Vec<InputVerdict>,
    pub signatures_checked: usize,
    pub cosigned: Vec<String>,
    pub fee: Option<Amount>,
    pub expected_fee: Option<Amount>,
    pub extracted: Option<Extracted>,
    pub refusals: Vec<Refusal>,
    pub notes: Vec<String>,
}

impl Outcome {
    /// The one question. A coordinator accepts a file when it IS the transaction that was
    /// approved, every input the device owns carries a signature that verifies, the
    /// transaction extracts, its shape is sane and its fee is the fee that was approved.
    ///
    /// Refusals decide first, and deliberately: a file that is both unrecognised and
    /// internally broken is reported as broken, because that is the finding somebody can
    /// act on. An unrecognised file with nothing else wrong is the one that gets the third
    /// answer, since the tool has then found no fault - it has only found the edge of what
    /// it is able to judge.
    pub fn verdict(&self) -> Verdict {
        if !self.refusals.is_empty() {
            Verdict::Refused
        } else if matches!(self.recognition, Recognition::Unknown) {
            Verdict::Unrecognised
        } else if self.signatures_checked == 0 {
            // Belt to the structural braces above. The two acceptance holes this tool
            // shipped with - a pass-through witness on an input whose origin hints were
            // absent, and a multisig leg counted because a key had SOME entry in
            // partial_sigs - both ended here with an empty refusal list, because in each
            // case nothing was ever checked and so nothing could refuse. `authorized` and
            // the WitnessNotVerified pass now catch both by construction.
            //
            // This guard exists anyway, and its value is exactly that it is redundant:
            // it converts "no refusal fired" into "at least one signature was verified",
            // which is the property an ACCEPTED verdict actually asserts. A future edit
            // that adds a fourth path into the accept branch without a matching refusal
            // gets caught here rather than certifying an unspendable transaction. For a
            // tool whose whole output is a yes or a no about somebody's money, the cheap
            // duplicate check is worth its line count.
            Verdict::Unrecognised
        } else {
            Verdict::Accepted
        }
    }

    pub fn accepted(&self) -> bool {
        matches!(self.verdict(), Verdict::Accepted)
    }

    /// The approved case this file claims to be, however altered.
    pub fn case_name(&self) -> Option<&str> {
        match &self.recognition {
            Recognition::Approved(case) => Some(case),
            Recognition::Altered { case, .. } => Some(case),
            Recognition::Unknown => None,
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.recognition {
            Recognition::Approved(case) => {
                writeln!(f, "  recognised    the approved '{case}' case, unchanged")?
            }
            Recognition::Altered { case, changes } => writeln!(
                f,
                "  recognised    the approved '{case}' case, with {} change(s) to the \
                 transaction itself",
                changes.len()
            )?,
            Recognition::Unknown => writeln!(
                f,
                "  recognised    NO - psbtgen never generated this transaction, so it holds \
                 no approved copy to compare it against"
            )?,
        }
        for input in &self.inputs {
            writeln!(
                f,
                "  input {:<3}     {} {} sat, {}{}",
                input.index,
                input.kind,
                input.value.to_sat(),
                if input.proven {
                    "proven by prev tx"
                } else {
                    "AMOUNT CLAIMED, NOT PROVEN"
                },
                if input.ours {
                    if input.verified {
                        ", ours, signature verified"
                    } else {
                        ", ours, SIGNATURE NOT VERIFIED"
                    }
                } else {
                    ", not ours"
                }
            )?;
            writeln!(f, "                spending {}", input.outpoint)?;
        }
        for label in &self.cosigned {
            writeln!(
                f,
                "  completed     added the {label} signature, as a coordinator would"
            )?;
        }
        if let Some(fee) = self.fee {
            match self.expected_fee {
                Some(expected) if expected == fee => writeln!(
                    f,
                    "  fee           {} sat, exactly the fee that was approved",
                    fee.to_sat()
                )?,
                Some(expected) => writeln!(
                    f,
                    "  fee           {} sat, and {} sat was approved",
                    fee.to_sat(),
                    expected.to_sat()
                )?,
                None => writeln!(
                    f,
                    "  fee           {} sat (no approved figure to compare it against)",
                    fee.to_sat()
                )?,
            }
        }
        if let Some(extracted) = &self.extracted {
            writeln!(f, "  txid          {}", extracted.txid)?;
            writeln!(
                f,
                "  size          {} vbytes, {} weight units, {:.2} sat/vB",
                extracted.vsize,
                extracted.weight.to_wu(),
                extracted.fee_rate
            )?;
        }
        for note in &self.notes {
            writeln!(f, "  note          {note}")?;
        }
        for refusal in &self.refusals {
            writeln!(f, "  REFUSED       {refusal}")?;
        }
        Ok(())
    }
}

/// One run of the verifier. A struct rather than a long function so that the steps can
/// share the resolved prevouts, the sighash cache and the growing refusal list without
/// threading six parameters through each other.
struct Verification<'a> {
    coordinator: &'a Coordinator,
    psbt: Psbt,
    /// Resolved previous outputs, indexed like the inputs. `None` where resolution failed;
    /// taproot needs all of them, so one hole is not a local problem.
    prevouts: Vec<Option<Resolved>>,
    /// Which inputs arrived with a witness already on them, before [`Verification::new`]
    /// took it off. Indexed like the inputs.
    supplied_final: Vec<bool>,
    /// Which inputs this verifier itself authorised: it built their witness, and every
    /// signature in that witness verified here against a digest recomputed here. Indexed
    /// like the inputs. Only [`Verification::finalize`] may set an entry of this.
    authorized: Vec<bool>,
    refusals: Vec<Refusal>,
    notes: Vec<String>,
}

#[derive(Debug, Clone)]
struct Resolved {
    txout: TxOut,
    proven: bool,
}

/// Which digest an ECDSA signature on a given spend has to verify against, and everything
/// that goes into computing it.
///
/// One variant per algorithm rather than a bare `&Script`, because the scripts are not
/// interchangeable and passing the wrong one produces a digest that is wrong in a way
/// nothing else catches: every signature simply fails to verify, and the finding reads as a
/// broken signer. The amount is carried by the two variants that hash one and is absent
/// from the one that does not, so the difference between the algorithms is in the type
/// rather than in a parameter somebody has to remember is ignored.
enum Digest<'s> {
    /// BIP-143 over the P2WPKH witness program. `p2wpkh_signature_hash` expands it into the
    /// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG` scriptCode BIP-143 specifies.
    P2wpkh { program: &'s Script, value: Amount },
    /// BIP-143 over the witness script itself, which is the scriptCode for a P2WSH spend.
    P2wsh {
        witness_script: &'s Script,
        value: Amount,
    },
    /// The pre-segwit algorithm over the subscript, and no amount: a legacy signature
    /// commits to what it spends but never to what that input is worth. That absence is
    /// the whole reason a legacy input's amount has to arrive proven by a previous
    /// transaction rather than claimed by the file.
    Legacy { subscript: &'s Script },
}

impl<'a> Verification<'a> {
    /// Take the file's own finished witnesses off before anything is judged.
    ///
    /// This is the invariant the module rests on: the only transaction this tool extracts,
    /// prices and reports is one it assembled itself, out of signatures it verified itself.
    /// A `final_script_witness` that arrives in the file is somebody else's assertion that
    /// an input is authorised, and a verifier that passes such an assertion through into
    /// the transaction it then calls ACCEPTED has certified a signature it never looked at.
    ///
    /// That was not hypothetical. Ownership is worked out from `bip32_derivation` and
    /// `tap_key_origins`, which are hints the file carries; an input whose hints are absent
    /// classified as foreign, foreign inputs are never signature-checked and are never
    /// finalized here, and so the witness the file brought - any bytes at all - survived
    /// untouched into the extracted transaction and was reported as accepted. The same file
    /// with the hints left in place is refused for a missing signature, which is what made
    /// the hole invisible: deleting evidence improved the verdict. Stripping the field
    /// closes the class rather than the instance, because after it every input has to earn
    /// a witness on this side of the airgap.
    ///
    /// Which inputs had one is remembered rather than forgotten: an input whose witness was
    /// taken away and could not be rebuilt has to be refused by name, not quietly reported
    /// as an input nobody signed.
    fn new(coordinator: &'a Coordinator, psbt: &Psbt) -> Verification<'a> {
        let mut psbt = psbt.clone();
        let mut supplied_final = Vec::with_capacity(psbt.inputs.len());
        for input in &mut psbt.inputs {
            supplied_final
                .push(input.final_script_witness.is_some() || input.final_script_sig.is_some());
            input.final_script_witness = None;
            input.final_script_sig = None;
        }
        let authorized = vec![false; psbt.inputs.len()];
        Verification {
            coordinator,
            psbt,
            prevouts: Vec::new(),
            supplied_final,
            authorized,
            refusals: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn run(mut self) -> Outcome {
        // Recognition first. Which transaction this file claims to be decides what every
        // check below is evidence ABOUT, and when it is the thing that is wrong it is the
        // finding that should lead the refusals rather than trail them.
        let tx = self.psbt.unsigned_tx.clone();
        let (recognition, expected_fee) = self.recognise(&tx);
        self.resolve_prevouts();

        let mut verdicts = Vec::new();
        let mut signatures_checked = 0usize;
        let mut cosigned = Vec::new();

        // The prevout set taproot's digest needs. Only usable when every input resolved,
        // because BIP-341 hashes all of them: a hole makes every taproot digest in the
        // transaction unknowable rather than just that input's.
        let all_prevouts: Option<Vec<TxOut>> = self
            .prevouts
            .iter()
            .map(|r| r.as_ref().map(|r| r.txout.clone()))
            .collect();

        let mut cache = SighashCache::new(&tx);
        for index in 0..self.psbt.inputs.len() {
            let Some(resolved) = self.prevouts[index].clone() else {
                verdicts.push(InputVerdict {
                    index,
                    outpoint: tx.input[index].previous_output,
                    value: Amount::ZERO,
                    proven: false,
                    kind: "unresolved",
                    ours: false,
                    verified: false,
                });
                continue;
            };
            let ownership = self.classify(index, &resolved.txout);
            let kind = kind_of(&ownership, &resolved.txout);
            let ours = !matches!(ownership, Ownership::Foreign);
            let mut verified = false;

            if ours {
                // The amount rule, at the only point where it bites: this device put a
                // signature on this input, so the amount that signature covers had better
                // be one somebody proved. Taproot is the documented exception - BIP-341
                // hashes every input's amount into the digest, so a lie costs the
                // coordinator a transaction that cannot confirm rather than the user a fee.
                if !resolved.proven && !matches!(ownership, Ownership::P2trKeyPath { .. }) {
                    self.refusals.push(Refusal::AmountUnproven {
                        index,
                        claimed: resolved.txout.value,
                    });
                }
                verified = self.check_signature(
                    index,
                    &ownership,
                    &resolved,
                    &mut cache,
                    all_prevouts.as_deref(),
                );
                // Completion and finalization run only on top of a device signature that
                // verified. Assembling a witness around one that did not would put bytes
                // nobody checked into the transaction this tool goes on to price, and
                // completing a multisig the device did not really sign answers a question
                // nobody asked: the finding is the device's own leg.
                if verified {
                    signatures_checked += 1;
                    if let Ownership::P2wsh { witness_script, .. } = &ownership {
                        let witness_script = witness_script.clone();
                        cosigned.extend(self.complete_multisig(
                            index,
                            &witness_script,
                            &resolved,
                            &mut cache,
                        ));
                    }
                    self.finalize(index, &ownership);
                }
            }

            verdicts.push(InputVerdict {
                index,
                outpoint: tx.input[index].previous_output,
                value: resolved.txout.value,
                proven: resolved.proven,
                kind,
                ours,
                verified,
            });
        }

        if !verdicts.iter().any(|v| v.ours) {
            self.notes.push(
                "no input of this transaction belongs to the wallet under test, so there \
                 was no device signature to judge"
                    .to_string(),
            );
        }

        // Every input the file had already finished and this side could not finish for
        // itself is a refusal. An input that arrived with nothing on it is left to the
        // shape check after extraction, which says the more useful thing about it: a
        // coordinator still has to go and collect that signature.
        for index in 0..self.psbt.inputs.len() {
            if self.supplied_final[index] && !self.authorized[index] {
                self.refusals.push(Refusal::WitnessNotVerified { index });
            }
        }

        let fee = self.fee();
        if let (Some(fee), Some(expected)) = (fee, expected_fee) {
            if fee != expected {
                self.refusals
                    .push(Refusal::FeeIsNotWhatWasApproved { expected, actual: fee });
            }
        }

        let extracted = self.extract(fee);

        Outcome {
            recognition,
            inputs: verdicts,
            signatures_checked,
            cosigned,
            fee,
            expected_fee,
            extracted,
            refusals: self.refusals,
            notes: self.notes,
        }
    }

    /// Step 0: which approved transaction is this, and is it still that transaction?
    ///
    /// Two stages, because "the same file" and "the same spend" are different questions.
    /// The txid settles the first: it commits to the version, the locktime and every input
    /// and output, so a match means the transaction is bit for bit the one that was handed
    /// out and only witness data can have been added. The input set settles the second: a
    /// file that spends an approved case's prevouts is a claim on that case's money, and
    /// the only reason for it not to match by txid is that somebody changed the
    /// transaction. So it is compared field by field and every difference is a refusal.
    ///
    /// The order matters. Matching on the outputs would fail on exactly the file this exists
    /// to catch, since editing the outputs is what such a file does; matching only on the
    /// txid - which is what this tool used to do - fails the same way, quietly, by finding
    /// nothing to compare and then comparing nothing.
    ///
    /// Returns the approved fee alongside, so the fee check below judges against the card
    /// the operator actually held rather than against whatever the file implies.
    fn recognise(&mut self, tx: &Transaction) -> (Recognition, Option<Amount>) {
        let txid = tx.compute_txid();
        if let Some(approved) = self
            .coordinator
            .expectations
            .iter()
            .find(|e| e.txid() == txid)
        {
            return (Recognition::Approved(approved.name.clone()), approved.fee);
        }

        // Not one of ours by txid. If it spends an approved case's inputs it is that case
        // with something changed, and the case with the most inputs in common is the one it
        // is claiming to be. A tie keeps the first, which only matters for determinism: no
        // two generated cases share a prevout, so a tie means a corpus worth looking at
        // rather than a judgement worth making here.
        let mut claimed: Option<(&Expectation, usize)> = None;
        for expectation in &self.coordinator.expectations {
            let shared = expectation.overlap(tx);
            if shared > claimed.map_or(0, |(_, best)| best) {
                claimed = Some((expectation, shared));
            }
        }

        let Some((approved, _)) = claimed else {
            return (Recognition::Unknown, None);
        };

        let mut changes = approved.divergences(tx, self.coordinator.network);
        if changes.is_empty() {
            // Unreachable while `divergences` covers every field the txid commits to, and
            // guarded anyway: the one outcome that must be impossible here is a file that
            // differs from the approved case and is accepted because the comparison had
            // nothing to say about it.
            changes.push(format!(
                "its txid is {txid} and the approved case's is {}, though this comparison \
                 cannot name the field that differs; treat that as a bug in psbtgen",
                approved.txid()
            ));
        }
        for change in &changes {
            self.refusals.push(Refusal::CaseDiverges {
                case: approved.name.clone(),
                change: change.clone(),
            });
        }
        (
            Recognition::Altered {
                case: approved.name.clone(),
                changes,
            },
            approved.fee,
        )
    }

    /// Step 1: what each input is really worth, and how well that is known.
    fn resolve_prevouts(&mut self) {
        let tx = self.psbt.unsigned_tx.clone();
        for (index, input) in self.psbt.inputs.iter().enumerate() {
            let outpoint = tx.input[index].previous_output;
            let resolved = match (&input.non_witness_utxo, &input.witness_utxo) {
                (Some(prev), claimed) => {
                    let supplied = prev.compute_txid();
                    if supplied != outpoint.txid {
                        self.refusals.push(Refusal::PrevTxIsNotTheOneNamed {
                            index,
                            named: outpoint.txid,
                            supplied,
                        });
                        None
                    } else if outpoint.vout as usize >= prev.output.len() {
                        self.refusals.push(Refusal::PrevTxTooShort {
                            index,
                            vout: outpoint.vout,
                            outputs: prev.output.len(),
                        });
                        None
                    } else {
                        let txout = prev.output[outpoint.vout as usize].clone();
                        // Both fields present and disagreeing is the amount attack in its
                        // purest form: the proof says one number and the field a signer
                        // reads says another.
                        if let Some(claimed) = claimed {
                            if claimed.value != txout.value {
                                self.refusals.push(Refusal::ProvenAmountContradicted {
                                    index,
                                    proven: txout.value,
                                    claimed: claimed.value,
                                });
                            }
                        }
                        Some(Resolved {
                            txout,
                            proven: true,
                        })
                    }
                }
                (None, Some(claimed)) => Some(Resolved {
                    txout: claimed.clone(),
                    proven: false,
                }),
                (None, None) => {
                    self.refusals.push(Refusal::NoPrevout { index });
                    None
                }
            };
            self.prevouts.push(resolved);
        }
    }

    /// Step 2: is this input ours, decided from the seed and the registration.
    ///
    /// The file's claim is only ever used as a hint about WHERE to look. What decides is
    /// re-derivation: the key at that path has to build the exact script the previous
    /// output is locked to. A claim that fails that test is a refusal rather than a shrug,
    /// because the only two files that carry one are a broken coordinator and an attack.
    fn classify(&mut self, index: usize, prevout: &TxOut) -> Ownership {
        let input = self.psbt.inputs[index].clone();
        let spk = &prevout.script_pubkey;
        let fingerprint = self.coordinator.device.fingerprint;
        let seed = self.coordinator.device.seed;
        let network = self.coordinator.network;

        if spk.is_p2tr() {
            for (internal_key, (_, (fp, path))) in &input.tap_key_origins {
                if *fp != fingerprint {
                    continue;
                }
                let Ok(key) = sign::derive_path(&seed, network, path) else {
                    continue;
                };
                let output_key = key.output_key(None);
                if ScriptBuf::new_p2tr_tweaked(output_key) == *spk
                    && key.internal_key() == *internal_key
                {
                    return Ownership::P2trKeyPath { output_key };
                }
                self.refusals.push(Refusal::ClaimedButNotOurs {
                    index,
                    path: path.clone(),
                });
            }
            return Ownership::Foreign;
        }

        for (pubkey, (fp, path)) in &input.bip32_derivation {
            if *fp != fingerprint {
                continue;
            }
            if spk.is_p2wsh() {
                // A P2WSH input is ours only if a REGISTERED wallet rebuilds this exact
                // script at the leaf the file names. The cosigner keys the PSBT carries are
                // not evidence of anything: believing them is the 2021 multisig attack.
                if let Some((_, located)) = multisig::locate_in(&self.coordinator.registry, path, spk)
                {
                    return Ownership::P2wsh {
                        our_key: located.our_key,
                        witness_script: located.witness_script,
                    };
                }
                self.refusals.push(Refusal::ClaimedButNotOurs {
                    index,
                    path: path.clone(),
                });
                continue;
            }

            let Ok(key) = sign::derive_path(&seed, network, path) else {
                continue;
            };
            let derived = key.public_key();
            let p2wpkh = ScriptBuf::new_p2wpkh(&derived.wpubkey_hash());
            if derived.0 == *pubkey && p2wpkh == *spk {
                return Ownership::P2wpkh { pubkey: derived };
            }
            // The pre-segwit shape, decided the same way and from the same seed. The
            // COMPRESSED key is the only form this wallet locks a BIP-44 leaf to, so an
            // uncompressed P2PKH coin of the same secret hashes to a different script and
            // is correctly not ours.
            if derived.0 == *pubkey && ScriptBuf::new_p2pkh(&derived.pubkey_hash()) == *spk {
                return Ownership::P2pkh { pubkey: derived };
            }
            if derived.0 == *pubkey
                && spk.is_p2sh()
                && input.redeem_script.as_ref() == Some(&p2wpkh)
                && ScriptBuf::new_p2sh(&p2wpkh.script_hash()) == *spk
            {
                return Ownership::P2shP2wpkh {
                    pubkey: derived,
                    redeem_script: p2wpkh,
                };
            }
            self.refusals.push(Refusal::ClaimedButNotOurs {
                index,
                path: path.clone(),
            });
        }
        Ownership::Foreign
    }

    /// Step 3: the device's signature, checked against a digest computed here.
    fn check_signature(
        &mut self,
        index: usize,
        ownership: &Ownership,
        resolved: &Resolved,
        cache: &mut SighashCache<&Transaction>,
        all_prevouts: Option<&[TxOut]>,
    ) -> bool {
        let input = self.psbt.inputs[index].clone();
        match ownership {
            Ownership::Foreign => false,
            Ownership::P2trKeyPath { output_key, .. } => {
                let Some(signature) = input.tap_key_sig else {
                    self.refusals.push(Refusal::SignatureMissing {
                        index,
                        key: format!("taproot output key {}", output_key.to_x_only_public_key()),
                    });
                    return false;
                };
                if !matches!(
                    signature.sighash_type,
                    TapSighashType::Default | TapSighashType::All
                ) {
                    self.refusals.push(Refusal::SighashNotWhitelisted {
                        index,
                        found: format!("{}", signature.sighash_type),
                    });
                    return false;
                }
                let Some(prevouts) = all_prevouts else {
                    self.refusals.push(Refusal::SighashUncomputable {
                        index,
                        reason: "BIP-341 commits to every input's previous output, and at \
                                 least one of them could not be resolved"
                            .to_string(),
                    });
                    return false;
                };
                let hash = match cache.taproot_key_spend_signature_hash(
                    index,
                    &Prevouts::All(prevouts),
                    signature.sighash_type,
                ) {
                    Ok(hash) => hash,
                    Err(error) => {
                        self.refusals.push(Refusal::SighashUncomputable {
                            index,
                            reason: error.to_string(),
                        });
                        return false;
                    }
                };
                self.verify_schnorr(index, hash.to_byte_array(), &signature, *output_key)
            }
            _ => {
                let (pubkey, digest) = match ownership {
                    Ownership::P2wpkh { pubkey } => (
                        *pubkey,
                        Digest::P2wpkh {
                            program: resolved.txout.script_pubkey.as_script(),
                            value: resolved.txout.value,
                        },
                    ),
                    // BIP-143's scriptCode for a P2SH-wrapped P2WPKH is built from the
                    // witness program inside the redeem script, not from the P2SH
                    // scriptPubKey the output is locked to.
                    Ownership::P2shP2wpkh {
                        pubkey,
                        redeem_script,
                    } => (
                        *pubkey,
                        Digest::P2wpkh {
                            program: redeem_script.as_script(),
                            value: resolved.txout.value,
                        },
                    ),
                    Ownership::P2wsh {
                        our_key,
                        witness_script,
                    } => (
                        *our_key,
                        Digest::P2wsh {
                            witness_script: witness_script.as_script(),
                            value: resolved.txout.value,
                        },
                    ),
                    // The pre-segwit algorithm hashes the SUBSCRIPT, and for a P2PKH coin
                    // the subscript is the previous output's own scriptPubKey - the script
                    // `classify` has just proven this key builds. There is no redeem script
                    // and no witness program here to pick the wrong one of.
                    Ownership::P2pkh { pubkey } => (
                        *pubkey,
                        Digest::Legacy {
                            subscript: resolved.txout.script_pubkey.as_script(),
                        },
                    ),
                    Ownership::Foreign | Ownership::P2trKeyPath { .. } => unreachable!(),
                };
                let Some(signature) = signature_for(&input, pubkey) else {
                    self.refusals.push(Refusal::SignatureMissing {
                        index,
                        key: pubkey.to_string(),
                    });
                    return false;
                };
                if signature.sighash_type != EcdsaSighashType::All {
                    self.refusals.push(Refusal::SighashNotWhitelisted {
                        index,
                        found: format!("{:?}", signature.sighash_type),
                    });
                    return false;
                }
                let Some(hash) = self.ecdsa_digest(index, cache, digest) else {
                    return false;
                };
                self.verify_ecdsa(index, hash, &signature, pubkey.0)
            }
        }
    }

    /// The digest an ECDSA signature on this input has to verify against, `SIGHASH_ALL`.
    ///
    /// Straight to `SighashCache`, which is what makes the independence this module claims
    /// real rather than stated: the device recomputes its digest through
    /// `notyas_core::sign`, and a defect shared between the signer and a verifier that
    /// called the same function would cancel out and be reported as agreement. `bitcoin`'s
    /// own implementations - of BIP-143 section "Specification", and of the pre-segwit
    /// algorithm - are the second opinion, and every argument handed to them here comes
    /// from this module's own reading of the file rather than from anything notyas-core
    /// concluded about it.
    ///
    /// `SIGHASH_ALL` is not a parameter. Every caller has already refused anything else -
    /// only `SIGHASH_ALL` commits to every output - so taking the type from the signature
    /// here would let the file choose the digest it is checked against. That matters more
    /// for the legacy algorithm than for BIP-143, because `SIGHASH_SINGLE` over an input
    /// with no matching output is where the pre-segwit index-overflow bug lives.
    fn ecdsa_digest(
        &mut self,
        index: usize,
        cache: &mut SighashCache<&Transaction>,
        digest: Digest<'_>,
    ) -> Option<[u8; 32]> {
        let hash = match digest {
            Digest::P2wpkh { program, value } => cache
                .p2wpkh_signature_hash(index, program, value, EcdsaSighashType::All)
                .map(|h| h.to_byte_array())
                .map_err(|e| e.to_string()),
            Digest::P2wsh {
                witness_script,
                value,
            } => cache
                .p2wsh_signature_hash(index, witness_script, value, EcdsaSighashType::All)
                .map(|h| h.to_byte_array())
                .map_err(|e| e.to_string()),
            // `to_u32` because the pre-segwit algorithm hashes four bytes of the flag while
            // only the low one is ever appended to a signature.
            Digest::Legacy { subscript } => cache
                .legacy_signature_hash(index, subscript, EcdsaSighashType::All.to_u32())
                .map(|h| h.to_byte_array())
                .map_err(|e| e.to_string()),
        };
        match hash {
            Ok(hash) => Some(hash),
            Err(reason) => {
                self.refusals
                    .push(Refusal::SighashUncomputable { index, reason });
                None
            }
        }
    }

    fn verify_ecdsa(
        &mut self,
        index: usize,
        digest: [u8; 32],
        signature: &ecdsa::Signature,
        pubkey: PublicKey,
    ) -> bool {
        if ecdsa_verifies(digest, signature, pubkey) {
            return true;
        }
        self.refusals.push(Refusal::SignatureDoesNotVerify {
            index,
            key: CompressedPublicKey(pubkey).to_string(),
            digest: hex(&digest),
        });
        false
    }

    fn verify_schnorr(
        &mut self,
        index: usize,
        digest: [u8; 32],
        signature: &taproot::Signature,
        output_key: TweakedPublicKey,
    ) -> bool {
        let secp = Secp256k1::verification_only();
        let key = output_key.to_x_only_public_key();
        if secp
            .verify_schnorr(&signature.signature, &Message::from_digest(digest), &key)
            .is_ok()
        {
            return true;
        }
        self.refusals.push(Refusal::SignatureDoesNotVerify {
            index,
            key: format!("taproot output key {key}"),
            digest: hex(&digest),
        });
        false
    }

    /// Step 4a: add the signatures a coordinator would add.
    ///
    /// Only ever for a wallet whose seed this side holds and whose key is one of the ones
    /// the witness script names. The device's own leg is never supplied this way: if it is
    /// missing, that is the finding, and papering over it would destroy the evidence.
    fn complete_multisig(
        &mut self,
        index: usize,
        witness_script: &ScriptBuf,
        resolved: &Resolved,
        cache: &mut SighashCache<&Transaction>,
    ) -> Vec<String> {
        let Some((threshold, keys)) = read_multisig(witness_script) else {
            self.refusals.push(Refusal::ConsensusShape {
                reason: format!("input {index}: the witness script is not an M-of-N multisig"),
            });
            return Vec::new();
        };
        let Some(digest) = self.ecdsa_digest(
            index,
            cache,
            Digest::P2wsh {
                witness_script: witness_script.as_script(),
                value: resolved.txout.value,
            },
        ) else {
            return Vec::new();
        };

        // Every leg already in the file is checked before it is counted, and a leg that
        // does not verify is taken out rather than left to be finalized. A coordinator's
        // job is to assemble a witness that will run, and an M-of-N whose other M-1 legs
        // arrived as noise extracts, prices and reads as ACCEPTED while being unspendable:
        // the only signature this tool used to look at was its own device's.
        for key in &keys {
            let Some(signature) = signature_for(&self.psbt.inputs[index], *key) else {
                continue;
            };
            if signature.sighash_type == EcdsaSighashType::All
                && ecdsa_verifies(digest, &signature, key.0)
            {
                continue;
            }
            self.psbt.inputs[index]
                .partial_sigs
                .remove(&notyas_core::bitcoin::PublicKey::from(*key));
            self.refusals.push(Refusal::SignatureDoesNotVerify {
                index,
                key: key.to_string(),
                digest: hex(&digest),
            });
        }

        let input = self.psbt.inputs[index].clone();
        let mut added = Vec::new();
        let mut missing = Vec::new();
        let mut have = keys
            .iter()
            .filter(|key| signature_for(&input, **key).is_some())
            .count();

        for key in &keys {
            if have >= usize::from(threshold) {
                break;
            }
            if signature_for(&input, *key).is_some() {
                continue;
            }
            let Some((fingerprint, path)) = input.bip32_derivation.get(&key.0) else {
                missing.push(key.to_string());
                continue;
            };
            let Some(signer) = self
                .coordinator
                .cosigners
                .iter()
                .find(|s| s.fingerprint == *fingerprint)
            else {
                missing.push(key.to_string());
                continue;
            };
            let Ok(secret) = sign::derive_path(&signer.seed, self.coordinator.network, path) else {
                missing.push(key.to_string());
                continue;
            };
            if secret.public_key() != *key {
                missing.push(key.to_string());
                continue;
            }
            let Signature::Ecdsa(signature) = secret.sign(&SignHash::SegwitV0 {
                hash: SegwitV0Sighash::from_byte_array(digest),
                sighash_type: EcdsaSighashType::All,
            }) else {
                unreachable!("a segwit v0 digest is signed with ECDSA");
            };
            self.psbt.inputs[index]
                .partial_sigs
                .insert(notyas_core::bitcoin::PublicKey::from(*key), signature);
            added.push(signer.label.clone());
            have += 1;
        }

        if have < usize::from(threshold) {
            self.refusals.push(Refusal::Incomplete {
                index,
                have,
                need: usize::from(threshold),
                missing,
            });
        }
        added
    }

    /// Step 4b: turn verified signatures into the witness a node would run, and record
    /// that this side - not the file - is what authorised the input.
    ///
    /// The only place `authorized` is ever set. Every path that returns early leaves it
    /// false, which is what makes "psbtgen built this witness out of signatures it checked"
    /// the precondition for the transaction being extracted and priced at all.
    fn finalize(&mut self, index: usize, ownership: &Ownership) {
        let input = self.psbt.inputs[index].clone();
        let witness = match ownership {
            Ownership::Foreign => return,
            // The one shape here with no witness, so it finishes and returns rather than
            // falling through to the assignment below: `<signature> <pubkey>` is the whole
            // of the input script that P2PKH's OP_DUP OP_HASH160 ... OP_CHECKSIG runs
            // against, and an empty witness left behind as well would serialise the
            // transaction under BIP-141 for an input with no witness data to carry.
            Ownership::P2pkh { pubkey } => {
                let Some(signature) = signature_for(&input, *pubkey) else {
                    return;
                };
                self.psbt.inputs[index].final_script_sig =
                    Some(legacy_script_sig(&signature, *pubkey));
                self.authorized[index] = true;
                return;
            }
            Ownership::P2wpkh { pubkey } | Ownership::P2shP2wpkh { pubkey, .. } => {
                let Some(signature) = signature_for(&input, *pubkey) else {
                    return;
                };
                if let Ownership::P2shP2wpkh { redeem_script, .. } = ownership {
                    let mut push = PushBytesBuf::new();
                    push.extend_from_slice(redeem_script.as_bytes())
                        .expect("a P2WPKH redeem script is 22 bytes");
                    self.psbt.inputs[index].final_script_sig =
                        Some(Builder::new().push_slice(push).into_script());
                }
                Witness::from_slice(&[signature.serialize().to_vec(), pubkey.to_bytes().to_vec()])
            }
            Ownership::P2trKeyPath { .. } => {
                let Some(signature) = input.tap_key_sig else {
                    return;
                };
                Witness::from_slice(&[signature.serialize().to_vec()])
            }
            Ownership::P2wsh { witness_script, .. } => {
                let Some((threshold, keys)) = read_multisig(witness_script) else {
                    return;
                };
                // OP_CHECKMULTISIG pops one item too many, and the witness stack has to
                // begin with the empty element that absorbs it. The signatures then follow
                // in the order their keys appear in the script, which for `sortedmulti` is
                // BIP-67 order - a set of correct signatures in the wrong order does not
                // validate.
                let mut stack: Vec<Vec<u8>> = vec![Vec::new()];
                for key in &keys {
                    if stack.len() > usize::from(threshold) {
                        break;
                    }
                    if let Some(signature) = signature_for(&input, *key) {
                        stack.push(signature.serialize().to_vec());
                    }
                }
                if stack.len() <= usize::from(threshold) {
                    return;
                }
                stack.push(witness_script.to_bytes());
                Witness::from_slice(&stack)
            }
        };
        self.psbt.inputs[index].final_script_witness = Some(witness);
        self.authorized[index] = true;
    }

    /// What the transaction really pays the miner: every resolved input, minus every output.
    fn fee(&self) -> Option<Amount> {
        let mut input_total = Amount::ZERO;
        for resolved in &self.prevouts {
            input_total = input_total.checked_add(resolved.as_ref()?.txout.value)?;
        }
        let mut output_total = Amount::ZERO;
        for output in &self.psbt.unsigned_tx.output {
            output_total = output_total.checked_add(output.value)?;
        }
        input_total.checked_sub(output_total)
    }

    /// Step 5: extract, and check the shape of what comes out.
    fn extract(&mut self, fee: Option<Amount>) -> Option<Extracted> {
        if !self.refusals.is_empty() {
            // Extraction after a refusal would print a txid for a transaction nobody should
            // broadcast, which is exactly the kind of half-answer this tool exists to stop.
            return None;
        }
        let tx = match self.psbt.clone().extract_tx() {
            Ok(tx) => tx,
            Err(error) => {
                self.refusals.push(Refusal::ExtractionFailed {
                    reason: error.to_string(),
                });
                return None;
            }
        };
        for reason in consensus_shape(&tx, &self.prevouts) {
            self.refusals.push(Refusal::ConsensusShape { reason });
        }
        let fee = fee?;
        let vsize = tx.vsize();
        Some(Extracted {
            txid: tx.compute_txid(),
            weight: tx.weight(),
            vsize,
            fee_rate: fee.to_sat() as f64 / vsize as f64,
            raw: notyas_core::bitcoin::consensus::serialize(&tx),
        })
    }
}

/// The rules a transaction can be judged against without a chain to look at.
///
/// Not a full validation and not pretending to be one: no script is executed and no UTXO
/// set is consulted. What it does cover is every way a coordinator's own assembly can
/// produce something no node would relay, which is the failure this harness could otherwise
/// mistake for success.
fn consensus_shape(tx: &Transaction, prevouts: &[Option<Resolved>]) -> Vec<String> {
    let mut problems = Vec::new();
    if tx.input.is_empty() {
        problems.push("it has no inputs".to_string());
    }
    if tx.output.is_empty() {
        problems.push("it has no outputs".to_string());
    }
    let mut seen: BTreeMap<OutPoint, usize> = BTreeMap::new();
    for (index, input) in tx.input.iter().enumerate() {
        if let Some(first) = seen.insert(input.previous_output, index) {
            problems.push(format!(
                "inputs {first} and {index} spend the same outpoint {}",
                input.previous_output
            ));
        }
    }
    if tx.base_size() < MIN_BASE_SIZE {
        problems.push(format!(
            "its non-witness serialization is {} bytes, and BIP-141 rejects anything under {MIN_BASE_SIZE}",
            tx.base_size()
        ));
    }
    if tx.weight() > MAX_STANDARD_WEIGHT {
        problems.push(format!(
            "it weighs {} units, over the {} a node will relay",
            tx.weight().to_wu(),
            MAX_STANDARD_WEIGHT.to_wu()
        ));
    }
    for (index, output) in tx.output.iter().enumerate() {
        let dust = output.script_pubkey.minimal_non_dust();
        if output.value < dust {
            problems.push(format!(
                "output {index} pays {}, under the {dust} dust threshold for its script",
                output.value
            ));
        }
    }
    // Nothing authorises an input with neither a witness nor a scriptSig. This is the case
    // a foreign input produces - one the device was never going to sign and this side
    // cannot sign either - and without this check such a file would extract cleanly and be
    // reported as accepted, which is the one wrong answer this whole tool exists to avoid.
    for (index, input) in tx.input.iter().enumerate() {
        if input.witness.is_empty() && input.script_sig.is_empty() {
            problems.push(format!(
                "input {index} carries neither a witness nor a scriptSig, so nothing \
                 authorises it; a coordinator still has to collect that signature"
            ));
        }
    }
    // A NATIVE segwit input's scriptSig must be empty. A non-empty one there means the
    // witness is not what authorises the spend, and the signature checked above is not the
    // thing being run. The test is on the witness program rather than on "anything but
    // P2SH", because the two shapes that are not native segwit carry a scriptSig
    // legitimately: the P2SH wrapper pushes its redeem script, and a pre-segwit input is
    // authorised by its scriptSig and by nothing else.
    for (index, input) in tx.input.iter().enumerate() {
        let Some(Some(resolved)) = prevouts.get(index) else {
            continue;
        };
        if !input.script_sig.is_empty() && resolved.txout.script_pubkey.is_witness_program() {
            problems.push(format!(
                "input {index} spends a native segwit output but carries a scriptSig"
            ));
        }
    }
    problems
}

/// Does this signature verify against this digest under this key?
///
/// `secp256k1_ecdsa_verify` is the whole check and is deliberately not wrapped in anything.
/// It rejects a signature whose `s` is above the group's half order, which is BIP-62 rule 5
/// and the reason this file carries no malleability arithmetic of its own; and the DER
/// rules are enforced one layer earlier still, by `bitcoin::ecdsa::Signature::from_slice`
/// in the PSBT decoder, so a truncated or over-long blob never reaches a `Signature` value
/// to be checked here at all.
///
/// A free function rather than a method: it must stay incapable of recording a verdict, so
/// that the two callers - the one that refuses and the one that quietly drops a bad
/// multisig leg - cannot drift into disagreeing about what verification means.
fn ecdsa_verifies(digest: [u8; 32], signature: &ecdsa::Signature, pubkey: PublicKey) -> bool {
    Secp256k1::verification_only()
        .verify_ecdsa(&Message::from_digest(digest), &signature.signature, &pubkey)
        .is_ok()
}

/// The scriptSig that authorises a P2PKH spend: the signature, then the key it sits under.
///
/// A free function beside the witness stacks `finalize` builds, and for the same reason
/// they are spelled out there: the order is consensus rather than preference.
/// `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG` hashes the top of the stack and
/// then checks the signature beneath it, so the key is what has to be pushed last.
fn legacy_script_sig(signature: &ecdsa::Signature, pubkey: CompressedPublicKey) -> ScriptBuf {
    let mut sig = PushBytesBuf::new();
    sig.extend_from_slice(signature.serialize().as_ref())
        .expect("a DER-encoded ECDSA signature is at most 73 bytes");
    let mut key = PushBytesBuf::new();
    key.extend_from_slice(&pubkey.to_bytes())
        .expect("a compressed public key is 33 bytes");
    Builder::new().push_slice(sig).push_slice(key).into_script()
}

/// The signature this input carries for `key`, if any.
fn signature_for(input: &Input, key: CompressedPublicKey) -> Option<ecdsa::Signature> {
    input
        .partial_sigs
        .get(&notyas_core::bitcoin::PublicKey::from(key))
        .copied()
}

/// `(M, keys)` of an `OP_M <key>... OP_N OP_CHECKMULTISIG` script, read from the script
/// itself.
///
/// Read rather than taken from the registration on purpose: this is the script the node
/// will run, and the witness stack has to be built in ITS key order. Rebuilding the order
/// from the registration would work right up until the two disagreed, which is the one case
/// worth catching.
fn read_multisig(script: &ScriptBuf) -> Option<(u8, Vec<CompressedPublicKey>)> {
    let mut threshold = None;
    let mut keys = Vec::new();
    for instruction in script.instructions() {
        match instruction.ok()? {
            Instruction::Op(op) => {
                let raw = op.to_u8();
                // OP_1 through OP_16 encode 1..16 as 0x51..0x60.
                if (0x51..=0x60).contains(&raw) && threshold.is_none() {
                    threshold = Some(raw - 0x50);
                }
            }
            Instruction::PushBytes(push) => {
                keys.push(CompressedPublicKey::from_slice(push.as_bytes()).ok()?);
            }
        }
    }
    let threshold = threshold?;
    if keys.is_empty() || usize::from(threshold) > keys.len() {
        return None;
    }
    Some((threshold, keys))
}

/// How a verdict line names an input's script type.
fn kind_of(ownership: &Ownership, prevout: &TxOut) -> &'static str {
    match ownership {
        Ownership::P2pkh { .. } => "p2pkh",
        Ownership::P2wpkh { .. } => "p2wpkh",
        Ownership::P2shP2wpkh { .. } => "p2sh-p2wpkh",
        Ownership::P2wsh { .. } => "p2wsh-multisig",
        Ownership::P2trKeyPath { .. } => "p2tr-keypath",
        Ownership::Foreign => {
            let spk = &prevout.script_pubkey;
            if spk.is_p2wpkh() {
                "p2wpkh"
            } else if spk.is_p2wsh() {
                "p2wsh"
            } else if spk.is_p2tr() {
                "p2tr"
            } else if spk.is_p2sh() {
                "p2sh"
            } else {
                "other"
            }
        }
    }
}

/// How a divergence names an output's destination.
///
/// The address where the script is one, and the raw script where it is not: an output an
/// operator cannot be shown as an address is precisely the one worth printing in full,
/// since it is either non-standard or an OP_RETURN and either way it is not something they
/// approved by reading an address off a card.
fn destination(script: &ScriptBuf, network: Network) -> String {
    match Address::from_script(script, network) {
        Ok(address) => address.to_string(),
        Err(_) => format!("the script {}", hex(script.as_bytes())),
    }
}

fn hex(bytes: &[u8]) -> String {
    use notyas_core::bitcoin::hex::DisplayHex as _;
    bytes.to_lower_hex_string()
}
