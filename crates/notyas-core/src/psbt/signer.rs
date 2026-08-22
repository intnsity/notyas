// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Signing, and the gate that runs before anything is allowed to leave.
//!
//! [`sign`] signs exactly the inputs an [`Inspection`] classified as ours, and nothing
//! else. It is not a policy engine and it does not repeat the checks: an inspection is the
//! evidence that the checks passed, and [`sign`] establishes that the inspection belongs
//! to this PSBT by recomputing its digest. Since [`inspect`](super::inspect) is pure, a
//! matching digest is the same statement as re-running it, at the cost of one hash.
//!
//! # Atomic by construction
//!
//! [`sign`] takes the PSBT by shared reference and returns a new one. A refusal anywhere -
//! including in the post-sign gate, which runs after every signature has been produced -
//! therefore yields no partially signed PSBT at all. Signing in place would leave the
//! caller holding a half-signed file after a failure it was supposed to be protected from.
//! It is also what makes one approval over many inputs safe to offer at all: a batch is N
//! signatures or none, never the first three of eight with a refusal after them.
//!
//! # Derive-and-compare
//!
//! Before signing, this module derives the key at the path a [`Claim::Ours`] carries and
//! rebuilds the script that key can spend; if it is not the script the input actually
//! locks, the answer is [`SignFailure::OriginDoesNotDeriveScript`]. That is ARCH check 1's
//! other half.
//!
//! It is no longer the ONLY place that half runs, and the change is worth stating because
//! this module's authority is what was copied. Since 2026-08-21 `checks::inspect_with_accounts`
//! makes the same comparison against an [`Account`](crate::derive::Account) - an account
//! xpub only the seed could have produced - so an input whose origin does not derive its own
//! script is [`Claim::Foreign`] before any review screen counts it, rather than a row in the
//! approved batch that this function refuses afterwards. The two are the same test against
//! two values, deliberately: an account can answer with no seed in scope and cannot answer
//! for a P2WSH leaf or for an account the session did not open, and where it cannot answer
//! the claim arrives here unproven and this is where it stops. Neither is a substitute for
//! the other, and this one is the last word.
//!
//! # The post-sign gate
//!
//! [`verify_signatures`] re-verifies the signatures THIS DEVICE made against a digest it
//! recomputes from the PSBT alone: a fresh [`SighashCache`], prevouts re-read from the
//! input maps rather than from the plan, and - for taproot - the output key taken out of
//! the scriptPubKey rather than out of any derivation. Nothing it uses comes from the
//! signing path except rust-bitcoin's digest implementation itself, which is what
//! notyas-wallet's miniscript interpreter is there to be independent of
//! (ARCHITECTURE.md 2.4, WALLET-API.md gate 11). Under a deterministic nonce a faulted
//! digest is a key-recovery event rather than an invalid transaction, so this is a
//! security control and its result is returned as data, not asserted and discarded.
//!
//! "This device's" is load bearing and is not a weakening: `partial_sigs` is a map a
//! coordinator writes into, so verifying every entry in it would let anyone veto a
//! transaction the user approved by adding one junk signature, and would report the
//! refusal as this device's own signature failing. See [`verify_signatures`] for what
//! happens to the entries it does not check, and why they are left exactly as they came.

use alloc::vec::Vec;
use core::fmt;

use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, XOnlyPublicKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{PublicKey, Script, ScriptBuf, Transaction, TxOut};

use crate::derive::secp;
use crate::sign::{derive_path, SignError, Signature};

use super::checks::{Check, Claim, ClaimedKey, Inspection, ScriptKind};
use super::codec;

/// What the post-sign gate actually verified.
///
/// Rendered in the deliver screen's small print and asserted in CI. A gate whose result
/// nobody can see is a gate nobody can tell has stopped running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignReport {
    pub signatures_added: u16,
    pub signatures_verified: u16,
    /// Input indexes, in order, that this device signed.
    pub inputs_signed: Vec<u16>,
}

/// A signed PSBT and the gate report that let it out.
///
/// The two travel together because a signed PSBT without the evidence that its signatures
/// were checked is exactly the artefact the gate exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    psbt: Psbt,
    report: SignReport,
}

impl Signed {
    pub fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    pub fn into_psbt(self) -> Psbt {
        self.psbt
    }

    pub fn report(&self) -> &SignReport {
        &self.report
    }
}

/// Why signing did not happen, or did not survive its own gate.
#[derive(Debug)]
pub enum SignFailure {
    /// The inspection was taken from different bytes. Either the caller paired the wrong
    /// two values or the PSBT changed between review and signature; both are the same
    /// refusal, because the device cannot tell them apart and must not sign either.
    InspectionDoesNotMatchPsbt,
    /// No input in this PSBT is ours. Not an error in the file: a wallet mismatch, which
    /// notyas-wallet turns into the wrong-wallet screen with a suggestion.
    NothingToSign,
    /// The claimed path derives a key that cannot spend this input. The 2019 Coldcard
    /// change-path ransom, and every forged origin, ends here.
    OriginDoesNotDeriveScript { index: u16 },
    /// BIP32 refused a step of a path that [`inspect`](super::inspect) accepted the shape
    /// of. Unreachable for any path this device produces; a PSBT can still ask for one.
    Derivation { index: u16, error: SignError },
    /// The sighash could not be computed.
    Digest { index: u16, error: SignError },
    /// The gate could not re-read an input's prevout out of the PSBT. Unreachable once the
    /// inspection binding holds - [`inspect`](super::inspect) refuses a PSBT with an input
    /// it cannot resolve a prevout for, and the binding says this is that PSBT - and it is
    /// a variant of its own rather than a reused one so that
    /// [`SignFailure::InspectionDoesNotMatchPsbt`] means one thing only.
    PrevoutUnavailable { index: u16 },
    /// A signature does not verify against a digest recomputed from the PSBT. Under a
    /// deterministic nonce this is a fault-injection signal, not a formality.
    SignatureVerificationFailed { index: u16 },
    /// The inputs this device signed are not the inputs the review named.
    ///
    /// One approval covers a LIST ([`Inspection::signable_input_indexes`]), and this is
    /// where the device proves it signed that list and nothing else: same indexes, same
    /// order, none added and none dropped. `reviewed` and `signed` are the two counts a
    /// bug report needs; a mismatch of equal length is caught too, because what is compared
    /// is the lists and not the numbers.
    ///
    /// Unreachable while [`sign`]'s loop and
    /// [`Inspection::signable_input_indexes`] read the same `Claim::Ours` predicate, and
    /// that is exactly why it is a refusal rather than a debug assertion. A batch is where
    /// "approve once, sign N times" lives; the day one of those two filters is widened
    /// without the other, the file must stop at the device rather than leave it carrying a
    /// signature no approval screen ever described.
    BatchDiffersFromReview { reviewed: u16, signed: u16 },
    /// An input this device signed carries no signature OF OURS afterwards - the entry
    /// under the key we signed with is not in `partial_sigs`, or the taproot key-path
    /// signature is gone. Named by key rather than by "the map is empty", because a
    /// coordinator's own entry would satisfy the weaker test while the user's file is
    /// still unsigned. Only reachable from a bug in this module or from a caller pairing a
    /// PSBT with an inspection of a version that has since lost its signatures, and it is a
    /// refusal rather than a debug assertion because the consequence of shipping past it is
    /// an unsigned file the user believes is signed.
    SignatureMissing { index: u16 },
}

impl SignFailure {
    /// Which of ARCHITECTURE.md 5.3's checks this belongs to.
    pub fn check(&self) -> Check {
        match self {
            SignFailure::InspectionDoesNotMatchPsbt
            | SignFailure::SignatureVerificationFailed { .. }
            | SignFailure::BatchDiffersFromReview { .. }
            | SignFailure::SignatureMissing { .. } => Check::PostSign,
            SignFailure::NothingToSign
            | SignFailure::OriginDoesNotDeriveScript { .. }
            | SignFailure::Derivation { .. } => Check::InputOwnership,
            SignFailure::Digest { .. } | SignFailure::PrevoutUnavailable { .. } => Check::Prevouts,
        }
    }
}

impl fmt::Display for SignFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.check())?;
        match self {
            SignFailure::InspectionDoesNotMatchPsbt => write!(
                f,
                "this transaction is not the one that was reviewed"
            ),
            SignFailure::NothingToSign => {
                write!(f, "none of these inputs belongs to this wallet")
            }
            SignFailure::OriginDoesNotDeriveScript { index } => write!(
                f,
                "the key named for input {index} cannot spend it"
            ),
            SignFailure::Derivation { index, error } => {
                write!(f, "input {index} claims a path this device cannot walk: {error}")
            }
            SignFailure::Digest { index, error } => {
                write!(f, "input {index} could not be hashed for signing: {error}")
            }
            SignFailure::PrevoutUnavailable { index } => {
                write!(f, "input {index} does not say what it is spending")
            }
            SignFailure::SignatureVerificationFailed { index } => write!(
                f,
                "the signature this device produced for input {index} did not verify"
            ),
            SignFailure::SignatureMissing { index } => {
                write!(f, "input {index} was signed and carries no signature")
            }
            SignFailure::BatchDiffersFromReview { reviewed, signed } => write!(
                f,
                "this device signed {signed} inputs and {reviewed} were reviewed"
            ),
        }
    }
}

impl core::error::Error for SignFailure {}

/// Sign every input the inspection classified as ours, then verify what was produced.
///
/// The seed is the only secret this function touches, and it never leaves it: each key is
/// derived, used and dropped inside the loop, and `SecretSigningKey` wipes on drop.
///
/// # One approval, N signatures (0.2.0-G10)
///
/// This IS the batch: there is no per-input entry point and never was one, so "Sign All"
/// is not a second mode with a second set of checks to keep in step. Everything an
/// inspection establishes it establishes about the whole file - the sighash whitelist, the
/// derive-and-compare below, check 2's rule about amounts a signature of ours does not
/// cover - and one refusal anywhere refuses the file, because [`sign`] returns a new PSBT
/// and a partially signed one is not a thing it can produce.
///
/// What a batch changes is not the signing, it is the approval: the user says yes once and
/// gets [`Inspection::signable_input_indexes`]`.len()` signatures. So the last thing this
/// function does before handing the file back is prove that the inputs it signed are that
/// list, in that order ([`SignFailure::BatchDiffersFromReview`]). The review data the
/// screen shows comes off the same `inspection` value, which this function refuses to be
/// paired with any other bytes, so there is no second object for "what was approved" and
/// "what was signed" to drift apart through.
///
/// The arithmetic underneath a batch is already pinned to published multi-input vectors:
/// `tests/signing_vectors.rs` runs BIP-341's `keyPathSpending[0]` - nine spent outputs and
/// seven key-path inputs of one transaction - and BIP-143's own two-input worked examples,
/// which between them are what a shared [`SighashCache`] across many inputs has to
/// reproduce.
pub fn sign(
    psbt: &Psbt,
    inspection: &Inspection,
    seed: &[u8; 64],
) -> Result<Signed, SignFailure> {
    if codec::psbt_id(psbt) != inspection.psbt_id() {
        return Err(SignFailure::InspectionDoesNotMatchPsbt);
    }

    let mut out = psbt.clone();
    let tx: Transaction = psbt.unsigned_tx.clone();
    // An entry here can rest on `witness_utxo` alone, and `inspect` has already decided
    // that it may: it refuses any file where a signature of ours would cover one input's
    // amount while another input's amount rests on nothing
    // (`CheckFailure::UnprovenAmountBesideOurSignature`, `MissingPreviousTransaction`). So
    // by the time this set is built, every unproven amount in it is one a signature of ours
    // is about to make binding, and there are exactly two ways that is true.
    //
    // Taproot: BIP-341 hashes every prevout amount into the digest, so one false claim
    // anywhere produces signatures that verify against nothing.
    //
    // A single-input transaction: the only amount is the one the only signature commits to
    // under BIP-143, so a lie invalidates it, and no second signature exists anywhere in
    // the transaction for a later round to combine the harvested one with. That escape is
    // keyed on the TRANSACTION's input count and never on a count of inputs the file claims
    // are ours - see `checks::our_signatures_bind_every_amount`.
    //
    // Either way the coordinator's reward for lying is a transaction that cannot confirm,
    // never a spend of ours under an amount nobody proved. Taproot is also the only family
    // that reads this set at all.
    let prevouts: Vec<TxOut> = inspection
        .inputs
        .iter()
        .map(|facts| TxOut {
            value: facts.value,
            script_pubkey: facts.script_pubkey.clone(),
        })
        .collect();
    let all_prevouts = Prevouts::All(&prevouts);

    // One cache for the whole transaction: BIP-143 and BIP-341 both reuse midstate hashes
    // across inputs, and a cache per input would make signing quadratic in the input count
    // (crate::sign::SpendKind::sign_hash).
    let mut cache = SighashCache::new(&tx);
    let mut inputs_signed = Vec::new();
    let mut produced = Vec::new();

    for facts in &inspection.inputs {
        let Claim::Ours { path, .. } = &facts.claim else {
            continue;
        };
        let index = facts.index;
        let i = usize::from(index);
        let key = derive_path(seed, inspection.network, path)
            .map_err(|error| SignFailure::Derivation { index, error })?;

        let spend = match facts.kind {
            ScriptKind::P2wpkh => {
                let derived = ScriptBuf::new_p2wpkh(&key.public_key().wpubkey_hash());
                if derived != facts.script_pubkey {
                    return Err(SignFailure::OriginDoesNotDeriveScript { index });
                }
                crate::sign::SpendKind::P2wpkh {
                    script_pubkey: &facts.script_pubkey,
                    value: facts.value,
                    sighash_type: EcdsaSighashType::All,
                }
            }
            ScriptKind::P2shP2wpkh => {
                let derived = ScriptBuf::new_p2wpkh(&key.public_key().wpubkey_hash());
                // The wrapper is invisible to BIP-143: what is hashed is the redeem
                // script, so proving OUR key builds that exact redeem script is what ties
                // the signature to the P2SH address the input actually holds.
                if facts.redeem_script.as_deref() != Some(derived.as_script())
                    || ScriptBuf::new_p2sh(&derived.script_hash()) != facts.script_pubkey
                {
                    return Err(SignFailure::OriginDoesNotDeriveScript { index });
                }
                crate::sign::SpendKind::P2shP2wpkh {
                    redeem_script: facts
                        .redeem_script
                        .as_deref()
                        .expect("checked immediately above"),
                    value: facts.value,
                    sighash_type: EcdsaSighashType::All,
                }
            }
            ScriptKind::P2wsh => {
                // `inspect` proved that a REGISTERED wallet builds this script at the leaf
                // the file claimed, and put its rebuild here. This is the other half, the
                // half that needs a seed: the key we are about to sign with has to be the
                // key the REGISTRATION puts in that script, not the key the PSBT named.
                // Comparing against the binding rather than against `Claim::Ours`'s key is
                // what makes that distinction real.
                let binding = facts
                    .multisig
                    .as_ref()
                    .ok_or(SignFailure::OriginDoesNotDeriveScript { index })?;
                if key.public_key() != binding.our_key {
                    return Err(SignFailure::OriginDoesNotDeriveScript { index });
                }
                // Cheap, and it is the statement the signature will be checked against: the
                // script code being hashed has to be the one this input is locked to.
                if ScriptBuf::new_p2wsh(&binding.witness_script.wscript_hash())
                    != facts.script_pubkey
                {
                    return Err(SignFailure::OriginDoesNotDeriveScript { index });
                }
                crate::sign::SpendKind::P2wsh {
                    witness_script: binding.witness_script.as_script(),
                    value: facts.value,
                    sighash_type: EcdsaSighashType::All,
                }
            }
            ScriptKind::P2tr => {
                let derived = ScriptBuf::new_p2tr_tweaked(key.output_key(facts.tap_merkle_root));
                if derived != facts.script_pubkey {
                    return Err(SignFailure::OriginDoesNotDeriveScript { index });
                }
                crate::sign::SpendKind::P2trKeyPath {
                    prevouts: &all_prevouts,
                    merkle_root: facts.tap_merkle_root,
                    sighash_type: TapSighashType::Default,
                }
            }
            // `inspect` refuses a claim on any other script kind, so this is a
            // contradiction in the inspection rather than something a PSBT can cause.
            _ => return Err(SignFailure::OriginDoesNotDeriveScript { index }),
        };

        let hash = spend
            .sign_hash(&mut cache, i)
            .map_err(|error| SignFailure::Digest { index, error })?;

        // The record the gate is checked against. It is built here, from the key that was
        // actually used, rather than reconstructed afterwards from the PSBT: a
        // `partial_sigs` map holds whatever the coordinator put there too, and "which of
        // these did we make" is a question only this loop can answer.
        match key.sign(&hash) {
            Signature::Ecdsa(signature) => {
                let pubkey = PublicKey::from(key.public_key());
                out.inputs[i].partial_sigs.insert(pubkey, signature);
                produced.push(Produced::Ecdsa { index, pubkey });
            }
            Signature::Schnorr(signature) => {
                out.inputs[i].tap_key_sig = Some(signature);
                produced.push(Produced::TaprootKeyPath { index });
            }
        }
        inputs_signed.push(index);
    }

    if inputs_signed.is_empty() {
        return Err(SignFailure::NothingToSign);
    }

    // The batch gate. `inputs_signed` was built by the loop above from what it actually
    // signed; `reviewed` is rebuilt here from the inspection the approval screen rendered.
    // Comparing them is one allocation and one comparison, and it is the only place the
    // device can state, rather than assume, that one approval bought exactly the
    // signatures it described.
    let reviewed = inspection.signable_input_indexes();
    if inputs_signed != reviewed {
        return Err(SignFailure::BatchDiffersFromReview {
            reviewed: reviewed.len() as u16,
            signed: inputs_signed.len() as u16,
        });
    }

    // Checking by key subsumes the older "this input has some signature on it" test, and
    // is what that test should always have been: an input can carry a foreign entry and
    // still be missing ours, so a non-empty map was never evidence that this device's
    // signature is there. `verify_produced` answers SignatureMissing for exactly that.
    let signatures_added = produced.len() as u16;
    let signatures_verified = verify_produced(&out, &produced)?;

    Ok(Signed {
        psbt: out,
        report: SignReport {
            signatures_added,
            signatures_verified,
            inputs_signed,
        },
    })
}

/// One signature this device is answerable for, and the key it has to verify under.
///
/// The gate checks exactly these. `partial_sigs` is a map, keyed by public key, that
/// anyone who can hand the device a file may write into, so "which signature is ours" is
/// answered by naming the key rather than by iterating the map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Produced {
    /// The `partial_sigs` entry under this exact key.
    Ecdsa { index: u16, pubkey: PublicKey },
    /// The input's single `tap_key_sig`. Key-path taproot has one signer by construction,
    /// so there is no key to name and nothing else could have written it.
    TaprootKeyPath { index: u16 },
}

impl Produced {
    fn index(self) -> u16 {
        match self {
            Produced::Ecdsa { index, .. } | Produced::TaprootKeyPath { index } => index,
        }
    }
}

/// The post-sign gate: re-verify the signatures this device made against a digest
/// recomputed from `psbt` alone.
///
/// Returns how many verified. Public because it is a control the wallet layer re-runs and
/// because the m6 mutation test - corrupt a signature, watch this catch it - is the
/// standing proof that it is wired.
///
/// What "independent" means here, exactly: the transaction, the prevouts, the script code
/// and the taproot output key are all re-read from the PSBT, and the taproot output key
/// comes from the scriptPubKey rather than from any derivation, so a wrong tweak cannot
/// verify against itself. It shares rust-bitcoin's digest implementation with the signing
/// path; being independent of THAT is notyas-wallet's miniscript interpreter, and neither
/// gate is a substitute for the other.
///
/// # The inspection has to belong to this PSBT
///
/// `inspection` decides which inputs are checked and under which keys, so an inspection
/// taken from other bytes does not merely give a wrong answer, it asks the wrong question,
/// and when it names more inputs than this PSBT has it asks that question of an input that
/// does not exist. The binding is [`Inspection::unsigned_id`] rather than
/// [`Inspection::psbt_id`]: signatures are what the gate is here to check, so it must
/// admit a file that has acquired some since review, and nothing else (`codec::unsigned_id`).
/// A mismatch is [`SignFailure::InspectionDoesNotMatchPsbt`], never a verification
/// failure: "you handed me the wrong pair of values" and "a signature on this device's own
/// transaction did not verify" are a caller bug and a fault-injection signal respectively,
/// and the wallet layer must not show one screen for both.
///
/// # Foreign entries in `partial_sigs`
///
/// Anyone who can hand this device a file can put an entry in that map under any key, so
/// the gate checks the entry under each of our inputs' claimed key and leaves every other
/// entry alone - unverified, unjudged, and above all still there when the PSBT is
/// re-emitted. Two reasons, pointing the same way. This device is not the authority on
/// another signer's work: it does not know that signer's sighash type, its script path, or
/// whether the entry was even meant for this transaction, so a failure it declared there
/// would be an opinion, not a finding. And refusing on one would hand any coordinator a
/// free veto over a transaction the user approved - one junk entry and a correct device
/// declines to sign - which is a denial of service against the user, paid for out of the
/// device's own gate. Dropping them instead of refusing would be worse still: this device
/// is a participant in a multi-signer ceremony, not its arbiter, and a cosigner's
/// signature is not ours to discard.
pub fn verify_signatures(psbt: &Psbt, inspection: &Inspection) -> Result<u16, SignFailure> {
    if codec::unsigned_id(psbt) != inspection.unsigned_id() {
        return Err(SignFailure::InspectionDoesNotMatchPsbt);
    }
    verify_produced(psbt, &ours_according_to(inspection))
}

/// The signatures this device is answerable for in `inspection`: one per input it
/// classified as ours, under the key that input's origin names.
///
/// Callable only behind the binding check, which is what makes the claimed key the key
/// [`sign`] used: `inspect` establishes that the claimed key is the one the script commits
/// to, and `sign` refuses any input whose derived key does not rebuild that same script.
fn ours_according_to(inspection: &Inspection) -> Vec<Produced> {
    inspection
        .inputs
        .iter()
        .filter_map(|facts| match facts.claim {
            Claim::Ours {
                key: ClaimedKey::Ecdsa(pubkey),
                ..
            } => Some(Produced::Ecdsa {
                index: facts.index,
                pubkey: PublicKey::new(pubkey),
            }),
            Claim::Ours {
                key: ClaimedKey::Taproot(_),
                ..
            } => Some(Produced::TaprootKeyPath { index: facts.index }),
            Claim::Foreign => None,
        })
        .collect()
}

/// Verify exactly `produced` against digests recomputed from `psbt`.
///
/// The shared body of the gate. [`sign`] passes the record it built while signing and
/// [`verify_signatures`] passes the one the inspection implies; both are the same claim
/// about the same keys, and keeping one implementation is what stops the control the
/// wallet re-runs from drifting away from the one that let the file out.
fn verify_produced(psbt: &Psbt, produced: &[Produced]) -> Result<u16, SignFailure> {
    // Both callers establish that every index addresses an input of this PSBT, by binding
    // an inspection to it first. Re-checking costs one comparison, and the failure mode it
    // removes is a panic on a device that is holding a seed.
    if produced
        .iter()
        .any(|p| usize::from(p.index()) >= psbt.inputs.len())
    {
        return Err(SignFailure::InspectionDoesNotMatchPsbt);
    }

    let tx = psbt.unsigned_tx.clone();
    let prevouts: Vec<TxOut> = (0..psbt.inputs.len())
        .map(|i| prevout_of(psbt, i).ok_or(SignFailure::PrevoutUnavailable { index: i as u16 }))
        .collect::<Result<Vec<_>, _>>()?;
    let all_prevouts = Prevouts::All(&prevouts);
    let mut cache = SighashCache::new(&tx);
    let mut verified = 0u16;

    for item in produced {
        let index = item.index();
        let i = usize::from(index);
        let input = &psbt.inputs[i];
        let prevout = &prevouts[i];

        match *item {
            Produced::Ecdsa { pubkey, .. } => {
                let signature = input
                    .partial_sigs
                    .get(&pubkey)
                    .ok_or(SignFailure::SignatureMissing { index })?;
                // The sighash type is read off the signature, which is sound here and
                // would not be over the whole map: this is the flag this device wrote,
                // under a key only this device holds.
                //
                // Which digest, and over which script, is decided from the PREVOUT alone -
                // the gate's own independent read of the file - and never from the plan the
                // signing loop followed. A P2WSH input hashes its witness script verbatim
                // (BIP-143 does not expand it the way it expands a P2WPKH program), and the
                // copy used here is the PSBT's, not the registration's rebuild: `inspect`
                // proved the two are equal, so taking the file's copy here keeps the gate a
                // second opinion instead of a second reading of the same value.
                let hash = if prevout.script_pubkey.is_p2wsh() {
                    let witness_script = input
                        .witness_script
                        .as_deref()
                        .ok_or(SignFailure::SignatureVerificationFailed { index })?;
                    cache
                        .p2wsh_signature_hash(
                            i,
                            witness_script,
                            prevout.value,
                            signature.sighash_type,
                        )
                        .map_err(|error| SignFailure::Digest {
                            index,
                            error: SignError::SegwitV0(bitcoin::sighash::P2wpkhError::Sighash(
                                error,
                            )),
                        })?
                } else {
                    let script_code: &Script = if prevout.script_pubkey.is_p2sh() {
                        input
                            .redeem_script
                            .as_deref()
                            .ok_or(SignFailure::SignatureVerificationFailed { index })?
                    } else {
                        prevout.script_pubkey.as_script()
                    };
                    cache
                        .p2wpkh_signature_hash(
                            i,
                            script_code,
                            prevout.value,
                            signature.sighash_type,
                        )
                        .map_err(|error| SignFailure::Digest {
                            index,
                            error: SignError::SegwitV0(error),
                        })?
                };
                secp()
                    .verify_ecdsa(
                        &Message::from_digest(*hash.as_ref()),
                        &signature.signature,
                        &pubkey.inner,
                    )
                    .map_err(|_| SignFailure::SignatureVerificationFailed { index })?;
            }
            Produced::TaprootKeyPath { .. } => {
                let signature = input
                    .tap_key_sig
                    .ok_or(SignFailure::SignatureMissing { index })?;
                // The verifying key comes out of the scriptPubKey, which is the only place
                // a network validator will look for it. Taking it from our own tweak
                // instead would make this check verify the signer against itself.
                let output_key = taproot_output_key(&prevout.script_pubkey)
                    .ok_or(SignFailure::SignatureVerificationFailed { index })?;
                let hash = cache
                    .taproot_key_spend_signature_hash(i, &all_prevouts, signature.sighash_type)
                    .map_err(|error| SignFailure::Digest {
                        index,
                        error: SignError::Taproot(error),
                    })?;
                secp()
                    .verify_schnorr(
                        &signature.signature,
                        &Message::from_digest(*hash.as_ref()),
                        &output_key,
                    )
                    .map_err(|_| SignFailure::SignatureVerificationFailed { index })?;
            }
        }
        verified += 1;
    }

    Ok(verified)
}

/// The prevout an input spends, taken from the PSBT's own maps. Deliberately does not go
/// through `checks::resolve_prevout`: this is the gate's independent read.
fn prevout_of(psbt: &Psbt, i: usize) -> Option<TxOut> {
    let input = &psbt.inputs[i];
    if let Some(prev) = &input.non_witness_utxo {
        let vout = psbt.unsigned_tx.input[i].previous_output.vout as usize;
        return prev.output.get(vout).cloned();
    }
    input.witness_utxo.clone()
}

/// The 32-byte x-only key in a v1 witness program, or `None` if the script is not one.
fn taproot_output_key(script: &Script) -> Option<XOnlyPublicKey> {
    if !script.is_p2tr() {
        return None;
    }
    XOnlyPublicKey::from_slice(&script.as_bytes()[2..34]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psbt::{fixture, inspect};
    use alloc::string::ToString;
    use bitcoin::Amount;

    fn sign_fixture(psbt: &Psbt) -> Signed {
        let inspection = inspect(psbt, &fixture::context()).unwrap();
        sign(psbt, &inspection, &fixture::SEED).unwrap()
    }

    #[test]
    fn a_p2wpkh_input_is_signed_and_verifies() {
        let psbt = fixture::p2wpkh_psbt();
        let signed = sign_fixture(&psbt);
        assert_eq!(signed.report().signatures_added, 1);
        assert_eq!(signed.report().signatures_verified, 1);
        assert_eq!(signed.report().inputs_signed, alloc::vec![0]);
        assert_eq!(signed.psbt().inputs[0].partial_sigs.len(), 1);
        let signature = signed.psbt().inputs[0].partial_sigs.values().next().unwrap();
        assert!(signature.serialize().len() <= crate::sign::MAX_ECDSA_SIGNATURE_LEN);
    }

    #[test]
    fn a_p2sh_p2wpkh_input_is_signed_and_verifies() {
        let signed = sign_fixture(&fixture::p2sh_p2wpkh_psbt());
        assert_eq!(signed.report().signatures_verified, 1);
        assert_eq!(signed.psbt().inputs[0].partial_sigs.len(), 1);
    }

    #[test]
    fn a_taproot_key_path_input_is_signed_and_verifies() {
        let signed = sign_fixture(&fixture::p2tr_psbt());
        assert_eq!(signed.report().signatures_verified, 1);
        let signature = signed.psbt().inputs[0].tap_key_sig.unwrap();
        // SIGHASH_DEFAULT omits the flag byte; anything else would be 65.
        assert_eq!(signature.serialize().len(), 64);
        assert!(signed.psbt().inputs[0].partial_sigs.is_empty());
    }

    // -- Multisig (0.2.0-m7) ------------------------------------------------------------

    fn sign_multisig(psbt: &Psbt, registry: &[crate::multisig::Registration]) -> Signed {
        let inspection = inspect(psbt, &fixture::context_with(registry)).unwrap();
        sign(psbt, &inspection, &fixture::SEED).unwrap()
    }

    /// A 2-of-3 P2WSH input, end to end: one partial signature, verified by the gate,
    /// left in `partial_sigs` under our own cosigner key so a coordinator can combine it.
    #[test]
    fn a_registered_multisig_input_is_signed_and_verifies() {
        let registry = alloc::vec![fixture::registration()];
        let psbt = fixture::multisig_psbt();
        let signed = sign_multisig(&psbt, &registry);

        assert_eq!(signed.report().signatures_added, 1);
        assert_eq!(signed.report().signatures_verified, 1);
        assert_eq!(signed.report().inputs_signed, alloc::vec![0]);

        // One signature, ours, and nothing finalized: a 2-of-3 is not spendable with one
        // cosigner and the device must not pretend otherwise.
        let sigs = &signed.psbt().inputs[0].partial_sigs;
        assert_eq!(sigs.len(), 1);
        let ours = registry[0].our_key_at(crate::multisig::Keychain::Receive, 0).unwrap();
        assert!(sigs.contains_key(&PublicKey::from(ours.0)));
        assert!(signed.psbt().inputs[0].final_script_witness.is_none());
        assert!(signed.psbt().inputs[0].final_script_sig.is_none());
    }

    /// The partial signature a cosigner already put in the file survives, and ours joins
    /// it. A signer that dropped the others would make a 2-of-3 unspendable one round at a
    /// time.
    #[test]
    fn signing_multisig_preserves_another_cosigners_signature() {
        let registry = alloc::vec![fixture::registration()];
        let mut psbt = fixture::multisig_psbt();

        // A well formed foreign entry: a real key from the wallet's own cosigner set, with
        // a signature this device neither made nor is answerable for.
        let other = registry[0]
            .cosigners()
            .iter()
            .find(|c| c.fingerprint != fixture::fingerprint())
            .unwrap();
        let other_key = PublicKey::from(
            other
                .xpub
                .derive_pub(
                    crate::derive::secp(),
                    &[
                        bitcoin::bip32::ChildNumber::from_normal_idx(0).unwrap(),
                        bitcoin::bip32::ChildNumber::from_normal_idx(0).unwrap(),
                    ],
                )
                .unwrap()
                .public_key,
        );
        let borrowed = {
            let signed = sign_multisig(&fixture::multisig_psbt(), &registry);
            *signed.psbt().inputs[0].partial_sigs.values().next().unwrap()
        };
        psbt.inputs[0].partial_sigs.insert(other_key, borrowed);

        let signed = sign_multisig(&psbt, &registry);
        assert_eq!(signed.report().signatures_added, 1);
        assert_eq!(signed.report().signatures_verified, 1);
        assert_eq!(signed.psbt().inputs[0].partial_sigs.len(), 2);
        assert_eq!(
            signed.psbt().inputs[0].partial_sigs.get(&other_key),
            Some(&borrowed),
            "the other cosigner's entry must come back byte for byte"
        );
    }

    /// The gate's own reading of a multisig input, run standalone the way notyas-wallet
    /// will run it.
    #[test]
    fn the_gate_verifies_a_multisig_signature_on_its_own() {
        let registry = alloc::vec![fixture::registration()];
        let psbt = fixture::multisig_psbt();
        let signed = sign_multisig(&psbt, &registry);
        let after = inspect(signed.psbt(), &fixture::context_with(&registry)).unwrap();
        assert_eq!(verify_signatures(signed.psbt(), &after).unwrap(), 1);
    }

    /// A multisig signature is over the WITNESS script, not over the scriptPubKey.
    ///
    /// Driven through `verify_produced` rather than [`verify_signatures`] on purpose: the
    /// public entry point binds an inspection to the file first and would refuse a mutated
    /// PSBT before reaching a digest, which is correct and is a different property. What
    /// is being pinned here is the gate's own arithmetic - swap the script code for
    /// another VALID multisig script from the same wallet and the signature must stop
    /// verifying, which it can only do if the digest depends on that script.
    #[test]
    fn a_multisig_signature_does_not_verify_against_a_different_script() {
        let registry = alloc::vec![fixture::registration()];
        let signed = sign_multisig(&fixture::multisig_psbt(), &registry);
        let ours = registry[0]
            .our_key_at(crate::multisig::Keychain::Receive, 0)
            .unwrap();
        let produced = alloc::vec![Produced::Ecdsa {
            index: 0,
            pubkey: PublicKey::from(ours.0),
        }];

        assert_eq!(verify_produced(signed.psbt(), &produced).unwrap(), 1);

        let mut tampered = signed.into_psbt();
        tampered.inputs[0].witness_script = registry[0]
            .witness_script(crate::multisig::Keychain::Receive, 1);
        assert!(matches!(
            verify_produced(&tampered, &produced),
            Err(SignFailure::SignatureVerificationFailed { index: 0 })
        ));
    }

    /// Deterministic in, deterministic out: the same seed and the same PSBT produce the
    /// same bytes, which is what makes a pinned vector possible at all (ARCH 2.4).
    #[test]
    fn signing_is_deterministic() {
        let psbt = fixture::p2wpkh_psbt();
        assert_eq!(
            crate::psbt::encode(sign_fixture(&psbt).psbt()),
            crate::psbt::encode(sign_fixture(&psbt).psbt())
        );
    }

    /// Signing must not disturb anything it was not asked to touch, unknown fields most of
    /// all: a coordinator round trips them.
    #[test]
    fn signing_preserves_unknown_fields() {
        let mut psbt = fixture::p2wpkh_psbt();
        let key = bitcoin::psbt::raw::Key {
            type_value: 0x0f,
            key: alloc::vec![1, 2, 3],
        };
        psbt.inputs[0].unknown.insert(key.clone(), alloc::vec![9, 9]);
        psbt.unknown.insert(
            bitcoin::psbt::raw::Key {
                type_value: 0x77,
                key: alloc::vec![],
            },
            alloc::vec![1],
        );
        let signed = sign_fixture(&psbt);
        assert_eq!(signed.psbt().inputs[0].unknown.get(&key), Some(&alloc::vec![9, 9]));
        assert_eq!(signed.psbt().unknown.len(), 1);
        assert_eq!(signed.psbt().unsigned_tx, psbt.unsigned_tx);
    }

    /// An inspection of a different PSBT must not authorize this one.
    #[test]
    fn an_inspection_of_another_psbt_is_refused() {
        let reviewed = fixture::p2wpkh_psbt();
        let inspection = inspect(&reviewed, &fixture::context()).unwrap();
        let substituted = fixture::p2tr_psbt();
        let err = sign(&substituted, &inspection, &fixture::SEED).unwrap_err();
        assert!(matches!(err, SignFailure::InspectionDoesNotMatchPsbt));
        assert_eq!(err.check(), Check::PostSign);
    }

    /// The output-substitution case in its most direct form: change the transaction after
    /// review and the digest no longer matches.
    #[test]
    fn a_psbt_mutated_after_review_is_refused() {
        let psbt = fixture::p2wpkh_psbt();
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        let mut mutated = psbt.clone();
        mutated.unsigned_tx.output[0].value = Amount::from_sat(1);
        assert!(matches!(
            sign(&mutated, &inspection, &fixture::SEED).unwrap_err(),
            SignFailure::InspectionDoesNotMatchPsbt
        ));
    }

    #[test]
    fn a_psbt_with_no_input_of_ours_is_refused() {
        let mut psbt = fixture::p2wpkh_psbt();
        psbt.inputs[0].bip32_derivation.clear();
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        let err = sign(&psbt, &inspection, &fixture::SEED).unwrap_err();
        assert!(matches!(err, SignFailure::NothingToSign));
        assert!(!err.to_string().is_empty());
    }

    /// Derive-and-compare. `inspect` cannot catch this on its own: the origin names the
    /// key the script commits to, and the PATH is what lies.
    #[test]
    fn a_path_that_derives_a_different_key_is_refused() {
        let mut psbt = fixture::p2wpkh_psbt();
        let entry = psbt.inputs[0].bip32_derivation.iter().next().unwrap();
        let pk = *entry.0;
        psbt.inputs[0]
            .bip32_derivation
            .insert(pk, (fixture::fingerprint(), fixture::path("m/84'/0'/0'/1/9")));
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        let err = sign(&psbt, &inspection, &fixture::SEED).unwrap_err();
        assert!(matches!(
            err,
            SignFailure::OriginDoesNotDeriveScript { index: 0 }
        ));
        assert_eq!(err.check(), Check::InputOwnership);
    }

    /// The standing proof that the post-sign gate is wired: break one signature, and the
    /// gate that would let the file leave the device says no.
    #[test]
    fn the_post_sign_gate_catches_a_corrupted_ecdsa_signature() {
        let psbt = fixture::p2wpkh_psbt();
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        let mut signed = sign(&psbt, &inspection, &fixture::SEED)
            .unwrap()
            .into_psbt();
        assert_eq!(verify_signatures(&signed, &inspection).unwrap(), 1);

        let (pubkey, signature) = signed.inputs[0].partial_sigs.iter().next().unwrap();
        let (pubkey, mut signature) = (*pubkey, *signature);
        let mut der = signature.signature.serialize_der().to_vec();
        // Flip the low bit of s. Still a well formed DER signature, still low-s, and no
        // longer a signature over this digest.
        let last = der.len() - 1;
        der[last] ^= 0x01;
        if let Ok(mutated) = bitcoin::secp256k1::ecdsa::Signature::from_der(&der) {
            signature.signature = mutated;
            signed.inputs[0].partial_sigs.insert(pubkey, signature);
            assert!(matches!(
                verify_signatures(&signed, &inspection).unwrap_err(),
                SignFailure::SignatureVerificationFailed { index: 0 }
            ));
        } else {
            panic!("the mutated DER should still parse");
        }
    }

    /// The same mutation on the taproot side, where a faulted digest is the more dangerous
    /// case because the nonce is deterministic.
    #[test]
    fn the_post_sign_gate_catches_a_corrupted_schnorr_signature() {
        let psbt = fixture::p2tr_psbt();
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        let mut signed = sign(&psbt, &inspection, &fixture::SEED)
            .unwrap()
            .into_psbt();
        assert_eq!(verify_signatures(&signed, &inspection).unwrap(), 1);

        let mut bytes = signed.inputs[0].tap_key_sig.unwrap().signature.serialize();
        bytes[63] ^= 0x01;
        signed.inputs[0].tap_key_sig = Some(bitcoin::taproot::Signature {
            signature: bitcoin::secp256k1::schnorr::Signature::from_slice(&bytes).unwrap(),
            sighash_type: TapSighashType::Default,
        });
        assert!(matches!(
            verify_signatures(&signed, &inspection).unwrap_err(),
            SignFailure::SignatureVerificationFailed { index: 0 }
        ));
    }

    /// The gate takes the taproot verifying key from the scriptPubKey, so a signature made
    /// under a different tweak cannot verify against itself.
    #[test]
    fn the_post_sign_gate_takes_the_taproot_key_from_the_script() {
        let psbt = fixture::p2tr_psbt();
        let script = &psbt.inputs[0].witness_utxo.as_ref().unwrap().script_pubkey;
        let from_script = taproot_output_key(script).unwrap();
        let derived = fixture::key_at(fixture::P2TR_PATH).output_key(None);
        assert_eq!(from_script, derived.to_x_only_public_key());
        assert!(taproot_output_key(&ScriptBuf::new()).is_none());
    }

    // -- the inspection-to-PSBT binding on the gate itself ---------------------------

    /// The gate is a public control and its `Inspection` is caller-supplied, so it has to
    /// establish the same binding [`sign`] does. An inspection naming more inputs than the
    /// PSBT has indexed past the end of `psbt.inputs` and of the gate's own prevout vector.
    #[test]
    fn the_gate_refuses_an_inspection_with_more_inputs_than_the_psbt() {
        let reviewed = fixture::two_input_psbt();
        let inspection = inspect(&reviewed, &fixture::context()).unwrap();
        let err = verify_signatures(&fixture::p2wpkh_psbt(), &inspection).unwrap_err();
        assert!(matches!(err, SignFailure::InspectionDoesNotMatchPsbt));
    }

    /// The same binding in the case that stays in bounds: same input count, different
    /// transaction. "Sign what was reviewed" has to hold for the control that re-checks it.
    #[test]
    fn the_gate_refuses_an_inspection_of_another_psbt_of_the_same_shape() {
        let reviewed = fixture::p2wpkh_psbt();
        let inspection = inspect(&reviewed, &fixture::context()).unwrap();
        let err = verify_signatures(&fixture::p2tr_psbt(), &inspection).unwrap_err();
        assert!(matches!(err, SignFailure::InspectionDoesNotMatchPsbt));
        assert_eq!(err.check(), Check::PostSign);
    }

    /// The gate's binding must be blind to signature fields and to nothing else: blind, or
    /// it could not run after signing at all; to nothing else, or it would not be a
    /// binding. Both halves in one test because they are one property.
    #[test]
    fn the_gate_binding_ignores_signatures_and_nothing_else() {
        let psbt = fixture::p2wpkh_psbt();
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        let signed = sign(&psbt, &inspection, &fixture::SEED)
            .unwrap()
            .into_psbt();
        assert_eq!(verify_signatures(&signed, &inspection).unwrap(), 1);

        let mut moved = signed.clone();
        moved.unsigned_tx.output[0].value = Amount::from_sat(1);
        assert!(matches!(
            verify_signatures(&moved, &inspection).unwrap_err(),
            SignFailure::InspectionDoesNotMatchPsbt
        ));

        let mut relabelled = signed;
        relabelled.inputs[0].bip32_derivation.clear();
        assert!(matches!(
            verify_signatures(&relabelled, &inspection).unwrap_err(),
            SignFailure::InspectionDoesNotMatchPsbt
        ));
    }

    // -- foreign entries in partial_sigs ---------------------------------------------

    /// A `partial_sigs` map is coordinator input. A bogus entry under somebody else's key
    /// must not cost the user a signature: the gate checks what this device produced, and
    /// a free veto over an approved transaction is a denial of service, not a refusal.
    #[test]
    fn a_foreign_partial_signature_cannot_block_signing() {
        // A well formed signature that is simply not a signature by `foreign`, which is
        // exactly what a coordinator can put in the map for nothing.
        let clean = fixture::p2wpkh_psbt();
        let borrowed = {
            let inspection = inspect(&clean, &fixture::context()).unwrap();
            let signed = sign(&clean, &inspection, &fixture::SEED).unwrap().into_psbt();
            *signed.inputs[0].partial_sigs.values().next().unwrap()
        };
        let foreign = PublicKey::from(fixture::key_at("m/84'/0'/9'/0/0").public_key());

        let mut attacked = fixture::p2wpkh_psbt();
        attacked.inputs[0].partial_sigs.insert(foreign, borrowed);
        let inspection = inspect(&attacked, &fixture::context()).unwrap();
        let signed = sign(&attacked, &inspection, &fixture::SEED)
            .expect("a foreign partial_sig must not veto a transaction the user approved");

        assert_eq!(signed.report().signatures_added, 1);
        assert_eq!(signed.report().signatures_verified, 1);
        // Untouched means untouched: dropping a cosigner's entry would break the ceremony
        // this device is a participant in rather than the arbiter of.
        assert_eq!(signed.psbt().inputs[0].partial_sigs.len(), 2);
        assert_eq!(
            signed.psbt().inputs[0].partial_sigs.get(&foreign),
            Some(&borrowed)
        );
    }

    /// The same entry through the public gate, and the count it reports: ours, not theirs.
    #[test]
    fn the_gate_counts_only_the_signatures_this_device_made() {
        let psbt = fixture::p2wpkh_psbt();
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        let mut signed = sign(&psbt, &inspection, &fixture::SEED)
            .unwrap()
            .into_psbt();
        let ours = *signed.inputs[0].partial_sigs.values().next().unwrap();
        let foreign = PublicKey::from(fixture::key_at("m/84'/0'/9'/0/0").public_key());
        signed.inputs[0].partial_sigs.insert(foreign, ours);
        assert_eq!(verify_signatures(&signed, &inspection).unwrap(), 1);
    }

    /// The other half of checking by key: our own signature going missing is a refusal,
    /// and a foreign entry left in the map must not stand in for it.
    #[test]
    fn our_signature_going_missing_is_not_covered_by_a_foreign_one() {
        let psbt = fixture::p2wpkh_psbt();
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        let mut signed = sign(&psbt, &inspection, &fixture::SEED)
            .unwrap()
            .into_psbt();
        let ours = *signed.inputs[0].partial_sigs.values().next().unwrap();
        let foreign = PublicKey::from(fixture::key_at("m/84'/0'/9'/0/0").public_key());
        signed.inputs[0].partial_sigs.clear();
        signed.inputs[0].partial_sigs.insert(foreign, ours);
        assert!(matches!(
            verify_signatures(&signed, &inspection).unwrap_err(),
            SignFailure::SignatureMissing { index: 0 }
        ));
    }

    /// Every input of ours in a two-input PSBT is signed, and both are reported.
    #[test]
    fn every_input_of_ours_is_signed() {
        let psbt = fixture::two_input_psbt();
        let signed = sign_fixture(&psbt);
        assert_eq!(signed.report().inputs_signed, alloc::vec![0, 1]);
        assert_eq!(signed.report().signatures_added, 2);
        assert_eq!(signed.report().signatures_verified, 2);
    }

    // -- Batch signing (0.2.0-G10) -------------------------------------------------------

    /// How many inputs the batch cases below hand over at once. Large enough that the
    /// approval is plainly about a list rather than about one row, small enough that a
    /// debug-build secp256k1 signs them all inside a test run.
    const BATCH: u32 = 8;

    /// The whole of "Sign All": one inspection, one call, one signature per input of ours,
    /// every one of them through the same post-sign gate a single-input spend goes through.
    #[test]
    fn a_batch_signs_every_input_of_ours_in_one_pass() {
        let psbt = fixture::batch_psbt(BATCH);
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        let signed = sign(&psbt, &inspection, &fixture::SEED).unwrap();

        let expected: Vec<u16> = (0..BATCH as u16).collect();
        assert_eq!(signed.report().inputs_signed, expected);
        assert_eq!(signed.report().signatures_added, BATCH as u16);
        assert_eq!(signed.report().signatures_verified, BATCH as u16);
        for i in 0..BATCH as usize {
            assert_eq!(
                signed.psbt().inputs[i].partial_sigs.len(),
                1,
                "input {i} of the batch"
            );
        }
        // The control the wallet layer re-runs, over the whole batch rather than a row.
        assert_eq!(
            verify_signatures(signed.psbt(), &inspection).unwrap(),
            BATCH as u16
        );
    }

    /// The approval and the signatures are one list.
    ///
    /// The batch failure mode is a screen that describes one set of inputs and a device
    /// that signs another, so the list the review shows
    /// ([`Inspection::signable_input_indexes`]) and the list the report names have to be
    /// the same value, and the totals beside them have to describe the file rather than
    /// the rows that happen to be ours.
    #[test]
    fn a_batch_review_describes_exactly_what_gets_signed() {
        let psbt = fixture::batch_psbt(BATCH);
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        let signed = sign(&psbt, &inspection, &fixture::SEED).unwrap();

        assert_eq!(inspection.signable_input_indexes(), signed.report().inputs_signed);
        assert_eq!(inspection.signable_inputs(), BATCH as usize);

        let coins = Amount::from_sat(u64::from(BATCH) * fixture::PREVOUT_SAT);
        assert_eq!(inspection.input_total, coins);
        assert_eq!(inspection.signable_input_total(), coins, "every input here is ours");
        assert_eq!(inspection.fee, Amount::from_sat(fixture::FEE_SAT));
        assert!(inspection.fee_is_enforced(), "every amount is proven by its prev tx");
        assert_eq!(inspection.unproven_amounts(), 0);
        // No registry, so no output can be PROVEN change: all of it counts as leaving.
        assert_eq!(inspection.change_total(), Amount::ZERO);
        assert_eq!(inspection.leaving_total(), inspection.output_total);
    }

    /// A batch beside a cosigner's own input signs ours and says so.
    ///
    /// The two totals differ here and that is the point: `signable_input_total` is what
    /// this device's signatures commit, `input_total` is what the transaction spends, and
    /// a review that showed only the first would understate a multi-party spend.
    #[test]
    fn a_batch_leaves_a_cosigners_input_alone_and_counts_it() {
        let psbt = fixture::ours_and_a_foreign_input_psbt();
        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        let signed = sign(&psbt, &inspection, &fixture::SEED).unwrap();

        assert_eq!(inspection.signable_input_indexes(), alloc::vec![0]);
        assert_eq!(signed.report().inputs_signed, alloc::vec![0]);
        assert_eq!(
            inspection.signable_input_total(),
            Amount::from_sat(fixture::PREVOUT_SAT)
        );
        assert_eq!(
            inspection.input_total,
            Amount::from_sat(2 * fixture::PREVOUT_SAT)
        );
        assert!(signed.psbt().inputs[1].partial_sigs.is_empty());
    }

    /// A batch cannot be used to bury an amount nobody proved, by either route.
    ///
    /// The rule is check 2's: refuse when this device would sign ANY input whose sighash
    /// does not commit to every input amount AND any input in the file carries an unproven
    /// amount. A batch is where that rule could plausibly be diluted - eight honest inputs
    /// and one quiet one - so both ways of getting there are pinned here.
    ///
    /// Route one is the direct file: `inspect` refuses it, and since `sign` cannot be
    /// reached without an [`Inspection`] there is nothing to sign. The refusal names the
    /// FIRST of our signatures rather than any particular one, because it is the pairing
    /// that is the defect and not the row.
    ///
    /// Route two is the one a batch actually invites: review the clean file, approve eight
    /// signatures, and hand the device the poisoned one. That is the fee-inflation shape,
    /// and what stops it is not a check at all - it is that an inspection is bound to the
    /// bytes it was taken from.
    #[test]
    fn a_batch_cannot_bury_an_unproven_amount() {
        let poisoned = fixture::batch_psbt_with_an_unproven_input(BATCH);
        let err = inspect(&poisoned, &fixture::context()).unwrap_err();
        assert_eq!(
            err,
            crate::psbt::CheckFailure::UnprovenAmountBesideOurSignature {
                signing: 0,
                unproven: BATCH as u16,
            }
        );

        let clean = fixture::batch_psbt(BATCH);
        let approved = inspect(&clean, &fixture::context()).unwrap();
        assert_eq!(approved.signable_inputs(), BATCH as usize);
        assert!(matches!(
            sign(&poisoned, &approved, &fixture::SEED).unwrap_err(),
            SignFailure::InspectionDoesNotMatchPsbt
        ));
    }

    /// One bad input refuses the whole batch, and leaves nothing behind.
    ///
    /// This is the property that makes a single approval over N inputs defensible: the
    /// checks are not relaxed because there are many of them, and a refusal on the sixth
    /// input does not leave five signatures on the card. The mutation is the derive-and
    /// -compare case, which is the only class of refusal that can reach the middle of the
    /// signing loop at all - everything else is decided by `inspect` before a key exists.
    #[test]
    fn one_bad_input_refuses_the_whole_batch() {
        let bad = 5u16;
        let mut psbt = fixture::batch_psbt(BATCH);
        let claimed = *psbt.inputs[usize::from(bad)]
            .bip32_derivation
            .iter()
            .next()
            .expect("every input of the batch carries an origin")
            .0;
        // The key the script commits to, under a path that derives a different one: the
        // 2019 Coldcard change-path shape, buried in the middle of a batch.
        psbt.inputs[usize::from(bad)].bip32_derivation.insert(
            claimed,
            (fixture::fingerprint(), fixture::path("m/84'/0'/0'/1/9")),
        );

        let inspection = inspect(&psbt, &fixture::context()).unwrap();
        assert_eq!(inspection.signable_inputs(), BATCH as usize, "all still claimed");
        let err = sign(&psbt, &inspection, &fixture::SEED).unwrap_err();
        assert!(matches!(
            err,
            SignFailure::OriginDoesNotDeriveScript { index } if index == bad
        ));
        // Atomic: `sign` returns a new PSBT, so a refusal leaves the caller holding the
        // file it started with and no signature of ours exists anywhere.
        assert!(psbt
            .inputs
            .iter()
            .all(|input| input.partial_sigs.is_empty() && input.tap_key_sig.is_none()));
    }

    /// What the single-input escape actually buys, measured on the signature rather than
    /// argued about.
    ///
    /// Fixture A with its `witness_utxo` understated: one input, one amount, and the amount
    /// is a lie. This device signs it, because with one input there is no OTHER amount to
    /// be lied about and no second signature anywhere for a later round to combine the
    /// harvested one with. The signature it produces is worthless: BIP-143 hashes the input
    /// amount into the digest, so the signature verifies under the amount the file stated
    /// and NOT under the amount the chain holds, and a transaction carrying it cannot
    /// confirm.
    ///
    /// This is the test the review screen's copy rests on. "The signature this device adds
    /// is worthless and this transaction cannot confirm" is a claim about cryptography, and
    /// it must not ship without something that verifies it against secp256k1.
    #[test]
    fn a_lying_single_input_signature_cannot_confirm() {
        use bitcoin::hashes::Hash as _;
        use bitcoin::secp256k1::Message;
        use bitcoin::sighash::{EcdsaSighashType, SighashCache};

        const LIE_SAT: u64 = 95_000;

        let mut psbt = fixture::bluewallet_watch_only_psbt();
        let spk = psbt.inputs[0]
            .witness_utxo
            .as_ref()
            .expect("fixture A states its amount")
            .script_pubkey
            .clone();
        psbt.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(LIE_SAT);

        // The device's own accounts, as `firmware/src/signing.rs` puts them in scope:
        // fixture A carries BlueWallet's zero fingerprint, and ownership is decided by
        // deriving the leaf it names rather than by reading that fingerprint.
        let accounts = fixture::device_accounts();
        let inspection = crate::psbt::inspect_with_accounts(&psbt, &fixture::context(), &accounts)
            .expect("one input, one amount");
        assert_eq!(inspection.signable_inputs(), 1);
        let signed = sign(&psbt, &inspection, &fixture::SEED).expect("this device signs it");
        assert_eq!(signed.report().inputs_signed, alloc::vec![0]);

        let out = signed.into_psbt();
        let (public, signature) = out.inputs[0]
            .partial_sigs
            .iter()
            .next()
            .expect("one signature");
        let tx = out.unsigned_tx.clone();
        let mut cache = SighashCache::new(&tx);
        let mut digest_for = |value: u64| {
            let hash = cache
                .p2wpkh_signature_hash(0, &spk, Amount::from_sat(value), EcdsaSighashType::All)
                .expect("a p2wpkh digest");
            Message::from_digest(hash.to_byte_array())
        };

        // Under the amount the FILE stated, which is the digest the device was shown.
        assert!(secp()
            .verify_ecdsa(&digest_for(LIE_SAT), &signature.signature, &public.inner)
            .is_ok());
        // Under the amount the CHAIN holds, which is the digest consensus computes. This is
        // the whole of the argument: the coordinator's reward for the lie is a transaction
        // that cannot confirm, not a fee nobody was shown.
        assert!(secp()
            .verify_ecdsa(
                &digest_for(fixture::PREVOUT_SAT),
                &signature.signature,
                &public.inner
            )
            .is_err());
    }

    /// The batch gate, and why it is a refusal rather than a debug assertion.
    ///
    /// [`sign`] compares the list it signed against the list the review named. Those two
    /// are the same predicate over the same vector today, so no file this API accepts can
    /// make them differ - which is the property being claimed, not a hole in the test. What
    /// is pinned here is that the equality really does hold across the shapes a batch
    /// arrives in, and that the refusal waiting for the day it stops holding is one a
    /// screen can render.
    #[test]
    fn the_batch_gate_holds_across_every_shape_a_batch_arrives_in() {
        for (case, psbt) in [
            ("one input", fixture::batch_psbt(1)),
            ("a full batch", fixture::batch_psbt(BATCH)),
            ("ours beside a cosigner's", fixture::ours_and_a_foreign_input_psbt()),
            ("two of ours", fixture::two_input_psbt()),
        ] {
            let inspection = inspect(&psbt, &fixture::context()).unwrap();
            let signed = sign(&psbt, &inspection, &fixture::SEED).unwrap();
            assert_eq!(
                signed.report().inputs_signed,
                inspection.signable_input_indexes(),
                "{case}"
            );
            assert_eq!(
                usize::from(signed.report().signatures_added),
                inspection.signable_inputs(),
                "{case}"
            );
        }

        let failure = SignFailure::BatchDiffersFromReview {
            reviewed: 7,
            signed: 8,
        };
        assert_eq!(failure.check(), Check::PostSign);
        let text = failure.to_string();
        assert!(text.is_ascii() && !text.is_empty(), "{text}");
    }
}
