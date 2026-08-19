// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bytes in, a reviewed transaction, bytes out.
//!
//! This is the device's whole signing surface. It takes a file that arrived over an
//! airgapped channel, runs it through `notyas_core::psbt` against the open wallet's
//! [`Context`](notyas_core::psbt::Context), and hands back the signed file with the report
//! that let it out:
//!
//! ```text
//!   bytes    -> psbt::decode  -> Psbt
//!   psbt+cx  -> psbt::inspect_with_accounts -> Inspection   (no signing key derived)
//!   [ the user reads the review and holds to sign ]
//!   psbt+seed-> psbt::sign    -> Signed       (signs only what the inspection named)
//!   psbt     -> psbt::encode  -> bytes
//! ```
//!
//! Everything above `decode` is I/O and everything below `encode` is I/O, and neither is
//! here. That split is the same one `src/store` keeps against the sealing engine: the
//! transport (SD, QR) hands this module a `&[u8]` and takes a `Vec<u8>` back, and the
//! engine stays a pure function of `(file, device context, seed)`.
//!
//! # There is one path, and it has no bypass
//!
//! [`Review`] can only be built by [`review`], and [`Signed`] can only be built by
//! [`Review::sign`]. There is no second entry point, no flag that skips a check, and no
//! variant of [`sign`] that retries with a check relaxed. A refusal from `inspect` ends the
//! transaction; the answer to it is a different file, not a different call.
//!
//! `psbt::sign` re-establishes that binding for itself - the inspection carries the
//! SHA-256 of the bytes it read and signing recomputes it - so even a caller that held a
//! [`Review`] across a re-read of the file cannot get a signature over bytes nobody looked
//! at.
//!
//! # The fee, and why it is not an `Amount`
//!
//! [`Review::fee`] returns a [`ReviewedFee`], which is two variants and no plain accessor.
//! A signer that renders an unprovable number the same way it renders a proven one has lied
//! by omission, and this is the type that stops it: the fee cannot be read off a [`Review`]
//! without the caller naming which kind of figure it is. That is a forcing function and not
//! a wall - [`Review::totals`] are sums over the same amounts, so subtracting them is
//! always available to anyone who means to - which is why the caveat is written on those
//! too rather than assumed to be unreachable.
//!
//! The engine has already refused the dangerous shape outright - a file where this device
//! would sign an input whose sighash covers only its own amount while some other input's
//! amount rests on nothing is `CheckFailure::UnprovenAmountBesideOurSignature`, the
//! one-BTC burn of BIP-174's line 415 footnote. [`ReviewedFee::Stated`] is what is LEFT
//! after that refusal: a file this device signs nothing in, whose fee is therefore a claim
//! the review screen must label as one. Read the doc comments on
//! `Inspection::fee_is_enforced` and `AmountProof` before touching either.
//!
//! # What a review screen gets, and what it does not
//!
//! It gets the facts: [`Review::inputs`], [`Review::outputs`], the totals, the fee as
//! above, the lock time, the RBF signal and the count of unknown fields. Those are
//! notyas-core's own types, rendered rather than re-modelled, for the reason report.rs has
//! always given - one pipeline, many renderers. What it does not get is the `Inspection`
//! itself, whose `fee` field is a bare `Amount`.

use std::fmt;

use notyas_core::bitcoin::absolute::LockTime;
use notyas_core::bitcoin::bip32::Fingerprint;
use notyas_core::bitcoin::psbt::Psbt;
use notyas_core::bitcoin::{Amount, Network};
use notyas_core::derive;
use notyas_core::psbt::{
    self, CheckFailure, InputFacts, Inspection, Malformed, OutputFacts, SignFailure, SignReport,
};

use crate::wallet::Wallet;

/// Why this device will not hand back a signed file.
///
/// Four arms, and the first three are notyas-core's own verdicts carried verbatim. They are
/// not flattened into one message: "that file is not a transaction" (gate 0), "this device
/// understood the transaction and declined it" (one of the ten checks) and "the signature
/// did not survive its own gate" are three different screens and three different things for
/// the user to do next. Each inner type already names the check it belongs to and prints
/// its own sentence.
#[derive(Debug)]
pub enum Refusal {
    /// The bytes are not a PSBT this device reads.
    NotAFile(Malformed),
    /// One of ARCHITECTURE.md 5.3's checks refused. Rendered by the refusal screen, which
    /// can cite `CheckFailure::check()` for the number.
    Check(CheckFailure),
    /// Signing, or the post-sign gate that runs after every signature was produced. A
    /// refusal here yields no partially signed file at all: `psbt::sign` builds a new PSBT
    /// and returns it only on success.
    Sign(SignFailure),
    /// The review was taken under a different wallet than the one now holding the seed.
    /// Reachable only from a caller that swapped wallets between review and signature; the
    /// derive-and-compare inside `psbt::sign` would refuse it too, and this arm exists so
    /// the message is about wallets rather than about a key that cannot spend an input.
    WrongWallet {
        reviewed: Fingerprint,
        holding: Fingerprint,
    },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::NotAFile(e) => write!(f, "{e}"),
            Refusal::Check(e) => write!(f, "{e}"),
            Refusal::Sign(e) => write!(f, "{e}"),
            Refusal::WrongWallet { reviewed, holding } => write!(
                f,
                "this transaction was reviewed for wallet {reviewed} and this device is holding {holding}"
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// The fee, and whether it is a number any transaction carrying this device's signature
/// would actually have to pay.
///
/// There is deliberately no `amount()`: a caller has to match, and matching is how the
/// caveat reaches the screen. See the module header, and
/// `Inspection::fee_is_enforced` for the two ways a fee becomes enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewedFee {
    /// Every input amount was proven against its own previous transaction, or this
    /// device's signature is about to commit to all of them at once (BIP-341 hashes
    /// `sha_amounts` over every input). Lying about one then costs the coordinator a
    /// transaction that cannot confirm, not a fee the user was never shown.
    Enforced(Amount),
    /// At least one input's amount is the file's word and no signature of ours makes it
    /// binding. A lower bound on what this transaction costs, never a measurement, and it
    /// must be rendered as such beside the input whose `InputFacts::amount_proof` is
    /// `AmountProof::ClaimedByFile`.
    ///
    /// Not a refusal, and it must never become one: the engine has already refused every
    /// file where this could cost the user money. What reaches here is a transaction this
    /// device signs nothing in.
    Stated(Amount),
}

impl ReviewedFee {
    pub fn is_enforced(&self) -> bool {
        matches!(self, ReviewedFee::Enforced(_))
    }
}

/// A transaction that passed every check, with the file it was read from.
///
/// Constructed only by [`review`]. Holding one means the ten checks that could be decided
/// have been, before any key existed to sign with.
#[derive(Debug)]
pub struct Review {
    psbt: Psbt,
    inspection: Inspection,
}

impl Review {
    /// One row per input, in the transaction's own order. Every input is here, including
    /// the ones that are not ours - a signer that hides them is a signer that can be shown
    /// one thing and sign another (check 9).
    pub fn inputs(&self) -> &[InputFacts] {
        &self.inspection.inputs
    }

    /// One row per output. `OutputFacts::role` is what the device PROVED; `claims_our_key`
    /// is what the file asserted. A change page renders the first and never the second.
    pub fn outputs(&self) -> &[OutputFacts] {
        &self.inspection.outputs
    }

    /// Total in and total out, in that order. Both are sums over the same amounts the fee
    /// is, so the caveat that applies to [`Review::fee`] applies to these.
    pub fn totals(&self) -> (Amount, Amount) {
        (self.inspection.input_total, self.inspection.output_total)
    }

    /// The fee, carrying whether it is enforced. See [`ReviewedFee`].
    pub fn fee(&self) -> ReviewedFee {
        if self.inspection.fee_is_enforced() {
            ReviewedFee::Enforced(self.inspection.fee)
        } else {
            ReviewedFee::Stated(self.inspection.fee)
        }
    }

    /// How many inputs this device would sign. Zero is a wrong-wallet screen, not an error.
    pub fn signable_inputs(&self) -> usize {
        self.inspection.signable_inputs()
    }

    /// Unknown and proprietary key-value pairs the file carries. They are preserved through
    /// signing untouched and are never read for any decision; the count exists so the
    /// review screen can say they are there.
    pub fn unknown_fields(&self) -> usize {
        self.inspection.unknown_fields
    }

    pub fn lock_time(&self) -> LockTime {
        self.inspection.lock_time
    }

    /// Any input signals replaceability (BIP125).
    pub fn rbf_signaled(&self) -> bool {
        self.inspection.rbf_signaled
    }

    pub fn network(&self) -> Network {
        self.inspection.network
    }

    /// The wallet this review was taken under.
    pub fn fingerprint(&self) -> Fingerprint {
        self.inspection.fingerprint
    }

    /// Serialized size of the file that was read.
    pub fn serialized_len(&self) -> usize {
        self.inspection.serialized_len
    }

    /// SHA-256 of the exact bytes reviewed. The deliver screen prints its first bytes so
    /// that what left the device can be tied to what was on screen.
    pub fn psbt_id(&self) -> [u8; 32] {
        self.inspection.psbt_id()
    }

    /// Sign every input the review classified as ours, verify what was produced, and
    /// serialize.
    ///
    /// The seed enters here and nowhere else on this path. `psbt::sign` derives each key
    /// inside its own loop, uses it and drops it; the post-sign gate then re-verifies every
    /// signature this device made against a digest recomputed from the PSBT alone, and its
    /// result travels with the file as [`Signed::report`].
    pub fn sign(&self, wallet: &Wallet) -> Result<Signed, Refusal> {
        if self.inspection.fingerprint != wallet.fingerprint() {
            return Err(Refusal::WrongWallet {
                reviewed: self.inspection.fingerprint,
                holding: wallet.fingerprint(),
            });
        }
        let signed = psbt::sign(&self.psbt, &self.inspection, wallet.seed())
            .map_err(Refusal::Sign)?;
        Ok(Signed {
            complete: is_complete(signed.psbt(), &self.inspection),
            bytes: psbt::encode(signed.psbt()),
            report: signed.report().clone(),
        })
    }
}

/// Whether every input of the signed file now carries the signatures its script needs.
///
/// Asked HERE, where the signed PSBT and the inspection that classified it are both in
/// scope, and never recomputed from the bytes afterwards: the deliver screen renders this
/// as "complete" or "still needs another cosigner", and re-deciding it from a file would be
/// a second answer to a question this function already has all the evidence for.
///
/// It is a statement about the SIGNATURES and not about the file. Nothing in this workspace
/// finalizes a PSBT - there is no witness assembler and no `extract_tx` - so what a
/// delivery writes is a signed PSBT that a coordinator finalizes, and this is the flag that
/// tells the user whether it is waiting on anybody else.
///
/// The rule per input, and every one of them is what the script itself demands:
///
/// - a taproot key-path spend is done when `tap_key_sig` is there, because BIP-341 puts
///   exactly one signature in that witness;
/// - a P2WSH input the engine bound to a registration needs M of them, and M is read off
///   the witness script the REGISTRATION rebuilt, never off the file's copy of it;
/// - everything else needs one.
///
/// An input nobody has signed yet is not complete, whoever it belongs to. A foreign input
/// therefore keeps the file incomplete, which is the truth: another signer has to act
/// before it can be broadcast.
fn is_complete(psbt: &Psbt, inspection: &Inspection) -> bool {
    inspection.inputs.iter().all(|facts| {
        let Some(input) = psbt.inputs.get(usize::from(facts.index)) else {
            return false;
        };
        if input.tap_key_sig.is_some() {
            return true;
        }
        let needed = match &facts.multisig {
            Some(binding) => usize::from(crate::flow::model::multisig_threshold(
                binding.witness_script.as_bytes(),
            )),
            None => 1,
        };
        input.partial_sigs.len() >= needed
    })
}

/// A signed file and the gate report that let it out.
///
/// The two travel together for the reason `notyas_core::psbt::Signed` gives: a signed PSBT
/// without the evidence that its signatures were checked is exactly the artefact the gate
/// exists to prevent.
#[derive(Debug, Clone)]
pub struct Signed {
    bytes: Vec<u8>,
    report: SignReport,
    complete: bool,
}

impl Signed {
    /// The serialized PSBT, ready for the transport that will carry it off the device.
    ///
    /// Binary. Base64, hex and UR framing are transport encodings and are applied by
    /// whatever is writing the file, which is also what knows the name and the channel.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// What the post-sign gate actually verified. Rendered in the deliver screen's small
    /// print: a gate whose result nobody can see is a gate nobody can tell has stopped
    /// running.
    pub fn report(&self) -> &SignReport {
        &self.report
    }

    /// Every input now carries the signatures its script needs. See [`is_complete`].
    pub fn complete(&self) -> bool {
        self.complete
    }
}

/// Read a file and decide whether it may be signed, with no signing key in scope.
///
/// The context comes from `wallet` and from nothing else (see `crate::wallet`): the network
/// and the fingerprint that decide which inputs are ours are device facts, and a file that
/// could move either would be deciding its own ownership.
///
/// # Why the accounts are here
///
/// `psbt::inspect` is `inspect_with_accounts` with an EMPTY slice, and check 3 has two
/// halves: multisig outputs against `Context::registry`, single-sig outputs against the
/// accounts the caller supplies. Calling `inspect` was therefore running half the check on
/// hardware - a single-sig change output could not be proven, so it was labelled a payment
/// and counted as money leaving, and every review of an ordinary single-sig spend
/// overstated what the transaction sends by the whole of its change.
///
/// `derive::device_accounts` is what the second half needs, and it is a device fact in the
/// same sense the registry is: an `Account` holds an account XPUB, cannot be built from a
/// PSBT, and proves an output only by rebuilding the exact script it pays. So the pipeline
/// still derives nothing from a file's say-so, and the four account nodes that go into it
/// could only have come from this seed.
///
/// COUPLING (wallet). The right home for these is `Wallet`, derived once at open time
/// beside the registry - which is proven from the seed there for exactly this reason - and
/// carried on `Context` alongside `registry`. That is a change to `firmware/src/wallet/`
/// and to `psbt::Context`'s shape; until it is made, this call site pays four hardened
/// derivations per review and the seed is borrowed for the length of them.
pub fn review(wallet: &Wallet, bytes: &[u8]) -> Result<Review, Refusal> {
    let psbt = psbt::decode(bytes).map_err(Refusal::NotAFile)?;
    let accounts = derive::device_accounts(wallet.seed(), wallet.network());
    let inspection =
        psbt::inspect_with_accounts(&psbt, &wallet.context(), &accounts).map_err(Refusal::Check)?;
    Ok(Review { psbt, inspection })
}

/// The whole pipeline in one call: bytes in, signed bytes out.
///
/// The form a bench console or a known-answer check wants, where no human reads a review
/// screen in between. The product path is [`review`], the review screens, and then
/// [`Review::sign`] on the hold-to-sign gesture; this function is that same sequence with
/// nothing skipped, and it is a convenience rather than a shortcut - every check still
/// runs, and a refusal still ends the transaction.
pub fn sign(wallet: &Wallet, bytes: &[u8]) -> Result<Signed, Refusal> {
    review(wallet, bytes)?.sign(wallet)
}
