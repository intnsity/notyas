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
    self, CheckFailure, InputFacts, Inspection, Malformed, OutputFacts, ScriptKind, SignFailure,
    SignReport,
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
///
/// Every one of those rules is asked of `InputFacts::kind`, which is the engine's verdict
/// from rebuilding the script, and never of which fields the file happens to carry. The
/// distinction is the whole of this function's honesty. `tap_key_sig` is a coordinator-
/// writable slot that nothing rejects on a non-taproot input - `global_sanity` does not
/// scan for it, check 8 runs only on inputs classified `P2tr`, `unsigned_id` strips it
/// before hashing, and `psbt::sign` clones the input file into its output - so a planted
/// one arrives here intact. Read as evidence it would have said a 2-of-3 holding one of
/// its two signatures was ready to broadcast, which is the one lie a signer's delivery
/// screen exists to prevent. It is evidence of nothing except on the one kind of input
/// whose witness actually consumes it.
fn is_complete(psbt: &Psbt, inspection: &Inspection) -> bool {
    inspection.inputs.iter().all(|facts| {
        let Some(input) = psbt.inputs.get(usize::from(facts.index)) else {
            return false;
        };
        if facts.kind == ScriptKind::P2tr {
            return input.tap_key_sig.is_some();
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

// ---------------------------------------------------------------------------------------
// Transport encoding
// ---------------------------------------------------------------------------------------

/// The text wrapper a PSBT file travelled in, and the rule for reproducing it on the way
/// back out.
///
/// `psbt::decode` reads binary only, by design: `PSBT_MAGIC` (`psbt\xff`) is the only shape
/// it will accept, and base64/hex are a transport concern handled one layer up (its own
/// doc comment says so). This type is that layer. BlueWallet writes its unsigned export as
/// base64 TEXT under a `.psbt` name (`screen/send/psbtWithHardwareWallet.tsx`), and its
/// "Open signed transaction" picker reads whatever file comes back with RNFS's default
/// UTF-8 text read (`blue_modules/fs.ts`'s `openSignedTransactionRaw`) - a binary reply is
/// mangled before that app ever gets to look at it. A device that always answered in binary
/// could therefore never round trip through BlueWallet's own read path; one that always
/// answered in base64 would break every coordinator that genuinely does hand it binary.
/// Coldcard's answer, in `shared/auth.py`'s `psbt_encoding_taster`, is to sniff the wrapper
/// the file arrived in and reply in the same one, and that is what this type carries: a
/// value threaded from the read that discovered it ([`PsbtEncoding::sniff`]) to the write
/// that has to match it, so a fourth wrapper showing up later is a compile error at every
/// site that matches on this enum rather than a write that silently guesses wrong.
///
/// Hex is real and not hypothetical - Coldcard emits and accepts it too - and this device
/// now does both directions of all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtEncoding {
    /// BIP-174's own framing: `PSBT_MAGIC` and the raw key-value stream.
    Binary,
    /// ASCII hex of the binary form. Either case decodes; this device always writes
    /// lowercase.
    Hex,
    /// Standard base64 (RFC 4648 section 4: `A-Za-z0-9+/`, optional `=` padding) of the
    /// binary form.
    Base64,
}

/// Why a file's wrapper could not be turned into the PSBT bytes underneath it.
///
/// This is about the WRAPPER and is raised before `psbt::decode` ever runs, which is the
/// distinction the whole type exists for: a base64 export that LOOKED like a PSBT - it
/// opened with `cHNidP`, base64 for `PSBT_MAGIC` - and then failed to decode is not "not a
/// PSBT". `Malformed::NotAPsbt` would be the wrong sentence there: it sends the user to
/// re-export a file whose transport, not whose content, is the actual problem. Every
/// variant here names the transport fault instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingError {
    /// A base64 `=` pad character appeared before the final group. Padding only means
    /// anything in the last four characters of the stream; one earlier means an encoder or
    /// a transfer truncated the file after it, and decoding around it would silently keep
    /// only the part that arrived.
    Base64PadMidStream,
    /// The base64 body's own structure was not respected: a byte outside `A-Za-z0-9+/=`,
    /// or a length (real characters plus padding, after CR/LF/space/tab are skipped) that
    /// is not a multiple of four.
    Base64Malformed,
    /// The hex digit stream had an odd number of digits, or a byte that is not one.
    HexMalformed,
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodingError::Base64PadMidStream => write!(
                f,
                "this base64 file has a '=' before its final group, which means it was cut short"
            ),
            EncodingError::Base64Malformed => write!(f, "this file is not valid base64"),
            EncodingError::HexMalformed => write!(f, "this file is not valid hex"),
        }
    }
}

impl std::error::Error for EncodingError {}

impl PsbtEncoding {
    /// Identify the wrapper from a file's first bytes, Coldcard-style: three fixed
    /// prefixes and nothing else. `psbt_encoding_taster` raises on anything that matches
    /// none of them rather than guessing, and this does the same by returning `None` - the
    /// caller's contract on `None` is to hand the bytes to `psbt::decode` unchanged and let
    /// gate 0 say they are not a PSBT, which for a file with none of these three wrappers
    /// is the truth. A leading UTF-8 BOM and leading CR/LF/space/tab are skipped first: a
    /// text editor or a coordinator's own file write can prepend either without changing
    /// what the file means.
    pub fn sniff(bytes: &[u8]) -> Option<PsbtEncoding> {
        let bytes = skip_bom_and_leading_ws(bytes);
        if bytes.starts_with(&psbt::PSBT_MAGIC) {
            return Some(PsbtEncoding::Binary);
        }
        if bytes.len() >= 10 && bytes[..10].eq_ignore_ascii_case(b"70736274ff") {
            return Some(PsbtEncoding::Hex);
        }
        // Base64 of `PSBT_MAGIC` never lands on a group boundary, so every base64 PSBT -
        // BlueWallet's export included - opens with exactly these six characters.
        if bytes.starts_with(b"cHNidP") {
            return Some(PsbtEncoding::Base64);
        }
        None
    }

    /// Unwrap a file carrying this encoding into the binary PSBT bytes underneath it.
    /// `psbt::decode` still runs after this and is what actually validates the result -
    /// this only undoes the text framing.
    pub fn decode(self, bytes: &[u8]) -> Result<Vec<u8>, EncodingError> {
        match self {
            // The same leading BOM/whitespace `sniff` may have looked past to find the
            // magic has to come off here too, or the bytes handed to `psbt::decode` would
            // still carry it and fail the exact-prefix check `sniff` just satisfied.
            PsbtEncoding::Binary => Ok(skip_bom_and_leading_ws(bytes).to_vec()),
            PsbtEncoding::Hex => hex_decode(bytes),
            PsbtEncoding::Base64 => base64_decode(bytes),
        }
    }

    /// Wrap signed binary PSBT bytes back in this same encoding, for the write that
    /// mirrors the read. This device's own output is always well-formed, so unlike
    /// [`PsbtEncoding::decode`] this cannot fail.
    pub fn encode(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            PsbtEncoding::Binary => bytes.to_vec(),
            PsbtEncoding::Hex => hex_encode(bytes).into_bytes(),
            PsbtEncoding::Base64 => base64_encode(bytes).into_bytes(),
        }
    }
}

/// A leading UTF-8 BOM (`EF BB BF`), stripped if present.
fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes)
}

/// [`strip_bom`], then any leading CR/LF/space/tab - the framing a text file can carry in
/// front of its real content without changing what that content is.
fn skip_bom_and_leading_ws(bytes: &[u8]) -> &[u8] {
    let bytes = strip_bom(bytes);
    let start = bytes
        .iter()
        .position(|b| !matches!(b, b'\r' | b'\n' | b' ' | b'\t'))
        .unwrap_or(bytes.len());
    &bytes[start..]
}

/// Lowercase ASCII hex of `bytes`.
fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    out
}

/// Decode ASCII hex (either case) into the bytes it spells. Tolerates the same framing
/// [`base64_decode`] does - a leading BOM and CR/LF/space/tab anywhere in the body - for
/// the same reason: nothing about those bytes is part of the PSBT.
fn hex_decode(text: &[u8]) -> Result<Vec<u8>, EncodingError> {
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let text = strip_bom(text);
    let mut digits = Vec::with_capacity(text.len());
    for &b in text {
        if matches!(b, b'\r' | b'\n' | b' ' | b'\t') {
            continue;
        }
        digits.push(nibble(b).ok_or(EncodingError::HexMalformed)?);
    }
    if digits.len() % 2 != 0 {
        return Err(EncodingError::HexMalformed);
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        out.push((pair[0] << 4) | pair[1]);
    }
    Ok(out)
}

/// Standard base64 (RFC 4648), encoder half. Padded, no line wrapping: the shape
/// `Buffer.toString('base64')` produces, which is what BlueWallet's own export is
/// ([`PsbtEncoding`]'s doc) and what this device now mirrors on the way out.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(ALPHABET[usize::try_from((n >> 18) & 0x3f).unwrap_or(0)] as char);
        out.push(ALPHABET[usize::try_from((n >> 12) & 0x3f).unwrap_or(0)] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[usize::try_from((n >> 6) & 0x3f).unwrap_or(0)] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[usize::try_from(n & 0x3f).unwrap_or(0)] as char
        } else {
            '='
        });
    }
    out
}

/// Standard base64, decoder half - hand rolled, and hardened for the framing real files
/// carry rather than the clean bytes a spec's examples show:
///
/// - a leading UTF-8 BOM is stripped ([`strip_bom`]);
/// - CR, LF, space and tab are skipped anywhere in the body, not only at the ends - a file
///   that passed through a text editor or a line-wrapping mailer can carry any of them;
/// - padding is optional (RFC 4648 section 3.2 makes it redundant with the length, and not
///   every exporter writes it);
/// - a `=` before the final group is REFUSED rather than decoded around. Padding only
///   means anything at the true end of the stream; one earlier is not a shorter file, it is
///   a truncated one, and decoding through it would silently keep only what arrived before
///   the cut - the one failure mode this function must never produce quietly.
fn base64_decode(input: &[u8]) -> Result<Vec<u8>, EncodingError> {
    const INVALID: i8 = -1;
    const TABLE: [i8; 256] = {
        let mut t = [INVALID; 256];
        let mut i = 0;
        while i < 26 {
            t[(b'A' as usize) + i] = i as i8;
            i += 1;
        }
        let mut i = 0;
        while i < 26 {
            t[(b'a' as usize) + i] = (26 + i) as i8;
            i += 1;
        }
        let mut i = 0;
        while i < 10 {
            t[(b'0' as usize) + i] = (52 + i) as i8;
            i += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };

    let input = strip_bom(input);
    let mut data: Vec<i8> = Vec::with_capacity(input.len());
    let mut padding = 0usize;
    let mut pad_seen = false;
    for &b in input {
        match b {
            b'\r' | b'\n' | b' ' | b'\t' => continue,
            b'=' => {
                pad_seen = true;
                padding += 1;
                if padding > 2 {
                    return Err(EncodingError::Base64Malformed);
                }
            }
            _ => {
                if pad_seen {
                    return Err(EncodingError::Base64PadMidStream);
                }
                let v = TABLE[b as usize];
                if v == INVALID {
                    return Err(EncodingError::Base64Malformed);
                }
                data.push(v);
            }
        }
    }
    if data.is_empty() || data.len() % 4 == 1 {
        return Err(EncodingError::Base64Malformed);
    }
    if padding > 0 && (data.len() + padding) % 4 != 0 {
        return Err(EncodingError::Base64Malformed);
    }

    let mut out = Vec::with_capacity(data.len() / 4 * 3);
    let mut groups = data.chunks_exact(4);
    for g in &mut groups {
        out.push(((g[0] as u8) << 2) | ((g[1] as u8) >> 4));
        out.push(((g[1] as u8) << 4) | ((g[2] as u8) >> 2));
        out.push(((g[2] as u8) << 6) | (g[3] as u8));
    }
    let rem = groups.remainder();
    match rem.len() {
        0 => {}
        2 => out.push(((rem[0] as u8) << 2) | ((rem[1] as u8) >> 4)),
        3 => {
            out.push(((rem[0] as u8) << 2) | ((rem[1] as u8) >> 4));
            out.push(((rem[1] as u8) << 4) | ((rem[2] as u8) >> 2));
        }
        _ => unreachable!("data.len() % 4 == 1 was already refused"),
    }
    Ok(out)
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

#[cfg(test)]
mod tests {
    //! Host cover for the judgements this file makes that no engine owns. Compiled and run
    //! by `firmware/hostcheck/tests/signing_complete.rs`, which supplies the crate root -
    //! the firmware itself cannot be built on a host at any price. See that file.

    use super::*;
    use notyas_core::bitcoin::secp256k1::schnorr;
    use notyas_core::bitcoin::sighash::TapSighashType;
    use notyas_core::bitcoin::taproot;
    use notyas_core::psbt::fixture;

    /// A taproot key-path signature nobody produced. Sixty-four bytes of a fixed pattern is
    /// everything the PSBT field has to be: it is a coordinator-writable slot, no check
    /// reads it on a non-taproot input, and `unsigned_id` strips it before hashing, so a
    /// file carrying one is a file this device accepts and signs.
    fn planted_tap_key_sig() -> taproot::Signature {
        taproot::Signature {
            signature: schnorr::Signature::from_slice(&[0x11; 64]).expect("64 bytes"),
            sighash_type: TapSighashType::Default,
        }
    }

    /// A 2-of-3 P2WSH input carrying a planted `tap_key_sig` is NOT complete after this
    /// device signs it: the witness that spends it takes two ECDSA signatures off the
    /// witness script and will never read a taproot field, so the honest answer is that the
    /// file still needs the other cosigner.
    ///
    /// The field is planted BEFORE the inspection, which is where an attacker puts it - the
    /// card file is what it is by the time this device reads it - and the inspection binds
    /// to those exact bytes, so this is one file travelling one path.
    #[test]
    fn a_planted_tap_key_sig_does_not_complete_a_multisig_input() {
        let registry = vec![fixture::registration()];
        let mut psbt = fixture::multisig_psbt();
        psbt.inputs[0].tap_key_sig = Some(planted_tap_key_sig());

        let inspection = psbt::inspect(&psbt, &fixture::context_with(&registry))
            .expect("a stray taproot field is not a refusal - no check reads it");
        let signed = psbt::sign(&psbt, &inspection, &fixture::SEED).expect("our leg signs");

        // One of the two signatures the script demands, which is the fact the flag has to
        // report. The planted field survives into the output because `sign` clones the
        // input file, which is exactly how it reaches the flag.
        assert_eq!(signed.psbt().inputs[0].partial_sigs.len(), 1);
        assert!(signed.psbt().inputs[0].tap_key_sig.is_some());
        assert!(
            !is_complete(signed.psbt(), &inspection),
            "a 2-of-3 with one signature was reported ready to broadcast"
        );
    }

    /// The same planting on a FOREIGN input - one this device does not own and will not
    /// sign. Nobody has signed it, so the file is not complete whatever the field says, and
    /// the user still has to forward it.
    #[test]
    fn a_planted_tap_key_sig_does_not_complete_a_foreign_input() {
        let mut psbt = fixture::ours_and_a_foreign_input_psbt();
        psbt.inputs[1].tap_key_sig = Some(planted_tap_key_sig());

        let inspection = psbt::inspect(&psbt, &fixture::context()).expect("a readable file");
        let signed = psbt::sign(&psbt, &inspection, &fixture::SEED).expect("our input signs");

        // Ours is done; the cosigner's is untouched, which is the whole point of the flag.
        assert_eq!(signed.psbt().inputs[0].partial_sigs.len(), 1);
        assert!(signed.psbt().inputs[1].partial_sigs.is_empty());
        assert!(
            !is_complete(signed.psbt(), &inspection),
            "an input nobody has signed was reported ready to broadcast"
        );
    }

    /// The other direction, so the gate above cannot be tightened into a lie: a real
    /// taproot key-path spend IS complete on its `tap_key_sig` alone, because BIP-341 puts
    /// exactly one signature in that witness.
    #[test]
    fn a_taproot_key_path_input_is_complete_on_its_tap_key_sig() {
        let psbt = fixture::p2tr_psbt();
        let inspection = psbt::inspect(&psbt, &fixture::context()).expect("a readable file");
        let signed = psbt::sign(&psbt, &inspection, &fixture::SEED).expect("our key signs");

        assert!(signed.psbt().inputs[0].partial_sigs.is_empty());
        assert!(signed.psbt().inputs[0].tap_key_sig.is_some());
        assert!(is_complete(signed.psbt(), &inspection));
    }

    /// And the ordinary single-sig case, which the count has always covered.
    #[test]
    fn a_signed_p2wpkh_input_is_complete() {
        let psbt = fixture::p2wpkh_psbt();
        let inspection = psbt::inspect(&psbt, &fixture::context()).expect("a readable file");
        let signed = psbt::sign(&psbt, &inspection, &fixture::SEED).expect("our key signs");

        assert!(is_complete(signed.psbt(), &inspection));
    }

    // -----------------------------------------------------------------------------------
    // Transport encoding
    // -----------------------------------------------------------------------------------

    fn fixture_a_binary() -> Vec<u8> {
        psbt::encode(&fixture::bluewallet_watch_only_psbt())
    }

    #[test]
    fn binary_in_produces_binary_out() {
        let raw = fixture_a_binary();
        let encoding = PsbtEncoding::sniff(&raw).expect("PSBT_MAGIC sniffs as Binary");
        assert_eq!(encoding, PsbtEncoding::Binary);
        let decoded = encoding.decode(&raw).expect("binary decode is a passthrough");
        assert_eq!(decoded, raw);
        assert_eq!(encoding.encode(&decoded), raw);
    }

    #[test]
    fn hex_in_produces_hex_out() {
        let raw = fixture_a_binary();
        let text = hex_encode(&raw).into_bytes();
        let encoding = PsbtEncoding::sniff(&text).expect("the hex magic sniffs as Hex");
        assert_eq!(encoding, PsbtEncoding::Hex);
        let decoded = encoding.decode(&text).expect("well-formed hex decodes");
        assert_eq!(decoded, raw);
        assert_eq!(encoding.encode(&decoded), text);
    }

    #[test]
    fn base64_in_produces_base64_out() {
        let raw = fixture_a_binary();
        let text = base64_encode(&raw).into_bytes();
        let encoding = PsbtEncoding::sniff(&text).expect("cHNidP sniffs as Base64");
        assert_eq!(encoding, PsbtEncoding::Base64);
        let decoded = encoding.decode(&text).expect("well-formed base64 decodes");
        assert_eq!(decoded, raw);
        assert_eq!(encoding.encode(&decoded), text);
    }

    #[test]
    fn unpadded_base64_is_accepted() {
        let raw = b"BlueWallet PSBT export test payload, deliberately not a multiple of 3!";
        let mut unpadded = base64_encode(raw).into_bytes();
        while unpadded.last() == Some(&b'=') {
            unpadded.pop();
        }
        assert_eq!(base64_decode(&unpadded).unwrap(), raw);
    }

    #[test]
    fn a_leading_bom_is_stripped_before_sniffing_and_decoding() {
        let raw = fixture_a_binary();
        let mut with_bom = vec![0xef, 0xbb, 0xbf];
        with_bom.extend_from_slice(base64_encode(&raw).as_bytes());
        assert_eq!(PsbtEncoding::sniff(&with_bom), Some(PsbtEncoding::Base64));
        assert_eq!(PsbtEncoding::Base64.decode(&with_bom).unwrap(), raw);
    }

    #[test]
    fn crlf_and_interior_whitespace_are_skipped() {
        let raw = fixture_a_binary();
        let clean = base64_encode(&raw);
        // Wrap at 16 characters with CRLF, the way a text editor or a line-wrapping mailer
        // might have re-flowed the file.
        let mut wrapped = String::new();
        for (i, ch) in clean.chars().enumerate() {
            if i > 0 && i % 16 == 0 {
                wrapped.push_str("\r\n");
            }
            wrapped.push(ch);
        }
        assert_eq!(base64_decode(wrapped.as_bytes()).unwrap(), raw);
    }

    /// The failure this decoder must never paper over: a `=` that is not padding but a
    /// truncation, decoded around instead of refused, would silently hand the parser a
    /// PSBT missing whatever came after the cut.
    #[test]
    fn a_pad_character_before_the_final_group_is_refused() {
        let raw = fixture_a_binary();
        let mut text = base64_encode(&raw).into_bytes();
        let mid = text.len() / 2;
        text[mid] = b'=';
        assert_eq!(base64_decode(&text), Err(EncodingError::Base64PadMidStream));
    }

    /// No wrapper this device recognises. `sniff` returns `None` rather than guessing, and
    /// the caller's contract on `None` (see its doc) is to hand the bytes to `psbt::decode`
    /// unchanged - proven at the codec layer's own `a_wrong_file_says_so_rather_than_
    /// blaming_the_psbt`. What this pins is that sniffing itself neither misclassifies nor
    /// panics on content that is not a transaction in any encoding.
    #[test]
    fn a_file_with_no_recognised_wrapper_is_refused_cleanly() {
        assert_eq!(
            PsbtEncoding::sniff(b"this is not a transaction in any encoding"),
            None
        );
        assert_eq!(PsbtEncoding::sniff(b""), None);
    }

    /// Fixture H (`fixture::bluewallet_base64_text`): fixture A exactly as BlueWallet
    /// writes it to an SD card - base64 text, trailing newline, `.psbt` extension implied
    /// by the file name rather than by these bytes. This is the concrete failure the whole
    /// module exists to fix, followed start to finish: sniff, unwrap, review, sign, and
    /// re-wrap in the SAME base64 encoding - the shape BlueWallet's own file read
    /// (`blue_modules/fs.ts`'s `openSignedTransactionRaw`) expects back.
    #[test]
    fn bluewallet_base64_export_signs_and_rewraps_in_base64() {
        let text = fixture::bluewallet_base64_text();
        let encoding = PsbtEncoding::sniff(&text).expect("BlueWallet's export sniffs as base64");
        assert_eq!(encoding, PsbtEncoding::Base64);
        let unwrapped = encoding
            .decode(&text)
            .expect("BlueWallet's export is well-formed base64");
        assert_eq!(unwrapped, fixture_a_binary(), "recovers exactly fixture A's bytes");

        let wallet = Wallet::for_test(fixture::NETWORK, fixture::fingerprint(), fixture::SEED);
        let review = review(&wallet, &unwrapped).expect("fixture A reviews clean");
        let signed = review.sign(&wallet).expect("fixture A signs");

        let rewrapped = encoding.encode(signed.bytes());
        assert_eq!(PsbtEncoding::sniff(&rewrapped), Some(PsbtEncoding::Base64));
        assert_eq!(encoding.decode(&rewrapped).unwrap(), signed.bytes());
    }
}
