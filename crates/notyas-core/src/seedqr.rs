// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! SeedQR ingress (0.2.0-m11): a scanned QR payload becomes a mnemonic here, or it is
//! refused here. Decode only - see "What this module deliberately does not do" below.
//!
//! # The trust boundary
//!
//! Every other module in this crate is fed by the user's own keystrokes or by a file the
//! user chose. This one is fed by a camera, and a camera photographs whatever is put in
//! front of it: the bytes arriving here were chosen by whoever printed, etched or
//! displayed the symbol, which on a signer is exactly the adversary's position. So the
//! rule for this module is the opposite of the rest of the crate's forgiving input
//! handling - structure, length, charset, range and checksum are all proven before any of
//! it is allowed to become a seed, and anything unproven is refused with a reason rather
//! than repaired into something plausible. `Q48`'s safety case rests on that: a scanned
//! seed follows exactly the same path as a typed one, with no shortcut for having arrived
//! by camera.
//!
//! # The two formats, from the specification
//!
//! Both are SeedSigner's, and the normative text is
//! <https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md>. The rules
//! this module implements, quoted:
//!
//! - Standard SeedQR: "We take the indices of the mnemonic seed phrase and write them in
//!   order, one after the next as one long stream of digits. Each index must be exactly
//!   four digits, so shorter numbers must be zero-padded (`12` becomes `0012`)." The
//!   indices are zero-based positions in the English BIP-39 list, so 12 words are 48
//!   digits and 24 words are 96, encoded in the QR numeric mode.
//! - CompactSeedQR: the same indices as an 11-bit-per-word stream with the checksum bits
//!   dropped - "The checksum is trivially calculated from the prior bits ... Therefore we
//!   do not need to include those bits in our CompactSeedQR" - which leaves exactly the
//!   BIP-39 entropy: "12-word CompactSeedQR = 132 bits - 4 checksum bits = 128 bits",
//!   "24-word CompactSeedQR = 264 bits - 8 checksum bits = 256 bits", encoded in the QR
//!   byte mode as 16 or 32 raw bytes.
//! - "SeedQR specifically assumes and recommends using the English BIP39 wordlist" and
//!   carries no field naming the language, which is why [`crate::bip39`]'s English list is
//!   the only one consulted and why a payload written against another list decodes to the
//!   wrong seed rather than to an error. That is the format's limitation, not this
//!   module's; it is the reason the scan flow shows the words and the fingerprint before
//!   anything is kept.
//!
//! Telling the two apart is not cosmetic. The same 12-word seed is 48 digits in one
//! format and 16 arbitrary bytes in the other, and decoding either as the other yields a
//! different, perfectly valid-looking wallet with no error anywhere - the failure mode
//! that loses money silently. Here the two are separated by a property that cannot
//! overlap: the accepted lengths are disjoint (16/32 against 48/96), so no payload can be
//! classified as both, and `classify` is a total function of the payload alone rather than
//! an ordered list of guesses. `tests/seedqr_vectors.rs` asserts the disjointness.
//!
//! # Why exactly four lengths are accepted
//!
//! [`ACCEPTED_LENGTHS`] is the whole ingress surface. It is the set the specification
//! defines and nothing else: no 15/18/21-word Standard SeedQR (60, 72 or 84 digits), no
//! 20/24/28-byte CompactSeedQR. Those lengths are arithmetically well formed, but no
//! published encoder emits them, so accepting them would widen an untrusted parser's
//! surface for no user - a user with such a phrase still has manual entry, and is told
//! why by [`IngressError::UnknownLength`] rather than left guessing.
//!
//! # The never-trim invariant
//!
//! Nothing here trims, unescapes, upper- or lower-cases, or otherwise touches the payload
//! before length and charset are decided. A CompactSeedQR is raw entropy, so every byte
//! value is data: published test vector 1's 24-word bytestream ENDS in `0x0a` and vectors
//! 7, 8 and 9 exist precisely because their entropy contains `0x0a`, `0x0d` and `0x0d 0x0a`.
//! A "helpful" trailing-whitespace trim would turn vector 1 into a 31-byte payload - a
//! refusal at best, and if a trim were paired with a re-pad it would be a different seed.
//! Equally, vectors 2 and 6 contain an embedded `0x00`: this module takes `&[u8]`, never a
//! `&str` or a C string, so a payload cannot be silently truncated at a NUL.
//!
//! # What this module deliberately does not do
//!
//! - **It does not encode.** Q17 declined SeedQR display-out; the encoder exists only in
//!   `tests/seedqr_fuzz.rs`, where it is the round-trip oracle. There is no path from a
//!   seed in this device to a QR on its screen, and adding one is a security decision, not
//!   a convenience.
//! - **It cannot tell a real CompactSeedQR from any other 16 or 32 byte QR.** The format
//!   carries no magic, no version and no integrity check whatsoever: the checksum is
//!   recomputed from the entropy, so EVERY 16-byte and 32-byte payload is a valid seed for
//!   some wallet. A mis-aimed scan that resolves a different symbol therefore produces a
//!   valid mnemonic, not an error. No validator can close that gap - only the user can,
//!   by confirming the words and the fingerprint on screen, which is why the scan flow
//!   shows them and why a camera is not allowed to approve anything. The Standard format
//!   is different in kind: its 4-bit or 8-bit BIP-39 checksum rejects roughly 15 of every
//!   16 corrupted digit streams, and [`IngressError::ChecksumFailed`] is that rejection.
//! - **It does not classify anything but a SeedQR.** The scan screen's autodetect table
//!   (UR, BBQr, descriptors, addresses, plain text) lives with its caller. Two ordering
//!   requirements it must respect are stated on [`classify`].
//!
//! # A note on the licence header
//!
//! Q8 puts a standalone `seedqr` crate under MIT OR Apache-2.0, on the reasoning that an
//! 11-bit packer for a published format has no implementation to protect. This file is
//! GPL-3.0-or-later anyway, because it is not that crate: it is a module of
//! GPL-3.0-or-later notyas-core, and half of what it contains is not the format at all but
//! this project's acceptance policy - which lengths are admitted, what a refusal means,
//! and the rule that nothing is ever coerced into a seed. The format half is written to
//! separate cleanly ([`classify`], `index_from_digits` and `mnemonic_from_entropy`
//! know nothing about policy), so the 0.3.0 extraction Q8 describes stays a move rather
//! than a rewrite, and re-heading a file is a one-line change on the day the owner makes
//! that call. Relicensing the policy half by accident would not be.

// This module parses bytes an adversary chose. A panic here is not a crash to be fixed
// later: it takes down a signer while the user is looking at a paper backup, and it does
// it on input the attacker picks. So the crate's one untrusted-input parser is compiled
// under the same proof obligation notyas-wallet's sealing engine carries - no indexing, no
// unwrap, no arithmetic that can trap - and the fuzz harness then demonstrates it over a
// corpus rather than only asserting it.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use core::fmt;

use alloc::string::String;
use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::bip39::{self, Checksum, Mnemonic, MnemonicMode, WORDLIST_LEN};
use crate::entropy::DiceEntropy;

/// Digits per word index in a Standard SeedQR, from the specification's padding rule.
const DIGITS_PER_INDEX: usize = 4;

/// Payload length in bytes of each defined format and word count. Named rather than
/// written inline because they are also the match patterns [`classify`] dispatches on, and
/// a bare `16 | 32 => Compact` is where a fifth length gets added by accident.
const COMPACT_12_WORDS: usize = 16;
const COMPACT_24_WORDS: usize = 32;
const STANDARD_12_WORDS: usize = 48;
const STANDARD_24_WORDS: usize = 96;

/// The complete ingress surface: a payload whose length is not one of these four is not a
/// SeedQR and is never parsed further. Ascending, and the fuzz harness sweeps every length
/// around them.
pub const ACCEPTED_LENGTHS: [usize; 4] = [
    COMPACT_12_WORDS,
    COMPACT_24_WORDS,
    STANDARD_12_WORDS,
    STANDARD_24_WORDS,
];

/// The longest payload that can be a SeedQR. [`decode`] rejects anything longer as its
/// first act, before it has allocated a byte, which is what bounds this module's memory
/// use against a symbol claiming megabytes.
pub const MAX_PAYLOAD_LEN: usize = STANDARD_24_WORDS;

/// Words in the longest accepted payload.
const MAX_WORDS: usize = 24;

/// Upper bound on the phrase this module builds: 24 words of at most 8 characters
/// ("abandon" is 7, the longest entries are 8) plus 23 separators, rounded to 24 * 9.
/// Used as an exact `with_capacity` so the buffer never grows - a grown `String` leaves
/// the partial phrase in freed heap where nothing wipes it, which is the reason
/// [`crate::bip39::normalize_phrase`] sizes its buffer the same way.
const MAX_PHRASE_BYTES: usize = 216;

/// Upper bound on the '0'/'1' bit string [`mnemonic_from_entropy`] builds: 32 bytes of
/// entropy at 8 characters each. Same fixed-capacity reasoning as [`MAX_PHRASE_BYTES`].
const MAX_ENTROPY_BIT_CHARS: usize = 256;

/// Which of SeedSigner's two encodings a payload is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Word indices as zero-padded 4-digit decimal, QR numeric mode.
    Standard,
    /// Raw BIP-39 entropy with the checksum bits dropped, QR byte mode.
    Compact,
}

impl Format {
    /// The name the UI and the logs use. Stable: it appears on the confirmation screen
    /// that tells the user which format was read, which is the user's only defence
    /// against a format confusion this module cannot detect.
    pub fn as_str(self) -> &'static str {
        match self {
            Format::Standard => "SeedQR",
            Format::Compact => "CompactSeedQR",
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a payload was refused.
///
/// Every variant names one property that failed and where, because "invalid QR" in front
/// of a user holding a metal plate is indistinguishable from a broken camera. None of
/// these carries secret material: an offset and a length describe the symbol's shape, and
/// [`IngressError::IndexOutOfRange`]'s value is by definition not a word index, so the
/// derived `Debug` is safe here in a way it would not be on a type holding entropy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressError {
    /// Longer than any SeedQR can be. Returned before anything is allocated.
    TooLong { len: usize },
    /// Not the length of any defined format, so not a SeedQR at all.
    UnknownLength { len: usize },
    /// A Standard SeedQR's length with a byte that is not an ASCII digit at `offset`.
    NotNumeric { offset: usize },
    /// The 4-digit group at word `position` (zero-based) is `value`, which is not below
    /// 2048 and so names no BIP-39 word. Refused rather than reduced: a modulo here would
    /// turn a transcription error into a different, valid-looking wallet.
    IndexOutOfRange { position: usize, value: u16 },
    /// The words decoded and are all real, but the BIP-39 checksum does not hold. This is
    /// the one refusal that must never be softened into a warning: a phrase failing its
    /// checksum is a mis-transcribed or tampered phrase, and deriving from it anyway
    /// hands the user a wallet that no backup restores.
    ChecksumFailed { words: usize },
    /// An invariant this module depends on did not hold - a wordlist lookup that cannot
    /// miss, an entropy length [`crate::bip39`] should always accept, or a re-encoding
    /// that should have reproduced the scanned words. Unreachable for any of the four
    /// accepted lengths, and it exists so that "unreachable" is a refusal rather than an
    /// assumption: the alternative is an `expect` in the one parser fed by an adversary.
    Unverifiable,
}

impl fmt::Display for IngressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IngressError::TooLong { len } => write!(
                f,
                "scanned {len} bytes, but the largest SeedQR is {MAX_PAYLOAD_LEN} bytes (a \
                 24-word Standard SeedQR); this symbol is not a seed"
            ),
            IngressError::UnknownLength { len } => write!(
                f,
                "scanned {len} bytes, which is no SeedQR length: 48 or 96 digits for a \
                 Standard SeedQR, 16 or 32 bytes for a CompactSeedQR"
            ),
            IngressError::NotNumeric { offset } => write!(
                f,
                "byte {offset} of this Standard SeedQR is not a digit; a Standard SeedQR \
                 is digits only"
            ),
            IngressError::IndexOutOfRange { position, value } => write!(
                f,
                "word {position} reads {value:04}, but BIP-39 word indices stop at \
                 {last}; check that group of four digits",
                last = WORDLIST_LEN.saturating_sub(1)
            ),
            IngressError::ChecksumFailed { words } => write!(
                f,
                "these {words} words are all BIP-39 words but the phrase fails its BIP-39 \
                 checksum, so it is not the phrase that was backed up; re-check the \
                 symbol rather than using it"
            ),
            IngressError::Unverifiable => write!(
                f,
                "this device could not verify the scanned seed and will not use it"
            ),
        }
    }
}

impl core::error::Error for IngressError {}

/// A payload that survived the validator.
///
/// The format is carried because the user is shown which one was read: it is the only
/// signal that would reveal a format confusion, and this module cannot detect one on its
/// own (see the module docs). Deriving `Debug` is safe because [`Mnemonic`]'s own `Debug`
/// redacts, and [`Mnemonic`]'s `Drop` wipes the entropy, so this type needs neither.
#[derive(Debug)]
pub struct Scan {
    pub format: Format,
    pub mnemonic: Mnemonic,
}

/// Which format a payload is in, or `None` if it is not a SeedQR.
///
/// Total, allocation-free, and decided by length and charset alone - never by a prefix,
/// which a raw-entropy format cannot have. Two requirements on the scan screen's
/// autodetect table, which is the caller and lives outside this module:
///
/// 1. **This check must come before the plain-text charset rule.** A CompactSeedQR is byte
///    mode and may contain any byte, `0x00` included (published vectors 2 and 6), so a
///    charset rule sees it as non-text and rejects it. That is the Q48 condition-1
///    defect ("the classifier as written cannot pass its own gate"), and this function
///    is its fix.
/// 2. **This check must also come before the `ur:` and `B$` prefix rules, not after
///    them.** A CompactSeedQR's first bytes are entropy, so they are `B$` for one seed in
///    65536 and `ur:` for one in 16.7 million. A prefix-first order therefore sends a real
///    CompactSeedQR to the BBQr decoder at a rate a shipped product will meet. Length
///    settles it safely in the other direction: no UR fragment and no BBQr part is as
///    short as 16 or 32 bytes, since a BBQr part spends 8 of those on its own header
///    before any payload.
pub fn classify(payload: &[u8]) -> Option<Format> {
    match payload.len() {
        COMPACT_12_WORDS | COMPACT_24_WORDS => Some(Format::Compact),
        // Charset is part of the identity of a Standard SeedQR, not a later check: a
        // 48-byte payload that is not all digits is some other symbol, and the caller's
        // table should go on considering it rather than see it refused as a broken seed.
        STANDARD_12_WORDS | STANDARD_24_WORDS if payload.iter().all(u8::is_ascii_digit) => {
            Some(Format::Standard)
        }
        _ => None,
    }
}

/// Decode a scanned QR payload into a mnemonic, or say precisely why it is not one.
///
/// This is the ingress validator. It is the only entry point, so there is no way to reach
/// the decoders while skipping a check, and every accepted result has passed the same
/// final gate: [`crate::bip39::check_phrase`] returning [`Checksum::Valid`]. The order is
/// length, then format and charset together, then index range, then checksum - each
/// step's input already proven by the one before it.
///
/// Allocation is bounded before it begins: over [`MAX_PAYLOAD_LEN`] returns immediately,
/// and every buffer below is sized once from a constant, never grown from the payload.
pub fn decode(payload: &[u8]) -> Result<Scan, IngressError> {
    // First, and before any allocation: a QR symbol can carry kilobytes, and the caller's
    // decoder hands us whatever it found. Everything after this point works on at most 96
    // bytes.
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(IngressError::TooLong {
            len: payload.len(),
        });
    }

    let format = match classify(payload) {
        Some(format) => format,
        None => {
            return Err(match payload.len() {
                // Right length for a Standard SeedQR, wrong charset. Naming the offending
                // byte is what lets a user with a hand-etched plate find the mistake.
                STANDARD_12_WORDS | STANDARD_24_WORDS => IngressError::NotNumeric {
                    offset: payload
                        .iter()
                        .position(|byte| !byte.is_ascii_digit())
                        .unwrap_or(0),
                },
                len => IngressError::UnknownLength { len },
            })
        }
    };

    let mnemonic = match format {
        // A CompactSeedQR is entropy and nothing else, so there is nothing to parse: the
        // payload IS the entropy, and the words come from the crate's one BIP-39 encoder.
        // Which is also why the checksum below cannot fail for this format - the encoder
        // has just computed it. Compact ingress has no integrity check of its own at all,
        // and the user's confirmation of the words is the only one there is.
        Format::Compact => mnemonic_from_entropy(payload)?,
        Format::Standard => decode_standard(payload)?,
    };

    // The single choke point. Both formats pass through it, so "accepted by this module"
    // means exactly one thing and there is no per-format definition of valid to keep in
    // step. For the standard path this repeats the check that produced the entropy a few
    // lines up; for the compact path it is the cross-check that the crate's BIP-39
    // encoder and its independent verifier agree, on every scan, at the cost of one
    // SHA-256.
    let phrase = mnemonic.phrase();
    match bip39::check_phrase(&phrase).checksum {
        Checksum::Valid => Ok(Scan { format, mnemonic }),
        Checksum::Invalid => Err(IngressError::ChecksumFailed {
            words: mnemonic.words.len(),
        }),
        Checksum::NotApplicable => Err(IngressError::Unverifiable),
    }
}

/// Standard SeedQR: 4-digit groups to word indices to a checksum-proven mnemonic.
///
/// The caller has already established that the payload is 48 or 96 ASCII digits, which is
/// why no charset case appears here.
fn decode_standard(payload: &[u8]) -> Result<Mnemonic, IngressError> {
    let list = bip39::wordlist();
    let mut phrase = Zeroizing::new(String::with_capacity(MAX_PHRASE_BYTES));
    let mut scanned: Vec<&'static str> = Vec::with_capacity(MAX_WORDS);

    for (position, group) in payload.chunks_exact(DIGITS_PER_INDEX).enumerate() {
        // Cannot fail: the group is four ASCII digits, so the value is at most 9999.
        let value = index_from_digits(group).ok_or(IngressError::Unverifiable)?;
        // The range check IS this lookup. 2048..=9999 misses the list and is refused with
        // the group that caused it; there is deliberately no fallback that maps such a
        // value onto some word.
        let word = list
            .get(usize::from(value))
            .copied()
            .ok_or(IngressError::IndexOutOfRange { position, value })?;
        if !phrase.is_empty() {
            phrase.push(' ');
        }
        phrase.push_str(word);
        scanned.push(word);
    }

    // check_phrase does the 11-bit unpacking and the checksum in one pass, so the entropy
    // below is the entropy of exactly the words that were scanned. Reusing it rather than
    // unpacking here is deliberate: it is the pass the crate's Trezor vectors already
    // cover, and a second unpacker in the module fed by an adversary is a second chance to
    // get the bit order wrong.
    let check = bip39::check_phrase(&phrase);
    match check.checksum {
        Checksum::Valid => {}
        Checksum::Invalid => {
            return Err(IngressError::ChecksumFailed {
                words: scanned.len(),
            })
        }
        // Every word came out of the list and the count is 12 or 24, so no
        // not-applicable case exists; refuse rather than assume.
        Checksum::NotApplicable => return Err(IngressError::Unverifiable),
    }

    // Rebuild the mnemonic from the recovered entropy through the same constructor the
    // compact path uses, then require that it reproduces the scanned words. Two things
    // fall out: every accepted `Mnemonic` in this module is built in exactly one place,
    // and the round trip digits -> entropy -> words is checked on the device at scan time
    // rather than only in a test. If the two ever disagree the phrase is not the one on
    // the paper, whichever half is wrong.
    let mnemonic = mnemonic_from_entropy(&check.entropy)?;
    if mnemonic.words != scanned {
        return Err(IngressError::Unverifiable);
    }
    Ok(mnemonic)
}

/// Four ASCII digits, most significant first, as a number. `None` if a byte is not a
/// digit or - impossibly, for four digits - the value would not fit.
///
/// Written with checked arithmetic rather than `parse`, which would need a `str` (so a
/// UTF-8 validation this module does not want) and would accept `+12`, ` 12` and `1_2`.
fn index_from_digits(group: &[u8]) -> Option<u16> {
    group.iter().try_fold(0u16, |acc, byte| {
        let digit = u16::from(byte.checked_sub(b'0')?);
        if digit > 9 {
            return None;
        }
        acc.checked_mul(10)?.checked_add(digit)
    })
}

/// BIP-39 entropy to the mnemonic it encodes, using the crate's own encoder.
///
/// This is the whole of the CompactSeedQR decode: the format's content is the entropy, and
/// the words are whatever BIP-39 says that entropy means. Routing it through
/// [`crate::bip39::mnemonic_from_dice`] rather than unpacking 11-bit groups here is the
/// point - the 11-bit packing, the checksum and the wordlist indexing then have one
/// implementation in this crate, the one the Trezor vectors already pin, and this module
/// adds no second opinion about bit order to code that reads attacker-supplied bytes.
///
/// `MnemonicMode::Raw` keeps the trailing whole 32-bit blocks of the bit string; for the
/// 128 and 256 bit lengths accepted here that is the entire string, unchanged.
fn mnemonic_from_entropy(entropy: &[u8]) -> Result<Mnemonic, IngressError> {
    let mut bits = Zeroizing::new(String::with_capacity(MAX_ENTROPY_BIT_CHARS));
    for byte in entropy {
        for shift in (0..8u32).rev() {
            // checked_shr cannot fail for shifts under 8; `unwrap_or(0)` keeps the
            // module's no-panic proof mechanical rather than argued.
            let bit = byte.checked_shr(shift).unwrap_or(0) & 1;
            bits.push(if bit == 1 { '1' } else { '0' });
        }
    }

    // `from_bits` panics on any character other than '0' or '1'. The loop above emits
    // nothing else, so that assertion is a statement about this function rather than about
    // the payload - no input can reach it. It is also the reason the bit string is built
    // here instead of being handed the payload directly.
    let dice = DiceEntropy::from_bits(&bits);
    // The two errors this can return are `NotEnoughEntropy` (under 32 bits) and
    // `EntropyTooLarge` (over 8192); the accepted lengths are 128 and 256, so neither is
    // reachable. Mapped rather than unwrapped for the reason `Unverifiable` exists.
    bip39::mnemonic_from_dice(&dice, MnemonicMode::Raw).map_err(|_| IngressError::Unverifiable)
}

#[cfg(test)]
mod tests {
    // The parser above carries the no-panic obligation; its harness does not. A test
    // SHOULD stop loudly on a broken expectation rather than carry on reporting a pass.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects
    )]

    use super::*;
    use alloc::string::ToString;

    /// SeedSigner test vector 4 (12-word), from the specification linked in the module
    /// docs. The full nine-vector set is exercised in `tests/seedqr_vectors.rs`; this one
    /// is here so the unit tests stand alone.
    const VECTOR_4_DIGITS: &[u8] = b"073318950739065415961602009907670428187212261116";
    const VECTOR_4_ENTROPY: [u8; 16] = [
        0x5b, 0xbd, 0x9d, 0x71, 0xa8, 0xec, 0x79, 0x90, 0x83, 0x1a, 0xff, 0x35, 0x9d, 0x42, 0x65,
        0x45,
    ];
    const VECTOR_4_PHRASE: &str =
        "forum undo fragile fade shy sign arrest garment culture tube off merit";

    #[test]
    fn both_formats_of_one_vector_agree() {
        let standard = decode(VECTOR_4_DIGITS).expect("published standard vector");
        let compact = decode(&VECTOR_4_ENTROPY).expect("published compact vector");
        assert_eq!(standard.format, Format::Standard);
        assert_eq!(compact.format, Format::Compact);
        assert_eq!(standard.mnemonic.phrase().as_str(), VECTOR_4_PHRASE);
        assert_eq!(compact.mnemonic.phrase().as_str(), VECTOR_4_PHRASE);
        assert_eq!(standard.mnemonic.entropy, VECTOR_4_ENTROPY.to_vec());
        assert_eq!(compact.mnemonic.entropy, VECTOR_4_ENTROPY.to_vec());
    }

    #[test]
    fn accepted_lengths_are_the_only_ones() {
        // A filler that is a digit, so a rejected length is rejected for its length and
        // not for its charset.
        for len in 0..=(MAX_PAYLOAD_LEN.saturating_add(64)) {
            let payload = alloc::vec![b'0'; len];
            let accepted = ACCEPTED_LENGTHS.contains(&len);
            assert_eq!(
                classify(&payload).is_some(),
                accepted,
                "length {len} classified against the accepted set"
            );
            if !accepted {
                let err = decode(&payload).expect_err("unaccepted length must be refused");
                assert!(
                    matches!(
                        err,
                        IngressError::UnknownLength { .. } | IngressError::TooLong { .. }
                    ),
                    "length {len} refused with {err:?}"
                );
            }
        }
    }

    #[test]
    fn a_broken_checksum_is_refused_not_coerced() {
        // Vector 4 with its first word index changed from 0733 to 0734: still twelve real
        // BIP-39 words, so only the checksum can catch it.
        let mut payload = VECTOR_4_DIGITS.to_vec();
        payload.splice(0..4, *b"0734");
        assert_eq!(
            decode(&payload).expect_err("a broken checksum must be refused"),
            IngressError::ChecksumFailed { words: 12 }
        );
    }

    #[test]
    fn an_out_of_range_group_is_refused_not_reduced() {
        // 2048 is the first value with no word. Reducing it modulo 2048 would give word 0
        // and a plausible phrase, which is the coercion this refuses.
        let mut payload = VECTOR_4_DIGITS.to_vec();
        payload.splice(4..8, *b"2048");
        assert_eq!(
            decode(&payload).expect_err("an out of range group must be refused"),
            IngressError::IndexOutOfRange {
                position: 1,
                value: 2048
            }
        );
    }

    #[test]
    fn nothing_is_trimmed_or_unescaped() {
        // Vector 4's entropy with a trailing newline is 17 bytes: no format has that
        // length, and trimming it back to the vector would be a decode of something the
        // user did not scan.
        let mut payload = VECTOR_4_ENTROPY.to_vec();
        payload.push(b'\n');
        assert_eq!(
            decode(&payload).expect_err("17 bytes is no format"),
            IngressError::UnknownLength { len: 17 }
        );

        // The same for a digit stream, where the temptation is stronger.
        let mut digits = VECTOR_4_DIGITS.to_vec();
        digits.push(b'\n');
        assert_eq!(
            decode(&digits).expect_err("49 digits is no format"),
            IngressError::UnknownLength { len: 49 }
        );
    }

    #[test]
    fn a_nul_byte_does_not_end_the_payload() {
        // Published vectors 2 and 6 contain 0x00. Here it is the whole payload: sixteen
        // NULs are a valid CompactSeedQR of the all-zero entropy, and a decoder that
        // stopped at the first NUL would see an empty payload instead.
        let payload = [0u8; COMPACT_12_WORDS];
        let scan = decode(&payload).expect("all-zero entropy is a valid compact payload");
        assert_eq!(scan.mnemonic.entropy, payload.to_vec());
        assert!(scan.mnemonic.phrase().starts_with("abandon abandon"));
    }

    #[test]
    fn a_non_digit_is_located() {
        let mut payload = VECTOR_4_DIGITS.to_vec();
        payload.splice(9..10, *b"x");
        assert_eq!(
            decode(&payload).expect_err("a non digit must be refused"),
            IngressError::NotNumeric { offset: 9 }
        );
    }

    #[test]
    fn an_oversized_payload_is_refused_by_length_alone() {
        let payload = alloc::vec![b'0'; 4096];
        assert_eq!(
            decode(&payload).expect_err("an oversized payload must be refused"),
            IngressError::TooLong { len: 4096 }
        );
    }

    #[test]
    fn errors_render_without_leaking_the_payload() {
        // Every message must name the shape of the failure, never a word or an entropy
        // byte. The index in `IndexOutOfRange` is 2048 or above and so is not a word.
        let rendered = IngressError::ChecksumFailed { words: 24 }.to_string();
        assert!(rendered.contains("24 words"));
        assert!(rendered.contains("checksum"));
    }
}
