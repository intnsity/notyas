// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Finishing a mnemonic the user assembled by hand: the final-word checksum calculator and
//! coin-flip entropy for the bits the words leave free (0.2.0 gap G8).
//!
//! Both tools serve one flow. A user holding 11, 14, 17, 20 or 23 words - copied off a
//! damaged backup, or chosen deliberately from the printed list - needs a last word that
//! makes the BIP-39 checksum hold. That word is not unique. It carries the entropy bits the
//! earlier words left over PLUS the whole checksum, so 128 of the 2048 words complete a
//! 12-word phrase and 8 complete a 24-word one. Choosing among them is choosing entropy,
//! and this module is shaped so that a caller cannot do it inattentively:
//!
//! - [`FinalWords`] hands out the whole set and has no accessor that returns "the" final
//!   word. The two that yield a single word ([`FinalWords::pick`] and
//!   [`FinalWords::choose`]) each take the free bits as an argument and each return an
//!   [`EntropyAccount`] alongside the word, so the accounting arrives with the answer
//!   rather than being an extra call a front end can forget.
//! - [`CoinFlips`] is how a user supplies those bits deterministically, and the same type
//!   supplies a whole mnemonic's worth through [`mnemonic_from_flips`], which is the
//!   128-flip / 256-flip generation SeedSigner and Krux ship.
//!
//! # The invariant this module exists to keep visible
//!
//! Every ENT bit of a mnemonic built here came from the user. [`EntropyAccount`] has two
//! terms and there cannot be a third: notyas reads no RNG anywhere (SECURITY invariant 3),
//! so a seed finished on this screen is exactly as unpredictable as the user's own choices
//! were and no more.
//!
//! `hand_chosen_bits` therefore counts bits the user FIXED, not bits of unpredictability.
//! Eleven words the user liked the sound of fix 121 bits of a 128-bit ENT with far less
//! than 121 bits of guesswork behind them, and no device can measure the difference. A
//! front end must be able to say "you chose 121 of these 128 bits and 7 came from your
//! coin" instead of showing a 12-word phrase and letting the user read it as a
//! device-generated 128-bit seed. That sentence is the whole reason [`EntropyAccount`]
//! travels with the word.
//!
//! # What is reused
//!
//! Nothing here reimplements BIP-39. The wordlist, the checksum and the encoder are
//! [`crate::bip39`]'s, reached through its public raw-entropy path: a bit string goes in as
//! [`crate::entropy::DiceEntropy::from_bits`] and comes back out of
//! [`crate::bip39::mnemonic_from_dice`] under [`crate::bip39::MnemonicMode::Raw`] as a
//! checksummed phrase. That composition is also why the candidate list below is indexed by
//! free-bit value STRUCTURALLY rather than by an assumption about
//! [`crate::bip39::valid_last_words`]'s ordering: candidate `v` is built from `v`, so the
//! mapping a coin flip relies on cannot drift. The two agree, and
//! `agrees_with_the_bip39_final_word_helper` below is what keeps them agreeing.
//!
//! A coin-flip mnemonic is bit-for-bit a raw-mode mnemonic whose bits the user wrote down
//! directly instead of encoding dice into them, which is what makes it reproducible on any
//! other tool that accepts binary entropy.

use core::fmt;

use alloc::string::String;
use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::bip39::{self, Mnemonic, MnemonicMode, WordCount};
use crate::entropy::DiceEntropy;

/// Word counts the final-word calculator can complete: one short of each count in
/// [`crate::bip39::FIXED_WORD_COUNTS`].
pub const PARTIAL_WORD_COUNTS: [usize; 5] = [11, 14, 17, 20, 23];

/// Bits per BIP-39 word index. `bip39` states this too and keeps its statement private;
/// `the_local_entropy_arithmetic_matches_the_encoder` pins the two together by running a
/// phrase of every supported length through the encoder rather than trusting the copy.
const BITS_PER_WORD: usize = 11;

/// BIP-39 entropy comes in whole 32-bit blocks with one checksum bit each. Same note as
/// [`BITS_PER_WORD`]: a restatement of a private `bip39` constant, pinned by test.
const ENTROPY_BLOCK_BITS: usize = 32;

/// ENT for a finished phrase of `words` words: three words carry 32 entropy bits plus one
/// checksum bit.
///
/// Only ever called with a count from [`crate::bip39::FIXED_WORD_COUNTS`], where the
/// division is exact.
const fn entropy_bits(words: usize) -> usize {
    ENTROPY_BLOCK_BITS * words / 3
}

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

/// Everything a user can hand these tools that they have to fix.
///
/// Note what these variants do NOT carry: no variant holds a word or a bit of the user's
/// input. An error is the value most likely to be formatted into a message, a log line or a
/// panic payload, and each of those is a copy of key material in a `String` that nothing in
/// this crate will wipe. Positions are 1-based so a front end can point at the offending
/// item without quoting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicToolError {
    /// The phrase is not one word short of a supported count.
    NotOneWordShort { typed: usize },
    /// The word at `position` is not in the BIP-39 English list.
    UnknownWord { position: usize },
    /// The number of coin flips supplied is not the number the operation consumes. Exact,
    /// never a minimum: every flip is one entropy bit and all of them are used.
    FlipCount { supplied: usize, needed: usize },
    /// The character at `position` of the coin-flip input is neither '0' nor '1'.
    NotABit { position: usize },
}

impl fmt::Display for MnemonicToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MnemonicToolError::NotOneWordShort { typed } => write!(
                f,
                "the final-word helper needs 11, 14, 17, 20 or 23 words and there are \
                 {typed}: a seed is 12, 15, 18, 21 or 24 words, so type all of yours but \
                 the last one"
            ),
            MnemonicToolError::UnknownWord { position } => write!(
                f,
                "word {position} is not in the BIP-39 English list. Every word before the \
                 last one must be a list word, or there is no checksum left to complete"
            ),
            MnemonicToolError::FlipCount { supplied, needed } => write!(
                f,
                "wrong number of coin flips: {supplied} supplied, {needed} needed. Every \
                 flip is one entropy bit and all of them are used, so the count is exact"
            ),
            MnemonicToolError::NotABit { position } => write!(
                f,
                "character {position} of the coin flips is neither '0' nor '1'. Write \
                 heads and tails down as 1 and 0 yourself: a device that picked which is \
                 which would derive a different wallet from the same coin log"
            ),
        }
    }
}

impl core::error::Error for MnemonicToolError {}

// ---------------------------------------------------------------------------------------
// Entropy accounting
// ---------------------------------------------------------------------------------------

/// Where every ENT bit of a mnemonic came from.
///
/// Structural invariant: `hand_chosen_bits() + flipped_bits() == advertised_bits()`, always.
/// [`EntropyAccount::split`] is the only constructor and derives the second term from the
/// first, so the two cannot fail to add up, and there is no third term because there is
/// nothing to put in it - this device chooses no bit of any seed (SECURITY invariant 3).
///
/// The checksum is deliberately outside that sum. It is computed from the entropy, so
/// counting it would inflate a 128-bit seed to 132 bits of nothing.
///
/// There is no `is_strong()` here, and adding one would be a mistake: the numbers say how
/// many bits the user fixed and by which method, which is a fact, while the strength of the
/// bits a person chose by hand is not something this device can know. Presenting the split
/// and letting the user judge it is the honest form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyAccount {
    advertised_bits: usize,
    hand_chosen_bits: usize,
    flipped_bits: usize,
}

impl EntropyAccount {
    /// The only constructor: `hand_chosen_bits` of the ENT were fixed by the user's own
    /// choices and the rest came from their coin.
    ///
    /// Panics if `hand_chosen_bits` exceeds `advertised_bits`, which would mean a caller
    /// had attributed bits the mnemonic does not contain.
    fn split(advertised_bits: usize, hand_chosen_bits: usize) -> Self {
        EntropyAccount {
            advertised_bits,
            hand_chosen_bits,
            flipped_bits: advertised_bits
                .checked_sub(hand_chosen_bits)
                .expect("hand-chosen bits cannot exceed the ENT they are part of"),
        }
    }

    /// ENT: the entropy length the finished word count implies, 128 for 12 words up to 256
    /// for 24. This is the number a UI must NOT present on its own.
    pub fn advertised_bits(self) -> usize {
        self.advertised_bits
    }

    /// Bits fixed by words or candidates the user chose themselves.
    ///
    /// A count of bits FIXED, not of unpredictability; see the module docs. This is the
    /// number a UI has to show beside [`EntropyAccount::advertised_bits`] for that figure
    /// to be honest.
    pub fn hand_chosen_bits(self) -> usize {
        self.hand_chosen_bits
    }

    /// Bits supplied one at a time as coin flips.
    pub fn flipped_bits(self) -> usize {
        self.flipped_bits
    }

    /// Checksum bits the phrase carries on top of the ENT: one per 32 entropy bits. Not
    /// entropy, and not part of the sum above.
    pub fn checksum_bits(self) -> usize {
        self.advertised_bits / ENTROPY_BLOCK_BITS
    }
}

// ---------------------------------------------------------------------------------------
// Coin flips
// ---------------------------------------------------------------------------------------

/// A run of coin flips the user recorded, one bit each, most significant first.
///
/// Only '0' and '1' are accepted. Heads/tails spellings are refused on purpose: the mapping
/// from a physical coin to a bit is the user's to record and to keep, and a device that
/// decided heads meant 1 would silently derive a different wallet from the same written log
/// than any tool that decided otherwise. ASCII whitespace is skipped so a log can be grouped
/// into readable blocks; nothing else is, and because every operation here demands an EXACT
/// flip count, a character dropped by accident shows up as a count error rather than as a
/// different seed.
///
/// Lifetime invariant: these bits ARE the seed, or the part of it the words did not fix, so
/// the value wipes itself on drop and its `Debug` rendering never shows them.
#[derive(Clone)]
pub struct CoinFlips {
    /// Invariant, established by the only constructor: '0' and '1' characters only.
    bits: Zeroizing<String>,
}

impl CoinFlips {
    /// Read a recorded coin log.
    ///
    /// Fails on the first character that is not a bit or ASCII whitespace, reporting its
    /// 1-based position, so a front end can point at the typo instead of guessing which
    /// flip the user meant.
    pub fn parse(text: &str) -> Result<Self, MnemonicToolError> {
        // The result is never longer than the input, so this buffer cannot grow and leave a
        // copy of the flips in freed heap.
        let mut bits = Zeroizing::new(String::with_capacity(text.len()));
        for (offset, c) in text.char_indices() {
            match c {
                '0' | '1' => bits.push(c),
                _ if c.is_ascii_whitespace() => {}
                _ => {
                    return Err(MnemonicToolError::NotABit {
                        position: text[..offset].chars().count() + 1,
                    })
                }
            }
        }
        Ok(CoinFlips { bits })
    }

    /// How many flips were recorded, i.e. how many entropy bits this supplies.
    pub fn count(&self) -> usize {
        self.bits.len()
    }

    /// The flips as a '0'/'1' string, which is exactly the entropy bit string they stand
    /// for. Borrowed, never handed out as an owned copy the caller would have to wipe.
    pub fn bits(&self) -> &str {
        &self.bits
    }

    /// The flips read as one big-endian integer.
    ///
    /// Private and only reached from [`FinalWords::choose`], which has already required the
    /// count to equal a free-bit width of at most 7, so the shift cannot overflow. A public
    /// version would have to answer for a 256-flip value that no integer here can hold.
    fn value(&self) -> usize {
        debug_assert!(
            self.count() < usize::BITS as usize,
            "value() is only defined for a final word's free bits"
        );
        self.bits
            .bytes()
            .fold(0usize, |acc, b| (acc << 1) | usize::from(b == b'1'))
    }
}

impl fmt::Debug for CoinFlips {
    /// Hand written for the reason every secret-bearing type in this crate has one: a `{:?}`
    /// in a caller, a log line or a panic payload would otherwise copy the seed bits into a
    /// fresh string that nothing wipes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoinFlips")
            .field("count", &self.count())
            .field("bits", &"<redacted>")
            .finish()
    }
}

/// Flips needed to generate a whole mnemonic of `words` words: one per ENT bit, so 128 for
/// 12 words and 256 for 24.
pub fn flips_for_word_count(words: WordCount) -> usize {
    entropy_bits(words.get())
}

/// A mnemonic and the accounting for it, which is the only form
/// [`mnemonic_from_flips`] hands one out in.
///
/// Plain fields and no `Drop` of its own: [`Mnemonic`] wipes its own entropy, and adding a
/// `Drop` here would only make the value non-destructurable for no gain.
pub struct FlippedMnemonic {
    pub mnemonic: Mnemonic,
    /// `hand_chosen_bits` is zero and `flipped_bits` is the whole ENT: on this path the
    /// user supplied every bit one flip at a time.
    pub account: EntropyAccount,
}

impl fmt::Debug for FlippedMnemonic {
    /// See [`CoinFlips::fmt`]; `Mnemonic`'s own `Debug` is already redacted and this keeps
    /// the wrapper from being the hole.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlippedMnemonic")
            .field("mnemonic", &self.mnemonic)
            .field("account", &self.account)
            .finish()
    }
}

/// Build a whole mnemonic from coin flips: the SeedSigner/Krux generation, done the way the
/// rest of this crate does everything, with the user as the only entropy source.
///
/// `flips.count()` must be exactly [`flips_for_word_count`] for `words`. Refusing a short
/// log rather than padding it is the point: padding would put bits into the seed that the
/// user did not flip, which is the one thing this device does not do.
///
/// The result is bit-for-bit what [`crate::bip39::MnemonicMode::Raw`] produces for the same
/// bit string, so the user can reproduce it from their written coin log on any tool that
/// takes binary entropy.
pub fn mnemonic_from_flips(
    flips: &CoinFlips,
    words: WordCount,
) -> Result<FlippedMnemonic, MnemonicToolError> {
    let needed = flips_for_word_count(words);
    if flips.count() != needed {
        return Err(MnemonicToolError::FlipCount {
            supplied: flips.count(),
            needed,
        });
    }
    Ok(FlippedMnemonic {
        mnemonic: encode(flips.bits()),
        account: EntropyAccount::split(needed, 0),
    })
}

// ---------------------------------------------------------------------------------------
// Final-word calculator
// ---------------------------------------------------------------------------------------

/// One valid completion of a partial phrase, with the accounting for how it was reached.
///
/// The two cannot be separated at the point of choice, which is the whole design: a front
/// end that shows the word has the entropy split in hand at the same moment.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FinalChoice {
    pub word: &'static str,
    pub account: EntropyAccount,
}

impl fmt::Debug for FinalChoice {
    /// The word is one word of someone's mnemonic; see [`CoinFlips::fmt`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinalChoice")
            .field("word", &"<redacted>")
            .field("account", &self.account)
            .finish()
    }
}

/// Every word that gives a partial phrase a valid BIP-39 checksum as its last word.
///
/// There is deliberately no method that returns a single word on its own. The set is never
/// a singleton - it holds `2^free_bits` words, from 128 for an 11-word phrase down to 8 for
/// a 23-word one - and a caller that took the first would be silently choosing several bits
/// of the user's seed for them. [`FinalWords::pick`] and [`FinalWords::choose`] are the two
/// ways out, and each takes the free bits as an argument and returns the accounting with the
/// word.
///
/// The set itself is not a secret beyond what the user's own words already published: it is
/// derived from the checksum they can compute from their phrase, and it constrains their
/// seed no more than the words they typed do.
#[derive(Clone)]
pub struct FinalWords {
    /// Index `v` is the word for free-bit value `v`, by construction rather than by
    /// convention: [`FinalWords::for_phrase`] builds entry `v` from the bit pattern `v`.
    candidates: Vec<&'static str>,
    typed_words: usize,
    free_bits: usize,
    advertised_bits: usize,
}

impl FinalWords {
    /// Compute the completions of a partial phrase.
    ///
    /// `phrase` must hold 11, 14, 17, 20 or 23 whitespace-separated words, each in the
    /// BIP-39 English list; case is folded for the lookup exactly as
    /// [`crate::bip39::check_phrase`] folds it. An unknown word is refused rather than
    /// skipped: there is no checksum to complete around a word the list does not have, and
    /// candidates offered past it would belong to a phrase nobody typed.
    pub fn for_phrase(phrase: &str) -> Result<Self, MnemonicToolError> {
        let typed: Vec<&str> = phrase.split_whitespace().collect();
        if !PARTIAL_WORD_COUNTS.contains(&typed.len()) {
            return Err(MnemonicToolError::NotOneWordShort { typed: typed.len() });
        }

        let advertised_bits = entropy_bits(typed.len() + 1);
        // Non-negative and under BITS_PER_WORD for every supported count - 7 bits free at
        // 11 words typed, 3 at 23 - which is why this needs no clamp and why the candidate
        // count below fits in a usize on any target.
        let free_bits = advertised_bits - typed.len() * BITS_PER_WORD;

        // Capacity is the FULL ENT, not just the typed words' share: the loop below appends
        // the free bits into this same buffer, and a reallocation there would leave a copy
        // of the user's entropy in freed heap.
        let mut bits = prefix_bits(&typed, advertised_bits)?;
        let fixed = bits.len();

        let mut candidates = Vec::with_capacity(1usize << free_bits);
        for value in 0..(1usize << free_bits) {
            bits.truncate(fixed);
            push_bits(&mut bits, value, free_bits);
            candidates.push(last_word(&bits));
        }

        Ok(FinalWords {
            candidates,
            typed_words: typed.len(),
            free_bits,
            advertised_bits,
        })
    }

    /// Every valid completion, in wordlist order, which is also free-bit-value order.
    ///
    /// For display. Committing to one of these is [`FinalWords::pick`]; indexing this slice
    /// gets a word without the accounting that has to travel with it.
    pub fn candidates(&self) -> &[&'static str] {
        &self.candidates
    }

    /// How many words complete the phrase: `2^free_bits`, never one.
    pub fn count(&self) -> usize {
        self.candidates.len()
    }

    /// Entropy bits the last word still has to supply, and therefore the number of coin
    /// flips [`FinalWords::choose`] consumes.
    pub fn free_bits(&self) -> usize {
        self.free_bits
    }

    /// Bits of the ENT the typed words already fixed: 11 per word.
    pub fn hand_chosen_bits(&self) -> usize {
        self.typed_words * BITS_PER_WORD
    }

    /// ENT of the finished phrase. Meaningless on its own; see [`EntropyAccount`].
    pub fn advertised_bits(&self) -> usize {
        self.advertised_bits
    }

    /// Words in the finished phrase, for a "word N of M" counter.
    pub fn word_count(&self) -> usize {
        self.typed_words + 1
    }

    /// Commit to the candidate the user chose by eye, identified by its position in
    /// [`FinalWords::candidates`].
    ///
    /// The returned account attributes the free bits to the HAND, because that is what
    /// happened: a user reading down a list and liking one word chose those bits themselves,
    /// with whatever bias reading down a list carries. [`FinalWords::choose`] is the same
    /// operation with a coin doing the choosing, and it is the one that earns
    /// `flipped_bits`.
    ///
    /// `None` when `index` is past the end.
    pub fn pick(&self, index: usize) -> Option<FinalChoice> {
        self.candidates.get(index).map(|word| FinalChoice {
            word,
            // Every bit is the user's own: the words fixed most of them and they fixed the
            // rest by picking this entry.
            account: EntropyAccount::split(self.advertised_bits, self.advertised_bits),
        })
    }

    /// Let the coin choose the last word.
    ///
    /// Consumes exactly [`FinalWords::free_bits`] flips, read most significant first, which
    /// is the same order the words themselves are packed in. Requiring the exact count means
    /// a miscounted log is an error the user sees rather than a seed they cannot reproduce.
    pub fn choose(&self, flips: &CoinFlips) -> Result<FinalChoice, MnemonicToolError> {
        if flips.count() != self.free_bits {
            return Err(MnemonicToolError::FlipCount {
                supplied: flips.count(),
                needed: self.free_bits,
            });
        }
        Ok(FinalChoice {
            // The index is the flip value by construction of `candidates`, so this cannot
            // be out of range: `value()` of `free_bits` bits is under `1 << free_bits`.
            word: self.candidates[flips.value()],
            account: EntropyAccount::split(self.advertised_bits, self.hand_chosen_bits()),
        })
    }
}

impl fmt::Debug for FinalWords {
    /// The candidate list narrows the user's seed to one of `count` wallets; see
    /// [`CoinFlips::fmt`] for why nothing secret-adjacent gets a derived `Debug` here.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FinalWords")
            .field("word_count", &self.word_count())
            .field("free_bits", &self.free_bits)
            .field(
                "candidates",
                &format_args!("<redacted, {} words>", self.count()),
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------------------
// Shared bit plumbing
// ---------------------------------------------------------------------------------------

/// The ENT-prefix bits the typed words fix, 11 per word, most significant first.
///
/// Wiped on drop: this is the user's entropy less the final word's share, which is nearly
/// the whole wallet. `capacity` is the full ENT so the caller can append the free bits
/// without reallocating.
fn prefix_bits(typed: &[&str], capacity: usize) -> Result<Zeroizing<String>, MnemonicToolError> {
    let list = bip39::wordlist();
    let mut bits = Zeroizing::new(String::with_capacity(capacity));
    for (offset, word) in typed.iter().enumerate() {
        // Folding case here rather than requiring lowercase input matches `check_phrase`,
        // so a phrase typed on a shifted keyboard resolves to the same indices and the same
        // candidate set.
        let lower = Zeroizing::new(word.to_lowercase());
        let index = list
            .binary_search_by(|probe| (**probe).cmp(lower.as_str()))
            .map_err(|_| MnemonicToolError::UnknownWord {
                position: offset + 1,
            })?;
        push_bits(&mut bits, index, BITS_PER_WORD);
    }
    Ok(bits)
}

/// Append the low `width` bits of `value`, most significant first.
fn push_bits(out: &mut String, value: usize, width: usize) {
    for shift in (0..width).rev() {
        out.push(char::from(b'0' + ((value >> shift) & 1) as u8));
    }
}

/// The BIP-39 phrase whose entropy is exactly `bits`.
///
/// The whole of this module's BIP-39 content: `bip39`'s raw path takes a bit string and
/// returns a checksummed phrase, so neither the wordlist nor the checksum is restated here.
///
/// `bits` is always a whole number of 32-bit blocks between 128 and 256, which is what makes
/// the two failure modes of `mnemonic_from_dice` unreachable and what makes the raw
/// selection rule a no-op: it keeps the trailing whole blocks, and every block is whole.
fn encode(bits: &str) -> Mnemonic {
    debug_assert_eq!(
        bip39::raw_bits_used(bits.len()),
        bits.len(),
        "raw mode must keep every bit the user supplied"
    );
    let entropy = DiceEntropy::from_bits(bits);
    bip39::mnemonic_from_dice(&entropy, MnemonicMode::Raw)
        .expect("ENT here is a whole number of 32-bit blocks in 128..=256")
}

/// The last word of the phrase [`encode`] builds from `bits`.
fn last_word(bits: &str) -> &'static str {
    encode(bits)
        .words
        .last()
        .copied()
        .expect("a mnemonic of at least 128 ENT bits has words")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip39::{check_phrase, valid_last_words, wordlist, Checksum, FIXED_WORD_COUNTS};
    use alloc::string::ToString;
    use serde_json::Value;

    /// The same embedded upstream file `bip39`'s tests use: the official BIP-39 vectors
    /// published by Trezor as `python-mnemonic/vectors.json` (and reproduced in
    /// bitcoin/bips bip-0039), verbatim
    /// (sha256 fa3b937b7cff9c9b8ecd3aa011faeb8d6dd67993174b72326e83f4de8fdb30f8).
    ///
    /// These are the only published vectors this module needs. Neither tool has vectors of
    /// its own to pin against and neither should: a coin-flip mnemonic IS the BIP-39
    /// entropy-to-mnemonic function with the user writing the bits down, and a final word is
    /// the last 11 bits of that same encoding, so the vectors that pin the encoding pin both
    /// tools exactly.
    const TREZOR_VECTORS: &str = include_str!("../tests/vectors/trezor_vectors.json");

    /// The 24 official english cases as (entropy hex, phrase, seed with passphrase
    /// "TREZOR").
    fn english_vectors() -> Vec<(String, String, String)> {
        let json: Value =
            serde_json::from_str(TREZOR_VECTORS).expect("malformed JSON in trezor_vectors.json");
        let cases = json["english"].as_array().expect("english array");
        assert_eq!(cases.len(), 24, "the official english set is 24 cases");
        cases
            .iter()
            .map(|c| {
                (
                    c[0].as_str().unwrap().to_string(),
                    c[1].as_str().unwrap().to_string(),
                    c[2].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    /// A vector's entropy hex as the bit string a user would have flipped, MSB first.
    fn bits_of(entropy_hex: &str) -> String {
        hex::decode(entropy_hex)
            .expect("vector entropy is hex")
            .iter()
            .map(|b| format!("{b:08b}"))
            .collect()
    }

    fn wc(words: usize) -> WordCount {
        WordCount::new(words).expect("test uses a supported word count")
    }

    fn flips(bits: &str) -> CoinFlips {
        CoinFlips::parse(bits).expect("test supplies a bit string")
    }

    /// The published BIP-39 vectors, driven from the coin-flip side: a user who flips the
    /// vector's entropy bit for bit must get the vector's phrase, and the vector's seed
    /// under the official "TREZOR" passphrase.
    ///
    /// This is the pin for the whole generation path, covering all three ENT sizes the
    /// official set uses (128, 192 and 256 bits).
    #[test]
    fn coin_flips_reproduce_the_official_bip39_vectors() {
        let mut seen = alloc::collections::BTreeSet::new();
        for (entropy_hex, phrase, seed_hex) in english_vectors() {
            let words = phrase.split(' ').count();
            seen.insert(words);
            let built = mnemonic_from_flips(&flips(&bits_of(&entropy_hex)), wc(words))
                .expect("the vector supplies exactly ENT flips");
            assert_eq!(built.mnemonic.phrase().as_str(), phrase, "{entropy_hex}");
            assert_eq!(
                hex::encode(bip39::seed(&phrase, "TREZOR")),
                seed_hex,
                "{entropy_hex}"
            );
            // Every bit came from the coin and none from this device.
            assert_eq!(built.account.flipped_bits(), entropy_hex.len() * 4);
            assert_eq!(built.account.hand_chosen_bits(), 0);
            assert_eq!(
                built.account.advertised_bits(),
                built.account.flipped_bits()
            );
        }
        assert_eq!(
            seen,
            [12usize, 18, 24].into_iter().collect(),
            "the official set must exercise 128, 192 and 256 bit ENT"
        );
    }

    /// The published vectors again, driven from the final-word side: strip each vector's
    /// last word, and the calculator must offer the word the vector says belongs there AND
    /// place it at the position the vector's own trailing entropy bits name.
    ///
    /// The position half is what makes the coin-flip selection meaningful. A candidate list
    /// with the right contents in the wrong order would still pass every checksum test and
    /// would still hand a user the wrong wallet for their flips.
    #[test]
    fn the_final_word_of_every_official_vector_is_offered_at_its_own_free_bit_value() {
        for (entropy_hex, phrase, _) in english_vectors() {
            let mut words: Vec<&str> = phrase.split(' ').collect();
            let last = words.pop().expect("a vector phrase has words");
            let head = words.join(" ");

            let final_words = FinalWords::for_phrase(&head).expect("one word short");
            assert!(
                final_words.candidates().contains(&last),
                "the vector's own last word must be offered: {entropy_hex}"
            );

            // The free bits ARE the tail of the vector's entropy, so the vector names the
            // position without any arithmetic of this module's own.
            let bits = bits_of(&entropy_hex);
            let tail = &bits[bits.len() - final_words.free_bits()..];
            let value = usize::from_str_radix(tail, 2).expect("a bit string");
            assert_eq!(
                final_words.pick(value).expect("in range").word,
                last,
                "{entropy_hex}"
            );
            assert_eq!(
                final_words.choose(&flips(tail)).expect("exact count").word,
                last,
                "{entropy_hex}"
            );
        }
    }

    /// Sizes stated by BIP-39's own arithmetic: the last word carries `ENT - 11 * typed`
    /// entropy bits, so 2^7 words complete a 12-word phrase down to 2^3 for a 24-word one.
    /// A set of the wrong size means the free-bit width is wrong, which would misroute every
    /// coin flip.
    #[test]
    fn the_candidate_set_has_one_word_per_free_bit_pattern() {
        for (typed, free, count) in [
            (11usize, 7usize, 128usize),
            (14, 6, 64),
            (17, 5, 32),
            (20, 4, 16),
            (23, 3, 8),
        ] {
            let head = vec!["abandon"; typed].join(" ");
            let fw = FinalWords::for_phrase(&head).unwrap();
            assert_eq!(fw.free_bits(), free, "{typed} typed");
            assert_eq!(fw.count(), count, "{typed} typed");
            assert_eq!(fw.candidates().len(), count);
            assert_eq!(fw.word_count(), typed + 1);
            assert_eq!(fw.advertised_bits(), entropy_bits(typed + 1));
            assert_eq!(fw.hand_chosen_bits(), typed * 11);
            assert_eq!(fw.free_bits(), fw.advertised_bits() - fw.hand_chosen_bits());
            assert!(
                fw.candidates().windows(2).all(|w| w[0] < w[1]),
                "candidates must come out in wordlist order, {typed} typed"
            );
        }
    }

    /// This module composes `bip39`'s raw encoder; `bip39::valid_last_words` walks the
    /// checksum itself. They are independent routes to the same set and must agree, in
    /// contents and in order, or one of them is wrong.
    ///
    /// This is also what pins the ordering contract `choose` rests on: if either side ever
    /// stopped enumerating in free-bit order, the two lists would stop matching here.
    #[test]
    fn agrees_with_the_bip39_final_word_helper() {
        for typed in PARTIAL_WORD_COUNTS {
            for filler in ["abandon", "zoo", "legal", "letter"] {
                let head = vec![filler; typed].join(" ");
                assert_eq!(
                    FinalWords::for_phrase(&head).unwrap().candidates(),
                    valid_last_words(&head),
                    "{typed} x {filler}"
                );
            }
        }
        // A head with no repetition either, so nothing about the agreement depends on the
        // prefix bits being uniform.
        let head = "legal winner thank year wave sausage worth useful legal winner thank";
        assert_eq!(
            FinalWords::for_phrase(head).unwrap().candidates(),
            valid_last_words(head)
        );
    }

    /// Every offered word must complete the phrase and no other word in the list may. The
    /// brute-force half is the one that catches an off-by-one in the free-bit width, which
    /// would still produce a plausible list of plausible words.
    #[test]
    fn every_offered_word_checks_out_and_no_other_word_does() {
        for head in [
            "legal winner thank year wave sausage worth useful legal winner thank",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
             zoo zoo zoo zoo",
        ] {
            let offered = FinalWords::for_phrase(head).unwrap();
            for word in offered.candidates() {
                assert_eq!(
                    check_phrase(&format!("{head} {word}")).checksum,
                    Checksum::Valid,
                    "{word} was offered but does not check out"
                );
            }
            let all_valid: Vec<&str> = wordlist()
                .iter()
                .copied()
                .filter(|w| check_phrase(&format!("{head} {w}")).checksum == Checksum::Valid)
                .collect();
            assert_eq!(offered.candidates(), all_valid);
        }
    }

    /// The accounting invariant, over every construction path this module has: the two terms
    /// add up to the ENT with nothing left over, because there is no source left to
    /// attribute a remainder to.
    #[test]
    fn every_entropy_account_attributes_the_whole_ent_to_the_user() {
        let check = |a: EntropyAccount, advertised: usize| {
            assert_eq!(a.advertised_bits(), advertised);
            assert_eq!(
                a.hand_chosen_bits() + a.flipped_bits(),
                a.advertised_bits(),
                "an unattributed bit would have to have come from the device"
            );
            assert_eq!(a.checksum_bits(), advertised / 32);
        };

        for typed in PARTIAL_WORD_COUNTS {
            let head = vec!["abandon"; typed].join(" ");
            let fw = FinalWords::for_phrase(&head).unwrap();
            let advertised = fw.advertised_bits();

            // Picked by eye: every bit is hand chosen, including the free ones.
            let picked = fw.pick(0).unwrap();
            check(picked.account, advertised);
            assert_eq!(picked.account.hand_chosen_bits(), advertised);
            assert_eq!(picked.account.flipped_bits(), 0);

            // Chosen by coin: only the free bits move to the coin.
            let chosen = fw.choose(&flips(&"0".repeat(fw.free_bits()))).unwrap();
            check(chosen.account, advertised);
            assert_eq!(chosen.account.hand_chosen_bits(), typed * 11);
            assert_eq!(chosen.account.flipped_bits(), fw.free_bits());

            // Same word either way; only the story about where its bits came from differs.
            assert_eq!(picked.word, chosen.word);
        }

        for words in FIXED_WORD_COUNTS {
            let count = wc(words);
            let n = flips_for_word_count(count);
            let built = mnemonic_from_flips(&flips(&"1".repeat(n)), count).unwrap();
            check(built.account, n);
            assert_eq!(built.account.hand_chosen_bits(), 0);
            assert_eq!(built.mnemonic.words.len(), words);
        }
    }

    /// The local restatements of `bip39`'s private 11-bits-per-word and 32-bits-per-block
    /// constants, pinned against the encoder itself rather than against a second copy of the
    /// same arithmetic.
    #[test]
    fn the_local_entropy_arithmetic_matches_the_encoder() {
        for words in FIXED_WORD_COUNTS {
            let ent = entropy_bits(words);
            let built = mnemonic_from_flips(&flips(&"0".repeat(ent)), wc(words)).unwrap();
            assert_eq!(built.mnemonic.words.len(), words, "ENT {ent}");
            assert_eq!(built.mnemonic.entropy.len() * 8, ent);
            assert_eq!(ent % ENTROPY_BLOCK_BITS, 0);
            // 11 bits per word, one checksum bit per 32 entropy bits.
            assert_eq!(words * BITS_PER_WORD, ent + ent / ENTROPY_BLOCK_BITS);
        }
    }

    /// Coin flips are the user's log, so the parser keeps their grouping whitespace and
    /// refuses everything else, pointing at the character rather than quoting it.
    #[test]
    fn coin_flips_accept_grouped_bits_and_nothing_else() {
        assert_eq!(flips("0101 1010\t1111\n0000").bits(), "0101101011110000");
        assert_eq!(flips("").count(), 0);
        assert_eq!(flips("  \r\n\t ").count(), 0);
        assert_eq!(flips("1").value(), 1);
        assert_eq!(flips("1010").value(), 10);
        assert_eq!(flips("0000000").value(), 0);
        // Heads and tails are the user's to record; the device does not decide which is 1.
        for (text, position) in [
            ("HTHT", 1usize),
            ("01H", 3),
            ("01 T0", 4),
            ("012", 3),
            ("01-01", 3),
            ("01\u{00a0}01", 3),
        ] {
            assert_eq!(
                CoinFlips::parse(text).err(),
                Some(MnemonicToolError::NotABit { position }),
                "{text:?}"
            );
        }
    }

    /// Both tools consume an exact number of flips. A short or long log is the user's to
    /// fix, never this module's to pad, because a padded bit is a bit the user did not flip.
    #[test]
    fn a_flip_count_that_is_not_exact_is_refused() {
        let fw = FinalWords::for_phrase(&["abandon"; 11].join(" ")).unwrap();
        for supplied in [0usize, 1, 6, 8, 128] {
            assert_eq!(
                fw.choose(&flips(&"0".repeat(supplied))),
                Err(MnemonicToolError::FlipCount {
                    supplied,
                    needed: 7
                })
            );
        }
        for supplied in [0usize, 127, 129, 256] {
            assert_eq!(
                mnemonic_from_flips(&flips(&"0".repeat(supplied)), wc(12)).err(),
                Some(MnemonicToolError::FlipCount {
                    supplied,
                    needed: 128
                })
            );
        }
        assert_eq!(flips_for_word_count(wc(12)), 128);
        assert_eq!(flips_for_word_count(wc(24)), 256);
    }

    /// The calculator answers only where a last word is actually determined, and refuses to
    /// invent candidates for a phrase it cannot read.
    #[test]
    fn only_a_phrase_one_word_short_of_a_seed_has_final_words() {
        for typed in [0usize, 1, 5, 10, 12, 13, 15, 21, 24, 25, 30] {
            let head = vec!["abandon"; typed].join(" ");
            assert_eq!(
                FinalWords::for_phrase(&head).err(),
                Some(MnemonicToolError::NotOneWordShort { typed }),
                "{typed} words"
            );
        }
        // One short, but with a word the list does not have.
        let mut head = ["abandon"; 11];
        head[3] = "notaword";
        assert_eq!(
            FinalWords::for_phrase(&head.join(" ")).err(),
            Some(MnemonicToolError::UnknownWord { position: 4 })
        );
        // Case is folded for the lookup, and extra whitespace is not a word.
        let mixed = "  ABANDON Abandon abandon\tabandon abandon abandon abandon abandon \
                     abandon abandon  abandon ";
        assert_eq!(
            FinalWords::for_phrase(mixed).unwrap().candidates(),
            FinalWords::for_phrase(&["abandon"; 11].join(" "))
                .unwrap()
                .candidates()
        );
    }

    /// `pick` is bounded by the set it belongs to; a UI index past the end is `None`, not a
    /// panic and not a wrapped-around word.
    #[test]
    fn pick_is_bounded_by_the_candidate_set() {
        let fw = FinalWords::for_phrase(&["zoo"; 23].join(" ")).unwrap();
        assert_eq!(fw.count(), 8);
        for i in 0..8 {
            assert_eq!(fw.pick(i).unwrap().word, fw.candidates()[i]);
        }
        assert!(fw.pick(8).is_none());
        assert!(fw.pick(usize::MAX).is_none());
    }

    /// The redacted renderings, checked rather than assumed: a `{:?}` on any of these types
    /// is one stray log line away from being the whole wallet.
    #[test]
    fn debug_renderings_hold_no_key_material() {
        let fw = FinalWords::for_phrase(&["abandon"; 11].join(" ")).unwrap();
        let rendered = format!(
            "{:?} {:?} {:?} {:?}",
            fw,
            fw.pick(0).unwrap(),
            flips("0101011"),
            mnemonic_from_flips(&flips(&"0".repeat(128)), wc(12)).unwrap()
        );
        // One per secret field: the candidate list, the chosen word, the flips, and the
        // mnemonic's own entropy and words. Counting them is what catches a field added
        // later that is rendered instead of redacted.
        assert_eq!(rendered.matches("<redacted").count(), 5, "{rendered}");
        for leak in ["abandon", "about", "0101011"] {
            assert!(!rendered.contains(leak), "{leak} leaked into {rendered}");
        }
    }

    #[test]
    fn error_messages_are_ascii_and_actionable() {
        let messages = [
            MnemonicToolError::NotOneWordShort { typed: 13 }.to_string(),
            MnemonicToolError::UnknownWord { position: 4 }.to_string(),
            MnemonicToolError::FlipCount {
                supplied: 120,
                needed: 128,
            }
            .to_string(),
            MnemonicToolError::NotABit { position: 3 }.to_string(),
        ];
        for m in &messages {
            assert!(m.is_ascii(), "message must be ASCII: {m}");
            assert!(!m.ends_with(' '));
            assert!(!m.is_empty());
        }
        assert!(messages[0].contains("13"));
        assert!(messages[1].contains("word 4"));
        assert!(messages[2].contains("120 supplied, 128 needed"));
        assert!(messages[3].contains("character 3"));
    }
}
