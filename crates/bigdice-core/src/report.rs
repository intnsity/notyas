// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The derived document: what a run produced.
//!
//! This module exists because the program has more than one front end. On the desktop the
//! command line and the window must not merely agree about the keys they show - they must
//! be incapable of disagreeing - so the pipeline that turns dice into keys
//! ([`Report::build`]) lives here, once, and every front end calls it. The device UI is
//! one more such front end: it renders a [`Report`] and can never compute one of its own.
//!
//! The desktop module also owns a hand-rolled JSON writer (`json_document`/`render_json`);
//! the device emits no JSON, so that half is not ported. [`capacity`] stays because it is
//! what lets a renderer pre-size its buffer so a `Zeroizing<String>` never reallocates and
//! leaves an unwiped copy of the report in freed heap - the obligation is the renderer's,
//! whichever crate it lives in. See PORTING.md.
//!
//! Secret handling: [`Report`] owns the mnemonic, the seed and every private key rendering,
//! and wipes what it owns on drop. Rendering buffers are sized from [`capacity`] before a
//! byte is written, because a `Zeroizing<String>` that reallocates leaves the old copy of
//! the whole report in freed heap.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use bitcoin::Network;
use zeroize::{Zeroize, Zeroizing};

use crate::bip39::{self, Bip39Error, MnemonicMode, PhraseCheck};
use crate::derive::{self, ChildIndex, Derived, Scheme};
use crate::entropy::DiceEntropy;

// ---------------------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------------------

/// One scheme's contribution to the report, paired with the scheme it came from.
pub struct SchemeReport {
    pub scheme: Scheme,
    pub derived: Derived,
}

/// Everything every renderer needs, captured once so no two views can drift apart.
///
/// `phrase` is the exact string that was fed to PBKDF2 (SPEC step 8); `words` is the same
/// sentence split for the JSON array.
///
/// The fields describing the dice - everything above `mode` - are meaningful only for a
/// report built by [`Report::build`]. On the [`Report::from_phrase`] path there were no
/// dice: they are all zero or empty, `mnemonic_input` is `Some`, and every renderer shows
/// that instead.
pub struct Report {
    pub events: usize,
    pub clean: String,
    pub binary: String,
    /// Bits the dice produced (SPEC step 3).
    pub total_bits: usize,
    /// ENT of the mnemonic: what the iancoleman page calls the entropy used, and what the
    /// word count implies. In fixed-word mode this is a hash output length, not a measure
    /// of anything the dice supplied.
    pub bits_used: usize,
    /// Entropy that actually protects the wallet: `min(bits_used, total_bits)` in
    /// fixed-word mode, `bits_used` in raw mode. This, not `bits_used`, is what every
    /// warning in the program is computed from. See [`effective_bits`].
    pub effective_bits: usize,
    pub mode: MnemonicMode,
    pub words: Vec<String>,
    /// Wiped by its own wrapper, which is what [`crate::bip39::Mnemonic::phrase`] hands out.
    pub phrase: Zeroizing<String>,
    pub entropy_hex: String,
    pub seed_hex: String,
    pub root_xprv: String,
    /// Master fingerprint: first 4 bytes of HASH160 of the master public key.
    /// Public identifier (not a secret), 8 lowercase hex characters.
    pub root_fingerprint: String,
    pub network: Network,
    pub has_passphrase: bool,
    /// What the phrase the user typed turned out to be, on the [`Report::from_phrase`] path
    /// only. `None` means the wallet came from dice.
    pub mnemonic_input: Option<PhraseCheck>,
    pub schemes: Vec<SchemeReport>,
}

impl Drop for Report {
    /// Wipe the secrets this value owns outright once the rendered text has been handed on.
    /// `phrase` wipes itself, and the account keys and WIFs are wiped by the types that own
    /// them in [`crate::derive`], so this impl covers exactly its own fields.
    fn drop(&mut self) {
        self.clean.zeroize();
        self.binary.zeroize();
        self.entropy_hex.zeroize();
        self.seed_hex.zeroize();
        self.root_xprv.zeroize();
        for word in &mut self.words {
            word.zeroize();
        }
    }
}

/// Everything the pipeline reads apart from the dice.
///
/// Borrowed rather than owned so that no front end has to copy the passphrase to call
/// [`Report::build`]: a copy is one more place the master secret has to be wiped from.
pub struct Parameters<'a> {
    pub mode: MnemonicMode,
    pub passphrase: &'a str,
    pub network: Network,
    /// Schemes to derive, in the order they will be reported.
    pub schemes: &'a [Scheme],
    pub account: ChildIndex,
    pub change: ChildIndex,
    /// Address rows per scheme. The upper bound belongs to the caller: different front
    /// ends offer different ones for the same reason they look different.
    pub count: u32,
    /// BIP48 script type: 0=P2SH, 1=P2WSH, 2=P2SH-P2WSH. Ignored for non-BIP48 schemes.
    /// Default 2 (P2SH-P2WSH) is the common wrapped-segwit multisig setup.
    pub script_type: u32,
}

/// Why a report could not be built.
///
/// [`BuildError::NoRolls`] is separate from every BIP39 condition because it is the one
/// input that yields a perfectly valid mnemonic and must still be refused: a fixed word
/// count is a SHA256 stretch of the digit string, and the empty digit string hashes to a
/// wallet anyone can look up and sweep.
///
/// The mnemonic-input path has no error type at all: [`Report::from_phrase`] refuses exactly
/// one input, a text with no words in it, and says so by returning `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    NoRolls,
    Bip39(Bip39Error),
}

impl core::fmt::Display for BuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BuildError::NoRolls => write!(
                f,
                "no dice rolls in the input, so there is no entropy to build a wallet from"
            ),
            BuildError::Bip39(error) => error.fmt(f),
        }
    }
}

impl core::error::Error for BuildError {}

impl From<Bip39Error> for BuildError {
    fn from(error: Bip39Error) -> Self {
        BuildError::Bip39(error)
    }
}

impl Report {
    /// Run the whole pipeline: dice -> mnemonic -> seed -> keys (SPEC steps 4-9).
    ///
    /// The single path from input to output. Every front end comes through here, which is
    /// what makes "the device computes what the desktop computes" a fact about the
    /// program rather than a claim about two pieces of code.
    ///
    /// Refuses an input that carried no rolls at all, whatever the mode: see
    /// [`BuildError::NoRolls`].
    pub fn build(dice: &DiceEntropy, params: &Parameters<'_>) -> Result<Report, BuildError> {
        if dice.events() == 0 {
            return Err(BuildError::NoRolls);
        }
        let mnemonic = bip39::mnemonic_from_dice(dice, params.mode)?;

        // Mnemonic zeroizes on drop and cannot be destructured, so copy out what the report
        // needs before the value goes away.
        let words: Vec<String> = mnemonic.words.iter().map(|w| (*w).to_string()).collect();
        let phrase = mnemonic.phrase();
        let entropy_hex = hex_encode(&mnemonic.entropy);
        let bits_used = mnemonic.entropy.len() * 8;
        drop(mnemonic);

        let (seed_hex, root_xprv, root_fingerprint, schemes) = derive_all(&phrase, params);

        Ok(Report {
            events: dice.events(),
            clean: dice.clean().to_string(),
            binary: dice.binary().to_string(),
            total_bits: dice.binary().len(),
            bits_used,
            effective_bits: effective_bits(params.mode, bits_used, dice.binary().len()),
            mode: params.mode,
            words,
            phrase,
            entropy_hex,
            seed_hex,
            root_xprv,
            root_fingerprint,
            network: params.network,
            has_passphrase: !params.passphrase.is_empty(),
            mnemonic_input: None,
            schemes,
        })
    }

    /// Run the pipeline from a phrase the user supplied instead of dice (SPEC steps 8-9).
    ///
    /// Validation never blocks derivation. The seed is PBKDF2 over the normalized text
    /// whatever [`bip39::check_phrase`] says about it - a misspelled word or a broken
    /// checksum is a warning the renderers show, not a refusal - because that is what the
    /// reference page does, and because a tool that refuses to show you the wallet your
    /// phrase produces cannot tell you which wallet your phrase produces.
    ///
    /// `None`, and only `None`, for a text with no words in it: PBKDF2 over the empty string
    /// is a wallet anyone can look up, exactly as it is on the dice side (see
    /// [`BuildError::NoRolls`]). Every other input has a wallet and gets one.
    pub fn from_phrase(text: &str, params: &Parameters<'_>) -> Option<Report> {
        let phrase = bip39::normalize_phrase(text);
        if phrase.is_empty() {
            return None;
        }
        let check = bip39::check_phrase(&phrase);
        // Normalized, so the words are exactly the single-space separated pieces.
        let words: Vec<String> = phrase.split(' ').map(str::to_string).collect();
        let (seed_hex, root_xprv, root_fingerprint, schemes) = derive_all(&phrase, params);

        Some(Report {
            events: 0,
            clean: String::new(),
            binary: String::new(),
            total_bits: 0,
            bits_used: 0,
            effective_bits: 0,
            // No selection was made; the phrase is the input. The renderers read
            // `mnemonic_input` rather than this field on this path.
            mode: MnemonicMode::Raw,
            words,
            phrase,
            entropy_hex: hex_encode(&check.entropy),
            seed_hex,
            root_xprv,
            root_fingerprint,
            network: params.network,
            has_passphrase: !params.passphrase.is_empty(),
            mnemonic_input: Some(check),
            schemes,
        })
    }
}

/// SPEC steps 8-9: phrase (plus passphrase) -> seed -> BIP32 root -> one derivation per
/// scheme. Shared by both entry points, so a wallet restored from its phrase cannot be
/// derived differently from the wallet the dice produced.
fn derive_all(phrase: &str, params: &Parameters<'_>) -> (String, String, String, Vec<SchemeReport>) {
    let seed = bip39::seed(phrase, params.passphrase);
    let root_xprv = derive::root_xprv(&seed, params.network);
    let root_fingerprint = derive::root_fingerprint(&seed, params.network);
    let schemes: Vec<SchemeReport> = params
        .schemes
        .iter()
        .map(|scheme| SchemeReport {
            scheme: *scheme,
            derived: derive::derive(
                &seed,
                params.network,
                *scheme,
                params.account,
                params.change,
                params.count,
                params.script_type,
            ),
        })
        .collect();
    (hex_encode(seed.as_slice()), root_xprv, root_fingerprint, schemes)
}

/// The entropy that actually protects the wallet, given the mnemonic's ENT and the bits the
/// dice supplied.
///
/// The crate's only statement of that rule, because every warning in the program is computed
/// from this number: a fixed word count is a SHA256 stretch of the digit string, so the ENT
/// it advertises says nothing about how hard the wallet is to guess, while raw mode uses the
/// dice bits themselves and the two agree.
pub fn effective_bits(mode: MnemonicMode, bits_used: usize, total_bits: usize) -> usize {
    match mode {
        MnemonicMode::Raw => bits_used,
        MnemonicMode::Words(_) => bits_used.min(total_bits),
    }
}

// ---------------------------------------------------------------------------------------
// Buffer sizing
// ---------------------------------------------------------------------------------------

/// Upper bound on the rendered report, whichever renderer runs.
///
/// Measured from the report rather than guessed per row: the desktop JSON row is 112 bytes
/// of keys, quotes and indentation plus its four values, and a human row is its four cells
/// padded to the column widths, so a fixed per-row constant is only ever right for the row
/// lengths someone happened to test. Under-reserving costs an unwiped copy of the whole
/// report in freed heap, so the fixed parts below are rounded well up.
pub fn capacity(report: &Report) -> usize {
    /// Banner, labels, the selection note and both warnings, all of which are short and
    /// bounded by their format strings.
    const FIXED: usize = 4 * 1024;
    /// One scheme's heading, account path, four key lines and table header.
    const PER_SCHEME: usize = 512;
    /// One row: 112 bytes of JSON scaffolding, or the padding of a human table line, plus
    /// the difference between a row's own cells and the widest cell in each column.
    const PER_ROW: usize = 160;

    let strings = escaped_len(&report.clean)
        + escaped_len(&report.binary)
        + escaped_len(&report.phrase)
        + escaped_len(&report.entropy_hex)
        + escaped_len(&report.seed_hex)
        + escaped_len(&report.root_xprv)
        + escaped_len(&report.root_fingerprint)
        // The words appear once as the phrase above and once as the JSON array.
        + report.words.iter().map(|w| escaped_len(w) + 4).sum::<usize>()
        // Unknown words are a third appearance of some of them: the JSON array and, in the
        // human report, the warning that lists them. An input of nothing but unknown words
        // is exactly the case FIXED does not cover.
        + report.mnemonic_input.as_ref().map_or(0, |input| {
            input
                .unknown_words
                .iter()
                .map(|w| escaped_len(w) + 4)
                .sum::<usize>()
                * 2
        });

    let schemes: usize = report
        .schemes
        .iter()
        .map(|scheme| {
            let account = &scheme.derived.account;
            let keys = escaped_len(&account.path)
                + escaped_len(&account.xprv)
                + escaped_len(&account.xpub)
                + account.slip132_prv.as_deref().map_or(0, escaped_len)
                + account.slip132_pub.as_deref().map_or(0, escaped_len);
            let rows: usize = scheme
                .derived
                .rows
                .iter()
                .map(|row| {
                    PER_ROW
                        + escaped_len(&row.path)
                        + escaped_len(&row.address)
                        + escaped_len(&row.pubkey)
                        + escaped_len(&row.wif)
                })
                .sum();
            PER_SCHEME + keys + rows
        })
        .sum();

    FIXED + strings + schemes
}

/// Bytes a string can take once written out: one per printable ASCII character, six for any
/// other character in the BMP and twelve above it, which is what the desktop JSON writer
/// escapes them to (`\uXXXX` per UTF-16 unit, so a surrogate pair costs two). A renderer
/// that copies verbatim spends less, so this bounds both.
fn escaped_len(value: &str) -> usize {
    value
        .chars()
        .map(|c| match c {
            ' '..='~' => 1,
            c if c.len_utf16() == 1 => 6,
            _ => 12,
        })
        .sum()
}

/// Lowercase hex digits, shared by [`hex_encode`] with the desktop JSON writer's escapes.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex. The `hex` crate is a dev-dependency only, and this is four lines.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        out.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip39::WordCount;
    use crate::entropy;

    fn word_count(words: usize) -> WordCount {
        WordCount::new(words).expect("test uses a supported word count")
    }

    // -- the pipeline --------------------------------------------------------------------

    /// The refusal that keeps the wallet of SHA256("") off the screen: a fixed word count is
    /// defined for the empty digit string, so without this an empty input would produce a
    /// published wallet in every front end.
    #[test]
    fn an_input_with_no_rolls_is_refused_in_every_mode() {
        let dice = entropy::parse_dice("no digits here");
        for mode in [MnemonicMode::Raw, MnemonicMode::Words(word_count(12))] {
            let params = Parameters {
                mode,
                passphrase: "",
                network: Network::Bitcoin,
                schemes: &Scheme::ALL,
                account: ChildIndex::ZERO,
                change: ChildIndex::ZERO,
                count: 1,
                script_type: 0,
            };
            assert_eq!(
                Report::build(&dice, &params).err(),
                Some(BuildError::NoRolls),
                "{mode} accepted an input with no rolls"
            );
        }
    }

    #[test]
    fn a_built_report_describes_the_dice_it_was_built_from() {
        let dice = entropy::parse_dice(&"123456".repeat(14));
        let params = Parameters {
            mode: MnemonicMode::Raw,
            passphrase: "",
            network: Network::Bitcoin,
            schemes: &[Scheme::Bip84],
            account: ChildIndex::ZERO,
            change: ChildIndex::ZERO,
            count: 2,
                script_type: 0,
        };
        let report = Report::build(&dice, &params).expect("84 rolls is plenty");
        assert_eq!(report.events, 84);
        assert_eq!(report.total_bits, dice.binary().len());
        assert_eq!(report.bits_used, bip39::raw_bits_used(report.total_bits));
        assert_eq!(report.effective_bits, report.bits_used);
        assert_eq!(report.words.len(), report.bits_used / 32 * 3);
        assert_eq!(report.phrase.as_str(), report.words.join(" "));
        assert_eq!(report.seed_hex.len(), 128);
        assert!(!report.has_passphrase);
        assert_eq!(report.schemes.len(), 1);
        assert_eq!(report.schemes[0].derived.rows.len(), 2);
    }

    /// The phrase path derives from the text as typed, whatever the checker says about it,
    /// and reports the dice fields as the nothing they are.
    #[test]
    fn a_phrase_report_derives_from_the_phrase_and_claims_no_dice() {
        let params = Parameters {
            mode: MnemonicMode::Raw,
            passphrase: "",
            network: Network::Bitcoin,
            schemes: &[Scheme::Bip84],
            account: ChildIndex::ZERO,
            change: ChildIndex::ZERO,
            count: 2,
                script_type: 0,
        };
        // Deliberately mis-spaced and mis-cased, and one word short of a checksum.
        let report =
            Report::from_phrase("  Zoo\tzoo   zoo zoo ", &params).expect("four words is a phrase");
        assert_eq!(report.phrase.as_str(), "Zoo zoo zoo zoo");
        assert_eq!(report.words, ["Zoo", "zoo", "zoo", "zoo"]);
        assert_eq!(report.events, 0);
        assert_eq!(report.total_bits, 0);
        assert_eq!(report.bits_used, 0);
        assert_eq!(report.effective_bits, 0);
        assert_eq!(report.entropy_hex, "");
        assert_eq!(report.seed_hex.len(), 128);
        assert_eq!(report.schemes[0].derived.rows.len(), 2);

        let input = report.mnemonic_input.as_ref().expect("phrase path");
        assert_eq!(input.word_count, 4);
        assert!(input.unknown_words.is_empty());
        assert_eq!(input.checksum, bip39::Checksum::NotApplicable);

        // The seed is the one the normalized text produces, nothing else.
        assert_eq!(
            report.seed_hex,
            hex_encode(bip39::seed("Zoo zoo zoo zoo", "").as_slice())
        );
    }

    /// The same refusal as [`BuildError::NoRolls`], for the same reason: PBKDF2 over the
    /// empty string is a wallet anyone can look up. It is also the only one on this path.
    #[test]
    fn a_phrase_with_no_words_is_refused() {
        let params = Parameters {
            mode: MnemonicMode::Raw,
            passphrase: "",
            network: Network::Bitcoin,
            schemes: &[],
            account: ChildIndex::ZERO,
            change: ChildIndex::ZERO,
            count: 0,
            script_type: 0,
        };
        for text in ["", "   ", "\t\r\n"] {
            assert!(Report::from_phrase(text, &params).is_none(), "{text:?}");
        }
        // One word is a phrase: it is not a mnemonic, but it is text with a wallet behind it,
        // and refusing it would be this program deciding which phrases are allowed.
        assert!(Report::from_phrase("word", &params).is_some());
    }

    /// The number every warning is computed from, checked directly rather than through a
    /// second copy of the rule in a test.
    #[test]
    fn effective_bits_is_bounded_by_the_dice_in_fixed_word_mode() {
        assert_eq!(effective_bits(MnemonicMode::Raw, 320, 334), 320);
        // Raw mode never advertises more than the dice gave, so the two agree.
        assert_eq!(effective_bits(MnemonicMode::Raw, 32, 34), 32);
        // A fixed word count stretches: 8 dice bits stay 8 however big the ENT is.
        assert_eq!(
            effective_bits(MnemonicMode::Words(word_count(24)), 256, 8),
            8
        );
        assert_eq!(
            effective_bits(MnemonicMode::Words(word_count(12)), 128, 334),
            128
        );
    }

    /// [`capacity`] must bound what any renderer writes; without the desktop JSON writer to
    /// exercise it end to end, hold it to the sum of everything a report contains plus the
    /// per-scheme and per-row scaffolding allowances it promises.
    #[test]
    fn capacity_covers_every_string_the_report_holds() {
        let dice = entropy::parse_dice(&"123456".repeat(14));
        let params = Parameters {
            mode: MnemonicMode::Raw,
            passphrase: "",
            network: Network::Bitcoin,
            schemes: &Scheme::ALL,
            account: ChildIndex::ZERO,
            change: ChildIndex::ZERO,
            count: 5,
            script_type: 0,
        };
        let report = Report::build(&dice, &params).expect("84 rolls is plenty");

        let mut contents = report.clean.len()
            + report.binary.len()
            + report.phrase.len()
            + report.entropy_hex.len()
            + report.seed_hex.len()
            + report.root_xprv.len()
            + report.root_fingerprint.len()
            + report.words.iter().map(|w| w.len() + 4).sum::<usize>();
        for scheme in &report.schemes {
            let account = &scheme.derived.account;
            contents += account.path.len()
                + account.xprv.len()
                + account.xpub.len()
                + account.slip132_prv.as_deref().map_or(0, str::len)
                + account.slip132_pub.as_deref().map_or(0, str::len);
            for row in &scheme.derived.rows {
                contents += row.path.len() + row.address.len() + row.pubkey.len() + row.wif.len();
            }
        }
        assert!(
            capacity(&report) >= contents,
            "capacity {} does not cover the report's own strings {contents}",
            capacity(&report)
        );
    }

    #[test]
    fn hex_encoding_is_lowercase_and_zero_padded() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }
}
