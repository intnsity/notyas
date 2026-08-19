// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Dice input parsing and the unbiased base-6 to binary encoding (SPEC steps 1-3).
//!
//! This module is deliberately total: any string at all is a valid input, it simply may
//! yield zero events. Rejecting under-length input is the job of [`crate::bip39`], which
//! is the layer that knows how many bits a mnemonic needs.

use core::fmt;

use alloc::string::{String, ToString};

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Everything the rest of the pipeline (and the entropy report) needs to know about one
/// dice session.
///
/// Invariants, enforced by keeping the fields private so that only the constructors below
/// can establish them:
/// - `clean` contains only the ASCII digits '0'..='5' and `events == clean.len()`.
/// - `binary` contains only '0' and '1'.
/// - `binary` is the concatenation, in order, of the per-digit codes of `clean`, so its
///   length depends on the roll VALUES, not just on `events` (5/3 bits per roll on
///   average: digits 0..3 cost two bits, digits 4 and 5 cost one). [`DiceEntropy::from_bits`]
///   is the one documented exception and says so.
///
/// Lifetime invariant: `clean` and `binary` are the master secret in its most usable form,
/// either one alone regenerating the wallet, so the value wipes itself on drop and its
/// `Debug` rendering never shows them. A copy taken out of here (the report, a clone) owns
/// the same obligation.
#[derive(Clone, Default, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DiceEntropy {
    /// Number of accepted rolls, i.e. characters kept by SPEC step 1.
    events: usize,
    /// Base-6 digit string after SPEC step 2 (a roll of 6 is recorded as '0').
    clean: String,
    /// Bit string after SPEC step 3, most significant bit of each code first.
    binary: String,
}

impl DiceEntropy {
    /// Number of accepted rolls (SPEC step 1).
    pub fn events(&self) -> usize {
        self.events
    }

    /// The base-6 digit string (SPEC step 2), which is what the fixed word-count mode
    /// hashes.
    pub fn clean(&self) -> &str {
        &self.clean
    }

    /// The bit string (SPEC step 3), which is what raw mode selects from.
    pub fn binary(&self) -> &str {
        &self.binary
    }

    /// Build a value from a bit string that no dice produced.
    ///
    /// The escape hatch for vector tests that drive the raw-mode encoder from published
    /// entropy rather than from rolls. `events` is 0 and `clean` is empty because no digit
    /// string corresponds to these bits, so the fixed word-count mode - which hashes
    /// `clean` - must never be fed a value built this way.
    ///
    /// Panics if `bits` is not a string of '0' and '1': that is a broken test, not input.
    pub fn from_bits(bits: &str) -> Self {
        assert!(
            bits.bytes().all(|b| b == b'0' || b == b'1'),
            "from_bits takes a string of '0' and '1' only"
        );
        DiceEntropy {
            events: 0,
            clean: String::new(),
            binary: bits.to_string(),
        }
    }
}

impl fmt::Debug for DiceEntropy {
    /// Hand written rather than derived: a stray `{:?}` in a caller, a log line or a panic
    /// payload would otherwise copy the rolls into a fresh, unwiped string. Only the shape
    /// of the session is printable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiceEntropy")
            .field("events", &self.events)
            .field("clean", &"<redacted>")
            .field(
                "binary",
                &format_args!("<redacted, {} bits>", self.binary.len()),
            )
            .finish()
    }
}

/// Per-digit codes of SPEC step 3, indexed by the base-6 digit value.
///
/// Why this is unbiased, stated correctly because the reason is not the obvious one. These
/// codes are NOT prefix-free - "0" prefixes both "00" and "01" - and they do not need to be.
/// Prefix-freeness buys unique DECODABILITY, and nothing here ever decodes: the bits are
/// consumed as entropy, never parsed back into rolls.
///
/// Uniformity comes from a different property. A fair roll is uniform over 0..=5, so it
/// emits a two-bit word (digits 0..=3) with probability 2/3 and a one-bit word (digits 4, 5)
/// with probability 1/3 - and CONDITIONAL ON THAT LENGTH the word is uniform over all
/// strings of it: {00, 01, 10, 11} each 1/4, {0, 1} each 1/2. The length carries no
/// information about the bit values, so concatenating the words of independent rolls yields
/// i.i.d. uniform bits, and any prefix of the stream is uniform over its own length.
///
/// The scheme is LOSSY, which is a separate matter and is fine: it keeps 5/3 bits of the
/// log2(6) = 2.585 bits a roll carries, so the caller needs more rolls, not better ones.
/// What would actually bias the result is truncating a roll to a fixed 2.58 bits, or taking
/// two bits by discarding 5 and 6 - both change the distribution rather than shortening it.
const CODES: [&str; 6] = ["00", "01", "10", "11", "0", "1"];

/// Parse raw dice text into [`DiceEntropy`].
///
/// SPEC obligations, in order:
/// - Step 1: keep every character in `[1-6]`; silently ignore ALL others (whitespace,
///   commas, '0', '7'..'9', letters, punctuation, non-ASCII). Do not reorder.
/// - Step 2: map each kept character to a base-6 digit, '1'..'5' unchanged and '6' -> '0'.
///   The concatenation is `clean`.
/// - Step 3: encode each digit with [`CODES`] and concatenate in order to form `binary`.
///
/// This mirrors iancoleman/bip39 `src/js/entropy.js` exactly.
pub fn parse_dice(input: &str) -> DiceEntropy {
    // A kept roll is one byte of input and costs at most two bits, so these capacities are
    // upper bounds and the two strings never reallocate.
    let mut clean = String::with_capacity(input.len());
    let mut binary = String::with_capacity(input.len() * 2);

    // Scanning bytes rather than chars is safe and lossless here: every byte of a
    // multi-byte UTF-8 sequence has the high bit set, so no fragment of a non-ASCII
    // character can be mistaken for a roll.
    for byte in input.bytes() {
        let value = match byte {
            b'1'..=b'5' => byte - b'0',
            b'6' => 0,
            _ => continue,
        };
        clean.push((b'0' + value) as char);
        binary.push_str(CODES[value as usize]);
    }

    DiceEntropy {
        events: clean.len(),
        clean,
        binary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cost in bits of one base-6 digit under [`CODES`].
    fn cost(digit: char) -> usize {
        match digit {
            '0'..='3' => 2,
            '4' | '5' => 1,
            other => panic!("digit out of range: {other}"),
        }
    }

    fn check_invariants(e: &DiceEntropy) {
        assert_eq!(
            e.events,
            e.clean.chars().count(),
            "events must count digits"
        );
        assert!(
            e.clean.chars().all(|c| ('0'..='5').contains(&c)),
            "clean must be base-6: {}",
            e.clean
        );
        assert!(
            e.binary.chars().all(|c| c == '0' || c == '1'),
            "binary must be bits: {}",
            e.binary
        );
        let expected: usize = e.clean.chars().map(cost).sum();
        assert_eq!(
            e.binary.len(),
            expected,
            "binary length must follow the table"
        );
    }

    #[test]
    fn per_digit_table() {
        // SPEC step 3, one roll at a time. '6' enters as digit 0 and so carries "00".
        let cases = [
            ("1", "1", "01"),
            ("2", "2", "10"),
            ("3", "3", "11"),
            ("4", "4", "0"),
            ("5", "5", "1"),
            ("6", "0", "00"),
        ];
        for (input, clean, binary) in cases {
            let e = parse_dice(input);
            assert_eq!(e.events, 1, "input {input}");
            assert_eq!(e.clean, clean, "input {input}");
            assert_eq!(e.binary, binary, "input {input}");
            check_invariants(&e);
        }
    }

    #[test]
    fn six_maps_to_zero_and_never_to_six() {
        let e = parse_dice("666666666666666666666666666666666666");
        assert_eq!(e.events, 36);
        assert_eq!(e.clean, "0".repeat(36));
        assert_eq!(e.binary, "0".repeat(72));
        assert!(!e.clean.contains('6'));
        check_invariants(&e);
    }

    #[test]
    fn literal_zero_is_noise_not_a_roll() {
        // A typed '0' is NOT a die face: only '6' becomes the digit 0.
        let e = parse_dice("0000");
        assert_eq!(e, DiceEntropy::default());
        assert_eq!(parse_dice("606").clean, "00");
    }

    #[test]
    fn noise_is_filtered_and_order_preserved() {
        // Whitespace, separators, out-of-range digits, letters and non-ASCII all vanish;
        // the surviving rolls keep their original order.
        let noisy = "1 2,3\t4\r\n5;6 -- 0789 abc XYZ \u{00e9}\u{4e2d}\u{1f600}";
        let e = parse_dice(noisy);
        assert_eq!(e.events, 6);
        assert_eq!(e.clean, "123450");
        assert_eq!(e.binary, "0110110100");
        assert_eq!(e, parse_dice("123456"));
        check_invariants(&e);
    }

    #[test]
    fn empty_and_all_noise_yield_no_events() {
        for input in ["", "   ", "hello world", "0789", "\u{4e2d}\u{6587}"] {
            let e = parse_dice(input);
            assert_eq!(e, DiceEntropy::default(), "input {input:?}");
            assert!(e.binary.is_empty());
        }
    }

    #[test]
    fn concatenation_is_order_dependent_not_multiset() {
        // Same rolls, different order: same length, different bits. Guards against any
        // future "sort/normalize" temptation in the parser.
        let a = parse_dice("1456");
        let b = parse_dice("6541");
        assert_eq!(a.binary.len(), b.binary.len());
        assert_ne!(a.binary, b.binary);
        assert_eq!(a.binary, "010100");
        assert_eq!(b.binary, "001001");
    }

    /// Hand-computed from the SPEC so the module is pinned even if the vector file is
    /// absent or regenerated.
    #[test]
    fn hand_computed_v20_and_v36_sixes() {
        // v20: "123456" -> digits "123450" -> 01 10 11 0 1 00, repeated, then "12".
        let unit = "0110110100";
        let e = parse_dice("12345612345612345612");
        assert_eq!(e.events, 20);
        assert_eq!(e.clean, "12345012345012345012");
        assert_eq!(e.binary, format!("{unit}{unit}{unit}0110"));
        assert_eq!(e.binary.len(), 34);
        check_invariants(&e);

        // v36_sixes: 36 rolls of six, two bits each.
        let e = parse_dice("666666666666666666666666666666666666");
        assert_eq!(e.events, 36);
        assert_eq!(e.clean, "000000000000000000000000000000000000");
        assert_eq!(e.binary.len(), 72);
        assert!(e.binary.chars().all(|c| c == '0'));
        check_invariants(&e);
    }

    /// Cross-check against the vectors produced by running the real iancoleman JS.
    ///
    /// Embedded, not read at run time; see the desktop crate's `tests/vectors/README.md`
    /// for why every vector file is loaded that way.
    const IANCOLEMAN_VECTORS: &str = include_str!("../tests/vectors/iancoleman_vectors.json");

    #[test]
    fn matches_iancoleman_vectors() {
        let doc: serde_json::Value =
            serde_json::from_str(IANCOLEMAN_VECTORS).expect("vector file is not JSON");
        let vectors = doc["vectors"]
            .as_object()
            .expect("vector file has no `vectors` object");

        let mut checked = 0usize;
        for (name, vector) in vectors {
            let input = vector["input"].as_str().expect("vector input");
            let e = parse_dice(input);
            check_invariants(&e);
            assert_eq!(
                e.events as u64,
                vector["events"].as_u64().expect("vector events"),
                "events mismatch for {name}"
            );
            assert_eq!(
                e.clean,
                vector["clean"].as_str().expect("vector clean"),
                "clean mismatch for {name}"
            );
            assert_eq!(
                e.binary,
                vector["binary"].as_str().expect("vector binary"),
                "binary mismatch for {name}"
            );
            // `bits` is redundant with `binary` in the file; checking it catches a vector
            // set that was edited inconsistently.
            if let Some(bits) = vector["bits"].as_u64() {
                assert_eq!(e.binary.len() as u64, bits, "bits mismatch for {name}");
            }
            checked += 1;
        }

        assert!(checked >= 2, "vector file is empty");
        for required in ["v20", "v36_sixes"] {
            assert!(
                vectors.contains_key(required),
                "vector file lost the {required} case"
            );
        }
    }
}
