// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Boot self-test: SECURITY.md invariant 5's "boot self-test with hard failure surfaced
//! on screen", and the "self-test results" line of the Verify screen.
//!
//! [`run`] executes a curated subset of the crate's verification vectors - small enough
//! to run at every boot, chosen so that every cryptographic primitive on the derivation
//! path is exercised at least once against a pinned expected value:
//!
//! | check          | exercises                                              |
//! |----------------|--------------------------------------------------------|
//! | `wordlist`     | embedded wordlist identity (SHA-256 vs upstream file)  |
//! | `dice raw`     | dice parse + raw-mode selection + BIP39 encode (SHA256)|
//! | `dice fixed`   | fixed-mode hash path + BIP39 encode                    |
//! | `bip39 seed`   | PBKDF2-HMAC-SHA512 x 2048, NFKD (the one slow vector)  |
//! | `bip84 account`| secp256k1, BIP32 hardened+normal derivation, base58,   |
//! |                | bech32 (P2WPKH)                                        |
//! | `bip86 taproot`| BIP341 key-path tweak, bech32m (P2TR)                  |
//!
//! Budget: the PBKDF2 vector dominates at 4096 SHA-512 compressions; the two derivation
//! checks add the one-time secp256k1 context build plus about a dozen point
//! multiplications; everything else is a handful of SHA-256 blocks. Comfortably under a
//! second on the 400 MHz target, which is why exactly one PBKDF2-heavy vector is
//! included and the full Trezor/iancoleman corpora stay in the host test suite.
//!
//! Failure discipline: a failing check is a reported [`Check::passed`] == `false`, never
//! a panic - the firmware must be able to render the failure, per the invariant. The
//! checks are pure computation over compile-time constants: no clock, no RNG, no I/O,
//! and therefore the same verdict on every boot.

use sha2::{Digest, Sha256};

use crate::bip39::{self, MnemonicMode};
use crate::derive::{self, ChildIndex, Scheme};
use crate::entropy;
use bitcoin::Network;

/// Number of checks [`run`] performs; the length of [`SelfTest::checks`].
pub const CHECK_COUNT: usize = 6;

/// One named check and its verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Check {
    /// Short ASCII label, stable across releases; what the Verify screen prints.
    pub name: &'static str,
    pub passed: bool,
}

/// The outcome of one boot self-test run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfTest {
    /// Every check, in the fixed order [`run`] executes them.
    pub checks: [Check; CHECK_COUNT],
}

impl SelfTest {
    /// True only when every individual check passed.
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.passed)
    }
}

// ---------------------------------------------------------------------------------------
// Pinned expected values. Each constant names the vector it came from; changing any of
// them is changing what the device accepts as a healthy build, so they are grouped here
// rather than scattered through the checks.
// ---------------------------------------------------------------------------------------

/// SHA-256 of every wordlist word followed by one LF - byte-for-byte the upstream
/// bitcoin/bips `bip-0039/english.txt` file. Same digest `build.rs` pins at compile time;
/// checking it again at boot verifies the table that actually got linked into this image,
/// not the file the build machine read.
const WORDLIST_SHA256: [u8; 32] =
    hex::<32>("2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda");

/// Spot glyphs: first, middle and last word of the official list. Cheap independent
/// probes that fail with a better signal than a digest mismatch alone.
const WORD_FIRST: &str = "abandon";
const WORD_MID: &str = "lend"; // index 1023
const WORD_LAST: &str = "zoo";

/// `tests/vectors/iancoleman_vectors.json`, case `v20`: input and `raw.phrase`
/// (captured from the real iancoleman page; 20 rolls -> 32 raw bits -> 3 words).
const DICE_RAW_INPUT: &str = "12345612345612345612";
const DICE_RAW_PHRASE: &str = "refuse hand spice";

/// `tests/vectors/iancoleman_vectors.json`, case `v36_sixes`, `w12.phrase`: 36 sixes
/// through the fixed 12-word (SHA256) path, exercising the 6 -> 0 digit mapping.
const DICE_FIXED_INPUT: &str = "666666666666666666666666666666666666";
const DICE_FIXED_WORDS: usize = 12;
const DICE_FIXED_PHRASE: &str =
    "donor twice business minimum roast snap laugh tribe wide elephant approve soda";

/// `tests/vectors/trezor_vectors.json`, `english[0]`: the all-zero-entropy mnemonic with
/// passphrase "TREZOR" and its official 64-byte seed. The one PBKDF2-heavy vector.
const SEED_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon about";
const SEED_PASSPHRASE: &str = "TREZOR";
const SEED_EXPECTED: [u8; 64] = hex::<64>(
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1\
     e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
);

/// BIP84 mainnet `m/84'/0'/0'` account xpub and first receive address for
/// [`SEED_EXPECTED`]. Derived once from that seed via the desktop-verified suite
/// (bigdice-cli 0.3.0, `--mnemonic <english[0]> --passphrase TREZOR`), pinned 2026-08-17.
const BIP84_ACCOUNT_XPUB: &str =
    "xpub6Crgkie5Rb7wDabkf4Uf6A2qnuERMA3p2QrnmHNQDrsXTaGvz9zugU38Apne8WqrcbSjdLwbhtfHrzWjNCJPVAkkNoQhMfzhBm8rKMA8KxH";
const BIP84_FIRST_ADDRESS: &str = "bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu";

/// BIP86 mainnet `m/86'/0'/0'/0/0` first receive address for [`SEED_EXPECTED`]; same
/// derivation run as the BIP84 constants above.
const BIP86_FIRST_ADDRESS: &str =
    "bc1p3ryfth56dp058avv97ppn065ctsk263puvwp4rcka3wpg6cudp9qd3jsuu";

/// Run every check. Never panics; a broken build is a `false` in the result, rendered by
/// the firmware, not an abort it cannot render.
pub fn run() -> SelfTest {
    // WordCount::new(12) cannot fail, but the no-panic rule holds even for "cannot": if
    // the count table were ever broken, the dice-fixed check reports the failure.
    let fixed_mode = bip39::WordCount::new(DICE_FIXED_WORDS)
        .ok()
        .map(MnemonicMode::Words);

    SelfTest {
        checks: [
            Check {
                name: "wordlist",
                passed: check_wordlist(bip39::wordlist(), &WORDLIST_SHA256),
            },
            Check {
                name: "dice raw",
                passed: check_dice(DICE_RAW_INPUT, MnemonicMode::Raw, DICE_RAW_PHRASE),
            },
            Check {
                name: "dice fixed",
                passed: fixed_mode
                    .is_some_and(|mode| check_dice(DICE_FIXED_INPUT, mode, DICE_FIXED_PHRASE)),
            },
            Check {
                name: "bip39 seed",
                passed: check_seed(SEED_PHRASE, SEED_PASSPHRASE, &SEED_EXPECTED),
            },
            // Both derivation checks start from the PINNED seed, not the one the previous
            // check computed, so a PBKDF2 fault shows up as exactly one failing line.
            Check {
                name: "bip84 account",
                passed: check_bip84(&SEED_EXPECTED, BIP84_ACCOUNT_XPUB, BIP84_FIRST_ADDRESS),
            },
            Check {
                name: "bip86 taproot",
                passed: check_bip86(&SEED_EXPECTED, BIP86_FIRST_ADDRESS),
            },
        ],
    }
}

/// Wordlist integrity: exact count, strict sort order, the three spot glyphs, and the
/// SHA-256 of the words rejoined with LF against the upstream file digest.
fn check_wordlist(list: &[&str], want_digest: &[u8; 32]) -> bool {
    if list.len() != bip39::WORDLIST_LEN {
        return false;
    }
    if !list.windows(2).all(|w| w[0] < w[1]) {
        return false;
    }
    if list.first().copied() != Some(WORD_FIRST)
        || list.get(bip39::WORDLIST_LEN / 2 - 1).copied() != Some(WORD_MID)
        || list.last().copied() != Some(WORD_LAST)
    {
        return false;
    }
    // Incremental hash of word + "\n" per entry reconstructs the upstream file's bytes
    // exactly, without allocating a 13 KB copy of the list at boot.
    let mut hasher = Sha256::new();
    for word in list {
        hasher.update(word.as_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize().as_slice() == want_digest
}

/// Dice pipeline: raw text through [`entropy::parse_dice`] and
/// [`bip39::mnemonic_from_dice`] must yield exactly the recorded mnemonic sentence.
/// An `Err` from the pipeline is a failed check, not a panic.
fn check_dice(input: &str, mode: MnemonicMode, want_phrase: &str) -> bool {
    let rolls = entropy::parse_dice(input);
    match bip39::mnemonic_from_dice(&rolls, mode) {
        Ok(m) => m.phrase().as_str() == want_phrase,
        Err(_) => false,
    }
}

/// BIP39 seed stretching: mnemonic + passphrase through PBKDF2-HMAC-SHA512 x 2048 must
/// reproduce the official 64-byte seed.
fn check_seed(phrase: &str, passphrase: &str, want: &[u8; 64]) -> bool {
    *bip39::seed(phrase, passphrase) == *want
}

/// BIP84: account xpub (secp256k1 + BIP32 + base58check) and first receive address
/// (bech32 P2WPKH) from a pinned seed.
fn check_bip84(seed: &[u8; 64], want_xpub: &str, want_address: &str) -> bool {
    let d = derive::derive(
        seed,
        Network::Bitcoin,
        Scheme::Bip84,
        ChildIndex::ZERO,
        ChildIndex::ZERO,
        1,
        0,
    );
    d.account.xpub == want_xpub && d.rows.first().is_some_and(|row| row.address == want_address)
}

/// BIP86: first receive address (BIP341 key-path tweak + bech32m P2TR) from a pinned
/// seed.
fn check_bip86(seed: &[u8; 64], want_address: &str) -> bool {
    let d = derive::derive(
        seed,
        Network::Bitcoin,
        Scheme::Bip86,
        ChildIndex::ZERO,
        ChildIndex::ZERO,
        1,
        0,
    );
    d.rows.first().is_some_and(|row| row.address == want_address)
}

/// Compile-time lowercase-hex decoder for the pinned digests and the seed. A malformed
/// literal is a compile error (const panic), so no runtime failure case exists.
const fn hex<const N: usize>(s: &str) -> [u8; N] {
    const fn nibble(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => panic!("pinned constant must be lowercase hex"),
        }
    }
    let bytes = s.as_bytes();
    assert!(bytes.len() == N * 2, "pinned constant has the wrong length");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (nibble(bytes[2 * i]) << 4) | nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn run_passes_and_reports_every_check_by_name() {
        let st = run();
        let names: Vec<&str> = st.checks.iter().map(|c| c.name).collect();
        assert_eq!(
            names,
            [
                "wordlist",
                "dice raw",
                "dice fixed",
                "bip39 seed",
                "bip84 account",
                "bip86 taproot"
            ]
        );
        for check in &st.checks {
            assert!(check.passed, "boot self-test check failed: {}", check.name);
        }
        assert!(st.passed());
    }

    /// The overall verdict must be AND, not OR or last-wins: any single failure flips it.
    #[test]
    fn one_failing_check_fails_the_whole_test() {
        let mut st = run();
        assert!(st.passed());
        for i in 0..CHECK_COUNT {
            st.checks[i].passed = false;
            assert!(!st.passed(), "check {i} did not gate the verdict");
            st.checks[i].passed = true;
        }
        assert!(st.passed());
    }

    /// The labels go on the Verify screen: keep them ASCII, short and unique.
    #[test]
    fn check_names_are_screen_renderable_and_unique() {
        let st = run();
        for (i, check) in st.checks.iter().enumerate() {
            assert!(check.name.is_ascii() && !check.name.is_empty());
            assert!(check.name.len() <= 16, "{} is too long for a line", check.name);
            assert!(
                st.checks[..i].iter().all(|prior| prior.name != check.name),
                "duplicate check name {}",
                check.name
            );
        }
    }

    /// Mutation coverage: each kind of wordlist damage must be caught, including damage
    /// only the digest can see.
    #[test]
    fn wordlist_check_catches_each_kind_of_damage() {
        let good: Vec<&str> = bip39::wordlist().to_vec();
        assert!(check_wordlist(&good, &WORDLIST_SHA256));

        // Truncated list.
        assert!(!check_wordlist(&good[..good.len() - 1], &WORDLIST_SHA256));

        // Sort order broken.
        let mut swapped = good.clone();
        swapped.swap(10, 11);
        assert!(!check_wordlist(&swapped, &WORDLIST_SHA256));

        // A smuggled word that keeps the length, the sort order and all three spot
        // glyphs intact: "about" -> "abouta" still sits between "able" and "above",
        // so only the digest can catch it.
        let mut doctored = good.clone();
        assert_eq!(doctored[3], "about");
        doctored[3] = "abouta";
        assert!(
            doctored.windows(2).all(|w| w[0] < w[1]),
            "mutation must keep the list sorted or it tests the wrong probe"
        );
        assert!(!check_wordlist(&doctored, &WORDLIST_SHA256));

        // And a wrong pinned digest must never pass a good list.
        assert!(!check_wordlist(&good, &[0u8; 32]));
    }

    #[test]
    fn dice_check_catches_doctored_rolls_and_reports_errors_as_failures() {
        assert!(check_dice(DICE_RAW_INPUT, MnemonicMode::Raw, DICE_RAW_PHRASE));

        // One extra roll shifts raw mode's trailing 32-bit window: different phrase.
        let doctored = format!("{DICE_RAW_INPUT}1");
        assert!(!check_dice(&doctored, MnemonicMode::Raw, DICE_RAW_PHRASE));

        // Under 32 bits the pipeline returns Err; the check must report, not panic.
        assert!(!check_dice("123", MnemonicMode::Raw, DICE_RAW_PHRASE));

        // Fixed mode hashes the digit string, so a single changed roll changes everything.
        let mode = MnemonicMode::Words(bip39::WordCount::new(DICE_FIXED_WORDS).unwrap());
        assert!(check_dice(DICE_FIXED_INPUT, mode, DICE_FIXED_PHRASE));
        let doctored = DICE_FIXED_INPUT.replacen('6', "1", 1);
        assert!(!check_dice(&doctored, mode, DICE_FIXED_PHRASE));
    }

    #[test]
    fn seed_check_catches_a_doctored_passphrase_and_a_doctored_expectation() {
        assert!(check_seed(SEED_PHRASE, SEED_PASSPHRASE, &SEED_EXPECTED));
        // Passphrase case matters to PBKDF2.
        assert!(!check_seed(SEED_PHRASE, "trezor", &SEED_EXPECTED));
        // A single flipped bit in the pinned seed must fail.
        let mut wrong = SEED_EXPECTED;
        wrong[0] ^= 0x01;
        assert!(!check_seed(SEED_PHRASE, SEED_PASSPHRASE, &wrong));
    }

    #[test]
    fn derivation_checks_catch_a_doctored_seed_and_wrong_constants() {
        assert!(check_bip84(&SEED_EXPECTED, BIP84_ACCOUNT_XPUB, BIP84_FIRST_ADDRESS));
        assert!(check_bip86(&SEED_EXPECTED, BIP86_FIRST_ADDRESS));

        let mut doctored = SEED_EXPECTED;
        doctored[63] ^= 0x80;
        assert!(!check_bip84(&doctored, BIP84_ACCOUNT_XPUB, BIP84_FIRST_ADDRESS));
        assert!(!check_bip86(&doctored, BIP86_FIRST_ADDRESS));

        // Both halves of the bip84 check must gate: right xpub + wrong address fails,
        // wrong xpub + right address fails.
        assert!(!check_bip84(&SEED_EXPECTED, BIP84_ACCOUNT_XPUB, BIP86_FIRST_ADDRESS));
        assert!(!check_bip84(&SEED_EXPECTED, BIP86_FIRST_ADDRESS, BIP84_FIRST_ADDRESS));
    }

    /// The pinned mnemonic/seed constants must be the committed Trezor vector, not a
    /// retyped copy that could drift from the corpus the host suite verifies.
    #[test]
    fn pinned_seed_constants_match_the_committed_trezor_vector() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/trezor_vectors.json"))
                .expect("vector file is valid JSON");
        let case = &doc["english"][0];
        assert_eq!(case[1].as_str().unwrap(), SEED_PHRASE);
        assert_eq!(case[2].as_str().unwrap(), hex::encode(SEED_EXPECTED));
    }

    /// Same anti-drift pin for the dice constants against the committed iancoleman file.
    #[test]
    fn pinned_dice_constants_match_the_committed_iancoleman_vectors() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/iancoleman_vectors.json"))
                .expect("vector file is valid JSON");
        let v20 = &doc["vectors"]["v20"];
        assert_eq!(v20["input"].as_str().unwrap(), DICE_RAW_INPUT);
        assert_eq!(v20["raw"]["phrase"].as_str().unwrap(), DICE_RAW_PHRASE);
        let v36 = &doc["vectors"]["v36_sixes"];
        assert_eq!(v36["input"].as_str().unwrap(), DICE_FIXED_INPUT);
        assert_eq!(v36["w12"]["phrase"].as_str().unwrap(), DICE_FIXED_PHRASE);
    }
}
