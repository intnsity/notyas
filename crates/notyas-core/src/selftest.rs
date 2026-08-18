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
//! | `derive path`  | [`crate::sign::derive_path`] over an arbitrary path,   |
//! |                | against the key the report path shows for the same one |
//! | `sign p2wpkh`  | BIP-143 digest + low-R ECDSA, native segwit v0         |
//! | `sign p2sh-wpkh`| BIP-143 digest + low-R ECDSA, wrapped segwit v0       |
//! | `sign p2tr`    | BIP-341 digest + Schnorr key-path spend, tweaked and   |
//! |                | untweaked, 64- and 65-byte serializations              |
//! | `low-r grind`  | a vector whose stock RFC6979 nonce yields a high R, so |
//! |                | only real grinding reproduces the pinned bytes         |
//!
//! Budget: the PBKDF2 vector dominates at 4096 SHA-512 compressions; the derivation and
//! signing checks add the one-time secp256k1 context build plus roughly two dozen point
//! multiplications; everything else is a handful of SHA-256 blocks. Measured at 490 ms on
//! both boards before the m2 signing checks, against a 1 s budget, which is why exactly
//! one PBKDF2-heavy vector is included and the full Trezor/iancoleman corpora stay in the
//! host test suite.
//!
//! Why these five and not the whole m2 corpus: `tests/signing_vectors.rs` runs every
//! BIP-143, BIP-340, BIP-341 and low-R vector on the host. What a boot needs is one
//! vector per primitive that could be wrong in a way the host build was not - so the five
//! here are exactly the distinct primitives (arbitrary-path derivation, the BIP-143
//! digest through each of its two script shapes, the BIP-341 digest with and without a
//! merkle root, and the grinding loop), and nothing that only repeats one.
//!
//! Failure discipline: a failing check is a reported [`Check::passed`] == `false`, never
//! a panic - the firmware must be able to render the failure, per the invariant. The
//! checks are pure computation over compile-time constants: no clock, no RNG, no I/O,
//! and therefore the same verdict on every boot.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex;
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SegwitV0Sighash, SighashCache, TapSighashType};
use bitcoin::taproot::TapNodeHash;
use bitcoin::{Amount, Network, ScriptBuf, Transaction, TxOut};

use crate::bip39::{self, MnemonicMode};
use crate::derive::{self, ChildIndex, Scheme};
use crate::entropy;
use crate::sign::{self, SecretSigningKey, SignHash, SpendKind};

/// Number of checks [`run`] performs; the length of [`SelfTest::checks`].
pub const CHECK_COUNT: usize = 11;

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

// --- Signing (0.2.0-m2) -----------------------------------------------------------------
//
// Every hex string below also appears in `tests/vectors/signing_vectors.json`, and a host
// test asserts the two agree - so these are a cheap copy of the committed corpus, not a
// second source of truth that could drift from it. The corpus records where each value
// came from; the short form is BIP-143, BIP-341, and Bitcoin Core's low-R corpus with the
// expected bytes produced by an independent RFC 6979 implementation.

/// `m/84'/0'/0'/0/0` under [`SEED_EXPECTED`]: the master fingerprint the origin must
/// carry and the compressed public key the leaf scalar must produce. The same node the
/// `bip84 account` check reaches by the report path, so a divergence between the two
/// derivation entry points shows up as exactly one failing line.
const DERIVE_PATH: &str = "m/84'/0'/0'/0/0";
const DERIVE_PATH_FINGERPRINT: &str = "b4e3f5ed";
const DERIVE_PATH_PUBKEY: &str =
    "02a0f073d11f80811fb4e6d2b0299695c866a0988c1acf9f82a96ebb925524f328";

/// One BIP-143 known-answer vector: the digest and the signature over it.
///
/// `Copy` so a test can take a pinned vector, damage one field and prove the check
/// notices - the mutation discipline the rest of this module's tests already follow.
#[derive(Clone, Copy)]
struct SegwitV0Kat {
    unsigned_tx: &'static str,
    input_index: usize,
    /// The `0014{keyhash}` witness program. Natively that is the input's own
    /// scriptPubKey; wrapped it is the redeem script, and BIP-143 hashes the same bytes
    /// either way - which is exactly the confusion `wrapped` exists to keep honest.
    program: &'static str,
    wrapped: bool,
    value_sat: u64,
    privkey: &'static str,
    sighash: &'static str,
    /// DER plus the one sighash byte: 71 bytes here, the low-R maximum.
    signature: &'static str,
}

const SEGWIT_V0_KATS: [SegwitV0Kat; 2] = [
    // BIP-143, "Native P2WPKH" worked example, input 1, SIGHASH_ALL.
    SegwitV0Kat {
        unsigned_tx: "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f\
                      0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d5\
                      7b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f\
                      85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50\
                      ce2f0167faa815988ac11000000",
        input_index: 1,
        program: "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1",
        wrapped: false,
        value_sat: 600_000_000,
        privkey: "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9",
        sighash: "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670",
        signature: "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a\
                    0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01",
    },
    // BIP-143, "P2SH-P2WPKH" worked example, the single input, SIGHASH_ALL.
    SegwitV0Kat {
        unsigned_tx: "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477\
                      0100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f\
                      35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8a\
                      d6d77c88ac92040000",
        input_index: 0,
        program: "001479091972186c449eb1ded22b78e40d009bdf0089",
        wrapped: true,
        value_sat: 1_000_000_000,
        privkey: "eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf",
        sighash: "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6",
        signature: "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f\
                    0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01",
    },
];

/// BIP-341 `keyPathSpending[0]`: the nine-input transaction and the outputs it spends.
/// Both taproot vectors below index into the same transaction, so the prevout table is
/// built once.
const TAPROOT_TX: &str = "02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b3\
    34e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd9900000\
    00000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a418420000000000fffff\
    ffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202b\
    df6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968\
    eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a2a3e\
    4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de67619e6a3924ae25696bb7b6\
    94bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a263dc090464cd125c466b5a99667720b1c11046\
    8831d058aa1b82af10100000000ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241\
    244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab9\
    62b0065cd1d";

const TAPROOT_PREVOUTS: [(&str, u64); 9] = [
    ("512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343", 420_000_000),
    ("5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3", 462_000_000),
    ("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", 294_000_000),
    ("5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e", 504_000_000),
    ("512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605", 630_000_000),
    ("00147dd65592d0ab2fe0d0257d571abf032cd9db93dc", 378_000_000),
    ("512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831", 672_000_000),
    ("5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5", 546_000_000),
    ("512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220", 588_000_000),
];

/// One BIP-341 key-path known-answer vector. `Copy` for the same reason as
/// [`SegwitV0Kat`].
#[derive(Clone, Copy)]
struct TaprootKat {
    input_index: usize,
    /// `None` is the BIP86 shape the device signs; `Some` proves the tweak is applied.
    merkle_root: Option<&'static str>,
    sighash_type: u8,
    internal_privkey: &'static str,
    sighash: &'static str,
    /// 64 bytes under SIGHASH_DEFAULT, 65 with the flag byte otherwise.
    signature: &'static str,
}

/// Two of BIP-341's seven key-path inputs, chosen so that between them they cover both
/// tweak shapes and both witness lengths: no merkle root with a non-default flag, and a
/// merkle root with SIGHASH_DEFAULT. The other five repeat those primitives under
/// different flags and stay in the host corpus.
const TAPROOT_KATS: [TaprootKat; 2] = [
    TaprootKat {
        input_index: 0,
        merkle_root: None,
        sighash_type: 3, // SIGHASH_SINGLE
        internal_privkey: "6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa",
        sighash: "2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555",
        signature: "ed7c1647cb97379e76892be0cacff57ec4a7102aa24296ca39af7541246d8ff1\
                    4d38958d4cc1e2e478e4d4a764bbfd835b16d4e314b72937b29833060b87276c03",
    },
    TaprootKat {
        input_index: 4,
        merkle_root: Some("ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2"),
        sighash_type: 0, // SIGHASH_DEFAULT
        internal_privkey: "f36bb07a11e469ce941d16b63b11b9b9120a84d9d87cff2c84a8d4affb438f4e",
        sighash: "4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef",
        signature: "b4010dd48a617db09926f729e79c33ae0b4e94b79f04a1ae93ede6315eb3669d\
                    e185a17d2b0ac9ee09fd4c64b678a0b61a0a86fa888a273c8511be83bfd6810f",
    },
];

/// A digest whose stock RFC6979 nonce yields a HIGH R, so reproducing the pinned bytes
/// takes two grind rounds and a build that quietly called `sign_ecdsa` cannot pass.
///
/// Key and message family are Bitcoin Core's own low-R corpus (`src/test/key_tests.cpp`,
/// `key_signature_tests`, digest = SHA256d of "A message to be signed0"); Core asserts
/// only a length property over them, so the expected bytes come from the independent
/// RFC 6979 implementation described in `tests/signing_vectors.rs`.
const LOW_R_PRIVKEY: &str = "12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747";
const LOW_R_DIGEST: &str = "e34e812f4c659156ac2279b92c22a53c9822ac10396fe8da12a2fcfef8813566";
const LOW_R_SIGNATURE: &str =
    "3044022068663052e6c29c7ed7ab02a68852301508503e7986b9754ec3e868772f2bf739\
     022028c6a35b2e90250d3179f96c2bb6b772e889e9a133a5156564a6965a8caa2b26";

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
            // The signing checks start from their vectors' own keys, not from anything a
            // previous check computed, for the same reason: one fault, one failing line.
            Check {
                name: "derive path",
                passed: check_derive_path(
                    &SEED_EXPECTED,
                    DERIVE_PATH,
                    DERIVE_PATH_FINGERPRINT,
                    DERIVE_PATH_PUBKEY,
                ),
            },
            Check {
                name: "sign p2wpkh",
                passed: check_segwit_v0(&SEGWIT_V0_KATS[0]),
            },
            Check {
                name: "sign p2sh-wpkh",
                passed: check_segwit_v0(&SEGWIT_V0_KATS[1]),
            },
            Check {
                name: "sign p2tr",
                passed: check_taproot(&TAPROOT_KATS),
            },
            Check {
                name: "low-r grind",
                passed: check_low_r(LOW_R_PRIVKEY, LOW_R_DIGEST, LOW_R_SIGNATURE),
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

// ---------------------------------------------------------------------------------------
// Signing checks (0.2.0-m2)
//
// Every one of these is written so that a malformed constant, a refused digest or an
// out-of-range scalar is a `false`, never an unwrap: the failure discipline at the top of
// this module applies to the new checks exactly as it does to the old ones, and these
// parse considerably more structure than the old ones do.
// ---------------------------------------------------------------------------------------

/// A signing key from a hex scalar, or `None` if the constant is malformed.
fn vector_key(privkey_hex: &str) -> Option<SecretSigningKey> {
    let mut raw = [0u8; 32];
    hex_into(privkey_hex, &mut raw)?;
    SecretSigningKey::from_secret_bytes(&raw, Network::Bitcoin)
}

/// Decode lowercase hex into a fixed buffer. `None` on a wrong length or a non-hex byte.
///
/// Runtime rather than the `const fn` above because these constants are compared as hex
/// strings anyway; keeping one small decoder here avoids a second `hex::<N>` call site
/// for every vector.
fn hex_into(s: &str, out: &mut [u8]) -> Option<()> {
    if s.len() != out.len() * 2 {
        return None;
    }
    for (byte, pair) in out.iter_mut().zip(s.as_bytes().chunks_exact(2)) {
        let nibble = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(())
}

/// [`sign::derive_path`] over an arbitrary path must reach the same leaf the report path
/// reaches, and must report the seed's master fingerprint as the origin.
fn check_derive_path(
    seed: &[u8; 64],
    path: &str,
    want_fingerprint: &str,
    want_pubkey: &str,
) -> bool {
    let Ok(path) = path.parse() else {
        return false;
    };
    let Ok(key) = sign::derive_path(seed, Network::Bitcoin, &path) else {
        return false;
    };
    let Some((fingerprint, origin_path)) = key.origin() else {
        return false;
    };
    *origin_path == path
        && fingerprint.to_bytes().to_lower_hex_string() == want_fingerprint
        && key.public_key().to_bytes().to_lower_hex_string() == want_pubkey
}

/// BIP-143: the digest for one segwit v0 input, and the low-R ECDSA signature over it.
fn check_segwit_v0(kat: &SegwitV0Kat) -> bool {
    let Ok(tx) = deserialize_hex::<Transaction>(kat.unsigned_tx) else {
        return false;
    };
    let Ok(program) = ScriptBuf::from_hex(kat.program) else {
        return false;
    };
    let value = Amount::from_sat(kat.value_sat);
    let spend = if kat.wrapped {
        SpendKind::P2shP2wpkh {
            redeem_script: &program,
            value,
            sighash_type: EcdsaSighashType::All,
        }
    } else {
        SpendKind::P2wpkh {
            script_pubkey: &program,
            value,
            sighash_type: EcdsaSighashType::All,
        }
    };

    let mut cache = SighashCache::new(&tx);
    let Ok(hash) = spend.sign_hash(&mut cache, kat.input_index) else {
        return false;
    };
    if hash.to_byte_array().to_lower_hex_string() != kat.sighash {
        return false;
    }
    let Some(key) = vector_key(kat.privkey) else {
        return false;
    };
    let signature = key.sign(&hash);
    signature.serialize().to_lower_hex_string() == kat.signature && key.verify(&hash, &signature)
}

/// BIP-341: the key-path digest and the Schnorr signature over the tweaked key, for every
/// pinned vector against the one shared transaction.
fn check_taproot(kats: &[TaprootKat]) -> bool {
    let Ok(tx) = deserialize_hex::<Transaction>(TAPROOT_TX) else {
        return false;
    };
    let mut spent = Vec::with_capacity(TAPROOT_PREVOUTS.len());
    for (script, value_sat) in TAPROOT_PREVOUTS {
        let Ok(script_pubkey) = ScriptBuf::from_hex(script) else {
            return false;
        };
        spent.push(TxOut {
            value: Amount::from_sat(value_sat),
            script_pubkey,
        });
    }
    let prevouts = Prevouts::All(&spent);
    let mut cache = SighashCache::new(&tx);

    for kat in kats {
        let merkle_root = match kat.merkle_root {
            None => None,
            Some(hex) => {
                let mut raw = [0u8; 32];
                if hex_into(hex, &mut raw).is_none() {
                    return false;
                }
                Some(TapNodeHash::from_byte_array(raw))
            }
        };
        let Ok(sighash_type) = TapSighashType::from_consensus_u8(kat.sighash_type) else {
            return false;
        };
        let Ok(hash) = (SpendKind::P2trKeyPath {
            prevouts: &prevouts,
            merkle_root,
            sighash_type,
        })
        .sign_hash(&mut cache, kat.input_index) else {
            return false;
        };
        if hash.to_byte_array().to_lower_hex_string() != kat.sighash {
            return false;
        }
        let Some(key) = vector_key(kat.internal_privkey) else {
            return false;
        };
        let signature = key.sign(&hash);
        if signature.serialize().to_lower_hex_string() != kat.signature
            || !key.verify(&hash, &signature)
        {
            return false;
        }
    }
    true
}

/// Low-R grinding, on a digest whose ungrounded RFC6979 nonce gives a high R. The pinned
/// bytes are unreachable without the grind loop, so this is the one check on the device
/// that stands behind the 71-byte signature the fee display quotes.
fn check_low_r(privkey: &str, digest: &str, want_der: &str) -> bool {
    let mut raw = [0u8; 32];
    if hex_into(digest, &mut raw).is_none() {
        return false;
    }
    let Some(key) = vector_key(privkey) else {
        return false;
    };
    let hash = SignHash::SegwitV0 {
        hash: SegwitV0Sighash::from_byte_array(raw),
        sighash_type: EcdsaSighashType::All,
    };
    let signature = key.sign(&hash);
    let serialized = signature.serialize();
    // `serialize` appends the sighash byte; the vector is the DER body alone, and the
    // length bound is what the check is really asserting.
    serialized.len() <= sign::MAX_ECDSA_SIGNATURE_LEN
        && serialized.split_last().map(|(flag, der)| {
            *flag == EcdsaSighashType::All as u8 && der.to_lower_hex_string() == want_der
        }) == Some(true)
        && key.verify(&hash, &signature)
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
                "bip86 taproot",
                "derive path",
                "sign p2wpkh",
                "sign p2sh-wpkh",
                "sign p2tr",
                "low-r grind",
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

    // -----------------------------------------------------------------------------------
    // Signing checks (0.2.0-m2): one mutation test per check, so every new line on the
    // Verify screen is proven to be able to say `false`.
    // -----------------------------------------------------------------------------------

    /// The derivation check must fail on a doctored seed, a doctored path, and either
    /// half of its pinned expectation - a check that only ever returns `true` is worse
    /// than no check, because it takes up a line that reads as evidence.
    #[test]
    fn derive_path_check_catches_a_doctored_seed_path_or_constant() {
        assert!(check_derive_path(
            &SEED_EXPECTED,
            DERIVE_PATH,
            DERIVE_PATH_FINGERPRINT,
            DERIVE_PATH_PUBKEY
        ));

        let mut doctored = SEED_EXPECTED;
        doctored[0] ^= 0x01;
        assert!(!check_derive_path(
            &doctored,
            DERIVE_PATH,
            DERIVE_PATH_FINGERPRINT,
            DERIVE_PATH_PUBKEY
        ));

        // A neighbouring address index is the mutation that matters: it still derives, it
        // still has the right fingerprint, and only the public key tells the difference.
        assert!(!check_derive_path(
            &SEED_EXPECTED,
            "m/84'/0'/0'/0/1",
            DERIVE_PATH_FINGERPRINT,
            DERIVE_PATH_PUBKEY
        ));
        // ... and the change chain, which is the same shape of mistake with worse
        // consequences (a change address the user was never shown).
        assert!(!check_derive_path(
            &SEED_EXPECTED,
            "m/84'/0'/0'/1/0",
            DERIVE_PATH_FINGERPRINT,
            DERIVE_PATH_PUBKEY
        ));

        assert!(!check_derive_path(
            &SEED_EXPECTED,
            DERIVE_PATH,
            "00000000",
            DERIVE_PATH_PUBKEY
        ));
        assert!(!check_derive_path(
            &SEED_EXPECTED,
            DERIVE_PATH,
            DERIVE_PATH_FINGERPRINT,
            BIP84_ACCOUNT_XPUB
        ));
        assert!(!check_derive_path(
            &SEED_EXPECTED,
            "not a path",
            DERIVE_PATH_FINGERPRINT,
            DERIVE_PATH_PUBKEY
        ));
    }

    /// Both BIP-143 checks must catch damage to every field the digest or the signature
    /// depends on. The amount is called out separately because BIP-143 exists precisely
    /// so that the signature commits to it: a signer that ignored it would sign a
    /// transaction whose fee is whatever the coordinator claims.
    #[test]
    fn segwit_v0_checks_catch_each_kind_of_damage() {
        for kat in &SEGWIT_V0_KATS {
            assert!(check_segwit_v0(kat), "pinned vector must pass");

            let mut wrong_value = *kat;
            wrong_value.value_sat += 1;
            assert!(!check_segwit_v0(&wrong_value), "amount is not committed");

            let mut wrong_index = *kat;
            wrong_index.input_index += 1;
            assert!(!check_segwit_v0(&wrong_index));

            let mut wrong_program = *kat;
            wrong_program.program = "0014000000000000000000000000000000000000000f";
            assert!(!check_segwit_v0(&wrong_program));

            let mut wrong_key = *kat;
            wrong_key.privkey = LOW_R_PRIVKEY;
            assert!(!check_segwit_v0(&wrong_key));

            let mut wrong_sighash = *kat;
            wrong_sighash.sighash = LOW_R_DIGEST;
            assert!(!check_segwit_v0(&wrong_sighash));

            let mut wrong_signature = *kat;
            wrong_signature.signature = SEGWIT_V0_KATS[0].signature;
            wrong_signature.privkey = SEGWIT_V0_KATS[1].privkey;
            assert!(!check_segwit_v0(&wrong_signature));

            // Malformed constants are reported, not unwrapped.
            let mut malformed = *kat;
            malformed.unsigned_tx = "not hex";
            assert!(!check_segwit_v0(&malformed));
            let mut malformed = *kat;
            malformed.privkey = "00";
            assert!(!check_segwit_v0(&malformed));
        }
    }

    /// The taproot check must catch a missing tweak, an invented tweak, a swapped sighash
    /// flag and a swapped input. The first two are the whole reason the merkle root is
    /// carried on the digest: signing a rooted output with the bare key produces a
    /// signature that looks fine and cannot spend.
    #[test]
    fn taproot_check_catches_a_missing_or_invented_tweak() {
        assert!(check_taproot(&TAPROOT_KATS));
        let bare = TAPROOT_KATS[0];
        let rooted = TAPROOT_KATS[1];
        assert!(bare.merkle_root.is_none() && rooted.merkle_root.is_some());

        let mut untweaked = rooted;
        untweaked.merkle_root = None;
        assert!(!check_taproot(&[untweaked]), "the tweak is not applied");

        let mut invented = bare;
        invented.merkle_root = rooted.merkle_root;
        assert!(!check_taproot(&[invented]), "a tweak is applied that should not be");

        let mut wrong_flag = bare;
        wrong_flag.sighash_type = 1; // SIGHASH_ALL instead of SIGHASH_SINGLE
        assert!(!check_taproot(&[wrong_flag]));

        let mut bad_flag = bare;
        bad_flag.sighash_type = 0x04; // not a sighash type at all
        assert!(!check_taproot(&[bad_flag]));

        let mut wrong_input = bare;
        wrong_input.input_index = rooted.input_index;
        assert!(!check_taproot(&[wrong_input]));

        let mut wrong_key = bare;
        wrong_key.internal_privkey = rooted.internal_privkey;
        assert!(!check_taproot(&[wrong_key]));

        let mut malformed = bare;
        malformed.merkle_root = Some("beef");
        assert!(!check_taproot(&[malformed]));

        // One bad vector fails the whole check even when the other passes.
        assert!(!check_taproot(&[bare, untweaked]));
    }

    /// The low-R check must reject the signature the STOCK nonce produces for the same
    /// digest. That is the mutation that matters: it is exactly what a build that lost
    /// `sign_ecdsa_low_r` would compute, and no other check on the device would notice.
    #[test]
    fn low_r_check_rejects_the_stock_signature() {
        assert!(check_low_r(LOW_R_PRIVKEY, LOW_R_DIGEST, LOW_R_SIGNATURE));

        // The ungrounded RFC6979 signature for this key and digest, from the same
        // independent implementation as the pinned value (corpus `low_r.cases[0]`).
        const STOCK: &str = "30450221008ae148d1657bfc509ac7e118c5ead62d4bb3eed608ccad323959cf\
                             cf3cd70933022014f8c7d85638181cf7c00af0a08e03e25a74770d38e12cd4a7\
                             40661a9b5c2faa";
        assert_ne!(STOCK, LOW_R_SIGNATURE);
        assert!(!check_low_r(LOW_R_PRIVKEY, LOW_R_DIGEST, STOCK));

        // ... and the ordinary damage cases.
        assert!(!check_low_r(
            SEGWIT_V0_KATS[0].privkey,
            LOW_R_DIGEST,
            LOW_R_SIGNATURE
        ));
        assert!(!check_low_r(
            LOW_R_PRIVKEY,
            SEGWIT_V0_KATS[0].sighash,
            LOW_R_SIGNATURE
        ));
        assert!(!check_low_r(LOW_R_PRIVKEY, "not hex", LOW_R_SIGNATURE));
        assert!(!check_low_r("00", LOW_R_DIGEST, LOW_R_SIGNATURE));
    }

    /// The pinned signing constants must be the committed corpus, for the same
    /// anti-drift reason as the seed and dice constants above: this module holds a cheap
    /// copy of vectors whose provenance lives in `tests/vectors/signing_vectors.json`,
    /// and a copy nobody compares is a second source of truth.
    #[test]
    fn pinned_signing_constants_match_the_committed_corpus() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/signing_vectors.json"))
                .expect("vector file is valid JSON");

        for (kat, case) in SEGWIT_V0_KATS.iter().zip(doc["bip143"].as_array().unwrap()) {
            assert_eq!(kat.unsigned_tx, case["unsigned_tx"].as_str().unwrap());
            assert_eq!(kat.program, case["script"].as_str().unwrap());
            assert_eq!(kat.input_index as u64, case["input_index"].as_u64().unwrap());
            assert_eq!(kat.value_sat, case["value_sat"].as_u64().unwrap());
            assert_eq!(kat.privkey, case["privkey"].as_str().unwrap());
            assert_eq!(kat.sighash, case["sighash"].as_str().unwrap());
            assert_eq!(kat.signature, case["signature"].as_str().unwrap());
            assert_eq!(kat.wrapped, case["spend"].as_str().unwrap() == "p2sh_p2wpkh");
        }

        let keypath = &doc["bip341_keypath"];
        assert_eq!(TAPROOT_TX, keypath["unsigned_tx"].as_str().unwrap());
        for (pinned, spent) in TAPROOT_PREVOUTS
            .iter()
            .zip(keypath["utxos_spent"].as_array().unwrap())
        {
            assert_eq!(pinned.0, spent["script_pubkey"].as_str().unwrap());
            assert_eq!(pinned.1, spent["value_sat"].as_u64().unwrap());
        }
        // The two pinned taproot vectors are cases 0 and 3 of the corpus.
        for (kat, case) in TAPROOT_KATS
            .iter()
            .zip([&keypath["cases"][0], &keypath["cases"][3]])
        {
            assert_eq!(kat.input_index as u64, case["input_index"].as_u64().unwrap());
            assert_eq!(kat.merkle_root, case["merkle_root"].as_str());
            assert_eq!(kat.sighash_type as u64, case["hash_type"].as_u64().unwrap());
            assert_eq!(
                kat.internal_privkey,
                case["internal_privkey"].as_str().unwrap()
            );
            assert_eq!(kat.sighash, case["sighash"].as_str().unwrap());
            assert_eq!(kat.signature, case["signature"].as_str().unwrap());
        }

        let low_r = &doc["low_r"];
        assert_eq!(LOW_R_PRIVKEY, low_r["privkey"].as_str().unwrap());
        assert_eq!(LOW_R_DIGEST, low_r["cases"][0]["digest"].as_str().unwrap());
        assert_eq!(
            LOW_R_SIGNATURE,
            low_r["cases"][0]["low_r_der"].as_str().unwrap()
        );
        assert!(
            low_r["cases"][0]["grind_counter"].as_u64().unwrap() > 0,
            "the boot vector no longer needs grinding, so it no longer proves low-R"
        );
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
