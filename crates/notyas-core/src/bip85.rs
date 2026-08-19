// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! BIP-85 deterministic entropy (0.2.0-G7): child secrets that are a FUNCTION of the
//! master seed instead of secrets of their own.
//!
//! <https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki> is normative for this
//! module the way `docs/SPEC.md` is for the dice pipeline. Every published vector in that
//! document that covers an application implemented here is pinned verbatim below, with
//! the section it came from named beside it.
//!
//! The whole scheme is two lines of arithmetic:
//!
//! ```text
//!   k       = the BIP32 private key at a fully hardened path under the master root
//!   entropy = HMAC-SHA512(key = "bip-entropy-from-k", msg = k)          // 64 bytes
//! ```
//!
//! and each application slices those 64 bytes its own way. So [`entropy()`] is the
//! module's primitive and the applications are thin wrappers on it: `39h` for a child
//! mnemonic ([`bip39_mnemonic`]) and `32h` for a child BIP-32 root ([`xprv`]), which are
//! the two BACKUP-FEATURES.md section 4.2 puts in 0.2.0.
//!
//! # Why it is in this release
//!
//! A duress wallet has to come from somewhere. An independently generated duress secret
//! means the device holds a SECOND secret that the owner's seed backup does not cover,
//! and 0.2.0 deferred encrypted backup entirely (OPEN-QUESTIONS Q14) - so switching
//! duress on would quietly create an unrecoverable wallet, and every later "restore from
//! your twelve words" would silently be missing it. A BIP-85 child cannot fail that way:
//! it is recomputable from the master seed forever, so the master backup already covers
//! it and the duress slot needs to persist a path rather than a key. Removing that
//! failure class is the reason this module exists; being what Coldcard's duress wallets
//! are built on (COMPETITIVE.md G7) is a consequence, not the argument.
//!
//! # What a child is, and what it costs
//!
//! A child is a full-power seed, not a lesser one, and the relationship runs one way
//! (BACKUP-FEATURES.md section 4.3):
//!
//! - the child is backed up by the parent's backup and by NOTHING else;
//! - there is no way back from a child to the parent, by construction - that is what the
//!   HMAC step is for;
//! - the parent's passphrase is part of the parent's seed, so re-deriving a child needs
//!   the same passphrase as well as the same words;
//! - a child shown or stored without its path is unreproducible. Whatever displays or
//!   persists one has to carry the application, the index and the parent fingerprint
//!   with it.
//!
//! # What this module does not do
//!
//! Derivation only. No storage, no display, no export, no policy. In particular it holds
//! no opinion about duress: it cannot tell whether the seed it was handed is the owner's
//! real seed or a decoy, and it must not be given the ability, because when a duress
//! wallet is used is a storage and UI question (OPEN-QUESTIONS Q2, MILESTONES m13) and
//! answering it here would bury that decision inside a pure function where no test can
//! see it.
//!
//! Nothing here reads an RNG (SECURITY.md invariant 3) and nothing can: the output is a
//! pure function of the seed and the path.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use bitcoin::bip32::{ChainCode, ChildNumber, DerivationPath, Fingerprint, Xpriv};
use bitcoin::secp256k1::SecretKey;
use bitcoin::Network;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

use crate::bip39::{Mnemonic, WordCount};
use crate::derive::{master, secp, xprv_string, ChildIndex, SecretXpriv};

/// First path element of every BIP-85 derivation, from the BIP's "Applications" section.
/// Public so that a policy check elsewhere can recognize a BIP-85 path rather than
/// restate the constant.
pub const PURPOSE: u32 = 83696968;

/// Application number of the BIP-39 application,
/// `m/83696968h/39h/{language}h/{words}h/{index}h`.
pub const APP_BIP39: u32 = 39;

/// Application number of the XPRV application, `m/83696968h/32h/{index}h`.
pub const APP_XPRV: u32 = 32;

/// The BIP-39 application's language element. Only English is offered, because the
/// language is not merely a path element: it selects the wordlist the entropy is rendered
/// through, and this crate embeds exactly one ([`crate::bip39::wordlist`]). Deriving under
/// another language code would produce a child this device could compute but not spell.
pub const LANGUAGE_ENGLISH: u32 = 0;

/// The HMAC key of the BIP's "Specification" section, verbatim. A fixed ASCII string, not
/// a secret: the secrecy is entirely in `k`.
const HMAC_KEY: &[u8] = b"bip-entropy-from-k";

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

/// Why a child could not be derived.
///
/// Both variants are astronomically unlikely rather than impossible, and both are errors
/// rather than panics for the reason [`crate::sign::SignError`] gives: a path can arrive
/// from outside this crate, and nothing outside this crate should be able to abort the
/// device.
#[derive(Debug)]
pub enum Bip85Error {
    /// BIP32 refused a step of the path: a child scalar at or above the curve order, or a
    /// depth past 255.
    Derivation(bitcoin::bip32::Error),
    /// The XPRV application's second 32 bytes were not a valid secp256k1 scalar (zero, or
    /// at/above the curve order). The BIP's footnote on this case requires a hard failure
    /// so the user moves to the next index rather than being handed a mangled key; the
    /// index is carried so a caller can say which one to skip.
    InvalidChildKey { index: u32 },
}

impl fmt::Display for Bip85Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bip85Error::Derivation(e) => write!(f, "BIP32 derivation failed: {e}"),
            Bip85Error::InvalidChildKey { index } => write!(
                f,
                "BIP-85 index {index} produced an invalid secp256k1 key (chance below 1 \
                 in 2^127); use the next index"
            ),
        }
    }
}

impl core::error::Error for Bip85Error {}

// ---------------------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------------------

/// The path of a BIP-39 child: `m/83696968h/39h/0h/{words}h/{index}h`.
///
/// Public because a child displayed or stored without its path is unreproducible
/// (BACKUP-FEATURES.md 4.3), so the UI and the wallet slot need the path this module
/// actually derived under rather than a second, hand-written copy of it. Rust-bitcoin
/// renders a [`DerivationPath`] without the leading `m/`; callers that show one to a user
/// add it.
pub fn bip39_path(words: WordCount, index: ChildIndex) -> DerivationPath {
    hardened(&[
        PURPOSE,
        APP_BIP39,
        LANGUAGE_ENGLISH,
        words.get() as u32,
        index.get(),
    ])
}

/// The path of an XPRV child: `m/83696968h/32h/{index}h`.
pub fn xprv_path(index: ChildIndex) -> DerivationPath {
    hardened(&[PURPOSE, APP_XPRV, index.get()])
}

/// Build a fully hardened path.
///
/// The `expect` is discharged by the callers rather than by hope: every element passed in
/// is either a constant below 2^31 or comes from a [`ChildIndex`] or a [`WordCount`],
/// whose constructors are the crate's only statement of those bounds. A caller that could
/// pass an arbitrary `u32` would have to be given a fallible signature instead.
fn hardened(elements: &[u32]) -> DerivationPath {
    elements
        .iter()
        .map(|&e| {
            ChildNumber::from_hardened_idx(e).expect("BIP-85 path elements are all below 2^31")
        })
        .collect::<Vec<ChildNumber>>()
        .into()
}

// ---------------------------------------------------------------------------------------
// The primitive
// ---------------------------------------------------------------------------------------

/// The 64 bytes of BIP-85 entropy at `path`, from the BIP's "Specification" section.
///
/// This is every application's input, and the applications below are slicing rules over
/// it. Public so that an application this module does not implement (the hex and password
/// ones, BACKUP-FEATURES.md 4.2) can be built without reopening this file.
///
/// `path` should be fully hardened, as the BIP requires. That is not enforced here, for
/// the reason the BIP itself gives in the footnote to that section: hardening cannot be
/// enforced at this layer, which is exactly why the HMAC step exists - it hardens the
/// entropy after the fact, so a compromised child cannot be walked back up the tree even
/// if a caller derived it through a normal step. Every path this module builds is
/// hardened throughout.
pub fn entropy(seed: &[u8; 64], path: &DerivationPath) -> Result<Zeroizing<[u8; 64]>, Bip85Error> {
    // Network::Bitcoin rather than a parameter: `Xpriv::new_master` takes a network only
    // to choose a serialization prefix, and that prefix reaches neither the key, the chain
    // code nor the HMAC. BIP-85 output is therefore identical on every network, and an
    // argument that cannot change the answer would be an invitation to believe it does.
    let root = master(seed, Network::Bitcoin);
    entropy_at(root.key(), path)
}

/// [`entropy()`] from an already-built root key.
///
/// Split out because the BIP states its vectors as a root xprv, so the tests have to be
/// able to start there, while the device only ever holds a seed and must not be handed an
/// `Xpriv` that nothing wipes.
fn entropy_at(root: &Xpriv, path: &DerivationPath) -> Result<Zeroizing<[u8; 64]>, Bip85Error> {
    let child = SecretXpriv::new(
        root.derive_priv(secp(), path)
            .map_err(Bip85Error::Derivation)?,
    );
    // `k` is the HMAC message, and it is the one intermediate here worth as much as the
    // master seed: it is a spendable key in its own right on the parent's tree.
    let k = Zeroizing::new(child.key().private_key.secret_bytes());

    let mut mac =
        Hmac::<Sha512>::new_from_slice(HMAC_KEY).expect("HMAC-SHA512 takes a key of any length");
    mac.update(&*k);
    let mut tag = mac.finalize().into_bytes();

    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&tag);
    // These 64 bytes are the child seed in every application below, so the copy the MAC
    // hands back is wiped instead of being left in this frame; `out` carries the only
    // live copy out.
    tag.zeroize();
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// Application 39h: a child mnemonic
// ---------------------------------------------------------------------------------------

/// The BIP-39 child mnemonic at `words` and `index`, English.
///
/// This is the application a derived duress wallet is built from: the child IS its
/// mnemonic, and the child's own BIP-39 seed is `bip39::seed(&child.phrase(), "")` - taken
/// by the caller, because whether a child carries a passphrase of its own is a wallet
/// decision and not this module's.
///
/// Per the BIP's BIP39 section the entropy is the LEADING 128/160/192/224/256 bits of the
/// 64-byte digest for 12/15/18/21/24 words; the trailing bytes are discarded.
pub fn bip39_mnemonic(
    seed: &[u8; 64],
    words: WordCount,
    index: ChildIndex,
) -> Result<Mnemonic, Bip85Error> {
    let root = master(seed, Network::Bitcoin);
    bip39_mnemonic_at(root.key(), words, index)
}

fn bip39_mnemonic_at(
    root: &Xpriv,
    words: WordCount,
    index: ChildIndex,
) -> Result<Mnemonic, Bip85Error> {
    let digest = entropy_at(root, &bip39_path(words, index))?;
    // ENT is 32 bits per three words, so the byte count is words/3*4 - exact for every
    // count `WordCount` admits, which is why no rounding case appears here.
    let bytes = words.get() / 3 * 4;
    Ok(mnemonic_from_entropy(digest[..bytes].to_vec()))
}

/// BIP-39 encoding of `entropy`, delegated to [`crate::bip39`].
///
/// This was briefly a duplicate of bip39's encoder, because that function was private and
/// a BIP-85 child is DEFINED as a mnemonic - stopping at raw entropy would leave every
/// caller unable to use the result. Two copies of a word encoding is the wrong shape for
/// this: they can drift apart silently and yield a phrase that checksums correctly but is
/// not the child the path names, which no test looking at one copy would catch. The
/// function is now `pub(crate)` and this calls it.
///
/// The delegation is proven equivalent by evidence, not by inspection: the published
/// BIP-85 mnemonics for 12, 18 and 24 words are pinned verbatim in this module's tests and
/// they passed before this change and after it.
///
/// The `expect` cannot fire: [`WordCount`] admits only 128..=256 bits in 32-bit steps, and
/// bip39's encoder rejects only ENT that is zero, not a multiple of 32, or above its
/// ceiling. A panic here would mean WordCount had been widened without revisiting this.
fn mnemonic_from_entropy(entropy: Vec<u8>) -> Mnemonic {
    let ent = entropy.len() * 8;
    debug_assert!(
        (128..=256).contains(&ent) && ent % 32 == 0,
        "BIP-85 BIP-39 entropy is 16, 20, 24, 28 or 32 bytes, got {ent} bits"
    );
    crate::bip39::mnemonic_from_entropy(entropy)
        .expect("WordCount admits only ENT that bip39's encoder accepts")
}

// ---------------------------------------------------------------------------------------
// Application 32h: a child BIP-32 root
// ---------------------------------------------------------------------------------------

/// The child extended private key at `index`, serialized for `network`.
///
/// Per the BIP's XPRV section the digest is read in the OPPOSITE order to BIP-32: the
/// FIRST 32 bytes are the chain code and the SECOND 32 are the private key. Depth, child
/// number and parent fingerprint are forced to zero, which is what makes the result a root
/// in its own right rather than a node that remembers where it came from.
///
/// Returned as a wiped string rather than an `Xpriv` for the reason
/// [`crate::derive::AccountKeys`] renders its keys as strings: rust-bitcoin gives `Xpriv`
/// no `Drop`, so a returned value would leave an unwiped copy of a spending key in freed
/// memory however careful the caller was. `Zeroizing<String>` derefs to `String`, and a
/// caller that needs the key rather than the rendering parses it back inside its own
/// wiping wrapper.
pub fn xprv(
    seed: &[u8; 64],
    network: Network,
    index: ChildIndex,
) -> Result<Zeroizing<String>, Bip85Error> {
    let root = master(seed, network);
    xprv_at(root.key(), index)
}

fn xprv_at(root: &Xpriv, index: ChildIndex) -> Result<Zeroizing<String>, Bip85Error> {
    let digest = entropy_at(root, &xprv_path(index))?;
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&digest[..32]);

    let child = SecretXpriv::new(Xpriv {
        // The child inherits the parent's network kind, which is what makes the BIP's rule
        // "emit TPRV if and only if the input root key is a Testnet key" fall out instead
        // of needing to be stated a second time.
        network: root.network,
        depth: 0,
        parent_fingerprint: Fingerprint::default(),
        child_number: ChildNumber::from_normal_idx(0).expect("0 is a valid normal index"),
        private_key: SecretKey::from_slice(&digest[32..])
            .map_err(|_| Bip85Error::InvalidChildKey { index: index.get() })?,
        chain_code: ChainCode::from(chain_code),
    });
    // Rendered through the crate's own encoder and NOT through `Xpriv`'s `Display`.
    // `Display` goes to base58ck's `encode_check_to_fmt`, which grows a `String` from empty
    // one character at a time and accumulates its digits in a hundred-element `SmallVec`
    // that spills to a `Vec` past digit 100 - an xprv is 111 digits - and drops both
    // unwiped. `Zeroizing` owns only the buffer it is handed, so it reaches none of them,
    // and what they hold is a spending key for the whole derived wallet. See
    // `derive::base58check_secret`, and `tests/key_material_residue.rs`, which fails if
    // this line goes back to `to_string()`.
    Ok(Zeroizing::new(xprv_string(child.key().encode())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip39::{check_phrase, Checksum};
    use core::str::FromStr;

    /// Every vector in BIP-85 uses this one root key: it is the "MASTER BIP32 ROOT KEY"
    /// line of every INPUT block in
    /// <https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki>.
    const ROOT: &str = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";

    fn root() -> Xpriv {
        Xpriv::from_str(ROOT).unwrap()
    }

    fn path(s: &str) -> DerivationPath {
        DerivationPath::from_str(s).unwrap()
    }

    fn index(i: u32) -> ChildIndex {
        ChildIndex::new(i).unwrap()
    }

    fn count(w: usize) -> WordCount {
        WordCount::new(w).unwrap()
    }

    /// BIP-85, "Test vectors": test case 1 and test case 2.
    ///
    /// Both halves of each case are pinned. Checking the derived key `k` before the HMAC
    /// is what makes a wrong path distinguishable from a wrong HMAC when one of these
    /// ever fails.
    #[test]
    fn specification_test_vectors() {
        let cases = [
            (
                "m/83696968'/0'/0'",
                "cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0",
                "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f0\
                 0b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7",
            ),
            (
                "m/83696968'/0'/1'",
                "503776919131758bb7de7beb6c0ae24894f4ec042c26032890c29359216e21ba",
                "70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872\
                 218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e",
            ),
        ];
        for (p, derived_key, derived_entropy) in cases {
            let at = path(p);
            let k = root().derive_priv(secp(), &at).unwrap().private_key;
            assert_eq!(hex::encode(k.secret_bytes()), derived_key, "k at {p}");
            assert_eq!(
                hex::encode(*entropy_at(&root(), &at).unwrap()),
                derived_entropy,
                "entropy at {p}"
            );
        }
    }

    /// BIP-85, "BIP39" application: the 12, 18 and 24 English word vectors.
    ///
    /// The BIP publishes no 15 or 21 word vector, so those two counts are covered by
    /// `every_word_count_round_trips` below and by nothing stronger. Said out loud because
    /// the difference matters: three of the five counts are pinned to the standard and two
    /// are only self-consistent.
    #[test]
    fn bip39_application_vectors() {
        let cases = [
            (
                12,
                "m/83696968'/39'/0'/12'/0'",
                "6250b68daf746d12a24d58b4787a714b",
                "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose",
            ),
            (
                18,
                "m/83696968'/39'/0'/18'/0'",
                "938033ed8b12698449d4bbca3c853c66b293ea1b1ce9d9dc",
                "near account window bike charge season chef number sketch tomorrow \
                 excuse sniff circle vital hockey outdoor supply token",
            ),
            (
                24,
                "m/83696968'/39'/0'/24'/0'",
                "ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f",
                "puppy ocean match cereal symbol another shed magic wrap hammer bulb \
                 intact gadget divorce twin tonight reason outdoor destroy simple truth \
                 cigar social volcano",
            ),
        ];
        for (words, p, derived_entropy, mnemonic) in cases {
            let words = count(words);
            // The path is a vector too: a child without it is unreproducible.
            assert_eq!(
                format!("m/{}", bip39_path(words, ChildIndex::ZERO)),
                p,
                "path for {words} words"
            );
            let child = bip39_mnemonic_at(&root(), words, ChildIndex::ZERO).unwrap();
            assert_eq!(
                hex::encode(&child.entropy),
                derived_entropy,
                "{words} words"
            );
            assert_eq!(*child.phrase(), mnemonic, "{words} words");
        }
    }

    /// Every mnemonic this module encodes decodes back through the crate's OTHER
    /// implementation of BIP-39, which is what stops this module's private encoder from
    /// drifting away from `bip39`'s.
    #[test]
    fn every_word_count_round_trips() {
        for words in [12, 15, 18, 21, 24] {
            let words = count(words);
            let child = bip39_mnemonic_at(&root(), words, index(7)).unwrap();
            let check = check_phrase(&child.phrase());
            assert_eq!(check.word_count, words.get(), "{words} words");
            assert_eq!(check.checksum, Checksum::Valid, "{words} words");
            assert_eq!(check.entropy, child.entropy, "{words} words");
            assert_eq!(child.entropy.len(), words.get() / 3 * 4, "{words} words");
        }
    }

    /// BIP-85, "XPRV" application (application number 32'), which BACKUP-FEATURES.md
    /// section 4.2 puts in 0.2.0 alongside 39'.
    #[test]
    fn xprv_application_vector() {
        assert_eq!(
            format!("m/{}", xprv_path(ChildIndex::ZERO)),
            "m/83696968'/32'/0'"
        );
        // The vector's DERIVED ENTROPY line is the SECOND half of the 64-byte digest -
        // the private key - not the first half and not the whole digest, which is what
        // the same label means in every other vector in the BIP (the HD-Seed WIF case
        // below is the first half, and the HEX case is all 64 bytes). Pinned where it
        // actually lands rather than where the label suggests, because the vector's
        // authoritative output is the DERIVED XPRV asserted immediately after it, and
        // that one matches byte for byte.
        assert_eq!(
            hex::encode(&entropy_at(&root(), &xprv_path(ChildIndex::ZERO)).unwrap()[32..]),
            "ead0b33988a616cf6a497f1c169d9e92562604e38305ccd3fc96f2252c177682"
        );
        assert_eq!(
            *xprv_at(&root(), ChildIndex::ZERO).unwrap(),
            "xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMmoZUurYuBuYG46c6P71UGXMzmriLzCCBvKQWBUv3vPB3m1SATMhp3uEjXHJ42jFg7myX"
        );
    }

    /// BIP-85, "HEX" application (128169'): the 64-byte vector, which pins the whole
    /// digest rather than a truncation of it.
    ///
    /// The application itself is not implemented (BACKUP-FEATURES.md 4.2 defers it to
    /// 0.2.x); its vector is used here because a full-width pin of [`entropy()`] at a
    /// four-element path is worth having whether or not that slicing rule ever ships.
    #[test]
    fn hex_application_vector_pins_the_full_digest() {
        assert_eq!(
            hex::encode(*entropy_at(&root(), &path("m/83696968'/128169'/64'/0'")).unwrap()),
            "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f8785\
             55d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c"
        );
    }

    /// BIP-85, "HD-Seed WIF" application (2'), entropy half only.
    ///
    /// The application is rejected for notyas (BACKUP-FEATURES.md 4.2, B13), so only the
    /// derivation is pinned: it is a free extra path shape under the same primitive.
    #[test]
    fn hd_seed_wif_application_entropy() {
        assert_eq!(
            hex::encode(&entropy_at(&root(), &path("m/83696968'/2'/0'")).unwrap()[..32]),
            "7040bb53104f27367f317558e78a994ada7296c6fde36a364e5baf206e502bb1"
        );
    }

    /// The seed-taking public API and the root-taking internals are the same function.
    ///
    /// The BIP states its vectors as a root key, so without this the public entry points -
    /// the only ones the device calls - would be pinned to nothing.
    #[test]
    fn public_entry_points_match_the_vector_path() {
        // BIP-39 English vector 1 (the all-zero entropy phrase) and the seed it produces
        // with passphrase "TREZOR", from
        // <https://github.com/trezor/python-mnemonic/blob/master/vectors.json>.
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon about";
        let seed = crate::bip39::seed(phrase, "TREZOR");
        assert_eq!(
            hex::encode(*seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );

        let root = Xpriv::new_master(Network::Bitcoin, &seed[..]).unwrap();
        let words = count(24);
        assert_eq!(
            *bip39_mnemonic(&seed, words, index(3)).unwrap().phrase(),
            *bip39_mnemonic_at(&root, words, index(3)).unwrap().phrase()
        );
        assert_eq!(
            *xprv(&seed, Network::Bitcoin, index(3)).unwrap(),
            *xprv_at(&root, index(3)).unwrap()
        );
        assert_eq!(
            hex::encode(*entropy(&seed, &bip39_path(words, index(3))).unwrap()),
            hex::encode(*entropy_at(&root, &bip39_path(words, index(3))).unwrap())
        );
    }

    /// The network reaches the serialization and nothing else: a child mnemonic is the
    /// same on every network, which is why [`bip39_mnemonic`] does not take one.
    #[test]
    fn network_changes_the_prefix_and_not_the_child() {
        let seed = [7u8; 64];
        let mainnet = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
        let testnet = Xpriv::new_master(Network::Testnet, &seed).unwrap();
        let words = count(12);
        assert_eq!(
            *bip39_mnemonic_at(&mainnet, words, ChildIndex::ZERO)
                .unwrap()
                .phrase(),
            *bip39_mnemonic_at(&testnet, words, ChildIndex::ZERO)
                .unwrap()
                .phrase()
        );
        assert!(xprv_at(&testnet, ChildIndex::ZERO)
            .unwrap()
            .starts_with("tprv"));
        assert!(xprv_at(&mainnet, ChildIndex::ZERO)
            .unwrap()
            .starts_with("xprv"));
    }

    /// Distinct indices and distinct word counts are distinct children. Cheap, and it is
    /// the property a duress slot rests on: index 0 is not index 1.
    #[test]
    fn children_are_distinct() {
        let words = count(12);
        let a = bip39_mnemonic_at(&root(), words, ChildIndex::ZERO).unwrap();
        let b = bip39_mnemonic_at(&root(), words, index(1)).unwrap();
        let c = bip39_mnemonic_at(&root(), count(24), ChildIndex::ZERO).unwrap();
        assert_ne!(a.entropy, b.entropy);
        assert_ne!(a.entropy, c.entropy[..a.entropy.len()].to_vec());
    }

    /// The largest index the type admits still builds a hardened path and derives.
    #[test]
    fn maximum_index_derives() {
        let top = index(ChildIndex::MAX);
        assert_eq!(
            format!("m/{}", bip39_path(count(12), top)),
            "m/83696968'/39'/0'/12'/2147483647'"
        );
        assert!(bip39_mnemonic_at(&root(), count(12), top).is_ok());
    }
}
