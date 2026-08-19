// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Wallet health check (0.2.0-G11): re-derive one address a wallet was saved with, compare
//! it, and produce no signature.
//!
//! The standing "prove this wallet is still intact" action on the wallet-detail screen
//! (UX-PATTERNS.md 4, Nunchuk's pattern). It is for the day BEFORE an emergency: a user who
//! has not touched a wallet in a year wants to know the device still holds it, and the only
//! honest way to answer without spending anything is to derive an address again and compare
//! it against the one that was recorded when the wallet was saved.
//!
//! ```text
//!   seed + wallet         -> derive one leaf again
//!   that leaf's address   -> compare to the address STORAGE holds
//!                         -> [`Pass`], or the one named [`Failure`]
//! ```
//!
//! # What a pass proves, and what it does not
//!
//! [`PASS_MEANS`] is that sentence, in the words the screen has to print. In full:
//!
//! - It proves the key material this device unlocked still derives the address this wallet
//!   was saved with. For a singlesig wallet the address is a function of the seed alone, so
//!   one comparison covers the whole chain from seed to script. For a multisig wallet the
//!   address is a function of the REGISTERED cosigner xpubs and not of the seed, so the
//!   comparison proves the stored registration is unchanged, and a second comparison - the
//!   one [`Pending::verify`](crate::multisig::Pending::verify) made at import time, run
//!   again here - proves this seed is still the member it was recorded as.
//! - It proves nothing about the device. A health check runs on the firmware it is asking
//!   about, so a device that has been replaced or reflashed passes it exactly as easily as
//!   an honest one: the answer it gives is about key material, and firmware integrity is
//!   what VERIFY.md's S-46 and reproducible builds are for. Saying otherwise would import
//!   the credibility of a claim this device cannot make (COMPETITIVE.md 9.9).
//! - It proves nothing about any leaf it was not asked about, and nothing about a
//!   passphrase that was not supplied: a different passphrase is a different wallet, and
//!   this check will say so by failing.
//!
//! # The expected address has to come from storage
//!
//! [`Expectation::address`] is the address the wallet record holds, written when the wallet
//! was saved. It must never be recomputed from the same seed and handed straight back in:
//! a comparison of a derivation against itself passes on every device, in every state, and
//! would turn this screen into a control that cannot fail.
//!
//! That is also why [`Wallet::Singlesig`] names a scheme and an account index rather than
//! carrying a [`SinglesigAccount`](crate::address::SinglesigAccount) the caller already
//! holds. An account value is an xpub, and an xpub is exactly the thing whose loss this
//! check is supposed to detect - accepting one would let the caller prove a watch-only
//! record consistent with itself while the seed behind it was gone. So the seed is the only
//! account source here, and the multisig arm's registration is admitted only because its
//! own half is re-derived from the seed too.
//!
//! # No signature, and no second unlock
//!
//! Nothing in this module constructs a signing key: it reaches [`crate::derive`] for an
//! account node and [`crate::address`] for the rendering, and imports nothing from
//! [`crate::sign`]. The account node's private rendering exists for the length of one
//! [`crate::derive::derive`] call and [`crate::derive::AccountKeys`] wipes it on drop;
//! nothing that could sign is ever built, so there is no transaction, no digest and no
//! signature for this action to leak.
//!
//! The one secret it takes is the 64-byte seed the caller already unlocked. It asks for no
//! further authority, which is what makes it safe to leave on a wallet-detail screen as a
//! one-tap action rather than behind the PIN ladder a spend goes through.
//!
//! # Vectors
//!
//! The singlesig path is pinned to BIP-84's own published address for the ABANDON mnemonic
//! in the tests below. The multisig path cannot be: a registration exists only for a wallet
//! this device is a member of, and nobody holds BIP-129's seeds, so its published address
//! is pinned through `multisig::sorted_multi_witness_script` in `tests/multisig_vectors.rs`
//! and this module rides on the same script assembler through
//! [`crate::address::AddressSource`].

use core::fmt;
use core::str::FromStr;

use alloc::vec::Vec;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::{Address, Network};

use crate::address::{AddressEntry, AddressSource, Keychain, SinglesigAccount};
use crate::derive::{self, ChildIndex, Scheme};
use crate::multisig::Registration;

/// The sentence a pass has to be shown with.
///
/// A constant rather than UI copy because the boundary it draws is the whole value of the
/// feature: a health check that a user reads as "this device is fine" is worse than no
/// health check, and the wording that keeps that from happening must not be re-invented per
/// screen. One ASCII line, no trailing period, in the shape every refusal in
/// [`crate::address`] is written in.
pub const PASS_MEANS: &str = "this proves the key material still derives this wallet's \
                              address; it does not prove the device or its firmware is \
                              honest";

/// Which wallet is being checked, in the terms it has to be RE-DERIVED from.
///
/// Deliberately not an [`AddressSource`]: see the module docs. The singlesig arm names the
/// path to walk, and the multisig arm takes the stored registration because a registration
/// is a public record whose own half this module re-proves against the seed before it
/// believes any address the registration renders.
#[derive(Debug, Clone, Copy)]
pub enum Wallet<'a> {
    /// A singlesig account: `m/{purpose}'/{coin}'/{account}'`, the node
    /// [`crate::derive::derive`] builds.
    Singlesig { scheme: Scheme, account: ChildIndex },
    /// A multisig wallet this device proved it was a member of at import time.
    Multisig(&'a Registration),
}

/// What the wallet record says this wallet's address at one leaf is.
///
/// The three fields travel together because a check against an address without the leaf it
/// came from is not a check: this device would have to guess which index to derive, and a
/// guess that happened to match somewhere in a gap would report a pass for a wallet whose
/// recorded address had moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectation {
    pub keychain: Keychain,
    pub index: ChildIndex,
    /// The address as STORAGE holds it, from when the wallet was saved. Never a fresh
    /// derivation; see the module docs for why that distinction is the feature.
    pub address: Address,
}

/// Which of the two statements in the module docs a pass established.
///
/// Two variants because the two wallet kinds prove different things by different routes,
/// and a screen that printed one sentence for both would overclaim for multisig, where the
/// address alone is a fact about the stored registration rather than about the seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proof {
    /// Singlesig: the address is a function of the seed, so re-deriving it and matching is
    /// the whole statement.
    SeedDerivesTheAddress,
    /// Multisig: the seed still derives the account node this registration records as ours
    /// AND the registration still builds the recorded address at that leaf. Both ran; either
    /// one alone would be an answer to a question nobody asked.
    SeedIsAMemberAndTheWalletBuildsTheAddress,
}

/// A wallet that answered correctly, and the evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pass {
    /// The row this device just re-derived: the address, the derivation path of every key
    /// that has to sign at that leaf, and for multisig the witness script. The same
    /// [`AddressEntry`] the address explorer shows, so the user can compare what the check
    /// derived against what their coordinator shows without a second rendering path.
    pub entry: AddressEntry,
    /// The master fingerprint of the seed that was checked, recomputed here. What the user
    /// compares against the fingerprint their coordinator holds.
    pub fingerprint: Fingerprint,
    pub proof: Proof,
}

/// Why the check did not pass.
///
/// Two kinds, and [`Failure::is_broken`] is the only way to ask which: a wallet that
/// answered WRONG is the alarming screen this feature exists to raise, and a check that
/// could not run at all is a caller error that must not be dressed up as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The address this device derived is not the address the wallet was saved with.
    ///
    /// The finding. `derived` is carried so the screen can show both strings: a user
    /// comparing them can tell a passphrase they mistyped (a coherent address from another
    /// wallet) from key material that is gone (no address at all, which arrives as
    /// [`Failure::LeafDoesNotDerive`] instead).
    AddressMismatch { derived: Address },
    /// The seed is not the cosigner this registration records as ours: its master
    /// fingerprint is not the registered one.
    NotAMember { device: Fingerprint, wallet: Fingerprint },
    /// The fingerprint matched and the account node did not. Either a four-byte
    /// fingerprint collision or a registration that changed under storage; both mean this
    /// seed cannot sign for this wallet, which is the same statement
    /// `multisig::Refusal::XpubDoesNotDerive` makes at import time.
    ///
    /// Also the answer if a registration's own origin is not the four hardened levels
    /// `Pending::verify` demands, which no value of that type can be - it has no public
    /// constructor - and which is folded in here rather than given a variant a screen would
    /// have to carry copy for.
    KeyDoesNotDerive,
    /// [`Scheme::Bip48`] asked for through [`Wallet::Singlesig`]. A multisig leaf is not any
    /// single key's address; the wallet wanted is a [`Wallet::Multisig`].
    NoAddressesForScheme(Scheme),
    /// The recorded address belongs to the other chain. Refused rather than compared,
    /// because a mainnet and a test-chain address over the same key have the SAME
    /// scriptPubKey: comparing scripts would pass this, and a pass here would tell a user
    /// their mainnet wallet is intact on the strength of a testnet string.
    AddressNotForNetwork { wallet: Network },
    /// The registration is for another chain than the device was asked about.
    RegistrationNotForNetwork { registration: Network, device: Network },
    /// The leaf has no address: BIP-32's roughly 2^-128 non-derivable child. Not a finding
    /// about the wallet, and never to be shown as one.
    LeafDoesNotDerive,
}

impl Failure {
    /// Whether this is a wallet that answered wrong, as opposed to a check that could not
    /// run.
    ///
    /// Written as an exhaustive match rather than as a list of the alarming variants, so
    /// that a variant added later has to be classified here instead of silently defaulting
    /// into the loud screen or out of it.
    pub fn is_broken(&self) -> bool {
        match self {
            Failure::AddressMismatch { .. }
            | Failure::NotAMember { .. }
            | Failure::KeyDoesNotDerive => true,
            Failure::NoAddressesForScheme(_)
            | Failure::AddressNotForNetwork { .. }
            | Failure::RegistrationNotForNetwork { .. }
            | Failure::LeafDoesNotDerive => false,
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::AddressMismatch { derived } => write!(
                f,
                "this wallet now derives {derived}, which is not the address it was saved with"
            ),
            Failure::NotAMember { device, wallet } => write!(
                f,
                "this seed is {device} and the wallet records {wallet} as its own key"
            ),
            Failure::KeyDoesNotDerive => write!(
                f,
                "this seed does not derive the key this wallet was registered with"
            ),
            Failure::NoAddressesForScheme(scheme) => {
                write!(f, "{scheme} has no single-key addresses to check")
            }
            Failure::AddressNotForNetwork { wallet } => {
                write!(f, "the saved address is not an address on {wallet}")
            }
            Failure::RegistrationNotForNetwork {
                registration,
                device,
            } => write!(
                f,
                "this wallet is registered on {registration} and the device is on {device}"
            ),
            Failure::LeafDoesNotDerive => {
                write!(f, "this wallet has no address at that index")
            }
        }
    }
}

impl core::error::Error for Failure {}

/// Re-derive one leaf of `wallet` from `seed` and compare it against what was recorded.
///
/// Produces no signature and asks for no authority beyond the seed the caller already
/// unlocked. Pure: same inputs, same answer, on every device holding this wallet.
///
/// `network` is the DEVICE's network and is never read out of the expectation or the
/// registration; both are compared against it instead.
pub fn check(
    seed: &[u8; 64],
    network: Network,
    wallet: Wallet<'_>,
    expected: &Expectation,
) -> Result<Pass, Failure> {
    // Before anything is derived: a mainnet and a test-chain address over one key share a
    // scriptPubKey, so the comparison below cannot tell them apart and this is the only
    // place the chain can be checked at all.
    if !expected.address.as_unchecked().is_valid_for_network(network) {
        return Err(Failure::AddressNotForNetwork { wallet: network });
    }
    let fingerprint = derive::master_fingerprint(seed, network);

    match wallet {
        Wallet::Singlesig { scheme, account } => {
            // `count` is 0: this needs the account node and no address rows, and a row
            // carries a WIF. The account's own private rendering is wiped by `AccountKeys`
            // on drop and is never read here - `SinglesigAccount` takes the xpub.
            let derived = derive::derive(seed, network, scheme, account, ChildIndex::ZERO, 0, 0);
            let account = SinglesigAccount::new(scheme, network, &derived.account)
                .ok_or(Failure::NoAddressesForScheme(scheme))?;
            let entry = AddressSource::Singlesig(&account)
                .entry(expected.keychain, expected.index)
                .ok_or(Failure::LeafDoesNotDerive)?;
            compare(entry, expected, fingerprint, Proof::SeedDerivesTheAddress)
        }
        Wallet::Multisig(registration) => {
            if registration.network() != network {
                return Err(Failure::RegistrationNotForNetwork {
                    registration: registration.network(),
                    device: network,
                });
            }
            // The address a registration renders is a function of the cosigner xpubs and
            // not of the seed, so it would match even if this device's own key were gone.
            // This is the half that answers the question actually being asked.
            membership(seed, network, registration)?;
            let entry = AddressSource::Multisig(registration)
                .entry(expected.keychain, expected.index)
                .ok_or(Failure::LeafDoesNotDerive)?;
            compare(
                entry,
                expected,
                fingerprint,
                Proof::SeedIsAMemberAndTheWalletBuildsTheAddress,
            )
        }
    }
}

/// The comparison, by `scriptPubKey` and never by text.
///
/// Two renderings of one script are the same address - BIP-173 permits an uppercase form -
/// so a text comparison would report a mismatch for a wallet that is perfectly intact,
/// which is the most damaging false alarm this feature could raise. Same rule, and the same
/// reason, as [`crate::address::find`].
fn compare(
    entry: AddressEntry,
    expected: &Expectation,
    fingerprint: Fingerprint,
    proof: Proof,
) -> Result<Pass, Failure> {
    if entry.address.script_pubkey() != expected.address.script_pubkey() {
        return Err(Failure::AddressMismatch {
            derived: entry.address,
        });
    }
    Ok(Pass {
        entry,
        fingerprint,
        proof,
    })
}

/// Re-run the membership proof [`crate::multisig::Pending::verify`] made at import time:
/// the account node this seed derives at the origin the registration records is the node the
/// registration holds.
///
/// Compared at the ACCOUNT node rather than at the checked leaf, which is strictly the
/// stronger statement: two extended keys with the same public key and chain code derive
/// identical children at every index, so a match here is a match at every leaf of the
/// wallet and not only at the one the user happened to save.
///
/// Key material only, for the reason `verify` gives: depth, parent fingerprint and child
/// number are metadata some wallets zero on export, and demanding them would fail a wallet
/// this device really is a member of.
fn membership(
    seed: &[u8; 64],
    network: Network,
    registration: &Registration,
) -> Result<(), Failure> {
    let ours = registration.ours();
    let device = derive::master_fingerprint(seed, network);
    if ours.fingerprint != device {
        return Err(Failure::NotAMember {
            device,
            wallet: ours.fingerprint,
        });
    }
    let (account, script_type) = bip48_levels(&ours.origin).ok_or(Failure::KeyDoesNotDerive)?;
    // Purpose and coin type are not passed because they are not free: `derive` builds
    // m/48'/{coin}'/{account}'/{script_type}' from the scheme and the network, and
    // `Pending::verify` refused this registration unless its origin had purpose 48 and this
    // device's coin type. With the network checked by the caller, the node built here is the
    // node the origin names.
    let derived = derive::derive(
        seed,
        network,
        Scheme::Bip48,
        account,
        ChildIndex::ZERO,
        0,
        script_type,
    );
    let mine = Xpub::from_str(&derived.account.xpub).map_err(|_| Failure::KeyDoesNotDerive)?;
    if mine.public_key != ours.xpub.public_key || mine.chain_code != ours.xpub.chain_code {
        return Err(Failure::KeyDoesNotDerive);
    }
    Ok(())
}

/// The account and script-type levels of a BIP-48 origin, or `None` if it is not one.
fn bip48_levels(origin: &DerivationPath) -> Option<(ChildIndex, u32)> {
    let steps: Vec<ChildNumber> = origin.into_iter().copied().collect();
    let [_, _, account, script_type] = steps[..] else {
        return None;
    };
    match (account, script_type) {
        (
            ChildNumber::Hardened { index: account },
            ChildNumber::Hardened { index: script_type },
        ) => Some((ChildIndex::new(account)?, script_type)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};

    use crate::multisig;

    const NETWORK: Network = Network::Bitcoin;

    /// The mnemonic BIP-84 publishes its test vectors for.
    const ABANDON: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon about";

    /// BIP-84's own m/84'/0'/0'/0/0 and m/84'/0'/0'/1/0 for that mnemonic
    /// (<https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki>, "Test vectors").
    /// The health check is a comparison, so a vector this device could have invented for
    /// itself would prove only that it agrees with itself.
    const BIP84_RECEIVE_0: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
    const BIP84_CHANGE_0: &str = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el";

    fn seed() -> zeroize::Zeroizing<[u8; 64]> {
        crate::bip39::seed(ABANDON, "")
    }

    /// The same mnemonic under a passphrase: a different wallet, which is one of the two
    /// things a health check is asked to catch.
    fn other_seed() -> zeroize::Zeroizing<[u8; 64]> {
        crate::bip39::seed(ABANDON, "not the passphrase this wallet was saved under")
    }

    fn expectation(keychain: Keychain, index: u32, address: &str) -> Expectation {
        Expectation {
            keychain,
            index: ChildIndex::new(index).expect("a test index"),
            address: crate::address::parse(address, NETWORK).expect("a published address"),
        }
    }

    fn bip84() -> Wallet<'static> {
        Wallet::Singlesig {
            scheme: Scheme::Bip84,
            account: ChildIndex::ZERO,
        }
    }

    // -- singlesig ----------------------------------------------------------------------

    /// The whole feature on the singlesig side: the wallet still derives the address it was
    /// saved with, on both keychains, and the evidence names the leaf it checked.
    #[test]
    fn a_wallet_that_still_derives_its_saved_address_passes() {
        for (keychain, index, address, path) in [
            (Keychain::Receive, 0, BIP84_RECEIVE_0, "m/84'/0'/0'/0/0"),
            (Keychain::Change, 0, BIP84_CHANGE_0, "m/84'/0'/0'/1/0"),
        ] {
            let expected = expectation(keychain, index, address);
            let pass = check(&seed(), NETWORK, bip84(), &expected).expect(address);
            assert_eq!(pass.proof, Proof::SeedDerivesTheAddress);
            assert_eq!(pass.entry.address.to_string(), address);
            assert_eq!(pass.entry.our_path(), path);
            assert_eq!(pass.entry.keychain, keychain);
            assert!(pass.entry.witness_script.is_none(), "singlesig has no script");
            assert_eq!(
                pass.fingerprint,
                crate::derive::master_fingerprint(&seed(), NETWORK)
            );
        }
    }

    /// A different wallet behind the same mnemonic fails, and the failure carries the
    /// address it did derive so the screen can show a user both strings.
    #[test]
    fn another_wallet_fails_and_says_what_it_derived() {
        let expected = expectation(Keychain::Receive, 0, BIP84_RECEIVE_0);
        let failure = check(&other_seed(), NETWORK, bip84(), &expected).unwrap_err();
        let Failure::AddressMismatch { derived } = &failure else {
            panic!("a passphrase is a different wallet: {failure}");
        };
        assert_ne!(derived.to_string(), BIP84_RECEIVE_0);
        assert!(failure.is_broken());
    }

    /// The wrong leaf of the RIGHT wallet is a mismatch too. A health check that searched
    /// for the address instead of deriving the recorded leaf would pass this, and would
    /// then be answering "is this address mine" - which is `address::find`, a different
    /// question with a different screen.
    #[test]
    fn the_right_wallet_at_the_wrong_leaf_is_a_mismatch() {
        let expected = expectation(Keychain::Receive, 1, BIP84_RECEIVE_0);
        let failure = check(&seed(), NETWORK, bip84(), &expected).unwrap_err();
        assert!(matches!(failure, Failure::AddressMismatch { .. }));
    }

    /// A test-chain address over this wallet's own key must not pass on a mainnet device.
    ///
    /// The two addresses have the SAME scriptPubKey - only the human-readable part differs -
    /// so the comparison this module rests on cannot separate them and the chain has to be
    /// checked before it runs. Without that check this is a green screen for a wallet the
    /// user was told is on mainnet.
    #[test]
    fn a_test_chain_address_over_our_own_key_is_refused_not_passed() {
        let derived = crate::derive::derive(
            &seed(),
            NETWORK,
            Scheme::Bip84,
            ChildIndex::ZERO,
            ChildIndex::ZERO,
            1,
            0,
        );
        let key: bitcoin::key::CompressedPublicKey = derived.rows[0]
            .pubkey
            .parse()
            .expect("the report renders a compressed point");
        let elsewhere = crate::address::for_key(Scheme::Bip84, key, Network::Testnet)
            .expect("BIP-84 renders an address");
        assert_eq!(
            elsewhere.script_pubkey(),
            crate::address::parse(BIP84_RECEIVE_0, NETWORK)
                .unwrap()
                .script_pubkey(),
            "the trap only exists because the scripts are equal"
        );

        let expected = Expectation {
            keychain: Keychain::Receive,
            index: ChildIndex::ZERO,
            address: elsewhere,
        };
        let failure = check(&seed(), NETWORK, bip84(), &expected).unwrap_err();
        assert!(matches!(
            failure,
            Failure::AddressNotForNetwork {
                wallet: Network::Bitcoin
            }
        ));
        assert!(!failure.is_broken(), "a wrong-chain record is not a broken wallet");
    }

    /// BIP-48 has no single-key address, so asking for one through the singlesig arm is a
    /// caller error and not a finding about the wallet.
    #[test]
    fn a_multisig_scheme_has_no_singlesig_address_to_check() {
        let expected = expectation(Keychain::Receive, 0, BIP84_RECEIVE_0);
        let wallet = Wallet::Singlesig {
            scheme: Scheme::Bip48,
            account: ChildIndex::ZERO,
        };
        let failure = check(&seed(), NETWORK, wallet, &expected).unwrap_err();
        assert!(matches!(failure, Failure::NoAddressesForScheme(Scheme::Bip48)));
        assert!(!failure.is_broken());
    }

    // -- multisig -----------------------------------------------------------------------

    /// Cosigners that are not us, from fixed seeds, so the wallets below are reproducible.
    const COSIGNER_SEEDS: [[u8; 64]; 3] = [[0x11; 64], [0x22; 64], [0x33; 64]];

    fn key_expression(seed: &[u8; 64]) -> String {
        let fingerprint = crate::derive::master_fingerprint(seed, NETWORK);
        let account = crate::derive::derive(
            seed,
            NETWORK,
            Scheme::Bip48,
            ChildIndex::ZERO,
            ChildIndex::ZERO,
            0,
            2,
        );
        format!(
            "[{fingerprint}/48h/0h/0h/2h]{}/<0;1>/*",
            account.account.xpub
        )
    }

    /// A 2-of-3 with this seed and two of the fixed cosigners, registered the way an import
    /// registers one: parsed from a descriptor, then proven ours by derivation.
    fn wallet_with(third: &[u8; 64]) -> multisig::Registration {
        let descriptor = format!(
            "wsh(sortedmulti(2,{},{},{}))",
            key_expression(&seed()),
            key_expression(&COSIGNER_SEEDS[0]),
            key_expression(third)
        );
        multisig::parse(&descriptor)
            .expect("the descriptor parses")
            .verify(&seed(), NETWORK)
            .expect("this seed is a member")
    }

    /// The multisig path end to end.
    ///
    /// The expected address here is the registration's own first receive address rather
    /// than a published string, because a registration exists only for a wallet this device
    /// is a member of and nobody holds BIP-129's seeds. That rendering is pinned to BIP-129
    /// in `tests/multisig_vectors.rs`; what this test is about is the two comparisons the
    /// check makes on top of it.
    #[test]
    fn a_registered_multisig_wallet_passes_and_names_our_key() {
        let registration = wallet_with(&COSIGNER_SEEDS[1]);
        let expected = Expectation {
            keychain: Keychain::Receive,
            index: ChildIndex::ZERO,
            address: registration
                .first_receive_address()
                .expect("the first receive leaf derives"),
        };

        let pass = check(&seed(), NETWORK, Wallet::Multisig(&registration), &expected)
            .expect("the wallet this seed was registered into is intact");
        assert_eq!(pass.proof, Proof::SeedIsAMemberAndTheWalletBuildsTheAddress);
        assert_eq!(pass.entry.paths.len(), 3, "one path per cosigner");
        assert!(pass.entry.witness_script.is_some(), "multisig carries its script");
        assert!(pass.entry.our_path().starts_with("m/48'/0'/0'/2'/0/0"));
    }

    /// A seed that is not this wallet's member fails on the KEY, not on the address: the
    /// address is a function of the registered xpubs and would have matched.
    ///
    /// This is the half a health check would silently lose if it only compared addresses,
    /// and it is the half that matters - a multisig wallet whose stored registration is
    /// perfect and whose own key is gone is unspendable, and looks healthy from the outside.
    #[test]
    fn a_multisig_wallet_this_seed_cannot_sign_for_fails_on_the_key() {
        let registration = wallet_with(&COSIGNER_SEEDS[1]);
        let expected = Expectation {
            keychain: Keychain::Receive,
            index: ChildIndex::ZERO,
            address: registration.first_receive_address().unwrap(),
        };

        let failure = check(
            &other_seed(),
            NETWORK,
            Wallet::Multisig(&registration),
            &expected,
        )
        .unwrap_err();
        let Failure::NotAMember { device, wallet } = failure else {
            panic!("the address would have matched: {failure}");
        };
        assert_ne!(device, wallet);
        assert_eq!(wallet, registration.ours().fingerprint);
        assert!(failure.is_broken());
    }

    /// And the other half is live: same seed, same membership, a wallet whose third
    /// cosigner is somebody else. The key comparison passes and the address does not.
    #[test]
    fn a_multisig_wallet_with_a_different_cosigner_fails_on_the_address() {
        let saved = wallet_with(&COSIGNER_SEEDS[1]);
        let other = wallet_with(&COSIGNER_SEEDS[2]);
        let expected = Expectation {
            keychain: Keychain::Receive,
            index: ChildIndex::ZERO,
            address: saved.first_receive_address().unwrap(),
        };

        let failure = check(&seed(), NETWORK, Wallet::Multisig(&other), &expected).unwrap_err();
        let Failure::AddressMismatch { derived } = &failure else {
            panic!("the seed is a member of both wallets: {failure}");
        };
        assert_ne!(derived, &expected.address);
        assert!(failure.is_broken());
    }

    /// Both halves of the chain check, in the two orders they arrive in.
    ///
    /// A record and a device that disagree about the chain is a stale wallet record, not a
    /// wallet that lost its key, and neither order may reach the comparison: the recorded
    /// address is checked first because it is the one whose scriptPubKey would silently
    /// match across chains, and the registration second because it names its own.
    #[test]
    fn a_chain_the_device_is_not_on_is_refused_before_anything_is_compared() {
        let registration = wallet_with(&COSIGNER_SEEDS[1]);
        let mainnet = Expectation {
            keychain: Keychain::Receive,
            index: ChildIndex::ZERO,
            address: registration.first_receive_address().unwrap(),
        };
        let failure = check(
            &seed(),
            Network::Testnet,
            Wallet::Multisig(&registration),
            &mainnet,
        )
        .unwrap_err();
        assert!(matches!(
            failure,
            Failure::AddressNotForNetwork {
                wallet: Network::Testnet
            }
        ));

        // The same mismatch with a record whose address does belong to the device's chain,
        // which is the only way the registration's own network is what refuses.
        let key: bitcoin::key::CompressedPublicKey = crate::derive::derive(
            &seed(),
            Network::Testnet,
            Scheme::Bip84,
            ChildIndex::ZERO,
            ChildIndex::ZERO,
            1,
            0,
        )
        .rows[0]
            .pubkey
            .parse()
            .expect("the report renders a compressed point");
        let on_testnet = Expectation {
            keychain: Keychain::Receive,
            index: ChildIndex::ZERO,
            address: crate::address::for_key(Scheme::Bip84, key, Network::Testnet)
                .expect("BIP-84 renders an address"),
        };
        let failure = check(
            &seed(),
            Network::Testnet,
            Wallet::Multisig(&registration),
            &on_testnet,
        )
        .unwrap_err();
        assert!(
            matches!(
                failure,
                Failure::RegistrationNotForNetwork {
                    registration: Network::Bitcoin,
                    device: Network::Testnet,
                }
            ),
            "{failure}"
        );
        assert!(!failure.is_broken(), "a chain mismatch is not a broken wallet");
    }

    // -- the copy the screens print -----------------------------------------------------

    /// [`PASS_MEANS`] and every refusal are one actionable ASCII line each, in the shape
    /// `crate::address`'s refusals are held to. The pass sentence additionally has to keep
    /// saying what it does NOT prove, which is the only reason it exists as a constant.
    #[test]
    fn the_copy_is_one_ascii_line_each() {
        let failures = [
            Failure::AddressMismatch {
                derived: crate::address::parse(BIP84_CHANGE_0, NETWORK).unwrap(),
            },
            Failure::NotAMember {
                device: Fingerprint::from([1u8; 4]),
                wallet: Fingerprint::from([2u8; 4]),
            },
            Failure::KeyDoesNotDerive,
            Failure::NoAddressesForScheme(Scheme::Bip48),
            Failure::AddressNotForNetwork {
                wallet: Network::Bitcoin,
            },
            Failure::RegistrationNotForNetwork {
                registration: Network::Testnet,
                device: Network::Bitcoin,
            },
            Failure::LeafDoesNotDerive,
        ];
        for text in failures.iter().map(ToString::to_string).chain([PASS_MEANS.to_string()]) {
            assert!(text.is_ascii(), "{text}");
            assert!(!text.is_empty() && !text.ends_with('.'), "{text}");
            assert!(!text.contains('\n'), "{text}");
        }
        assert!(PASS_MEANS.contains("does not prove"), "{PASS_MEANS}");
    }
}
