// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Published address vectors, through the public API only (0.2.0-m10).
//!
//! An integration test rather than a unit test, for the reason `spec_vectors.rs` and
//! `multisig_vectors.rs` are ones: it links the crate the way the firmware does, so a
//! vector cannot pass by reaching a private helper the shipped build does not expose.
//!
//! `spec_vectors.rs` already pins the same published values through `derive::derive`, which
//! walks the path with the SEED in scope. This file pins the other half of m10: the
//! watch-only path, where an account's addresses come from its xpub alone
//! (`address::SinglesigAccount`), which is what the address explorer, the CSV and the
//! ownership search actually run on. Both must land on the same published strings, because
//! a device that shows one address on the receive screen and recognises a different one
//! during an ownership search is worse than a device with neither feature.
//!
//! What is pinned, and to what:
//!
//! - **BIP-84** (<https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki>, "Test
//!   vectors"): P2WPKH receive 0, receive 1 and change 0 for the ABANDON mnemonic.
//! - **BIP-86** (<https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki>, "Test
//!   vectors"): P2TR key-path receive 0, receive 1 and change 0 for the same mnemonic. This
//!   is the vector that matters most to the watch-only path, because it is the one place
//!   the two paths compute the internal key differently - from the private key on one side
//!   and from the compressed public key on the other.
//! - **BIP-49** (<https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki>, "Test
//!   vectors"): P2SH-P2WPKH on testnet, which is the only chain BIP-49 publishes.
//! - **SLIP-132** (<https://github.com/satoshilabs/slips/blob/master/slip-0132.md>,
//!   "Bitcoin Test Vectors"): the BIP-44 P2PKH row the BIPs above omit, for the same
//!   mnemonic.
//! - **BIP-350** (<https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki>, "Test
//!   vectors for v0-v16 native segregated witness addresses", which supersede BIP-173's):
//!   every valid address with its published scriptPubKey, and every invalid one with the
//!   refusal it must get. This is `address::parse`'s whole contract - it is the only place
//!   in the crate that reads an address someone else wrote.
//! - **BIP-129** (<https://github.com/bitcoin/bips/blob/master/bip-0129.mediawiki>, test
//!   vector 1): used here as the negative control for the ownership search. Its positive
//!   pin - descriptor in, published first receive address out - lives in
//!   `multisig_vectors.rs`, because a registration can only be built for a wallet this
//!   device is a member of and nobody holds BIP-129's seeds. The two are one chain: the
//!   published address is reached through `multisig::sorted_multi_witness_script`, which is
//!   the same script assembler `Registration::witness_script` uses, and this file pins
//!   `Registration::address` to that script.

use bitcoin::Network;

use notyas_core::address::{
    self, AddressError, AddressSource, Keychain, Search, SearchBounds, SinglesigAccount, Step,
};
use notyas_core::derive::{self, ChildIndex, Scheme};
use notyas_core::{bip39, export, multisig};

// =======================================================================================
// Shared fixtures
// =======================================================================================

/// The mnemonic BIP-49, BIP-84, BIP-86 and SLIP-132 all share.
const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// Seed for [`ABANDON`] with an empty passphrase, as all four documents assume. Computed
/// rather than transcribed, so a mistyped hex digit cannot silently swap in another wallet.
fn abandon_seed() -> zeroize::Zeroizing<[u8; 64]> {
    bip39::seed(ABANDON, "")
}

/// BIP-32's own version bytes for a serialized extended PUBLIC key, mainnet and test chain.
/// The published account keys below are SLIP-132 renderings (`zpub`, `upub`) of nodes this
/// crate renders as `xpub`/`tpub`, and only those four bytes differ.
const XPUB: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
const TPUB: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];

/// Re-serialize an extended key under different version bytes; the payload is untouched.
/// Panics on a bad base58check string, which for a constant lifted from a BIP means the
/// transcription is wrong.
fn reversion(xkey: &str, version: [u8; 4]) -> String {
    let mut raw = bitcoin::base58::decode_check(xkey).expect("published vector is base58check");
    assert_eq!(raw.len(), 78, "not a BIP32 extended key: {xkey}");
    raw[..4].copy_from_slice(&version);
    bitcoin::base58::encode_check(&raw)
}

fn index(value: u32) -> ChildIndex {
    ChildIndex::new(value).expect("test uses an in-range child index")
}

/// The account node alone: `count` of zero, because everything below derives its addresses
/// from the account's PUBLIC key and never from a row the report built.
fn account_of(scheme: Scheme, network: Network) -> derive::Derived {
    derive::derive(
        &abandon_seed(),
        network,
        scheme,
        ChildIndex::ZERO,
        ChildIndex::ZERO,
        0,
        0,
    )
}

/// One watch-only account, with the published account xpub asserted on the way through so a
/// later address mismatch cannot be blamed on the wrong account node.
fn watch_only(scheme: Scheme, network: Network, published_account: &str) -> SinglesigAccount {
    let derived = account_of(scheme, network);
    assert_eq!(
        derived.account.xpub,
        published_account,
        "{scheme}: account node disagrees with the published vector"
    );
    SinglesigAccount::new(scheme, network, &derived.account)
        .expect("a singlesig account node yields an address source")
}

/// `(receive 0, receive 1, change 0)` through the watch-only path.
fn first_three(account: &SinglesigAccount) -> (String, String, String) {
    let at = |keychain, i| {
        account
            .address(keychain, index(i))
            .expect("an in-range leaf derives")
            .to_string()
    };
    (
        at(Keychain::Receive, 0),
        at(Keychain::Receive, 1),
        at(Keychain::Change, 0),
    )
}

// =======================================================================================
// BIP-84 - P2WPKH, mainnet
// =======================================================================================

const BIP84_ACCOUNT_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
const BIP84_RECEIVE_0: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
const BIP84_RECEIVE_1: &str = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g";
const BIP84_CHANGE_0: &str = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el";

#[test]
fn bip84_addresses_from_the_account_xpub() {
    let account = watch_only(
        Scheme::Bip84,
        Network::Bitcoin,
        &reversion(BIP84_ACCOUNT_ZPUB, XPUB),
    );
    assert_eq!(
        first_three(&account),
        (
            BIP84_RECEIVE_0.into(),
            BIP84_RECEIVE_1.into(),
            BIP84_CHANGE_0.into()
        )
    );
    assert_eq!(
        account.leaf_path(Keychain::Receive, index(0)),
        "m/84'/0'/0'/0/0"
    );
    assert_eq!(
        account.leaf_path(Keychain::Change, index(0)),
        "m/84'/0'/0'/1/0",
        "the change tab derives the internal keychain, not a second copy of the external one"
    );
}

// =======================================================================================
// BIP-86 - P2TR key-path, mainnet
// =======================================================================================

const BIP86_ACCOUNT_XPUB: &str = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";
const BIP86_RECEIVE_0: &str = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
const BIP86_RECEIVE_1: &str = "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh";
const BIP86_CHANGE_0: &str = "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7";

/// The taproot vector is the one that proves the watch-only path is not a second
/// implementation: `derive::derive` reaches the internal key through the leaf's PRIVATE
/// key, and this path reaches the same x-only key from the compressed public key.
#[test]
fn bip86_addresses_from_the_account_xpub() {
    let account = watch_only(Scheme::Bip86, Network::Bitcoin, BIP86_ACCOUNT_XPUB);
    assert_eq!(
        first_three(&account),
        (
            BIP86_RECEIVE_0.into(),
            BIP86_RECEIVE_1.into(),
            BIP86_CHANGE_0.into()
        )
    );
}

// =======================================================================================
// BIP-49 - P2SH-P2WPKH, testnet (the only chain BIP-49 publishes)
// =======================================================================================

const BIP49_TESTNET_ACCOUNT_UPUB: &str = "upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8DehrnHtv21XXEMYRUocHqguyjknFHYfgY";
const BIP49_TESTNET_RECEIVE_0: &str = "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2";

#[test]
fn bip49_testnet_address_from_the_account_xpub() {
    let account = watch_only(
        Scheme::Bip49,
        Network::Testnet,
        &reversion(BIP49_TESTNET_ACCOUNT_UPUB, TPUB),
    );
    assert_eq!(
        account.address(Keychain::Receive, index(0)).unwrap().to_string(),
        BIP49_TESTNET_RECEIVE_0
    );
    assert_eq!(
        account.leaf_path(Keychain::Receive, index(0)),
        "m/49'/1'/0'/0/0",
        "BIP-49's vector is on coin type 1"
    );
}

// =======================================================================================
// BIP-44 - P2PKH, mainnet, from SLIP-132 (BIP-44 publishes no addresses)
// =======================================================================================

const BIP44_ACCOUNT_XPUB: &str = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj";
const BIP44_RECEIVE_0: &str = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA";

#[test]
fn bip44_address_from_the_account_xpub() {
    let account = watch_only(Scheme::Bip44, Network::Bitcoin, BIP44_ACCOUNT_XPUB);
    assert_eq!(
        account.address(Keychain::Receive, index(0)).unwrap().to_string(),
        BIP44_RECEIVE_0
    );
}

// =======================================================================================
// The account node an address source will not take
// =======================================================================================

/// Multisig has no singlesig addresses, and a test-chain account node cannot render mainnet
/// money. Both are refusals rather than a rendering nobody could check.
#[test]
fn an_account_that_cannot_produce_addresses_is_refused() {
    let bip48 = account_of(Scheme::Bip48, Network::Bitcoin);
    assert!(
        SinglesigAccount::new(Scheme::Bip48, Network::Bitcoin, &bip48.account).is_none(),
        "a BIP-48 account is a multisig cosigner key, not an address source"
    );

    let testnet = account_of(Scheme::Bip84, Network::Testnet);
    assert!(
        SinglesigAccount::new(Scheme::Bip84, Network::Bitcoin, &testnet.account).is_none(),
        "a tpub may not render mainnet addresses"
    );
}

// =======================================================================================
// BIP-350 - reading an address someone else wrote
// =======================================================================================

/// Every valid address of BIP-350's list with the scriptPubKey the document publishes for
/// it, split by the chain its prefix names.
const BIP350_VALID_MAINNET: [(&str, &str); 5] = [
    (
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
        "0014751e76e8199196d454941c45d1b3a323f1433bd6",
    ),
    (
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
        "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
    ),
    ("BC1SW50QGDZ25J", "6002751e"),
    (
        "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
        "5210751e76e8199196d454941c45d1b3a323",
    ),
    (
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ),
];

const BIP350_VALID_TESTNET: [(&str, &str); 3] = [
    (
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
    ),
    (
        "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
        "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    ),
    (
        "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
        "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    ),
];

/// BIP-350's invalid list, with the document's own reason beside each one. Every entry has
/// to be refused as unreadable: none of them is a real address of any chain, so none may
/// ever reach the ownership search and come back "not yours".
const BIP350_INVALID: [(&str, &str); 15] = [
    (
        "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
        "invalid human-readable part",
    ),
    (
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
        "invalid checksum (bech32 instead of bech32m)",
    ),
    (
        "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
        "invalid checksum (bech32 instead of bech32m)",
    ),
    (
        "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
        "invalid checksum (bech32 instead of bech32m)",
    ),
    (
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
        "invalid checksum (bech32m instead of bech32)",
    ),
    (
        "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
        "invalid checksum (bech32m instead of bech32)",
    ),
    (
        "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
        "invalid character in checksum",
    ),
    (
        "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
        "invalid witness version",
    ),
    ("bc1pw5dgrnzv", "invalid program length (1 byte)"),
    (
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
        "invalid program length (41 bytes)",
    ),
    (
        "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
        "invalid program length for witness version 0",
    ),
    (
        "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
        "mixed case",
    ),
    (
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
        "zero padding of more than 4 bits",
    ),
    (
        "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
        "non-zero padding in 8-to-5 conversion",
    ),
    ("bc1gmk9yu", "empty data section"),
];

#[test]
fn bip350_valid_addresses_parse_to_their_published_scripts() {
    for (address, script) in BIP350_VALID_MAINNET {
        let parsed = address::parse(address, Network::Bitcoin)
            .unwrap_or_else(|error| panic!("{address}: {error}"));
        assert_eq!(
            parsed.script_pubkey().to_hex_string(),
            script,
            "{address}: scriptPubKey"
        );
    }
    for (address, script) in BIP350_VALID_TESTNET {
        let parsed = address::parse(address, Network::Testnet)
            .unwrap_or_else(|error| panic!("{address}: {error}"));
        assert_eq!(
            parsed.script_pubkey().to_hex_string(),
            script,
            "{address}: scriptPubKey"
        );
    }
}

#[test]
fn bip350_invalid_addresses_are_refused_as_unreadable() {
    for (address, reason) in BIP350_INVALID {
        for network in [Network::Bitcoin, Network::Testnet] {
            assert_eq!(
                address::parse(address, network),
                Err(AddressError::Malformed),
                "{address} ({reason}) was accepted on {network}"
            );
        }
    }
}

/// A real address of the other chain is its own answer and never "not yours": the search is
/// what would have to say that, and this refusal is what keeps it from being asked.
#[test]
fn a_valid_address_of_the_other_chain_is_named_as_such() {
    assert_eq!(
        address::parse(BIP84_RECEIVE_0, Network::Testnet),
        Err(AddressError::WrongNetwork {
            address: bitcoin::NetworkKind::Main,
            wallet: Network::Testnet,
        })
    );
    assert_eq!(
        address::parse(BIP350_VALID_TESTNET[0].0, Network::Bitcoin),
        Err(AddressError::WrongNetwork {
            address: bitcoin::NetworkKind::Test,
            wallet: Network::Bitcoin,
        })
    );
    assert_eq!(
        address::parse("   \n", Network::Bitcoin),
        Err(AddressError::Empty)
    );
}

/// Surrounding whitespace is what a line read from a card carries; the address inside it is
/// still that address, and BIP-173's uppercase form still names the same output.
#[test]
fn whitespace_and_case_do_not_change_which_output_an_address_names() {
    let lowercase = address::parse(BIP84_RECEIVE_0, Network::Bitcoin).unwrap();
    let padded = address::parse(&format!("  {}\r\n", BIP84_RECEIVE_0), Network::Bitcoin).unwrap();
    let uppercase =
        address::parse(&BIP84_RECEIVE_0.to_uppercase(), Network::Bitcoin).unwrap();
    assert_eq!(lowercase.script_pubkey(), padded.script_pubkey());
    assert_eq!(lowercase.script_pubkey(), uppercase.script_pubkey());
}

// =======================================================================================
// Verify address ownership
// =======================================================================================

/// The published BIP-84 and BIP-86 addresses, found through the same search a user runs on
/// S-24 - over two accounts at once, on both keychains.
#[test]
fn the_ownership_search_finds_the_published_addresses() {
    let bip84 = watch_only(
        Scheme::Bip84,
        Network::Bitcoin,
        &reversion(BIP84_ACCOUNT_ZPUB, XPUB),
    );
    let bip86 = watch_only(Scheme::Bip86, Network::Bitcoin, BIP86_ACCOUNT_XPUB);
    let sources = [
        AddressSource::Singlesig(&bip84),
        AddressSource::Singlesig(&bip86),
    ];
    let bounds = SearchBounds::new(4).expect("4 is inside the ceiling");

    let cases = [
        (BIP84_RECEIVE_1, 0usize, Keychain::Receive, 1u32, "m/84'/0'/0'/0/1"),
        (BIP84_CHANGE_0, 0, Keychain::Change, 0, "m/84'/0'/0'/1/0"),
        (BIP86_RECEIVE_0, 1, Keychain::Receive, 0, "m/86'/0'/0'/0/0"),
        (BIP86_CHANGE_0, 1, Keychain::Change, 0, "m/86'/0'/0'/1/0"),
    ];
    for (address, source, keychain, at, path) in cases {
        let target = address::parse(address, Network::Bitcoin).expect("published address parses");
        let found = match address::find(&target, &sources, bounds, &mut |_| Step::Continue) {
            Search::Yours(found) => found,
            other => panic!("{address}: {other:?}"),
        };
        assert_eq!(found.source, source, "{address}: source");
        assert_eq!(found.entry.keychain, keychain, "{address}: keychain");
        assert_eq!(found.entry.index.get(), at, "{address}: index");
        assert_eq!(found.entry.our_path(), path, "{address}: path");
        assert_eq!(found.entry.address.to_string(), address, "{address}: address");
    }
}

/// A real address of somebody else's wallet - BIP-129 test vector 1's first receive address
/// - inside the bound, answered NOT FOUND, with the count the verdict quotes.
#[test]
fn a_foreign_address_is_not_found_within_the_bound() {
    const BSMS_ADDRESS_1: &str = "bc1qrgc6p3kylfztu06ysl752gwwuekhvtfh9vr7zg43jvu60mutamcsv948ej";

    let bip84 = watch_only(
        Scheme::Bip84,
        Network::Bitcoin,
        &reversion(BIP84_ACCOUNT_ZPUB, XPUB),
    );
    let sources = [AddressSource::Singlesig(&bip84)];
    let bounds = SearchBounds::new(10).unwrap();
    let target = address::parse(BSMS_ADDRESS_1, Network::Bitcoin).unwrap();

    assert_eq!(
        address::find(&target, &sources, bounds, &mut |_| Step::Continue),
        Search::NotFound { searched: 20 }
    );
    assert_eq!(
        address::search_total(&sources, bounds),
        20,
        "the busy screen counts up to what the search will actually build"
    );
    assert_eq!(
        address::search_total(&sources, SearchBounds::DEFAULT),
        1528,
        "S-24 and S-25 quote 1528 addresses across receive and change"
    );
}

/// A stopped search is not a verdict, and the type says so.
#[test]
fn a_stopped_search_reports_its_own_incompleteness() {
    let bip84 = watch_only(
        Scheme::Bip84,
        Network::Bitcoin,
        &reversion(BIP84_ACCOUNT_ZPUB, XPUB),
    );
    let sources = [AddressSource::Singlesig(&bip84)];
    // The target IS this wallet's, three past where the caller stops.
    let target = address::parse(BIP84_CHANGE_0, Network::Bitcoin).unwrap();
    let outcome = address::find(
        &target,
        &sources,
        SearchBounds::new(20).unwrap(),
        &mut |searched| {
            if searched >= 3 {
                Step::Stop
            } else {
                Step::Continue
            }
        },
    );
    assert_eq!(outcome, Search::Stopped { searched: 3 });
}

/// An unbounded search is refused at the type, not clamped at the loop.
#[test]
fn the_search_bound_has_a_ceiling() {
    assert!(SearchBounds::new(SearchBounds::MAX_PER_KEYCHAIN).is_some());
    assert!(SearchBounds::new(SearchBounds::MAX_PER_KEYCHAIN + 1).is_none());
    assert!(SearchBounds::new(0).is_none());
}

// =======================================================================================
// Multisig addresses
// =======================================================================================

/// A 2-of-2 whose first cosigner is a seed this device holds and whose second is BIP-129
/// test vector 1's first published key, built the way `multisig_vectors.rs` builds it.
///
/// A registration exists only for a wallet this device is a member of, so a published
/// vector cannot be registered whole; what this pins is that the address source renders
/// exactly the P2WSH commitment of the registration's own witness script, which is the
/// script `multisig_vectors.rs` pins to BIP-129's published address through the same
/// assembler.
fn half_published_registration() -> multisig::Registration {
    const SEED: [u8; 64] = [0x5c; 64];
    let network = Network::Bitcoin;
    let fingerprint = derive::master_fingerprint(&SEED, network);
    let ours = {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let master = bitcoin::bip32::Xpriv::new_master(network, &SEED).unwrap();
        let path: bitcoin::bip32::DerivationPath = "m/48'/0'/0'/2'".parse().unwrap();
        bitcoin::bip32::Xpub::from_priv(&secp, &master.derive_priv(&secp, &path).unwrap())
    };
    let published = "[1cf0bf7e/48'/0'/0'/2']xpub6FL8FhxNNUVnG64YurPd16AfGyvFLhh7S2uSsDqR3Qfcm6o9jtcMYwh6DvmcBF9qozxNQmTCVvWtxLpKTnhVLN3Pgnu2D3pAoXYFgVyd8Yz/**";
    let descriptor =
        format!("wsh(sortedmulti(2,[{fingerprint}/48h/0h/0h/2h]{ours}/<0;1>/*,{published}))");
    multisig::parse(&descriptor)
        .expect("the descriptor parses")
        .verify(&SEED, network)
        .expect("this seed is one of the two cosigners")
}

#[test]
fn a_registration_renders_its_addresses_through_one_path() {
    let registration = half_published_registration();
    let source = AddressSource::Multisig(&registration);

    for keychain in [Keychain::Receive, Keychain::Change] {
        for i in 0..3 {
            let entry = source.entry(keychain, index(i)).expect("a leaf derives");
            let witness_script = registration.witness_script(keychain, i).unwrap();
            assert_eq!(
                entry.address,
                bitcoin::Address::p2wsh(&witness_script, Network::Bitcoin),
                "the address is the P2WSH commitment of the registration's own script"
            );
            assert_eq!(
                entry.witness_script.as_deref(),
                Some(witness_script.to_hex_string().as_str())
            );
            assert_eq!(entry.paths.len(), 2, "one derivation per cosigner");
            assert_eq!(
                entry.our_path(),
                format!("m/48'/0'/0'/2'/{}/{i}", registration.chain_index(keychain)),
                "our own cosigner's leaf, which is what S-23 and S-25 print"
            );
            assert_eq!(
                entry.paths[1 - registration.our_position()],
                format!("m/48'/0'/0'/2'/{}/{i}", registration.chain_index(keychain)),
                "BIP-129 vector 1's cosigner shares that origin, at its own master key"
            );
        }
    }
    assert_eq!(
        source.address(Keychain::Receive, ChildIndex::ZERO),
        registration.first_receive_address(),
        "the explorer's first row is the address the registration screen made the user compare"
    );
}

/// The multisig half of the ownership search, over the same registration.
#[test]
fn the_ownership_search_answers_for_a_registration() {
    let registration = half_published_registration();
    let sources = [AddressSource::Multisig(&registration)];
    let bounds = SearchBounds::new(6).unwrap();

    let ours = registration.address(Keychain::Change, 4).unwrap();
    let found = match address::find(&ours, &sources, bounds, &mut |_| Step::Continue) {
        Search::Yours(found) => found,
        other => panic!("{other:?}"),
    };
    assert_eq!(found.entry.keychain, Keychain::Change);
    assert_eq!(found.entry.index.get(), 4);
    assert_eq!(found.entry.our_path(), "m/48'/0'/0'/2'/1/4");

    // BIP-129 test vector 1 whole, which this wallet shares exactly one cosigner with. A
    // shared cosigner is not a shared wallet, and the answer has to be NOT FOUND.
    let foreign = address::parse(
        "bc1qrgc6p3kylfztu06ysl752gwwuekhvtfh9vr7zg43jvu60mutamcsv948ej",
        Network::Bitcoin,
    )
    .unwrap();
    assert_eq!(
        address::find(&foreign, &sources, bounds, &mut |_| Step::Continue),
        Search::NotFound { searched: 12 }
    );
}

// =======================================================================================
// The address-range CSV
// =======================================================================================

/// The CSV, byte for byte, over the published BIP-84 addresses.
///
/// The shape is Coldcard's `shared/address_explorer.py` (quoted headers, an unquoted index
/// column); the addresses inside it are BIP-84's own, so a change to either the format or
/// the derivation shows up here.
#[test]
fn the_singlesig_csv_carries_the_published_addresses() {
    let bip84 = watch_only(
        Scheme::Bip84,
        Network::Bitcoin,
        &reversion(BIP84_ACCOUNT_ZPUB, XPUB),
    );
    let source = AddressSource::Singlesig(&bip84);
    let csv = export::address_range_csv(&source, Keychain::Receive, ChildIndex::ZERO, 2)
        .expect("two rows is inside the bound");
    assert_eq!(
        csv,
        concat!(
            "\"Index\",\"Payment Address\",\"Derivation\"\n",
            "0,\"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu\",\"m/84'/0'/0'/0/0\"\n",
            "1,\"bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g\",\"m/84'/0'/0'/0/1\"\n",
        )
    );

    let change = export::address_range_csv(&source, Keychain::Change, ChildIndex::ZERO, 1).unwrap();
    assert!(
        change.contains("0,\"bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el\",\"m/84'/0'/0'/1/0\"\n"),
        "the change tab exports the internal keychain: {change}"
    );
}

#[test]
fn the_multisig_csv_carries_a_column_per_cosigner() {
    let registration = half_published_registration();
    let source = AddressSource::Multisig(&registration);
    let csv = export::address_range_csv(&source, Keychain::Receive, ChildIndex::ZERO, 1).unwrap();
    let mut lines = csv.lines();
    assert_eq!(
        lines.next().unwrap(),
        "\"Index\",\"Payment Address\",\"Redeem Script\",\"Derivation (1 of 2)\",\"Derivation (2 of 2)\""
    );
    let row = lines.next().expect("one row");
    let address = registration.first_receive_address().unwrap().to_string();
    let script = registration
        .witness_script(Keychain::Receive, 0)
        .unwrap()
        .to_hex_string();
    assert_eq!(
        row,
        format!("0,\"{address}\",\"{script}\",\"m/48'/0'/0'/2'/0/0\",\"m/48'/0'/0'/2'/0/0\"")
    );
    assert!(lines.next().is_none(), "one row was asked for");
}

/// The bound is the milestone's own word: a range past it is refused, not clamped.
#[test]
fn the_csv_refuses_an_unbounded_range() {
    let bip84 = watch_only(
        Scheme::Bip84,
        Network::Bitcoin,
        &reversion(BIP84_ACCOUNT_ZPUB, XPUB),
    );
    let source = AddressSource::Singlesig(&bip84);
    assert!(source.range(Keychain::Receive, ChildIndex::ZERO, address::MAX_RANGE + 1).is_none());
    assert!(export::address_range_csv(
        &source,
        Keychain::Receive,
        ChildIndex::ZERO,
        address::MAX_RANGE + 1
    )
    .is_none());
    assert!(
        source
            .range(Keychain::Receive, index(ChildIndex::MAX), 2)
            .is_none(),
        "a run may not walk off the end of the unhardened half"
    );
}
