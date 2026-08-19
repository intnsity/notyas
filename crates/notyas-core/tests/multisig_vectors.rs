// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Published multisig vectors, through the public API only (0.2.0-m7).
//!
//! An integration test rather than a unit test, for the reason `spec_vectors.rs` is one:
//! it links the crate the way the firmware does, so a vector cannot pass by reaching a
//! private helper the shipped build does not expose. What it pins is the part of multisig
//! that is not this project's to decide -
//!
//! - **BIP-67** (https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki): the
//!   lexicographic key ordering, at the level of the finished `OP_M ... OP_N
//!   OP_CHECKMULTISIG` script.
//! - **BIP-129** (https://github.com/bitcoin/bips/blob/master/bip-0129.mediawiki), test
//!   vectors 1 and 2: a whole `wsh(sortedmulti(...))` descriptor and the first receive
//!   address it derives. That one line covers xpub parsing, BIP-32 derivation at `0/0`,
//!   the BIP-67 sort, the P2WSH commitment and the bech32 rendering, and it is the exact
//!   value the milestone asks a user to compare across devices before approving a
//!   registration. Its first vector, whose keys are plain public keys rather than xpubs,
//!   pins the ordering AT a P2WSH address with no derivation step in between.
//! - **BIP-32** (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), test
//!   vector 5: the sixteen serialised extended keys the BIP says must be recognised as
//!   invalid, run against the one place this device meets a key somebody else serialised -
//!   a coordinator-supplied cosigner in an import.
//!
//! Getting the ordering wrong is not a bug that shows up as a failed signature. It shows
//! up as a device that computes a different address than every other signer in the wallet
//! and quietly disagrees about where the money is, which is why these are pinned against
//! published text rather than against this crate's own output.
//!
//! # Provenance
//!
//! Every vector here says whether it is PUBLISHED or SELF-GENERATED, because the two prove
//! different things and only one of them is worth much. A PUBLISHED vector is a value some
//! other implementation wrote down first, so agreeing with it is evidence this device will
//! agree with its cosigners. A SELF-GENERATED one is this crate's own output frozen into an
//! assertion: it catches a regression and nothing else, because the code and its expectation
//! can be wrong together and still match. Nothing in this file that decides an address is
//! SELF-GENERATED.

use bitcoin::CompressedPublicKey;
use notyas_core::multisig::{self, Keychain, Malformed};

/// PUBLISHED. BIP-67's vectors 1, 2 and 4, restated as this crate's public API takes them:
/// parsed keys. Key lists and expected scripts are the BIP's own text, character for
/// character; only the P2SH addresses beside them are left out, because a P2SH address is
/// not a thing this device builds.
///
/// Vector 3 of the BIP is deliberately absent here and lives in the module's unit tests
/// instead: its keys are not points on the curve, so `CompressedPublicKey` cannot hold
/// them, and pinning it needs the byte-level assembler. The three vectors that use real
/// keys belong here, where they prove the shipped, typed entry point applies the same
/// ordering.
#[test]
fn bip67_vectors_through_the_public_script_builder() {
    let cases: [(u8, &[&str], &str); 3] = [
        (
            2,
            &[
                "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
                "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f",
            ],
            "522102fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f2102ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f852ae",
        ),
        (
            2,
            &[
                "02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0",
                "027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77",
                "02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404",
            ],
            "522102632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed021027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e772102e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b40453ae",
        ),
        (
            2,
            &[
                "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da",
                "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9",
                "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18",
            ],
            "5221021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc1821022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da2103e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e953ae",
        ),
    ];

    for (threshold, keys, want) in cases {
        let parsed: Vec<CompressedPublicKey> = keys
            .iter()
            .map(|k| k.parse().expect("vector key is a valid compressed point"))
            .collect();
        let script = multisig::sorted_multi_witness_script(threshold, &parsed)
            .expect("a 2-of-N is a policy this device holds");
        assert_eq!(hex::encode(script.as_bytes()), want);
    }
}

/// NOT A VECTOR. This device's own policy range, which no BIP states: a threshold of zero
/// or one larger than the key set, and a cosigner list past [`MAX_COSIGNERS`], answer `None`
/// rather than building a script nobody can spend.
#[test]
fn a_policy_outside_the_supported_range_builds_no_script() {
    let key: CompressedPublicKey =
        "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8"
            .parse()
            .unwrap();
    assert!(multisig::sorted_multi_witness_script(0, &[key]).is_none());
    assert!(multisig::sorted_multi_witness_script(2, &[key]).is_none());
    let too_many = vec![key; usize::from(multisig::MAX_COSIGNERS) + 1];
    assert!(multisig::sorted_multi_witness_script(2, &too_many).is_none());
}

/// PUBLISHED. BIP-129 "Mode: NO_ENCRYPTION" ROUND 2: the coordinator's descriptor and the
/// first address of the wallet it describes.
const BSMS_VECTOR_1: &str = "wsh(sortedmulti(2,[1cf0bf7e/48'/0'/0'/2']xpub6FL8FhxNNUVnG64YurPd16AfGyvFLhh7S2uSsDqR3Qfcm6o9jtcMYwh6DvmcBF9qozxNQmTCVvWtxLpKTnhVLN3Pgnu2D3pAoXYFgVyd8Yz/**,[4fc1dd4a/48'/0'/0'/2']xpub6EebMbEps7ZcV3FYEnddRsvrFWDrt2tiPmCeM7pPXQEmphvq9ZfJ1LWFUDjf3vxCeBuPrfyGrMazWUsYsetrnHatQZVLJH7LsgCjtMqdzgj/**))";
const BSMS_ADDRESS_1: &str = "bc1qrgc6p3kylfztu06ysl752gwwuekhvtfh9vr7zg43jvu60mutamcsv948ej";

/// PUBLISHED. BIP-129 "Mode: STANDARD Encryption" ROUND 2, the same two lines of the
/// coordinator's record.
const BSMS_VECTOR_2: &str = "wsh(sortedmulti(2,[b7868815/48'/0'/0'/2']xpub6FA5rfxJc94K1kNtxRby1hoHwi7YDyTWwx1KUR3FwskaF6HzCbZMz3zQwGnCqdiFeMTPV3YneTGS2YQPiuNYsSvtggWWMQpEJD4jXU7ZzEh/**,[eedff89a/48'/0'/0'/2']xpub6EhJvMneoLWAf8cuyLBLQiKiwh89RAmqXEqYeFuaCEHdHwxSRfzLrUxKXEBap7nZSHAYP7Jfq6gZmucotNzpMQ9Sb1nTqerqW8hrtmx6Y6o/**))";
const BSMS_ADDRESS_2: &str = "bc1qhs4u273g4azq7kqqpe6vh5wfhasfmrq7nheyzsnq77humd7rwtkqagvakf";

/// PUBLISHED. The whole chain against published text: descriptor -> first receive address.
///
/// These wallets belong to nobody this device holds a seed for, so `Pending::verify` is
/// not the route in - it would refuse them, correctly, for the reason the milestone cares
/// about. What is being pinned is derivation and ordering, so the vectors are driven
/// through the parse plus the witness-script build that verification would otherwise wrap.
#[test]
fn bip129_descriptors_derive_their_published_first_address() {
    for (descriptor, want) in [
        (BSMS_VECTOR_1, BSMS_ADDRESS_1),
        (BSMS_VECTOR_2, BSMS_ADDRESS_2),
    ] {
        let pending = multisig::parse(descriptor).expect("a BIP-129 descriptor parses");
        assert_eq!(pending.threshold, 2);
        assert_eq!(pending.cosigners.len(), 2);
        assert_eq!((pending.receive_chain, pending.change_chain), (0, 1));

        let keys: Vec<CompressedPublicKey> = pending
            .cosigners
            .iter()
            .map(|cosigner| {
                let child = cosigner
                    .xpub
                    .derive_pub(
                        &bitcoin::secp256k1::Secp256k1::verification_only(),
                        &[
                            bitcoin::bip32::ChildNumber::from_normal_idx(0).unwrap(),
                            bitcoin::bip32::ChildNumber::from_normal_idx(0).unwrap(),
                        ],
                    )
                    .expect("the receive keychain derives");
                CompressedPublicKey(child.public_key)
            })
            .collect();

        let witness_script = multisig::sorted_multi_witness_script(pending.threshold, &keys)
            .expect("a 2-of-2 is a policy this device holds");
        let address = bitcoin::Address::p2wsh(&witness_script, bitcoin::Network::Bitcoin);
        assert_eq!(address.to_string(), want, "descriptor: {descriptor}");
    }
}

/// SELF-GENERATED, with one published half. The same two vectors reaching the device the
/// way a real import does, complete with the membership proof.
///
/// Nothing here is compared against a value another implementation wrote down: the seed is
/// this test's own, so the wallet it forms is this crate's own and so is every address in
/// it. What is asserted is therefore structure - that verification accepts, that change and
/// receive differ, that `locate` answers only under the right path - and not an address. The
/// addresses are pinned above, where they are somebody else's numbers.
///
/// The seed here is the one cosigner of a 2-of-2 that the device really holds; the other
/// cosigner is BIP-129 vector 1's first key, verbatim. So the wallet is half published and
/// half ours, which is exactly the situation a registration is for, and it exercises
/// `Pending::verify` end to end on real third-party key material.
#[test]
fn a_wallet_sharing_a_published_cosigner_registers_and_derives() {
    const SEED: [u8; 64] = [0x5c; 64];
    let network = bitcoin::Network::Bitcoin;

    let fingerprint = notyas_core::derive::master_fingerprint(&SEED, network);
    let ours = {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let master = bitcoin::bip32::Xpriv::new_master(network, &SEED).unwrap();
        let path: bitcoin::bip32::DerivationPath = "m/48'/0'/0'/2'".parse().unwrap();
        bitcoin::bip32::Xpub::from_priv(&secp, &master.derive_priv(&secp, &path).unwrap())
    };
    let published = "[1cf0bf7e/48'/0'/0'/2']xpub6FL8FhxNNUVnG64YurPd16AfGyvFLhh7S2uSsDqR3Qfcm6o9jtcMYwh6DvmcBF9qozxNQmTCVvWtxLpKTnhVLN3Pgnu2D3pAoXYFgVyd8Yz/**";

    let descriptor =
        format!("wsh(sortedmulti(2,[{fingerprint}/48h/0h/0h/2h]{ours}/<0;1>/*,{published}))");
    let registration = multisig::parse(&descriptor)
        .expect("parses")
        .verify(&SEED, network)
        .expect("this seed is one of the two cosigners");

    assert_eq!(registration.threshold_of(), (2, 2));
    assert_eq!(registration.ours().fingerprint, fingerprint);
    // The stored form is canonical and carries a checksum that validates on the way back in.
    assert!(multisig::parse(registration.descriptor()).is_ok());

    // Change and receive are different scripts, and neither is the other's.
    let receive = registration.script_pubkey(Keychain::Receive, 0).unwrap();
    let change = registration.script_pubkey(Keychain::Change, 0).unwrap();
    assert_ne!(receive, change);
    assert_eq!(
        registration.first_receive_address().unwrap().script_pubkey(),
        receive
    );

    // And `locate` answers for each of them only under its own path.
    let receive_path: bitcoin::bip32::DerivationPath = "m/48'/0'/0'/2'/0/0".parse().unwrap();
    let change_path: bitcoin::bip32::DerivationPath = "m/48'/0'/0'/2'/1/0".parse().unwrap();
    assert_eq!(
        registration.locate(&receive_path, &receive).unwrap().keychain,
        Keychain::Receive
    );
    assert_eq!(
        registration.locate(&change_path, &change).unwrap().keychain,
        Keychain::Change
    );
    assert!(registration.locate(&receive_path, &change).is_none());
    assert!(registration.locate(&change_path, &receive).is_none());
}

// =======================================================================================
// BIP-129 vector 1 in its raw-public-key form, and BIP-32 test vector 5
// =======================================================================================

/// PUBLISHED. BIP-129 "Mode: NO_ENCRYPTION with Public Keys", ROUND 2: a 1-of-2
/// `sortedmulti` over two plain public keys, and the P2WSH address the coordinator
/// publishes for it.
///
/// This is the vector that closes the gap the other two leave. BIP-67's vectors stop at the
/// redeem script and give P2SH addresses this device does not build; BIP-129's xpub vectors
/// reach an address but only through a derivation step, so a sorting fault and a derivation
/// fault land in the same assertion. Here the two published keys go straight into the
/// shipped script builder and the answer is an address a coordinator wrote down: if this
/// device ordered keys differently from its cosigners, this is the line that says so.
#[test]
fn a_published_sortedmulti_of_raw_keys_derives_its_published_p2wsh_address() {
    const SIGNER_1: &str = "026d15412460ba0d881c21837bb999233896085a9ed4e5445bd637c10e579768ba";
    const SIGNER_2: &str = "030baf0497ab406ff50cb48b4013abac8a0338758d2fd54cd934927afa57cc2062";
    const ADDRESS: &str = "bc1quqy523xu3l8che3s8vja8n33qtg0uyugr9l5z092s3wa50p8t7rqy6zumf";

    let keys: Vec<CompressedPublicKey> = [SIGNER_1, SIGNER_2]
        .iter()
        .map(|key| key.parse().expect("a published key is on the curve"))
        .collect();
    let script = multisig::sorted_multi_witness_script(1, &keys)
        .expect("a 1-of-2 is a policy this device holds");
    let address = bitcoin::Address::p2wsh(&script, bitcoin::Network::Bitcoin);
    assert_eq!(address.to_string(), ADDRESS);

    // And handed over in the other order, which is the whole reason BIP-67 exists: the
    // coordinator's order is not the order the address is built in.
    let reversed: Vec<CompressedPublicKey> = keys.iter().rev().cloned().collect();
    assert_eq!(
        multisig::sorted_multi_witness_script(1, &reversed).unwrap(),
        script
    );
}

/// PUBLISHED. BIP-32 test vector 5 in full: sixteen serialised extended keys the BIP
/// states "must be recognized as invalid", each with the BIP's own reason, transcribed
/// from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki.
const BIP32_VECTOR_5_INVALID: [(&str, &str); 16] = [
    ("xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm", "pubkey version / prvkey mismatch"),
    ("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH", "prvkey version / pubkey mismatch"),
    ("xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn", "invalid pubkey prefix 04"),
    ("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ", "invalid prvkey prefix 04"),
    ("xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4", "invalid pubkey prefix 01"),
    ("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J", "invalid prvkey prefix 01"),
    ("xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv", "zero depth with non-zero parent fingerprint"),
    ("xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ", "zero depth with non-zero parent fingerprint"),
    ("xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN", "zero depth with non-zero index"),
    ("xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8", "zero depth with non-zero index"),
    ("DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4", "unknown extended key version"),
    ("DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9", "unknown extended key version"),
    ("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx", "private key 0 not in 1..n-1"),
    ("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G", "private key n not in 1..n-1"),
    ("xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY", "invalid pubkey 020000000000000000000000000000000000000000000000000000000000000007"),
    ("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL", "invalid checksum"),
];

/// BIP-32 test vector 5 at the boundary where this device actually meets a serialised
/// extended key: a cosigner in a coordinator-supplied import.
///
/// `spec_vectors.rs` runs the same sixteen against the `bitcoin` crate's parser on its own,
/// where the test is `#[ignore]`d because that parser accepts seven of them: it enforces
/// neither BIP-32's depth/parent/index consistency rules nor, for an `Xpriv`, the key-type
/// byte. That was harmless while nothing in this crate deserialized a key somebody else
/// wrote. Multisig registration does, so the rule has to live here, and this is the test
/// that says it does.
///
/// All sixteen are refused at the import boundary: the eight `xprv`s because a registration
/// names public keys and an extended PRIVATE key has no version bytes this device reads, the
/// two unknown-version strings and four of the six `xpub`s by the dependency's own checks,
/// and the remaining two `xpub`s - BIP-32's zero-depth pair - by the structure check `parse`
/// adds. Which entries land in which bucket is asserted, not assumed, so this test cannot go
/// on passing once the check it exists for is gone.
#[test]
fn bip32_vector_5_invalid_keys_never_enter_a_registration() {
    // The second cosigner is BIP-129 vector 1's second signer, taken from the descriptor
    // pinned above rather than transcribed a second time. Its fingerprint is not checked
    // against its key by `parse` - that is `verify`'s job, and these wallets are nobody's -
    // so a placeholder origin on the key under test is enough to make the descriptor whole.
    let published = multisig::parse(BSMS_VECTOR_1).expect("the published descriptor parses");
    let other = &published.cosigners[1];
    let naming = |key: &str| {
        format!(
            "wsh(sortedmulti(2,[00000000/48h/0h/0h/2h]{key}/<0;1>/*,[{}/48h/0h/0h/2h]{}/<0;1>/*))",
            other.fingerprint, other.xpub
        )
    };

    // The control: the same shape, holding a key that is valid. Without it every assertion
    // below would also pass on a descriptor template that was simply malformed.
    let control = published.cosigners[0].xpub.to_string();
    assert!(
        multisig::parse(&naming(&control)).is_ok(),
        "the template itself must accept a valid cosigner"
    );

    let mut refused_for_structure = Vec::new();
    for (key, why) in BIP32_VECTOR_5_INVALID {
        match multisig::parse(&naming(key)) {
            Err(Malformed::XpubUnparseable { at: 0 }) => {}
            Err(Malformed::XpubStructurallyInvalid { at: 0 }) => {
                refused_for_structure.push((key, why))
            }
            other => panic!("BIP-32 vector 5 ({why}) was not refused as a cosigner: {other:?}"),
        }
    }

    // Which entries land in which bucket is itself the claim, so it is asserted rather than
    // left to the loop above: two, both extended PUBLIC keys, both the zero-depth rule. A
    // change that dropped the structure check would empty this list, and one that refused
    // too much would lengthen it - neither can pass by being refused for some other reason.
    assert_eq!(
        refused_for_structure.len(),
        2,
        "expected exactly two entries to need this crate's own check: {refused_for_structure:?}"
    );
    for (key, why) in refused_for_structure {
        assert!(key.starts_with("xpub"), "{why}");
        assert!(why.starts_with("zero depth"), "{why}");
    }
}
