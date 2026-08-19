// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The wallet the device is put under test with, and where every byte of it comes from.
//!
//! Three seeds, and not one of them is invented. Each is a published BIP-39 English test
//! vector, transcribed with the seed the vector states, from
//!
//!   https://github.com/trezor/python-mnemonic/blob/master/vectors.json
//!
//! which is the file BIP-39 normatively points at and the same file
//! `crates/notyas-core/tests/vectors/trezor_vectors.json` already carries. Two properties
//! follow, and both are why a published vector is used instead of a seed made up here:
//!
//! 1. Reproducible and citable. Anyone can rebuild this harness from the specification and
//!    get the same addresses, so a device that disagrees is wrong about something a third
//!    party can check. It also means the harness needs no entropy: a generator that read an
//!    RNG could not be re-run to reproduce a failure, and re-running it is the whole point.
//!
//! 2. Self-checking. [`Wallet::new`] asserts that `bip39::seed(mnemonic, PASSPHRASE)`
//!    reproduces the seed the vector publishes. A typo in a mnemonic here, or a regression
//!    in the crate's PBKDF2, stops the tool before it can emit artifacts that would send an
//!    operator hunting a device bug that is not there.
//!
//! Every vector in that file is stated under the passphrase "TREZOR", so the operator has
//! to enter that passphrase on the device. That cost is worth paying: with an empty
//! passphrase the seed would be a number only this tool asserts, which is exactly the
//! property the published vector was chosen to avoid. A device given the words without the
//! passphrase derives a different master fingerprint, and the manifest prints that
//! fingerprint first, so the mistake shows up as one wrong line rather than as an
//! unexplained address mismatch three steps later.
//!
//! NOT SECRET, and deliberately handled as such: these seeds appear in every BIP-39 test
//! suite in existence. They are held as plain `[u8; 64]` rather than behind `Zeroizing`,
//! because pretending to guard a published constant teaches a reader the wrong thing about
//! which values in this tree are real. The rule that keeps that honest is the one asserted
//! on construction: nothing in this file may be given a seed that is not published.

use notyas_core::bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
use notyas_core::bitcoin::hex::FromHex;
use notyas_core::bitcoin::{Address, Network, ScriptBuf};
use notyas_core::derive::Scheme;
use notyas_core::multisig::{Keychain, Registration};
use notyas_core::psbt::fixture;
use notyas_core::sign::SecretSigningKey;
use notyas_core::{address, bip39, derive, multisig, sign};

/// The network every artifact is built for.
///
/// Mainnet, matching `notyas_core::psbt::fixture` and therefore the corpus the engine's own
/// tests pin. Check 5 (network isolation) reads the coin type of every origin, so a testnet
/// harness would be a second set of derivation paths and a second set of expected addresses
/// for no gain. Nothing here is broadcastable in any case - the funding transactions this
/// tool builds do not exist on any chain - so "mainnet" is a statement about derivation
/// paths and address prefixes, not about money.
pub const NETWORK: Network = Network::Bitcoin;

/// The passphrase every vector in the published file is stated under.
pub const PASSPHRASE: &str = "TREZOR";

/// The BIP-84 account the single-sig case spends from.
pub const ACCOUNT_84: &str = "m/84'/0'/0'";

/// The BIP-48 P2WSH account each cosigner of the multisig case sits on.
///
/// Taken from the crate's own fixtures rather than restated, so the harness wallet has the
/// shape the engine's tests are already pinned to and the two cannot drift.
pub const BIP48_ORIGIN: &str = fixture::BIP48_ORIGIN;

/// One published BIP-39 vector: the words, and the seed the upstream file states for them.
#[derive(Clone, Copy, Debug)]
pub struct Vector {
    /// Position in the `english` array of the upstream vectors file, so a reader can find
    /// this exact row rather than take the transcription on trust.
    pub upstream_index: usize,
    pub entropy: &'static str,
    pub mnemonic: &'static str,
    pub seed: &'static str,
}

/// The wallet the DEVICE is given. Upstream `english[0]`.
pub const DEVICE_VECTOR: Vector = Vector {
    upstream_index: 0,
    entropy: "00000000000000000000000000000000",
    mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
               abandon abandon about",
    seed: "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d182\
           64c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
};

/// The second member of the 2-of-3, and the payee of both generated spends. Upstream
/// `english[1]`.
pub const COSIGNER_B_VECTOR: Vector = Vector {
    upstream_index: 1,
    entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow",
    seed: "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559\
           a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
};

/// The third member of the 2-of-3. Upstream `english[2]`.
pub const COSIGNER_C_VECTOR: Vector = Vector {
    upstream_index: 2,
    entropy: "80808080808080808080808080808080",
    mnemonic: "letter advice cage absurd amount doctor acoustic avoid letter advice cage \
               above",
    seed: "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed\
           2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
};

/// A seed that came from a published vector, plus the derivations this harness needs of it.
#[derive(Debug)]
pub struct Wallet {
    /// How the artifacts and the refusals name this wallet.
    pub label: &'static str,
    pub vector: Vector,
    seed: [u8; 64],
}

impl Wallet {
    /// Derive the seed and prove it is the published one.
    ///
    /// The assertion is the reason this constructor exists at all. It is cheap, it runs
    /// before any artifact is written, and it turns two whole classes of silent failure - a
    /// mistyped word here, a broken PBKDF2 in the crate - into one message naming the
    /// vector that disagreed.
    pub fn new(label: &'static str, vector: Vector) -> Wallet {
        let seed = *bip39::seed(vector.mnemonic, PASSPHRASE);
        let published =
            <[u8; 64]>::from_hex(vector.seed).expect("a transcribed vector seed is 64 hex bytes");
        assert_eq!(
            seed, published,
            "{label}: bip39::seed does not reproduce the seed published for english[{}]",
            vector.upstream_index
        );
        Wallet {
            label,
            vector,
            seed,
        }
    }

    /// The seed itself. Published, so handing it out is not a leak; see the module docs.
    pub fn seed(&self) -> &[u8; 64] {
        &self.seed
    }

    pub fn fingerprint(&self) -> Fingerprint {
        derive::master_fingerprint(&self.seed, NETWORK)
    }

    pub fn key_at(&self, path: &DerivationPath) -> SecretSigningKey {
        sign::derive_path(&self.seed, NETWORK, path).expect("a harness path derives")
    }

    /// The account xpub at `origin`.
    ///
    /// Goes through `bitcoin::bip32` exactly as `psbt::fixture` does, and for the same
    /// reason: the node a cosigner is listed under in the descriptor has to be the node the
    /// crate itself derives, not a second rendering of it that could drift.
    pub fn xpub_at(&self, origin: &DerivationPath) -> Xpub {
        let secp = derive::secp();
        let master = Xpriv::new_master(NETWORK, &self.seed).expect("a 64-byte seed is a master");
        let account = master
            .derive_priv(secp, origin)
            .expect("a harness origin derives");
        Xpub::from_priv(secp, &account)
    }

    /// This wallet as one key expression of a `sortedmulti` descriptor: the origin, the
    /// account xpub, and the BIP-389 multipath tail that gives the wallet its two keychains.
    pub fn key_expression(&self) -> String {
        let origin = path(BIP48_ORIGIN);
        format!(
            "[{}/48h/0h/0h/2h]{}/<0;1>/*",
            self.fingerprint(),
            self.xpub_at(&origin)
        )
    }

    /// The BIP-84 single-sig leaf address.
    pub fn singlesig_address(&self, keychain: Keychain, index: u32) -> Address {
        let key = self.key_at(&singlesig_path(keychain, index));
        address::for_key(Scheme::Bip84, key.public_key(), NETWORK)
            .expect("BIP-84 renders a P2WPKH address")
    }

    /// The scriptPubKey behind [`Wallet::singlesig_address`].
    pub fn singlesig_script(&self, keychain: Keychain, index: u32) -> ScriptBuf {
        let key = self.key_at(&singlesig_path(keychain, index));
        ScriptBuf::new_p2wpkh(&key.public_key().wpubkey_hash())
    }
}

/// Parse a path this tool wrote itself. A failure here is a bug in this file, not input.
pub fn path(s: &str) -> DerivationPath {
    s.parse().expect("a harness path is well formed")
}

/// `m/84'/0'/0'/{0,1}/{index}`.
pub fn singlesig_path(keychain: Keychain, index: u32) -> DerivationPath {
    path(&format!("{ACCOUNT_84}/{}/{index}", chain_of(keychain)))
}

/// `m/48'/0'/0'/2'/{0,1}/{index}`, in the spelling a PSBT's `bip32_derivation` carries.
pub fn multisig_leaf_path(keychain: Keychain, index: u32) -> DerivationPath {
    path(&format!("{BIP48_ORIGIN}/{}/{index}", chain_of(keychain)))
}

/// The keychain's index, as a descriptor and a derivation path spell it.
pub fn chain_of(keychain: Keychain) -> u32 {
    match keychain {
        Keychain::Receive => 0,
        Keychain::Change => 1,
    }
}

/// The three wallets, the 2-of-3 they form, and the payee.
#[derive(Debug)]
pub struct Harness {
    /// The wallet the device is loaded with.
    pub device: Wallet,
    /// The other two members of the 2-of-3.
    ///
    /// The harness holds their seeds on purpose. Clause 2 asks whether a coordinator would
    /// accept what the device produced, and for a 2-of-3 that question cannot be answered
    /// by one signature: the coordinator has to be able to add the second, finalize and
    /// extract. See `verify::Coordinator::finalize`.
    pub cosigners: [Wallet; 2],
    registration: Registration,
}

impl Harness {
    /// Build the harness, proving as it goes that the device wallet really is a member of
    /// the 2-of-3 it is about to be asked to sign for.
    ///
    /// `Pending::verify` is that proof: it takes the seed and refuses unless one of the
    /// listed cosigner xpubs derives from it. So the descriptor this returns is one the
    /// device can be registered into, and a device that then refuses the multisig PSBT has
    /// said something about the device rather than about this file.
    pub fn new() -> Harness {
        let device = Wallet::new("device", DEVICE_VECTOR);
        let cosigners = [
            Wallet::new("cosigner-b", COSIGNER_B_VECTOR),
            Wallet::new("cosigner-c", COSIGNER_C_VECTOR),
        ];
        // Written without a checksum: the canonical checksummed form is what
        // `Pending::verify` produces, and hand-writing one here would pin the crate's
        // checksum arithmetic against a copy of itself.
        let descriptor = format!(
            "wsh(sortedmulti(2,{},{},{}))",
            device.key_expression(),
            cosigners[0].key_expression(),
            cosigners[1].key_expression()
        );
        let registration = multisig::parse(&descriptor)
            .expect("the harness descriptor parses")
            .verify(device.seed(), NETWORK)
            .expect("the device wallet is a member of the harness 2-of-3");
        Harness {
            device,
            cosigners,
            registration,
        }
    }

    /// The registered 2-of-3: the only thing that decides which P2WSH scripts are ours.
    pub fn registration(&self) -> &Registration {
        &self.registration
    }

    /// The canonical, checksummed descriptor: what goes on the card for the device to
    /// import, and what a coordinator would be given.
    pub fn descriptor(&self) -> &str {
        self.registration.descriptor()
    }

    /// Where both generated spends send their payment.
    ///
    /// Cosigner B's BIP-84 receive address. It is deterministic, it is derived from a
    /// published vector so a reader can rebuild it, and it is unmistakably not the device
    /// wallet - which is the whole requirement for a payee: the review screen has to show
    /// an address the device cannot claim as its own.
    pub fn payee(&self) -> Address {
        self.cosigners[0].singlesig_address(Keychain::Receive, 0)
    }

    pub fn payee_script(&self) -> ScriptBuf {
        self.cosigners[0].singlesig_script(Keychain::Receive, 0)
    }

    /// The script on the funding transactions' OTHER output.
    ///
    /// Cosigner C's receive address, for the same reason the payee is cosigner B's: it is
    /// an address this tree can rebuild and the device cannot claim. Its only job is to
    /// make the funding transaction have more than one output, so that a reader of a
    /// previous transaction which ignores the outpoint's `vout` is wrong instead of lucky.
    pub fn decoy_script(&self) -> ScriptBuf {
        self.cosigners[1].singlesig_script(Keychain::Receive, 0)
    }
}

impl Default for Harness {
    fn default() -> Self {
        Harness::new()
    }
}
