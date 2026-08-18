// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! BIP32/44/49/84/86 derivation (SPEC step 9).
//!
//! This is thin orchestration over rust-bitcoin: the crate owns the elliptic curve, the
//! base58 and bech32 encodings and the taproot tweak, and this module only decides which
//! paths to walk and how to render each row. Nothing here is allowed to generate keys
//! from anything but the supplied seed.

use core::fmt;
use core::sync::atomic::{AtomicPtr, Ordering};

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use bitcoin::bip32::{ChainCode, ChildNumber, DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::key::{CompressedPublicKey, UntweakedKeypair};
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{Address, Network, PrivateKey};
use zeroize::Zeroize;

/// SLIP-132 alternative version bytes. They change ONLY the four leading version bytes of
/// the serialized extended key; the key data is identical to the xprv/xpub rendering of
/// the very same account node, which is why both are shown side by side.
pub const YPRV: [u8; 4] = [0x04, 0x9d, 0x78, 0x78];
pub const YPUB: [u8; 4] = [0x04, 0x9d, 0x7c, 0xb2];
pub const ZPRV: [u8; 4] = [0x04, 0xb2, 0x43, 0x0c];
pub const ZPUB: [u8; 4] = [0x04, 0xb2, 0x47, 0x46];

/// A BIP32 child index: any value below 2^31.
///
/// The constructor is the only statement of that rule in the crate. Above 2^31 the number
/// collides with the hardened flag, so `m/44h/0h/{account}h` would silently not be the path
/// the user asked for; refusing it here means nothing downstream re-validates and no public
/// function of this module can be made to panic by an index its own types accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct ChildIndex(u32);

impl ChildIndex {
    /// Largest representable index; 2^31 and above is the hardened half of the space.
    pub const MAX: u32 = 0x7fff_ffff;

    /// Index 0, the default account, change level and address.
    pub const ZERO: ChildIndex = ChildIndex(0);

    /// The only way to build a [`ChildIndex`]; `None` for anything at or above 2^31.
    pub fn new(index: u32) -> Option<Self> {
        (index <= Self::MAX).then_some(ChildIndex(index))
    }

    pub fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ChildIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The supported address schemes, each pinned to its BIP44 purpose value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// m/44h/0h/Ah/C/i, P2PKH (legacy "1..." addresses).
    Bip44,
    /// m/49h/0h/Ah/C/i, P2SH-P2WPKH (wrapped segwit "3..." addresses), SLIP-132 y-keys.
    Bip49,
    /// m/84h/0h/Ah/C/i, P2WPKH (native segwit bech32), SLIP-132 z-keys.
    Bip84,
    /// m/86h/0h/Ah/C/i, P2TR key-path per BIP341 (internal key tweaked with an empty
    /// merkle root), bech32m.
    Bip86,
    /// m/48h/0h/Ah/STh/C/i, BIP48 multisig. No address rows: multisig addresses require
    /// cosigner xpubs that this tool does not accept. The account xprv/xpub is what gets
    /// imported into a multisig coordinator (Sparrow, Electrum). Plain xprv/xpub only -
    /// SLIP-132 prefixes are single-sig and must not be used for multisig keys.
    Bip48,
}

impl Scheme {
    /// Report order used by `--scheme all` and by the JSON `schemes` array.
    pub const ALL: [Scheme; 4] = [Scheme::Bip44, Scheme::Bip49, Scheme::Bip84, Scheme::Bip86];

    /// Lowercase identifier used on the command line and in JSON output.
    pub fn name(self) -> &'static str {
        match self {
            Scheme::Bip44 => "bip44",
            Scheme::Bip49 => "bip49",
            Scheme::Bip84 => "bip84",
            Scheme::Bip86 => "bip86",
            Scheme::Bip48 => "bip48",
        }
    }

    /// The hardened purpose index of the scheme (44, 48, 49, 84 or 86).
    pub fn purpose(self) -> u32 {
        match self {
            Scheme::Bip44 => 44,
            Scheme::Bip48 => 48,
            Scheme::Bip49 => 49,
            Scheme::Bip84 => 84,
            Scheme::Bip86 => 86,
        }
    }

    /// SLIP-132 version bytes and report labels for the account node, `None` where the
    /// ecosystem renders the account as plain xprv/xpub (BIP44 and BIP86, matching
    /// iancoleman and bip-utils).
    ///
    /// One match arm per scheme decides both, so the keys a scheme produces and the lines
    /// the report has to show them on can never disagree; a new scheme is a single edit.
    fn slip132(self) -> Option<Slip132> {
        match self {
            Scheme::Bip49 => Some(Slip132 {
                versions: (YPRV, YPUB),
                labels: ("Account yprv", "Account ypub"),
            }),
            Scheme::Bip84 => Some(Slip132 {
                versions: (ZPRV, ZPUB),
                labels: ("Account zprv", "Account zpub"),
            }),
            Scheme::Bip44 | Scheme::Bip86 | Scheme::Bip48 => None,
        }
    }

    /// SLIP-132 line labels (private, public) for the account node, `None` for the schemes
    /// that have no SLIP-132 rendering. Exactly the schemes for which
    /// [`AccountKeys::slip132_prv`] is `Some`.
    pub fn slip132_labels(self) -> Option<(&'static str, &'static str)> {
        self.slip132().map(|s| s.labels)
    }
}

/// The SLIP-132 facts about one scheme: what the version bytes are and what the report
/// calls the resulting keys.
#[derive(Clone, Copy)]
struct Slip132 {
    versions: ([u8; 4], [u8; 4]),
    labels: (&'static str, &'static str),
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl core::str::FromStr for Scheme {
    type Err = ();

    /// Accepts exactly "bip44", "bip48", "bip49", "bip84", "bip86" (case-insensitive). The
    /// "all" keyword is a CLI concept and is handled there, not here.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for scheme in Scheme::ALL {
            if s.eq_ignore_ascii_case(scheme.name()) {
                return Ok(scheme);
            }
        }
        if s.eq_ignore_ascii_case("bip48") {
            return Ok(Scheme::Bip48);
        }
        Err(())
    }
}

/// The account-level node of one scheme, rendered every way the report shows it.
#[derive(Clone)]
pub struct AccountKeys {
    /// Account path in `m/84h/0h/0h` shape, printed with `'` for hardened to match the
    /// iancoleman page.
    pub path: String,
    pub xprv: String,
    pub xpub: String,
    /// SLIP-132 rendering of the SAME node: yprv/zprv for BIP49/84, `None` otherwise.
    pub slip132_prv: Option<String>,
    /// SLIP-132 rendering of the SAME node: ypub/zpub for BIP49/84, `None` otherwise.
    pub slip132_pub: Option<String>,
}

impl Drop for AccountKeys {
    /// The private renderings are spending authority for the whole account, so the value
    /// that owns them wipes them. Doing it here rather than in the caller means every
    /// consumer of this module gets it, not just the CLI's report.
    fn drop(&mut self) {
        self.xprv.zeroize();
        if let Some(prv) = &mut self.slip132_prv {
            prv.zeroize();
        }
    }
}

impl fmt::Debug for AccountKeys {
    /// Hand written rather than derived: an extended private key is spending authority for
    /// the whole account, and `{:?}` would copy it somewhere nothing wipes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountKeys")
            .field("path", &self.path)
            .field("xprv", &"<redacted>")
            .field("xpub", &self.xpub)
            .field(
                "slip132_prv",
                &self.slip132_prv.as_ref().map(|_| "<redacted>"),
            )
            .field("slip132_pub", &self.slip132_pub)
            .finish()
    }
}

/// One derived address row of the report.
#[derive(Clone)]
pub struct AddressRow {
    /// Full path of the leaf, e.g. `m/84'/0'/0'/0/3`.
    pub path: String,
    pub address: String,
    /// Compressed public key, 33 bytes, lowercase hex. For BIP86 this is still the
    /// 33-byte compressed key (as the iancoleman page shows), not the x-only key.
    pub pubkey: String,
    /// Private key in compressed WIF form.
    pub wif: String,
}

impl Drop for AddressRow {
    /// `wif` is the spending key for this row; see the `AccountKeys` Drop impl for why the
    /// wipe lives with the value rather than with the report that prints it.
    fn drop(&mut self) {
        self.wif.zeroize();
    }
}

impl fmt::Debug for AddressRow {
    /// Hand written rather than derived: `wif` is the spending key for this row.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddressRow")
            .field("path", &self.path)
            .field("address", &self.address)
            .field("pubkey", &self.pubkey)
            .field("wif", &"<redacted>")
            .finish()
    }
}

/// Everything one scheme contributes to the report.
#[derive(Debug, Clone)]
pub struct Derived {
    pub account: AccountKeys,
    pub rows: Vec<AddressRow>,
}

/// BIP32 root key serialization for the given network (SPEC step 9).
///
/// The seed is the 64-byte PBKDF2 output; the master node is HMAC-SHA512("Bitcoin seed").
/// Returns `xprv...` on mainnet and `tprv...` on testnet.
pub fn root_xprv(seed: &[u8; 64], network: bitcoin::Network) -> String {
    master(seed, network).key().to_string()
}

/// The master fingerprint: first 4 bytes of HASH160 of the master public key.
///
/// This is a public identifier (not a secret). Hardware wallets display it so a user
/// can confirm two devices hold the same wallet without exposing any key.
///
/// The typed form is the one the signing path and PSBT key sources want (a PSBT's
/// `bip32_derivation` is a `(Fingerprint, DerivationPath)` pair);
/// [`root_fingerprint`] is the same value rendered for a screen.
pub fn master_fingerprint(seed: &[u8; 64], network: bitcoin::Network) -> Fingerprint {
    let secp = secp();
    let root = master(seed, network);
    Xpub::from_priv(secp, root.key()).fingerprint()
}

/// [`master_fingerprint`] as the 8-character lowercase hex string the report and the
/// Verify screen print, e.g. `73c5da0a`.
pub fn root_fingerprint(seed: &[u8; 64], network: bitcoin::Network) -> String {
    master_fingerprint(seed, network).to_string()
}

/// Derive one scheme's account keys and `count` address rows (SPEC step 9).
///
/// SPEC obligations:
/// - Account node is `m/{purpose}h/{coin}h/{account}h`, where coin is 0 on mainnet and 1
///   on testnet; leaves are `.../{change}/{i}` for `i` in `0..count`.
/// - Renderings: BIP44 P2PKH, BIP49 P2SH-P2WPKH, BIP84 P2WPKH bech32, BIP86 P2TR
///   key-path with an empty merkle root (`Address::p2tr(secp, xonly, None, network)`).
/// - BIP49 and BIP84 additionally expose the account node under the SLIP-132 version
///   bytes ([`YPRV`]/[`YPUB`], [`ZPRV`]/[`ZPUB`]): take the 78-byte `Xpriv::encode` /
///   `Xpub::encode`, overwrite bytes 0..4, base58check-encode the result. BIP44 and BIP86
///   leave both `slip132_*` fields `None`.
/// - WIF is the compressed form for the given network.
///
/// Derivation is infallible for the indices this program can produce ([`ChildIndex`] cannot
/// hold one that is not); any error from rust-bitcoin here is a bug and should panic with a
/// message naming the path, which is why this returns `Derived` rather than a `Result`.
///
/// Panics if `count` is above [`ChildIndex::MAX`], i.e. if the last row would need an
/// address index outside the non-hardened half of the space.
pub fn derive(
    seed: &[u8; 64],
    network: bitcoin::Network,
    scheme: Scheme,
    account: ChildIndex,
    change: ChildIndex,
    count: u32,
    script_type: u32,
) -> Derived {
    assert!(
        count <= ChildIndex::MAX,
        "count {count} would need an address index above {}",
        ChildIndex::MAX
    );
    let secp = secp();
    let root = master(seed, network);

    let coin = coin_type(network);

    // BIP48 has a 4th hardened level: script_type. The path is
    // m/48'/coin'/account'/script_type', and no address rows are derived because
    // multisig addresses require cosigner xpubs this tool does not accept.
    let (account_path, node) = if scheme == Scheme::Bip48 {
        let st = ChildIndex::new(script_type).unwrap_or(ChildIndex::ZERO);
        let path = format!("m/{}'/{}'/{}'/{}'", scheme.purpose(), coin, account, st);
        // NOTE: format renders as m/48'/0'/0'/2' - all four levels hardened
        let node = derive_child(
            secp,
            root.key(),
            &DerivationPath::from(vec![
                hardened(fixed_index(scheme.purpose())),
                hardened(fixed_index(coin)),
                hardened(account),
                hardened(st),
            ]),
            &path,
        );
        (path, node)
    } else {
        let path = format!("m/{}'/{}'/{}'", scheme.purpose(), coin, account);
        let node = derive_child(
            secp,
            root.key(),
            &DerivationPath::from(vec![
                hardened(fixed_index(scheme.purpose())),
                hardened(fixed_index(coin)),
                hardened(account),
            ]),
            &path,
        );
        (path, node)
    };
    let node_pub = Xpub::from_priv(secp, node.key());

    let (slip132_prv, slip132_pub) = match scheme.slip132() {
        // SLIP-132 assigns version bytes per network; only the mainnet set is specified
        // here, so a testnet run stays with tprv/tpub alone rather than mislabelling keys.
        Some(slip) if network == Network::Bitcoin => (
            Some(reversion(node.key().encode(), slip.versions.0)),
            Some(reversion(node_pub.encode(), slip.versions.1)),
        ),
        _ => (None, None),
    };

    // BIP48 produces no address rows: multisig address construction requires cosigner
    // xpubs, which are external input this tool does not accept. The account xprv/xpub
    // is what gets imported into a coordinator (Sparrow, Electrum).
    let rows: Vec<AddressRow> = if scheme == Scheme::Bip48 {
        Vec::new()
    } else {
        let change_step = normal(change);
        (0..count)
            .map(|index| {
                let index = ChildIndex::new(index)
                    .expect("count is checked against ChildIndex::MAX by the caller");
                let path = format!("{account_path}/{change}/{index}");
                let child = derive_child(secp, node.key(), &[change_step, normal(index)], &path);
                let mut key = PrivateKey::new(child.key().private_key, network);
                let pubkey = CompressedPublicKey::from_private_key(secp, &key)
                    .expect("PrivateKey::new yields a compressed key");
                let row = AddressRow {
                    path,
                    address: address(scheme, secp, child.key(), pubkey, network),
                    pubkey: pubkey.to_string(),
                    wif: key.to_wif(),
                };
                key.inner.non_secure_erase();
                row
            })
            .collect()
    };

    Derived {
        account: AccountKeys {
            path: account_path,
            xprv: node.key().to_string(),
            xpub: node_pub.to_string(),
            slip132_prv,
            slip132_pub,
        },
        rows,
    }
}

/// The scheme's payment address for one leaf.
///
/// BIP86 tweaks the internal key with an empty merkle root (BIP341 key-path spend); the
/// untweaked key is what the row reports as `pubkey` and encodes as WIF, so the tweak must
/// not escape this function.
fn address(
    scheme: Scheme,
    secp: &Secp256k1<All>,
    child: &Xpriv,
    pubkey: CompressedPublicKey,
    network: Network,
) -> String {
    match scheme {
        Scheme::Bip44 => Address::p2pkh(pubkey, network).to_string(),
        Scheme::Bip49 => Address::p2shwpkh(&pubkey, network).to_string(),
        Scheme::Bip84 => Address::p2wpkh(&pubkey, network).to_string(),
        // BIP48 never reaches here: derive() produces no address rows for it.
        Scheme::Bip48 => unreachable!("BIP48 produces no address rows"),
        Scheme::Bip86 => {
            let mut keypair = UntweakedKeypair::from_secret_key(secp, &child.private_key);
            let (internal_key, _parity) = keypair.x_only_public_key();
            let address = Address::p2tr(secp, internal_key, None, network).to_string();
            keypair.non_secure_erase();
            address
        }
    }
}

/// The one secp256k1 context of the process.
///
/// Public because it is a crate-wide resource, not a detail of this module: [`crate::sign`]
/// and every front end that has to call rust-bitcoin directly must reach THIS context
/// rather than build a second one, which on the device would cost a second copy of the
/// precomputed tables for no benefit.
///
/// Building a context is pure computation over the curve constants, so sharing it changes
/// nothing but the cost - `--scheme all` would otherwise build four. It is deliberately
/// never randomized: randomization would need an OS RNG, which this program must not use.
///
/// The desktop crate keeps the context in a `std::sync::OnceLock`; no_std has no blocking
/// primitive to replace that with, so this is the racy-init pattern instead (the same one
/// `once_cell::race` implements, hand-rolled here to avoid a dependency for fifteen
/// lines): the first caller through publishes a leaked `Box` with a compare-exchange, and
/// a concurrent loser frees its own candidate and adopts the winner's. Initialization may
/// run more than once under contention; exactly one result is ever published, every caller
/// sees that one, and the context is identical whoever builds it (curve constants, no
/// randomization), so the race is unobservable. The single published context is
/// deliberately never freed - it lives for the process, exactly as the OnceLock did.
pub fn secp() -> &'static Secp256k1<All> {
    static CONTEXT: AtomicPtr<Secp256k1<All>> = AtomicPtr::new(core::ptr::null_mut());
    let mut published = CONTEXT.load(Ordering::Acquire);
    if published.is_null() {
        let candidate = Box::into_raw(Box::new(Secp256k1::new()));
        match CONTEXT.compare_exchange(
            core::ptr::null_mut(),
            candidate,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => published = candidate,
            Err(winner) => {
                // SAFETY: `candidate` came from Box::into_raw above and lost the race, so
                // this thread is its only owner and nothing else has seen the pointer.
                drop(unsafe { Box::from_raw(candidate) });
                published = winner;
            }
        }
    }
    // SAFETY: a non-null value in CONTEXT is always a pointer published by the
    // compare-exchange above, never removed or mutated afterwards, so it is valid for the
    // rest of the process.
    unsafe { &*published }
}

/// An extended private key that erases its secret material when it goes out of scope.
///
/// `Xpriv` is a plain value type: rust-bitcoin gives it no `Drop`, so the master node, the
/// account node and every leaf this module derives would otherwise be left behind in freed
/// stack frames and heap after the report itself has been wiped. Wrapping it is the only
/// way to meet that obligation for the KEYS, as opposed to their string renderings.
///
/// The wipe is best effort in the same sense as `SecretKey::non_secure_erase`: it overwrites
/// the copy this value owns, and cannot follow copies the compiler made in registers.
pub(crate) struct SecretXpriv(Xpriv);

impl SecretXpriv {
    pub(crate) fn new(xpriv: Xpriv) -> Self {
        SecretXpriv(xpriv)
    }

    pub(crate) fn key(&self) -> &Xpriv {
        &self.0
    }
}

impl Drop for SecretXpriv {
    fn drop(&mut self) {
        self.0.private_key.non_secure_erase();
        // `ChainCode` has no interior mutation, so overwrite it wholesale: on its own it
        // cannot spend, but paired with the public key it derives every child.
        self.0.chain_code = ChainCode::from([0u8; 32]);
    }
}

pub(crate) fn master(seed: &[u8; 64], network: Network) -> SecretXpriv {
    // A 64-byte seed is always within BIP32's accepted length and the chance of the master
    // scalar landing outside the curve order is negligible, so failure here is not a user
    // error but a broken build.
    SecretXpriv(
        Xpriv::new_master(network, seed).expect("64-byte seed is a valid BIP32 master seed"),
    )
}

/// BIP44 coin type: 0 for mainnet, 1 for every test chain (SLIP-44).
fn coin_type(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 0,
        _ => 1,
    }
}

fn derive_child<P: AsRef<[ChildNumber]>>(
    secp: &Secp256k1<All>,
    parent: &Xpriv,
    path: &P,
    label: &str,
) -> SecretXpriv {
    SecretXpriv(
        parent
            .derive_priv(secp, path)
            .unwrap_or_else(|e| panic!("BIP32 derivation of {label} failed: {e}")),
    )
}

/// A structural constant of this module (a purpose or a coin type) as a child index.
fn fixed_index(value: u32) -> ChildIndex {
    ChildIndex::new(value).expect("purposes and coin types are small constants")
}

fn hardened(index: ChildIndex) -> ChildNumber {
    ChildNumber::from_hardened_idx(index.get()).expect("a ChildIndex is below 2^31")
}

fn normal(index: ChildIndex) -> ChildNumber {
    ChildNumber::from_normal_idx(index.get()).expect("a ChildIndex is below 2^31")
}

/// Re-encode a 78-byte extended key under different version bytes (SLIP-132).
///
/// The remaining 74 bytes are copied verbatim: the SLIP-132 form is the same key, only
/// labelled with the script type it is meant for. `raw` is a serialized private key on the
/// yprv/zprv side, so this owns it and wipes it rather than dropping it as it came in.
fn reversion(mut raw: [u8; 78], version: [u8; 4]) -> String {
    raw[..4].copy_from_slice(&version);
    let encoded = bitcoin::base58::encode_check(&raw);
    raw.zeroize();
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Ground truth generated by python bip-utils, independent of this implementation.
    /// Embedded, like every vector file in this crate; see the desktop crate's
    /// `tests/vectors/README.md`.
    const VECTORS: &str = include_str!("../tests/vectors/derivation_vectors.json");

    fn seed_from_hex(hex_str: &str) -> [u8; 64] {
        let bytes = hex::decode(hex_str).expect("vector seed is hex");
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&bytes);
        seed
    }

    fn vectors() -> Value {
        serde_json::from_str(VECTORS).expect("vector file is valid JSON")
    }

    fn scheme_by_name(name: &str) -> Scheme {
        name.parse().expect("vector scheme name is known")
    }

    /// Shorthand for the tests; every index used here is in range.
    fn index(value: u32) -> ChildIndex {
        ChildIndex::new(value).expect("test uses an in-range child index")
    }

    #[test]
    fn matches_reference_vectors() {
        let doc = vectors();
        let all = doc["vectors"].as_object().expect("vectors object");
        assert_eq!(all.len(), 20, "vector file lost entries");

        let mut checked_rows = 0usize;
        for (name, vector) in all {
            // The reference derives from the no-passphrase seed.
            let seed = seed_from_hex(vector["seed_hex_nopass"].as_str().unwrap());
            assert_eq!(
                root_xprv(&seed, Network::Bitcoin),
                vector["root_xprv"].as_str().unwrap(),
                "{name}: root xprv"
            );

            let schemes = vector["schemes"].as_object().unwrap();
            assert_eq!(schemes.len(), 4, "{name}: scheme count");
            for (scheme_name, want) in schemes {
                let scheme = scheme_by_name(scheme_name);
                let got = derive(
                    &seed,
                    Network::Bitcoin,
                    scheme,
                    ChildIndex::ZERO,
                    ChildIndex::ZERO,
                    5,
                    0,
                );
                let at = format!("{name}/{scheme_name}");

                assert_eq!(
                    got.account.path,
                    want["account_path"].as_str().unwrap(),
                    "{at}: account path"
                );
                assert_eq!(
                    got.account.xprv,
                    want["account_xprv"].as_str().unwrap(),
                    "{at}: account xprv"
                );
                assert_eq!(
                    got.account.xpub,
                    want["account_xpub"].as_str().unwrap(),
                    "{at}: account xpub"
                );

                match scheme {
                    Scheme::Bip49 | Scheme::Bip84 => {
                        let (prv_key, pub_key) = if scheme == Scheme::Bip49 {
                            ("account_yprv", "account_ypub")
                        } else {
                            ("account_zprv", "account_zpub")
                        };
                        assert_eq!(
                            got.account.slip132_prv.as_deref(),
                            Some(
                                want[prv_key].as_str().unwrap_or_else(|| {
                                    panic!("{at}: reference lost {prv_key}")
                                })
                            ),
                            "{at}: SLIP-132 private"
                        );
                        assert_eq!(
                            got.account.slip132_pub.as_deref(),
                            Some(
                                want[pub_key].as_str().unwrap_or_else(|| {
                                    panic!("{at}: reference lost {pub_key}")
                                })
                            ),
                            "{at}: SLIP-132 public"
                        );
                    }
                    // Absence is the assertion here, on both sides: SLIP-132 is defined
                    // only for bip49 and bip84, so a reference that grew one of those keys
                    // under bip44/bip86 is a changed reference, not a passing test.
                    Scheme::Bip44 | Scheme::Bip86 | Scheme::Bip48 => {
                        assert!(
                            got.account.slip132_prv.is_none() && got.account.slip132_pub.is_none(),
                            "{at}: SLIP-132 is defined only for bip49 and bip84"
                        );
                        for key in [
                            "account_yprv",
                            "account_ypub",
                            "account_zprv",
                            "account_zpub",
                        ] {
                            assert!(want.get(key).is_none(), "{at}: reference gained {key}");
                        }
                    }
                }

                let rows = want["rows"].as_array().unwrap();
                assert_eq!(got.rows.len(), rows.len(), "{at}: row count");
                for (i, (row, want_row)) in got.rows.iter().zip(rows).enumerate() {
                    assert_eq!(
                        row.path,
                        want_row["path"].as_str().unwrap(),
                        "{at}/{i}: path"
                    );
                    assert_eq!(
                        row.address,
                        want_row["address"].as_str().unwrap(),
                        "{at}/{i}: address"
                    );
                    assert_eq!(
                        row.pubkey,
                        want_row["pubkey"].as_str().unwrap(),
                        "{at}/{i}: pubkey"
                    );
                    assert_eq!(row.wif, want_row["wif"].as_str().unwrap(), "{at}/{i}: wif");
                    checked_rows += 1;
                }
            }
        }
        assert_eq!(checked_rows, 20 * 4 * 5, "not every row was compared");
    }

    fn sample_seed() -> [u8; 64] {
        let doc = vectors();
        seed_from_hex(
            doc["vectors"]["v100_raw"]["seed_hex_nopass"]
                .as_str()
                .unwrap(),
        )
    }

    /// SLIP-132 must be a relabelling, never a re-derivation: the 74 payload bytes have to
    /// survive byte for byte.
    #[test]
    fn slip132_differs_only_in_version_bytes() {
        let seed = sample_seed();
        for (scheme, prv_version, pub_version) in
            [(Scheme::Bip49, YPRV, YPUB), (Scheme::Bip84, ZPRV, ZPUB)]
        {
            let d = derive(
                &seed,
                Network::Bitcoin,
                scheme,
                ChildIndex::ZERO,
                ChildIndex::ZERO,
                1,
                0,
            );
            for (xkey, slip, version) in [
                (
                    &d.account.xprv,
                    d.account.slip132_prv.as_ref().unwrap(),
                    prv_version,
                ),
                (
                    &d.account.xpub,
                    d.account.slip132_pub.as_ref().unwrap(),
                    pub_version,
                ),
            ] {
                let plain = bitcoin::base58::decode_check(xkey).unwrap();
                let alt = bitcoin::base58::decode_check(slip).unwrap();
                assert_eq!(plain.len(), 78);
                assert_eq!(alt.len(), 78);
                assert_eq!(&alt[..4], &version[..], "{scheme}: version bytes");
                assert_eq!(&alt[4..], &plain[4..], "{scheme}: payload changed");
            }
        }
    }

    #[test]
    fn address_prefixes_per_scheme() {
        let seed = sample_seed();
        let expect: [(Scheme, &str); 4] = [
            (Scheme::Bip44, "1"),
            (Scheme::Bip49, "3"),
            (Scheme::Bip84, "bc1q"),
            (Scheme::Bip86, "bc1p"),
        ];
        for (scheme, prefix) in expect {
            for row in derive(
                &seed,
                Network::Bitcoin,
                scheme,
                ChildIndex::ZERO,
                ChildIndex::ZERO,
                3,
                0,
            )
            .rows
            {
                assert!(
                    row.address.starts_with(prefix),
                    "{scheme}: {} does not start with {prefix}",
                    row.address
                );
                assert!(
                    row.wif.starts_with('K') || row.wif.starts_with('L'),
                    "{scheme}: {} is not a compressed mainnet WIF",
                    row.wif
                );
                assert_eq!(
                    row.pubkey.len(),
                    66,
                    "{scheme}: pubkey is not 33 bytes of hex"
                );
            }
        }
    }

    /// The rows must live on the requested account and change chain, and the leaf public
    /// keys must agree with public-only derivation from the account xpub - an independent
    /// check of the non-hardened leg for indexes the vector file does not cover.
    #[test]
    fn honours_account_and_change_and_agrees_with_public_derivation() {
        let seed = sample_seed();
        let secp = secp();
        let (account, change) = (index(7), index(1));
        for scheme in Scheme::ALL {
            let d = derive(&seed, Network::Bitcoin, scheme, account, change, 4, 0);
            assert_eq!(
                d.account.path,
                format!("m/{}'/0'/{account}'", scheme.purpose())
            );

            let xpub: Xpub = d.account.xpub.parse().unwrap();
            for (i, row) in d.rows.iter().enumerate() {
                assert_eq!(
                    row.path,
                    format!("m/{}'/0'/{account}'/{change}/{i}", scheme.purpose())
                );
                let child = xpub
                    .derive_pub(secp, &[normal(change), normal(index(i as u32))])
                    .unwrap();
                assert_eq!(row.pubkey, child.public_key.to_string(), "{scheme}/{i}");
            }
        }
    }

    #[test]
    fn testnet_uses_coin_type_one_and_no_slip132() {
        let seed = sample_seed();
        assert!(root_xprv(&seed, Network::Testnet).starts_with("tprv"));
        for scheme in Scheme::ALL {
            let d = derive(
                &seed,
                Network::Testnet,
                scheme,
                ChildIndex::ZERO,
                ChildIndex::ZERO,
                1,
                0,
            );
            assert_eq!(d.account.path, format!("m/{}'/1'/0'", scheme.purpose()));
            assert!(d.account.xprv.starts_with("tprv"));
            assert!(d.account.xpub.starts_with("tpub"));
            assert!(d.account.slip132_prv.is_none() && d.account.slip132_pub.is_none());
            let address = &d.rows[0].address;
            let ok = match scheme {
                Scheme::Bip44 => address.starts_with('m') || address.starts_with('n'),
                Scheme::Bip49 => address.starts_with('2'),
                Scheme::Bip84 => address.starts_with("tb1q"),
                Scheme::Bip86 => address.starts_with("tb1p"),
                // BIP48 has no address rows, so this is unreachable for it.
                Scheme::Bip48 => unreachable!("BIP48 has no testnet address rows"),
            };
            assert!(ok, "{scheme}: unexpected testnet address {address}");
        }
    }

    #[test]
    fn zero_count_yields_account_only() {
        let seed = sample_seed();
        let d = derive(
            &seed,
            Network::Bitcoin,
            Scheme::Bip84,
            ChildIndex::ZERO,
            ChildIndex::ZERO,
            0,
            0,
        );
        assert!(d.rows.is_empty());
        assert!(d.account.xprv.starts_with("xprv"));
    }

    /// The rule lives in one place now: an index at or above 2^31 cannot be built, so no
    /// caller can hand `derive` one and no derivation path can silently become hardened.
    #[test]
    fn child_indexes_stop_below_the_hardened_half() {
        assert_eq!(ChildIndex::new(0).map(ChildIndex::get), Some(0));
        assert_eq!(
            ChildIndex::new(ChildIndex::MAX).map(ChildIndex::get),
            Some(ChildIndex::MAX)
        );
        assert_eq!(ChildIndex::new(0x8000_0000), None);
        assert_eq!(ChildIndex::new(u32::MAX), None);
        assert_eq!(ChildIndex::ZERO.to_string(), "0");
        assert_eq!(index(7).to_string(), "7");
    }

    /// The labels and the version bytes come from one decision, so a scheme either has
    /// both or neither - the report can never end up with a key it has no line for.
    #[test]
    fn slip132_labels_track_the_keys_that_exist() {
        let seed = sample_seed();
        for scheme in Scheme::ALL {
            let d = derive(
                &seed,
                Network::Bitcoin,
                scheme,
                ChildIndex::ZERO,
                ChildIndex::ZERO,
                1,
                0,
            );
            assert_eq!(
                scheme.slip132_labels().is_some(),
                d.account.slip132_prv.is_some(),
                "{scheme}: labels and keys disagree"
            );
            assert_eq!(
                d.account.slip132_prv.is_some(),
                d.account.slip132_pub.is_some(),
                "{scheme}: only half of the SLIP-132 pair"
            );
        }
        assert_eq!(
            Scheme::Bip49.slip132_labels(),
            Some(("Account yprv", "Account ypub"))
        );
        assert_eq!(
            Scheme::Bip84.slip132_labels(),
            Some(("Account zprv", "Account zpub"))
        );
        assert_eq!(Scheme::Bip44.slip132_labels(), None);
    }

    #[test]
    fn scheme_round_trips_through_str() {
        for scheme in Scheme::ALL {
            assert_eq!(scheme.name().parse::<Scheme>(), Ok(scheme));
            assert_eq!(
                scheme.to_string().to_uppercase().parse::<Scheme>(),
                Ok(scheme)
            );
        }
        assert_eq!("all".parse::<Scheme>(), Err(()));
        // BIP48 is not in Scheme::ALL, so test it explicitly.
        assert_eq!("bip48".parse::<Scheme>(), Ok(Scheme::Bip48));
        assert_eq!("BIP48".parse::<Scheme>(), Ok(Scheme::Bip48));
    }

    /// BIP48 derives account keys at m/48'/coin'/account'/script_type' with a 4th
    /// hardened level, produces no address rows, and uses plain xprv/xpub (no SLIP-132).
    #[test]
    fn bip48_account_keys_and_no_address_rows() {
        let seed = sample_seed();
        for st in [0u32, 1, 2] {
            let d = derive(
                &seed,
                Network::Bitcoin,
                Scheme::Bip48,
                ChildIndex::ZERO,
                ChildIndex::ZERO,
                5, // count is ignored for BIP48
                st,
            );
            // Path has 4 hardened levels: m/48'/0'/0'/st'
            assert_eq!(
                d.account.path,
                format!("m/48'/0'/0'/{}'", st),
                "script_type {st}: path"
            );
            // No address rows - multisig needs cosigner xpubs.
            assert!(d.rows.is_empty(), "script_type {st}: BIP48 must have no rows");
            // Plain xprv/xpub, no SLIP-132 (single-sig prefixes must not label multisig keys).
            assert!(d.account.xprv.starts_with("xprv"), "script_type {st}: xprv");
            assert!(d.account.xpub.starts_with("xpub"), "script_type {st}: xpub");
            assert!(
                d.account.slip132_prv.is_none() && d.account.slip132_pub.is_none(),
                "script_type {st}: BIP48 must not have SLIP-132 keys"
            );
        }
    }

    /// BIP48 on testnet uses coin type 1 and tprv/tpub.
    #[test]
    fn bip48_testnet() {
        let seed = sample_seed();
        let d = derive(
            &seed,
            Network::Testnet,
            Scheme::Bip48,
            ChildIndex::ZERO,
            ChildIndex::ZERO,
            0,
            2,
        );
        assert_eq!(d.account.path, "m/48'/1'/0'/2'");
        assert!(d.account.xprv.starts_with("tprv"));
        assert!(d.account.xpub.starts_with("tpub"));
        assert!(d.rows.is_empty());
    }

    /// BIP48 with a non-zero account index derives the correct path.
    #[test]
    fn bip48_account_index() {
        let seed = sample_seed();
        let d = derive(
            &seed,
            Network::Bitcoin,
            Scheme::Bip48,
            index(3),
            ChildIndex::ZERO,
            0,
            1, // P2WSH
        );
        assert_eq!(d.account.path, "m/48'/0'/3'/1'");
        assert!(d.rows.is_empty());
    }

    /// Different script types produce different account keys.
    #[test]
    fn bip48_script_types_produce_different_keys() {
        let seed = sample_seed();
        let st0 = derive(&seed, Network::Bitcoin, Scheme::Bip48, ChildIndex::ZERO, ChildIndex::ZERO, 0, 0);
        let st1 = derive(&seed, Network::Bitcoin, Scheme::Bip48, ChildIndex::ZERO, ChildIndex::ZERO, 0, 1);
        let st2 = derive(&seed, Network::Bitcoin, Scheme::Bip48, ChildIndex::ZERO, ChildIndex::ZERO, 0, 2);
        assert_ne!(st0.account.xpub, st1.account.xpub, "st0 vs st1");
        assert_ne!(st1.account.xpub, st2.account.xpub, "st1 vs st2");
        assert_ne!(st0.account.xpub, st2.account.xpub, "st0 vs st2");
    }
}
