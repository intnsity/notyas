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
use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::{Network, PrivateKey, ScriptBuf};
use zeroize::{Zeroize, Zeroizing};

// One wallet has one notion of an internal keychain and m7's type is it, exactly as
// `crate::address` re-exports it rather than declaring a second.
use crate::multisig::Keychain;

/// SLIP-132 alternative version bytes. They change ONLY the four leading version bytes of
/// the serialized extended key; the key data is identical to the xprv/xpub rendering of
/// the very same account node, which is why both are shown side by side.
pub const YPRV: [u8; 4] = [0x04, 0x9d, 0x78, 0x78];
pub const YPUB: [u8; 4] = [0x04, 0x9d, 0x7c, 0xb2];
pub const ZPRV: [u8; 4] = [0x04, 0xb2, 0x43, 0x0c];
pub const ZPUB: [u8; 4] = [0x04, 0xb2, 0x47, 0x46];

/// SLIP-132 registers a set of version bytes per chain, and testnet, signet and regtest
/// share one set. These are the public halves of the test-chain set: the counterparts of
/// [`YPUB`] and [`ZPUB`] on any chain that is not mainnet.
///
/// The private halves are deliberately absent. Nothing renders a test-chain private key -
/// the key report shows the mainnet pair and [`derive`] produces no other - so a `uprv` or
/// `vprv` constant here would be a value with no reader and one more way to write a secret
/// out of the device.
pub const UPUB: [u8; 4] = [0x04, 0x4a, 0x52, 0x62];
pub const VPUB: [u8; 4] = [0x04, 0x5f, 0x1c, 0xf6];

/// BIP-32's own version bytes for a serialized extended PUBLIC key: `xpub` on mainnet,
/// `tpub` on every test chain. What [`slip132_pub`] reads to decide which SLIP-132 set an
/// account node belongs to.
const XPUB_MAINNET: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
const XPUB_TESTNET: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];

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
                mainnet: (YPRV, YPUB),
                testnet_pub: UPUB,
                labels: ("Account yprv", "Account ypub"),
            }),
            Scheme::Bip84 => Some(Slip132 {
                mainnet: (ZPRV, ZPUB),
                testnet_pub: VPUB,
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
    /// (private, public) version bytes on mainnet - the pair [`derive`] renders.
    mainnet: ([u8; 4], [u8; 4]),
    /// The PUBLIC version bytes on the test chains. Public only, for the reason given on
    /// [`UPUB`].
    testnet_pub: [u8; 4],
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
///
/// The returned `String` is spending authority for the whole wallet and is the CALLER's to
/// wipe; the buffer is the only one that ever held it (see [`xprv_string`]), so a
/// `zeroize` on it is complete.
pub fn root_xprv(seed: &[u8; 64], network: bitcoin::Network) -> String {
    xprv_string(master(seed, network).key().encode())
}

/// The master account's own extended PUBLIC key: `Xpub::from_priv` of the same node
/// [`root_xprv`] serializes, depth 0 ("m"), on the given network.
///
/// Public identifier, not spending authority: this is the counterpart export code wants
/// (SPEC/0.2.0-m10) when a coordinator's watch-only file format includes the master xpub
/// alongside each account's own (e.g. Coldcard's `generic-wallet-export.md`, whose top
/// level `xpub` field is exactly this value at the mainnet/testnet-appropriate prefix).
pub fn root_xpub(seed: &[u8; 64], network: bitcoin::Network) -> String {
    let secp = secp();
    Xpub::from_priv(secp, master(seed, network).key()).to_string()
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
            Some(reversion(node.key().encode(), slip.mainnet.0)),
            Some(reversion(node_pub.encode(), slip.mainnet.1)),
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
                    // `crate::address::for_key` is the crate's one scheme-to-address
                    // mapping, so the row the report prints and the row the explorer,
                    // the CSV and the ownership search build are the same address by
                    // construction rather than by two implementations agreeing.
                    address: crate::address::for_key(scheme, pubkey, network)
                        .expect("BIP48 produces no address rows")
                        .to_string(),
                    pubkey: pubkey.to_string(),
                    // Not `key.to_wif()`: see `wif_string` for what rust-bitcoin's own
                    // rendering leaves behind.
                    wif: wif_string(&key),
                };
                key.inner.non_secure_erase();
                row
            })
            .collect()
    };

    Derived {
        account: AccountKeys {
            path: account_path,
            // The private rendering goes through this module's own encoder and the public
            // one does not. That asymmetry is the point: an xpub is not a secret, so the
            // buffers rust-bitcoin's `Display` abandons behind it cost nothing, while the
            // same buffers behind an xprv are the account's spending key sitting in the
            // free list. See `xprv_string`.
            xprv: xprv_string(node.key().encode()),
            xpub: node_pub.to_string(),
            slip132_prv,
            slip132_pub,
        },
        rows,
    }
}

// ---------------------------------------------------------------------------------------
// One single-sig account, as a value a file cannot forge
// ---------------------------------------------------------------------------------------

/// A name for one single-sig account: the scheme it belongs to and its index.
///
/// Enough to say WHICH account proved an output and no more. The network is the device's
/// own and is the same for every account in a session, so putting it here would be a field
/// that can only ever hold one value; the account node itself is public but far too large
/// to carry through [`crate::psbt::OutputRole`], which is what this is carried inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountId {
    scheme: Scheme,
    account: ChildIndex,
}

impl AccountId {
    pub fn scheme(self) -> Scheme {
        self.scheme
    }

    pub fn account(self) -> ChildIndex {
        self.account
    }
}

impl fmt::Display for AccountId {
    /// `bip84/0`: the scheme's own command-line name and the account index, which is the
    /// pair a user can match against the account line of their key report.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.scheme.name(), self.account)
    }
}

/// One leaf of an account: the key it derives, and the script that key locks.
///
/// The two travel together because they are one derivation seen twice, and a caller that
/// asked for them separately could compare a script from one leaf against a key from
/// another - which is the shape of every change-confusion bug there has been.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    pub key: CompressedPublicKey,
    /// What this account locks at this leaf, from [`crate::address::for_key`] - the
    /// crate's one scheme-to-script rule, so the change proof and the address explorer
    /// cannot disagree about what an account owns.
    pub script_pubkey: ScriptBuf,
}

/// One single-sig account of this wallet, reduced to what proving ownership of a script
/// needs.
///
/// The single-sig counterpart of [`crate::multisig::Registration`], built the same way and
/// for the same reason: the fields are private and [`Account::derive`] is the only
/// constructor, so no value of this type can be assembled out of a PSBT. That is what
/// makes ARCHITECTURE.md check 3 decidable by a pipeline holding no seed - the answer to
/// "is this script ours" comes from a value that could only have come from the seed, or it
/// does not come at all.
///
/// It holds the account node's PUBLIC key. Everything it can do - derive the two
/// unhardened levels below that node - is everything a watch-only wallet can do, so a
/// session may keep one in scope for as long as it keeps the review it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    id: AccountId,
    network: Network,
    /// `m/84h/0h/0h` and the like: where `xpub` sits under the master key. Kept typed
    /// rather than rendered, because it is compared against a PSBT's own origin path and a
    /// comparison of two spellings of a path is a comparison of two spellings.
    origin: DerivationPath,
    xpub: Xpub,
}

impl Account {
    /// Derive one account node from the seed.
    ///
    /// `None` for [`Scheme::Bip48`]: a BIP48 account is a cosigner in a multisig wallet and
    /// locks nothing on its own, so the only honest source of one of its scripts is a
    /// [`crate::multisig::Registration`] carrying every cosigner.
    ///
    /// The seed is read here and nowhere else in the life of the value. What survives the
    /// call is the account xpub, its path and its name.
    pub fn derive(
        seed: &[u8; 64],
        network: Network,
        scheme: Scheme,
        account: ChildIndex,
    ) -> Option<Account> {
        if scheme == Scheme::Bip48 {
            return None;
        }
        let secp = secp();
        let origin = DerivationPath::from(alloc::vec![
            hardened(fixed_index(scheme.purpose())),
            hardened(fixed_index(coin_type(network))),
            hardened(account),
        ]);
        // Both `SecretXpriv`s wipe themselves when this frame ends; the xpub taken from the
        // account node is the only thing that outlives the call.
        let root = master(seed, network);
        let node = derive_child(secp, root.key(), &origin, "an account node");
        Some(Account {
            id: AccountId { scheme, account },
            network,
            origin,
            xpub: Xpub::from_priv(secp, node.key()),
        })
    }

    pub fn id(&self) -> AccountId {
        self.id
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// Where this account sits under the master key, e.g. `m/84h/0h/0h`.
    pub fn origin(&self) -> &DerivationPath {
        &self.origin
    }

    /// The account node's public key, for a caller that has to export or display it.
    pub fn xpub(&self) -> &Xpub {
        &self.xpub
    }

    /// Which leaf of this account a derivation path names, if it names one at all.
    ///
    /// A hint reader and nothing more: it says WHERE to look, and a hostile file is free to
    /// point it anywhere. What decides ownership is [`Account::leaf`] rebuilding the script
    /// the output actually pays. The two halves are deliberately separate calls for the
    /// same reason they are on [`crate::multisig::Registration`] - a path that resolves is
    /// not a proof, and one function returning both would read as though it were.
    ///
    /// `None` for a path that is not exactly this account's origin followed by two
    /// unhardened steps, and for a chain step that is neither of BIP-44's two keychains.
    pub fn locate_path(&self, path: &DerivationPath) -> Option<(Keychain, u32)> {
        let steps: Vec<ChildNumber> = path.into_iter().copied().collect();
        let origin: Vec<ChildNumber> = self.origin.into_iter().copied().collect();
        if steps.len() != origin.len() + 2 || steps[..origin.len()] != origin[..] {
            return None;
        }
        let (ChildNumber::Normal { index: chain }, ChildNumber::Normal { index }) =
            (steps[origin.len()], steps[origin.len() + 1])
        else {
            return None;
        };
        Some((keychain_of(chain)?, index))
    }

    /// How many BIP-32 child derivations one [`leaf`](Account::leaf) costs: the keychain
    /// step and the index step.
    ///
    /// The single-sig half of the price list [`crate::multisig::Registration::leaf_derivations`]
    /// gives for the multisig half, and it exists for the same caller: `psbt::checks` has
    /// to charge this against a file's work budget before it derives, and a number written
    /// out at the call site is a number that stops matching this function.
    pub const LEAF_DERIVATIONS: u32 = 2;

    /// This account's key and script at one leaf.
    ///
    /// `None` only if the child key does not derive, which for an index below 2^31 is the
    /// roughly 2^-128 case BIP-32 tells implementations to skip, or if the scheme has no
    /// single-key script ([`Scheme::Bip48`], which [`Account::derive`] already refuses).
    pub fn leaf(&self, keychain: Keychain, index: u32) -> Option<Leaf> {
        let child = self
            .xpub
            .derive_pub(
                secp(),
                &[
                    ChildNumber::from_normal_idx(chain_index(keychain)).ok()?,
                    ChildNumber::from_normal_idx(index).ok()?,
                ],
            )
            .ok()?;
        let key = CompressedPublicKey(child.public_key);
        Some(Leaf {
            key,
            script_pubkey: crate::address::for_key(self.id.scheme, key, self.network)?
                .script_pubkey(),
        })
    }
}

/// Every single-sig account this device owns, for the caller that has to hand them to
/// [`crate::psbt::inspect_with_accounts`].
///
/// This is a POLICY statement and the only one there is: the device's single-sig wallets
/// are the four BIP-44 family schemes ([`Scheme::ALL`]) at account index 0, and nothing on
/// this device derives, displays or exports any other. Written once, here, so that the
/// change check and the address screens cannot come to disagree about which accounts a
/// wallet has - that disagreement is a change output the review calls a payment.
///
/// [`Scheme::Bip48`] is absent because [`Account::derive`] refuses it: a BIP-48 account is
/// a cosigner and locks nothing on its own, so its outputs are proven from a
/// [`crate::multisig::Registration`] or not at all.
///
/// What is NOT covered: an account index above 0. A coordinator that spends from one gets
/// [`crate::psbt::OutputRole::ClaimedButUnproven`] on its change, which counts as money
/// leaving - the review OVERSTATES the spend rather than understating it, which is the
/// direction this whole check exists to keep. Widening the set is a UI decision (there is
/// no screen that selects an account) and not one to make here on speculation.
///
/// The seed is read for the length of the call and the four account xpubs are what
/// survives it; every [`Account`] this returns is watch-only.
pub fn device_accounts(seed: &[u8; 64], network: Network) -> Vec<Account> {
    Scheme::ALL
        .iter()
        .filter_map(|scheme| Account::derive(seed, network, *scheme, ChildIndex::ZERO))
        .collect()
}

/// BIP-44's change level: 0 is the external keychain and 1 the internal one. Fixed for
/// single-sig, where a multisig descriptor instead names its own two chains and a
/// registration stores them.
///
/// The one statement of the rule in this module, read in both directions by
/// [`keychain_of`], so a device that derives change at chain 1 cannot come to recognise it
/// at some other chain.
fn chain_index(keychain: Keychain) -> u32 {
    match keychain {
        Keychain::Receive => 0,
        Keychain::Change => 1,
    }
}

/// The inverse of [`chain_index`]: which keychain a path's chain step names, or `None` for
/// a chain this device does not use. "Chain 7" is not a thing anyone can ask for, which is
/// what [`Keychain`] exists to say.
fn keychain_of(chain: u32) -> Option<Keychain> {
    [Keychain::Receive, Keychain::Change]
        .into_iter()
        .find(|keychain| chain_index(*keychain) == chain)
}

/// The one secp256k1 context of the process.
///
/// Public because it is a crate-wide resource, not a detail of this module: [`crate::sign`]
/// and every front end that has to call rust-bitcoin directly must reach THIS context
/// rather than build a second one, which on the device would cost a second copy of the
/// precomputed tables for no benefit.
///
/// Building a context is pure computation over the curve constants, so sharing it changes
/// nothing but the cost - `--scheme all` would otherwise build four.
///
/// It is UNBLINDED unless [`blind_secp`] is called first, and that is a decision with a
/// history, so here is what the primitive actually is. A previous note here said
/// randomization "would need an OS RNG, which this program must not use". Both halves of
/// that were wrong, and a wrong justification in security code is worse than none, because
/// it retires the question:
///
/// - `Secp256k1::seeded_randomize(&[u8; 32])` takes the 32 bytes from the caller and needs
///   no RNG at all. Only the `randomize(rng)` convenience wrapper does, and it is behind
///   secp256k1's `rand` feature, which this build does not enable.
/// - Randomization is NOT an entropy source and cannot put randomness on a derivation
///   path. `secp256k1_context_randomize` reaches exactly one thing: the ecmult_gen
///   context. It sets a blinding scalar `b`, so a secret scalar `a` is multiplied as
///   `(a - b)*G + b*G` rather than directly, and it rescales the projective representation
///   of the accumulator's initial point. Both are side-channel countermeasures against
///   power analysis and cache timing during signing and public key generation. Every
///   output is bit-for-bit unchanged: ECDSA here is RFC 6979, Schnorr is the no-aux-rand
///   BIP-340 path, and BIP-32 derivation is a hash chain. SECURITY.md invariant 3 bans an
///   RNG from the derivation and sealing paths; blinding is neither, and it does not need
///   one regardless.
///
/// What actually keeps 0.2.0 unblinded is narrower and is a property of THIS crate: the
/// seed has to be a device-bound value, and this crate cannot obtain one. It reads no
/// peripheral and no eFuse by construction (see the crate docs), so the only 32 bytes it
/// could supply itself would be a constant compiled into the image - and the image is open
/// source and reproducible, so that constant is public, the blinding scalar derived from
/// it is computable by the attacker, and the countermeasure buys nothing against the only
/// attacker it is for. A blind that the attacker can compute is not a blind.
///
/// [`blind_secp`] is therefore the seam: the firmware owns the eFuse HMAC key and can
/// derive 32 secret, device-unique, deterministic bytes from it, and passing them in makes
/// the blinding real without this crate learning anything about hardware. Nothing in
/// 0.2.0 calls it, so 0.2.0 signs on an unblinded context; that is the state to change
/// when the boot path is next opened, not a fact to be re-derived from scratch.
///
/// The desktop crate keeps the context in a `std::sync::OnceLock`; no_std has no blocking
/// primitive to replace that with, so this is the racy-init pattern instead (the same one
/// `once_cell::race` implements, hand-rolled here to avoid a dependency for fifteen
/// lines): the first caller through publishes a leaked `Box` with a compare-exchange, and
/// a concurrent loser frees its own candidate and adopts the winner's. Initialization may
/// run more than once under contention; exactly one result is ever published and every
/// caller sees that one. The race is unobservable because two contexts differ in nothing a
/// caller can see - identical curve constants, and, per the paragraphs above, identical
/// output even when one of them is blinded and the other is not. The single published
/// context is deliberately never freed: it lives for the process, exactly as the OnceLock
/// did.
pub fn secp() -> &'static Secp256k1<All> {
    let published = CONTEXT.load(Ordering::Acquire);
    if !published.is_null() {
        // SAFETY: see `publish`; a non-null CONTEXT is always a live leaked Box.
        return unsafe { &*published };
    }
    publish(Secp256k1::new()).0
}

/// Whether a blinding seed reached the context this process will actually use.
///
/// Returned rather than swallowed because the failure is silent and total: a caller that
/// asks too late gets an unblinded context and no other signal that its countermeasure did
/// not happen. `#[must_use]` so it cannot be dropped on the floor.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blinding {
    /// The seed was applied to the context every later caller will use.
    Applied,
    /// A context was already published, so nothing was blinded. Something on this boot
    /// called [`secp`] first; the fix is to call this earlier, not to call it again.
    TooLate,
}

/// Install a side-channel blinding seed on the process's secp256k1 context.
///
/// Call this once, at boot, BEFORE anything derives or signs. The context is published on
/// first use and is never replaced afterwards, which is why a late call reports
/// [`Blinding::TooLate`] rather than pretending to succeed. See [`secp`] for what blinding
/// is, what it is not, and why this crate cannot produce the seed itself.
///
/// Requirements on `seed`, in the order they matter:
/// - It must be SECRET. A value an attacker can read or recompute - anything constant in
///   the published image - produces a blinding scalar the attacker can also compute, which
///   is the same as no blinding.
/// - It must be DEVICE-BOUND, so one unit's analysis does not carry to another.
/// - It need not be random, and must not come from an RNG: libsecp256k1 runs the seed
///   through an RFC 6979 HMAC-SHA256 generator chained with the previous blinding value,
///   which is precisely what makes a derived, low-entropy or adversarial seed safe to use.
///   A value HKDF'd from the eFuse HMAC key is the intended shape.
///
/// Output is unaffected: signatures, public keys and derived addresses are identical
/// whether or not this is called, which is what makes it safe to add to a boot path that
/// is covered by byte-exact vectors (SECURITY.md invariant 4).
pub fn blind_secp(seed: &[u8; 32]) -> Blinding {
    let mut candidate = Secp256k1::new();
    candidate.seeded_randomize(seed);
    if publish(candidate).1 {
        Blinding::Applied
    } else {
        Blinding::TooLate
    }
}

/// The process's context, or null until the first caller publishes one.
static CONTEXT: AtomicPtr<Secp256k1<All>> = AtomicPtr::new(core::ptr::null_mut());

/// Publish `candidate` as THE context if none exists yet, and report whether it won.
///
/// The one place `CONTEXT` is ever stored to, so the invariant that a non-null `CONTEXT`
/// is a live, leaked, never-mutated `Box` has exactly one proof obligation.
fn publish(candidate: Secp256k1<All>) -> (&'static Secp256k1<All>, bool) {
    let raw = Box::into_raw(Box::new(candidate));
    match CONTEXT.compare_exchange(
        core::ptr::null_mut(),
        raw,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        // SAFETY: `raw` came from Box::into_raw, is now owned by the static for the rest
        // of the process, and is never freed or mutated again.
        Ok(_) => (unsafe { &*raw }, true),
        Err(winner) => {
            // SAFETY: `raw` lost the race, so this thread is still its only owner and no
            // other thread has ever seen the pointer. `winner` is a pointer some thread
            // published through the arm above.
            drop(unsafe { Box::from_raw(raw) });
            (unsafe { &*winner }, false)
        }
    }
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
    let encoded = base58check_secret(&raw);
    raw.zeroize();
    encoded
}

/// The base58check rendering of a serialized extended PRIVATE key, taking ownership of the
/// 78 bytes so the copy this frame holds is wiped rather than abandoned.
///
/// Callers pass `node.key().encode()` directly: rust-bitcoin returns that array by value,
/// so binding it here is what gives anything a chance to wipe it at all.
///
/// `pub(crate)` because this is the crate's ONLY sanctioned rendering of an extended
/// private key, not a detail of this module: `Xpriv`'s own `Display` is the leak
/// [`base58check_secret`] documents, so every module that renders one - [`crate::bip85`]
/// included - has to come through here or reintroduce it.
pub(crate) fn xprv_string(mut raw: [u8; 78]) -> String {
    let encoded = base58check_secret(&raw);
    raw.zeroize();
    encoded
}

/// A private key in WIF form, on the network and compression the key itself declares.
/// Every key this module produces is compressed; the other branch exists because
/// `PrivateKey` can represent both and a renderer that silently ignored the flag would be
/// wrong in a way nothing here would catch.
///
/// Replaces `PrivateKey::to_wif`, which is correct but leaves three complete or partial
/// copies of the key behind: `fmt_wif` builds the 34-byte payload on a stack array it does
/// not wipe, base58-encodes it into a `String` grown from empty, writes THAT into a second
/// `String` grown from empty, and then calls `shrink_to_fit`, whose reallocation frees a
/// buffer holding the entire 52-character WIF. `AddressRow::drop` wipes the one string it
/// is given and can reach none of them. A WIF is short enough to fit whole inside those
/// abandoned buffers, so this is not a partial disclosure: it is the leaf's spending key.
fn wif_string(key: &PrivateKey) -> String {
    // Layout per WIF: version byte, the 32-byte scalar, then 0x01 to mark the public key
    // compressed. 128 is mainnet and 239 is every test chain.
    let mut payload = [0u8; 34];
    payload[0] = if key.network.is_mainnet() { 128 } else { 239 };
    let mut secret = key.inner.secret_bytes();
    payload[1..33].copy_from_slice(&secret);
    secret.zeroize();
    let len = if key.compressed {
        payload[33] = 1;
        34
    } else {
        33
    };
    let encoded = base58check_secret(&payload[..len]);
    payload.zeroize();
    encoded
}

/// Largest payload this module base58check-encodes: a 78-byte extended key. The 4-byte
/// checksum is appended by [`base58check_secret`] itself and is counted in
/// [`B58_MAX_DIGITS`].
const B58_MAX_PAYLOAD: usize = 78;

/// Upper bound on the characters an 82-byte value (payload plus checksum) encodes to:
/// `ceil(82 * 8 / log2(58))` is 112. A leading zero byte contributes one '1' and no digit,
/// so this bounds the total output length whatever the input looks like. An xprv is 111
/// characters and a WIF is 52.
const B58_MAX_DIGITS: usize = 112;

/// The base58 alphabet, Bitcoin ordering.
const B58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Base58check-encode a secret payload, leaving no copy of it anywhere but the returned
/// `String`.
///
/// INVARIANT, and the whole reason this exists rather than a call to
/// `bitcoin::base58::encode_check`: an encoder that is merely correct is not sufficient for
/// a private key. The upstream one starts from `String::new()` and pushes one character at
/// a time, so encoding a 111-character xprv abandons buffers holding its first 8, 16, 32
/// and 64 characters - 64 base58 characters already cover the entire chain code - and it
/// accumulates the base58 digits in a `SmallVec` that spills to the heap past 100 digits
/// and is dropped unwiped. None of that is reachable from `AccountKeys::drop`, which sees
/// only the final buffer. This encoder has exactly two secret-bearing buffers, both of
/// known size before the first byte is written, and both are wiped: `digits` here, and the
/// `String` it returns, which the owning type wipes.
///
/// Two properties are load bearing, and a change to either reintroduces the defect:
/// - `out` is created at [`B58_MAX_DIGITS`] and never exceeds it, so no push reallocates.
///   Nothing may `shrink_to_fit` it afterwards; that reallocation is itself the leak.
/// - `digits` is a fixed array, not a `Vec`, so it cannot grow and abandon a buffer.
///
/// `crates/notyas-core/tests/key_material_residue.rs` fails if either is undone, and
/// `base58check_matches_rust_bitcoin` fails if the encoding drifts from the crate this
/// module used to call.
fn base58check_secret(payload: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    assert!(
        payload.len() <= B58_MAX_PAYLOAD,
        "base58check_secret is sized for payloads up to {B58_MAX_PAYLOAD} bytes, got {}",
        payload.len()
    );

    // Base58CHECK: the trailer is the first four bytes of SHA256d over the payload. Both
    // digests are wiped - the first is an intermediate over key material, and sha2's own
    // `zeroize` feature (enabled in Cargo.toml, deliberately) clears the hasher state.
    let first = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(payload)));
    let checksum = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(*first)));

    // Base 256 to base 58 by repeated division, least significant digit first. Leading
    // zero BYTES carry no value and so produce no digit; base58check renders each as a
    // literal '1', which is why they are counted separately.
    let mut digits = [0u8; B58_MAX_DIGITS];
    let mut len = 0usize;
    let mut leading_zeros = 0usize;
    let mut still_leading = true;
    for &byte in payload.iter().chain(checksum[..4].iter()) {
        if still_leading && byte == 0 {
            leading_zeros += 1;
        } else {
            still_leading = false;
        }
        let mut carry = usize::from(byte);
        for digit in digits[..len].iter_mut() {
            let value = usize::from(*digit) * 256 + carry;
            *digit = (value % 58) as u8;
            carry = value / 58;
        }
        while carry > 0 {
            digits[len] = (carry % 58) as u8;
            len += 1;
            carry /= 58;
        }
    }

    let mut out = String::with_capacity(B58_MAX_DIGITS);
    for _ in 0..leading_zeros {
        out.push('1');
    }
    for digit in digits[..len].iter().rev() {
        out.push(char::from(B58_ALPHABET[usize::from(*digit)]));
    }
    digits.zeroize();
    debug_assert_eq!(
        out.capacity(),
        B58_MAX_DIGITS,
        "the output buffer grew, so an abandoned copy of the key is in the free list"
    );
    out
}

/// The SLIP-132 public rendering of an already-serialized account node: `ypub`/`zpub` on
/// mainnet, `upub`/`vpub` on the test chains.
///
/// This exists because two consumers of the same account node disagree about what they
/// need, and both are right. The key report renders the mainnet pair only, which is why
/// [`AccountKeys::slip132_pub`] is `None` off mainnet: showing a user a fourth line of key
/// material they have no use for is noise. Electrum, on the other hand, infers an
/// account's script type from nothing but these version bytes, so a BIP84 testnet account
/// exported under its plain `tpub` is not a lesser export, it is a wallet that builds
/// legacy addresses from a native-segwit key. Rendering on demand serves both without
/// making either the default.
///
/// The chain is read out of `xpub`'s own version bytes rather than taken as an argument.
/// There is then no second source of truth to disagree with the key, and no way to hand
/// this function a testnet account and a mainnet label and get a file back that lies about
/// which chain it is for.
///
/// `None` when `scheme` has no SLIP-132 rendering (BIP44 and BIP86, which the ecosystem
/// leaves as a plain xpub/tpub; BIP48, which is multisig), and when `xpub` is not a
/// 78-byte base58check extended public key of a chain SLIP-132 registers.
pub fn slip132_pub(scheme: Scheme, xpub: &str) -> Option<String> {
    let slip = scheme.slip132()?;
    let raw: [u8; 78] = bitcoin::base58::decode_check(xpub).ok()?.try_into().ok()?;
    let version = if raw[..4] == XPUB_MAINNET {
        slip.mainnet.1
    } else if raw[..4] == XPUB_TESTNET {
        slip.testnet_pub
    } else {
        return None;
    };
    Some(reversion(raw, version))
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

    /// [`root_xpub`] must be the public half of exactly the node [`root_xprv`] serializes:
    /// parsing the xprv and dropping to its public key is an independent path to the same
    /// value (rust-bitcoin's `Xpriv::from_str` + `Xpub::from_priv`, not this module's own
    /// `master()`), and on testnet the prefix must flip from tprv to tpub.
    #[test]
    fn root_xpub_is_the_public_half_of_root_xprv() {
        let seed = sample_seed();
        for network in [Network::Bitcoin, Network::Testnet] {
            let xprv: Xpriv = root_xprv(&seed, network).parse().expect("valid xprv/tprv");
            let want = Xpub::from_priv(secp(), &xprv).to_string();
            assert_eq!(root_xpub(&seed, network), want);
        }
        assert!(root_xpub(&seed, Network::Bitcoin).starts_with("xpub"));
        assert!(root_xpub(&seed, Network::Testnet).starts_with("tpub"));
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
            // BIP-48 script_type 1 is P2SH-P2WSH; script_type 2 is P2WSH
            // (WALLET-API.md 2.6 restricts 0.2.0 to script_type 2 / WshSortedMulti). This
            // test only exercises path arithmetic, so either value works, but 1 is
            // labelled correctly here rather than as "P2WSH" (a stale mislabel this
            // comment used to carry).
            1,
        );
        assert_eq!(d.account.path, "m/48'/0'/3'/1'");
        assert!(d.rows.is_empty());
    }

    /// The hand rolled base58check encoder must agree with the crate this module used to
    /// call, on every shape an extended key or a WIF can take.
    ///
    /// The reference-vector tests above already pin the real renderings; this pins the
    /// EDGES those vectors never reach - leading zero bytes (a version byte of 0x00 is
    /// what makes a base58 address start with '1'), the shortest and longest payloads, and
    /// the all-0xff carry chain that exercises every division in the loop.
    #[test]
    fn base58check_matches_rust_bitcoin() {
        let mut payloads: Vec<Vec<u8>> = alloc::vec![
            alloc::vec![0x00],
            alloc::vec![0x00, 0x00, 0x00, 0x00],
            alloc::vec![0xff],
            alloc::vec![0x00; B58_MAX_PAYLOAD],
            alloc::vec![0xff; B58_MAX_PAYLOAD],
        ];
        // A pattern with no structure that could accidentally agree, at every length the
        // module can hand the encoder, plus the same with a run of leading zeros.
        for len in 1..=B58_MAX_PAYLOAD {
            let body: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                .collect();
            let mut zeroed = body.clone();
            for byte in zeroed.iter_mut().take(len.min(5)) {
                *byte = 0;
            }
            payloads.push(body);
            payloads.push(zeroed);
        }

        for payload in &payloads {
            let want = bitcoin::base58::encode_check(payload);
            let got = base58check_secret(payload);
            assert_eq!(got, want, "payload of {} bytes", payload.len());
            assert!(
                got.len() <= B58_MAX_DIGITS,
                "a {}-byte payload encoded to {} characters, above the {B58_MAX_DIGITS} \
                 the output buffer is sized for",
                payload.len(),
                got.len()
            );
        }
    }

    /// The WIF this module builds must be the one rust-bitcoin would have produced.
    /// Rendering a key by hand is only acceptable while it is byte-identical.
    #[test]
    fn wif_string_matches_rust_bitcoin() {
        let seed = sample_seed();
        for network in [Network::Bitcoin, Network::Testnet] {
            let root = master(&seed, network);
            for index in 0u32..8 {
                let child = derive_child(
                    secp(),
                    root.key(),
                    &[normal(fixed_index(index))],
                    "test child",
                );
                let key = PrivateKey::new(child.key().private_key, network);
                assert_eq!(wif_string(&key), key.to_wif(), "{network} child {index}");

                // The uncompressed form is not rendered anywhere in this program, but the
                // branch exists, so it is checked rather than left as the one untested
                // path through a function that emits spending keys.
                let uncompressed = PrivateKey {
                    compressed: false,
                    ..key
                };
                assert_eq!(
                    wif_string(&uncompressed),
                    uncompressed.to_wif(),
                    "{network} child {index} uncompressed"
                );
            }
        }
    }

    /// Blinding must not move a single output bit. This is what makes [`blind_secp`] safe
    /// to put on a boot path that is pinned to byte-exact published vectors, and it is the
    /// claim the doc comment on [`secp`] rests on.
    ///
    /// Deliberately built on a LOCAL context rather than through `blind_secp`, which
    /// publishes into the process-wide one: this must be re-runnable and must not depend on
    /// whether some other test in this binary called `secp()` first.
    #[test]
    fn blinding_the_context_changes_no_output() {
        let seed = sample_seed();
        let plain = Secp256k1::new();
        let mut blinded = Secp256k1::new();
        blinded.seeded_randomize(&[0xa5; 32]);
        // Twice, because libsecp chains each seed into the previous blinding value; the
        // second call must be as output-neutral as the first.
        blinded.seeded_randomize(&[0x5a; 32]);

        let root = master(&seed, Network::Bitcoin);
        for index in 0u32..4 {
            let path = [hardened(fixed_index(84)), hardened(fixed_index(index))];
            let a = derive_child(&plain, root.key(), &path, "plain");
            let b = derive_child(&blinded, root.key(), &path, "blinded");
            assert_eq!(a.key().encode(), b.key().encode(), "child {index}");
            assert_eq!(
                Xpub::from_priv(&plain, a.key()).encode(),
                Xpub::from_priv(&blinded, b.key()).encode(),
                "public half of child {index}"
            );
        }
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
