// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Addresses (0.2.0-m10): how a scheme renders one public key, which addresses a wallet
//! owns, and whether an address someone else supplied is one of them.
//!
//! # What this module is for
//!
//! Three surfaces of MILESTONES.md 0.2.0-m10 sit on top of it, and they are the reason its
//! shape is what it is:
//!
//! - **The address explorer** (UX-SCREENS.md S-22/S-23) pages a wallet's receive and
//!   change addresses and shows each one's full derivation path: [`AddressSource::range`].
//! - **The address-range CSV** ([`crate::export::address_range_csv`]) writes a bounded run
//!   of the same rows to the card.
//! - **Verify Address Ownership** (S-24/S-25) answers "is this address mine?" over
//!   singlesig accounts and multisig registrations at once: [`parse`] then [`find`].
//!
//! # Watch-only, by signature
//!
//! Nothing here takes a seed, and no function of this module can reach an `xprv` or a WIF:
//! a singlesig source is built from [`crate::derive::AccountKeys`] and reads only its
//! public half ([`SinglesigAccount::new`]), and a multisig source is m7's [`Registration`],
//! which holds cosigner xpubs and nothing else. That is the same "borrowing rules
//! guarantee it" discipline [`crate::export`] uses, and it is what makes it safe for
//! [`find`] to walk thousands of leaves: a search that never has spending authority in
//! scope cannot leak any.
//!
//! # One rendering path
//!
//! [`for_key`] is the crate's ONLY mapping from a scheme and a public key to an address.
//! [`crate::derive::derive`] calls it for the key report's rows, this module calls it for
//! the explorer, the CSV and the ownership search, and multisig addresses come from
//! [`Registration::address`] for the same reason. The alternative - each surface building
//! its own address - is how a device ends up showing one string on the receive screen and
//! recognising a different one during a search, which is precisely the failure the
//! ownership check exists to catch.
//!
//! Comparison is by `scriptPubKey`, never by text ([`find`]). Two renderings of one script
//! are the same address - BIP-173 permits an uppercase form and the published vectors use
//! it - so comparing scripts asks "is this the same output?" rather than "is this the same
//! string?", which is the question that matters and the one with a single answer.
//!
//! # Vectors
//!
//! Every address shape this module renders is pinned to published text in
//! `tests/address_vectors.rs`: BIP-84, BIP-86 and BIP-49 publish mnemonic-to-address
//! vectors, SLIP-132 publishes the BIP-44 row those documents omit, BIP-129 publishes a
//! multisig descriptor with its first receive address, and BIP-350 publishes the valid and
//! invalid address lists [`parse`] is measured against.

use core::fmt;
use core::str::FromStr;

use alloc::string::String;
use alloc::vec::Vec;

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpub};
use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{Address, Network, NetworkKind};

use crate::derive::{secp, AccountKeys, ChildIndex, Scheme};
use crate::multisig::Registration;

/// Receive-versus-change, which is m7's type and stays m7's type: one wallet has one notion
/// of an internal keychain, and a multisig registration already carries it.
pub use crate::multisig::Keychain;

/// The largest run of addresses one request may ask for.
///
/// The explorer pages a handful of rows at a time and the CSV is the only caller that wants
/// many, so this is the CSV's own bound: 250 is what Coldcard's address explorer writes
/// (`shared/address_explorer.py`) and what PARITY.md section 5 records as the row this
/// milestone closes. A refusal rather than a clamp, because a caller that asked for 10,000
/// rows has a bug and silently writing 250 of them to a card would hide it.
pub const MAX_RANGE: u32 = 250;

// ---------------------------------------------------------------------------------------
// Script-type rendering
// ---------------------------------------------------------------------------------------

/// The address one scheme renders for one leaf's public key.
///
/// `None` for [`Scheme::Bip48`]: a multisig leaf is not any single key's address, and the
/// only honest source of one is a [`Registration`] that supplies every cosigner.
///
/// The BIP-86 arm takes the x-only half of the same compressed key and tweaks it with an
/// empty merkle root, which is BIP-86's key-path-only output. It needs no private key to do
/// that, so this function - unlike the version that lived in [`crate::derive`] until m10 -
/// never puts a keypair on the stack to wipe again.
pub fn for_key(scheme: Scheme, key: CompressedPublicKey, network: Network) -> Option<Address> {
    Some(match scheme {
        Scheme::Bip44 => Address::p2pkh(key, network),
        Scheme::Bip49 => Address::p2shwpkh(&key, network),
        Scheme::Bip84 => Address::p2wpkh(&key, network),
        Scheme::Bip86 => Address::p2tr(secp(), XOnlyPublicKey::from(key.0), None, network),
        Scheme::Bip48 => return None,
    })
}

/// BIP-44's change level: 0 is the external keychain and 1 the internal one
/// (<https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki>, "Change"). Fixed for
/// singlesig, which is why it is a constant here and a stored pair on a registration - a
/// descriptor names its own two chains, and this device must use the ones it registered.
fn chain_index(keychain: Keychain) -> u32 {
    match keychain {
        Keychain::Receive => 0,
        Keychain::Change => 1,
    }
}

/// A derivation path in the spelling the screens and the key report use: leading `m/`,
/// hardened written with an apostrophe.
///
/// Deliberately not [`crate::export`]'s descriptor spelling (`48h/0h/0h/2h`, no `m/`). The
/// two are one node named in two registers, and the register matters: a user compares a CSV
/// column against the path their coordinator shows beside an address, and coordinators show
/// that one with an apostrophe.
fn report_path(path: &DerivationPath) -> String {
    let mut out = String::from("m");
    for step in path {
        match step {
            ChildNumber::Normal { index } => out.push_str(&format!("/{index}")),
            ChildNumber::Hardened { index } => out.push_str(&format!("/{index}'")),
        }
    }
    out
}

// ---------------------------------------------------------------------------------------
// One singlesig account
// ---------------------------------------------------------------------------------------

/// One singlesig account's addresses, derived from its account node's PUBLIC key.
///
/// Built from an [`AccountKeys`] because [`crate::derive::derive`] is the only thing that
/// produces one, so the path this renders and the xpub it derives from provably describe
/// the same node. The private renderings on that value are borrowed and never read; see the
/// module docs.
#[derive(Debug, Clone)]
pub struct SinglesigAccount {
    scheme: Scheme,
    network: Network,
    /// The account path as the key report wrote it (`m/84'/0'/0'`), so every leaf path this
    /// type renders extends the exact string the user already saw.
    path: String,
    xpub: Xpub,
}

impl SinglesigAccount {
    /// `None` if `scheme` is [`Scheme::Bip48`] (multisig has no singlesig addresses - use a
    /// [`Registration`]), if `account.xpub` is not a serialized extended public key, or if
    /// that key belongs to the other chain.
    ///
    /// The chain check is not ceremony: [`AccountKeys`] has public fields, and rendering a
    /// mainnet address from a `tpub` would produce a string that looks exactly like money
    /// and is not.
    pub fn new(scheme: Scheme, network: Network, account: &AccountKeys) -> Option<Self> {
        if scheme == Scheme::Bip48 {
            return None;
        }
        let xpub = Xpub::from_str(&account.xpub).ok()?;
        if xpub.network != NetworkKind::from(network) {
            return None;
        }
        Some(SinglesigAccount {
            scheme,
            network,
            path: account.path.clone(),
            xpub,
        })
    }

    /// The full path of one leaf, e.g. `m/84'/0'/0'/1/7`. What S-23 prints above the
    /// address and what the CSV's derivation column carries.
    pub fn leaf_path(&self, keychain: Keychain, index: ChildIndex) -> String {
        format!("{}/{}/{}", self.path, chain_index(keychain), index)
    }

    /// This account's address at one leaf.
    ///
    /// `None` only if the child key does not derive, which for an index [`ChildIndex`]
    /// admits is the roughly 2^-128 case BIP-32 tells implementations to skip.
    pub fn address(&self, keychain: Keychain, index: ChildIndex) -> Option<Address> {
        let leaf = self
            .xpub
            .derive_pub(
                secp(),
                &[
                    ChildNumber::from_normal_idx(chain_index(keychain)).ok()?,
                    ChildNumber::from_normal_idx(index.get()).ok()?,
                ],
            )
            .ok()?;
        for_key(self.scheme, CompressedPublicKey(leaf.public_key), self.network)
    }
}

// ---------------------------------------------------------------------------------------
// One wallet's addresses
// ---------------------------------------------------------------------------------------

/// Everything that can name an address as this device's own: one singlesig account, or one
/// verified multisig registration.
///
/// A view rather than an owner, so "every account this wallet has" is a slice of these
/// built at the call site over values the caller already holds. Singlesig and multisig are
/// two variants of one type and not two APIs, because the ownership question is one
/// question - WALLET-API.md decision D2 gives the reason at the layer above: two code paths
/// that are supposed to agree are how the 2019 multisig change confusion happened.
#[derive(Debug, Clone, Copy)]
pub enum AddressSource<'a> {
    Singlesig(&'a SinglesigAccount),
    Multisig(&'a Registration),
}

/// One address of one wallet, with everything the screens and the CSV say about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressEntry {
    pub keychain: Keychain,
    pub index: ChildIndex,
    pub address: Address,
    /// One leaf path per key that has to sign here: exactly one for singlesig, one per
    /// cosigner in the registration's own order for multisig.
    pub paths: Vec<String>,
    /// Which element of `paths` is THIS device's key. Always 0 for singlesig.
    pub ours: usize,
    /// The P2WSH witness script in lowercase hex for a multisig leaf; `None` for singlesig,
    /// whose script is fully described by the address itself.
    pub witness_script: Option<String>,
}

impl AddressEntry {
    /// The path of this device's own key at this leaf: what S-23 prints beside the address
    /// and what S-25 answers "yours at ..." with.
    pub fn our_path(&self) -> &str {
        // `ours` indexes `paths` by construction in `AddressSource::entry`, the only
        // constructor; the fallback keeps a hand-built value from panicking a screen.
        self.paths.get(self.ours).map_or("", String::as_str)
    }
}

impl AddressSource<'_> {
    /// This source's address at one leaf, and nothing else - the search's inner loop, which
    /// must not allocate a path or a script hex string for every candidate it rejects.
    pub fn address(&self, keychain: Keychain, index: ChildIndex) -> Option<Address> {
        match self {
            AddressSource::Singlesig(account) => account.address(keychain, index),
            AddressSource::Multisig(registration) => registration.address(keychain, index.get()),
        }
    }

    /// The full row: address, paths, and for multisig the witness script.
    pub fn entry(&self, keychain: Keychain, index: ChildIndex) -> Option<AddressEntry> {
        match self {
            AddressSource::Singlesig(account) => Some(AddressEntry {
                keychain,
                index,
                address: account.address(keychain, index)?,
                paths: vec![account.leaf_path(keychain, index)],
                ours: 0,
                witness_script: None,
            }),
            AddressSource::Multisig(registration) => {
                // One derivation of the cosigner keys serves both the address and the script
                // column, which keeps a 250-row multisig CSV at 250 rounds of key derivation
                // rather than 500.
                let witness_script = registration.witness_script(keychain, index.get())?;
                let address = Address::p2wsh(&witness_script, registration.network());
                let chain = registration.chain_index(keychain);
                let paths = registration
                    .cosigners()
                    .iter()
                    .map(|cosigner| format!("{}/{}/{}", report_path(&cosigner.origin), chain, index))
                    .collect();
                Some(AddressEntry {
                    keychain,
                    index,
                    address,
                    paths,
                    ours: registration.our_position(),
                    witness_script: Some(witness_script.to_hex_string()),
                })
            }
        }
    }

    /// `count` consecutive rows from `start` on one keychain.
    ///
    /// `None` if `count` is above [`MAX_RANGE`], if the run would reach past the last
    /// unhardened index, or if a leaf does not derive. Bounded because this is what writes a
    /// file: MILESTONES.md 0.2.0-m10 asks for a CSV of "a bounded address range", and an
    /// unbounded one is a card-filling loop with a progress bar.
    pub fn range(
        &self,
        keychain: Keychain,
        start: ChildIndex,
        count: u32,
    ) -> Option<Vec<AddressEntry>> {
        if count > MAX_RANGE {
            return None;
        }
        let mut out = Vec::with_capacity(count as usize);
        for offset in 0..count {
            let index = ChildIndex::new(start.get().checked_add(offset)?)?;
            out.push(self.entry(keychain, index)?);
        }
        Some(out)
    }
}

// ---------------------------------------------------------------------------------------
// Reading an address someone else supplied
// ---------------------------------------------------------------------------------------

/// Why an address the user typed or read from the card is not something this device will
/// search for.
///
/// Named variants rather than a bare `None`, because the three are different answers: one
/// is a typo, one means the user is looking at the wrong wallet, and neither may ever be
/// reported as "not yours" - a wrong-chain address that IS theirs on the other chain would
/// then get the most dangerous verdict this device gives (UX-SCREENS.md S-25 edge states).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    /// Nothing but whitespace.
    Empty,
    /// Not a bitcoin address: bad checksum, bad character, a witness program of a length its
    /// version does not allow, mixed case. The reason is deliberately not carried - the
    /// screen's copy is one line, and propagating `bitcoin::address::ParseError` would put a
    /// third-party enum into every UI match arm to say the same thing.
    Malformed,
    /// A real address of the other chain. `address` is as fine an answer as the string
    /// itself allows: legacy testnet, signet and regtest share one prefix set, so "a test
    /// chain" is the truth and "testnet" would be a guess.
    WrongNetwork {
        address: NetworkKind,
        wallet: Network,
    },
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressError::Empty => write!(f, "no address was entered"),
            AddressError::Malformed => write!(f, "that is not a valid bitcoin address"),
            AddressError::WrongNetwork { address, wallet } => {
                let chain = match address {
                    NetworkKind::Main => "a mainnet",
                    NetworkKind::Test => "a test-chain",
                };
                write!(f, "that is {chain} address and this wallet is on {wallet}")
            }
        }
    }
}

impl core::error::Error for AddressError {}

/// Read an address for `network`, or refuse it.
///
/// Surrounding whitespace goes (a line read from a card carries its line ending); nothing
/// inside the string is touched, because an address with a space in it is a mistyped address
/// and repairing it would be this device guessing at money.
///
/// This is [`Address::require_network`] split open so the refusal can say WHICH chain the
/// address belongs to, which is the difference between the S-25 copy "this is a testnet
/// address" and the answer that must never appear for one, "not yours".
pub fn parse(text: &str, network: Network) -> Result<Address, AddressError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(AddressError::Empty);
    }
    let unchecked = Address::from_str(trimmed).map_err(|_| AddressError::Malformed)?;
    if !unchecked.is_valid_for_network(network) {
        return Err(AddressError::WrongNetwork {
            address: if unchecked.is_valid_for_network(Network::Bitcoin) {
                NetworkKind::Main
            } else {
                NetworkKind::Test
            },
            wallet: network,
        });
    }
    Ok(unchecked.assume_checked())
}

// ---------------------------------------------------------------------------------------
// Verify address ownership
// ---------------------------------------------------------------------------------------

/// How far into each keychain an ownership search may look.
///
/// A type rather than a `u32` parameter, so the bound is checked once at construction and no
/// search can start with one that was never checked. MILESTONES.md 0.2.0-m10's "must not
/// break" list names exactly this: the search refuses rather than scans unboundedly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchBounds {
    per_keychain: u32,
}

impl SearchBounds {
    /// 764 per keychain, so 1,528 addresses per source across receive and change - the
    /// figure UX-SCREENS.md S-24/S-25 writes into the busy screen and both verdicts, and the
    /// depth Coldcard's own verify-address-ownership searches
    /// (<https://coldcard.com/docs/verify-address-ownership/>).
    pub const DEFAULT: SearchBounds = SearchBounds { per_keychain: 764 };

    /// The ceiling a caller may not raise the bound past.
    ///
    /// Every candidate costs one EC point derivation, so the wall clock is linear in this
    /// number and in the number of sources; an order of magnitude above
    /// [`SearchBounds::DEFAULT`] is where the busy screen stops being a progress bar and
    /// becomes a hang the user can only answer by pulling power. [`Step::Stop`] is what
    /// makes anything in this range survivable.
    pub const MAX_PER_KEYCHAIN: u32 = 10_000;

    /// `None` above [`SearchBounds::MAX_PER_KEYCHAIN`], and at zero, which would answer "NOT
    /// FOUND" without looking at anything.
    pub fn new(per_keychain: u32) -> Option<Self> {
        (1..=Self::MAX_PER_KEYCHAIN)
            .contains(&per_keychain)
            .then_some(SearchBounds { per_keychain })
    }

    pub fn per_keychain(self) -> u32 {
        self.per_keychain
    }
}

/// What the caller wants after each candidate: S-24's Stop button, in the only shape a
/// no_std module with no threads can offer one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Continue,
    Stop,
}

/// The address is this wallet's, and here is where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ownership {
    /// Position in the `sources` slice [`find`] was given, so the caller can name the
    /// account or registration it already knows by that position.
    pub source: usize,
    pub entry: AddressEntry,
    /// How many addresses had been built when the match was found. The screen quotes it; it
    /// measures nothing else.
    pub searched: u32,
}

/// The answer to "is this address mine?", including the answer that is not an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Search {
    Yours(Ownership),
    /// Every address within the bound was built and none matched. The bound is what makes
    /// this statement finite rather than universal: it says nothing about index 5,000, and
    /// S-25's copy is written to say only what `searched` supports.
    NotFound { searched: u32 },
    /// The caller stopped it. Not a verdict, and S-25 says so in those words.
    Stopped { searched: u32 },
}

/// How many addresses a [`find`] over these sources will build at most: what the busy
/// screen's "i of n" counts up to.
pub fn search_total(sources: &[AddressSource], bounds: SearchBounds) -> u32 {
    u32::try_from(sources.len())
        .unwrap_or(u32::MAX)
        .saturating_mul(2)
        .saturating_mul(bounds.per_keychain())
}

/// Search every source for `target`, receive keychain before change, up to `bounds`.
///
/// The comparison is between `scriptPubKey`s, not between strings: `target` came from
/// [`parse`], so an address written in the uppercase form BIP-173 also permits matches the
/// same output as the lowercase one.
///
/// `progress` is called once per candidate with the running count and may stop the search;
/// pass `&mut |_| Step::Continue` when there is nothing to report to.
///
/// A leaf that does not derive is skipped rather than aborting the run: it is a leaf with no
/// address at all, so it cannot be the one being looked for, and refusing to answer because
/// of it would turn a 2^-128 accident into a device that cannot verify an address.
pub fn find(
    target: &Address,
    sources: &[AddressSource],
    bounds: SearchBounds,
    progress: &mut dyn FnMut(u32) -> Step,
) -> Search {
    let want = target.script_pubkey();
    let mut searched = 0u32;
    for (source_position, source) in sources.iter().enumerate() {
        for keychain in [Keychain::Receive, Keychain::Change] {
            for raw in 0..bounds.per_keychain() {
                let Some(index) = ChildIndex::new(raw) else {
                    break;
                };
                if let Some(candidate) = source.address(keychain, index) {
                    searched = searched.saturating_add(1);
                    if candidate.script_pubkey() == want {
                        // The full row is built once, here, for the one leaf that matched -
                        // the rejected candidates never allocate a path or a script string.
                        // `entry` re-derives the same leaf from the same keys that just
                        // produced `candidate`, so it cannot fail where that succeeded, and
                        // an `expect` is what keeps an impossible state from turning into
                        // the wrong verdict about an address that IS this wallet's.
                        let entry = source
                            .entry(keychain, index)
                            .expect("a leaf whose address derived has a row");
                        return Search::Yours(Ownership {
                            source: source_position,
                            entry,
                            searched,
                        });
                    }
                }
                if progress(searched) == Step::Stop {
                    return Search::Stopped { searched };
                }
            }
        }
    }
    Search::NotFound { searched }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use crate::bip39;
    use crate::derive::Derived;

    /// BIP-84's own m/84'/0'/0'/0/0 public key
    /// (https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki, "Test vectors"),
    /// used here only as a well-formed point; the addresses it renders are pinned in
    /// `tests/address_vectors.rs`.
    const PUBKEY: &str = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c";

    fn key() -> CompressedPublicKey {
        PUBKEY.parse().expect("a published compressed point")
    }

    fn bip84_account() -> Derived {
        let seed = bip39::seed(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon about",
            "",
        );
        crate::derive::derive(
            &seed,
            Network::Bitcoin,
            Scheme::Bip84,
            ChildIndex::ZERO,
            ChildIndex::ZERO,
            0,
            0,
        )
    }

    #[test]
    fn a_multisig_leaf_is_not_any_single_keys_address() {
        assert!(for_key(Scheme::Bip48, key(), Network::Bitcoin).is_none());
        for scheme in Scheme::ALL {
            assert!(for_key(scheme, key(), Network::Bitcoin).is_some(), "{scheme}");
        }
    }

    /// Every refusal is one actionable line the screen can print unchanged: ASCII, no
    /// trailing period, and never the word this device must not say about an address of
    /// another chain.
    #[test]
    fn refusals_read_as_one_line() {
        let cases = [
            AddressError::Empty,
            AddressError::Malformed,
            AddressError::WrongNetwork {
                address: NetworkKind::Test,
                wallet: Network::Bitcoin,
            },
        ];
        for error in cases {
            let text = error.to_string();
            assert!(text.is_ascii(), "{text}");
            assert!(!text.is_empty() && !text.ends_with('.'), "{text}");
            assert!(!text.contains('\n'), "{text}");
            assert!(!text.contains("not yours"), "{text}");
        }
    }

    /// A full-size range is what the CSV writes: every row present, indices consecutive,
    /// no two rows the same address.
    #[test]
    fn a_full_range_is_consecutive() {
        let derived = bip84_account();
        let account = SinglesigAccount::new(Scheme::Bip84, Network::Bitcoin, &derived.account)
            .expect("a BIP-84 account is an address source");
        let source = AddressSource::Singlesig(&account);
        let rows = source
            .range(Keychain::Receive, ChildIndex::ZERO, MAX_RANGE)
            .expect("MAX_RANGE is the bound, not one past it");
        assert_eq!(rows.len() as u32, MAX_RANGE);
        for (offset, row) in rows.iter().enumerate() {
            assert_eq!(row.index.get(), offset as u32);
            assert_eq!(row.keychain, Keychain::Receive);
            assert!(row.witness_script.is_none(), "singlesig rows carry no script");
            assert_eq!(row.our_path(), account.leaf_path(Keychain::Receive, row.index));
        }
        let mut addresses: Vec<String> = rows.iter().map(|row| row.address.to_string()).collect();
        addresses.sort();
        addresses.dedup();
        assert_eq!(addresses.len() as u32, MAX_RANGE, "an index repeated an address");
    }
}
