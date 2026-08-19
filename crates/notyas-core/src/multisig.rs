// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Multisig: P2WSH `sortedmulti` registration, script derivation and the change proof
//! (0.2.0-m7).
//!
//! This module holds no keys and signs nothing. What it adds to the signing pipeline is
//! the one fact the PSBT engine cannot establish on its own: which multi-party script a
//! device has been told, in advance and by its owner, that it is a member of.
//!
//! ```text
//!   descriptor / Coldcard .txt -> [`parse`]                -> [`Pending`]  (nothing checked)
//!   pending + seed             -> [`Pending::verify`]      -> [`Registration`]
//!   registration + path + spk  -> [`Registration::locate`] -> [`Located`] or nothing
//! ```
//!
//! # Why a registration is the trust boundary
//!
//! A PSBT carries the cosigners' xpubs. Believing them is the 2021 Coldcard
//! xpub-substitution vulnerability: a coordinator that supplies the cosigner set also
//! decides what "our" change address is, and can make an address it controls look like
//! change. So [`Registration`] has no public constructor. The only way to make one is
//! [`Pending::verify`], which derives OUR key at the origin the descriptor claims and
//! refuses a wallet this device is not provably a member of. Everything downstream -
//! input binding, change classification, the first receive address - derives from the
//! stored record and never reads a cosigner xpub out of a PSBT.
//!
//! # Why the key ordering is consensus-relevant
//!
//! `sortedmulti` sorts the DERIVED public keys at each index, as 33-byte compressed
//! serializations in lexicographic byte order (BIP-67). It does not sort the xpubs and it
//! does not preserve the order the descriptor was written in. A signer that gets this
//! wrong computes a different witness script, therefore a different address, therefore a
//! different sighash, and disagrees with every other signer in the wallet about where the
//! money is. [`sorted_multi_witness_script`] is the one place the ordering is applied, and
//! this module's tests pin it against BIP-67's published vectors.
//!
//! # Scope
//!
//! P2WSH `sortedmulti` only (ARCHITECTURE.md 4, OPEN-QUESTIONS Q7). P2SH and P2SH-P2WSH
//! multisig are refused by name rather than silently ignored, and taproot multisig is not
//! in 0.2.0 at all. `multi(...)` - the unsorted form - is refused too: accepting it would
//! make the descriptor's textual key order decide the address, which is a second ordering
//! rule to get wrong for no gain, since no coordinator this device targets emits it.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::opcodes::all::OP_CHECKMULTISIG;
use bitcoin::script::Builder;
use bitcoin::{CompressedPublicKey, Network, NetworkKind, Script, ScriptBuf};

use crate::derive::secp;

// ---------------------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------------------

/// BIP-48's purpose. The only purpose a 0.2.0 multisig registration may claim.
const BIP48_PURPOSE: u32 = 48;
/// BIP-48's script-type step for native segwit multisig.
const BIP48_P2WSH: u32 = 2;

/// The largest cosigner set a registration may hold.
///
/// `OP_1`..`OP_16` encode the threshold and the key count in one byte, and Coldcard - the
/// interop target for the `.txt` dialect - caps a wallet at 15. Taking the lower of the
/// two keeps every registration this device stores importable by the coordinator it most
/// often shares a wallet with, and keeps the review screen a bounded size.
pub const MAX_COSIGNERS: u8 = 15;

// ---------------------------------------------------------------------------------------
// Public value types
// ---------------------------------------------------------------------------------------

/// The script type a registration covers.
///
/// One variant, deliberately: 0.2.0 is P2WSH `sortedmulti` and nothing else. It is an enum
/// rather than an assumption so that the record notyas-wallet seals SAYS which script type
/// it is, instead of leaving a future second type to be inferred from a record written
/// before it existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultisigScript {
    WshSortedMulti,
}

impl fmt::Display for MultisigScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("P2WSH sortedmulti")
    }
}

/// Which of a wallet's two keychains a leaf sits on.
///
/// A registration's descriptor names its own two chain indexes (`<0;1>` in every wallet
/// this device has met, but the descriptor is what decides). Callers ask in these terms so
/// that "chain 7" is not a thing anyone can ask for, and so that the meaning of the second
/// index - change, the thing check 3 is about - is carried by the type rather than by a
/// convention every call site has to remember.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keychain {
    Receive,
    Change,
}

impl fmt::Display for Keychain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Keychain::Receive => "receive",
            Keychain::Change => "change",
        })
    }
}

/// A content-derived name for a registration: the 8-character BIP-380 checksum of its
/// canonical descriptor.
///
/// Every device holding the same wallet computes the same value, because the canonical
/// form fixes the cosigner order and the hardened-marker spelling before the checksum is
/// taken. An index into a registry slice would not have that property, and a refusal that
/// names "registration 2" tells a user with three wallets nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegistrationId([u8; 8]);

impl fmt::Display for RegistrationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Every byte came from the BIP-380 checksum charset, which is ASCII.
        f.write_str(core::str::from_utf8(&self.0).unwrap_or("????????"))
    }
}

/// One member of a multisig wallet, as the descriptor states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cosigner {
    /// The MASTER fingerprint of the cosigner's seed, not the account node's own.
    pub fingerprint: Fingerprint,
    /// Where `xpub` sits under that master key, e.g. `m/48'/0'/0'/2'`.
    pub origin: DerivationPath,
    /// The account node. Everything this wallet locks is derived from these.
    pub xpub: Xpub,
}

/// Which text format an import arrived in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportDialect {
    /// BIP-380 output descriptor. The canonical form.
    Descriptor,
    /// Coldcard's multisig setup `.txt`. Converted to a descriptor on ingest and never
    /// stored in its own form (ARCHITECTURE.md 4), so there is exactly one stored shape to
    /// verify a PSBT against and one to re-render.
    ColdcardTxt,
}

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

/// The import could not be read at all. Says nothing about whether we are a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Malformed {
    Empty,
    /// A `#checksum` was present and did not validate. Present-and-wrong is a corrupted
    /// transfer, which is a refusal; absent is accepted, because a descriptor a user typed
    /// or a coordinator truncated the checksum from is still unambiguous, and the
    /// membership proof does not rest on it.
    ChecksumInvalid,
    /// Not a `wsh(...)` descriptor and not a Coldcard setup file.
    Unrecognised,
    /// A script type this device does not do, named so the refusal can say which
    /// (OPEN-QUESTIONS Q7).
    ScriptTypeUnsupported { named: &'static str },
    /// `multi(...)` rather than `sortedmulti(...)`. See the module docs.
    UnsortedMulti,
    ThresholdUnparseable,
    NoCosigners,
    /// More key expressions than [`MAX_COSIGNERS`]. Refused while reading rather than at
    /// verification, so that a descriptor listing thousands of cosigners costs one base58
    /// parse too many instead of thousands.
    TooManyCosigners { max: u8 },
    KeyExpressionMalformed { at: usize },
    /// A key expression with no `[fingerprint/path]` origin. Without one there is nothing
    /// to prove membership against.
    OriginMissing { at: usize },
    FingerprintUnparseable { at: usize },
    OriginPathUnparseable { at: usize },
    XpubUnparseable { at: usize },
    /// An xpub that base58-decodes and that BIP-32 nevertheless says cannot exist: depth
    /// zero - a master node - carrying a parent fingerprint or a child number. Distinct
    /// from [`Malformed::XpubUnparseable`] because the key IS readable, the objection is to
    /// its structure, and the two want different sentences on a screen.
    XpubStructurallyInvalid { at: usize },
    /// The tail after the xpub is not `<A;B>/*` or its `**` shorthand (BIP-389).
    DerivationSuffixUnsupported { at: usize },
    /// Key expressions disagree about the wallet's two keychains.
    KeychainsInconsistent,
    /// Both keychains are the same index, which would make every receive address also pass
    /// as change.
    KeychainsIdentical { chain: u32 },
    /// The cosigners are not all on one network.
    NetworkMixed,
    ColdcardMissingField { field: &'static str },
    ColdcardPolicyUnparseable,
    ColdcardCosignerCountMismatch { declared: usize, found: usize },
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Malformed::Empty => f.write_str("the file is empty"),
            Malformed::ChecksumInvalid => f.write_str("the descriptor checksum does not match"),
            Malformed::Unrecognised => {
                f.write_str("not a wsh() descriptor and not a Coldcard setup file")
            }
            Malformed::ScriptTypeUnsupported { named } => write!(
                f,
                "{named} multisig is not supported; this device does P2WSH only"
            ),
            Malformed::UnsortedMulti => {
                f.write_str("multi() is not supported; this device does sortedmulti() only")
            }
            Malformed::ThresholdUnparseable => f.write_str("the M of M-of-N is not a number"),
            Malformed::NoCosigners => f.write_str("the wallet lists no cosigners"),
            Malformed::TooManyCosigners { max } => {
                write!(f, "more cosigners than the {max} this device holds")
            }
            Malformed::KeyExpressionMalformed { at } => write!(f, "cosigner {at} is malformed"),
            Malformed::OriginMissing { at } => {
                write!(f, "cosigner {at} carries no [fingerprint/path] origin")
            }
            Malformed::FingerprintUnparseable { at } => {
                write!(f, "cosigner {at} has an unreadable fingerprint")
            }
            Malformed::OriginPathUnparseable { at } => {
                write!(f, "cosigner {at} has an unreadable derivation path")
            }
            Malformed::XpubUnparseable { at } => write!(f, "cosigner {at} has an unreadable xpub"),
            Malformed::XpubStructurallyInvalid { at } => write!(
                f,
                "cosigner {at} has an xpub BIP-32 forbids: a master key that claims a parent"
            ),
            Malformed::DerivationSuffixUnsupported { at } => write!(
                f,
                "cosigner {at} does not use a <receive;change>/* derivation"
            ),
            Malformed::KeychainsInconsistent => {
                f.write_str("the cosigners disagree about the wallet's keychains")
            }
            Malformed::KeychainsIdentical { chain } => write!(
                f,
                "receive and change are both keychain {chain}, so change cannot be told apart"
            ),
            Malformed::NetworkMixed => f.write_str("the cosigners are not all on one network"),
            Malformed::ColdcardMissingField { field } => {
                write!(f, "the setup file has no {field} line")
            }
            Malformed::ColdcardPolicyUnparseable => f.write_str("the Policy line is not \"M of N\""),
            Malformed::ColdcardCosignerCountMismatch { declared, found } => write!(
                f,
                "the policy says {declared} cosigners and the file lists {found}"
            ),
        }
    }
}

impl core::error::Error for Malformed {}

/// The import was readable and this device will not store it.
///
/// Every variant is a refusal with no override (OPEN-QUESTIONS Q24). A registration that
/// is wrong in any of these ways would go on to decide what "change" means for every
/// transaction the wallet ever signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The xpubs are for a different network than the device is on. Never taken from the
    /// file: the device's own network wins, which is the 2020 isolation-bypass lesson.
    NetworkMismatch { device: Network },
    ThresholdOutOfRange { m: u8, n: usize },
    TooManyCosigners { n: usize, max: u8 },
    /// Two cosigners share an account key. A "2-of-3" whose second and third members are
    /// the same key is a 2-of-2 the user did not agree to, and if the duplicate is the
    /// attacker's it is a 1-of-1.
    DuplicateXpub { first: usize, second: usize },
    /// Two cosigners share a master fingerprint. Same attack one step earlier, and it also
    /// makes "which origin is ours" ambiguous in every PSBT afterwards.
    DuplicateFingerprint { fingerprint: Fingerprint },
    /// A BIP-48 origin whose script-type step is not P2WSH. `1'` is P2SH-P2WSH and `3'` is
    /// taproot; both are out of 0.2.0 scope and are named rather than ignored.
    ScriptTypeNotP2wsh { at: usize, script_type: u32 },
    /// An origin that is not four hardened steps under purpose 48.
    OriginNotBip48 { at: usize },
    CoinTypeMismatch {
        at: usize,
        found: u32,
        expected: u32,
    },
    /// No cosigner carries this device's master fingerprint. Registering a wallet we cannot
    /// sign for would give the user a change-verification rule with nothing behind it.
    NotAMember { fingerprint: Fingerprint },
    /// A cosigner claims OUR fingerprint and OUR origin and names an xpub our seed does not
    /// derive there. This is the 2021 substitution attack arriving by its front door, and
    /// it is a distinct variant from [`Refusal::NotAMember`] because the two want very
    /// different sentences on a screen.
    XpubDoesNotDerive { at: usize },
    KeychainsIdentical { chain: u32 },
    /// A step of a claimed origin BIP32 will not walk. Unreachable for any path [`parse`]
    /// accepts; kept as a refusal rather than an unwrap because the alternative on a device
    /// holding a seed is a panic.
    Derivation,
    /// The canonical descriptor could not be checksummed, which would mean it contained a
    /// byte outside BIP-380's charset. Unreachable: every byte of it comes from hex,
    /// base58 or this module's own literals.
    DescriptorUnrenderable,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::NetworkMismatch { device } => write!(f, "those keys are not for {device}"),
            Refusal::ThresholdOutOfRange { m, n } => {
                write!(f, "{m} of {n} is not a policy this device can hold")
            }
            Refusal::TooManyCosigners { n, max } => {
                write!(f, "{n} cosigners is more than the {max} this device holds")
            }
            Refusal::DuplicateXpub { first, second } => write!(
                f,
                "cosigners {first} and {second} are the same key, so the policy is weaker than it reads"
            ),
            Refusal::DuplicateFingerprint { fingerprint } => {
                write!(f, "two cosigners both claim fingerprint {fingerprint}")
            }
            Refusal::ScriptTypeNotP2wsh { at, script_type } => write!(
                f,
                "cosigner {at} derives for script type {script_type}h; this device does P2WSH (2h) only"
            ),
            Refusal::OriginNotBip48 { at } => write!(f, "cosigner {at} is not on a BIP-48 path"),
            Refusal::CoinTypeMismatch {
                at,
                found,
                expected,
            } => write!(
                f,
                "cosigner {at} derives for coin type {found} and this device is on {expected}"
            ),
            Refusal::NotAMember { fingerprint } => {
                write!(f, "this device ({fingerprint}) is not one of the cosigners")
            }
            Refusal::XpubDoesNotDerive { at } => write!(
                f,
                "cosigner {at} claims this device's key and names an xpub this seed does not derive"
            ),
            Refusal::KeychainsIdentical { chain } => write!(
                f,
                "receive and change are both keychain {chain}, so change cannot be told apart"
            ),
            Refusal::Derivation => f.write_str("a claimed derivation path cannot be walked"),
            Refusal::DescriptorUnrenderable => {
                f.write_str("the descriptor could not be written back out")
            }
        }
    }
}

impl core::error::Error for Refusal {}

// ---------------------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------------------

/// A wallet as the file describes it. Nothing here has been checked against our keys.
///
/// This is what a confirmation screen renders. It is deliberately not storable: the type
/// that reaches the registry is [`Registration`], and the only way across is
/// [`Pending::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub dialect: ImportDialect,
    pub script: MultisigScript,
    pub threshold: u8,
    pub cosigners: Vec<Cosigner>,
    /// Taken from the xpub version bytes, and used only to check the file AGAINST the
    /// device's own network. It is never promoted to "the network we are on".
    pub network_kind: NetworkKind,
    pub receive_chain: u32,
    pub change_chain: u32,
}

/// Read a multisig wallet description, autodetecting the dialect.
///
/// A `wsh(` prefix means a descriptor; anything else is tried as a Coldcard setup file.
pub fn parse(text: &str) -> Result<Pending, Malformed> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(Malformed::Empty);
    }
    if let Some(named) = unsupported_wrapper(trimmed) {
        return Err(Malformed::ScriptTypeUnsupported { named });
    }
    if trimmed.starts_with("wsh(") {
        parse_descriptor(trimmed)
    } else {
        parse_coldcard(trimmed)
    }
}

/// The wrappers a user could plausibly hand this device that it will not do, so the refusal
/// can name the script type instead of saying "unrecognised" (Q7).
fn unsupported_wrapper(text: &str) -> Option<&'static str> {
    if text.starts_with("sh(wsh(") {
        Some("P2SH-P2WSH")
    } else if text.starts_with("sh(") {
        Some("P2SH")
    } else if text.starts_with("tr(") {
        Some("taproot")
    } else {
        None
    }
}

fn parse_descriptor(text: &str) -> Result<Pending, Malformed> {
    // BIP-380 pins the checksum to the last nine bytes exactly, so a '#' anywhere else
    // makes the whole string fail `check` - which is the right answer for a tail this
    // device cannot account for.
    let body = if text.contains('#') {
        if !crate::export::checksum::check(text) {
            return Err(Malformed::ChecksumInvalid);
        }
        &text[..text.len() - 9]
    } else {
        text
    };

    let inner = body
        .strip_prefix("wsh(")
        .and_then(|s| s.strip_suffix(')'))
        .ok_or(Malformed::Unrecognised)?;
    let args = match inner
        .strip_prefix("sortedmulti(")
        .and_then(|s| s.strip_suffix(')'))
    {
        Some(args) => args,
        None if inner.starts_with("multi(") => return Err(Malformed::UnsortedMulti),
        None => return Err(Malformed::Unrecognised),
    };

    // A key expression holds no comma: an origin uses '/', a multipath uses ';', and base58
    // has neither. Splitting on ',' is therefore exact rather than a heuristic.
    let mut fields = args.split(',');
    let threshold_text = fields.next().ok_or(Malformed::ThresholdUnparseable)?;
    let threshold: u8 = decimal(threshold_text.trim()).ok_or(Malformed::ThresholdUnparseable)?;

    let mut cosigners = Vec::new();
    let mut chains: Option<(u32, u32)> = None;
    for (at, field) in fields.enumerate() {
        if at >= usize::from(MAX_COSIGNERS) {
            return Err(Malformed::TooManyCosigners {
                max: MAX_COSIGNERS,
            });
        }
        let (cosigner, receive, change) = parse_key_expression(field.trim(), at)?;
        match chains {
            None => chains = Some((receive, change)),
            Some(seen) if seen != (receive, change) => {
                return Err(Malformed::KeychainsInconsistent)
            }
            Some(_) => {}
        }
        cosigners.push(cosigner);
    }
    let (receive_chain, change_chain) = chains.ok_or(Malformed::NoCosigners)?;
    if receive_chain == change_chain {
        return Err(Malformed::KeychainsIdentical {
            chain: receive_chain,
        });
    }

    Ok(Pending {
        dialect: ImportDialect::Descriptor,
        script: MultisigScript::WshSortedMulti,
        threshold,
        network_kind: one_network(&cosigners)?,
        cosigners,
        receive_chain,
        change_chain,
    })
}

/// `[fingerprint/origin]xpub/<receive;change>/*`, the only key expression 0.2.0 accepts.
fn parse_key_expression(expr: &str, at: usize) -> Result<(Cosigner, u32, u32), Malformed> {
    let rest = expr.strip_prefix('[').ok_or(Malformed::OriginMissing { at })?;
    let (origin_text, tail) = rest
        .split_once(']')
        .ok_or(Malformed::KeyExpressionMalformed { at })?;
    let (fingerprint_text, path_text) = origin_text
        .split_once('/')
        .ok_or(Malformed::OriginPathUnparseable { at })?;
    let fingerprint = Fingerprint::from_str(fingerprint_text)
        .map_err(|_| Malformed::FingerprintUnparseable { at })?;
    let origin = parse_path(path_text).ok_or(Malformed::OriginPathUnparseable { at })?;

    let (xpub_text, suffix) = tail
        .split_once('/')
        .ok_or(Malformed::DerivationSuffixUnsupported { at })?;
    let xpub = Xpub::from_str(xpub_text).map_err(|_| Malformed::XpubUnparseable { at })?;
    bip32_well_formed(&xpub, at)?;
    let (receive, change) =
        parse_multipath(suffix).ok_or(Malformed::DerivationSuffixUnsupported { at })?;

    Ok((
        Cosigner {
            fingerprint,
            origin,
            xpub,
        },
        receive,
        change,
    ))
}

/// The one spelling of a non-negative decimal this module accepts, wherever it reads a
/// number out of an import.
///
/// `u8::from_str` and its siblings also accept a leading `+`, and neither a BIP-380
/// descriptor nor a Coldcard setup file is ever written that way. Two devices holding one
/// wallet have to agree on its descriptor character for character, or the checksum a user
/// compares across screens and the [`RegistrationId`] derived from it differ for what is
/// the same wallet - so "what counts as a number here" is this module's rule to state, not
/// `core`'s to decide by accident. It is stated once because a parser that applies one rule
/// to a path step and another to a threshold has a seam in it, and a seam is what a hostile
/// file is written to sit in.
///
/// Leading zeros are accepted: they name the same index, and [`Pending::verify`] re-renders
/// the canonical spelling before anything is stored, so they cannot survive into a record.
fn decimal<T: FromStr>(text: &str) -> Option<T> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// BIP-32's must-reject rules for a serialised extended key, for the one part `bitcoin`'s
/// parser leaves open.
///
/// [`Xpub::from_str`] already refuses the version bytes, the 78-byte length, the base58
/// checksum, the `02`/`03` key prefix and the "the X coordinate must correspond to a point
/// on the curve" rule BIP-32 states for import. Run against BIP-32's own test vector 5 it
/// accepts exactly two of the sixteen invalid keys, and both are one rule: depth zero IS a
/// master node, and a master node has no parent and is nobody's child, so a non-zero parent
/// fingerprint or a non-zero child number at depth zero describes a key that cannot exist.
///
/// Refusing it moves no address by one bit - public child derivation reads only the chain
/// code and the public key, so such a key derives exactly what its well-formed twin does,
/// down to the P2WSH address. The reason to refuse anyway is that a registration is a
/// long-lived record: notyas-wallet re-parses and re-verifies it on every load, and the
/// user is shown it before every change approval. Accepting one means storing, for the life
/// of the wallet, a key this device has already seen it cannot fully validate, and a
/// coordinator that emits one has a defect its user wants to hear about at import rather
/// than at spend.
fn bip32_well_formed(xpub: &Xpub, at: usize) -> Result<(), Malformed> {
    let claims_a_parent = xpub.parent_fingerprint != Fingerprint::from([0u8; 4]);
    // Read as its full 32 bits rather than through `index_of`, which flattens the hardened
    // flag away: `0x80000000` is a non-zero child number that would otherwise pass as 0.
    let claims_an_index = u32::from(xpub.child_number) != 0;
    if xpub.depth == 0 && (claims_a_parent || claims_an_index) {
        return Err(Malformed::XpubStructurallyInvalid { at });
    }
    Ok(())
}

/// A derivation path in descriptor spelling: steps separated by `/`, hardened marked with
/// `h`, `H` or `'`, with or without a leading `m/`.
///
/// Hand written rather than delegated to `DerivationPath::from_str` so that the accepted
/// spellings are stated here rather than inherited from whatever a dependency's parser
/// happens to tolerate this release. A registration is compared against what another
/// device produced, so "what counts as the same path" is not a detail to leave to a
/// version bump.
fn parse_path(text: &str) -> Option<DerivationPath> {
    let text = text.strip_prefix("m/").unwrap_or(text);
    if text.is_empty() {
        return Some(DerivationPath::master());
    }
    let mut steps = Vec::new();
    for step in text.split('/') {
        let (digits, hardened) = match step.strip_suffix(['h', 'H', '\'']) {
            Some(digits) => (digits, true),
            None => (step, false),
        };
        let index: u32 = decimal(digits)?;
        steps.push(if hardened {
            ChildNumber::from_hardened_idx(index).ok()?
        } else {
            ChildNumber::from_normal_idx(index).ok()?
        });
    }
    Some(DerivationPath::from(steps))
}

/// `<receive;change>/*`, or BIP-389's `**` shorthand for `<0;1>/*`.
///
/// Single-chain forms (`0/*` alone) are rejected on purpose. A descriptor that names only
/// the receive chain has no change chain to derive, so every genuine change output would
/// classify as a payment and the user would be asked to approve a transaction that looks
/// like it burns its own change. Refusing at import is the honest place to say so.
fn parse_multipath(suffix: &str) -> Option<(u32, u32)> {
    if suffix == "**" {
        return Some((0, 1));
    }
    let inner = suffix.strip_suffix("/*")?;
    let inner = inner.strip_prefix('<')?.strip_suffix('>')?;
    let (receive, change) = inner.split_once(';')?;
    Some((unhardened_index(receive)?, unhardened_index(change)?))
}

fn unhardened_index(text: &str) -> Option<u32> {
    let index: u32 = decimal(text)?;
    // A keychain step is never hardened - an xpub could not walk one - so the hardened half
    // of the index space is not a spelling this device accepts here.
    ChildNumber::from_normal_idx(index).ok()?;
    Some(index)
}

fn one_network(cosigners: &[Cosigner]) -> Result<NetworkKind, Malformed> {
    let mut seen: Option<NetworkKind> = None;
    for cosigner in cosigners {
        match seen {
            None => seen = Some(cosigner.xpub.network),
            Some(kind) if kind != cosigner.xpub.network => return Err(Malformed::NetworkMixed),
            Some(_) => {}
        }
    }
    seen.ok_or(Malformed::NoCosigners)
}

// ---------------------------------------------------------------------------------------
// The Coldcard setup dialect
// ---------------------------------------------------------------------------------------

/// Coldcard's multisig setup `.txt` (https://coldcard.com/docs/multisig/).
///
/// A header of `Field: value` lines, then one `FINGERPRINT: xpub` line per cosigner.
/// `Derivation:` may appear once in the header or repeatedly between cosigners, in which
/// case it applies to the cosigners that follow it - which is how a wallet whose members
/// sit on different account indexes is expressed.
///
/// Converted straight to a [`Pending`] and never stored in this shape: one stored form
/// means one thing to verify a PSBT against.
fn parse_coldcard(text: &str) -> Result<Pending, Malformed> {
    let mut policy: Option<(usize, usize)> = None;
    let mut derivation: Option<DerivationPath> = None;
    let mut format_seen = false;
    let mut cosigners: Vec<Cosigner> = Vec::new();

    for raw in text.lines() {
        let line = match raw.split_once('#') {
            Some((before, _)) => before.trim(),
            None => raw.trim(),
        };
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());

        // A cosigner line is keyed by an 8-hex-digit fingerprint and every header line is
        // keyed by a word, so the two cannot collide.
        if key.len() == 8 && key.bytes().all(|b| b.is_ascii_hexdigit()) {
            let at = cosigners.len();
            if at >= usize::from(MAX_COSIGNERS) {
                return Err(Malformed::TooManyCosigners {
                    max: MAX_COSIGNERS,
                });
            }
            let fingerprint =
                Fingerprint::from_str(key).map_err(|_| Malformed::FingerprintUnparseable { at })?;
            let origin = derivation
                .clone()
                .ok_or(Malformed::ColdcardMissingField {
                    field: "Derivation",
                })?;
            let xpub = Xpub::from_str(value).map_err(|_| Malformed::XpubUnparseable { at })?;
            bip32_well_formed(&xpub, at)?;
            cosigners.push(Cosigner {
                fingerprint,
                origin,
                xpub,
            });
            continue;
        }

        match key.to_ascii_lowercase().as_str() {
            "policy" => {
                let (m, n) = value
                    .split_once(" of ")
                    .ok_or(Malformed::ColdcardPolicyUnparseable)?;
                policy = Some((
                    decimal(m.trim()).ok_or(Malformed::ColdcardPolicyUnparseable)?,
                    decimal(n.trim()).ok_or(Malformed::ColdcardPolicyUnparseable)?,
                ));
            }
            "derivation" => {
                derivation = Some(parse_path(value).ok_or(Malformed::OriginPathUnparseable {
                    at: cosigners.len(),
                })?);
            }
            "format" => {
                format_seen = true;
                match value.to_ascii_uppercase().as_str() {
                    "P2WSH" => {}
                    "P2SH-P2WSH" | "P2WSH-P2SH" => {
                        return Err(Malformed::ScriptTypeUnsupported {
                            named: "P2SH-P2WSH",
                        })
                    }
                    "P2SH" => return Err(Malformed::ScriptTypeUnsupported { named: "P2SH" }),
                    _ => return Err(Malformed::Unrecognised),
                }
            }
            // Name, and anything a later Coldcard release adds, are the wallet layer's
            // business or nobody's. Ignoring them keeps a new header line from making an
            // otherwise valid file unreadable.
            _ => {}
        }
    }

    if !format_seen {
        return Err(Malformed::ColdcardMissingField { field: "Format" });
    }
    let (m, n) = policy.ok_or(Malformed::ColdcardMissingField { field: "Policy" })?;
    if cosigners.is_empty() {
        return Err(Malformed::NoCosigners);
    }
    if n != cosigners.len() {
        return Err(Malformed::ColdcardCosignerCountMismatch {
            declared: n,
            found: cosigners.len(),
        });
    }
    let threshold = u8::try_from(m).map_err(|_| Malformed::ColdcardPolicyUnparseable)?;

    Ok(Pending {
        dialect: ImportDialect::ColdcardTxt,
        script: MultisigScript::WshSortedMulti,
        threshold,
        network_kind: one_network(&cosigners)?,
        cosigners,
        // The setup file carries no multipath. Coldcard's own wallets are `<0;1>`, and that
        // is the pair the canonical descriptor is written with.
        receive_chain: 0,
        change_chain: 1,
    })
}

// ---------------------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------------------

impl Pending {
    /// (M, N), for a review header.
    pub fn threshold_of(&self) -> (u8, usize) {
        (self.threshold, self.cosigners.len())
    }

    /// Prove membership and produce the record the registry stores.
    ///
    /// The 2021 xpub-substitution defense in one function: our own key is DERIVED at the
    /// origin the file claims and compared, the cosigner set is checked for the duplicates
    /// that quietly weaken a policy, the origins are checked for BIP-48 P2WSH shape and
    /// for this device's coin type, and a wallet we cannot prove membership of is refused
    /// rather than stored with a warning.
    ///
    /// `network` is the DEVICE's network and is never read from the file.
    pub fn verify(self, seed: &[u8; 64], network: Network) -> Result<Registration, Refusal> {
        let Pending {
            script,
            threshold,
            cosigners,
            network_kind,
            receive_chain,
            change_chain,
            ..
        } = self;

        if network_kind != NetworkKind::from(network) {
            return Err(Refusal::NetworkMismatch { device: network });
        }
        if receive_chain == change_chain {
            return Err(Refusal::KeychainsIdentical {
                chain: receive_chain,
            });
        }

        let n = cosigners.len();
        if n == 0 || n > usize::from(MAX_COSIGNERS) {
            return Err(Refusal::TooManyCosigners {
                n,
                max: MAX_COSIGNERS,
            });
        }
        if threshold == 0 || usize::from(threshold) > n {
            return Err(Refusal::ThresholdOutOfRange { m: threshold, n });
        }

        // Quadratic over at most 15 cosigners, which is 105 comparisons once per import.
        for i in 0..n {
            for j in i + 1..n {
                if cosigners[i].xpub.public_key == cosigners[j].xpub.public_key
                    && cosigners[i].xpub.chain_code == cosigners[j].xpub.chain_code
                {
                    return Err(Refusal::DuplicateXpub {
                        first: i,
                        second: j,
                    });
                }
                if cosigners[i].fingerprint == cosigners[j].fingerprint {
                    return Err(Refusal::DuplicateFingerprint {
                        fingerprint: cosigners[i].fingerprint,
                    });
                }
            }
        }

        let expected_coin = coin_type_for(network);
        for (at, cosigner) in cosigners.iter().enumerate() {
            let steps: Vec<ChildNumber> = cosigner.origin.into_iter().copied().collect();
            if steps.len() != 4 || steps.iter().any(|step| !step.is_hardened()) {
                return Err(Refusal::OriginNotBip48 { at });
            }
            if index_of(steps[0]) != BIP48_PURPOSE {
                return Err(Refusal::OriginNotBip48 { at });
            }
            let coin = index_of(steps[1]);
            if coin != expected_coin {
                return Err(Refusal::CoinTypeMismatch {
                    at,
                    found: coin,
                    expected: expected_coin,
                });
            }
            let script_type = index_of(steps[3]);
            if script_type != BIP48_P2WSH {
                return Err(Refusal::ScriptTypeNotP2wsh { at, script_type });
            }
        }

        let our_fingerprint = crate::derive::master_fingerprint(seed, network);
        let mut ours: Option<usize> = None;
        for (at, cosigner) in cosigners.iter().enumerate() {
            if cosigner.fingerprint != our_fingerprint {
                continue;
            }
            let mine = xpub_at(seed, network, &cosigner.origin).ok_or(Refusal::Derivation)?;
            // Compared on key material only. Depth, parent fingerprint and child number are
            // metadata some wallets zero on export, and two xpubs with the same chain code
            // and public key derive identical children whatever their metadata says, so
            // demanding those too would refuse a wallet this device really is a member of.
            if mine.public_key != cosigner.xpub.public_key
                || mine.chain_code != cosigner.xpub.chain_code
            {
                return Err(Refusal::XpubDoesNotDerive { at });
            }
            ours = Some(at);
        }
        let ours = ours.ok_or(Refusal::NotAMember {
            fingerprint: our_fingerprint,
        })?;

        // Canonical order, fixed AFTER every refusal above so that a refusal's `at` names
        // the cosigner in the order the user was shown. sortedmulti sorts derived keys at
        // every index and is therefore entirely indifferent to descriptor order; fixing one
        // here is what makes the stored string, and so the id, identical on every device
        // holding this wallet. Sorted by the xpub's own text rather than by its key bytes,
        // so that nobody reads this as a second, competing application of BIP-67.
        let our_xpub = cosigners[ours].xpub;
        let mut cosigners = cosigners;
        cosigners.sort_by_cached_key(|cosigner| cosigner.xpub.to_string());
        let ours = cosigners
            .iter()
            .position(|cosigner| cosigner.xpub == our_xpub)
            .expect("the cosigner just proven ours survives a reordering");

        let descriptor = render_descriptor(threshold, &cosigners, receive_chain, change_chain)
            .ok_or(Refusal::DescriptorUnrenderable)?;
        let id = id_from_descriptor(&descriptor).ok_or(Refusal::DescriptorUnrenderable)?;

        Ok(Registration {
            id,
            network,
            script,
            threshold,
            cosigners,
            ours,
            receive_chain,
            change_chain,
            descriptor,
        })
    }
}

// ---------------------------------------------------------------------------------------
// The stored record
// ---------------------------------------------------------------------------------------

/// A multisig wallet this device has proven it is a member of.
///
/// Fields are private and there is no public constructor: [`Pending::verify`] is the only
/// way to make one, and it needs a seed. That is the mechanism behind "multisig change is
/// derived from the STORED registration and never from PSBT-supplied xpubs" - not a rule a
/// reviewer has to enforce, but a type nobody can build out of a PSBT.
///
/// notyas-wallet wraps this with the identity a sealed record needs - the slot it lives in,
/// the owning wallet and the user's label - and re-runs [`parse`] and [`Pending::verify`]
/// when it loads one, so a record that somehow changed under storage cannot become
/// authoritative by having been stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    id: RegistrationId,
    network: Network,
    script: MultisigScript,
    threshold: u8,
    cosigners: Vec<Cosigner>,
    ours: usize,
    receive_chain: u32,
    change_chain: u32,
    descriptor: String,
}

/// Where a script sits in a registration, and everything a signer needs about that leaf.
///
/// Produced only by [`Registration::locate`], which returns it only after re-deriving the
/// script and finding it equal to the one asked about. Holding this value IS the proof;
/// there is no way to obtain one for a script the registration does not build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    pub keychain: Keychain,
    pub index: u32,
    /// Rebuilt from the registration. Never the copy a PSBT supplied.
    pub witness_script: ScriptBuf,
    /// Our own cosigner's key at this leaf, from the registration's xpub.
    pub our_key: CompressedPublicKey,
}

impl Registration {
    pub fn id(&self) -> RegistrationId {
        self.id
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn script(&self) -> MultisigScript {
        self.script
    }

    /// (M, N), for the review header.
    pub fn threshold_of(&self) -> (u8, u8) {
        (self.threshold, self.cosigners.len() as u8)
    }

    pub fn cosigners(&self) -> &[Cosigner] {
        &self.cosigners
    }

    /// The cosigner this device holds the key for.
    pub fn ours(&self) -> &Cosigner {
        &self.cosigners[self.ours]
    }

    /// Which cosigner that is, as a position in [`Registration::cosigners`].
    ///
    /// The identity is already reachable through [`Registration::ours`]; the POSITION is
    /// what anything rendering one row or column per cosigner has to line up with, and
    /// recovering it by comparing fingerprints would re-derive an answer the registration
    /// already knows (`crate::address::AddressEntry::our_path` is the caller).
    pub fn our_position(&self) -> usize {
        self.ours
    }

    /// The canonical descriptor with its BIP-380 checksum. This is what gets sealed.
    pub fn descriptor(&self) -> &str {
        &self.descriptor
    }

    /// The descriptor's own index for one keychain.
    pub fn chain_index(&self, keychain: Keychain) -> u32 {
        match keychain {
            Keychain::Receive => self.receive_chain,
            Keychain::Change => self.change_chain,
        }
    }

    /// How many BIP-32 child derivations one [`locate`](Registration::locate) of this
    /// wallet costs at worst.
    ///
    /// The price list a caller that has to RATION this work needs, and the reason it is a
    /// method and not a comment: [`witness_script`](Registration::witness_script) derives
    /// two levels (the keychain step and the leaf index) for every cosigner, and
    /// [`our_key_at`](Registration::our_key_at) derives the same two again for ours, so a
    /// 15-of-15 costs four times what a 2-of-3 does and a caller that priced them alike
    /// would be rationing the wrong thing. Quoted as the ceiling - the whole of `locate`,
    /// proof included - so that charging it before the call can never under-charge.
    ///
    /// [`locate_path`](Registration::locate_path) is not in this figure and must not be:
    /// it compares a path against a stored origin and derives nothing at all, which is
    /// what lets a caller ask "could this path name this wallet" for free.
    pub fn leaf_derivations(&self) -> u32 {
        // Each `derive_leaf` walks the chain step and then the index step.
        2 * (self.cosigners.len() as u32 + 1)
    }

    /// The witness script this wallet locks at one leaf, with BIP-67 ordering applied.
    ///
    /// `None` only if a child number is outside the unhardened range, which
    /// [`Registration::locate_path`] has already excluded for any path that got this far.
    pub fn witness_script(&self, keychain: Keychain, index: u32) -> Option<ScriptBuf> {
        let chain = self.chain_index(keychain);
        let mut keys = Vec::with_capacity(self.cosigners.len());
        for cosigner in &self.cosigners {
            keys.push(derive_leaf(&cosigner.xpub, chain, index)?.serialize());
        }
        Some(sorted_multi_script(self.threshold, &mut keys))
    }

    /// The P2WSH scriptPubKey for the same leaf: what an address renders and what an output
    /// has to equal to be this wallet's.
    pub fn script_pubkey(&self, keychain: Keychain, index: u32) -> Option<ScriptBuf> {
        let witness_script = self.witness_script(keychain, index)?;
        Some(ScriptBuf::new_p2wsh(&witness_script.wscript_hash()))
    }

    /// The address one leaf of this wallet pays to: the P2WSH commitment of
    /// [`Registration::witness_script`], rendered on the registration's own network.
    ///
    /// Built from the witness script directly rather than from
    /// [`Registration::script_pubkey`], so one leaf costs one derivation of the cosigner
    /// keys rather than two; the two agree by construction because P2WSH is the only
    /// script shape 0.2.0 registers.
    pub fn address(&self, keychain: Keychain, index: u32) -> Option<bitcoin::Address> {
        let witness_script = self.witness_script(keychain, index)?;
        Some(bitcoin::Address::p2wsh(&witness_script, self.network))
    }

    /// The wallet's first receive address, which is the manual stand-in for BSMS round 2:
    /// the user compares it across devices before approving the registration.
    pub fn first_receive_address(&self) -> Option<bitcoin::Address> {
        self.address(Keychain::Receive, 0)
    }

    /// Our own cosigner's public key at one leaf.
    pub fn our_key_at(&self, keychain: Keychain, index: u32) -> Option<CompressedPublicKey> {
        let chain = self.chain_index(keychain);
        Some(CompressedPublicKey(derive_leaf(
            &self.ours().xpub,
            chain,
            index,
        )?))
    }

    /// Read a claimed derivation path as a leaf of THIS wallet, or refuse to.
    ///
    /// The path has to be our own cosigner's origin followed by exactly one keychain step
    /// and one unhardened index. A path that is longer, shorter, hardened below the origin,
    /// or on a chain this descriptor does not name is not a leaf of this wallet, and
    /// answering `None` is what makes such an output a payment rather than change.
    pub fn locate_path(&self, path: &DerivationPath) -> Option<(Keychain, u32)> {
        let steps: Vec<ChildNumber> = path.into_iter().copied().collect();
        let origin: Vec<ChildNumber> = self.ours().origin.into_iter().copied().collect();
        if steps.len() != origin.len() + 2 || steps[..origin.len()] != origin[..] {
            return None;
        }
        let (ChildNumber::Normal { index: chain }, ChildNumber::Normal { index }) =
            (steps[origin.len()], steps[origin.len() + 1])
        else {
            return None;
        };
        let keychain = if chain == self.receive_chain {
            Keychain::Receive
        } else if chain == self.change_chain {
            Keychain::Change
        } else {
            return None;
        };
        Some((keychain, index))
    }

    /// The whole change check in one call: does this wallet independently build
    /// `script_pubkey` at the leaf `path` claims?
    ///
    /// Both halves are required and neither is inferred from the other. The path decides
    /// WHICH leaf to build - it is a hint, and a hostile one is free to point anywhere -
    /// and the rebuilt script decides whether the answer is yes. A coordinator that labels
    /// its own address as our change supplies a path that builds some script of ours; that
    /// script is not the attacker's address, so the comparison fails and the output is a
    /// payment. That failure is the whole of the 2019 change-confusion defense, which is
    /// why this function has no "close enough" branch and no script-shape heuristic
    /// anywhere in it.
    pub fn locate(&self, path: &DerivationPath, script_pubkey: &Script) -> Option<Located> {
        let (keychain, index) = self.locate_path(path)?;
        self.locate_leaf(keychain, index, script_pubkey)
    }

    /// The half of [`locate`](Registration::locate) that costs something: rebuild the leaf
    /// and compare the whole scriptPubKey.
    ///
    /// Split out for one caller and one reason - `psbt::checks` has to CHARGE
    /// [`leaf_derivations`](Registration::leaf_derivations) against a file's work budget
    /// before this runs, and a charge levied after the derivations is not a bound. Every
    /// other caller wants the two halves in one call and should keep using `locate`;
    /// nothing about the decision changes here, and there is still no branch that accepts
    /// a near miss.
    pub fn locate_leaf(
        &self,
        keychain: Keychain,
        index: u32,
        script_pubkey: &Script,
    ) -> Option<Located> {
        let witness_script = self.witness_script(keychain, index)?;
        if ScriptBuf::new_p2wsh(&witness_script.wscript_hash()) != *script_pubkey {
            return None;
        }
        let our_key = self.our_key_at(keychain, index)?;
        Some(Located {
            keychain,
            index,
            witness_script,
            our_key,
        })
    }
}

/// The one registration in `registry` that builds `script_pubkey` at `path`, if any.
///
/// Two registrations cannot meaningfully collide on a script: if both build it then both
/// have the same cosigner keys at that index, so which one answers is immaterial. Returning
/// the first keeps the search linear in a registry that holds eight records.
///
/// # What this costs, and who has to care
///
/// Linear is not cheap here. [`Registration::locate`] does the free half first, so a
/// registration whose origin the path cannot name costs a path comparison and nothing
/// more - but a path that every registration's origin DOES name costs every registration's
/// [`leaf_derivations`](Registration::leaf_derivations), and eight 15-of-15 records is 256
/// BIP-32 derivations for one answer. Two things make that an attacker's number rather
/// than a user's: the path comes out of a PSBT, and registrations share an origin whenever
/// a user registers several wallets at the same BIP-48 account.
///
/// So a caller that runs this ONCE per file may use it as it stands, and a caller that
/// runs it once per entry of a map the file sizes must not: it has to walk the registry
/// itself, charging [`Registration::leaf_derivations`] against a budget before each
/// [`Registration::locate_leaf`]. `psbt::checks::prove_registered_output` is that caller
/// and says so.
pub fn locate_in(
    registry: &[Registration],
    path: &DerivationPath,
    script_pubkey: &Script,
) -> Option<(RegistrationId, Located)> {
    registry.iter().find_map(|registration| {
        Some((registration.id(), registration.locate(path, script_pubkey)?))
    })
}

// ---------------------------------------------------------------------------------------
// BIP-67 ordering and script assembly
// ---------------------------------------------------------------------------------------

/// `OP_M <key>... OP_N OP_CHECKMULTISIG` with the keys in BIP-67 order.
///
/// `None` for a policy outside 1-of-1 to [`MAX_COSIGNERS`]-of-[`MAX_COSIGNERS`], because a
/// script built from one would either not encode (`OP_0`) or not be a policy this device
/// stores.
pub fn sorted_multi_witness_script(
    threshold: u8,
    keys: &[CompressedPublicKey],
) -> Option<ScriptBuf> {
    if threshold == 0
        || usize::from(threshold) > keys.len()
        || keys.len() > usize::from(MAX_COSIGNERS)
    {
        return None;
    }
    let mut serialized: Vec<[u8; 33]> = keys.iter().map(|key| key.0.serialize()).collect();
    Some(sorted_multi_script(threshold, &mut serialized))
}

/// The ordering rule itself, over raw compressed serializations.
///
/// Takes bytes rather than parsed keys for one reason: BIP-67's third published vector uses
/// keys that are not points on the curve, precisely so that a signer's SORTING can be
/// pinned independently of its key parsing. A typed-only implementation cannot be tested
/// against it.
///
/// Sorting in place is what makes the descriptor's own key order irrelevant, which is the
/// property the whole scheme rests on: every cosigner writes the wallet down in whatever
/// order it received the xpubs, and they all still compute one address.
fn sorted_multi_script(threshold: u8, keys: &mut [[u8; 33]]) -> ScriptBuf {
    keys.sort_unstable();
    let mut builder = Builder::new().push_int(i64::from(threshold));
    for key in keys.iter() {
        builder = builder.push_slice(key);
    }
    builder
        .push_int(keys.len() as i64)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script()
}

// ---------------------------------------------------------------------------------------
// Rendering and small helpers
// ---------------------------------------------------------------------------------------

/// The canonical stored form: `wsh(sortedmulti(M,[fp/48h/0h/0h/2h]xpub/<0;1>/*,...))#sum`.
fn render_descriptor(
    threshold: u8,
    cosigners: &[Cosigner],
    receive: u32,
    change: u32,
) -> Option<String> {
    let mut body = format!("wsh(sortedmulti({threshold}");
    for cosigner in cosigners {
        body.push_str(&format!(
            ",[{}/{}]{}/<{};{}>/*",
            cosigner.fingerprint,
            render_path(&cosigner.origin),
            cosigner.xpub,
            receive,
            change
        ));
    }
    body.push_str("))");
    crate::export::checksum::create(&body)
}

/// A path in the descriptor's own spelling: no leading `m/`, hardened as `h`. Matches the
/// form [`crate::export::descriptor`] writes, so the two modules render one wallet's
/// origins identically.
fn render_path(path: &DerivationPath) -> String {
    let mut out = String::new();
    for (i, step) in path.into_iter().enumerate() {
        if i > 0 {
            out.push('/');
        }
        match step {
            ChildNumber::Normal { index } => out.push_str(&format!("{index}")),
            ChildNumber::Hardened { index } => out.push_str(&format!("{index}h")),
        }
    }
    out
}

/// The last eight characters of a checksummed descriptor.
fn id_from_descriptor(descriptor: &str) -> Option<RegistrationId> {
    let bytes = descriptor.as_bytes();
    let start = bytes.len().checked_sub(8)?;
    Some(RegistrationId(bytes[start..].try_into().ok()?))
}

fn derive_leaf(xpub: &Xpub, chain: u32, index: u32) -> Option<bitcoin::secp256k1::PublicKey> {
    let path = [
        ChildNumber::from_normal_idx(chain).ok()?,
        ChildNumber::from_normal_idx(index).ok()?,
    ];
    Some(xpub.derive_pub(secp(), &path).ok()?.public_key)
}

/// The account xpub our seed derives at `path`.
///
/// Goes through [`crate::derive::SecretXpriv`] so the intermediate private node is wiped on
/// the way out, exactly as [`crate::sign::derive_path`] does: a membership proof must not be
/// a cheaper way to leave key material on the stack than signing is.
fn xpub_at(seed: &[u8; 64], network: Network, path: &DerivationPath) -> Option<Xpub> {
    let secp = secp();
    let root = crate::derive::master(seed, network);
    let child = crate::derive::SecretXpriv::new(root.key().derive_priv(secp, path).ok()?);
    Some(Xpub::from_priv(secp, child.key()))
}

/// BIP44/SLIP-44 coin type: 0 for mainnet, 1 for every test chain. The same rule
/// `psbt::checks` and `derive` apply; all three are pinned against SLIP-44 itself rather
/// than against each other, because a shared helper would let one wrong answer be
/// consistent everywhere.
fn coin_type_for(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 0,
        _ => 1,
    }
}

fn index_of(child: ChildNumber) -> u32 {
    match child {
        ChildNumber::Normal { index } | ChildNumber::Hardened { index } => index,
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Three seeds that stand in for three devices. Constants, so the wallet they form has
    /// one descriptor and one first address for every run.
    const SEEDS: [[u8; 64]; 3] = [[0x2a; 64], [0x11; 64], [0x22; 64]];
    const NETWORK: Network = Network::Bitcoin;
    const ORIGIN: &str = "48h/0h/0h/2h";

    fn key_expression(seed: &[u8; 64], origin: &str) -> String {
        let fingerprint = crate::derive::master_fingerprint(seed, NETWORK);
        let path = parse_path(origin).expect("test origin parses");
        let xpub = xpub_at(seed, NETWORK, &path).expect("test origin derives");
        format!("[{fingerprint}/{origin}]{xpub}/<0;1>/*")
    }

    /// A 2-of-3 whose first member is `SEEDS[0]`, written in the order given.
    fn descriptor_of(order: [usize; 3]) -> String {
        format!(
            "wsh(sortedmulti(2,{},{},{}))",
            key_expression(&SEEDS[order[0]], ORIGIN),
            key_expression(&SEEDS[order[1]], ORIGIN),
            key_expression(&SEEDS[order[2]], ORIGIN)
        )
    }

    fn wallet() -> Registration {
        parse(&descriptor_of([0, 1, 2]))
            .expect("test descriptor parses")
            .verify(&SEEDS[0], NETWORK)
            .expect("seed 0 is a member")
    }

    // -- BIP-67, the consensus-relevant part -------------------------------------------

    fn keys_from_hex(list: &[&str]) -> Vec<[u8; 33]> {
        list.iter()
            .map(|text| {
                let bytes = hex::decode(text).expect("vector key is hex");
                let mut key = [0u8; 33];
                key.copy_from_slice(&bytes);
                key
            })
            .collect()
    }

    /// BIP-67's four published vectors, at the level the BIP states them: a key list, a
    /// threshold, and the resulting `OP_M ... OP_N OP_CHECKMULTISIG` script.
    ///
    /// Vector 3's keys are not points on the curve. That is the whole reason this runs
    /// against the byte-level assembler: it isolates the ORDERING - which is what a signer
    /// gets wrong and disagrees with its cosigners about - from key parsing, and it covers
    /// the two edges that matter, a `02` prefix sorting before an `03` one and two keys
    /// differing only in their final byte.
    #[test]
    fn sorted_multi_matches_the_bip67_published_vectors() {
        let cases: [(u8, &[&str], &str); 4] = [
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
                    "030000000000000000000000000000000000004141414141414141414141414141",
                    "020000000000000000000000000000000000004141414141414141414141414141",
                    "020000000000000000000000000000000000004141414141414141414141414140",
                    "030000000000000000000000000000000000004141414141414141414141414140",
                ],
                "522102000000000000000000000000000000000000414141414141414141414141414021020000000000000000000000000000000000004141414141414141414141414141210300000000000000000000000000000000000041414141414141414141414141402103000000000000000000000000000000000000414141414141414141414141414154ae",
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
            let mut serialized = keys_from_hex(keys);
            let script = sorted_multi_script(threshold, &mut serialized);
            assert_eq!(
                hex::encode(script.as_bytes()),
                want,
                "BIP-67 vector with {} keys",
                keys.len()
            );
        }
    }

    /// The ordering is a property of the key set and not of the order it arrives in. Every
    /// permutation of one cosigner set has to give one script, or two devices holding the
    /// same wallet compute two different addresses.
    #[test]
    fn sorted_multi_is_indifferent_to_the_order_it_is_given() {
        let base = keys_from_hex(&[
            "02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0",
            "027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77",
            "02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404",
        ]);
        let want = sorted_multi_script(2, &mut base.clone());
        for permutation in [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]] {
            let mut keys: Vec<[u8; 33]> = permutation.iter().map(|&i| base[i]).collect();
            assert_eq!(sorted_multi_script(2, &mut keys), want);
        }
    }

    /// A whole registration re-derives one wallet however the descriptor is written.
    #[test]
    fn a_registration_is_indifferent_to_descriptor_order() {
        let a = wallet();
        let b = parse(&descriptor_of([2, 0, 1]))
            .unwrap()
            .verify(&SEEDS[0], NETWORK)
            .unwrap();
        assert_eq!(a.descriptor(), b.descriptor());
        assert_eq!(a.id(), b.id());
        assert_eq!(
            a.script_pubkey(Keychain::Receive, 0),
            b.script_pubkey(Keychain::Receive, 0)
        );
    }

    // -- Parsing ------------------------------------------------------------------------

    #[test]
    fn the_canonical_descriptor_round_trips_through_its_own_parser() {
        let registration = wallet();
        let again = parse(registration.descriptor())
            .unwrap()
            .verify(&SEEDS[0], NETWORK)
            .unwrap();
        assert_eq!(registration, again);
        assert!(crate::export::checksum::check(registration.descriptor()));
    }

    /// BIP-389's `**` means `<0;1>/*` and has to land on the same wallet.
    #[test]
    fn the_double_wildcard_shorthand_is_the_zero_one_multipath() {
        let shorthand = descriptor_of([0, 1, 2]).replace("/<0;1>/*", "/**");
        let pending = parse(&shorthand).unwrap();
        assert_eq!((pending.receive_chain, pending.change_chain), (0, 1));
        assert_eq!(
            pending.verify(&SEEDS[0], NETWORK).unwrap().descriptor(),
            wallet().descriptor()
        );
    }

    /// Untrusted text reaches the checksum reader, so it must refuse rather than panic on
    /// anything, a multi-byte character at the split position most of all.
    #[test]
    fn a_non_ascii_descriptor_is_refused_and_does_not_panic() {
        for hostile in [
            // Fourteen bytes, so the checksum split falls at byte 5 - the SECOND byte
            // of the two-byte character. A split by byte position lands inside a
            // character there, which is the case that panics rather than refusing.
            "wsh(#\u{00e9}12345678",
            "wsh(sortedmulti(1))#aaaaaaa\u{00e9}",
            "\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}",
            "#",
            "wsh(sortedmulti(2,#",
        ] {
            let answer = parse(hostile);
            assert!(answer.is_err(), "{hostile:?} must not be accepted");
        }
    }

    #[test]
    fn a_cosigner_list_past_the_cap_is_refused_while_reading() {
        let mut body = String::from("wsh(sortedmulti(2");
        for _ in 0..usize::from(MAX_COSIGNERS) + 2 {
            body.push(',');
            body.push_str(&key_expression(&SEEDS[0], ORIGIN));
        }
        body.push_str("))");
        assert_eq!(
            parse(&body),
            Err(Malformed::TooManyCosigners {
                max: MAX_COSIGNERS
            })
        );
    }

    #[test]
    fn a_bad_checksum_is_refused_and_a_good_one_is_not() {
        let registration = wallet();
        assert!(parse(registration.descriptor()).is_ok());
        let mut broken = String::from(registration.descriptor());
        broken.pop();
        broken.push('q');
        assert_eq!(parse(&broken), Err(Malformed::ChecksumInvalid));
    }

    #[test]
    fn the_script_types_out_of_scope_are_refused_by_name() {
        let body = descriptor_of([0, 1, 2]);
        let inner = body.strip_prefix("wsh(").unwrap().strip_suffix(')').unwrap();
        assert_eq!(
            parse(&format!("sh(wsh({inner}))")),
            Err(Malformed::ScriptTypeUnsupported {
                named: "P2SH-P2WSH"
            })
        );
        assert_eq!(
            parse(&format!("sh({inner})")),
            Err(Malformed::ScriptTypeUnsupported { named: "P2SH" })
        );
        assert_eq!(
            parse(&format!("tr({inner})")),
            Err(Malformed::ScriptTypeUnsupported { named: "taproot" })
        );
    }

    /// `multi()` orders by the text, `sortedmulti()` by the keys. Accepting both would put
    /// two ordering rules in one device.
    #[test]
    fn unsorted_multi_is_refused() {
        let unsorted = descriptor_of([0, 1, 2]).replace("sortedmulti(", "multi(");
        assert_eq!(parse(&unsorted), Err(Malformed::UnsortedMulti));
    }

    /// A descriptor whose two keychains are the same index would make every receive address
    /// pass as change.
    #[test]
    fn identical_keychains_are_refused() {
        let collapsed = descriptor_of([0, 1, 2]).replace("/<0;1>/*", "/<1;1>/*");
        assert_eq!(
            parse(&collapsed),
            Err(Malformed::KeychainsIdentical { chain: 1 })
        );
    }

    #[test]
    fn a_single_chain_derivation_is_refused() {
        let single = descriptor_of([0, 1, 2]).replace("/<0;1>/*", "/0/*");
        assert_eq!(
            parse(&single),
            Err(Malformed::DerivationSuffixUnsupported { at: 0 })
        );
    }

    #[test]
    fn a_key_with_no_origin_is_refused() {
        let stripped = descriptor_of([0, 1, 2]);
        let start = stripped.find('[').unwrap();
        let end = stripped.find(']').unwrap();
        let stripped = format!("{}{}", &stripped[..start], &stripped[end + 1..]);
        assert_eq!(parse(&stripped), Err(Malformed::OriginMissing { at: 0 }));
    }

    /// One module, one spelling for a number.
    ///
    /// `u8::from_str` takes a leading `+` and [`parse_path`], one function away, does not.
    /// No wallet is lost to the difference - [`Pending::verify`] re-renders the canonical
    /// descriptor from the parsed integer, so `+2` and `2` reach storage as one record with
    /// one id and one set of addresses - but a parser holding two rules for one thing is a
    /// seam, and a device that accepts a spelling it will never itself emit invites two
    /// devices to disagree about what their shared wallet's descriptor says.
    #[test]
    fn a_signed_number_is_refused_wherever_the_module_reads_one() {
        let signed = descriptor_of([0, 1, 2]).replace("sortedmulti(2,", "sortedmulti(+2,");
        assert_eq!(parse(&signed), Err(Malformed::ThresholdUnparseable));
        let signed_policy = coldcard_file().replace("Policy: 2 of 3", "Policy: +2 of 3");
        assert_eq!(
            parse(&signed_policy),
            Err(Malformed::ColdcardPolicyUnparseable)
        );
        // The two that were already strict, so the test fails if the rule ever splits again.
        assert!(parse_path("48h/+0h/0h/2h").is_none());
        assert!(parse_multipath("<+0;1>/*").is_none());
    }

    /// BIP-32 test vector 5, "zero depth with non-zero parent fingerprint", arriving by the
    /// dialect's other door.
    ///
    /// Both dialects take coordinator-supplied xpubs, so both have to apply the structure
    /// rule; `multisig_vectors.rs` runs the whole published vector-5 list through the
    /// descriptor path, and this pins that the Coldcard path is not a way around it.
    #[test]
    fn a_coldcard_file_naming_a_structurally_invalid_xpub_is_refused() {
        // PUBLISHED. BIP-32 test vector 5, entry "zero depth with non-zero parent
        // fingerprint" (https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
        const ZERO_DEPTH_WITH_PARENT: &str = "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ";

        let ours = key_expression(&SEEDS[0], ORIGIN);
        let ours_xpub = ours.split(']').nth(1).unwrap().replace("/<0;1>/*", "");
        let ours_fingerprint = crate::derive::master_fingerprint(&SEEDS[0], NETWORK);
        let other_fingerprint = crate::derive::master_fingerprint(&SEEDS[1], NETWORK);
        let file = format!(
            "Name: notyas-m7\nPolicy: 2 of 2\nDerivation: m/{ORIGIN}\nFormat: P2WSH\n\n{ours_fingerprint}: {ours_xpub}\n{other_fingerprint}: {ZERO_DEPTH_WITH_PARENT}\n"
        );
        assert_eq!(
            parse(&file),
            Err(Malformed::XpubStructurallyInvalid { at: 1 })
        );
    }

    /// Hardened steps spelled `'` and `h` are the same path, because two coordinators
    /// spell them differently and both mean one wallet.
    #[test]
    fn the_two_hardened_spellings_agree() {
        // Only the origins: an xpub's base58 contains 'h' too, and rewriting those would
        // be testing the parser against a corrupted key rather than a second spelling.
        let apostrophes = descriptor_of([0, 1, 2]).replace("48h/0h/0h/2h]", "48'/0'/0'/2']");
        assert_eq!(
            parse(&apostrophes)
                .unwrap()
                .verify(&SEEDS[0], NETWORK)
                .unwrap(),
            wallet()
        );
    }

    // -- The Coldcard dialect -----------------------------------------------------------

    fn coldcard_file() -> String {
        let mut out = String::from(
            "# Coldcard Multisig setup file (exported by a test)\nName: notyas-m7\nPolicy: 2 of 3\nDerivation: m/48'/0'/0'/2'\nFormat: P2WSH\n\n",
        );
        for seed in &SEEDS {
            let fingerprint = crate::derive::master_fingerprint(seed, NETWORK);
            let path = parse_path(ORIGIN).unwrap();
            let xpub = xpub_at(seed, NETWORK, &path).unwrap();
            out.push_str(&format!("{fingerprint}: {xpub}\n"));
        }
        out
    }

    /// The dialect is a spelling, not a second wallet model: the Coldcard file and the
    /// descriptor for one wallet have to verify to the identical record, or the device
    /// would have two ideas of what it registered.
    #[test]
    fn a_coldcard_setup_file_registers_the_same_wallet_as_its_descriptor() {
        let pending = parse(&coldcard_file()).unwrap();
        assert_eq!(pending.dialect, ImportDialect::ColdcardTxt);
        assert_eq!(pending.threshold_of(), (2, 3));
        assert_eq!(pending.verify(&SEEDS[0], NETWORK).unwrap(), wallet());
    }

    #[test]
    fn a_coldcard_file_naming_a_wrapped_format_is_refused_by_name() {
        let wrapped = coldcard_file().replace("Format: P2WSH", "Format: P2SH-P2WSH");
        assert_eq!(
            parse(&wrapped),
            Err(Malformed::ScriptTypeUnsupported {
                named: "P2SH-P2WSH"
            })
        );
    }

    #[test]
    fn a_coldcard_policy_that_does_not_match_the_cosigner_list_is_refused() {
        let lying = coldcard_file().replace("Policy: 2 of 3", "Policy: 2 of 4");
        assert_eq!(
            parse(&lying),
            Err(Malformed::ColdcardCosignerCountMismatch {
                declared: 4,
                found: 3
            })
        );
    }

    // -- Verification -------------------------------------------------------------------

    #[test]
    fn a_wallet_we_are_not_in_is_refused() {
        let outsider = [0x99u8; 64];
        let err = parse(&descriptor_of([0, 1, 2]))
            .unwrap()
            .verify(&outsider, NETWORK)
            .unwrap_err();
        assert_eq!(
            err,
            Refusal::NotAMember {
                fingerprint: crate::derive::master_fingerprint(&outsider, NETWORK)
            }
        );
    }

    /// The 2021 Coldcard xpub substitution: our fingerprint and our origin, somebody
    /// else's key. A device that took the file's word for it would compute the attacker's
    /// addresses for the rest of the wallet's life.
    #[test]
    fn an_xpub_substituted_under_our_fingerprint_is_refused() {
        let ours = key_expression(&SEEDS[0], ORIGIN);
        let attacker_xpub = {
            let path = parse_path(ORIGIN).unwrap();
            xpub_at(&[0x99u8; 64], NETWORK, &path).unwrap().to_string()
        };
        let (prefix, _) = ours.split_once(']').unwrap();
        let forged = format!("{prefix}]{attacker_xpub}/<0;1>/*");
        let substituted = descriptor_of([0, 1, 2]).replace(&ours, &forged);
        assert_eq!(
            parse(&substituted)
                .unwrap()
                .verify(&SEEDS[0], NETWORK)
                .unwrap_err(),
            Refusal::XpubDoesNotDerive { at: 0 }
        );
    }

    /// A "2-of-3" whose second and third members are one key is a 2-of-2, and if the
    /// duplicate is the attacker's it is a 1-of-1.
    #[test]
    fn a_duplicated_cosigner_is_refused() {
        let duplicated = format!(
            "wsh(sortedmulti(2,{},{},{}))",
            key_expression(&SEEDS[0], ORIGIN),
            key_expression(&SEEDS[1], ORIGIN),
            key_expression(&SEEDS[1], ORIGIN)
        );
        assert_eq!(
            parse(&duplicated)
                .unwrap()
                .verify(&SEEDS[0], NETWORK)
                .unwrap_err(),
            Refusal::DuplicateXpub { first: 1, second: 2 }
        );
    }

    #[test]
    fn a_threshold_above_the_cosigner_count_is_refused() {
        let impossible = descriptor_of([0, 1, 2]).replace("sortedmulti(2,", "sortedmulti(4,");
        assert_eq!(
            parse(&impossible)
                .unwrap()
                .verify(&SEEDS[0], NETWORK)
                .unwrap_err(),
            Refusal::ThresholdOutOfRange { m: 4, n: 3 }
        );
    }

    /// The BIP-48 script-type step. `1h` is P2SH-P2WSH, which 0.2.0 does not do, and the
    /// refusal names it rather than silently deriving P2WSH scripts from it (Q7).
    #[test]
    fn a_bip48_script_type_other_than_p2wsh_is_refused() {
        let wrapped = format!(
            "wsh(sortedmulti(2,{},{},{}))",
            key_expression(&SEEDS[0], "48h/0h/0h/1h"),
            key_expression(&SEEDS[1], "48h/0h/0h/1h"),
            key_expression(&SEEDS[2], "48h/0h/0h/1h")
        );
        assert_eq!(
            parse(&wrapped)
                .unwrap()
                .verify(&SEEDS[0], NETWORK)
                .unwrap_err(),
            Refusal::ScriptTypeNotP2wsh {
                at: 0,
                script_type: 1
            }
        );
    }

    #[test]
    fn an_origin_outside_bip48_is_refused() {
        let bip84_shaped = format!(
            "wsh(sortedmulti(2,{},{},{}))",
            key_expression(&SEEDS[0], "84h/0h/0h"),
            key_expression(&SEEDS[1], "84h/0h/0h"),
            key_expression(&SEEDS[2], "84h/0h/0h")
        );
        assert_eq!(
            parse(&bip84_shaped)
                .unwrap()
                .verify(&SEEDS[0], NETWORK)
                .unwrap_err(),
            Refusal::OriginNotBip48 { at: 0 }
        );
    }

    /// The device's network wins over the file's, which is the 2020 isolation-bypass rule.
    #[test]
    fn mainnet_keys_are_refused_on_a_test_network() {
        assert_eq!(
            parse(&descriptor_of([0, 1, 2]))
                .unwrap()
                .verify(&SEEDS[0], Network::Testnet)
                .unwrap_err(),
            Refusal::NetworkMismatch {
                device: Network::Testnet
            }
        );
    }

    #[test]
    fn a_coin_type_that_is_not_the_devices_is_refused() {
        let testnet_coin = format!(
            "wsh(sortedmulti(2,{},{},{}))",
            key_expression(&SEEDS[0], "48h/1h/0h/2h"),
            key_expression(&SEEDS[1], "48h/1h/0h/2h"),
            key_expression(&SEEDS[2], "48h/1h/0h/2h")
        );
        assert_eq!(
            parse(&testnet_coin)
                .unwrap()
                .verify(&SEEDS[0], NETWORK)
                .unwrap_err(),
            Refusal::CoinTypeMismatch {
                at: 0,
                found: 1,
                expected: 0
            }
        );
    }

    /// SLIP-44, stated here rather than shared with the other two modules that need it, so
    /// that one wrong answer cannot be consistent across all three.
    #[test]
    fn the_coin_type_rule_is_slip44() {
        assert_eq!(coin_type_for(Network::Bitcoin), 0);
        for test_chain in [Network::Testnet, Network::Signet, Network::Regtest] {
            assert_eq!(coin_type_for(test_chain), 1);
        }
    }

    // -- Locating -----------------------------------------------------------------------

    #[test]
    fn locate_answers_only_for_the_script_the_wallet_actually_builds() {
        let registration = wallet();
        let path: DerivationPath = format!("m/{ORIGIN}/1/7").parse().unwrap();
        let script = registration.script_pubkey(Keychain::Change, 7).unwrap();

        let located = registration.locate(&path, &script).expect("its own script");
        assert_eq!(located.keychain, Keychain::Change);
        assert_eq!(located.index, 7);

        // The same path against a script from the neighbouring leaf: nothing.
        let neighbour = registration.script_pubkey(Keychain::Change, 8).unwrap();
        assert!(registration.locate(&path, &neighbour).is_none());
        // The same script against the receive chain: nothing.
        let receive_path: DerivationPath = format!("m/{ORIGIN}/0/7").parse().unwrap();
        assert!(registration.locate(&receive_path, &script).is_none());
    }

    /// A path that is not our own cosigner's origin is not a leaf of this wallet, however
    /// plausible it looks.
    #[test]
    fn locate_path_refuses_paths_outside_our_own_branch() {
        let registration = wallet();
        for path in [
            "m/48h/0h/1h/2h/1/7", // another account
            "m/48h/0h/0h/2h/1",   // one step short
            "m/48h/0h/0h/2h/1/7/0", // one step long
            "m/48h/0h/0h/2h/1h/7", // hardened keychain step
            "m/48h/0h/0h/2h/2/7", // a keychain this descriptor does not name
        ] {
            let path: DerivationPath = path.parse().unwrap();
            assert!(
                registration.locate_path(&path).is_none(),
                "{path} must not read as a leaf of this wallet"
            );
        }
    }

    #[test]
    fn the_registration_names_the_cosigner_we_hold_the_key_for() {
        let registration = wallet();
        assert_eq!(registration.threshold_of(), (2, 3));
        assert_eq!(
            registration.ours().fingerprint,
            crate::derive::master_fingerprint(&SEEDS[0], NETWORK)
        );
        assert_eq!(registration.script(), MultisigScript::WshSortedMulti);
        assert_eq!(registration.network(), NETWORK);
        // The id is the descriptor's own checksum, so it is stable and content-derived.
        assert!(registration
            .descriptor()
            .ends_with(&registration.id().to_string()));
    }

    #[test]
    fn the_first_receive_address_is_the_wallets_own_p2wsh() {
        let registration = wallet();
        let address = registration.first_receive_address().unwrap();
        assert_eq!(
            address.script_pubkey(),
            registration.script_pubkey(Keychain::Receive, 0).unwrap()
        );
        assert!(address.to_string().starts_with("bc1q"));
    }
}
