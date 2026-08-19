// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The two sealed-record bodies this device writes, and nothing else.
//!
//! `notyas_wallet` stores opaque bytes (ESP-SEAL.md 2.4): the slot, the A/B election, the
//! AEAD and the power-loss guarantees are all its business, and what those bytes MEAN is
//! all of this file's. Keeping the two apart is why the sealing engine could be proven
//! against 71,910 host power-loss cases without knowing what a wallet is.
//!
//! # Why a phrase and not entropy, and why not a seed
//!
//! WALLET-API.md 2.6's `WalletDraft` stores BIP39 entropy so that mnemonic re-display and
//! the backup-verify dry run stay possible. This record stores the normalized PHRASE,
//! which keeps both of those and costs nothing: notyas-core's entropy-to-mnemonic
//! direction is private (`bip39::mnemonic_from_entropy`), so a device that sealed entropy
//! could not show the user their words again without a change to that crate. The phrase is
//! the same secret by a different spelling - it is what a paper backup carries - and
//! [`notyas_core::bip39::seed`] takes exactly this string as its PBKDF2 password.
//!
//! What is deliberately NOT stored is the 64-byte seed. A seed cannot be turned back into
//! words, so a device holding only seeds could never re-show a backup, and the user's
//! recovery path would exist only outside the device.
//!
//! # Why the fingerprint is in the record
//!
//! A BIP39 passphrase is an argument and never stored state (WALLET-API.md 2.6), which
//! means a mistyped one silently opens a DIFFERENT wallet rather than failing. Recording
//! the master fingerprint the seed must produce - a public value, four bytes - turns that
//! into a refusal at open time (UX.md commandment 8, `WalletMeta::passphrase_check`). It
//! is stored unconditionally rather than only for passphrased wallets: one rule, checked
//! on every open, also catches a phrase that came back from flash wrong.

use std::fmt;
use std::str::FromStr;

use notyas_core::bip39;
use notyas_core::derive;
use notyas_core::bitcoin::bip32::Fingerprint;
use notyas_core::bitcoin::Network;
use zeroize::Zeroizing;

/// Wallet record, format 1. The magic IS the format version: a body that means something
/// else will not be read as this by accident, and a future revision takes a new token
/// rather than a flag inside an old one.
const WALLET_MAGIC: [u8; 4] = *b"NYW1";
const WALLET_HEADER: usize = 14;

/// Multisig registration record, format 2.
///
/// Format 1 stored the descriptor alone, which made the record self-certifying: the only
/// thing a reader could establish from it was a property of whatever it now said. Format 2
/// adds the [`RegistrationRecord::id`] the registration was approved under, and the magic
/// is bumped rather than a flag added, per this file's rule above. A format 1 body decodes
/// as `NotThisKind`, which `load_registry` reports as a registry fault - the right
/// treatment for a record whose identity this build cannot establish, and reachable only
/// on a device that registered a wallet under a 0.2.0 pre-release.
const REGISTRATION_MAGIC: [u8; 4] = *b"NYR2";
const REGISTRATION_HEADER: usize = 18;

/// Longest label either record accepts.
///
/// A bound rather than "whatever fits" because the label shares a slot with a wallet's
/// recovery words: a screen that let the label grow without limit would let it push the
/// phrase out of the slot, and the failure would land on the save rather than on the
/// typing.
pub const MAX_LABEL_BYTES: usize = 64;

/// Why a record could not be built, or could not be read back.
///
/// One variant per concrete reason, in the vocabulary of the thing that went wrong, so a
/// screen can say what the user can do about it. `NotThisKind` and `Truncated` are the two
/// that mean the flash gave back something that is not this record at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// The body does not start with this record kind's magic: a record of the other kind,
    /// a record from a future format, or a slot holding something else entirely.
    NotThisKind,
    /// A declared length runs past the end of the body.
    Truncated,
    /// The declared fields end before the body does. Refused rather than ignored: a record
    /// is exactly its declared contents, and a reader that skips a tail is a reader that
    /// can be fed one.
    TrailingBytes { extra: usize },
    /// A network byte this firmware does not know. Refused rather than defaulted, because
    /// defaulting a network is ARCHITECTURE.md 5.3 check 5's isolation bypass with the
    /// flash in the file's place.
    UnknownNetwork { code: u8 },
    /// The reserved byte is not zero, i.e. the record uses a feature this build does not
    /// implement. Refusing is the only safe reading of a record we only half understand.
    ReservedNotZero,
    LabelTooLong { bytes: usize, max: usize },
    /// A text field is not UTF-8. Only reachable from a corrupt record: everything written
    /// here came from a Rust `str`.
    NotUtf8,
    /// A wallet record with no words in it. Nothing can be derived from it and nothing
    /// should have written it.
    EmptyPhrase,
    /// The fingerprint the record would have been sealed under is not the eight hex
    /// characters a [`Fingerprint`] renders.
    ///
    /// Reported rather than defaulted or recomputed. On the path this reaches - a save of
    /// an identity a screen confirmed - the fingerprint IS the wallet's identity, so a
    /// record written with a substituted one would certify a wallet nobody approved, which
    /// is the failure the field exists to prevent.
    UnreadableFingerprint,
    /// The words do not derive the identity the record was about to claim, with no
    /// passphrase in play to explain the difference. Sealing it would produce a wallet
    /// that can never be opened.
    FingerprintNotFromPhrase,
    /// The record does not fit the slot it was going to be sealed into. Reported by the
    /// encoder, before anything is written, and carrying both numbers so the message can
    /// state the shortfall rather than only that there was one.
    TooLarge { bytes: usize, max: usize },
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordError::NotThisKind => write!(f, "this slot does not hold that kind of record"),
            RecordError::Truncated => write!(f, "the record is truncated"),
            RecordError::TrailingBytes { extra } => write!(
                f,
                "the record carries {extra} bytes past its declared contents"
            ),
            RecordError::UnknownNetwork { code } => write!(
                f,
                "the record names network {code}, which this firmware does not know"
            ),
            RecordError::ReservedNotZero => write!(
                f,
                "the record uses a feature this firmware does not implement"
            ),
            RecordError::LabelTooLong { bytes, max } => {
                write!(f, "the name is {bytes} bytes and the limit is {max}")
            }
            RecordError::NotUtf8 => write!(f, "the record's text is damaged"),
            RecordError::EmptyPhrase => write!(f, "the record holds no recovery words"),
            RecordError::UnreadableFingerprint => {
                write!(f, "the wallet's fingerprint is not eight hex characters")
            }
            RecordError::FingerprintNotFromPhrase => write!(
                f,
                "these words do not produce the wallet this record would claim - it would                  never open again"
            ),
            RecordError::TooLarge { bytes, max } => {
                write!(f, "the record is {bytes} bytes and the slot holds {max}")
            }
        }
    }
}

impl std::error::Error for RecordError {}

/// One stored wallet: what it is called, which network it is on, the words it is made of,
/// and the fingerprint that proves those words plus the typed passphrase are the pair that
/// was saved.
///
/// Secret-bearing. The phrase is `Zeroizing`, the encoder's output buffer is `Zeroizing`,
/// and `Debug` is hand written for the reason every secret-bearing type in notyas-core has
/// one: a `{:?}` in a log line or a panic payload copies the value somewhere nothing wipes.
pub struct WalletRecord {
    /// The DEVICE's network for every operation this wallet performs. Read from here and
    /// never from a PSBT or from a descriptor a coordinator sent.
    pub network: Network,
    /// The master fingerprint the seed must produce, passphrase applied. A public value.
    pub fingerprint: Fingerprint,
    pub label: String,
    /// Normalized by [`notyas_core::bip39::normalize_phrase`] before it was sealed, so the
    /// bytes that come back are the exact PBKDF2 password (SPEC step 8).
    pub phrase: Zeroizing<String>,
}

impl fmt::Debug for WalletRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletRecord")
            .field("network", &self.network)
            .field("fingerprint", &self.fingerprint)
            .field("label", &self.label)
            .field("phrase", &"<redacted>")
            .finish()
    }
}

impl WalletRecord {
    /// Serialize, refusing if the result would not fit `capacity` bytes.
    ///
    /// The capacity check is here rather than at the seal because this is the layer that
    /// knows which field a user could shorten. `Vault::write` reports the same condition as
    /// `StorageError::Capacity`, which is true and says nothing.
    pub fn encode(&self, capacity: usize) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        let code = network_code(self.network).ok_or(RecordError::UnknownNetwork { code: 0xff })?;
        let label = self.label.as_bytes();
        let phrase = self.phrase.as_bytes();
        if label.len() > MAX_LABEL_BYTES {
            return Err(RecordError::LabelTooLong {
                bytes: label.len(),
                max: MAX_LABEL_BYTES,
            });
        }
        if phrase.is_empty() {
            return Err(RecordError::EmptyPhrase);
        }
        let len = WALLET_HEADER
            .saturating_add(label.len())
            .saturating_add(phrase.len());
        if len > capacity {
            return Err(RecordError::TooLarge {
                bytes: len,
                max: capacity,
            });
        }

        // Zeroizing from the first byte: the phrase is copied into this buffer, and a plain
        // Vec would leave it in freed heap after the seal.
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        out.extend_from_slice(&WALLET_MAGIC);
        out.push(code);
        out.push(0); // reserved
        out.extend_from_slice(&self.fingerprint.to_bytes());
        out.extend_from_slice(&len16(label.len()).to_le_bytes());
        out.extend_from_slice(&len16(phrase.len()).to_le_bytes());
        out.extend_from_slice(label);
        out.extend_from_slice(phrase);
        Ok(out)
    }

    /// Parse a body that came off flash.
    ///
    /// Every length is checked against what is left before it is used, and the tail must be
    /// empty once the declared fields are done. Nothing here can panic on a corrupt body,
    /// which matters because this runs on bytes that survived an AEAD but not necessarily a
    /// firmware version change.
    pub fn decode(body: &[u8]) -> Result<WalletRecord, RecordError> {
        if take(body, 0, WALLET_MAGIC.len()).ok_or(RecordError::Truncated)? != WALLET_MAGIC {
            return Err(RecordError::NotThisKind);
        }
        let code = *body.get(4).ok_or(RecordError::Truncated)?;
        let network = network_of(code).ok_or(RecordError::UnknownNetwork { code })?;
        if *body.get(5).ok_or(RecordError::Truncated)? != 0 {
            return Err(RecordError::ReservedNotZero);
        }
        let fingerprint =
            Fingerprint::from(arr4(take(body, 6, 4).ok_or(RecordError::Truncated)?));
        let label_len = u16le(body, 10).ok_or(RecordError::Truncated)? as usize;
        let phrase_len = u16le(body, 12).ok_or(RecordError::Truncated)? as usize;
        let label = take(body, WALLET_HEADER, label_len).ok_or(RecordError::Truncated)?;
        let phrase_at = WALLET_HEADER.saturating_add(label_len);
        let phrase = take(body, phrase_at, phrase_len).ok_or(RecordError::Truncated)?;
        let end = phrase_at.saturating_add(phrase_len);
        if body.len() > end {
            return Err(RecordError::TrailingBytes {
                extra: body.len().saturating_sub(end),
            });
        }
        if phrase.is_empty() {
            return Err(RecordError::EmptyPhrase);
        }
        // The phrase lands in a Zeroizing String on its way out of the borrowed body; the
        // body itself is the caller's Zeroizing buffer (see `Wallet::open`).
        let phrase = Zeroizing::new(
            core::str::from_utf8(phrase)
                .map_err(|_| RecordError::NotUtf8)?
                .to_string(),
        );
        Ok(WalletRecord {
            network,
            fingerprint,
            label: core::str::from_utf8(label)
                .map_err(|_| RecordError::NotUtf8)?
                .to_string(),
            phrase,
        })
    }
}

/// A wallet whose identity was established somewhere else, on its way into a slot.
///
/// `NewWallet` is the other way in, and it DERIVES the fingerprint from a passphrase. The
/// create flow on the touchscreen cannot use that door. A BIP-39 passphrase is typed per
/// session and is never a field of anything that outlives the screen that took it (Q22),
/// so the draft that arrives from those screens carries no passphrase - it carries the
/// fingerprint the user read off the panel and approved, which was computed with the
/// passphrase applied.
///
/// So the identity travels as DATA here. Re-deriving it with the only passphrase this path
/// could supply - an empty one - would seal the empty-passphrase wallet under the name of
/// the one the user confirmed: their real passphrase would then be refused by
/// `Wallet::open` forever, and an empty one would open a wallet they have never seen. The
/// record certifies what was approved, or it certifies nothing.
pub struct SealedWallet<'a> {
    pub label: &'a str,
    /// The device's network for this wallet, for the whole of its life.
    pub network: Network,
    /// The words as the user holds them. Normalized by [`SealedWallet::body`] before they
    /// are sealed, so what comes back is byte-for-byte the PBKDF2 password.
    pub phrase: &'a str,
    /// The master fingerprint these words produce under the passphrase that was applied
    /// when they were derived. A public value, and the one that was on the screen.
    pub fingerprint: Fingerprint,
}

impl fmt::Debug for SealedWallet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedWallet")
            .field("label", &self.label)
            .field("network", &self.network)
            .field("fingerprint", &self.fingerprint)
            .field("phrase", &"<redacted>")
            .finish()
    }
}

impl<'a> SealedWallet<'a> {
    /// Build from an identity a screen confirmed, taking the fingerprint in the spelling
    /// that screen rendered: the eight lowercase hex characters of [`Fingerprint`]'s
    /// `Display`, which this parse is the exact inverse of.
    ///
    /// A fingerprint that does not parse is a refusal, and never a zero, a default or a
    /// value recomputed from something else. It means this device could not establish the
    /// identity of the wallet it was about to write down, and there is no version of that
    /// which is safe to store.
    pub fn confirmed(
        label: &'a str,
        network: Network,
        phrase: &'a str,
        fingerprint: &str,
        passphrase_applied: bool,
    ) -> Result<SealedWallet<'a>, RecordError> {
        let fingerprint =
            Fingerprint::from_str(fingerprint).map_err(|_| RecordError::UnreadableFingerprint)?;

        // The identity is GIVEN here rather than derived, because the only place the
        // passphrase ever existed is the screen that took it (Q22 keeps it out of storage
        // and out of `WalletDraft`). That is a real constraint, but it must not become a
        // licence to seal an identity nothing can reproduce: the record's fingerprint is
        // the value `Wallet::open` will later re-derive and compare against, so a record
        // whose fingerprint does not belong to its phrase is a wallet that is refused
        // forever, with a mismatch that reads exactly like a forgotten passphrase.
        //
        // Whenever no passphrase was applied the check costs one PBKDF2 and is EXACT, so
        // it is taken. It cannot be taken for a passphrase wallet without the passphrase,
        // and the honest thing is to say so here rather than to pretend the two cases are
        // equally trusted.
        if !passphrase_applied {
            let seed = bip39::seed(&bip39::normalize_phrase(phrase), "");
            if derive::master_fingerprint(&seed, network) != fingerprint {
                return Err(RecordError::FingerprintNotFromPhrase);
            }
        }

        Ok(SealedWallet { label, network, phrase, fingerprint })
    }

    /// The body to seal, refusing if it would not fit `capacity`.
    ///
    /// Normalization happens HERE rather than at the call sites, so no caller can seal a
    /// phrase whose bytes are not the PBKDF2 password [`WalletRecord::phrase`] promises
    /// they are. It is idempotent, so a caller that already normalized (the derive path
    /// must, to build the seed) loses nothing by passing its own result back in.
    pub fn body(&self, capacity: usize) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        WalletRecord {
            network: self.network,
            fingerprint: self.fingerprint,
            label: self.label.to_string(),
            phrase: bip39::normalize_phrase(self.phrase),
        }
        .encode(capacity)
    }
}

/// One registered multisig wallet, as a public record.
///
/// It holds cosigner xpubs, a threshold and a name, and no key material at all - which is
/// why it can be a record of its own class rather than a field inside a wallet's sealed
/// body. It is sealed all the same, because the set of wallets a device is a member of is
/// exactly the metadata a flash dump should not yield.
///
/// The DESCRIPTOR is what a registration is rebuilt FROM, and rebuilding a
/// [`notyas_core::multisig::Registration`] from it costs one parse and one membership proof
/// at open time. That is deliberate: the registration type has private fields and no public
/// constructor precisely so that `Pending::verify` - which needs a seed - is the only way
/// to obtain one (multisig.rs: "not a rule a reviewer has to enforce, but a type nobody can
/// build out of a PSBT"). Storing a decomposed registration and reassembling it would be a
/// second constructor.
///
/// The ID is what says WHICH registration the rebuild was supposed to produce, and it is
/// the field that makes this record something other than self-certifying. A membership
/// proof answers "is this device a member of the wallet this text describes"; it cannot
/// answer "is this text the wallet we registered", because the only thing it has to
/// compare against is the text. Carrying the approved id turns the second question into a
/// comparison the loader can actually make - see `super::reproven`, which is the only
/// reader of this field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationRecord {
    /// The payload slot of the wallet this registration belongs to.
    ///
    /// Registry slots are their own class and carry no reference to a wallet otherwise, so
    /// without this a second wallet on the same device would try to prove membership of the
    /// first wallet's registrations and report a fault for each. WALLET-API.md 2.7 carries
    /// the same field as `Registration::wallet`.
    pub wallet_slot: u8,
    /// The [`notyas_core::multisig::RegistrationId`] this wallet was approved under, as
    /// the eight characters that type renders.
    ///
    /// Eight bytes rather than the type itself because `RegistrationId` has no public
    /// constructor - `Pending::verify` is the only thing that may mint one, which is the
    /// property this record exists to serve rather than to work around. These are also
    /// exactly the characters a user compares between two devices holding the wallet, so
    /// the stored form and the compared form are the same string.
    pub id: [u8; 8],
    /// The name the user gave this wallet.
    ///
    /// Not covered by [`RegistrationRecord::id`], and it cannot be: the id is the BIP-380
    /// checksum of the descriptor, fixed by m7 so that every device holding the wallet
    /// computes the same one, and nothing re-derives a label. Nothing outside this record
    /// reads it either - it is written here and never loaded - so a screen that starts
    /// showing it must show the id beside it, because the id is the part of this record
    /// that a reader can independently establish.
    pub label: String,
    /// The canonical BIP-380 descriptor with its checksum, exactly as
    /// [`notyas_core::multisig::Registration::descriptor`] rendered it.
    pub descriptor: String,
}

impl RegistrationRecord {
    pub fn encode(&self, capacity: usize) -> Result<Vec<u8>, RecordError> {
        let label = self.label.as_bytes();
        let descriptor = self.descriptor.as_bytes();
        if label.len() > MAX_LABEL_BYTES {
            return Err(RecordError::LabelTooLong {
                bytes: label.len(),
                max: MAX_LABEL_BYTES,
            });
        }
        let len = REGISTRATION_HEADER
            .saturating_add(label.len())
            .saturating_add(descriptor.len());
        if len > capacity {
            return Err(RecordError::TooLarge {
                bytes: len,
                max: capacity,
            });
        }
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(&REGISTRATION_MAGIC);
        out.push(self.wallet_slot);
        out.push(0); // reserved
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&len16(label.len()).to_le_bytes());
        out.extend_from_slice(&len16(descriptor.len()).to_le_bytes());
        out.extend_from_slice(label);
        out.extend_from_slice(descriptor);
        Ok(out)
    }

    pub fn decode(body: &[u8]) -> Result<RegistrationRecord, RecordError> {
        if take(body, 0, REGISTRATION_MAGIC.len()).ok_or(RecordError::Truncated)?
            != REGISTRATION_MAGIC
        {
            return Err(RecordError::NotThisKind);
        }
        let wallet_slot = *body.get(4).ok_or(RecordError::Truncated)?;
        if *body.get(5).ok_or(RecordError::Truncated)? != 0 {
            return Err(RecordError::ReservedNotZero);
        }
        let id = arr8(take(body, 6, 8).ok_or(RecordError::Truncated)?);
        let label_len = u16le(body, 14).ok_or(RecordError::Truncated)? as usize;
        let descriptor_len = u16le(body, 16).ok_or(RecordError::Truncated)? as usize;
        let label = take(body, REGISTRATION_HEADER, label_len).ok_or(RecordError::Truncated)?;
        let descriptor_at = REGISTRATION_HEADER.saturating_add(label_len);
        let descriptor =
            take(body, descriptor_at, descriptor_len).ok_or(RecordError::Truncated)?;
        let end = descriptor_at.saturating_add(descriptor_len);
        if body.len() > end {
            return Err(RecordError::TrailingBytes {
                extra: body.len().saturating_sub(end),
            });
        }
        Ok(RegistrationRecord {
            wallet_slot,
            id,
            label: core::str::from_utf8(label)
                .map_err(|_| RecordError::NotUtf8)?
                .to_string(),
            descriptor: core::str::from_utf8(descriptor)
                .map_err(|_| RecordError::NotUtf8)?
                .to_string(),
        })
    }
}

/// The on-flash network code. Frozen: these are stored values, so a variant's number is
/// part of the format and the list only ever grows.
fn network_code(network: Network) -> Option<u8> {
    match network {
        Network::Bitcoin => Some(0),
        Network::Testnet => Some(1),
        Network::Signet => Some(2),
        Network::Regtest => Some(3),
        // `Network` is non_exhaustive upstream. A variant this build has never heard of
        // must not be given a number here, because that number would mean something else
        // the day the match is completed.
        _ => None,
    }
}

fn network_of(code: u8) -> Option<Network> {
    match code {
        0 => Some(Network::Bitcoin),
        1 => Some(Network::Testnet),
        2 => Some(Network::Signet),
        3 => Some(Network::Regtest),
        _ => None,
    }
}

/// Sub-slice or `None`, never a panic. The firmware is std and does not deny
/// `clippy::indexing_slicing` the way notyas-wallet does, but a record decoder reads bytes
/// that survived an AEAD and not necessarily a format change, so it is written to the same
/// rule (notyas-wallet's `bytes` module carries the argument in full).
fn take(buf: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    buf.get(off..off.checked_add(len)?)
}

fn u16le(buf: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(arr2(take(buf, off, 2)?)))
}

fn arr2(src: &[u8]) -> [u8; 2] {
    let mut out = [0u8; 2];
    for (dst, byte) in out.iter_mut().zip(src.iter()) {
        *dst = *byte;
    }
    out
}

fn arr4(src: &[u8]) -> [u8; 4] {
    let mut out = [0u8; 4];
    for (dst, byte) in out.iter_mut().zip(src.iter()) {
        *dst = *byte;
    }
    out
}

fn arr8(src: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (dst, byte) in out.iter_mut().zip(src.iter()) {
        *dst = *byte;
    }
    out
}

/// A length already bounded by [`MAX_LABEL_BYTES`] or by the slot capacity, so the clamp is
/// unreachable; it exists so the cast is not a silent truncation if a future caller forgets
/// one of those checks.
fn len16(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}
