// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The unlocked wallet: the one place on this device where a seed exists, and the only
//! source the signing pipeline's [`Context`](notyas_core::psbt::Context) is built from.
//!
//! # What this module is for
//!
//! `notyas_core::psbt::inspect` decides whether a transaction may be signed, and it takes
//! exactly two things it cannot get from the file: this device's network and fingerprint,
//! and the multisig wallets this device has proven it is a member of. That is the whole
//! reason this module exists. It turns an unlocked session - a PIN that was known, and the
//! sealed records that proof opens - into those values, and it is the only thing that
//! builds them.
//!
//! # The property this file exists to keep
//!
//! **Nothing in a [`Context`](notyas_core::psbt::Context) can be influenced by the PSBT
//! being validated.** Ownership of an input is decided by comparing an origin's
//! fingerprint against ours; if the file could move ours, every check downstream would be
//! deciding against the attacker's own answer. So:
//!
//! - `network` comes from the sealed wallet record, never from an xpub prefix, an address,
//!   or a coin type in the file (Coldcard isolation bypass, 2020).
//! - `fingerprint` is DERIVED here from the seed, by
//!   [`notyas_core::derive::master_fingerprint`], and is not the fingerprint the record
//!   stored - the record's copy is used once, to refuse a wrong passphrase, and never as
//!   the value the engine runs on.
//! - `registry` holds [`Registration`]s, and the only constructor for one is
//!   `Pending::verify`, which needs a seed. A registration is re-parsed and re-proven from
//!   its stored descriptor on every open, AND the result is checked against the
//!   [`RegistrationId`] the record was written under. Both halves are needed and they
//!   answer different questions - see [`reproven`], which is where the reasoning lives.
//!
//! [`Wallet::context`] is a `&self` method returning a borrow, which is what makes the
//! property structural rather than a convention: there is no way to hand `inspect` a
//! context that did not come from an open wallet, and no way to mutate one after it is
//! built.
//!
//! # Where the wallet-record schema belongs
//!
//! In [`record`], and in this crate only until notyas-wallet grows the `wallet` and
//! `registry` modules WALLET-API.md 2.6 and 2.7 specify. The sealing engine stores opaque
//! bytes by design (ESP-SEAL.md 2.4); what those bytes mean is a product decision, and the
//! product is here. When that crate-side layer lands, this module becomes its adapter and
//! [`record`] becomes its format, unchanged.

pub mod erase;
pub mod record;

use std::fmt;

use notyas_core::bitcoin::bip32::Fingerprint;
use notyas_core::bitcoin::Network;
use notyas_core::multisig::{self, Registration, RegistrationId};
use notyas_core::psbt::{Context, StructuralLimits};
use notyas_core::report::{Parameters, Report};
use notyas_core::{bip39, derive};
use notyas_wallet::SlotState;
use zeroize::Zeroizing;

use crate::store::Store;
use notyas_ui::PassphraseState;
use record::{RecordError, RegistrationRecord, SealedWallet, StoredPassphrase, WalletRecord};

/// Why a wallet could not be opened or saved.
#[derive(Debug)]
pub enum WalletError {
    /// No session. Every record here is sealed under a PIN, so this is the type saying
    /// what the session discipline already required.
    Locked,
    /// The slot index is outside this layout's payload slots.
    NoSuchSlot { index: u8 },
    /// Nothing is stored there, or the record belongs to another PIN identity.
    SlotEmpty { index: u8 },
    /// A wallet is already stored there. Refused rather than overwritten: the record this
    /// would replace is the only copy of somebody's words that this device holds.
    SlotInUse { index: u8 },
    /// Every payload slot already holds a wallet. The device is full, and nothing was
    /// overwritten to make room: see [`WalletError::SlotInUse`] for why not.
    NoFreeSlot { slots: u8 },
    /// The store refused. Carries its `Debug` rendering, matching how the rest of the
    /// firmware surfaces `StorageError` (see `Store::read_payload`).
    Storage(String),
    Record(RecordError),
    /// The seed derived from the stored words plus the typed passphrase is not the seed
    /// that was saved. Almost always a mistyped passphrase, which without this check would
    /// silently open a DIFFERENT wallet - the failure UX.md commandment 8 is about. Both
    /// fingerprints are public values, so the screen may show them.
    PassphraseMismatch {
        expected: Fingerprint,
        derived: Fingerprint,
    },
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalletError::Locked => write!(f, "the device is locked"),
            WalletError::NoSuchSlot { index } => write!(f, "there is no wallet slot {index}"),
            WalletError::SlotEmpty { index } => write!(f, "wallet slot {index} is empty"),
            WalletError::SlotInUse { index } => {
                write!(f, "wallet slot {index} already holds a wallet")
            }
            WalletError::NoFreeSlot { slots } => {
                write!(f, "all {slots} wallet slots are used - delete a wallet first")
            }
            WalletError::Storage(e) => write!(f, "the store refused: {e}"),
            WalletError::Record(e) => write!(f, "{e}"),
            WalletError::PassphraseMismatch { expected, derived } => write!(
                f,
                "that passphrase opens wallet {derived}, not the saved wallet {expected}"
            ),
        }
    }
}

impl std::error::Error for WalletError {}

impl From<RecordError> for WalletError {
    fn from(e: RecordError) -> WalletError {
        WalletError::Record(e)
    }
}

/// Why a multisig registration was not stored.
#[derive(Debug)]
pub enum RegisterError {
    /// The text is not a wallet description this device reads.
    Malformed(multisig::Malformed),
    /// It parsed, and this device is not a member of it, or it is a shape 0.2.0 refuses.
    /// This is the 2021 xpub-substitution defence answering; it is never downgraded to a
    /// warning (Q11/Q24).
    Refused(multisig::Refusal),
    /// This exact wallet is already registered. Named by its content-derived id, so the
    /// message is about the wallet rather than about a slot number.
    AlreadyRegistered(RegistrationId),
    /// Every registry slot is taken.
    NoFreeSlot { slots: u8 },
    /// No registration of THIS wallet lives in that slot. A delete names a slot the screen
    /// read off this wallet's own list, so reaching this means the list the screen is
    /// holding is older than the registry - which is a refusal and never a delete of
    /// whatever happens to be there now.
    NoSuchRegistration { slot: u8 },
    Storage(String),
    Record(RecordError),
}

impl fmt::Display for RegisterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegisterError::Malformed(e) => write!(f, "{e}"),
            RegisterError::Refused(e) => write!(f, "{e}"),
            RegisterError::AlreadyRegistered(id) => {
                write!(f, "this wallet is already registered as {id}")
            }
            RegisterError::NoFreeSlot { slots } => write!(
                f,
                "all {slots} registration slots are in use - remove one first"
            ),
            RegisterError::NoSuchRegistration { slot } => write!(
                f,
                "this wallet has no registration in slot {slot}"
            ),
            RegisterError::Storage(e) => write!(f, "the store refused: {e}"),
            RegisterError::Record(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RegisterError {}

/// A registry record that could not be turned back into a proven registration.
///
/// Collected rather than dropped. A registration that vanishes silently is a multisig
/// wallet the user believes is registered and is not, and the next PSBT from it would be
/// refused as `MultisigNotRegistered` with no way to tell why. The screen that lists
/// wallets renders these beside them.
#[derive(Debug)]
pub struct RegistryFault {
    pub slot: u8,
    pub reason: FaultReason,
}

#[derive(Debug)]
pub enum FaultReason {
    Storage(String),
    Record(RecordError),
    /// The stored descriptor no longer parses. Only reachable from a record that changed
    /// under storage, which the AEAD makes a hardware event rather than an attack.
    Malformed(multisig::Malformed),
    /// The descriptor parses and this wallet cannot prove membership of it any more. The
    /// honest reading is that the record is not this wallet's, and it is reported rather
    /// than used.
    Unproven(multisig::Refusal),
    /// The descriptor parses, this device IS a member of it, and it is not the wallet this
    /// slot was registered for.
    ///
    /// The one an attacker with flash access aims for: our own xpub is left in place, so
    /// every membership check still passes, and the other cosigners are somebody else's.
    /// Reported with both ids because they are public values and because the user can
    /// compare the stored one against the other devices holding the wallet.
    NotAsRegistered {
        stored: String,
        derived: RegistrationId,
    },
}

impl fmt::Display for FaultReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FaultReason::Storage(e) => write!(f, "the store refused: {e}"),
            FaultReason::Record(e) => write!(f, "{e}"),
            FaultReason::Malformed(e) => write!(f, "{e}"),
            FaultReason::Unproven(e) => write!(f, "{e}"),
            FaultReason::NotAsRegistered { stored, derived } => write!(
                f,
                "this record now describes wallet {derived}, and it was registered as {stored}"
            ),
        }
    }
}

/// What a save needs, and nothing more.
///
/// The passphrase is an argument here and is never a field of anything stored, which is
/// WALLET-API.md 2.6's rule and the reason [`WalletRecord`] carries a fingerprint instead.
pub struct NewWallet<'a> {
    pub label: &'a str,
    /// The device's network for this wallet, for the whole of its life.
    pub network: Network,
    /// The words, as the user typed or rolled them. Normalized here before sealing, so
    /// what comes back is byte-for-byte the PBKDF2 password.
    ///
    /// NOT validated here. `bip39::check_phrase` is advisory by design ("what this
    /// produces is the warning the user is shown, not a veto"), and the screen that
    /// collected the words is where that warning belongs. Storage does not get to have a
    /// second opinion about a phrase the user confirmed.
    pub phrase: &'a str,
    pub passphrase: &'a str,
}

impl fmt::Debug for NewWallet<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewWallet")
            .field("label", &self.label)
            .field("network", &self.network)
            .field("phrase", &"<redacted>")
            .field("passphrase", &"<redacted>")
            .finish()
    }
}

/// What a wallet record says about itself, read WITHOUT deriving anything.
///
/// One AEAD open and a parse, and no PBKDF2 at all - which is the whole point. The open
/// path has to decide WHICH passphrase to try before it spends the seconds that trying one
/// costs, and this is what it decides from: the record's own statement, plus the passphrase
/// the record carries when the owner has asked this device to remember it.
///
/// Secret-bearing in one field, so `Debug` is hand written like every other type here.
pub struct RecordFacts {
    pub label: String,
    pub network: Network,
    /// The record's statement. A format 1 record makes none, and decodes as
    /// [`StoredPassphrase::None`] - which is why the open path tries the empty passphrase
    /// first and asks only if that does not open it.
    pub passphrase: StoredPassphrase,
}

impl fmt::Debug for RecordFacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordFacts")
            .field("label", &self.label)
            .field("network", &self.network)
            .field("passphrase", &self.passphrase)
            .finish()
    }
}

/// An open wallet: the seed is live.
///
/// Held only for as long as a session is. Secret-bearing, so `Debug` redacts and the seed
/// is `Zeroizing`; there is no `Clone`, because a second copy of a seed is a second thing
/// to wipe.
pub struct Wallet {
    slot: u8,
    label: String,
    network: Network,
    /// Derived from the live seed at open time. The value the engine runs on.
    fingerprint: Fingerprint,
    /// What a passphrase has to do with this wallet, decided at open time from the record
    /// AND from what it took to open it. Public - it is what the identity card renders -
    /// and never the passphrase itself.
    passphrase: PassphraseState,
    seed: Zeroizing<[u8; 64]>,
    /// The recovery words this wallet was sealed with, normalized.
    ///
    /// Kept rather than dropped at the end of `open`, and the reason is a REDUCTION in how
    /// many copies of the mnemonic exist. The export and signing screens need
    /// `notyas_core::report::Report`, which is derived from the phrase; without this field
    /// the only way to produce one would be to read and decrypt the record a second time,
    /// which puts a second copy of the same words in a fresh buffer while the first is
    /// still live. It is exactly as secret as `seed` - which IS the spending authority and
    /// is already here - it is under the same `Zeroizing`, and the same redacting `Debug`
    /// covers both.
    phrase: Zeroizing<String>,
    registrations: Vec<Registration>,
    /// Where each proven registration lives and what the user called it, index-aligned
    /// with `registrations`. See [`RegistryEntry`] for why it is a second vector rather
    /// than a field on the registration.
    entries: Vec<RegistryEntry>,
    faults: Vec<RegistryFault>,
}

/// The record identity behind one proven registration: its slot and its label.
///
/// Neither is a fact about the WALLET - `notyas_core::multisig::Registration` is the
/// descriptor and nothing else, deliberately, so that two devices holding the same wallet
/// compute the same id from the same bytes - and both are facts the screens need: the slot
/// is the handle `UiRequest::DeleteRegistration` names, and the label is what the user
/// called it when they approved it.
///
/// Index-aligned with `Wallet::registrations` rather than carried in a vector of pairs,
/// because `notyas_core::psbt::Context::registry` takes a `&[Registration]` and a vector of
/// pairs cannot produce that slice. The alignment is held by there being exactly two
/// places that extend either vector - [`load_registry`] builds both, [`Wallet::register`]
/// pushes to both - and one place that reads them, [`Wallet::registered`].
#[derive(Debug, Clone)]
pub struct RegistryEntry {
    pub slot: u8,
    pub label: String,
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Wallet")
            .field("slot", &self.slot)
            .field("label", &self.label)
            .field("network", &self.network)
            .field("fingerprint", &self.fingerprint)
            .field("passphrase", &self.passphrase)
            .field("registrations", &self.registrations.len())
            .field("faults", &self.faults.len())
            .field("seed", &"<redacted>")
            .finish()
    }
}

impl Wallet {
    /// Seal a wallet whose identity is already established into `slot`.
    ///
    /// This is the whole write path for a wallet record, and the only one. The occupancy
    /// gate, the encoder and the store call are here together on purpose: a caller that
    /// reaches `Store::write_payload` by itself can write bytes that are not a record and
    /// can overwrite the only copy of somebody's words, and both of those are exactly what
    /// happened while the touch UI had a save path of its own.
    ///
    /// It returns nothing. Without a passphrase there is no seed, and without a seed there
    /// is no open [`Wallet`] to hand back - which is what the screens want anyway: their
    /// save answers a bool.
    pub fn seal(
        store: &mut Store,
        slot: u8,
        new: &SealedWallet<'_>,
    ) -> Result<(), WalletError> {
        match payload_state(store, slot)? {
            SlotState::Empty => {}
            // `Opaque` is another identity's record. It is not ours to read and not ours
            // to overwrite either: the slot is occupied on the flash whoever can open it.
            SlotState::Occupied { .. } | SlotState::Opaque => {
                return Err(WalletError::SlotInUse { index: slot })
            }
        }

        let body = new.body(Store::max_payload_bytes())?;
        store
            .write_payload(slot, &body)
            .map_err(WalletError::Storage)
    }

    /// Seal into the lowest payload slot that holds nothing, and report which one it was.
    ///
    /// The slot is the DEVICE's to choose here. No ratified document names a selection
    /// rule for a save made from the touchscreen: the screens raise `PersistWallet` with
    /// no slot in it, `Ui::persist_result` takes no slot back, and the frozen storage API
    /// (WALLET-API.md 2.6) has the sealing side return the id rather than be told it. So
    /// this takes the one rule this firmware already ships, from [`free_registry_slot`] -
    /// the lowest-index empty slot. It is deterministic, it needs no stored cursor, and it
    /// cannot pick a slot that holds anything: an `Occupied` or `Opaque` slot is skipped
    /// here and would be refused again by [`Wallet::seal`].
    ///
    /// A full device is a refusal ([`WalletError::NoFreeSlot`]) rather than a slot chosen
    /// for eviction. UX-SCREENS.md S-19 has the offer disabled before the user ever gets
    /// here; this is the same answer given by the layer that can actually see the flash.
    pub fn seal_into_free_slot(
        store: &mut Store,
        new: &SealedWallet<'_>,
    ) -> Result<u8, WalletError> {
        let slot = free_payload_slot(store)?;
        Wallet::seal(store, slot, new)?;
        Ok(slot)
    }

    /// Seal a new wallet into an empty payload slot and return it open.
    ///
    /// The identity is DERIVED here, from the passphrase this caller holds and never
    /// stores. That derivation is the only thing this adds over [`Wallet::seal`], and it is
    /// why this is the one door that can return an open wallet.
    pub fn save(
        store: &mut Store,
        slot: u8,
        new: &NewWallet<'_>,
    ) -> Result<Wallet, WalletError> {
        let phrase = bip39::normalize_phrase(new.phrase);
        let seed = bip39::seed(&phrase, new.passphrase);
        let fingerprint = derive::master_fingerprint(&seed, new.network);

        // Derived BEFORE the slot is checked, so a refused save costs one PBKDF2 run it
        // will not use. That is the price of there being exactly one occupancy gate and
        // one encoder in this file, and it is worth paying: a second gate here is how a
        // caller ends up going through neither, which is what the UI save path did.
        Wallet::seal(
            store,
            slot,
            &SealedWallet {
                label: new.label,
                network: new.network,
                phrase: &phrase,
                fingerprint,
                // This door stores no passphrase. Storing one is a decision the owner
                // makes per wallet, afterwards, on a screen that states what it costs
                // (Q22 amendment, 2026-08-19) - never as a side effect of a save.
                passphrase: if new.passphrase.is_empty() {
                    StoredPassphrase::None
                } else {
                    StoredPassphrase::Applied
                },
            },
        )?;

        Ok(Wallet {
            slot,
            label: new.label.to_string(),
            network: new.network,
            fingerprint,
            passphrase: if new.passphrase.is_empty() {
                PassphraseState::None
            } else {
                PassphraseState::Required
            },
            seed,
            phrase,
            // A brand new wallet is a member of nothing. Registrations arrive through
            // `register`, one proven import at a time.
            registrations: Vec::new(),
            entries: Vec::new(),
            faults: Vec::new(),
        })
    }

    /// Open the wallet in `slot` with `passphrase`, and rebuild its registry.
    ///
    /// The registry rebuild is a re-proof and not a load: every stored descriptor is parsed
    /// and put back through `Pending::verify` against THIS seed, and what comes out must be
    /// the registration the record was written for. A record that fails either test becomes
    /// a [`RegistryFault`] and never a registration. See [`reproven`].
    pub fn open(
        store: &mut Store,
        slot: u8,
        passphrase: &str,
    ) -> Result<Wallet, WalletError> {
        let record = read_record(store, slot)?;

        let phrase = record.phrase.clone();
        let seed = bip39::seed(&phrase, passphrase);
        let fingerprint = derive::master_fingerprint(&seed, record.network);
        if fingerprint != record.fingerprint {
            return Err(WalletError::PassphraseMismatch {
                expected: record.fingerprint,
                derived: fingerprint,
            });
        }

        // What the identity card will say, decided from the record AND from what it took
        // to open it. The second half matters for exactly one case and it is the owner's:
        // a format 1 record carries no flag, so a wallet that HAS a passphrase decodes as
        // `None`, and the only evidence that it has one is that a non-empty passphrase is
        // what opened it. Reading the flag alone would put "no passphrase" on the card of
        // a wallet the user had just typed a passphrase into.
        let passphrase = match (&record.passphrase, passphrase.is_empty()) {
            (StoredPassphrase::Stored(_), _) => PassphraseState::Stored,
            (StoredPassphrase::Applied, _) => PassphraseState::Required,
            (StoredPassphrase::None, false) => PassphraseState::Required,
            (StoredPassphrase::None, true) => PassphraseState::None,
        };

        let (registrations, entries, faults) = load_registry(store, slot, record.network, &seed);
        Ok(Wallet {
            slot,
            label: record.label,
            network: record.network,
            fingerprint,
            passphrase,
            seed,
            phrase,
            registrations,
            entries,
            faults,
        })
    }

    /// Everything `notyas_core::psbt::inspect` is allowed to know besides the PSBT.
    ///
    /// Read the module header before changing anything here: every field is a device fact
    /// and none of them may ever be sourced from a file. `StructuralLimits::DEFAULT` is
    /// the ratified set (Q25) and is deliberately not adjustable from any screen - Q24
    /// forbids an override that reaches a refusal, and every one of those limits is one.
    pub fn context(&self) -> Context<'_> {
        Context {
            network: self.network,
            fingerprint: self.fingerprint,
            limits: StructuralLimits::DEFAULT,
            registry: &self.registrations,
        }
    }

    /// Prove membership of a multisig wallet and seal it into a registry slot.
    ///
    /// Two things happen in this order and the order is the point: `verify` needs the seed
    /// and refuses a wallet this device is not a member of, and only what it returns is
    /// ever written. There is no path from a descriptor to storage that does not pass
    /// through it.
    pub fn register(
        &mut self,
        store: &mut Store,
        label: &str,
        text: &str,
    ) -> Result<RegistrationId, RegisterError> {
        let pending = multisig::parse(text).map_err(RegisterError::Malformed)?;
        let registration = pending
            .verify(&self.seed, self.network)
            .map_err(RegisterError::Refused)?;
        let id = registration.id();
        if self.registrations.iter().any(|r| r.id() == id) {
            return Err(RegisterError::AlreadyRegistered(id));
        }

        let free = free_registry_slot(store)?;
        let body = RegistrationRecord {
            wallet_slot: self.slot,
            // Written here, at the one moment this device knows which wallet the user
            // approved, and never recomputed from the record afterwards. That asymmetry is
            // the whole point: a value the loader re-derives from the descriptor could only
            // ever agree with the descriptor.
            id: id_bytes(id),
            label: label.to_string(),
            // The registration's OWN canonical rendering, not the text that came in. Two
            // devices holding this wallet then store the same bytes and compute the same
            // id, and a Coldcard-dialect import is stored as the descriptor it means.
            descriptor: registration.descriptor().to_string(),
        }
        .encode(Store::max_registry_bytes())
        .map_err(RegisterError::Record)?;
        store
            .write_registry(free, &body)
            .map_err(RegisterError::Storage)?;

        // Both vectors, together, at the one site that adds a registration after open
        // time. See `RegistryEntry` for the invariant this keeps.
        self.registrations.push(registration);
        self.entries.push(RegistryEntry {
            slot: free,
            label: label.to_string(),
        });
        Ok(id)
    }

    /// Erase the registration in registry slot `slot`, if it is one of this wallet's.
    ///
    /// The ownership test is not a formality. A screen names a slot it read off this
    /// wallet's own list, so a slot this wallet does not hold means the list is older than
    /// the registry - and erasing whatever is in that slot now would destroy another
    /// wallet's registration on the strength of a stale screen. It is a refusal instead,
    /// and the screen states it.
    ///
    /// The in-memory registration goes with the record, in the same call: a `Wallet` whose
    /// `context()` still named a wallet whose record has been erased would keep proving
    /// change against a registration the device no longer has, until the next unlock.
    pub fn deregister(&mut self, store: &mut Store, slot: u8) -> Result<(), RegisterError> {
        let Some(at) = self.entries.iter().position(|e| e.slot == slot) else {
            return Err(RegisterError::NoSuchRegistration { slot });
        };
        store.clear_registry(slot).map_err(RegisterError::Storage)?;
        self.entries.remove(at);
        self.registrations.remove(at);
        Ok(())
    }

    /// Each proven registration with the record identity behind it, in slot order.
    ///
    /// The only reader of the alignment `RegistryEntry` documents, which is what makes that
    /// invariant a local property rather than a rule every call site has to keep.
    pub fn registered(&self) -> impl Iterator<Item = (&RegistryEntry, &Registration)> {
        self.entries.iter().zip(self.registrations.iter())
    }

    /// The PUBLIC derivation the export and signing screens are gated on.
    ///
    /// Everything here is public: an account xpub, a descriptor, the first receive
    /// addresses of each scheme. It is what `Ui::wallet_opened_with_keys` takes, and a
    /// stored wallet opened WITHOUT one can only be deleted - which is what a wallet behind
    /// the PIN could do and nothing else until this method existed.
    ///
    /// `passphrase` has to be given again rather than remembered, because Q22 keeps a
    /// BIP-39 passphrase out of every structure that outlives the screen that took it. It
    /// must be the one this wallet was opened with; a different one derives a DIFFERENT
    /// wallet, and the report would describe keys this device is not holding. The
    /// fingerprint comparison below is what says so out loud rather than trusting the
    /// caller: a mismatch is `None`, never a report about somebody else's wallet.
    ///
    /// Costs one BIP-39 stretch plus one account derivation per scheme, which is the
    /// several hundred milliseconds the create flow already spends on its own interstitial.
    /// A caller that does not need the report must not call this.
    pub fn derivation(&self, passphrase: &str, addresses: u32) -> Option<Report> {
        let report = Report::from_phrase(
            &self.phrase,
            &Parameters {
                // The record stores words, not dice. `Raw` is what the phrase path uses
                // (see `Report::from_phrase`), and the renderers read `mnemonic_input`
                // rather than this field on that path.
                mode: bip39::MnemonicMode::Raw,
                passphrase,
                // The WALLET's network, out of its own sealed record. Never the device
                // setting: a wallet's chain is fixed for the whole of its life.
                network: self.network,
                schemes: &derive::Scheme::ALL,
                account: derive::ChildIndex::ZERO,
                change: derive::ChildIndex::ZERO,
                count: addresses,
                script_type: 2,
            },
        )?;
        if report.root_fingerprint != self.fingerprint.to_string() {
            log::error!(
                "wallet: derivation for slot {} refused: it produces wallet {} and this                  wallet is {} - the passphrase does not match the open wallet",
                self.slot,
                report.root_fingerprint,
                self.fingerprint
            );
            return None;
        }
        Some(report)
    }

    /// What a passphrase has to do with this wallet. Public, and never the passphrase.
    pub fn passphrase(&self) -> PassphraseState {
        self.passphrase
    }

    pub fn slot(&self) -> u8 {
        self.slot
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The master fingerprint of the live seed. Public, and the same value the review
    /// screen prints beside every input this device claims.
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Read what the record in `slot` says, without deriving anything.
    ///
    /// One AEAD open, no PBKDF2. The open path calls this FIRST, because which passphrase
    /// to try is a decision that has to be made before trying one costs several seconds -
    /// and because trying the empty passphrase on a wallet that has one produces a
    /// mismatch whose derived fingerprint must never reach a screen (it is what the words
    /// derive with no passphrase, which is an existence proof for a hidden wallet).
    pub fn inspect(store: &mut Store, slot: u8) -> Result<RecordFacts, WalletError> {
        let record = read_record(store, slot)?;
        Ok(RecordFacts {
            label: record.label,
            network: record.network,
            passphrase: record.passphrase,
        })
    }

    /// Re-seal the record in `slot` with the passphrase remembered (`Some`) or forgotten
    /// (`None`), and report what the record says when it is READ BACK.
    ///
    /// # Why this is the one place a wallet record is replaced
    ///
    /// Every other write path here CREATES: `seal` refuses an occupied slot, deliberately,
    /// because the record it would replace is the only copy of somebody's words. This one
    /// replaces on purpose, and it is written so that it cannot lose them: the new body is
    /// built from the record that was just read, so the phrase, the label, the network and
    /// the fingerprint are the ones already on the flash, and the ONLY difference is the
    /// passphrase field.
    ///
    /// # Why the passphrase is checked on the way in
    ///
    /// [`SealedWallet::confirmed`] re-derives the fingerprint from the words plus the
    /// passphrase being stored and refuses if they disagree. A stored passphrase that does
    /// not open its own record would be worse than storing nothing: the wallet would be
    /// refused forever, with a mismatch that reads exactly like a forgotten passphrase.
    ///
    /// # What forgetting destroys
    ///
    /// The write goes to the slot's INACTIVE side and the vault erases the stale side
    /// before it returns (`Vault::write` -> `seal_into` -> `StaleSide::EraseNow`), so when
    /// this returns there is exactly one side of this slot that opens under the session
    /// key and it is the one with no passphrase in it. A cut in that window leaves the
    /// stale side for the next mount's cleanup, which is the same guarantee every other
    /// record write on this device has.
    pub fn set_passphrase_storage(
        store: &mut Store,
        slot: u8,
        remember: Option<&str>,
    ) -> Result<PassphraseState, WalletError> {
        let record = read_record(store, slot)?;
        let fingerprint = record.fingerprint.to_string();
        let sealed = SealedWallet::confirmed(
            &record.label,
            record.network,
            &record.phrase,
            &fingerprint,
            match remember {
                Some(p) => StoredPassphrase::Stored(Zeroizing::new(p.to_string())),
                None => record.passphrase.forgotten(),
            },
        )?;
        let body = sealed.body(Store::max_payload_bytes())?;
        store
            .write_payload(slot, &body)
            .map_err(WalletError::Storage)?;

        // Read back and re-decode, so what the screen renders is what the flash says
        // rather than what this function meant. A toggle whose state came from the intent
        // would be a switch that lies about the one thing it controls.
        let back = read_record(store, slot)?;
        Ok(match back.passphrase {
            StoredPassphrase::Stored(_) => PassphraseState::Stored,
            StoredPassphrase::Applied => PassphraseState::Required,
            // Unreachable through this function - `forgotten` never drops to `None` - and
            // reported honestly rather than asserted: it would mean the record now claims
            // a wallet that no passphrase belongs to.
            StoredPassphrase::None => PassphraseState::None,
        })
    }

    /// The multisig wallets this device has proven it is a member of, in slot order.
    pub fn registrations(&self) -> &[Registration] {
        &self.registrations
    }

    /// Registry records that did not prove out at open time. Empty is the normal case.
    pub fn registry_faults(&self) -> &[RegistryFault] {
        &self.faults
    }

    /// The seed, for the three callers that may have it.
    ///
    /// Crate-private and borrowed, so it cannot escape this device. Each call site hands it
    /// straight to a notyas-core function that derives inside its own loop and keeps nothing:
    ///
    /// - `crate::signing::Review::sign` -> `psbt::sign`, one key per input, dropped there;
    /// - `crate::signing::review` -> `derive::device_accounts`, four watch-only account
    ///   xpubs and no private material;
    /// - `crate::flow::import_registration` -> `multisig::Pending::verify`, which derives
    ///   this device's cosigner key at the origin a descriptor claims and compares it. That
    ///   comparison IS the 2021 xpub-substitution defence, and it cannot be performed
    ///   without the seed - which is the whole reason a registration is imported through an
    ///   open wallet rather than through the store.
    ///
    /// Nothing else in the firmware calls this, and nothing else should: a screen that needs
    /// a public key wants a derivation, not a seed.
    ///
    /// The account set belongs beside `registry`, proven from the seed once at open time
    /// for the same reason the registry is. It is derived per review instead because the
    /// move needs a field here AND a field on `notyas_core::psbt::Context`, and the two
    /// have to land together.
    pub(crate) fn seed(&self) -> &[u8; 64] {
        &self.seed
    }
}

/// The recovery words stored in payload slot `slot`, without opening the wallet.
///
/// # Why this exists at all, and why it is not [`Wallet::open`]
///
/// Opening a wallet derives a seed, which needs a BIP-39 passphrase this device never
/// stored (ratified Q22) and costs a PBKDF2 stretch. Re-SHOWING the words needs neither: the
/// record holds the normalized phrase, deliberately, because "a seed cannot be turned back
/// into words, so a device holding only seeds could never re-show a backup"
/// (`record.rs`). This reads exactly that field and derives nothing, which is what lets the
/// last-words step in front of a delete work on a passphrase wallet the session cannot open.
///
/// # What the caller is agreeing to
///
/// This is the only function in the firmware that returns a stored mnemonic to its caller.
/// The value is `Zeroizing` and the buffer it was decoded from is too, so the words exist in
/// exactly two places that both wipe themselves. What the caller must not do is copy them
/// into anything that does not - the screen that receives them holds this same value and
/// borrows into it to draw, and `Ui::lock` drops the whole navigation stack on the
/// auto-lock, which is what takes a revealed screen down with it.
///
/// The words alone are NOT the whole of a passphrase wallet, and every surface that shows
/// them owes the user that sentence. See `crates/notyas-ui/src/screens/erase.rs`.
pub fn stored_phrase(store: &mut Store, slot: u8) -> Result<Zeroizing<String>, WalletError> {
    match payload_state(store, slot)? {
        SlotState::Occupied { .. } => {}
        SlotState::Empty | SlotState::Opaque => {
            return Err(WalletError::SlotEmpty { index: slot })
        }
    }
    // Zeroizing for the reason `Wallet::open`'s is: this buffer holds the user's words
    // between the AEAD and the parse.
    let mut buf = Zeroizing::new(vec![0u8; Store::max_payload_bytes()]);
    let n = store
        .read_payload(slot, &mut buf)
        .map_err(WalletError::Storage)?;
    let record = WalletRecord::decode(buf.get(..n).ok_or(RecordError::Truncated)?)?;
    Ok(record.phrase)
}

/// [`erase::WalletSlots`] over the real store and the open wallet.
///
/// Five short methods and no decisions: the ordering lives in [`erase::erase`] so that the
/// device and `firmware/hostcheck` run the same one. Exactly the shape
/// `crate::flow::replace::SlotSwap` has, and for the same reason.
pub struct StoredWallets<'a> {
    store: &'a mut Store,
    /// The wallet the session currently has open, if any. Borrowed rather than owned
    /// because dropping it is one of the five operations: a wallet whose record is about to
    /// be erased must not stay live behind the screen that erased it.
    open: &'a mut Option<Wallet>,
}

impl<'a> StoredWallets<'a> {
    pub fn new(store: &'a mut Store, open: &'a mut Option<Wallet>) -> StoredWallets<'a> {
        StoredWallets { store, open }
    }
}

impl erase::WalletSlots for StoredWallets<'_> {
    type Error = String;

    /// Every registry slot whose record NAMES this payload slot.
    ///
    /// Deliberately not [`load_registry`]: that one re-proves each registration against a
    /// live seed, and a delete must work on a wallet nobody has opened. What is needed here
    /// is the `wallet_slot` field and nothing else, so no seed is touched and no
    /// registration is re-derived.
    ///
    /// A registry record that will not decode is SKIPPED rather than erased. It names no
    /// wallet this device can read, so attributing it to the one being deleted would be a
    /// guess, and the thing the guess destroys on a miss is another wallet's registration.
    /// It is already invisible to every wallet (`load_registry` reports it as a fault and
    /// moves on); leaving it costs a registry slot and no correctness.
    fn registrations_of(&mut self, slot: u8) -> Result<Vec<u8>, String> {
        // A registration record is public - cosigner xpubs, a threshold, a name - so this
        // buffer needs no wiping, unlike a payload one.
        let mut buf = vec![0u8; Store::max_registry_bytes()];
        let mut out = Vec::new();
        for index in 0..Store::registry_slots() {
            match self.store.registry_state(index) {
                Ok(SlotState::Occupied { .. }) => {}
                // Empty is empty; `Opaque` is another PIN identity's record and is not this
                // session's to read, let alone to erase.
                Ok(_) => continue,
                // A slot that will not even report its state stops the walk. Pressing on
                // would be deciding that a registration this device could not look at does
                // not belong to the wallet about to be erased - which is exactly the orphan
                // the ordering rule exists to prevent.
                Err(e) => return Err(format!("registry slot {index} did not read: {e}")),
            }
            let n = match self.store.read_registry(index, &mut buf) {
                Ok(n) => n,
                Err(e) => return Err(format!("registry slot {index} did not open: {e}")),
            };
            let record = match buf
                .get(..n)
                .ok_or(record::RecordError::Truncated)
                .and_then(RegistrationRecord::decode)
            {
                Ok(r) => r,
                Err(e) => {
                    log::error!(
                        "wallet: registry slot {index} is not a readable registration ({e}), \
                         so the delete of wallet slot {slot} leaves it alone"
                    );
                    continue;
                }
            };
            if record.wallet_slot == slot {
                out.push(index);
            }
        }
        Ok(out)
    }

    fn erase_registration(&mut self, registry_slot: u8) -> Result<(), String> {
        self.store.clear_registry(registry_slot)
    }

    fn erase_wallet(&mut self, slot: u8) -> Result<(), String> {
        if slot >= Store::payload_slots() {
            return Err(format!("there is no wallet slot {slot}"));
        }
        self.store.clear_payload(slot)
    }

    fn occupancy(&mut self, slot: u8) -> Result<erase::Occupancy, String> {
        match payload_state(self.store, slot).map_err(|e| e.to_string())? {
            SlotState::Empty => Ok(erase::Occupancy::Free),
            SlotState::Occupied { .. } => Ok(erase::Occupancy::Mine),
            SlotState::Opaque => Ok(erase::Occupancy::Opaque),
        }
    }

    /// Take the open wallet when it is the one being erased. The take IS the wipe: `Wallet`
    /// owns the seed and the phrase under `Zeroizing`, so dropping it here is what stops a
    /// deleted wallet's key material outliving its record.
    fn close_if_open(&mut self, slot: u8) {
        if self.open.as_ref().is_some_and(|w| w.slot() == slot) {
            self.open.take();
            log::info!("wallet: slot {slot} was open - the session wallet was dropped first");
        }
    }
}

/// Read and decode the wallet record in `slot`.
///
/// The one reader, so that "an occupied slot, opened with this session's key, decoded as a
/// wallet" is one piece of code rather than three copies that can drift. The buffer is
/// `Zeroizing` because a wallet record IS a mnemonic: it holds the user's words between
/// the AEAD and the parse, and a plain `Vec` would leave them in freed heap.
fn read_record(store: &mut Store, slot: u8) -> Result<WalletRecord, WalletError> {
    match payload_state(store, slot)? {
        SlotState::Occupied { .. } => {}
        SlotState::Empty | SlotState::Opaque => {
            return Err(WalletError::SlotEmpty { index: slot })
        }
    }
    let mut buf = Zeroizing::new(vec![0u8; Store::max_payload_bytes()]);
    let n = store
        .read_payload(slot, &mut buf)
        .map_err(WalletError::Storage)?;
    Ok(WalletRecord::decode(buf.get(..n).ok_or(RecordError::Truncated)?)?)
}

/// A payload slot's state, with the slot index checked as a wallet-level fact rather than
/// as a storage string. `Store` answers in its own vocabulary; this is where "there is no
/// slot 9" becomes something a screen can say.
fn payload_state(store: &mut Store, slot: u8) -> Result<SlotState, WalletError> {
    if slot >= Store::payload_slots() {
        return Err(WalletError::NoSuchSlot { index: slot });
    }
    store.payload_state(slot).map_err(WalletError::Storage)
}

/// The first payload slot holding nothing, i.e. the slot a save with no slot named goes
/// into. [`Wallet::seal_into_free_slot`] carries the reasoning for the rule.
///
/// A slot whose state will not read stops the walk instead of being treated as free. The
/// alternative is to skip it and keep looking, which reads a storage fault as "this slot is
/// occupied" on the way past - and the next reading of it, at the seal, would be the same
/// fault stopping the write anyway.
fn free_payload_slot(store: &mut Store) -> Result<u8, WalletError> {
    let slots = Store::payload_slots();
    for index in 0..slots {
        match store.payload_state(index) {
            Ok(SlotState::Empty) => return Ok(index),
            Ok(_) => continue,
            Err(e) => return Err(WalletError::Storage(e)),
        }
    }
    Err(WalletError::NoFreeSlot { slots })
}

/// The first registry slot holding nothing.
fn free_registry_slot(store: &mut Store) -> Result<u8, RegisterError> {
    let slots = Store::registry_slots();
    for index in 0..slots {
        match store.registry_state(index) {
            Ok(SlotState::Empty) => return Ok(index),
            Ok(_) => continue,
            Err(e) => return Err(RegisterError::Storage(e)),
        }
    }
    Err(RegisterError::NoFreeSlot { slots })
}

/// Rebuild the registry for one wallet: every registry slot, every record that names this
/// wallet, re-parsed and re-proven against this seed, and checked against the id it was
/// registered under ([`reproven`]).
///
/// Never fails as a whole. One bad record must not cost a user the wallets stored beside
/// it, so a failure becomes a [`RegistryFault`] and the walk continues.
fn load_registry(
    store: &mut Store,
    wallet_slot: u8,
    network: Network,
    seed: &[u8; 64],
) -> (Vec<Registration>, Vec<RegistryEntry>, Vec<RegistryFault>) {
    let mut registrations = Vec::new();
    let mut entries = Vec::new();
    let mut faults = Vec::new();
    let mut buf = vec![0u8; Store::max_registry_bytes()];

    for slot in 0..Store::registry_slots() {
        match store.registry_state(slot) {
            // Empty is empty. `Opaque` is another PIN identity's record: not readable with
            // this session's key, not ours, and not a fault of this wallet's.
            Ok(SlotState::Empty) | Ok(SlotState::Opaque) => continue,
            Ok(SlotState::Occupied { .. }) => {}
            Err(e) => {
                faults.push(RegistryFault {
                    slot,
                    reason: FaultReason::Storage(e),
                });
                continue;
            }
        }

        let n = match store.read_registry(slot, &mut buf) {
            Ok(n) => n,
            Err(e) => {
                faults.push(RegistryFault {
                    slot,
                    reason: FaultReason::Storage(e),
                });
                continue;
            }
        };
        let record = match buf
            .get(..n)
            .ok_or(RecordError::Truncated)
            .and_then(RegistrationRecord::decode)
        {
            Ok(r) => r,
            Err(e) => {
                faults.push(RegistryFault {
                    slot,
                    reason: FaultReason::Record(e),
                });
                continue;
            }
        };
        // Another wallet's registration. Not this wallet's business and not its fault.
        if record.wallet_slot != wallet_slot {
            continue;
        }

        match reproven(&record, network, seed) {
            Ok(registration) => {
                registrations.push(registration);
                entries.push(RegistryEntry {
                    slot,
                    label: record.label,
                });
            }
            Err(reason) => faults.push(RegistryFault { slot, reason }),
        }
    }

    (registrations, entries, faults)
}

/// Turn one stored record back into the registration it was written for, or say why not.
///
/// Two questions, and it takes both to get an answer worth having:
///
/// 1. **Are we a member of the wallet this text describes?** `Pending::verify` against the
///    live seed, which is the 2021 xpub-substitution defence. It needs the seed, so its
///    answer cannot be manufactured by anything on flash.
/// 2. **Is this text the wallet we registered?** The id comparison. `verify` cannot answer
///    this and never could: the only thing it has to compare the descriptor against is the
///    descriptor. Left at (1) alone, a record whose OTHER cosigners were replaced - ours
///    untouched, so every membership check still passes - loads as a proven registration
///    of a wallet the user never approved. That decides which outputs re-derive as change,
///    which is the multisig case m7 exists to cover, so it is the change-confusion attack
///    with the registry in the PSBT's place.
///
/// # Why a comparison, and not an AAD binding or a device MAC
///
/// The obvious alternative is to bind the id into the sealing layer's associated data, or
/// to store a tag from the eFuse HMAC key beside it. Neither is the right answer here:
///
/// - The id is the BIP-380 checksum OF the descriptor, and the descriptor is the body the
///   AEAD already authenticates. Binding it into that AEAD's associated data would
///   authenticate a function of the ciphertext with the ciphertext - the circularity
///   `notyas_wallet::format`'s `body_digest` comment declines for the same reason.
/// - A device-keyed tag over the same bytes adds no adversary. The eFuse key is already an
///   input to the key that produced the AEAD tag over this body, so anyone who can present
///   a body the seal accepts can present the tag too, and anyone who cannot, cannot. It
///   would buy one more hardware call that can fail on every unlock, and nothing else.
///
/// What was missing was never a stronger key. It was that the device kept no record of
/// what it had approved, so the loader had nothing to check against. The id is that record,
/// written once by `Wallet::register` and only ever read here.
///
/// The honest limit: this establishes identity against the record, and the seal is what
/// establishes the record. An attacker who can produce a body the AEAD accepts can write a
/// matching id as easily as a matching descriptor - no field inside a record can outrank
/// the seal around it. Closing THAT is Secure Boot v2 and flash encryption (Q32, Q63), and
/// until they ship this check is what keeps the gap to exactly that adversary instead of
/// leaving it open to anyone who can read the flash and think.
fn reproven(
    record: &RegistrationRecord,
    network: Network,
    seed: &[u8; 64],
) -> Result<Registration, FaultReason> {
    let pending = multisig::parse(&record.descriptor).map_err(FaultReason::Malformed)?;
    let registration = pending.verify(seed, network).map_err(FaultReason::Unproven)?;
    let derived = registration.id();
    if id_bytes(derived) != record.id {
        return Err(FaultReason::NotAsRegistered {
            stored: id_text(&record.id),
            derived,
        });
    }
    Ok(registration)
}

/// A [`RegistrationId`] as the eight bytes a record stores.
///
/// Written as a copy rather than a `try_into` because a short or long rendering must not
/// panic on a device: a mismatch is this file's reported fault, and a crash inside the
/// unlock path would take the user's other wallets with it.
fn id_bytes(id: RegistrationId) -> [u8; 8] {
    let mut out = [0u8; 8];
    let text = id.to_string();
    for (dst, byte) in out.iter_mut().zip(text.as_bytes()) {
        *dst = *byte;
    }
    out
}

/// A stored id rendered for the screen, in `RegistrationId`'s own spelling.
///
/// Those eight bytes come from the BIP-380 checksum charset, which is ASCII; bytes that are
/// not are exactly the case being reported, so they render as `RegistrationId::fmt`'s own
/// fallback rather than as a second error the screen would have to explain.
fn id_text(id: &[u8; 8]) -> String {
    core::str::from_utf8(id).unwrap_or("????????").to_string()
}
