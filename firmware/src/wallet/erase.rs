// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Erasing a stored wallet: what is destroyed, in what order, and what is checked after.
//!
//! # Why an order, and why this one
//!
//! Deleting a wallet destroys two kinds of record. The wallet's own payload record holds
//! the recovery words. Its multisig registrations are separate registry records that NAME
//! the payload slot (`RegistrationRecord::wallet_slot`), and a registry record carries no
//! other tie to the wallet it belongs to.
//!
//! `Store` publishes no transaction and no multi-slot atomic write, so the two erases are
//! two commits and a power cut can land between them. That makes the order a safety
//! property rather than a preference:
//!
//! - Registrations first, then the record. A cut in between leaves a wallet that still
//!   opens and has fewer registrations than it had. The user sees the wallet, deletes
//!   again, and nothing was lost that the coordinator cannot re-issue (ratified Q14: a
//!   registration is re-importable, a seed is not).
//! - The other order leaves the opposite: registry records naming a payload slot that is
//!   now free. The next wallet stored on this device takes the LOWEST free slot, which is
//!   the one just vacated, and would inherit a dead wallet's registrations - the device
//!   would then prove change against a multisig wallet the new seed is not a member of.
//!   That is a silent, durable wrong answer, and it is why this is a module with an
//!   ordering rule in it rather than two calls at a call site.
//!
//! # Why the slot is read back
//!
//! Because the complaint that produced this module was a delete that reported nothing. An
//! `Ok` from the store says the write returned; it does not say the slot is free. [`erase`]
//! asks the flash what the slot now holds and reports [`Erased::Gone`] only when the answer
//! is "nothing". Every other answer becomes a sentence the user reads.
//!
//! # Why a trait
//!
//! The ordering above is the whole content of this module, and against a real `Store` - an
//! ESP-IDF flash partition - none of it can run on a host. Behind [`WalletSlots`] the same
//! code runs on the device and against slots that can be made to fail on demand, so the
//! partial-failure paths are covered by tests in CI rather than by review alone
//! (`firmware/hostcheck`). This file holds no `Store`, no logger and no ESP-IDF, and must
//! not acquire any of them.

use core::fmt;

/// Whether a payload slot holds anything, as the session that asked can see it.
///
/// Three states and not a bool: `Opaque` is a slot holding a record this session's key
/// cannot open, and counting that as "gone" would report another identity's wallet as
/// deleted. It is `notyas_wallet::SlotState` reduced to what an erase needs, which is what
/// lets this module depend on no storage crate at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Occupancy {
    /// Nothing is there. On this product that covers device filler, an erased side and a
    /// slot never used - the store deliberately does not distinguish them, because telling
    /// them apart is the occupancy leak `Occupancy::AlwaysFilled` exists to close.
    Free,
    /// A record this session can open.
    Mine,
    /// A record this session cannot open. Not ours to read and not ours to report gone.
    Opaque,
}

/// Everything an erase does to storage, and nothing else.
///
/// Deliberately narrow, for the reason `crate::flow::replace::RegistrySlots` is: an
/// implementation that could do more would invite a second ordering decision at the call
/// site, and the point of this module is that there is exactly one.
pub trait WalletSlots {
    /// What any of these can fail with, already worded for a person. `String` on the
    /// device, because that is what `Store` returns.
    type Error: fmt::Display;

    /// The registry slots holding registrations that name payload slot `slot`.
    ///
    /// Read fresh rather than taken from the count on the consent sheet: that number was
    /// rendered a user's reading-time ago, and what gets erased has to be what is there
    /// now.
    fn registrations_of(&mut self, slot: u8) -> Result<Vec<u8>, Self::Error>;

    /// Erase one registry slot.
    fn erase_registration(&mut self, registry_slot: u8) -> Result<(), Self::Error>;

    /// Erase the wallet's own payload record.
    fn erase_wallet(&mut self, slot: u8) -> Result<(), Self::Error>;

    /// What payload slot `slot` holds, read from storage.
    fn occupancy(&mut self, slot: u8) -> Result<Occupancy, Self::Error>;

    /// Drop the open wallet if it is this one, so that no seed, no derivation and no proven
    /// registration outlives the record it came from.
    ///
    /// Called BEFORE anything is erased. S-47 requires it, and so does correctness: a live
    /// wallet for a slot whose record is gone would go on offering a signing context built
    /// from registrations this call is about to destroy.
    fn close_if_open(&mut self, slot: u8);
}

/// What the device now holds, in terms a screen can put in front of a person.
///
/// Four outcomes rather than `Result<(), E>`, because "it failed" is three different
/// situations for the owner of a wallet and only one of them is answered by tapping again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Erased {
    /// The registrations and the record are gone, and the slot was read back afterwards to
    /// say so. The only outcome that may be reported as a completed delete.
    Gone {
        /// How many registry records went with the wallet. Reported because the consent
        /// sheet named a count and the user is owed the one that actually happened.
        registrations: u8,
    },
    /// Nothing was destroyed. The device is exactly as it was.
    Refused(String),
    /// Some registrations were erased and the wallet record was not. The wallet still
    /// opens, with fewer registrations than it had. Its own outcome because a screen must
    /// not call this a refusal: something WAS destroyed, and the user has to know which.
    Partial(String),
    /// Every erase returned success and the slot still does not read as free. Nothing here
    /// can explain that, so nothing here pretends to - it is the one outcome that tells the
    /// user to distrust the device rather than to try again.
    NotGone(String),
}

impl Erased {
    /// The sentence for the user, or `None` where there is nothing to explain.
    ///
    /// `None` is the ONLY reading of a completed delete, which is what makes this the whole
    /// predicate: a caller that has something to say has something that did not happen.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Erased::Gone { .. } => None,
            Erased::Refused(s) | Erased::Partial(s) | Erased::NotGone(s) => Some(s),
        }
    }
}

/// Destroy the wallet in payload slot `slot`, registrations first, and check afterwards.
///
/// `name` is used to write sentences and for nothing else; no lookup is keyed on it.
pub fn erase<S: WalletSlots>(slots: &mut S, slot: u8, name: &str) -> Erased {
    // Before the first erase, so a cut anywhere below cannot leave a live wallet whose
    // registry list describes records that are gone.
    slots.close_if_open(slot);

    let registry = match slots.registrations_of(slot) {
        Ok(r) => r,
        // Refused rather than pressed on with. Erasing the payload record while the
        // registry could not even be listed is exactly the orphan case the ordering exists
        // to prevent, and "the registry would not read" is not a reason to create it.
        Err(e) => {
            return Erased::Refused(format!(
                "\"{name}\" was not deleted. This device could not read which multisig \
                 registrations belong to it ({e}), and erasing the wallet without them would \
                 leave registrations pointing at a free slot. Nothing was erased."
            ))
        }
    };
    let claimed = registry.len();

    let mut done = 0u8;
    for registry_slot in registry {
        if let Err(e) = slots.erase_registration(registry_slot) {
            // Stop at the first failure. Going on would destroy more of a wallet that is
            // going to survive this call anyway.
            let sentence = format!(
                "\"{name}\" was NOT deleted. Registry slot {registry_slot} would not erase \
                 ({e}), so the wallet was left in place."
            );
            return if done == 0 {
                Erased::Refused(format!("{sentence} Nothing was erased."))
            } else {
                Erased::Partial(format!(
                    "{sentence} {done} of its {claimed} multisig registrations were erased \
                     first and are gone - import those again from your other devices, or \
                     delete the wallet again to finish."
                ))
            };
        }
        done = done.saturating_add(1);
    }

    if let Err(e) = slots.erase_wallet(slot) {
        let sentence =
            format!("\"{name}\" was NOT deleted: the wallet slot would not erase ({e}).");
        return if done == 0 {
            Erased::Refused(format!("{sentence} Nothing was erased."))
        } else {
            Erased::Partial(format!(
                "{sentence} Its {done} multisig registration(s) were erased first and are \
                 gone. The recovery words are still on this device. Delete the wallet again \
                 to finish, or import the registrations again from your other devices."
            ))
        };
    }

    // The claim is CHECKED, not inferred. This read-back is the line between this build and
    // the one that logged a refusal and re-installed an unchanged list.
    match slots.occupancy(slot) {
        Ok(Occupancy::Free) => Erased::Gone { registrations: done },
        Ok(Occupancy::Mine) => Erased::NotGone(format!(
            "This device wrote the erase for \"{name}\" and wallet slot {slot} still reads \
             as holding a wallet. Do not treat those recovery words as destroyed."
        )),
        Ok(Occupancy::Opaque) => Erased::NotGone(format!(
            "This device wrote the erase for \"{name}\" and wallet slot {slot} still holds a \
             record it cannot open. Do not treat those recovery words as destroyed."
        )),
        Err(e) => Erased::NotGone(format!(
            "This device wrote the erase for \"{name}\" and could not read wallet slot \
             {slot} back afterwards ({e}), so it cannot say the words are gone."
        )),
    }
}
