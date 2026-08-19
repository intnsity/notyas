// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Replacing one registry record with another, without a window in which the device holds
//! neither.
//!
//! # Why this is not simply a write followed by an erase
//!
//! The obvious safe order - write the replacement, then erase what it replaced - is not
//! available here, and the reasons are properties of the layers below rather than a
//! preference:
//!
//! - `Wallet::register` is the only write path to the registry, and it refuses
//!   `AlreadyRegistered` when the wallet already holds a registration with the incoming
//!   id. A replacement has, by construction, the SAME content-derived id as the record it
//!   replaces - that is how the duplicate was found in the first place - so a write-first
//!   attempt cannot even reach the store.
//! - The registry is a fixed, small number of slots. Write-first needs a spare one, so a
//!   replace on a full registry would refuse for want of a slot on a device that is about
//!   to have one. A full registry is precisely the case a replace exists to serve.
//! - `Store` publishes no transaction and no multi-slot atomic write. `write_registry` and
//!   `clear_registry` each act on one slot; there is no primitive to build write-then-erase
//!   on top of.
//!
//! So the order stays erase-then-write, and the missing safety is supplied here instead: the
//! record is READ OUT before it is erased, and put back if the write that was supposed to
//! succeed it does not. What that turns a failed replacement into is a refusal plus an
//! unchanged device, rather than a device that has lost both the old registration and the
//! new one - which for a multisig wallet is the difference between one it can sign for and
//! one it cannot.
//!
//! # The window that remains, stated plainly
//!
//! A power cut between the erase and the write still loses the record: no rollback can run
//! if the CPU stops. That window is not closable from this layer and is not pretended away
//! - it is why a registration is a PUBLIC record that the coordinator can re-issue, and why
//! [`Replaced::Lost`] exists as an outcome a screen must state out loud rather than as a
//! case that falls through to a generic write failure.
//!
//! # Why a trait
//!
//! The ordering above is the whole content of this module, and it is exactly the part that
//! cannot be tested on a host against a real `Store` - an ESP-IDF flash partition. Behind
//! [`RegistrySlots`] the same code runs against the device and against a registry that can
//! be made to fail on demand, so the rollback path is covered by a test that runs in CI
//! rather than by review alone (firmware/hostcheck).

/// The four registry operations a replacement needs, and nothing else.
///
/// Deliberately narrow: an implementation that could do more would invite a second ordering
/// decision at the call site, and the point of this module is that there is only one.
pub trait RegistrySlots {
    /// What a successful install is called. `RegistrationId` on the device.
    type Id;
    /// What any of these can fail with. `RegisterError` on the device.
    type Error;

    /// The bytes registry slot `slot` currently holds, as they would have to be written
    /// back to restore it.
    fn snapshot(&mut self, slot: u8) -> Result<Vec<u8>, Self::Error>;

    /// Erase slot `slot`, dropping the registration it held from the open wallet too.
    fn erase(&mut self, slot: u8) -> Result<(), Self::Error>;

    /// Write the reviewed registration into whatever free slot the store picks.
    fn install(&mut self) -> Result<Self::Id, Self::Error>;

    /// Put `bytes` back into slot `slot`. The rollback, and the only reason [`snapshot`]
    /// exists.
    ///
    /// [`snapshot`]: RegistrySlots::snapshot
    fn restore(&mut self, slot: u8, bytes: &[u8]) -> Result<(), Self::Error>;
}

/// What became of a replacement, in terms of what the DEVICE now holds.
///
/// Four outcomes rather than `Result`, because "it failed" is three different situations
/// for the owner of the wallet and only one of them is recoverable by tapping again.
#[derive(Debug)]
pub enum Replaced<Id, E> {
    /// The replacement is in the registry and the record it replaced is gone.
    Done(Id),

    /// Refused before anything was erased. The device is exactly as it was, and the same
    /// approval can be retried once the cause is dealt with.
    Untouched(E),

    /// The install failed and the old record was written back to its slot.
    ///
    /// Storage is intact. The OPEN wallet is not: `erase` dropped the in-memory
    /// registration along with the record, and nothing outside a fresh unlock puts it back,
    /// so the caller must say so instead of implying the wallet is usable.
    RolledBack { slot: u8, cause: E },

    /// The install failed and the old record could not be written back.
    ///
    /// This is the one real loss, and it is reported as one. The registration has to be
    /// imported again from the coordinator that issued it.
    Lost { slot: u8, cause: E, restore: E },
}

/// Replace the registration in `slot` with the one `reg` is holding, or leave the device no
/// worse than it was.
///
/// The snapshot is taken FIRST and a snapshot that fails aborts the whole thing: this will
/// not erase a record it has no copy of. That single ordering rule is what makes every
/// failure below recoverable except the one that says it is not.
pub fn replace_in_slot<R: RegistrySlots>(reg: &mut R, slot: u8) -> Replaced<R::Id, R::Error> {
    let saved = match reg.snapshot(slot) {
        Ok(bytes) => bytes,
        Err(e) => return Replaced::Untouched(e),
    };
    if let Err(e) = reg.erase(slot) {
        return Replaced::Untouched(e);
    }
    match reg.install() {
        Ok(id) => Replaced::Done(id),
        Err(cause) => match reg.restore(slot, &saved) {
            Ok(()) => Replaced::RolledBack { slot, cause },
            Err(restore) => Replaced::Lost { slot, cause, restore },
        },
    }
}
