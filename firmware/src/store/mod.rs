// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The sealed store, as this device actually has it: two `esp_partition` regions, a
//! device-binding MAC, a PSRAM Argon2id working set, and the one session that outlives a
//! single call.
//!
//! `notyas_wallet` is the whole of the sealing logic and none of it lives here. This
//! module is the board's answer to the three questions that crate deliberately refuses to
//! answer for itself - where the flash is, where the key is, and where 16 MiB of scratch
//! comes from - plus the session lifetime, which is a product decision (how long is too
//! long to leave a wallet open?) and not a storage one.
//!
//! # The one thing to understand before changing anything here
//!
//! Everything below the `Vault` is a pure function of `(flash bytes, MAC responses,
//! caller inputs)`. That is what let a host fuzzer prove 71,910 power-loss cases with no
//! silicon at all. This module is the part that is NOT covered by that proof: if a flash
//! write here is not what the engine asked for, or the MAC is not deterministic, or the
//! scratch is aliased, then the proof is about a device that does not exist. The
//! known-answer test in `src/hil.rs` is the bridge - it re-runs the published host vector
//! on this driver and compares the resulting flash image byte for byte.

mod flash;
mod mac;
mod scratch;

use std::time::Instant;

use esp_idf_svc::sys;
use notyas_ui::StoreStatus;
use notyas_wallet::{
    Config, KdfParams, KeyProvenance, Layout, Liveness, Occupancy, Pin, PolicyRequest, Session,
    SlotClass, SlotId, SlotState, StoreState, UnlockError, Vault,
};

pub use flash::{FlashError, OpenError, PartitionFlash};
pub use mac::{DeviceHmac, MacError};
pub use scratch::{PsramScratch, ScratchError};

#[cfg(feature = "hil-console")]
pub use mac::{soft_hmac, FixedKeyMac};
#[cfg(feature = "hil-console")]
pub use flash::SECTOR_BYTES;

/// The store as this firmware configures it.
///
/// `accept_provenance` is the only field that differs between a product image and a
/// development one, and it differs by cargo feature rather than by a runtime check:
/// ESP-SEAL.md 6.4 fence 4. A product build that somehow acquired an emulated backend
/// fails at `mount()` instead of sealing anything.
pub const CONFIG: Config = Config {
    // Distinct from the KAT vectors' tag on purpose: the domain tag separates two
    // products sharing one silicon key, and a device store must not share a derivation
    // domain with a published test vector.
    domain_tag: *b"notyas-wallet-v1",
    kdf: KdfParams::PINNED,
    layout: Layout::V1,
    format_policy: PolicyRequest {
        wipe_after: 15,
        min_pin_len: 4,
    },
    occupancy: Occupancy::AlwaysFilled,
    #[cfg(feature = "unsafe-emulated-key")]
    accept_provenance: &[KeyProvenance::EfuseReadProtected, KeyProvenance::Emulated],
    #[cfg(not(feature = "unsafe-emulated-key"))]
    accept_provenance: &[KeyProvenance::EfuseReadProtected],
    // PIN-MODES.md / ratified Q62(b): no PIN-length floor for disabling the wipe. The
    // warning states the concrete guess count instead of withholding the setting.
    disable_wipe_min_pin_len: None,
};

/// The layout as a borrow, so the const geometry helpers below can be `const fn`.
/// `&CONFIG.layout` is not writable inside a `const fn` body; a const item is.
const LAYOUT: &Layout = &CONFIG.layout;

/// Idle timeout before the session is dropped and the device relocks.
///
/// Two minutes is `notyas_wallet::DEFAULT_AUTO_LOCK_MS`, restated here because it is a
/// product decision this file owns and a library default is not an argument for it.
pub const AUTO_LOCK_MS: u32 = 120_000;

/// Everything the boot log and the Verify screen need to know about the storage stack,
/// captured once at bring-up so that no screen ever re-reads the flash to render itself.
#[derive(Clone, Debug)]
pub struct StoreReport {
    /// One line, already worded for a human. Never a constant - see `DeviceHmac::label`.
    pub provenance: &'static str,
    pub state: StoreState,
    /// `None` until the ledger's auxiliary sector exists; the Verify row then renders
    /// `not counted` rather than `0` (VERIFY.md 6 / R24: a convenience row does not get
    /// to falsify the stateless property of a device that has stored nothing).
    pub boot_count: Option<u64>,
    /// The boot index the owner last marked as seen. `None` renders `not acknowledged`.
    pub acknowledged_at: Option<u64>,
    pub free_psram_before: usize,
    pub free_psram_after: usize,
    pub scratch_bytes: usize,
    pub records_base: u32,
    pub ledger_base: u32,
}

/// Why an unlock attempt did not produce a session.
///
/// Distinguishes "the device cannot try" from "the device tried and the PIN was wrong",
/// because only the second consumes an attempt and only the second is the user's fault.
#[derive(Debug)]
pub enum UnlockFailure {
    /// The Argon2id working set was never allocated, so no guess was made and no attempt
    /// was consumed.
    NoScratch,
    Refused(UnlockError<FlashError, MacError>),
}

/// Why the storage stack could not be brought up at all. Distinct from a store that
/// mounted and reported `Unprovisioned` or `Inconsistent`: those are states, these are
/// the device failing to have the parts.
#[derive(Clone, Copy, Debug)]
pub enum BringUpError {
    Partitions(OpenError),
    Scratch(ScratchError),
    /// `Vault::mount` refused. Rendered by its own Debug; the variants that matter to a
    /// user (unprovisioned, tampered) are states rather than errors, so anything here is
    /// a hardware fault or a firmware/flash mismatch.
    Mount(&'static str),
}

/// The device's store, plus the session it may or may not be holding.
pub struct Store {
    vault: Vault<PartitionFlash, DeviceHmac>,
    /// The Argon2id working set. `None` between [`Store::mount`] and
    /// [`Store::attach_scratch`], which is the window the boot counter is written in:
    /// counting a boot needs the ledger and nothing else, and the ratified Q61(i) puts
    /// that write before the self-test, which is before the panel exists to allocate
    /// framebuffers against.
    scratch: Option<PsramScratch>,
    session: Option<Session>,
    report: StoreReport,
    /// Wall clock of the last `tick`, so the auto-lock counts real elapsed milliseconds
    /// rather than main-loop passes. A pass that took 900 ms because it ran an Argon2id
    /// derivation must age the session by 900 ms, not by one poll interval.
    last_tick: Instant,
}

impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Store")
            .field("state", &self.report.state)
            .field("unlocked", &self.session.is_some())
            .finish()
    }
}

impl Store {
    /// Find the partitions, read the key state, and mount. Allocates nothing.
    ///
    /// Call FIRST, before the boot self-test: the boot counter has to advance before any
    /// check that can abort the boot, or a failure becomes a free way to power the device
    /// on without being counted (ratified Q61(i)). Mounting reads flash and derives the
    /// device keys; it takes no heap, so it can run before the panel exists.
    ///
    /// The Argon2id working set is deliberately NOT taken here - see
    /// [`Store::attach_scratch`].
    pub fn mount() -> Result<Store, BringUpError> {
        let layout = CONFIG.layout;
        let flash = PartitionFlash::open(
            layout.records_bytes(),
            layout.ledger_sectors * layout.sector_size,
        )
        .map_err(BringUpError::Partitions)?;
        let records_base = flash.base(notyas_wallet::Region::Records);
        let ledger_base = flash.base(notyas_wallet::Region::Ledger);

        let mac = DeviceHmac::detect();
        let provenance = mac.label();

        let vault = Vault::mount(flash, mac, &CONFIG).map_err(|e| {
            // The mount error types are generic over both backends' error types, which
            // makes them awkward to carry; the log line above the call site has already
            // printed the full Debug, so the caller only needs the class.
            log::error!("store: mount refused: {e:?}");
            BringUpError::Mount("Vault::mount refused - see the line above")
        })?;

        let state = vault.state();
        let report = StoreReport {
            provenance,
            state,
            boot_count: None,
            acknowledged_at: None,
            free_psram_before: 0,
            free_psram_after: 0,
            scratch_bytes: 0,
            records_base,
            ledger_base,
        };
        Ok(Store {
            vault,
            scratch: None,
            session: None,
            report,
            last_tick: Instant::now(),
        })
    }

    /// Take the Argon2id working set.
    ///
    /// Call AFTER display bring-up, and in that order for a reason the boot log then
    /// prints as arithmetic: the free-PSRAM numbers are only meaningful with the
    /// framebuffers already standing, and proving the working set fits ALONGSIDE them is
    /// the whole question m4a asks of the heap. Splitting the mount from this allocation
    /// is what lets the boot counter run early without moving that allocation earlier
    /// too, which would have changed the answer to that question.
    ///
    /// Without it the device still boots and still counts, and every PIN operation
    /// refuses with `no Argon2 working set` rather than the device pretending to work.
    pub fn attach_scratch(&mut self) -> Result<(), BringUpError> {
        let free_psram_before = free_psram();
        let scratch = PsramScratch::allocate(&CONFIG.kdf).map_err(BringUpError::Scratch)?;
        self.report.free_psram_before = free_psram_before;
        self.report.free_psram_after = free_psram();
        self.report.scratch_bytes = scratch.bytes();
        self.scratch = Some(scratch);
        Ok(())
    }


    pub fn report(&self) -> &StoreReport {
        &self.report
    }

    pub fn state(&self) -> StoreState {
        self.vault.state()
    }

    pub fn is_unlocked(&self) -> bool {
        self.session.is_some()
    }

    /// Attempts left before the wipe, or `None` when the wipe is disabled.
    pub fn attempts_remaining(&self) -> Option<u8> {
        self.vault.attempts_remaining()
    }

    pub fn failures(&self) -> u32 {
        self.vault.failures()
    }

    /// The wipe threshold in force, or `None` when the wipe is off. Always shown on the
    /// screens that name it (Q37): it tells the user the consequence of their next
    /// mistake and leaks nothing a coercer cannot get by trying one wrong PIN.
    pub fn wipe_after(&self) -> Option<u8> {
        let n = self.vault.policy().wipe_after;
        if n == 0 {
            None
        } else {
            Some(n)
        }
    }

    /// The shortest PIN this store will accept, from the policy its format was written
    /// with.
    ///
    /// Read rather than assumed, and handed to the UI, because the UI is what decides
    /// whether Unlock is pressable: 0.2.0 shipped a screen carrying its own literal floor
    /// of 6 against a store formatted at 4, so a provisioned device could type its whole
    /// PIN and never enable the button. The store owns the number; every other layer asks.
    pub fn min_pin_len(&self) -> u8 {
        self.vault.policy().min_pin_len
    }

    /// Count this boot in the ledger, BEFORE the self-test runs its verdict past the
    /// user (VERIFY.md 6, ratified Q61): a boot that ends on the failure screen is still
    /// a boot, and a failed self-test must not be a free way to avoid advancing the
    /// counter that exists to reveal unattended power-ups.
    ///
    /// Writes NOTHING while the store is `Unprovisioned`, `Blank` or `Wiped`. That is
    /// SECURITY invariant 2a, not an optimisation: a device that has never stored a
    /// wallet keeps the 0.1.0 stateless property verbatim, and a convenience row does not
    /// get to falsify it (R24). The Verify row then renders `not counted`, never `0`.
    pub fn record_boot(&mut self) {
        if !matches!(self.vault.state(), StoreState::Formatted { .. }) {
            self.report.boot_count = None;
            return;
        }
        match self.vault.record_boot() {
            Ok(n) => {
                self.report.boot_count = Some(n);
                self.report.acknowledged_at = self.vault.acknowledged_at();
                log::info!(
                    "store: boot counter advanced to {n} (acknowledged at {:?})",
                    self.report.acknowledged_at
                );
            }
            Err(e) => {
                // Surfaced, never swallowed. The counter failing is not a reason to
                // refuse the device, but it IS a reason the Verify row must not claim a
                // number: a stale count is worse than an absent one.
                self.report.boot_count = None;
                log::error!("store: boot counter did not advance: {e:?}");
            }
        }
    }

    /// Write the boot-counter acknowledgement mark (VERIFY.md 6.3).
    ///
    /// Post-PIN only, and the check is here rather than only on the screen: a coercer who
    /// can press the button erases the very gap the counter exists to show, so the write
    /// is gated on a session existing and not on which screen asked.
    pub fn acknowledge_boots(&mut self) -> Result<u64, String> {
        if self.session.is_none() {
            return Err(String::from("locked"));
        }
        let at = self.vault.acknowledge_boots().map_err(|e| format!("{e:?}"))?;
        self.report.acknowledged_at = Some(at);
        log::info!("store: boots acknowledged at {at}");
        Ok(at)
    }

    /// The two anti-phishing words for a typed PIN prefix, as words.
    ///
    /// The derivation is `notyas-wallet`'s (device-bound, host-tested); the wordlist
    /// lookup is here because the list lives in `notyas-core` and the sealing crate does
    /// not depend on it. Costs no attempt-counter decrement, and answers for ANY prefix:
    /// refusing an unreal one would turn the words into an oracle for prefix correctness.
    pub fn anti_phishing_words(&mut self, prefix: &str) -> Result<[String; 2], String> {
        let idx = self
            .vault
            .anti_phishing_words(prefix.as_bytes())
            .map_err(|e| format!("{e:?}"))?;
        let list = notyas_core::bip39::wordlist();
        let word = |i: u16| {
            list.get(i as usize).copied().map(String::from).ok_or("word index out of range")
        };
        Ok([word(idx[0])?, word(idx[1])?])
    }

    /// What the lock and PIN screens are allowed to know about this store.
    ///
    /// The mapping is one-way and lossy on purpose: `StoreStatus` cannot express a wallet
    /// COUNT, so no pre-PIN surface can render one (ratified Q2(a)).
    pub fn ui_status(&self) -> StoreStatus {
        match self.vault.state() {
            StoreState::Unprovisioned => StoreStatus::NotProvisioned,
            StoreState::Blank | StoreState::Wiped { .. } => StoreStatus::Blank,
            StoreState::Inconsistent(_) => StoreStatus::Unreadable,
            StoreState::Formatted { .. } if self.session.is_some() => StoreStatus::Unlocked,
            StoreState::Formatted { .. } => StoreStatus::Locked,
        }
    }

    /// Install the first PIN. Returns the measured milliseconds on success.
    pub fn format(&mut self, pin: &Pin, label: &[u8]) -> Result<u128, String> {
        let t0 = Instant::now();
        let scratch = self.scratch.as_mut().ok_or("no Argon2 working set")?.borrow();
        let session = self
            .vault
            .format(pin, label, scratch)
            .map_err(|e| format!("{e:?}"))?;
        let ms = t0.elapsed().as_millis();
        self.adopt(session);
        self.report.state = self.vault.state();
        Ok(ms)
    }

    /// Consume one attempt. On success the session is adopted and the auto-lock starts.
    ///
    /// Returns the measured milliseconds, which is the number m4a's exit gate asks for:
    /// the whole cost a user waits through between the last digit and an open device.
    pub fn unlock(&mut self, pin: &Pin) -> Result<u128, UnlockFailure> {
        let t0 = Instant::now();
        let scratch = self.scratch.as_mut().ok_or(UnlockFailure::NoScratch)?.borrow();
        let session = self.vault.unlock(pin, scratch).map_err(UnlockFailure::Refused)?;
        let ms = t0.elapsed().as_millis();
        self.adopt(session);
        Ok(ms)
    }

    fn adopt(&mut self, session: Session) {
        let mut session = session;
        session.set_auto_lock_ms(AUTO_LOCK_MS);
        self.session = Some(session);
        self.last_tick = Instant::now();
    }

    /// Drop the session. `Session::Drop` is the wipe point, so this IS the lock.
    pub fn lock(&mut self) -> bool {
        self.session.take().is_some()
    }

    /// User activity: restart the idle timer.
    pub fn touch(&mut self) {
        if let Some(s) = self.session.as_mut() {
            s.touch();
        }
    }

    /// Age the session by the real elapsed time and lock it if it expired.
    ///
    /// Returns `true` exactly on the pass that locked, so the caller can repaint and log
    /// once rather than every pass thereafter. Called unconditionally from the main loop;
    /// a no-op with no session, which is the common case.
    pub fn tick(&mut self) -> bool {
        let elapsed = self.last_tick.elapsed().as_millis();
        self.last_tick = Instant::now();
        let Some(s) = self.session.as_mut() else {
            return false;
        };
        let elapsed = u32::try_from(elapsed).unwrap_or(u32::MAX);
        if matches!(s.tick(elapsed), Liveness::Expired) {
            self.session = None;
            log::info!("store: auto-lock after {AUTO_LOCK_MS} ms idle - session dropped");
            return true;
        }
        false
    }

    /// Milliseconds of idle time left before the auto-lock fires, for the UI.
    pub fn idle_remaining_ms(&self) -> Option<u32> {
        Some(self.session.as_ref()?.remaining_ms())
    }

    /// Seal `plaintext` into payload slot `index`. Requires an open session.
    pub fn write_payload(&mut self, index: u8, plaintext: &[u8]) -> Result<(), String> {
        let slot = self.payload_slot(index)?;
        let session = self.session.as_ref().ok_or("locked")?;
        self.vault
            .write(session, slot, plaintext)
            .map_err(|e| format!("{e:?}"))
    }

    /// Read payload slot `index` back. Requires an open session.
    pub fn read_payload(&mut self, index: u8, out: &mut [u8]) -> Result<usize, String> {
        let slot = self.payload_slot(index)?;
        let session = self.session.as_ref().ok_or("locked")?;
        self.vault
            .read(session, slot, out)
            .map_err(|e| format!("{e:?}"))
    }

    fn payload_slot(&self, index: u8) -> Result<SlotId, String> {
        SlotId::new(SlotClass::Payload, index, &CONFIG.layout)
            .ok_or_else(|| format!("no payload slot {index}"))
    }

    // -----------------------------------------------------------------------
    // The registry class (0.2.0-m7)
    //
    // A multisig registration is a PUBLIC record - cosigner xpubs, a threshold and a name,
    // no key material - and it gets its own slot class rather than a field inside a
    // wallet's body for the reason ESP-SEAL.md 3.2 gave it one: the classes are sized
    // separately (two sectors a side here, one for a payload), and the AEAD's associated
    // data binds `slot_class`, so a registry record cannot be replayed into a payload slot
    // or the other way round. It is sealed all the same, because the set of wallets a
    // device is a member of is exactly the metadata a flash dump should not yield.
    //
    // These four methods are `write_payload`/`read_payload` for that class and nothing
    // more: what the bytes mean is `crate::wallet::record`'s business, and this file stays
    // the board's answer to where the flash is.
    // -----------------------------------------------------------------------

    /// Seal `plaintext` into registry slot `index`. Requires an open session.
    pub fn write_registry(&mut self, index: u8, plaintext: &[u8]) -> Result<(), String> {
        let slot = self.registry_slot(index)?;
        let session = self.session.as_ref().ok_or("locked")?;
        self.vault
            .write(session, slot, plaintext)
            .map_err(|e| format!("{e:?}"))
    }

    /// Read registry slot `index` back. Requires an open session.
    pub fn read_registry(&mut self, index: u8, out: &mut [u8]) -> Result<usize, String> {
        let slot = self.registry_slot(index)?;
        let session = self.session.as_ref().ok_or("locked")?;
        self.vault
            .read(session, slot, out)
            .map_err(|e| format!("{e:?}"))
    }

    /// Erase registry slot `index`. Requires an open session.
    ///
    /// A registration is a PUBLIC record that the user can import again from the
    /// coordinator that issued it, so erasing one costs a re-import. Its payload-class
    /// twin is [`Store::clear_payload`], which is the same `Vault::clear` over the class
    /// that holds the only copy of somebody's words - and which is behind a two-sheet
    /// typed-name consent plus the last-words step for exactly that reason.
    ///
    /// `Vault::clear` is what performs it, and under `Occupancy::AlwaysFilled` it REWRITES
    /// the slot with device-derived filler rather than erasing it: leaving an erased-flash
    /// signature where a registration used to be is the occupancy leak that mode exists to
    /// close.
    pub fn clear_registry(&mut self, index: u8) -> Result<(), String> {
        let slot = self.registry_slot(index)?;
        let session = self.session.as_ref().ok_or("locked")?;
        self.vault
            .clear(session, slot)
            .map_err(|e| format!("{e:?}"))
    }

    /// Erase payload slot `index`. Requires an open session.
    ///
    /// # No empty record is written, and none ever was going to be
    ///
    /// The objection this route had to answer is a real one: a record encoder that emitted
    /// an EMPTY body into the slot would leave bytes that read as occupied and decode as
    /// nothing - a corrupted wallet wearing a delete's clothes. Nothing here does that.
    /// `Vault::clear` under [`Occupancy::AlwaysFilled`] writes device FILLER, sealed under
    /// the key ladder's `filler_root` rather than under this session's PIN-derived key, and
    /// `Vault::slot_state` tries `filler_root` FIRST and answers [`SlotState::Empty`] when
    /// it opens. So the slot reads as free to every caller, no wallet-record encoder is
    /// invoked, and no half-record exists at any instant.
    ///
    /// # Why filler and not an erase
    ///
    /// Ratified Q2: `AlwaysFilled` is this product's permanent, only storage mode. Erasing
    /// a payload slot back to 0xff would leave exactly the occupancy tell that mode exists
    /// to close - a flash dump would say how many wallets a device holds. A delete
    /// therefore REWRITES. `Vault::clear`'s `Sparse` arm is unreachable here and must stay
    /// so; the constant above is the only thing that decides it.
    ///
    /// # What a power cut does
    ///
    /// What a seal does, because this IS a seal. The commit point is the 16-byte header MAC
    /// of the filler side, programmed last: before it, the old record is still elected and
    /// the wallet is still there to delete again; after it, the filler wins the max-seq
    /// election on every boot forever, and `mount`'s cleanup finishes the stale-side erase
    /// if the cut landed inside it. There is no third outcome and no torn state. The one
    /// thing it does not promise is instantaneous physical destruction: between the commit
    /// and the stale-side erase the previous ciphertext is still on the flash, still sealed
    /// under the user's PIN. `crates/notyas-wallet/src/fuzz.rs`'s `Op::Clear` cuts this
    /// operation at every step boundary, over a slot holding a real record.
    ///
    /// # The read-back is the caller's
    ///
    /// This returns what the store returned and claims nothing beyond it. Whether the slot
    /// is actually free afterwards is a question with an answer on the flash, and
    /// `crate::wallet::erase` asks it rather than assuming this call implies it.
    pub fn clear_payload(&mut self, index: u8) -> Result<(), String> {
        let slot = self.payload_slot(index)?;
        let session = self.session.as_ref().ok_or("locked")?;
        self.vault
            .clear(session, slot)
            .map_err(|e| format!("{e:?}"))
    }

    /// What payload slot `index` holds, as seen by this session's key.
    ///
    /// `Empty` covers both erased flash and the device-derived filler this store writes
    /// under `Occupancy::AlwaysFilled`, which is what makes a caller able to ask "is this
    /// slot free" without the answer leaking occupancy to anyone who has not proved a PIN.
    pub fn payload_state(&mut self, index: u8) -> Result<SlotState, String> {
        let slot = self.payload_slot(index)?;
        let session = self.session.as_ref().ok_or("locked")?;
        self.vault
            .slot_state(session, slot)
            .map_err(|e| format!("{e:?}"))
    }

    /// What registry slot `index` holds, as seen by this session's key.
    pub fn registry_state(&mut self, index: u8) -> Result<SlotState, String> {
        let slot = self.registry_slot(index)?;
        let session = self.session.as_ref().ok_or("locked")?;
        self.vault
            .slot_state(session, slot)
            .map_err(|e| format!("{e:?}"))
    }

    fn registry_slot(&self, index: u8) -> Result<SlotId, String> {
        SlotId::new(SlotClass::Registry, index, &CONFIG.layout)
            .ok_or_else(|| format!("no registry slot {index}"))
    }

    /// Payload slots this layout provides: how many wallets the device can hold.
    pub const fn payload_slots() -> u8 {
        LAYOUT.payload_slots
    }

    /// Registry slots this layout provides: how many multisig wallets can be registered.
    pub const fn registry_slots() -> u8 {
        LAYOUT.registry_slots
    }

    /// Largest record body a payload slot takes, side minus header, AEAD tag and length
    /// prefix. The record encoder checks against this before anything is written, so a
    /// wallet that will not fit is refused with a sentence about the record rather than
    /// with `StorageError::Capacity`.
    pub const fn max_payload_bytes() -> usize {
        SlotClass::Payload.max_payload(LAYOUT) as usize
    }

    /// The same for a registry slot, which is two sectors a side.
    pub const fn max_registry_bytes() -> usize {
        SlotClass::Registry.max_payload(LAYOUT) as usize
    }

    /// Re-seal every record of the open identity under a new PIN.
    pub fn change_pin(&mut self, new_pin: &Pin) -> Result<u128, String> {
        let session = self.session.take().ok_or("locked")?;
        let t0 = Instant::now();
        let Some(scratch) = self.scratch.as_mut().map(PsramScratch::borrow) else {
            return Err(String::from("no Argon2 working set"));
        };
        match self.vault.change_pin(session, new_pin, scratch) {
            Ok(s) => {
                let ms = t0.elapsed().as_millis();
                self.adopt(s);
                Ok(ms)
            }
            Err(e) => Err(format!(
                "{:?} (old PIN still valid: {})",
                e.source, e.old_pin_still_valid
            )),
        }
    }

    /// Set the wrong-PIN wipe policy. Re-seals the store under the given PIN, so the
    /// PIN is confirmed inside the AEAD (PIN-MODES.md). The session is borrowed, not
    /// consumed: `set_policy` returns a Policy, not a Session.
    pub fn set_policy(&mut self, pin: &Pin, wipe_after: u8) -> Result<notyas_wallet::config::Policy, String> {
        let min_pin = self.min_pin_len();
        let session = self.session.take().ok_or("locked")?;
        let Some(scratch) = self.scratch.as_mut().map(PsramScratch::borrow) else {
            self.adopt(session);
            return Err(String::from("no Argon2 working set"));
        };
        let request = notyas_wallet::config::PolicyRequest { wipe_after, min_pin_len: min_pin };
        match self.vault.set_policy(&session, request, pin, scratch) {
            Ok(policy) => {
                self.adopt(session);
                Ok(policy)
            }
            Err(e) => {
                self.adopt(session);
                Err(format!("{e:?}"))
            }
        }
    }

    /// Destroy every sealed record and leave the store unformatted (Q5.5). The PIN is
    /// confirmed inside the AEAD before the wipe. Returns the count of what was destroyed.
    pub fn remove_pin(&mut self, pin: &Pin) -> Result<notyas_wallet::Destroyed, String> {
        let session = self.session.take().ok_or("locked")?;
        let Some(scratch) = self.scratch.as_mut().map(PsramScratch::borrow) else {
            self.adopt(session);
            return Err(String::from("no Argon2 working set"));
        };
        match self.vault.remove_pin(&session, pin, scratch) {
            Ok(destroyed) => {
                // No session to adopt: the store is now unformatted.
                self.session = None;
                Ok(destroyed)
            }
            Err(e) => {
                self.adopt(session);
                Err(format!("{e:?}"))
            }
        }
    }


    /// The mounted vault, for the paths that need the whole surface (the HIL console).
    /// Deliberately not public to the UI: every operation the product performs has a
    /// named method above, so a new screen cannot reach past the session discipline.
    #[cfg(feature = "hil-console")]
    pub fn vault_mut(&mut self) -> &mut Vault<PartitionFlash, DeviceHmac> {
        &mut self.vault
    }

    #[cfg(feature = "hil-console")]
    pub fn scratch_mut(&mut self) -> Option<&mut PsramScratch> {
        self.scratch.as_mut()
    }

    #[cfg(feature = "hil-console")]
    pub fn session_ref(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// Re-run the whole mount sequence, adopting whatever the flash now says. Used after
    /// an operation the console performed out of band; the product path never needs it,
    /// because every `Vault` method already keeps its own view in step.
    #[cfg(feature = "hil-console")]
    pub fn refresh_report(&mut self) {
        self.report.state = self.vault.state();
    }
}

/// Free PSRAM right now. Reported before and after the working-set allocation so the
/// heap claim in the boot log is arithmetic a reader can check, not an adjective.
pub fn free_psram() -> usize {
    // SAFETY: a read-only heap query.
    unsafe { sys::heap_caps_get_free_size(sys::MALLOC_CAP_SPIRAM) }
}

/// Free internal RAM right now.
pub fn free_internal() -> usize {
    // SAFETY: a read-only heap query.
    unsafe { sys::heap_caps_get_free_size(sys::MALLOC_CAP_INTERNAL) }
}

/// Bytes of this task's stack that have never been used, i.e. the smallest headroom
/// since it started. ESP-IDF's port returns bytes, not words.
///
/// Reported rather than assumed because m4a found the previous value the hard way: the
/// key ladder overran the 20 KB main task by 108 bytes and the board took a stack
/// protection fault. A number that is printed every boot is a number that cannot drift
/// silently under a future change to the crypto stack.
pub fn stack_headroom() -> u32 {
    // SAFETY: a read-only FreeRTOS query; a null handle means "the calling task".
    unsafe { sys::uxTaskGetStackHighWaterMark(core::ptr::null_mut()) }
}

/// The configured main-task stack, from the sdkconfig the image was built with.
pub const MAIN_STACK_BYTES: u32 = sys::CONFIG_ESP_MAIN_TASK_STACK_SIZE;

/// One-line rendering of a [`StoreState`] for the boot log and the Verify screen.
///
/// Deliberately says "blank" and "not provisioned" as different things, and never
/// reports a wallet count for a store nobody has unlocked - the count of OCCUPIED slots
/// is available without a PIN (`Vault::occupancy`) but naming it here would put it on
/// every boot log, and a duress-capable product must not.
pub fn state_label(state: StoreState) -> String {
    match state {
        StoreState::Unprovisioned => "not provisioned".to_string(),
        StoreState::Blank => "blank (nothing has ever been sealed)".to_string(),
        StoreState::Formatted { identities_present, .. } => {
            format!("formatted, {identities_present} PIN identity/identities")
        }
        StoreState::Wiped { epoch } => format!("wiped (epoch {epoch})"),
        StoreState::Inconsistent(kind) => format!("INCONSISTENT: {kind:?}"),
    }
}
