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
use notyas_wallet::{
    Config, KdfParams, KeyProvenance, Layout, Liveness, Occupancy, Pin, PolicyRequest, Session,
    SlotClass, SlotId, StoreState, UnlockError, Vault,
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
    pub free_psram_before: usize,
    pub free_psram_after: usize,
    pub scratch_bytes: usize,
    pub records_base: u32,
    pub ledger_base: u32,
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
    scratch: PsramScratch,
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
    /// Find the partitions, read the key state, take the working set, and mount.
    ///
    /// Call AFTER display bring-up: the free-PSRAM numbers in the report are only
    /// meaningful with the framebuffers already standing, and proving the working set
    /// fits alongside them is the whole question m4a asks of the heap.
    pub fn bring_up() -> Result<Store, BringUpError> {
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

        let free_psram_before = free_psram();
        let scratch = PsramScratch::allocate(&CONFIG.kdf).map_err(BringUpError::Scratch)?;
        let free_psram_after = free_psram();
        let scratch_bytes = scratch.bytes();

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
            free_psram_before,
            free_psram_after,
            scratch_bytes,
            records_base,
            ledger_base,
        };
        Ok(Store {
            vault,
            scratch,
            session: None,
            report,
            last_tick: Instant::now(),
        })
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
                log::info!("store: boot counter advanced to {n}");
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

    /// Install the first PIN. Returns the measured milliseconds on success.
    pub fn format(&mut self, pin: &Pin, label: &[u8]) -> Result<u128, String> {
        let t0 = Instant::now();
        let session = self
            .vault
            .format(pin, label, self.scratch.borrow())
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
    pub fn unlock(&mut self, pin: &Pin) -> Result<u128, UnlockError<FlashError, MacError>> {
        let t0 = Instant::now();
        let session = self.vault.unlock(pin, self.scratch.borrow())?;
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
        match self.session.as_ref()?.liveness() {
            Liveness::Live { idle_ms } => Some(AUTO_LOCK_MS.saturating_sub(idle_ms)),
            Liveness::Expired => Some(0),
        }
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

    /// Re-seal every record of the open identity under a new PIN.
    pub fn change_pin(&mut self, new_pin: &Pin) -> Result<u128, String> {
        let session = self.session.take().ok_or("locked")?;
        let t0 = Instant::now();
        match self.vault.change_pin(session, new_pin, self.scratch.borrow()) {
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

    /// The mounted vault, for the paths that need the whole surface (the HIL console).
    /// Deliberately not public to the UI: every operation the product performs has a
    /// named method above, so a new screen cannot reach past the session discipline.
    #[cfg(feature = "hil-console")]
    pub fn vault_mut(&mut self) -> &mut Vault<PartitionFlash, DeviceHmac> {
        &mut self.vault
    }

    #[cfg(feature = "hil-console")]
    pub fn scratch_mut(&mut self) -> &mut PsramScratch {
        &mut self.scratch
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
