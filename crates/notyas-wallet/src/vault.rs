// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The store: mount, format, unlock, seal, change-PIN, set-policy, wipe.
//!
//! Every operation in this module has exactly one commit point and the power-loss
//! behaviour of the whole operation is the behaviour of that one write. There are only
//! three shapes of commit in the entire design, and that is deliberate - one story,
//! re-used, is auditable in a way that six stories are not:
//!
//! | Operation | Commit point |
//! |---|---|
//! | FORMAT, SEAL, superblock rewrite | the 16-byte `header_mac` write of one record side |
//! | WIPE | one 8-byte `epoch_log` cell |
//! | CHANGE-PIN | one 16-byte `pin_gen_log` cell |
//! | SET-POLICY | one 16-byte `policy_log` cell |
//! | LEDGER ROTATION | the 16-byte `head_mac` write of the target sector |
//!
//! Before the commit the operation has not happened; after it, it has. There is no third
//! outcome, because every one of those writes is a keyed MAC that either verifies or does
//! not, and every reader treats "does not verify" as "absent".
//!
//! ESP-SEAL.md sections 4.2 to 4.8 are normative; OPEN-QUESTIONS.md Q5.1-Q5.5 are
//! normative for the policy. Where an implementation choice had to be made that those
//! documents did not settle - or settled in a way that turned out to be unimplementable -
//! it is marked `DEVIATION` at the site with the reasoning.

use alloc::vec;
use zeroize::Zeroizing;

use crate::config::{Config, Occupancy, Policy, PolicyRequest, WIPE_AFTER_MAX, WIPE_AFTER_MIN};
use crate::crypto::{self, Bound, DeviceKeys};
use crate::error::{
    ChangePinError, Corruption, FormatError, HardwareFault, MountError, PolicyRefusal,
    StorageError, TamperFlags, TamperKind, UnlockError,
};
use crate::format::{Canary, LedgerHead, RecordHeader, Superblock, SEQ_LOG, SEQ_RESERVE};
use crate::hal::{DeviceMac, Flash, KeyProvenance, Region, Scratch};
use crate::ledger::{self, AuxState, LedgerState};
use crate::pin::Pin;
use crate::records::{self, Elected, SlotTable};
use crate::session::Session;
use crate::slot::{Identity, Side, SlotClass, SlotId, SlotMap, SlotState};

/// When the losing side of an A/B pair is erased.
///
/// For a single-record operation the answer is "immediately after the commit", and that
/// erase is what closes the window in which the previous ciphertext still exists. For a
/// BATCH it is not: a PIN change re-seals every record before its commit cell is
/// programmed, and erasing each old side as it goes would demolish the rollback path one
/// record at a time. The old PIN has to keep working right up to the commit, and by the
/// time the canary had been re-sealed there would be nothing left for it to open.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StaleSide {
    /// Erase as soon as the new side is verified. SEAL's S9.
    EraseNow,
    /// Leave it committed and let the operation's own commit point decide which side
    /// wins. CHANGE-PIN's C6 erases them all once, after C5.
    DeferToCommit,
}

/// Shorthand for the error every internal step produces.
type SErr<F, M> =
    StorageError<<F as Flash>::Error, <M as DeviceMac>::Error>;

/// What the store is, as reported without a PIN.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StoreState {
    /// The factory HMAC ceremony (ESP-SEAL.md 4.3) has not been run on this board, so
    /// there is no device key and nothing can be derived, sealed or even identified.
    /// Every operation refuses. Ratified Q45 requires this to be a real state rather than
    /// a generic hardware fault, because "your board was never provisioned" and "your
    /// board is broken" are different sentences to show a user.
    Unprovisioned,
    /// Nothing has ever been sealed. The device is behaviourally a 0.1.0 device.
    Blank,
    Formatted {
        identities_present: u8,
        occupied_slots: u8,
    },
    /// Every record has been destroyed and the one-way epoch bumped. There is no PIN, and
    /// `format` is the way out.
    Wiped { epoch: u64 },
    /// Structural evidence of interference. Refuses everything except `wipe` and a fresh
    /// `format`, and carries the kind for the product to display.
    Inconsistent(TamperKind),
}

/// What `remove_pin` destroyed, so the confirmation screen can name each item rather than
/// summarise (OPEN-QUESTIONS Q5.5).
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Destroyed {
    pub wallets: u8,
    pub registrations: u8,
    pub identities: u8,
    /// The epoch the wipe advanced to.
    pub epoch: u64,
}

/// The store.
///
/// Owns the two backends, the parsed ledger, the elected side of every slot, and the
/// sequence cursor. It holds no PIN-derived secret: that lives in a [`Session`], which the
/// caller holds and can drop.
pub struct Vault<F: Flash, M: DeviceMac> {
    flash: F,
    mac: M,
    cfg: Config,
    /// `None` only in [`StoreState::Unprovisioned`], where there is no device key to
    /// derive anything from. Every operation checks the state first, so the `None` case is
    /// unreachable below the guard rather than handled twice.
    keys: Option<DeviceKeys>,
    ledger: Option<LedgerState>,
    aux: Option<AuxState>,
    table: SlotTable,
    superblock: Option<Superblock>,
    next_seq: u64,
    state: StoreState,
    tamper: TamperFlags,
    policy: Policy,
}

impl<F: Flash, M: DeviceMac> core::fmt::Debug for Vault<F, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vault")
            .field("state", &self.state)
            .field("policy", &self.policy)
            .field("tamper", &self.tamper)
            .field("next_seq", &self.next_seq)
            .finish()
    }
}

/// Storage errors that reach the mount boundary become mount errors. Only a hardware
/// fault can legitimately get here; anything else is this crate misusing itself and says
/// so rather than pretending the flash was at fault.
fn as_mount<F: Flash, M: DeviceMac>(e: SErr<F, M>) -> MountError<F::Error, M::Error> {
    match e {
        StorageError::Hardware(h) => MountError::Hardware(h),
        StorageError::Invariant(m) => MountError::Invariant(m),
        _ => MountError::Invariant("unexpected storage error during mount"),
    }
}

impl<F: Flash, M: DeviceMac> Vault<F, M> {
    // -----------------------------------------------------------------------
    // MOUNT (ESP-SEAL.md 4.2)
    // -----------------------------------------------------------------------

    /// Read the ledger and every slot header, complete any interrupted operation, and
    /// elect the authoritative side of every slot. Requires no PIN.
    ///
    /// The only writes mount performs are idempotent erases of data that has already been
    /// superseded (M3 and M9), the wipe that M8 owes an over-limit store, and the policy
    /// mirror rewrite the ledger's authority demands. A cut anywhere re-runs harmlessly on
    /// the next boot.
    pub fn mount(flash: F, mac: M, cfg: &Config) -> Result<Vault<F, M>, MountError<F::Error, M::Error>> {
        cfg.validate().map_err(MountError::Config)?;
        let mut flash = flash;
        let mut mac = mac;
        let _ = &mut flash;

        let geo = flash.geometry();
        if geo.sector_size != cfg.layout.sector_size
            || geo.records_sectors < cfg.layout.records_sectors
            || geo.ledger_sectors < cfg.layout.ledger_sectors
            || geo.cipher_block == 0
            || geo.write_gran == 0
        {
            return Err(MountError::Geometry);
        }

        let provenance = mac.provenance();
        if provenance == KeyProvenance::Absent {
            // No key, so nothing below this point is derivable. Reported as a state rather
            // than an error so the product can show the Verify screen and the provisioning
            // instructions instead of a dead end.
            return Ok(Vault {
                flash,
                mac,
                cfg: *cfg,
                keys: None,
                ledger: None,
                aux: None,
                table: SlotTable::default(),
                superblock: None,
                next_seq: 0,
                state: StoreState::Unprovisioned,
                tamper: TamperFlags::NONE,
                policy: cfg.format_policy(),
            });
        }
        if !cfg.accept_provenance.contains(&provenance) {
            return Err(MountError::Provenance(provenance));
        }

        let keys = crypto::device_keys(&mut mac, &cfg.domain_tag)
            .map_err(|e| MountError::Hardware(HardwareFault::Mac(e)))?;

        let mut vault = Vault {
            flash,
            mac,
            cfg: *cfg,
            keys: Some(keys),
            ledger: None,
            aux: None,
            table: SlotTable::default(),
            superblock: None,
            next_seq: 0,
            state: StoreState::Blank,
            tamper: TamperFlags::NONE,
            policy: cfg.format_policy(),
        };
        vault.remount()?;
        Ok(vault)
    }

    /// Re-run the whole mount sequence against the current flash contents. Called by
    /// `mount` and again after any operation that changes the store's shape, so there is
    /// exactly one election implementation and a post-operation view can never diverge
    /// from what the next boot would see.
    fn remount(&mut self) -> Result<(), MountError<F::Error, M::Error>> {
        self.refresh().map_err(as_mount::<F, M>)?;
        // M8: an over-limit store is wiped before any unlock is possible. Deliberately
        // after the election, so the wipe sees the true failure count, and deliberately
        // before this function returns, so no caller can observe a mountable store that
        // owes a wipe.
        if self.wipe_is_due() {
            self.wipe_inner().map_err(as_mount::<F, M>)?;
            self.refresh().map_err(as_mount::<F, M>)?;
        }
        self.validate_superblock()?;
        self.cleanup().map_err(as_mount::<F, M>)?;
        self.sync_policy_mirror().map_err(as_mount::<F, M>)?;
        Ok(())
    }

    /// M1-M7 and M10: everything that decides what the store IS, with no writes except the
    /// two idempotent tidy-up erases of an interrupted rotation.
    fn refresh(&mut self) -> Result<(), SErr<F, M>> {
        let Some(keys) = self.keys.as_ref() else {
            return Ok(());
        };
        let cfg = self.cfg;
        let mut tamper = TamperFlags::NONE;

        // M1, M2.
        let scanned = ledger::scan::<F, M>(&mut self.flash, keys)?;
        let records_blank = self
            .flash
            .is_erased(Region::Records, 0, cfg.layout.records_bytes())
            .map_err(|e| StorageError::Hardware(HardwareFault::Flash(e)))?;
        let ledger = match scanned {
            Some(l) => {
                tamper = l.tamper;
                Some(l)
            }
            None => {
                if !records_blank {
                    // A blank ledger beside a non-blank records region is the cheap
                    // counter-reset attack: erase the counters, keep the wallets. Refusing
                    // rather than silently re-initialising is what makes it not free.
                    tamper.insert(TamperKind::LedgerMissing);
                }
                None
            }
        };

        // M3: complete an interrupted rotation. Idempotent, which is why it can run
        // unconditionally on every boot.
        if let Some(l) = ledger.as_ref() {
            ledger::tidy_main_pair::<F, M>(&mut self.flash, l.side)?;
        }
        let aux = ledger::scan_aux::<F, M>(&mut self.flash, keys)?;
        if let Some(a) = aux.as_ref() {
            ledger::tidy_aux_pair::<F, M>(&mut self.flash, a.side)?;
        }

        // M4.
        let epoch = ledger.as_ref().map_or(0, LedgerState::wipe_epoch);
        let high_water = ledger.as_ref().map_or(0, LedgerState::seq_high_water);
        let pin_gen = ledger.as_ref().map_or([0u32; 4], |l| l.pin_gen);

        // M5, M6: one election pass over every slot of every class.
        let mut table = SlotTable::default();
        let mut max_elected_seq = 0u64;
        let mut rollback = false;
        let mut any_elected = false;
        for slot in records::all_slots(&cfg) {
            let mut best: Option<Elected> = None;
            for side in Side::BOTH {
                let Some(header) = records::read_header::<F, M>(&mut self.flash, keys, &cfg, slot, side)?
                else {
                    continue;
                };
                // M7's witness check looks at every side with a valid MAC, not only the
                // elected ones: a record the ledger cannot account for is evidence the
                // ledger was rolled back under the records, and the loser of an election
                // is just as much evidence as the winner.
                if header.wipe_epoch > epoch || header.seal_seq >= high_water {
                    rollback = true;
                }
                if header.wipe_epoch != epoch {
                    continue;
                }
                // Generation 0 is the reserved "no identity" value and is never a
                // candidate outside the superblock.
                //
                // DEVIATION from ESP-SEAL.md 4.6, which makes a side a candidate iff its
                // `pin_gen` is one of the four current per-identity generations. That rule
                // has a hole the document does not see: at format every identity's
                // generation is 0, so after identity 0 changes its PIN, generation 0 is
                // still "current" for identities 1 to 3 and identity 0's OLD records
                // remain electable. Old-PIN ciphertext surviving a completed change is
                // exactly what the stale-ciphertext rule forbids. The fix is to make
                // generations device-globally unique per identity - which `pin_gen_next`
                // already provides - and to reserve 0 for an identity that does not exist.
                if slot.class() != SlotClass::Superblock
                    && (header.pin_gen == 0 || !pin_gen.contains(&header.pin_gen))
                {
                    continue;
                }
                if header.kdf != cfg.kdf {
                    // A record whose cost parameters disagree with the store's is a
                    // downgrade attempt or a half-finished migration. Either way it is not
                    // a candidate; the AAD would refuse it at open anyway, and refusing it
                    // here means no Argon2 time is spent finding that out.
                    continue;
                }
                if best.is_none_or(|b| header.seal_seq > b.header.seal_seq) {
                    best = Some(Elected { side, header });
                }
            }
            if let Some(e) = best {
                any_elected = true;
                max_elected_seq = max_elected_seq.max(e.header.seal_seq);
                table.set(slot, &cfg, Some(e));
            }
        }
        if rollback && ledger.is_some() {
            tamper.insert(TamperKind::LedgerRollback);
        }

        // M7.
        self.next_seq = high_water.max(if any_elected {
            max_elected_seq.saturating_add(1)
        } else {
            0
        });

        // The superblock body, which carries the layout the store was formatted with and
        // the fast-read policy mirror.
        let superblock = match table.get(SlotId::superblock(), &cfg) {
            Some(e) => {
                match records::read_plain_body::<F, M>(
                    &mut self.flash,
                    keys,
                    &cfg,
                    SlotId::superblock(),
                    e.side,
                    &e.header,
                )? {
                    Ok(body) => Superblock::decode(
                        body.as_slice(),
                        cfg.layout.sector_size,
                        cfg.layout.ledger_sectors,
                    )
                    .ok(),
                    Err(_) => None,
                }
            }
            None => None,
        };

        self.policy = resolve_policy(ledger.as_ref(), superblock.as_ref(), &cfg);
        self.table = table;
        self.superblock = superblock;
        self.ledger = ledger;
        self.aux = aux;
        self.tamper = tamper;

        // Counting real content means telling filler apart from a record, which needs the
        // device-derived filler key and one AEAD open per slot. That is a cost mount pays
        // deliberately: under `AlwaysFilled` every slot is occupied on the surface, and a
        // state that reported 4 identities on a device with one would be a lie the Verify
        // screen would repeat.
        let mut identities = 0u8;
        let mut occupied = 0u8;
        for slot in records::all_slots(&cfg) {
            match slot.class() {
                SlotClass::Superblock => continue,
                SlotClass::Canary => {
                    if self.slot_state_unkeyed(slot)? {
                        identities = identities.saturating_add(1);
                    }
                }
                SlotClass::Payload | SlotClass::Registry => {
                    if self.slot_state_unkeyed(slot)? {
                        occupied = occupied.saturating_add(1);
                    }
                }
            }
        }
        self.state = classify(self.superblock.is_some(), identities, occupied, epoch, tamper);
        Ok(())
    }

    /// M5's validation half: the recorded layout, the device fingerprint and the suite
    /// must match the running firmware. A mismatch is a refusal, never a best-effort
    /// reinterpretation, because that refusal is exactly what lets a future firmware
    /// change the layout without silently eating a user's wallets.
    fn validate_superblock(&mut self) -> Result<(), MountError<F::Error, M::Error>> {
        if self.superblock.is_none() {
            return self.diagnose_foreign();
        }
        let (Some(sb), Some(keys)) = (self.superblock.as_ref(), self.keys.as_ref()) else {
            return Ok(());
        };
        if sb.domain_tag != self.cfg.domain_tag || sb.device_tag != keys.device_tag {
            return Err(MountError::Foreign);
        }
        if !sb.layout_matches(&self.cfg.layout) {
            return Err(MountError::LayoutMismatch);
        }
        if sb.kdf != self.cfg.kdf {
            return Err(MountError::LayoutMismatch);
        }
        Ok(())
    }

    /// No superblock elected. Before calling that corruption, check whether the bytes on
    /// flash still look like a superblock written by a different board, because those are
    /// two different sentences to show a user and only one of them means "your data is
    /// gone".
    ///
    /// The read is unauthenticated and it has to be: on a foreign board every device-bound
    /// MAC fails, so there is nothing left to authenticate it with. It decides the wording
    /// of a refusal and nothing else. On a release unit with flash encryption on it will
    /// usually find nothing at all, because the XTS key moved with the board too, and the
    /// refusal falls back to the generic one.
    fn diagnose_foreign(&mut self) -> Result<(), MountError<F::Error, M::Error>> {
        let cfg = self.cfg;
        let Some(want) = self.keys.as_ref().map(|k| k.device_tag) else {
            return Ok(());
        };
        let slot = SlotId::superblock();
        for side in Side::BOTH {
            let Some(base) = slot.side_offset(side, &cfg.layout) else {
                continue;
            };
            let Some(at) = base.checked_add(crate::format::HEADER_LEN as u32) else {
                continue;
            };
            let mut body = [0u8; 0x48];
            if self.flash.read(Region::Records, at, &mut body).is_err() {
                continue;
            }
            if let Some((domain, device_tag)) = Superblock::peek_fingerprint(&body) {
                if domain == cfg.domain_tag && device_tag != want {
                    return Err(MountError::Foreign);
                }
            }
        }
        Ok(())
    }

    /// M9: erase every slot side that is non-erased and is not the elected candidate.
    ///
    /// This is the crash-recovery half of three different operations at once - SEAL's
    /// stale-side erase, CHANGE-PIN's C6, and WIPE's lazy erasure - and it is bounded by
    /// two erases per slot, idempotent, and restartable.
    fn cleanup(&mut self) -> Result<(), SErr<F, M>> {
        let Some(_) = self.keys.as_ref() else {
            return Ok(());
        };
        let cfg = self.cfg;
        for slot in records::all_slots(&cfg) {
            let elected = self.table.get(slot, &cfg).map(|e| e.side);
            for side in Side::BOTH {
                if elected == Some(side) {
                    continue;
                }
                if !records::side_is_erased::<F, M>(&mut self.flash, &cfg, slot, side)? {
                    records::erase_side::<F, M>(&mut self.flash, &cfg, slot, side)?;
                }
            }
        }
        Ok(())
    }

    /// The ledger is the authority for the policy and the superblock is a mirror, so a
    /// disagreement is repaired in one direction only: the mirror is rewritten.
    ///
    /// Skipped whenever tamper is suspected. Rewriting a record on a store that may have
    /// been interfered with would destroy the evidence the product is about to show.
    fn sync_policy_mirror(&mut self) -> Result<(), SErr<F, M>> {
        if !self.tamper.is_empty() {
            return Ok(());
        }
        let (Some(sb), true) = (self.superblock, matches!(self.state, StoreState::Formatted { .. }))
        else {
            return Ok(());
        };
        if sb.policy_mirror == self.policy {
            return Ok(());
        }
        let mut updated = sb;
        updated.policy_mirror = self.policy;
        self.write_superblock(&updated)?;
        self.refresh()
    }

    // -----------------------------------------------------------------------
    // Read-only accessors
    // -----------------------------------------------------------------------

    pub fn state(&self) -> StoreState {
        self.state
    }

    /// The effective wipe policy: the ledger's `policy_log` if it has one, the
    /// superblock's format-time policy if it does not, and the strict default if the
    /// ledger's top cell is malformed. Never a value read from a single unauthenticated
    /// place.
    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// `failures_base + len(attempt_entry) - len(attempt_success)`.
    pub fn failures(&self) -> u32 {
        self.ledger.as_ref().map_or(0, LedgerState::failures)
    }

    /// `None` when the wipe is disabled, which is a different fact from "zero left" and
    /// must not be rendered as a number.
    pub fn attempts_remaining(&self) -> Option<u8> {
        if !self.policy.wipe_enabled() {
            return None;
        }
        let left = u32::from(self.policy.wipe_after).saturating_sub(self.failures());
        Some(left.min(u32::from(u8::MAX)) as u8)
    }

    pub fn wipe_epoch(&self) -> u64 {
        self.ledger.as_ref().map_or(0, LedgerState::wipe_epoch)
    }

    /// Device-global monotonic sequence cursor. Exposed because the fuzzer asserts it
    /// never goes backwards across a cut.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// One past the highest PIN generation ever committed.
    pub fn pin_gen_next(&self) -> u32 {
        self.ledger.as_ref().map_or(1, |l| l.pin_gen_next)
    }

    pub fn pin_gen(&self, identity: Identity) -> u32 {
        self.ledger
            .as_ref()
            .and_then(|l| l.pin_gen.get(identity.0 as usize).copied())
            .unwrap_or(0)
    }

    pub fn key_provenance(&self) -> KeyProvenance {
        self.mac.provenance()
    }

    pub fn tamper_flags(&self) -> TamperFlags {
        self.tamper
    }

    /// Boots counted since the store was formatted (Q53). Zero when the auxiliary sector
    /// has never been written, which the Verify screen renders as `not counted`.
    pub fn boot_count(&self) -> u64 {
        self.aux.as_ref().map_or(0, AuxState::boot_count)
    }

    /// Which payload and registry slots hold a real record, WITHOUT a PIN.
    ///
    /// Under `Occupancy::AlwaysFilled` every slot holds a genuine AEAD record and the
    /// distinction is made by opening it with the device-derived filler key, which costs
    /// one HKDF and one AEAD per slot and no user secret at all. Products that ship duress
    /// must not surface this.
    pub fn occupancy(&mut self) -> SlotMap {
        let cfg = self.cfg;
        let mut map = SlotMap::EMPTY;
        for slot in records::user_slots(&cfg) {
            if matches!(self.slot_state_unkeyed(slot), Ok(true)) {
                map = map.with(slot);
            }
        }
        map
    }

    /// True iff the slot holds something that is not filler and not erased.
    fn slot_state_unkeyed(&mut self, slot: SlotId) -> Result<bool, SErr<F, M>> {
        let cfg = self.cfg;
        let Some(keys) = self.keys.as_ref() else {
            return Ok(false);
        };
        let Some(e) = self.table.get(slot, &cfg) else {
            return Ok(false);
        };
        let opened = records::read_record::<F, M>(
            &mut self.flash,
            keys,
            &cfg,
            slot,
            e.side,
            &e.header,
            &keys.filler_root,
        )?;
        Ok(opened.is_err())
    }

    pub fn into_parts(self) -> (F, M) {
        (self.flash, self.mac)
    }

    /// The flash backend, so the power-loss harness can arm a cut mid-operation.
    ///
    /// Compiled out of every firmware build. It is not a back door into the state
    /// machine: it hands out the backend the caller already owned before `mount` took it.
    /// Without it the fuzzer could only cut between operations, which is the one place a
    /// cut is uninteresting.
    #[cfg(feature = "testkit")]
    pub fn backend_mut(&mut self) -> &mut F {
        &mut self.flash
    }

    /// Every (slot, side) anywhere on flash whose ciphertext opens under `pin`, elected or
    /// not, erased-pending or not.
    ///
    /// This exists for one invariant: "no stale old-PIN ciphertext survives a completed
    /// change". That property is about sides no election will ever reach, so it cannot be
    /// tested through `read`, and testing it by re-implementing the record parser in the
    /// harness would only prove the harness agrees with itself. Compiled out of every
    /// firmware build.
    #[cfg(feature = "testkit")]
    pub fn open_any_side(
        &mut self,
        pin: &Pin,
        scratch: Scratch<'_>,
    ) -> Result<alloc::vec::Vec<(SlotId, Side)>, SErr<F, M>> {
        let cfg = self.cfg;
        let bound = self.stretch(pin, scratch)?;
        let mut found = alloc::vec::Vec::new();
        for slot in records::all_slots(&cfg) {
            if slot.class() == SlotClass::Superblock {
                continue;
            }
            for side in Side::BOTH {
                let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
                let Some(header) =
                    records::read_header::<F, M>(&mut self.flash, keys, &cfg, slot, side)?
                else {
                    continue;
                };
                let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
                if records::read_record::<F, M>(
                    &mut self.flash,
                    keys,
                    &cfg,
                    slot,
                    side,
                    &header,
                    bound.as_bytes(),
                )?
                .is_ok()
                {
                    found.push((slot, side));
                }
            }
        }
        Ok(found)
    }

    /// Domain-separated device-bound derivation for embedder use: anti-phishing words,
    /// the PIN-pad permutation, lock-screen words.
    ///
    /// Length-prefixed under tag `0x7f`, so an attacker who can choose the input, and for
    /// the anti-phishing words they can because it is a partial PIN, can never steer it
    /// into colliding with the fixed-length internal message `0x02 || prestretch`.
    ///
    /// A label longer than 64 bytes or data longer than 256 is refused with
    /// [`StorageError::Capacity`]. Truncating instead would let two inputs that differ
    /// only past the cut derive the same value, which is precisely what the length prefix
    /// is there to stop.
    pub fn device_derive(
        &mut self,
        label: &[u8],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<(), SErr<F, M>> {
        if self.keys.is_none() {
            return Err(StorageError::WrongState);
        }
        let accepted = crypto::device_derive(&mut self.mac, label, data, out)
            .map_err(|e| StorageError::Hardware(HardwareFault::Mac(e)))?;
        if accepted {
            Ok(())
        } else {
            Err(StorageError::Capacity)
        }
    }

    /// Program one boot-log cell and return the new count (Q53).
    pub fn record_boot(&mut self) -> Result<u64, SErr<F, M>> {
        let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
        match self.aux.as_mut() {
            Some(aux) => ledger::tick_boot::<F, M>(&mut self.flash, keys, aux),
            None => {
                let mut created = ledger::create_aux::<F, M>(&mut self.flash, keys, 0)?;
                let n = ledger::tick_boot::<F, M>(&mut self.flash, keys, &mut created)?;
                self.aux = Some(created);
                Ok(n)
            }
        }
    }

    // -----------------------------------------------------------------------
    // FORMAT (ESP-SEAL.md 4.4)
    // -----------------------------------------------------------------------

    /// Install the first PIN. Requires [`StoreState::Blank`] or [`StoreState::Wiped`].
    ///
    /// Nothing in this sequence can lose a user secret, because there is no user secret
    /// yet: a cut before F2 leaves a blank store, between F2 and F4 a live ledger over a
    /// blank records region, and between F4 and F5 a superblock with no identity. All
    /// three re-enter `format` and finish the job.
    pub fn format(
        &mut self,
        pin: &Pin,
        label: &[u8],
        scratch: Scratch<'_>,
    ) -> Result<Session, FormatError<F::Error, M::Error>> {
        match self.state {
            StoreState::Blank | StoreState::Wiped { .. } => {}
            StoreState::Unprovisioned => {
                return Err(FormatError::Provenance(KeyProvenance::Absent))
            }
            StoreState::Inconsistent(k) => return Err(FormatError::Tamper(k)),
            StoreState::Formatted { .. } => return Err(FormatError::AlreadyFormatted),
        }
        let requested = self.cfg.format_policy;
        if requested.wipe_after < WIPE_AFTER_MIN || requested.wipe_after > WIPE_AFTER_MAX {
            return Err(FormatError::Policy(PolicyRefusal::OutOfRange));
        }
        if pin.len() < usize::from(requested.min_pin_len) {
            return Err(FormatError::Policy(PolicyRefusal::PinTooShortToDisableWipe {
                min_len: requested.min_pin_len,
            }));
        }
        self.format_inner(pin, label, scratch).map_err(Into::into)
    }

    fn format_inner(
        &mut self,
        pin: &Pin,
        label: &[u8],
        scratch: Scratch<'_>,
    ) -> Result<Session, SErr<F, M>> {
        let cfg = self.cfg;
        let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;

        // F2. A store that has been wiped already has a ledger, and its epoch is one-way:
        // recreating it would reset `wipe_epoch` to zero and let a post-format re-save
        // collide with a pre-wipe flash snapshot's keystream. That is precisely the
        // vulnerability `wipe_epoch` exists to close, so the existing ledger is ROTATED
        // (which carries the epoch forward and resets the attempt logs) and only a truly
        // blank store is created from nothing.
        //
        // DEVIATION from ESP-SEAL.md 4.4 F2, which says "erase all ledger sectors" without
        // qualification. Taken literally that is a one-way counter that is not one-way.
        let format_policy = Policy {
            wipe_after: cfg.format_policy.wipe_after,
            occupancy: cfg.occupancy,
            min_pin_len: cfg.format_policy.min_pin_len,
            policy_gen: 0,
        };
        match self.ledger.take() {
            Some(mut live) => {
                let installed = Policy {
                    policy_gen: live.policy_gen().saturating_add(1),
                    ..format_policy
                };
                ledger::rotate::<F, M>(&mut self.flash, keys, &mut live, 0, installed)?;
                self.ledger = Some(live);
            }
            None => {
                let created = ledger::create::<F, M>(&mut self.flash, keys, &format_policy)?;
                self.ledger = Some(created);
            }
        }
        if self.aux.is_none() {
            let created = ledger::create_aux::<F, M>(&mut self.flash, keys, 0)?;
            self.aux = Some(created);
        }
        self.refresh()?;

        // F3.
        let bound = self.stretch(pin, scratch)?;

        let epoch = self.wipe_epoch();
        let policy = self.policy;
        let identity = Identity(0);
        // Generation 0 means "this identity does not exist", so the first identity needs a
        // real one. A previously interrupted format has already allocated one and it is
        // reused rather than burning a fresh cell on every retry.
        let existing_gen = self.pin_gen(identity);
        let pin_gen = if existing_gen == 0 {
            self.pin_gen_next().max(1)
        } else {
            existing_gen
        };

        // F4. The superblock is plaintext - there is no PIN at mount time - so its
        // integrity rests entirely on the device-bound header MAC.
        let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
        let sb = Superblock {
            domain_tag: cfg.domain_tag,
            device_tag: keys.device_tag,
            layout: cfg.layout,
            kdf: cfg.kdf,
            format_policy: policy,
            policy_mirror: policy,
            formatted_at_epoch: epoch,
        };
        self.write_superblock(&sb)?;

        // F5.
        let canary = Canary {
            identity,
            visible: SlotMap::ALL,
            created_epoch: epoch,
            label: fixed_label(label),
            policy,
        };
        self.write_canary(identity, &canary, &bound, pin_gen, StaleSide::EraseNow)?;
        if existing_gen != pin_gen {
            // The generation cell is the commit point when the generation is new: until it
            // lands, the canary just written is not a candidate, mount reports an
            // unformatted store and cleanup erases it. Fail-closed toward "nothing
            // happened", and there is no user secret to lose either way.
            let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
            let ledger = self.ledger.as_mut().ok_or(StorageError::NotFormatted)?;
            ledger::commit_pin_gen::<F, M>(&mut self.flash, keys, ledger, identity.0, pin_gen)?;
        }

        // F6. Filler is cosmetic and is re-run at the next mount if a cut lands here.
        self.refresh()?;
        self.fill_unoccupied()?;
        self.refresh()?;

        // F7: prove the canary opens from flash before handing back a session.
        let (found, visible) = self
            .open_canary(identity, &bound)?
            .ok_or(StorageError::Hardware(HardwareFault::WriteVerify))?;
        if found.policy != policy {
            return Err(StorageError::Invariant("format canary policy mismatch"));
        }
        Ok(Session::new(bound, identity, visible, self.pin_gen(identity), epoch))
    }

    // -----------------------------------------------------------------------
    // UNLOCK and VERIFY-PIN (ESP-SEAL.md 4.5)
    // -----------------------------------------------------------------------

    /// Consume one attempt and return a session on success.
    pub fn unlock(
        &mut self,
        pin: &Pin,
        scratch: Scratch<'_>,
    ) -> Result<Session, UnlockError<F::Error, M::Error>> {
        self.counted_unlock(pin, scratch)
    }

    /// Consume one attempt and return only the identity. Identical to [`Vault::unlock`]
    /// in every observable way including the counter, because anything else would be a
    /// free guessing oracle. Inside a session use [`Vault::confirm_pin`] instead.
    pub fn verify_pin(
        &mut self,
        pin: &Pin,
        scratch: Scratch<'_>,
    ) -> Result<Identity, UnlockError<F::Error, M::Error>> {
        self.counted_unlock(pin, scratch).map(|s| s.identity())
    }

    fn counted_unlock(
        &mut self,
        pin: &Pin,
        scratch: Scratch<'_>,
    ) -> Result<Session, UnlockError<F::Error, M::Error>> {
        // ---- U1: pre-checks. NO attempt is consumed anywhere in this block. ----
        match self.state {
            StoreState::Formatted { .. } => {}
            StoreState::Unprovisioned => {
                return Err(UnlockError::Provenance(KeyProvenance::Absent))
            }
            StoreState::Inconsistent(k) => return Err(UnlockError::Tamper(k)),
            _ => return Err(UnlockError::NotFormatted),
        }
        if self.wipe_is_due() {
            return Err(UnlockError::Locked);
        }
        let cfg = self.cfg;
        if !scratch.fits(&cfg.kdf) {
            return Err(UnlockError::Scratch {
                required_blocks: cfg.kdf.scratch_blocks(),
            });
        }
        // At least one canary must be structurally intact before an Argon2id spend is
        // committed to. A torn canary is `Corrupt`, not `WrongPin`, and it costs nothing.
        let mut any_canary = false;
        let mut first_corrupt: Option<(SlotId, Corruption)> = None;
        for i in 0..cfg.layout.identities {
            let Some(slot) = SlotId::new(SlotClass::Canary, i, &cfg.layout) else {
                continue;
            };
            let Some(e) = self.table.get(slot, &cfg) else {
                continue;
            };
            let keys = self.keys.as_ref().ok_or(UnlockError::NotFormatted)?;
            match records::verify_body_digest::<F, M>(&mut self.flash, keys, &cfg, slot, e.side, &e.header)
            {
                Ok(true) => any_canary = true,
                Ok(false) => {
                    if first_corrupt.is_none() {
                        first_corrupt = Some((slot, Corruption::BodyDigest));
                    }
                }
                Err(e) => return Err(unlock_hw::<F, M>(e, false)),
            }
        }
        if !any_canary {
            return Err(match first_corrupt {
                Some((slot, detail)) => UnlockError::Corrupt { slot, detail },
                None => UnlockError::NotFormatted,
            });
        }

        // ---- U2, U3: the expensive, uncounted part. ----
        // The counter is decremented before the VERIFICATION, not before the COMPUTATION.
        // An attacker who cuts power here has paid the full Argon2id cost and learned
        // nothing, and cannot obtain an uncounted verification because the verification is
        // strictly after U4.
        let bound = self.stretch(pin, scratch).map_err(|e| unlock_hw::<F, M>(e, false))?;

        // ---- U4: === COUNTED REGION BEGINS === ----
        // With the wipe disabled a failure streak is not bounded by anything, so the
        // attempt log can fill. Rotating on failure carries the count forward in
        // `failures_base` and is therefore not a counter reset (Q5.4).
        if self.attempt_log_is_full() {
            let carry = self.failures();
            self.rotate_ledger(carry).map_err(|e| unlock_hw::<F, M>(e, false))?;
        }
        {
            let keys = self.keys.as_ref().ok_or(UnlockError::NotFormatted)?;
            let ledger = self.ledger.as_mut().ok_or(UnlockError::NotFormatted)?;
            ledger::tick_attempt_entry::<F, M>(&mut self.flash, keys, ledger)
                .map_err(|e| unlock_hw::<F, M>(e, true))?;
        }

        // ---- U5: four HKDFs and four AEAD opens. Microseconds. ----
        let mut found: Option<(Identity, Canary, SlotMap)> = None;
        for i in 0..cfg.layout.identities {
            match self.open_canary(Identity(i), &bound) {
                Ok(Some((canary, visible))) => {
                    found = Some((Identity(i), canary, visible));
                    break;
                }
                Ok(None) => {}
                Err(e) => return Err(unlock_hw::<F, M>(e, true)),
            }
        }

        // ---- U6 ----
        let Some((identity, canary, visible)) = found else {
            let failures = self.failures();
            if self.policy.wipe_enabled() && failures >= u32::from(self.policy.wipe_after) {
                self.wipe_inner().map_err(|e| unlock_hw::<F, M>(e, true))?;
                self.remount().map_err(mount_to_unlock)?;
                return Err(UnlockError::Wiped {
                    epoch: self.wipe_epoch(),
                });
            }
            return Err(UnlockError::WrongPin {
                attempts_remaining: self.attempts_remaining(),
            });
        };

        // ---- U7: catch-up. ----
        // Without this an interrupted unlock leaves entry = success + 1 forever, the gap
        // never closes, and the device slowly accumulates phantom failures until it wipes
        // itself. The loop only runs after a genuine success, so it is not an
        // attacker-reachable counter reset.
        self.catch_up_success().map_err(|e| unlock_hw::<F, M>(e, true))?;
        // ---- === COUNTED REGION ENDS === ----

        // The policy reconciliation of Q5.1, possible only now that the PIN is proven.
        self.reconcile_policy(identity, &canary, &bound)
            .map_err(|e| unlock_hw::<F, M>(e, true))?;

        // Rotation (4.8) is triggered on a successful unlock, so it is never an
        // attacker-reachable counter reset. Two triggers: the tail reserve, and a nonzero
        // `failures_base` that only a rotation can clear.
        if self.rotation_is_due() {
            self.rotate_ledger(0).map_err(|e| unlock_hw::<F, M>(e, true))?;
        }

        let epoch = self.wipe_epoch();
        Ok(Session::new(
            bound,
            identity,
            visible,
            self.pin_gen(identity),
            epoch,
        ))
    }

    /// Constant-time re-derivation compared against the live session secret. Touches no
    /// flash and consumes NO attempt: the session already proves the PIN was known, so
    /// re-proving it inside the session is not a new guess.
    pub fn confirm_pin(
        &mut self,
        session: &Session,
        pin: &Pin,
        scratch: Scratch<'_>,
    ) -> Result<bool, SErr<F, M>> {
        if !scratch.fits(&self.cfg.kdf) {
            return Err(StorageError::Scratch {
                required_blocks: self.cfg.kdf.scratch_blocks(),
            });
        }
        let candidate = self.stretch(pin, scratch)?;
        Ok(session.bound().ct_eq(&candidate))
    }

    // -----------------------------------------------------------------------
    // Record access (ESP-SEAL.md 5.3)
    // -----------------------------------------------------------------------

    /// Copy a slot's plaintext into `out` and return its true length.
    pub fn read(
        &mut self,
        session: &Session,
        slot: SlotId,
        out: &mut [u8],
    ) -> Result<usize, SErr<F, M>> {
        self.check_session(session)?;
        let cfg = self.cfg;
        if !matches!(slot.class(), SlotClass::Payload | SlotClass::Registry) {
            return Err(StorageError::WrongState);
        }
        let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
        let e = self.table.get(slot, &cfg).ok_or(StorageError::Corrupt {
            slot,
            detail: Corruption::Magic,
        })?;
        let opened = records::read_record::<F, M>(
            &mut self.flash,
            keys,
            &cfg,
            slot,
            e.side,
            &e.header,
            session.bound().as_bytes(),
        )?;
        let plain = opened.map_err(|detail| StorageError::Corrupt { slot, detail })?;
        let n = plain.len();
        let dst = crate::bytes::rd_mut(out, 0, n).ok_or(StorageError::Capacity)?;
        dst.copy_from_slice(plain.as_slice());
        Ok(n)
    }

    /// What a slot holds, as seen by this session's key.
    pub fn slot_state(&mut self, session: &Session, slot: SlotId) -> Result<SlotState, SErr<F, M>> {
        self.check_session(session)?;
        let cfg = self.cfg;
        let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
        let Some(e) = self.table.get(slot, &cfg) else {
            return Ok(SlotState::Empty);
        };
        if records::read_record::<F, M>(
            &mut self.flash,
            keys,
            &cfg,
            slot,
            e.side,
            &e.header,
            &keys.filler_root,
        )?
        .is_ok()
        {
            return Ok(SlotState::Empty);
        }
        match records::read_record::<F, M>(
            &mut self.flash,
            keys,
            &cfg,
            slot,
            e.side,
            &e.header,
            session.bound().as_bytes(),
        )? {
            Ok(plain) => Ok(SlotState::Occupied {
                len: plain.len().min(usize::from(u16::MAX)) as u16,
            }),
            Err(_) => Ok(SlotState::Opaque),
        }
    }

    /// Seal a record into the inactive side, verify it from flash, then erase the stale
    /// side (S1-S9). A successful return means the record is durable.
    pub fn write(
        &mut self,
        session: &Session,
        slot: SlotId,
        plaintext: &[u8],
    ) -> Result<(), SErr<F, M>> {
        self.check_session(session)?;
        if !matches!(slot.class(), SlotClass::Payload | SlotClass::Registry) {
            return Err(StorageError::WrongState);
        }
        self.seal_into(slot, session.bound().as_bytes(), session.pin_gen(), plaintext)
    }

    /// Erase the slot (Sparse) or overwrite it with filler (AlwaysFilled).
    ///
    /// Under AlwaysFilled the filler write is not cosmetic: leaving an erased-flash
    /// signature where a wallet used to be is exactly the occupancy leak the mode exists
    /// to close, so a delete rewrites rather than erases.
    pub fn clear(&mut self, session: &Session, slot: SlotId) -> Result<(), SErr<F, M>> {
        self.check_session(session)?;
        if !matches!(slot.class(), SlotClass::Payload | SlotClass::Registry) {
            return Err(StorageError::WrongState);
        }
        match self.cfg.occupancy {
            Occupancy::AlwaysFilled => self.write_filler(slot),
            Occupancy::Sparse => {
                let cfg = self.cfg;
                for side in Side::BOTH {
                    if !records::side_is_erased::<F, M>(&mut self.flash, &cfg, slot, side)? {
                        records::erase_side::<F, M>(&mut self.flash, &cfg, slot, side)?;
                    }
                }
                self.table.set(slot, &cfg, None);
                Ok(())
            }
        }
    }

    // -----------------------------------------------------------------------
    // CHANGE-PIN (ESP-SEAL.md 4.6 C1-C6)
    // -----------------------------------------------------------------------

    /// Re-seal every record of this identity under a new PIN and commit with one ledger
    /// cell.
    ///
    /// The session is consumed and a new one returned, so a caller cannot keep using keys
    /// derived from the retired PIN by accident. Before the commit cell the old PIN works
    /// and nothing is lost; after it the new PIN works and the stale sides are erased.
    /// There is no window in which neither works, and `old_pin_still_valid` on the error
    /// states which side of the commit a failure fell on rather than leaving the caller to
    /// infer it.
    pub fn change_pin(
        &mut self,
        session: Session,
        new_pin: &Pin,
        scratch: Scratch<'_>,
    ) -> Result<Session, ChangePinError<F::Error, M::Error>> {
        let mut committed = false;
        match self.change_pin_inner(&session, new_pin, scratch, &mut committed) {
            Ok(s) => Ok(s),
            Err(source) => Err(ChangePinError {
                source,
                old_pin_still_valid: !committed,
            }),
        }
    }

    fn change_pin_inner(
        &mut self,
        session: &Session,
        new_pin: &Pin,
        scratch: Scratch<'_>,
        committed: &mut bool,
    ) -> Result<Session, SErr<F, M>> {
        self.check_session(session)?;
        let cfg = self.cfg;
        if new_pin.len() < usize::from(self.policy.min_pin_len) {
            return Err(StorageError::Policy(PolicyRefusal::PinTooShortToDisableWipe {
                min_len: self.policy.min_pin_len,
            }));
        }
        if !scratch.fits(&cfg.kdf) {
            return Err(StorageError::Scratch {
                required_blocks: cfg.kdf.scratch_blocks(),
            });
        }

        // C1, C2. Nothing is written by either.
        let bound_new = self.stretch(new_pin, scratch)?;
        let identity = session.identity();
        let generation = self.pin_gen_next();
        let old_bound = Zeroizing::new(*session.bound().as_bytes());
        let epoch = self.wipe_epoch();

        // C3. One record's plaintext is in RAM at a time, deliberately: a batch that
        // decrypted everything first would put every wallet on the stack at once.
        //
        // Identity indices are not stored in headers, so "belongs to this identity" is
        // decided by what the old key opens. Filler is re-sealed too - it carries identity
        // 0's generation, and letting it go stale would leave an erased slot where the
        // AlwaysFilled mode promises a record.
        for slot in records::user_slots(&cfg) {
            let Some(e) = self.table.get(slot, &cfg) else {
                continue;
            };
            let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
            let filler_root = Zeroizing::new(*keys.filler_root);
            if e.header.pin_gen != session.pin_gen() {
                continue;
            }
            let as_filler = records::read_record::<F, M>(
                &mut self.flash,
                keys,
                &cfg,
                slot,
                e.side,
                &e.header,
                &filler_root,
            )?;
            if as_filler.is_ok() {
                if identity.0 == 0 {
                    self.reseal(
                        slot,
                        &filler_root,
                        generation,
                        &[],
                        epoch,
                        StaleSide::DeferToCommit,
                    )?;
                }
                continue;
            }
            let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
            let opened = records::read_record::<F, M>(
                &mut self.flash,
                keys,
                &cfg,
                slot,
                e.side,
                &e.header,
                &old_bound,
            )?;
            let Ok(plain) = opened else {
                continue;
            };
            let payload = Zeroizing::new(plain.to_vec());
            let new_key = Zeroizing::new(*bound_new.as_bytes());
            self.reseal(
                slot,
                &new_key,
                generation,
                payload.as_slice(),
                epoch,
                StaleSide::DeferToCommit,
            )?;
        }

        // C4. The canary carries the policy witness forward unchanged: a PIN change is not
        // a policy change, and re-signing the same policy under the new key is what keeps
        // the witness meaningful after the key moves.
        let (canary, _) = self
            .open_canary(identity, session.bound())?
            .ok_or(StorageError::Corrupt {
                slot: SlotId::superblock(),
                detail: Corruption::Tag,
            })?;
        let canary_new = Canary {
            policy: self.policy,
            ..canary
        };
        self.write_canary(
            identity,
            &canary_new,
            &bound_new,
            generation,
            StaleSide::DeferToCommit,
        )?;

        // C5. THE COMMIT POINT. A value is never in the current set until its own cell is
        // programmed, so everything written above is invisible to mount until this lands.
        {
            let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
            let ledger = self.ledger.as_mut().ok_or(StorageError::NotFormatted)?;
            ledger::commit_pin_gen::<F, M>(&mut self.flash, keys, ledger, identity.0, generation)?;
        }
        *committed = true;

        // C6. Erase every side whose generation is no longer current. `refresh` re-elects
        // against the new generation set and `cleanup` erases the losers, which is the
        // same code path mount uses to finish an interrupted change.
        self.refresh()?;
        self.cleanup()?;

        Ok(Session::new(
            bound_new,
            identity,
            canary_new.visible,
            generation,
            epoch,
        ))
    }

    /// Add a duress identity. The format always supports it; whether the product exposes
    /// it is a product decision, not this crate's.
    pub fn add_identity(
        &mut self,
        session: &Session,
        identity: Identity,
        pin: &Pin,
        visible: SlotMap,
        scratch: Scratch<'_>,
    ) -> Result<(), SErr<F, M>> {
        self.check_session(session)?;
        let cfg = self.cfg;
        if identity.0 == 0 || identity.0 >= cfg.layout.identities {
            return Err(StorageError::WrongState);
        }
        if !scratch.fits(&cfg.kdf) {
            return Err(StorageError::Scratch {
                required_blocks: cfg.kdf.scratch_blocks(),
            });
        }
        let bound = self.stretch(pin, scratch)?;
        let epoch = self.wipe_epoch();
        // A fresh device-global generation, never a shared one: two identities on the same
        // generation would make one identity's PIN change leave the other's records
        // electable under the retired key.
        let generation = self.pin_gen_next().max(1);
        let canary = Canary {
            identity,
            visible,
            created_epoch: epoch,
            label: [0u8; 16],
            policy: self.policy,
        };
        self.write_canary(identity, &canary, &bound, generation, StaleSide::DeferToCommit)?;
        {
            let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
            let ledger = self.ledger.as_mut().ok_or(StorageError::NotFormatted)?;
            ledger::commit_pin_gen::<F, M>(&mut self.flash, keys, ledger, identity.0, generation)?;
        }
        self.refresh()?;
        self.cleanup()?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // SET-POLICY (OPEN-QUESTIONS Q5.2 Y1-Y7)
    // -----------------------------------------------------------------------

    /// Change the wipe policy, or switch the wipe off.
    ///
    /// Requires an unlocked session AND a fresh PIN confirmation, and that is the whole
    /// answer to "what stops someone holding the device from turning wipe off before
    /// guessing": every attempt to reach this operation without the PIN spends a guess
    /// against the counter they are trying to disable, and the counter is enforced at
    /// mount before any UI exists.
    pub fn set_policy(
        &mut self,
        session: &Session,
        request: PolicyRequest,
        pin: &Pin,
        scratch: Scratch<'_>,
    ) -> Result<Policy, SErr<F, M>> {
        self.check_session(session)?;

        // Y1.
        if !self.confirm_pin(session, pin, scratch)? {
            return Err(StorageError::PinMismatch);
        }

        // Y2.
        if request.wipe_after != 0
            && !(WIPE_AFTER_MIN..=WIPE_AFTER_MAX).contains(&request.wipe_after)
        {
            return Err(StorageError::Policy(PolicyRefusal::OutOfRange));
        }
        let failures = self.failures();
        if request.wipe_after != 0 && u32::from(request.wipe_after) <= failures {
            // Lowering N to at or below the failures already accumulated would wipe the
            // device the instant it commits. Refused, not honoured.
            return Err(StorageError::Policy(
                PolicyRefusal::BelowAccumulatedFailures { failures },
            ));
        }

        // Y3. The floor is a parameter rather than a constant so the ratified answer
        // (no floor, Q62(b)) is a value and not a code change if it is ever revisited.
        if request.wipe_after == 0 {
            if let Some(min) = self.cfg.disable_wipe_min_pin_len {
                if pin.len() < usize::from(min) {
                    return Err(StorageError::Policy(
                        PolicyRefusal::PinTooShortToDisableWipe { min_len: min },
                    ));
                }
            }
        }

        if ledger::policy_log_full(self.ledger.as_ref().ok_or(StorageError::NotFormatted)?) {
            // The array is per-rotation and rotation needs a successful unlock, which the
            // caller has by definition: they hold a session.
            self.rotate_ledger(failures)?;
        }

        let next = Policy {
            wipe_after: request.wipe_after,
            occupancy: self.policy.occupancy,
            min_pin_len: request.min_pin_len,
            policy_gen: self.policy.policy_gen.saturating_add(1),
        };

        // Y4. THE COMMIT POINT, one guarded cell, exactly like WIPE's epoch cell and
        // CHANGE-PIN's generation cell.
        {
            let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
            let ledger = self.ledger.as_mut().ok_or(StorageError::NotFormatted)?;
            ledger::commit_policy::<F, M>(&mut self.flash, keys, ledger, &next)?;
        }
        self.policy = next;

        // Y5. The canary is now one generation behind until this lands; the unlock-time
        // reconciliation repairs that case without user action if a cut arrives here.
        let identity = session.identity();
        let (canary, _) = self
            .open_canary(identity, session.bound())?
            .ok_or(StorageError::Corrupt {
                slot: SlotId::superblock(),
                detail: Corruption::Tag,
            })?;
        let updated = Canary {
            policy: next,
            ..canary
        };
        self.write_canary(
            identity,
            &updated,
            session.bound(),
            session.pin_gen(),
            StaleSide::EraseNow,
        )?;

        // Y6, Y7.
        self.refresh()?;
        self.sync_policy_mirror()?;
        self.cleanup()?;
        Ok(next)
    }

    /// Turn the PIN off: destroy every sealed record and leave the store unformatted.
    ///
    /// "Keep the stored wallets with no PIN" is not a thing this device can do and the API
    /// must not imply one - the sealing key is derived from the PIN, so with no PIN there
    /// is no key. The returned counts exist so the confirmation screen can name each item
    /// rather than summarise (Q5.5).
    pub fn remove_pin(
        &mut self,
        session: &Session,
        pin: &Pin,
        scratch: Scratch<'_>,
    ) -> Result<Destroyed, SErr<F, M>> {
        self.check_session(session)?;
        if !self.confirm_pin(session, pin, scratch)? {
            return Err(StorageError::PinMismatch);
        }
        let cfg = self.cfg;
        let mut destroyed = Destroyed::default();
        for slot in records::user_slots(&cfg) {
            if !self.slot_state_unkeyed(slot)? {
                continue;
            }
            match slot.class() {
                SlotClass::Payload => destroyed.wallets = destroyed.wallets.saturating_add(1),
                SlotClass::Registry => {
                    destroyed.registrations = destroyed.registrations.saturating_add(1)
                }
                _ => {}
            }
        }
        for i in 0..cfg.layout.identities {
            if let Some(slot) = SlotId::new(SlotClass::Canary, i, &cfg.layout) {
                // A canary slot holding filler is not an identity. Counting it would make
                // the confirmation screen name three duress identities the user never
                // created, which is exactly the kind of number Q5.5 says must be read from
                // the store rather than guessed.
                if self.slot_state_unkeyed(slot)? {
                    destroyed.identities = destroyed.identities.saturating_add(1);
                }
            }
        }
        self.wipe_inner()?;
        self.remount().map_err(|e| match e {
            MountError::Hardware(h) => StorageError::Hardware(h),
            _ => StorageError::Invariant("remount after remove_pin"),
        })?;
        destroyed.epoch = self.wipe_epoch();
        Ok(destroyed)
    }

    // -----------------------------------------------------------------------
    // WIPE (ESP-SEAL.md 4.7)
    // -----------------------------------------------------------------------

    /// Destroy every record and bump the one-way epoch. Needs no PIN: it only destroys.
    /// Idempotent and restartable.
    pub fn wipe(&mut self) -> Result<(), SErr<F, M>> {
        if self.keys.is_none() {
            return Err(StorageError::WrongState);
        }
        self.wipe_inner()?;
        self.remount().map_err(|e| match e {
            MountError::Hardware(h) => StorageError::Hardware(h),
            _ => StorageError::Invariant("remount after wipe"),
        })
    }

    /// W1 then W2.
    ///
    /// The commit point is one 8-byte cell program and everything after it is lazy
    /// cleanup, which is the strongest property in the design: bumping the epoch destroys
    /// every record LOGICALLY and instantaneously, because a record whose `wipe_epoch` is
    /// not the current one can never be elected or opened. Physical erasure is
    /// housekeeping that the next mount will finish if this one is cut.
    ///
    /// Bump-before-erase is mandatory and the reverse order is a real vulnerability:
    /// erasing first and losing power before the bump would let a re-save collide with a
    /// pre-wipe snapshot's keystream.
    fn wipe_inner(&mut self) -> Result<(), SErr<F, M>> {
        let cfg = self.cfg;
        // A store with no ledger has nothing to bump and nothing to destroy, but it may
        // hold a torn record from an interrupted format. Erase and be done.
        if self.ledger.is_none() {
            return self.erase_all_records();
        }
        if self.epoch_log_is_full() {
            self.rotate_ledger(self.failures())?;
        }
        {
            let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
            let ledger = self.ledger.as_mut().ok_or(StorageError::NotFormatted)?;
            // W1: THE COMMIT POINT.
            ledger::tick_epoch::<F, M>(&mut self.flash, keys, ledger)?;
        }
        // W2. Every surviving record now carries a stale epoch and cannot be elected, so
        // this is housekeeping and a cut inside it changes nothing an observer can see.
        //
        // DEVIATION from ESP-SEAL.md 4.7 W3/W4, which rewrite the superblock and the
        // filler after a wipe "so the store is provisioned-but-PIN-less rather than
        // blank". Those two steps are dropped. Q5.5 requires `remove_pin` to leave a
        // device on which "nothing is written to flash", and W3 contradicts it directly;
        // W3's stated purpose - distinguishing a wiped store from a virgin one - is
        // already served at zero cost by the ledger's nonzero epoch, which mount reads
        // before it looks at a single record. Filler on a wiped device hides nothing,
        // because there is nothing to hide.
        let _ = cfg;
        self.erase_all_records()
    }

    fn erase_all_records(&mut self) -> Result<(), SErr<F, M>> {
        let cfg = self.cfg;
        for slot in records::all_slots(&cfg) {
            for side in Side::BOTH {
                if !records::side_is_erased::<F, M>(&mut self.flash, &cfg, slot, side)? {
                    records::erase_side::<F, M>(&mut self.flash, &cfg, slot, side)?;
                }
            }
        }
        self.table = SlotTable::default();
        self.superblock = None;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    /// A session is valid only for the epoch it was created in and only while its
    /// generation is still current. A wipe or a PIN change kills every session in
    /// existence, which is what keeps a stale session from writing a record that nobody
    /// will ever be able to read.
    fn check_session(&self, session: &Session) -> Result<(), SErr<F, M>> {
        match self.state {
            StoreState::Formatted { .. } => {}
            StoreState::Inconsistent(k) => return Err(StorageError::Tamper(k)),
            StoreState::Unprovisioned => return Err(StorageError::WrongState),
            _ => return Err(StorageError::NotFormatted),
        }
        if session.epoch() != self.wipe_epoch() {
            return Err(StorageError::WrongState);
        }
        if session.pin_gen() != self.pin_gen(session.identity()) {
            return Err(StorageError::WrongState);
        }
        Ok(())
    }

    /// `prestretch = Argon2id(pin, kdf_salt)` then `bound = hmac_efuse(0x02, prestretch)`.
    /// The scratch buffer is wiped on every path out, including the error paths.
    fn stretch(&mut self, pin: &Pin, scratch: Scratch<'_>) -> Result<Bound, SErr<F, M>> {
        let cfg = self.cfg;
        let mut scratch = scratch;
        if !scratch.fits(&cfg.kdf) {
            scratch.wipe();
            return Err(StorageError::Scratch {
                required_blocks: cfg.kdf.scratch_blocks(),
            });
        }
        let salt = self
            .keys
            .as_ref()
            .map(|k| k.kdf_salt)
            .ok_or(StorageError::WrongState)?;
        let pre = crypto::prestretch(pin.as_bytes(), &salt, &cfg.kdf, &mut scratch)
            .ok_or(StorageError::Invariant("argon2 parameters"))?;
        crypto::bind(&mut self.mac, &pre).map_err(|e| StorageError::Hardware(HardwareFault::Mac(e)))
    }

    /// Open identity `i`'s canary with `bound`. `Ok(None)` means the tag did not verify,
    /// which is the ordinary "this is not that identity's PIN" answer and not an error.
    fn open_canary(
        &mut self,
        identity: Identity,
        bound: &Bound,
    ) -> Result<Option<(Canary, SlotMap)>, SErr<F, M>> {
        let cfg = self.cfg;
        let Some(slot) = SlotId::new(SlotClass::Canary, identity.0, &cfg.layout) else {
            return Ok(None);
        };
        let Some(e) = self.table.get(slot, &cfg) else {
            return Ok(None);
        };
        let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
        let opened = records::read_record::<F, M>(
            &mut self.flash,
            keys,
            &cfg,
            slot,
            e.side,
            &e.header,
            bound.as_bytes(),
        )?;
        let Ok(plain) = opened else {
            return Ok(None);
        };
        let Ok(canary) = Canary::decode(plain.as_slice()) else {
            // A forced tag comparison yields garbage, and garbage fails the fixed magic
            // and the zero-pad check. Treated as "did not open" rather than as corruption.
            return Ok(None);
        };
        if canary.identity != identity {
            return Ok(None);
        }
        Ok(Some((canary, canary.visible)))
    }

    /// The Q5.1 reconciliation table, run once the canary has opened and the PIN is
    /// therefore proven. Every row that is not an explicit repair is treated as tamper.
    fn reconcile_policy(
        &mut self,
        identity: Identity,
        canary: &Canary,
        bound: &Bound,
    ) -> Result<(), SErr<F, M>> {
        let ledger_gen = self.policy.policy_gen;
        let witness = canary.policy;
        if witness.policy_gen == ledger_gen {
            if witness == self.policy {
                return Ok(());
            }
            // Same generation, different bytes. Impossible without forgery: both copies
            // are device-MACed and only one of them can be the truth.
            self.tamper.insert(TamperKind::PolicyMismatch);
            self.policy = self.strict_default();
            return Ok(());
        }
        if witness.policy_gen.saturating_add(1) == ledger_gen {
            // SET-POLICY was interrupted after its commit. The ledger is the authority, so
            // the repair is to re-seal the canary with the ledger's policy. No user action,
            // and no weakening: the policy in force does not move.
            let repaired = Canary {
                policy: self.policy,
                ..*canary
            };
            let gen = self.pin_gen(identity);
            self.write_canary(identity, &repaired, bound, gen, StaleSide::EraseNow)?;
            self.refresh()?;
            self.cleanup()?;
            return Ok(());
        }
        // Witness ahead of the ledger means the ledger was rolled back independently;
        // any other gap is unreachable. Both fail closed.
        if witness.policy_gen > ledger_gen {
            self.tamper.insert(TamperKind::LedgerRollback);
        } else {
            self.tamper.insert(TamperKind::PolicyMismatch);
        }
        self.policy = self.strict_default();
        Ok(())
    }

    /// Wipe ON, `wipe_after` = the superblock's FORMAT-TIME value, occupancy unchanged.
    /// Defined once so "fail closed" means something specific, and every fail-closed path
    /// in the design resolves here.
    fn strict_default(&self) -> Policy {
        let base = self
            .superblock
            .as_ref()
            .map(|sb| sb.format_policy)
            .unwrap_or_else(|| self.cfg.format_policy());
        Policy {
            wipe_after: if base.wipe_enabled() {
                base.wipe_after
            } else {
                self.cfg.format_policy.wipe_after
            },
            occupancy: self.policy.occupancy,
            min_pin_len: base.min_pin_len,
            policy_gen: self.policy.policy_gen,
        }
    }

    fn wipe_is_due(&self) -> bool {
        matches!(self.state, StoreState::Formatted { .. })
            && self.policy.wipe_enabled()
            && self.failures() >= u32::from(self.policy.wipe_after)
    }

    fn attempt_log_is_full(&self) -> bool {
        self.ledger.as_ref().is_some_and(ledger::attempt_log_full)
    }

    fn epoch_log_is_full(&self) -> bool {
        self.ledger
            .as_ref()
            .is_some_and(|l| l.epoch_len >= crate::format::EPOCH_LOG.cells)
    }

    fn rotation_is_due(&self) -> bool {
        self.ledger.as_ref().is_some_and(|l| {
            ledger::attempt_log_near_full(l) || l.head.failures_base != 0
        })
    }

    fn rotate_ledger(&mut self, carry_failures: u32) -> Result<(), SErr<F, M>> {
        let policy = self.policy;
        let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
        let ledger = self.ledger.as_mut().ok_or(StorageError::NotFormatted)?;
        ledger::rotate::<F, M>(&mut self.flash, keys, ledger, carry_failures, policy)
    }

    /// U7's loop, as its own function so that `attempt_success` is programmed at exactly
    /// one place in the crate and a reviewer can check the claim by grepping for it.
    fn catch_up_success(&mut self) -> Result<(), SErr<F, M>> {
        loop {
            let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
            let ledger = self.ledger.as_mut().ok_or(StorageError::NotFormatted)?;
            if ledger.success_len >= ledger.entry_len {
                return Ok(());
            }
            ledger::tick_attempt_success::<F, M>(&mut self.flash, keys, ledger)?;
        }
    }

    /// S1 and S2: reserve-ahead. The high-water mark is advanced BEFORE the sequence is
    /// used, so every sequence number ever used is strictly below it. A crash between the
    /// advance and the write loses up to 256 sequence numbers, which costs nothing:
    /// sequence numbers need to be unique and monotonic, not dense.
    fn reserve_seq(&mut self) -> Result<u64, SErr<F, M>> {
        let seq = self.next_seq;
        loop {
            let high = self
                .ledger
                .as_ref()
                .map(LedgerState::seq_high_water)
                .ok_or(StorageError::NotFormatted)?;
            if seq < high {
                break;
            }
            if self
                .ledger
                .as_ref()
                .is_some_and(|l| l.seq_len >= SEQ_LOG.cells)
            {
                self.rotate_ledger(self.failures())?;
                continue;
            }
            let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
            let ledger = self.ledger.as_mut().ok_or(StorageError::NotFormatted)?;
            ledger::tick_seq::<F, M>(&mut self.flash, keys, ledger)?;
        }
        self.next_seq = seq.saturating_add(1);
        Ok(seq)
    }

    /// SEAL S1-S9 for a PIN-keyed record.
    fn seal_into(
        &mut self,
        slot: SlotId,
        key_source: &[u8; 32],
        pin_gen: u32,
        payload: &[u8],
    ) -> Result<(), SErr<F, M>> {
        let epoch = self.wipe_epoch();
        self.reseal(slot, key_source, pin_gen, payload, epoch, StaleSide::EraseNow)
    }

    fn reseal(
        &mut self,
        slot: SlotId,
        key_source: &[u8; 32],
        pin_gen: u32,
        payload: &[u8],
        epoch: u64,
        stale: StaleSide,
    ) -> Result<(), SErr<F, M>> {
        let cfg = self.cfg;
        let target = self
            .table
            .get(slot, &cfg)
            .map_or(Side::A, |e| e.side.other());
        let seq = self.reserve_seq()?;
        let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
        let header = records::write_sealed::<F, M>(
            &mut self.flash,
            keys,
            &cfg,
            slot,
            target,
            seq,
            epoch,
            pin_gen,
            key_source,
            payload,
        )?;
        // The record is durable at this point; the stale side is housekeeping and mount's
        // cleanup finishes it if a cut lands in the window. That window is the only place
        // an old-PIN ciphertext can survive a completed change, and it is closed
        // unconditionally before any unlock is possible.
        if stale == StaleSide::EraseNow {
            let loser = target.other();
            if !records::side_is_erased::<F, M>(&mut self.flash, &cfg, slot, loser)? {
                records::erase_side::<F, M>(&mut self.flash, &cfg, slot, loser)?;
            }
        }
        self.table.set(
            slot,
            &cfg,
            Some(Elected {
                side: target,
                header,
            }),
        );
        Ok(())
    }

    fn write_canary(
        &mut self,
        identity: Identity,
        canary: &Canary,
        bound: &Bound,
        pin_gen: u32,
        stale: StaleSide,
    ) -> Result<(), SErr<F, M>> {
        let cfg = self.cfg;
        let slot = SlotId::new(SlotClass::Canary, identity.0, &cfg.layout)
            .ok_or(StorageError::WrongState)?;
        let body = canary.encode();
        let epoch = self.wipe_epoch();
        self.reseal(slot, bound.as_bytes(), pin_gen, &body, epoch, stale)
    }

    fn write_superblock(&mut self, sb: &Superblock) -> Result<(), SErr<F, M>> {
        let cfg = self.cfg;
        let slot = SlotId::superblock();
        let target = self
            .table
            .get(slot, &cfg)
            .map_or(Side::A, |e| e.side.other());
        let seq = self.reserve_seq()?;
        let epoch = self.wipe_epoch();
        let cap = SlotClass::Superblock.body_capacity(&cfg.layout) as usize;
        let mut body = vec![0u8; cap];
        sb.encode(&mut body).ok_or(StorageError::Capacity)?;
        let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
        let header = records::write_plain::<F, M>(
            &mut self.flash,
            keys,
            &cfg,
            slot,
            target,
            seq,
            epoch,
            &body,
        )?;
        let stale = target.other();
        if !records::side_is_erased::<F, M>(&mut self.flash, &cfg, slot, stale)? {
            records::erase_side::<F, M>(&mut self.flash, &cfg, slot, stale)?;
        }
        self.table.set(
            slot,
            &cfg,
            Some(Elected {
                side: target,
                header,
            }),
        );
        Ok(())
    }

    /// Write a device-keyed filler record into one slot.
    ///
    /// An attacker without the eFuse key cannot distinguish filler from a real record; the
    /// device can, with one HKDF and one AEAD open and no PIN. Filler consumes a
    /// `seal_seq` like any other record, so sequence-number gaps do not betray occupancy
    /// either.
    fn write_filler(&mut self, slot: SlotId) -> Result<(), SErr<F, M>> {
        let keys = self.keys.as_ref().ok_or(StorageError::WrongState)?;
        let key = Zeroizing::new(*keys.filler_root);
        let epoch = self.wipe_epoch();
        let pin_gen = self.pin_gen(Identity(0));
        self.reseal(slot, &key, pin_gen, &[], epoch, StaleSide::EraseNow)
    }

    /// F6: filler into every unoccupied slot, and into every canary slot with no identity.
    fn fill_unoccupied(&mut self) -> Result<(), SErr<F, M>> {
        if self.cfg.occupancy != Occupancy::AlwaysFilled {
            return Ok(());
        }
        let cfg = self.cfg;
        for slot in records::all_slots(&cfg) {
            if slot.class() == SlotClass::Superblock {
                continue;
            }
            if self.table.get(slot, &cfg).is_some() {
                continue;
            }
            self.write_filler(slot)?;
        }
        Ok(())
    }
}

/// The ledger is the authority; the superblock is a mirror and the config is the last
/// resort. Never the other way round: a superblock-only rollback to an older mirror must
/// not be able to weaken the effective policy.
fn resolve_policy(
    ledger: Option<&LedgerState>,
    superblock: Option<&Superblock>,
    cfg: &Config,
) -> Policy {
    let fallback = || {
        superblock
            .map(|sb| sb.format_policy)
            .unwrap_or_else(|| cfg.format_policy())
    };
    match ledger {
        None => fallback(),
        Some(l) => match l.policy {
            Some(p) => p,
            // The top cell was malformed. Fail closed to the format-time policy, which is
            // the one policy the store can be held to and which always has wipe ON.
            None => {
                let base = fallback();
                Policy {
                    policy_gen: l.policy_gen(),
                    ..base
                }
            }
        },
    }
}

fn classify(
    has_superblock: bool,
    identities: u8,
    occupied: u8,
    epoch: u64,
    tamper: TamperFlags,
) -> StoreState {
    if let Some(kind) = tamper.iter().find(|k| {
        matches!(
            k,
            TamperKind::LedgerMissing | TamperKind::LedgerAmbiguous | TamperKind::LedgerRollback
        )
    }) {
        return StoreState::Inconsistent(kind);
    }
    if has_superblock && identities > 0 {
        return StoreState::Formatted {
            identities_present: identities,
            occupied_slots: occupied,
        };
    }
    // No identity means no PIN, which means no user secret, which means the store is
    // formattable. A nonzero epoch is the only thing that distinguishes "was used and
    // wiped" from "never used", and it is the reason WIPE does not need to rewrite the
    // superblock to record that it happened.
    if epoch > 0 {
        StoreState::Wiped { epoch }
    } else {
        StoreState::Blank
    }
}

fn unlock_hw<F: Flash, M: DeviceMac>(
    e: SErr<F, M>,
    attempt_consumed: bool,
) -> UnlockError<F::Error, M::Error> {
    match e {
        StorageError::Hardware(source) => UnlockError::Hardware {
            source,
            attempt_consumed,
        },
        other => UnlockError::from(other),
    }
}

fn mount_to_unlock<FE, ME>(e: MountError<FE, ME>) -> UnlockError<FE, ME> {
    match e {
        MountError::Hardware(source) => UnlockError::Hardware {
            source,
            attempt_consumed: true,
        },
        MountError::Invariant(m) => UnlockError::Invariant(m),
        _ => UnlockError::Invariant("remount refused after wipe"),
    }
}

fn fixed_label(label: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let n = label.len().min(out.len());
    if let (Some(dst), Some(src)) = (out.get_mut(..n), label.get(..n)) {
        dst.copy_from_slice(src);
    }
    out
}

/// The ledger head's shape is frozen at 128 bytes and its MAC is its last 16. Asserted
/// here so a change to either is a compile error at the operation layer, not a silent
/// format break discovered on a user's device.
const _: () = assert!(SEQ_RESERVE == 256);
const _: () = assert!(core::mem::size_of::<Option<LedgerHead>>() > 0);
const _: () = assert!(core::mem::size_of::<Option<RecordHeader>>() > 0);
