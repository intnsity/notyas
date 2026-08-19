// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The plaintext counter ledger: guarded bit-clear logs, their fail-closed scan rules,
//! and rotation.
//!
//! The ledger cannot be encrypted. XTS partitions require 16-byte-aligned writes and
//! cannot reprogram individual bits, and progressive bit clearing is the entire mechanism
//! here (ARCHITECTURE.md 2.5, red-team correction). Its content is therefore non-secret
//! by construction and its integrity rests on device-bound guard MACs: an attacker with a
//! programmer can write any bytes they like into it and cannot make them verify.
//!
//! Every scan rule in this module resolves ambiguity in the direction that INCREASES the
//! apparent failure count and DECREASES the effective permissiveness. That asymmetry is
//! the design, not caution: a torn cell must never be able to buy a guess.

use alloc::vec;
use alloc::vec::Vec;

use crate::bytes as by;
use crate::config::Policy;
use crate::crypto::DeviceKeys;
use crate::error::{HardwareFault, StorageError, TamperFlags, TamperKind};
use crate::format::{
    self, AuxHead, LedgerHead, LogSpec, ATTEMPT_ENTRY_LOG, ATTEMPT_SUCCESS_LOG, BOOT_LOG,
    EPOCH_LOG, LEDGER_HEAD_LEN, PIN_GEN_LOG, POLICY_LOG, SEQ_LOG, SEQ_RESERVE,
};
use crate::hal::{DeviceMac, Flash, Region};
use crate::slot::Side;

/// Sector indices inside the ledger region. Sectors 0 and 1 are the rotation pair for the
/// live counter ledger; 2 and 3 are the auxiliary pair that carries the boot log.
const MAIN_SECTORS: [u32; 2] = [0, 1];
const AUX_SECTORS: [u32; 2] = [2, 3];
const SECTOR_LEN: usize = 4096;

/// How one cell read back.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cell {
    Erased,
    Valid,
    Malformed,
}

/// The scanned state of the live ledger sector.
#[derive(Clone, Debug)]
pub(crate) struct LedgerState {
    /// Which sector of the main pair is live.
    pub side: Side,
    pub head: LedgerHead,
    pub epoch_len: u32,
    pub seq_len: u32,
    pub entry_len: u32,
    pub success_len: u32,
    pub pin_gen: [u32; 4],
    /// One past the largest generation ever committed on this device.
    pub pin_gen_next: u32,
    pub policy_consumed: u32,
    /// `None` means the highest non-erased policy cell was malformed and the caller must
    /// fall back to the strict default.
    pub policy: Option<Policy>,
    pub tamper: TamperFlags,
}

impl LedgerState {
    pub fn wipe_epoch(&self) -> u64 {
        self.head.epoch_base.saturating_add(self.epoch_len as u64)
    }

    pub fn seq_high_water(&self) -> u64 {
        self.head
            .seq_base
            .saturating_add(self.seq_len as u64)
            .saturating_mul(SEQ_RESERVE)
    }

    /// `failures = failures_base + len(attempt_entry) - len(attempt_success)`.
    ///
    /// The base exists because with the wipe DISABLED a failure streak is no longer
    /// bounded by the wipe, so the 128-cell log can overflow with no success to rotate it
    /// (Q5.4). On a wipe-enabled device the base is always 0 and the arithmetic is
    /// byte-for-byte what it was before the settable policy landed.
    pub fn failures(&self) -> u32 {
        self.head
            .failures_base
            .saturating_add(self.entry_len)
            .saturating_sub(self.success_len)
    }

    pub fn policy_gen(&self) -> u32 {
        self.head.policy_gen_base.saturating_add(self.policy_consumed)
    }
}

/// The scanned state of the auxiliary sector.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AuxState {
    pub side: Side,
    pub head: AuxHead,
    pub boot_len: u32,
    pub tamper: TamperFlags,
}

impl AuxState {
    pub fn boot_count(&self) -> u64 {
        self.head.boot_base.saturating_add(self.boot_len as u64)
    }
}

fn flash_err<F: Flash, M: DeviceMac>(e: F::Error) -> StorageError<F::Error, M::Error> {
    StorageError::Hardware(HardwareFault::Flash(e))
}

fn read_sector<F: Flash, M: DeviceMac>(
    flash: &mut F,
    sector: u32,
) -> Result<Vec<u8>, StorageError<F::Error, M::Error>> {
    let mut buf = vec![0u8; SECTOR_LEN];
    let off = sector
        .checked_mul(SECTOR_LEN as u32)
        .ok_or(StorageError::Invariant("ledger sector offset overflow"))?;
    flash
        .read(Region::Ledger, off, &mut buf)
        .map_err(flash_err::<F, M>)?;
    Ok(buf)
}

fn classify(raw: &[u8], expect: &[u8]) -> Cell {
    if by::all_ones(raw) {
        Cell::Erased
    } else if crate::crypto::ct_eq(raw, expect) {
        Cell::Valid
    } else {
        Cell::Malformed
    }
}

fn cell_bytes<'a>(sector: &'a [u8], spec: &LogSpec, i: u32) -> Option<&'a [u8]> {
    let off = spec.cell_offset(i)? as usize;
    by::rd(sector, off, spec.cell_len as usize)
}

/// Scan a tick log under the "counts them all" rule: any malformed cell counts as
/// consumed, and the length is the highest non-erased index plus one, so a hole in the
/// middle inflates the count rather than hiding entries behind it.
fn scan_tick_log(
    sector: &[u8],
    spec: &LogSpec,
    guard_key: &[u8; 32],
    side: u8,
    rotation: u32,
    flags: &mut TamperFlags,
) -> u32 {
    let mut highest: Option<u32> = None;
    let mut seen_erased = false;
    for i in 0..spec.cells {
        let expect = format::tick_cell(guard_key, side, rotation, spec.id, i);
        let raw = match cell_bytes(sector, spec, i) {
            Some(r) => r,
            None => break,
        };
        match classify(raw, &expect) {
            Cell::Erased => seen_erased = true,
            Cell::Valid => {
                if seen_erased {
                    flags.insert(TamperKind::LogHole);
                }
                highest = Some(i);
            }
            Cell::Malformed => {
                flags.insert(TamperKind::GuardMismatch);
                if seen_erased {
                    flags.insert(TamperKind::LogHole);
                }
                highest = Some(i);
            }
        }
    }
    highest.map_or(0, |i| i.saturating_add(1))
}

/// Scan the success log under the "truncate there" rule: a malformed cell counts as NOT
/// consumed and everything after the first erased cell is ignored. Paired with the entry
/// log's opposite rule, a torn cell can only ever raise the failure count.
fn scan_success_log(
    sector: &[u8],
    spec: &LogSpec,
    guard_key: &[u8; 32],
    side: u8,
    rotation: u32,
    flags: &mut TamperFlags,
) -> u32 {
    let mut len = 0u32;
    let mut stopped = false;
    for i in 0..spec.cells {
        let expect = format::tick_cell(guard_key, side, rotation, spec.id, i);
        let raw = match cell_bytes(sector, spec, i) {
            Some(r) => r,
            None => break,
        };
        match classify(raw, &expect) {
            Cell::Valid if !stopped => len = i.saturating_add(1),
            Cell::Valid => flags.insert(TamperKind::LogHole),
            Cell::Erased => stopped = true,
            Cell::Malformed => {
                flags.insert(TamperKind::GuardMismatch);
                stopped = true;
            }
        }
    }
    len
}

/// Scan the `pin_gen_log`. Malformed cells are ignored and flagged: an uncommitted
/// generation must never enter the current set, which is what makes CHANGE-PIN's single
/// cell program a true commit point.
fn scan_pin_gen_log(
    sector: &[u8],
    guard_key: &[u8; 32],
    side: u8,
    rotation: u32,
    head: &LedgerHead,
    flags: &mut TamperFlags,
) -> ([u32; 4], u32) {
    let mut current = [0u32; 4];
    for (i, slot) in current.iter_mut().enumerate() {
        *slot = head
            .pin_gen_current
            .get(i)
            .copied()
            .unwrap_or(0)
            .min(u32::MAX as u64) as u32;
    }
    let mut highest = current.iter().copied().max().unwrap_or(0);
    let mut seen_erased = false;
    for i in 0..PIN_GEN_LOG.cells {
        let raw = match cell_bytes(sector, &PIN_GEN_LOG, i) {
            Some(r) => r,
            None => break,
        };
        if by::all_ones(raw) {
            seen_erased = true;
            continue;
        }
        if seen_erased {
            flags.insert(TamperKind::LogHole);
        }
        match format::parse_pin_gen_cell(raw, guard_key, side, rotation, i) {
            Some((identity, new_gen)) => {
                if let Some(slot) = current.get_mut(identity as usize) {
                    *slot = new_gen;
                } else {
                    flags.insert(TamperKind::GuardMismatch);
                }
                highest = highest.max(new_gen);
            }
            None => flags.insert(TamperKind::GuardMismatch),
        }
    }
    (current, highest.saturating_add(1))
}

/// Scan the `policy_log`. The effective policy is the highest-index well-formed cell; a
/// malformed cell at the top counts as consumed, flags tamper and forces the strict
/// default, so glitching a cell during a "turn wipe back on" write cannot preserve an
/// "off" policy.
fn scan_policy_log(
    sector: &[u8],
    guard_key: &[u8; 32],
    side: u8,
    rotation: u32,
    head: &LedgerHead,
    flags: &mut TamperFlags,
) -> (u32, Option<Policy>) {
    let mut consumed = 0u32;
    let mut top: Option<Option<Policy>> = None;
    let mut seen_erased = false;
    for i in 0..POLICY_LOG.cells {
        let raw = match cell_bytes(sector, &POLICY_LOG, i) {
            Some(r) => r,
            None => break,
        };
        if by::all_ones(raw) {
            seen_erased = true;
            continue;
        }
        if seen_erased {
            flags.insert(TamperKind::LogHole);
        }
        consumed = i.saturating_add(1);
        let want_gen = head
            .policy_gen_base
            .saturating_add(i)
            .saturating_add(1);
        match format::parse_policy_cell(raw, guard_key, side, rotation, i) {
            Some(p) if p.policy_gen == want_gen => top = Some(Some(p)),
            _ => {
                flags.insert(TamperKind::GuardMismatch);
                top = Some(None);
            }
        }
    }
    match top {
        Some(p) => (consumed, p),
        // No cell has been programmed since this rotation: the head carries the policy
        // forward. Its embedded generation must equal the head's base, or the head and
        // the array disagree about where the sequence stands and there is no safe
        // reading of it.
        None => (
            0,
            Policy::decode(&head.policy_current)
                .filter(|p| p.policy_gen == head.policy_gen_base),
        ),
    }
}

/// Read both main-pair heads and elect the live one.
///
/// Returns `Ok(None)` when neither head is valid, which the caller resolves against the
/// records region: blank records means a blank store, non-blank records means the ledger
/// was erased under it, which is the cheap counter-reset attack and is refused.
pub(crate) fn scan<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
) -> Result<Option<LedgerState>, StorageError<F::Error, M::Error>> {
    let mut best: Option<(Side, LedgerHead, Vec<u8>)> = None;
    let mut ambiguous = false;
    for side in Side::BOTH {
        let sector = MAIN_SECTORS
            .get(side as usize)
            .copied()
            .ok_or(StorageError::Invariant("ledger side index"))?;
        let buf = read_sector::<F, M>(flash, sector)?;
        let Some(head) = LedgerHead::decode(&buf, &keys.guard_key) else {
            continue;
        };
        if head.side != side as u8 {
            // A head that claims to be the other side is a copied sector, not a valid one.
            continue;
        }
        match &best {
            Some((_, prev, _)) if prev.rotation_ctr > head.rotation_ctr => {}
            Some((_, prev, _)) if prev.rotation_ctr == head.rotation_ctr => ambiguous = true,
            _ => best = Some((side, head, buf)),
        }
    }
    let Some((side, head, buf)) = best else {
        return Ok(None);
    };

    let mut tamper = TamperFlags::NONE;
    if ambiguous {
        tamper.insert(TamperKind::LedgerAmbiguous);
    }
    let side_u8 = side as u8;
    let rot = head.rotation_ctr;
    let gk = &keys.guard_key;

    let epoch_len = scan_tick_log(&buf, &EPOCH_LOG, gk, side_u8, rot, &mut tamper);
    let seq_len = scan_tick_log(&buf, &SEQ_LOG, gk, side_u8, rot, &mut tamper);
    let entry_len = scan_tick_log(&buf, &ATTEMPT_ENTRY_LOG, gk, side_u8, rot, &mut tamper);
    let success_len = scan_success_log(&buf, &ATTEMPT_SUCCESS_LOG, gk, side_u8, rot, &mut tamper);
    let (pin_gen, pin_gen_next) = scan_pin_gen_log(&buf, gk, side_u8, rot, &head, &mut tamper);
    let (policy_consumed, policy) = scan_policy_log(&buf, gk, side_u8, rot, &head, &mut tamper);

    // The success log can never legitimately outrun the entry log. If it does, something
    // rewrote one of them, and the fail-closed direction is to trust the entry log.
    let success_len = success_len.min(entry_len);

    Ok(Some(LedgerState {
        side,
        head,
        epoch_len,
        seq_len,
        entry_len,
        success_len,
        pin_gen,
        pin_gen_next,
        policy_consumed,
        policy,
        tamper,
    }))
}

/// Erase the non-live sector of the main pair. Completes an interrupted rotation and is
/// idempotent, which is why mount can run it unconditionally.
pub(crate) fn tidy_main_pair<F: Flash, M: DeviceMac>(
    flash: &mut F,
    live: Side,
) -> Result<(), StorageError<F::Error, M::Error>> {
    let sector = MAIN_SECTORS
        .get(live.other() as usize)
        .copied()
        .ok_or(StorageError::Invariant("ledger side index"))?;
    let off = sector
        .checked_mul(SECTOR_LEN as u32)
        .ok_or(StorageError::Invariant("ledger sector offset overflow"))?;
    if !flash
        .is_erased(Region::Ledger, off, SECTOR_LEN as u32)
        .map_err(flash_err::<F, M>)?
    {
        flash
            .erase_sector(Region::Ledger, sector)
            .map_err(flash_err::<F, M>)?;
    }
    Ok(())
}

/// Write a head into a sector, MAC last.
///
/// Splitting the write at the MAC boundary is deliberate: the commit point of a head
/// write must be one program, and a driver is free to reorder or partially apply a
/// 128-byte call. With the split, a cut before the second write leaves a head that cannot
/// verify, which is exactly the outcome the rotation analysis assumes.
fn write_head<F: Flash, M: DeviceMac>(
    flash: &mut F,
    sector: u32,
    bytes: &[u8; LEDGER_HEAD_LEN as usize],
) -> Result<(), StorageError<F::Error, M::Error>> {
    let base = sector
        .checked_mul(SECTOR_LEN as u32)
        .ok_or(StorageError::Invariant("ledger sector offset overflow"))?;
    let body = by::rd(bytes, 0, 0x70).ok_or(StorageError::Invariant("head body"))?;
    let mac = by::rd(bytes, 0x70, 16).ok_or(StorageError::Invariant("head mac"))?;
    flash
        .write(Region::Ledger, base, body)
        .map_err(flash_err::<F, M>)?;
    flash
        .write(
            Region::Ledger,
            base.checked_add(0x70)
                .ok_or(StorageError::Invariant("head mac offset"))?,
            mac,
        )
        .map_err(flash_err::<F, M>)?;
    Ok(())
}

/// Program one cell and verify the read-back.
///
/// The read-back is not belt and braces: a glitched program that leaves a plausible value
/// is precisely the fault this design is built against, and `CellVerify` is how the
/// caller learns the attempt must still be counted.
fn program_cell<F: Flash, M: DeviceMac>(
    flash: &mut F,
    sector: u32,
    offset: u32,
    cell: &[u8],
) -> Result<(), StorageError<F::Error, M::Error>> {
    let base = sector
        .checked_mul(SECTOR_LEN as u32)
        .ok_or(StorageError::Invariant("ledger sector offset overflow"))?;
    let at = base
        .checked_add(offset)
        .ok_or(StorageError::Invariant("cell offset"))?;
    flash
        .write(Region::Ledger, at, cell)
        .map_err(flash_err::<F, M>)?;
    let mut back = [0u8; 16];
    let n = cell.len().min(back.len());
    let dst = by::rd_mut(&mut back, 0, n).ok_or(StorageError::Invariant("cell readback"))?;
    flash.read(Region::Ledger, at, dst).map_err(flash_err::<F, M>)?;
    if !crate::crypto::ct_eq(by::rd(&back, 0, n).unwrap_or(&[]), cell) {
        return Err(StorageError::Hardware(HardwareFault::CellVerify));
    }
    Ok(())
}

fn live_sector(state: &LedgerState) -> Result<u32, &'static str> {
    MAIN_SECTORS
        .get(state.side as usize)
        .copied()
        .ok_or("ledger side index")
}

/// Program the next tick into a tick log. Returns the new length.
pub(crate) fn tick<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    state: &mut LedgerState,
    spec: &LogSpec,
    len_field: fn(&mut LedgerState) -> &mut u32,
) -> Result<u32, StorageError<F::Error, M::Error>> {
    let sector = live_sector(state).map_err(StorageError::Invariant)?;
    let index = *len_field(state);
    let offset = spec
        .cell_offset(index)
        .ok_or(StorageError::Capacity)?;
    let cell = format::tick_cell(
        &keys.guard_key,
        state.side as u8,
        state.head.rotation_ctr,
        spec.id,
        index,
    );
    program_cell::<F, M>(flash, sector, offset, &cell)?;
    let slot = len_field(state);
    *slot = slot.saturating_add(1);
    Ok(*slot)
}

pub(crate) fn tick_epoch<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    state: &mut LedgerState,
) -> Result<(), StorageError<F::Error, M::Error>> {
    tick::<F, M>(flash, keys, state, &EPOCH_LOG, |s| &mut s.epoch_len).map(|_| ())
}

pub(crate) fn tick_seq<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    state: &mut LedgerState,
) -> Result<(), StorageError<F::Error, M::Error>> {
    tick::<F, M>(flash, keys, state, &SEQ_LOG, |s| &mut s.seq_len).map(|_| ())
}

pub(crate) fn tick_attempt_entry<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    state: &mut LedgerState,
) -> Result<(), StorageError<F::Error, M::Error>> {
    tick::<F, M>(flash, keys, state, &ATTEMPT_ENTRY_LOG, |s| &mut s.entry_len).map(|_| ())
}

pub(crate) fn tick_attempt_success<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    state: &mut LedgerState,
) -> Result<(), StorageError<F::Error, M::Error>> {
    tick::<F, M>(flash, keys, state, &ATTEMPT_SUCCESS_LOG, |s| {
        &mut s.success_len
    })
    .map(|_| ())
}

pub(crate) fn attempt_log_full(state: &LedgerState) -> bool {
    state.entry_len >= ATTEMPT_ENTRY_LOG.cells
}

/// True when the tail reserve has been reached and rotation should happen at the next
/// successful unlock.
pub(crate) fn attempt_log_near_full(state: &LedgerState) -> bool {
    state.entry_len
        >= ATTEMPT_ENTRY_LOG
            .cells
            .saturating_sub(format::ATTEMPT_TAIL_RESERVE)
}

/// Program one `pin_gen_log` cell. THE COMMIT POINT of a PIN change.
pub(crate) fn commit_pin_gen<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    state: &mut LedgerState,
    identity: u8,
    new_gen: u32,
) -> Result<(), StorageError<F::Error, M::Error>> {
    let sector = live_sector(state).map_err(StorageError::Invariant)?;
    let index = next_free_cell::<F, M>(flash, sector, &PIN_GEN_LOG)?;
    let offset = PIN_GEN_LOG.cell_offset(index).ok_or(StorageError::Capacity)?;
    let cell = format::pin_gen_cell(
        &keys.guard_key,
        state.side as u8,
        state.head.rotation_ctr,
        index,
        identity,
        new_gen,
    );
    program_cell::<F, M>(flash, sector, offset, &cell)?;
    if let Some(slot) = state.pin_gen.get_mut(identity as usize) {
        *slot = new_gen;
    }
    state.pin_gen_next = state.pin_gen_next.max(new_gen.saturating_add(1));
    Ok(())
}

/// Program one `policy_log` cell. THE COMMIT POINT of SET-POLICY.
pub(crate) fn commit_policy<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    state: &mut LedgerState,
    policy: &Policy,
) -> Result<(), StorageError<F::Error, M::Error>> {
    let sector = live_sector(state).map_err(StorageError::Invariant)?;
    // Scanned rather than taken from the in-RAM length, for the same reason
    // `commit_pin_gen` scans: a previous commit interrupted between the program and the
    // state update would leave the cursor one behind, and re-programming a cell that is
    // already written is the one thing the LEDGER INVARIANT forbids.
    let index = next_free_cell::<F, M>(flash, sector, &POLICY_LOG)?;
    let offset = POLICY_LOG.cell_offset(index).ok_or(StorageError::Capacity)?;
    let cell = format::policy_cell(
        &keys.guard_key,
        state.side as u8,
        state.head.rotation_ctr,
        index,
        &policy.encode(),
    );
    program_cell::<F, M>(flash, sector, offset, &cell)?;
    state.policy_consumed = state.policy_consumed.max(index.saturating_add(1));
    state.policy = Some(*policy);
    Ok(())
}

pub(crate) fn policy_log_full(state: &LedgerState) -> bool {
    state.policy_consumed >= POLICY_LOG.cells
}

/// First erased cell in a log, by scan. Used where the in-RAM length is not authoritative
/// because a previous operation may have been interrupted between the program and the
/// state update.
fn next_free_cell<F: Flash, M: DeviceMac>(
    flash: &mut F,
    sector: u32,
    spec: &LogSpec,
) -> Result<u32, StorageError<F::Error, M::Error>> {
    let buf = read_sector::<F, M>(flash, sector)?;
    let mut highest: Option<u32> = None;
    for i in 0..spec.cells {
        let raw = cell_bytes(&buf, spec, i).ok_or(StorageError::Invariant("cell bytes"))?;
        if !by::all_ones(raw) {
            highest = Some(i);
        }
    }
    Ok(highest.map_or(0, |i| i.saturating_add(1)))
}

/// LEDGER ROTATION (ESP-SEAL.md 4.8), extended to carry `failures_base` (Q5.4) and the
/// policy generation forward.
///
/// R1 erase the target, R2 write its head - THE COMMIT POINT - R3 erase the source. A cut
/// at R1 leaves the live sector untouched; at R2 the head MAC either verifies or it does
/// not; at R3 two valid heads exist and election by `rotation_ctr` is deterministic.
///
/// `new_policy` is the policy that will be in force after the rotation and its
/// `policy_gen` becomes the new base. Callers pass the current effective policy; FORMAT
/// passes the newly chosen one at the next generation, which is what lets a re-format
/// keep the one-way epoch and still install a fresh policy.
pub(crate) fn rotate<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    state: &mut LedgerState,
    carry_failures: u32,
    new_policy: Policy,
) -> Result<(), StorageError<F::Error, M::Error>> {
    let target_side = state.side.other();
    let target = MAIN_SECTORS
        .get(target_side as usize)
        .copied()
        .ok_or(StorageError::Invariant("ledger side index"))?;
    let source = live_sector(state).map_err(StorageError::Invariant)?;

    flash
        .erase_sector(Region::Ledger, target)
        .map_err(flash_err::<F, M>)?;

    let policy = new_policy.encode();
    let mut pin_gen_current = [0u64; 4];
    for (dst, src) in pin_gen_current.iter_mut().zip(state.pin_gen.iter()) {
        *dst = *src as u64;
    }
    let head = LedgerHead {
        side: target_side as u8,
        rotation_ctr: state.head.rotation_ctr.saturating_add(1),
        epoch_base: state.wipe_epoch(),
        seq_base: state
            .head
            .seq_base
            .saturating_add(state.seq_len as u64),
        pin_gen_current,
        failures_base: carry_failures,
        policy_gen_base: new_policy.policy_gen,
        policy_current: policy,
    };
    let bytes = head.encode(&keys.guard_key);
    write_head::<F, M>(flash, target, &bytes)?;

    flash
        .erase_sector(Region::Ledger, source)
        .map_err(flash_err::<F, M>)?;

    let effective = Policy::decode(&policy);
    *state = LedgerState {
        side: target_side,
        head,
        epoch_len: 0,
        seq_len: 0,
        entry_len: 0,
        success_len: 0,
        pin_gen: state.pin_gen,
        pin_gen_next: state.pin_gen_next,
        policy_consumed: 0,
        policy: effective,
        tamper: state.tamper,
    };
    Ok(())
}

/// Create the main ledger from nothing. Only FORMAT on a truly blank store reaches this.
pub(crate) fn create<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    policy: &Policy,
) -> Result<LedgerState, StorageError<F::Error, M::Error>> {
    for sector in MAIN_SECTORS {
        flash
            .erase_sector(Region::Ledger, sector)
            .map_err(flash_err::<F, M>)?;
    }
    let head = LedgerHead {
        side: Side::A as u8,
        rotation_ctr: 1,
        epoch_base: 0,
        seq_base: 0,
        pin_gen_current: [0; 4],
        failures_base: 0,
        policy_gen_base: 0,
        policy_current: policy.encode(),
    };
    let sector = MAIN_SECTORS
        .first()
        .copied()
        .ok_or(StorageError::Invariant("ledger side index"))?;
    let bytes = head.encode(&keys.guard_key);
    write_head::<F, M>(flash, sector, &bytes)?;
    Ok(LedgerState {
        side: Side::A,
        head,
        epoch_len: 0,
        seq_len: 0,
        entry_len: 0,
        success_len: 0,
        pin_gen: [0; 4],
        pin_gen_next: 1,
        policy_consumed: 0,
        policy: Some(*policy),
        tamper: TamperFlags::NONE,
    })
}

// ---------------------------------------------------------------------------
// Auxiliary sector: the boot log
// ---------------------------------------------------------------------------

pub(crate) fn scan_aux<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
) -> Result<Option<AuxState>, StorageError<F::Error, M::Error>> {
    let mut best: Option<(Side, AuxHead, Vec<u8>)> = None;
    for side in Side::BOTH {
        let sector = AUX_SECTORS
            .get(side as usize)
            .copied()
            .ok_or(StorageError::Invariant("aux side index"))?;
        let buf = read_sector::<F, M>(flash, sector)?;
        let Some(head) = AuxHead::decode(&buf, &keys.guard_key) else {
            continue;
        };
        if head.side != side as u8 {
            continue;
        }
        match &best {
            Some((_, prev, _)) if prev.rotation_ctr >= head.rotation_ctr => {}
            _ => best = Some((side, head, buf)),
        }
    }
    let Some((side, head, buf)) = best else {
        return Ok(None);
    };
    let mut tamper = TamperFlags::NONE;
    let boot_len = scan_tick_log(
        &buf,
        &BOOT_LOG,
        &keys.guard_key,
        side as u8,
        head.rotation_ctr,
        &mut tamper,
    );
    Ok(Some(AuxState {
        side,
        head,
        boot_len,
        tamper,
    }))
}

pub(crate) fn create_aux<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    boot_base: u64,
) -> Result<AuxState, StorageError<F::Error, M::Error>> {
    for sector in AUX_SECTORS {
        flash
            .erase_sector(Region::Ledger, sector)
            .map_err(flash_err::<F, M>)?;
    }
    let head = AuxHead {
        side: Side::A as u8,
        rotation_ctr: 1,
        boot_base,
        acknowledged_at: 0,
    };
    let sector = AUX_SECTORS
        .first()
        .copied()
        .ok_or(StorageError::Invariant("aux side index"))?;
    let bytes = head.encode(&keys.guard_key);
    write_head::<F, M>(flash, sector, &bytes)?;
    Ok(AuxState {
        side: Side::A,
        head,
        boot_len: 0,
        tamper: TamperFlags::NONE,
    })
}

/// Program one boot cell, rotating the auxiliary pair when the array is exhausted.
pub(crate) fn tick_boot<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    state: &mut AuxState,
) -> Result<u64, StorageError<F::Error, M::Error>> {
    if state.boot_len >= BOOT_LOG.cells {
        rotate_aux::<F, M>(flash, keys, state)?;
    }
    let sector = AUX_SECTORS
        .get(state.side as usize)
        .copied()
        .ok_or(StorageError::Invariant("aux side index"))?;
    let index = state.boot_len;
    let offset = BOOT_LOG.cell_offset(index).ok_or(StorageError::Capacity)?;
    let cell = format::tick_cell(
        &keys.guard_key,
        state.side as u8,
        state.head.rotation_ctr,
        BOOT_LOG.id,
        index,
    );
    program_cell::<F, M>(flash, sector, offset, &cell)?;
    state.boot_len = index.saturating_add(1);
    Ok(state.boot_count())
}

/// Record the boot index the owner marked as seen (VERIFY.md 6.3).
///
/// The mark lives in the auxiliary head, and a head is only ever written into a freshly
/// erased sector, so setting it IS a rotation - the same single-head-write commit point
/// the boot log already relies on, carrying the count across in `boot_base` exactly as an
/// exhausted-array rotation does. A cut before that write leaves the old side
/// authoritative with the old mark; a cut after leaves the new side, which carries the
/// higher `rotation_ctr` and wins the scan. No intermediate state moves the count.
pub(crate) fn set_acknowledged<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    state: &mut AuxState,
    at: u64,
) -> Result<(), StorageError<F::Error, M::Error>> {
    rotate_aux_to::<F, M>(flash, keys, state, at)
}

fn rotate_aux<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    state: &mut AuxState,
) -> Result<(), StorageError<F::Error, M::Error>> {
    let keep = state.head.acknowledged_at;
    rotate_aux_to::<F, M>(flash, keys, state, keep)
}

/// Flip the auxiliary pair to its other side, installing `acknowledged_at` in the new
/// head. The only writer of an auxiliary head after `create_aux`.
fn rotate_aux_to<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    state: &mut AuxState,
    acknowledged_at: u64,
) -> Result<(), StorageError<F::Error, M::Error>> {
    let target_side = state.side.other();
    let target = AUX_SECTORS
        .get(target_side as usize)
        .copied()
        .ok_or(StorageError::Invariant("aux side index"))?;
    let source = AUX_SECTORS
        .get(state.side as usize)
        .copied()
        .ok_or(StorageError::Invariant("aux side index"))?;
    flash
        .erase_sector(Region::Ledger, target)
        .map_err(flash_err::<F, M>)?;
    let head = AuxHead {
        side: target_side as u8,
        rotation_ctr: state.head.rotation_ctr.saturating_add(1),
        boot_base: state.boot_count(),
        acknowledged_at,
    };
    let bytes = head.encode(&keys.guard_key);
    write_head::<F, M>(flash, target, &bytes)?;
    flash
        .erase_sector(Region::Ledger, source)
        .map_err(flash_err::<F, M>)?;
    *state = AuxState {
        side: target_side,
        head,
        boot_len: 0,
        tamper: state.tamper,
    };
    Ok(())
}

/// Erase the non-live sector of the auxiliary pair.
pub(crate) fn tidy_aux_pair<F: Flash, M: DeviceMac>(
    flash: &mut F,
    live: Side,
) -> Result<(), StorageError<F::Error, M::Error>> {
    let sector = AUX_SECTORS
        .get(live.other() as usize)
        .copied()
        .ok_or(StorageError::Invariant("aux side index"))?;
    let off = sector
        .checked_mul(SECTOR_LEN as u32)
        .ok_or(StorageError::Invariant("aux sector offset"))?;
    if !flash
        .is_erased(Region::Ledger, off, SECTOR_LEN as u32)
        .map_err(flash_err::<F, M>)?
    {
        flash
            .erase_sector(Region::Ledger, sector)
            .map_err(flash_err::<F, M>)?;
    }
    Ok(())
}
