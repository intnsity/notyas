// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The two-slot A/B record engine: election, sealing, opening and cleanup.
//!
//! The whole power-loss story of a single record is one sentence: **the header is written
//! last, the header MAC is its final 16 bytes, and a side is committed if and only if
//! that MAC verifies.** Everything else in this module exists to make that sentence true
//! on real silicon - the erase-before-write, the split header write, and the read-back
//! verification that refuses to leave a faulted record elected.

use alloc::vec;
use alloc::vec::Vec;
use zeroize::Zeroizing;

use crate::bytes as by;
use crate::config::Config;
use crate::crypto::{self, DeviceKeys, RecordInfo};
use crate::error::{Corruption, HardwareFault, StorageError};
use crate::format::{self, RecordHeader, AAD_LEN, HEADER_LEN, HEADER_MAC_OFF, TAG_LEN};
use crate::hal::{DeviceMac, Flash, Region};
use crate::slot::{Side, SlotClass, SlotId};

/// Upper bound on slots of all classes. `Layout::V1` uses 21; the slack costs 11 pointers
/// of table and removes a resize from every future layout tweak.
pub(crate) const MAX_SLOTS: usize = 32;

/// The elected side of one slot, as decided at mount.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Elected {
    pub side: Side,
    pub header: RecordHeader,
}

/// The per-slot election result for the whole store.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SlotTable {
    entries: [Option<Elected>; MAX_SLOTS],
}

impl Default for SlotTable {
    fn default() -> Self {
        SlotTable {
            entries: [None; MAX_SLOTS],
        }
    }
}

impl SlotTable {
    pub fn get(&self, slot: SlotId, cfg: &Config) -> Option<Elected> {
        self.entries
            .get(linear_index(slot, cfg)?)
            .copied()
            .flatten()
    }

    pub fn set(&mut self, slot: SlotId, cfg: &Config, value: Option<Elected>) {
        if let Some(i) = linear_index(slot, cfg) {
            if let Some(e) = self.entries.get_mut(i) {
                *e = value;
            }
        }
    }

}

/// Linear index of a slot within [`SlotTable`].
fn linear_index(slot: SlotId, cfg: &Config) -> Option<usize> {
    let l = &cfg.layout;
    let base: usize = match slot.class() {
        SlotClass::Superblock => 0,
        SlotClass::Canary => 1,
        SlotClass::Payload => 1usize.checked_add(l.canary_slots as usize)?,
        SlotClass::Registry => 1usize
            .checked_add(l.canary_slots as usize)?
            .checked_add(l.payload_slots as usize)?,
    };
    let i = base.checked_add(slot.index() as usize)?;
    if i < MAX_SLOTS {
        Some(i)
    } else {
        None
    }
}

/// Every slot of every class, in a fixed order.
pub(crate) fn all_slots(cfg: &Config) -> impl Iterator<Item = SlotId> + '_ {
    SlotClass::ALL.into_iter().flat_map(move |class| {
        (0..class.count(&cfg.layout)).filter_map(move |i| SlotId::new(class, i, &cfg.layout))
    })
}

/// Payload and registry slots only: the ones a session can read and write.
pub(crate) fn user_slots(cfg: &Config) -> impl Iterator<Item = SlotId> + '_ {
    all_slots(cfg).filter(|s| matches!(s.class(), SlotClass::Payload | SlotClass::Registry))
}

fn flash_err<F: Flash, M: DeviceMac>(e: F::Error) -> StorageError<F::Error, M::Error> {
    StorageError::Hardware(HardwareFault::Flash(e))
}

fn side_offset<F: Flash, M: DeviceMac>(
    cfg: &Config,
    slot: SlotId,
    side: Side,
) -> Result<u32, StorageError<F::Error, M::Error>> {
    slot.side_offset(side, &cfg.layout)
        .ok_or(StorageError::Invariant("slot side offset"))
}

/// Read the 80-byte header of one side.
pub(crate) fn read_header<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    cfg: &Config,
    slot: SlotId,
    side: Side,
) -> Result<Option<RecordHeader>, StorageError<F::Error, M::Error>> {
    let off = side_offset::<F, M>(cfg, slot, side)?;
    let mut raw = [0u8; HEADER_LEN];
    flash
        .read(Region::Records, off, &mut raw)
        .map_err(flash_err::<F, M>)?;
    if !RecordHeader::verify_mac(&raw, &keys.hdr_key) {
        return Ok(None);
    }
    match RecordHeader::decode(&raw) {
        Ok(h) => {
            // The header must describe the slot it was found in. Without this, a whole
            // side copied from another slot would present a header whose MAC verifies.
            if h.slot_class != slot.class() as u8
                || h.slot_index != slot.index()
                || h.slot_side != side as u8
                || h.body_capacity != slot.class().body_capacity(&cfg.layout)
            {
                return Ok(None);
            }
            // The provenance flags must match the key this board actually has. A record
            // sealed with a development key is not a candidate on a production board and
            // vice versa, and saying so here means no crypto is spent finding it out.
            if h.flags != keys.provenance.flags() {
                return Ok(None);
            }
            Ok(Some(h))
        }
        Err(_) => Ok(None),
    }
}

/// True iff the whole side reads back as erased flash (raw view).
pub(crate) fn side_is_erased<F: Flash, M: DeviceMac>(
    flash: &mut F,
    cfg: &Config,
    slot: SlotId,
    side: Side,
) -> Result<bool, StorageError<F::Error, M::Error>> {
    let off = side_offset::<F, M>(cfg, slot, side)?;
    let len = slot.class().side_bytes(&cfg.layout);
    flash
        .is_erased(Region::Records, off, len)
        .map_err(flash_err::<F, M>)
}

pub(crate) fn erase_side<F: Flash, M: DeviceMac>(
    flash: &mut F,
    cfg: &Config,
    slot: SlotId,
    side: Side,
) -> Result<(), StorageError<F::Error, M::Error>> {
    let off = side_offset::<F, M>(cfg, slot, side)?;
    let first = off
        .checked_div(cfg.layout.sector_size)
        .ok_or(StorageError::Invariant("sector size zero"))?;
    for i in 0..slot.class().side_sectors(&cfg.layout) {
        let sector = first
            .checked_add(i)
            .ok_or(StorageError::Invariant("sector index"))?;
        flash
            .erase_sector(Region::Records, sector)
            .map_err(flash_err::<F, M>)?;
    }
    Ok(())
}

/// Ensure a side is erased before it is written to. The RECORDS INVARIANT forbids a
/// second program of any cipher block between erases, so this is not an optimisation to
/// skip when the side "looks" blank.
fn ensure_erased<F: Flash, M: DeviceMac>(
    flash: &mut F,
    cfg: &Config,
    slot: SlotId,
    side: Side,
) -> Result<(), StorageError<F::Error, M::Error>> {
    if !side_is_erased::<F, M>(flash, cfg, slot, side)? {
        erase_side::<F, M>(flash, cfg, slot, side)?;
    }
    Ok(())
}

/// A body that came off flash: secret until proven otherwise, so it is `Zeroizing` even
/// when it turns out to be filler.
pub(crate) type Body<F, M> =
    Result<Zeroizing<Vec<u8>>, StorageError<<F as Flash>::Error, <M as DeviceMac>::Error>>;

/// A body that came off flash and was then either opened or rejected. The outer result is
/// "could the flash be read", the inner one is "did the record make sense": two different
/// questions with two different answers for the product, which is why they are not
/// flattened into one.
pub(crate) type OpenedBody<F, M> = Result<
    Result<Zeroizing<Vec<u8>>, Corruption>,
    StorageError<<F as Flash>::Error, <M as DeviceMac>::Error>,
>;

/// Read the body region of one side.
fn read_body<F: Flash, M: DeviceMac>(
    flash: &mut F,
    cfg: &Config,
    slot: SlotId,
    side: Side,
) -> Body<F, M> {
    let off = side_offset::<F, M>(cfg, slot, side)?;
    let cap = slot.class().body_capacity(&cfg.layout);
    let mut buf = Zeroizing::new(vec![0u8; cap as usize]);
    let at = off
        .checked_add(HEADER_LEN as u32)
        .ok_or(StorageError::Invariant("body offset"))?;
    flash
        .read(Region::Records, at, buf.as_mut_slice())
        .map_err(flash_err::<F, M>)?;
    Ok(buf)
}

/// Build the `RecordInfo` a header derives its key from. There is exactly one place this
/// is constructed, so the header on flash and the key that opens it cannot diverge.
pub(crate) fn record_info(cfg: &Config, keys: &DeviceKeys, header: &RecordHeader) -> RecordInfo {
    let mut domain_prefix = [0u8; 8];
    if let Some(src) = cfg.domain_tag.get(..8) {
        domain_prefix.copy_from_slice(src);
    }
    RecordInfo {
        slot_class: header.slot_class,
        slot_index: header.slot_index,
        slot_side: header.slot_side,
        // The LIVE provenance, never the one the header claims. Deriving it from the
        // header would make the binding circular and let a development-mode build open a
        // production record simply by reading a flag it also wrote. With the live value in
        // the info string, a record sealed at one provenance cannot be opened at another -
        // not "should not", cannot, because the key is different.
        provenance: keys.provenance.tag(),
        wipe_epoch: header.wipe_epoch,
        pin_gen: header.pin_gen,
        seal_seq: header.seal_seq,
        domain_prefix,
    }
}

/// SEAL, steps S3-S9 of ESP-SEAL.md 4.6. The caller owns S1 and S2 (the sequence
/// reservation), because only it holds the ledger.
///
/// Returns the committed header. A successful return means the record is durable: the
/// read-back verification has already passed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_sealed<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    cfg: &Config,
    slot: SlotId,
    target: Side,
    seal_seq: u64,
    wipe_epoch: u64,
    pin_gen: u32,
    key_source: &[u8; 32],
    payload: &[u8],
) -> Result<RecordHeader, StorageError<F::Error, M::Error>> {
    let class = slot.class();
    let cap = class.body_capacity(&cfg.layout) as usize;
    let pt_len = cap
        .checked_sub(TAG_LEN)
        .ok_or(StorageError::Invariant("body capacity underflow"))?;
    if payload.len() > class.max_payload(&cfg.layout) as usize {
        return Err(StorageError::Capacity);
    }

    let header = RecordHeader {
        slot_class: class as u8,
        slot_index: slot.index(),
        slot_side: target as u8,
        flags: RecordHeader::flags_for(keys.provenance),
        kdf: cfg.kdf,
        seal_seq,
        wipe_epoch,
        pin_gen,
        body_capacity: cap as u32,
    };
    let aad = header.aad();
    let info = record_info(cfg, keys, &header);

    // S3: derive twice by independent invocations and compare in constant time. A single
    // fault would have to corrupt both identically.
    let okm = crypto::record_okm(key_source, &keys.kdf_salt, &info);
    let okm2 = crypto::record_okm(key_source, &keys.kdf_salt, &info);
    if !okm.ct_eq(&okm2) {
        return Err(StorageError::Hardware(HardwareFault::DerivationMismatch));
    }

    // S4: frame and seal in place.
    let mut body = Zeroizing::new(vec![0u8; cap]);
    {
        let pt = by::rd_mut(body.as_mut_slice(), 0, pt_len)
            .ok_or(StorageError::Invariant("plaintext window"))?;
        format::frame_plaintext(payload, pt).ok_or(StorageError::Capacity)?;
        let tag = crypto::aead_seal(&okm.key(), &okm.nonce(), &aad, pt)
            .ok_or(StorageError::Invariant("aead seal"))?;
        by::wr(body.as_mut_slice(), pt_len, &tag).ok_or(StorageError::Invariant("tag window"))?;
    }

    write_side_bytes::<F, M>(flash, keys, cfg, slot, target, &header, body.as_slice())?;

    // S8: verify from flash, with the key re-derived from the FLASH-RESIDENT header
    // rather than from the one in RAM.
    verify_written::<F, M>(flash, keys, cfg, slot, target, key_source, payload)?;
    Ok(header)
}

/// The superblock's body is plaintext: there is no PIN at mount time, so there is nothing
/// to seal it under. Its integrity comes from `body_digest` and `header_mac`, both keyed
/// by the device-bound `hdr_key`, so it cannot be edited offline either.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_plain<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    cfg: &Config,
    slot: SlotId,
    target: Side,
    seal_seq: u64,
    wipe_epoch: u64,
    body_content: &[u8],
) -> Result<RecordHeader, StorageError<F::Error, M::Error>> {
    let class = slot.class();
    let cap = class.body_capacity(&cfg.layout) as usize;
    if body_content.len() > cap {
        return Err(StorageError::Capacity);
    }
    let header = RecordHeader {
        slot_class: class as u8,
        slot_index: slot.index(),
        slot_side: target as u8,
        flags: RecordHeader::flags_for(keys.provenance),
        kdf: cfg.kdf,
        seal_seq,
        wipe_epoch,
        pin_gen: 0,
        body_capacity: cap as u32,
    };
    let mut body = vec![0u8; cap];
    by::wr(&mut body, 0, body_content).ok_or(StorageError::Capacity)?;
    write_side_bytes::<F, M>(flash, keys, cfg, slot, target, &header, &body)?;

    // Read back and re-check both MACs. There is no AEAD here, so this is the only
    // independent proof the side landed.
    let back = read_body::<F, M>(flash, cfg, slot, target)?;
    let stored = read_header::<F, M>(flash, keys, cfg, slot, target)?
        .ok_or(StorageError::Hardware(HardwareFault::WriteVerify))?;
    if stored != header
        || !crypto::ct_eq(back.as_slice(), &body)
    {
        return Err(StorageError::Hardware(HardwareFault::WriteVerify));
    }
    Ok(header)
}

/// S5-S7: erase, body, header body, header MAC. The last of those four writes is the
/// commit point, and it is issued as its own call so no driver is free to reorder it into
/// the same program as the rest of the header.
fn write_side_bytes<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    cfg: &Config,
    slot: SlotId,
    target: Side,
    header: &RecordHeader,
    body: &[u8],
) -> Result<(), StorageError<F::Error, M::Error>> {
    ensure_erased::<F, M>(flash, cfg, slot, target)?;
    let off = side_offset::<F, M>(cfg, slot, target)?;
    let body_at = off
        .checked_add(HEADER_LEN as u32)
        .ok_or(StorageError::Invariant("body offset"))?;
    flash
        .write(Region::Records, body_at, body)
        .map_err(flash_err::<F, M>)?;

    let bytes = header.encode(&keys.hdr_key, body);
    let head = by::rd(&bytes, 0, HEADER_MAC_OFF).ok_or(StorageError::Invariant("header body"))?;
    let mac = by::rd(&bytes, HEADER_MAC_OFF, 16).ok_or(StorageError::Invariant("header mac"))?;
    flash
        .write(Region::Records, off, head)
        .map_err(flash_err::<F, M>)?;
    flash
        .write(
            Region::Records,
            off.checked_add(HEADER_MAC_OFF as u32)
                .ok_or(StorageError::Invariant("header mac offset"))?,
            mac,
        )
        .map_err(flash_err::<F, M>)?;
    Ok(())
}

/// S8, the independent post-write verification the red team required.
///
/// Its independence is specific and each part matters: it re-reads from flash rather than
/// trusting RAM, it re-derives the key from the flash-resident header rather than from
/// the in-memory one, and it compares the recovered plaintext to the source in constant
/// time. Its failure action is to erase the side it just wrote, so a faulted write cannot
/// become the elected record.
fn verify_written<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    cfg: &Config,
    slot: SlotId,
    target: Side,
    key_source: &[u8; 32],
    expect: &[u8],
) -> Result<(), StorageError<F::Error, M::Error>> {
    let outcome = (|| -> Result<bool, StorageError<F::Error, M::Error>> {
        let Some(header) = read_header::<F, M>(flash, keys, cfg, slot, target)? else {
            return Ok(false);
        };
        let body = read_body::<F, M>(flash, cfg, slot, target)?;
        match open_body(keys, cfg, &header, key_source, &body) {
            Ok(pt) => Ok(crypto::ct_eq(pt.as_slice(), expect)),
            Err(_) => Ok(false),
        }
    })()?;
    if outcome {
        Ok(())
    } else {
        erase_side::<F, M>(flash, cfg, slot, target)?;
        Err(StorageError::Hardware(HardwareFault::WriteVerify))
    }
}

/// Open a body that has already been read, against a header that has already been
/// validated. Split out so the write-verify path and the read path share one decoder.
pub(crate) fn open_body(
    keys: &DeviceKeys,
    cfg: &Config,
    header: &RecordHeader,
    key_source: &[u8; 32],
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Corruption> {
    // The body digest is NOT checked here. It is checked by the caller, before this
    // function is reached, so that a torn body is a cheap and specific answer rather than
    // an expensive generic one - and computing it twice would be a second HMAC over the
    // whole 4 KiB or 8 KiB side on a device whose entire unlock budget is 1.8 seconds.
    let cap = body.len();
    let ct_len = cap.checked_sub(TAG_LEN).ok_or(Corruption::Geometry)?;
    let mut scratch = Zeroizing::new(vec![0u8; cap]);
    by::wr(scratch.as_mut_slice(), 0, body).ok_or(Corruption::Geometry)?;

    let info = record_info(cfg, keys, header);
    let okm = crypto::record_okm(key_source, &keys.kdf_salt, &info);
    let tag = by::rd_arr::<TAG_LEN>(body, ct_len).ok_or(Corruption::Geometry)?;
    let aad = header.aad();
    let window = by::rd_mut(scratch.as_mut_slice(), 0, ct_len).ok_or(Corruption::Geometry)?;
    if !crypto::aead_open(&okm.key(), &okm.nonce(), &aad, window, &tag) {
        return Err(Corruption::Tag);
    }
    let plain = format::unframe_plaintext(by::rd(scratch.as_slice(), 0, ct_len).unwrap_or(&[]))?;
    Ok(Zeroizing::new(plain.to_vec()))
}

/// Check the body digest of a side without decrypting it. This is what lets the unlock
/// path reject a torn canary BEFORE spending 1.8 seconds on Argon2id.
pub(crate) fn verify_body_digest<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    cfg: &Config,
    slot: SlotId,
    side: Side,
    header: &RecordHeader,
) -> Result<bool, StorageError<F::Error, M::Error>> {
    let body = read_body::<F, M>(flash, cfg, slot, side)?;
    check_body_digest::<F, M>(flash, keys, cfg, slot, side, header, body.as_slice())
}

/// The same check against a body the caller already has in hand.
///
/// Split out because the read path had been reading every side twice and hashing it
/// twice: once to open it and once to check the digest it had just read. Mount does this
/// for every slot, so on the shipped map that was 21 redundant 4 KiB reads and HMACs on
/// every boot.
#[allow(clippy::too_many_arguments)]
fn check_body_digest<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    cfg: &Config,
    slot: SlotId,
    side: Side,
    header: &RecordHeader,
    body: &[u8],
) -> Result<bool, StorageError<F::Error, M::Error>> {
    let want = header.body_digest(&keys.hdr_key, body);
    let off = side_offset::<F, M>(cfg, slot, side)?;
    let mut stored = [0u8; 16];
    flash
        .read(
            Region::Records,
            off.checked_add(0x30)
                .ok_or(StorageError::Invariant("digest offset"))?,
            &mut stored,
        )
        .map_err(flash_err::<F, M>)?;
    Ok(crypto::ct_eq(&want, &stored))
}

/// Read and open one side's record.
pub(crate) fn read_record<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    cfg: &Config,
    slot: SlotId,
    side: Side,
    header: &RecordHeader,
    key_source: &[u8; 32],
) -> OpenedBody<F, M> {
    let body = read_body::<F, M>(flash, cfg, slot, side)?;
    if !check_body_digest::<F, M>(flash, keys, cfg, slot, side, header, body.as_slice())? {
        return Ok(Err(Corruption::BodyDigest));
    }
    Ok(open_body(keys, cfg, header, key_source, body.as_slice()))
}

/// Read the raw body of a side, for the superblock's plaintext parse.
pub(crate) fn read_plain_body<F: Flash, M: DeviceMac>(
    flash: &mut F,
    keys: &DeviceKeys,
    cfg: &Config,
    slot: SlotId,
    side: Side,
    header: &RecordHeader,
) -> OpenedBody<F, M> {
    let body = read_body::<F, M>(flash, cfg, slot, side)?;
    if !check_body_digest::<F, M>(flash, keys, cfg, slot, side, header, body.as_slice())? {
        return Ok(Err(Corruption::BodyDigest));
    }
    Ok(Ok(body))
}

/// Sanity: the AAD length is a frozen 48 bytes and the header is a frozen 80. A change to
/// either is a format change, and this is where the compiler notices.
const _: () = assert!(AAD_LEN == 0x30 && HEADER_LEN == 0x50 && HEADER_MAC_OFF == 0x40);
