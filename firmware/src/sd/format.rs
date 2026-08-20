// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The one write this device makes that it cannot undo and cannot read back: a fresh FAT
//! filesystem inside a card's EXISTING partition.
//!
//! Read [`super::mount`]'s "what is deliberately not done here" first. This module is the
//! narrow exception it names, and every property that paragraph protected is held here by
//! the route rather than by the absence of one.
//!
//! # Neither ESP-IDF wrapper can be used, for two independent reasons
//!
//! The standing constraint is **filesystem only**: no partition is created, deleted,
//! resized or retyped. ESP-IDF offers two ways to format a card and both break it.
//!
//! - `format_if_mount_failed` calls `partition_card` (`vfs_fat_sdmmc.c`), which runs
//!   `f_fdisk(pdrv, {100,0,0,0}, buf)` - an explicit MBR rewrite - before `f_mkfs`.
//! - `esp_vfs_fat_sdcard_format[_cfg]` skips `f_fdisk` but calls `f_mkfs` with
//!   `MKFS_PARM{FM_ANY, ...}` and no `FM_SFD`, against ESP-IDF's `VolToPart` table, whose
//!   entries are `{pdrv, 0}` - partition index 0, "auto". With `ipart == 0` and `FM_SFD`
//!   clear, `f_mkfs` takes its "volume as a new single partition" branch and calls
//!   `create_partition()`, writing a fresh MBR. It is also documented to work only on an
//!   ALREADY MOUNTED volume and returns `ESP_ERR_INVALID_STATE` otherwise - which makes it
//!   useless by construction for the only card anyone would want to format.
//!
//! So the write is three calls of our own: bring the slot up at block level
//! ([`RawCard`]), point one FatFs logical drive at the partition the user consented to,
//! and call `f_mkfs` directly. With `ipart != 0`, `f_mkfs` reads the existing MBR and
//! takes `b_vol` and `sz_vol` straight out of that entry (ff.c), so the geometry is not
//! its to choose.
//!
//! # The one byte of the table that does change, stated because it does
//!
//! After the volume is built, `f_mkfs` reads sector 0, writes the new filesystem's type
//! byte into the partition entry it just formatted, and writes sector 0 back ("Update
//! system ID in the partition table", ff.c). Start sector, sector count, the other three
//! entries and the signature are untouched. The screen says this in as many words; a
//! feature that claimed "the partition table is not written" would be lying by one byte,
//! and one byte is enough to make the rest of the claim worthless.
//!
//! # Allocation unit: pass zero, and pass it directly
//!
//! `esp_vfs_fat_get_allocation_unit_size` raises a requested 0 up to the sector size, 512.
//! FatFs's automatic cluster sizing runs ONLY when `au_size == 0`, so handing the IDF
//! wrappers a zero does not get auto-selection - it pins 512-byte clusters, which on a
//! 32 GB card is a legal and pathological FAT32 with roughly 62 million clusters and a
//! quarter-gigabyte FAT. Calling `f_mkfs` directly with `au_size: 0` gets the real thing.
//! A FIXED unit would be worse still: it disables every "shrink the cluster and retry"
//! path inside `f_mkfs`, so one hardcoded number would abort outright on small cards.
//!
//! # What can still go wrong, and why the failure has two shapes
//!
//! Write protect is invisible to this firmware: `ff_sdmmc_status` never returns
//! `STA_PROTECT` and the slot's `wp` line is `GPIO_NUM_NC` on both boards. A physically
//! locked card therefore fails INSIDE `f_mkfs`, not before it, and possibly after some
//! sectors have already been overwritten. `FormatOutcome::Failed`'s `wrote` is that
//! distinction, and it
//! exists so the screen can tell a user whose card was left untouched from a user whose
//! card was left in a worse state than it was found in. Guessing that apart on the panel
//! is not an option: the second user has to know to stop using the card.

use std::ffi::CString;

use esp_idf_svc::sys;
use notyas_ui::{FormatOffer, FormatOutcome, FormatRefusal, FormatTarget};

use super::mount::{self, Card, CardError};
use super::pins;
use super::probe::{self, Capacity, Refusal, Verdict, SECTOR_BYTES};

/// `FM_FAT | FM_FAT32` from `ff.h`. FAT12 and FAT16 come along with `FM_FAT`: `f_mkfs`
/// starts at FAT16, drops to FAT12 for a tiny volume and escalates to FAT32 once the
/// cluster count passes `MAX_FAT16`. Written out because bindgen does not export the
/// `#define`s of a header it only parses for types, and because naming them here puts the
/// one decision - "any FAT this build can mount, and nothing else" - next to its reason.
/// `FM_EXFAT` is deliberately absent: `FF_FS_EXFAT` is 0 in this build, so a card
/// formatted exFAT would be a card this device had just made unreadable.
const FM_FAT: u8 = 0x01;
const FM_FAT32: u8 = 0x02;

/// `FR_OK` from `ff.h`. Every other `FRESULT` is reported by number rather than guessed
/// at, on `mount::classify`'s rule.
const FR_OK: u32 = 0;

/// Bytes of scratch handed to `f_mkfs`. ESP-IDF's own format path uses exactly this, and
/// matching it is deliberate: the buffer is where the FAT tables are staged, a smaller one
/// costs write transactions and a larger one costs the framebuffer's heap.
const WORK_BYTES: usize = 4096;

/// The drive number that means "no free FatFs volume" (`diskio_impl.h`).
const DRIVE_NOT_USED: u8 = 0xFF;

/// Refuse, with the frozen sentence the screen will draw and the machine detail this side
/// is the only one that knows.
///
/// The vocabulary is `notyas_ui`'s throughout this module rather than a set of types of
/// its own. There is exactly one consumer - `crate::flow` hands these straight to the
/// screen - and an intermediate copy of five strings would be five strings that could
/// drift from the ones the panel measures its layout against.
fn refuse(why: FormatRefusal, note: String) -> FormatOffer {
    FormatOffer::Refused { why, note }
}

/// The pure verdict, as the screen names it. The count rides along because
/// [`FormatRefusal::SeveralPartitions`] states it.
fn as_refusal(why: Refusal, count: u8) -> FormatRefusal {
    match why {
        Refusal::NoTable => FormatRefusal::NoPartitionTable,
        Refusal::Gpt => FormatRefusal::Gpt,
        Refusal::NoPartitions => FormatRefusal::NoPartitions,
        Refusal::Several => FormatRefusal::SeveralPartitions(count),
        Refusal::Extended => FormatRefusal::ExtendedPartition,
        Refusal::Damaged => FormatRefusal::TableDamaged,
        Refusal::TooSmall => FormatRefusal::TooSmall,
    }
}

/// Look at the card and decide whether formatting it could help.
///
/// Writes nothing, on any path. Reads exactly one sector, and only after a normal mount
/// has been tried and has failed - which is what makes the first refusal below possible at
/// all, and that refusal is the most valuable line of this function: a card that works is
/// a card this device will not offer to erase.
pub fn probe() -> FormatOffer {
    let Some(slot) = pins::SLOT else {
        return refuse(FormatRefusal::NoSlot, String::from(pins::SOURCE));
    };

    match Card::mount() {
        Ok(card) => {
            drop(card);
            return refuse(FormatRefusal::CardAlreadyReadable, String::new());
        }
        // Neither of these can be reached from the shipped screens - `pins::SLOT` was
        // matched above, and a format is never opened from inside a card flow - and each
        // gets its OWN sentence anyway. Folding them together would mean one of the two
        // was reported with the other's words, and a device that says something false in a
        // branch nobody expects to reach is a device that says something false.
        Err(e @ CardError::NoSlot) => return refuse(FormatRefusal::NoSlot, format!("{e}")),
        Err(e @ CardError::AlreadyMounted) => {
            return refuse(FormatRefusal::Busy, format!("{e}"));
        }
        // The most important refusal in the function after `CardAlreadyReadable`, and the
        // one every build hit until `CONFIG_FATFS_LFN_HEAP=y` was added: without long
        // names `Card::mount` fails before it powers the slot, so EVERY card looks
        // unreadable. Formatting one would erase somebody's data to work around a missing
        // sdkconfig line and leave the device exactly as unable to read it. The compile
        // gate at `mount::LONG_NAMES` now stops such an image from existing, so this arm
        // is unreachable rather than routine - and it stays, because the cost of keeping
        // it is one match arm and the cost of dropping it is erasing a card by default if
        // the gate is ever weakened.
        Err(CardError::ShortNamesOnly) => {
            return refuse(
                FormatRefusal::FirmwareCannotRead,
                String::from(mount::LONG_NAMES_FIX),
            );
        }
        Err(CardError::NoCard(code)) => {
            return refuse(FormatRefusal::NoCard, format!("esp_err=0x{code:x}"));
        }
        // The bus came up, the card answered, and no filesystem could be mounted on what
        // it holds. THIS is the state a format might repair - and might not, because
        // ESP-IDF collapses "no filesystem", "a filesystem I cannot read" and "this card
        // is failing" into one `ESP_FAIL`. The two reads below are what separate them.
        Err(CardError::Unreadable(_) | CardError::Driver(_)) => {}
    }

    let mut card = match RawCard::open(&slot) {
        Ok(card) => card,
        // The card answered `esp_vfs_fat_sdmmc_mount` a moment ago and will not answer
        // now. That is hardware, not a filesystem.
        Err(note) => return refuse(FormatRefusal::Hardware, note),
    };

    let mut sector = [0u8; SECTOR_BYTES];
    if let Err(code) = card.read_sector(0, &mut sector) {
        // The one unambiguous hardware verdict this device can reach: the card initialised
        // and then would not hand back its very first sector. A format writes to that same
        // region, so it would fail too - after destroying whatever a recovery tool might
        // still have got out.
        return refuse(FormatRefusal::Hardware, format!("esp_err=0x{code:x}"));
    }

    let capacity = Capacity::of(card.sectors());
    match probe::read_table(&sector, card.sectors()) {
        Verdict::Format(target) => {
            log::info!(
                "card: {capacity} card, partition {} at LBA {} ({} sectors), type 0x{:02x} - \
                 formattable",
                target.index,
                target.start_lba,
                target.sectors,
                target.kind
            );
            FormatOffer::Ready(FormatTarget {
                partition: target.index,
                capacity: capacity.to_string(),
                word: capacity.word(),
                holds: String::from(probe::kind_label(target.kind)),
                volume: Capacity::of(u64::from(target.sectors)).to_string(),
            })
        }
        Verdict::Refuse(why, count) => {
            log::warn!("card: {capacity} card refused for formatting: {why:?}");
            refuse(as_refusal(why, count), String::new())
        }
    }
}

/// Write a fresh FAT filesystem into partition `partition` of the card whose capacity
/// renders as `word`.
///
/// Both arguments are re-derived from the card in the slot NOW and compared before
/// anything is written. That is not ceremony: a card can be swapped between the consent
/// sheet and the tap that follows it, and this is the only thing standing between that and
/// erasing a card nobody consented to.
///
/// The whole read half of [`probe`] runs again here for the same reason. Consent was given
/// against a partition table that was read before the user started reading the screen.
pub fn format(partition: u8, word: &str) -> FormatOutcome {
    let Some(slot) = pins::SLOT else {
        return refused_write("This board has no card slot this device can use.");
    };
    if mount::is_mounted() {
        // Unreachable from the screens - a format is not reachable from inside an SD flow -
        // and refused rather than trusted, because formatting a volume FatFs holds a live
        // handle on is a filesystem corrupted from two directions at once.
        return refused_write("A card operation is already running.");
    }

    let mut card = match RawCard::open(&slot) {
        Ok(card) => card,
        Err(note) => return refused_write(&note),
    };
    let mut sector = [0u8; SECTOR_BYTES];
    if let Err(code) = card.read_sector(0, &mut sector) {
        return refused_write(&format!(
            "The card would not return its first sector (esp_err=0x{code:x})."
        ));
    }
    let capacity = Capacity::of(card.sectors());
    let target = match probe::read_table(&sector, card.sectors()) {
        Verdict::Format(target) => target,
        Verdict::Refuse(why, _) => {
            return refused_write(&format!("The card is no longer formattable ({why:?})."));
        }
    };
    if target.index != partition || capacity.word() != word {
        // Everything about this line is deliberate. It compares the card's OWN identity,
        // not a handle or a session, because a handle would be identical across a swap.
        return refused_write(
            "The card in the slot is not the card that was checked. Take it out, put it \
             back in, and start again.",
        );
    }

    // Everything above this line reads. Everything below it writes.
    let drive = match Drive::claim(&mut card) {
        Ok(drive) => drive,
        Err(note) => return refused_write(&note),
    };
    log::warn!(
        "card: formatting partition {} of {capacity} at LBA {} ({} sectors) as FAT",
        target.index,
        target.start_lba,
        target.sectors
    );
    match drive.mkfs(target.index) {
        Ok(()) => {
            log::warn!("card: partition {} of {capacity} formatted", target.index);
            FormatOutcome::Done(format!(
                "The {capacity} card now holds one empty FAT filesystem in partition {}.",
                target.index
            ))
        }
        Err(res) => {
            log::error!("card: f_mkfs failed (FRESULT={res})");
            FormatOutcome::Failed {
                // `f_mkfs` writes the reserved area, both FATs and the root directory
                // before it touches the partition table, so ANY failure after it is
                // entered may have left sectors overwritten. No `FRESULT` means "and
                // nothing was written", so none is claimed. The write-protect hint is here
                // rather than in the screen's frozen copy because it is the likeliest
                // cause and this firmware cannot see the switch: the `wp` line is not
                // routed on either board, so a locked card gets this far and fails.
                why: format!(
                    "The card refused the write (FatFs error {res}). A write-protect switch \
                     on the card or its adapter fails like this."
                ),
                wrote: true,
            }
        }
    }
}

/// A format that was refused BEFORE anything was written.
///
/// The constructor exists so that `wrote: false` is stated once, in the one place that can
/// honestly state it, rather than at each of the six sites that need it - where the
/// seventh would eventually be written as `true` by accident, or worse, the other way
/// round.
fn refused_write(why: &str) -> FormatOutcome {
    log::error!("card: format refused before any write: {why}");
    FormatOutcome::Failed { why: String::from(why), wrote: false }
}

// ---------------------------------------------------------------------------------------
// The slot, without a filesystem
// ---------------------------------------------------------------------------------------

/// An initialised card at block level: no VFS, no FatFs, no mount point.
///
/// This is what `esp_vfs_fat_sdmmc_mount` does before it hands the card to FatFs, and the
/// reason it is done by hand is that the mount cannot survive a card with no filesystem -
/// its cleanup path frees the card structure and deinitialises the host before returning,
/// so there is nothing left to format. `sdmmc_card_init` succeeds on a card holding
/// nothing at all, which is exactly the case this feature exists for.
///
/// The host is deinitialised by `Drop`, on [`Card`]'s reasoning: a slot left initialised
/// after an early return is a slot the next mount cannot have.
struct RawCard {
    card: Box<sys::sdmmc_card_t>,
    host: sys::sdmmc_host_t,
}

impl RawCard {
    /// Bring the slot up and let the card identify itself. The sentence in the error is
    /// for the panel.
    fn open(slot: &pins::Slot) -> Result<RawCard, String> {
        let host = mount::host_config(slot);
        let slot_config = mount::slot_config(slot);
        // The airgap cross-check, on the mount path's rule: printed against the numbers
        // about to be handed to the driver rather than against a copy.
        log::info!("{}", pins::note());

        // SAFETY: `host.init` is `sdmmc_host_init`, taking no arguments.
        let err = unsafe { (host.init.expect("host_config always sets init"))() };
        if err != sys::ESP_OK {
            return Err(format!("The card slot would not start (esp_err=0x{err:x})."));
        }
        // From here on the host is initialised, so every exit has to deinitialise it. The
        // guard is built NOW, holding a zeroed card, so that the two failures below unwind
        // through its `Drop` rather than through a hand-written cleanup path.
        // SAFETY: `sdmmc_card_t` is a C aggregate of scalars and arrays with no niche and
        // no invalid bit patterns; `sdmmc_card_init` overwrites all of it.
        let mut raw = RawCard { card: Box::new(unsafe { core::mem::zeroed() }), host };

        // SAFETY: `slot_config` outlives the call and is the type this API documents for
        // an SDMMC slot.
        let err = unsafe { sys::sdmmc_host_init_slot(raw.host.slot, &slot_config) };
        if err != sys::ESP_OK {
            return Err(format!("The card slot would not start (esp_err=0x{err:x})."));
        }
        // SAFETY: both pointers are to live locals that outlive the call.
        let err = unsafe { sys::sdmmc_card_init(&raw.host, raw.card.as_mut()) };
        if err != sys::ESP_OK {
            return Err(format!("The card did not answer (esp_err=0x{err:x})."));
        }
        Ok(raw)
    }

    /// The card's capacity in 512-byte sectors.
    ///
    /// `csd.capacity` counts sectors of `csd.sector_size`, which is 512 for every SD card,
    /// but the arithmetic is written out rather than assumed: this number is the only
    /// bound on a partition table's claims, and a bound computed from an assumption is not
    /// a bound.
    fn sectors(&self) -> u64 {
        let csd = self.card.csd;
        let bytes = u64::try_from(csd.capacity).unwrap_or(0)
            * u64::try_from(csd.sector_size).unwrap_or(0);
        bytes / SECTOR_BYTES as u64
    }

    /// Read one 512-byte sector. The `Err` is the driver's own code, for the log and for
    /// the sentence that quotes it.
    fn read_sector(&mut self, lba: u32, out: &mut [u8; SECTOR_BYTES]) -> Result<(), sys::esp_err_t> {
        // SAFETY: `out` is 512 bytes, which is one sector of `sector_size` on every SD
        // card this driver initialises, and `self.card` was written by a successful
        // `sdmmc_card_init`.
        let err = unsafe {
            sys::sdmmc_read_sectors(
                self.card.as_mut(),
                out.as_mut_ptr().cast(),
                usize::try_from(lba).unwrap_or(0),
                1,
            )
        };
        if err == sys::ESP_OK {
            Ok(())
        } else {
            Err(err)
        }
    }
}

impl Drop for RawCard {
    fn drop(&mut self) {
        // `FLAG_DEINIT_ARG` is set by `mount::host_config`, so the slot-taking arm of the
        // union is the live one - the same choice `call_host_deinit` makes in ESP-IDF.
        // SAFETY: the host was initialised by `open`, which is the only constructor, and
        // this is the only release.
        if let Some(deinit) = unsafe { self.host.__bindgen_anon_1.deinit_p } {
            let err = unsafe { deinit(self.host.slot) };
            if err != sys::ESP_OK {
                log::error!("card: slot deinit failed (esp_err=0x{err:x})");
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// One FatFs logical drive, pointed at one partition
// ---------------------------------------------------------------------------------------

/// A FatFs volume borrowed for the length of one `f_mkfs`, and put back exactly as found.
///
/// Two pieces of global state are touched and both are restored by `Drop`: the disk-I/O
/// registration for the drive number, and its row of `VolToPart`. That row is what makes
/// the whole feature possible - `LD2PT(vol)` is where `f_mkfs` reads the partition index
/// from, and the difference between 0 and 1 is the difference between "rewrite the
/// partition table" and "write inside the partition that is already there". Leaving it at
/// a forced index afterwards would silently change what every LATER mount does, which is
/// the class of bug that gets found six months out.
struct Drive<'card> {
    pdrv: u8,
    /// `VolToPart[pdrv]` as it was before this drive was claimed.
    saved: sys::PARTITION,
    /// FatFs holds a raw pointer to the card for as long as the drive is registered, and
    /// nothing in C says so. This says it in the type system instead: a `Drive` cannot
    /// outlive the [`RawCard`] whose slot it was pointed at, so the deinitialise-then-format
    /// ordering bug cannot be written.
    card: core::marker::PhantomData<&'card mut RawCard>,
}

impl<'card> Drive<'card> {
    /// Take a free FatFs drive number and attach `card` to it.
    fn claim(card: &'card mut RawCard) -> Result<Drive<'card>, String> {
        let mut pdrv: u8 = DRIVE_NOT_USED;
        // SAFETY: writes one byte through a valid pointer to a live local.
        let err = unsafe { sys::ff_diskio_get_drive(&mut pdrv) };
        if err != sys::ESP_OK || pdrv == DRIVE_NOT_USED {
            return Err(String::from(
                "No free filesystem slot was available. Nothing was written.",
            ));
        }
        // SAFETY: `pdrv` is a free drive number this call has just been handed, and the
        // card outlives the `Drive` (it is borrowed for the lifetime of this value).
        unsafe {
            sys::ff_diskio_register_sdmmc(pdrv, card.card.as_mut());
        }
        // SAFETY: `VolToPart` is FatFs's own table, defined by ESP-IDF's `diskio.c` with
        // `FF_VOLUMES` entries; `ff_diskio_get_drive` only ever returns an index inside
        // it. bindgen renders `extern PARTITION VolToPart[]` as a zero-length array, so
        // the base address is taken and the element computed here exactly as `LD2PD` and
        // `LD2PT` compute it in C.
        let saved = unsafe { *Self::entry(pdrv) };
        Ok(Drive { pdrv, saved, card: core::marker::PhantomData })
    }

    /// `&mut VolToPart[pdrv]`, as a raw pointer.
    ///
    /// # Safety
    ///
    /// `pdrv` must be a drive number `ff_diskio_get_drive` returned, which is by
    /// construction less than `FF_VOLUMES`.
    unsafe fn entry(pdrv: u8) -> *mut sys::PARTITION {
        core::ptr::addr_of_mut!(sys::VolToPart)
            .cast::<sys::PARTITION>()
            .add(pdrv as usize)
    }

    /// Build a FAT volume inside partition `partition` of this drive.
    ///
    /// `Err` carries the raw `FRESULT`. It is not translated into a sentence here: which
    /// numbers mean what to a user is the caller's judgement, and the caller has the one
    /// fact that decides it - that a write was in flight.
    fn mkfs(&self, partition: u8) -> Result<(), u32> {
        // SAFETY: see `claim`. The row is restored by `Drop` on every path out.
        unsafe {
            *Self::entry(self.pdrv) = sys::PARTITION { pd: self.pdrv, pt: partition };
        }
        let opt = sys::MKFS_PARM {
            // Any FAT this build can mount, and nothing else. FatFs picks between FAT12,
            // FAT16 and FAT32 from the volume's own size.
            fmt: FM_FAT | FM_FAT32,
            // Two FATs, which is what every desktop operating system writes and what a
            // repair tool expects to find a spare copy of.
            n_fat: 2,
            // Let FatFs align the data area to the medium's own block size, which it asks
            // the driver for. Zero here is "ask", not "do not align".
            align: 0,
            // FAT12/FAT16 root directory entries: FatFs's own default of 512.
            n_root: 0,
            // See the module docs. Zero, and reaching `f_mkfs` as zero, is the whole point.
            au_size: 0,
        };
        // "0:", "1:" - the drive string `f_mkfs` parses back into the logical volume whose
        // `VolToPart` row was just written.
        let path = CString::new(format!("{}:", self.pdrv)).expect("a digit and a colon");
        let mut work = vec![0u8; WORK_BYTES];
        // SAFETY: `path` and `opt` outlive the call, and `work` is `WORK_BYTES` long, which
        // is the length passed. `f_mkfs` writes only through the pointers it is given.
        let res = unsafe {
            sys::f_mkfs(
                path.as_ptr(),
                &opt,
                work.as_mut_ptr().cast(),
                WORK_BYTES as u32,
            )
        };
        if res == FR_OK {
            Ok(())
        } else {
            Err(res)
        }
    }
}

impl Drop for Drive<'_> {
    fn drop(&mut self) {
        // SAFETY: see `claim`. Both of these put back state this value took.
        unsafe {
            *Self::entry(self.pdrv) = self.saved;
            // `ff_diskio_unregister` is a macro over `ff_diskio_register(pdrv, NULL)`, and
            // a macro is not something bindgen can export - so the call it expands to is
            // written out.
            sys::ff_diskio_register(self.pdrv, core::ptr::null());
        }
    }
}
