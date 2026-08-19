// Copyright (C) 2026 intnsity

// SPDX-License-Identifier: GPL-3.0-or-later

//! Mount on demand, unmount on drop, and never hold either across an idle moment.
//!
//! MILESTONES.md m5 states the requirement twice, once as scope and once as a thing this
//! milestone must not break: "the mount is never held outside an SD flow (asserted in code
//! and tested)". [`Card`] is that assertion. It is the only way to reach the filesystem,
//! it is not `Clone` and not `Send`, and its `Drop` unmounts. A flow that finishes, panics
//! or returns early through `?` has already unmounted by the time control leaves the
//! frame; the only way to keep a mount alive is to keep the value alive, which is visible
//! in the code that does it.
//!
//! [`is_mounted`] exists so a caller can assert the negative - that the device is idle with
//! no card mounted - without being able to reach the mount itself.
//!
//! # What is deliberately not done here
//!
//! **The card is never formatted.** `format_if_mount_failed` is false and there is no code
//! path that sets it. A signer that reformats a card it cannot read would destroy the only
//! copy of a transaction the user was trying to sign, and it would do it in response to
//! input from outside the airgap.
//!
//! **The power gate is never driven.** On the Waveshare 4B the microSD supply is a P-FET
//! with a pulldown, so the card is powered from reset, and the vendor BSP leaves the line
//! alone too (docs/HARDWARE.md). Cycling it would be a change with no evidence behind it,
//! on the one rail whose failure mode is a card that browns out mid-write.
//!
//! **The mount does not survive a card swap.** Nothing here polls card-detect; the card
//! detect line is not routed on either board and the mount lives only inside a flow, so
//! the window in which a swap matters is the window in which the user is watching a
//! progress screen.

use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Instant;

use esp_idf_svc::sys;

use super::pins::{self, NC};

/// Where the volume appears in the VFS. Every path this subsystem builds starts here, and
/// `notyas_wallet::sd::Location::render` is the only thing that builds one.
pub const MOUNT_POINT: &str = "/sd";
const MOUNT_POINT_C: &CStr = c"/sd";

/// Open file descriptors the VFS reserves for this mount.
///
/// Four, not the IDF example's five, and not a larger number for comfort: one file is open
/// at a time in every flow this subsystem has, plus a directory handle during a listing.
/// The rest is margin, and margin here is heap that a 720x720 framebuffer would rather
/// have.
const MAX_OPEN_FILES: i32 = 4;

/// `SDMMC_HOST_FLAG_1BIT`, `_4BIT`, `_DDR`, `_DEINIT_ARG` from
/// `components/sdmmc/include/sd_protocol_types.h`. Written out because they are `BIT(n)`
/// macros, which bindgen cannot evaluate and therefore does not export.
const FLAG_1BIT: u32 = 1 << 0;
const FLAG_4BIT: u32 = 1 << 1;
const FLAG_DDR: u32 = 1 << 4;
const FLAG_DEINIT_ARG: u32 = 1 << 5;

/// Whether this build's FatFs can represent a name longer than 8.3.
///
/// `CONFIG_FATFS_LFN_NONE` is the ESP-IDF default and it is what this build currently has:
/// `sys::CONFIG_FATFS_LFN_NONE` is present in the generated bindings today. Under it FatFs
/// stores and returns short names only, which means `psbt-2026-08-17-signed.psbt` cannot be
/// created and a card written by any desktop operating system lists as a set of mangled
/// stems. Both failures are silent in the sense that matters: the device would look like it
/// worked and the user would look at the wrong file names.
///
/// So the subsystem refuses to mount and says exactly which line is missing, rather than
/// mounting into a filesystem it cannot name things in. The `esp_idf_*` cfgs are the ones
/// esp-idf-sys derives from sdkconfig (the same mechanism behind
/// `esp_idf_esp32p4_selects_rev_less_v3` in esp-idf-hmac); `esp_idf_fatfs_lfn_none` is set
/// today and stops being set the moment the choice moves to `CONFIG_FATFS_LFN_HEAP`.
#[allow(unexpected_cfgs)]
// The lint is waived because this deliberately asks about a cfg the build may NOT set:
// cargo can only know the names a build script actually emitted, and the whole purpose of
// the question is to notice when this one stops being emitted.
pub const LONG_NAMES: bool = !cfg!(esp_idf_fatfs_lfn_none);

/// The sdkconfig change [`LONG_NAMES`] is waiting for. Quoted verbatim in the error so the
/// person reading a boot log does not have to go looking for it.
pub const LONG_NAMES_FIX: &str = "firmware/sdkconfig.base.defaults needs \
     CONFIG_FATFS_LFN_HEAP=y (long file names, allocated on the heap rather than on the \
     main task stack)";

/// True while a [`Card`] is alive.
///
/// `SeqCst` throughout. The cost is irrelevant next to an SD transaction and the ordering
/// question is not worth having: this flag is the interlock that keeps two mounts of the
/// same slot from existing, and a relaxed load that raced would defeat it.
static MOUNTED: AtomicBool = AtomicBool::new(false);
/// Mounts since boot. Evidence for the "never held outside an SD flow" claim: a device
/// left idle does not advance it.
static MOUNTS: AtomicU32 = AtomicU32::new(0);

/// True if a card is mounted right now.
pub fn is_mounted() -> bool {
    MOUNTED.load(Ordering::SeqCst)
}

/// How many times a card has been mounted since boot.
pub fn mounts() -> u32 {
    MOUNTS.load(Ordering::SeqCst)
}

/// Why a card could not be mounted.
///
/// Split by what the user can do about it, because that is what the screen has to say
/// (UX-SCREENS R-23 "Unreadable card", R-24 "No card detected"). The two build-configuration
/// variants can only be produced by a build, never by a user, and they name the fix.
#[derive(Debug)]
pub enum CardError {
    /// This board has no verified microSD wiring in `pins.rs`. Every scaffold board is
    /// here (docs/BOARDS.md marks them UNTESTED) and it is not a runtime fault.
    NoSlot,
    /// The build's FatFs is short-names-only. See [`LONG_NAMES`].
    ShortNamesOnly,
    /// A `Card` already exists. A programming error, not a card fault: the guard is the
    /// mechanism that keeps the mount inside one flow, and two flows want reviewing rather
    /// than a second mount.
    AlreadyMounted,
    /// The slot is empty, or the card did not answer.
    NoCard(sys::esp_err_t),
    /// The bus came up and no FAT filesystem could be mounted on what it found.
    Unreadable(sys::esp_err_t),
    /// Anything else the driver reported.
    Driver(sys::esp_err_t),
}

impl std::fmt::Display for CardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CardError::NoSlot => write!(
                f,
                "no microSD wiring is verified for this board ({})",
                pins::SOURCE
            ),
            CardError::ShortNamesOnly => write!(
                f,
                "this build's FatFs supports 8.3 names only, so a signed transaction \
                 cannot be named: {LONG_NAMES_FIX}"
            ),
            CardError::AlreadyMounted => write!(f, "a card is already mounted"),
            CardError::NoCard(code) => write!(f, "no card in the slot (esp_err=0x{code:x})"),
            CardError::Unreadable(code) => write!(
                f,
                "the card holds no filesystem this device can read (esp_err=0x{code:x})"
            ),
            CardError::Driver(code) => write!(f, "microSD driver failed (esp_err=0x{code:x})"),
        }
    }
}

/// A mounted microSD card.
///
/// Holding one of these is what "inside an SD flow" means. Dropping it unmounts, so a flow
/// cannot leak the mount by returning early, and the raw pointer inside makes the type
/// neither `Send` nor `Sync`, so it cannot be parked in a static or handed to another task.
#[derive(Debug)]
pub struct Card {
    card: *mut sys::sdmmc_card_t,
    at: Instant,
}

impl Card {
    /// Bring the slot up and mount the filesystem on it.
    ///
    /// Mounts eagerly: `esp_vfs_fat_sdmmc_mount` force-mounts, so a card with no readable
    /// filesystem fails HERE, with a code, rather than at the first `open` inside a flow
    /// that has already told the user it was about to write something.
    pub fn mount() -> Result<Card, CardError> {
        let Some(slot) = pins::SLOT else {
            return Err(CardError::NoSlot);
        };
        if !LONG_NAMES {
            return Err(CardError::ShortNamesOnly);
        }
        if MOUNTED.swap(true, Ordering::SeqCst) {
            return Err(CardError::AlreadyMounted);
        }

        // SDMMC_HOST_DEFAULT(), with two departures, both deliberate:
        //
        // - the width flags advertise only the lines this board actually routes, so a
        //   1-bit board can never negotiate a 4-bit transfer onto pins that carry the
        //   panel's sync signals;
        // - the slot index comes from the wiring table rather than from the macro's
        //   SDMMC_HOST_SLOT_1.
        let width_flags = if slot.width >= 4 {
            FLAG_1BIT | FLAG_4BIT
        } else {
            FLAG_1BIT
        };
        let host = sys::sdmmc_host_t {
            flags: width_flags | FLAG_DDR | FLAG_DEINIT_ARG,
            slot: slot.index,
            max_freq_khz: sys::SDMMC_FREQ_DEFAULT as i32,
            io_voltage: 3.3,
            driver_strength: sys::sdmmc_driver_strength_t_SDMMC_DRIVER_STRENGTH_B,
            current_limit: sys::sdmmc_current_limit_t_SDMMC_CURRENT_LIMIT_200MA,
            init: Some(sys::sdmmc_host_init),
            set_bus_width: Some(sys::sdmmc_host_set_bus_width),
            get_bus_width: Some(sys::sdmmc_host_get_slot_width),
            set_bus_ddr_mode: Some(sys::sdmmc_host_set_bus_ddr_mode),
            set_card_clk: Some(sys::sdmmc_host_set_card_clk),
            set_cclk_always_on: Some(sys::sdmmc_host_set_cclk_always_on),
            do_transaction: Some(sys::sdmmc_host_do_transaction),
            // FLAG_DEINIT_ARG is set above, so the driver calls the slot-taking arm of
            // this union. Setting the other arm with that flag set would hand the driver
            // a function of the wrong shape.
            __bindgen_anon_1: sys::sdmmc_host_t__bindgen_ty_1 {
                deinit_p: Some(sys::sdmmc_host_deinit_slot),
            },
            io_int_enable: Some(sys::sdmmc_host_io_int_enable),
            io_int_wait: Some(sys::sdmmc_host_io_int_wait),
            command_timeout_ms: 0,
            get_real_freq: Some(sys::sdmmc_host_get_real_freq),
            input_delay_phase: sys::sdmmc_delay_phase_t_SDMMC_DELAY_PHASE_0,
            set_input_delay: Some(sys::sdmmc_host_set_input_delay),
            dma_aligned_buffer: std::ptr::null_mut(),
            pwr_ctrl_handle: std::ptr::null_mut(),
            get_dma_info: None,
            check_buffer_alignment: Some(sys::sdmmc_host_check_buffer_alignment),
            is_slot_set_to_uhs1: Some(sys::sdmmc_host_is_slot_set_to_uhs1),
        };

        // Card detect and write protect are NOT routed on either board, and the union
        // fields default to zero, which would mean GPIO0. They are set to GPIO_NUM_NC
        // explicitly for that reason; a default here is a wrong pin, not an absent one.
        let nc = sys::gpio_num_t_GPIO_NUM_NC;
        let slot_config = sys::sdmmc_slot_config_t {
            clk: slot.clk(),
            cmd: slot.cmd(),
            d0: slot.d0(),
            d1: if slot.d1() == NC { nc } else { slot.d1() },
            d2: if slot.d2() == NC { nc } else { slot.d2() },
            d3: if slot.d3() == NC { nc } else { slot.d3() },
            // d4-d7 are ignored in 1- and 4-line mode, and on the Waveshare 4B the chip's
            // default d4 is GPIO45, the card's own power gate. NC, always.
            d4: nc,
            d5: nc,
            d6: nc,
            d7: nc,
            __bindgen_anon_1: sys::sdmmc_slot_config_t__bindgen_ty_1 { cd: nc },
            __bindgen_anon_2: sys::sdmmc_slot_config_t__bindgen_ty_2 { wp: nc },
            width: slot.width,
            // No SDMMC_SLOT_FLAG_INTERNAL_PULLUP: the internal pullups are documented as
            // insufficient for a real bus and both boards carry external ones.
            flags: 0,
        };

        let mount_config = sys::esp_vfs_fat_mount_config_t {
            // Never. See the module docs.
            format_if_mount_failed: false,
            max_files: MAX_OPEN_FILES,
            // Only consulted when formatting, which never happens.
            allocation_unit_size: 0,
            // The real disk-status call costs a command per transfer, and the thing it
            // buys - noticing a card pulled out from under an open file - is bought here
            // instead by never holding a mount outside a flow.
            disk_status_check_enable: false,
            // Only consulted when formatting.
            use_one_fat: false,
        };

        // The airgap cross-check, printed against the numbers that are about to be handed
        // to the driver rather than against a copy (MILESTONES.md m5 exit gate, R16).
        log::info!("{}", pins::note());

        let mut card: *mut sys::sdmmc_card_t = std::ptr::null_mut();
        // SAFETY: every pointer is to a live local that outlives the call, `slot_config`
        // is the `sdmmc_slot_config_t` this API's `*const c_void` parameter is documented
        // to take for an SDMMC host, and `card` is written only on success.
        let err = unsafe {
            sys::esp_vfs_fat_sdmmc_mount(
                MOUNT_POINT_C.as_ptr(),
                &host,
                (&slot_config as *const sys::sdmmc_slot_config_t).cast(),
                &mount_config,
                &mut card,
            )
        };
        if err != sys::ESP_OK {
            MOUNTED.store(false, Ordering::SeqCst);
            return Err(classify(err));
        }

        MOUNTS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: the driver returned ESP_OK, which is documented to mean `card` points at
        // a card structure it owns and keeps alive until the matching unmount.
        let megabytes = unsafe {
            let csd = (*card).csd;
            (i64::from(csd.capacity) * i64::from(csd.sector_size)) / (1024 * 1024)
        };
        log::info!("microSD mounted at {MOUNT_POINT} ({megabytes} MB)");
        Ok(Card {
            card,
            at: Instant::now(),
        })
    }

    /// How long this mount has been held. For the log line on unmount, which is the
    /// evidence behind "the mount is never held outside an SD flow" - a mount measured in
    /// minutes is a bug report.
    pub fn held(&self) -> std::time::Duration {
        self.at.elapsed()
    }
}

impl Drop for Card {
    fn drop(&mut self) {
        // SAFETY: `self.card` is the pointer the matching mount returned, and this is the
        // only place it is released; `Card` is not `Clone`, so there is no second owner.
        let err = unsafe { sys::esp_vfs_fat_sdcard_unmount(MOUNT_POINT_C.as_ptr(), self.card) };
        // The flag is cleared whatever happened. Leaving it set would make every later
        // mount in this boot fail with `AlreadyMounted` and give the user no way back
        // short of a power cycle; a failed unmount is worth an error line, not a dead
        // subsystem for the rest of the session.
        MOUNTED.store(false, Ordering::SeqCst);
        if err == sys::ESP_OK {
            log::info!("microSD unmounted after {} ms", self.held().as_millis());
        } else {
            log::error!(
                "microSD unmount failed (esp_err=0x{err:x}) after {} ms; the slot may need \
                 a power cycle before the next mount",
                self.held().as_millis()
            );
        }
    }
}

/// Turn the driver's code into the distinction a screen has to draw.
///
/// The mapping is a best effort at the boundary between "nothing is in the slot" and "what
/// is in the slot is not readable", and the hardware gate is what confirms which code an
/// empty slot actually produces on each board. Anything unrecognised stays a
/// [`CardError::Driver`] with its number rather than being folded into a guess.
fn classify(err: sys::esp_err_t) -> CardError {
    match err {
        sys::ESP_ERR_TIMEOUT | sys::ESP_ERR_NOT_FOUND | sys::ESP_ERR_INVALID_RESPONSE => {
            CardError::NoCard(err)
        }
        sys::ESP_FAIL => CardError::Unreadable(err),
        _ => CardError::Driver(err),
    }
}
