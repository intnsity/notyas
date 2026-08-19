//! Verify-screen data: everything is READ from the running system at boot
//! (SECURITY.md invariant 5) - the app hash comes from the flash partition the
//! chip is executing, the eFuse states from the eFuse controller, the radio
//! state from the kill pin's actual pad level. A value this build cannot read
//! renders `not read`; a fake value would defeat the screen's purpose.
//!
//! Two surfaces live here and the split is deliberate.
//!
//! - [`build`] produces the `notyas_ui::VerifyInfo` the S-46 sheet renders, in
//!   VERIFY.md section 10's frozen field order. Every value comes from the
//!   readout rather than being read a second time, so the screen and the log
//!   cannot disagree about the same fact.
//! - [`payload`] and [`log_readout`] produce the full `notyas-verify/1`
//!   key=value readout (VERIFY.md 7.2) from [`crate::readout`]. That is the
//!   export format, the boot-log format and the input to S-46's row set, and
//!   there is exactly one implementation of it.
//!
//! The two compile-time values on the readout - the firmware semver and the
//! board name - are added here rather than in `readout.rs`, because that module
//! is measurement only and mixing a build's claims about itself into it would
//! blur the line the whole screen rests on.

use esp_idf_hmac::identity::DieUniqueId;
use esp_idf_hmac::DigestSlot;
use notyas_core::selftest::SelfTest;
use notyas_ui::{Bit, HexValue, KeyBlockInfo, RegionDigest, ReservedSpace, VerifyInfo};

use notyas_wallet::StoreState;

use crate::board;
use crate::readout::Readout;
use crate::store::StoreReport;

/// One-line self-test summary for the Verify screen and the boot log.
pub fn selftest_summary(st: &SelfTest) -> String {
    let total = st.checks.len();
    let passed = st.checks.iter().filter(|c| c.passed).count();
    if st.passed() {
        format!("{passed}/{total} passed")
    } else {
        let failed: Vec<&str> =
            st.checks.iter().filter(|c| !c.passed).map(|c| c.name).collect();
        format!("FAILED: {} ({passed}/{total} passed)", failed.join(", "))
    }
}

/// Build the [`VerifyInfo`] the S-46 sheet shows, from values already read.
///
/// One rule governs every line: this function TRANSLATES the readout into the screen's
/// vocabulary and measures nothing itself, so the screen and the boot log cannot disagree
/// about the same fact. A field this build did not read keeps the shape that says so -
/// `None`, [`Bit::NotRead`], [`HexValue::NotRead`], an empty `Vec` - and never a plausible
/// default (VERIFY.md contract, "read, never claim").
///
/// **Polarity, stated once.** Most download and debug fuses are `DIS_*`: the bit is set
/// when the access is GONE. The screen names the ACCESS, so the inversion happens here and
/// nowhere else, and a reader of `VerifyInfo` never has to remember which way a symbol
/// points. `ENABLE_SECURITY_DOWNLOAD` is the one field that is already positive.
///
/// `store` is `None` when the storage stack could not be brought up at all, which is a
/// different fact from a store that mounted and reported no key: the first says the device
/// could not look, the second says it looked and found nothing.
pub fn build(st: &SelfTest, ro: &Readout, store: Option<&StoreReport>) -> VerifyInfo {
    let board = if board::UNTESTED {
        format!("{} (UNTESTED CONFIG)", board::BOARD_NAME)
    } else {
        String::from(board::BOARD_NAME)
    };

    // The kill line's level as it reads RIGHT NOW (claim_output keeps the input buffer
    // enabled for exactly this readback). One of the two rows on S-46 where semantic
    // colour survives, and the WORD carries the meaning either way.
    let level = unsafe { esp_idf_svc::sys::gpio_get_level(board::RADIO_KILL_GPIO) };
    let radio_ok = level == 0;

    let fe = &ro.flash_encryption;
    let dl = &ro.download;
    let jt = &ro.jtag;

    VerifyInfo {
        // --- identity (VERIFY.md 10.1) ---
        board: Some(board),
        chip: Some(String::from("ESP32-P4")),
        chip_revision: Some(ro.chip_revision.to_string()),
        boot_rom: Some(format!("eco {}", ro.rom_eco_version)),
        rom_chip_id: Some(format!("0x{:02x}", ro.rom_chip_id)),
        // Colon-separated for the screen, matching what `esptool chip_id` prints and
        // therefore what the owner wrote down; the readout's own line stays unspaced hex,
        // which is what an off-device checker diffs.
        mac: ro.mac.map(|m| {
            m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
        }),
        die_unique_id: match ro.die_unique_id {
            DieUniqueId::Burned(id) => HexValue::Read(hex(&id)),
            DieUniqueId::NotBurned => HexValue::NotBurned,
        },

        // --- firmware (VERIFY.md 10.2) ---
        firmware_version: Some(String::from(env!("CARGO_PKG_VERSION"))),
        idf_app: Some(ro.app_idf_version.clone()),
        idf_bootloader: ro.bootloader_idf_version.clone(),
        rollback_image: ro.image_secure_version.map(|v| v.to_string()),
        rollback_efuse: Some(ro.efuse_secure_version.to_string()),
        firmware_digest: opt_hex(ro.firmware_digest.as_ref().map(|d| &d[..])),
        app: region(ro.app),
        bootloader: region(ro.bootloader),
        partition_table: region(ro.partition_table),

        // --- flash (VERIFY.md 10.3) ---
        flash_size_header: ro.flash_size_header.map(bytes_si),
        flash_size_detected: ro.flash_size_detected.map(bytes_si),
        // Manufacturer / type / capacity, spaced so the three codes are read as three.
        jedec_id: ro.jedec_id.map(|id| {
            format!("{:02x} {:02x} {:02x}", (id >> 16) & 0xff, (id >> 8) & 0xff, id & 0xff)
        }),
        flash_unique_id: ro.flash_unique_id.map(|id| group4(&format!("{id:016x}"))),
        // The partition map, the two mutable-region digests and the reserved-space scan
        // are the three readers `readout.rs` states are outside its scope. Until they
        // land, each row says `not read` - which is the true statement about this build.
        partitions: Vec::new(),
        reserved_space: ReservedSpace::NotScanned,
        wallets_digest: HexValue::NotRead,
        counters_digest: HexValue::NotRead,

        // --- efuse (VERIFY.md 10.4) ---
        secure_boot: Bit::read(ro.secure_boot.enabled),
        aggressive_revoke: Bit::read(ro.secure_boot.aggressive_revoke),
        key_digests: core::array::from_fn(|i| match ro.secure_boot.digests[i] {
            DigestSlot::Burned { digest, .. } => HexValue::Read(hex(&digest)),
            DigestSlot::NotBurned => HexValue::NotBurned,
            DigestSlot::Revoked => HexValue::Revoked,
            DigestSlot::ReadProtected => HexValue::ReadProtected,
        }),
        flash_encryption: Bit::read(fe.enabled),
        encryption_mode: Some(fe.mode.to_string()),
        crypt_count: Some(fe.crypt_count),
        xts_key_read_protected: Bit::present(fe.key_read_protected),
        manual_encrypt: Bit::read(!fe.manual_encrypt_disabled),
        uart_download: Bit::read(!dl.uart_download_disabled),
        secure_download: Bit::read(dl.secure_download_enabled),
        usb_serial_jtag_download: Bit::read(!dl.usb_serial_jtag_download_disabled),
        usb_otg_download: Bit::read(!dl.usb_otg_download_disabled),
        forced_download: Bit::read(!dl.force_download_disabled),
        direct_boot: Bit::read(!dl.direct_boot_disabled),
        jtag_pad: Bit::read(!jt.pad_disabled),
        jtag_usb: Bit::read(!jt.usb_disabled),
        jtag_soft: Some((jt.soft_disable_count, jt.soft_disable_width)),
        // A selector, not an access: it names which JTAG path the strapping pin picks,
        // so the raw bit is the value and "enabled" would be an interpretation.
        jtag_select: Bit::read(jt.select_enabled),
        rom_log: ro.rom_log.uart_print_control,
        rom_log_usb: Bit::read(!ro.rom_log.usb_serial_jtag_print_disabled),
        key_blocks: ro
            .key_blocks
            .iter()
            .map(|b| KeyBlockInfo {
                // IDF's own enumerator name, never translated: the screen row is compared
                // character for character against `espefuse.py summary` and the m13 burn
                // runbook, and a friendlier word would destroy the row's only use.
                purpose: (!b.unused).then(|| b.purpose.to_string()),
                read_protected: b.read_protected,
                write_protected: b.write_protected,
            })
            .collect(),

        // --- state (VERIFY.md 10.5) ---
        // `not counted`, never `0`: on an unprovisioned or blank device nothing is
        // written and nothing is read (VERIFY.md 6 / R24).
        boot_count: store.and_then(|r| r.boot_count),
        acknowledged_at: store.and_then(|r| r.acknowledged_at),
        // The epoch is one-way and lives in the plaintext ledger head. It is a number
        // only a wiped store carries today; a formatted store reports none rather than
        // asserting zero.
        wipe_epoch: match store.map(|r| r.state) {
            Some(StoreState::Wiped { epoch }) => Some(epoch),
            _ => None,
        },
        // Q2(a): `present` / `blank`, permanently and for all users. Never a count - the
        // count is what a coercer gets for free from a device they cannot open.
        storage: match store.map(|r| r.state) {
            Some(StoreState::Formatted { .. }) => Some(String::from("present")),
            Some(StoreState::Blank) => Some(String::from("blank")),
            Some(StoreState::Wiped { .. }) => Some(String::from("blank")),
            Some(StoreState::Unprovisioned) => Some(String::from("not provisioned")),
            Some(StoreState::Inconsistent(kind)) => Some(format!("unreadable ({kind:?})")),
            None => None,
        },

        // --- operation (VERIFY.md 10.6) ---
        radio_gpio: u8::try_from(board::RADIO_KILL_GPIO).ok(),
        radio: Some(String::from(if radio_ok {
            "low"
        } else {
            "high - RADIO NOT HELD IN RESET"
        })),
        radio_ok,
        self_test: Some(selftest_summary(st)),
        self_test_ok: st.passed(),
    }
}

/// A hashed region with its offset and length, which travel with the digest because a
/// digest without them is a number rather than a checkable number.
fn region(r: Option<crate::readout::Region>) -> Option<RegionDigest> {
    r.map(|r| RegionDigest { offset: r.offset, len: r.len, sha256: hex(&r.sha256) })
}

fn opt_hex(bytes: Option<&[u8]>) -> HexValue {
    match bytes {
        Some(b) => HexValue::Read(hex(b)),
        None => HexValue::NotRead,
    }
}

/// A byte count as the unit the part is sold in. Exact powers of two only: anything else
/// is printed as bytes rather than rounded, because a rounded flash size is a value the
/// owner cannot compare against a datasheet.
fn bytes_si(n: u32) -> String {
    match n {
        n if n >= 1 << 20 && n % (1 << 20) == 0 => format!("{} MB", n >> 20),
        n if n >= 1 << 10 && n % (1 << 10) == 0 => format!("{} KB", n >> 10),
        n => format!("{n} B"),
    }
}

/// Hex in groups of four, which is how the screen's mono column is read and compared.
fn group4(hex: &str) -> String {
    hex.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The complete `notyas-verify/1` payload, in VERIFY.md section 10's frozen
/// field order: the format line, this build's two compile-time claims, then
/// every measured field.
///
/// Sections 10.5 (`state`, the ledger counters) and 10.6 (`operation`, the
/// radio pad level and the self-test) are appended by their owners; the field
/// order places them after these, so appending is all that is required.
pub fn payload(ro: &Readout) -> Vec<String> {
    let mut lines = Vec::with_capacity(72);
    lines.push(String::from("notyas-verify/1"));
    lines.push(format!("version={}", env!("CARGO_PKG_VERSION")));
    lines.push(format!("board={}", board::BOARD_SLUG));
    lines.extend(ro.to_lines());
    lines
}

/// Print the whole readout to the boot log, one field per line.
///
/// Verbose on purpose. This is the artifact that proves each field was read on
/// each board: a serial capture can be diffed field by field against
/// `espefuse.py summary`, `esptool flash_id` and the release manifest, which is
/// a check nobody can perform against a claim that the values were correct.
pub fn log_readout(ro: &Readout) {
    log::info!("readout: notyas-verify/1 ({} fields, read in {} ms)", ro.to_lines().len(), ro.elapsed_ms);
    if ro.efuse_virtual {
        log::warn!(
            "readout: CONFIG_EFUSE_VIRTUAL is ON - every eFuse value below comes from a RAM \
             copy and any write went nowhere. NOT a release configuration."
        );
    }
    for line in payload(ro) {
        log::info!("readout: {line}");
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
