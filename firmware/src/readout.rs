//! The security-state readout: everything the device can say about itself that
//! it READ from the running system (SECURITY.md invariant 5, VERIFY.md sections
//! 2, 4 and 5).
//!
//! Three rules govern every line of this module, all three from VERIFY.md's
//! design contract, and each of them rules out an implementation that would
//! otherwise be shorter:
//!
//! 1. **Read, never claim.** No value here is compiled in. A field this build
//!    cannot read renders `not read` - never a plausible default, and never a
//!    zero standing in for a value the hardware declined to give.
//! 2. **Raw values, no verdicts.** Fields are reported as they read. There is
//!    no summary boolean, no "secure" and no "ok". Interpretation belongs to
//!    the reader and to the documentation; a verdict computed here would be the
//!    firmware grading itself, which is worth nothing (VERIFY.md section 9).
//! 3. **Frozen field order.** [`Readout::to_lines`] emits the `notyas-verify/1`
//!    key=value format in VERIFY.md section 10's order, which is also the
//!    screen order and the QR export order. Two devices' readouts therefore
//!    `diff` against each other and against a release manifest with no
//!    reordering noise, which is the entire point of freezing it.
//!
//! The eFuse half of the work lives in the `esp-idf-hmac` crate, not here.
//! It is generic platform code with no notyas policy in it, and keeping it
//! there is what stops a product-specific default leaking into a value that is
//! supposed to be a measurement.
//!
//! Not in this module, and deliberately: the reserved-space scan, the mutable
//! partition digests and the boot counter (all on-demand or storage-dependent,
//! VERIFY.md 3.3 and 6, owned by later milestones), and the partition map.

use std::ffi::CStr;
use std::time::Instant;

use esp_idf_hmac::identity::{ChipRevision, DieUniqueId};
use esp_idf_hmac::posture::{Download, FlashEncryption, Jtag, RomLog};
use esp_idf_hmac::{identity, key_block, posture, secure_boot};
use esp_idf_hmac::{DigestSlot, KeyBlockState, SecureBoot};
use esp_idf_svc::sys;

/// The domain tag of the composite firmware digest (VERIFY.md 2.4). Frozen:
/// changing it silently invalidates every published number, so a future
/// construction is `notyas-fw-digest/2` and is visibly a different value.
const FW_DIGEST_TAG: &[u8] = b"notyas-fw-digest/1";

/// One hashed flash region: what was hashed, from where, and to what.
///
/// The offset and length travel with the digest because a digest without them
/// is a number rather than a checkable number.
#[derive(Clone, Copy, Debug)]
pub struct Region {
    /// Flash offset the region starts at.
    pub offset: u32,
    /// Number of bytes hashed. For an image this is the image content length,
    /// which excludes the 32 bytes of appended digest - the same convention
    /// `esp_partition_get_sha256()` hashes to, and the number the release
    /// manifest publishes as `*_image_len`.
    pub len: u32,
    /// SHA-256 over exactly `len` bytes at `offset`.
    pub sha256: [u8; 32],
}

/// Everything read at boot, structured.
///
/// Fields are `Option` wherever the underlying read can legitimately fail or
/// the value can legitimately be absent, so that "could not read this" is
/// representable and is not silently the same as "read a zero".
pub struct Readout {
    // --- identity (VERIFY.md 10.1) ---
    /// Silicon revision, composed by the HAL from the eFuse wafer fields.
    pub chip_revision: ChipRevision,
    /// Boot ROM ECO version, from the `_rom_eco_version` linker symbol.
    pub rom_eco_version: u32,
    /// Boot ROM chip id, from `_rom_chip_id`. `0x12` is ESP32-P4.
    pub rom_chip_id: u32,
    /// Factory base MAC, eFuse BLK1.
    pub mac: Option<[u8; 6]>,
    /// `OPTIONAL_UNIQUE_ID`, eFuse BLK2, or the fact that it is not burned.
    pub die_unique_id: DieUniqueId,

    // --- firmware (VERIFY.md 10.2) ---
    /// ESP-IDF version the running app was linked against.
    pub app_idf_version: String,
    /// ESP-IDF version that built the bootloader now in flash. A different
    /// string from the app's is a stale bootloader, which is the most likely
    /// real fault on this hardware and the one a digest alone cannot name.
    pub bootloader_idf_version: Option<String>,
    /// The bootloader's own build timestamp, from its description structure.
    pub bootloader_date_time: Option<String>,
    /// Anti-rollback version compiled into the running image.
    pub image_secure_version: Option<u32>,
    /// Anti-rollback floor burned into eFuse. Shown beside the image value
    /// rather than alone: one number hides whether the pair agrees.
    pub efuse_secure_version: u32,
    /// The running app image at `0x10000`.
    pub app: Option<Region>,
    /// The second-stage bootloader at `0x2000` (ESP32-P4's offset; not `0x0`
    /// and not `0x1000`).
    pub bootloader: Option<Region>,
    /// The partition table at `0x8000`, hashed over its used length.
    pub partition_table: Option<Region>,
    /// The composite over the three regions above (VERIFY.md 2.4). Present
    /// only when all three were read: a composite over two of them would be a
    /// number that matches nothing.
    pub firmware_digest: Option<[u8; 32]>,

    // --- flash (VERIFY.md 10.3) ---
    /// Flash size from the image header, i.e. what the build was told.
    pub flash_size_header: Option<u32>,
    /// Flash size detected from the RDID capacity byte, i.e. what is fitted.
    pub flash_size_detected: Option<u32>,
    /// 24-bit JEDEC RDID: manufacturer, type, capacity.
    pub jedec_id: Option<u32>,
    /// The flash part's 64-bit unique id, where the part implements `4Bh`.
    /// `None` means `ESP_ERR_NOT_SUPPORTED`, which is an honest answer and not
    /// a failure.
    pub flash_unique_id: Option<u64>,

    // --- efuse (VERIFY.md 10.4) ---
    /// Whether this build's eFuse API is a RAM copy rather than the fuses.
    /// A readout that did not say so would be showing a reader a fiction.
    pub efuse_virtual: bool,
    /// Secure Boot v2: enabled, aggressive revoke, and the three key digests.
    pub secure_boot: SecureBoot,
    /// Flash encryption: enabled, mode, crypt count, key block and protection.
    pub flash_encryption: FlashEncryption,
    /// The download-mode field group.
    pub download: Download,
    /// The three JTAG fields and the strapping selector.
    pub jtag: Jtag,
    /// Boot ROM logging configuration.
    pub rom_log: RomLog,
    /// All six eFuse key blocks, in block order.
    pub key_blocks: [KeyBlockState; 6],

    /// Wall time the whole readout took, for the boot budget.
    pub elapsed_ms: u128,
}

/// Read everything, now.
///
/// Cost is dominated by the app image hash, which 0.1.0 already paid at boot
/// (~295 ms over the running partition). Everything added here is
/// sub-millisecond or microseconds: the bootloader is 24 KiB, the partition
/// table is at most 3 KiB, and the entire eFuse section is memory-mapped
/// register reads.
///
/// Never fails. Every component either produces a value or produces the fact
/// that it has none, because a readout that refuses wholesale on one bad field
/// tells the reader less than one that reports the field as unread.
pub fn read() -> Readout {
    let t0 = Instant::now();

    let app = hash_running_app();
    let bootloader = hash_bootloader();
    let partition_table = hash_partition_table();

    let mut readout = Readout {
        chip_revision: identity::chip_revision(),
        rom_eco_version: rom_eco_version(),
        rom_chip_id: rom_chip_id(),
        mac: identity::mac().ok(),
        die_unique_id: identity::die_unique_id(),

        app_idf_version: idf_version(),
        bootloader_idf_version: None,
        bootloader_date_time: None,
        image_secure_version: image_secure_version(),
        efuse_secure_version: posture::efuse_secure_version(),
        app,
        bootloader,
        partition_table,
        firmware_digest: composite_digest(bootloader, partition_table, app),

        flash_size_header: flash_u32(sys::esp_flash_get_size),
        flash_size_detected: flash_u32(sys::esp_flash_get_physical_size),
        jedec_id: flash_u32(sys::esp_flash_read_id),
        flash_unique_id: flash_unique_id(),

        efuse_virtual: esp_idf_hmac::EFUSE_VIRTUAL,
        secure_boot: secure_boot::read(),
        flash_encryption: posture::flash_encryption(),
        download: posture::download(),
        jtag: posture::jtag(),
        rom_log: posture::rom_log(),
        key_blocks: key_block::all_states(),

        elapsed_ms: 0,
    };

    if let Some((idf, date)) = bootloader_description() {
        readout.bootloader_idf_version = Some(idf);
        readout.bootloader_date_time = Some(date);
    }

    readout.elapsed_ms = t0.elapsed().as_millis();
    readout
}

impl Readout {
    /// The `notyas-verify/1` payload: one `key=value` line per field, in
    /// VERIFY.md section 10's frozen order.
    ///
    /// This is the export format (VERIFY.md 7.2) and it is also what the boot
    /// log prints, deliberately: one rendering means the log and the QR cannot
    /// disagree, and it means every field on this screen is proven readable by
    /// a serial capture rather than by an assertion that it was.
    ///
    /// Conventions, fixed here so an off-device checker can rely on them:
    /// digests and IDs are lowercase unspaced hex; single-bit eFuse fields are
    /// the raw bit, `0` or `1`, not a word; a field that could not be read is
    /// the literal `not read`; a field that is absent from this silicon is
    /// `not present`.
    ///
    /// Sections 10.5 (`state`) and 10.6 (`operation`) are not emitted here.
    /// They come from the storage ledger and from the board module, which are
    /// other milestones' surfaces; their lines append after these.
    pub fn to_lines(&self) -> Vec<String> {
        let mut out = Vec::with_capacity(64);
        let mut kv = |k: &str, v: String| out.push(format!("{k}={v}"));

        // --- identity ---
        kv("chip", String::from("esp32p4"));
        kv("chip_rev", self.chip_revision.to_string());
        kv("rom_eco", self.rom_eco_version.to_string());
        kv("rom_chip_id", format!("0x{:02x}", self.rom_chip_id));
        kv(
            "mac",
            match self.mac {
                Some(m) => hex(&m),
                None => not_read(),
            },
        );
        kv(
            "die_uid",
            match self.die_unique_id {
                DieUniqueId::Burned(id) => hex(&id),
                DieUniqueId::NotBurned => String::from("not burned"),
            },
        );

        // --- firmware ---
        kv("idf_ver", self.app_idf_version.clone());
        kv(
            "bootloader_idf_ver",
            self.bootloader_idf_version.clone().unwrap_or_else(not_read),
        );
        kv(
            "bootloader_date",
            self.bootloader_date_time.clone().unwrap_or_else(not_read),
        );
        kv(
            "secure_version_image",
            opt_num(self.image_secure_version.map(u64::from)),
        );
        kv(
            "secure_version_efuse",
            self.efuse_secure_version.to_string(),
        );
        kv(
            "firmware_digest",
            self.firmware_digest.map(|d| hex(&d)).unwrap_or_else(not_read),
        );
        region(&mut kv, "app", self.app);
        region(&mut kv, "bootloader", self.bootloader);
        region(&mut kv, "partition_table", self.partition_table);

        // --- flash ---
        kv("flash_size_header", opt_num(self.flash_size_header.map(u64::from)));
        kv(
            "flash_size_detected",
            opt_num(self.flash_size_detected.map(u64::from)),
        );
        kv(
            "jedec_id",
            match self.jedec_id {
                Some(id) => format!("{:06x}", id & 0x00ff_ffff),
                None => not_read(),
            },
        );
        kv(
            "flash_uid",
            match self.flash_unique_id {
                Some(id) => format!("{id:016x}"),
                None => String::from("not supported"),
            },
        );

        // --- efuse ---
        kv("efuse_virtual", bit(self.efuse_virtual));
        kv("secure_boot", bit(self.secure_boot.enabled));
        kv(
            "secure_boot_aggressive_revoke",
            bit(self.secure_boot.aggressive_revoke),
        );
        for (slot, digest) in self.secure_boot.digests.iter().enumerate() {
            kv(
                &format!("secure_boot_digest{slot}"),
                match digest {
                    DigestSlot::Burned { digest, .. } => hex(digest),
                    DigestSlot::NotBurned => String::from("not burned"),
                    DigestSlot::Revoked => String::from("revoked"),
                    DigestSlot::ReadProtected => String::from("read-protected"),
                },
            );
            kv(
                &format!("secure_boot_digest{slot}_revoke_wr_dis"),
                bit(self.secure_boot.revoke_write_protected[slot]),
            );
        }

        let fe = &self.flash_encryption;
        kv("flash_encryption", bit(fe.enabled));
        kv("flash_encryption_mode", fe.mode.idf_name().to_string());
        kv("flash_crypt_cnt", fe.crypt_count.to_string());
        kv(
            "xts_key_length_256",
            match fe.xts_key_length_256 {
                Some(b) => bit(b),
                None => String::from("not present"),
            },
        );
        kv("dis_download_manual_encrypt", bit(fe.manual_encrypt_disabled));
        kv("spi_download_mspi_dis", bit(fe.mspi_download_disabled));
        kv(
            "xts_key_block",
            match fe.key_block {
                Some(b) => b.name().to_string(),
                None => String::from("none"),
            },
        );
        kv(
            "xts_key_rd_dis",
            match fe.key_read_protected {
                Some(b) => bit(b),
                None => String::from("none"),
            },
        );

        let d = &self.download;
        kv("dis_download_mode", bit(d.uart_download_disabled));
        kv("enable_security_download", bit(d.secure_download_enabled));
        kv(
            "dis_usb_serial_jtag_download_mode",
            bit(d.usb_serial_jtag_download_disabled),
        );
        kv(
            "dis_usb_otg_download_mode",
            bit(d.usb_otg_download_disabled),
        );
        kv("dis_force_download", bit(d.force_download_disabled));
        kv("dis_direct_boot", bit(d.direct_boot_disabled));

        let j = &self.jtag;
        kv("dis_pad_jtag", bit(j.pad_disabled));
        kv("dis_usb_jtag", bit(j.usb_disabled));
        kv(
            "soft_dis_jtag",
            format!("{}/{}", j.soft_disable_count, j.soft_disable_width),
        );
        kv("jtag_sel_enable", bit(j.select_enabled));

        kv(
            "uart_print_control",
            self.rom_log.uart_print_control.to_string(),
        );
        kv(
            "dis_usb_serial_jtag_rom_print",
            bit(self.rom_log.usb_serial_jtag_print_disabled),
        );

        for st in &self.key_blocks {
            let purpose = if st.unused {
                String::from("<unused>")
            } else {
                st.purpose.to_string()
            };
            kv(
                &format!("key_block{}", st.block.index()),
                format!(
                    "{purpose} rd_dis {} wr_dis {} purpose_wr_dis {}",
                    st.read_protected as u8,
                    st.write_protected as u8,
                    st.purpose_write_protected as u8
                ),
            );
        }

        out
    }
}

// ---------------------------------------------------------------------------
// Renderers. Shared so the log, the screen and the QR cannot render the same
// value three slightly different ways.
// ---------------------------------------------------------------------------

/// VERIFY.md's honest placeholder, and the only thing that may stand in for a
/// value this build could not obtain.
fn not_read() -> String {
    String::from("not read")
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn bit(b: bool) -> String {
    String::from(if b { "1" } else { "0" })
}

fn opt_num(v: Option<u64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(not_read)
}

/// A hashed region renders as three lines - offset, length, digest - so the
/// reader can see what was hashed and not only the result.
fn region(kv: &mut impl FnMut(&str, String), name: &str, region: Option<Region>) {
    match region {
        Some(r) => {
            kv(&format!("{name}_offset"), format!("0x{:08x}", r.offset));
            kv(&format!("{name}_len"), r.len.to_string());
            kv(&format!("{name}_sha256"), hex(&r.sha256));
        }
        None => {
            kv(&format!("{name}_offset"), not_read());
            kv(&format!("{name}_len"), not_read());
            kv(&format!("{name}_sha256"), not_read());
        }
    }
}

// ---------------------------------------------------------------------------
// The reads themselves.
// ---------------------------------------------------------------------------

// _rom_eco_version / _rom_chip_id: the boot ROM's ECO version and chip id.
//
// The ROM banner string (`ESP-ROM:esp32p4-eco2-20240710`) is NOT at a stable
// address - it moves between ROM revisions - so scanning for it would be a
// heuristic. These two linker symbols are stable by contract: ESP-IDF's
// `esp32p4.rom.version.ld` says "these addresses should be compatible with any
// ROM version for this chip", they are linked into every P4 app and bootloader,
// and ESP-IDF reads them exactly this way itself.
//
// esp_flash_default_chip: the SPI flash driver's default chip handle. Declared
// here rather than used from the generated bindings because esp-idf-sys's
// bindgen allowlist takes ESP-IDF's functions but not this variable, and
// `esp_partition_read()` refuses the encrypted path for any partition whose
// `flash_chip` is not exactly this pointer.
extern "C" {
    static _rom_eco_version: u32;
    static _rom_chip_id: u32;
    static esp_flash_default_chip: *mut sys::esp_flash_t;
}

fn default_flash_chip() -> *mut sys::esp_flash_t {
    // SAFETY: a pointer-sized global the SPI flash driver initialises during
    // startup, long before app_main. Read, never written.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(esp_flash_default_chip)) }
}

fn rom_eco_version() -> u32 {
    // SAFETY: a linker-placed absolute symbol at 0x4FC00014, inside the ROM
    // region that cpu_region_protect.c covers with a locked R+X PMP entry.
    // Loads succeed; nothing writes through this.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(_rom_eco_version)) }
}

fn rom_chip_id() -> u32 {
    // SAFETY: as above, at 0x4FC00010.
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(_rom_chip_id)) }
}

fn idf_version() -> String {
    // SAFETY: returns a pointer to a static C string in .rodata.
    unsafe { CStr::from_ptr(sys::esp_get_idf_version()) }
        .to_str()
        .unwrap_or("unavailable")
        .to_string()
}

/// The anti-rollback version compiled into the running image.
fn image_secure_version() -> Option<u32> {
    // SAFETY: returns a pointer to the app description structure in this
    // image's own .rodata; never null in an app build.
    let desc = unsafe { sys::esp_app_get_description() };
    if desc.is_null() {
        return None;
    }
    // SAFETY: non-null, and points at a structure with static lifetime.
    Some(unsafe { (*desc).secure_version })
}

/// The bootloader's IDF version string and build timestamp.
///
/// `NULL` for the partition means the primary bootloader at the configured
/// offset. A bootloader built before ESP-IDF started appending this structure
/// returns an error, which is reported as `not read` rather than guessed at.
fn bootloader_description() -> Option<(String, String)> {
    let mut desc = sys::esp_bootloader_desc_t::default();
    // SAFETY: `desc` is a valid, fully-initialised out-parameter.
    let err = unsafe { sys::esp_ota_get_bootloader_description(core::ptr::null(), &mut desc) };
    if err != sys::ESP_OK {
        log::warn!("esp_ota_get_bootloader_description failed: 0x{err:x}");
        return None;
    }
    Some((c_array_string(&desc.idf_ver), c_array_string(&desc.date_time)))
}

/// A fixed-size, NUL-padded C char array as a String. Stops at the first NUL
/// and drops anything that is not valid UTF-8 rather than propagating a
/// failure: this is a label, and a mangled label is more useful than no label.
fn c_array_string(bytes: &[core::ffi::c_char]) -> String {
    let end = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
    let as_u8: Vec<u8> = bytes[..end].iter().map(|&c| c as u8).collect();
    String::from_utf8_lossy(&as_u8).into_owned()
}

/// SHA-256 of the running app image, from flash through the partition API, so
/// it covers what the chip is executing rather than what this binary claims.
fn hash_running_app() -> Option<Region> {
    // SAFETY: returns a pointer into the static partition table, or null.
    let part = unsafe { sys::esp_ota_get_running_partition() };
    if part.is_null() {
        log::warn!("esp_ota_get_running_partition returned null");
        return None;
    }
    // SAFETY: non-null and points at a live partition entry.
    let (address, size, type_) = unsafe { ((*part).address, (*part).size, (*part).type_) };
    hash_image(address, size, type_)
}

/// SHA-256 of the second-stage bootloader.
///
/// ESP32-P4 puts it at `0x2000`, not `0x0` (the other RISC-V parts) and not
/// `0x1000` (the original ESP32): the ROM reserves the first two sectors for
/// the Key Manager's AES-XTS use. `ESP_BOOTLOADER_OFFSET` and
/// `ESP_BOOTLOADER_SIZE` are the authority and are used rather than literals.
///
/// The digest is obtained exactly as the app's is. ESP-IDF's
/// `bootloader_common_get_sha256_of_partition()` branches on the partition type
/// and handles `PART_TYPE_BOOTLOADER` the same way it handles `PART_TYPE_APP`,
/// so filling a stack-local `esp_partition_t` - ESP-IDF's own pattern, and the
/// header documents that only address, size and type need to be set - costs
/// nothing and leaves `firmware/partitions.csv` untouched.
fn hash_bootloader() -> Option<Region> {
    hash_image(
        sys::ESP_BOOTLOADER_OFFSET,
        sys::ESP_BOOTLOADER_SIZE,
        sys::esp_partition_type_t_ESP_PARTITION_TYPE_BOOTLOADER,
    )
}

/// Hash one image region, and report the length that was actually hashed.
///
/// The length is not the partition size. `esp_image_get_metadata()` parses the
/// image headers (cheap - it does not re-hash) and reports `image_len`, which
/// INCLUDES the 32 bytes of appended digest; `esp_partition_get_sha256()`
/// hashes `image_len - 32`. Publishing the wrong one of those two numbers is
/// the difference between a manifest a user can check and a manifest that
/// makes their correct device look wrong.
fn hash_image(address: u32, size: u32, type_: sys::esp_partition_type_t) -> Option<Region> {
    let mut part = sys::esp_partition_t {
        address,
        size,
        type_,
        ..Default::default()
    };
    // esp_partition_get_sha256 reads only address/size/type, but flash_chip is
    // set anyway so this struct stays valid if it is ever passed elsewhere.
    part.flash_chip = default_flash_chip();

    let mut sha256 = [0u8; 32];
    // SAFETY: `part` is a fully-initialised partition descriptor and `sha256`
    // is the 32-byte buffer the C contract requires.
    let err = unsafe { sys::esp_partition_get_sha256(&part, sha256.as_mut_ptr()) };
    if err != sys::ESP_OK {
        log::warn!("esp_partition_get_sha256(0x{address:06x}) failed: 0x{err:x}");
        return None;
    }

    let pos = sys::esp_partition_pos_t {
        offset: address,
        size,
    };
    let mut meta = sys::esp_image_metadata_t::default();
    // SAFETY: both are valid pointers for the duration of the call; the
    // function parses headers and does not retain either.
    let err = unsafe { sys::esp_image_get_metadata(&pos, &mut meta) };
    if err != sys::ESP_OK {
        log::warn!("esp_image_get_metadata(0x{address:06x}) failed: 0x{err:x}");
        return None;
    }
    let hashed = if meta.image.hash_appended != 0 {
        meta.image_len.saturating_sub(32)
    } else {
        meta.image_len
    };

    Some(Region {
        offset: address,
        len: hashed,
        sha256,
    })
}

/// SHA-256 of the partition table at `0x8000`, over its USED length.
///
/// There is no ESP-IDF call that returns the table's raw bytes or its length,
/// so the app reads the region, validates it, and derives the length:
/// `esp_partition_table_verify()` checks the magics and the trailing MD5 record
/// and yields the entry count excluding that record, so the used length is
/// `(n + 1) * 32`.
///
/// Hashing the used length rather than the padded `0xC00` is deliberate. Most
/// of the 3 KiB region is `0xff` padding, and a digest over it would match no
/// published artifact; a digest over the used length is one the build can
/// compute directly from the bytes it writes into `partition-table.bin`.
fn hash_partition_table() -> Option<Region> {
    const MAX_LEN: usize = sys::ESP_PARTITION_TABLE_MAX_LEN as usize;
    const ENTRY: usize = core::mem::size_of::<sys::esp_partition_info_t>();

    let mut part = sys::esp_partition_t {
        address: sys::ESP_PARTITION_TABLE_OFFSET,
        size: MAX_LEN as u32,
        type_: sys::esp_partition_type_t_ESP_PARTITION_TYPE_PARTITION_TABLE,
        // The one path that is correct whether or not flash encryption is on:
        // esp_partition_read decrypts when the flag is set, and the published
        // artifact is the plaintext table either way (VERIFY.md 3.3 - content
        // is hashed on the decrypted view).
        // SAFETY: no arguments; reads eFuse read registers.
        encrypted: unsafe { sys::esp_flash_encryption_enabled() },
        ..Default::default()
    };
    part.flash_chip = default_flash_chip();

    let mut buf = vec![0u8; MAX_LEN];
    // SAFETY: `part` is fully initialised and `buf` has exactly MAX_LEN bytes.
    let err = unsafe { sys::esp_partition_read(&part, 0, buf.as_mut_ptr().cast(), MAX_LEN) };
    if err != sys::ESP_OK {
        log::warn!("partition table read failed: 0x{err:x}");
        return None;
    }

    let mut num_partitions: core::ffi::c_int = 0;
    // SAFETY: `buf` holds ESP_PARTITION_TABLE_MAX_LEN bytes, which is what the
    // header documents as the required input size; log_errors is false because
    // an invalid table is a value to report, not an error to shout about.
    let err = unsafe {
        sys::esp_partition_table_verify(buf.as_ptr().cast(), false, &mut num_partitions)
    };
    if err != sys::ESP_OK {
        log::warn!("esp_partition_table_verify failed: 0x{err:x}");
        return None;
    }

    // +1 for the trailing MD5 record, which CONFIG_PARTITION_TABLE_MD5 emits
    // and which esp_partition_table_verify excludes from its count.
    let used = (num_partitions as usize + 1) * ENTRY;
    if used > MAX_LEN {
        log::warn!("partition table reports {num_partitions} entries, which does not fit");
        return None;
    }

    Some(Region {
        offset: sys::ESP_PARTITION_TABLE_OFFSET,
        len: used as u32,
        sha256: sha256(&buf[..used]),
    })
}

/// The composite firmware digest (VERIFY.md 2.4), frozen:
///
/// ```text
/// SHA-256( "notyas-fw-digest/1" || 0x00
///          || u32le(bootloader_len) || bootloader_sha256   // 0x2000
///          || u32le(pt_len)         || partition_table_sha256
///          || u32le(app_len)        || app_sha256 )
/// ```
///
/// Domain-separated so it can never collide with a raw SHA-256 of anything else
/// in the system; length-prefixed so it is reconstructible by hand from the
/// nine numbers printed beside it; fixed region order, low offset to high.
///
/// It is a convenience, not a security boundary: it compresses three
/// comparisons into one and adds no property the three digests do not already
/// have. `None` unless all three are present, because a composite over a subset
/// would be a number that matches nothing and says so to nobody.
fn composite_digest(
    bootloader: Option<Region>,
    partition_table: Option<Region>,
    app: Option<Region>,
) -> Option<[u8; 32]> {
    let (bl, pt, app) = (bootloader?, partition_table?, app?);
    let mut input = Vec::with_capacity(FW_DIGEST_TAG.len() + 1 + 3 * (4 + 32));
    input.extend_from_slice(FW_DIGEST_TAG);
    input.push(0x00);
    for r in [bl, pt, app] {
        input.extend_from_slice(&r.len.to_le_bytes());
        input.extend_from_slice(&r.sha256);
    }
    Some(sha256(&input))
}

/// SHA-256 of a buffer already in RAM, through mbedtls (which ESP-IDF routes to
/// the hardware SHA peripheral). Used for the two small digests; the image
/// digests come from `esp_partition_get_sha256`, which hashes from flash.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // SAFETY: `data` is a readable slice of its own length and `out` is the
    // 32-byte buffer SHA-256 requires. is224 = 0 selects SHA-256.
    unsafe { sys::mbedtls_sha256(data.as_ptr(), data.len(), out.as_mut_ptr(), 0) };
    out
}

/// The three `esp_flash_*` calls that share a shape: default chip, one `u32`
/// out-parameter. `None` on any error rather than a zero, because a zero flash
/// size or a zero JEDEC id would read as a value.
fn flash_u32(f: unsafe extern "C" fn(*mut sys::esp_flash_t, *mut u32) -> sys::esp_err_t) -> Option<u32> {
    let mut value: u32 = 0;
    // SAFETY: a null chip selects esp_flash_default_chip inside ESP-IDF, and
    // `value` is a valid out-pointer for the duration of the call.
    let err = unsafe { f(core::ptr::null_mut(), &mut value) };
    (err == sys::ESP_OK).then_some(value)
}

/// The flash part's 64-bit unique id, where it has one.
///
/// `ESP_ERR_NOT_SUPPORTED` is the documented answer for a part that does not
/// implement the `4Bh` command, and it is reported as `not supported` rather
/// than as a failure. Two caveats that belong with the value and are in
/// VERIFY.md 4.6: on GigaDevice parts this is the top 64 bits of a 128-bit
/// factory id, and on a 32 MB part in 4-byte address mode the generic driver's
/// dummy-cycle count may produce a byte-shifted value. The number is reported
/// as read either way; interpreting it is the documentation's job.
fn flash_unique_id() -> Option<u64> {
    let mut id: u64 = 0;
    // SAFETY: null chip selects the default; `id` is a valid out-pointer.
    let err = unsafe { sys::esp_flash_read_unique_chip_id(core::ptr::null_mut(), &mut id) };
    match err {
        sys::ESP_OK => Some(id),
        sys::ESP_ERR_NOT_SUPPORTED => None,
        other => {
            log::warn!("esp_flash_read_unique_chip_id failed: 0x{other:x}");
            None
        }
    }
}
