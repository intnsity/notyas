//! Verify-screen data: everything is READ from the running system at boot
//! (SECURITY.md invariant 5) - the app hash comes from the flash partition the
//! chip is executing, the eFuse states from the eFuse controller, the radio
//! state from the kill pin's actual pad level. A value this build cannot read
//! reports "unavailable"; a fake value would defeat the screen's purpose.

use std::ffi::CStr;
use std::time::Instant;

use esp_idf_svc::sys;
use notyas_core::selftest::SelfTest;
use notyas_ui::VerifyInfo;

use crate::board;

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

/// Build the VerifyInfo the UI will show, reading every value now.
pub fn build(st: &SelfTest) -> VerifyInfo {
    let board = if board::UNTESTED {
        format!("{} (UNTESTED CONFIG)", board::BOARD_NAME)
    } else {
        String::from(board::BOARD_NAME)
    };

    let idf = unsafe { CStr::from_ptr(sys::esp_get_idf_version()) }
        .to_str()
        .unwrap_or("unavailable");
    // major*100 + minor, composed from the pre-v3 split eFuse fields by the HAL
    // (firmware/README.md pitfall 4; bindings/verify.h).
    let rev = unsafe { sys::efuse_hal_chip_revision() };
    let platform = format!("ESP-IDF {idf} | ESP32-P4 rev v{}.{}", rev / 100, rev % 100);

    // Radio: the compile-time kill mechanism plus the pad level as it reads RIGHT NOW
    // (claim_output keeps the input buffer enabled for exactly this readback).
    let level = unsafe { sys::gpio_get_level(board::RADIO_KILL_GPIO) };
    let radio_ok = level == 0;
    let radio = format!(
        "kill GPIO{} reads {} | {}",
        board::RADIO_KILL_GPIO,
        if radio_ok { "LOW (C6 held in reset)" } else { "HIGH - RADIO NOT HELD IN RESET" },
        board::RADIO_KILL_DOC
    );

    // Dev boards run with secure boot / flash encryption off; the screen reports the
    // true eFuse state either way (SECURITY.md invariant 6 - honesty over reassurance).
    let secure_boot = if efuse_secure_boot_enabled() {
        String::from("enabled (eFuse SECURE_BOOT_EN burned)")
    } else {
        String::from("disabled (dev unit; release units burn Secure Boot v2 RSA-3072)")
    };
    let flash_encryption = if unsafe { sys::esp_flash_encryption_enabled() } {
        String::from("enabled")
    } else {
        String::from("disabled (dev unit; release units enable XTS-AES)")
    };

    VerifyInfo {
        firmware_version: String::from(env!("CARGO_PKG_VERSION")),
        board,
        platform,
        app_sha256: running_app_sha256().unwrap_or_else(|| String::from("unavailable")),
        // Reproducible-build source id ships with the release tooling (0.1.0 final);
        // until then the screen says so instead of inventing one.
        source_id: String::from("unavailable"),
        self_test: selftest_summary(st),
        self_test_ok: st.passed(),
        radio,
        radio_ok,
        secure_boot,
        flash_encryption,
    }
}

/// SHA256 of the app image in the RUNNING partition, lowercase hex - hashed from
/// flash through the partition API, so it covers what the chip is executing, not
/// what this binary was compiled to claim. None (-> "unavailable") on any error.
fn running_app_sha256() -> Option<String> {
    let t0 = Instant::now();
    let mut digest = [0u8; 32];
    unsafe {
        let part = sys::esp_ota_get_running_partition();
        if part.is_null() {
            log::warn!("esp_ota_get_running_partition returned null");
            return None;
        }
        let err = sys::esp_partition_get_sha256(part, digest.as_mut_ptr());
        if err != sys::ESP_OK {
            log::warn!("esp_partition_get_sha256 failed: 0x{err:x}");
            return None;
        }
    }
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    log::info!(
        "app sha256 (running partition, hashed in {} ms): {hex}",
        t0.elapsed().as_millis()
    );
    Some(hex)
}

/// The eFuse bit behind esp_secure_boot_enabled(). That function is static inline in
/// esp_secure_boot.h (not bindgen-able); on ESP32-P4 its non-virtual-eFuse arm reads
/// this same SECURE_BOOT_EN bit through efuse_ll, so the public field-read API below
/// is the equivalent - and it is a real symbol.
fn efuse_secure_boot_enabled() -> bool {
    // addr_of_mut!: bindgen exposes the descriptor table as a `static mut` array, and
    // taking a plain reference to one is the static_mut_refs footgun; the raw-pointer
    // cast never creates a reference. The *mut is only because the C prototype is not
    // const-qualified - the read never writes through it.
    unsafe {
        sys::esp_efuse_read_field_bit(
            core::ptr::addr_of_mut!(sys::ESP_EFUSE_SECURE_BOOT_EN)
                as *mut *const sys::esp_efuse_desc_t,
        )
    }
}
