//! Verify-screen data: everything is READ from the running system at boot
//! (SECURITY.md invariant 5) - the app hash comes from the flash partition the
//! chip is executing, the eFuse states from the eFuse controller, the radio
//! state from the kill pin's actual pad level. A value this build cannot read
//! reports "unavailable"; a fake value would defeat the screen's purpose.
//!
//! Two surfaces live here and the split is deliberate.
//!
//! - [`build`] produces the nine-row `notyas_ui::VerifyInfo` the 0.1.0 screen
//!   renders. Unchanged in shape; it now takes its values from the readout
//!   rather than reading them a second time, so the screen and the log cannot
//!   disagree about the same fact.
//! - [`payload`] and [`log_readout`] produce the full `notyas-verify/1`
//!   key=value readout (VERIFY.md 7.2) from [`crate::readout`]. That is the
//!   export format, the boot-log format and the input to S-46's row set, and
//!   there is exactly one implementation of it.
//!
//! The two compile-time values on the readout - the firmware semver and the
//! board name - are added here rather than in `readout.rs`, because that module
//! is measurement only and mixing a build's claims about itself into it would
//! blur the line the whole screen rests on.

use notyas_core::selftest::SelfTest;
use notyas_ui::VerifyInfo;

use crate::board;
use crate::readout::Readout;

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

/// Build the VerifyInfo the UI will show, from values already read.
pub fn build(st: &SelfTest, ro: &Readout) -> VerifyInfo {
    let board = if board::UNTESTED {
        format!("{} (UNTESTED CONFIG)", board::BOARD_NAME)
    } else {
        String::from(board::BOARD_NAME)
    };

    let platform = format!(
        "ESP-IDF {} | ESP32-P4 rev {}",
        ro.app_idf_version, ro.chip_revision
    );

    // Radio: the compile-time kill mechanism plus the pad level as it reads RIGHT NOW
    // (claim_output keeps the input buffer enabled for exactly this readback).
    let level = unsafe { esp_idf_svc::sys::gpio_get_level(board::RADIO_KILL_GPIO) };
    let radio_ok = level == 0;
    let radio = format!(
        "kill GPIO{} reads {} | {}",
        board::RADIO_KILL_GPIO,
        if radio_ok { "LOW (C6 held in reset)" } else { "HIGH - RADIO NOT HELD IN RESET" },
        board::RADIO_KILL_DOC
    );

    // Dev boards run with secure boot / flash encryption off; the screen reports the
    // true eFuse state either way (SECURITY.md invariant 6 - honesty over reassurance).
    let secure_boot = if ro.secure_boot.enabled {
        String::from("enabled (eFuse SECURE_BOOT_EN burned)")
    } else {
        String::from("disabled (dev unit; release units burn Secure Boot v2 RSA-3072)")
    };
    let flash_encryption = if ro.flash_encryption.enabled {
        format!("enabled ({})", ro.flash_encryption.mode.idf_name())
    } else {
        String::from("disabled (dev unit; release units enable XTS-AES)")
    };

    VerifyInfo {
        firmware_version: String::from(env!("CARGO_PKG_VERSION")),
        board,
        platform,
        app_sha256: ro
            .app
            .map(|r| hex(&r.sha256))
            .unwrap_or_else(|| String::from("unavailable")),
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
