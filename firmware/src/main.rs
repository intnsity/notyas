//! BigDice32 firmware, milestone 0.1.0-m1: toolchain proof.
//!
//! Boots on the Waveshare ESP32-P4-WiFi6-Touch-LCD-4B (rev v1.3), locks down
//! the radio, and logs a heartbeat banner once per second over UART0 (CH343).

use std::ffi::CStr;
use std::thread;
use std::time::Duration;

use esp_idf_svc::hal::gpio::PinDriver;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::sys;

fn main() {
    // Apply esp-idf-sys patches (rt linkage etc.) - must be first per template.
    sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    let peripherals = Peripherals::take().expect("peripherals already taken");

    // AIRGAP LOCKDOWN - do this before anything else.
    // GPIO54 is wired to the ESP32-C6 radio module's enable pin (CHIP_PU).
    // Driving it LOW and never releasing it holds the C6 - the only radio on
    // this board - in reset for the entire power cycle. This is lockdown
    // layer 2 of the security model (layer 1: no WiFi stack in the build;
    // layer 3: the C6 SDIO GPIOs are never configured as an SDIO host).
    let mut c6_reset = PinDriver::output(peripherals.pins.gpio54)
        .expect("failed to claim GPIO54 (C6 enable)");
    c6_reset.set_low().expect("failed to drive GPIO54 low");
    log::info!("C6 radio held in reset (GPIO54 low)");

    let idf_version = unsafe { CStr::from_ptr(sys::esp_get_idf_version()) }
        .to_str()
        .unwrap_or("<invalid>");

    // Chip revision straight from eFuse (esp_chip_info is not in the default
    // esp-idf-sys binding set; the efuse field API is).
    // The field descriptors are extern statics of type [*const esp_efuse_desc_t; 0]
    // (C flexible arrays); their address is the descriptor list the API wants.
    // With the pre-v3.0 efuse table the major version is split LO(2b)/HI(1b);
    // major = (HI << 2) | LO, same composition as IDF's efuse_ll.h.
    let rev_major = (read_efuse_field(
        core::ptr::addr_of_mut!(sys::ESP_EFUSE_WAFER_VERSION_MAJOR_HI).cast(),
    ) << 2)
        | read_efuse_field(core::ptr::addr_of_mut!(sys::ESP_EFUSE_WAFER_VERSION_MAJOR_LO).cast());
    let rev_minor =
        read_efuse_field(core::ptr::addr_of_mut!(sys::ESP_EFUSE_WAFER_VERSION_MINOR).cast());

    loop {
        log::info!("BigDice32 0.1.0-m1 hello");
        log::info!(
            "IDF {idf_version} | chip ESP32-P4 rev v{rev_major}.{rev_minor} | free heap {} bytes",
            unsafe { sys::esp_get_free_heap_size() }
        );
        thread::sleep(Duration::from_secs(1));
    }
    // Unreachable: c6_reset must never drop - dropping the PinDriver would
    // reset the pin and release the C6 from reset.
}

/// Read a whole eFuse field (e.g. wafer version major/minor) as a u32.
fn read_efuse_field(field: *mut *const sys::esp_efuse_desc_t) -> u32 {
    let bits = unsafe { sys::esp_efuse_get_field_size(field) };
    debug_assert!((1..=32).contains(&bits));
    let mut value: u32 = 0;
    let err = unsafe {
        sys::esp_efuse_read_field_blob(
            field,
            &mut value as *mut u32 as *mut core::ffi::c_void,
            bits as usize,
        )
    };
    if err != sys::ESP_OK {
        log::warn!("esp_efuse_read_field_blob failed: {err}");
    }
    value
}
