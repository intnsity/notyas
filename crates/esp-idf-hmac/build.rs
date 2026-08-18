// SPDX-FileCopyrightText: 2026 intnsity
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Re-emits the four ESP-IDF configuration flags this crate compiles against,
//! and refuses to build a burn-capable binary by accident.
//!
//! esp-idf-sys turns every `CONFIG_X=y` in the merged sdkconfig into a
//! `cargo:rustc-cfg=esp_idf_x`, and propagates the whole set to its direct
//! dependents through the `DEP_ESP_IDF_EMBUILD_CFG_ARGS` metadata variable
//! (it declares `links = "esp_idf"`). `embuild::espidf::sysenv::output()` is
//! the usual way to re-emit them, but it re-emits all ~960 of them and costs a
//! build dependency to read one colon-separated string. This crate names the
//! four flags it actually uses, checks them, and depends on nothing.
//!
//! Naming them explicitly is not only about the dependency. An
//! `#[cfg(esp_idf_something_misspelled)]` silently evaluates false forever, and
//! silence is the failure mode a security readout can least afford; a flag that
//! must appear in this list to have any effect is a flag whose spelling was
//! reviewed once, here.

/// The ESP-IDF configuration flags this crate reads, and nothing else.
const CONSUMED: &[&str] = &[
    // CONFIG_SOC_HMAC_SUPPORTED - the HMAC peripheral exists on this target.
    "esp_idf_soc_hmac_supported",
    // CONFIG_EFUSE_VIRTUAL - the eFuse API is backed by a RAM copy. Reads still
    // show the real fuses (they are copied in at startup); writes go nowhere.
    "esp_idf_efuse_virtual",
    // CONFIG_IDF_TARGET_ESP32P4 - selects the P4 field set in src/posture.rs.
    "esp_idf_idf_target_esp32p4",
    // CONFIG_ESP32P4_SELECTS_REV_LESS_V3 - selects which of the two generated P4
    // eFuse tables is in scope. The two differ in field set, not only in bits.
    "esp_idf_esp32p4_selects_rev_less_v3",
];

fn main() {
    println!("cargo::rerun-if-env-changed=DEP_ESP_IDF_EMBUILD_CFG_ARGS");
    println!("cargo::rerun-if-env-changed=ESP_IDF_HMAC_ALLOW_REAL_EFUSE_BURN");

    for flag in CONSUMED {
        println!("cargo::rustc-check-cfg=cfg({flag})");
    }

    // Absent on a host or bare-metal build: the crate then compiles only its
    // pure `core` half, which is exactly what the host test suite exercises.
    let cfg_args = std::env::var("DEP_ESP_IDF_EMBUILD_CFG_ARGS").unwrap_or_default();
    let active: Vec<&str> = cfg_args.split(':').collect();

    for flag in CONSUMED {
        if active.contains(flag) {
            println!("cargo::rustc-cfg={flag}");
        }
    }

    // The burn firewall. `provisioning` compiles code that programs eFuses, and
    // an eFuse write cannot be undone on any ESP32 part: the block is spent, and
    // read-protecting one destroys the key value for every observer including
    // JTAG. The feature therefore may not be enabled by a build that could reach
    // real fuses unless the operator says so in the environment, out loud, on
    // the command line, once per shell. Cargo feature unification means a
    // transitive dependency can turn a feature on without the application
    // author noticing; it cannot set an environment variable on their behalf.
    if cfg!(feature = "provisioning")
        && !active.contains(&"esp_idf_efuse_virtual")
        && std::env::var("ESP_IDF_HMAC_ALLOW_REAL_EFUSE_BURN").as_deref() != Ok("1")
    {
        // Only a build that actually has an ESP-IDF behind it can burn anything;
        // a host `cargo check --all-features` has no fuses to spend.
        if !cfg_args.is_empty() {
            panic!(
                "esp-idf-hmac: feature `provisioning` is enabled, CONFIG_EFUSE_VIRTUAL is off, \
                 and ESP_IDF_HMAC_ALLOW_REAL_EFUSE_BURN is not set to 1.\n\
                 \n\
                 This build would be able to program eFuses on the attached device. eFuse \
                 writes are IRREVERSIBLE: a key block is spent permanently, and a \
                 read-protected block's value is unrecoverable by any means.\n\
                 \n\
                 To develop against the eFuse API safely, set CONFIG_EFUSE_VIRTUAL=y - the \
                 API is then backed by a RAM copy and writes touch no hardware.\n\
                 To provision a device for real, set ESP_IDF_HMAC_ALLOW_REAL_EFUSE_BURN=1 \
                 deliberately, and read the irreversibility ladder in src/provisioning.rs first."
            );
        }
    }
}
