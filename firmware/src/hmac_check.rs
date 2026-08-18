//! The `esp-idf-hmac` exercise, run against VIRTUAL eFuses.
//!
//! Compiled only by `--features hmac-virtual-check`, which is not a product
//! feature and is not enabled by any release build. Its whole purpose is to
//! drive the crate's provisioning and HMAC paths on real silicon without
//! spending an irreversible resource, which is the only form of this test the
//! project's hardware budget permits: there are two ESP32-P4 boards, both must
//! stay eFuse-virgin, and there is no third (SECUREBOOT.md section 9).
//!
//! # What a virtual run proves, and what it cannot
//!
//! Under `CONFIG_EFUSE_VIRTUAL`, ESP-IDF's `esp_efuse_utility_burn_chip_opt()`
//! has no real-burn arm compiled in at all: it ORs the write registers into a
//! RAM mirror and logs that it is not really burning. So every eFuse write
//! below is a write to RAM, it dies with the power cycle, and no fuse is
//! touched. That is enough to prove:
//!
//! - the provisioning helper drives `esp_efuse_write_key()` correctly and the
//!   full protection ladder lands (purpose, `RD_DIS`, `WR_DIS`, purpose
//!   `WR_DIS`) rather than only some of it;
//! - the key-block readout reflects that state through the same API the Verify
//!   screen uses;
//! - `HmacKey::find()` locates the block by purpose;
//! - the two failure paths return the right typed errors.
//!
//! It cannot prove the silicon path, and step 6 is where that becomes visible
//! rather than being an assertion in a document. **The HMAC peripheral's
//! key-purpose check is performed by hardware against the REAL eFuse block.**
//! It does not consult the eFuse API and cannot see the RAM mirror, so on a
//! virgin part it reads purpose `USER`, sets `HMAC_QUERY_ERROR_REG`, and
//! `esp_hmac_calculate()` returns `ESP_FAIL`. The expected outcome of step 6 is
//! therefore `Error::PeripheralRefused`, and a run in which it unexpectedly
//! succeeded would mean a fuse had been burned.
//!
//! Read-protection BEHAVIOUR - that a read-protected block is unreadable by
//! software while the peripheral still uses it - is consequently **not verified
//! on hardware** by this or any other test in the tree, and must be recorded
//! that way rather than inferred from a green virtual run.

use esp_idf_hmac::key_block::{self, KeyPurpose};
use esp_idf_hmac::provisioning::Irreversible;
use esp_idf_hmac::{provisioning, Error, HmacKey, KeyBlock};

/// The block the exercise uses. Arbitrary, and irrelevant: nothing is
/// programmed. It is deliberately not KEY0, so a log reader cannot mistake the
/// output for the first block a real provisioning run would take.
const TEST_BLOCK: KeyBlock = KeyBlock::Key2;

/// A visibly fake key. Not a secret and not a value any device will ever hold;
/// it exists so the log shows which bytes were handed to the API.
const TEST_KEY: [u8; 32] = [0xa5; 32];

/// Run the exercise and log every step.
///
/// Returns `true` if every step produced its expected result. Never programs a
/// fuse: the first thing it does is refuse to run outside virtual mode, and the
/// crate's build script has already refused to compile this configuration
/// against real fuses without an explicit environment override.
pub fn run() -> bool {
    log::warn!("hmac-check: DEVELOPMENT BUILD - virtual eFuse exercise, not a product image");

    // Guard 1 of 2 (guard 2 is esp-idf-hmac's build script). Belt and braces on
    // purpose: this is the one code path in the tree that calls a burn API, and
    // the cost of a redundant check is nothing against the cost of being wrong.
    if !esp_idf_hmac::EFUSE_VIRTUAL {
        log::error!(
            "hmac-check: CONFIG_EFUSE_VIRTUAL is OFF. Refusing to run - this exercise \
             writes eFuse key material and the write would be permanent. Rebuild with \
             tools\\build.ps1 -Overlay firmware\\sdkconfig.efuse-virtual.defaults"
        );
        return false;
    }

    let mut ok = true;
    let mut step = |n: u32, what: &str, passed: bool, detail: &str| {
        if passed {
            log::info!("hmac-check: {n} {what}: pass ({detail})");
        } else {
            log::error!("hmac-check: {n} {what}: FAIL ({detail})");
            ok = false;
        }
        passed
    };

    // 1. The starting state: a virgin part has no committed key blocks.
    let before = key_block::state(TEST_BLOCK);
    step(
        1,
        "block starts unused",
        before.unused && before.purpose == KeyPurpose::User,
        &format!("{} {} unused {}", before.block.name(), before.purpose, before.unused),
    );

    // 2. No HMAC_UP block exists yet, and the error says exactly that.
    let found = HmacKey::find();
    step(
        2,
        "find() reports no HMAC_UP block",
        matches!(found, Err(Error::PurposeNotFound(KeyPurpose::HmacUp))),
        &format!("{found:?}"),
    );

    // 3. Burn (into RAM). This is the call the whole feature gate exists for.
    let burned = provisioning::burn_hmac_up_key(
        TEST_BLOCK,
        &TEST_KEY,
        Irreversible::i_understand_this_permanently_consumes_an_efuse_block(),
    );
    if !step(
        3,
        "burn_hmac_up_key into the RAM mirror",
        burned.is_ok(),
        &format!("{burned:?}"),
    ) {
        return false;
    }

    // 4. The whole protection ladder landed, not just part of it. ESP-IDF's
    //    esp_efuse_write_key() applies RD_DIS for HMAC_UP itself; this asserts
    //    that it did rather than trusting the documentation of it.
    let after = key_block::state(TEST_BLOCK);
    step(
        4,
        "purpose, RD_DIS, WR_DIS and purpose WR_DIS are all set",
        after.purpose == KeyPurpose::HmacUp
            && after.read_protected
            && after.write_protected
            && after.purpose_write_protected
            && !after.unused
            && after.is_sealed_hmac_up(),
        &format!(
            "{} rd_dis {} wr_dis {} purpose_wr_dis {}",
            after.purpose,
            after.read_protected as u8,
            after.write_protected as u8,
            after.purpose_write_protected as u8
        ),
    );

    // 5. The block is now discoverable by purpose.
    let key = HmacKey::find();
    let key = match key {
        Ok(k) => {
            step(
                5,
                "find() locates the HMAC_UP block",
                k.block() == TEST_BLOCK,
                k.block().name(),
            );
            k
        }
        Err(e) => {
            step(5, "find() locates the HMAC_UP block", false, &format!("{e:?}"));
            return false;
        }
    };

    // 6. The hardware disagrees, and MUST. See this module's header: the
    //    peripheral checks the real fuses, so a virtual key is refused. A
    //    success here would mean something was actually burned.
    let mac = key.mac(b"esp-idf-hmac virtual exercise");
    step(
        6,
        "peripheral refuses a virtual key (expected: hardware reads the real block)",
        matches!(mac, Err(Error::PeripheralRefused)),
        &match &mac {
            Ok(tag) => format!("UNEXPECTED SUCCESS, tag starts {:02x}{:02x}", tag[0], tag[1]),
            Err(e) => format!("{e}"),
        },
    );
    if mac.is_ok() {
        log::error!(
            "hmac-check: the peripheral accepted a VIRTUAL key block. That is only \
             possible if a real eFuse carries purpose HMAC_UP. STOP and read espefuse \
             summary before doing anything else with this board."
        );
    }

    // 7. Binding to a block committed to something else is refused, and the
    //    error names what it found - the state a mis-provisioned unit is in.
    let wrong = HmacKey::bind(KeyBlock::Key3);
    step(
        7,
        "bind() refuses a block with the wrong purpose",
        matches!(
            wrong,
            Err(Error::WrongPurpose {
                found: KeyPurpose::User,
                expected: KeyPurpose::HmacUp,
                ..
            })
        ),
        &format!("{wrong:?}"),
    );

    // 8. A second burn into the same block is refused before anything is
    //    written, which is what stops a retry loop spending a second block.
    let again = provisioning::burn_hmac_up_key(
        TEST_BLOCK,
        &TEST_KEY,
        Irreversible::i_understand_this_permanently_consumes_an_efuse_block(),
    );
    step(
        8,
        "a second burn into a used block is refused",
        matches!(
            again,
            Err(Error::BlockInUse {
                block: TEST_BLOCK,
                purpose: KeyPurpose::HmacUp,
            })
        ),
        &format!("{again:?}"),
    );

    log::warn!(
        "hmac-check: {} - every eFuse write above went to RAM and is gone at the next \
         power cycle. Read protection BEHAVIOUR on real silicon remains unverified.",
        if ok { "all steps passed" } else { "FAILURES ABOVE" }
    );
    ok
}
