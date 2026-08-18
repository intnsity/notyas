/*
 * SPDX-FileCopyrightText: 2026 intnsity
 * SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Bindgen surface for esp-idf-hmac.
 *
 * esp-idf-sys's default allowlist carries none of this: the HMAC peripheral is
 * absent entirely, and the eFuse surface stops at the handful of symbols the
 * default header happens to reach. Every declaration below is a REAL symbol -
 * ESP-IDF's security headers are full of `static inline` wrappers
 * (esp_secure_boot_enabled() is the notorious one) which bindgen cannot see at
 * any setting, so this crate binds the underlying functions instead and the
 * Rust side documents each equivalence.
 *
 * esp_hmac.h        - esp_hmac_calculate() (upstream mode), esp_hmac_jtag_enable()
 *                     / _disable() (downstream mode). Guarded by SOC_HMAC_SUPPORTED,
 *                     which is 1 on ESP32-P4; the header #errors out on a target
 *                     without the peripheral, so a build for such a target fails
 *                     here rather than at link time.
 * esp_efuse.h       - key-block purposes and their read/write protection, the
 *                     secure-boot key digests, the anti-rollback secure version.
 *                     Also pulls in esp_efuse_chip.h (esp_efuse_block_t,
 *                     esp_efuse_purpose_t) and the esp_secure_boot_key_digests_t
 *                     struct, which lives in THIS header rather than in
 *                     esp_secure_boot.h.
 * esp_efuse_table.h - the ESP_EFUSE_* descriptor tables. On ESP32-P4 this header
 *                     dispatches on CONFIG_ESP32P4_SELECTS_REV_LESS_V3 between two
 *                     generated tables that are NOT identical in field set: the
 *                     pre-v3 table has XTS_KEY_LENGTH_256 at BLK0 bit 78, the v3.0
 *                     table has KM_XTS_KEY_LENGTH_256 at the same bit with a
 *                     different meaning. src/posture.rs handles both.
 * esp_flash_encrypt.h - esp_flash_encryption_enabled() and
 *                     esp_get_flash_encryption_mode(). Both are real functions.
 * esp_mac.h         - esp_read_mac(), for the factory MAC in eFuse BLK1.
 * hal/efuse_hal.h   - efuse_hal_chip_revision() and the major/minor split. On the
 *                     pre-v3 P4 table the wafer major version is stored as two
 *                     fields (LO 2 bits, HI 1 bit) and the HAL is what composes
 *                     them; reading the CSV fields directly would get this wrong.
 */
#include "esp_hmac.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_flash_encrypt.h"
#include "esp_mac.h"
#include "hal/efuse_hal.h"
