<!--
SPDX-FileCopyrightText: 2026 intnsity
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# esp-idf-hmac

Safe Rust over the ESP32 HMAC peripheral and the eFuse state it depends on.

`esp-idf-sys`'s default binding surface carries neither. The HMAC peripheral is
absent entirely, and ESP-IDF's security headers are full of `static inline`
wrappers that bindgen cannot see at any setting, so a project that wants a
device-bound MAC or an honest eFuse readout has to build the binding surface
itself and then get a set of easily-transposed integer conventions right. This
crate does that once.

## What it gives you

**A device-bound MAC.** `HmacKey` computes HMAC-SHA256 under a key held in an
eFuse block that software cannot read. The handle carries a block index and
nothing else - no key, no buffer, no cached state - so a caller obtains a tag
only this physical part can produce, and no key material crosses the API. There
is deliberately no function in this crate that returns the contents of a key
block.

**The eFuse state that says whether that means anything.** A key in a block that
was never read-protected computes identical MACs and is a materially weaker
device. So the crate also reads out, as raw values: the six key blocks'
purposes and their read/write protection, Secure Boot v2 and the SHA-256 digests
of its enrolled public keys, flash encryption and its Development/Release mode,
the download-mode and JTAG field group, ROM logging, anti-rollback, and the
factory identity in eFuse (silicon revision, MAC, optional die unique ID).

## What it will not do

- **Hold a secret.** Nothing is compiled in and nothing is cached. Key material
  appears in exactly one signature - the optional provisioning burn - where the
  caller supplies it and it is handed to ESP-IDF without being copied.
- **Make a policy decision.** There is no `is_secure()`, no verdict, no
  threshold, and no default standing in for a value the hardware did not
  supply. ESP-IDF's `esp_flash_encryption_cfg_verify_release_mode()` exists for
  callers who want a judgement; this crate reports the fields it checks,
  individually.

Both are licensing constraints as much as design ones. The crate is
MIT OR Apache-2.0 and depends on nothing but `esp-idf-sys`, so any project can
adopt it.

## Using it

Add it as a **direct** dependency of your application crate:

```toml
[target.'cfg(target_os = "espidf")'.dependencies]
esp-idf-hmac = "0.1"
```

Direct matters. `esp-idf-sys` collects `extra_components` from the root crate
and from its direct dependencies only, and this crate's bindings header rides in
that way. Nothing else is needed: no fork of `esp-idf-sys`, no header of your
own, no `sdkconfig` entry.

```rust,ignore
use esp_idf_hmac::{key_block, HmacKey};

for st in key_block::all_states() {
    log::info!("{}  {}  rd_dis {}  wr_dis {}",
               st.block.name(), st.purpose,
               st.read_protected as u8, st.write_protected as u8);
}

let tag = HmacKey::find()?.mac(b"context||counter")?;
```

## Portability

Types, enumerator tables and their renderings are pure `core` and compile
everywhere; the crate is `no_std` and allocates nothing. The readers are
`#[cfg(target_os = "espidf")]`. The download / JTAG / ROM-log / flash-encryption
field group in `posture` is additionally ESP32-P4 only, because that field set
genuinely differs between parts - see below. `hmac`, `key_block`, `secure_boot`
and `identity` use target-generic ESP-IDF APIs.

## Notes from the silicon, in case they save you the afternoon

- **`EFUSE_BLK_KEY0` is block 4, and `HMAC_KEY0` is 0.** The same block has two
  numbers, four apart, and both are plain integers at the FFI boundary.
  `KeyBlock` owns the conversion and a host test pins it.
- **The HMAC peripheral's purpose check is in hardware.** It reads the real
  eFuse block. `CONFIG_EFUSE_VIRTUAL` cannot forge it: the eFuse API will
  cheerfully report a virtual block with purpose `HMAC_UP`, and the peripheral
  will still refuse it. Virtual eFuses exercise code, never silicon.
- **`esp_efuse_read_block()` performs no `RD_DIS` check.** A read-protected
  block returns `ESP_OK` and zeros, and `esp_secure_boot_read_key_digests()`
  hands back a pointer to the same registers. This crate checks read protection
  first and reports `DigestSlot::ReadProtected` rather than a row of zeros.
- **Secure-boot digests are readable by design.** `esp_efuse_write_key()`
  read-protects the XTS, ECDSA, HMAC and Key Manager purposes and deliberately
  does not read-protect the digest purposes. A digest of a public key is not a
  secret, and being able to show *which* key the ROM trusts is the difference
  between a checkbox and an answer.
- **`HARD_DIS_JTAG` does not exist on ESP32-P4.** It is on the S2 and S3 and it
  appears in cross-target documentation; ESP-IDF substitutes `DIS_PAD_JTAG` on
  the P4. The permanent lock there is `DIS_PAD_JTAG` and `DIS_USB_JTAG`
  together. Also absent on the P4: `DIS_LEGACY_SPI_BOOT`, `DIS_BOOT_REMAP`,
  `DIS_DOWNLOAD_ICACHE`, `DIS_DOWNLOAD_DCACHE`, `UART_DOWNLOAD_DIS`.
- **The ESP32-P4 has two eFuse tables and they differ in field set, not only in
  bits.** `esp_efuse_table.h` dispatches on `CONFIG_ESP32P4_SELECTS_REV_LESS_V3`.
  The pre-v3.0 table has `XTS_KEY_LENGTH_256` at BLK0 bit 78; the v3.0 table has
  `KM_XTS_KEY_LENGTH_256` at the same bit, selecting xts-512 versus xts-256 for
  the Key Manager rather than 128 versus 256 for flash encryption. They are not
  one field renamed, so `FlashEncryption::xts_key_length_256` is `None` on v3.0
  silicon rather than showing a bit whose meaning has moved.
- **`esp_efuse_read_field_blob()` retries with `vTaskDelay(1)`** on a
  coding-scheme recount disagreement, so it is not bounded-time. Do not call any
  of this from an ISR.

## Provisioning

`burn_hmac_up_key()` lives behind a non-default `provisioning` feature and is
fenced three ways: the feature, a build-script refusal when the build could
reach real fuses (`CONFIG_EFUSE_VIRTUAL` off and
`ESP_IDF_HMAC_ALLOW_REAL_EFUSE_BURN` unset), and a witness argument whose
constructor is named in full at every call site. eFuse writes cannot be undone
and a part has six key blocks and no seventh. Read `src/provisioning.rs` before
enabling it, and consider not enabling it: provisioning from the host with
`espefuse.py` prompts before every irreversible step and leaves an auditable
command line, which is the better default unless a device must provision itself
in the field.

## Licence

MIT OR Apache-2.0, at your option. See `LICENSE-MIT` and `LICENSE-APACHE`.
