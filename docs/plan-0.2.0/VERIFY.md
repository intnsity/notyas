# VERIFY.md - notyas 0.2.0 "Verify device" capability

Status: PLAN (buildable spec). Owner document for screen **S-46 Verify device** and for
everything the device reads in order to fill it. Companion to `UX-SCREENS.md` (which owns
the screen inventory, the component library and the copy vocabulary this document uses
without extending), `SECURITY.md` (invariants 5 and 6, and the tiered attacker-with-the-
device statement), `ARCHITECTURE.md` (partition layout 2.7, counters 2.5),
`ESP-SEAL.md` (the counters ledger and the eFuse key budget), `REPRODUCIBLE.md` (what a
published digest is and what it proves), and `PARITY.md` (the Coldcard rows this closes).

The question this document answers, as the project owner put it: **what else can the
Verify screen show so a customer can satisfy themselves that nothing else is running and
nothing has been modified - that the device is just running notyas?**

The short version of the answer, before the detail: the screen can show considerably more
than 0.1.0 shows, all of it raw and checkable - the two currently unverified members of
the trusted path (bootloader, partition table), an emptiness scan of every flash region
that is supposed to be blank, the full eFuse posture, hardware identity down to the flash
chip's own serial number, and a power-on counter. None of it, and nothing that could ever
be added to it, answers "nothing else is running" - because that answer would be given by
the software under suspicion. Section 8 states that boundary precisely and section 7
rejects, permanently, the class of indicator that pretends otherwise.

---

## 0. The design contract (normative - read before changing anything below)

S-46 is an **instrument panel**, not a report. Five binding rules; a change that breaks one
of them is a bug in the change.

1. **RAW VALUES, SHOWN.** The screen displays the actual data: full 64-character digests,
   the real eFuse field states, the chip revision, the MAC, the ROM banner string, the
   flash JEDEC and unique IDs, per-region hashes. No digest is truncated, abbreviated,
   replaced by a short stand-in, or hidden behind a "show full value" tap. There is no
   Advanced layer and no collapsed section. **Scrolling is acceptable; hiding is not.**
   Grouping a digest into blocks of four and wrapping it across lines is *formatting* and
   is required; substituting a shortened form for it is *obscuring* and is forbidden.

2. **NO OPINING.** Label the field, print the value, stop. No verdicts, no "protected", no
   "safe" or "unsafe", no risk language, no advice sentence, no interpretive gloss beside
   a value. `Secure boot   disabled` is the whole row. What that means for the reader is
   the reader's business and the documentation's job, not this screen's. This also
   forecloses status *badges*: no green ticks, no red crosses, no "GENUINE" stamp. The one
   place semantic colour survives is where 0.1.0 already uses it and where it restates a
   value rather than judging it - a `FAIL` self-test row and the radio-kill row - and even
   there the word carries the meaning and the colour only reinforces it.

3. **DESIGN CARRIES THE LOAD.** Digestibility comes from typography and structure:
   a fixed label column and value column, values in notyas Mono so digests align and can be
   compared column-by-column against another device or a printout, sections with headings
   that group related fields, generous vertical rhythm, hairline separators, and a **field
   order that is frozen** - the same field is at the same position in every build, so two
   devices side by side can be scanned rather than read. Section 5 specifies the geometry.

4. **CURATED, NOT EXHAUSTIVE.** Not every sdkconfig or kernel flag. Section 3 lists every
   field that ships with a one-line justification, and section 4 lists everything
   considered and left out with the reason, so the curation is reviewable rather than
   arbitrary.

5. **CAPTURE, NOT INTERPRETATION.** The screen presents; comparison happens elsewhere. A
   QR of the complete readout is an export affordance and ships (section 6.2). Judging the
   values against a published manifest is an off-device operation and the manifest exists
   to make it possible (section 6.3).

One further rule, inherited and unchanged from 0.1.0's `verify.rs` header comment and
`SECURITY.md` invariant 5: **every value is read from the running system, never compiled
in.** A field this build cannot read renders `not read` (0.1.0's honest placeholder), never
a plausible default.

---

## 1. What 0.1.0 reports today, and how

`firmware/src/verify.rs` builds a `notyas_ui::VerifyInfo` at boot and
`crates/notyas-ui/src/screens/verify.rs::content` renders it as nine `kv` rows in a single
scrolling column. The nine:

| Row | Source | Read how |
|---|---|---|
| Firmware version | `env!("CARGO_PKG_VERSION")` | compile-time (the only one) |
| Board | `board::BOARD_NAME`, `board::UNTESTED` | compile-time cfg |
| Platform | `esp_get_idf_version()` + `efuse_hal_chip_revision()` | run time |
| App SHA256 (running partition) | `esp_ota_get_running_partition()` -> `esp_partition_get_sha256()` | run time, from flash |
| Source id | - | hardcoded `"unavailable"` |
| Boot self-test | `notyas_core::selftest::SelfTest` | run time |
| Radio | `gpio_get_level(board::RADIO_KILL_GPIO)` | run time, actual pad level |
| Secure boot | `esp_efuse_read_field_bit(ESP_EFUSE_SECURE_BOOT_EN)` | run time, eFuse |
| Flash encryption | `esp_flash_encryption_enabled()` | run time, eFuse |

Two structural facts about that code carry into everything below.

- **The binding surface is a bindgen header, not the default allowlist.**
  `firmware/bindings/verify.h` is a `bindings_header`-only `extra_components` entry
  (`firmware/README.md` pitfall 13) pulling in `esp_partition.h`, `esp_ota_ops.h`,
  `esp_flash_encrypt.h`, `esp_efuse.h`, `esp_efuse_table.h` and `hal/efuse_hal.h`. Every
  new API this document proposes is added by extending that header - there is no other
  mechanism, and static-inline IDF functions (`esp_secure_boot_enabled()`,
  `esp_flash_encryption_enabled()`'s siblings) are not bindgen-able and must be reached
  through their underlying real symbols.
- **The eFuse descriptor table is revision-family dependent.** `esp_efuse_table.h`
  dispatches on `CONFIG_ESP32P4_SELECTS_REV_LESS_V3`, which
  `firmware/sdkconfig.base.defaults` pins for the rev v1.3 dev silicon
  (`firmware/README.md` pitfall 4; the pre-v3 table splits the wafer major version into
  LO/HI fields). Release hardware at rev >= v3.1 drops that option, so **every
  `ESP_EFUSE_*` symbol named in this document must be re-checked against the post-v3
  table when the production-silicon decision (`OPEN-QUESTIONS` Q9) lands.** That is a
  standing requirement, not a one-off.

What is *not* verified today, and is the substance of this document: the second-stage
bootloader at `0x2000`, the partition table at `0x8000`, every flash region that is
supposed to be empty, the eFuse posture beyond two bits, hardware identity, and any
persistent record that the device was powered on.

---

## 2. The firmware chain: hashing all three members of the trusted path

Three things execute before and as notyas runs. Exactly one of them is verified today.

```
  mask ROM  ->  second-stage bootloader (0x2000)  ->  app (0x10000)
  silicon        NOT hashed today                     hashed today
                 partition table (0x8000)
                 NOT hashed today - decides what exists in flash
```

The mask ROM is silicon and is covered as *identity* in section 4, not as an integrity check
(section 8, R7). The other two are code we build, publish and are accountable for, and they
are the gap this section closes.

`REPRODUCIBLE.md` 4.2 already argues why they matter, in the context of comparing published
artifacts, and the argument transfers verbatim to the device:

- The **bootloader** "runs before `app_main`, chooses and (under secure boot) authenticates
  the app, and is where the chip-revision gate lives... A substituted bootloader is a complete
  compromise that an app-only comparison misses." On this specific chip it is also the most
  likely *accidental* fault: `tools/flash.ps1` already warns about stale bootloaders, and
  `firmware/README.md` records that a bootloader built for the wrong P4 revision family
  flashes cleanly and then boot-loops printing the ROM banner. An app-only digest cannot
  distinguish that from a hardware fault.
- The **partition table** "defines what exists in flash. The whole stateless claim... is
  encoded in these 3 KB. If this region differs from the repo CSV, the device is not the
  device the security model describes." For 0.2.0 that is stronger, not weaker: the table now
  declares which partition is `encrypted` and which is plaintext, so a modified table is a way
  to turn flash encryption off for the wallet region without touching a single eFuse.

### 2.1 The app image (already implemented, semantics worth restating)

`esp_ota_get_running_partition()` -> `esp_partition_get_sha256(part, digest)`, exactly as
`firmware/src/verify.rs` does today. Two properties that carry into everything else:

- It hashes **from flash**, through the partition API, so it covers what the chip is
  executing rather than what the binary was compiled to claim. That is `SECURITY.md`
  invariant 5 in one function call and it is the model every new digest here follows.
- It returns the digest of the **image content**, which is **not** `sha256sum app.bin`.
  `REPRODUCIBLE.md` 4.3 spells this out and calls the confusion "the single most likely
  support question"; section 7.3 of this document removes it from the user's path by
  publishing both numbers in the manifest instead of asking the user to run `tail -c 32`.

The screen labels the row with its offset and length -
`App image (0x010000, 1 842 176 B)` - so the reader can see *what was hashed*, which is the
difference between a number and a checkable number.

Cost: the only one of the three that is not free. It is paid at boot today and
`verify.rs` already logs it (`"app sha256 (running partition, hashed in {} ms)"`); the number
is not recorded in the repo, so m1's **V1** measurement commits it on both boards rather than
this document guessing it.

### 2.2 The second-stage bootloader at 0x2000

**The offset is 0x2000 on ESP32-P4, and it is a P4 special case.** Not 0x0 like the other
RISC-V targets and not 0x1000 like the original ESP32.
`components/bootloader/Kconfig.projbuild`, verbatim:

```
config BOOTLOADER_OFFSET_IN_FLASH
    hex
    default 0x1000 if IDF_TARGET_ESP32 || IDF_TARGET_ESP32S2
    # the first 2 sectors are reserved for the key manager with AES-XTS (flash encryption) purpose
    default 0x2000 if IDF_TARGET_ESP32P4 || IDF_TARGET_ESP32C5 || IDF_TARGET_ESP32H4
    default 0x0
```

There is no prompt, so it is not user-settable: the ROM decides. The reserved first two
sectors are the Key Manager's, which is also why `0x000000-0x002000` is in the must-be-blank
class in section 3.1 rather than being part of the bootloader region.
https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-guides/startup.html

Region size is `ESP_BOOTLOADER_SIZE = ESP_PARTITION_TABLE_OFFSET - ESP_BOOTLOADER_OFFSET` =
`0x8000 - 0x2000` = **0x6000, 24 KiB** (`esp_flash_partitions.h`). Note the
`api-guides/bootloader.html` page renders the size limit as "0x8000 bytes", ignoring the
0x2000 start; the macro is authoritative.

**How it is hashed - one call, no manual parsing.** `esp_partition_get_sha256()` already
handles bootloader images. Its implementation is
`bootloader_common_get_sha256_of_partition(address, size, type, out)`, and that function
branches on the type: for `PART_TYPE_APP (0)` **and `PART_TYPE_BOOTLOADER (2)`** it calls
`esp_image_get_metadata()` to obtain `image_len` and then, when `hash_appended` is set,
returns the image's own stored digest after re-hashing `[address, address + image_len - 32)`
to verify it. For any other type it hashes the whole `size`.

So the bootloader digest is obtained exactly like the app digest, with the same semantics
(image-content digest, stopping before the appended 32 bytes), by filling a stack-local
`esp_partition_t` - IDF's own pattern in `esp_ota_ops.c`, and the header documents that only
three fields are required: *"(fields: address, size and type, are required to be filled)"*.

```
  address   = 0x2000                              (CONFIG_BOOTLOADER_OFFSET_IN_FLASH)
  size      = 0x6000                              (ESP_BOOTLOADER_SIZE)
  type      = ESP_PARTITION_TYPE_BOOTLOADER (2)
  encrypted = esp_flash_encryption_enabled()
```

Two alternatives were considered and are not used. A **CSV entry** (`gen_esp32part.py` accepts
type `bootloader`, subtype `primary`, auto-filling offset and size) would work and is the
sanctioned route, but it changes `firmware/partitions.csv` - a file whose current content is
part of the stateless claim and which `REPRODUCIBLE.md` publishes as its own artifact - to buy
nothing the stack-local struct does not already give. `esp_partition_register_external()` also
works but is undocumented for this use.
https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/storage/partition.html

**Getting the length independently.** If the length is wanted without the digest, the app can
call `esp_image_verify_bootloader(uint32_t *length)` (`bootloader_support/include/esp_image_format.h`)
- the doc says it plainly: *"it will be set to the length of the bootloader image"*. Both that
header and `esp_app_format.h` are in `bootloader_support`'s **public** include directory and
`esp_image_format.c` is compiled into the app under the default
`CONFIG_APP_BUILD_TYPE_APP_2NDBOOT`, so this is app-callable - but `bootloader_support` must be
added to the component's `REQUIRES`/`PRIV_REQUIRES`, because it is not in `requires_common`.
Note also `esp_app_format.h` lives under `bootloader_support/include/`, **not** under
`esp_app_format/include/` (that path does not exist).

**A second, cheaper row that catches the same bug.**
`esp_ota_get_bootloader_description(NULL, &desc)` (`esp_ota_ops.h`; NULL means the primary
bootloader at the configured offset) fills an `esp_bootloader_desc_t` carrying `version`,
`idf_ver[32]`, `date_time[24]` and `secure_version`. Printing the bootloader's IDF version
next to the app's is a one-line row that catches the single most likely real-world fault on
this project - a stale bootloader from a different build, which `tools/flash.ps1` already warns
about and `firmware/README.md` records as a boot loop on the wrong revision family. A digest
mismatch tells you something is wrong; two different IDF version strings tell you *what*.

**Cost: sub-millisecond.** 24 KiB at any plausible flash rate is a rounding error; see 2.5.

### 2.3 The partition table at 0x8000

Constants, from `bootloader_support/include/esp_flash_partitions.h`:

```c
#define ESP_PARTITION_MAGIC             0x50AA
#define ESP_PARTITION_MAGIC_MD5         0xEBEB
#define ESP_PARTITION_TABLE_OFFSET      CONFIG_PARTITION_TABLE_OFFSET   /* 0x8000 */
#define ESP_PARTITION_TABLE_MAX_LEN     0xC00
#define ESP_PARTITION_TABLE_MAX_ENTRIES (ESP_PARTITION_TABLE_MAX_LEN / sizeof(esp_partition_info_t))
```

`esp_partition_info_t` is 32 bytes (`magic`, `type`, `subtype`, `pos`, `label[16]`, `flags`).
The table ends with an MD5 record - a 32-byte entry whose magic is `0xEBEB` and whose digest
sits at `+16`, covering `num_parts * 32` bytes of preceding entries - and everything after it
is `0xff`.

**There is no API that returns the raw table bytes or its used length.** The app reads it:

1. Read `ESP_PARTITION_TABLE_MAX_LEN` (0xC00) into RAM through a stack-local
   `esp_partition_t` with `.address = 0x8000`, `.size = 0xC00`,
   `.type = ESP_PARTITION_TYPE_PARTITION_TABLE (3)`, `.encrypted =
   esp_flash_encryption_enabled()`. That single path is correct whether or not encryption is
   on, which is why it is preferred over `esp_flash_read_encrypted()`.
2. `esp_partition_table_verify(buf, /*log_errors=*/false, &num_partitions)` -
   **app-callable** (public header, `flash_partitions.c` compiled into the app). It validates
   the magics and the MD5 and yields the entry count, excluding the MD5 record.
3. **Used length = `(num_partitions + 1) * 32`** with `CONFIG_PARTITION_TABLE_MD5=y`.
   SHA-256 exactly that many bytes.

**DECISION - hash the used length, not the padded region.** 0xC00 is a fixed 3072 bytes of
which most is `0xff` padding, and hashing it would produce a number that matches no published
artifact. Hashing the used length produces a number the build can compute directly from the
same bytes it writes into `partition-table.bin`. The screen prints the length beside the
digest (`Partition table (0x008000, 128 B)`) so the reader can see what was hashed, and the
manifest (7.3) publishes `partition_table_sha256` over exactly that length **plus**
`partition_table_file_sha256` over the artifact file - the same both-numbers discipline the app
digest needs, for the same reason, and confirmed empirically at m1 rather than assumed here.
Whether the two coincide depends on whether the image producer pads the file (`OPEN-QUESTIONS`
Q27 has not yet settled esptool versus espflash as the normative producer), which is precisely
why both are published instead of one being explained.

**Why this region is worth a row at all**, restating `REPRODUCIBLE.md` 4.2 for 0.2.0: the table
declares which partition carries the `encrypted` flag. A modified table is a way to turn flash
encryption off for the wallet region without touching a single eFuse, and an app-only digest
comparison does not see it.

**Cost: sub-millisecond.** 3 KiB read plus one MD5 and one SHA-256 over at most 3 KiB.

### 2.4 The composite `firmware_digest`

Three region digests are three numbers, and a user asked to compare three numbers compares
one. So the screen shows all three (contract rule 1 - nothing is hidden) **and** one composite
over them, and the composite is the number `VERIFYING.md` tells people to check first.

```
  firmware_digest = SHA-256(
        "notyas-fw-digest/1"            // 18-byte ASCII domain tag
     || 0x00                            // tag terminator
     || u32le(bootloader_len) || bootloader_image_sha256   // 0x2000
     || u32le(pt_len)         || partition_table_sha256    // 0x8000
     || u32le(app_len)        || app_image_sha256          // 0x10000
  )
```

Four properties, each deliberate:

- **Domain-separated.** The tag means this digest can never collide with a raw SHA-256 of
  anything else in the system, and a future `notyas-fw-digest/2` (a fourth region, a changed
  offset) is a different, obviously-different value rather than a silent redefinition.
- **Length-prefixed.** Concatenating three fixed-32-byte digests would technically be
  unambiguous, but including the lengths makes the composite change when an image's length
  changes even in the pathological case, and - more usefully - it makes the composite
  reconstructible by hand from the three numbers plus three integers that are all printed on
  the same screen.
- **Fixed region order**, low offset to high. Not sorted by name, not by size.
- **Computable off-device from published artifacts alone**, with no access to a device. The
  manifest (7.3) carries every input, so a third party who rebuilds from source per
  `REPRODUCIBLE.md` section 3 can compute the number a device should show without owning one.
  This is what makes the multi-party attestation idea in `OPEN-QUESTIONS` Q31 apply to the
  device screen and not just to the release files.

**It is a convenience, not a security boundary.** It compresses three comparisons into one; it
adds no property the three digests do not already have, and a user who compares all three has
done strictly more. The screen shows it first because it is the cheapest correct check, and
shows the three components immediately below it because contract rule 1 says nothing is
hidden.

**Frozen at m1.** The construction is an input to the release manifest, which is m12's
artifact set, and changing it after a release would silently invalidate every published
number. It is one paragraph of specification and it costs nothing to fix early.

### 2.5 Cost, at boot and on demand

The measured numbers come from m1's **V1** and **V2** runs (section 13). The arithmetic below
is what to expect and why, so that a wildly different measurement is recognised as a bug
rather than accepted as fact.

**No published ESP32-P4 throughput number exists** for either SHA-256 or `esp_flash_read`.
IDF's `idf_performance.h` has no SHA, AES or SPI-flash constant for P4 (the P4 lacks
`SOC_CCOMP_TIMER_SUPPORTED`, so its benchmarks log without asserting). The nearest published
figure is the ESP32-S3 CI *floor* of 90 MB/s for SHA-256, which is a different chip and a
minimum rather than a measurement. This document therefore states arithmetic, not results.

Flash side: P4 has **no octal flash** (`ESPTOOLPY_OCT_FLASH` depends on
`SOC_SPI_MEM_SUPPORT_FLASH_OPI_MODE`, undefined on P4), so QIO/QOUT/DIO/DOUT only, default
**80 MHz** (`components/spi_flash/esp32p4/Kconfig.flash_freq`; 120 MHz exists behind
`IDF_EXPERIMENTAL_FEATURES`). `esp_flash_read()` issues one SPI transaction per **64 bytes**
(`SPI_FLASH_HAL_MAX_READ_BYTES 64`), which caps the practical ceiling near **34.6 MB/s** at
80 MHz once command, address and dummy clocks are counted.

SHA side, and this is the non-obvious one: **`esp_partition_get_sha256()` does not use the
SHA DMA engine.** It hashes through `bootloader_mmap()`/`spi_flash_mmap()` and feeds
mbedtls the mapped pointer; P4's DMA-capable window is internal L2MEM
(`SOC_DMA_LOW/HIGH` = 0x4FF00000-0x4FFC0000) while the flash cache window is 0x40000000, so
`s_check_dma_capable()` fails and `sha.c` falls back to CPU block mode with the comment
*"DMA cannot access memory in flash, hash block by block instead of using DMA"*. This costs
throughput and it is fine for the app image; it matters for the reserved-space scan, which is
why the scan reads into internal RAM and hashes from there rather than reusing the mmap path.
It is also **not reentrant** (*"tried to bootloader_mmap twice"*), so the three region digests
are computed sequentially.

| Operation | Bytes | Expectation | When |
|---|---|---|---|
| App image | ~1.8 MB | tens of ms; 0.1.0 already logs the real number (`verify.rs`), which m1 **V1** commits | boot (already paid today) |
| Bootloader image | 24 KiB | **sub-ms** | boot |
| Partition table | <= 3 KiB | **sub-ms** | boot |
| Composite `firmware_digest` | 104 B | **microseconds** | boot |
| eFuse section, entire | - | **microseconds** (memory-mapped register reads, section 5) | boot |
| Identity section, entire | - | **microseconds**, except the flash IDs which are two short SPI transactions | boot |
| Reserved-space scan | ~14.0 MiB (16 MB board) / ~30.0 MiB (32 MB board), for a 1.8 MiB app image | **~0.6-1.1 s at 16 MB, ~1.1-1.8 s at 32 MB** at 80 MHz with double-buffered read-and-hash; flash read dominates SHA by 1.5x to 4.5x | **on demand** |
| `wallets` / `counters` raw digests | 272 KiB | tens of ms | on demand |

**The boot budget is therefore essentially unchanged from 0.1.0.** Everything new that runs at
boot is sub-millisecond or microseconds; the one expensive operation is on demand behind a
button with a C3 determinate Busy screen. That is the whole reason the reserved-space scan is
not a boot-time check (section 3.4).

---

## 3. Whole-flash attestation: which regions, and why not one number

The instinct is right and the naive implementation is wrong. The instinct: hash *everything*,
including the space nothing is supposed to occupy, so a payload hidden in a spare sector
changes the number. The naive implementation: one SHA-256 over the whole chip. That number is
useless here, and it is worth being precise about why, because the reasons determine the
design.

### 3.1 The flash map, classified

One shared partition table across both boards - the **frozen** geometry of the ratified
`OPEN-QUESTIONS` Q7 / `MILESTONES` R2, restated in `ARCHITECTURE.md` 2.7, sized within the
smaller 16 MB part (`docs/BOARDS.md`); the Waveshare's extra 16 MB is unmapped by design:

```
  0x000000 .. 0x002000       8 KiB   pre-bootloader reserved
  0x002000 .. 0x008000      24 KiB   second-stage bootloader image, then padding
  0x008000 .. 0x009000       4 KiB   partition table (<= 0xC00 used), then padding
  0x009000 .. 0x010000      28 KiB   gap - no partition covers this
  0x010000 .. 0xE00000   13.94 MiB   factory app: image, then padding
  0xE00000 .. 0xE40000     256 KiB   wallets   (encrypted)
  0xE40000 .. 0xE44000      16 KiB   counters  (plaintext)
  0xE44000 .. flash_end             unmapped tail: 1.73 MiB (16 MB) / 17.73 MiB (32 MB)
```

**This document was drafted against the superseded 4 MiB-app layout (`wallets` at
`0x410000`, `counters` at `0x450000`, an 11.7 MiB tail) and is corrected in place
2026-08-17.** The correction is not cosmetic for section 3, because it moves where the
blank space *is*: the app partition is declared at its collision bound, so almost all of
the must-be-blank space is now the **app tail** rather than the unmapped tail, and on
board B the unmapped tail shrinks from 11.7 MiB to 1.73 MiB. That matters because the app
tail is exactly the region the merged-image caveat below covers, and the tail is the
region it does not. The honest consequence is stated where the argument is made, at the
end of 3.3.

Three classes, and the class decides the treatment:

| Class | Regions | Expected value | Comparable against |
|---|---|---|---|
| **Immutable code** | bootloader image, partition table, app image | fixed per release+board | the published manifest (7.3) |
| **Must be blank** | `0x000000-0x002000`, bootloader tail, partition-table tail, `0x009000-0x010000`, app tail, `0xE44000-end` | erased flash, raw `0xff` | a **universal constant**, no manifest needed |
| **Mutable by design** | `wallets`, `counters` | changes as the device is used | nothing; reported as-is |

### 3.2 Why one whole-flash digest cannot work

Four independent reasons, each fatal on its own:

1. **`wallets` and `counters` legitimately change.** Saving a wallet, a wrong PIN, a
   successful unlock, a boot - every one of them rewrites bytes. A whole-flash digest would
   change constantly for entirely correct reasons, which trains the owner that a changed
   number means nothing. That is the single worst outcome available: a verification value
   nobody looks at.
2. **`wallets` is XTS-encrypted with a per-device key.** Its ciphertext is device-unique by
   construction, so even two identical devices with identical wallets produce different bytes.
   There is no publishable value. (On a dev board the `encrypted` flag is inert because no
   XTS key is burned - `MILESTONES` R17 - so the raw view is the AEAD record itself. The
   conclusion is unchanged either way: an AEAD record sealed under a device-bound ladder is
   just as device-unique as its XTS wrapper, so there is still nothing to publish.)
3. **Erased flash inside an encrypted partition does not read back as `0xff`.**
   `esp_partition_read()` decrypts, so an erased sector in the `wallets` partition decrypts to
   **pseudorandom bytes**. This is documented in `ESP-SEAL.md` (the `Flash::is_erased` trait
   method exists precisely because of it, with the comment "MUST be implemented against the
   RAW (undecrypted) view ... `read()` can never be used to test for erasure", and `SimFlash`
   is configurable to reproduce it so the mistake fails in host tests rather than on release
   silicon). Any emptiness test written against the decrypting view is not merely inaccurate,
   it is inverted: it sees noise where there is nothing. This trap is live on release units
   only - a dev board with no XTS key burned decrypts nothing - which is precisely why the
   rule is applied uniformly rather than conditionally: code that is correct only on the
   hardware it was tested on is code that fails on the hardware that matters.
4. **The flash sizes differ between boards.** 16 MB versus 32 MB, same partition table, so a
   whole-chip digest is not even the same length of input on the two shipped units.

### 3.3 The scheme: two digests and one scan, each with a defined comparand

**Rule that resolves the encryption traps, applied uniformly:**

> **Content is hashed on the decrypted view. Emptiness is tested on the raw view.**

Both halves matter. Content on the decrypted view, because the published artifact is the
plaintext image and a raw read of an encrypted unit returns device-unique ciphertext that
matches nothing. Emptiness on the raw view, because erased flash is physically `0xff`
regardless of encryption, while the decrypted view of erased flash is pseudorandom (3.2 item
3). Getting either half backwards produces a value that looks fine and means nothing.

**(A) `firmware_digest`** - the one number for the immutable code. Section 2.4 defines the
construction. Comparand: the published manifest. Cost: boot-time, dominated by the app hash
that 0.1.0 already pays.

**(B) Reserved-space scan** - the emptiness proof, and the honest answer to "a hidden payload
in a spare sector". Raw read of every must-be-blank span, reported **per span** rather than as
one digest:

Illustrative, on a 32 MB board, for a build whose bootloader is 22 352 B and whose app
image is 1 842 176 B. **Only the four fixed boundaries are constants; every span that
begins at the end of an image moves with the build**, which is why the manifest (7.3)
publishes the image lengths and the screen prints the spans it actually scanned rather
than a compiled-in list:

```
  Reserved space
    0x000000-0x002000        8 192 B   all 0xff
    0x007750-0x008000        2 224 B   all 0xff
    0x008080-0x010000       32 640 B   all 0xff
    0x1d1c00-0xe00000   12 772 352 B   all 0xff
    0xe44000-0x2000000  18 595 840 B   all 0xff
    digest  < K2 block, 64 hex over the concatenated spans >
```

(Spans are listed and hashed in address order, which is also the order the digest
concatenates them in. The earlier draft of this block omitted each image's base offset
when computing where its tail began - a tail starts at `base + length`, not at `length` -
and that arithmetic is corrected here along with the geometry.)

A span that is not blank reports the count and the first offset:
`0xe44000-0x2000000   18 595 840 B   4 096 set, first 0x0a12000`.

Per-span rather than aggregate for a reason that is entirely about being useful: an aggregate
"not blank" tells the owner nothing they can act on, whereas an offset tells them, and anyone
they report it to, exactly where to look. The concatenated digest is there so two devices can
be compared and so the value survives the QR export; the per-span lines are what a human
reads.

**Why this beats a whole-flash digest even where a whole-flash digest would work:** the
comparand is `0xff`, a constant known to everyone, with no manifest, no release page and no
network. It is the only value on this screen the user can check without obtaining anything
from anywhere.

**Honest limits, all three of which go in `VERIFYING.md`:**

- **A merged-image flash writes the padding.** `REPRODUCIBLE.md` 3.3 produces a
  `merged.bin` "0x2000..end, 0xFF padded" for single-file flashing. Flashing that image
  *writes* those `0xff` bytes rather than leaving the sectors erased. On an unencrypted unit
  the raw bytes are still `0xff` and the scan is unaffected. **On an encrypted unit they are
  not**: esptool encrypts what it writes, so written-`0xff` becomes ciphertext and the spans
  between `0x2000` and the end of the app read as non-blank. That is a flashing-method
  artefact, not a finding. Consequence: the scan's strongest region is the **unmapped tail
  above `0xE44000`**, which no image ever covers.
- **The frozen geometry makes that strongest region small on board B, and this is the one
  place the Q7 freeze costs this feature something.** The tail is 1.73 MiB on the 16 MB
  board and 17.73 MiB on the 32 MB board; the bulk of the blank space - about 12.8 MiB on
  a 1.8 MiB image - is now the **app tail**, inside the app partition, which is exactly the
  span a merged-image flash writes. So on a release board B flashed from `merged.bin`, the
  span that a payload would most plausibly occupy is also the span the scan cannot
  distinguish from a normal flashing method, and only 1.73 MiB is scanned with full
  confidence. Three things keep this honest rather than fatal, and all three go in
  `VERIFYING.md`: flashing the artifacts separately rather than as `merged.bin` leaves the
  app tail genuinely erased and restores the scan's reach; on an UNencrypted unit the
  written padding is still raw `0xff`, so the scan is unaffected regardless of method; and
  the per-span report makes which case the owner is in visible rather than hidden inside an
  aggregate. What must NOT happen is the scan quietly excluding the app tail to avoid false
  positives - that would trade a legible caveat for an invisible blind spot.
- The scan reports raw bytes and does not interpret them. `all 0xff` means those sectors are
  erased. Anything else means bytes are present, which may be a merged-image flash, a previous
  firmware's data partition, factory test residue, or a payload. The screen prints which; the
  documentation explains the cases.
- Like everything else here, the scan is performed and reported by the firmware under
  suspicion (section 9).

**(C) Mutable-region digests** - `wallets` and `counters`, raw view, reported as digests with
no published comparand. Their use is longitudinal: the owner compares today's value against
the one they captured yesterday. `counters` is expected to change on every boot (the boot
counter is in it); `wallets` changes only when a wallet is saved, deleted or re-sealed, which
makes it the more interesting of the two. Pre-PIN visibility of the `wallets` digest is
governed by section 7.4 and interacts with `OPEN-QUESTIONS` Q2.

### 3.4 Cost

The reserved-space scan reads and hashes roughly 14 MiB on board B and 30 MiB on board A -
the app tail dominates on both, because the frozen geometry declares the app at its
collision bound (3.1). That is on-demand behind `[ Scan ]`
with a C3 determinate Busy screen ("Reading flash", "span 3 of 5", byte progress), never at
boot: the C3 law requires a painted frame for anything over 150 ms, and adding seconds to
every boot for a value that changes only when someone has written outside the partitions is
the wrong trade. Section 2.5 has the arithmetic and m1's **V2** measurement, which sizes it on
both fitted parts; the honest expectation is roughly 0.5-0.9 s on the 16 MB board and
1.0-1.7 s on the 32 MB board.

---

## 4. Silicon and hardware identity

Identity answers a different question from integrity: not "is the code what it should be" but
"is this the physical object I own". A substituted unit running perfectly good notyas firmware
is still a substituted unit, and the lock-screen word (`UX-SCREENS.md` S-03) has a documented
limit - it defeats swap-by-a-stranger, not substitution by someone who held the device long
enough to read the word off it.

Note the exact shape of what identity buys, because it is narrower than it looks. A substituted
unit running *honest* notyas firmware reports its own, different values, so identity catches
the cheap substitution. A substituted unit running *hostile* firmware reports whatever it
likes, so identity does not catch the expensive one. What it does is move the attacker from
"buy an identical board and flash the release image" to "buy an identical board and write
custom firmware that impersonates one specific unit's MAC, die ID, flash JEDEC ID and flash
serial number". That is a different budget, and it is the same budget secure boot addresses
from the other side.

### 4.1 Board (compile-time, and the run-time values that check it)

`board::BOARD_NAME` is a `cfg` constant - one of only two compiled-in values on the screen (the
other is the semver). It is a *claim by the build*, not a measurement, and the honest way to
place a claim on this screen is directly above the measurements that constrain it: flash size
and JEDEC ID are read from the fitted part at run time, and the two shipped boards differ in
exactly those (Waveshare 4B: 32 MB; Elecrow 5: 16 MB - `docs/BOARDS.md`). A `waveshare-4b`
build reporting 16 MB of flash is a contradiction the reader can see without being told to
look for it, because the rows are adjacent. 0.1.0's `UNTESTED CONFIG` suffix for scaffold
boards is unchanged.

### 4.2 Chip and revision

`efuse_hal_chip_revision()` (`hal/efuse_hal.h`, already bound in `firmware/bindings/verify.h`)
returns `major * 100 + minor`, so **rev v1.3 reads 103**. Also available and worth binding for
clarity: `efuse_hal_get_major_chip_version()` / `efuse_hal_get_minor_chip_version()`.
0.1.0 renders `ESP32-P4 rev v1.3` from the composite; the new layout splits it into `Chip` and
`Chip revision` because they answer different questions and the value column is 23 characters.

`esp_chip_info()` is deliberately **not** used. Two reasons, the second decisive: it is not in
the default esp-idf-sys binding allowlist (`firmware/README.md` pitfall 4), and on P4 its
implementation is four assignments with `features = 0` unconditionally
(`esp_hw_support/port/esp32p4/chip_info.c`), so it carries no information the HAL call does
not. Nothing on this screen may infer PSRAM or embedded flash from it.

The revision is not decoration: it selects the eFuse table variant (section 5's standing
caveat) and it is what `CONFIG_ESP32P4_SELECTS_REV_LESS_V3` / `CONFIG_ESP32P4_REV_MIN_100`
exist to gate. v5.5 supports P4 v0.0 through v1.99 (`ESP32P4_REV_MAX_FULL = 199`).
https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/system/chip_revision.html

### 4.3 Boot ROM version - readable, and not the way you would guess

**The ROM banner string is not reliably readable from the app.** The banner
(`ESP-ROM:esp32p4-eco2-20240710`, which is what this project's own boards print - it is
recorded verbatim in `firmware/README.md`) lives in ROM `.rodata`, but **not at a stable
address**: it is at `0x4fc1d18c` in `esp32p4_rev0_rom.elf` and `0x4fc1d4dc` in
`esp32p4_rev300_rom.elf`. Scanning ROM for it would be a heuristic, and heuristics do not
belong on this screen.

**What is stable is a pair of linker symbols.**
`components/esp_rom/esp32p4/ld/esp32p4.rom.version.ld`, verbatim:

```
/* These addresses should be compatible with any ROM version for this chip. */
_rom_chip_id = 0x4fc00010;
_rom_eco_version = 0x4fc00014;
```

They are linked into **every** P4 app and bootloader (`esp_rom/CMakeLists.txt`, the "linked
both for bootloader and app builds" block, guarded by `CONFIG_ESP_ROM_HAS_VERSION`, which
`esp_rom_caps.h` defines as 1 for P4 and Kconfig defaults to `y`). IDF reads them itself the
same way, e.g. `extern uint32_t _rom_eco_version;` in `bootloader_ecdsa.c`. Verified across
both published ROM ELFs: rev0 gives `_rom_chip_id = 0x12` (18 = ESP32-P4) and
`_rom_eco_version = 0`; rev300 gives `0x12` and `5`. The eco value equals the `ecoN` in the
banner, and the symbol address did not move between the Aug-2023 and Apr-2025 ROMs.

**Screen rows:** `Boot ROM` = the eco version as a number, and `ROM chip id` = the chip id as
hex. The banner-string-to-revision mapping goes in `VERIFYING.md`, not on the device, because
Espressif does not publish it - the errata explicitly retires ECO numbering ("The vM.X scheme
replaces previously used chip revision schemes, including ECOx numbers"). The reconstructed
table, with its confidence marked, for the documentation:

| Banner | eco | Chip revision | Confidence |
|---|---|---|---|
| `esp32p4-20230811` | 0 | v0.0 | confirmed (ROM ELF) |
| `esp32p4-eco1-20240205` | 1 | v1.0 | inferred by ordering only |
| `esp32p4-eco2-20240710` | 2 | **v1.3** | confirmed - this project's boards |
| `esp32p4-eco5-20250430` | 5 | v3.0 | confirmed (ROM ELF) |
| `esp32p4-eco6-20251011` | 6 | v3.1 | confirmed (public log) |

**Can the ROM region be hashed?** Yes, technically, and the answer is worth recording because
it will be asked. The HP ROM is 128 KiB at `0x4FC00000-0x4FC20000` (`soc.h`:
`SOC_IROM_MASK_LOW/HIGH`, `SOC_DROM_MASK_LOW/HIGH` - unified on P4; TRM ch.8 table 8.3-1, with
an uncached alias at `0x8FC00000`), and a normal app can read it without faulting:
`esp_hw_support/port/esp32p4/cpu_region_protect.c` sets a **locked PMP entry with R+X over
exactly that range** in both the bootloader and app paths, and PMA entry 13 marks it valid and
cacheable. Loads succeed, stores fault. There is also a 16 KiB LP ROM at
`0x50100000-0x50104000` with no PMP entry (M-mode default-permit, so probably readable -
derived, not tested).

**It is nonetheless not on the screen, and section 8 R7 gives the principled reason** (the ROM
is silicon; a digest of it can never detect a modification, only a different chip, which the
eco version and revision already report more legibly). There is now also a practical reason:
**no offline reference digest can be computed.** Espressif published exactly two P4 ROM ELFs,
they cover only 97.5% and 99.4% of the 128 KiB, and IDF v5.5 pins `esp-rom-elfs 20241011`
which contains only rev0 - the ROM these boards actually run has never been released in
symbolised form. A device-side digest would be deterministic but comparable only against a
value enrolled from a known-good unit. See section 14's `OPEN:` on this; the recommendation is
to report the eco version and revisit a ROM digest only if the project ever runs the
multi-party enrolment `OPEN-QUESTIONS` Q31 contemplates.

Espressif states the immutability but says nothing about attestation: *"Reset vector code is
located in the mask ROM of the ESP32-P4 chip and cannot be modified"* (startup guide);
*"This read-only memory is dedicated to the HP system and is not programmable"* (TRM).
ESP-TEE's attestation token covers bootloader, TEE and app digests plus the eFuse SoC
revision - the ROM is not hashed anywhere in ESP-IDF.
`SECURITY.md` invariant 6's phrase - "the only non-reproducible element below our code is the
mask ROM, whose behavior the ROM banner and revision readout expose" - is satisfied by these
two rows, and this section is the detail behind it.

### 4.4 MAC address

`esp_read_mac(uint8_t mac[6], ESP_MAC_BASE)` (`esp_mac.h`), or equivalently
`esp_efuse_mac_get_default()`. `ESP_EFUSE_MAC` is BLK1 bits 0..47 (`ESP_EFUSE_MAC_FACTORY` is
an alias for it), and `esp_efuse_mac_get_default()` on P4 is a plain
`esp_efuse_read_field_blob` with **no CRC check** - the CRC branch is `#ifdef
CONFIG_IDF_TARGET_ESP32`.

P4 has no radio, so most of `esp_mac_type_t` is unavailable at run time even though the
enumerators exist unconditionally. Valid on P4: `ESP_MAC_BASE`, `ESP_MAC_ETH`,
`ESP_MAC_EFUSE_FACTORY`, `ESP_MAC_EFUSE_CUSTOM`. Invalid (`ESP_ERR_NOT_SUPPORTED` from
`get_idx()`): `ESP_MAC_WIFI_STA`, `ESP_MAC_WIFI_SOFTAP`, `ESP_MAC_BT`, `ESP_MAC_IEEE802154`,
`ESP_MAC_EFUSE_EXT`. Note that on P4 **`ESP_MAC_ETH` equals the base MAC exactly** - the usual
`mac[5] += 3` is inside `#if SOC_WIFI_SUPPORTED || CONFIG_ESP_MAC_ADDR_UNIVERSE_BT`, neither of
which holds - and `esp32p4/Kconfig.mac` offers exactly one option
(`ESP32P4_UNIVERSAL_MAC_ADDRESSES_ONE`, universe ETH). Espressif: *"ESP32-P4 comes
pre-programmed with enough valid Espressif universally administered MAC addresses for all
internal interfaces."*
https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/system/misc_system_api.html

**Rendered in canonical lowercase colon-separated form** (`60:55:f9:xx:xx:xx`), which is a
deliberate exception to the house group-of-four rule for long values: this is the form
`esptool chip_id` prints, and the whole purpose of the row is comparing it against what the
owner recorded from exactly that tool. Comparing like with like beats internal consistency
here. 17 characters, so it fits the 23-character inline budget.

**This value is not a secret**, and treating it as one would be theatre: it is in eFuse BLK1,
which any flash-mode read or `esptool` invocation returns, and it is a *label*, not a key.
Section 7.4 shows it pre-PIN for exactly that reason.

### 4.5 Die unique ID

`ESP_EFUSE_OPTIONAL_UNIQUE_ID` **exists on ESP32-P4**. From
`components/efuse/esp32p4/esp_efuse_table.csv`:

```
OPTIONAL_UNIQUE_ID,   EFUSE_BLK2,   0, 128, [] Optional unique 128-bit ID
```

Read with `esp_efuse_read_field_blob(ESP_EFUSE_OPTIONAL_UNIQUE_ID, buf, 128)` - note the size
argument is in **bits**, so 128 fills 16 bytes.

**Two honest caveats, both of which change the row rather than removing it.** Nothing in
ESP-IDF reads this field, and no Espressif statement was found confirming that it is burned on
P4 production silicon - it is named *optional* for a reason. So the implementation tests it
with `esp_efuse_read_field_cnt()` (which counts programmed bits) and renders `not burned` when
the count is zero, rather than printing sixteen zero bytes as though they were an identity.
Whether it is burned on the two dev units is a bench question, answered by m1's **V3**
measurement alongside the JEDEC read that m1 already requires.

If it is burned it is the strongest identity value available: 128 bits, per-die, factory-set,
write-protected (`WR_DIS.OPTIONAL_UNIQUE_ID` is BLK0 bit 21). Rendered as a K2 block, 128 bits
= 32 hex characters = two lines of the frozen 24-character format.

Also present in BLK1 and deliberately **not** shown: `WAFER_VERSION_MAJOR/MINOR` (the
revision row already carries them), `BLK_VERSION_MAJOR/MINOR`, `PKG_VERSION`, `PSRAM_CAP`,
`PSRAM_VENDOR`, `TEMP`. There are **no lot / die / wafer-coordinate trace fields on P4**, so
`OPTIONAL_UNIQUE_ID` and the factory MAC are the only per-part unique values the chip has.

### 4.6 Flash chip identity

The flash chip is the one component that holds the firmware, and it is socketed only in the
sense that it is solderable - a swapped flash part is a real substitution vector and is exactly
what these two rows detect.

**JEDEC ID.** `esp_flash_read_id(esp_flash_t *chip, uint32_t *out_id)` (`esp_flash.h`); NULL
chip substitutes `esp_flash_default_chip`. Opcode `RDID 0x9F`; the returned 24-bit value is
`[23:16] manufacturer, [15:8] type, [7:0] capacity`. GigaDevice is `0xC8`. The Elecrow unit's
probed value `c8 40 18` = GD25Q128 is already recorded in `docs/research/elecrow-board.md`
(and matches IDF's own `case 0xC84018:` in `spi_flash_chip_gd.c`); the Waveshare's
GD25Q256-class part is expected to be `c8 40 19` by family pattern and by IDF's
`(chip_id & 0xFF) >= 0x19` 32 MB check, but that is **unconfirmed** and is read off the bench
as part of m1's existing M6 work.

Printed as raw hex bytes, `c8 40 18`, with **no vendor-name translation on the screen**. The
raw ID is what `esptool flash_id` prints and what the datasheet lists; a decoded name would be
a lookup the firmware performs, which is one more thing the firmware could get wrong or lie
about, for no gain. The manufacturer-code table goes in `VERIFYING.md`.

**Flash size, two rows, deliberately.** `esp_flash_get_size()` returns the size recorded in the
**binary image header** (i.e. `CONFIG_ESPTOOLPY_FLASHSIZE`, a build-time claim);
`esp_flash_get_physical_size()` calls `chip_drv->detect_size()`, which is `1 << (id & 0xFF)`
from the RDID capacity byte - a measurement. Both exist in v5.5. Showing both means a
mismatch is visible, and a mismatch is a real and previously-hit condition: the per-board
`CONFIG_ESPTOOLPY_FLASHSIZE_*` split is `REPRODUCIBLE.md` item 23's documented trap and
`firmware/README.md` records the failure it causes.

**64-bit unique ID.** `esp_flash_read_unique_chip_id(esp_flash_t *chip, uint64_t *out_id)`
(`esp_flash.h`). The header is blunt: *"This is an optional feature, which is not supported on
all flash chips. READ PROGRAMMING GUIDE FIRST!"* The unsupported return is
**`ESP_ERR_NOT_SUPPORTED`** (never `ESP_ERR_FLASH_UNSUPPORTED_CHIP`), from three places: the
`SPI_FLASH_CHIP_CAP_UNIQUE_ID` capability gate, the `..._read_unique_id_none` vtable entry, and
an all-zeros / all-ones heuristic on the result.
https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/peripherals/spi_flash/spi_flash_optional_feature.html

Four caveats, and they are the reason this row carries an m1 measurement rather than an
assumption:

1. **The GD vendor driver is off by default on P4.**
   `components/spi_flash/esp32p4/Kconfig.soc_caps.in` contains only
   `SPI_FLASH_VENDOR_XMC_SUPPORTED`, so on P4 the GD, ISSI, MXIC, Winbond, BOYA and TH drivers
   default to off (unlike the S3, which enables all seven). A GigaDevice part therefore falls
   through to `esp_flash_chip_generic`, which advertises `CAP_UNIQUE_ID` unconditionally. The
   read still works, but the only unsupported-detection left is the all-0/all-FF heuristic.
2. **GD parts have a 128-bit unique ID, and this API returns 64 bits of it.**
   GD25Q128E s7.21: *"The Read Unique ID command accesses a factory-set read-only 128bit number
   that is unique to each device."* `esp_flash_read_unique_chip_id` reads `miso_len = 8`, so
   the value is the **top 64 bits**, byte-swapped. Still unique in practice; the screen labels
   the row `Flash unique ID (64 of 128)` so the number is not mistaken for the whole thing.
3. **GD25Q128C has no `4Bh` command at all** and reports the *same* JEDEC ID `c8 40 18` as the
   GD25Q128E. RDID cannot distinguish them. This is not hypothetical for this project:
   `docs/research/elecrow-board.md` already records a vendor swap on board B (schematic says
   Winbond W25Q128JVSIQ, the probed unit says GigaDevice). If a fitted part turns out to be a
   C die, the row renders `not supported` and that is the honest outcome.
4. **32 MB parts may return a byte-shifted value.** `dummy_bitlen = 32` in the generic driver
   equals 24 address bits plus 8 dummy, which is correct only in 3-byte address mode; a
   GD25Q256E in 4-byte mode expects 40 clocks. The Waveshare board is exactly that case. This
   is analysis, not documentation, and it is a hardware check.

**Consequently:** the unique-ID row ships only if m1's **V3** measurement returns a plausible,
stable, non-zero value on both fitted parts. If it does not, the row renders `not supported`
and the JEDEC ID plus the physical size carry the flash-substitution check on their own. That
is a weaker check - a swapped part of the same model is undetectable - and the documentation
says so rather than the screen implying otherwise.

---

## 5. eFuse posture, itemised

eFuses are the one-way configuration of the chip. They are the only state on the device that
cannot be rewritten by whoever holds it, which makes them the most interesting rows on the
screen - and, per section 9, they are still *reported* by the app, so a hostile build prints
whatever it likes. What they are good for is the honest device: a release unit that came off
the burn runbook wrong, or a dev board someone is about to store a wallet on.

**Standing caveat on every symbol in this section.** The bit positions and symbol set below
are from ESP-IDF v5.5's `components/efuse/esp32p4/esp_efuse_table.csv`. `esp_efuse_table.h`
dispatches on `CONFIG_ESP32P4_SELECTS_REV_LESS_V3`, which `firmware/sdkconfig.base.defaults`
pins for rev v1.3 silicon; release hardware at rev >= v3.1 drops it (`OPEN-QUESTIONS` Q9).
**Every field here is re-read on the bench against both tables before m13 signs off**, and a
symbol that does not resolve renders `not read` rather than being silently dropped.

Cost, for the whole section: **negligible, and it is worth stating why rather than guessing.**
eFuse reads in a non-virtual build are not eFuse-controller transactions. The controller
auto-loads the eFuse contents into memory-mapped read registers at reset, and
`esp_efuse_utility_read_reg()` is a plain `REG_READ` of `range_read_addr_blocks[blk].start +
num_reg * 4`. A field read is a handful of loads plus a `memset`, so the entire eFuse section
costs microseconds. Two caveats that belong in the implementation and not on the screen:
`esp_efuse_read_field_blob()` retries with `vTaskDelay(1)` on `ESP_ERR_DAMAGED_READING` (a
coding-scheme recount disagreement), so it is not bounded-time and must not run from an ISR;
and under `CONFIG_EFUSE_VIRTUAL` the values come from a RAM copy, which is exactly the
condition under which none of this means anything - so **the build asserts `CONFIG_EFUSE_VIRTUAL`
is off in release** and the screen has no way to report a virtualised eFuse as real.
https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/system/efuse.html#virtual-efuses

### 5.1 Secure boot

| Field | API | Notes |
|---|---|---|
| Secure boot enabled | `esp_efuse_read_field_bit(ESP_EFUSE_SECURE_BOOT_EN)` (BLK0 bit 116) | What 0.1.0 already reads. `esp_secure_boot_enabled()` itself is `static inline` and not bindgen-able (`firmware/README.md` pitfall 13); on P4 its live branch is `efuse_ll_get_secure_boot_v2_en()`, the same bit. |
| Aggressive revoke | `esp_efuse_read_field_bit(ESP_EFUSE_SECURE_BOOT_AGGRESSIVE_REVOKE)` (bit 117) | Whether a single failed verification revokes a digest. |
| Which digests are burned | **`esp_secure_boot_read_key_digests(esp_secure_boot_key_digests_t *)`** | Declared in **`esp_efuse.h`**, not `esp_secure_boot.h`. `SOC_EFUSE_SECURE_BOOT_KEY_DIGESTS == 3` on P4. |
| Digest revocation | `esp_efuse_get_digest_revoke(unsigned num_digest)`, `esp_efuse_get_write_protect_of_digest_revoke(unsigned)` | Note the parameter is `unsigned`, not `uint8_t`. |
| Per-block purpose | `esp_efuse_get_key_purpose(esp_efuse_block_t)` -> `esp_efuse_purpose_t` | `esp_efuse_get_keypurpose` does not exist; only `esp_efuse_get_keypurpose_dis_write`. |
| Block protection | `esp_efuse_get_key_dis_read(blk)`, `esp_efuse_get_key_dis_write(blk)` | |
| Block unused | `esp_efuse_key_block_unused(blk)` | purpose USER, unprotected, all-zero. |

https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/security/secure-boot-v2.html ,
https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/system/efuse.html

**The digest values are readable, and they are the most valuable eFuse row on the screen.**
`esp_secure_boot_read_key_digests()` returns, for each non-revoked slot, a pointer straight
into the eFuse read registers (`esp_efuse_utility_get_read_register_address(key_block)`) -
32 bytes of SHA-256 digest of the RSA-3072 public key, in the clear. This is by design, not
oversight: IDF's `esp_efuse_write_key()` sets read protection for XTS, ECDSA, HMAC and KM
purposes and deliberately **not** for `SECURE_BOOT_DIGEST0/1/2`, and the Secure Boot v2 page
states it in words - "The key(s) must be readable in order to give software access to it ...
The write-protection bit must be set, but the read-protection bit must not."

So S-46 can print **the actual root of trust**: the digest of the public key that the ROM
will check the bootloader's signature against. That value is comparable off-device against
`espsecure.py digest_sbv2_public_key` run on the published release signing key. It answers a
question none of the other rows do - not "is secure boot on" but "**whose** secure boot".
For a project where `OPEN-QUESTIONS` Q32 is literally "whose secure-boot key?" and where the
GPL3 answer includes users signing their own firmware, showing which key is enrolled is the
difference between a meaningful row and a checkbox.

Implementation caveat, worth writing into the code: `esp_efuse_read_block()` performs no
`RD_DIS` check - a read-protected block returns `ESP_OK` and (TRM-level behaviour,
**not documented by IDF**, so treat as unverified until the bench confirms it) zeros. Any
path that reads block bytes therefore checks `esp_efuse_get_key_dis_read(blk)` first and
renders `read-protected` rather than a row of zeros. Rendering thirty-two zero bytes as if
they were a digest would be the worst kind of wrong value on this screen.

**Screen rows** (K1 unless noted):

```
  Secure boot                     disabled
  Aggressive revoke               no
  Key digest 0                    < K2 block, 64 hex >   |  or  not burned / revoked
  Key digest 1                    not burned
  Key digest 2                    not burned
  Key blocks                      < K3 table >
```

K3 key-block table, column budget 6 + 22 + 11 = 39 characters (663 px, exactly the 720x720
`MONO_SMALL` body capacity):

```
  KEY0  SECURE_BOOT_DIGEST0   -
  KEY1  XTS_AES_128_KEY       RD_DIS WR
  KEY2  HMAC_UP               RD_DIS WR
  KEY3  <unused>              -
  KEY4  <unused>              -
  KEY5  <unused>              -
```

The three-block allocation shown is `ESP-SEAL.md` 6.1's budget (1 secure boot digest, 1 XTS
key, 1 `HMAC_UP` for the sealing ladder, 3 spare). The purposes are printed as IDF's own
enumerator names rather than translated, because the name is the value: a reader comparing
against the burn runbook or against `espefuse.py summary` output is comparing the same
string. P4's purpose enumeration is `USER=0, ECDSA_KEY=1, XTS_AES_256_KEY_1=2,
XTS_AES_256_KEY_2=3, XTS_AES_128_KEY=4, HMAC_DOWN_ALL=5, HMAC_DOWN_JTAG=6,
HMAC_DOWN_DIGITAL_SIGNATURE=7, HMAC_UP=8, SECURE_BOOT_DIGEST0/1/2=9/10/11, KM_INIT_KEY=12`
(`components/efuse/esp32p4/include/esp_efuse_chip.h`), and blocks `EFUSE_BLK_KEY0..KEY5` are
`EFUSE_BLK4..BLK9`, 256 bits each.

### 5.2 Flash encryption

| Field | API | Notes |
|---|---|---|
| Enabled | `esp_flash_encryption_enabled()` | What 0.1.0 reads. Odd parity of `SPI_BOOT_CRYPT_CNT`. |
| Mode | `esp_get_flash_encryption_mode()` -> `ESP_FLASH_ENC_MODE_DISABLED` / `_DEVELOPMENT` / `_RELEASE` | `esp_flash_encrypt.h`. **New, and the row that matters** - "enabled" alone does not distinguish a development-mode board (re-flashable, `SPI_BOOT_CRYPT_CNT` not maxed, manual encrypt still allowed) from a release-mode unit. |
| Crypt count | `esp_efuse_read_field_cnt(ESP_EFUSE_SPI_BOOT_CRYPT_CNT, &cnt)` (BLK0 bit 82, **3 bits**) | Printed as the raw popcount 0..3. CSV: `{0: Disable; 1: Enable; 3: Disable; 7: Enable}`. |
| Key block read protection | `esp_efuse_find_purpose(XTS_AES_*, &blk)` then `esp_efuse_get_key_dis_read(blk)` | The row the owner actually cares about: a burned but software-readable XTS key is not flash encryption in any useful sense. |
| Key length | `esp_efuse_read_field_bit(ESP_EFUSE_XTS_KEY_LENGTH_256)` (bit 78) | 128 vs 256. |
| Manual encrypt disabled | `ESP_EFUSE_DIS_DOWNLOAD_MANUAL_ENCRYPT` (bit 52) | |
| MSPI download access disabled | `ESP_EFUSE_SPI_DOWNLOAD_MSPI_DIS` (bit 45) | |

https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/security/flash-encryption.html

P4 has all three XTS purposes (`XTS_AES_256_KEY_1`, `_2`, `XTS_AES_128_KEY`); IDF's
`esp_efuse_write_key()` read-protects the block for all of them, so `RD_DIS` set is the
expected state and `RD_DIS` clear is a real finding. `ESP-SEAL.md` 6.1 budgets
`XTS_AES_128_KEY`.

**A documentation trap worth recording so nobody chases it.** The flash-encryption page lists
`DIS_DOWNLOAD_ICACHE`, `DIS_DOWNLOAD_DCACHE`, `HARD_DIS_JTAG` and `DIS_LEGACY_SPI_BOOT` among
the release-mode eFuses. **None of those four exist on ESP32-P4** - the page's text is generic
across targets. The P4 CSV is authoritative and IDF's own
`esp_flash_encryption_cfg_verify_release_mode()` compiles those terms out on P4
(`SOC_EFUSE_DIS_DOWNLOAD_ICACHE`/`DCACHE` undefined). P4's actual release-mode determination
is: encryption enabled AND (`WR_DIS_SPI_BOOT_CRYPT_CNT` set OR the count maxed to `0b111`) AND
`DIS_DOWNLOAD_MANUAL_ENCRYPT` AND `SPI_DOWNLOAD_MSPI_DIS`.

### 5.3 Download mode and debug access

This is the group the project owner's question is really about, and it is the group 0.1.0
does not report at all. All BLK0, all one bit unless noted:

| Screen label | Symbol | Bit |
|---|---|---|
| `UART download` | `ESP_EFUSE_DIS_DOWNLOAD_MODE` | 128 |
| `Secure download` | `ESP_EFUSE_ENABLE_SECURITY_DOWNLOAD` | 133 |
| `USB-serial-JTAG download` | `ESP_EFUSE_DIS_USB_SERIAL_JTAG_DOWNLOAD_MODE` | 132 |
| `USB-OTG download` | `ESP_EFUSE_DIS_USB_OTG_DOWNLOAD_MODE` | 123 |
| `Forced download` | `ESP_EFUSE_DIS_FORCE_DOWNLOAD` | 44 |
| `Direct boot` | `ESP_EFUSE_DIS_DIRECT_BOOT` | 129 |
| `JTAG (pad)` | `ESP_EFUSE_DIS_PAD_JTAG` | 51 |
| `JTAG (USB)` | `ESP_EFUSE_DIS_USB_JTAG` | 41 |
| `JTAG (soft)` | `ESP_EFUSE_SOFT_DIS_JTAG` - **3 bits**, `esp_efuse_read_field_cnt` | 48 |
| `JTAG select` | `ESP_EFUSE_JTAG_SEL_ENABLE` | 47 |
| `ROM log` | `ESP_EFUSE_UART_PRINT_CONTROL` - **2 bits**, `esp_efuse_read_field_blob` | 134 |
| `ROM log (USB)` | `ESP_EFUSE_DIS_USB_SERIAL_JTAG_ROM_PRINT` | 130 |

**`HARD_DIS_JTAG` does not exist on ESP32-P4.** It is present on several other ESP32 targets
and appears in generic documentation, but the P4 eFuse table has no such field and
`SOC_EFUSE_HARD_DIS_JTAG` is undefined. The P4 permanent JTAG lock is `DIS_PAD_JTAG` **and**
`DIS_USB_JTAG` together, which is exactly what IDF's
`esp_secure_boot_enable_secure_features()` burns. Also absent on P4, recorded so nobody
tries to bind them: `DIS_LEGACY_SPI_BOOT`, `DIS_BOOT_REMAP`, `DIS_DOWNLOAD_ICACHE`,
`DIS_DOWNLOAD_DCACHE`, `UART_DOWNLOAD_DIS`.

`SOFT_DIS_JTAG` is a 3-bit odd/even field ("odd number: disabled, even number: enabled"), so
it is read with `esp_efuse_read_field_cnt` and printed as the raw count; IDF itself treats
"soft-disabled" as complete when the count equals the field's 3-bit width. Soft-disabled JTAG
can be re-enabled at run time with an HMAC token
(`esp_hmac_jtag_enable(hmac_key_id_t, const uint8_t *token)` / `esp_hmac_jtag_disable()`,
`esp_hmac.h`, `SOC_HMAC_SUPPORTED == 1` on P4) against a key block with purpose
`HMAC_DOWN_JTAG` or `HMAC_DOWN_ALL`. That is a materially different situation from
`DIS_PAD_JTAG`, so the screen prints the three JTAG fields separately rather than collapsing
them into one row - collapsing would be interpretation, and it would hide the case that
matters.
https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/peripherals/hmac.html

**Why download mode is on this screen at all**, stated here in the document and nowhere on
the device (contract rule 2): a chip whose ROM download mode is open can be put into download
mode and reflashed by anyone holding it, over the same USB port the owner uses for power.
Secure boot narrows that to "they can flash it, but the ROM will refuse to run what they
flashed"; secure download mode narrows it further; `DIS_DOWNLOAD_MODE` closes it. Those are
four genuinely different postures and no single word covers them, which is why the screen
prints four fields instead of one verdict. The user-facing explanation lives in
`VERIFYING.md` beside the same four field names.

Programmatic setters exist (`esp_efuse_disable_rom_download_mode()`,
`esp_efuse_enable_rom_secure_download_mode()`, `esp_efuse_set_rom_log_scheme()`) and are
**not** called from release firmware - burns belong to the m13 runbook with `espefuse.py`,
consistent with `ESP-SEAL.md`'s factory-provisioning recommendation (`OPEN-QUESTIONS` Q45).

### 5.4 Anti-rollback

| Field | API | Notes |
|---|---|---|
| eFuse secure version | `uint32_t esp_efuse_read_secure_version(void)` | **Takes no out-parameter** and returns a `__builtin_popcount()` - the field is thermometer-encoded, so the return is the version number, not a raw blob. |
| Image secure version | `esp_app_get_description()->secure_version` (`esp_app_desc.h`) | `esp_ota_get_app_secure_version()` **does not exist**. |
| Field width | `ESP_EFUSE_SECURE_VERSION` = BLK0 bit 137, **16 bits** | `CONFIG_BOOTLOADER_APP_SEC_VER_SIZE_EFUSE_FIELD`, range 1..16, default 16 on P4. |
| Check | `esp_efuse_check_secure_version(uint32_t)` | Reads three times under `ESP_FAULT_ASSERT`; not needed on the screen (the bootloader already enforced it), listed for completeness. |

https://docs.espressif.com/projects/esp-idf/en/v5.5/esp32p4/api-reference/system/ota.html#anti-rollback

Trap: with `CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK` unset, `esp_efuse_fields.c` falls back to a
4-bit field width, so `esp_efuse_read_secure_version()` in an app built without anti-rollback
reports a capped value. The screen therefore shows **both** numbers -
`Anti-rollback (image)` and `Anti-rollback (efuse)` - as two rows rather than one, because
"2" alone hides whether the pair agrees, and because during the m13 rollout the two are
deliberately different for a while.

### 5.5 What is deliberately not read from eFuse

`esp_flash_encryption_cfg_verify_release_mode()` and `esp_secure_boot_cfg_verify_release_mode()`
exist and audit exactly the P4-correct field set (they are the right *reference* for which
checks matter, and they are `SOC_*`-gated so they encode P4's real feature set). They are
**not** used to produce a screen row, for one reason: each returns a single `bool`, and a
single bool on this screen is a verdict, which contract rule 2 forbids. The fields they check
are enumerated above and printed individually. Their logging output is a good source for the
implementation to mirror and a good thing to have in the boot log; it is not a row.

---

## 6. Anti-tamper state (exists only once 0.2.0 has storage)

0.1.0 is stateless, so it has no way to know it was ever booted before. 0.2.0 has a
plaintext `counters` partition, which makes exactly one new class of statement possible:
**this device has been powered on N times.** An owner who powered it on five times and reads
"1 240" learns something no digest can tell them.

Designing it honestly means being precise about what it survives, because a counter that
quietly resets is worse than no counter.

**One hard precondition, found during the 2026-08-17 reconciliation and binding on the
implementation: the counter does not exist, and nothing is written, until the ledger has
been formatted.** `SECURITY.md` invariant 2a says of a device with no stored wallet that
"nothing is ever written to flash" - the 0.1.0 stateless property, retained verbatim. A boot
counter that incremented on every power-up would falsify that sentence on every blank and
every unprovisioned device, which is not a trade this project makes: an invariant that is
mechanically enforced everywhere else does not acquire an exception for a convenience row.
So the rule is: while `StoreState` is `Unprovisioned` or `Blank` the row renders
`not counted` (never `0`, which would be a value the device did not read), no cell is
programmed, and the device is byte-for-byte as stateless as 0.1.0. Counting begins when the
ledger is formatted, which is the same moment the device stops being stateless for every
other reason. The honest cost, and it goes in `VERIFYING.md` rather than on the screen: the
counter cannot report boots that happened before the owner set the device up, so it answers
"has anyone powered this on since I configured it" and not "since it left the factory". The
second question is not answerable on this hardware by any means, so nothing is lost that was
ever available.

### 6.1 Where it lives, and what that implies

`counters` is a 16 KiB plaintext partition at `0xE40000` (the frozen geometry of the ratified
Q7; `ARCHITECTURE.md` 2.7), holding the
`ESP-SEAL.md` 3.7 ledger: two A/B rotation sectors plus two reserved, one live sector at a
time, a 128-byte head with a `rotation_ctr` and a `head_mac` keyed by the device guard key,
and guarded bit-clear cell arrays. Plaintext by necessity - XTS's 16-byte write granularity
cannot express progressive 1->0 bit programming, which is the whole basis of the scheme
(`ARCHITECTURE.md` 2.5, `ESP-SEAL.md` 3.1).

Three consequences follow directly and all three go in the documentation:

- **Bit-clear means the count cannot go down without an erase.** Programming clears bits;
  nothing but a sector erase returns them. An attacker cannot decrement the counter in place.
- **The cells are guard-MAC'd with a device-bound key.** A cell is
  `HMAC(guard_key, "ESLG" || side || rotation_ctr || log_id || index)[0..8]`, and `guard_key`
  descends from the read-protected `HMAC_UP` eFuse block. So forging a *plausible* ledger
  state on a fresh sector requires the eFuse key, which is the tier-2 fault-injection
  attacker, not the tier-1 bench attacker (`SECURITY.md`, "An attacker with the device").
- **A full-flash restore defeats it completely, and this is not fixable on this silicon.**
  An attacker who snapshots the whole flash before booting the device and writes the same
  bytes back afterwards returns the counter, the ledger, the records and the epoch to their
  snapshot values. No key is broken; identical bytes are written back. `SECURITY.md` tier 3
  already concedes exactly this for the attempt counter and the same sentence covers the boot
  counter. **The document says so and the screen does not**, because saying it on the screen
  would be opining.

### 6.2 The fields

| Screen label | Value | Where it comes from |
|---|---|---|
| `Boot count` | `rotation_ctr * cells_per_sector + cells_programmed` | ledger, computed at mount |
| `Since acknowledged` | `boot_count - acknowledged_at` | ledger head |
| `Acknowledged at boot` | the boot index the owner last marked | ledger head |
| `Wipe epoch` | `wipe_epoch` | ledger head (one-way bit-clear, `ARCHITECTURE.md` 2.5) |
| `Storage` | occupancy at the granularity Q2 sets | wallets partition |

The counter is a bit-clear cell array like the attempt log, so it inherits `ESP-SEAL.md` 8.3's
**M6 measurement as a hard constraint**: SPI NOR parts limit partial-page programs to one
256-byte page between erases, m1 is already measuring that limit on both fitted flash parts,
and the boot log's cells-per-page must be sized against the measured number, not a guessed
one. This is why the boot counter is specified here and implemented at m4a rather than
bolted on later - it consumes the same scarce resource the attempt counter does, in the same
partition, under the same measured limit, and adding it after the geometry freeze would be a
format change.

**`OPEN:` the boot log's cell budget and its placement inside the ledger sector.**
`ESP-SEAL.md` 3.7 owns the sector map (head at `0x00`, `attempt_entry` at `0x0380`,
`attempt_success` at `0x0780`, `pin_gen_log` at `0x0B80`, reserved at `0x0F80`). A boot log
needs its own cell array and two head words (`acknowledged_at`, and the boot log's own
`log_id`). Recommendation: take it from the reserved region and the second reserved sector
pair rather than shrinking an existing log, and size the array from m1's M6 result. This is a
storage-format decision and belongs to the `ESP-SEAL.md` owner; it is flagged, not decided
here.

### 6.3 Why an acknowledgement mark rather than a "last boot marker"

The obvious design is a per-boot marker value the owner records and compares. **It is
redundant and it is dropped**, and the reasoning is recorded so it is not re-proposed: a
device-derived marker is a deterministic function of the boot index, so it carries exactly
the information the boot count already carries, and both are rolled back by precisely the
same thing (a full-flash restore) and by nothing else. Two numbers, one fact, one extra thing
for the owner to write down.

What is *not* redundant is a **mark the owner sets**. `[ Mark as seen ]`
(`RegionId::VerifyAckBoots`) writes the current boot index into the ledger head. The screen
then shows `Since acknowledged  5`, which is a number the owner can evaluate without having
written anything down and without remembering what the count was last month. That is a real
improvement in usability at the cost of one head field and one bit-clear write, and it stays
inside the contract: the row prints a number, not a judgement.

Two honest properties of the mark, documented and not on the screen:

- Pressing it is a write to flash, so it gets a `C12 WriteNotice` band before the action, per
  invariant 2b: *"This writes to the device: boot counter acknowledgement. Nothing secret is
  written."*
- It is **post-PIN only** (section 7.4). A coercer who can press the button erases the very
  gap the counter exists to show. The raw `Boot count` stays pre-PIN, because the owner needs
  it *before* deciding to unlock, which is the entire point of the feature.

### 6.4 What resets it, stated plainly

Three events, and the documentation names all three:

1. **`Erase this device` (S-48).** The device returns to blank, which includes the counters
   partition; the boot count restarts at zero. This is an owner action, announced on screen,
   and S-48b already says the device is blank.
2. **A full-flash restore.** Undetectable and unpreventable, per 6.1 and `SECURITY.md` tier 3.
3. **Re-flashing the firmware.** `espflash`/`esptool` writing the whole flash, or an erase
   that covers `0xE40000`, resets it. A user who reflashes their own device and finds the
   count back at 1 has not been attacked; they have flashed their device. This is the most
   likely real-world encounter with the reset and it is the first line of the
   `VERIFYING.md` paragraph.

And one event that must **not** reset it, asserted in the host fuzz tests alongside the
existing power-loss properties: a ledger sector rotation. `rotation_ctr` carries the count
across the A/B flip, so the number is monotone across rotations; a rotation that lost the
count would look exactly like a tamper event and would train users to ignore the row.

---

## 7. Cross-check affordances

A value the user cannot compare against anything is decoration. This section covers how the
values leave the screen, what has to be published for the comparison to exist at all, and
which values may be shown before the PIN.

### 7.1 The comparison is off-device, always

Design contract rule 5. The screen never tells the reader whether a value is "right". It
cannot: an expected-value table shipped inside the firmware would be the firmware checking
itself against itself, which is worth nothing (section 9), and it would also be a compiled-in
constant, which `SECURITY.md` invariant 5 forbids on this screen by name. So the flow is:

```
  device screen  ->  QR or transcription  ->  user's own machine
                                                    |
                          release verification manifest (signed, off-device)
                          or an independent rebuild (REPRODUCIBLE.md section 3)
```

### 7.2 QR export of the full readout

`[ Show as QR ]` (`RegionId::VerifyQr`) hands the complete readout to C11 QrPlayer. No new
component: C11 already does fountain-encoded multi-frame `ur:bytes` with pause / speed /
density controls and a frame counter, and it degrades to a single static symbol when the
payload fits one frame.

**Payload format - `notyas-verify/1`.** Line-oriented ASCII, `key=value`, one field per
line, **in the frozen field order of section 10**, LF-terminated, no trailing whitespace,
digests lowercase unspaced hex. Wrapped as `ur:bytes` for C11.

```
notyas-verify/1
version=0.2.0
board=waveshare-4b
chip=esp32p4
chip_rev=v1.3
rom_eco=2
rom_chip_id=0x12
mac=6055f93a1c04
die_uid=1f4c90ab3e77d2158c6044f9b1a35e08
jedec_id=c84019
flash_uid=4d812f60aa3907c5
firmware_digest=9b21c7fe...
app_offset=0x00010000
app_len=1842176
app_sha256=3f9a27c1...
bootloader_offset=0x00002000
bootloader_len=26512
bootloader_sha256=...
...
```

Three properties this format is chosen for, each load-bearing:

- **Diffable.** Two readouts, or a readout against a manifest, compare with `diff`. Fixed
  field order means a diff shows only real differences, never reordering noise.
- **Human-readable after scanning.** A user with no tooling gets text they can read, not an
  opaque blob. The QR is a transcription aid first and a machine format second.
- **Self-describing and versioned.** The `notyas-verify/1` first line lets the off-device
  checker refuse a format it does not know rather than mis-parse it.

The payload contains no secret and no wallet-identifying value (section 7.4 governs what is
in it), so it does not violate the masking law's "no QR is ever generated from a masked or
derived-secret value" rule (`UX-SCREENS.md` 0.6). Pre-PIN, the QR carries exactly the pre-PIN
field set and nothing more.

### 7.3 What the published release must contain

Coordinated by name with `REPRODUCIBLE.md`. That document's section 3.5 artifact table and
section 4.3 ("relating an artifact to the device in your hand") are the counterpart to this
one; the requirement here is one new artifact per board.

**New artifact: `notyas-<ver>-<board>-VERIFY.json`**, added to `REPRODUCIBLE.md` 3.5's
table, produced by `tools/repro/build.sh` step 8 alongside `BUILDINFO.txt`, and **listed in
`SHA256SUMS.txt`** so the existing detached GPG signature covers it. Contents, all of which
the build already knows:

| Key | Value |
|---|---|
| `format` | `"notyas-verify-manifest/1"` |
| `version`, `board` | the tag and the board slug (`REPRODUCIBLE.md` 3.5 vocabulary) |
| `app_image_sha256` | **image-content** digest - the number the device shows |
| `app_image_len` | image length in bytes, excluding the appended digest |
| `app_file_sha256` | the `sha256sum app.bin` file digest, for cross-reference |
| `app_offset` | `0x10000` |
| `bootloader_image_sha256`, `bootloader_image_len`, `bootloader_offset` | as above, at `0x2000` |
| `bootloader_file_sha256` | file digest of `bootloader.bin` |
| `partition_table_sha256`, `partition_table_len`, `partition_table_offset` | at `0x8000` |
| `partition_table_csv_sha256` | digest of `firmware/partitions.csv`, so the CSV and the binary are tied together |
| `firmware_digest` | the composite of section 2.4, computed by the identical construction |
| `secure_version` | the anti-rollback value compiled into this image |
| `partitions` | the parsed table: name, type, subtype, offset, size, flags - so the device's `Partitions` block is comparable row by row |

**Why the image-vs-file digest distinction must be published rather than explained.**
`REPRODUCIBLE.md` 4.3 already identifies this as "the single most likely support question":
`esp_partition_get_sha256()` returns the digest of the image *content*, which is not
`sha256sum app.bin`, because the file digest also covers the 32 bytes of appended digest.
Today the answer is a three-command shell recipe in that document. Publishing
`app_image_sha256` next to `app_file_sha256` in a signed manifest removes the recipe from the
user's path entirely: they compare the number on the screen to the number in the manifest,
full stop. **This is the single highest-value item in this section** - the most likely way a
user's verification attempt fails today is not an attack, it is comparing two legitimate but
different numbers and concluding their device is compromised.

`VERIFYING.md` (`REPRODUCIBLE.md` 5.3's outline, aimed at a non-expert) gains one section:
"Compare your device against the release", consisting of the four digest comparisons and the
identity fields the owner should record for themselves.

**`OPEN:` the manifest artifact belongs to `REPRODUCIBLE.md`'s artifact set, which this
document does not own.** Recommendation: accept as specified, and add the row to
`REPRODUCIBLE.md` 3.5 plus the emit step to 3.3's `build.sh` list. The alternative
considered - folding the fields into the existing free-form `BUILDINFO.txt` - is rejected
because `BUILDINFO.txt` is a human triage artifact whose format is deliberately loose, and an
off-device checker needs a stable parse.

### 7.4 Pre-PIN visibility

`UX-SCREENS.md` S-03 already places `HomeVerifyDevice` on the lock screen, deliberately:
commandment 4 is that the device authenticates itself to the user before the user
authenticates to it, and a user who suspects a swap must be able to check the firmware
without typing a digit into a device they do not trust. That decision is not re-opened. What
this document decides is *which fields* that pre-PIN view contains.

**The governing test:** a field may be shown pre-PIN if a person holding the device can
already obtain it without the PIN - by reading the chip over USB with `esptool`, by desoldering
the flash, or from the public release - **and** it says nothing about the wallets stored on
this unit.

**Shown pre-PIN** - the whole of the `identity`, `firmware`, `efuse` and `operation` sections,
and all of `flash` except the mutable-region digests (10.1, 10.2, 10.4, 10.6, and 10.3 minus
the last two rows):

Device name, board, chip, chip revision, boot ROM eco version, ROM chip id, MAC, die unique
ID, firmware version, both ESP-IDF versions, both anti-rollback values, the firmware digest,
the app / bootloader / partition-table digests with their offsets and lengths, both flash
sizes, JEDEC ID, flash unique ID, the partition map, the reserved-space scan, every eFuse
field including the secure-boot key digests, the radio kill level and the self-test result.

Reasoning, stated plainly because the instinct is to withhold: **withholding these costs the
owner the exact check they need and buys the attacker nothing.** Every one of them is
readable off the silicon with a USB cable and `esptool chip_id` / `flash_id` / `read_flash`,
or is printed on the release page. An attacker holding the device has them already. The
owner, standing in front of a device they are not sure is theirs, does not - unless the
screen shows them. Hiding them behind the PIN inverts commandment 4 exactly: it would require
authenticating to the device before the device authenticates to you.

**Not shown pre-PIN:**

| Field | Why |
|---|---|
| Storage occupancy (`2 wallets`) | Pre-PIN it is already governed elsewhere and S-46 must not become a second, finer source: the row shows **exactly** the granularity S-01's boot row and S-03's footer show, and no more. Under Q2(a) that is `present` / `blank` permanently and for all users. |
| `wallets` partition raw digest | See below - this one has a real leak and a clean rule. |
| `seal_seq` high-water | It counts wallet saves. A coercer reading "the device has sealed 14 records" learns about activity that a decoy wallet cannot explain. Post-PIN only, always. |
| "Since acknowledged" / `[ Mark as seen ]` | The acknowledgement is an owner action against owner-held state; a coercer who can press it can erase the evidence the counter exists to preserve. The raw **boot count** is pre-PIN (see below); the acknowledgement mark is not. |

**The `wallets` raw digest and the duress interaction.** A raw (undecrypted) digest of the
wallets partition is genuinely useful anti-tamper state - it changes if and only if the
sealed region changed - and it reveals nothing about *content*, since it is a digest of
ciphertext. But under `Occupancy::Sparse` (`ESP-SEAL.md` 3.6) an unoccupied slot is erased,
a blank wallets partition is therefore all `0xFF`, and the digest of a blank partition is a
**publicly computable constant**. Showing it pre-PIN would announce blank-versus-not to
anyone holding the device, which is precisely the leak `OPEN-QUESTIONS` Q2 exists to close.

**DECISION:** the `wallets` raw digest is **post-PIN only under Q2(b)/(c)**, and **may be
pre-PIN under Q2(a)**, because `Occupancy::AlwaysFilled` fills every unoccupied slot with a
genuine AEAD record under a device-derived key, so there is no constant to recognise and the
digest is device-unique in every state. This is one more line in Q2's ledger and it points
the same way Q2's own recommendation does.

**Boot count is pre-PIN, and that is the point.** A boot counter the owner can only read
*after* unlocking is useless for its one job - telling the owner, before they trust the
device with a PIN, that it was powered on more times than they powered it on. It also leaks
nothing about wallets: it counts power-ons, including power-ons that ended at the lock
screen, on a device that may never have held a wallet. `wipe_epoch` is likewise pre-PIN: a
wipe is not a secret (S-48b announces it in words on the device's own screen), and the value
is in the plaintext `counters` partition where a flash dump reads it anyway.

**Mechanically:** the pre-PIN field set is a checked-in golden list and CI asserts the
rendered label sequence with no session open equals it, and that it is a strict subset of the
unlocked list (11.7). Rows absent pre-PIN are **absent**, not disabled and not blanked - the
0.1.0 rule from `draw_bar_no_back` generalised: never draw an affordance or a label that
resolves to nothing.

---

## 8. Rejected permanently, with the reasoning written down

These are not "later" items. They are wrong in kind, and the reasoning is recorded here so
that nobody re-proposes them in a 0.3.0 planning session and nobody has to re-derive the
argument. Each one *feels* like it strengthens the screen. Each one weakens it, because it
teaches the reader that this screen can answer a question it structurally cannot.

**R1. A running-task list.** FreeRTOS can enumerate its own tasks (`uxTaskGetSystemState`,
`vTaskList`). Rejected for two independent reasons, either sufficient. First: the list is
printed by the firmware under suspicion, and a hostile build prints whatever list it likes
- it is one string literal, and the forged list is indistinguishable from the honest one.
Second, and less obvious: on this SoC the app image *is* the operating system. There is no
loader, no second application, no package manager, no dynamic code loading, and no
filesystem the app executes from. An honest task list can therefore only ever enumerate
the tasks this build's own source creates, which anyone can already read in the source at
the published tag. So the feature adds **zero information on an honest device and
unbounded reassurance on a dishonest one**. That is the worst possible ratio.

**R2. A "no other code is running" claim, in any wording.** Same forgery argument as R1,
without even a list behind it. A claim with no evidence except the claimant is not
evidence. Also rejected in its softer disguises: "only notyas is installed", "no unknown
modules", "clean". The screen never characterises the whole system; it prints values.

**R3. RAM scans / heap or stack attestation.** Hashing `.data`/`.bss`/heap at run time and
showing a digest. Rejected: the digest is not comparable to anything - RAM contents legitimately
differ between two boots of the *same* image (stack depth, allocator state, touch and
display driver buffers, PSRAM contents), so there is no published constant to compare it
against and no stable value to compare against yesterday. It would be a 64-character number
that changes every boot for benign reasons, which trains the reader to ignore changing
numbers - the precise habit that makes the firmware digests useless. And it is
self-reported like everything else.

**R4. Any indicator whose only evidence is the firmware's assertion about itself.**
The general rule R1-R3 are instances of. Concretely this bans: a "verified" or "genuine"
badge, a green tick summarising the eFuse section, a "tamper check passed" line, a boot-time
"integrity OK" banner, and a checkmark next to the app digest. The screen may print an eFuse
bit as read; it may not print a conclusion drawn from it. Note the asymmetry that makes this
tolerable: reporting a *value* is falsifiable against an independent source (the release
manifest, esptool over USB, another unit), whereas reporting a *verdict* is not.

**R5. Encoding a digest as BIP-39 words.** Some products render fingerprints as word lists
for readability. Rejected outright and permanently on this product: this is a wallet whose
users are trained that a list of BIP-39 words is seed material and must be written down and
never shown to anyone. Manufacturing a second, harmless-but-identical-looking word list and
putting it on a verification screen is a phishing primitive we would be shipping ourselves
("read me the words on your Verify screen"). Hex only.

**R6. A truncated fingerprint as the comparison value.** Recorded here because it is the
natural first instinct for a small screen and because design contract rule 1 forbids it.
A short form is fine for *detecting accidental corruption* and useless for anything else; a
device that only ever shows the first 12 characters cannot be used to detect a deliberately
ground collision-prefix image, and more importantly it teaches the comparison habit at the
wrong length. The digests fit (section 11 does the arithmetic): 64 hex characters is three
lines of Mono at 24 characters per line, and the screen has room for all of them.

**R7. Hashing the mask ROM as a security control.** The ROM region is discussed in section 6
and its identity *is* reported, but note what it can and cannot be: the mask ROM is silicon
and cannot be modified, so a ROM digest can never detect a modification - it can only detect
a *different chip*, which the chip revision and the ROM banner already report more legibly.
Presenting a ROM hash as a tamper check would imply the ROM is a thing that could have been
tampered with. It is reported as identity, in the identity section, and nowhere else.

---

## 9. The self-reporting boundary

This is the section that governs every claim in this document, and the one to read if you
read nothing else.

### 9.1 The statement

**Every value on the Verify screen is read and reported by the firmware being verified.**
The app reads the eFuse controller, reads flash through the partition and SPI-flash APIs,
reads the chip's identity registers, computes the digests, and draws the result. Firmware
that has been replaced controls every step of that chain. It can print the digest of the
image it *replaced* rather than the one it is; it can print `Secure boot   enabled` on a
blank device; it can print any MAC, any ROM banner, any boot count. There is no arrangement
of software running on the suspect processor that closes this, because the thing doing the
reporting is the thing in question.

This is not a defect specific to notyas. It is why Coldcard drives its genuine-state LEDs
from a secure element the main processor cannot lie to (`PARITY.md` class-c row), and it is
why `PARITY.md` already classifies the notyas answer as **software attestation, labeled as
such**. This document is the labelling.

### 9.2 What the screen is genuinely good for

Three things, all real, none of them "proves the firmware is honest":

1. **Detecting accidental corruption and incomplete flashes.** By far the most common real
   failure and the one users actually hit: a flash interrupted partway, a stale bootloader
   left over from a different board (`tools/flash.ps1` warns about exactly this), an app
   written at the wrong offset, a partition table from an older layout. In every one of
   those cases the firmware is *honest and wrong*, which is precisely the case a
   self-reported digest catches perfectly. The bootloader and partition-table digests
   (section 2) exist mostly for this, and it is not a small thing: a mismatched
   bootloader/app pair on the P4 flashes cleanly and then fails in ways that look like
   hardware faults (`firmware/README.md`, the rev-family boot loop).
2. **Comparing against independently obtained published values.** The digests on the screen
   are comparable to the release verification manifest (section 7.3), which is covered by
   the signed `SHA256SUMS.txt` and which a third party can regenerate from source with the
   `REPRODUCIBLE.md` container recipe. The comparison is only meaningful because the user
   obtains the published value **from somewhere other than the device** - the release page,
   a rebuild, another person's attestation. A device that showed both the digest and "and
   here is the digest it should be" would be comparing itself against itself.
3. **Confirming device identity against a substituted unit.** The chip MAC, the die unique
   ID, the flash JEDEC and unique IDs (section 4) are values the owner records once, off the
   device, when they first set it up. A look-alike unit handed back to them reports
   different ones. This complements, and does not replace, the lock-screen word
   (`UX-SCREENS.md` S-03), whose known limit is already documented: it defeats
   swap-by-a-stranger, not substitution by someone who held your device long enough to read
   the word off it. The hardware identity values have the same limit for the same reason -
   an attacker who held the device can read them too - but they are much harder to *forge on
   different silicon*, because a substituted unit has to lie about them rather than merely
   display them, and lying requires the substituted unit to run modified firmware, which is
   the case secure boot addresses.

### 9.3 What only secure boot can provide

There is exactly one link in the chain the app cannot forge, and the app is not part of it.

With Secure Boot v2 burned, the **boot ROM** - mask silicon, not our code, not
modifiable - verifies the RSA-3072 signature on the second-stage bootloader against a
digest burned irreversibly into eFuse, before that bootloader executes; the bootloader
then verifies the app the same way before the app executes (`SECURITY.md` invariant 6;
`MILESTONES.md` m13 burn runbook). An app that fails that check **does not run**, so there
is no firmware left to print a reassuring screen. That is the whole of the unforgeable
guarantee, and it is a guarantee about *which code starts*, not about what that code then
says about itself.

Consequently the honest ranking, which the documentation states and the screen does not:
on a unit with secure boot burned, the screen's digests are a convenience - the ROM already
refused to run anything unsigned. On a unit without it (every dev board, and any release
unit before the m13 burn), the digests are the only firmware check there is, and they are
self-reported. The screen reports the eFuse bit that distinguishes those two worlds, as a
value, and lets the reader draw the conclusion.

### 9.4 The wording

**On the device.** One line, at the foot of the readout, `MONO_SMALL`, `INK_SECONDARY`, no
band, no colour, no icon - a provenance note, not a warning:

> `These values are read from the chip and from flash by the firmware running on this device.`

That is the entire on-screen caveat. It is a statement of fact about where the numbers came
from, it is short enough to be read, and it opines about nothing. It is a fixed string in
the string inventory (`UX-SCREENS.md` section 6) and it is asserted in CI like every other
literal.

**In the documentation** (`VERIFYING.md`, and quoted into `docs/SECURITY.md` at m13):

> Every value on the Verify screen is read and reported by the firmware being verified.
> Firmware that has been replaced can report anything.
>
> The screen detects accidental corruption and incomplete flashes, it lets you compare the
> firmware digests against the digests published for the release and independently
> rebuilt from source, and it lets you confirm that the hardware identity in front of you
> is the hardware identity you recorded. It cannot establish that the firmware reporting
> those values is the firmware you intended to run.
>
> One check does not depend on the firmware: with Secure Boot v2 burned, the chip's boot
> ROM verifies the signature on the bootloader, and the bootloader verifies the signature
> on the application, before either runs. Unsigned or modified code does not execute, so
> there is nothing left to report a false value. The Verify screen shows whether that eFuse
> is burned on your unit.

---

## 10. Every proposed item

The complete field set in one table, in **screen order** - which is the frozen order of
section 11.2, so this table doubles as the golden list CI asserts against. "Boot" means the
value is read during startup and is on the screen the moment it opens; "on demand" means a
button on the screen triggers it.

Cost column: values marked *(V1)*, *(V2)*, *(V3)* are measured by the m1 harness (section 13)
and are placeholders here rather than guesses - `MILESTONES.md`'s own rule is "committed
numbers, no invented values".

### 10.1 identity

| Field | Source / API | When | Cost | Proves | Does NOT prove |
|---|---|---|---|---|---|
| Device name | user setting, `counters`/settings | boot | 0 | the owner's own label is intact | anything about the hardware - it is user text |
| Board | `board::BOARD_NAME` (cfg) | compile | 0 | which build this is | that the build matches the hardware - the flash rows are the check |
| Chip | fixed for the target | boot | 0 | - | - |
| Chip revision | `efuse_hal_chip_revision()` (`hal/efuse_hal.h`); 103 = v1.3 | boot | us | which silicon family, hence which eFuse table applies | nothing about firmware |
| Boot ROM | `extern uint32_t _rom_eco_version;` @ `0x4FC00014` | boot | us | which mask-ROM build is in this die - the code below ours that we cannot rebuild | nothing about integrity; ROM is silicon and cannot be modified (section 8 R7) |
| ROM chip id | `extern uint32_t _rom_chip_id;` @ `0x4FC00010` | boot | us | the die reports itself as ESP32-P4 (`0x12`) | that it is one, if firmware is hostile |
| MAC | `esp_read_mac(mac, ESP_MAC_BASE)` / `esp_efuse_mac_get_default()`; `ESP_EFUSE_MAC` BLK1:0..47 | boot | us | this unit's factory identity, comparable to what the owner recorded from `esptool chip_id` | that a different unit could not report the same six bytes |
| Die unique ID | `esp_efuse_read_field_blob(ESP_EFUSE_OPTIONAL_UNIQUE_ID, buf, 128)`, BLK2:0, 128 bits | boot | us | a 128-bit factory per-die value, write-protected | anything if it is not burned - the row reads `not burned` and says nothing (m1 V3) |

### 10.2 firmware

| Field | Source / API | When | Cost | Proves | Does NOT prove |
|---|---|---|---|---|---|
| Version | `env!("CARGO_PKG_VERSION")` | compile | 0 | what the build calls itself | nothing - it is a compiled-in string, which is why the digests are beside it |
| ESP-IDF version | `esp_get_idf_version()` | boot | us | which IDF the app was linked against | that the bootloader was built from the same one - the bootloader digest is that check |
| Anti-rollback (image) | `esp_app_get_description()->secure_version` | boot | us | the version this image claims | that the chip enforces it |
| Anti-rollback (efuse) | `esp_efuse_read_secure_version()` | boot | us | the floor the bootloader will enforce | that a lower image cannot be flashed - only that it will not boot |
| `firmware_digest` | composite, section 2.4 | boot | 0 (three digests already computed) | the three immutable regions together match a published release | that the reporting firmware is honest (section 9) |
| App image | `esp_partition_get_sha256()` on the running partition | boot | *(V1)* | the app in flash is byte-for-byte a published app | that this digest is the app that is executing, if the firmware is hostile |
| Bootloader IDF | `esp_ota_get_bootloader_description(NULL, &desc)->idf_ver` | boot | us | which IDF built the bootloader now in flash - a different string from the app's row is a stale bootloader | that the bootloader is otherwise unmodified; the digest is that check |
| Bootloader image | `esp_partition_get_sha256()` on a stack `esp_partition_t` at `0x2000`, type `ESP_PARTITION_TYPE_BOOTLOADER` (section 2.2) | boot | sub-ms | the code that runs before ours matches the release | that the ROM verified it - only secure boot does that |
| Partition table | read 0xC00, `esp_partition_table_verify()`, SHA-256 over `(n+1)*32` (section 2.3) | boot | sub-ms | flash is laid out the way the security model describes, including which partition carries the `encrypted` flag | that the partitions contain what their names say |

### 10.3 flash

| Field | Source / API | When | Cost | Proves | Does NOT prove |
|---|---|---|---|---|---|
| Size (header) | `esp_flash_get_size()` - the value in the image header, i.e. `CONFIG_ESPTOOLPY_FLASHSIZE` | boot | us | what the build was told the flash is | what the flash is |
| Size (detected) | `esp_flash_get_physical_size()` - `1 << (id & 0xFF)` from RDID | boot | us | what the fitted part reports | - |
| JEDEC ID | `esp_flash_read_id(NULL, &id)`, `RDID 0x9F`, `[23:16] mfr` | boot | us | the fitted flash part's manufacturer / type / capacity codes | that two parts with the same ID are the same die (GD25Q128C and E share `c8 40 18`) |
| Flash unique ID | `esp_flash_read_unique_chip_id(NULL, &u64)`; `ESP_ERR_NOT_SUPPORTED` if absent | boot | us | a factory serial number for the flash part - a swapped chip changes it | anything if the part does not implement `4Bh`; and it is the top 64 of 128 bits on GD parts (section 4.6) |
| Partitions (map) | `esp_partition_find` / iterator | boot | us | the live table, row by row, comparable to `firmware/partitions.csv` | that a partition's contents match its declared purpose |
| Reserved space | raw read of the must-be-blank spans, section 3.3 | **on demand** | *(V2)*, seconds | no bytes are present outside the partitions and images | that a payload is absent from a *mutable* partition, or that the scan itself is honest |
| `wallets` digest (raw) | raw read of `0xE00000..0xE40000` | on demand | ~ms | whether the sealed region changed since the owner last looked | anything about content - it is a digest of ciphertext |
| `counters` digest (raw) | raw read of `0xE40000..0xE44000` | on demand | ~ms | the ledger changed (it changes every boot) | anything - it is expected to change |

### 10.4 efuse

Every row here: read via `esp_efuse_read_field_bit` / `_blob` / `_cnt` from memory-mapped read
registers, cost microseconds, at boot. Section 5 has the symbol, bit position and doc link for
each; this table is the "what does it prove" column.

| Field | Proves | Does NOT prove |
|---|---|---|
| Secure boot | the ROM will refuse to run a bootloader whose signature does not verify against a burned digest - **the one guarantee on this screen the app cannot forge** (section 9.3) | that *this* app is the signed one, if the row itself is a lie; a burned unit proves it structurally, a lying unit proves nothing |
| Aggressive revoke | whether one failed verification revokes a digest | - |
| Key digest 0/1/2 | **which** public key the ROM trusts - comparable off-device against `espsecure.py digest_sbv2_public_key` on the published signing key | that only that key is trusted, unless all three slots are shown - which is why all three are |
| Flash encryption + mode | whether flash contents are XTS-encrypted, and whether the unit is in re-flashable Development mode or locked Release mode | that the key is unrecoverable - the fault-injection tier in `SECURITY.md` concedes it may not be |
| Crypt count | the raw `SPI_BOOT_CRYPT_CNT` popcount | - |
| XTS key read protection | software, including attacker firmware, cannot read the flash encryption key | that a lab attacker cannot extract it |
| UART / USB-serial-JTAG / USB-OTG / forced download | whether someone holding the device can put the chip into ROM download mode over USB and write flash | that they cannot make the device *run* what they wrote - secure boot is that check |
| Secure download | whether download mode is restricted to the secure subset | - |
| Direct boot | whether the ROM will jump straight to unsigned flash contents | - |
| JTAG (pad / USB / soft) | whether a debugger can attach to the running CPU; `soft` is re-enablable with an HMAC token, `pad` and `USB` are permanent | that the CPU cannot be attacked by other means |
| JTAG select | which JTAG path the strapping pin selects | - |
| ROM log | whether the boot ROM prints over UART / USB-serial-JTAG | anything security-relevant on its own; it is here because it is one-way state a reader comparing against the burn runbook will look for |
| Key blocks (table) | how the six eFuse key blocks are allocated and protected, against `ESP-SEAL.md` 6.1's budget | that an unused block stays unused |

### 10.5 state

| Field | Source | When | Cost | Proves | Does NOT prove |
|---|---|---|---|---|---|
| Boot count | ledger, section 6.2 | boot | us (plus one bit-clear program) | the device has been powered on this many times since the counters partition was last erased | anything against a full-flash restore, which rolls it back undetectably |
| Since acknowledged | ledger head | boot | us | power-ons since the owner last pressed `Mark as seen` | same limit |
| Wipe epoch | ledger head | boot | us | how many times the device has been wiped | - |
| Storage | wallets partition, granularity per Q2 | boot | ms | whether anything is stored | nothing about what |

### 10.6 operation (0.1.0's rows, kept)

| Field | Source | When | Cost | Proves | Does NOT prove |
|---|---|---|---|---|---|
| Radio kill GPIO | `gpio_get_level(board::RADIO_KILL_GPIO)`, pad claimed `INPUT_OUTPUT` so the readback is the real level (`firmware/README.md` pitfall 14) | boot | us | the kill line is actually low right now | that the C6 was held low during the pre-`app_main` window - the Elecrow power-on window is a documented, unfixable-in-firmware gap (`SECURITY.md`) |
| Boot self-test | `notyas_core::selftest` | boot | ms | this build computes the published test vectors correctly on this silicon | that it computes anything else correctly |

---

## 11. Screen layout - S-46 Verify device

Consistent with `UX-SCREENS.md` throughout: the layout law (section 0.1 - everything derives
from `Metrics`, no absolute positions), the type conventions (0.5 - hex is `MONO_SMALL`,
never Sans), the component library (C1 TopBar, C6 scroll convention, C8 MonoValue's group
gutter, C11 QrPlayer), the button vocabulary (3.1) and the reflow rules (5). It introduces
no new component and three new `RegionId` values.

### 11.1 The three row kinds

Everything on the screen is one of exactly three shapes. Nothing else is permitted; a
fourth shape is a design review.

**K1 - inline row.** One label, one short value, one line.

```
  Chip revision                    v1.3
  |<------ label col ------>| gap |<-- value col -->|
```

- Label: `SANS_REGULAR_32`, `INK_SECONDARY`, left-aligned in the label column.
- Value: `MONO_SMALL`, `INK_PRIMARY`, left-aligned at the value column origin. Left-aligned,
  not right-aligned: a column of left-aligned mono values makes differing *prefixes* jump
  out, which is how digests and IDs are actually compared.
- `label_w = (body.w * 2 / 5).clamp(220, 300)`; `value_x = body.x + label_w + m.gap`.
  At 720x720: `label_w = 268`, value column `392 px` = **23 `MONO_SMALL` characters**.
  At 800x480: `label_w = 299`, value column `436 px` = **25 characters**.
- **Inline budget is 23 characters** (the narrower panel governs, so a value never wraps on
  one panel and not the other). A value longer than 23 characters is a K2 row, and CI
  asserts it: any K1 value whose rendered advance exceeds the 720x720 value column is a
  test failure, not a wrap.
- Row height `ROW_H = 50` (`SANS_REGULAR_32.line_height` 42 + 8). Label and value share one
  baseline.
- Hairline (`theme::HAIRLINE`) across the full body width at the row's bottom edge.

**K2 - block row.** One label, one long value that gets the full width.

```
  App SHA-256 (running partition)
    00  3f9a 27c1 b40e 55d2 8a11 6ffe
    24  0c93 4471 e2ab 1d05 77c8 39b6
    48  aa41 0e2f 9c73 5b18
```

- Label line: `SANS_REGULAR_32`, `INK_SECONDARY`, at `body.x`, height `ROW_H`.
- Value lines: `MONO_SMALL`, `INK_PRIMARY`, indented `m.gap` from `body.x`, line pitch 36
  (`MONO_REGULAR_28.line_height`).
- **Hex formatting, frozen:** lowercase, grouped in fours separated by one space,
  **six groups (24 hex characters) per line**, each line prefixed with the character offset
  of its first group in `INK_MUTED` mono (`00`, `24`, `48`) plus one space - C8's group-index
  gutter verbatim, including C8's own worked example offsets. A 64-character digest is
  therefore always exactly three lines, broken at exactly the same characters, on every
  panel and in every build.
  Width: `gap(12) + 3 chars gutter (51) + 29 chars value (493) = 556 px`, against 672 px of
  body at 720x720 and 748 px at 800x480. Fits both with margin; **the break is a constant,
  not a fit computation**, so two devices with different panels can be held side by side
  and compared line by line. This is the single most important formatting decision on the
  screen and it is why S-46 does not use a landscape rail (11.4).
- Block height: `ROW_H + lines * 36 + m.gap`. A 64-hex digest block is `50 + 108 + 12 = 170`.

**K3 - table.** Fixed mono columns, used where a field is naturally a small matrix (the
partition map, the eFuse key blocks, the reserved-space spans). Column widths are specified
in **characters**, and the renderer multiplies by `MONO_SMALL.glyph('m').advance` (17 px), so
the table is byte-identical at both geometries.

- Header line is the section-style label (K2's label line shape).
- Table body is indented `m.gap` from `body.x`, so the **character budget is 38**
  (`12 + 38*17 = 658 px`, against 672 px of body at 720x720). Any table wider than that
  wraps to a two-line-per-entry form rather than shrinking the font or truncating.
- Row pitch 36; no per-row hairline inside a table (the column alignment is the separator);
  one hairline under the whole table.

Three tables ship, and their budgets are fixed here rather than left to the implementation:

*Partition map* - 38 characters (`10 + 10 + 9 + 6 + 3`), field order and spelling matching
`firmware/partitions.csv` so the two are compared directly:

```
    factory   app/fact  0x010000  14272K
    wallets   data/0x40 0xE00000    256K  enc
    counters  data/0x41 0xE40000     16K
```

(`14272K` is `0xDF0000`, the app declared at its collision bound by the ratified Q7. The
six-character size column was sized for `4096K` and still fits; nothing in the layout moves.)

*eFuse key blocks* - **two lines per block**, because P4's longest key-purpose enumerator is
`HMAC_DOWN_DIGITAL_SIGNATURE` at 27 characters and truncating an enumerator name would break
the property that makes the row useful (it is compared character-for-character against
`espefuse.py summary` output and against the burn runbook):

```
    KEY0  SECURE_BOOT_DIGEST0
          rd_dis 0   wr_dis 1
    KEY1  XTS_AES_128_KEY
          rd_dis 1   wr_dis 1
```

Line 1 is `6 + up to 28` characters; line 2 is indented six characters and prints the raw bit
values, not words. `<unused>` is the rendering for a block where
`esp_efuse_key_block_unused()` is true.

*Reserved-space spans* - two lines per span for the same reason (a span line plus a status
line that can carry an offset):

```
    0xe44000-0x2000000     18 595 840 B
      all 0xff
    0x1d1c00-0xe00000      12 772 352 B
      4 096 set, first 0x01d2000
```

### 11.2 Sections

Six section headings, in this order, **frozen** - contract rule 3. A reader who has seen the
screen once knows where to look; a reader comparing two units scans the same y-offset. The
exact field list under each is section 10's table, which is also the golden list CI asserts.

```
  identity      who this unit is                        detail: section 4,  fields 10.1
  firmware      what it is running                              section 2,         10.2
  flash         the medium and what is on it                    section 3,         10.3
  efuse         the one-way chip configuration                  section 5,         10.4
  state         counters and storage                            section 6,         10.5
  operation     radio and self-test (0.1.0's rows, kept)        section 1,         10.6
```

Order is not arbitrary: identity first because "is this my device" is answerable without
comparing anything against a release; firmware second because it is the reason most people
open the screen; the one-way chip configuration after the things it protects; mutable state
after the immutable; and 0.1.0's two existing rows last, where they have always been.

Heading style: `SANS_SEMIBOLD_32`, `INK_PRIMARY`, all lower-case-as-written (not shouted -
`UX-SCREENS.md` reserves the product's only all-caps string for S-02), preceded by
`2 * m.gap` of space, followed by a full-width `BORDER_STRONG`-weight rule and `m.gap`.
Heading block height `= 2*m.gap + 42 + m.gap` (78 at 720x720).

### 11.3 Wireframe (720x720)

Rendered at the spec's character grid (72 columns x 36 rows, 10 px x 20 px per cell). Three
viewports shown; the sheet is longer and scrolls.

```
+----------------------------------------------------------------------+
| < Back   Verify device                          [ 1 / 5 ]    [ Lock ] |
+----------------------------------------------------------------------+
|  identity                                                             |
|  --------------------------------------------------------------------|
|  Device name                     "kitchen-desk"                       |
|  Board                           waveshare-4b                         |
|  Chip                            ESP32-P4                             |
|  Chip revision                   v1.3                                 |
|  Boot ROM                        eco 2                                |
|  ROM chip id                     0x12                                 |
|  MAC                             60:55:f9:3a:1c:04                    |
|  Die unique ID                                                        |
|    00  1f4c 90ab 3e77 d215 8c60 44f9                                  |
|    24  b1a3 5e08                                                      |
|                                                                       |
|  firmware                                                             |
|  --------------------------------------------------------------------|
|  Version                         0.2.0                                |
|  ESP-IDF (app)                   v5.5.4                               |
|  ESP-IDF (bootloader)            v5.5.4                               |
|  Anti-rollback (image)           2                                    |
|  Anti-rollback (efuse)           2                                    |
|  Firmware digest                                                      |
|    00  9b21 c7fe 034a 88d5 6e19 22bc                                  |
|    24  af70 5d31 e0c8 1946 7b2f aa53                                  |
|    48  0d84 c611 39e7 f2a0                                            |
|  App image (0x010000, 1 842 176 B)                                    |
|    00  3f9a 27c1 b40e 55d2 8a11 6ffe                                  |
|    24  0c93 4471 e2ab 1d05 77c8 39b6                                  |
|    48  aa41 0e2f 9c73 5b18                                            |
|  Bootloader image (0x002000, 22 352 B)                                |
|    00  ...                                                            |
|                                                    ------ more below  |
+----------------------------------------------------------------------+
|  [ < Prev ]            [ Show as QR ]                    [ Next > ]   |
+----------------------------------------------------------------------+
```

Later viewports, same shapes:

```
|  Partition table (0x008000, 128 B)                                    |
|    00  71e0 3c9d 4a15 b8f2 0c67 9dd1                                  |
|    24  ...                                                            |
|                                                                       |
|  flash                                                                |
|  --------------------------------------------------------------------|
|  Size (header)                   32 MB                                |
|  Size (detected)                 32 MB                                |
|  JEDEC ID                        c8 40 19                             |
|  Flash unique ID (64 of 128)     4d81 2f60 aa39 07c5                  |
|  Partitions                                                           |
|    factory   app/fact  0x010000  14272K                               |
|    wallets   data/0x40 0xE00000    256K  enc                          |
|    counters  data/0x41 0xE40000     16K                               |
|  Reserved space                  not scanned      [ Scan ]            |
|                                                                       |
|  efuse                                                                |
|  --------------------------------------------------------------------|
|  Secure boot                     disabled                             |
|  Aggressive revoke               no                                   |
|  Key digest 0                    not burned                           |
|  Key digest 1                    not burned                           |
|  Key digest 2                    not burned                           |
|  Flash encryption                disabled                             |
|  Encryption mode                 disabled                             |
|  Crypt count                     0                                    |
|  Manual encrypt                  enabled                              |
|  UART download                   enabled                              |
|  Secure download                 disabled                             |
|  USB-serial-JTAG download        enabled                              |
|  USB-OTG download                enabled                              |
|  Forced download                 enabled                              |
|  Direct boot                     enabled                              |
|  JTAG (pad)                      enabled                              |
|  JTAG (USB)                      enabled                              |
|  JTAG (soft)                     0 of 3                               |
|  JTAG select                     0                                    |
|  ROM log                         0                                    |
|  ROM log (USB)                   enabled                              |
|  Key blocks                                                           |
|    KEY0  <unused>                                                     |
|          rd_dis 0   wr_dis 0                                          |
|    ...                                                                |
|                                                                       |
|  state                                                                |
|  --------------------------------------------------------------------|
|  Boot count                      1 235                                |
|  Since acknowledged              5             [ Mark as seen ]       |
|  Acknowledged at boot            1 230                                |
|  Wipe epoch                      0                                    |
|  Storage                         2 wallets                            |
|                                                                       |
|  operation                                                            |
|  --------------------------------------------------------------------|
|  Radio kill GPIO54               low                                  |
|  Boot self-test                  6/6 passed                           |
|                                                                       |
|  These values are read from the chip and from flash by the firmware   |
|  running on this device.                                              |
```

The eFuse block is shown as a dev board reads today, which is the honest worst case and the
one most readers will see first: twenty rows, every one of them a raw state. On a release unit
after the m13 burn runbook roughly half of them change and three 64-hex digest blocks appear.
That the section is long is the point - collapsing it into one row would be the verdict
contract rule 2 forbids, and the reader who does not care simply pages past a labelled
section, which is what the section headings are for.

### 11.4 Reflow (800x480), and the one documented exemption

Identical arrangement, identical column model, identical hex line breaks; the body is
377 px instead of 604 px, so the sheet is roughly eight viewports instead of five and the
bar's viewport counter reads `[ i / 8 ]`.

**DECISION - S-46 is exempt from reflow rule 1 (landscape content + rail).** Rule 1 moves the
action set into a right-hand rail of `clamp(w/4, 220, 300)` on landscape panels. Applying it
here would narrow the body to about 475 px, which is below the 556 px the frozen hex block
needs, forcing either a different line break at 800x480 or a smaller group count. Either
outcome destroys the property that makes the screen useful - that the same digest occupies
the same three lines with the same breaks on every unit. Rule 3 of the reflow set
("verification data gets the width") is the governing rule for this screen and it wins.
The action row stays at the foot at both geometries.

### 11.5 Regions

| RegionId | Label | Min size | Enabled when |
|---|---|---|---|
| `Back` | "< Back" | bar | always |
| `Lock` | "Lock" | bar chip | a session is open (absent pre-PIN) |
| `ReviewPrev` | "< Prev" | 200 x `TOUCH_MIN` | viewport > 1 |
| `ReviewNext` | "Next >" | 200 x `TOUCH_MIN` | viewport < n |
| `VerifyQr` | "Show as QR" | 240 x `TOUCH_MIN` | always |
| `VerifyScanFlash` | "Scan" | 140 x `TOUCH_MIN` | always (re-runs when already scanned) |
| `VerifyAckBoots` | "Mark as seen" | 240 x `TOUCH_MIN` | storage present and unlocked |

`ReviewPrev`/`ReviewNext` and the `[ i / n ]` bar counter already exist in `UX-SCREENS.md`
(C1 right slot, C5 labels, section 4's enum) and are reused verbatim rather than inventing a
scroll pager: S-46 is long reference material, C6 requires an explicit pager once content
exceeds two viewports, and stepping one viewport at a time is exactly what a spec sheet
wants. Drag-scroll (0.1.0's `scroll_by`) stays as the fast path, and C6's "more below" /
"more above" markers are added - 0.1.0 lacks them, and C6 already names that as a bug.

**Three additions to `UX-SCREENS.md` section 4's `RegionId` list are required**:
`VerifyQr`, `VerifyScanFlash`, `VerifyAckBoots`. They follow the naming rule (the meaning of
the tap, not the widget). Flagged for the UX-SCREENS owner rather than edited here.

### 11.6 Colour

Contract rule 2 bans verdict colour. What survives:

- `INK_SECONDARY` labels, `INK_PRIMARY` values, `INK_MUTED` offset gutters. That contrast
  ladder is the whole visual hierarchy and it is doing the work colour would otherwise do.
- `HAIRLINE` per row, `BORDER_STRONG` under a section heading.
- Two pre-existing exceptions, both restatements of a value rather than judgements of it,
  both already shipped in 0.1.0 and both carried by the **word** first: a self-test row
  reading `FAILED: <names>` is `DANGER`, and the radio row is `DANGER` when the kill GPIO
  does not read low. These stay because a device that failed its own arithmetic or is not
  holding the radio in reset is a different situation from a field the reader is being asked
  to compare, and 0.1.0 already established them.
- `not read` renders in `INK_MUTED`. It is the absence of a value, not a bad value.
- Nothing else on the screen is coloured. No `SUCCESS` green appears anywhere on S-46.

### 11.7 What CI asserts (additions to `UX-SCREENS.md` section 6)

- **Field order is frozen**: the rendered label sequence equals a checked-in golden list,
  at both geometries. A reordering is a deliberate, reviewed change to that list.
- **No truncation**: every digest rendered on S-46, recovered from the draw calls with
  grouping spaces removed, equals its full 64-character source string. S-46 is added to the
  existing no-truncation test's screen set with no allow-listed exceptions.
- **Inline budget**: no K1 value's rendered advance exceeds the 720x720 value column.
- **Hex breaks are geometry-invariant**: the line partition of every K2 block is identical
  at 720x720 and 800x480.
- **Pre-PIN field set**: the label sequence rendered with no session open equals the
  pre-PIN golden list, which is a strict subset of the unlocked one (section 7.4).
- **No banned words**: the existing banned-words check ("secure", "safe", ...) covers S-46's
  literals; extended with the verdict vocabulary this contract bans ("genuine", "verified",
  "protected", "trusted", "clean", "OK").

---

## 12. Considered and left out

Design contract rule 4: the curation has to be reviewable, so here is everything that was on
the table and did not make it, with the reason. This list is as much a part of the spec as
the field list - a future "we should also show..." is answered here or it is a real addition.

Note the difference between this section and section 8. Section 8 rejects things that are
*wrong in kind* and would be wrong at any size. This section drops things that are merely
**not worth a row** on a screen whose value depends on nobody skipping it.

| Considered | Left out because |
|---|---|
| Build date and time | `CONFIG_APP_REPRODUCIBLE_BUILD` zeroes them in `esp_app_desc_t` by design (`REPRODUCIBLE.md` 1.3). A field that is deliberately constant across all builds is noise. |
| Compiler / CMake / Ninja / IDF-tool versions | They belong to the build, not the device, and they are already published per release in `BUILDINFO.txt` where a verifier can diff them properly. Putting a subset on the device would invite comparing the wrong four of twenty. |
| The full merged `sdkconfig` | Thousands of lines. The security-relevant ones are eFuses, which are read from silicon rather than from a claimed config; the rest is build configuration that the published `*-sdkconfig.txt` artifact covers exhaustively. |
| CPU frequency, cache configuration, PSRAM size and mode | Performance configuration. They do not distinguish an honest device from a modified one, and a wrong value here has no security meaning. |
| Free heap / largest free block / PSRAM free | Changes every boot for benign reasons; nothing to compare against. Same objection as the RAM scan (section 8, R3) without even the pretence of integrity. |
| Uptime | Resets on every power cycle. The boot counter is the durable version and is in. |
| Reset reason (`esp_reset_reason()`) | Genuinely tempting as anti-tamper - a brownout or watchdog reset the owner did not cause is *information*. Left out because it is a one-boot value with a high benign rate (every USB reflash, every power blip, every debug session), so it would sit on the screen changing for uninteresting reasons and dilute the fields that do not. It stays in the boot log, where triage can reach it. Revisit if field reports ever need it. |
| Die temperature, supply voltage | Sensor readings. Not identity, not integrity. |
| Per-slot occupancy map of the `wallets` partition | Directly leaks how many wallets exist, which is the leak `OPEN-QUESTIONS` Q2 is about. The aggregate storage row at Q2's granularity is the ceiling. |
| Per-sector erase map of any partition | Same objection, plus it would make the duress filler design (`ESP-SEAL.md` 3.6) pointless by construction. |
| The `wallets` partition **decrypted** digest | Would require unsealing, so it is post-PIN by construction, and it is a digest of plaintext secret material - it must never exist even as an intermediate. |
| The ESP32-C6 radio module's MAC or any C6 state | The C6 is held in reset by the kill GPIO from the first line of `app_main` and there is no code path to talk to it (`SECURITY.md` invariant 1). Reading it would require adding one, to display a value with no verification use. The kill-GPIO pad level is the row that matters and it is already there. |
| The GT911 touch controller / display panel firmware versions | Vendor init sequences with no published integrity story (`SECURITY.md` known accepted risks). A version string from an unverifiable peripheral is not evidence, and printing it implies it is. |
| The STC8 co-MCU state (Elecrow only) | Same, and we deliberately read nothing security-relevant from it (`SECURITY.md`). |
| Task / thread counts, scheduler statistics, stack high-water marks | Section 8 R1. |
| A count of "modules" or "features" compiled in | A compiled-in constant, which invariant 5 forbids on this screen, and a self-assertion, which section 8 R4 forbids everywhere. |
| SD card presence, card CID/CSD | The card is removable user media, mounted on demand only. Not part of the device's identity or its trusted path. |
| Certificate or key material of any kind other than the secure boot **public key digest** | The digest is a public value and the actual root of trust (section 5.1). Nothing else key-shaped goes near this screen. |
| A "last successful unlock" timestamp | There is no clock (`SECURITY.md` invariant 3 - no clock on any path). A boot index is the only ordering the device honestly has, and that is what the counter provides. |

---

## 13. Milestones

Mapped onto `MILESTONES.md`'s existing milestones; nothing here asks for a new one. The
sequencing rule is the one that document already uses: decisions and measurements first,
because they constrain formats that cannot change afterwards.

| Milestone | What lands |
|---|---|
| **m1** (foundations, frozen geometry) | **Decisions and numbers only, no UI.** Freeze the `firmware_digest` construction (2.4) and the release verification manifest field set (7.3) - both constrain m12's artifact set, so they cannot wait. Add three measurements to the existing m1 harness alongside M3-M9: **V1** app / bootloader / partition-table hash times at boot on both boards; **V2** full raw-flash read-and-hash throughput on both fitted parts (sizes the reserved-space scan); **V3** `esp_flash_read_unique_chip_id()` support on each fitted part, taken on the bench at the same time as the M6 JEDEC read, which m1 already requires. Size the boot-log cell array against M6's partial-page-program result. Commit the numbers; no invented values. |
| **m3h** (esp-idf-hmac, safe Rust over the P4 security peripherals) | The eFuse posture readout surface: key-block purposes, `RD_DIS`/`WR_DIS`, `esp_secure_boot_read_key_digests()`, the download-mode and JTAG field group, the anti-rollback pair. This is the crate whose whole purpose is safe Rust over these peripherals, and `KeyProvenance` (`ESP-SEAL.md` 4.x) is already the same readout in miniature. Extend `firmware/bindings/verify.h` with the headers this needs. |
| **m4a** (storage on hardware, PIN unlock, minimal UI) | Boot counter and the acknowledgement mark in the ledger (section 6). S-03's pre-PIN entry into Verify with the pre-PIN field set and its CI golden list (7.4). |
| **m4b** (wallet management UI) | The S-46 rebuild: K1/K2/K3 row kinds, the six frozen sections, the viewport pager, the frozen field order, the identity / firmware / flash rows, the reserved-space scan and its C3 Busy screen, and the CI assertions in 11.7. Storage-row granularity per whichever Q2 package was ratified. |
| **m8** (animated QR out) | `[ Show as QR ]` - the `notyas-verify/1` payload through C11 QrPlayer. Depends on the QR player existing, which is m8's own deliverable. |
| **m12** (reproducible builds published) | `notyas-<ver>-<board>-VERIFY.json` emitted by the container build, listed in `SHA256SUMS.txt`, and the "Compare your device against the release" section of `VERIFYING.md`. m12's existing exit gate already requires the reproduced image to boot with the same Verify-screen SHA256 on both boards; that gate extends to the composite `firmware_digest` and the two new region digests. |
| **m13** (hardening closeout and release) | The eFuse section validated against a real release unit after the burn runbook, which is the first time most of those fields are anything but `disabled`. The self-reporting wording (9.4) into `docs/SECURITY.md` and `VERIFYING.md`. The final frozen field order. The post-v3 eFuse table re-check if `OPEN-QUESTIONS` Q9 moved production to rev >= v3.1. |

Parity rows this closes, in `PARITY.md`'s vocabulary: **"Bless Firmware / genuine-state LEDs"**
(class c) - the notyas equivalent is this screen plus reproducible builds, and `PARITY.md`
already frames it as "software attestation, labeled as such"; section 9 is the labelling that
row promises. **"View Identity"** (class a) - the identity section covers the device half; the
master fingerprint half belongs to the wallet screens. **"Firmware upgrade, factory-signed
only"** (class b, completed at m13) - the secure boot digest row is what makes "which key
signs this device's firmware" answerable on the device.

---

## 14. Open decisions

Each is a genuine owner decision with a recommendation. Greppable for the reconciliation pass
that folds them into `OPEN-QUESTIONS.md`.

`OPEN:` **The release verification manifest artifact.** Section 7.3 requires a new per-board
artifact `notyas-<ver>-<board>-VERIFY.json` in `REPRODUCIBLE.md` 3.5's table, emitted by
`build.sh` and listed in `SHA256SUMS.txt`. That table is `REPRODUCIBLE.md`'s to own.
*Recommendation: accept.* Without it there is no published number the device's digests can be
compared against, and the image-content-versus-file-digest confusion (`REPRODUCIBLE.md` 4.3
calls it the single most likely support question) stays in the user's path. The alternative -
folding the fields into `BUILDINFO.txt` - is rejected because that artifact's format is
deliberately loose for human triage and an off-device checker needs a stable parse.

`OPEN:` **Boot-log cell budget and placement in the ledger sector.** Section 6.2. The
`ESP-SEAL.md` 3.7 sector map is that document's to own. *Recommendation: take the cells from
the reserved region plus the second reserved sector pair rather than shrinking an existing
log, and size the array from m1's M6 partial-page-program measurement.* Must be settled
before m3 freezes the format.

`OPEN:` **Three new `RegionId` values.** `VerifyQr`, `VerifyScanFlash`, `VerifyAckBoots`
(11.5), for `UX-SCREENS.md` section 4. *Recommendation: accept* - they follow the naming rule
and no existing variant carries the meaning. Reject only if you would rather the reserved-space
scan and the acknowledgement mark be settings-screen actions instead of inline rows, which
would separate an action from the value it changes.

`OPEN:` **S-46's exemption from reflow rule 1.** Section 11.4 keeps the full body width at
800x480 instead of moving actions into a landscape rail, so the hex line breaks are identical
on both panels. *Recommendation: accept* - reflow rule 3 ("verification data gets the width")
is the governing rule for a screen made of verification data, and identical breaks are what
make two units comparable side by side.

`OPEN:` **The `wallets` raw digest pre-PIN, contingent on Q2.** Section 7.4.
*Recommendation: post-PIN only under Q2(b)/(c); permitted pre-PIN under Q2(a).* Under sparse
occupancy a blank encrypted partition raw-reads as all `0xFF`, so its digest is a publicly
computable constant and showing it pre-PIN announces blank-versus-not. Under
`Occupancy::AlwaysFilled` there is no constant to recognise. This is one more entry in Q2's
ledger and it points the same way Q2's own recommendation does.

`OPEN:` **Does the reserved-space scan run at boot?** Section 3.3 / 2.5 specifies it as
on-demand behind `[ Scan ]` with a C3 determinate Busy screen, because it reads the whole
flash. *Recommendation: keep it on demand.* Adding seconds to every boot for a check whose
result changes only when someone has written to flash outside the partitions is the wrong
trade, and the C3 law would force a Busy screen into the boot path anyway. Reject if you want
the boot self-test to be a complete integrity pass at the cost of boot time - in which case it
becomes a self-test row (S-01) with its own progress unit, not a Verify row.

`OPEN:` **Multiple enrolled secure-boot key digests.** Section 5.1 prints all three slots.
This interacts with `OPEN-QUESTIONS` Q32 ("whose secure-boot key?"): a GPL3 product where users
may sign their own firmware could enrol a user key alongside the project key, and the screen
then shows two digests and which are revoked. *Recommendation: print all three slots
unconditionally, `not burned` for empty ones*, and let Q32 decide what gets burned. The
alternative - showing only the first burned digest - hides exactly the case (a second key
enrolled without the owner's knowledge) that makes the row worth having.

`OPEN:` **A mask-ROM digest.** Section 4.3 establishes that the P4's 128 KiB HP ROM at
`0x4FC00000-0x4FC20000` is readable from the app (a locked PMP R+X entry covers exactly that
range) and could be hashed in a few milliseconds. It is left off the screen for two reasons:
a ROM digest can only ever detect a *different chip*, never a modification (section 8 R7), and
**no offline reference exists** - Espressif published two P4 ROM ELFs covering 97.5% and 99.4%
of the region, and neither is the ROM these boards run. *Recommendation: report
`_rom_eco_version` and `_rom_chip_id` only, as specified.* Revisit only if the project ever
runs the per-revision reference enrolment that `OPEN-QUESTIONS` Q31 (multi-party attestation)
contemplates, in which case the digest becomes comparable and is worth one more row.

`OPEN:` **Does the flash unique-ID row ship at all?** Section 4.6. It depends on m1's **V3**
bench result on both fitted parts, and there are four documented ways it can come back
useless (vendor driver off by default on P4, 128-bit GD IDs truncated to 64, GD25Q128C sharing
a JEDEC ID with the E die while lacking the `4Bh` command, and a probable byte-shift on 32 MB
parts in 4-byte address mode). *Recommendation: ship it if V3 returns a plausible, stable,
non-zero value on both boards; otherwise render `not supported` and say in `VERIFYING.md` that
flash-substitution detection rests on the JEDEC ID and physical size alone, which does not
catch a swap for the same model.*

`OPEN:` **Does the boot counter increment on a boot that fails the self-test?**
*Recommendation: yes, and increment before the self-test runs.* A boot that ended at S-02
still happened, and a counter that skips failed boots is a counter an attacker can advance for
free by causing failures. Cost: the counter write happens early in boot, before the UI exists,
which is fine - it is one bit-clear program into an already-erased cell. **Bounded by the
precondition in section 6: early in boot means early in boot on a device whose ledger is
formatted. On an unprovisioned or blank device there is no write at all, because invariant 2a
forbids one.**
