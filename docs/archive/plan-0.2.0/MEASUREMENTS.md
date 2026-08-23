# MEASUREMENTS - numbers taken off the real silicon

Every number here was measured on the two dev boards on the bench, on
**2026-08-18**, with the temporary harness in `firmware/src/measure.rs`
(cargo feature `measure`, off by default). Nothing in this file is an estimate,
a datasheet figure, or a scaled-from-another-chip guess; where a number could
not be taken, section 10 says so and why.

The milestone-1 storage freeze depends on several of these. Section 9 lists, in
plain terms, the design assumptions that the measurements **disprove** - that is
the most important part of this document.

## 1. Bench

| | Board A | Board B |
|---|---|---|
| Board | Waveshare ESP32-P4-WiFi6-Touch-LCD-4B | Elecrow CrowPanel Advanced 5inch ESP32-P4 |
| Port | COM3 | COM6 |
| SoC | ESP32-P4NRW32, **rev v1.3** (pre-v3.0 family) | ESP32-P4NRW32, **rev v1.3** |
| CPU tick rate | 360 ticks/us (360 MHz) | 360 ticks/us (360 MHz) |
| PSRAM | 33,554,432 B (32 MiB), 200 MHz, XIP from PSRAM on | same |
| Flash | 33,554,432 B (32 MiB) | 16,777,216 B (16 MiB) |
| Flash JEDEC ID | `0xC8 40 19` | `0xC8 40 18` |
| Flash unique ID | `0x4550343733115619` | `0x55373533320f2533` |
| Flash encryption | disabled (eFuse unburned) | disabled (eFuse unburned) |
| Secure boot | disabled (eFuse unburned) | disabled (eFuse unburned) |
| ESP-IDF | v5.5.4 | v5.5.4 |
| Firmware | 0.1.0 tree + `--features measure` | same |

Free memory at the moment the harness runs (after the boot self-test, before any
peripheral is brought up - the most memory the device will ever have):

| | Waveshare 4B | Elecrow 5 |
|---|---|---|
| PSRAM free | 31,395,344 B | 31,395,216 B |
| PSRAM largest free block | **30,932,992 B (29.5 MiB)** | **30,932,992 B (29.5 MiB)** |
| Internal RAM free | 429,507 B | 429,507 B |
| Internal largest free block | **253,952 B (248 KiB)** | **253,952 B (248 KiB)** |

## 2. Method, and how to reproduce it

```powershell
tools\build.ps1 -Board waveshare-4b --features measure
tools\flash.ps1 -Board waveshare-4b
espflash monitor --port COM3 --non-interactive     # capture; grep for "MEAS|"
```

- The harness runs from `main` immediately after the boot self-test and
  **before** `board::display_init()`, and never returns. Running it there is
  deliberate: the panel driver's framebuffer is the largest single PSRAM
  allocation in the product, so the Argon2id ceiling measured here is an upper
  bound the product cannot beat, and no other bus master is touching flash.
- Results are logged one per line as `MEAS|key=value|...`, microseconds unless
  the key says otherwise. Section 11 is the verbatim capture.
- Timing is `std::time::Instant` (esp-idf `gettimeofday`, 1 us resolution).
- The task watchdog is deinitialized for the run: a single Argon2id call at
  m=24 MiB blocks the calling task for nine seconds. The product image keeps its
  watchdog; this module is not in the product image.
- Every measurement ran three times (three flash-and-boot cycles across the
  day). Run-to-run spread is under 1% everywhere except the 4 KiB flash erase
  (see section 7). The tables quote the third run; the other two are within the
  spread quoted per table.
- **Flash writes.** Only the M6 soak writes, and only into the LAST 4 KiB sector
  of each part (Waveshare `0x1fff000`, Elecrow `0xfff000`) - far past the 4 MB
  app partition and outside every entry of `firmware/partitions.csv`. The sector
  is erased before the soak and erased again after it, with the all-`0xff` state
  verified by read-back both times (`MEAS|soak_restore|...|sector_blank=true` on
  both boards). Both boards were reflashed with the ordinary product image at
  the end of the session and verified running normally (free heap
  29,328,708 / 29,914,448 bytes, `repaints 0`, identical to the 0.1.0-m4 log).

## 3. M1 - Argon2id cost curve

`argon2` 0.5.3 (RustCrypto), `default-features = false`, Argon2id, version 0x13,
p = 1, 32-byte output, 6-byte password, 16-byte salt. The scratch is one
contiguous `heap_caps_aligned_alloc(64, m_kib * 1024, MALLOC_CAP_SPIRAM)` buffer
handed to `hash_password_into_with_memory`, so the crate never allocates and the
scratch location is exactly the one the real design would use. Times exclude the
allocation, include the whole KDF; the separate zeroization of the scratch is in
section 4.

Milliseconds, PSRAM scratch (Waveshare 4B / Elecrow 5):

| m_kib | m | t=1 | t=2 | t=3 |
|---|---|---|---|---|
| 64 | 64 KiB | 11.6 / 11.6 | 19.4 / 19.4 | 27.1 / 27.1 |
| 128 | 128 KiB | 18.3 / 18.3 | 33.8 / 33.8 | 49.3 / 49.3 |
| 256 | 256 KiB | 32.3 / 32.2 | 63.4 / 63.3 | 94.6 / 94.5 |
| 1024 | 1 MiB | 116.7 / 116.5 | 246.3 / 246.0 | 376.0 / 375.6 |
| 4096 | 4 MiB | 457.3 / 456.7 | 980.4 / 979.2 | 1503.2 / 1501.7 |
| 8192 | 8 MiB | 913.3 / 912.0 | 1961.5 / 1959.2 | 3009.8 / 3006.6 |
| **16384** | **16 MiB** | **1827.3 / 1824.7** | **3927.5 / 3922.8** | **6027.6 / 6020.6** |
| 24576 | 24 MiB | 2742.1 / 2738.0 | 5895.0 / 5887.6 | 9046.1 / 9036.8 |
| 32768 | 32 MiB | **ALLOCATION FAILED** | - | - |
| 65536 | 64 MiB | **IMPOSSIBLE** | - | - |
| 131072 | 128 MiB | **IMPOSSIBLE** | - | - |

The two boards agree to within 0.2% at every point (identical silicon, identical
clock, pure computation), and the digests match point for point across boards,
which is the check that the two runs computed the same thing.

**The grid stops at 24 MiB because the hardware stops there.** `m_kib = 32768`
asks for 33,554,432 bytes; the largest allocatable PSRAM block on a P4NRW32,
measured before any peripheral exists, is **30,932,992 bytes**. 64 MiB and
128 MiB are not near-misses - they are twice and four times the physical PSRAM
in the package. See section 9, finding A.

### Cost model

The marginal cost is dead linear in m and in t across three orders of magnitude:

```
t_ms  ~=  m_MiB * (114.2 + 131.5 * (t - 1))      +- 0.5%
```

Derived from the measured deltas (Waveshare, t=1): 8 -> 16 MiB costs
114.24 ms/MiB, 16 -> 24 MiB costs 114.35 ms/MiB, 4 -> 8 MiB costs 114.0 ms/MiB.
Extra passes cost 131.5 ms/MiB each (the first pass is cheaper because it has no
XOR-with-previous read). Checked against the measurement: 24 MiB, t=3 predicts
9053 ms, measured 9046 ms.

Anyone can now price a parameter set without a board.

### Where the scratch lives, and what PSRAM costs

Same parameters, scratch in internal SRAM versus in PSRAM (Waveshare,
milliseconds):

| m_kib | t | internal SRAM | PSRAM | difference |
|---|---|---|---|---|
| 64 | 1 | 11.751 | 11.610 | -1.2% |
| 64 | 2 | 19.356 | 19.354 | 0.0% |
| 64 | 3 | 27.098 | 27.103 | 0.0% |
| 128 | 1 | 18.262 | 18.276 | +0.1% |
| 128 | 2 | 33.776 | 33.803 | +0.1% |
| 128 | 3 | 49.308 | 49.328 | 0.0% |
| 256 | any | **ALLOCATION FAILED** (248 KiB is the biggest internal block) | 32.3 / 63.4 / 94.6 | - |

**PSRAM residency costs nothing measurable on this workload, and the linearity
of the main curve proves it beyond the cache-resident sizes.** At 64-128 KiB
both variants sit inside the 256 KB L2 cache, so that pair alone would not
settle it; but if PSRAM bandwidth mattered, the per-MiB cost would rise once the
working set passed the cache, and it does not: 114.0, 114.2 and 114.35 ms/MiB at
4, 8 and 24 MiB respectively. The workload is CPU-bound in BLAKE2b, not
memory-bound. The arithmetic agrees: Argon2 moves about 3 KiB of block traffic
per 1 KiB block processed, so at 114 ms/MiB it demands roughly 26 MB/s, against
the 203 MB/s of PSRAM write bandwidth measured in section 4 - about 13% of it.

### Recommended parameters

**Argon2id, m = 16384 KiB (16 MiB), t = 1, p = 1, 32-byte output.**
Measured cost: **1827 ms (Waveshare) / 1825 ms (Elecrow)**, plus 82.5 ms to
zeroize the scratch, so about **1.91 s of PIN stretch per unlock attempt**.

Reasoning:

1. It sits at the top of the ratified 0.5-2 s unlock budget, and the budget
   should be spent, because every millisecond is also the attacker's.
2. At a fixed time budget, buy memory before passes. m=16 MiB/t=1 (1.83 s) and
   m=8 MiB/t=2 (1.96 s) cost the same wall time, but the first forces an
   attacker to hold twice the memory per guess. RFC 9106's first recommendation
   is the same shape: maximize m, then set t to fill the budget.
3. It leaves headroom against the hard ceiling. 24 MiB/t=1 would be 2.74 s -
   over budget - and 32 MiB does not allocate at all, so 16 MiB is not near the
   cliff. It also survives the product's real memory situation: the display
   framebuffer and back buffer take about 2 MiB together at 720x720, and the
   product's measured free heap with the UI up is 29.3 MB, so a transient
   16 MiB allocation fits with room to spare, while 24 MiB would be tight.
4. p = 1 because parallelism the defender cannot use is a gift to the attacker.
   The RustCrypto crate is single-threaded on this target (no rayon), so p = 2
   would cost the same wall time here while letting an attacker with two cores
   halve theirs.
5. It is a round, standard, defensible parameter set to write into a format that
   is about to be frozen, and the cost model above lets it be re-priced on
   production silicon without a new harness.

Fallbacks if the unlock budget is later cut: m=8 MiB/t=1 = 913 ms, or
m=4 MiB/t=2 = 980 ms. If it is raised to 3 s: m=24 MiB/t=1 = 2742 ms.

## 4. M5 - scratch zeroization and PSRAM bandwidth

`memset` of the Argon2 scratch, measured on the same buffers:

| Buffer | Location | Time | Rate |
|---|---|---|---|
| 64 KiB | internal SRAM | 86 us | 762 MB/s |
| 1 MiB | PSRAM | 4.85 ms | 216 MB/s |
| 8 MiB | PSRAM | 41.25 ms | 203 MB/s |
| 16 MiB | PSRAM | 82.51 ms | 203 MB/s |
| 24 MiB | PSRAM | 123.75 ms | 203 MB/s |

**PSRAM write bandwidth is 203 MB/s** and flat with size. Zeroizing the whole
32 MiB of PSRAM would therefore take about **165 ms**; the plan's M5 item asks
for 64 MiB, which does not exist (finding A). Wiping a 16 MiB KDF scratch costs
82.5 ms, which is small enough that the design should simply always do it.

## 5. V1 / V2 - SHA-256 over flash

Two different mechanisms matter here and they do not cost the same:

| Operation | Waveshare | Elecrow | Rate |
|---|---|---|---|
| `esp_partition_get_sha256` on the running app (2,243,072 B image) | 255.6 ms | 255.7 ms | 8.78 MB/s |
| Raw `esp_flash_read` of 4 MiB, no hashing, 32 KiB chunks | 461.9 ms | 462.0 ms | 9.08 MB/s |
| Raw read + streaming SHA-256 of the same 4 MiB | 501.0 ms | 500.4 ms | 8.37 MB/s |
| SHA-256 alone over 4 MiB already in RAM | 36.6 ms | 36.1 ms | **115 MB/s** |
| Bootloader region (0x2000, 24 KiB): read + hash | 3.06 ms | 3.06 ms | - |
| Partition table (0x8000, 4 KiB): read + hash | 0.55 ms | 0.55 ms | - |

**The Verify hash is flash-read-bound, not SHA-bound.** Hashing costs 115 MB/s
against a 9.08 MB/s flash read: SHA-256 adds only 8% to the cost of reading the
same bytes. Optimizing the hash would buy nothing; the only lever is reading
fewer bytes.

`esp_partition_get_sha256` is slightly faster than our own read-and-hash loop
(8.78 vs 8.37 MB/s) because it goes through the memory-mapped cache path rather
than the SPI driver.

**Boot cost as shipped.** Applied to the current product image
(2,616,864 bytes), 8.78 MB/s predicts 298 ms - which is exactly the number
0.1.0-m4 measured on both boards, so the model is validated end to end. Adding
the two other images the Verify screen must cover:

| Verify hash at boot | Cost |
|---|---|
| App image (2,616,864 B, running partition) | 298 ms |
| Bootloader region (24 KiB) | 3.1 ms |
| Partition table (4 KiB) | 0.6 ms |
| **Total added boot time** | **~302 ms** |

Decides: the Verify screen can hash all three at every boot for about a third of
a second, so no caching, no deferral and no "hash on demand" design is needed
for these three. If the app partition is ever hashed in full (4 MB rather than
the image length) the cost becomes 462 ms.

## 6. M6 - flash part identification and the partial-page-program limit

**This is the milestone-1 exit gate: the ledger programs up to 32 cells into one
256-byte page between erases.**

### 6.1 The parts actually fitted

| | Waveshare 4B | Elecrow 5 |
|---|---|---|
| `esp_flash_read_id` | `0xC8 40 19` | `0xC8 40 18` |
| Manufacturer | 0xC8 = GigaDevice | 0xC8 = GigaDevice |
| Memory type / capacity | 0x40 / 0x19 = 32 MiB | 0x40 / 0x18 = 16 MiB |
| Part (ID + schematic) | GD25Q256E family (schematic: GD25Q256EYIGR) | GD25Q128 family (schematic said Winbond W25Q128JVSIQ) |
| `esp_flash_read_unique_chip_id` | `0x4550343733115619`, err 0 | `0x55373533320f2533`, err 0 |
| Unique ID stable over 3 reads | yes | yes |

Two things to carry forward:

- The Elecrow vendor swap recorded in `docs/research/elecrow-board.md` is
  confirmed on this unit: the fitted part is GigaDevice, not the Winbond part
  the schematic specifies. **A production build must not assume either vendor.**
- A JEDEC ID cannot name a die revision: `0xC8 40 19` is shared by the
  GD25Q256C, D and E. **The Verify screen should print the raw JEDEC ID and the
  unique ID, never a marketing part number**, because the raw ID is what the
  device actually knows.

**V3 verdict: PASS on both boards.** `esp_flash_read_unique_chip_id` returns
ESP_OK, a non-zero, plausible and repeatable 64-bit value on both fitted parts,
so the ratified Q60 flash unique-ID Verify row ships rather than rendering
`not supported`.

### 6.2 Empirical soak - what the parts actually tolerate

Per board, in the last 4 KiB sector: erase, verify blank, then program 8-byte
cells one at a time into a single 256-byte page, **reading back and comparing
the whole page after every single program**, repeated over three separate pages.
Then a deliberately harsher probe: 256 consecutive one-byte programs into one
page, again verifying the whole page after each.

| Test | Waveshare (GD25Q256E) | Elecrow (GD25Q128) |
|---|---|---|
| 32 x 8-byte cells into one page, page 1 | 32/32 verified | 32/32 verified |
| page 2 | 32/32 verified | 32/32 verified |
| page 3 | 32/32 verified | 32/32 verified |
| 256 x 1-byte programs into one page | **256/256 verified** | **256/256 verified** |
| Sector blank again after the run | yes | yes |

No divergence anywhere: every read-back matched the expected page content
exactly, including the untouched `0xff` tail, at every step. The one-byte probe
takes each part to **eight times** the format's requirement of 32 partial
programs per page, and it holds.

### 6.3 Verdict

| Board | Part | Verdict |
|---|---|---|
| Waveshare 4B | GigaDevice `0xC84019` (GD25Q256E family) | **PASS - the 32-cells-per-256-byte-page ledger layout is safe** |
| Elecrow 5 | GigaDevice `0xC84018` (GD25Q128 family) | **PASS - the 32-cells-per-256-byte-page ledger layout is safe** |

**The on-flash ledger format does not have to change.** The attempt ledger, the
boot counter (Q53) and the `policy_log` (Q5.1) can all keep 32 cells per page.

### 6.4 The datasheet half of M6 is NOT closed

MILESTONES requires both a soak and a datasheet citation. The soak is done and
is what the plan says the freeze should rest on ("datasheet numbers here are
conservative and sometimes silent, so the soak is what the format is frozen
against"). The datasheet half is **open**, honestly:

- The parts are identified and their current datasheets are identified by
  GigaDevice document number:
  - GD25Q256E: **DS-00526-GD25Q256E-Rev1.3**, dated 2026-04-09,
    https://www.gigadevice.com/product/flash/spi-nor-flash/gd25q256e
  - GD25Q128E: **DS-00480-GD25Q128E-Rev1.4**, dated 2024-09-20,
    https://www.gigadevice.com/product/flash/spi-nor-flash/gd25q128e
  - Product index: https://www.gigadevice.com/product/flash/spi-nor-flash/serial-nor-flash
  - Winbond W25Q128JV (what the Elecrow schematic specifies, in case a unit with
    that part turns up): https://www.winbond.com/hq/product/code-storage-flash-memory/serial-nor-flash/?__locale=en&partNo=W25Q128JV
- GigaDevice serves the PDFs from a document system rather than a stable public
  URL, and the PDFs could not be retrieved in this session. **No number from
  either datasheet is quoted here, because quoting one unread would be worse
  than admitting the gap.** The remaining work is to download the two documents
  above and record whether they specify a maximum partial-program count (NOP)
  per page. Note that many vendors, GigaDevice among them, are silent on this
  where Micron and Spansion parts specify NOP=8; if a citation does turn up
  below 32, the soak result above stands as the contradicting evidence and the
  conservative reading (redesign the cell layout) should win.

## 7. M4 - erase and program timing (power-loss window)

Worst observed value per operation, over three runs:

| Operation | Waveshare | Elecrow |
|---|---|---|
| Erase one 4 KiB sector | 16.4 - 17.9 ms | 14.1 - 16.3 ms |
| Program a full 256-byte page | 0.53 - 0.56 ms | 0.60 ms |
| Program one 8-byte cell (worst of 96) | 0.128 ms | 0.117 ms |
| Program one byte (worst of 256) | 1.08 ms | 0.58 ms |

The power-loss window that matters for the ledger is the **8-byte cell program
at about 0.13 ms**, three orders of magnitude below the erase. A sector erase at
up to 17.9 ms is the long pole; any design that must erase should treat 20 ms as
the interruption window.

## 8. Reserved-space scan and app image size

### 8.1 Whole-part blank scan (VERIFY.md on-demand check)

Read the entire part in 32 KiB chunks into internal RAM and compare against
`0xff`. Two implementations were measured because they answer different
questions:

| Scan | Span | Waveshare | Elecrow |
|---|---|---|---|
| Detect-only ("is it all 0xff") | 16 MiB | **1.899 s** (1.849 read + 0.048 compare) | **1.899 s** (1.849 + 0.048) |
| Detect-only | 32 MiB | **3.824 s** (3.723 + 0.096) | n/a (16 MiB part) |
| Per-byte tally of non-blank bytes | 16 MiB | 3.642 s | 2.505 s |
| Per-byte tally | 32 MiB | 6.703 s | n/a |

**Report 1.9 s at 16 MB and 3.8 s at 32 MB.** The detect-only form is
branch-free, so its cost does not depend on what the flash holds and the number
transfers to a production unit; the tally form is a diagnostic and its cost
varies with how much is non-blank (which is why the two boards differ there).
Either way the scan is flash-read-bound at 8.8 MB/s: the comparison itself is
2.5% of the time.

A user-facing scan of a 32 MB part therefore takes under four seconds, which is
fast enough to offer on demand without a progress bar, and far too slow to do at
every boot.

### 8.2 Neither dev board's flash is blank outside our partitions

The same scan reports how many bytes are not `0xff`:

| | Waveshare 4B | Elecrow 5 |
|---|---|---|
| Non-blank bytes in the first 16 MiB | 8,730,694 | 3,200,857 |
| Non-blank bytes over the whole part | 14,450,662 (32 MiB) | 3,200,857 (16 MiB) |
| Accounted for by our images (bootloader + table + 2.24 MB app) | ~2.3 MB | ~2.3 MB |

**About 12 MB of the Waveshare part and 0.9 MB of the Elecrow part is vendor
factory-image residue that our flashing procedure never erases.** See section 9,
finding D.

### 8.3 App image size, camera in versus out (Waveshare 4B, dev profile)

`espflash save-image --chip esp32p4 --flash-size 32mb` over the built ELF, which
is exactly the image `tools/flash.ps1` writes:

| Build | app.bin bytes | Delta |
|---|---|---|
| Base (today's tree, `board-waveshare-4b`) | **2,616,864** | - |
| With the camera stack linked | **3,023,152** | **+406,288 B (+396.8 KiB, +15.5%)** |
| Base, Elecrow 5 (for reference) | 2,576,320 | - |
| Measurement build (`--features measure`) | 2,243,072 | -373,792 (the harness diverts `main`, so `--gc-sections` drops the whole UI) |

What "with the camera stack" means precisely, because the number is only as good
as its definition: `espressif/esp_video` ^2.2 pulled in as an
`extra_components` entry (which also pulls `esp_cam_sensor`, `esp_ipa`,
`esp_sccb_intf` and `esp_h264`), `CONFIG_CAMERA_OV5647=y` on top of the normal
board sdkconfig pair (esp_video's own defaults already enable the MIPI-CSI, DVP
and ISP video devices), the `rqrr` 0.9.3 pure-Rust QR decoder, and a reference
call path in the image that calls `esp_video_init()`, opens `/dev/video0` and
runs an `rqrr` detect-and-decode over a grayscale plane. The call path exists
because IDF links with `--gc-sections`: a component that is compiled but never
called contributes almost nothing, so a size taken without a call site would be
a fiction. Both builds are the dev profile (`opt-level = "z"`), the profile that
actually gets flashed today; a release-profile pair was not measured.

Decides: **the camera costs about 0.4 MB of app image.** The 4 MB app partition
holds the camera build at 72% full, so the current geometry does not need to
grow for the camera, and the storage freeze does not have to reserve for it
beyond what is already there. This retires the assumption that the camera gated
the partition freeze - it was asserted against a number nobody had.

### 8.4 App image size, microSD long file names in versus out (both boards, dev profile)

Taken **2026-08-19**, on the workstation rather than on the boards: these are
sizes of the artifact, by the same method as 8.3 - `espflash save-image --chip
esp32p4 --flash-size <board>` over the built ELF, which is exactly the image
`tools/flash.ps1` writes. Everything else in this document was read off the
silicon; this subsection is host-side by nature, and the two on-hardware numbers
it is paired with are still owed (below).

The change measured is `CONFIG_FATFS_LFN_HEAP=y` plus the two pinned defaults
`CONFIG_FATFS_MAX_LFN=255` and `CONFIG_FATFS_CODEPAGE_437=y` in
`firmware/sdkconfig.base.defaults`, i.e. FatFs going from `FF_USE_LFN=0` to
`FF_USE_LFN=3`. Before the change `CONFIG_FATFS_LFN_NONE=y` (the ESP-IDF
default) was in force on every build, `sd::Card::mount` refused every card
before powering the slot, and no card had ever been addressed.

Both builds are the dev profile (`opt-level = "z"`) with the same features the
bench uses: `hil-console` on the Elecrow 5, `unsafe-emulated-key,hil-console` on
the Waveshare 4B.

| Build | app.bin bytes | Delta | Of the 4 MiB app partition |
|---|---|---|---|
| Elecrow 5, LFN off (`CONFIG_FATFS_LFN_NONE`, the shipped defect) | 3,785,856 | - | 90.3%, 408,448 B free |
| Elecrow 5, **LFN on (`CONFIG_FATFS_LFN_HEAP`)** | **3,853,344** | **+67,488 B (+65.9 KiB, +1.8%)** | **91.9%, 340,960 B free** |
| Waveshare 4B, LFN off | 3,826,288 | - | 91.2%, 368,016 B free |
| Waveshare 4B, **LFN on** | **3,893,408** | **+67,120 B (+65.5 KiB, +1.8%)** | **92.8%, 300,896 B free** |

The two boards' deltas agree to within 368 bytes, which is what you would expect
of a change that is entirely FatFs code and the CP437 tables in `ffunicode.c`:
it is the same object code on both, and the small difference is layout.

**The estimate this replaces was low by a factor of about three.** The change was
specified at "+10 to +25 KiB"; it costs 66 KiB. It still fits comfortably - the
tighter of the two boards keeps 294 KiB of the app partition free - but the
headroom figure quoted alongside that estimate (~560 KiB free, from a 3.62 MB
image) was also stale: the tree had already grown past it before this change was
made. Record the real number rather than the projection, because the app
partition is frozen at 4 MiB and 8.3's camera option (+406,288 B) is still
notionally on the table. That option no longer fits: camera on top of today's
tree with LFN on comes to 4,259,632 B on the Elecrow 5 and 4,299,696 B on the
Waveshare 4B, i.e. **65,328 B and 105,392 B PAST the 4 MiB app partition**. 8.3
concluded the camera left the geometry alone; that conclusion was true of a
2.6 MB tree and is not true of this one. LFN is not what broke it - the tree
grew 1.2 MB between the two measurements and LFN is 66 KB of that - but the
camera decision now has to be taken against a partition change.

RAM cost is zero statically. The 512-byte `(FF_MAX_LFN+1)*2` UTF-16 working
buffer that LFN needs is taken from the heap per FatFs call and freed on return
(`FF_USE_LFN=3` -> `ff_memalloc`), which is why `LFN_HEAP` was chosen over
`LFN_STACK`: `LFN_STACK` would put those 512 bytes on the main task stack, on top
of the deepest frames this firmware has (`std::fs` -> VFS -> FatFs), and the main
task stack is the one number this project has twice got wrong on hardware rather
than on paper (see `CONFIG_ESP_MAIN_TASK_STACK_SIZE` in
`firmware/sdkconfig.base.defaults`).

**Still owed, and only the bench can pay it** (the boards are not on this
machine): after a full SD flow on real hardware - mount, list, read a PSBT - read
the boot-log line `main task stack: N bytes free of M` (printed every boot from
`firmware/src/main.rs` via `store::stack_headroom()`) and record it here beside
the pre-change reading. That number is what proves the `LFN_HEAP` choice cost the
stack nothing; the sizes above prove only what it cost the image.

## 9. Findings that disprove design assumptions

### A. **64 MiB of Argon2 working memory does not exist on this hardware, and neither does 16 MiB of internal SRAM**

MILESTONES m1 states: *"Argon2id benchmark harness ... m=64 MiB in PSRAM vs
m=16 MiB in internal SRAM at several t ... All boards are P4NRW32 with 32 MB
PSRAM, so 64 MiB working memory is not the constraint; latency is."*

Measured, on both boards:

- The package has **32 MiB** of PSRAM (33,554,432 bytes), not 64 MiB of
  headroom. 64 MiB is twice the part; 128 MiB is four times it.
- The largest **single allocation** available, taken before any peripheral
  exists, is **30,932,992 bytes (29.5 MiB)**. So even m = 32768 KiB fails, and
  the measured ceiling for Argon2 memory is between 24 and 29 MiB.
- Internal SRAM cannot hold 16 MiB by three orders of magnitude: the largest
  free internal block is **253,952 bytes (248 KiB)**. The internal-versus-PSRAM
  comparison the plan wanted cannot be run above 128 KiB, and was run at
  64 and 128 KiB instead.
- **Memory is therefore a hard constraint, not a free variable**, and the
  sentence "64 MiB working memory is not the constraint" must be struck. The
  usable maximum is 24 MiB, and the recommended operating point is 16 MiB.

The good news buried in the same finding: latency is not the constraint either.
PSRAM residency costs nothing measurable (section 3), so the KDF parameter
choice is purely a wall-clock-versus-attacker-cost decision.

### B. **Neither dev board reads all-`0xff` outside our partitions, so "the reserve is blank" is not true of a board flashed the way we flash today**

`tools/flash.ps1` writes the bootloader, the partition table and the app. It
never erases the rest of the part, and both boards arrived with a vendor factory
image. Measured non-blank bytes outside our ~2.3 MB of images: about **12.1 MB
on the Waveshare part and 0.9 MB on the Elecrow part**.

This matters for three things the plan states as facts:

1. The m1 `media`/reserved partition is specified to "read all-`0xff`, its SHA256
   is a Verify row, and any non-blank content on a release unit is a finding".
   **On a unit flashed with today's procedure that row would fail on arrival.**
2. VERIFY.md's on-demand reserved-space scan would report leftovers that have
   nothing to do with notyas, on a device whose whole pitch is that it writes
   nothing to flash.
3. It is a privacy and provenance issue in its own right: unknown vendor data
   sitting in a wallet's flash.

**The release flashing recipe must erase the whole chip** (`espflash erase-flash`
or equivalent) before writing, and the pre-handover gauntlet should assert the
all-`0xff` state of everything outside the partition table rather than assume
it. This is a tooling change, not a format change.

### C. `CONFIG_APP_REPRODUCIBLE_BUILD` is not enabled today

MILESTONES m1 says "keep CONFIG_APP_REPRODUCIBLE_BUILD", which reads as though it
is already on. The generated sdkconfig for both boards says
`# CONFIG_APP_REPRODUCIBLE_BUILD is not set`. It has to be *added*, not kept.

### D. Nothing else here invalidates a design assumption

M6 passes on both boards, so the ledger format survives. The Verify screen's
boot hashing is affordable at 302 ms. The reserved-space scan is affordable at
under four seconds. The camera costs 0.4 MB, not the multi-megabyte figure that
would have forced a partition redesign.

## 10. What could not be measured, and why

**Flash encryption and PSRAM encryption were not measured, and cannot be
measured representatively on these boards.**

- On the ESP32-P4, external-memory encryption is a single eFuse decision: with
  flash encryption enabled the XTS-AES machinery also encrypts external PSRAM
  traffic (ARCH 2.3), so the Argon2id numbers above would be the ones affected.
- Both boards report `esp_flash_encryption_enabled() == false` and unburned
  eFuses. Turning it on burns eFuses - **irreversible on the unit** - and on a
  rev v1.3 engineering sample in Development mode it also consumes the limited
  re-flash count (the plan's M7 item). Neither board on this bench is
  sacrificial, and doing it without the owner's explicit decision would be a
  destructive act on hardware the project depends on.
- What can be said from the data instead, as a bound rather than a measurement:
  Argon2id at these parameters demands about 26 MB/s of PSRAM traffic against
  203 MB/s of measured bandwidth, and it is provably compute-bound (the per-MiB
  cost does not change when the working set outgrows the L2 cache). For the
  encryption to move the Argon2 number materially it would have to cut effective
  external-memory throughput by roughly 7x. The published behaviour of the P4's
  inline XTS-AES path is nowhere near that. **This is an argument, not a number**
  - the honest position is that the encryption-on measurement remains open and
  needs a sacrificial board, and the plan should say so.
- Everything else in this document is unaffected by flash encryption in the way
  that matters: the flash read rate, the SHA rate, the erase and program times
  and the partial-page behaviour are properties of the SPI part and the SPI
  driver, not of the cache-level encryption.

**Silicon revision caveat.** Every number is from **rev v1.3** pre-v3.0
engineering samples, which is all the bench has. Production units are rev v3.1+
and are a different binary target (firmware/README.md, "Chip revision config").
Clock, PSRAM part and flash part are expected to be the same, so the numbers
should carry, but the whole harness should be re-run once on production silicon
before anything irreversible depends on them.

## 11. Raw capture

Verbatim `MEAS|` lines, third run, 2026-08-18. Log tag prefixes stripped;
nothing else changed.

### Waveshare ESP32-P4-WiFi6-Touch-LCD-4B (COM3)

```
MEAS|harness|schema=1|board=Waveshare ESP32-P4-WiFi6-Touch-LCD-4B|wdt_deinit_err=0x0
MEAS|flash_size|configured_mb=32|logical_bytes=33554432|logical_err=0x0|physical_bytes=33554432|physical_err=0x0
MEAS|psram|size_bytes=33554432|free_bytes=31395344|largest_free_block_bytes=30932992
MEAS|internal_ram|free_bytes=429507|largest_free_block_bytes=253952
MEAS|chip|rev=v1.3|cpu_ticks_per_us=360|flash_encryption=false
MEAS|jedec_id|err=0x0|raw=0xc84019|manufacturer=0xc8|memory_type=0x40|capacity_code=0x19|implied_bytes=33554432
MEAS|unique_id|read=0|err=0x0|value=0x4550343733115619
MEAS|unique_id|read=1|err=0x0|value=0x4550343733115619
MEAS|unique_id|read=2|err=0x0|value=0x4550343733115619
MEAS|running_partition|offset=0x10000|size=4194304
MEAS|app_sha256|run=0|err=0x0|us=255644|digest=ce9bb0b0d2cc76bd
MEAS|app_sha256|run=1|err=0x0|us=255628|digest=ce9bb0b0d2cc76bd
MEAS|app_sha256|run=2|err=0x0|us=255625|digest=ce9bb0b0d2cc76bd
MEAS|bootloader_region|addr=0x2000|bytes=24576|total_us=3064|read_us=2737|hash_us=299|digest=97d21f374a928aa3
MEAS|partition_table|addr=0x8000|bytes=4096|total_us=556|read_us=470|hash_us=63|digest=7a09d497a03c9214
MEAS|app_partition_raw|addr=0x10000|bytes=4194304|total_us=501038|read_us=462568|hash_us=37776|digest=bac00e0034195fde
MEAS|app_partition_read_only|bytes=4194304|us=461905
MEAS|ram_hash_only|bytes=4194304|us=36576|digest=5fe4ce6c727a4d65
MEAS|blank_detect_16mb|bytes=16777216|total_us=1899425|read_us=1849003|compare_us=47945|all_blank=false
MEAS|blank_detect_full|bytes=33554432|total_us=3823939|read_us=3723024|compare_us=95903|all_blank=false
MEAS|blank_scan_16mb|bytes=16777216|total_us=3641606|read_us=1849409|compare_us=1789712|nonblank_bytes=8730694
MEAS|blank_scan_full|bytes=33554432|total_us=6702757|read_us=3724738|compare_us=2973131|nonblank_bytes=14450662
MEAS|erase_4k|addr=0x1fff000|err=0x0|us=17893
MEAS|program_256B_full_page|err=0x0|us=561
MEAS|soak_cells|page=1|addr=0x1fff100|cell_bytes=8|cells_ok=32|cells_attempted=32|worst_program_us=122
MEAS|soak_cells|page=2|addr=0x1fff200|cell_bytes=8|cells_ok=32|cells_attempted=32|worst_program_us=128
MEAS|soak_cells|page=3|addr=0x1fff300|cell_bytes=8|cells_ok=32|cells_attempted=32|worst_program_us=127
MEAS|soak_bytes|addr=0x1fff400|programs_ok=256|programs_attempted=256|worst_program_us=985
MEAS|soak_restore|erase_err=0x0|sector_blank=true
MEAS|argon2_env|crate=argon2 0.5.3|block_bytes=1024|block_align=64
MEAS|argon2|mem=internal|m_kib=64|t=1|p=1|us=11751|ms=11|zeroize_us=86|out=e491fbbd04a1138d
MEAS|argon2|mem=psram|m_kib=64|t=1|p=1|us=11610|ms=11|zeroize_us=310|out=e491fbbd04a1138d
MEAS|argon2|mem=internal|m_kib=64|t=2|p=1|us=19356|ms=19|zeroize_us=99|out=e21efbc6157a5d1f
MEAS|argon2|mem=psram|m_kib=64|t=2|p=1|us=19354|ms=19|zeroize_us=99|out=e21efbc6157a5d1f
MEAS|argon2|mem=internal|m_kib=64|t=3|p=1|us=27098|ms=27|zeroize_us=100|out=c40895931b36f017
MEAS|argon2|mem=psram|m_kib=64|t=3|p=1|us=27103|ms=27|zeroize_us=99|out=c40895931b36f017
MEAS|argon2|mem=internal|m_kib=128|t=1|p=1|us=18262|ms=18|zeroize_us=196|out=38f1c8b155f17e76
MEAS|argon2|mem=psram|m_kib=128|t=1|p=1|us=18276|ms=18|zeroize_us=414|out=38f1c8b155f17e76
MEAS|argon2|mem=internal|m_kib=128|t=2|p=1|us=33776|ms=33|zeroize_us=203|out=ec8b908415f7a64a
MEAS|argon2|mem=psram|m_kib=128|t=2|p=1|us=33803|ms=33|zeroize_us=199|out=ec8b908415f7a64a
MEAS|argon2|mem=internal|m_kib=128|t=3|p=1|us=49308|ms=49|zeroize_us=197|out=1b7ba765b8c09a86
MEAS|argon2|mem=psram|m_kib=128|t=3|p=1|us=49328|ms=49|zeroize_us=200|out=1b7ba765b8c09a86
MEAS|argon2|mem=internal|m_kib=256|t=1|p=1|alloc=FAILED|wanted_bytes=262144|largest_free_block=253952
MEAS|argon2|mem=psram|m_kib=256|t=1|p=1|us=32274|ms=32|zeroize_us=818|out=9ddebb5d80a3c544
MEAS|argon2|mem=internal|m_kib=256|t=2|p=1|alloc=FAILED|wanted_bytes=262144|largest_free_block=253952
MEAS|argon2|mem=psram|m_kib=256|t=2|p=1|us=63437|ms=63|zeroize_us=999|out=32442f3c2e1e5cda
MEAS|argon2|mem=internal|m_kib=256|t=3|p=1|alloc=FAILED|wanted_bytes=262144|largest_free_block=253952
MEAS|argon2|mem=psram|m_kib=256|t=3|p=1|us=94594|ms=94|zeroize_us=945|out=34ca7325e58c6a75
MEAS|argon2|mem=psram|m_kib=1024|t=1|p=1|us=116684|ms=116|zeroize_us=4845|out=4b361c060a04a8e3
MEAS|argon2|mem=psram|m_kib=1024|t=2|p=1|us=246316|ms=246|zeroize_us=5157|out=09c6146136764aee
MEAS|argon2|mem=psram|m_kib=1024|t=3|p=1|us=376007|ms=376|zeroize_us=5138|out=596be31236c657a2
MEAS|argon2|mem=psram|m_kib=4096|t=1|p=1|us=457317|ms=457|zeroize_us=20620|out=5c8e2f48a2671f53
MEAS|argon2|mem=psram|m_kib=4096|t=2|p=1|us=980379|ms=980|zeroize_us=20617|out=46709414bf307921
MEAS|argon2|mem=psram|m_kib=4096|t=3|p=1|us=1503248|ms=1503|zeroize_us=20619|out=0a5b8d2f7e9bd828
MEAS|argon2|mem=psram|m_kib=8192|t=1|p=1|us=913320|ms=913|zeroize_us=41250|out=4166f97e9f713f5b
MEAS|argon2|mem=psram|m_kib=8192|t=2|p=1|us=1961484|ms=1961|zeroize_us=41245|out=65b9fafc4bb96b61
MEAS|argon2|mem=psram|m_kib=8192|t=3|p=1|us=3009785|ms=3009|zeroize_us=41260|out=e14bbcc453ab7b5e
MEAS|argon2|mem=psram|m_kib=16384|t=1|p=1|us=1827253|ms=1827|zeroize_us=82515|out=ee33f1d46d1115bb
MEAS|argon2|mem=psram|m_kib=16384|t=2|p=1|us=3927547|ms=3927|zeroize_us=82500|out=3e610c0e14b7404b
MEAS|argon2|mem=psram|m_kib=16384|t=3|p=1|us=6027560|ms=6027|zeroize_us=82510|out=cfc67b7441007ddf
MEAS|argon2|mem=psram|m_kib=24576|t=1|p=1|us=2742056|ms=2742|zeroize_us=123764|out=144ca64b43bef19e
MEAS|argon2|mem=psram|m_kib=24576|t=2|p=1|us=5895025|ms=5895|zeroize_us=123744|out=69cceab50efc3e88
MEAS|argon2|mem=psram|m_kib=24576|t=3|p=1|us=9046108|ms=9046|zeroize_us=123747|out=566c9217e415f089
MEAS|argon2|mem=psram|m_kib=32768|t=1|p=1|alloc=FAILED|wanted_bytes=33554432|largest_free_block=30932992
MEAS|argon2|mem=psram|m_kib=65536|t=1|p=1|alloc=FAILED|wanted_bytes=67108864|largest_free_block=30932992
MEAS|argon2|mem=psram|m_kib=131072|t=1|p=1|alloc=FAILED|wanted_bytes=134217728|largest_free_block=30932992
MEAS|done
```

### Elecrow CrowPanel Advanced 5inch ESP32-P4 (COM6)

```
MEAS|harness|schema=1|board=Elecrow CrowPanel Advanced 5inch ESP32-P4|wdt_deinit_err=0x0
MEAS|flash_size|configured_mb=16|logical_bytes=16777216|logical_err=0x0|physical_bytes=16777216|physical_err=0x0
MEAS|psram|size_bytes=33554432|free_bytes=31395216|largest_free_block_bytes=30932992
MEAS|internal_ram|free_bytes=429507|largest_free_block_bytes=253952
MEAS|chip|rev=v1.3|cpu_ticks_per_us=360|flash_encryption=false
MEAS|jedec_id|err=0x0|raw=0xc84018|manufacturer=0xc8|memory_type=0x40|capacity_code=0x18|implied_bytes=16777216
MEAS|unique_id|read=0|err=0x0|value=0x55373533320f2533
MEAS|unique_id|read=1|err=0x0|value=0x55373533320f2533
MEAS|unique_id|read=2|err=0x0|value=0x55373533320f2533
MEAS|running_partition|offset=0x10000|size=4194304
MEAS|app_sha256|run=0|err=0x0|us=255656|digest=f7ab7dbc995482e0
MEAS|app_sha256|run=1|err=0x0|us=255638|digest=f7ab7dbc995482e0
MEAS|app_sha256|run=2|err=0x0|us=255641|digest=f7ab7dbc995482e0
MEAS|bootloader_region|addr=0x2000|bytes=24576|total_us=3062|read_us=2728|hash_us=306|digest=47e57258da0098c8
MEAS|partition_table|addr=0x8000|bytes=4096|total_us=550|read_us=465|hash_us=63|digest=7a09d497a03c9214
MEAS|app_partition_raw|addr=0x10000|bytes=4194304|total_us=500438|read_us=462216|hash_us=37576|digest=a9c27929359dad86
MEAS|app_partition_read_only|bytes=4194304|us=461966
MEAS|ram_hash_only|bytes=4194304|us=36146|digest=cd3517473707d59c
MEAS|blank_detect_16mb|bytes=16777216|total_us=1899313|read_us=1848992|compare_us=47908|all_blank=false
MEAS|blank_scan_16mb|bytes=16777216|total_us=2504844|read_us=1849655|compare_us=652737|nonblank_bytes=3200857
MEAS|erase_4k|addr=0xfff000|err=0x0|us=16295
MEAS|program_256B_full_page|err=0x0|us=603
MEAS|soak_cells|page=1|addr=0xfff100|cell_bytes=8|cells_ok=32|cells_attempted=32|worst_program_us=116
MEAS|soak_cells|page=2|addr=0xfff200|cell_bytes=8|cells_ok=32|cells_attempted=32|worst_program_us=117
MEAS|soak_cells|page=3|addr=0xfff300|cell_bytes=8|cells_ok=32|cells_attempted=32|worst_program_us=114
MEAS|soak_bytes|addr=0xfff400|programs_ok=256|programs_attempted=256|worst_program_us=479
MEAS|soak_restore|erase_err=0x0|sector_blank=true
MEAS|argon2_env|crate=argon2 0.5.3|block_bytes=1024|block_align=64
MEAS|argon2|mem=internal|m_kib=64|t=1|p=1|us=11755|ms=11|zeroize_us=86|out=e491fbbd04a1138d
MEAS|argon2|mem=psram|m_kib=64|t=1|p=1|us=11605|ms=11|zeroize_us=321|out=e491fbbd04a1138d
MEAS|argon2|mem=internal|m_kib=64|t=2|p=1|us=19352|ms=19|zeroize_us=100|out=e21efbc6157a5d1f
MEAS|argon2|mem=psram|m_kib=64|t=2|p=1|us=19353|ms=19|zeroize_us=99|out=e21efbc6157a5d1f
MEAS|argon2|mem=internal|m_kib=64|t=3|p=1|us=27089|ms=27|zeroize_us=99|out=c40895931b36f017
MEAS|argon2|mem=psram|m_kib=64|t=3|p=1|us=27088|ms=27|zeroize_us=99|out=c40895931b36f017
MEAS|argon2|mem=internal|m_kib=128|t=1|p=1|us=18258|ms=18|zeroize_us=195|out=38f1c8b155f17e76
MEAS|argon2|mem=psram|m_kib=128|t=1|p=1|us=18260|ms=18|zeroize_us=418|out=38f1c8b155f17e76
MEAS|argon2|mem=internal|m_kib=128|t=2|p=1|us=33757|ms=33|zeroize_us=203|out=ec8b908415f7a64a
MEAS|argon2|mem=psram|m_kib=128|t=2|p=1|us=33770|ms=33|zeroize_us=197|out=ec8b908415f7a64a
MEAS|argon2|mem=internal|m_kib=128|t=3|p=1|us=49277|ms=49|zeroize_us=196|out=1b7ba765b8c09a86
MEAS|argon2|mem=psram|m_kib=128|t=3|p=1|us=49277|ms=49|zeroize_us=198|out=1b7ba765b8c09a86
MEAS|argon2|mem=internal|m_kib=256|t=1|p=1|alloc=FAILED|wanted_bytes=262144|largest_free_block=253952
MEAS|argon2|mem=psram|m_kib=256|t=1|p=1|us=32223|ms=32|zeroize_us=829|out=9ddebb5d80a3c544
MEAS|argon2|mem=internal|m_kib=256|t=2|p=1|alloc=FAILED|wanted_bytes=262144|largest_free_block=253952
MEAS|argon2|mem=psram|m_kib=256|t=2|p=1|us=63333|ms=63|zeroize_us=976|out=32442f3c2e1e5cda
MEAS|argon2|mem=internal|m_kib=256|t=3|p=1|alloc=FAILED|wanted_bytes=262144|largest_free_block=253952
MEAS|argon2|mem=psram|m_kib=256|t=3|p=1|us=94461|ms=94|zeroize_us=948|out=34ca7325e58c6a75
MEAS|argon2|mem=psram|m_kib=1024|t=1|p=1|us=116508|ms=116|zeroize_us=4831|out=4b361c060a04a8e3
MEAS|argon2|mem=psram|m_kib=1024|t=2|p=1|us=245980|ms=245|zeroize_us=5152|out=09c6146136764aee
MEAS|argon2|mem=psram|m_kib=1024|t=3|p=1|us=375553|ms=375|zeroize_us=5141|out=596be31236c657a2
MEAS|argon2|mem=psram|m_kib=4096|t=1|p=1|us=456672|ms=456|zeroize_us=20614|out=5c8e2f48a2671f53
MEAS|argon2|mem=psram|m_kib=4096|t=2|p=1|us=979179|ms=979|zeroize_us=20620|out=46709414bf307921
MEAS|argon2|mem=psram|m_kib=4096|t=3|p=1|us=1501666|ms=1501|zeroize_us=20620|out=0a5b8d2f7e9bd828
MEAS|argon2|mem=psram|m_kib=8192|t=1|p=1|us=911961|ms=911|zeroize_us=41245|out=4166f97e9f713f5b
MEAS|argon2|mem=psram|m_kib=8192|t=2|p=1|us=1959173|ms=1959|zeroize_us=41246|out=65b9fafc4bb96b61
MEAS|argon2|mem=psram|m_kib=8192|t=3|p=1|us=3006582|ms=3006|zeroize_us=41256|out=e14bbcc453ab7b5e
MEAS|argon2|mem=psram|m_kib=16384|t=1|p=1|us=1824744|ms=1824|zeroize_us=82508|out=ee33f1d46d1115bb
MEAS|argon2|mem=psram|m_kib=16384|t=2|p=1|us=3922831|ms=3922|zeroize_us=82499|out=3e610c0e14b7404b
MEAS|argon2|mem=psram|m_kib=16384|t=3|p=1|us=6020592|ms=6020|zeroize_us=82508|out=cfc67b7441007ddf
MEAS|argon2|mem=psram|m_kib=24576|t=1|p=1|us=2737972|ms=2737|zeroize_us=123743|out=144ca64b43bef19e
MEAS|argon2|mem=psram|m_kib=24576|t=2|p=1|us=5887633|ms=5887|zeroize_us=123734|out=69cceab50efc3e88
MEAS|argon2|mem=psram|m_kib=24576|t=3|p=1|us=9036834|ms=9036|zeroize_us=123748|out=566c9217e415f089
MEAS|argon2|mem=psram|m_kib=32768|t=1|p=1|alloc=FAILED|wanted_bytes=33554432|largest_free_block=30932992
MEAS|argon2|mem=psram|m_kib=65536|t=1|p=1|alloc=FAILED|wanted_bytes=67108864|largest_free_block=30932992
MEAS|argon2|mem=psram|m_kib=131072|t=1|p=1|alloc=FAILED|wanted_bytes=134217728|largest_free_block=30932992
MEAS|done
```

## 12. State of the tree after this session

- `firmware/src/measure.rs` is committed behind the `measure` cargo feature,
  which nothing else enables. With the feature off the module is not compiled
  and `argon2` is not in the dependency graph.
- Proven, not asserted: the app image built from this tree with the feature off
  was diffed byte for byte against an image built from the pristine parent
  commit in the same target directory. Same size (2,616,864 bytes both), and the
  only differing bytes are the 32-byte ELF SHA-256 inside the app descriptor,
  the 33-byte image checksum, and 29 single bytes that are line numbers inside
  `core::panic::Location` records for `main.rs` (the file gained lines). No code
  difference.
- The camera-size measurement was a working-tree-only patch (an
  `extra_components` entry for `esp_video`, a temporary sdkconfig overlay, a
  `camera` feature, `rqrr`, and `firmware/src/camera.rs`). It is fully reverted;
  `Cargo.lock` no longer names `rqrr`, `g2p`, `g2gen`, `g2poly` or `lru`.
- Both boards were reflashed with the ordinary product image and verified
  running 0.1.0-m4 normally.
