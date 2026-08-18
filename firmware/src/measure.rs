//! Temporary hardware-measurement harness for the 0.2.0 m1 storage freeze.
//!
//! Compiled ONLY with `--features measure` (off by default, no other feature
//! enables it) and entered from `main` before any peripheral comes up, so the
//! PSRAM heap is at its largest and nothing else is competing for the flash
//! bus. It never returns: a measurement image is not a product image, and it
//! must not be mistaken for one on the bench.
//!
//! Every result is emitted as one `MEAS|key=value|...` line so a capture can be
//! parsed mechanically instead of eyeballed. Times are microseconds unless the
//! key says otherwise. What the numbers decide is recorded in
//! docs/plan-0.2.0/MEASUREMENTS.md - this file only produces them.
//!
//! Flash writes: the only thing written is the LAST 4 KiB sector of the part
//! (the M6 partial-page soak), which lies far past the 4 MB app partition and
//! outside every entry of firmware/partitions.csv. The sector is erased before
//! the soak and erased again after it, with the all-`0xff` state verified by
//! read-back both times, so a measurement run leaves the part exactly as blank
//! as it found it (SECURITY.md invariant 2 holds for the product image, which
//! never contains this module at all).

use std::ffi::c_void;
use std::thread;
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use esp_idf_svc::sys;

use crate::board;

/// Chunk size for every raw flash read. Internal DMA-capable RAM: `esp_flash_read`
/// into PSRAM either fails or falls back to a bounce buffer, which would measure
/// the bounce buffer instead of the flash.
const CHUNK: usize = 32 * 1024;
/// SPI NOR program page. The ledger format's unit (ESP-SEAL.md 5).
const PAGE: usize = 256;
const SECTOR: usize = 4096;

/// Fixed KDF inputs. A PIN-shaped password and a 16-byte salt: the parameters
/// are what is under test, not the input lengths, but they are pinned so the
/// numbers are reproducible.
const PWD: &[u8] = b"123456";
const SALT: &[u8] = b"notyas-measure16";

pub fn run() -> ! {
    // The task watchdog watches the idle task; a single Argon2id call at
    // m=16 MiB blocks this task for tens of seconds and would otherwise print a
    // WDT backtrace into the middle of the capture. The product image keeps the
    // WDT - this module is never in it.
    let err = unsafe { sys::esp_task_wdt_deinit() };
    log::info!("MEAS|harness|schema=1|board={}|wdt_deinit_err=0x{err:x}", board::BOARD_NAME);

    environment();
    flash_identity();
    sha256_throughput();
    blank_scan();
    program_soak();
    argon2_grid();

    log::info!("MEAS|done");
    loop {
        log::info!("MEAS|parked (measurement image - reflash a product build to use the device)");
        thread::sleep(Duration::from_secs(10));
    }
}

// --- environment -------------------------------------------------------------

fn environment() {
    unsafe {
        let mut logical: u32 = 0;
        let mut physical: u32 = 0;
        let e1 = sys::esp_flash_get_size(core::ptr::null_mut(), &mut logical);
        let e2 = sys::esp_flash_get_physical_size(core::ptr::null_mut(), &mut physical);
        log::info!(
            "MEAS|flash_size|configured_mb={}|logical_bytes={logical}|logical_err=0x{e1:x}|physical_bytes={physical}|physical_err=0x{e2:x}",
            board::FLASH_SIZE_MB
        );
        log::info!(
            "MEAS|psram|size_bytes={}|free_bytes={}|largest_free_block_bytes={}",
            sys::esp_psram_get_size(),
            sys::heap_caps_get_free_size(sys::MALLOC_CAP_SPIRAM),
            sys::heap_caps_get_largest_free_block(sys::MALLOC_CAP_SPIRAM)
        );
        log::info!(
            "MEAS|internal_ram|free_bytes={}|largest_free_block_bytes={}",
            sys::heap_caps_get_free_size(sys::MALLOC_CAP_INTERNAL),
            sys::heap_caps_get_largest_free_block(sys::MALLOC_CAP_INTERNAL)
        );
        let rev = sys::efuse_hal_chip_revision();
        log::info!(
            "MEAS|chip|rev=v{}.{}|cpu_ticks_per_us={}|flash_encryption={}",
            rev / 100,
            rev % 100,
            sys::esp_rom_get_cpu_ticks_per_us(),
            sys::esp_flash_encryption_enabled()
        );
    }
}

// --- M6 part identification / V3 unique id ------------------------------------

fn flash_identity() {
    unsafe {
        let mut id: u32 = 0;
        let err = sys::esp_flash_read_id(core::ptr::null_mut(), &mut id);
        log::info!(
            "MEAS|jedec_id|err=0x{err:x}|raw=0x{id:06x}|manufacturer=0x{:02x}|memory_type=0x{:02x}|capacity_code=0x{:02x}|implied_bytes={}",
            (id >> 16) & 0xff,
            (id >> 8) & 0xff,
            id & 0xff,
            1u64 << (id & 0xff)
        );
        // V3: read three times - the row only ships if the value is non-zero and stable.
        for i in 0..3 {
            let mut uid: u64 = 0;
            let err = sys::esp_flash_read_unique_chip_id(core::ptr::null_mut(), &mut uid);
            log::info!("MEAS|unique_id|read={i}|err=0x{err:x}|value=0x{uid:016x}");
        }
    }
}

// --- V1 / V2 SHA-256 over flash ----------------------------------------------

fn sha256_throughput() {
    // The Verify screen's own call, three times: it re-hashes on every call
    // (no cache), so this is the boot cost as shipped.
    unsafe {
        let part = sys::esp_ota_get_running_partition();
        if part.is_null() {
            log::warn!("MEAS|app_sha256|err=no_running_partition");
        } else {
            log::info!(
                "MEAS|running_partition|offset=0x{:x}|size={}",
                (*part).address,
                (*part).size
            );
            for i in 0..3 {
                let mut digest = [0u8; 32];
                let t0 = Instant::now();
                let err = sys::esp_partition_get_sha256(part, digest.as_mut_ptr());
                let us = t0.elapsed().as_micros();
                log::info!(
                    "MEAS|app_sha256|run={i}|err=0x{err:x}|us={us}|digest={}",
                    hex8(&digest)
                );
            }
        }
    }

    let buf = alloc_internal(CHUNK);
    if buf.is_null() {
        log::warn!("MEAS|sha256_raw|err=chunk_alloc_failed");
        return;
    }

    // Bootloader (0x2000..0x8000 on P4) and partition table (0x8000, 3 KiB):
    // the other two images the Verify screen hashes at boot.
    read_hash("bootloader_region", 0x2000, 0x6000, buf);
    read_hash("partition_table", 0x8000, 0x1000, buf);
    // A large span: the whole 4 MB app partition, read raw and hashed.
    read_hash("app_partition_raw", 0x10000, 4 * 1024 * 1024, buf);
    // Read with no hashing at all, same span - separates flash-read cost from
    // SHA cost, which is what decides whether the Verify scan is IO- or CPU-bound.
    read_only("app_partition_read_only", 0x10000, 4 * 1024 * 1024, buf);
    // Hash with no flash reads at all, same byte count, from the same buffer.
    hash_only("ram_hash_only", 4 * 1024 * 1024, buf);

    unsafe { sys::heap_caps_free(buf as *mut c_void) };
}

/// Raw read + streaming SHA-256 over `len` bytes at `addr`, reporting the read
/// and hash halves separately.
fn read_hash(label: &str, addr: u32, len: u32, buf: *mut u8) {
    let mut ctx: sys::mbedtls_sha256_context = unsafe { core::mem::zeroed() };
    let mut digest = [0u8; 32];
    let mut read_us: u128 = 0;
    let mut hash_us: u128 = 0;
    let t_all = Instant::now();
    unsafe {
        sys::mbedtls_sha256_init(&mut ctx);
        sys::mbedtls_sha256_starts(&mut ctx, 0);
        let mut off = 0u32;
        while off < len {
            let n = core::cmp::min(CHUNK as u32, len - off);
            let t0 = Instant::now();
            let err = sys::esp_flash_read(core::ptr::null_mut(), buf as *mut c_void, addr + off, n);
            read_us += t0.elapsed().as_micros();
            if err != sys::ESP_OK {
                log::warn!("MEAS|{label}|err=0x{err:x}|at=0x{:x}", addr + off);
                sys::mbedtls_sha256_free(&mut ctx);
                return;
            }
            let t1 = Instant::now();
            sys::mbedtls_sha256_update(&mut ctx, buf, n as usize);
            hash_us += t1.elapsed().as_micros();
            off += n;
        }
        sys::mbedtls_sha256_finish(&mut ctx, digest.as_mut_ptr());
        sys::mbedtls_sha256_free(&mut ctx);
    }
    log::info!(
        "MEAS|{label}|addr=0x{addr:x}|bytes={len}|total_us={}|read_us={read_us}|hash_us={hash_us}|digest={}",
        t_all.elapsed().as_micros(),
        hex8(&digest)
    );
}

fn read_only(label: &str, addr: u32, len: u32, buf: *mut u8) {
    let t0 = Instant::now();
    let mut off = 0u32;
    while off < len {
        let n = core::cmp::min(CHUNK as u32, len - off);
        let err = unsafe {
            sys::esp_flash_read(core::ptr::null_mut(), buf as *mut c_void, addr + off, n)
        };
        if err != sys::ESP_OK {
            log::warn!("MEAS|{label}|err=0x{err:x}");
            return;
        }
        off += n;
    }
    log::info!("MEAS|{label}|bytes={len}|us={}", t0.elapsed().as_micros());
}

fn hash_only(label: &str, len: u32, buf: *mut u8) {
    let mut ctx: sys::mbedtls_sha256_context = unsafe { core::mem::zeroed() };
    let mut digest = [0u8; 32];
    let t0 = Instant::now();
    unsafe {
        sys::mbedtls_sha256_init(&mut ctx);
        sys::mbedtls_sha256_starts(&mut ctx, 0);
        let mut off = 0u32;
        while off < len {
            let n = core::cmp::min(CHUNK as u32, len - off);
            sys::mbedtls_sha256_update(&mut ctx, buf, n as usize);
            off += n;
        }
        sys::mbedtls_sha256_finish(&mut ctx, digest.as_mut_ptr());
        sys::mbedtls_sha256_free(&mut ctx);
    }
    log::info!("MEAS|{label}|bytes={len}|us={}|digest={}", t0.elapsed().as_micros(), hex8(&digest));
}

// --- reserved-space scan (VERIFY.md on-demand blank check) --------------------

fn blank_scan() {
    let buf = alloc_internal(CHUNK);
    if buf.is_null() {
        log::warn!("MEAS|blank_scan|err=chunk_alloc_failed");
        return;
    }
    let chip_bytes = (board::FLASH_SIZE_MB as u32) * 1024 * 1024;
    // Detect-only first: that is what VERIFY.md's on-demand check actually asks
    // ("is the reserve still blank"), and its cost does not depend on the
    // content, so the number transfers to a production unit.
    scan_detect("blank_detect_16mb", 0, 16 * 1024 * 1024, buf);
    if chip_bytes > 16 * 1024 * 1024 {
        scan_detect("blank_detect_full", 0, chip_bytes, buf);
    }
    // Then the same span with a per-byte tally of what is NOT blank - the
    // diagnostic form, and the upper bound on the compare half.
    scan_span("blank_scan_16mb", 0, 16 * 1024 * 1024, buf);
    if chip_bytes > 16 * 1024 * 1024 {
        scan_span("blank_scan_full", 0, chip_bytes, buf);
    }
    unsafe { sys::heap_caps_free(buf as *mut c_void) };
}

/// "Is this whole span still 0xff?" - the branch-free form: AND every word into
/// an accumulator, which costs the same whatever the flash holds, so the number
/// is not an artifact of this particular dev board's leftovers.
fn scan_detect(label: &str, addr: u32, len: u32, buf: *mut u8) {
    let mut acc = 0xffff_ffffu32;
    let mut read_us: u128 = 0;
    let mut cmp_us: u128 = 0;
    let t_all = Instant::now();
    let mut off = 0u32;
    while off < len {
        let n = core::cmp::min(CHUNK as u32, len - off);
        let t0 = Instant::now();
        let err = unsafe {
            sys::esp_flash_read(core::ptr::null_mut(), buf as *mut c_void, addr + off, n)
        };
        read_us += t0.elapsed().as_micros();
        if err != sys::ESP_OK {
            log::warn!("MEAS|{label}|err=0x{err:x}|at=0x{:x}", addr + off);
            return;
        }
        let t1 = Instant::now();
        let words = unsafe { core::slice::from_raw_parts(buf as *const u32, n as usize / 4) };
        for w in words {
            acc &= *w;
        }
        cmp_us += t1.elapsed().as_micros();
        off += n;
    }
    log::info!(
        "MEAS|{label}|bytes={len}|total_us={}|read_us={read_us}|compare_us={cmp_us}|all_blank={}",
        t_all.elapsed().as_micros(),
        acc == 0xffff_ffff
    );
}

/// Read `len` bytes and compare every one against 0xff, word at a time. Reports
/// the non-blank byte count so the scan is provably doing the comparison.
fn scan_span(label: &str, addr: u32, len: u32, buf: *mut u8) {
    let mut nonblank: u64 = 0;
    let mut read_us: u128 = 0;
    let mut cmp_us: u128 = 0;
    let t_all = Instant::now();
    let mut off = 0u32;
    while off < len {
        let n = core::cmp::min(CHUNK as u32, len - off);
        let t0 = Instant::now();
        let err = unsafe {
            sys::esp_flash_read(core::ptr::null_mut(), buf as *mut c_void, addr + off, n)
        };
        read_us += t0.elapsed().as_micros();
        if err != sys::ESP_OK {
            log::warn!("MEAS|{label}|err=0x{err:x}|at=0x{:x}", addr + off);
            return;
        }
        let t1 = Instant::now();
        let words = unsafe { core::slice::from_raw_parts(buf as *const u32, n as usize / 4) };
        for w in words {
            if *w != 0xffff_ffff {
                nonblank += (4 - (w.to_le_bytes().iter().filter(|b| **b == 0xff).count())) as u64;
            }
        }
        cmp_us += t1.elapsed().as_micros();
        off += n;
    }
    log::info!(
        "MEAS|{label}|bytes={len}|total_us={}|read_us={read_us}|compare_us={cmp_us}|nonblank_bytes={nonblank}",
        t_all.elapsed().as_micros()
    );
}

// --- M4 / M6 program timing and partial-page soak -----------------------------

fn program_soak() {
    // The last sector of the part: past every partition (the table ends at
    // 0x410000) and blank on a device that has only ever been flashed by
    // tools/flash.ps1. Left erased when this returns.
    let chip_bytes = (board::FLASH_SIZE_MB as u32) * 1024 * 1024;
    let sector = chip_bytes - SECTOR as u32;
    let buf = alloc_internal(SECTOR);
    let src = alloc_internal(PAGE);
    if buf.is_null() || src.is_null() {
        log::warn!("MEAS|soak|err=alloc_failed");
        return;
    }
    let read_page = |addr: u32, into: *mut u8, n: usize| -> bool {
        let err =
            unsafe { sys::esp_flash_read(core::ptr::null_mut(), into as *mut c_void, addr, n as u32) };
        if err != sys::ESP_OK {
            log::warn!("MEAS|soak|read_err=0x{err:x}|addr=0x{addr:x}");
            return false;
        }
        true
    };
    let all_ff = |p: *const u8, n: usize| -> bool {
        unsafe { core::slice::from_raw_parts(p, n).iter().all(|b| *b == 0xff) }
    };

    // M4: erase time for one 4 KiB sector.
    let t0 = Instant::now();
    let err = unsafe { sys::esp_flash_erase_region(core::ptr::null_mut(), sector, SECTOR as u32) };
    let erase_us = t0.elapsed().as_micros();
    log::info!("MEAS|erase_4k|addr=0x{sector:x}|err=0x{err:x}|us={erase_us}");
    if err != sys::ESP_OK {
        log::warn!("MEAS|soak|abandoned=erase_failed");
        return;
    }
    if !read_page(sector, buf, SECTOR) || !all_ff(buf, SECTOR) {
        log::warn!("MEAS|soak|abandoned=sector_not_blank_after_erase");
        return;
    }

    // M4: one full 256-byte page program, for the power-loss window.
    unsafe { core::ptr::write_bytes(src, 0x5a, PAGE) };
    let t0 = Instant::now();
    let err = unsafe {
        sys::esp_flash_write(core::ptr::null_mut(), src as *const c_void, sector, PAGE as u32)
    };
    let prog_us = t0.elapsed().as_micros();
    log::info!("MEAS|program_256B_full_page|err=0x{err:x}|us={prog_us}");

    // M6, the format gate: 32 x 8-byte cells programmed one at a time into a
    // single 256-byte page, verifying the WHOLE page after every program. Run
    // on three separate pages. The pattern is per-cell distinct so a page-level
    // corruption cannot be mistaken for a pass.
    for page_idx in 1..4u32 {
        let page_addr = sector + page_idx * PAGE as u32;
        let mut expect = [0xffu8; PAGE];
        let mut worst_us: u128 = 0;
        let mut ok_cells = 0u32;
        for cell in 0..32usize {
            let cell_addr = page_addr + (cell * 8) as u32;
            let payload: [u8; 8] = [
                0xc0,
                0xde,
                page_idx as u8,
                cell as u8,
                (cell as u8) ^ 0xff,
                0x11,
                0x22,
                0x33,
            ];
            let t0 = Instant::now();
            let err = unsafe {
                sys::esp_flash_write(
                    core::ptr::null_mut(),
                    payload.as_ptr() as *const c_void,
                    cell_addr,
                    8,
                )
            };
            let us = t0.elapsed().as_micros();
            worst_us = worst_us.max(us);
            if err != sys::ESP_OK {
                log::warn!("MEAS|soak_cells|page={page_idx}|cell={cell}|write_err=0x{err:x}");
                break;
            }
            expect[cell * 8..cell * 8 + 8].copy_from_slice(&payload);
            if !read_page(page_addr, buf, PAGE) {
                break;
            }
            let got = unsafe { core::slice::from_raw_parts(buf as *const u8, PAGE) };
            if got != expect {
                let first = got.iter().zip(expect.iter()).position(|(a, b)| a != b).unwrap_or(0);
                log::warn!(
                    "MEAS|soak_cells|page={page_idx}|DIVERGED_AT_CELL={cell}|first_bad_byte={first}|got=0x{:02x}|want=0x{:02x}",
                    got[first],
                    expect[first]
                );
                break;
            }
            ok_cells += 1;
        }
        log::info!(
            "MEAS|soak_cells|page={page_idx}|addr=0x{page_addr:x}|cell_bytes=8|cells_ok={ok_cells}|cells_attempted=32|worst_program_us={worst_us}"
        );
    }

    // Far past the format's requirement: 256 single-byte programs into ONE page,
    // each clearing bits in a byte that is still 0xff, verifying the whole page
    // after every one. If a part's internal page latch tolerated only a handful
    // of partial programs this is where it shows.
    let page_addr = sector + 4 * PAGE as u32;
    let mut expect = [0xffu8; PAGE];
    let mut ok = 0u32;
    let mut worst_us: u128 = 0;
    for i in 0..PAGE {
        let byte = [(i as u8) ^ 0xa5];
        let t0 = Instant::now();
        let err = unsafe {
            sys::esp_flash_write(
                core::ptr::null_mut(),
                byte.as_ptr() as *const c_void,
                page_addr + i as u32,
                1,
            )
        };
        worst_us = worst_us.max(t0.elapsed().as_micros());
        if err != sys::ESP_OK {
            log::warn!("MEAS|soak_bytes|i={i}|write_err=0x{err:x}");
            break;
        }
        expect[i] = byte[0];
        if !read_page(page_addr, buf, PAGE) {
            break;
        }
        let got = unsafe { core::slice::from_raw_parts(buf as *const u8, PAGE) };
        if got != expect {
            let first = got.iter().zip(expect.iter()).position(|(a, b)| a != b).unwrap_or(0);
            log::warn!("MEAS|soak_bytes|DIVERGED_AT_PROGRAM={i}|first_bad_byte={first}");
            break;
        }
        ok += 1;
    }
    log::info!(
        "MEAS|soak_bytes|addr=0x{page_addr:x}|programs_ok={ok}|programs_attempted={PAGE}|worst_program_us={worst_us}"
    );

    // Leave the part as we found it: erase and prove blank.
    let err = unsafe { sys::esp_flash_erase_region(core::ptr::null_mut(), sector, SECTOR as u32) };
    let blank = read_page(sector, buf, SECTOR) && all_ff(buf, SECTOR);
    log::info!("MEAS|soak_restore|erase_err=0x{err:x}|sector_blank={blank}");

    unsafe {
        sys::heap_caps_free(buf as *mut c_void);
        sys::heap_caps_free(src as *mut c_void);
    }
}

// --- M1 Argon2id cost curve ---------------------------------------------------

fn argon2_grid() {
    assert_eq!(core::mem::size_of::<Block>(), 1024, "argon2 block is not 1 KiB");
    log::info!(
        "MEAS|argon2_env|crate=argon2 0.5.3|block_bytes={}|block_align={}",
        core::mem::size_of::<Block>(),
        core::mem::align_of::<Block>()
    );

    // Internal SRAM vs PSRAM at identical parameters: the ratio IS the PSRAM
    // bandwidth penalty on this workload (Argon2 is a random-access memory
    // benchmark with a little BLAKE2b on top).
    for m_kib in [64u32, 128, 256] {
        for t in 1..=3u32 {
            argon2_case(m_kib, t, sys::MALLOC_CAP_INTERNAL | sys::MALLOC_CAP_8BIT, "internal");
            argon2_case(m_kib, t, sys::MALLOC_CAP_SPIRAM | sys::MALLOC_CAP_8BIT, "psram");
        }
    }

    // The real grid, PSRAM-backed. The last three entries are expected to be
    // unallocatable on a 32 MB part - that is a result, not a failure, and the
    // log says which.
    for m_kib in [1024u32, 4096, 8192, 16384, 24576, 32768, 65536, 131072] {
        for t in 1..=3u32 {
            if !argon2_case(m_kib, t, sys::MALLOC_CAP_SPIRAM | sys::MALLOC_CAP_8BIT, "psram") {
                break; // allocation failed: the other t values cannot run either
            }
        }
    }
}

/// One Argon2id point. Returns false only when the scratch could not be
/// allocated (the interesting failure), true otherwise.
fn argon2_case(m_kib: u32, t: u32, caps: u32, mem: &str) -> bool {
    let blocks = m_kib as usize;
    let bytes = blocks * 1024;
    // heap_caps_malloc only guarantees 8-byte alignment; argon2's Block is
    // over-aligned (SIMD-friendly), and building a &mut [Block] over a
    // less-aligned pointer is UB (a debug build catches it with a panic).
    let align = core::mem::align_of::<Block>();
    let p = unsafe { sys::heap_caps_aligned_alloc(align, bytes, caps) } as *mut u8;
    if p.is_null() {
        log::warn!(
            "MEAS|argon2|mem={mem}|m_kib={m_kib}|t={t}|p=1|alloc=FAILED|wanted_bytes={bytes}|largest_free_block={}",
            unsafe { sys::heap_caps_get_largest_free_block(caps) }
        );
        return false;
    }
    // Zeroing the scratch is both required (a &mut [Block] over uninitialized
    // memory is not sound) and a measurement: this is the M5 zeroization rate.
    let t0 = Instant::now();
    unsafe { core::ptr::write_bytes(p, 0, bytes) };
    let zero_us = t0.elapsed().as_micros();

    let scratch: &mut [Block] = unsafe { core::slice::from_raw_parts_mut(p as *mut Block, blocks) };
    let params = match Params::new(m_kib, t, 1, Some(32)) {
        Ok(params) => params,
        Err(e) => {
            log::warn!("MEAS|argon2|mem={mem}|m_kib={m_kib}|t={t}|params_err={e}");
            unsafe { sys::heap_caps_aligned_free(p as *mut c_void) };
            return true;
        }
    };
    let ctx = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    let t0 = Instant::now();
    let res = ctx.hash_password_into_with_memory(PWD, SALT, &mut out, scratch);
    let us = t0.elapsed().as_micros();
    match res {
        Ok(()) => log::info!(
            "MEAS|argon2|mem={mem}|m_kib={m_kib}|t={t}|p=1|us={us}|ms={}|zeroize_us={zero_us}|out={}",
            us / 1000,
            hex8(&out)
        ),
        Err(e) => log::warn!("MEAS|argon2|mem={mem}|m_kib={m_kib}|t={t}|p=1|err={e}|us={us}"),
    }
    unsafe { sys::heap_caps_aligned_free(p as *mut c_void) };
    true
}

// --- helpers ------------------------------------------------------------------

fn alloc_internal(n: usize) -> *mut u8 {
    unsafe {
        sys::heap_caps_malloc(n, sys::MALLOC_CAP_INTERNAL | sys::MALLOC_CAP_DMA | sys::MALLOC_CAP_8BIT)
            as *mut u8
    }
}

/// First 8 bytes of a digest as hex - enough to tell two results apart in a log
/// without printing a full hash on every line.
fn hex8(d: &[u8]) -> String {
    d.iter().take(8).map(|b| format!("{b:02x}")).collect()
}
