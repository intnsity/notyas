// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The hardware-in-the-loop test console: a line-oriented command set on UART0 that
//! drives the sealed store directly.
//!
//! Compiled only by `--features hil-console`, which `build.rs` refuses to accept in a
//! release profile (MILESTONES.md m4a, Q41). It exists because m4a's exit gate cannot be
//! evidenced any other way. Two of its items in particular:
//!
//! - **The known-answer test.** The host power-loss fuzzer proved 71,910 cases against a
//!   *simulated* NOR part. That proof is about this device only if the real driver, on
//!   real silicon, produces the same bytes. [`kat`] re-runs the published vector sequence
//!   against `esp_partition` and compares the resulting flash image, byte for byte, with
//!   the digests in `crates/notyas-wallet/tests/vectors.rs`. A match is the bridge
//!   between the simulation and the part; a mismatch is the most important finding this
//!   milestone could produce.
//! - **The manual power-cut gate.** Q43's USB-controlled relay is deferred to 0.3.0, so
//!   the cuts are made by hand at the connector. That only means anything if the operator
//!   knows exactly which step was in flight when the power went and can read the ledger
//!   back afterwards. [`soak`] prints the index before every seal and [`pin_soak`] before
//!   every change-PIN, and the boot banner prints the mount verdict before a single key
//!   is pressed.
//!
//! Every reply is one `HIL|key=value|...` line so a capture can be parsed mechanically
//! rather than eyeballed, matching `src/measure.rs`'s convention.
//!
//! # What this console is allowed to print
//!
//! PINs arrive on the wire in the clear, because a bench operator typing into a serial
//! terminal has no other way to supply one and the boards hold no real money. Nothing
//! else is relaxed: no derived key, no session secret and no Argon2 state is ever
//! rendered, and record plaintexts are printed only because the console is the thing that
//! put them there.

use std::ffi::c_void;
use std::time::Instant;

use esp_idf_svc::sys;
use notyas_wallet::{
    Config, KdfParams, KeyProvenance, Layout, Occupancy, Pin, PolicyRequest, Region, SlotClass,
    SlotId, Vault,
};
use sha2::{Digest, Sha256};

use crate::store::{
    self, soft_hmac, FixedKeyMac, PartitionFlash, Store, SECTOR_BYTES,
};

/// UART the ESP-IDF console already owns (`CONFIG_ESP_CONSOLE_UART_NUM`).
const CONSOLE_UART: i32 = 0;
/// RX ring the driver keeps for us. A command line is tens of bytes; this is slack.
const RX_RING: i32 = 1024;
/// Longest command line accepted. Anything longer is discarded with a diagnostic rather
/// than silently truncated into a different command.
const LINE_MAX: usize = 256;

// -------------------------------------------------------------------------------------
// The published known-answer vectors
// -------------------------------------------------------------------------------------

/// The KAT's own configuration, character for character the `kat_config()` in
/// `crates/notyas-wallet/tests/vectors.rs`. It is NOT the product configuration: a
/// device whose ordinary store shared a domain tag or a device key with a published
/// vector would let that vector open a developer's records.
const KAT_CONFIG: Config = Config {
    domain_tag: *b"esl-kat-vector01",
    kdf: KdfParams::TEST_ONLY,
    layout: Layout::V1,
    format_policy: PolicyRequest {
        wipe_after: 15,
        min_pin_len: 4,
    },
    occupancy: Occupancy::AlwaysFilled,
    accept_provenance: &[KeyProvenance::EfuseReadProtected, KeyProvenance::Emulated],
    disable_wipe_min_pin_len: None,
};

/// The host vector's device key. `notyas_wallet::sim::SoftMac::new()`.
const KAT_KEY: [u8; 32] = [0x5a; 32];
const KAT_PIN: &str = "135790";
const KAT_LABEL: &[u8] = b"kat";
const KAT_PAYLOAD: &[u8] = b"ESL known-answer payload";

/// `vectors.rs::the_whole_image_is_a_pure_function_of_its_inputs_at_test_parameters`.
const KAT_RECORDS_TEST: &str = "5e5d5be317de8758e4fd95cbfff90002f68009cc8a89d5fcb0f60def0b591bc6";
const KAT_LEDGER_TEST: &str = "b85e4183a213ca4d3405f7385073c5d68eab3ad223602673e9632cb29daa207b";
/// `vectors.rs::the_whole_image_is_a_pure_function_of_its_inputs_at_pinned_parameters`.
/// This one is the milestone's real question: it can only pass if 16 MiB of Argon2id
/// working set fits in PSRAM alongside the framebuffers AND completes correctly here.
const KAT_RECORDS_PINNED: &str = "3bf12e16356aa19e4270019e8ff1af0d73d4f648d84fbd68263322cb9a6b0beb";
/// `vectors.rs::the_header_layout_is_byte_exact`, superblock side A at sector 0.
const KAT_SUPERBLOCK_HEADER: &str = concat!(
    "45534c520100010000000000",
    "200000000100000001000000",
    "0000000000000000",
    "0000000000000000",
    "00000000b00f0000",
    "e09e6d5eac572dac0bc5e46d52584e13",
    "e0fe7820b39e63ac207322e3fe1f78d2",
);

// -------------------------------------------------------------------------------------
// Console plumbing
// -------------------------------------------------------------------------------------

/// Line assembler over the console UART.
pub struct Console {
    line: String,
    /// True once the UART driver is installed. A failed install is reported once and the
    /// console then does nothing, rather than spinning on an error every pass.
    live: bool,
}

impl Console {
    /// Install the RX driver on the console UART.
    ///
    /// The driver is installed WITHOUT `uart_param_config`: the console has already
    /// configured the port at `CONFIG_ESP_CONSOLE_UART_BAUDRATE` and reconfiguring it
    /// here would risk a garbled log for no gain. Output stays on the polling path, so
    /// `log::info!` is unaffected.
    pub fn install() -> Console {
        // SAFETY: a driver install on a UART nothing else has claimed a driver for.
        let err = unsafe {
            sys::uart_driver_install(
                CONSOLE_UART as sys::uart_port_t,
                RX_RING,
                0,
                0,
                core::ptr::null_mut(),
                0,
            )
        };
        let live = err == sys::ESP_OK;
        if live {
            log::warn!(
                "hil: TEST CONSOLE ACTIVE on UART{CONSOLE_UART} - this build can format, \
                 seal and erase the store from the serial port with no PIN. Not a product \
                 image. Type `help`."
            );
        } else {
            log::error!("hil: uart_driver_install failed (0x{err:x}) - console disabled");
        }
        Console { line: String::new(), live }
    }

    /// Print the mount verdict before the operator can touch anything.
    ///
    /// This line is the entire read-back half of the manual power-cut gate: after a cut
    /// taken mid-seal or mid-change-PIN, what matters is whether the store mounted
    /// cleanly and what the ledger says, measured before any command can perturb it.
    pub fn boot_banner(&mut self, store: &mut Option<Store>) {
        match store.as_mut() {
            Some(s) => status(s),
            None => log::error!("HIL|status|err=store_unavailable"),
        }
    }

    /// Drain whatever arrived and run every complete line. Non-blocking: the timeout is
    /// zero ticks, so an idle console costs one syscall per main-loop pass and cannot
    /// perturb the idle-repaint or heartbeat invariants.
    pub fn poll(&mut self, store: &mut Option<Store>) {
        if !self.live {
            return;
        }
        let mut buf = [0u8; 64];
        loop {
            // SAFETY: `buf` is ours and `len` is its true length.
            let n = unsafe {
                sys::uart_read_bytes(
                    CONSOLE_UART as sys::uart_port_t,
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len() as u32,
                    0,
                )
            };
            if n <= 0 {
                return;
            }
            for &b in &buf[..n as usize] {
                match b {
                    b'\r' | b'\n' => {
                        let line = core::mem::take(&mut self.line);
                        let line = line.trim();
                        if !line.is_empty() {
                            dispatch(line, store);
                        }
                    }
                    // Backspace / DEL, so a human at a terminal can correct a typo.
                    0x08 | 0x7f => {
                        self.line.pop();
                    }
                    0x20..=0x7e => {
                        if self.line.len() < LINE_MAX {
                            self.line.push(b as char);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

// -------------------------------------------------------------------------------------
// Dispatch
// -------------------------------------------------------------------------------------

fn dispatch(line: &str, store: &mut Option<Store>) {
    let mut it = line.splitn(2, ' ');
    let cmd = it.next().unwrap_or("");
    let rest = it.next().unwrap_or("").trim();
    log::info!("HIL|cmd={cmd}|args={rest}");

    match cmd {
        "help" => help(),
        "heap" => heap(),
        "kat" => kat(store),
        _ => {
            let Some(s) = store.as_mut() else {
                log::error!("HIL|{cmd}|err=store_unavailable");
                return;
            };
            match cmd {
                "status" => status(s),
                "erase" => erase(s),
                "format" => format_cmd(s, rest),
                "unlock" => unlock(s, rest),
                "lock" => lock(s),
                "seal" => seal(s, rest),
                "read" => read(s, rest),
                "changepin" => change_pin(s, rest),
                "wipe" => wipe(s),
                "scan" => scan(s),
                "dump" => dump(s, rest),
                "soak" => soak(s, rest),
                "pinsoak" => pin_soak(s, rest),
                other => log::error!("HIL|err=unknown_command|cmd={other}"),
            }
        }
    }
}

fn help() {
    for l in [
        "status                 - state, provenance, counters, policy, boot count",
        "heap                   - free PSRAM, internal RAM and main-task stack headroom",
        "kat                    - known-answer test against the published host vectors",
        "erase                  - erase BOTH partitions (store returns to blank)",
        "format <pin>           - install the first PIN",
        "unlock <pin>           - consume one attempt; prints the measured ms",
        "lock                   - drop the session",
        "seal <slot> <text>     - seal text into a payload slot",
        "read <slot>            - read a payload slot back",
        "changepin <newpin>     - re-seal every record under a new PIN",
        "wipe                   - destroy every record and bump the epoch",
        "scan                   - per-sector non-0xff byte counts, both regions",
        "dump <r> <off> <len>   - raw hex, r = rec | led",
        "soak <slot> <n>        - seal n times, announcing each; for power cuts",
        "pinsoak <a> <b> <n>    - alternate the PIN n times; for power cuts",
    ] {
        log::info!("HIL|help|{l}");
    }
}

fn heap() {
    log::info!(
        "HIL|heap|free_psram={}|free_internal={}|free_total={}|         main_stack_free={}|main_stack_size={}",
        store::free_psram(),
        store::free_internal(),
        // SAFETY: a read-only heap query.
        unsafe { sys::esp_get_free_heap_size() },
        store::stack_headroom(),
        store::MAIN_STACK_BYTES,
    );
}

fn status(s: &mut Store) {
    // Every value read before the vault is borrowed mutably: `Vault`'s accessors need
    // `&self` but `Store::vault_mut` hands out `&mut`, and mixing the two in one format
    // argument list is a borrow error rather than a style question.
    let r = s.report().clone();
    let unlocked = s.is_unlocked();
    let v = s.vault_mut();
    let (state, failures, attempts, policy) =
        (v.state(), v.failures(), v.attempts_remaining(), v.policy());
    let (epoch, next_seq, tamper) = (v.wipe_epoch(), v.next_seq(), v.tamper_flags());
    log::info!(
        "HIL|status|provenance={}|state={}|unlocked={unlocked}|failures={failures}|         attempts_left={attempts:?}|wipe_after={}|policy_gen={}|epoch={epoch}|         next_seq={next_seq}|boot_count={:?}|tamper={tamper:?}",
        r.provenance,
        store::state_label(state),
        policy.wipe_after,
        policy.policy_gen,
        r.boot_count,
    );
}

fn erase(s: &mut Store) {
    let t0 = Instant::now();
    let mut flash = match PartitionFlash::open(
        store::CONFIG.layout.records_bytes(),
        store::CONFIG.layout.ledger_sectors * store::CONFIG.layout.sector_size,
    ) {
        Ok(f) => f,
        Err(e) => {
            log::error!("HIL|erase|err={e:?}");
            return;
        }
    };
    for region in [Region::Records, Region::Ledger] {
        if let Err(e) = flash.erase_all(region) {
            log::error!("HIL|erase|region={region:?}|err={e:?}");
            return;
        }
    }
    let _ = s;
    log::info!(
        "HIL|erase|ok=true|ms={}|note=reboot_required_the_mounted_vault_view_is_now_stale",
        t0.elapsed().as_millis()
    );
}

fn format_cmd(s: &mut Store, rest: &str) {
    let Some(pin) = parse_pin(rest) else { return };
    match s.format(&pin, b"hil") {
        Ok(ms) => log::info!("HIL|format|ok=true|ms={ms}"),
        Err(e) => log::error!("HIL|format|ok=false|err={e}"),
    }
    status(s);
}

fn unlock(s: &mut Store, rest: &str) {
    let Some(pin) = parse_pin(rest) else { return };
    match s.unlock(&pin) {
        Ok(ms) => log::info!("HIL|unlock|ok=true|ms={ms}|failures_after={}", s.failures()),
        Err(e) => log::error!(
            "HIL|unlock|ok=false|err={e:?}|failures_after={}|attempts_left={:?}",
            s.failures(),
            s.attempts_remaining()
        ),
    }
}

fn lock(s: &mut Store) {
    log::info!("HIL|lock|had_session={}", s.lock());
}

fn seal(s: &mut Store, rest: &str) {
    let mut it = rest.splitn(2, ' ');
    let Some(slot) = it.next().and_then(|t| t.parse::<u8>().ok()) else {
        log::error!("HIL|seal|err=usage|want=seal <slot> <text>");
        return;
    };
    let text = it.next().unwrap_or("").as_bytes();
    let t0 = Instant::now();
    match s.write_payload(slot, text) {
        Ok(()) => log::info!(
            "HIL|seal|ok=true|slot={slot}|len={}|ms={}",
            text.len(),
            t0.elapsed().as_millis()
        ),
        Err(e) => log::error!("HIL|seal|ok=false|slot={slot}|err={e}"),
    }
}

fn read(s: &mut Store, rest: &str) {
    let Some(slot) = rest.parse::<u8>().ok() else {
        log::error!("HIL|read|err=usage|want=read <slot>");
        return;
    };
    let mut out = [0u8; 3072];
    match s.read_payload(slot, &mut out) {
        Ok(n) => log::info!(
            "HIL|read|ok=true|slot={slot}|len={n}|sha256={}|text={}",
            hex(&Sha256::digest(&out[..n])),
            String::from_utf8_lossy(&out[..n])
        ),
        Err(e) => log::error!("HIL|read|ok=false|slot={slot}|err={e}"),
    }
}

fn change_pin(s: &mut Store, rest: &str) {
    let Some(pin) = parse_pin(rest) else { return };
    match s.change_pin(&pin) {
        Ok(ms) => log::info!("HIL|changepin|ok=true|ms={ms}"),
        Err(e) => log::error!("HIL|changepin|ok=false|err={e}"),
    }
}

fn wipe(s: &mut Store) {
    match s.vault_mut().wipe() {
        Ok(()) => {
            s.lock();
            s.refresh_report();
            log::info!("HIL|wipe|ok=true");
        }
        Err(e) => log::error!("HIL|wipe|ok=false|err={e:?}"),
    }
    status(s);
}

/// Per-sector non-`0xff` byte counts over the RAW view of both regions.
///
/// This is the evidence for two separate gate items. "The stateless path writes nothing"
/// is every count being zero on a device that only ever ran the stateless flow. "A PIN
/// change leaves no stale old-PIN ciphertext" is the retired side of every re-sealed slot
/// reading zero afterwards - proven from the flash, which is what the gate demands, and
/// not from code inspection.
fn scan(s: &mut Store) {
    let _ = s;
    let mut flash = match PartitionFlash::open(
        store::CONFIG.layout.records_bytes(),
        store::CONFIG.layout.ledger_sectors * store::CONFIG.layout.sector_size,
    ) {
        Ok(f) => f,
        Err(e) => {
            log::error!("HIL|scan|err={e:?}");
            return;
        }
    };
    for region in [Region::Records, Region::Ledger] {
        let mut counts: Vec<u32> = Vec::new();
        let mut in_sector = 0u32;
        let mut seen = 0u32;
        let res = flash.scan_raw(region, |chunk| {
            for b in chunk {
                if *b != 0xff {
                    in_sector += 1;
                }
                seen += 1;
                if seen % SECTOR_BYTES == 0 {
                    counts.push(in_sector);
                    in_sector = 0;
                }
            }
        });
        if let Err(e) = res {
            log::error!("HIL|scan|region={region:?}|err={e:?}");
            return;
        }
        let total: u32 = counts.iter().sum();
        let cells: Vec<String> = counts.iter().map(|c| c.to_string()).collect();
        log::info!(
            "HIL|scan|region={region:?}|nonblank_total={total}|per_sector={}",
            cells.join(",")
        );
    }
}

fn dump(s: &mut Store, rest: &str) {
    let _ = s;
    let parts: Vec<&str> = rest.split_whitespace().collect();
    let (Some(r), Some(off), Some(len)) = (
        parts.first().copied(),
        parts.get(1).and_then(|t| parse_u32(t)),
        parts.get(2).and_then(|t| parse_u32(t)),
    ) else {
        log::error!("HIL|dump|err=usage|want=dump <rec|led> <offset> <len>");
        return;
    };
    let region = match r {
        "rec" => Region::Records,
        "led" => Region::Ledger,
        other => {
            log::error!("HIL|dump|err=bad_region|got={other}");
            return;
        }
    };
    let len = len.min(1024) as usize;
    let mut buf = vec![0u8; len];
    let mut flash = match PartitionFlash::open(
        store::CONFIG.layout.records_bytes(),
        store::CONFIG.layout.ledger_sectors * store::CONFIG.layout.sector_size,
    ) {
        Ok(f) => f,
        Err(e) => {
            log::error!("HIL|dump|err={e:?}");
            return;
        }
    };
    match flash.read_raw(region, off, &mut buf) {
        Ok(()) => log::info!(
            "HIL|dump|region={region:?}|off=0x{off:x}|len={len}|hex={}",
            hex(&buf)
        ),
        Err(e) => log::error!("HIL|dump|err={e:?}"),
    }
}

/// Seal `n` times in a row, announcing the index BEFORE each attempt.
///
/// The announcement is the point. The power cut is made by hand at the connector, so the
/// timing is sampled rather than swept (MILESTONES.md m4a test method says so out loud);
/// what makes a sampled cut evidence at all is knowing exactly which seal was in flight.
/// After the cut, the next boot's mount verdict plus `read` must show either index `i-1`
/// or index `i`, never a corrupt slot and never a store that refuses to mount.
fn soak(s: &mut Store, rest: &str) {
    let parts: Vec<&str> = rest.split_whitespace().collect();
    let (Some(slot), Some(n)) = (
        parts.first().and_then(|t| t.parse::<u8>().ok()),
        parts.get(1).and_then(|t| t.parse::<u32>().ok()),
    ) else {
        log::error!("HIL|soak|err=usage|want=soak <slot> <count>");
        return;
    };
    for i in 0..n {
        let payload = format!("soak-seal-{i:06}");
        log::info!("HIL|soak|about_to_seal|i={i}|payload={payload}");
        match s.write_payload(slot, payload.as_bytes()) {
            Ok(()) => log::info!("HIL|soak|sealed|i={i}"),
            Err(e) => {
                log::error!("HIL|soak|failed|i={i}|err={e}");
                return;
            }
        }
    }
    log::info!("HIL|soak|done|count={n}");
}

/// Alternate the PIN `n` times, announcing each change before it starts.
///
/// Change-PIN is the operation with the most steps and the only one whose commit point
/// moves a whole identity's records, so it is where a torn write would hurt most. After a
/// cut, exactly one of the two PINs must open the device and no record may be lost.
fn pin_soak(s: &mut Store, rest: &str) {
    let parts: Vec<&str> = rest.split_whitespace().collect();
    let (Some(a), Some(b), Some(n)) = (
        parts.first().copied(),
        parts.get(1).copied(),
        parts.get(2).and_then(|t| t.parse::<u32>().ok()),
    ) else {
        log::error!("HIL|pinsoak|err=usage|want=pinsoak <pin_a> <pin_b> <count>");
        return;
    };
    for i in 0..n {
        let to = if i % 2 == 0 { b } else { a };
        let Some(pin) = parse_pin(to) else { return };
        log::info!("HIL|pinsoak|about_to_change|i={i}|to={to}");
        match s.change_pin(&pin) {
            Ok(ms) => log::info!("HIL|pinsoak|changed|i={i}|to={to}|ms={ms}"),
            Err(e) => {
                log::error!("HIL|pinsoak|failed|i={i}|to={to}|err={e}");
                return;
            }
        }
    }
    log::info!("HIL|pinsoak|done|count={n}");
}

// -------------------------------------------------------------------------------------
// The known-answer test
// -------------------------------------------------------------------------------------

/// Re-run the published host vector against the real flash driver and compare images.
///
/// The sequence is `crates/notyas-wallet/tests/vectors.rs::build` verbatim: mount a blank
/// store under the vector's device key and domain tag, format with PIN `135790`, write
/// one payload record and one 512-byte registry record, drop the session. Every byte of
/// the resulting image is then a pure function of those inputs - there is no clock, no
/// RNG and no allocator address anywhere in the engine - so a digest that matches the
/// host's proves the whole chain agrees: the ladder, the header layout, the AAD framing,
/// the AEAD, the ledger encoding, AND this file's `esp_partition` driver.
///
/// Run twice, at test cost and at the pinned production cost. The second run is the one
/// m4a's exit gate names, because it can only complete if 16 MiB of Argon2id working set
/// really is available on this board with the framebuffers already allocated.
///
/// Destructive: it leaves both partitions holding the vector's image, not the user's.
/// The store must be erased and the board rebooted afterwards, and the reply says so.
fn kat(store: &mut Option<Store>) {
    let Some(s) = store.as_mut() else {
        log::error!("HIL|kat|err=store_unavailable_no_scratch");
        return;
    };
    // Drop any session first: the product vault's cached view is about to go stale, and
    // an open session over an image that is no longer the one it was derived from is the
    // one state this console must never leave behind.
    s.lock();

    // `check` returns its verdict rather than mutating a captured flag: a closure that
    // borrows `pass` for the whole function makes every later `pass = false` a borrow
    // error, and threading the boolean is clearer than a RefCell would be.
    let mut pass = true;
    fn check(what: &str, got: &str, want: &str) -> bool {
        if got == want {
            log::info!("HIL|kat|check={what}|result=PASS|digest={got}");
            true
        } else {
            log::error!("HIL|kat|check={what}|result=FAIL|got={got}|want={want}");
            false
        }
    }

    // Prove the MAC first. If the software HMAC under the vector key does not agree with
    // the host, nothing downstream can, and a header digest mismatch would be a much
    // harder thing to read than this line.
    let probe = soft_hmac(&KAT_KEY, b"notyas-hil-kat-probe");
    log::info!("HIL|kat|mac_probe={}", hex(&probe));

    for (label, params, want_records, want_ledger) in [
        (
            "test_params",
            KdfParams::TEST_ONLY,
            KAT_RECORDS_TEST,
            Some(KAT_LEDGER_TEST),
        ),
        (
            "pinned_params",
            KdfParams::PINNED,
            KAT_RECORDS_PINNED,
            None,
        ),
    ] {
        // Yield between phases: each one holds this core for seconds and the task
        // watchdog watches the idle task.
        std::thread::sleep(std::time::Duration::from_millis(50));

        let cfg = Config { kdf: params, ..KAT_CONFIG };
        let mut flash = match PartitionFlash::open(
            cfg.layout.records_bytes(),
            cfg.layout.ledger_sectors * cfg.layout.sector_size,
        ) {
            Ok(f) => f,
            Err(e) => {
                log::error!("HIL|kat|phase={label}|err=open:{e:?}");
                return;
            }
        };
        // The host vector starts from `SimFlash::v1()`, which is all-0xff. Anything less
        // than a full erase here would compare a different starting state.
        for region in [Region::Records, Region::Ledger] {
            if let Err(e) = flash.erase_all(region) {
                log::error!("HIL|kat|phase={label}|err=erase:{e:?}");
                return;
            }
        }

        let mac = FixedKeyMac::new(KAT_KEY, KeyProvenance::EfuseReadProtected);
        let mut v = match Vault::mount(flash, mac, &cfg) {
            Ok(v) => v,
            Err(e) => {
                log::error!("HIL|kat|phase={label}|err=mount:{e:?}");
                return;
            }
        };

        let Ok(pin) = Pin::from_normalized_utf8(KAT_PIN) else {
            log::error!("HIL|kat|err=pin_rejected");
            return;
        };
        let t0 = Instant::now();
        let session = match v.format(&pin, KAT_LABEL, s.scratch_mut().borrow()) {
            Ok(sess) => sess,
            Err(e) => {
                log::error!("HIL|kat|phase={label}|err=format:{e:?}");
                return;
            }
        };
        let format_ms = t0.elapsed().as_millis();

        let (Some(payload_slot), Some(registry_slot)) = (
            SlotId::new(SlotClass::Payload, 0, &cfg.layout),
            SlotId::new(SlotClass::Registry, 3, &cfg.layout),
        ) else {
            log::error!("HIL|kat|phase={label}|err=slot_ids");
            return;
        };
        let t1 = Instant::now();
        if let Err(e) = v.write(&session, payload_slot, KAT_PAYLOAD) {
            log::error!("HIL|kat|phase={label}|err=write_payload:{e:?}");
            return;
        }
        if let Err(e) = v.write(&session, registry_slot, &[0x11u8; 512]) {
            log::error!("HIL|kat|phase={label}|err=write_registry:{e:?}");
            return;
        }
        let write_ms = t1.elapsed().as_millis();
        drop(session);
        let (mut flash, _) = v.into_parts();

        log::info!(
            "HIL|kat|phase={label}|m_kib={}|t={}|format_ms={format_ms}|two_writes_ms={write_ms}",
            params.m_kib,
            params.t
        );

        // The 80-byte superblock header, raw. Checked only at test parameters, because
        // it encodes m_kib and the published bytes are the m=32 ones.
        if label == "test_params" {
            let mut hdr = [0u8; 80];
            match flash.read_raw(Region::Records, 0, &mut hdr) {
                Ok(()) => pass &= check("superblock_header", &hex(&hdr), KAT_SUPERBLOCK_HEADER),
                Err(e) => {
                    log::error!("HIL|kat|phase={label}|err=header_read:{e:?}");
                    pass = false;
                }
            }
        }

        match digest_region(&mut flash, Region::Records) {
            Ok(d) => pass &= check(&format!("{label}_records_image"), &d, want_records),
            Err(e) => {
                log::error!("HIL|kat|phase={label}|err=digest_records:{e:?}");
                pass = false;
            }
        }
        if let Some(want) = want_ledger {
            match digest_region(&mut flash, Region::Ledger) {
                Ok(d) => pass &= check(&format!("{label}_ledger_image"), &d, want),
                Err(e) => {
                    log::error!("HIL|kat|phase={label}|err=digest_ledger:{e:?}");
                    pass = false;
                }
            }
        }
    }

    log::warn!(
        "HIL|kat|result={}|main_stack_free={}|main_stack_size={}|         note=both_partitions_now_hold_the_vector_image_run_erase_then_reboot",
        if pass { "PASS" } else { "FAIL" },
        store::stack_headroom(),
        store::MAIN_STACK_BYTES,
    );
}

fn digest_region(flash: &mut PartitionFlash, region: Region) -> Result<String, store::FlashError> {
    let mut h = Sha256::new();
    flash.scan_raw(region, |chunk| h.update(chunk))?;
    Ok(hex(&h.finalize()))
}

// -------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------

fn parse_pin(text: &str) -> Option<Pin> {
    match Pin::from_normalized_utf8(text) {
        Ok(p) => Some(p),
        Err(e) => {
            log::error!("HIL|err=bad_pin|reason={e:?}");
            None
        }
    }
}

fn parse_u32(t: &str) -> Option<u32> {
    t.strip_prefix("0x")
        .map(|h| u32::from_str_radix(h, 16))
        .unwrap_or_else(|| t.parse())
        .ok()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
