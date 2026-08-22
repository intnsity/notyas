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
//! Since 0.2.0 it carries a third job, and it is the one that decides the release.
//! MILESTONES.md section 9 clause 2 asks for a working wallet doing the whole loop on real
//! hardware, and the screens that will drive that loop for a user are m4b's, still being
//! written. The commands in the release-loop section below drive the same loop over the
//! wire today - register a multisig wallet, verify its first receive address, load a PSBT,
//! review it, sign it - so the gate can be attempted and captured now, and so the screens
//! have a transcript to be compared against when they land.
//!
//! Every reply is one `HIL|key=value|...` line so a capture can be parsed mechanically
//! rather than eyeballed, matching `src/measure.rs`'s convention.
//!
//! # What this console is allowed to print
//!
//! INVARIANT. This console may print what is PUBLIC, and what the OPERATOR supplied UNLESS
//! that value would open a wallet somewhere else. It may never print what the device
//! DERIVED or what it stored as a secret. Every rule below is that one sentence applied to
//! a particular value, and a new command earns its output by being read against it rather
//! than against what the neighbouring command happens to do.
//!
//! The exception in the first sentence is not a detail, it is the whole edge. "The operator
//! typed it" was the rule once, and it is false: the operator types the recovery phrase
//! too, into [`wallet_new`], and under that rule the dispatch echo put all twenty-four
//! words on UART0 before the handler that is careful with them had run. What an operator
//! supplied is a reason to print a value only while the value is not itself a key.
//!
//! PINs arrive on the wire in the clear, because a bench operator typing into a serial
//! terminal has no other way to supply one, the boards hold no real money, and [`pin_soak`]
//! prints them by design. A PIN is a thing the operator already knew before the device did,
//! and it guards a secret this device holds rather than being one: it is worth nothing away
//! from the sealed store it unlocks. Nothing else is relaxed: no derived key, no seed, no
//! session secret, no xprv and no Argon2 state is ever rendered.
//!
//! A recovery phrase is the other kind, and it is NOT a PIN. A PIN is one factor guarding
//! a secret this device holds; the phrase IS that secret, it opens the wallet on any device
//! in the world, and this console - unlike the screens - has no PIN gate that could make
//! printing it survivable. A BIP39 passphrase belongs with the phrase and not with the PIN:
//! it is the other half of the same key, it opens a wallet on any device the same way, and
//! this console cannot tell a bench passphrase from the one protecting a real coin. So
//! neither is echoed, and [`echo_prefix`] is where that decision is made once for every
//! command instead of per handler. [`read`] renders a payload slot as text only while the
//! body is not a record this firmware wrote; see its own docs for why the test is the
//! record's magic and not a successful parse. A body that came from [`seal`] is still
//! printed in full, because the console is the thing that put it there.
//!
//! The release-loop commands sign, and they widen that list by nothing. The seed lives in
//! [`crate::wallet::Wallet`], whose accessor is crate-private and whose `Debug` redacts,
//! and this file never asks for it. What these commands print is public by construction: a
//! master fingerprint, a descriptor, an address, a cosigner's public key, an amount, a fee,
//! a signature, a signed transaction. A signature and an address are safe to publish; the
//! key that made the signature is not, and it never reaches this file at all.

// The Q41 fence, second shape. `firmware/build.rs` refuses this feature in a product image
// from cargo's side; this is the same rule seen by rustc, on the module itself, where
// `debug_assertions` is not a report about how the build was invoked but the switch that
// decides what code this file compiles to.
//
// Two fences of the same rule because they fail differently and neither subsumes the other.
// build.rs is where the explanation lives and it stops the artefact existing before a single
// crate is compiled; this one holds even if a build script is skipped, stubbed or wired to
// succeed, because rustc evaluates it while compiling the very code that would ship. Neither
// is evidence: `tools/ci/check-release-symbols.sh` reads the linked ELF, and a promise made
// by a build flag is not a finding about an image.
//
// BOTH CONDITIONS, BECAUSE ONE BIT WAS NOT ENOUGH. This used to read `debug_assertions`
// alone, which is the same bit build.rs keyed on - so `[profile.hardened] inherits =
// "release", debug-assertions = true` cleared both fences at once with one line of TOML,
// and an optimized, stripped, release-rooted image compiled the console in. `notyas_bench_image`
// is build.rs's whole four-property verdict handed to rustc, and it is required IN ADDITION
// to rustc's own view of the code being emitted, so the two layers no longer share a
// failure. A cfg that is absent refuses: a build script that was skipped, stubbed or wired
// to succeed silently emits nothing, and nothing is not permission.
#[cfg(not(all(debug_assertions, notyas_bench_image)))]
compile_error!(
    "notyas-firmware: feature `hil-console` is compiled into an image that is not \
     bench-shaped, which is what a product image is. This console drives the store from the \
     UART with no PIN - it can format, seal, wipe, dump raw flash and SIGN a transaction. \
     Build the bench image in the dev profile; firmware/build.rs prints every property that \
     disagreed, and sets `notyas_bench_image` only when all of them hold. There is no override."
);

use std::ffi::c_void;
use std::time::Instant;

use esp_idf_svc::sys;
// The product crates, through notyas-core's own re-export of `bitcoin`: naming a second
// copy of that crate here is how a firmware ends up validating against one pin and signing
// with another (notyas-core's lib docs say why the re-export exists).
use notyas_core::address::AddressSource;
use notyas_core::bitcoin::{Address, Network};
use notyas_core::derive::ChildIndex;
use notyas_core::multisig::{Keychain, Registration};
use notyas_core::psbt::{AmountProof, Claim, OutputRole};
use notyas_wallet::{
    Config, KdfParams, KeyProvenance, Layout, Occupancy, Pin, PolicyRequest, Region, SlotClass,
    SlotId, Vault,
};
use sha2::{Digest, Sha256};

// The device's own signing surface and the only place a seed exists. The console drives
// these rather than notyas-core directly, so what a transcript evidences is the path a
// screen will take (see the release-loop section header).
use crate::signing::{self, Refusal, Review, ReviewedFee};
use crate::store::{
    self, soft_hmac, FixedKeyMac, PartitionFlash, PsramScratch, Store, SECTOR_BYTES,
};
use crate::wallet::record::{SealedWallet, StoredPassphrase, WalletRecord};
use crate::wallet::{NewWallet, Wallet};

/// UART the ESP-IDF console already owns (`CONFIG_ESP_CONSOLE_UART_NUM`).
const CONSOLE_UART: i32 = 0;
/// RX ring the driver keeps for us.
///
/// Sized for the longest line the console accepts plus slack, not for a command word: the
/// release-loop commands carry descriptors and PSBT hex, and a ring smaller than one line
/// would drop bytes out of the middle of a transaction whenever the main loop spent a pass
/// repainting. The cost is a few KiB of internal RAM held for the lifetime of a build that
/// is not a product image.
const RX_RING: i32 = 4096;
/// Longest command line accepted. Anything longer is discarded with a diagnostic rather
/// than silently truncated into a different command.
///
/// A kilobyte because a BIP-380 descriptor for a 2-of-3 wallet is around 420 characters
/// with its origins and its checksum, and a value that has to be split across lines to be
/// registered is a value an operator will split wrongly. Anything genuinely longer - a
/// PSBT - goes through `paste`, which is chunked by design and reports a digest.
const LINE_MAX: usize = 1024;

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
    /// State the release-loop commands keep between lines. It belongs to the console rather
    /// than to the store because none of it is sealed and none of it survives a reboot -
    /// see [`Bench`].
    bench: Bench,
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
                 seal and erase the store from the serial port with no PIN, and can SIGN a \
                 transaction on command. Not a product image. Type `help`."
            );
        } else {
            log::error!("hil: uart_driver_install failed (0x{err:x}) - console disabled");
        }
        Console { line: String::new(), live, bench: Bench::new() }
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
                            dispatch(line, store, &mut self.bench);
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

/// What the echo prints in place of a command word this console does not recognise.
const UNKNOWN_CMD: &str = "?";

fn dispatch(line: &str, store: &mut Option<Store>, bench: &mut Bench) {
    let mut it = line.splitn(2, ' ');
    let cmd = it.next().unwrap_or("");
    let rest = it.next().unwrap_or("").trim();

    // The transcript line, redacted by [`echo_prefix`]. `withheld` is printed on every line,
    // including the ones that withhold nothing, so a parsed capture can tell "this command
    // took no arguments" from "this line is not all of what was typed" - a redaction that
    // looked like a complete record would be worse than either.
    //
    // A command word this console does not know is withheld along with its arguments. The
    // first word of a line is operator input like every other word on it, and the accident
    // this console has to absorb is a recovery phrase pasted without its command in front of
    // it: every line of that paste dispatches, and an unredacted `cmd=` would put one BIP39
    // word per line on the wire. What an operator loses is the readback of their typo, which
    // their own terminal still has; what they cannot lose is a word of the phrase.
    let classified = echo_prefix(cmd, rest);
    let shown_cmd = if classified.is_some() { cmd } else { UNKNOWN_CMD };
    let shown_args = &rest[..classified.unwrap_or(0)];
    let withheld = classified.is_none() || shown_args.len() != rest.len();
    log::info!("HIL|cmd={shown_cmd}|args={shown_args}|withheld={withheld}");

    // Every command below wants a matching entry in [`echo_prefix`]. One that is missing
    // still runs: it is transcribed as `cmd=?` with its arguments withheld, which is the
    // safe direction to forget in and a visible one to read in a capture.
    match cmd {
        "help" => help(),
        "heap" => heap(),
        "kat" => kat(store),
        // The release-loop arm. These commands are NOT gated on the store: only `seed`
        // reads a record, and it says so itself when the store is missing. Gating a command
        // on state it does not read is docs/KNOWN-ISSUES.md K3, where `erase` and `scan`
        // vanish at exactly the moment they are the only commands worth having.
        "network" => network_cmd(bench, rest),
        "wallet" => wallet_cmd(store, bench, rest),
        "paste" => paste_cmd(bench, rest),
        "register" => register_cmd(store, bench, rest),
        "registrations" => registrations_cmd(bench),
        "address" => address_cmd(bench, rest),
        "psbtload" => psbt_load(bench, rest),
        "psbtinspect" => psbt_inspect(bench),
        "psbtsign" => psbt_sign(bench),
        _ => {
            // `shown_cmd`, not `cmd`: this arm is also where an unrecognised word lands, and
            // the echo above already said why one is never repeated.
            let Some(s) = store.as_mut() else {
                log::error!("HIL|{shown_cmd}|err=store_unavailable");
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
                "policysoak" => policy_soak_cmd(s, rest),
                "setpolicy" => set_policy_cmd(s, rest),
                "removepin" => remove_pin_cmd(s, rest),
                "wipe" => wipe(s),
                "scan" => scan(s),
                "dump" => dump(s, rest),
                "soak" => soak(s, rest),
                "pinsoak" => pin_soak(s, rest),
                // The word is not repeated back, for the reason the echo above gives: an
                // unrecognised first word is unclassified operator input, and this is the
                // arm a pasted recovery phrase reaches, one line at a time.
                _ => log::error!("HIL|err=unknown_command|try=help"),
            }
        }
    }
}

/// How much of a command's argument text the transcript echo may repeat, as a byte length
/// of `rest`; `None` when this console does not recognise `cmd` at all.
///
/// WHY THE ECHO IS REDACTED AND NOT REMOVED. The dispatch line is what makes a captured
/// session parseable rather than eyeballed (this module's header), and it is the only record
/// of what the device was ASKED before its answer. It is also where the recovery phrase
/// reached the wire: `wallet new <slot> <label> <pass|-> <words...>` printed every word of
/// the seed before [`wallet_new`], which is careful with it, ever ran. Keeping the line and
/// withholding the arguments keeps both properties instead of trading one for the other.
///
/// WHY A TABLE, AND WHY ITS DEFAULT IS TO WITHHOLD. A command that is not named below is
/// echoed with no arguments at all, and its command word is withheld too. That direction is
/// the point: a command added to [`dispatch`] later cannot open a disclosure by being
/// forgotten here, only by someone deliberately adding an entry - and the cost of forgetting
/// one is a transcript that says less than it could, never one that says too much.
///
/// The classification is this module's invariant applied argument by argument. The question
/// for each is never "did the operator type it", because the operator types the phrase too;
/// it is "would this value open a wallet somewhere else", and after that "does the console
/// print this value anyway, in which case withholding it here is theatre".
fn echo_prefix(cmd: &str, rest: &str) -> Option<usize> {
    let all = rest.len();
    Some(match cmd {
        // No arguments, or arguments that are pure structure: a slot, a region, an offset, a
        // length, an index, a chain name, a count. None of them identifies a key.
        "help" | "heap" | "kat" | "status" | "erase" | "lock" | "wipe" | "scan"
        | "registrations" | "psbtinspect" | "psbtsign" | "network" | "read" | "dump"
        | "soak" | "address" => all,

        // PINs, sanctioned by this module's header: a bench operator has no other way to
        // type one, [`pin_soak`] prints them by design, and a PIN is worth nothing away from
        // the store it unlocks.
        "format" | "unlock" | "changepin" | "pinsoak" | "setpolicy" | "policysoak" | "removepin" => all,

        // A payload this console wrote itself, which [`read`] hands back in full on purpose.
        // Withholding it on the way in while printing it on the way out would be theatre.
        "seal" => all,

        // A descriptor and a PSBT: public by construction, and printed in full by
        // [`report_registrations`] and [`psbt_sign`] for the same reason. Neither carries a
        // private key, and the operator's task is to compare them with another signer's copy.
        "register" | "psbtload" => all,

        // The paste buffer takes arbitrary operator text and [`paste_cmd`] deliberately
        // answers with a length and a digest instead of the content. The echo must not undo
        // that decision one line above it, so only the control words are repeated.
        "paste" => match rest {
            "" | "begin" | "reset" | "end" | "nl" => all,
            _ => 0,
        },

        // `wallet new <slot> <label> <passphrase|-> <words...>` and
        // `wallet open <slot> [passphrase]`. The kept prefix is what says WHICH wallet a
        // transcript is about; from the passphrase rightwards it is the key itself. An
        // unrecognised subcommand keeps its first word only - the same default as an
        // unrecognised command, one level down - so a mistyped `wallet nwe 2 label - <words>`
        // cannot spill the phrase either.
        "wallet" => match rest.split_whitespace().next() {
            Some("new") => tokens(rest, 3),
            Some("open") => tokens(rest, 2),
            _ => tokens(rest, 1),
        },

        _ => return None,
    })
}

/// The byte length of the first `n` whitespace-separated tokens of `rest`, excluding the
/// separator that follows them; all of `rest` when it holds `n` tokens or fewer.
///
/// A length rather than a `&str` so [`echo_prefix`] can answer every command with one value
/// of one type. The index returned is always a token's last byte plus that character's own
/// width, so it is a char boundary by construction and slicing on it cannot panic - the RX
/// path only ever admits 0x20..=0x7e, but a redaction is the wrong place to rely on that.
fn tokens(rest: &str, n: usize) -> usize {
    let mut end = 0;
    let mut seen = 0;
    let mut inside = false;
    for (i, c) in rest.char_indices() {
        if c.is_whitespace() {
            inside = false;
        } else {
            if !inside {
                inside = true;
                seen += 1;
                if seen > n {
                    return end;
                }
            }
            end = i + c.len_utf8();
        }
    }
    end
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
        "read <slot>            - read a payload slot back; a wallet record is described, never printed",
        "changepin <newpin>     - re-seal every record under a new PIN",
        "setpolicy <wipe_after|off> <min_pin_len> <pin> - set wrong-PIN wipe threshold",
        "policysoak <wipe_a> <wipe_b> <min_pin_len> <pin> <n> - set-policy n times, announcing each Y1-Y7 step",
        "removepin <pin>         - destroy every sealed record and unformat the store",
        "wipe                   - destroy every record and bump the epoch",
        "scan                   - per-sector non-0xff byte counts, both regions",
        "dump <r> <off> <len>   - raw hex, r = rec | led",
        "soak <slot> <n>        - seal n times, announcing each; for power cuts",
        "pinsoak <a> <b> <n>    - alternate the PIN n times; for power cuts",
        "network [name]         - chain for NEW wallets: bitcoin, testnet, signet, regtest",
        "wallet status          - which wallet is open, and any registry faults",
        "wallet new <slot> <label> <pass|-> <words...> - import a seed and seal it",
        "wallet persist <label> <fingerprint> <words...> - the touch UI's save: the identity is given, not derived, and the store picks the slot",
        "wallet open <slot> [pass]  - open the sealed wallet in a payload slot",
        "wallet close           - drop the open wallet and its seed",
        "paste <begin|end|nl|x> - accumulate a long value across lines; reports its digest",
        "register <label> <text|paste> - prove and seal a multisig descriptor",
        "registrations          - every registered wallet, with its descriptor",
        "address <id> <r|c> <n> - one address of a registered wallet",
        "psbtload <hex|paste>   - load a PSBT; also psbtload sd <path>",
        "psbtinspect            - the review facts: ownership, amounts, fee, refusals",
        "psbtsign               - sign the reviewed PSBT and print it as hex",
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
        "HIL|status|provenance={}|state={}|unlocked={unlocked}|failures={failures}|         attempts_left={attempts:?}|wipe_after={}|min_pin_len={}|policy_gen={}|epoch={epoch}|         next_seq={next_seq}|boot_count={:?}|tamper={tamper:?}",
        r.provenance,
        store::state_label(state),
        policy.wipe_after, policy.min_pin_len, policy.policy_gen,
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

/// The wallet record's magic, `crate::wallet::record`'s private `WALLET_MAGIC`.
///
/// Spelled out here rather than imported for two reasons. It belongs to the module that
/// defines the format, and - the one that decides - recognising the body must not depend on
/// parsing it. `WalletRecord::decode` is the wrong instrument for this question: it answers
/// "is this a record I can read", and the bodies that most need withholding are the ones
/// that answer no.
///
/// COUPLING. record.rs states that the magic IS the format version and that a future
/// revision takes a NEW token rather than a flag inside this one. When one lands it joins
/// this check, or `read` starts printing recovery phrases again.
const WALLET_RECORD_MAGIC: [u8; 4] = *b"NYW1";

/// Read a payload slot back.
///
/// INVARIANT (the module's rule, applied to the one command that could break it). This
/// console may print what the operator supplied and what is public, never what the device
/// derived or stored as a secret.
///
/// The rule bites here because `crate::wallet` seals its `WalletRecord` into the SAME
/// `SlotClass::Payload` that [`seal`] writes bench payloads into, and record.rs appends the
/// normalized BIP-39 phrase raw into that body. Rendering a payload slot as text was
/// harmless while `seal` was the only writer - the operator was reading back a string the
/// operator had typed. Against a wallet slot the same line is a seed disclosure over UART,
/// on a console with no PIN gate at all.
///
/// So the BODY decides, before anything is rendered, and it decides on the magic alone:
/// a body that CLAIMS to be a wallet record is described and never printed, whether or not
/// it parses. Fail-closed on purpose. A truncated record, a record with trailing bytes and
/// a record from a format this build half understands all still carry the phrase, and a
/// check that only fired on records which decode cleanly would open on precisely the
/// damaged records an operator reaches for `read` to inspect.
///
/// The command is kept whole rather than deleted: it is the read-back half of the manual
/// power-cut gate ([`soak`]'s docs) and the only way to see what survived a cut. What it
/// loses against a wallet slot is the phrase, and nothing else - the length, the digest, the
/// structure and the provenance are all still on the line, which is what storage debugging
/// was ever about.
fn read(s: &mut Store, rest: &str) {
    let Some(slot) = rest.parse::<u8>().ok() else {
        log::error!("HIL|read|err=usage|want=read <slot>");
        return;
    };
    let mut out = [0u8; 3072];
    match s.read_payload(slot, &mut out) {
        Ok(n) => {
            let body = &out[..n];
            // Length and digest are structure rather than content: they identify the bytes
            // for a transcript without describing them, so they ride on both arms.
            let head = format!(
                "HIL|read|ok=true|slot={slot}|len={n}|sha256={}",
                hex(&Sha256::digest(body))
            );
            match describe_wallet_body(body) {
                Some(fields) => log::info!(
                    "{head}|kind=wallet_record|{fields}|text=<withheld_this_body_holds_the_recovery_phrase>"
                ),
                None => log::info!("{head}|kind=opaque|text={}", String::from_utf8_lossy(body)),
            }
        }
        Err(e) => log::error!("HIL|read|ok=false|slot={slot}|err={e}"),
    }
}

/// `Some(fields)` when `body` claims to be a wallet record, `None` when it cannot be one.
///
/// What comes back is structure and provenance only: the magic, the format version the
/// magic IS, the master fingerprint, the network and the label. Each of those is public or
/// operator-supplied - the fingerprint is the value a coordinator already holds and
/// `wallet open` already prints, the network is on the wire in every address the device
/// renders, and the label is what the operator typed at `wallet new`.
///
/// The phrase is the field this function exists to leave out, and it is left out on the
/// success path too: the decoded record is dropped at the end of the match arm and its
/// phrase is `Zeroizing`, so the only copy this function makes wipes itself.
fn describe_wallet_body(body: &[u8]) -> Option<String> {
    if !body.starts_with(&WALLET_RECORD_MAGIC) {
        return None;
    }
    // Every byte of the magic is ASCII by construction; the fallback keeps a future magic
    // that is not ASCII from costing the operator the whole line.
    let magic = core::str::from_utf8(&WALLET_RECORD_MAGIC).unwrap_or("<non_ascii>");
    Some(match WalletRecord::decode(body) {
        Ok(r) => format!(
            "magic={magic}|decoded=true|network={:?}|fingerprint={}|label={}|label_bytes={}",
            r.network,
            r.fingerprint,
            r.label,
            r.label.len()
        ),
        // A body carrying the magic that will not decode is the case this whole check is
        // shaped around. It is still a wallet record, it still has a phrase in it, and the
        // reason it will not parse is exactly what a storage debugger came here to read -
        // so the reason is printed and the body is not.
        Err(e) => format!("magic={magic}|decoded=false|variant={e:?}|reason={e}"),
    })
}

fn change_pin(s: &mut Store, rest: &str) {
    let Some(pin) = parse_pin(rest) else { return };
    match s.change_pin(&pin) {
        Ok(ms) => log::info!("HIL|changepin|ok=true|ms={ms}"),
        Err(e) => log::error!("HIL|changepin|ok=false|err={e}"),
    }
}

fn set_policy_cmd(s: &mut Store, rest: &str) {
    let parts: Vec<&str> = rest.split_whitespace().collect();
    let (Some(wipe_str), Some(min_pin_str), Some(pin_str)) = (
        parts.first().copied(),
        parts.get(1).copied(),
        parts.get(2).copied(),
    ) else {
        log::error!("HIL|setpolicy|err=usage|want=setpolicy <wipe_after|off> <min_pin_len> <pin>");
        return;
    };
    let Some(pin) = parse_pin(pin_str) else { return };
    let wipe_after = if wipe_str == "off" || wipe_str == "0" {
        0u8
    } else {
        match wipe_str.parse::<u8>() {
            Ok(n) if (3..=25).contains(&n) => n,
            Ok(_) => {
                log::error!("HIL|setpolicy|err=bad_range|hint=3..=25 or off");
                return;
            }
            Err(_) => {
                log::error!("HIL|setpolicy|err=bad_arg|hint=<n>|off");
                return;
            }
        }
    };
    let min_pin_len: u8 = match min_pin_str.parse() {
        Ok(n) => n,
        Err(_) => {
            log::error!("HIL|setpolicy|err=bad_min_pin_len");
            return;
        }
    };
    match s.set_policy_full(&pin, wipe_after, min_pin_len) {
        Ok(p) => log::info!("HIL|setpolicy|ok=true|wipe_after={}|min_pin_len={}|policy_gen={}",
            if p.wipe_after == 0 { "off".to_string() } else { p.wipe_after.to_string() },
            p.min_pin_len, p.policy_gen),
        Err(e) => log::error!("HIL|setpolicy|ok=false|err={e}"),
    }
}

fn policy_soak_cmd(s: &mut Store, rest: &str) {
    let parts: Vec<&str> = rest.split_whitespace().collect();
    let (Some(wipe_a), Some(wipe_b), Some(min_pin_str), Some(pin_str), Some(n)) = (
        parts.first().copied(),
        parts.get(1).copied(),
        parts.get(2).copied(),
        parts.get(3).copied(),
        parts.get(4).and_then(|t| t.parse::<u32>().ok()),
    ) else {
        log::error!("HIL|policysoak|err=usage|want=policysoak <wipe_a> <wipe_b> <min_pin_len> <pin> <n>");
        return;
    };
    let Some(pin) = parse_pin(pin_str) else { return };
    let min_pin_len: u8 = match min_pin_str.parse() {
        Ok(n) => n,
        Err(_) => { log::error!("HIL|policysoak|err=bad_min_pin_len"); return; }
    };
    for i in 0..n {
        let wipe_str = if i % 2 == 0 { wipe_a } else { wipe_b };
        let wipe_after = if wipe_str == "off" || wipe_str == "0" { 0u8 } else {
            match wipe_str.parse::<u8>() { Ok(n) => n, Err(_) => { log::error!("HIL|policysoak|err=bad_wipe"); return; } }
        };
        // Announce each step with a delay between them, so cuts can land at
        // different points in the 7-step commit. The harness reads the LAST
        // about_to_step line before the port vanishes, so spacing these out
        // across the Argon2id + commit window gives real step coverage.
        let steps = ["Y1", "Y2", "Y3", "Y4", "Y5", "Y6", "Y7"];
        for step in &steps {
            log::info!("HIL|policysoak|about_to_step|i={i}|step={step}|wipe_after={wipe_after}");
            // Delay 400ms between steps - 7 steps * 400ms = 2.8s spread,
            // plus the ~3.5s Argon2id in set_policy_full = ~6.3s total window.
            // The harness delay window (40..4000ms) will land cuts at different steps.
            std::thread::sleep(std::time::Duration::from_millis(400));
        }
        match s.set_policy_full(&pin, wipe_after, min_pin_len) {
            Ok(p) => log::info!("HIL|policysoak|done|i={i}|wipe_after={}|policy_gen={}",
                if p.wipe_after == 0 { "off".to_string() } else { p.wipe_after.to_string() }, p.policy_gen),
            Err(e) => { log::error!("HIL|policysoak|failed|i={i}|err={e}"); return; }
        }
    }
    log::info!("HIL|policysoak|complete|count={n}");
}

fn remove_pin_cmd(s: &mut Store, rest: &str) {
    let Some(pin) = parse_pin(rest) else { return };
    match s.remove_pin(&pin) {
        Ok(d) => log::info!("HIL|removepin|ok=true|wallets={}|registrations={}|identities={}",
            d.wallets, d.registrations, d.identities),
        Err(e) => log::error!("HIL|removepin|ok=false|err={e}"),
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
        let Some(scratch) = s.scratch_mut().map(PsramScratch::borrow) else {
            log::error!("HIL|kat|err=no_argon2_working_set");
            return;
        };
        let session = match v.format(&pin, KAT_LABEL, scratch) {
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

// -------------------------------------------------------------------------------------
// The release loop
// -------------------------------------------------------------------------------------
//
// MILESTONES.md section 9 clause 2 is the only clause that can fail 0.2.0 on its own: a
// working wallet doing the whole loop on real hardware - create or import a seed, save it
// under a PIN, power cycle, unlock, register a 2-of-3 P2WSH multisig, verify the first
// receive address, load a PSBT, review it, sign it, hand the result to a coordinator. The
// screens that will drive that loop for a user are m4b's. These commands drive it over the
// wire TODAY, so the gate can be attempted, captured and read before the screens exist,
// and so that when the screens arrive there is a transcript to compare them against.
//
// THEY DRIVE THE PRODUCT PATH, NOT A COPY OF IT. Every one of them goes through
// `crate::wallet::Wallet` and `crate::signing`, which is the same sequence a screen will
// call: `Wallet::open` for the seed and the re-proven registry, `Wallet::register` for a
// descriptor, `signing::review` for the checks with no seed in scope, `Review::sign` for
// the signature and its post-sign gate. A console that reimplemented any of that would be
// evidence about the console. This one is evidence about the device.
//
// The command names are `tools/hil/end-to-end-loop.ps1`'s vocabulary - it probes `help` and
// reports which steps of the clause the device cannot yet be driven through. `register`,
// `address`, `psbtload`, `psbtinspect` and `psbtsign` are the names it looks for; renaming
// one here silently reopens the gap that script exists to measure.
//
// INVARIANT (the one this section makes load-bearing). The console could already format,
// seal and erase the store with no PIN. It can now SIGN. A shipped image containing it
// would be a signer that signs on command from a serial port, which is the worst defect
// this project could produce. Two fences were meant to stand between that and a release,
// and only the first exists: `firmware/build.rs` panics when `hil-console` is on in a
// release profile, and it cannot be unified away because it stops the artefact existing.
// The belt-and-braces gate `firmware/Cargo.toml` names - `tools/ci/check-release-symbols.sh`,
// which would assert these symbols are absent from a shipped binary - was still missing
// when signing landed here (docs/KNOWN-ISSUES.md K3). Until it exists, the profile fence is
// the whole of the defence, and it is now guarding a signer rather than a store editor.
//
// INVARIANT (what may be printed). The module docs allow PINs on the wire because a bench
// operator has no other way to type one; a BIP39 passphrase is the same class of value and
// joins them as an INPUT, echoed by the same dispatch line as every other argument. Nothing
// DERIVED joins them. The seed lives in `crate::wallet::Wallet`, whose accessor is
// crate-private and whose `Debug` redacts, and this file never asks for it. What these
// commands print is public by construction: a master fingerprint, a descriptor, an address,
// a cosigner's public key, an amount, a fee, a signature, a signed transaction.

/// Longest value the paste buffer will hold, in characters.
///
/// 64 KiB of hex is 32 KiB of PSBT: past any transaction this device is meant to review,
/// and far short of anything that could crowd PSRAM beside the framebuffers and the Argon2
/// arena. `StructuralLimits::max_psbt_bytes` is a megabyte, but a megabyte does not arrive
/// over a 115200 baud line in a bench session, so the console's own bound is the one that
/// decides.
const PASTE_MAX: usize = 64 * 1024;

/// Hex characters per emitted line. Long enough that a few-kilobyte PSBT is a handful of
/// lines, short enough that one `log::info!` cannot hold the polling TX path for long.
const HEX_CHUNK: usize = 512;

/// The working set the release-loop commands keep between lines.
///
/// Only the network is the console's own state. The seed, the registry and the wallet
/// record all live in [`Wallet`], sealed under the PIN, which is what makes the clause's
/// power-cycle step mean something: after the cut the only way back to any of it is
/// `unlock` and `wallet open`. A console that cached a registry in RAM would make the step
/// prove nothing.
struct Bench {
    /// The chain a NEW wallet is created on.
    ///
    /// Used by `wallet new` and by nothing else - once a wallet is open, its own record's
    /// network is what every check runs against, because a device fact that a file or a
    /// console setting could move is not a device fact (see `crate::wallet`). It is the
    /// console's own setting rather than the UI's so that a transcript states which chain
    /// it was taken on, and it defaults to the product network so a mistake is a refusal
    /// rather than a signature on the wrong chain.
    network: Network,
    /// The open wallet. Secret-bearing; never printed, never `{:?}`-ed except through
    /// `Wallet`'s own redacting `Debug`.
    wallet: Option<Wallet>,
    /// Accumulator for values longer than one command line.
    paste: String,
    /// The PSBT bytes as they were loaded. Kept as bytes because that is what
    /// `signing::review` takes and what the transcript's digest is about.
    file: Option<Vec<u8>>,
    /// The review `psbtsign` acts on.
    ///
    /// Held rather than recomputed inside `psbtsign` so the console enforces what the
    /// product enforces: a signature follows a review of the same bytes. `Review::sign`
    /// proves the "same bytes" half for itself - `psbt::sign` recomputes the file's
    /// identity - and checks the wallet is the one the review was taken under. What the
    /// cache adds is that the transcript SHOWS the review happened, and that a review whose
    /// inputs have since changed cannot authorise anything.
    review: Option<Review>,
}

impl Bench {
    fn new() -> Bench {
        Bench {
            network: Network::Bitcoin,
            wallet: None,
            paste: String::new(),
            file: None,
            review: None,
        }
    }
}

/// Drop the cached review.
///
/// Called from every command that changes an input to `signing::review` - the wallet, the
/// registry it carries, or the loaded file. One function rather than a rule spread over the
/// call sites, so that adding such a command is a one-line obligation instead of something
/// to remember.
fn invalidate_review(bench: &mut Bench) {
    if bench.review.take().is_some() {
        log::info!("HIL|review|invalidated=true|note=an_input_to_review_changed_run_psbtinspect_again");
    }
}

// --- the console's own settings -------------------------------------------------------

/// Show or set the chain a new wallet is created on.
fn network_cmd(bench: &mut Bench, rest: &str) {
    if rest.is_empty() {
        log::info!(
            "HIL|network|new_wallets={:?}|open_wallet={}",
            bench.network,
            bench
                .wallet
                .as_ref()
                .map_or_else(|| "-".to_string(), |w| format!("{:?}", w.network()))
        );
        return;
    }
    let Some(network) = parse_network(rest) else {
        log::error!(
            "HIL|network|err=usage|want=network <bitcoin|testnet|signet|regtest>|got={rest}"
        );
        return;
    };
    bench.network = network;
    // Deliberately NOT invalidating the review or closing the wallet: this setting does not
    // reach an open wallet at all. Its network came out of its sealed record and stays
    // there for the whole of that wallet's life.
    log::info!("HIL|network|ok=true|new_wallets={network:?}");
}

/// Accumulate a value too long for one command line.
///
/// `paste begin` clears, a bare chunk appends, `paste nl` appends one newline and
/// `paste end` reports what accumulated. The digest in that report is the point: it is how
/// an operator proves the device received the coordinator's descriptor or PSBT and not a
/// line-noise variant of it, BEFORE anything acts on the bytes.
///
/// Whitespace at the ends of a chunk is not preserved - the dispatcher trims it - which is
/// why `paste nl` exists rather than being spelled with a space, and why this is for hex
/// and descriptors, neither of which carries meaningful whitespace. A multi-line Coldcard
/// setup file is fed with `paste nl` between its lines.
fn paste_cmd(bench: &mut Bench, rest: &str) {
    match rest {
        "begin" | "reset" => {
            bench.paste.clear();
            log::info!("HIL|paste|reset=true");
            return;
        }
        "end" | "" => {
            log::info!(
                "HIL|paste|len={}|sha256={}",
                bench.paste.len(),
                hex(&Sha256::digest(bench.paste.as_bytes()))
            );
            return;
        }
        "nl" => {
            bench.paste.push('\n');
            log::info!("HIL|paste|appended=newline|len={}", bench.paste.len());
            return;
        }
        _ => {}
    }
    if bench.paste.len() + rest.len() > PASTE_MAX {
        log::error!(
            "HIL|paste|err=overflow|len={}|adding={}|max={PASTE_MAX}",
            bench.paste.len(),
            rest.len()
        );
        return;
    }
    bench.paste.push_str(rest);
    log::info!("HIL|paste|appended={}|len={}", rest.len(), bench.paste.len());
}

// --- the wallet -----------------------------------------------------------------------

/// Create, open, close or describe the wallet the rest of the loop runs on.
///
/// `wallet new` is clause 2's "import a seed and save it under a PIN" and `wallet open` is
/// its "unlock" - the two halves the power cycle sits between. Neither prints the phrase,
/// the passphrase or anything derived from them; what comes back is the fingerprint, which
/// is four public bytes of the master PUBLIC key and the only honest answer to "which
/// wallet is this".
///
/// A passphrase is positional and `-` means none, because an empty positional argument
/// cannot be typed at a serial terminal. One that contains a space cannot be typed here at
/// all; that is a console limit and not a wallet limit, and it is why the argument is last
/// on `wallet open` and third on `wallet new`.
fn wallet_cmd(store: &mut Option<Store>, bench: &mut Bench, rest: &str) {
    let mut it = rest.splitn(2, ' ');
    let sub = it.next().unwrap_or("");
    let args = it.next().unwrap_or("").trim();

    match sub {
        "" | "status" => report_wallet(bench),
        "close" => {
            // The seed goes with it: `Wallet` is `Zeroizing` inside and wipes on drop.
            let had = bench.wallet.take().is_some();
            invalidate_review(bench);
            log::info!("HIL|wallet|closed={had}");
        }
        "new" => wallet_new(store, bench, args),
        "persist" => wallet_persist(store, bench, args),
        "open" => wallet_open(store, bench, args),
        other => log::error!(
            "HIL|wallet|err=usage|want=wallet <status|new|persist|open|close>|got={other}"
        ),
    }
}

/// `wallet new <slot> <label> <passphrase|-> <words...>`
fn wallet_new(store: &mut Option<Store>, bench: &mut Bench, args: &str) {
    let mut parts = args.splitn(4, ' ');
    let (Some(slot), Some(label), Some(passphrase), Some(phrase)) = (
        parts.next().and_then(|t| t.parse::<u8>().ok()),
        parts.next(),
        parts.next(),
        // Explicitly non-empty. `bip39::seed` derives a perfectly good 64-byte seed from an
        // empty phrase, so an operator who mistyped the command would get a wallet rather
        // than a usage error, and would find out at the first address that did not match.
        parts.next().map(str::trim).filter(|t| !t.is_empty()),
    ) else {
        log::error!(
            "HIL|wallet|err=usage|want=wallet new <slot> <label> <passphrase|-> <words...>"
        );
        return;
    };
    let Some(s) = store.as_mut() else {
        log::error!("HIL|wallet|err=store_unavailable");
        return;
    };
    let new = NewWallet {
        label,
        network: bench.network,
        phrase,
        passphrase: passphrase_of(passphrase),
    };
    match Wallet::save(s, slot, &new) {
        Ok(wallet) => {
            bench.wallet = Some(wallet);
            invalidate_review(bench);
            log::info!("HIL|wallet|new=true|slot={slot}");
            report_wallet(bench);
        }
        Err(e) => log::error!("HIL|wallet|new=false|slot={slot}|variant={e:?}|reason={e}"),
    }
}

/// `wallet persist <label> <fingerprint> <words...>`
///
/// The touchscreen's save path, driven from the bench: the identity arrives as DATA - the
/// fingerprint the panel showed and the user approved - and the store picks the slot, both
/// exactly as `answer_persist_wallet` does it.
///
/// It exists because `wallet new` cannot prove the property that matters here. That command
/// derives its own fingerprint from a passphrase it was handed, so it can only ever store
/// an identity it computed; this one stores one it was told. Seal a wallet under the
/// fingerprint its PASSPHRASE produces, then `wallet open <slot> <passphrase>` - which
/// re-derives and compares - and the round trip is the proof that the record certifies the
/// wallet the user confirmed rather than the empty-passphrase one.
///
/// No wallet is opened: there is no passphrase here and therefore no seed, so the bench's
/// open wallet is left exactly as it was.
fn wallet_persist(store: &mut Option<Store>, bench: &Bench, args: &str) {
    let mut parts = args.splitn(3, ' ');
    let (Some(label), Some(fingerprint), Some(phrase)) = (
        parts.next().filter(|t| !t.is_empty()),
        parts.next(),
        // Explicitly non-empty, for the reason `wallet new` gives: an empty phrase seals a
        // wallet rather than reporting a mistyped command.
        parts.next().map(str::trim).filter(|t| !t.is_empty()),
    ) else {
        log::error!(
            "HIL|wallet|err=usage|want=wallet persist <label> <fingerprint> <words...>"
        );
        return;
    };
    let Some(s) = store.as_mut() else {
        log::error!("HIL|wallet|err=store_unavailable");
        return;
    };
    // The console persists a passphrase-free wallet: it has no way to collect one, and a
    // record that claimed a passphrase it does not hold could never be reopened.
    let new = match SealedWallet::confirmed(
        label,
        bench.network,
        phrase,
        fingerprint,
        StoredPassphrase::None,
    ) {
        Ok(new) => new,
        Err(e) => {
            log::error!("HIL|wallet|persist=false|variant={e:?}|reason={e}");
            return;
        }
    };
    match Wallet::seal_into_free_slot(s, &new) {
        Ok(slot) => log::info!("HIL|wallet|persist=true|slot={slot}|fingerprint={fingerprint}"),
        Err(e) => log::error!("HIL|wallet|persist=false|variant={e:?}|reason={e}"),
    }
}

/// `wallet open <slot> [passphrase]`
fn wallet_open(store: &mut Option<Store>, bench: &mut Bench, args: &str) {
    let mut parts = args.splitn(2, ' ');
    let Some(slot) = parts.next().and_then(|t| t.parse::<u8>().ok()) else {
        log::error!("HIL|wallet|err=usage|want=wallet open <slot> [passphrase]");
        return;
    };
    let passphrase = passphrase_of(parts.next().unwrap_or("").trim());
    let Some(s) = store.as_mut() else {
        log::error!("HIL|wallet|err=store_unavailable");
        return;
    };
    let t0 = Instant::now();
    match Wallet::open(s, slot, passphrase) {
        Ok(wallet) => {
            bench.wallet = Some(wallet);
            invalidate_review(bench);
            log::info!("HIL|wallet|open=true|slot={slot}|ms={}", t0.elapsed().as_millis());
            report_wallet(bench);
        }
        // `PassphraseMismatch` carries the two fingerprints, which are public: the one the
        // record was sealed with and the one this passphrase derives. Printing both is what
        // turns "wrong passphrase" from a guess into a comparison.
        Err(e) => log::error!("HIL|wallet|open=false|slot={slot}|variant={e:?}|reason={e}"),
    }
}

/// What is open, and what did not survive the registry's re-proof at open time.
///
/// The fault lines matter as much as the wallet line. A registration that vanished silently
/// is a multisig wallet the user believes is registered and is not, and the next PSBT from
/// it would be refused with nothing to say why.
fn report_wallet(bench: &Bench) {
    let Some(w) = bench.wallet.as_ref() else {
        log::info!(
            "HIL|wallet|open=false|new_wallet_network={:?}|note=run_unlock_then_wallet_open_<slot>",
            bench.network
        );
        return;
    };
    log::info!(
        "HIL|wallet|open=true|slot={}|label={}|network={:?}|fingerprint={}|         registrations={}|registry_faults={}",
        w.slot(),
        w.label(),
        w.network(),
        w.fingerprint(),
        w.registrations().len(),
        w.registry_faults().len(),
    );
    for fault in w.registry_faults() {
        log::error!(
            "HIL|wallet|registry_fault|slot={}|variant={:?}|reason={}",
            fault.slot, fault.reason, fault.reason
        );
    }
}

// --- multisig registration ------------------------------------------------------------

/// Read a multisig wallet description, prove this device is a member of it, and seal it.
///
/// `Wallet::register` is the whole of the work: `multisig::parse` autodetects the dialect,
/// `Pending::verify` derives our own key at the origin the file claims and compares it -
/// the 2021 xpub-substitution defence - and only what that returns is ever written. A
/// wallet this device cannot prove membership of is refused and never stored, so nothing
/// `psbtinspect` later calls "ours" rests on a file's say-so.
///
/// The first receive address is printed because it is clause 2's next step: the operator
/// reads it against another signer's, and two independent implementations agreeing on it is
/// what says both are registered into the same wallet.
fn register_cmd(store: &mut Option<Store>, bench: &mut Bench, rest: &str) {
    let mut it = rest.splitn(2, ' ');
    let (Some(label), Some(source)) = (it.next().filter(|t| !t.is_empty()), it.next()) else {
        log::error!("HIL|register|err=usage|want=register <label> <descriptor> OR register <label> paste");
        return;
    };
    let text = if source.trim() == "paste" {
        bench.paste.clone()
    } else {
        source.trim().to_string()
    };
    let Some(s) = store.as_mut() else {
        log::error!("HIL|register|err=store_unavailable");
        return;
    };
    // The wallet borrow is scoped to the call that needs it, so the reporting below can
    // take `bench` again without the two overlapping.
    let outcome = {
        let Some(wallet) = bench.wallet.as_mut() else {
            log::error!("HIL|register|err=no_wallet|note=run_wallet_open_first");
            return;
        };
        wallet.register(s, label, &text)
    };

    match outcome {
        Ok(id) => {
            log::info!("HIL|register|ok=true|label={label}|id={id}");
            // The registry is an input to every review from here on.
            invalidate_review(bench);
            report_registrations(bench, Some(id.to_string().as_str()));
        }
        Err(e) => log::error!("HIL|register|ok=false|label={label}|variant={e:?}|reason={e}"),
    }
}

/// Every wallet the open wallet is a proven member of.
fn registrations_cmd(bench: &mut Bench) {
    report_registrations(bench, None);
}

/// Print the registry, or one member of it.
///
/// Every field is public. The descriptor is the value another signer is registered with,
/// the cosigner fingerprints are what a user compares by eye, and the address is the one
/// clause 2 asks to be verified against a second implementation.
fn report_registrations(bench: &Bench, only: Option<&str>) {
    let Some(w) = bench.wallet.as_ref() else {
        log::error!("HIL|registrations|err=no_wallet");
        return;
    };
    let registrations = w.registrations();
    if only.is_none() {
        log::info!("HIL|registrations|count={}", registrations.len());
    }
    for (at, r) in registrations.iter().enumerate() {
        let id = r.id().to_string();
        if only.is_some_and(|want| want != id) {
            continue;
        }
        let (m, n) = r.threshold_of();
        let first = r
            .first_receive_address()
            .map_or_else(|| "-".to_string(), |a| a.to_string());
        log::info!(
            "HIL|registration|i={at}|id={id}|m={m}|n={n}|script={}|network={:?}|         ours={}|our_position={}|first_receive={first}",
            r.script(),
            r.network(),
            r.ours().fingerprint,
            r.our_position(),
        );
        for (position, cosigner) in r.cosigners().iter().enumerate() {
            log::info!(
                "HIL|registration|i={at}|id={id}|cosigner={position}|fingerprint={}|         origin={}|ours={}",
                cosigner.fingerprint,
                cosigner.origin,
                position == r.our_position(),
            );
        }
        log::info!("HIL|registration|i={at}|id={id}|descriptor={}", r.descriptor());
    }
}

/// Derive one address of a registered wallet.
///
/// `<who>` is the registration id as `registrations` prints it, or `#N` for its position in
/// that listing. The id is content-derived - it is the descriptor's BIP-380 checksum - so
/// naming a wallet by it means the same thing on every device that holds it, which a
/// position would not.
fn address_cmd(bench: &mut Bench, rest: &str) {
    let parts: Vec<&str> = rest.split_whitespace().collect();
    let (Some(who), Some(keychain), Some(index)) = (
        parts.first().copied(),
        parts.get(1).and_then(|t| parse_keychain(t)),
        parts.get(2).and_then(|t| parse_u32(t)),
    ) else {
        log::error!("HIL|address|err=usage|want=address <id|#n> <receive|change> <index>");
        return;
    };
    let Some(w) = bench.wallet.as_ref() else {
        log::error!("HIL|address|err=no_wallet");
        return;
    };
    let Some(at) = find_registration(w.registrations(), who) else {
        log::error!("HIL|address|err=no_such_registration|who={who}");
        return;
    };
    let Some(child) = ChildIndex::new(index) else {
        log::error!("HIL|address|err=index_hardened|index={index}|max={}", ChildIndex::MAX);
        return;
    };
    let registration = &w.registrations()[at];
    let Some(entry) = AddressSource::Multisig(registration).entry(keychain, child) else {
        log::error!(
            "HIL|address|err=no_leaf|id={}|keychain={keychain}|index={index}",
            registration.id()
        );
        return;
    };
    log::info!(
        "HIL|address|ok=true|id={}|keychain={keychain}|index={index}|addr={}|our_path={}|         witness_script={}",
        registration.id(),
        entry.address,
        entry.our_path(),
        entry.witness_script.as_deref().unwrap_or("-"),
    );
    for (position, path) in entry.paths.iter().enumerate() {
        log::info!(
            "HIL|address|id={}|keychain={keychain}|index={index}|signer={position}|path={path}|         ours={}",
            registration.id(),
            position == entry.ours,
        );
    }
}

// --- PSBT: load, review, sign ---------------------------------------------------------

/// Load a PSBT.
///
/// `psbtload <hex>` for a file short enough to fit one line, `psbtload paste` for the
/// buffer, `psbtload sd <path>` for a card. The digest of the loaded bytes is printed so a
/// transcript can be matched against the coordinator's file before anything is reviewed.
///
/// Nothing is parsed here. `signing::review` is the only entry to the pipeline and its
/// first act is `psbt::decode`, so a file that is not a PSBT is refused there, once, with
/// the sentence that belongs to it - a second decode here would be a second opinion about
/// the same bytes.
///
/// COUPLING (SD). `firmware/src/sd/` did not exist when this landed, so the `sd` form is
/// grammar and a refusal rather than a read. It is here rather than added later because
/// neither the harness nor the operator's muscle memory should change when the card
/// arrives: wiring it is one call in [`read_sd_file`], and everything downstream of that is
/// already written against bytes.
fn psbt_load(bench: &mut Bench, rest: &str) {
    let mut it = rest.splitn(2, ' ');
    let head = it.next().unwrap_or("");
    let tail = it.next().unwrap_or("").trim();

    let bytes = match head {
        "" => {
            log::error!(
                "HIL|psbtload|err=usage|want=psbtload <hex> OR psbtload paste OR psbtload sd <path>"
            );
            return;
        }
        "sd" => match read_sd_file(tail) {
            Ok(b) => b,
            Err(e) => {
                log::error!("HIL|psbtload|ok=false|source=sd|path={tail}|err={e}");
                return;
            }
        },
        "paste" => match parse_hex(&bench.paste) {
            Some(b) => b,
            None => {
                log::error!(
                    "HIL|psbtload|ok=false|source=paste|err=not_hex|len={}",
                    bench.paste.len()
                );
                return;
            }
        },
        inline => match parse_hex(inline) {
            Some(b) => b,
            None => {
                log::error!(
                    "HIL|psbtload|ok=false|source=inline|err=not_hex|len={}",
                    inline.len()
                );
                return;
            }
        },
    };

    // A review is about the file that was reviewed. A new file has not been.
    invalidate_review(bench);
    log::info!(
        "HIL|psbtload|ok=true|bytes={}|sha256={}",
        bytes.len(),
        hex(&Sha256::digest(&bytes)),
    );
    bench.file = Some(bytes);
}

/// Print the review facts, or the refusal.
///
/// This is the command the whole section exists for. Until m4b's review screens land, these
/// lines ARE the review, and clause 2 asks a human to check that the device is showing the
/// truth - so what is printed is what a screen would have to show and nothing less: every
/// input's amount and whether that amount is proven, whether the input is ours and by which
/// path, every output's amount and address and whether the device could prove it is change,
/// the fee, and whether the fee is a number anyone is bound to.
///
/// `fee_enforced=false` is not a refusal and must not be read as one. `ReviewedFee::Stated`
/// says the figure rests on amounts the file asserted rather than on amounts anything
/// proved, which is a different sentence from the fee being wrong; the input rows say which
/// amounts those are. The engine has already refused outright every file where the
/// difference could cost the user money (`UnprovenAmountBesideOurSignature`).
fn psbt_inspect(bench: &mut Bench) {
    let Some(wallet) = bench.wallet.as_ref() else {
        log::error!("HIL|psbtinspect|err=no_wallet|note=the_wallet_decides_which_inputs_are_ours");
        return;
    };
    let Some(file) = bench.file.as_ref() else {
        log::error!("HIL|psbtinspect|err=no_psbt|note=run_psbtload_first");
        return;
    };
    let review = match signing::review(wallet, file) {
        Ok(r) => r,
        Err(e) => {
            // Refusals are singular by construction: `inspect` returns the FIRST check that
            // said no, because a device that kept validating past a refusal would be
            // reporting on a file it had already decided not to sign. The Debug form carries
            // every field of the reason; the Display form is the sentence a screen shows.
            report_refusal("psbtinspect", &e);
            bench.review = None;
            return;
        }
    };

    let (input_total, output_total) = review.totals();
    let (fee_sat, fee_enforced) = match review.fee() {
        ReviewedFee::Enforced(fee) => (fee.to_sat(), true),
        ReviewedFee::Stated(fee) => (fee.to_sat(), false),
    };
    let unproven_inputs = review
        .inputs()
        .iter()
        .filter(|i| i.amount_proof == AmountProof::ClaimedByFile)
        .count();
    let change_sat: u64 = review
        .outputs()
        .iter()
        .filter(|o| o.role.is_change())
        .map(|o| o.value.to_sat())
        .sum();
    let unproven_ours = review
        .outputs()
        .iter()
        .filter(|o| matches!(o.role, OutputRole::ClaimedButUnproven))
        .count();

    // The file's own digest rides on the verdict line so a transcript never has to be read
    // backwards to learn which bytes were reviewed.
    log::info!(
        "HIL|psbtinspect|ok=true|network={:?}|fingerprint={}|file_bytes={}|file_sha256={}|         serialized_len={}|inputs={}|outputs={}|signable={}|in_total_sat={}|out_total_sat={}|         fee_sat={fee_sat}|fee_enforced={fee_enforced}|unknown_fields={}|locktime={}|rbf={}|         psbt_id={}",
        review.network(),
        review.fingerprint(),
        file.len(),
        hex(&Sha256::digest(file)),
        review.serialized_len(),
        review.inputs().len(),
        review.outputs().len(),
        review.signable_inputs(),
        input_total.to_sat(),
        output_total.to_sat(),
        review.unknown_fields(),
        review.lock_time(),
        review.rbf_signaled(),
        hex(&review.psbt_id()),
    );

    for facts in review.inputs() {
        let (claim, path) = match &facts.claim {
            Claim::Ours { path, .. } => ("ours", path.to_string()),
            Claim::Foreign => ("foreign", "-".to_string()),
        };
        // Upper case on the caveat, because this is the one input fact a reader must not
        // skim: the amount beside it is the file's word, not this device's finding.
        let proof = match facts.amount_proof {
            AmountProof::ProvenByPrevTx => "proven_by_prev_tx",
            // Lower case: the number came off the file, but a signature this device is
            // about to add makes it binding, so a transcript reader has nothing to act on.
            // The upper case above is reserved for the one state that is a caveat.
            AmountProof::BoundByOurSignature => "bound_by_our_signature",
            AmountProof::ClaimedByFile => "CLAIMED_BY_FILE",
        };
        let multisig = facts.multisig.as_ref().map_or_else(
            || "-".to_string(),
            |b| format!("{}@{}/{}", b.registration, b.keychain, b.address_index),
        );
        let our_key = facts
            .multisig
            .as_ref()
            .map_or_else(|| "-".to_string(), |b| b.our_key.to_string());
        log::info!(
            "HIL|psbtinspect|in|i={}|outpoint={}|value_sat={}|amount={proof}|kind={:?}|         claim={claim}|path={path}|multisig={multisig}|our_key={our_key}",
            facts.index,
            facts.outpoint,
            facts.value.to_sat(),
            facts.kind,
        );
    }

    for facts in review.outputs() {
        let (role, reg, index) = match facts.role {
            OutputRole::Payment => ("payment", "-".to_string(), "-".to_string()),
            OutputRole::ClaimedButUnproven => {
                ("CLAIMED_BUT_UNPROVEN", "-".to_string(), "-".to_string())
            }
            // Destructured by name because `Owner` is what the role carries now, and
            // `OutputRole`'s own doc makes that name part of the contract with this log
            // site. It renders as the wallet's name either way: a registration id, or an
            // account's scheme and index.
            OutputRole::OwnNotChange { owner, index } => {
                ("own_not_change", owner.to_string(), index.to_string())
            }
            OutputRole::Change { owner, index } => {
                ("change", owner.to_string(), index.to_string())
            }
        };
        // An address is what a user compares against the coordinator's screen; the script is
        // what the transaction actually locks. Both, because a script this device cannot
        // render as an address is exactly the case where only the second one exists.
        let addr = Address::from_script(&facts.script_pubkey, review.network())
            .map_or_else(|_| "-".to_string(), |a| a.to_string());
        log::info!(
            "HIL|psbtinspect|out|i={}|value_sat={}|kind={:?}|claims_our_key={}|role={role}|         reg={reg}|index={index}|addr={addr}|spk={}",
            facts.index,
            facts.value.to_sat(),
            facts.kind,
            facts.claims_our_key,
            hex(facts.script_pubkey.as_bytes()),
        );
    }

    // The line a human reads. "Leaving" is every output the device could NOT prove is
    // change, which is the honest denominator: an output that merely CLAIMS to be ours
    // counts as money going out, exactly as `OutputRole` says it must, because treating a
    // claim as change is the 2019 change-confusion bug.
    log::info!(
        "HIL|psbtinspect|review|leaving_sat={}|change_sat={change_sat}|fee_sat={fee_sat}|         fee_enforced={fee_enforced}|unproven_amount_inputs={unproven_inputs}|         unproven_ours_outputs={unproven_ours}",
        output_total.to_sat() - change_sat,
    );
    bench.review = Some(review);
}

/// Sign the reviewed PSBT and print the result.
///
/// `Review::sign` signs only what the review named, re-derives every claimed key before it
/// trusts it, and re-verifies every signature it produced against a digest recomputed from
/// the PSBT alone. The report those checks produce is printed rather than summarised: a gate
/// whose result nobody can see is a gate nobody can tell has stopped running.
///
/// Stack headroom is printed for the reason `kat` prints it - this is the deepest call this
/// task makes, and a transcript that ends here without it cannot tell an exhausted stack
/// from a hang.
fn psbt_sign(bench: &mut Bench) {
    let Some(wallet) = bench.wallet.as_ref() else {
        log::error!("HIL|psbtsign|err=no_wallet");
        return;
    };
    let Some(review) = bench.review.as_ref() else {
        log::error!(
            "HIL|psbtsign|err=not_reviewed|note=run_psbtinspect_first_a_signature_follows_a_review"
        );
        return;
    };

    let t0 = Instant::now();
    let signed = match review.sign(wallet) {
        Ok(s) => s,
        Err(e) => {
            report_refusal("psbtsign", &e);
            return;
        }
    };
    let ms = t0.elapsed().as_millis();
    let report = signed.report();
    let signed_inputs: Vec<String> = report.inputs_signed.iter().map(|i| i.to_string()).collect();
    log::info!(
        "HIL|psbtsign|ok=true|signatures_added={}|signatures_verified={}|inputs_signed={}|         ms={ms}|main_stack_free={}|main_stack_size={}",
        report.signatures_added,
        report.signatures_verified,
        signed_inputs.join(","),
        store::stack_headroom(),
        store::MAIN_STACK_BYTES,
    );
    emit_hex("psbtsign", signed.bytes());
}

// --- release-loop helpers -------------------------------------------------------------

/// Print a refusal from the signing pipeline with the check it belongs to.
///
/// The check number is what ARCHITECTURE.md 5.3, the refusal screens and this transcript all
/// name a refusal by, so it is recovered here rather than left to whoever reads the log.
/// A malformed file has no check number - it never reached one - and says so.
fn report_refusal(tag: &str, refusal: &Refusal) {
    let check = match refusal {
        Refusal::NotAFile(_) => "-".to_string(),
        Refusal::Check(e) => e.check().number().to_string(),
        Refusal::Sign(e) => e.check().number().to_string(),
        Refusal::WrongWallet { .. } => "-".to_string(),
    };
    log::error!("HIL|{tag}|ok=false|check={check}|variant={refusal:?}|reason={refusal}");
}

/// Read a file off the SD card.
///
/// COUPLING. `firmware/src/sd/` was being written by another workflow when this landed and
/// did not yet exist, so this is the one place the card enters and the one place that has to
/// change when it does: replace the body with that module's read and keep the signature. The
/// error is a sentence rather than a silence because an operator who typed `psbtload sd`
/// needs to know the difference between "no such file" and "this build has no card driver".
///
/// Read only, deliberately. Nothing in this console writes to a card: the airgap crossing
/// this device performs is a file the user carries, and a test console that could also write
/// one would be a second, unreviewed crossing.
fn read_sd_file(path: &str) -> Result<Vec<u8>, String> {
    let _ = path;
    Err("sd_unsupported_in_this_build_no_firmware_src_sd_module_at_compile_time".to_string())
}

/// A positional passphrase argument, where `-` means none.
///
/// An empty argument cannot be typed at a serial terminal, so the absence of a passphrase
/// needs a spelling. `-` is not a BIP39 passphrase anyone would choose and, unlike an empty
/// token, it cannot be produced by a stray space.
fn passphrase_of(text: &str) -> &str {
    if text == "-" {
        ""
    } else {
        text
    }
}

/// Decode an ASCII hex string. Strict: an odd length or a non-hex character is `None` rather
/// than a shorter value, because a PSBT that lost a nibble in transit must not parse as a
/// different PSBT.
fn parse_hex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Emit a value too long for one line, as a header plus numbered chunks.
///
/// The header carries the length and the digest first, so a truncated capture is detectable
/// from the transcript alone: reassemble the chunks, hash them, and the two either agree or
/// the capture is not evidence.
fn emit_hex(tag: &str, bytes: &[u8]) {
    let text = hex(bytes);
    let total = text.as_bytes().chunks(HEX_CHUNK).len();
    log::info!(
        "HIL|{tag}|hex_bytes={}|sha256={}|chunks={total}",
        bytes.len(),
        hex(&Sha256::digest(bytes)),
    );
    for (i, chunk) in text.as_bytes().chunks(HEX_CHUNK).enumerate() {
        // Every byte came out of `hex`, so it is ASCII and the conversion cannot fail; the
        // fallback keeps a formatting slip from costing the operator the whole transcript.
        let piece = core::str::from_utf8(chunk).unwrap_or("<non_ascii>");
        log::info!("HIL|{tag}|hex|i={i}|of={total}|data={piece}");
    }
}

/// Find a registration by its content-derived id, or by `#N` for its listing position.
///
/// Two spellings because they answer different questions. The id is the same value on every
/// device that holds the wallet, which is what a refusal or a transcript should name; the
/// position is what an operator has in front of them after `registrations`. `#` keeps them
/// apart with no guessing - the BIP-380 checksum charset includes digits, so "0" is a
/// legitimate id fragment and length alone could not decide.
fn find_registration(registrations: &[Registration], who: &str) -> Option<usize> {
    if let Some(n) = who.strip_prefix('#') {
        let index = n.parse::<usize>().ok()?;
        return (index < registrations.len()).then_some(index);
    }
    registrations.iter().position(|r| r.id().to_string() == who)
}

fn parse_keychain(text: &str) -> Option<Keychain> {
    match text {
        "receive" | "recv" | "r" => Some(Keychain::Receive),
        "change" | "chg" | "c" => Some(Keychain::Change),
        _ => None,
    }
}

/// The four chains this device knows, spelled as `bitcoin-cli` spells them.
///
/// Written out rather than taken from `FromStr` so an unknown name is a usage error naming
/// the four, and so a future variant of a non-exhaustive `Network` cannot be selected here
/// by a string this console has never been told the meaning of.
fn parse_network(text: &str) -> Option<Network> {
    match text {
        "bitcoin" | "mainnet" | "main" => Some(Network::Bitcoin),
        "testnet" | "test" => Some(Network::Testnet),
        "signet" => Some(Network::Signet),
        "regtest" => Some(Network::Regtest),
        _ => None,
    }
}
