// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Two properties nothing in the suite proves, written the way a regression would break
//! them rather than the way the feature was built.
//!
//! 1. **Q2(a) across the WHOLE pre-PIN Verify sheet.** The existing capacity test renders
//!    one viewport. S-46 is a pager of 13 to 24 viewports, so a count-bearing row below
//!    the fold would pass it. This one walks every page.
//! 2. **Drop-equals-zeroize as a RUNTIME fact.** The crate's `WipesOnDrop` marker is a
//!    claim about a field's TYPE. It cannot see a `String` that reallocated while it was
//!    being typed into, a per-frame temporary, or a `Drop` impl that forgets a field. A
//!    global allocator that scans every freed block for the secret can - so long as it is
//!    really scanning, which is a claim of its own and is why the first test in that half
//!    is a positive control rather than another measurement.

use embedded_graphics::draw_target::DrawTarget;
use embedded_graphics::geometry::{OriginDimensions, Size};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::Pixel;

use notyas_ui::{
    PassphraseState,
    BackupState, LockInfo, Network, Region, RegionId, ScreenId, StoreStatus, TouchEvent, Ui,
    VerifyInfo, WalletInfo, WalletKind, WalletRow, WALLET_SLOTS,
};

// ---------------------------------------------------------------------------------------
// A framebuffer and a driver
// ---------------------------------------------------------------------------------------

struct Fb {
    w: u32,
    h: u32,
    px: Vec<Rgb565>,
}

impl Fb {
    fn render(ui: &Ui, w: u32, h: u32) -> Fb {
        let mut fb = Fb { w, h, px: vec![Rgb565::new(0, 0, 0); (w * h) as usize] };
        ui.draw(&mut fb).unwrap();
        fb
    }
}

impl OriginDimensions for Fb {
    fn size(&self) -> Size {
        Size::new(self.w, self.h)
    }
}

impl DrawTarget for Fb {
    type Color = Rgb565;
    type Error = core::convert::Infallible;
    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        it: I,
    ) -> Result<(), Self::Error> {
        for Pixel(p, c) in it {
            if p.x >= 0 && p.y >= 0 && (p.x as u32) < self.w && (p.y as u32) < self.h {
                self.px[(p.y as u32 * self.w + p.x as u32) as usize] = c;
            }
        }
        Ok(())
    }
}

fn find(ui: &Ui, id: RegionId) -> Option<Region> {
    ui.regions().into_iter().find(|r| r.id == id)
}

fn tap(ui: &mut Ui, id: RegionId) {
    let r = find(ui, id)
        .unwrap_or_else(|| panic!("no region {id:?} on {:?}", ui.screen()))
        .rect;
    let (x, y) = (r.x + r.w / 2, r.y + r.h / 2);
    ui.touch(TouchEvent::Down { x, y });
    ui.touch(TouchEvent::Up { x, y });
}

fn type_keys(ui: &mut Ui, s: &str) {
    for c in s.chars() {
        if c == ' ' {
            tap(ui, RegionId::Space);
        } else {
            tap(ui, RegionId::Key(c));
        }
    }
}

fn locked(w: u32, h: u32) -> Ui {
    let mut ui = Ui::new(w, h);
    ui.set_lock_info(LockInfo {
        status: StoreStatus::Locked,
        device_name: String::from("kitchen-desk"),
        attempts_left: Some(9),
        wipe_after: Some(15),
        ..LockInfo::default()
    });
    assert!(ui.lock());
    ui
}

fn sample_wallets(n: u8) -> Vec<WalletRow> {
    (0..n)
        .map(|i| {
            WalletRow::Wallet(WalletInfo {
                slot: i,
                name: format!("wallet-{i}"),
                fingerprint: format!("a1b2c3d{i}"),
                path: String::from("m/84h/0h/0h"),
                script_type: String::from("native segwit"),
                kind: WalletKind::SingleSig,
                backup: BackupState::Verified(String::new()),
                network: Network::Bitcoin,
                registrations: 0,
                stored: true,
                passphrase: PassphraseState::None,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------------------
// 1. Q2(a) over every viewport of the pre-PIN Verify sheet
// ---------------------------------------------------------------------------------------

/// Walk S-46 from the first page to the last, before the PIN, with an EMPTY store and
/// with a FULL one, and compare every frame. A row that renders the count anywhere in the
/// sheet - not merely in the first viewport the existing test renders - fails here.
#[test]
fn the_whole_pre_pin_verify_sheet_is_identical_with_zero_and_with_eight_wallets() {
    for (w, h) in [(720u32, 720u32), (800u32, 480u32)] {
        let pages = |n: u8| -> Vec<Vec<Rgb565>> {
            let mut ui = locked(w, h);
            ui.set_verify_info(VerifyInfo::default());
            ui.set_wallets(sample_wallets(n));
            tap(&mut ui, RegionId::HomeVerifyDevice);
            assert_eq!(ui.screen(), ScreenId::VerifyDevice);
            let mut out = vec![Fb::render(&ui, w, h).px];
            // Page to the end. The pager stops offering Next on the last viewport, which
            // is what terminates this; the bound is a runaway guard, not the exit.
            for _ in 0..64 {
                if find(&ui, RegionId::ReviewNext).is_none() {
                    break;
                }
                tap(&mut ui, RegionId::ReviewNext);
                let px = Fb::render(&ui, w, h).px;
                if *out.last().unwrap() == px {
                    break; // the pager clamped: we are on the last page
                }
                out.push(px);
            }
            out
        };
        let blank = pages(0);
        let full = pages(WALLET_SLOTS);
        assert!(
            blank.len() > 3,
            "{w}x{h}: the sheet must actually page ({} pages)",
            blank.len()
        );
        assert_eq!(blank.len(), full.len(), "{w}x{h}: the sheet is a different LENGTH");
        for (i, (a, b)) in blank.iter().zip(full.iter()).enumerate() {
            assert_eq!(a, b, "{w}x{h}: pre-PIN Verify page {i} moved with the wallet count");
        }
    }
}

/// The other pre-PIN surface with an input on it. A pad, a bullet row and an attempt line
/// must all be blind to how many wallets the device holds.
#[test]
fn the_pin_screen_is_identical_with_zero_and_with_eight_wallets() {
    for (w, h) in [(720u32, 720u32), (800u32, 480u32)] {
        let frame = |n: u8| {
            let mut ui = locked(w, h);
            ui.set_wallets(sample_wallets(n));
            tap(&mut ui, RegionId::LockWake);
            assert_eq!(ui.screen(), ScreenId::PinEntry);
            for i in 0..4u8 {
                tap(&mut ui, RegionId::PinKey(i));
            }
            Fb::render(&ui, w, h).px
        };
        assert_eq!(frame(0), frame(WALLET_SLOTS), "{w}x{h}: PIN entry counted the wallets");
    }
}

// ---------------------------------------------------------------------------------------
// 2. Drop-equals-zeroize, observed on the heap
// ---------------------------------------------------------------------------------------

// THE INVARIANT THESE LITERALS EXIST TO KEEP. The scanner is global to the process, so
// while any test is armed it sees every thread's frees, not only its own. That is harmless
// only as long as no test puts a needle on the heap outside its own armed window - a stray
// copy freed on another thread is indistinguishable from residue and fails the wrong test.
// So every byte of needle material in this file is `'static`, assembled at compile time.
// `concat!` takes literals only, hence the macros: they are what keeps the needle, the
// padding and the string built from both from being three separately edited copies.
//
// Cost of getting this wrong, measured: `PASSPHRASE_NEEDLE.to_string() + PADDING` used to
// build the seed test's password. `to_string` allocates twelve bytes, `+` reallocates, and
// the abandoned twelve-byte block - the whole needle, intact - was freed on that thread
// whenever it happened to run. Roughly one full-suite run in two failed the UI passphrase
// test on the seed test's litter.

/// The needle: what a user types as a passphrase. Long and unlikely enough that a hit is
/// this passphrase and not a coincidence, and typable on the C9 keyboard.
macro_rules! passphrase_needle {
    () => {
        "zqxjvbkwmpfg"
    };
}

/// Padding typed AFTER the needle. Its job is to force the buffer past the 16-byte
/// growth step a non-preallocated `String` would take, so that if the buffer ever
/// reallocates the abandoned block holds the whole needle. Without it this test cannot
/// tell a preallocated buffer from a grown one (verified: with `secret_buf` reduced to
/// `String::new()` and no padding, the test still passes).
macro_rules! padding {
    () => {
        "abcdefghijklmnopqrstuvwxyzabcdefghij"
    };
}

const PASSPHRASE_NEEDLE: &str = passphrase_needle!();
const PADDING: &str = padding!();
/// The whole passphrase as the user leaves it: needle then padding, as one static string
/// so that handing it to `bip39::seed` costs no allocation of its own.
const TYPED_PASSPHRASE: &str = concat!(passphrase_needle!(), padding!());

/// Six words of a typed phrase: long enough that a hit is this phrase, short enough to sit
/// inside the block a growing buffer abandons.
const PHRASE_NEEDLE: &str = "zoo zoo zoo zoo zoo zoo";

/// The scanning allocator and the dials that aim it, behind the only handle that can turn
/// them.
///
/// The allocator is global to the PROCESS and libtest runs this file's tests as threads of
/// ONE process, so the armed state below is a single instrument shared by every test that
/// measures heap residue. Left as bare statics it was exactly that - one instrument with
/// three tests turning its dials at once - and each of the three interleavings ended in a
/// green run over real residue: a sibling's counter reset landing after a hit and before
/// the read, a sibling's disarm landing between the arming and the frees, a sibling's
/// needle switch sending the scanner hunting for the wrong secret. A security test whose
/// failure mode is to succeed.
///
/// So the dials are private to this module and `Armed` is the only way to reach them. It
/// cannot be constructed without the lock, cannot be constructed without arming, and
/// cannot be dropped without disarming - which makes "armed without exclusive access" a
/// state no caller can write, rather than a rule every future caller has to remember.
/// Serialising the RUN instead (`--test-threads=1`) is a property of one CI invocation: it
/// leaves every `cargo test` typed by hand measuring the untrustworthy thing. The lock
/// travels with the file.
mod scanner {
    use super::{PASSPHRASE_NEEDLE, PHRASE_NEEDLE};
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard, TryLockError};
    use std::time::{Duration, Instant};

    /// Held for the whole armed window, so no second test can arm inside this one's
    /// measurement.
    static SCANNER: Mutex<()> = Mutex::new(());
    /// The dials. Only `Armed` and `Scanning` touch them, and `Relaxed` is enough because
    /// the lock - not these - is what orders one test's window against the next.
    static ARMED: AtomicBool = AtomicBool::new(false);
    static HITS: AtomicUsize = AtomicUsize::new(0);
    static WHICH: AtomicUsize = AtomicUsize::new(0);

    /// The phrase every refused-nesting panic carries. Exported so the test that proves
    /// the refusal still fires can look for the real message instead of a second copy of
    /// it that is free to drift away from this one.
    pub(super) const NESTED_ARM: &str = "Armed::on cannot nest";

    /// How long a caller waits for a window another thread holds before calling it wedged.
    /// Every armed window in this file is milliseconds long and the whole binary finishes
    /// in well under a second, so no amount of ordinary slowness reaches this: it is
    /// reached only by an `Armed` that was leaked (`mem::forget`) or by a test that wedged
    /// while holding one. Bounding the wait is what turns that from a binary CI kills at
    /// the job timeout - no failing test, no message, nothing to attribute it to - into
    /// one assertion that names the thread that was waiting.
    const LOCK_WAIT_LIMIT: Duration = Duration::from_secs(60);
    /// Poll interval while waiting. Contention here is between at most a handful of tests
    /// holding the lock for milliseconds each, so the cost of polling instead of parking
    /// is invisible, and polling is what makes the wait bounded at all.
    const LOCK_POLL: Duration = Duration::from_millis(2);

    /// Which secret the scanner is looking for. An enum rather than the raw discriminant
    /// the atomic stores, so a caller cannot aim the scanner at a needle that does not
    /// exist and then read the zero that follows as proof of anything.
    #[derive(Clone, Copy)]
    pub(super) enum Needle {
        Passphrase,
        Phrase,
    }

    impl Needle {
        fn bytes(self) -> &'static [u8] {
            match self {
                Needle::Passphrase => PASSPHRASE_NEEDLE.as_bytes(),
                Needle::Phrase => PHRASE_NEEDLE.as_bytes(),
            }
        }

        /// Total by construction: the atomic is written only by `Armed`, and the value it
        /// is left at while disarmed decodes to a needle rather than to a panic inside
        /// `dealloc`.
        fn decode(raw: usize) -> Needle {
            if raw == Needle::Phrase as usize {
                Needle::Phrase
            } else {
                Needle::Passphrase
            }
        }
    }

    thread_local! {
        /// True while THIS thread holds the scanner. Thread-local, and not an atomic
        /// `ThreadId`, because the only question it has to answer is asked by the thread
        /// that is about to deadlock itself, and it has to be answerable BEFORE the lock
        /// is touched: once a thread is parked on a lock it holds, nothing is left running
        /// that could notice.
        ///
        /// `const`-initialised and not `Drop`, for the same reason as `IN_SCAN` below:
        /// neither an allocation on first touch nor a TLS destructor, either of which
        /// would re-enter the allocator this module installs.
        static HOLDS_SCANNER: Cell<bool> = const { Cell::new(false) };
    }

    /// Exclusive use of the scanner, waited for but not waited for indefinitely.
    ///
    /// Contention between two tests on two threads is the normal case and is waited out:
    /// serialising the windows is the whole point of the lock, so the wait here is
    /// bounded, never skipped.
    fn acquire() -> MutexGuard<'static, ()> {
        let deadline = Instant::now() + LOCK_WAIT_LIMIT;
        loop {
            match SCANNER.try_lock() {
                Ok(lock) => return lock,
                // Poison recovery is deliberate. These dials are a unit with no invariant
                // a panic can leave half-applied - a panicking test's `Armed` still runs
                // Drop while unwinding, so the scanner is disarmed either way - and
                // refusing the lock afterwards would turn one real failure into three.
                // Three broken security tests is a worse report than the one that is
                // actually true.
                Err(TryLockError::Poisoned(e)) => return e.into_inner(),
                Err(TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        panic!(
                            "scanner: thread '{}' waited {LOCK_WAIT_LIMIT:?} for the \
                             scanner and never got it. No window in this file is held for \
                             more than a few milliseconds, so the holder was leaked \
                             (`mem::forget` on an `Armed`) or wedged while armed. Failing \
                             here rather than waiting forever: a hung test binary reports \
                             nothing at all.",
                            std::thread::current().name().unwrap_or("<unnamed>"),
                        );
                    }
                    std::thread::sleep(LOCK_POLL);
                }
            }
        }
    }

    /// Exclusive use of the scanner: armed on construction, disarmed on drop.
    pub(super) struct Armed<'a> {
        _lock: MutexGuard<'a, ()>,
    }

    impl Armed<'_> {
        /// # Panics
        ///
        /// If this thread already holds an `Armed`, or if another thread has held one for
        /// longer than [`LOCK_WAIT_LIMIT`]. Both are defects in this test file rather than
        /// findings about the firmware, and both are reported rather than waited on.
        pub(super) fn on(which: Needle) -> Self {
            // A nested arm on one thread cannot be waited for. `SCANNER` is a plain std
            // `Mutex` and std mutexes are not reentrant, so the second `lock()` parks the
            // thread on a guard that same thread is holding, forever. What that produces
            // is the worst report a test binary can give: no failure, no message, no test
            // name, no timeout - and unattended, a job that runs until CI kills it and
            // then blames the whole binary rather than the line responsible. A future test
            // that nests two windows, or one that calls a helper which arms, arrives there
            // without writing anything that looks wrong. So the case is caught before the
            // lock is touched and becomes an ordinary panic, which libtest attributes to
            // the offending test by name.
            //
            // A thread whose TLS is already gone cannot be holding an `Armed` - the guard
            // is a local of a running test - so `false` is the correct answer there.
            if HOLDS_SCANNER.try_with(Cell::get).unwrap_or(false) {
                panic!(
                    "scanner: {NESTED_ARM}. Thread '{}' already holds an armed scanner, \
                     and std `Mutex` is not reentrant, so waiting for it here would hang \
                     this binary with no message and no named test. Pass the enclosing \
                     `Armed` down instead of arming again inside its window.",
                    std::thread::current().name().unwrap_or("<unnamed>"),
                );
            }
            let _lock = acquire();
            // Set only once the lock is ours, so the flag means "holds it" and never
            // "wanted it": a panic on the way in must not leave this thread unable to arm.
            let _ = HOLDS_SCANNER.try_with(|h| h.set(true));
            WHICH.store(which as usize, Ordering::Relaxed);
            HITS.store(0, Ordering::Relaxed);
            ARMED.store(true, Ordering::Relaxed);
            Self { _lock }
        }

        /// Freed blocks that held the needle since arming. Taking `&self` is what keeps
        /// the number this test's own: it cannot be read after the window has closed.
        pub(super) fn hits(&self) -> usize {
            HITS.load(Ordering::Relaxed)
        }
    }

    impl Drop for Armed<'_> {
        fn drop(&mut self) {
            // Disarm BEFORE the guard releases. Reversed, the next test would take the
            // lock and arm while this scanner was still live, and the frees it was about
            // to make would land in a window that had already been read.
            //
            // Neither store allocates, and neither does `Mutex::try_lock`,
            // `PoisonError::into_inner`, the `HOLDS_SCANNER` access (const-initialised,
            // no destructor) or the unlock on the way out, so no part of this instrument
            // can re-enter the scanning `dealloc` below.
            ARMED.store(false, Ordering::Relaxed);
            WHICH.store(0, Ordering::Relaxed);
            // Cleared in the same order and for the same reason: this thread stops holding
            // the scanner before the lock is free for anyone else to take, so the flag can
            // never claim a window that has already been handed on.
            let _ = HOLDS_SCANNER.try_with(|h| h.set(false));
        }
    }

    thread_local! {
        /// Reentrancy guard for the scan, per THREAD and not per process.
        ///
        /// `windows` allocates nothing today, but a future edit that allocated here would
        /// recurse forever, so the scan has to be able to see that it is already running.
        /// Doing that by clearing the global `ARMED` - the obvious way, and the way this
        /// started - clears it for EVERY thread: while any stranger's free was being
        /// scanned, the armed test's own frees read the scanner as disarmed and were not
        /// examined at all. That is the same silent pass the lock exists to prevent,
        /// reached by a different road (demonstrated: a 1 MiB block parked mid-scan on one
        /// thread hides a needle freed on the armed thread, every time).
        ///
        /// `const`-initialised and not `Drop`, so it neither allocates on first touch nor
        /// registers a TLS destructor - both of which would re-enter this allocator.
        static IN_SCAN: Cell<bool> = const { Cell::new(false) };
    }

    /// Takes this thread's scan slot, returning false if the thread is already scanning.
    /// A thread whose TLS is gone (it is being torn down) also declines: skipping a scan
    /// there costs a free no armed test is measuring, while scanning there would risk
    /// re-entering an allocator that is losing its thread state.
    fn enter_scan() -> bool {
        IN_SCAN.try_with(|s| !s.replace(true)).unwrap_or(false)
    }

    fn leave_scan() {
        let _ = IN_SCAN.try_with(|s| s.set(false));
    }

    struct Scanning;

    unsafe impl GlobalAlloc for Scanning {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            System.alloc(l)
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            // RESIDUAL, accepted: while one test is armed this scans deallocations made by
            // every other thread in the binary, the capacity tests included. That is cost,
            // not a correctness hole, and it holds only while every needle in this file
            // stays `'static` (see the note above the literals). A test that heap-allocates
            // a needle outside its own window puts that cost back on the wrong side of the
            // line and starts failing whichever test happens to be armed.
            let n = Needle::decode(WHICH.load(Ordering::Relaxed)).bytes();
            if ARMED.load(Ordering::Relaxed) && l.size() >= n.len() && enter_scan() {
                let block = core::slice::from_raw_parts(p, l.size());
                if block.windows(n.len()).any(|w| w == n) {
                    HITS.fetch_add(1, Ordering::Relaxed);
                }
                leave_scan();
            }
            System.dealloc(p, l)
        }
    }

    #[global_allocator]
    static ALLOC: Scanning = Scanning;
}

use scanner::{Armed, Needle};

// ---------------------------------------------------------------------------------------
// 2a. The instrument, checked before anything is measured with it
// ---------------------------------------------------------------------------------------

/// THE POSITIVE CONTROL, and the reason the three `hits == 0` assertions below are worth
/// reading. A dead instrument asserts `hits == 0` just as confidently as a clean heap
/// does: delete the `ARMED.store(true)` in `Armed::on`, point `Needle::bytes` at the wrong
/// constant, widen the size filter in `dealloc` until it swallows every block, and all
/// three residue tests go green while measuring nothing at all - a file that looks
/// healthier than it ever has. Nothing else in this binary can tell those two worlds
/// apart. When this test fails, the passes below mean nothing until it is fixed again.
///
/// It walks BOTH needles rather than one of its own, because a control that proved only
/// "some bytes are findable" would stay green after `Needle::Passphrase` was aimed at the
/// wrong constant - which is precisely the aiming fault it exists to catch. Each needle is
/// checked in its own window, so a hit is attributable to the needle that was armed.
///
/// Putting needle bytes on the heap on purpose is the one thing the note above the
/// literals forbids, and the lock is what makes it safe HERE: while this window is open no
/// sibling is armed, and each block is allocated and freed inside the window that hunts
/// it. Before the lock existed this test could not have been written at all - its needles
/// would have been indistinguishable from litter to whichever sibling was armed alongside
/// it, and it would have failed that sibling instead.
#[test]
fn the_scanner_finds_a_needle_deliberately_left_in_a_freed_block() {
    let needles = [(Needle::Passphrase, PASSPHRASE_NEEDLE), (Needle::Phrase, PHRASE_NEEDLE)];
    for (which, needle) in needles {
        let armed = Armed::on(which);
        assert_eq!(armed.hits(), 0, "{needle:?}: the window did not open at zero");

        // Exactly one allocation, of exactly the needle's length, filled a character at a
        // time from a black-boxed source: this file builds with optimisations on, and a
        // `String::from(CONST)` whose block is never read is something the optimiser is
        // free to fold away, which would leave the control passing or failing on codegen
        // rather than on the scanner. One allocation also means no growth step frees a
        // block on the way, so the free below is the only candidate for a hit.
        let mut block = String::with_capacity(needle.len());
        for c in core::hint::black_box(needle).chars() {
            block.push(c);
        }
        core::hint::black_box(&block);

        // The needle is on the heap and the block is still LIVE. A hit at this point would
        // mean the scanner reports on memory that was never freed, and every `hits == 0`
        // below would be an answer to a different question than the one being asked.
        assert_eq!(armed.hits(), 0, "{needle:?}: a hit before the block was freed");

        drop(block);
        let hits = armed.hits();
        drop(armed);
        assert!(
            hits >= 1,
            "{needle:?}: the scanner did not see a needle freed in front of it. The \
             instrument is dead, and the residue tests below prove nothing until this \
             passes."
        );
    }
}

/// THE OTHER WAY THIS FILE COULD STOP REPORTING: not a wrong answer, but no answer.
///
/// `Armed::on` twice on one thread - an outer guard plus a helper that arms, say - used to
/// park on a lock that same thread was holding. The binary then hangs with no failing
/// test, no message and no timeout, which unattended means a CI job killed at its wall
/// clock with the blame spread across every test in the run. This asserts the refusal that
/// replaced the hang is still there, and that it still says what to do about it. Nothing
/// else exercises that path: it is on the road no correct test ever takes.
#[test]
fn arming_the_scanner_inside_an_armed_window_says_so_instead_of_hanging() {
    let armed = Armed::on(Needle::Passphrase);

    // libtest captures this unless the test fails or `--nocapture` is passed, so a passing
    // run stays quiet. Under `--nocapture` - which is how tools/ci/check-heap-residue.sh
    // runs this binary - it is what tells a reader that the panic printed underneath is
    // the one being asserted rather than a failure.
    eprintln!("note: the panic below is the expected one, and is what this test asserts");

    // Were the guard gone, this call would hang rather than unwind. Not forever, though:
    // the bounded wait inside `acquire` turns even that regression into a failing test
    // after LOCK_WAIT_LIMIT, which is why this test cannot become the hang it guards.
    let outcome = std::panic::catch_unwind(|| drop(Armed::on(Needle::Passphrase)));
    let payload = match outcome {
        Ok(()) => panic!("a nested Armed::on returned a second guard instead of refusing"),
        Err(payload) => payload,
    };
    let msg = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("<the panic payload was not a string>")
        .to_owned();

    // The refusal happens before the lock is touched, so the window this test still holds
    // has to be exactly as it was: a guard that half-armed on its way to panicking would
    // leave the next reader measuring someone else's dials.
    assert_eq!(armed.hits(), 0, "the refused arm disturbed the window it was refused from");
    drop(armed);

    assert!(
        msg.contains(scanner::NESTED_ARM),
        "the nested arm panicked, but not with the message that names the problem and \
         says what to do about it: {msg:?}"
    );
}

/// Type a passphrase, derive a wallet from it, then throw the device away - which is what
/// a power cut is - and prove the passphrase is in none of the blocks that were freed on
/// the way.
///
/// This is the check the `WipesOnDrop` marker cannot make. The marker says
/// `PassState::entry` has a type whose `Drop` wipes. It says nothing about the String
/// having REALLOCATED at character nine and left the first eight bytes at the old address,
/// about the per-frame copies the phrase well makes while drawing, or about a screen that
/// hands the passphrase onward into a plain `String` the marker was never told about.
#[test]
fn a_typed_passphrase_is_in_no_freed_block_after_the_screens_holding_it_are_dropped() {
    const VECTOR1: &str = "abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon about";
    let armed = Armed::on(Needle::Passphrase);

    let mut ui = Ui::new(720, 720);
    tap(&mut ui, RegionId::HomeVerifySeed);
    assert_eq!(ui.screen(), ScreenId::PhraseEntry);
    type_keys(&mut ui, VECTOR1);
    tap(&mut ui, RegionId::KeyDone);
    assert_eq!(ui.screen(), ScreenId::PassphraseEntry);

    tap(&mut ui, RegionId::PassToggle);
    type_keys(&mut ui, PASSPHRASE_NEEDLE);
    type_keys(&mut ui, PADDING);
    tap(&mut ui, RegionId::PassConfirm);
    type_keys(&mut ui, PASSPHRASE_NEEDLE);
    type_keys(&mut ui, PADDING);
    // Draw it: the well and the masked fields make per-frame copies of what is typed.
    Fb::render(&ui, 720, 720);
    tap(&mut ui, RegionId::KeyDone);
    assert_eq!(ui.screen(), ScreenId::Deriving);
    assert!(ui.tick(0).dirty);
    Fb::render(&ui, 720, 720);

    // Power off. Everything the session held - the current screen AND the whole back
    // stack, which still owns the phrase and the passphrase - is dropped here. Those frees
    // ARE the measurement, so this stays ahead of the read.
    drop(ui);

    let hits = armed.hits();
    drop(armed);
    assert_eq!(hits, 0, "the passphrase survived in {hits} freed heap block(s)");
}

/// The minimal reproducer for the failure above, with no UI in the way.
///
/// `bip39::seed` builds its PBKDF2 password and salt with `nfkd().collect::<String>()`.
/// `collect` into a `String` reserves the iterator's lower size hint and then grows, so
/// every reallocation on the way abandons a block holding the secret so far. `Zeroizing`
/// wipes only the buffer that survives to the end; the abandoned ones are freed intact.
/// `normalize_phrase`, eleven lines below it in the same file, documents exactly this
/// hazard and preallocates against it.
#[test]
fn bip39_seed_leaves_no_copy_of_the_passphrase_in_freed_heap() {
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon                           abandon abandon abandon abandon about";
    let armed = Armed::on(Needle::Passphrase);
    let s = notyas_core::bip39::seed(PHRASE, TYPED_PASSPHRASE);
    let hits = armed.hits();
    drop(armed);
    core::hint::black_box(&s);
    assert_eq!(hits, 0, "bip39::seed abandoned the passphrase in {hits} freed heap block(s)");
}

/// The password side of the same function leaks the MNEMONIC by the same mechanism, which
/// is the more expensive half: the passphrase is one factor, the phrase is the wallet.
#[test]
fn bip39_seed_leaves_no_copy_of_the_mnemonic_in_freed_heap() {
    // Not a valid checksum, and it does not need to be: `seed` is a pure PBKDF2 over the
    // sentence it is handed and never consults the wordlist.
    const PHRASE: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo";
    let armed = Armed::on(Needle::Phrase);
    let s = notyas_core::bip39::seed(PHRASE, "");
    let hits = armed.hits();
    drop(armed);
    core::hint::black_box(&s);
    assert_eq!(hits, 0, "bip39::seed abandoned the mnemonic in {hits} freed heap block(s)");
}

