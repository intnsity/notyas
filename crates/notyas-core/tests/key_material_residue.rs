// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Does key material survive in freed heap after the value that owns it has dropped?
//!
//! `Mnemonic`, `PhraseCheck`, `AccountKeys` and `AddressRow` all carry a hand written
//! `Drop` whose entire job is to wipe what they hold. A `Drop` can only reach the buffer
//! the value owns AT THE MOMENT IT DROPS, which is exactly what the zeroize crate's own
//! `Vec` documentation warns about: "Cannot ensure that previous reallocations did not
//! leave values on the heap." Every intermediate buffer - a `String` that grew from
//! `String::new()`, a working vector nobody wipes, a `shrink_to_fit` that copied and freed
//! the original - is out of that `Drop`'s reach and is handed straight back to the
//! allocator with the secret still in it. On the device that memory is reused by the next
//! screen, written into a driver buffer, or simply sits in PSRAM until power is cut.
//!
//! Reasoning about which allocation reallocates is exactly the discipline that erodes, so
//! this file does not reason: it installs a global allocator that inspects the CONTENTS of
//! every block at the moment it is freed and fails the test if a named secret is still
//! legible there. A future `to_string()` added anywhere on these paths trips it.
//!
//! Scope, and honesty about it:
//! - Heap only. Dead stack frames (rust-bitcoin's `Xpriv::encode` returns `[u8; 78]` by
//!   value, `PrivateKey::fmt_wif` builds a 34-byte array) are not observable from an
//!   allocator hook. The fixes wipe those too; only the heap half is under test here.
//! - Growth is modelled as allocate-copy-free, because this allocator does not override
//!   `GlobalAlloc::realloc` and so the default trait body runs. A system allocator that
//!   happened to resize in place would hide the residue on this host without making it any
//!   less real on the device, whose allocator is a different one.
//! - The check is "is the plaintext still there", not "is the block zero". A freed block
//!   legitimately holds unrelated data; only a block that still spells the secret fails.
//! - Frees made on the ARMED THREAD only. See the `scanner` module: the code under test is
//!   pure and single-threaded, so every buffer a probe is responsible for is freed on the
//!   probe's own thread, and counting anyone else's frees only ever produced false reports.

use notyas_core::bip39::{self, MnemonicMode, WordCount};
use notyas_core::bitcoin::Network;
use notyas_core::derive::{self, ChildIndex, Scheme};
use notyas_core::entropy::parse_dice;

use scanner::{assert_no_residue, residue_after, Secret};

/// The passphrase probe's secret. A file-level `const` so that its bytes are `'static`:
/// the only heap copy that ever exists is the one the scanner holds, and that one is not
/// freed until after the window has closed.
const PASSPHRASE: &str = "correct horse battery staple, and a distinctive tail";

// ---------------------------------------------------------------------------------------
// The scanning allocator
// ---------------------------------------------------------------------------------------

/// The scanning allocator, the dials that aim it, and the only handle that can turn them.
///
/// # Why the dials are not bare statics
///
/// The allocator is global to the PROCESS and libtest runs this file's probes as threads of
/// ONE process, so the state below is a single instrument shared by thirteen tests. Left as
/// bare statics it was exactly that, and every interleaving ends somewhere bad: a sibling's
/// `HIT_SIZE` reset landing after a hit and before the read (a green run over real
/// residue), a sibling's needle overwrite sending the scanner hunting for the wrong secret,
/// a sibling's disarm landing between the arming and the frees. A security test whose
/// failure mode is to succeed.
///
/// So the dials are private to this module, and `Armed` is the only thing that can reach
/// them: it cannot be constructed without the lock, cannot be constructed without arming,
/// and cannot be dropped without disarming. "Armed without exclusive access" becomes a
/// state no caller can write, rather than a rule every future caller has to remember.
/// Serialising the RUN instead (`--test-threads=1`) is a property of one CI invocation; it
/// leaves every `cargo test` typed by hand measuring the untrustworthy thing. The lock
/// travels with the file.
///
/// # Why the armed flag is THREAD-LOCAL and not global
///
/// A global flag makes the window scan every thread's frees, not only the armed probe's.
/// That is not a tolerable residual here, because every probe in this file derives its
/// needle from the SAME fixture wallet: while one probe is armed on the phrase tail, a
/// sibling that is merely building `build_mnemonic()` for its own needle frees a block
/// spelling that tail, on another thread, and the armed probe reports residue it did not
/// cause. Measured at 1 failure in 12 runs as this file was written; a stranger thread that
/// rebuilds the fixture in a loop turns it into 3 failed probes on every run.
///
/// The sibling instrument in `notyas-ui` answers this by making every byte of needle
/// material `'static`, which cannot work here: the litter is the FIXTURE, not the needle
/// copy, and one needle (the wordlist indices, native-endian `usize`) has no portable
/// compile-time spelling at all. Aiming the flag at one thread removes the whole class
/// instead, and costs nothing real - the code under test is pure and allocates, copies and
/// frees on the caller's thread. `a_stranger_threads_free_is_not_counted_as_residue` pins
/// that behaviour; `the_scanner_detects_residue_it_is_meant_to_detect` pins that the
/// instrument is nonetheless armed and looking.
mod scanner {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};

    use notyas_core::bip39;
    use notyas_core::bip85;
    use notyas_core::bitcoin::Network;
    use notyas_core::derive::{self, ChildIndex};

    /// Longest secret this harness can watch for. A 24-word phrase as `usize` word indices
    /// is 192 bytes and is the largest needle any probe below uses.
    const NEEDLE_CAP: usize = 256;

    /// Held for the whole armed window, so no second probe can publish a needle inside this
    /// one's measurement.
    static SCANNER: Mutex<()> = Mutex::new(());

    /// The needle, valid only while `NEEDLE_LEN` is non-zero and only on the armed thread.
    ///
    /// Atomic bytes rather than a `Mutex<Vec<u8>>` because the reader is
    /// `GlobalAlloc::dealloc`: it must not allocate and must not block, so it cannot take a
    /// lock (a deallocation on the thread already holding it would deadlock) and it cannot
    /// own a heap buffer. `Relaxed` is enough for all three dials: the only thread that
    /// reads them is the thread that wrote them, so program order already orders the
    /// publication, and the mutex - not these - is what orders one window against the next.
    static NEEDLE: [AtomicU8; NEEDLE_CAP] = [const { AtomicU8::new(0) }; NEEDLE_CAP];
    static NEEDLE_LEN: AtomicUsize = AtomicUsize::new(0);

    /// Size of the first freed block that still contained the needle, plus one, so that
    /// zero can mean "clean" (a zero-sized allocation cannot contain anything).
    static HIT_SIZE: AtomicUsize = AtomicUsize::new(0);

    thread_local! {
        /// Whether THIS thread is inside an armed window. See the module note: a global
        /// flag makes every probe measure the whole binary's litter.
        ///
        /// `const`-initialised and not `Drop`, so it neither allocates on first touch nor
        /// registers a TLS destructor - both of which would re-enter this allocator. The
        /// same is true of the two below.
        static ARMED: Cell<bool> = const { Cell::new(false) };

        /// A window is open on this thread. Bookkeeping for the deadlock guard in
        /// `Armed::on`, and deliberately NOT `ARMED`, which is a statement about what
        /// `dealloc` should do.
        ///
        /// Reusing `ARMED` for both reads as a harmless saving today, because the two
        /// happen to be set on the same line. It is not: an edit that changes when the
        /// scanner looks then silently removes the deadlock guard as well, and the way
        /// that failure presents is a test binary that hangs forever with no output at
        /// all - no failing test, no message, nothing to search for. Demonstrated by
        /// inverting the `ARMED` store below while the two were one flag: the run had to
        /// be killed after ten minutes. The guard is worth its own bit.
        static WINDOW_OPEN: Cell<bool> = const { Cell::new(false) };

        /// Reentrancy guard for the scan itself, per THREAD and not per process.
        ///
        /// `scan` allocates nothing today, but a future edit that allocated here would
        /// recurse forever, so the scan has to be able to see that it is already running.
        /// This is deliberately NOT `ARMED`: reusing the armed flag as the guard would
        /// blind the probe to its own frees for the duration of every scan, which is the
        /// same silent pass the lock exists to prevent, reached by a different road.
        static IN_SCAN: Cell<bool> = const { Cell::new(false) };
    }

    /// A thread whose TLS is gone (it is being torn down) reads as not armed and declines
    /// to scan: skipping a scan there costs a free no probe is measuring, while touching
    /// TLS there risks re-entering an allocator that is losing its thread state.
    fn armed_here() -> bool {
        ARMED.try_with(Cell::get).unwrap_or(false)
    }

    /// Whether this thread already has a window open. Same TLS-teardown rule as above; a
    /// thread being torn down cannot be inside `residue_after`, so `false` is the truth.
    fn window_open_here() -> bool {
        WINDOW_OPEN.try_with(Cell::get).unwrap_or(false)
    }

    /// Takes this thread's scan slot, returning false if the thread is already scanning.
    fn enter_scan() -> bool {
        IN_SCAN.try_with(|s| !s.replace(true)).unwrap_or(false)
    }

    fn leave_scan() {
        let _ = IN_SCAN.try_with(|s| s.set(false));
    }

    /// Which secret the scanner is looking for.
    ///
    /// A closed enum rather than a caller-supplied `&[u8]`, so that no probe can aim the
    /// scanner at a needle that is not actually a secret of this wallet - an empty slice, a
    /// prefix of the wrong string, a buffer it built and then dropped - and read the zero
    /// that follows as proof of anything. Every variant names a real secret and knows how
    /// to rebuild it, and `needle` asserts the shape of what it built, so a fixture that
    /// silently changed shape fails here rather than quietly narrowing the search.
    #[derive(Clone, Copy)]
    pub(super) enum Secret {
        MnemonicEntropy,
        PhraseTail,
        PhraseHead,
        Passphrase,
        WordIndices,
        AccountXprv,
        AccountSlip132Prv,
        AddressRowWif,
        RootXprv,
        Bip85ChildXprv,
        /// Positive control, leaked deliberately on the armed thread.
        Control,
        /// The control's mirror, leaked deliberately on a STRANGER thread.
        ForeignControl,
    }

    /// The control needles. Distinct from each other so that neither control test can be
    /// answered by the other's litter, and `'static` so the only heap copy of either is the
    /// one the test makes on purpose.
    const CONTROL: &[u8] = b"an unmistakable value that nothing else allocates";
    const FOREIGN_CONTROL: &[u8] = b"a value only a stranger thread ever writes down";

    impl Secret {
        /// What to name in a failure.
        fn label(self) -> &'static str {
            match self {
                Secret::MnemonicEntropy => "Mnemonic entropy",
                Secret::PhraseTail => "Mnemonic phrase",
                Secret::PhraseHead => "phrase through seed derivation",
                Secret::Passphrase => "passphrase through seed derivation",
                Secret::WordIndices => "check_phrase word indices",
                Secret::AccountXprv => "account xprv",
                Secret::AccountSlip132Prv => "account zprv",
                Secret::AddressRowWif => "address row WIF",
                Secret::RootXprv => "root xprv",
                Secret::Bip85ChildXprv => "bip85 child xprv",
                Secret::Control => "positive control",
                Secret::ForeignControl => "foreign positive control",
            }
        }

        /// Rebuild this secret's bytes.
        ///
        /// Called BEFORE the window opens, so every temporary it frees on the way - the
        /// whole fixture wallet, in most variants - is freed while this thread is disarmed
        /// and is invisible to the scanner. Nothing in here may run inside a window.
        fn needle(self) -> Vec<u8> {
            match self {
                Secret::MnemonicEntropy => {
                    let entropy = super::build_mnemonic().entropy.clone();
                    assert_eq!(entropy.len(), 32, "24 words carry 256 bits of entropy");
                    entropy
                }
                // The tail of the sentence: unique to this phrase, and short enough to sit
                // inside even the small buffers an incrementally grown string leaves behind.
                Secret::PhraseTail => {
                    let phrase = super::build_mnemonic().phrase().to_string();
                    assert_eq!(phrase.split(' ').count(), 24, "fixture is a 24 word phrase");
                    phrase.as_bytes()[phrase.len() - 40..].to_vec()
                }
                Secret::PhraseHead => {
                    let phrase = super::build_mnemonic().phrase().to_string();
                    phrase.as_bytes()[..40].to_vec()
                }
                Secret::Passphrase => super::PASSPHRASE.as_bytes().to_vec(),
                // What the decoded vector looks like in memory: the wordlist index of each
                // word, in order, in the platform's own `usize` encoding. Computed from the
                // public wordlist rather than taken from the module under test, so the
                // probe cannot agree with a bug in it.
                Secret::WordIndices => {
                    let phrase = super::build_mnemonic().phrase().to_string();
                    let list = bip39::wordlist();
                    let mut needle = Vec::new();
                    for word in phrase.split(' ') {
                        let index = list
                            .binary_search(&word)
                            .expect("every fixture word is in the list");
                        needle.extend_from_slice(&index.to_ne_bytes());
                    }
                    assert_eq!(needle.len(), 24 * core::mem::size_of::<usize>());
                    needle
                }
                // Deliberately a PREFIX: incremental growth leaves the LEADING characters
                // of the key in each abandoned buffer, and 48 base58 characters already
                // cover the whole chain code, which is half of what an attacker needs.
                Secret::AccountXprv => {
                    let xprv = super::build_account().account.xprv.clone();
                    assert!(xprv.starts_with("xprv"), "fixture derives a mainnet account");
                    xprv.as_bytes()[..48].to_vec()
                }
                Secret::AccountSlip132Prv => {
                    let zprv = super::build_account()
                        .account
                        .slip132_prv
                        .clone()
                        .expect("BIP84 on mainnet has a zprv rendering");
                    assert!(zprv.starts_with("zprv"), "SLIP-132 private rendering");
                    zprv.as_bytes()[..48].to_vec()
                }
                // A WIF is 52 characters, so unlike the xprv it fits ENTIRELY inside an
                // abandoned buffer: the whole spending key for the row, not a prefix of it.
                Secret::AddressRowWif => {
                    let wif = super::build_account().rows[0].wif.clone();
                    assert_eq!(wif.len(), 52, "compressed mainnet WIF");
                    wif.into_bytes()
                }
                Secret::RootXprv => {
                    let root = derive::root_xprv(&super::build_seed(), Network::Bitcoin);
                    assert!(root.starts_with("xprv"), "fixture derives a mainnet root");
                    root.as_bytes()[..48].to_vec()
                }
                Secret::Bip85ChildXprv => {
                    let child =
                        bip85::xprv(&super::build_seed(), Network::Bitcoin, ChildIndex::ZERO)
                            .expect("index 0 derives a BIP-85 child root")
                            .to_string();
                    assert!(child.starts_with("xprv"), "a mainnet BIP-85 child root");
                    child.as_bytes()[..48].to_vec()
                }
                Secret::Control => CONTROL.to_vec(),
                Secret::ForeignControl => FOREIGN_CONTROL.to_vec(),
            }
        }
    }

    /// Exclusive use of the scanner: armed on construction, disarmed on drop.
    struct Armed<'a> {
        /// The live needle. Held for the whole window so that the one heap copy of the
        /// secret this instrument is responsible for is not freed while the scanner is
        /// looking for it. Declared before `_lock` so that it is dropped before the lock is
        /// released, and after `Drop::drop` below has disarmed.
        _needle: Vec<u8>,
        _lock: MutexGuard<'a, ()>,
    }

    impl Armed<'_> {
        fn on(secret: Secret) -> Self {
            // Detect nesting BEFORE touching the lock. A plain `Mutex` re-entered on one
            // thread deadlocks the whole binary with no output at all, which is the worst
            // way for a future edit to be told it made a mistake; this is the same mistake,
            // named, at the same instant, with a stack trace.
            assert!(
                !window_open_here(),
                "the residue scanner is already armed on this thread: a probe body cannot \
                 open a second window inside its own. One window measures one secret."
            );

            // Rebuilds the fixture and so allocates and frees heavily. It has to happen
            // before the arming below, or the probe measures its own needle construction.
            let needle = secret.needle();
            assert!(
                !needle.is_empty() && needle.len() <= NEEDLE_CAP,
                "{}: needle must be 1..={NEEDLE_CAP} bytes, got {}",
                secret.label(),
                needle.len()
            );

            // Poison recovery is deliberate. These dials are a unit with no invariant a
            // panic can leave half-applied - a panicking probe's `Armed` still runs Drop
            // while unwinding, so the scanner is disarmed either way - and refusing the
            // lock afterwards would turn one real failure into twelve. Twelve broken
            // security tests is a worse report than the one that is actually true.
            let _lock = SCANNER.lock().unwrap_or_else(|e| e.into_inner());

            for (slot, byte) in NEEDLE.iter().zip(&needle) {
                slot.store(*byte, Ordering::Relaxed);
            }
            NEEDLE_LEN.store(needle.len(), Ordering::Relaxed);
            HIT_SIZE.store(0, Ordering::Relaxed);
            // Last, and allocation-free from here to the caller: the window is open. Both
            // flags are set only once construction is certain, so a needle that fails its
            // own shape assertion above leaves this thread exactly as it found it.
            WINDOW_OPEN.with(|w| w.set(true));
            ARMED.with(|a| a.set(true));
            Self { _needle: needle, _lock }
        }

        /// Size of the first freed block that still held the needle. Taking `&self` is what
        /// keeps the number this probe's own: it cannot be read after the window closed.
        fn residue(&self) -> Option<usize> {
            HIT_SIZE.load(Ordering::Relaxed).checked_sub(1)
        }
    }

    impl Drop for Armed<'_> {
        fn drop(&mut self) {
            // Disarm BEFORE anything else. Reversed, the next probe would take the lock and
            // arm while this scanner was still live, and `_needle`'s own free - a block
            // that spells the secret in full - would land in a window that has been read.
            //
            // Neither store allocates, and neither does `Cell::set`, `Mutex::lock`,
            // `PoisonError::into_inner` or the unlock on the way out, so no part of this
            // instrument can re-enter the scanning `dealloc` below.
            ARMED.with(|a| a.set(false));
            NEEDLE_LEN.store(0, Ordering::Relaxed);
            WINDOW_OPEN.with(|w| w.set(false));
        }
    }

    /// Run `body` with the scanner watching for `secret`, and return the size of the first
    /// freed block that still contained it.
    ///
    /// `body` returns nothing on purpose: everything it builds must be dropped INSIDE the
    /// window, because a secret still alive when the window closes has not been tested at
    /// all.
    pub(super) fn residue_after(secret: Secret, body: impl FnOnce()) -> Option<usize> {
        let armed = Armed::on(secret);
        body();
        // Read inside the window; the drop that follows closes it.
        let hit = armed.residue();
        drop(armed);
        hit
    }

    /// Assert that `body` left nothing of `secret` behind.
    pub(super) fn assert_no_residue(secret: Secret, body: impl FnOnce()) {
        if let Some(size) = residue_after(secret, body) {
            // Disarmed by now, which is what makes this formatting - an allocation - safe.
            panic!(
                "{}: a {size}-byte block was returned to the allocator still containing the \
                 secret. Some buffer on this path was reallocated, cloned or copied out, so \
                 the owning type's Drop never saw the copy that leaked.",
                secret.label()
            );
        }
    }

    struct Scanner;

    // SAFETY: every method forwards to `System`, which upholds the contract; the added work
    // is a read of memory that is still allocated at that point, and the pointer is not
    // touched afterwards. `realloc` is deliberately NOT overridden, so the default
    // allocate-copy-free body runs and the abandoned buffer passes through `dealloc` where
    // it can be inspected.
    unsafe impl GlobalAlloc for Scanner {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            System.alloc(layout)
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            System.alloc_zeroed(layout)
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            if armed_here() && enter_scan() {
                scan(ptr, layout.size());
                leave_scan();
            }
            System.dealloc(ptr, layout)
        }
    }

    #[global_allocator]
    static ALLOCATOR: Scanner = Scanner;

    /// Look for the armed needle in a block that is about to be freed.
    ///
    /// Allocation-free by construction, which is not a style preference: allocating here
    /// would re-enter the allocator from inside a deallocation.
    ///
    /// # Safety
    /// `ptr` must be valid for `size` bytes, which is the `dealloc` contract, and the
    /// caller must hold this thread's scan slot. The bytes may be uninitialized - spare
    /// `Vec` capacity is - so they are read one at a time through `read_volatile`, which is
    /// as close as a stable-Rust probe gets to a byte-wise memory inspection the compiler
    /// is not allowed to fold away.
    unsafe fn scan(ptr: *const u8, size: usize) {
        let needle_len = NEEDLE_LEN.load(Ordering::Relaxed);
        if needle_len == 0 || size < needle_len {
            return;
        }
        for start in 0..=(size - needle_len) {
            let mut matched = true;
            for (i, want) in NEEDLE[..needle_len].iter().enumerate() {
                if ptr.add(start + i).read_volatile() != want.load(Ordering::Relaxed) {
                    matched = false;
                    break;
                }
            }
            if matched {
                // First hit wins, so a later and larger block cannot overwrite the report.
                // A plain load-then-store rather than a compare-exchange: only the armed
                // thread reaches this line, so there is no second writer to race with.
                if HIT_SIZE.load(Ordering::Relaxed) == 0 {
                    HIT_SIZE.store(size + 1, Ordering::Relaxed);
                }
                return;
            }
        }
    }

    /// The bytes `Secret::Control` watches for, so a control test can leak them on purpose.
    pub(super) fn control_needle() -> &'static [u8] {
        CONTROL
    }

    /// The bytes `Secret::ForeignControl` watches for.
    pub(super) fn foreign_control_needle() -> &'static [u8] {
        FOREIGN_CONTROL
    }
}

// ---------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------

/// 120 d6 faces. The exact values are irrelevant: every probe below learns the secret it
/// watches for from a fixture run rather than from a hard coded expectation, so this
/// fixture is a source of a realistic wallet and nothing more.
const DICE: &str = concat!(
    "415263145362415263145362415263145362415263145362415263145362",
    "263514362514263514362514263514362514263514362514263514362514"
);

fn build_mnemonic() -> notyas_core::bip39::Mnemonic {
    let words = WordCount::new(24).expect("24 is a supported word count");
    bip39::mnemonic_from_dice(&parse_dice(DICE), MnemonicMode::Words(words))
        .expect("the hashed path is infallible for a supported word count")
}

/// The 64-byte PBKDF2 seed of the fixture wallet, with no passphrase.
fn build_seed() -> zeroize::Zeroizing<[u8; 64]> {
    let mnemonic = build_mnemonic();
    bip39::seed(&mnemonic.phrase(), "")
}

/// One BIP84 account plus a single address row, from the phrase the fixture dice produce.
fn build_account() -> derive::Derived {
    derive::derive(
        &build_seed(),
        Network::Bitcoin,
        Scheme::Bip84,
        ChildIndex::ZERO,
        ChildIndex::ZERO,
        1,
        0,
    )
}

/// Warm every lazily built global - above all the process-wide secp256k1 context, which is
/// allocated once and deliberately never freed - before any probe arms the scanner, so a
/// first-call allocation cannot be mistaken for residue.
fn warm_up() {
    let _ = build_account();
}

// ---------------------------------------------------------------------------------------
// bip39: the mnemonic and its entropy
// ---------------------------------------------------------------------------------------

/// DEFECT 1. `Mnemonic::drop` wipes `self.entropy`, which is the buffer the value owns at
/// that instant and nothing else. Anything the entropy passed through on its way there is
/// already back in the allocator's free list by then.
#[test]
fn mnemonic_entropy_does_not_survive_construction_and_drop() {
    warm_up();
    assert_no_residue(Secret::MnemonicEntropy, || {
        let mnemonic = build_mnemonic();
        drop(mnemonic);
    });
}

/// DEFECT 1, the other half. The sentence regenerates the wallet on its own, so clean
/// entropy is only half the obligation: `phrase()` is what the seed screen renders and
/// what the PBKDF2 password is built from.
#[test]
fn mnemonic_phrase_does_not_survive_being_rendered() {
    warm_up();
    assert_no_residue(Secret::PhraseTail, || {
        let mnemonic = build_mnemonic();
        let rendered = mnemonic.phrase();
        assert!(!rendered.is_empty());
        drop(rendered);
        drop(mnemonic);
    });
}

/// DEFECT 1, third place the sentence goes. `seed` NFKD-normalizes the phrase before
/// PBKDF2, and normalization is a character iterator with no known length: whatever
/// collects it cannot size the buffer in advance. This is the step every wallet creation
/// and every restore runs, so it is the one that matters most.
#[test]
fn mnemonic_phrase_does_not_survive_seed_derivation() {
    warm_up();
    let phrase: String = build_mnemonic().phrase().to_string();

    assert_no_residue(Secret::PhraseHead, || {
        let seed = bip39::seed(&phrase, "");
        assert_eq!(seed.len(), 64);
        drop(seed);
    });
}

/// The passphrase is the other half of the PBKDF2 input and is a secret in its own right:
/// it is the whole of a plausible-deniability wallet's protection.
#[test]
fn passphrase_does_not_survive_seed_derivation() {
    warm_up();
    let phrase: String = build_mnemonic().phrase().to_string();

    assert_no_residue(Secret::Passphrase, || {
        let seed = bip39::seed(&phrase, PASSPHRASE);
        assert_eq!(seed.len(), 64);
        drop(seed);
    });
}

/// DEFECT 2. `check_phrase` decodes the user's words into a vector of wordlist indices.
/// That vector IS the phrase - an 11-bit code per word, one per `usize` - and
/// `PhraseCheck::drop` never sees it, because it is a local that is consumed and freed
/// before the value the caller gets back is even built.
#[test]
fn check_phrase_word_indices_do_not_survive() {
    warm_up();
    let phrase: String = build_mnemonic().phrase().to_string();

    assert_no_residue(Secret::WordIndices, || {
        let check = bip39::check_phrase(&phrase);
        assert_eq!(check.word_count, 24);
        drop(check);
    });
}

// ---------------------------------------------------------------------------------------
// derive: the extended private key and the WIF renderings
// ---------------------------------------------------------------------------------------

/// DEFECT 3. `AccountKeys::drop` wipes the `xprv` String it owns. The buffers that
/// produced it - a `String` grown from empty one base58 character at a time, so freed at
/// capacity 8, 16, 32 and 64 with that many characters of the key still in it - are owned
/// by nothing and are never wiped.
#[test]
fn account_xprv_does_not_survive_serialisation() {
    warm_up();
    assert_no_residue(Secret::AccountXprv, || {
        let derived = build_account();
        assert!(!derived.account.xprv.is_empty());
        drop(derived);
    });
}

/// DEFECT 3, the SLIP-132 rendering of the same node. A separate probe because `reversion`
/// already wipes the 78 bytes it is handed: what it does not cover is the String the
/// base58 encoder builds and returns.
#[test]
fn account_slip132_private_key_does_not_survive_serialisation() {
    warm_up();
    assert_no_residue(Secret::AccountSlip132Prv, || {
        let derived = build_account();
        assert!(derived.account.slip132_prv.is_some());
        drop(derived);
    });
}

/// DEFECT 3, the leaf keys. A WIF is 52 characters, so unlike the xprv it fits ENTIRELY
/// inside an abandoned buffer: the whole spending key for the row, not a prefix of it.
#[test]
fn address_row_wif_does_not_survive_serialisation() {
    warm_up();
    assert_no_residue(Secret::AddressRowWif, || {
        let derived = build_account();
        assert_eq!(derived.rows.len(), 1);
        drop(derived);
    });
}

/// The root key has its own entry point, used by the report header and by the watch-only
/// exports, and it renders through the same serialisation as the account node.
#[test]
fn root_xprv_does_not_survive_serialisation() {
    use zeroize::Zeroize;

    warm_up();
    let seed = build_seed();

    assert_no_residue(Secret::RootXprv, || {
        let mut rendered = derive::root_xprv(&seed, Network::Bitcoin);
        assert!(rendered.starts_with("xprv"));
        // `root_xprv` returns a bare String: that value is the CALLER's to wipe, and here
        // the caller is this probe. Without this the probe would be reporting the final
        // buffer, which is not the defect under test.
        rendered.zeroize();
    });
}

// ---------------------------------------------------------------------------------------
// bip85: the derived child root
// ---------------------------------------------------------------------------------------

/// DEFECT 4. `bip85::xprv` hands back a `Zeroizing<String>`, so the buffer the CALLER holds
/// is wiped - and that was the whole of the obligation only for as long as the rendering
/// came from this crate's own encoder. Rendering the child through rust-bitcoin's
/// `Display` instead puts the key through `base58ck::encode_check_to_fmt`, which grows a
/// `String` from empty one character at a time and accumulates its base58 digits in a
/// hundred-element `SmallVec` that spills to a `Vec` past digit 100 - an xprv is 111 digits
/// - and drops both unwiped. `Zeroizing` reaches none of that.
///
/// This is the same defect the account xprv probe above pins, at the other entry point:
/// BIP-85 application 32h is a spending key for a whole derived wallet, so the buffers
/// abandoned here are worth exactly what the account ones are.
#[test]
fn bip85_child_xprv_does_not_survive_serialisation() {
    warm_up();
    let seed = build_seed();

    assert_no_residue(Secret::Bip85ChildXprv, || {
        let rendered = notyas_core::bip85::xprv(&seed, Network::Bitcoin, ChildIndex::ZERO)
            .expect("index 0 derives a BIP-85 child root");
        assert!(!rendered.is_empty());
        // `Zeroizing` wipes this one on the way out, which is what makes any hit below a
        // buffer nothing owns rather than the value the caller was handed.
        drop(rendered);
    });
}

// ---------------------------------------------------------------------------------------
// The instrument itself
// ---------------------------------------------------------------------------------------

/// The harness has to be able to FAIL, or every clean result above means nothing: an edit
/// that broke arming would turn this whole file green and no probe would notice. This frees
/// a buffer that deliberately still holds the needle and asserts the scanner says so, at
/// the exact size of the block it leaked - which is what distinguishes "the scanner found
/// my block" from "the scanner found something".
#[test]
fn the_scanner_detects_residue_it_is_meant_to_detect() {
    let needle = scanner::control_needle();
    let hit = residue_after(Secret::Control, || {
        let mut leaked: Vec<u8> = Vec::with_capacity(needle.len());
        leaked.extend_from_slice(needle);
        // Dropped without being wiped: exactly the shape of every defect above.
        drop(leaked);
    });
    assert_eq!(
        hit,
        Some(needle.len()),
        "the residue scanner failed to see a buffer freed with the needle still in it"
    );
}

/// The counterpart, and the regression guard for the race this file was written twice for:
/// a block freed by a STRANGER THREAD inside the window is not this probe's residue and
/// must not be counted. Every probe here derives its needle from one shared fixture, so
/// with a process-wide armed flag this leak is indistinguishable from a real one and the
/// wrong test fails - which is exactly what a sibling building `build_mnemonic()` for its
/// own needle used to do, at roughly one run in twelve.
#[test]
fn a_stranger_threads_free_is_not_counted_as_residue() {
    let needle = scanner::foreign_control_needle();
    let hit = residue_after(Secret::ForeignControl, || {
        std::thread::spawn(move || {
            let mut litter: Vec<u8> = Vec::with_capacity(needle.len());
            litter.extend_from_slice(needle);
            drop(litter);
        })
        .join()
        .expect("the litter thread does not panic");
    });
    assert_eq!(hit, None, "a stranger thread's free was charged to this probe");
}

/// Nesting one window inside another is a mistake a future edit can make, and with a plain
/// `Mutex` it is the worst kind: the binary deadlocks with no failing test and no message.
/// It fails loudly instead, and this is what says so.
#[test]
#[should_panic(expected = "already armed on this thread")]
fn arming_twice_on_one_thread_fails_instead_of_deadlocking() {
    residue_after(Secret::Control, || {
        let _ = residue_after(Secret::Control, || {});
    });
}
