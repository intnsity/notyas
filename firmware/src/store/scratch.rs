// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The Argon2id working set, in PSRAM, owned for the life of the device.
//!
//! # Why the firmware allocates it and the engine does not
//!
//! 16 MiB is a board decision. `notyas_wallet` borrows a `Scratch<'_>` precisely so that
//! it never has to know that this part has 32 MB of PSRAM behind a cache, that the panel
//! driver has already taken a framebuffer out of it, or that `argon2::Block` is
//! over-aligned. The crate stays a pure function of its inputs; this file knows the board.
//!
//! # Why it is allocated once at boot and never freed
//!
//! The alternative - allocate per unlock - moves a 16 MiB allocation onto the path that
//! runs immediately after a user types their PIN, where a failure has no good answer:
//! the device would have to refuse an unlock for a reason that is neither the PIN nor the
//! flash. Allocating at boot turns that into a boot-time diagnostic on a device that has
//! not yet claimed it can store anything. It also makes the free-heap number in the
//! heartbeat honest: what it reports is what is left with the working set already
//! standing, not what is left before the first unlock eats 16 MiB of it.
//!
//! The cost is 16 MiB of PSRAM held permanently. On a part with ~30 MB free after the
//! framebuffers that is affordable, and `Store::heap_report` prints the before/after
//! numbers at boot so the claim is measured rather than assumed.
//!
//! # Zeroization
//!
//! The engine wipes the working set on every return path including the error paths
//! (`Scratch::wipe`, ESP-SEAL.md 5.5), so a resident buffer holds Argon2 state only for
//! the duration of one derivation. That is the same exposure a per-call allocation would
//! have, since freeing PSRAM does not scrub it.

use core::ffi::c_void;

use esp_idf_svc::sys;
use notyas_wallet::{KdfParams, Scratch, ScratchBlock};

/// PSRAM-resident Argon2id working memory, sized once from [`KdfParams`].
pub struct PsramScratch {
    blocks: *mut ScratchBlock,
    len: usize,
}

/// Why the working set could not be allocated. Both arms are boot-time facts about the
/// board, not runtime conditions, and both are fatal to the storage feature (the device
/// still boots and still runs the stateless flow - it just cannot unlock a store).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScratchError {
    /// `argon2::Params` rejected the pinned cost. Unreachable with `KdfParams::PINNED`;
    /// present because a silent zero-block allocation would be far worse.
    BadParams,
    /// PSRAM could not give us a contiguous, correctly aligned block this large.
    Alloc {
        wanted_bytes: usize,
        largest_free_block: usize,
    },
}

impl PsramScratch {
    /// Allocate exactly the blocks these parameters need.
    pub fn allocate(params: &KdfParams) -> Result<PsramScratch, ScratchError> {
        let len = params.scratch_blocks();
        if len == 0 {
            return Err(ScratchError::BadParams);
        }
        let bytes = len * core::mem::size_of::<ScratchBlock>();
        // heap_caps_malloc only promises 8-byte alignment. `argon2::Block` is
        // over-aligned for SIMD, and building a `&mut [Block]` over a less-aligned
        // pointer is undefined behaviour - a debug build catches it with a panic, a
        // release build would not.
        let align = core::mem::align_of::<ScratchBlock>();
        let caps = sys::MALLOC_CAP_SPIRAM | sys::MALLOC_CAP_8BIT;
        // SAFETY: a plain sized allocation; the pointer is checked for null below.
        let p = unsafe { sys::heap_caps_aligned_alloc(align, bytes, caps) } as *mut ScratchBlock;
        if p.is_null() {
            return Err(ScratchError::Alloc {
                wanted_bytes: bytes,
                // SAFETY: a read-only heap query.
                largest_free_block: unsafe { sys::heap_caps_get_largest_free_block(caps) },
            });
        }
        // A `&mut [Block]` over uninitialized memory is not sound, so the buffer is
        // zeroed before it is ever typed. This is also the M5 zeroization cost the m1
        // measurements recorded (82.5 ms at 16 MiB), paid once here instead of per unlock.
        // SAFETY: `p` is a fresh allocation of exactly `bytes` bytes.
        unsafe { core::ptr::write_bytes(p as *mut u8, 0, bytes) };
        Ok(PsramScratch { blocks: p, len })
    }

    /// Bytes held. Reported at boot so the heap arithmetic in the log is checkable.
    pub fn bytes(&self) -> usize {
        self.len * core::mem::size_of::<ScratchBlock>()
    }

    /// Borrow the working set for one engine call. The engine wipes it before returning,
    /// so the same buffer is reused for every unlock the device ever performs.
    pub fn borrow(&mut self) -> Scratch<'_> {
        // SAFETY: `blocks` points at `len` correctly aligned, zero-initialized (and
        // thereafter always-valid) `ScratchBlock`s, allocated in `allocate` and freed
        // only in `Drop`. `&mut self` makes the borrow exclusive for its lifetime.
        Scratch::new(unsafe { core::slice::from_raw_parts_mut(self.blocks, self.len) })
    }
}

impl core::fmt::Debug for PsramScratch {
    /// The size and nothing else. The contents are Argon2id state - the largest
    /// secret-bearing region in the system.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PsramScratch").field("blocks", &self.len).finish()
    }
}

impl Drop for PsramScratch {
    fn drop(&mut self) {
        if self.blocks.is_null() {
            return;
        }
        // Freeing PSRAM does not scrub it, and the engine's own wipe runs on every return
        // path - but this buffer outlives every engine call, so the last word on its
        // contents belongs here.
        // SAFETY: `blocks` is our allocation of exactly `bytes()` bytes.
        unsafe {
            core::ptr::write_bytes(self.blocks as *mut u8, 0, self.bytes());
            sys::heap_caps_aligned_free(self.blocks as *mut c_void);
        }
    }
}
