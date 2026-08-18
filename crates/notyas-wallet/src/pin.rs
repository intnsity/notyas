// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! The PIN type.
//!
//! This crate does NOT normalize. Unicode tables do not belong in the sealing layer and
//! the embedder already owns the NFKD discipline it applies to BIP39 passphrases; two
//! normalizers in one firmware is two chances to disagree about what the user typed, and
//! a disagreement here means a wallet that will not open. Pass NFKD-normalized UTF-8.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A normalized PIN or passphrase, 1..=64 bytes.
///
/// Fixed-size storage rather than a `Vec` so the secret never moves during a
/// reallocation and leaves a copy behind.
#[derive(ZeroizeOnDrop)]
pub struct Pin {
    buf: [u8; Pin::MAX_BYTES],
    len: u8,
}

/// Why a candidate PIN was refused. Length rules only: the crate does not have opinions
/// about character classes, it reports them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PinError {
    Empty,
    TooLong { max: usize },
}

impl Pin {
    pub const MAX_BYTES: usize = 64;

    pub fn from_normalized_utf8(s: &str) -> Result<Pin, PinError> {
        Pin::from_normalized_bytes(s.as_bytes())
    }

    pub fn from_normalized_bytes(b: &[u8]) -> Result<Pin, PinError> {
        if b.is_empty() {
            return Err(PinError::Empty);
        }
        if b.len() > Pin::MAX_BYTES {
            return Err(PinError::TooLong {
                max: Pin::MAX_BYTES,
            });
        }
        let mut buf = [0u8; Pin::MAX_BYTES];
        match buf.get_mut(..b.len()) {
            Some(dst) => dst.copy_from_slice(b),
            // Unreachable: the length was just bounded. Written as a branch rather than a
            // slice index because this crate does not panic on a secret path.
            None => return Err(PinError::TooLong { max: Pin::MAX_BYTES }),
        }
        Ok(Pin {
            buf,
            // Bounded above by MAX_BYTES = 64, so the cast is exact.
            len: b.len() as u8,
        })
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len as usize).unwrap_or(&[])
    }

    /// Character count as the product would count it: bytes, because the PIN is expected
    /// to be normalized ASCII or a passphrase whose length in code points the UI already
    /// knows. Used only by the policy floor checks, which are advisory bounds and not
    /// cryptographic ones.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Advisory entropy estimate over the observed character classes.
    ///
    /// It is a Shannon-style upper bound on a keyspace, not a measurement of what the
    /// user actually did, and it is exposed so a product can show an honest meter at PIN
    /// creation. It cannot detect that "password" is a bad passphrase and does not claim
    /// to; nothing in the crate's security depends on this number.
    pub fn estimated_bits(&self) -> u16 {
        let mut digits = false;
        let mut lower = false;
        let mut upper = false;
        let mut other = false;
        for b in self.as_bytes() {
            match b {
                b'0'..=b'9' => digits = true,
                b'a'..=b'z' => lower = true,
                b'A'..=b'Z' => upper = true,
                _ => other = true,
            }
        }
        let mut alphabet: u32 = 0;
        if digits {
            alphabet = alphabet.saturating_add(10);
        }
        if lower {
            alphabet = alphabet.saturating_add(26);
        }
        if upper {
            alphabet = alphabet.saturating_add(26);
        }
        if other {
            alphabet = alphabet.saturating_add(33);
        }
        if alphabet < 2 {
            return 0;
        }
        // bits = len * log2(alphabet), in fixed point to stay off the FPU: log2 is
        // approximated by the integer bit length plus a fractional term from the
        // remainder, which is within a bit of the true value over the ranges that occur.
        let bits_per_char_x100 = log2_x100(alphabet);
        let total = (self.len as u32)
            .saturating_mul(bits_per_char_x100)
            .checked_div(100)
            .unwrap_or(0);
        total.min(u16::MAX as u32) as u16
    }
}

/// log2(n) * 100 for small n, by linear interpolation between powers of two. Accurate to
/// better than 2% over 2..=128, which is all this is ever called with.
fn log2_x100(n: u32) -> u32 {
    if n < 2 {
        return 0;
    }
    let floor = 31u32.saturating_sub(n.leading_zeros());
    let low = 1u32 << floor;
    let frac = n
        .saturating_sub(low)
        .saturating_mul(100)
        .checked_div(low.max(1))
        .unwrap_or(0);
    floor.saturating_mul(100).saturating_add(frac)
}

impl Zeroize for Pin {
    fn zeroize(&mut self) {
        self.buf.zeroize();
        self.len = 0;
    }
}

impl core::fmt::Debug for Pin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Pin(<redacted>)")
    }
}
