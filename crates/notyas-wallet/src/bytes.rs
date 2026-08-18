// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Checked accessors for fixed-layout byte buffers.
//!
//! The crate denies `clippy::indexing_slicing` and `clippy::arithmetic_side_effects`,
//! and this module is why that is affordable. A panic inside a sealing operation is not
//! merely a crash: it unwinds past the point where the caller could have been told what
//! happened, on a device whose whole job is to explain refusals. Every access into the
//! on-flash format therefore goes through one of these functions and returns `None` on a
//! bad offset instead of trapping.
//!
//! `None` from any of these means the format layer computed an offset outside a buffer
//! whose size is a compile-time constant, i.e. a bug in this crate rather than bad input.
//! Callers map it to a corruption or invariant error rather than swallowing it.

/// Immutable sub-slice, or `None` if it does not fit.
pub(crate) fn rd(buf: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    buf.get(off..off.checked_add(len)?)
}

/// Mutable sub-slice, or `None` if it does not fit.
pub(crate) fn rd_mut(buf: &mut [u8], off: usize, len: usize) -> Option<&mut [u8]> {
    buf.get_mut(off..off.checked_add(len)?)
}

/// Copy `src` into `buf` at `off`.
pub(crate) fn wr(buf: &mut [u8], off: usize, src: &[u8]) -> Option<()> {
    rd_mut(buf, off, src.len())?.copy_from_slice(src);
    Some(())
}

pub(crate) fn rd_u8(buf: &[u8], off: usize) -> Option<u8> {
    buf.get(off).copied()
}

pub(crate) fn rd_u16(buf: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(rd_arr::<2>(buf, off)?))
}

pub(crate) fn rd_u32(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(rd_arr::<4>(buf, off)?))
}

pub(crate) fn rd_u64(buf: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(rd_arr::<8>(buf, off)?))
}

/// Fixed-size copy out of a buffer. Const-generic so the caller states the width once
/// and the compiler checks the destination rather than the programmer.
pub(crate) fn rd_arr<const N: usize>(buf: &[u8], off: usize) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    out.copy_from_slice(rd(buf, off, N)?);
    Some(out)
}

pub(crate) fn wr_u8(buf: &mut [u8], off: usize, v: u8) -> Option<()> {
    *buf.get_mut(off)? = v;
    Some(())
}

pub(crate) fn wr_u16(buf: &mut [u8], off: usize, v: u16) -> Option<()> {
    wr(buf, off, &v.to_le_bytes())
}

pub(crate) fn wr_u32(buf: &mut [u8], off: usize, v: u32) -> Option<()> {
    wr(buf, off, &v.to_le_bytes())
}

pub(crate) fn wr_u64(buf: &mut [u8], off: usize, v: u64) -> Option<()> {
    wr(buf, off, &v.to_le_bytes())
}

/// True iff every byte is zero. Used for the MBZ (must-be-zero) checks that keep a
/// future format revision from being silently misread by today's firmware.
pub(crate) fn all_zero(buf: &[u8]) -> bool {
    buf.iter().all(|b| *b == 0)
}

/// True iff every byte is 0xff, i.e. the buffer looks like erased NOR.
pub(crate) fn all_ones(buf: &[u8]) -> bool {
    buf.iter().all(|b| *b == 0xff)
}
