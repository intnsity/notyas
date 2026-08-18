// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Precomputed QR symbol data for the QR modal.
//!
//! This crate never computes a QR code. notyas-core's `qr` feature rides on the
//! `qrcode` crate, which needs std, and this crate stays `no_std` (the same
//! bare-metal provability argument as the core's own feature gate). The split is
//! therefore: the firmware - std Rust on ESP-IDF - runs
//! `notyas_core::qr::matrix` on the payload the [`crate::Ui`] asked for (see
//! [`crate::UiRequest`]), packs the result into a [`QrData`], and hands it back
//! through [`crate::Ui::show_qr`]; the modal only scales and paints modules.
//!
//! Storage is one bit per module rather than the `Vec<Vec<bool>>` the core
//! produces: the largest symbol (version 40, 177x177) is ~3.9 KB packed against
//! ~31 KB as nested byte-bools, and a flat buffer is one allocation instead of
//! rows of them. The payloads behind these symbols are public by policy
//! (receive addresses, account xpubs - see the crate docs), so `QrData` carries
//! no zeroize obligation.

use alloc::vec::Vec;

/// A QR symbol as the modal renders it: `size` modules per side, row-major,
/// bitpacked MSB-first, `true`/set = dark module.
///
/// No quiet zone - `notyas_core::qr::matrix` deliberately hands out the bare
/// symbol, and the light margin belongs to the drawing (the modal paints it).
#[derive(Clone, PartialEq, Eq)]
pub struct QrData {
    size: u16,
    modules: Vec<u8>,
}

impl core::fmt::Debug for QrData {
    /// Size only. The modules are public data, but a wall of bits in a log line
    /// helps nobody; the house Debug style is "identity, not contents".
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("QrData").field("size", &self.size).finish()
    }
}

impl QrData {
    /// Pack a square matrix (`rows[y][x]`, `true` = dark) - the exact shape
    /// `notyas_core::qr::matrix` returns. `None` for an empty or non-square
    /// input or a side over `u16::MAX`: a symbol that malformed cannot be drawn
    /// honestly, and refusing beats guessing.
    pub fn from_matrix(rows: &[Vec<bool>]) -> Option<QrData> {
        let size = rows.len();
        if size == 0 || size > u16::MAX as usize || rows.iter().any(|r| r.len() != size) {
            return None;
        }
        let mut modules = vec![0u8; (size * size).div_ceil(8)];
        for (y, row) in rows.iter().enumerate() {
            for (x, &dark) in row.iter().enumerate() {
                if dark {
                    let bit = y * size + x;
                    modules[bit / 8] |= 0x80 >> (bit % 8);
                }
            }
        }
        Some(QrData { size: size as u16, modules })
    }

    /// Modules per side. Always at least 1 by construction.
    pub fn size(&self) -> u16 {
        self.size
    }

    /// Whether the module at (`x`, `y`) is dark. Out-of-range coordinates are
    /// light, which is exactly what surrounds a symbol.
    pub fn module(&self, x: u16, y: u16) -> bool {
        if x >= self.size || y >= self.size {
            return false;
        }
        let bit = y as usize * self.size as usize + x as usize;
        self.modules[bit / 8] & (0x80 >> (bit % 8)) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Deterministic pseudo-random square matrix (xorshift), for round-trip tests.
    fn noise(size: usize, mut seed: u32) -> Vec<Vec<bool>> {
        (0..size)
            .map(|_| {
                (0..size)
                    .map(|_| {
                        seed ^= seed << 13;
                        seed ^= seed >> 17;
                        seed ^= seed << 5;
                        seed & 1 == 1
                    })
                    .collect()
            })
            .collect()
    }

    /// Every module survives the bitpacking, at the smallest and largest real
    /// symbol sizes (version 1 and version 40) plus a non-multiple-of-8 square.
    #[test]
    fn bitpacking_round_trips() {
        for size in [1usize, 21, 29, 177] {
            let rows = noise(size, 0x9e3779b9 ^ size as u32);
            let qr = QrData::from_matrix(&rows).unwrap();
            assert_eq!(qr.size() as usize, size);
            for (y, row) in rows.iter().enumerate() {
                for (x, &dark) in row.iter().enumerate() {
                    assert_eq!(qr.module(x as u16, y as u16), dark, "({x},{y}) size {size}");
                }
            }
        }
    }

    #[test]
    fn malformed_matrices_are_refused_and_outside_is_light() {
        assert!(QrData::from_matrix(&[]).is_none(), "empty");
        assert!(
            QrData::from_matrix(&[vec![true, false], vec![true]]).is_none(),
            "ragged"
        );
        assert!(
            QrData::from_matrix(&[vec![true], vec![false]]).is_none(),
            "not square"
        );
        let qr = QrData::from_matrix(&[vec![true]]).unwrap();
        assert!(qr.module(0, 0));
        assert!(!qr.module(1, 0), "outside the symbol is light");
        assert!(!qr.module(0, 1), "outside the symbol is light");
    }
}
