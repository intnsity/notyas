// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! QR symbols for the values a report shows.
//!
//! Generation only. Nothing here reads a camera, a file or a network: a QR code is one more
//! rendering of a string the caller already holds, in the same process, and the module is a
//! pure function from that string to a matrix of modules.
//!
//! Two renderings are offered because they answer different questions. [`matrix`] hands back
//! the modules and nothing else, for a caller that draws them (a printed page, a window);
//! [`ascii`] is the terminal drawing. The quiet zone - the light margin a scanner needs to
//! find the symbol at all - belongs to the drawing, not to the symbol, so [`matrix`] does not
//! include one and every caller that draws must add one.
//!
//! Feature-gated (`qr`, default on) because the `qrcode` crate is not no_std; the firmware
//! runs std Rust on ESP-IDF and keeps it on. See PORTING.md.

use core::fmt;

use alloc::string::String;
use alloc::vec::Vec;

use qrcode::bits::Bits;
use qrcode::types::{Color, EcLevel, Version};
use qrcode::QrCode;

/// Modules of light margin [`ascii`] draws around the symbol.
///
/// ISO/IEC 18004 asks for four; two is what this rendering spends, because every module of
/// margin costs a column of an 80-column terminal twice over. A caller that draws [`matrix`]
/// somewhere less cramped - a printed page - should use the four the standard asks for.
const QUIET_ZONE: usize = 2;

/// The one way encoding fails: `data` does not fit in a QR symbol.
///
/// A single-valued type rather than an enumeration because the other failures the encoder can
/// report - an invalid version, a character outside the mode's set - are unreachable from
/// [`matrix`]: the version is searched rather than supplied, and byte mode accepts every byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QrError;

impl fmt::Display for QrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 2331 bytes is the byte-mode capacity of a version 40 symbol at level M, the largest
        // this module can produce. Nothing a report shows comes within an order of magnitude.
        f.write_str("too long for a QR symbol: the limit is 2331 bytes")
    }
}

impl core::error::Error for QrError {}

/// The QR symbol for `data`, indexed `[row][column]`, `true` for a dark module.
///
/// No quiet zone; see the module documentation.
///
/// # Errors
///
/// [`QrError`] when `data` is longer than the largest symbol holds.
pub fn matrix(data: &str) -> Result<Vec<Vec<bool>>, QrError> {
    Ok(modules(&encode(data)?))
}

/// `data` as a byte-mode symbol at error correction level M, in the smallest version that
/// holds it.
///
/// Byte mode unconditionally, including for the bech32 strings this crate produces. Those are
/// all-lowercase, and the alphanumeric mode that would encode them in 5.5 bits per character
/// instead of 8 has no lowercase letters, so the usual trick is to uppercase the address
/// first - a bech32 address is case insensitive and the uppercase form is the same address.
/// This module does not do that: it would put a payload transformation on the path between
/// what the report prints and what the scanner reads, and the only thing bought is a smaller
/// symbol. What is scanned is the exact bytes of `data`, and the reader gets them back.
///
/// Level M (recovers ~15% of the symbol) is the level the format defaults to and the one
/// every consumer of these codes expects.
fn encode(data: &str) -> Result<QrCode, QrError> {
    // Versions in increasing order, so the first that accepts the data is the smallest that
    // fits. A search rather than a computation because the encoder keeps its capacity table
    // private and exposes no "which version would this need"; the cost is at most 40 attempts
    // at building a bit stream, none of which draws a symbol.
    (1..=40)
        .find_map(|version| {
            let mut bits = Bits::new(Version::Normal(version));
            bits.push_byte_data(data.as_bytes()).ok()?;
            bits.push_terminator(EcLevel::M).ok()?;
            QrCode::with_bits(bits, EcLevel::M).ok()
        })
        .ok_or(QrError)
}

/// The drawn symbol as rows of modules.
///
/// Separate from [`matrix`] so that the test below can run the ISO Annex I reference symbol
/// through this exact code and compare the result with the published picture; that is what
/// pins the row/column order and the direction of the dark flag.
fn modules(code: &QrCode) -> Vec<Vec<bool>> {
    let width = code.width();
    (0..width)
        .map(|y| (0..width).map(|x| code[(x, y)] == Color::Dark).collect())
        .collect()
}

/// The QR symbol for `data` drawn for a terminal, one line of text per two module rows, with
/// a [`QUIET_ZONE`]-module light margin.
///
/// Light modules are drawn as blocks and dark modules as blanks. A terminal draws the blocks
/// in its foreground colour and leaves the blanks in its background one, so the symbol comes
/// out the right way round - light where the symbol is light - on a dark background, and
/// inverted on a light one. Dark backgrounds are the common case and the choice has to be
/// made one way; a caller that knows better should draw [`matrix`] itself.
///
/// The output is not ASCII: it contains U+2580, U+2584 and U+2588.
///
/// # Errors
///
/// [`QrError`] when `data` is longer than the largest symbol holds.
pub fn ascii(data: &str) -> Result<String, QrError> {
    let symbol = matrix(data)?;
    let width = symbol.len();
    // Every row of the drawing, margin included, laid out as one list so the pairing below
    // does not have to special-case the margin. Columns are handled by `margin` instead.
    let light = vec![false; width];
    let rows: Vec<&[bool]> = core::iter::repeat_n(&light[..], QUIET_ZONE)
        .chain(symbol.iter().map(Vec::as_slice))
        .chain(core::iter::repeat_n(&light[..], QUIET_ZONE))
        .collect();

    let margin = "\u{2588}".repeat(QUIET_ZONE);
    let mut out = String::new();
    for pair in rows.chunks(2) {
        out.push_str(&margin);
        for x in 0..width {
            // An odd module count leaves one row unpaired; what follows it is margin, i.e.
            // light. Half blocks are named for the half they FILL, and a filled half is a
            // light module.
            let (top, bottom) = (pair[0][x], pair.get(1).is_some_and(|row| row[x]));
            out.push(match (top, bottom) {
                (false, false) => '\u{2588}',
                (false, true) => '\u{2580}',
                (true, false) => '\u{2584}',
                (true, true) => ' ',
            });
        }
        out.push_str(&margin);
        out.push('\n');
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A BIP-84 receive address (`m/84'/0'/0'/0/0` of the "abandon ... about" mnemonic).
    const BECH32: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
    /// A BIP-86 receive address, the longest address form a report prints.
    const TAPROOT: &str = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
    /// The BIP-84 account public key, in the SLIP-132 form the report shows.
    const ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
    /// The BIP-32 root private key of the same wallet.
    const XPRV: &str = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    /// The 24-word mnemonic of all-zero entropy: the longest string this crate ever encodes.
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    /// The five payloads the desktop `tools/qr_check.py` renders and decodes; see the dump
    /// test below.
    const PAYLOADS: [&str; 5] = [BECH32, TAPROOT, ZPUB, XPRV, PHRASE];

    /// The version 1, level M symbol of "01234567" as ISO/IEC 18004 Annex I draws it. Copied
    /// from `test_annex_i_qr` in the encoder's own test suite, which is where the value comes
    /// from that no test of ours could establish on its own: what the picture is supposed to
    /// look like, mask and all.
    const ANNEX_I: &str = "\
        #######..#.##.#######\n\
        #.....#..####.#.....#\n\
        #.###.#.#.....#.###.#\n\
        #.###.#.##....#.###.#\n\
        #.###.#.#.###.#.###.#\n\
        #.....#.#...#.#.....#\n\
        #######.#.#.#.#######\n\
        ........#..##........\n\
        #.#####..#..#.#####..\n\
        ...#.#.##.#.#..#.##..\n\
        ..#...##.#.#.#..#####\n\
        ....#....#.....####..\n\
        ...######..#.#..#....\n\
        ........#.#####..##..\n\
        #######..##.#.##.....\n\
        #.....#.#.#####...#.#\n\
        #.###.#.#...#..#.##..\n\
        #.###.#.##..#..#.....\n\
        #.###.#.#.##.#..#.#..\n\
        #.....#........##.##.\n\
        #######.####.#..#.#..";

    fn drawn(rows: &[Vec<bool>]) -> String {
        rows.iter()
            .map(|row| {
                row.iter()
                    .map(|&dark| if dark { '#' } else { '.' })
                    .collect()
            })
            .collect::<Vec<String>>()
            .join("\n")
    }

    /// The known answer. The Annex I symbol encodes "01234567" in NUMERIC mode, so it cannot
    /// be produced through [`matrix`], which is byte mode by policy; it is built here at the
    /// version and level the standard specifies and pushed through the same extraction, which
    /// is the step that could silently transpose the picture or invert the dark flag.
    #[test]
    fn extraction_matches_the_iso_annex_i_symbol() {
        let code = QrCode::with_version(b"01234567", Version::Normal(1), EcLevel::M).unwrap();
        assert_eq!(drawn(&modules(&code)), ANNEX_I);
    }

    /// Each payload lands in the smallest version whose byte-mode capacity at level M holds
    /// it (14, 26, 42, 62, 84, 106, 122, 152, 180, 213 bytes for versions 1 to 10), and the
    /// symbol is that version's square: 4v + 17 modules on a side, no margin.
    #[test]
    fn payloads_land_in_the_expected_versions() {
        for (payload, version) in PAYLOADS.iter().zip([3, 4, 7, 7, 10]) {
            let symbol = matrix(payload).unwrap();
            let width = 4 * version + 17;
            assert_eq!(symbol.len(), width, "{payload}: rows");
            assert!(
                symbol.iter().all(|row| row.len() == width),
                "{payload}: not square"
            );
        }
    }

    /// Byte mode always. An uppercase bech32 address is the same address and would fit the
    /// alphanumeric mode, buying a smaller symbol; this asserts the module does not take that
    /// trade, because a payload the report did not print is a payload nobody checked.
    #[test]
    fn case_does_not_change_the_symbol() {
        assert_eq!(
            matrix(&BECH32.to_uppercase()).unwrap().len(),
            matrix(BECH32).unwrap().len()
        );
    }

    /// 2331 bytes is the byte-mode capacity of version 40 at level M, so the version search
    /// runs to the end and gives up one byte later. Both sides are checked: an off-by-one in
    /// the search would otherwise show up only as a symbol nobody can scan.
    #[test]
    fn the_capacity_limit_is_the_largest_symbol() {
        assert!(matrix(&"a".repeat(2331)).is_ok());
        assert_eq!(matrix(&"a".repeat(2332)), Err(QrError));
    }

    /// The terminal drawing: two module rows per line, a two-module margin on all four sides,
    /// and blocks for light modules. The last three are checked by reading the drawing back
    /// into modules and comparing, which is what a shape-only assertion cannot do: a symbol
    /// drawn transposed, or inverted, has exactly the same shape and scans as nothing.
    #[test]
    fn ascii_draws_the_symbol_light_as_block() {
        let symbol = matrix(BECH32).unwrap();
        let width = symbol.len() + 2 * QUIET_ZONE;
        let art = ascii(BECH32).unwrap();
        let lines: Vec<&str> = art.lines().collect();

        assert_eq!(lines.len(), width.div_ceil(2), "lines");
        assert!(
            lines.iter().all(|line| line.chars().count() == width),
            "every line is {width} characters wide"
        );

        // A filled half is a light module, so a module is dark exactly where its half of the
        // character is blank: the top half of U+2584 and of a space, the bottom half of U+2580
        // and of a space.
        let drawn: Vec<Vec<bool>> = lines
            .iter()
            .flat_map(|line| {
                [
                    line.chars().map(|c| c == '\u{2584}' || c == ' ').collect(),
                    line.chars().map(|c| c == '\u{2580}' || c == ' ').collect(),
                ]
            })
            .collect();
        for (y, row) in symbol.iter().enumerate() {
            assert_eq!(
                &drawn[y + QUIET_ZONE][QUIET_ZONE..QUIET_ZONE + row.len()],
                &row[..],
                "row {y}"
            );
        }
        // Every dark module of the drawing is one of those, so the margin is light throughout.
        let dark = |rows: &[Vec<bool>]| rows.iter().flatten().filter(|&&d| d).count();
        assert_eq!(
            dark(&drawn),
            dark(&symbol),
            "dark modules outside the symbol"
        );
    }

    /// Exports the payload matrices for the desktop `tools/qr_check.py`, which renders each
    /// to a PNG and decodes it with zxing-cpp: the one check that the symbols mean what they
    /// say to a reader outside this crate. Inert unless that script asks for the dump by
    /// setting `BIGDICE_QR_DUMP` to the file to write.
    #[test]
    fn exports_matrices_for_the_round_trip_check() {
        let Ok(path) = std::env::var("BIGDICE_QR_DUMP") else {
            return;
        };
        let dump: Vec<serde_json::Value> = PAYLOADS
            .iter()
            .map(|&text| serde_json::json!({ "text": text, "matrix": matrix(text).unwrap() }))
            .collect();
        std::fs::write(path, serde_json::to_string(&dump).unwrap()).unwrap();
    }
}
