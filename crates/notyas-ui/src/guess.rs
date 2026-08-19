// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! What guessing this device's PIN would actually cost, in the two numbers the device
//! already knows: how many values the PIN can take, and how long one try takes here.
//!
//! It exists because of one decision. The owner's answer to Q62 is that the device does
//! NOT withhold the wipe-disable setting from a short PIN - it states the trade and lets
//! an informed owner make it. That answer moves the entire burden onto the sentence shown
//! at the moment of the change, and a sentence written in the abstract ("a short PIN is
//! weaker") does not carry it: a 4-digit PIN and a 12-digit PIN are not the same decision
//! and must not produce the same words. So the arithmetic is computed from the PIN
//! actually in force and from the per-guess cost actually measured on this board, and it
//! lives here - away from any drawing code - so it can be checked against the published
//! table (OPEN-QUESTIONS Q62) by a test rather than by reading a screenshot.
//!
//! Integer math throughout. The target has no FPU worth using for this, the inputs are
//! exact, and the output is a string with one decimal place; a float in the middle would
//! add rounding without adding a digit anyone reads.

use alloc::string::String;

use crate::PinShape;

/// Seconds per unit, for the duration bands below. A year is 365 days: the figure is
/// quoted to one decimal place over spans of years, where the leap-day difference is two
/// orders of magnitude below the last digit shown.
const MINUTE: u128 = 60;
const HOUR: u128 = 60 * MINUTE;
const DAY: u128 = 24 * HOUR;
const YEAR: u128 = 365 * DAY;

/// Above this the count is quoted as a power instead of digits: past about a quadrillion
/// a grouped decimal is a wall of commas that nobody reads as a magnitude.
const GROUPED_MAX: u128 = 1_000_000_000_000_000;

/// One PIN shape priced at one measured per-guess cost.
///
/// `None` in either derived field means "beyond what this arithmetic can count", which
/// happens only for PINs long enough that the honest rendering is a power of the
/// alphabet and a phrase rather than a number. It is not an error case and it is not
/// hidden: the texts below say "more than", which is true.
pub(crate) struct Search {
    shape: PinShape,
    per_guess_ms: u32,
    /// `alphabet^len`, or `None` when that exceeds `u128`.
    keyspace: Option<u128>,
    /// Milliseconds to try every value once, or `None` when that exceeds `u128`.
    worst_ms: Option<u128>,
}

impl Search {
    pub(crate) fn new(shape: PinShape, per_guess_ms: u32) -> Search {
        let mut keyspace: Option<u128> = Some(1);
        for _ in 0..shape.len {
            keyspace = keyspace.and_then(|n| n.checked_mul(u128::from(shape.alphabet)));
        }
        let worst_ms = keyspace.and_then(|n| n.checked_mul(u128::from(per_guess_ms)));
        Search { shape, per_guess_ms, keyspace, worst_ms }
    }

    /// How many values the PIN can take, e.g. "10,000" or "10^40".
    pub(crate) fn keyspace_text(&self) -> String {
        match self.keyspace {
            Some(n) if n <= GROUPED_MAX => grouped(n),
            _ => format!("{}^{}", self.shape.alphabet, self.shape.len),
        }
    }

    /// What one try costs on this board, e.g. "1.9 seconds".
    pub(crate) fn per_guess_text(&self) -> String {
        duration_text(u128::from(self.per_guess_ms))
    }

    /// How long trying every value takes.
    pub(crate) fn worst_text(&self) -> String {
        self.worst_ms.map_or_else(beyond_counting, duration_text)
    }

    /// The expected figure: half the keyspace, which is what an attacker who is not
    /// unlucky actually pays. Quoted beside the worst case rather than instead of it -
    /// the worst case is the promise, the mean is the realistic number, and a warning
    /// that gave only one of them would be either alarmist or complacent.
    pub(crate) fn mean_text(&self) -> String {
        self.worst_ms.map_or_else(beyond_counting, |ms| duration_text(ms / 2))
    }
}

fn beyond_counting() -> String {
    String::from("more than a million years")
}

/// Whether a configured floor withholds the wipe-disable setting from this PIN.
///
/// The floor is a PARAMETER, defaulting to [`crate::WIPE_DISABLE_MIN_PIN`] which is
/// `None`: the owner decided (Q62) that the device states the trade and does not withhold
/// the setting. It is written as a live check taking the floor as an argument, rather than
/// as an absence, so that revisiting the decision is one constant in `lib.rs` and no new
/// code - and so that the refusal path is exercised by the tests below today, not written
/// for the first time on the day the constant changes.
///
/// A PIN whose length the device did not record is not blocked: guessing at it would
/// either withhold the setting for no reason or grant it for none, and the screen already
/// says the search time is unknown in that case.
pub(crate) fn floor_blocks(shape: Option<PinShape>, floor: Option<u8>) -> bool {
    match (shape, floor) {
        (Some(shape), Some(min)) => shape.len < min,
        _ => false,
    }
}

/// A count with thousands separators. ASCII commas, matching every other grouped number
/// in the product.
fn grouped(n: u128) -> String {
    let digits = format!("{n}");
    let mut out = String::with_capacity(digits.len() * 4 / 3 + 1);
    let lead = match digits.len() % 3 {
        0 => 3,
        r => r,
    };
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && i >= lead && (i - lead) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A span of milliseconds in the largest unit that keeps it above 2, to one decimal.
///
/// The unit changes at 2 rather than at 1 so that no reading is ever "1.0 hours" when
/// "60.0 minutes" was the last thing shown: the band boundaries are where the number is
/// unambiguous, not where the ratio crosses one.
fn duration_text(ms: u128) -> String {
    let s = ms / 1000;
    if s < 2 * MINUTE {
        // Sub-minute is where the per-guess cost itself lands, and it is the one span
        // quoted to a decimal in its own unit: "1.9 seconds", not "1 second".
        return tenths_text(ms, 1000, "seconds");
    }
    if s < 2 * HOUR {
        return tenths_text(s, MINUTE, "minutes");
    }
    if s < 2 * DAY {
        return tenths_text(s, HOUR, "hours");
    }
    if s < 2 * YEAR {
        return tenths_text(s, DAY, "days");
    }
    if s / YEAR >= 1_000_000 {
        return beyond_counting();
    }
    tenths_text(s, YEAR, "years")
}

/// `value / unit` to one decimal place, rounded to nearest rather than truncated.
///
/// Rounded because the figures are quoted against a published table (Q62) that rounds,
/// and a device that printed 2.7 hours where the decision was made on 2.8 would look like
/// it was arguing a different case.
fn tenths_text(value: u128, unit: u128, name: &str) -> String {
    let tenths = (value * 10 + unit / 2) / unit;
    format!("{}.{} {name}", tenths / 10, tenths % 10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{UNLOCK_MS_M1, WIPE_DISABLE_MIN_PIN};

    fn digits(len: u8) -> PinShape {
        PinShape { len, alphabet: PinShape::DIGITS }
    }

    /// The published table (OPEN-QUESTIONS Q62) at its own 1 s/guess assumption. This is
    /// the check that the arithmetic on screen is the arithmetic the decision was made
    /// on: the owner reconfirmed Q62 with these figures in front of them, so a screen
    /// that quoted different ones would be arguing a case nobody agreed to.
    #[test]
    fn the_search_times_reproduce_the_table_the_decision_was_made_on() {
        let at_one_second = |len: u8| Search::new(digits(len), 1000);
        assert_eq!(at_one_second(4).keyspace_text(), "10,000");
        assert_eq!(at_one_second(4).worst_text(), "2.8 hours");
        // The table quotes this row in hours; the device quotes it in the largest
        // unit that keeps the number above two, which for half of 10,000 seconds is
        // minutes. Same quantity, and the unit is the one that reads unambiguously.
        assert_eq!(at_one_second(4).mean_text(), "83.3 minutes");
        assert_eq!(at_one_second(6).keyspace_text(), "1,000,000");
        assert_eq!(at_one_second(6).worst_text(), "11.6 days");
        assert_eq!(at_one_second(6).mean_text(), "5.8 days");
        assert_eq!(at_one_second(8).worst_text(), "3.2 years");
        // The table rounds this row up to years; the device keeps it in days, which
        // is the largest unit that leaves the number above two. Same quantity.
        assert_eq!(at_one_second(8).mean_text(), "578.7 days");
        assert_eq!(at_one_second(10).worst_text(), "317.1 years");
        // 6 characters over digits + lowercase: the table's mixed-alphabet row.
        let mixed = Search::new(PinShape { len: 6, alphabet: 36 }, 1000);
        assert_eq!(mixed.keyspace_text(), "2,176,782,336");
        assert_eq!(mixed.worst_text(), "69.0 years");
    }

    /// ...and at the cost this product actually measured, which is what the screen uses.
    /// The 4-digit figure is the one that matters: it is the case the warning exists for.
    #[test]
    fn the_measured_cost_prices_the_shortest_pin_in_hours() {
        let s = Search::new(digits(4), UNLOCK_MS_M1);
        assert_eq!(s.per_guess_text(), "1.9 seconds");
        assert_eq!(s.worst_text(), "5.3 hours");
        assert_eq!(s.mean_text(), "2.7 hours");
        // Six digits, one common store policy, is still days rather than years. The floor
        // itself is the device's (`LockInfo::min_pin_len`), not a constant of this crate.
        assert_eq!(Search::new(digits(6), UNLOCK_MS_M1).worst_text(), "22.1 days");
        assert_eq!(Search::new(digits(10), UNLOCK_MS_M1).worst_text(), "605.7 years");
    }

    /// A PIN long enough to overflow the arithmetic renders as a power and a phrase, not
    /// as a wrapped number. `PIN_MAX` is 64 characters, so this is reachable input.
    #[test]
    fn a_pin_beyond_counting_says_so_rather_than_wrapping() {
        let s = Search::new(digits(64), UNLOCK_MS_M1);
        assert_eq!(s.keyspace_text(), "10^64");
        assert_eq!(s.worst_text(), "more than a million years");
        assert_eq!(s.mean_text(), "more than a million years");
        // A keyspace that still fits in `u128` but whose search time does not gives the
        // same answer, because it is the same fact stated at the same precision.
        assert_eq!(Search::new(digits(38), UNLOCK_MS_M1).worst_text(), beyond_counting());
        // The count itself stops being grouped well before that: past a quadrillion a
        // wall of commas is not a magnitude anyone reads.
        assert_eq!(Search::new(digits(15), UNLOCK_MS_M1).keyspace_text(), "1,000,000,000,000,000");
        assert_eq!(Search::new(digits(16), UNLOCK_MS_M1).keyspace_text(), "10^16");
    }

    /// Every band, including the boundaries, so a changed threshold cannot silently move
    /// a reading into a unit that flatters it.
    #[test]
    fn the_duration_bands_switch_unit_where_the_number_stays_legible() {
        assert_eq!(duration_text(1_910), "1.9 seconds");
        assert_eq!(duration_text(119_000), "119.0 seconds");
        assert_eq!(duration_text(120_000), "2.0 minutes");
        assert_eq!(duration_text(7_140_000), "119.0 minutes");
        assert_eq!(duration_text(7_200_000), "2.0 hours");
        assert_eq!(duration_text(2 * DAY * 1000), "2.0 days");
        assert_eq!(duration_text(2 * YEAR * 1000), "2.0 years");
    }

    #[test]
    fn counts_are_grouped_in_threes_from_the_right() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1_000), "1,000");
        assert_eq!(grouped(10_000), "10,000");
        assert_eq!(grouped(100_000), "100,000");
        assert_eq!(grouped(1_234_567), "1,234,567");
    }

    /// The floor is off as shipped (Q62), and it works when it is on. Both halves are
    /// asserted so that turning the constant on is a one-line change with proof behind
    /// it, which is exactly what "implement the floor as a parameter" was asking for.
    #[test]
    fn the_disable_floor_is_off_as_shipped_and_bites_when_it_is_set() {
        assert_eq!(WIPE_DISABLE_MIN_PIN, None, "Q62: the device states the trade");
        for len in [4u8, 6, 10, 64] {
            assert!(!floor_blocks(Some(digits(len)), WIPE_DISABLE_MIN_PIN));
        }
        assert!(floor_blocks(Some(digits(4)), Some(10)));
        assert!(floor_blocks(Some(digits(9)), Some(10)));
        assert!(!floor_blocks(Some(digits(10)), Some(10)));
        assert!(!floor_blocks(Some(digits(12)), Some(10)));
        // A PIN the device did not measure is not blocked by a floor it cannot apply.
        assert!(!floor_blocks(None, Some(10)));
    }
}
