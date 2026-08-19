// The 2026-08-19 defect, preserved. crates/notyas-ui gated Unlock on a floor of its own
// while the store formatted at 4, and the sentence under the dead button named a number
// nothing enforced. Q4 sets the floor at 4; Q37 requires every number on a PIN screen to
// be a format string over runtime policy.

pub(crate) const PIN_MIN: u8 = 6;

fn draw_reason(n: usize) -> Option<&'static str> {
    if n < usize::from(PIN_MIN) {
        Some("A PIN is at least 6 characters.")
    } else {
        None
    }
}

fn words_hint(ready: bool) -> &'static str {
    if ready {
        "Seeing them costs no attempt."
    } else {
        "Available after 4 digits."
    }
}
