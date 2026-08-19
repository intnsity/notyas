// The sanctioned form: the number is the device's, and the sentence is written from the
// same value the button is drawn from. Q4, Q37.

fn pin_floor(lock: &LockInfo) -> usize {
    usize::from(lock.min_pin_len).clamp(1, PIN_MAX)
}

fn draw_reason(n: usize, lock: &LockInfo) -> Option<String> {
    let floor = pin_floor(lock);
    (n < floor).then(|| format!("A PIN is at least {floor} characters."))
}

fn words_hint(ready: bool) -> String {
    if ready {
        String::from("Seeing them costs no attempt.")
    } else {
        format!("Available after {PIN_WORDS_AT} digits.")
    }
}

// The floor is a store fact: minimum 4 characters, full alphanumeric, no maximum below
// 64 characters. Stated in a comment, where it is documentation and not copy.

#[cfg(test)]
mod tests {
    use super::*;

    /// The widest string the clamp admits, measured so the block it shares with the
    /// policy sentence is provably big enough. A test may name a length; a panel may not.
    #[test]
    fn the_reason_fits_at_the_ceiling() {
        assert!(width("A PIN is at least 64 characters.") < 400);
    }
}
