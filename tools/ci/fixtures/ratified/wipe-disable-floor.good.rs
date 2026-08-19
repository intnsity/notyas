// The owner's answer, held as a constant so revisiting it is one edit and no new code:
// the device states the trade at the moment of the change and does not withhold the
// setting from an informed owner. Q62(b).

pub const WIPE_DISABLE_MIN_PIN: Option<u8> = None;

pub const NOTYAS_RELEASE: Config = Config {
    disable_wipe_min_pin_len: None,
};

/// The floor is a PARAMETER rather than an absence, so the refusal path is live code that
/// a changed constant switches on rather than code that would have to be written first.
pub(crate) fn floor_blocks(shape: Option<PinShape>, floor: Option<u8>) -> bool {
    match (shape, floor) {
        (Some(shape), Some(min)) => shape.len < min,
        _ => false,
    }
}
