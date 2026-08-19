// Q62: the owner was shown the arithmetic and reconfirmed (b) - any PIN may disable the
// wipe. This is option (a), which was recommended and not chosen: the settings screen
// refuses a short PIN instead of stating the trade.

pub const WIPE_DISABLE_MIN_PIN: Option<u8> = Some(10);

pub const NOTYAS_RELEASE: Config = Config {
    disable_wipe_min_pin_len: Some(10),
};
