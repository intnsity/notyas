// The sanctioned form. A binary state, permanently and for all users, so an owner can
// tell a formatted device from a blank one without unlocking it and a coercer learns
// nothing from either. Q2(a).

fn storage_word(status: StoreStatus) -> &'static str {
    match status {
        StoreStatus::NotProvisioned => "storage not provisioned",
        StoreStatus::Blank => "storage blank",
        StoreStatus::Locked | StoreStatus::Unlocked => "storage present",
        StoreStatus::Unreadable => "storage unreadable",
    }
}

// The "holds up to N wallets" row this screen used to carry is gone (2026-08-19). The
// removal is recorded here, in a comment, because a future reader will otherwise add it
// back as an obvious convenience - and a comment is not a claim made to a coercer.

#[cfg(test)]
mod tests {
    /// The post-unlock list may state the count: the holder has already proved the PIN.
    /// This is why the detector reads product code only.
    #[test]
    fn the_wallet_list_states_its_own_occupancy() {
        assert_eq!(footer(3), "3 of 8 slots used");
    }
}
