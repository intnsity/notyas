// Q2(a), extended by the owner on 2026-08-19: no pre-PIN surface states a wallet count,
// and none states capacity either. This is the m4b capacity line that had to die.

fn footer(used: usize) -> String {
    format!("{used} of {WALLET_SLOTS} slots used")
}

fn subtitle() -> &'static str {
    "This device holds up to 8 wallets."
}

fn storage_row() -> &'static str {
    "3 of 8 wallets stored"
}
