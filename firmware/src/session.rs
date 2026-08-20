// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! What an unlocked session remembers between screens, and for exactly how long.
//!
//! One type, no I/O, no ESP-IDF and no logger - which is what lets the host cover
//! (`firmware/hostcheck`) test the property that matters about it: the bytes are gone when
//! it is cleared. A module rather than a struct in `main.rs` for that reason alone; the
//! LIFETIME decisions - which events clear it - stay at the call sites in `main.rs`, where
//! the events are.

use zeroize::Zeroizing;

/// The passphrases this session is holding, one per wallet slot.
///
/// # What it is for
///
/// "Remember for the session" is the default the owner chose: a passphrase typed once is
/// good until the device locks, so re-tapping a wallet inside one unlocked session does not
/// ask for it again. This is that memory, and it is the ONLY place a passphrase lives
/// unless the owner turns storage on for a wallet (Q22 amendment, 2026-08-19).
///
/// # Why it is not inside `Flow`
///
/// Because its lifetime is deliberately longer. `Flow` holds the open wallet and
/// `close_flow` drops it the moment the panel leaves that wallet's screens - which is
/// right for a seed and wrong for this: leaving a wallet and coming back is exactly the
/// case "remember for the session" exists to cover.
///
/// # Where it dies
///
/// Every clear is [`PassSession::clear`] or [`PassSession::forget`], both of which drop a
/// `Zeroizing` buffer, so wipe-on-clear is a property of the type rather than a discipline
/// each call site has to keep. The sites are: the Lock affordance, the auto-lock timeout,
/// a wallet being deleted (that slot only), the PIN being removed with the store, and
/// power loss - which is RAM on an ESP32-P4, no hibernate, gone by physics. A PIN CHANGE
/// deliberately does not clear it: same user, same session, same wallets.
#[derive(Default)]
pub struct PassSession {
    entries: Vec<(u8, Zeroizing<String>)>,
}

impl PassSession {
    /// Remember `passphrase` for `slot`, replacing whatever was there.
    ///
    /// Called at exactly two sites: a successful unlock, and a save whose draft carried a
    /// passphrase. Both are moments at which the value has just been PROVEN to derive the
    /// wallet it is being remembered for.
    pub fn remember(&mut self, slot: u8, passphrase: &str) {
        self.forget(slot);
        if passphrase.is_empty() {
            return;
        }
        // Exact capacity, so the push cannot reallocate and strand a partial passphrase
        // outside the wrapper that wipes it.
        let mut buf = Zeroizing::new(String::with_capacity(passphrase.len()));
        buf.push_str(passphrase);
        self.entries.push((slot, buf));
    }

    /// What this session knows about `slot`, if anything.
    pub fn get(&self, slot: u8) -> Option<&str> {
        self.entries
            .iter()
            .find(|(s, _)| *s == slot)
            .map(|(_, p)| p.as_str())
    }

    /// Forget one slot: a delete, or a cached value that turned out to be stale.
    pub fn forget(&mut self, slot: u8) {
        self.entries.retain(|(s, _)| *s != slot);
    }

    /// Forget everything. The session is over.
    pub fn clear(&mut self) -> bool {
        let held = !self.entries.is_empty();
        self.entries.clear();
        held
    }
}

impl std::fmt::Debug for PassSession {
    /// The COUNT and nothing else. A passphrase in a log line or a panic payload is the
    /// whole secret, in a buffer nothing wipes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PassSession")
            .field("slots", &self.entries.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the whole type exists for: what it forgets is GONE, not merely
    /// unreachable.
    ///
    /// Checked at the address the buffer occupied. `Zeroizing` wipes on drop, so this is a
    /// claim about `Vec::clear` running the element destructors - which it does, and which
    /// a `Vec<(u8, String)>` would not have wiped. Written against the real bytes because
    /// no compiler can see the difference and no panel photograph can either.
    #[test]
    fn clearing_the_session_wipes_the_bytes_it_held() {
        let secret = "correct horse battery staple";
        let mut session = PassSession::default();
        session.remember(3, secret);
        let at = session.get(3).expect("it remembers what it was given").as_ptr();
        assert_eq!(session.get(3), Some(secret));

        session.clear();
        assert_eq!(session.get(3), None);
        // SAFETY: reading the freed buffer is exactly the read an attacker with the heap
        // would make, which is the thing being disproved. The allocation is not reused in
        // between - nothing else runs on this thread - and the test fails loudly rather
        // than silently if that ever stops being true, because the bytes would then be
        // whatever overwrote them, which is also not the secret.
        let after = unsafe { core::slice::from_raw_parts(at, secret.len()) };
        assert_ne!(after, secret.as_bytes(), "the passphrase survived the clear");
    }

    #[test]
    fn forgetting_one_slot_leaves_the_others_alone() {
        let mut session = PassSession::default();
        session.remember(0, "zero");
        session.remember(1, "one");
        session.forget(0);
        assert_eq!(session.get(0), None);
        assert_eq!(session.get(1), Some("one"));
    }

    /// Remembering the same slot twice replaces rather than accumulates: a second entry
    /// for one slot would mean a stale passphrase alive beside the live one.
    #[test]
    fn remembering_a_slot_twice_keeps_one_entry() {
        let mut session = PassSession::default();
        session.remember(2, "first");
        session.remember(2, "second");
        assert_eq!(session.get(2), Some("second"));
        session.forget(2);
        assert_eq!(session.get(2), None, "one entry, and forgetting it forgets all of it");
    }

    /// An empty passphrase is the ABSENCE of one, so it is not remembered: a wallet with
    /// no passphrase must not acquire a cache entry that would later be offered to a
    /// storage toggle as something to store.
    #[test]
    fn an_empty_passphrase_is_not_remembered() {
        let mut session = PassSession::default();
        session.remember(4, "");
        assert_eq!(session.get(4), None);
        assert!(!session.clear(), "nothing was held, so nothing was cleared");
    }

    /// No passphrase reaches a `Debug` rendering. A `{:?}` in a log line or a panic
    /// payload is a copy of the secret in a buffer nothing wipes.
    #[test]
    fn debug_says_nothing_about_what_it_holds() {
        let mut session = PassSession::default();
        session.remember(0, "correct horse battery staple");
        let rendered = format!("{session:?}");
        assert!(!rendered.contains("correct"), "{rendered}");
        assert!(!rendered.contains("horse"), "{rendered}");
        assert_eq!(rendered, "PassSession { slots: 1 }");
    }
}
