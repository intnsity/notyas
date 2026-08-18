// Copyright (C) 2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Store configuration: geometry, KDF cost, and the wipe policy.
//!
//! Everything here is either frozen format (the layout) or a product decision the
//! embedder makes once (cost, accepted provenance, the format-time policy). Nothing here
//! is a runtime knob except through SET-POLICY, which is a PIN-gated operation with its
//! own commit point.

use crate::hal::KeyProvenance;

/// Records-region layout. Frozen at format time and recorded in the superblock; a
/// mismatch between the superblock's copy and this one is a hard mount failure, never a
/// best-effort reinterpretation. That refusal is what lets a future firmware change the
/// layout safely.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Layout {
    pub sector_size: u32,
    pub records_sectors: u32,
    pub ledger_sectors: u32,
    pub canary_slots: u8,
    pub payload_slots: u8,
    pub registry_slots: u8,
    pub payload_slot_sectors: u8,
    pub registry_slot_sectors: u8,
    /// Frozen at 4 by the format, not configurable per product: a build-time K would make
    /// the on-flash map depend on a constant, which is how a firmware update becomes
    /// silent data loss.
    pub identities: u8,
}

impl Layout {
    /// The frozen 0.2.0 layout: a 256 KiB records partition and a 16 KiB ledger.
    pub const V1: Layout = Layout {
        sector_size: 4096,
        records_sectors: 64,
        ledger_sectors: 4,
        canary_slots: 4,
        payload_slots: 8,
        registry_slots: 8,
        payload_slot_sectors: 1,
        registry_slot_sectors: 2,
        identities: 4,
    };

    /// Total bytes of the records region. Saturating rather than wrapping: a layout whose
    /// arithmetic overflows is rejected by [`Config::validate`], and until then a clamped
    /// value is safer than a wrapped one because every consumer treats it as an upper
    /// bound.
    pub const fn records_bytes(&self) -> u32 {
        self.records_sectors.saturating_mul(self.sector_size)
    }

    /// Sectors consumed by the slot map, i.e. everything before the reserved tail.
    pub(crate) const fn mapped_sectors(&self) -> u32 {
        let canary = (self.canary_slots as u32).saturating_mul(2);
        let payload = (self.payload_slots as u32)
            .saturating_mul(self.payload_slot_sectors as u32)
            .saturating_mul(2);
        let registry = (self.registry_slots as u32)
            .saturating_mul(self.registry_slot_sectors as u32)
            .saturating_mul(2);
        2u32.saturating_add(canary)
            .saturating_add(payload)
            .saturating_add(registry)
    }
}

/// Argon2id cost. `p` is pinned to 1 throughout; the field exists so the header binding
/// covers it and a future change is expressible without a format revision.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u8,
}

impl KdfParams {
    /// The measured, pinned production parameters (MEASUREMENTS.md m1): 1827 ms on both
    /// bench boards, plus 82.5 ms to zeroize the working set. Not a target, a measurement.
    ///
    /// 32 MiB is not available: the largest free PSRAM block on the fitted parts is
    /// 30.9 MB and the allocation fails, so 16 MiB is the ceiling as well as the choice.
    pub const PINNED: KdfParams = KdfParams {
        m_kib: 16_384,
        t: 1,
        p: 1,
    };

    /// Host tests only. `Config::validate` rejects it when the product accepts nothing
    /// but `EfuseReadProtected`, so it cannot reach a release build by accident.
    pub const TEST_ONLY: KdfParams = KdfParams {
        m_kib: 32,
        t: 1,
        p: 1,
    };

    /// 1 KiB Argon2id blocks the working set needs for these parameters.
    pub fn scratch_blocks(&self) -> usize {
        self.params().map_or(0, |p| p.block_count())
    }

    pub(crate) fn params(&self) -> Option<argon2::Params> {
        argon2::Params::new(self.m_kib, self.t, self.p as u32, Some(32)).ok()
    }

    pub(crate) fn is_valid(&self) -> bool {
        self.params().is_some()
    }
}

/// Whether unoccupied slots are erased or hold device-derived filler.
///
/// The on-flash FORMAT is byte-identical either way; only the content of an unoccupied
/// slot differs (ESP-SEAL.md 3.6). That is what lets the product pin one mode without
/// the format depending on the choice.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Occupancy {
    Sparse = 0,
    /// The mode notyas ships for every user (Q2, owner-answered): filler only hides the
    /// wallet count if everybody has it.
    AlwaysFilled = 1,
}

impl Occupancy {
    fn from_bit(v: u8) -> Occupancy {
        if v & 1 == 0 {
            Occupancy::Sparse
        } else {
            Occupancy::AlwaysFilled
        }
    }
}

/// The wipe policy, in the one fixed 8-byte little-endian encoding used by all three of
/// its homes (OPEN-QUESTIONS Q5.1).
///
/// ```text
/// off len field
/// 0    1  wipe_after   u8. 0 = wipe DISABLED; otherwise 3..=25
/// 1    1  flags        bit0 occupancy (0 Sparse, 1 AlwaysFilled), bits1-7 MBZ
/// 2    1  min_pin_len  u8, the floor in force when this policy was written
/// 3    1  MBZ
/// 4    4  policy_gen   u32, strictly increasing, device-global
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Policy {
    /// 0 is the disabled sentinel, adopted from PIN-MODES.md in preference to a separate
    /// enable flag: two encodings for one fact is a defect waiting to happen.
    pub wipe_after: u8,
    pub occupancy: Occupancy,
    pub min_pin_len: u8,
    pub policy_gen: u32,
}

/// Smallest and largest attempt limits when the wipe is enabled. The ceiling is a frozen
/// format constant, not a preference: the attempt log's tail reserve is sized to it.
pub const WIPE_AFTER_MIN: u8 = 3;
pub const WIPE_AFTER_MAX: u8 = 25;

impl Policy {
    pub const ENCODED_LEN: usize = 8;

    pub const fn wipe_enabled(&self) -> bool {
        self.wipe_after != 0
    }

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0] = self.wipe_after;
        out[1] = self.occupancy as u8;
        out[2] = self.min_pin_len;
        out[3] = 0;
        let gen = self.policy_gen.to_le_bytes();
        out[4] = gen[0];
        out[5] = gen[1];
        out[6] = gen[2];
        out[7] = gen[3];
        out
    }

    /// Decode, rejecting anything the encoding does not define. A malformed policy is
    /// never silently coerced: the caller resolves it to the strict default instead.
    pub fn decode(raw: &[u8; Self::ENCODED_LEN]) -> Option<Policy> {
        let wipe_after = raw[0];
        if wipe_after != 0 && !(WIPE_AFTER_MIN..=WIPE_AFTER_MAX).contains(&wipe_after) {
            return None;
        }
        if raw[1] & 0xfe != 0 || raw[3] != 0 {
            return None;
        }
        Some(Policy {
            wipe_after,
            occupancy: Occupancy::from_bit(raw[1]),
            min_pin_len: raw[2],
            policy_gen: u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
        })
    }

    /// Ordering used by the power-loss fuzzer's policy invariant, and by nothing else.
    ///
    /// "Stricter" means "gives an attacker fewer guesses": wipe enabled beats wipe
    /// disabled, and among enabled policies a smaller N beats a larger one. `min_pin_len`
    /// and occupancy do not participate; neither bounds an attacker's guess count.
    pub fn at_least_as_strict_as(&self, other: &Policy) -> bool {
        match (self.wipe_enabled(), other.wipe_enabled()) {
            (true, false) => true,
            (false, true) => false,
            (false, false) => true,
            (true, true) => self.wipe_after <= other.wipe_after,
        }
    }
}

/// What SET-POLICY is asked to change. Occupancy is deliberately absent: it is not
/// settable in 0.2.0, and a request to change it is refused rather than ignored.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PolicyRequest {
    /// 0 disables the wipe; otherwise 3..=25.
    pub wipe_after: u8,
    pub min_pin_len: u8,
}

/// Store configuration. `'static` because it describes the firmware, not a session.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Embedder-chosen, mixed into every derivation and recorded in the superblock.
    pub domain_tag: [u8; 16],
    pub kdf: KdfParams,
    pub layout: Layout,
    /// The policy written at FORMAT time. It is the fallback the ledger falls back TO
    /// when the `policy_log` is empty, so it must be a policy the product is willing to
    /// be held to: every fail-closed path in the design resolves here.
    pub format_policy: PolicyRequest,
    pub occupancy: Occupancy,
    /// Provenance values this product will run with. A release build passes
    /// `&[KeyProvenance::EfuseReadProtected]`.
    pub accept_provenance: &'static [KeyProvenance],
    /// Q5.2 Y3, wired as a parameter rather than a constant so the owner's answer is a
    /// value and not a code change: the minimum PIN length required to DISABLE the wipe.
    /// `None` is the ratified answer (Q62(b), PIN-MODES.md) - no floor.
    pub disable_wipe_min_pin_len: Option<u8>,
}

impl Config {
    /// The configuration notyas release firmware uses.
    pub const NOTYAS_RELEASE: Config = Config {
        domain_tag: *b"notyas-wallet-v1",
        kdf: KdfParams::PINNED,
        layout: Layout::V1,
        format_policy: PolicyRequest {
            wipe_after: 15,
            min_pin_len: 4,
        },
        occupancy: Occupancy::AlwaysFilled,
        accept_provenance: &[KeyProvenance::EfuseReadProtected],
        disable_wipe_min_pin_len: None,
    };

    /// The format-time policy as a [`Policy`], at generation 0.
    pub(crate) fn format_policy(&self) -> Policy {
        Policy {
            wipe_after: self.format_policy.wipe_after,
            occupancy: self.occupancy,
            min_pin_len: self.format_policy.min_pin_len,
            policy_gen: 0,
        }
    }

    /// Structural validation, run once at mount so nothing below it re-checks.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.kdf.is_valid() {
            return Err(ConfigError::Kdf);
        }
        if self.kdf.p != 1 {
            return Err(ConfigError::Kdf);
        }
        let l = &self.layout;
        if l.sector_size != 4096 || l.identities != 4 || l.identities as usize > 8 {
            return Err(ConfigError::Layout);
        }
        if l.mapped_sectors() > l.records_sectors {
            return Err(ConfigError::Layout);
        }
        if l.payload_slots > 8 || l.registry_slots > 8 || l.canary_slots != l.identities {
            return Err(ConfigError::Layout);
        }
        if l.ledger_sectors != 4 {
            return Err(ConfigError::Layout);
        }
        let p = self.format_policy;
        if p.wipe_after == 0 || !(WIPE_AFTER_MIN..=WIPE_AFTER_MAX).contains(&p.wipe_after) {
            // The FORMAT-time policy is the strict default every fail-closed path lands
            // on. It may not be "wipe disabled": that would make the strict default the
            // permissive one, and every refusal in the design would resolve the wrong way.
            return Err(ConfigError::Policy);
        }
        if self.accept_provenance.is_empty() {
            return Err(ConfigError::Provenance);
        }
        // A release product (one that accepts only a read-protected eFuse key) must not
        // be running test-cost parameters. Cheap to state, and it closes the path where a
        // debug constant survives into a signed image.
        let production_only = self
            .accept_provenance
            .iter()
            .all(|p| matches!(p, KeyProvenance::EfuseReadProtected));
        if production_only && self.kdf.m_kib < 4096 {
            return Err(ConfigError::Kdf);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfigError {
    Kdf,
    Layout,
    Policy,
    Provenance,
}
