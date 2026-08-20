// SPDX-License-Identifier: GPL-3.0-or-later
// notyas release signing key - embedded at compile time so the binary is self-contained.

pub const FINGERPRINT: &str = "A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D";
pub const PUBLIC_KEY: &str = include_str!("../../docs/keys/A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D.asc");
