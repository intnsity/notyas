// Copyright (C) 2025-2026 intnsity
// SPDX-License-Identifier: GPL-3.0-or-later

//! Watch-only export rendering: BIP-380 descriptors and the named coordinator export
//! bodies MILESTONES.md 0.2.0-m10 requires (Sparrow, Bitcoin Core `importdescriptors`,
//! Electrum, Nunchuk, generic JSON).
//!
//! # Scope
//!
//! Rendering only. Everything here takes [`derive::AccountKeys`] / [`derive::Derived`]
//! that [`derive::derive`] already produced and turns it into the text a coordinator
//! reads - no key derivation happens in this module (the address-range CSV asks
//! [`crate::address`] for its rows, which is the one place the values are not handed in,
//! and that module derives from an account xpub), and nothing here ever reads an
//! `AccountKeys::xprv` or an `AddressRow::wif`: every function's signature is built from
//! types that make the secret fields unreachable (`&AccountKeys` alone, never the seed),
//! which is the same "borrowing rules guarantee it" discipline WALLET-API.md 2.6 uses for
//! `WalletView`. Multisig (BIP48/`Scheme::Bip48`) is xpub-only for the same reason
//! [`derive::derive`] itself gives no address rows for it: a multisig descriptor needs
//! cosigner xpubs this crate does not accept, so every export function here either omits
//! the multisig entry's descriptor or refuses the scheme outright, rather than fabricate a
//! `sortedmulti(...)` with placeholder cosigners no coordinator could use.
//!
//! # Where each format comes from
//!
//! - **BIP-380 descriptor + checksum** ([`descriptor`], [`checksum`]): the checksum is the
//!   reference algorithm from BIP-380 itself
//!   (<https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki>), hand-transcribed
//!   rather than pulled in as a dependency - this module only ever computes a checksum
//!   over text it built from its own validated components (a `Scheme`, a `Fingerprint`, an
//!   xpub `derive::derive` returned), so there is no attacker-supplied descriptor to PARSE
//!   here. That parser, when 0.2.0 needs one for multisig import, is `miniscript`'s job in
//!   the future `wallet` module (WALLET-API.md 2.6), not this one's. The wrapped forms
//!   (`pkh(...)`, `sh(wpkh(...))`, `wpkh(...)`, `tr(...)`) and the `<0;1>/*` multipath
//!   suffix match the worked example UX-SCREENS.md S-26 already commits to on screen:
//!   `wpkh([a1b2c3d4/84h/0h/0h]xpub.../<0;1>/*)#checksum`.
//! - **Generic JSON, and Sparrow / Nunchuk under that same shape**
//!   ([`generic_wallet_json`]): field-for-field the schema Coldcard documents at
//!   <https://github.com/Coldcard/firmware/blob/master/docs/generic-wallet-export.md> and
//!   implements in `shared/export.py`'s `generate_generic_export`. Sparrow and Nunchuk are
//!   not separate formats there either: Coldcard's own `shared/flow.py` wires `"Sparrow"`,
//!   `"Nunchuk"` and `"Cove"` to the identical `named_generic_skeleton` handler as the
//!   plain `"Generic JSON"` entry - one body, four menu labels, four filenames. This
//!   module adds a `bip86` (`p2tr`) entry the cited Coldcard source does not have, because
//!   0.2.0 supports taproot and the source predates Coldcard's own taproot support; every
//!   other field name, nesting and per-scheme key matches the cited schema exactly.
//! - **Bitcoin Core `importdescriptors`** ([`bitcoin_core_import_descriptors`]): the
//!   request-array shape and field names (`desc`, `timestamp`, `active`, `range`,
//!   `next_index`, `internal`, `label`) are the RPC's own documented parameters,
//!   <https://developer.bitcoin.org/reference/rpc/importdescriptors.html>.
//! - **Electrum** ([`electrum_wallet_file`]): the enclosing wallet-file shape
//!   (`seed_version`, `use_encryption`, `wallet_type`, a `keystore` object) is Coldcard's
//!   own sample,
//!   <https://github.com/Coldcard/firmware/blob/master/docs/sample-electrum-wallets/electrum-single.json>.
//!   The keystore body is NOT copied from that sample, though: Coldcard's sample sets
//!   `"type": "hardware"`, `"hw_type": "coldcard"` and Coldcard-only `ckcc_*` fields to
//!   drive Electrum's Coldcard plugin, and this device is not a Coldcard - writing that
//!   would be a coordinator-actionable lie. Electrum's own watch-only keystore instead
//!   uses `"type": "bip32"` plus `xpub`/`root_fingerprint`/`derivation`
//!   (`BIP32_KeyStore.watching_only_keystore` in
//!   <https://github.com/spesmilo/electrum/blob/master/electrum/keystore.py>, fingerprint
//!   format - lowercase 8 hex chars - from `calc_fingerprint_of_this_node` in
//!   `electrum/bip32.py` in the same repository), and that is what this module writes.
//!   Electrum infers the script type from the xpub's own SLIP-132 version bytes
//!   (documented at
//!   <https://electrum.readthedocs.io/en/latest/xpub_version_bytes.html>: xpub/ypub/zpub
//!   for P2PKH / P2WPKH-in-P2SH / native P2WPKH on mainnet, and tpub/upub/vpub for the
//!   same three on the test chains) and that table has no taproot entry, so
//!   [`electrum_wallet_file`] accepts [`Scheme::Bip44`], [`Scheme::Bip49`] and
//!   [`Scheme::Bip84`], and [`Scheme::Bip86`] is refused rather than exported under a
//!   prefix Electrum would misread as segwit-v0. The test-chain row is why this is the one
//!   export that renders SLIP-132 itself, through [`crate::derive::slip132_pub`], instead
//!   of reading [`derive::AccountKeys::slip132_pub`]: that field carries the mainnet pair
//!   the key report shows and is `None` elsewhere, and a `tpub` in an Electrum keystore
//!   does not mean "testnet BIP84", it means "testnet P2PKH".
//! - **Address-range CSV** ([`address_range_csv`]): the header line and the row shape -
//!   quoted field names, an unquoted index column, and for multisig a `Redeem Script`
//!   column followed by one `Derivation (i of N)` column per cosigner - are Coldcard's own
//!   `shared/address_explorer.py`,
//!   <https://github.com/Coldcard/firmware/blob/master/shared/address_explorer.py>, which
//!   is also where [`crate::address::MAX_RANGE`]'s 250 comes from. The derivation strings
//!   inside those columns are this crate's report spelling (leading `m/`, hardened written
//!   with an apostrophe), not the descriptor spelling the formats above use.
//!
//! Every export but the CSV is handed the values it renders. The CSV is the one that asks
//! for them, because its rows are addresses rather than keys and only
//! [`crate::address`] builds those; that module is xpub-only, so this one still cannot
//! reach a secret through anything it calls.

use alloc::string::String;
use core::str::FromStr;

use bitcoin::bip32::{Fingerprint, Xpub};
use bitcoin::Network;

use crate::address::{AddressSource, Keychain};
use crate::derive::{AccountKeys, ChildIndex, Derived, Scheme};

// -----------------------------------------------------------------------------------------
// BIP-380 descriptor checksum
// -----------------------------------------------------------------------------------------

/// The BIP-380 descriptor checksum: a transcription of the reference `descsum_*` Python in
/// the BIP text, not a reimplementation from first principles. Crate-private: the ways to
/// reach it are [`descriptor`], which supplies a body this crate built itself, and
/// [`crate::multisig`], which supplies one it built from a parsed registration and uses
/// [`checksum::check`] to refuse an import whose checksum does not match. There is
/// deliberately one implementation of BIP-380 in this crate and not two.
pub(crate) mod checksum {
    use alloc::string::String;
    use alloc::vec::Vec;

    const INPUT_CHARSET: &[u8] =
        b"0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const GENERATOR: [u64; 5] = [
        0xf5dee51989,
        0xa9fdca3312,
        0x1bab10e32d,
        0x3706b1677a,
        0x644d626ffd,
    ];

    fn polymod(symbols: &[u8]) -> u64 {
        let mut chk: u64 = 1;
        for &value in symbols {
            let top = chk >> 35;
            chk = ((chk & 0x7_ffff_ffff) << 5) ^ u64::from(value);
            for (i, gen) in GENERATOR.iter().enumerate() {
                if (top >> i) & 1 == 1 {
                    chk ^= gen;
                }
            }
        }
        chk
    }

    /// Character-to-symbol expansion (BIP-380's `descsum_expand`). `None` for any byte
    /// outside the descriptor character set - unreachable for text this crate assembles
    /// itself from hex digits, base58/bech32 alphabets and the fixed descriptor grammar,
    /// but returning `Option` rather than panicking keeps that a documented assumption
    /// instead of an unstated one.
    fn expand(s: &str) -> Option<Vec<u8>> {
        let mut groups: Vec<u8> = Vec::new();
        let mut symbols: Vec<u8> = Vec::new();
        for c in s.bytes() {
            let v = INPUT_CHARSET.iter().position(|&x| x == c)? as u8;
            symbols.push(v & 31);
            groups.push(v >> 5);
            if groups.len() == 3 {
                symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]);
                groups.clear();
            }
        }
        match groups.len() {
            1 => symbols.push(groups[0]),
            2 => symbols.push(groups[0] * 3 + groups[1]),
            _ => {}
        }
        Some(symbols)
    }

    /// `body#checksum`, the 8-character lowercase checksum BIP-380 defines. `None` only if
    /// `body` used a byte outside the descriptor charset - see [`expand`].
    pub(crate) fn create(body: &str) -> Option<String> {
        let mut symbols = expand(body)?;
        symbols.extend_from_slice(&[0u8; 8]);
        let checksum = polymod(&symbols) ^ 1;
        let mut out = String::with_capacity(body.len() + 9);
        out.push_str(body);
        out.push('#');
        for i in 0..8u32 {
            let idx = (checksum >> (5 * (7 - i))) & 31;
            out.push(char::from(CHECKSUM_CHARSET[idx as usize]));
        }
        Some(out)
    }

    /// Verifies a full `body#checksum` string (BIP-380's `descsum_check`).
    ///
    /// Two callers, and they want it for opposite reasons. This module's own tests use it
    /// as an independent round-trip check on [`create`], pinned first against BIP-380's own
    /// published vector. [`crate::multisig`] uses it on the way IN, where a descriptor
    /// arrives from an SD card or a QR code and a checksum that does not match means the
    /// transfer was corrupted, not that the wallet is wrong.
    pub(crate) fn check(full: &str) -> bool {
        // BIP-380's whole input charset is ASCII, so a descriptor carrying a multi-byte
        // character cannot have a valid checksum whatever else is true of it. Checking that
        // first is not an optimisation: the split below is by BYTE position, and on a
        // string whose last characters are multi-byte it would panic. Since m7 this
        // function reads descriptors that arrived from an SD card or a camera, and a
        // refusal path that can be made to panic is not a refusal path.
        if !full.is_ascii() {
            return false;
        }
        // The checksum is pinned to the last 9 bytes exactly (a '#' plus 8 characters),
        // so this splits on position rather than searching for '#'.
        if full.len() < 9 {
            return false;
        }
        let split = full.len() - 9;
        let (body, tail) = full.split_at(split);
        let Some(sum) = tail.strip_prefix('#') else {
            return false;
        };
        if sum.len() != 8 || !sum.bytes().all(|b| CHECKSUM_CHARSET.contains(&b)) {
            return false;
        }
        let Some(mut symbols) = expand(body) else {
            return false;
        };
        for b in sum.bytes() {
            // Presence in CHECKSUM_CHARSET was just checked above.
            let idx = CHECKSUM_CHARSET.iter().position(|&x| x == b).unwrap_or(0);
            symbols.push(idx as u8);
        }
        polymod(&symbols) == 1
    }
}

/// The descriptor key-origin path: `account.path` without its leading `m/`, with `'` (the
/// iancoleman-style hardened marker [`AccountKeys::path`] is written in) swapped for the
/// `h` BIP-380 descriptors use, e.g. `m/84'/0'/0'` -> `84h/0h/0h`. Matches the Coldcard
/// `generic-wallet-export.md` descriptor examples exactly (`[0f056943/44h/0h/123h]...`).
fn origin_path(path: &str) -> String {
    path.trim_start_matches("m/").replace('\'', "h")
}

/// `account.path` reformatted to the `deriv` field's own spelling: same swap as
/// [`origin_path`] but the leading `m/` stays, e.g. `m/84'/0'/0'` -> `m/84h/0h/0h`
/// (Coldcard `generic-wallet-export.md`, `"deriv": "m/44h/0h/123h"`).
fn generic_deriv(path: &str) -> String {
    format!("m/{}", origin_path(path))
}

/// The BIP-380 output descriptor for one account, with its checksum
/// (UX-SCREENS.md S-26; BIP-380 for the grammar and checksum).
///
/// `fingerprint` is the WALLET's root fingerprint ([`crate::derive::root_fingerprint`]),
/// not the account node's own - a descriptor's key origin always names the path's start,
/// which is the root.
///
/// `None` for [`Scheme::Bip48`]: 0.2.0 builds multisig descriptors only from a verified
/// registration that supplies every cosigner (WALLET-API.md 2.6/2.7), never speculatively
/// from this wallet's key alone.
pub fn descriptor(scheme: Scheme, fingerprint: Fingerprint, account: &AccountKeys) -> Option<String> {
    if scheme == Scheme::Bip48 {
        return None;
    }
    let key_expr = format!(
        "[{fingerprint}/{}]{}/<0;1>/*",
        origin_path(&account.path),
        account.xpub
    );
    let body = match scheme {
        Scheme::Bip44 => format!("pkh({key_expr})"),
        Scheme::Bip49 => format!("sh(wpkh({key_expr}))"),
        Scheme::Bip84 => format!("wpkh({key_expr})"),
        Scheme::Bip86 => format!("tr({key_expr})"),
        Scheme::Bip48 => unreachable!("returned above"),
    };
    checksum::create(&body)
}

// -----------------------------------------------------------------------------------------
// Generic JSON (also: Sparrow, Nunchuk - see module docs)
// -----------------------------------------------------------------------------------------

/// `"BTC"`/`"XTN"` chain code (Coldcard's own `chain.ctype` strings). Mirrors
/// [`crate::derive`]'s own mainnet-vs-everything-else simplification (see its
/// `coin_type`): 0.2.0 has no export-time reason to tell testnet from signet apart that
/// derivation itself does not already make.
fn chain_code(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "BTC",
        _ => "XTN",
    }
}

fn field_key(scheme: Scheme) -> &'static str {
    match scheme {
        Scheme::Bip44 => "bip44",
        Scheme::Bip49 => "bip49",
        Scheme::Bip84 => "bip84",
        Scheme::Bip86 => "bip86",
        // Coldcard's own two BIP48 script types are p2sh-p2wsh (bip48_1) and p2wsh
        // (bip48_2); WALLET-API.md 2.7 restricts 0.2.0 to WshSortedMulti (P2WSH) only, so
        // only the bip48_2 slot is ever produced here.
        Scheme::Bip48 => "bip48_2",
    }
}

fn script_name(scheme: Scheme) -> &'static str {
    match scheme {
        Scheme::Bip44 => "p2pkh",
        Scheme::Bip49 => "p2sh-p2wpkh",
        Scheme::Bip84 => "p2wpkh",
        Scheme::Bip86 => "p2tr",
        Scheme::Bip48 => "p2wsh",
    }
}

/// The generic multi-scheme watch-only export (also what this crate hands out under the
/// "Sparrow" and "Nunchuk" labels - see the module docs for why those are the same body).
///
/// `master_xpub` is [`crate::derive::root_xpub`] for the same seed and network;
/// `fingerprint` is [`crate::derive::root_fingerprint`]'s typed form
/// ([`crate::derive::master_fingerprint`]). `entries` is one `(Scheme, &Derived)` pair per
/// scheme to include, in the order they should appear - callers decide which schemes and
/// what count (this module does not derive anything itself).
///
/// # Panics
///
/// Only if an entry's `account.xpub` is not valid base58check - unreachable for an
/// `AccountKeys` [`crate::derive::derive`] produced, which is the only public source of
/// one.
pub fn generic_wallet_json(
    network: Network,
    fingerprint: Fingerprint,
    master_xpub: &str,
    account_number: u32,
    entries: &[(Scheme, &Derived)],
) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("  \"chain\": \"{}\",\n", chain_code(network)));
    out.push_str(&format!("  \"xfp\": \"{fingerprint}\",\n"));
    out.push_str(&format!("  \"account\": {account_number},\n"));
    out.push_str(&format!("  \"xpub\": \"{master_xpub}\""));

    for (scheme, derived) in entries {
        let scheme = *scheme;
        let account = &derived.account;
        let own_fp = Xpub::from_str(&account.xpub)
            .expect("AccountKeys::xpub is always well-formed base58check")
            .fingerprint();

        out.push_str(",\n");
        out.push_str(&format!("  \"{}\": {{\n", field_key(scheme)));
        out.push_str(&format!("    \"name\": \"{}\",\n", script_name(scheme)));
        out.push_str(&format!("    \"xfp\": \"{own_fp}\",\n"));
        out.push_str(&format!(
            "    \"deriv\": \"{}\",\n",
            generic_deriv(&account.path)
        ));
        out.push_str(&format!("    \"xpub\": \"{}\"", account.xpub));
        if let Some(desc) = descriptor(scheme, fingerprint, account) {
            out.push_str(&format!(",\n    \"desc\": \"{desc}\""));
        }
        if let Some(slip) = &account.slip132_pub {
            out.push_str(&format!(",\n    \"_pub\": \"{slip}\""));
        }
        if let Some(first) = derived.rows.first() {
            out.push_str(&format!(",\n    \"first\": \"{}\"", first.address));
        }
        out.push_str("\n  }");
    }
    out.push_str("\n}\n");
    out
}

// -----------------------------------------------------------------------------------------
// Bitcoin Core `importdescriptors`
// -----------------------------------------------------------------------------------------

/// The RPC's required `timestamp`: a UNIX time to start rescanning from, or the literal
/// string `"now"` (developer.bitcoin.org `importdescriptors`). Every account this crate
/// exports is freshly derived and has no prior chain history to rescan, so `Now` is what
/// every caller wants; `Unix` exists for completeness against the documented parameter.
pub enum CoreTimestamp {
    Now,
    Unix(u64),
}

/// One element of an `importdescriptors` request array. Field names and meaning are the
/// RPC's own (developer.bitcoin.org `importdescriptors`): `label` is rejected by Core
/// unless `internal` is false, which this module does not enforce - Core's own error is
/// the correct place for that refusal to surface.
pub struct CoreImportRequest<'a> {
    pub desc: &'a str,
    pub timestamp: CoreTimestamp,
    pub active: bool,
    pub range: Option<(u32, u32)>,
    pub next_index: Option<u32>,
    pub internal: bool,
    pub label: Option<&'a str>,
}

/// Minimal JSON string escaping (quotes, backslashes, control characters), for the two
/// fields in this module that are not built by this crate itself: an `importdescriptors`
/// `label` and a caller-supplied `desc`. Every other string this module writes
/// (fingerprints, xpubs, descriptors it built via [`descriptor`], derivation paths,
/// addresses) comes from fixed, quote-free charsets and is written unescaped.
fn json_escaped(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// The JSON array text for `bitcoin-cli -named importdescriptors requests=<this>`
/// (developer.bitcoin.org `importdescriptors`). Field order per entry matches the RPC
/// doc's own example: `desc`, `timestamp`, then whichever optional fields the caller set.
pub fn bitcoin_core_import_descriptors(requests: &[CoreImportRequest]) -> String {
    let mut out = String::new();
    out.push_str("[\n");
    for (i, r) in requests.iter().enumerate() {
        if i > 0 {
            out.push_str(",\n");
        }
        out.push_str("  {\n");
        out.push_str(&format!("    \"desc\": \"{}\",\n", json_escaped(r.desc)));
        match r.timestamp {
            CoreTimestamp::Now => out.push_str("    \"timestamp\": \"now\""),
            CoreTimestamp::Unix(t) => out.push_str(&format!("    \"timestamp\": {t}")),
        }
        if r.active {
            out.push_str(",\n    \"active\": true");
        }
        if let Some((begin, end)) = r.range {
            out.push_str(&format!(",\n    \"range\": [{begin}, {end}]"));
        }
        if let Some(next) = r.next_index {
            out.push_str(&format!(",\n    \"next_index\": {next}"));
        }
        if r.internal {
            out.push_str(",\n    \"internal\": true");
        }
        if let Some(label) = r.label {
            out.push_str(&format!(",\n    \"label\": \"{}\"", json_escaped(label)));
        }
        out.push_str("\n  }");
    }
    out.push_str("\n]\n");
    out
}

// -----------------------------------------------------------------------------------------
// Electrum
// -----------------------------------------------------------------------------------------

/// Why an account has no Electrum wallet file.
///
/// A named refusal rather than a bare `None`: a device that will not export has to say
/// which of these it is, because one of them is answered by picking a different format and
/// the other is a bug in the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElectrumError {
    /// Electrum reads an account's script type out of its xpub's own version bytes, and
    /// that table has no taproot entry, so a [`Scheme::Bip86`] account could only go out
    /// under a prefix Electrum would read as segwit v0 - the wrong addresses, silently.
    /// [`Scheme::Bip48`] is multisig and needs cosigner keys this crate does not accept.
    UnsupportedScheme(Scheme),
    /// `account.xpub` is not a serialized extended public key of a chain SLIP-132
    /// registers, so there are no version bytes to re-render it under. Unreachable for an
    /// [`AccountKeys`] that [`crate::derive::derive`] produced; `AccountKeys` has public
    /// fields, so this is a refusal rather than a panic for a caller that builds one
    /// itself.
    MalformedAccountXpub,
}

impl core::fmt::Display for ElectrumError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ElectrumError::UnsupportedScheme(scheme) => {
                write!(f, "Electrum has no wallet file for {scheme} accounts")
            }
            ElectrumError::MalformedAccountXpub => {
                write!(f, "this account's xpub is not a serialized extended key")
            }
        }
    }
}

impl core::error::Error for ElectrumError {}

/// A watch-only Electrum wallet file body.
///
/// Defined on every chain this device can be switched to. Electrum infers the script type
/// from the xpub's own SLIP-132 version bytes, and its table has a test-chain row
/// (`tpub`/`upub`/`vpub`) beside the mainnet one, so a testnet account exports under the
/// test-chain prefix rather than being refused - see [`crate::derive::slip132_pub`] for why
/// that rendering is computed here and not carried on [`AccountKeys`].
///
/// Refuses [`Scheme::Bip86`] and [`Scheme::Bip48`]; see [`ElectrumError`].
pub fn electrum_wallet_file(
    scheme: Scheme,
    fingerprint: Fingerprint,
    account: &AccountKeys,
) -> Result<String, ElectrumError> {
    let xpub = match scheme {
        // SLIP-132 registers no alternative for P2PKH: Electrum reads a plain xpub or
        // tpub as exactly this scheme, which is what `derive` already produced.
        Scheme::Bip44 => account.xpub.clone(),
        Scheme::Bip49 | Scheme::Bip84 => crate::derive::slip132_pub(scheme, &account.xpub)
            .ok_or(ElectrumError::MalformedAccountXpub)?,
        Scheme::Bip86 | Scheme::Bip48 => return Err(ElectrumError::UnsupportedScheme(scheme)),
    };
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"keystore\": {\n");
    out.push_str("    \"type\": \"bip32\",\n");
    out.push_str(&format!("    \"xpub\": \"{xpub}\",\n"));
    out.push_str(&format!("    \"root_fingerprint\": \"{fingerprint}\",\n"));
    out.push_str(&format!("    \"derivation\": \"{}\"\n", account.path));
    out.push_str("  },\n");
    out.push_str("  \"wallet_type\": \"standard\",\n");
    out.push_str("  \"use_encryption\": false,\n");
    out.push_str("  \"seed_version\": 17\n");
    out.push_str("}\n");
    Ok(out)
}

// -----------------------------------------------------------------------------------------
// Address-range CSV
// -----------------------------------------------------------------------------------------

/// A bounded run of one wallet's addresses as the CSV the address explorer writes to the
/// card (MILESTONES.md 0.2.0-m10; Coldcard's `shared/address_explorer.py` for the shape -
/// see the module docs).
///
/// `None` for a range [`crate::address::AddressSource::range`] refuses: more than
/// [`crate::address::MAX_RANGE`] rows, or a run reaching past the last unhardened index.
///
/// Multisig sources get Coldcard's wider table - the witness script and one derivation
/// column per cosigner - because a P2WSH address is not reconstructible from the address
/// alone, and a coordinator or a human auditing the file needs the same cosigner order the
/// registration itself fixed.
///
/// No field is escaped and none needs to be: an index is decimal, an address is base58 or
/// bech32, a script is hex and a derivation path is digits with `/` and `'`. None of those
/// charsets contains a quote, a comma or a newline. That is a property of what this crate
/// builds, not an assumption about a caller's input - the rows come from
/// [`crate::address`], which derives them.
pub fn address_range_csv(
    source: &AddressSource,
    keychain: Keychain,
    start: ChildIndex,
    count: u32,
) -> Option<String> {
    let entries = source.range(keychain, start, count)?;
    let mut out = String::new();
    match source {
        AddressSource::Singlesig(_) => {
            out.push_str("\"Index\",\"Payment Address\",\"Derivation\"\n");
            for entry in &entries {
                out.push_str(&format!(
                    "{},\"{}\",\"{}\"\n",
                    entry.index,
                    entry.address,
                    entry.our_path()
                ));
            }
        }
        AddressSource::Multisig(registration) => {
            let n = registration.cosigners().len();
            out.push_str("\"Index\",\"Payment Address\",\"Redeem Script\"");
            for i in 1..=n {
                out.push_str(&format!(",\"Derivation ({i} of {n})\""));
            }
            out.push('\n');
            for entry in &entries {
                // Present for every multisig entry by construction; an entry that somehow
                // carries no script is dropped rather than written as an empty column,
                // because a blank script column in an audited file reads as "no script".
                let script = entry.witness_script.as_deref()?;
                out.push_str(&format!("{},\"{}\",\"{}\"", entry.index, entry.address, script));
                for path in &entry.paths {
                    out.push_str(&format!(",\"{path}\""));
                }
                out.push('\n');
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use crate::bip39;
    use crate::derive::{self, ChildIndex};
    use serde_json::Value;

    /// The BIP39 seed for "abandon abandon abandon abandon abandon abandon abandon
    /// abandon abandon abandon abandon about" with no passphrase - the exact mnemonic and
    /// passphrase BIP-84's own test vectors use
    /// (https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki, "Test vectors").
    /// Computed via this crate's own `bip39::seed` (PBKDF2-HMAC-SHA512 per BIP-39) rather
    /// than a transcribed hex constant, so a mistyped hex digit cannot silently swap in a
    /// different vector - `derive::derive` below is what has to match the published zpub.
    fn bip84_test_seed() -> [u8; 64] {
        *bip39::seed(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon about",
            "",
        )
    }

    // -- checksum: BIP-380's own published vector -----------------------------------

    /// https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki, "Test Vectors":
    /// `raw(deadbeef)#89f8spxm` is the worked example of a descriptor whose checksum
    /// validates.
    #[test]
    fn checksum_matches_bip380_published_vector() {
        assert_eq!(
            checksum::create("raw(deadbeef)"),
            Some("raw(deadbeef)#89f8spxm".to_string())
        );
        assert!(checksum::check("raw(deadbeef)#89f8spxm"));
        assert!(!checksum::check("raw(deadbeef)#89f8spxx"));
        assert!(!checksum::check("raw(deedbeef)#89f8spxm"));
    }

    /// Three more published checksums, one per wrapping shape [`descriptor`] produces
    /// (`pkh`, `sh(wpkh(...))`, `wpkh`), taken verbatim from Coldcard's own documented
    /// example account: https://github.com/Coldcard/firmware/blob/master/docs/generic-wallet-export.md.
    #[test]
    fn checksum_matches_coldcard_published_examples() {
        let cases = [
            (
                "pkh([0f056943/44h/0h/123h]xpub6DStQXfAgHuLbMpCf86ruVkF4yT9pSLyWsFiqQTWY9osuinq8Dyee4W5jCjMfyku5LNkRB9oFinrY5ufn9XXEn8Vvzc2jnifKMaQCNV7RBZ/<0;1>/*)",
                "4tl8jryn",
            ),
            (
                "sh(wpkh([0f056943/49h/0h/123h]xpub6DDm8WzH5a9qjKkttzqSB3uGofNohU9D3n3UG8WMxkUZzJEMPTYiQRf1dvTFCQR82MjGW4LUMVuTtnW4hF17RpzCqVwhf6Z2fnJPWtjG164/<0;1>/*))",
                "5j7t2n2u",
            ),
            (
                "wpkh([0f056943/84h/0h/123h]xpub6CaWStGvcXqSW9BzU2vpCoP7aWjz9VfR5DS2nuYWVvKV2nug2dESg3HdFsaWHeoZaxuAhNcPB3TH2gq8MugS3JX1yGuhB4QbC2BneaYqB16/<0;1>/*)",
                "yk84tprf",
            ),
        ];
        for (body, want_checksum) in cases {
            let full = checksum::create(body).expect("descriptor body uses only the descriptor charset");
            assert_eq!(full, format!("{body}#{want_checksum}"), "body: {body}");
            assert!(checksum::check(&full), "check() must accept its own create(): {full}");
        }
    }

    // -- descriptor(): built from a published derivation vector ----------------------

    /// The key material (fingerprint, path, xpub) comes from BIP-84's own published
    /// account-0 vector; [`descriptor`] is then checked for shape and for a
    /// self-consistent checksum (independently verified by [`checksum::check`], which
    /// is itself pinned against BIP-380's own vector above).
    #[test]
    fn descriptor_matches_bip84_vector_and_has_a_valid_checksum() {
        let seed = bip84_test_seed();
        let fingerprint = derive::master_fingerprint(&seed, Network::Bitcoin);
        let d = derive::derive(&seed, Network::Bitcoin, Scheme::Bip84, ChildIndex::ZERO, ChildIndex::ZERO, 1, 0);
        // BIP-84's own published account-0 zpub
        // (https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki, "Test vectors").
        assert_eq!(
            d.account.slip132_pub.as_deref(),
            Some("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")
        );
        // `descriptor()` embeds the PLAIN xpub, never the SLIP-132 alias (BIP-380
        // descriptors always carry the plain form - Coldcard's own examples above use it
        // too), so this is checked against `d.account.xpub`, not the zpub above.
        let full = descriptor(Scheme::Bip84, fingerprint, &d.account).expect("bip84 has a descriptor");
        assert!(full.starts_with("wpkh(["));
        assert!(full.contains("/84h/0h/0h]"));
        assert!(full.contains(&d.account.xpub));
        assert!(full.contains("/<0;1>/*)#"));
        assert!(checksum::check(&full), "self-built descriptor must pass its own checksum check");
        assert_eq!(descriptor(Scheme::Bip48, fingerprint, &d.account), None);
    }

    // -- generic_wallet_json(): schema shape -----------------------------------------

    #[test]
    fn generic_wallet_json_matches_coldcard_schema_field_names() {
        let seed = bip84_test_seed();
        let network = Network::Bitcoin;
        let fingerprint = derive::master_fingerprint(&seed, network);
        let master_xpub = derive::root_xpub(&seed, network);
        let d84 = derive::derive(&seed, network, Scheme::Bip84, ChildIndex::ZERO, ChildIndex::ZERO, 1, 0);
        let d48 = derive::derive(&seed, network, Scheme::Bip48, ChildIndex::ZERO, ChildIndex::ZERO, 0, 2);

        let text = generic_wallet_json(
            network,
            fingerprint,
            &master_xpub,
            0,
            &[(Scheme::Bip84, &d84), (Scheme::Bip48, &d48)],
        );
        let v: Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(v["chain"], "BTC");
        assert_eq!(v["xfp"], fingerprint.to_string());
        assert_eq!(v["account"], 0);
        assert_eq!(v["xpub"], master_xpub);

        let bip84 = &v["bip84"];
        assert_eq!(bip84["name"], "p2wpkh");
        assert_eq!(bip84["deriv"], "m/84h/0h/0h");
        assert_eq!(bip84["xpub"], d84.account.xpub);
        assert_eq!(bip84["_pub"], d84.account.slip132_pub.clone().unwrap());
        assert_eq!(bip84["first"], d84.rows[0].address);
        assert!(bip84["desc"].as_str().unwrap().starts_with("wpkh(["));

        let bip48 = &v["bip48_2"];
        assert_eq!(bip48["name"], "p2wsh");
        assert_eq!(bip48["deriv"], "m/48h/0h/0h/2h");
        assert_eq!(bip48["xpub"], d48.account.xpub);
        // No descriptor, no SLIP-132, no first-address for multisig - see module docs.
        assert!(bip48.get("desc").is_none());
        assert!(bip48.get("_pub").is_none());
        assert!(bip48.get("first").is_none());
    }

    // -- bitcoin_core_import_descriptors(): RPC request shape ------------------------

    #[test]
    fn core_import_descriptors_matches_documented_fields() {
        let requests = [CoreImportRequest {
            desc: "wpkh([...]xpub.../<0;1>/*)#abcdefgh",
            timestamp: CoreTimestamp::Now,
            active: true,
            range: Some((0, 999)),
            next_index: None,
            internal: false,
            label: Some("notyas"),
        }];
        let text = bitcoin_core_import_descriptors(&requests);
        let v: Value = serde_json::from_str(&text).expect("valid JSON");
        assert!(v.is_array());
        let entry = &v[0];
        assert_eq!(entry["desc"], requests[0].desc);
        assert_eq!(entry["timestamp"], "now");
        assert_eq!(entry["active"], true);
        assert_eq!(entry["range"][0], 0);
        assert_eq!(entry["range"][1], 999);
        assert_eq!(entry["label"], "notyas");
        assert!(entry.get("internal").is_none(), "internal:false is omitted, not written");
    }

    #[test]
    fn core_import_descriptors_unix_timestamp_and_internal() {
        let requests = [CoreImportRequest {
            desc: "wpkh([...]xpub.../1/*)#abcdefgh",
            timestamp: CoreTimestamp::Unix(1_455_191_478),
            active: false,
            range: None,
            next_index: None,
            internal: true,
            label: None,
        }];
        let text = bitcoin_core_import_descriptors(&requests);
        let v: Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(v[0]["timestamp"], 1_455_191_478u64);
        assert_eq!(v[0]["internal"], true);
        assert!(v[0].get("active").is_none());
        assert!(v[0].get("label").is_none());
    }

    // -- electrum_wallet_file(): watch-only bip32 keystore ---------------------------

    #[test]
    fn electrum_wallet_file_matches_documented_keystore_shape() {
        let seed = bip84_test_seed();
        let network = Network::Bitcoin;
        let fingerprint = derive::master_fingerprint(&seed, network);
        let d84 = derive::derive(&seed, network, Scheme::Bip84, ChildIndex::ZERO, ChildIndex::ZERO, 0, 0);

        let text = electrum_wallet_file(Scheme::Bip84, fingerprint, &d84.account).expect("bip84 exports");
        let v: Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(v["seed_version"], 17);
        assert_eq!(v["use_encryption"], false);
        assert_eq!(v["wallet_type"], "standard");
        let ks = &v["keystore"];
        assert_eq!(ks["type"], "bip32");
        assert_eq!(ks["xpub"], d84.account.slip132_pub.clone().unwrap());
        assert_eq!(ks["root_fingerprint"], fingerprint.to_string());
        assert_eq!(ks["derivation"], "m/84'/0'/0'");
        // Never Coldcard's own hardware fields - see module docs on why.
        assert!(ks.get("hw_type").is_none());
        assert!(ks.get("ckcc_xfp").is_none());
    }

    /// Testnet is one tap away on the Home screen, so every export has to be defined
    /// there. Electrum picks the script type out of the xpub's own version bytes and its
    /// table has a test-chain row (tpub / upub / vpub); handing it the plain tpub for a
    /// BIP84 account would make it build P2PKH addresses from a native-segwit key.
    #[test]
    fn electrum_wallet_file_on_testnet_uses_the_test_chain_prefixes() {
        let seed = bip84_test_seed();
        let network = Network::Testnet;
        let fingerprint = derive::master_fingerprint(&seed, network);
        for (scheme, prefix, path) in [
            (Scheme::Bip44, "tpub", "m/44'/1'/0'"),
            (Scheme::Bip49, "upub", "m/49'/1'/0'"),
            (Scheme::Bip84, "vpub", "m/84'/1'/0'"),
        ] {
            let d = derive::derive(
                &seed,
                network,
                scheme,
                ChildIndex::ZERO,
                ChildIndex::ZERO,
                0,
                0,
            );
            let text = electrum_wallet_file(scheme, fingerprint, &d.account)
                .expect("every single-sig scheme Electrum understands exports on testnet");
            let v: Value = serde_json::from_str(&text).expect("valid JSON");
            let xpub = v["keystore"]["xpub"].as_str().expect("keystore xpub");
            assert!(xpub.starts_with(prefix), "{scheme}: {xpub} is not a {prefix}");
            assert_eq!(v["keystore"]["derivation"], path);

            // SLIP-132 is a relabelling, never a re-derivation: only the four version
            // bytes may differ from the tpub of the very same node.
            let relabelled = bitcoin::base58::decode_check(xpub).expect("base58check");
            let plain = bitcoin::base58::decode_check(&d.account.xpub).expect("base58check");
            assert_eq!(relabelled[4..], plain[4..], "{scheme}: payload changed");
        }
    }

    #[test]
    fn electrum_wallet_file_refuses_taproot_and_multisig() {
        let seed = bip84_test_seed();
        let network = Network::Bitcoin;
        let fingerprint = derive::master_fingerprint(&seed, network);
        let d86 = derive::derive(&seed, network, Scheme::Bip86, ChildIndex::ZERO, ChildIndex::ZERO, 0, 0);
        let d48 = derive::derive(&seed, network, Scheme::Bip48, ChildIndex::ZERO, ChildIndex::ZERO, 0, 2);
        assert_eq!(
            electrum_wallet_file(Scheme::Bip86, fingerprint, &d86.account),
            Err(ElectrumError::UnsupportedScheme(Scheme::Bip86))
        );
        assert_eq!(
            electrum_wallet_file(Scheme::Bip48, fingerprint, &d48.account),
            Err(ElectrumError::UnsupportedScheme(Scheme::Bip48))
        );
        // The refusal has to name the combination, or a device cannot tell the user which
        // format to pick instead.
        assert_eq!(
            ElectrumError::UnsupportedScheme(Scheme::Bip86).to_string(),
            "Electrum has no wallet file for bip86 accounts"
        );
    }

    /// The panic this replaced was reachable from the Home screen's network toggle. An
    /// `AccountKeys` a caller assembled by hand is the only way left to fail here, and it
    /// has to be a refusal: this runs on a device holding a seed.
    #[test]
    fn electrum_wallet_file_refuses_a_malformed_xpub_rather_than_panicking() {
        let account = AccountKeys {
            path: "m/84'/0'/0'".to_string(),
            xprv: String::new(),
            xpub: "not an extended key".to_string(),
            slip132_prv: None,
            slip132_pub: None,
        };
        assert_eq!(
            electrum_wallet_file(Scheme::Bip84, Fingerprint::default(), &account),
            Err(ElectrumError::MalformedAccountXpub)
        );
    }
}
