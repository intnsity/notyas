# notyas-wallet - API design (0.2.0)

Status: PLAN. This document makes plan-0.2.0/ARCHITECTURE.md section 1 ("Responsibility
boundary of notyas-wallet vs vetted primitives"), section 2 (storage), section 3 (wallet
management), section 4 (multisig) and section 5 (signing pipeline) concrete as a Rust API.
It does not re-decide the crate stack, the storage scheme, the randomness policy or the
multisig scope - those are settled in ARCHITECTURE.md and ratified (or queued) in
OPEN-QUESTIONS.md Q1-Q13.

Normative inputs, cited throughout:

- plan-0.2.0/ARCHITECTURE.md - crate boundary (1), key ladder and record format (2.2-2.7),
  wallet/session model (3), multisig registry (4), signing pipeline and the 10-check
  validation table (5.1-5.4).
- plan-0.2.0/SECURITY.md - invariants 2a/2b (what may be written), 3 (deterministic, no
  RNG), 4 (equivalence), 7 (the policy engine is the trust boundary).
- plan-0.2.0/PARITY.md - the Coldcard feature bar this API must be able to reach
  (sections 3, 4, 5, 6).
- plan-0.2.0/UX.md - screens 9-12 and commandment 10 (refusals are first-class,
  plain-words, rendered verbatim).
- plan-0.2.0/MILESTONES.md - m2 (notyas-core signing API), m3 (sealing/storage),
  m4a (session), m6 (PSBT engine), m7 (multisig), m8 (UR2).
- docs/SECURITY.md and docs/ARCHITECTURE.md (0.1.0 baseline) - the stateless identity this
  crate must preserve.
- Existing code this API must fit: crates/notyas-core/src/{lib,derive,bip39,report}.rs
  (ChildIndex, Scheme, Mnemonic, the Drop/redacting-Debug discipline) and
  crates/notyas-ui/src/lib.rs (the Ui / UiRequest request-response boundary).

The firmware side of the three platform traits defined here (Storage, DeviceBinding,
KdfScratch) is specified in plan-0.2.0/ESP-SEAL.md, written in parallel. This document owns
the trait shapes; ESP-SEAL.md owns their esp_partition / HMAC-peripheral / PSRAM
implementations. Where the two disagree, the trait signatures here are the contract to
reconcile against.

---

## 0. The rules this API is built to

Non-negotiable, inherited from the plan and the house rules. Every one of them is a
property of the API surface, not a promise in prose:

1. `#![no_std]` + `alloc`, `#![forbid(unsafe_code)]`. No `std`, no IDF, no I/O, no clock,
   no RNG - not in the crate, not in its dependency graph (SECURITY.md invariant 3; the
   build-graph CI check from tools/ extends to this crate at m3).
2. Everything the outside world can do to the crate arrives as bytes or as a trait call
   the firmware implements. Time arrives as an `elapsed_ms` argument. There is no
   `Read`/`Write`, no filename opening, no peripheral handle.
3. Primitives are reused, never reimplemented: rust-bitcoin `=0.32.102`
   (`default-features=false, features=["alloc","base64"]`), miniscript `13.1`
   (`default-features=false`), RustCrypto `argon2`/`chacha20poly1305`/`hkdf`/`hmac`/`sha2`
   (all `default-features=false`), `foundation-ur`/`foundation-urtypes`
   (`default-features=false`), `zeroize`. What this crate owns is policy, state machines,
   the storage format and the validation pipeline (ARCHITECTURE.md 1).
4. Every secret-bearing type gets zeroize-on-drop and a hand-written redacting `Debug`,
   exactly as `notyas_core::bip39::Mnemonic`, `derive::AccountKeys` and
   `derive::SecretXpriv` do today. Deriving `Debug` on a type that transitively holds key
   material is a review-blocking defect.
5. Nothing on an untrusted-input path may panic. notyas-core is allowed its `expect` on
   structurally impossible derivation failures; notyas-wallet parses hostile input, so a
   would-be panic becomes `Error::Invariant` with a stable code that the UI can display and
   a bug report can quote. The host fuzzer asserts this (m3, m6 gates).
6. Stateless 0.1.0 mode is first-class in the type system, not a branch in the firmware: a
   session need not come from a vault, and `Vault::mount` on a blank partition performs no
   write (OPEN-QUESTIONS Q11, ARCHITECTURE.md 8).
7. Host-testable with zero hardware. Every trait has a stub in `testkit`; every
   cryptographic step has known-answer vectors; the storage engine is power-loss fuzzable
   on host.

Cargo manifest sketch (features are additive and none of them can reach std or an RNG):

```toml
[package]
name = "notyas-wallet"
edition = "2021"
license = "GPL-3.0-or-later"

[features]
default = []
# Host-side stubs (MemStorage, StubBinding, VecScratch, tiny KDF params) for unit tests,
# the power-loss fuzzer and tools/. Adds no dependency; gated so it cannot ship in
# firmware by accident.
testkit = []

[dependencies]
notyas-core        = { path = "../notyas-core", default-features = false }
miniscript         = { version = "13.1", default-features = false, features = ["no-std"] } # see DECISION D1
argon2             = { version = "0.5", default-features = false, features = ["alloc"] }
chacha20poly1305   = { version = "0.10", default-features = false, features = ["alloc"] }
hkdf               = { version = "0.12", default-features = false }
hmac               = { version = "0.12", default-features = false }
sha2               = { version = "0.10", default-features = false }
foundation-ur      = { version = "*", default-features = false }
foundation-urtypes = { version = "*", default-features = false }
zeroize            = { version = "1", default-features = false, features = ["alloc", "derive"] }
```

`bitcoin` is NOT a direct dependency: the crate names `notyas_core::bitcoin`, the same
re-export notyas-ui uses, so a version or feature drift between the derivation path and the
signing path is impossible to express (crates/notyas-core/src/lib.rs, lines 51-55).

DECISION D1: the exact miniscript feature spelling is verified at m6 against the pinned
13.1 metadata (ARCHITECTURE.md 1 records that 13.x is no_std with default features off and
that the named `no-std` feature was the 12.x convention). The manifest line above is
written the way the audit expects it and is a build-gate item, not a design question.

---

## 1. Module map

Eight modules, each a deep module in the Ousterhout sense: a small interface over
substantial implementation. The count is deliberate - the alternative decompositions
considered and rejected are listed after the table, because a wallet crate is exactly the
place where "one shallow module per concept" produces forty types and no simplification.

| Module | Interface size | What it owns |
|---|---|---|
| `wallet` | ~10 items | identity, records, accounts, descriptors |
| `seal` | ~8 items | the key ladder and the AEAD record cryptography |
| `store` | ~12 items | the Storage trait, two-slot A/B commit, counters, mount/commit/wipe |
| `session` | ~8 items | unlock -> use -> lock/wipe lifecycle and secret ownership |
| `registry` | ~10 items | multisig registrations, import dialects, verification rules |
| `policy` | ~15 items | the validation pipeline, review model, refusals |
| `signer` | ~5 items | signing execution, post-sign gate, finalization |
| `transport` | ~10 items | PSBT encodings, Coldcard file naming, UR2 chunking |

**`wallet`** - what a notyas wallet *is*. A wallet is one BIP39 entropy value plus its
metadata; accounts are `(Scheme, ChildIndex)` pairs over it, and each account projects to a
descriptor. This module owns `WalletId`, `WalletMeta`, `WalletDraft`, `OpenWallet`,
`WalletView`, `AccountSpec` and `OwnedDescriptor`, and it is the only place that turns seed
material into keys (by calling notyas-core, never by deriving anything itself). Its deep
part is the descriptor projection: singlesig descriptors are *built* here from the wallet's
own xpubs and multisig descriptors are *adopted* here from a verified registration, so
everything downstream sees one uniform "descriptor we can prove is ours" type.

**`seal`** - the ladder of ARCHITECTURE.md 2.2 as three functions
(`device_id`, `stretch`, `seal`/`open`) over two platform traits. It knows Argon2id
parameters, the HKDF info construction (label, slot, wipe_epoch, seal_seq), the AAD framing
and the ChaCha20-Poly1305 call. It knows nothing about flash, slots-as-storage, or what a
record means; it takes a header and bytes. This is the crate's smallest interface over its
most security-critical implementation, which is exactly the shape a KAT suite wants.

**`store`** - the `Storage` trait the firmware implements plus the record engine above it:
sector geometry, the two-slot A/B commit with seq-comparison as the commit point, the
stale-inactive-slot erase rule (ARCHITECTURE.md 2.6), the plaintext counters area with
Trezor-style bit-clear attempt logs and guard bits, `seal_seq` high-water reconciliation and
the one-way `wipe_epoch` (2.5). `Vault<S>` is the deep object: mount, unlock, open, save,
delete, change PIN, wipe - each a single call whose implementation is a power-loss-safe
sequence of erases and writes. Nothing above this module ever names a sector.

**`session`** - the lifecycle. `Session` owns the post-Argon2 `Bound` key and the device id
in `Zeroizing` wrappers, tracks idle time fed by `tick(elapsed_ms)`, and is the capability
token every vault operation on secret data requires. It is the first notyas secret that
outlives a screen (ARCHITECTURE.md 3), so its wipe points are its API: `lock()`, `Drop`,
`Liveness::Expired`. It also carries the "where did this session come from" distinction
(sealed slot vs transient, Q11) that the review UI must show.

**`registry`** - multisig registrations. Canonical form is a descriptor string with
checksum (`wsh(sortedmulti(...))`, multipath `<0;1>`); the Coldcard `.txt` format is an
import *dialect* converted on ingest, never a stored form (ARCHITECTURE.md 4). The deep
part is the verification pipeline that turns an untrusted file into a `VerifiedRegistration`
- our-key membership by derive-and-compare, M/N/script-type/derivation agreement, cosigner
enumeration for on-screen confirmation - which is the direct answer to the 2021 Coldcard
xpub-substitution disclosure.

**`policy`** - the trust boundary (SECURITY.md invariant 7). One pure function,
`evaluate(psbt, context) -> Verdict`, that runs the ordered gates of section 3, produces
either a displayable `Refusal` or an `Approval` carrying the review model the UI renders
verbatim, and touches no private key: it takes a `WalletView`, which structurally cannot
derive one. Everything else in the module is the vocabulary of its output.

**`signer`** - execution. Takes an `Approval` by value (it is a non-`Clone` witness bound to
the exact PSBT bytes that were reviewed), derives exactly the keys the approved plan names,
calls `Psbt::sign`, then runs the post-sign gate: independent sighash recomputation and
signature verification, then miniscript's interpreter/finalizer. Small interface, three
substantial obligations.

**`transport`** - the byte formats of the airgap. PSBT encoding autodetect
(binary/base64/hex) and re-encoding in the input's encoding, the Coldcard output-name
convention, the raw-transaction rendering for `-final.txn`, and the UR2 fountain chunking
parameters and frame cursor. No file is opened here; the firmware hands in bytes and takes
out bytes or frame strings.

Rejected decompositions, recorded so they are not re-proposed:

- A separate `descriptor` module wrapping miniscript, a separate `psbt` module wrapping
  rust-bitcoin, a separate `ur` module wrapping foundation-ur. All three would be shallow
  modules whose interface is as wide as their implementation - the exact anti-pattern
  ARCHITECTURE.md 1 rejects when it says "one new crate, not three".
- A separate `error` module as the public home of every error type. Errors live with the
  operation that produces them (`policy::Refusal`, `store::UnlockRefused`); only the
  crate-level `Error` sum and the shared `Fault`/`Invariant` types are re-exported at the
  root (section 4).
- Splitting `policy` into ten gate modules. The gates share the derived-script cache, the
  amount arithmetic and the review model; ten modules would mean ten interfaces over one
  data structure. They are ten functions in one module with one `Gate` enum.
- Merging `policy` and `signer`. Tempting (one "signing" module), rejected: the whole point
  of the design is that evaluation happens with no key material in scope. Two modules make
  that inspectable at the import list, and `Approval` is the seam.

---

## 2. Public API

Signatures are the design; bodies are m3/m6/m7 work. Types are grouped by module. All
`Vec`/`String` are `alloc`'s.

### 2.1 Shared value types (crate root)

```rust
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;

pub use notyas_core::bitcoin;   // the pipeline's own pin, never a second dependency
pub use miniscript;             // re-exported for the firmware's few type mentions

pub mod policy;
pub mod registry;
pub mod seal;
pub mod session;
pub mod signer;
pub mod store;
pub mod transport;
pub mod wallet;

#[cfg(feature = "testkit")]
pub mod testkit;

pub use error::{Error, Fault, Invariant, InvariantCode, Malformed};
pub use policy::{Refusal, RefusalCode};

/// Which sealed slot a record lives in. Constructing one out of range is impossible, so
/// no code below this type re-validates a slot index (the `ChildIndex` pattern from
/// notyas-core/src/derive.rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SlotId(u8);

impl SlotId {
    /// ARCHITECTURE.md 2.6: 8 wallet slot pairs in the 256 KiB wallets partition.
    pub const CAPACITY: u8 = 8;
    pub fn new(index: u8) -> Option<SlotId>;
    pub fn get(self) -> u8;
}

/// A user-visible wallet name. ASCII printable, 1..=20 bytes, no leading/trailing space:
/// it is rendered in mono on the wallet list and typed back verbatim to confirm a delete,
/// so the charset is part of the safety story, not cosmetics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label(alloc::string::String);

impl Label {
    pub const MAX_BYTES: usize = 20;
    pub fn new(text: &str) -> Result<Label, Malformed>;
    pub fn as_str(&self) -> &str;
}

/// Proof that the user typed a destructive operation's target name correctly. The only
/// constructor compares against the live label, so a delete/wipe entry point cannot be
/// called without the confirmation having happened (UX.md screen 15, grade (c)).
#[derive(Debug)]
pub struct TypedName<'a>(&'a Label);

impl<'a> TypedName<'a> {
    pub fn check(label: &'a Label, typed: &str) -> Option<TypedName<'a>>;
}

/// A device PIN or passphrase. NFKD-normalized at construction (the same normalization
/// discipline as BIP39, ARCHITECTURE.md 2.2), zeroize-on-drop, redacting Debug.
pub struct Pin(/* Zeroizing<String> */);

impl Pin {
    /// OPEN-QUESTIONS Q5: minimum 6, no maximum below 64, full alphanumeric accepted.
    pub const MIN_CHARS: usize = 6;
    pub const MAX_CHARS: usize = 64;
    pub fn new(raw: &str) -> Result<Pin, PinRejected>;
    /// Conservative entropy estimate for the creation screen's honesty line
    /// ("a digits-only PIN protects against theft, not against a funded lab").
    pub fn strength(&self) -> Strength;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRejected { TooShort { min: usize }, TooLong { max: usize }, DisallowedChar }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Strength { pub bits: u16, pub class: PinClass }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinClass { DigitsOnly, Alphanumeric, Passphrase }

/// The first N characters of a PIN, for the half-PIN anti-phishing words. Separate type so
/// a prefix can never be mistaken for a full PIN by a call site.
pub struct PinPrefix(/* Zeroizing<String> */);

/// Two BIP39 words derived as HMAC_efuse(pin_prefix), Coldcard's anti-phishing pattern
/// (ARCHITECTURE.md 3, OPEN-QUESTIONS Q10). Lives here rather than in the firmware because
/// it is deterministic policy over the shared wordlist and must be host-testable; the
/// firmware only supplies the `DeviceBinding`. Costs no attempt-counter decrement.
pub fn anti_phishing_words<B: seal::DeviceBinding>(
    prefix: &PinPrefix,
    binding: &B,
) -> Result<[&'static str; 2], Fault>;
```

`Zeroize`/`Drop`/redacting-`Debug` obligations, stated once and applied everywhere below:
`Pin`, `PinPrefix`, `seal::Bound`, `seal::DeviceId`, `wallet::WalletDraft`,
`wallet::OpenWallet`, `session::Session`, `registry::` nothing (registrations are public
data), and every buffer handed to `KdfScratch` (the crate zeroizes caller-owned scratch
before returning, whether the call succeeded or not).

### 2.2 Platform traits (what the firmware implements)

Three narrow traits instead of one `Platform` supertrait, deliberately: the storage fuzzer
must stub flash without stubbing the HMAC peripheral, and the seal KAT suite must stub the
HMAC peripheral without owning a flash image. See ESP-SEAL.md for the ESP32-P4 side.

```rust
// --- store ---------------------------------------------------------------------------

/// Which raw partition an access targets (ARCHITECTURE.md 2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Area {
    /// `wallets`, 256 KiB, `encrypted` flag on release units. Sealed records only.
    Wallets,
    /// `counters`, 16 KiB, plaintext by necessity: bit-clear attempt logs are incompatible
    /// with XTS write granularity (ARCHITECTURE.md 2.5).
    Counters,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub sector_bytes: u32,
    pub wallets_sectors: u32,
    pub counters_sectors: u32,
}

/// Raw flash, as narrow as the record engine can make it. Erase is sector-granular, writes
/// obey `write_granularity` (16 bytes on the XTS-encrypted wallets area, byte or word on
/// the plaintext counters area - which is what makes progressive 1->0 bit programming of
/// the attempt log legal there and illegal in Wallets).
pub trait Storage {
    type Error: core::fmt::Debug;

    fn geometry(&self) -> Geometry;
    fn write_granularity(&self, area: Area) -> u32;

    fn read(&self, area: Area, sector: u32, offset: u32, buf: &mut [u8]) -> Result<(), Self::Error>;
    fn write(&mut self, area: Area, sector: u32, offset: u32, data: &[u8]) -> Result<(), Self::Error>;
    fn erase(&mut self, area: Area, sector: u32) -> Result<(), Self::Error>;
}

// --- seal ----------------------------------------------------------------------------

/// The device-binding step of the ladder: HMAC-SHA256 under a key in a read-protected
/// eFuse block, computed by the P4 HMAC peripheral. Software never sees the key, so every
/// PIN guess must run on this physical device (ARCHITECTURE.md 2.2, SECURITY.md tier 1).
pub trait DeviceBinding {
    type Error: core::fmt::Debug;
    fn hmac_sha256(&self, message: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>, Self::Error>;
}

/// Working memory for Argon2id. The firmware owns the allocation policy (PSRAM on device,
/// a Vec on host) because 64 MiB is a board decision, not a crate decision; the crate owns
/// the wipe. Returning `None` for a size the platform cannot serve is not an error, it is
/// the input to the fallback parameter set (ARCHITECTURE.md 2.3).
pub trait KdfScratch {
    fn scratch(&mut self, bytes: usize) -> Option<&mut [u8]>;
}
```

### 2.3 `seal` - the key ladder and record cryptography

```rust
/// HKDF info label, pinned in SPEC. Changing it invalidates every stored record, which is
/// why it is a versioned constant and not a formatted string.
pub const SEAL_LABEL: &[u8] = b"notyas-seal-v1";
pub const SALT_LABEL: &[u8] = b"notyas-salt-v1";
pub const DEVICE_ID_MESSAGE: &[u8] = b"notyas-device-id";

/// Argon2id cost. `p` is pinned to 1; `m_kib`/`t` are measured at m1 on rev v1.3 silicon
/// WITH flash+PSRAM encryption enabled and then pinned in SPEC (ARCHITECTURE.md 2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams { pub m_kib: u32, pub t: u32, pub p: u32 }

impl KdfParams {
    /// The shipped parameters. Placeholder until the m1 benchmark pins them.
    pub const PINNED: KdfParams = KdfParams { m_kib: 65_536, t: 3, p: 1 };
    /// Internal-SRAM fallback if PSRAM latency is pathological (ARCHITECTURE.md 2.3).
    pub const FALLBACK: KdfParams = KdfParams { m_kib: 16_384, t: 6, p: 1 };
    /// Cheap parameters for host unit tests and the reduced-cost boot self-test vector.
    pub const REDUCED: KdfParams = KdfParams { m_kib: 64, t: 1, p: 1 };
}

/// HMAC_efuse("notyas-device-id"). Not a secret the user has, but device-bound material:
/// treated as secret (Zeroizing, redacting Debug) because it is an input to every salt.
pub struct DeviceId(/* Zeroizing<[u8; 32]> */);

/// The post-Argon2, post-HMAC value the whole session's record keys derive from. PIN-
/// equivalent for this device while it lives; that is exactly why `Session` owns it and
/// wipes it on lock, timeout and drop (SECURITY.md invariant 2a).
pub struct Bound(/* Zeroizing<[u8; 32]> */);

pub fn device_id<B: DeviceBinding>(binding: &B) -> Result<DeviceId, Fault>;

/// kdf_salt = SHA256(SALT_LABEL || device_id || slot). Deterministic by policy: the salt's
/// only job is defeating cross-device precomputation (ARCHITECTURE.md 2.4, Q4).
pub fn kdf_salt(device: &DeviceId, slot: SlotId) -> [u8; 32];

/// pin -> Argon2id -> HMAC-eFuse. The only expensive call in a session; runs once at unlock
/// and once per PIN change. Zeroizes the scratch buffer before returning on every path.
pub fn stretch<B, K>(
    pin: &Pin,
    device: &DeviceId,
    params: KdfParams,
    binding: &B,
    scratch: &mut K,
) -> Result<Bound, Fault>
where
    B: DeviceBinding,
    K: KdfScratch;

/// What a record's AAD commits to. Serialized verbatim as the record header on flash, so
/// the header a reader parsed and the AAD it authenticates cannot diverge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub format: u8,
    pub kind: RecordKind,
    pub slot: SlotId,
    pub seal_seq: u64,
    pub wipe_epoch: u32,
    pub kdf: KdfParams,
    pub plaintext_len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind { VaultHeader, Wallet, Registration, Filler }

/// okm = HKDF-SHA256(ikm=bound, salt=kdf_salt(device, slot),
///                   info=SEAL_LABEL || slot || wipe_epoch || seal_seq);
/// key = okm[0..32], nonce = okm[32..44]; AEAD AAD = the serialized header.
/// Nonce uniqueness is structural, never random (ARCHITECTURE.md 2.4).
pub fn seal(
    bound: &Bound,
    device: &DeviceId,
    header: &RecordHeader,
    plaintext: &[u8],
    out: &mut alloc::vec::Vec<u8>,
) -> Result<(), Fault>;

pub fn open(
    bound: &Bound,
    device: &DeviceId,
    header: &RecordHeader,
    ciphertext: &[u8],
) -> Result<zeroize::Zeroizing<alloc::vec::Vec<u8>>, OpenFailure>;

/// Deliberately coarse. A wrong PIN and a corrupt record are the same event to a caller:
/// the AEAD tag failed. There is no oracle beyond the attempt counter, which was already
/// decremented before the attempt (Trezor discipline, ARCHITECTURE.md 2.2/2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenFailure { Tag, Header, Fault(Fault) }

/// Device-bound pseudorandom filler for unoccupied slots, so occupancy is not readable from
/// a pre-PIN flash dump. Present as a hook and OFF by default: it only ships if
/// OPEN-QUESTIONS Q2 takes option (a), which also degrades the Verify screen's storage
/// readout. No RNG involved - the stream is HMAC-eFuse derived (Q2 analysis, invariant 3).
pub fn filler(device: &DeviceId, slot: SlotId, len: usize, out: &mut alloc::vec::Vec<u8>);
```

### 2.4 `store` - vault, records, counters

```rust
pub struct Vault<S: Storage> { /* storage, geometry, parsed slot table, counter state */ }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    /// Nothing has ever been sealed. The device is behaviorally a 0.1.0 device and this
    /// crate has not written a byte (ARCHITECTURE.md 8, SECURITY.md invariant 2a).
    Blank,
    Provisioned { occupied: u8, capacity: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterState {
    pub attempts_remaining: u8,
    pub attempts_max: u8,
    pub wipe_epoch: u32,
    pub seal_seq: u64,
}

impl<S: Storage> Vault<S> {
    /// Read-only. Parses both slots of every pair, reconciles seal_seq
    /// (`max(counter high-water, max over valid record seqs) + 1`), and reports torn or
    /// superseded slots for cleanup. Writes nothing, ever - including on a blank partition.
    pub fn mount(storage: S) -> Result<Vault<S>, Fault>;

    pub fn state(&self) -> VaultState;
    pub fn counters(&self) -> CounterState;

    /// Occupancy only, no PIN required - which is precisely the leak OPEN-QUESTIONS Q2
    /// analyses. Under Q2 option (a) every slot reads as occupied and this returns a
    /// constant.
    pub fn occupancy(&self) -> [bool; SlotId::CAPACITY as usize];

    /// First save on a blank device: burns nothing here (the eFuse provisioning is the
    /// firmware's job, ESP-SEAL.md) but writes the vault header and pins the KDF params
    /// the device will use forever after. Announced on-screen before it is called
    /// (UX.md commandment 6).
    pub fn provision<B, K>(&mut self, pin: &Pin, params: KdfParams, binding: &B, scratch: &mut K)
        -> Result<session::Session, Fault>
    where B: DeviceBinding, K: KdfScratch;

    /// Decrements the attempt counter BEFORE the unseal attempt and clears it on success
    /// (fail-closed, ARCHITECTURE.md 2.5). On the last failure it erases every wallet and
    /// registration record and bumps the one-way wipe epoch.
    pub fn unlock<B, K>(&mut self, pin: &Pin, binding: &B, scratch: &mut K)
        -> Result<session::Session, UnlockRefused>
    where B: DeviceBinding, K: KdfScratch;

    pub fn open(&self, session: &session::Session, id: wallet::WalletId, passphrase: &wallet::Passphrase<'_>)
        -> Result<wallet::OpenWallet, Error>;

    /// Seals a new record into the free half of the target slot pair, verifies readback,
    /// then erases the stale half (ARCHITECTURE.md 2.6 stale-ciphertext rule).
    pub fn save(&mut self, session: &session::Session, draft: &wallet::WalletDraft)
        -> Result<wallet::WalletId, Error>;

    pub fn update_meta(&mut self, session: &session::Session, id: wallet::WalletId, patch: wallet::MetaPatch)
        -> Result<(), Error>;

    pub fn delete(&mut self, session: &session::Session, id: wallet::WalletId, confirm: TypedName<'_>)
        -> Result<(), Error>;

    pub fn registrations(&self, session: &session::Session, id: wallet::WalletId)
        -> Result<alloc::vec::Vec<registry::Registration>, Error>;

    pub fn register(&mut self, session: &session::Session, verified: registry::VerifiedRegistration)
        -> Result<registry::RegistrationId, Error>;

    pub fn unregister(&mut self, session: &session::Session, id: registry::RegistrationId, confirm: TypedName<'_>)
        -> Result<(), Error>;

    /// Re-seals every record under the new PIN and erases each pair's stale half. Consumes
    /// the old session and returns a new one, so no caller can keep using keys derived from
    /// the retired PIN.
    pub fn change_pin<B, K>(&mut self, session: session::Session, new: &Pin, binding: &B, scratch: &mut K)
        -> Result<session::Session, Error>
    where B: DeviceBinding, K: KdfScratch;

    /// Destroys every sealed record and bumps the wipe epoch. Requires no session: it is
    /// the escape hatch for a user who cannot unlock, and the epoch bump is what keeps a
    /// post-wipe re-save under the same PIN from repeating a (key, nonce) pair
    /// (ARCHITECTURE.md 2.4/2.5).
    pub fn wipe(&mut self) -> Result<(), Fault>;

    pub fn into_storage(self) -> S;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockRefused {
    WrongPin { attempts_remaining: u8 },
    /// This attempt consumed the last try; records are gone, the epoch is bumped, and the
    /// user's own backup is the recovery path (SECURITY.md deterministic-wipe posture).
    Wiped { wipe_epoch: u32 },
    /// Nothing is sealed. Not an error: the caller should offer the 0.1.0 stateless flow.
    Blank,
    Fault(Fault),
}
```

### 2.5 `session` - unlock, use, lock, wipe

```rust
/// The unlocked-device capability. Holds `Bound` and `DeviceId` (both Zeroizing) so the
/// expensive ladder runs once per unlock; every vault operation on sealed data takes
/// `&Session`, so "you must be unlocked" is a type rule rather than a runtime check.
///
/// Redacting Debug prints the source and the idle time only.
pub struct Session { /* bound, device, source, idle_ms, auto_lock_ms */ }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSource {
    /// Unlocked from the sealed vault with the device PIN.
    Sealed,
    /// Typed dice/mnemonic this power cycle, nothing stored, nothing will be
    /// (OPEN-QUESTIONS Q11). Vault operations are unreachable: a transient session is
    /// constructed by `OpenWallet::transient`, which never yields a `Session` at all.
    Transient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness { Live { idle_ms: u32 }, Expired }

impl Session {
    pub fn source(&self) -> SessionSource;

    /// Metadata for every occupied slot, unsealed once at unlock so the wallet list needs
    /// no further key use. Public data only - no entropy is held here.
    pub fn wallets(&self) -> &[wallet::WalletMeta];

    /// Fed by the firmware main loop (`Ui::tick` cadence, ARCHITECTURE.md 6). The ONLY
    /// notion of time in the crate.
    pub fn tick(&mut self, elapsed_ms: u32) -> Liveness;
    /// User activity resets the idle timer.
    pub fn touch(&mut self);
    pub fn auto_lock_ms(&self) -> u32;
    pub fn set_auto_lock_ms(&mut self, ms: u32);

    /// Explicit lock. Consumes the session; `Drop` performs the same wipe, so forgetting to
    /// call this is safe and calling it is documentation.
    pub fn lock(self);
}
```

Wipe points, in the order the UX drives them (UX.md screens 7, 14, 16): Lock button ->
`Session::lock`; screen timeout -> `tick` returns `Expired` and the firmware drops the
session; power-off -> RAM loss plus the crate's own drop glue on the way down; wipe-on-N ->
`Vault::unlock` returns `Wiped` and no session ever exists.

### 2.6 `wallet` - identity, accounts, descriptors

```rust
/// Stable identity of a stored wallet. Equal to its slot, which is what the record header
/// binds the AEAD to, so a record cannot be replayed into a different slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletId(pub SlotId);

/// Everything the wallet list, review screens and exports need, and nothing secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletMeta {
    pub id: WalletId,
    pub label: Label,
    pub network: bitcoin::Network,
    /// Master fingerprint of the wallet as stored (no passphrase applied).
    pub fingerprint: bitcoin::bip32::Fingerprint,
    /// Fingerprint the wallet has WITH its passphrase, recorded at save time so a re-typed
    /// passphrase can be confirmed instead of silently opening a different wallet
    /// (UX.md commandment 8). `None` when the wallet was saved without one. See OPEN-W1.
    pub passphrase_check: Option<bitcoin::bip32::Fingerprint>,
    pub accounts: AccountSet,
    pub backup: BackupState,
    pub mode: notyas_core::bip39::MnemonicMode,
    pub created_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupState {
    /// The mandatory quiz was passed (UX.md screen 5). `seq` is the seal sequence at the
    /// time, the closest thing to a timestamp a clockless device has.
    Verified { seq: u64 },
    NotVerified,
}

/// The accounts a wallet exposes. Bounded (8) so a record has a fixed size ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSet(/* Vec<AccountSpec> */);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountSpec {
    /// notyas-core's `Scheme` verbatim - no parallel enum. Bip48 means P2WSH multisig
    /// (script_type 2) in 0.2.0 (OPEN-QUESTIONS Q7).
    pub scheme: notyas_core::derive::Scheme,
    pub account: notyas_core::derive::ChildIndex,
}

/// Which half of a descriptor's multipath `<0;1>` a derivation is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keychain { External, Internal }

/// Secret-bearing. Zeroize-on-drop, redacting Debug.
pub struct WalletDraft {
    pub label: Label,
    pub network: bitcoin::Network,
    /// BIP39 entropy bytes, not the 64-byte seed: keeps mnemonic re-display and the
    /// backup-verify dry run possible (ARCHITECTURE.md 2.2).
    pub entropy: zeroize::Zeroizing<alloc::vec::Vec<u8>>,
    pub mode: notyas_core::bip39::MnemonicMode,
    pub accounts: AccountSet,
    pub backup: BackupState,
    pub passphrase_check: Option<bitcoin::bip32::Fingerprint>,
}

/// A BIP39 passphrase as an argument, never as stored state. `none()` is the explicit,
/// readable way to say "this wallet has none" (the empty string is the same value but not
/// the same statement).
pub struct Passphrase<'a>(/* &'a str */);

impl<'a> Passphrase<'a> {
    pub fn none() -> Passphrase<'static>;
    pub fn new(text: &'a str) -> Passphrase<'a>;
}

/// Seed material for a transient (never-stored) wallet - the Q11 stateless signing path.
pub enum SeedInput<'a> {
    Entropy(&'a [u8]),
    Phrase(&'a str),
}

/// An unlocked wallet: the seed is live. Secret-bearing; zeroize-on-drop; redacting Debug.
pub struct OpenWallet { /* meta, entropy, seed */ }

impl OpenWallet {
    /// Stateless mode: a wallet that exists only in RAM and is not backed by any slot.
    /// Signing works identically; multisig change claims are refused by default because
    /// there is no registration to verify them against (Q11).
    pub fn transient(
        input: SeedInput<'_>,
        passphrase: &Passphrase<'_>,
        network: bitcoin::Network,
        accounts: AccountSet,
    ) -> Result<OpenWallet, Error>;

    pub fn meta(&self) -> &WalletMeta;
    /// The fingerprint of THIS open wallet (passphrase applied). Echoed on screen before
    /// any use, and compared against `meta.passphrase_check` when one was stored.
    pub fn fingerprint(&self) -> bitcoin::bip32::Fingerprint;

    /// The mnemonic for re-display and the backup-verify dry run. notyas-core's self-wiping
    /// type; the UI masks it per the 0.1.0 rules.
    pub fn mnemonic(&self) -> Result<notyas_core::bip39::Mnemonic, Error>;

    /// Public key source for export: (fingerprint, path, xpub) - the three things a
    /// coordinator needs and the three things the export screen shows (UX.md screen 13).
    pub fn key_source(&self, spec: AccountSpec) -> Result<KeySource, Error>;

    /// The singlesig descriptor for one account, built here from our own xpub - never
    /// parsed from anything a coordinator sent.
    pub fn account_descriptor(&self, spec: AccountSpec) -> Result<OwnedDescriptor, Error>;

    /// Everything this wallet can prove it owns: one descriptor per account plus one per
    /// registration bound to this wallet. This is the single input the policy engine
    /// classifies scripts against (see DECISION D2).
    pub fn descriptor_set(&self, registrations: &[registry::Registration])
        -> Result<DescriptorSet, Error>;

    /// Public projection handed to the policy engine. Borrowing rules then guarantee the
    /// engine cannot reach the seed: `WalletView` has no path to it.
    pub fn view<'a>(&'a self, set: &'a DescriptorSet) -> WalletView<'a>;

    // Private: key derivation is reachable only from `signer`, only for paths an
    // `Approval`'s plan names.
    // fn signing_key(&self, path: &DerivationPath) -> Result<notyas_core::derive::SecretSigningKey, Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySource {
    pub fingerprint: bitcoin::bip32::Fingerprint,
    pub path: bitcoin::bip32::DerivationPath,
    pub xpub: bitcoin::bip32::Xpub,
    /// SLIP-132 rendering where the ecosystem uses one (BIP49/84 mainnet), matching
    /// notyas-core's rule that multisig keys never wear singlesig prefixes.
    pub slip132: Option<alloc::string::String>,
}

/// A descriptor we can prove is ours, with the origin of that proof attached. Constructed
/// only by `OpenWallet::account_descriptor` (derived from our seed) or from a
/// `VerifiedRegistration` (membership checked). There is no public constructor from a
/// string, which is the whole point.
pub struct OwnedDescriptor { /* Descriptor<DescriptorPublicKey> (multipath), origin */ }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorOrigin {
    Derived(AccountSpec),
    Registered(registry::RegistrationId),
}

impl OwnedDescriptor {
    pub fn origin(&self) -> DescriptorOrigin;
    /// Canonical text WITH the BIP-380 checksum. The stored form and the exported form are
    /// this same string (ARCHITECTURE.md 4).
    pub fn to_string_with_checksum(&self) -> alloc::string::String;
    pub fn script_at(&self, keychain: Keychain, index: notyas_core::derive::ChildIndex)
        -> Result<bitcoin::ScriptBuf, Error>;
    /// First receive address, for the cross-device comparison that stands in for BSMS
    /// round 2 (ARCHITECTURE.md 4, OPEN-QUESTIONS Q6).
    pub fn first_address(&self, network: bitcoin::Network) -> Result<bitcoin::Address, Error>;
}

pub struct DescriptorSet { /* Vec<OwnedDescriptor> + derived-script cache */ }

impl DescriptorSet {
    /// Exact-match classification: does any owned descriptor derive this script_pubkey,
    /// within the search bounds? No heuristics, ever (ARCHITECTURE.md 5.3 check 3).
    pub fn locate(&self, spk: &bitcoin::Script, bounds: policy::GapBounds) -> Option<Ownership>;
    pub fn iter(&self) -> impl Iterator<Item = &OwnedDescriptor>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ownership {
    pub origin: DescriptorOrigin,
    pub keychain: Keychain,
    pub index: notyas_core::derive::ChildIndex,
    pub within_gap: bool,
}

/// Fields a UI action may change on a stored wallet. A patch type rather than a mutable
/// record: it enumerates exactly what is mutable, and everything else is immutable by
/// construction (relabel and backup-verified are the only two in 0.2.0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaPatch {
    pub label: Option<Label>,
    pub backup: Option<BackupState>,
}
```

DECISION D2: singlesig and multisig share one ownership mechanism. Both become
`OwnedDescriptor`s and both are classified by exact derive-and-compare through
`DescriptorSet::locate`. The alternative - a script-type-aware classifier with a separate
multisig path - is how the 2019 Coldcard multisig change confusion happened: two code paths
that were supposed to agree. One path, two sources of descriptors, one attack surface.

### 2.7 `registry` - multisig registrations

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationId(pub SlotId);

/// 0.2.0 script scope. Explicitly closed: an import naming P2SH or P2SH-P2WSH is refused
/// with a message that says so, rather than silently accepted (OPEN-QUESTIONS Q7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultisigScript { WshSortedMulti }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cosigner {
    pub fingerprint: bitcoin::bip32::Fingerprint,
    pub origin: bitcoin::bip32::DerivationPath,
    pub xpub: bitcoin::bip32::Xpub,
    /// True for exactly one cosigner in a stored registration: ours, proven by derivation.
    pub is_ours: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub id: RegistrationId,
    pub wallet: wallet::WalletId,
    pub label: Label,
    pub network: bitcoin::Network,
    pub script: MultisigScript,
    pub threshold: u8,
    pub cosigners: alloc::vec::Vec<Cosigner>,
    /// Canonical stored form: descriptor + checksum, multipath `<0;1>`.
    pub descriptor: alloc::string::String,
}

impl Registration {
    pub fn owned_descriptor(&self) -> Result<wallet::OwnedDescriptor, Error>;
    pub fn threshold_of(&self) -> (u8, u8);       // (M, N), for the review header
}

/// Import dialects. Descriptor is canonical; Coldcard `.txt` is converted on ingest and
/// never stored in its own form (ARCHITECTURE.md 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportDialect { Descriptor, ColdcardTxt }

/// Autodetects the dialect, parses, and produces a proposal that is NOT yet a registration:
/// nothing here has been checked against our keys.
pub fn parse(bytes: &[u8]) -> Result<Pending, Malformed>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub dialect: ImportDialect,
    pub script: MultisigScript,
    pub threshold: u8,
    pub cosigners: alloc::vec::Vec<Cosigner>,   // is_ours is false for all of them here
    pub descriptor: alloc::string::String,
    pub network: bitcoin::Network,
}

impl Pending {
    /// The 2021 xpub-substitution defense: derives OUR xpub at each claimed origin and
    /// compares, checks M/N bounds, script type, network, derivation shape, and rejects a
    /// registration we are not a member of. Also refuses duplicate xpubs and duplicate
    /// fingerprints, which is how a "2-of-3" becomes an attacker's 1-of-1.
    pub fn verify(self, wallet: &wallet::OpenWallet, label: Label)
        -> Result<VerifiedRegistration, Refusal>;

    /// Everything the confirmation screen shows before the user approves (UX.md screen 12).
    pub fn review(&self) -> RegistrationReview;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationReview {
    pub threshold: (u8, u8),
    pub script: MultisigScript,
    pub network: bitcoin::Network,
    pub cosigners: alloc::vec::Vec<Cosigner>,
    /// Shown for cross-device comparison; the manual stand-in for BSMS round 2.
    pub first_address: alloc::string::String,
    pub descriptor: alloc::string::String,
}

/// Only `Vault::register` accepts this, and only `Pending::verify` produces it: an
/// unverified descriptor cannot reach storage.
pub struct VerifiedRegistration { /* private */ }
```

### 2.8 `policy` - the validation pipeline

```rust
/// Policy constants in one place (OPEN-QUESTIONS Q13 for the fee numbers, ratified at 5%
/// and 500 sat/vB). **Only the WARNING thresholds are adjustable behind the Settings
/// expert gate - `fee.warn_percent_of_send` and `fee.warn_sat_per_vb`. `sighash` and
/// `fee.hard_max_percent` are NOT settable from any screen (ratified Q24: no override
/// ever disables a refusal).** The defaults are what ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_psbt_bytes: usize,
    pub max_inputs: u16,
    pub max_outputs: u16,
    pub max_path_depth: u8,
    pub fee: FeeLimits,
    pub gap: GapBounds,
    pub sighash: SighashPolicy,
}

impl Limits { pub const DEFAULT: Limits; }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeLimits {
    pub warn_percent_of_send: u8,   // 5
    pub warn_sat_per_vb: u32,       // 500
    pub hard_max_percent: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GapBounds {
    /// How far past the anchor a change index may sit and still be called CHANGE.
    pub forward: u32,
    /// Absolute ceiling on descriptor search; beyond it a script is EXTERNAL even if it
    /// would derive, because an unbounded search is a denial-of-service on a 400 MHz core.
    pub ceiling: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SighashPolicy {
    /// SIGHASH_ALL and SIGHASH_DEFAULT only. The 0.2.0 shipped value (see OPEN-W3).
    AllOnly,
    /// Reserved for an expert-gated future; refuses today.
    ExpertUnlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningMode {
    /// Wallet came from a sealed slot; registrations are available.
    Registered,
    /// Q11 stateless signing. Multisig change claims are refused, not downgraded to a
    /// warning: an unverifiable cosigner set is exactly the 2021 attack.
    Stateless,
}

pub struct PolicyContext<'a> {
    pub wallet: wallet::WalletView<'a>,
    pub limits: &'a Limits,
    pub mode: SigningMode,
}

/// The trust boundary (SECURITY.md invariant 7). Pure: no key derivation, no allocation of
/// secret material, no I/O, no time. Same PSBT + same context always yields the same
/// verdict, which is what makes the adversarial corpus a regression suite.
#[must_use]
pub fn evaluate(psbt: &bitcoin::psbt::Psbt, cx: &PolicyContext<'_>) -> Verdict;

#[must_use]
pub enum Verdict {
    Approve(Approval),
    /// Never `Result::Err`: a refusal is a normal, expected, displayable outcome, and
    /// making it an error invites a `?` that swallows the reason.
    Refuse(Refusal),
}

/// Witness that a specific PSBT passed every gate, plus the review model the UI renders.
/// Not `Clone`, not constructible outside this module, and bound to the exact bytes
/// reviewed - so it cannot be carried from one PSBT to another.
pub struct Approval {
    psbt_id: PsbtDigest,
    plan: SigningPlan,          // private: which inputs, which derivation paths
    pub summary: Summary,
    pub inputs: alloc::vec::Vec<InputRow>,
    pub outputs: alloc::vec::Vec<OutputRow>,
    pub warnings: alloc::vec::Vec<Warning>,
}

impl Approval {
    /// SHA256 of the serialized PSBT this approval belongs to.
    pub fn psbt_id(&self) -> PsbtDigest;
    /// The exact page list the review screen must show, in order. The UI enforces full
    /// traversal; the crate defines what "full" is, so the two cannot drift (DECISION D3).
    pub fn pages(&self) -> alloc::vec::Vec<ReviewPage>;
    pub fn signable_inputs(&self) -> usize;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PsbtDigest([u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub network: bitcoin::Network,
    pub leaving: bitcoin::Amount,        // total to EXTERNAL outputs
    pub returning: bitcoin::Amount,      // verified CHANGE back to us
    pub fee: bitcoin::Amount,
    pub fee_rate_sat_per_vb: u32,
    pub fee_percent_of_send: u16,        // basis points / 100, integer math only
    pub input_count: u16,
    pub output_count: u16,
    pub lock_time: bitcoin::absolute::LockTime,
    pub rbf_signaled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputRow {
    pub index: u16,
    pub outpoint: bitcoin::OutPoint,
    pub value: bitcoin::Amount,
    pub ownership: InputOwnership,
    pub script_kind: ScriptKind,
    pub sighash: SighashKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputOwnership {
    /// Ours, and we will sign it: the origin re-derives to this input's actual script.
    Ours { origin: wallet::DescriptorOrigin, keychain: wallet::Keychain, index: notyas_core::derive::ChildIndex },
    /// Not ours. Shown, never signed, never silently ignored.
    Foreign,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputRow {
    pub index: u16,
    pub value: bitcoin::Amount,
    /// FULL address, mono-rendered by the UI in 4-char chunks (UX.md commandment 1).
    pub destination: Destination,
    pub class: OutputClass,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    Address(alloc::string::String),
    /// OP_RETURN / data / unknown script types get their own page with the script type and
    /// raw payload in mono - never coerced into an address shape (UX.md screen 10 (a)).
    NonAddress { kind: ScriptKind, payload_hex: alloc::string::String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputClass {
    External,
    /// Proven change: our descriptor derives exactly this script at an internal index
    /// within the gap bound.
    Change { origin: wallet::DescriptorOrigin, index: notyas_core::derive::ChildIndex },
    /// Ours, but not change: an external-keychain script of ours, or an internal one past
    /// the gap bound. Counted as money leaving in the headline figure, with a warning
    /// (DECISION D4).
    OwnNotChange { origin: wallet::DescriptorOrigin, keychain: wallet::Keychain, index: notyas_core::derive::ChildIndex },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning { pub code: WarningCode, pub detail: alloc::string::String }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningCode {
    FeeAbovePercentThreshold,
    FeeAboveRateThreshold,
    ChangePastGapBound,
    SelfSendNotChange,
    NonAddressOutput,
    LockTimeInFuture,
    NoRbfSignal,
    ForeignInputsPresent,
    ManyOutputs,
    UnknownPsbtFieldsPresent,
    MultisigPartialSignatures,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewPage { Overview, Output(u16), Fee, Warnings, Inputs }
```

The refusal type - the part the UI must never be able to swallow:

```rust
/// Why the device said no, in a form a screen can render without interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub gate: Gate,
    pub code: RefusalCode,
    /// Bounded, secret-free evidence: indexes, amounts, fingerprints, script hex prefixes.
    pub evidence: alloc::vec::Vec<Evidence>,
}

impl Refusal {
    /// Short line, plain words, no jargon: "This transaction is missing data".
    pub fn headline(&self) -> &'static str;
    /// What happened and why the device refused, with the evidence interpolated.
    pub fn explain(&self) -> alloc::string::String;
    /// What to do next: the sentence that makes a refusal screen useful rather than a wall
    /// (UX.md commandment 10).
    pub fn next_step(&self) -> &'static str;
    /// Stable identifier for the golden-text tests and for a user quoting a bug report.
    pub fn code(&self) -> RefusalCode;
}

impl core::fmt::Display for Refusal { /* headline + explain */ }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    Structure = 1,
    Network = 2,
    Prevouts = 3,
    InputOwnership = 4,
    MultisigBinding = 5,
    Outputs = 6,
    Fee = 7,
    Sighash = 8,
    Taproot = 9,
    Plan = 10,
    PostSign = 11,
}

/// One variant per concrete reason the device refuses. Exhaustive matching in the UI is the
/// mechanism that keeps a new refusal from shipping without a screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCode {
    // Gate 1
    PsbtVersionUnsupported, DuplicateInput, InputAlreadyFinalized, TooManyInputs,
    TooManyOutputs, PsbtTooLarge, NoInputs, NoOutputs,
    // Gate 2
    NetworkMismatch, CoinTypeMismatch,
    // Gate 3
    MissingPreviousTransaction, PrevTxidMismatch, PrevAmountMismatch, MissingWitnessUtxo,
    // Gate 4
    OriginDoesNotDeriveScript, PathOutsidePurposeWhitelist, PathTooDeep,
    PathHardenedShapeInvalid, ForeignFingerprintClaimsOurKey,
    // Gate 5
    MultisigNotRegistered, MultisigRegistrationMismatch, MultisigNotAMember,
    MultisigStatelessUnverifiable, MultisigScriptTypeUnsupported,
    // Gate 6
    ChangeNotDerivable, OutputScriptUnparseable,
    // Gate 7
    NegativeFee, FeeAboveHardCap, FeeArithmeticOverflow,
    // Gate 8
    SighashTypeNotWhitelisted, SighashTypeMixedAcrossInputs,
    // Gate 9
    TaprootTweakMismatch, TaprootLeafNotRegistered, TaprootAnnexPresent,
    // Gate 10
    NothingToSign, WrongWallet,
    // Gate 11 (post-sign)
    ApprovalDoesNotMatchPsbt, SignatureVerificationFailed, InterpreterRejectedInput,
    PolicyChangedAfterSigning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    InputIndex(u16),
    OutputIndex(u16),
    Amount(bitcoin::Amount),
    Fingerprint(bitcoin::bip32::Fingerprint),
    Path(alloc::string::String),
    Expected(alloc::string::String),
    Found(alloc::string::String),
    /// For the wrong-wallet routing case: the stored wallet these inputs DO belong to
    /// (UX.md screen 9, red-team addition).
    SuggestWallet { id: wallet::WalletId, label: Label, fingerprint: bitcoin::bip32::Fingerprint },
}
```

DECISION D3: full-traversal enforcement stays in notyas-ui, but the page list comes from
`Approval::pages()`. Enforcement is an interaction property (which page has been visited)
and belongs with the state machine that owns the touch input; the *definition* of the
required set is policy and belongs here. This split is what lets a corpus test assert "this
PSBT requires 7 pages" without a display.

DECISION D4: an output that our descriptors derive but that is not verified change (wrong
keychain, or an internal index past the gap bound) is classified `OwnNotChange`, counted in
the "leaving" headline, warned about, and signed if the user approves - not refused. It is
our money either way; the risk the gate addresses is recoverability, not theft. Refusing
would make legitimate coordinator behavior (a change index the device cannot anchor) look
like an attack, and a device that cries wolf is a device whose warnings get ignored.

### 2.9 `signer` - execution and the post-sign gate

```rust
/// Derives exactly the keys the approved plan names, signs, then re-verifies. Takes the
/// `Approval` by value: an approval is spent by the signature it authorizes.
///
/// Order (ARCHITECTURE.md 5.2, 5.3 check 10):
///   1. recompute the PSBT digest and compare against `approval.psbt_id`;
///   2. re-run `policy::evaluate` and require an identical verdict (the "re-asserted
///      immediately before signing" step);
///   3. derive plan keys, `Psbt::sign` through rust-bitcoin;
///   4. recompute each sighash INDEPENDENTLY of the signing path and verify every
///      signature we just produced (the deterministic-nonce fault mitigation,
///      ARCHITECTURE.md 2.4);
///   5. run miniscript's interpreter; finalize only if our signatures complete every input.
pub fn sign(
    psbt: &bitcoin::psbt::Psbt,
    approval: policy::Approval,
    wallet: &wallet::OpenWallet,
    cx: &policy::PolicyContext<'_>,
) -> Result<Signed, Error>;

pub struct Signed { /* psbt, report */ }

impl Signed {
    pub fn psbt(&self) -> &bitcoin::psbt::Psbt;
    pub fn into_psbt(self) -> bitcoin::psbt::Psbt;
    pub fn completion(&self) -> &Completion;
    pub fn report(&self) -> &PostSignReport;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completion {
    /// Other cosigners are still needed; the emitted PSBT preserves their partial
    /// signatures and every unknown field untouched.
    Partial { signed_inputs: u16, total_inputs: u16, still_missing: u16 },
    /// Every input finalizes: a `-final.txn` can be written alongside the signed PSBT.
    Final { tx: bitcoin::Transaction, vsize: u32 },
}

/// What the post-sign gate actually verified. Rendered on the deliver screen (small print)
/// and asserted in CI: it is a security control, not a formality, so its result is data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostSignReport {
    pub signatures_added: u16,
    pub signatures_verified: u16,
    pub interpreter_checked_inputs: u16,
    pub sighashes_recomputed: u16,
}
```

### 2.10 `transport` - encodings, names, UR2 frames

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtEncoding { Binary, Base64, Hex }

/// Autodetect over the Coldcard-convention set (ARCHITECTURE.md 5.4). Size is capped by the
/// caller before the bytes ever reach here; this refuses anything that is not a PSBT v0
/// with a message a human can act on.
pub fn decode(bytes: &[u8]) -> Result<(bitcoin::psbt::Psbt, PsbtEncoding), Malformed>;

/// Re-encode in the input's encoding - the Coldcard behavior coordinators expect.
pub fn encode(psbt: &bitcoin::psbt::Psbt, encoding: PsbtEncoding) -> alloc::vec::Vec<u8>;

/// `-final.txn` content: the raw transaction as hex text.
pub fn encode_final_tx(tx: &bitcoin::Transaction) -> alloc::vec::Vec<u8>;

/// Coldcard output-name convention: `<stem>-signed.psbt`, plus `<stem>-final.txn` when
/// finalizable. Pure string policy, so it is unit-testable and cannot drift from what the
/// firmware writes.
pub fn output_names(input_name: &str, completion: &signer::Completion) -> OutputNames;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputNames {
    pub signed: alloc::string::String,
    pub final_txn: Option<alloc::string::String>,
}

/// Animated `ur:crypto-psbt` output (QR is out-only; there is no camera).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UrParams { pub max_fragment_len: usize }

impl UrParams { pub const DEFAULT: UrParams = UrParams { max_fragment_len: 200 }; }

pub struct UrStream { /* foundation-ur fountain encoder state */ }

impl UrStream {
    pub fn new(psbt: &bitcoin::psbt::Psbt, params: UrParams) -> Result<UrStream, Error>;
    /// Advance one frame. Called from the firmware's tick-driven repaint; the stream is
    /// a fountain, so it never ends and `cursor` is for the on-screen "i / j" counter.
    pub fn next_frame(&mut self) -> &str;
    pub fn cursor(&self) -> (usize, usize);
    pub fn set_density(&mut self, params: UrParams);
}
```

### 2.11 How this reaches the UI without dragging I/O into no_std

notyas-ui's `UiRequest` is the established seam (crates/notyas-ui/src/lib.rs, lines 223-236):
the state machine returns a request, the firmware performs the std-side work, and the answer
comes back through a `Ui::` setter. 0.2.0 extends the same pattern to storage and signing.
The rule this crate imposes on that extension:

DECISION D5: the UI owns render models, never secrets. `WalletMeta`, `Approval`, `Refusal`,
`RegistrationReview`, `Summary`, `InputRow`, `OutputRow`, `PostSignReport`, `UrStream`
frames and `CounterState` may cross into notyas-ui. `Session`, `OpenWallet`, `WalletDraft`,
`Bound`, `DeviceId` and `Pin` may not: they live on the firmware side, which already holds
the peripherals and the heap they need. A PIN typed on screen crosses as
`Zeroizing<String>` inside a `UiRequest`, is converted to `Pin` by the firmware, and the
UI's buffer is wiped on screen exit exactly as the passphrase buffer is today. This keeps
notyas-ui's "exactly one state alive, drop equals zeroize" property intact without teaching
it about vaults.

---

## 3. The signing validation pipeline

ARCHITECTURE.md 5.3 lists ten checks. Rendered as API they become eleven ordered gates (the
tenth check, the post-sign interpreter, runs after `Psbt::sign` and therefore lives in
`signer`, not in `evaluate`; and structural sanity splits from output classification because
one must run before anything else and the other needs the prevout values).

Ordering principle: cheap and decisive first, expensive last, and no key material in scope
for any of it. Every gate runs against the same immutable PSBT and appends to one review
model; the first refusal stops the pipeline (there is no "collect all errors" mode - the
first reason a device refuses is the one a user must act on, and a list of eleven complaints
is a screen nobody reads).

| # | Gate | ARCH 5.3 | What it checks | Enforcing layer | Attack class it answers | Failure mode |
|---|---|---|---|---|---|---|
| 0 | decode | 5.4 | encoding autodetect, size cap, PSBT v0 magic | RB parse, NW cap | oversized/garbage media, PSBT v2 confusion | `Malformed` (not a refusal - the file never became a PSBT) |
| 1 | `Structure` | 9 | duplicate inputs, already-finalized inputs, input/output count caps, non-empty tx, unknown fields recorded and preserved untouched | RB parse + NW | malformed/hostile PSBTs, finalize-then-resign tricks | `Refusal{DuplicateInput, InputAlreadyFinalized, TooManyInputs, ...}` |
| 2 | `Network` | 5 | every address and every key origin's coin_type match the WALLET's network (taken from the wallet record, never from the PSBT) | NW | Coldcard isolation bypass 2020 (benma) | `Refusal{NetworkMismatch, CoinTypeMismatch}` |
| 3 | `Prevouts` | 2 | `non_witness_utxo` present for every legacy and segwit-v0 input; its txid equals the outpoint's txid; its output amount equals the claimed amount. `witness_utxo` alone accepted for taproot only | NW over RB | BIP-143 fee attack (Trezor 2020) | `Refusal{MissingPreviousTransaction, PrevTxidMismatch, PrevAmountMismatch}` |
| 4 | `InputOwnership` | 1 | for every input claiming our fingerprint: derive the key at the claimed path and rebuild the script; it must equal the input's actual script. Path sanity: purpose whitelist (44/48/49/84/86), depth bound, hardened-prefix shape | NW over RB | Coldcard change-path ransom 2019; forged origins | `Refusal{OriginDoesNotDeriveScript, PathOutsidePurposeWhitelist, PathTooDeep, PathHardenedShapeInvalid}` |
| 5 | `MultisigBinding` | 4 | any input or output whose script is multisig must rebuild from a REGISTERED descriptor: membership, M, N, script type, derivation. PSBT-supplied cosigner xpubs are evidence to display, never a source of truth. In `SigningMode::Stateless` this gate refuses rather than downgrades | NW over MS | Coldcard xpub substitution 2021 (benma) | `Refusal{MultisigNotRegistered, MultisigRegistrationMismatch, MultisigNotAMember, MultisigStatelessUnverifiable}` |
| 6 | `Outputs` | 3 | classify every output by exact descriptor derivation within `GapBounds`: External / Change(verified) / OwnNotChange. No script heuristics, no "looks like change". Non-address scripts get their own row rather than being skipped | MS derive + NW loop | Coldcard multisig change confusion 2019; change substitution; silent OP_RETURN | `Refusal{ChangeNotDerivable, OutputScriptUnparseable}`; `Warning{ChangePastGapBound, SelfSendNotChange, NonAddressOutput}` |
| 7 | `Fee` | 6 | fee = sum(validated prevout values) - sum(output values); refuse negative or overflowing; compute sat/vB from the projected vsize; compare against `FeeLimits` | RB arithmetic, NW thresholds | fee burn, dust-the-user attacks | `Refusal{NegativeFee, FeeAboveHardCap, FeeArithmeticOverflow}`; `Warning{FeeAbove*Threshold}` |
| 8 | `Sighash` | 7 | every input we would sign uses SIGHASH_ALL (legacy/segwit-v0) or SIGHASH_DEFAULT (taproot); mixed types across our inputs refused | NW (rust-bitcoin would honor any type) | output swap after signing (SINGLE/NONE/ANYONECANPAY games) | `Refusal{SighashTypeNotWhitelisted, SighashTypeMixedAcrossInputs}` |
| 9 | `Taproot` | 8 | key-path inputs: the claimed internal key tweaks to the actual output key; script-path leaves must come from a registered descriptor; any annex refused | RB tweak, NW/MS whitelist | key leak via unknown-leaf signing; annex smuggling | `Refusal{TaprootTweakMismatch, TaprootLeafNotRegistered, TaprootAnnexPresent}` |
| 10 | `Plan` | 1, 9 | every input classified Ours or Foreign and present in the review model; at least one input is ours; the plan lists exactly the (input, path) pairs to be signed and nothing else | NW | signing-by-omission (an input nobody looked at), wrong-wallet dead ends | `Refusal{NothingToSign, WrongWallet + Evidence::SuggestWallet}` |
| 11 | `PostSign` | 10 | approval digest still matches; `evaluate` re-run yields the identical verdict; every produced signature verifies against a sighash recomputed independently of the signing path; miniscript's interpreter accepts every input we touched (and finalization runs only if our signatures complete all of them) | NW + MS + RB verify | any policy-engine bug; faulted-digest nonce reuse; a mutated PSBT between review and signature | `Refusal{ApprovalDoesNotMatchPsbt, SignatureVerificationFailed, InterpreterRejectedInput, PolicyChangedAfterSigning}` returned as `Error::Refused`; nothing leaves the device |

Notes that are part of the contract, not commentary:

- Gate 11's sighash recomputation must not share code with the signing path's digest
  computation. ARCHITECTURE.md 2.4 makes this explicit and it is the mitigation the
  deterministic-nonce decision rests on; a refactor that merges the two paths defeats the
  control and is a review-blocking change. The m6 mutation test (break a signature, watch
  the gate catch it) is the standing proof.
- The whole pipeline runs before any key derivation because `evaluate` takes a
  `WalletView`, which has no path to a seed. This is enforced by the type system, not by
  code review.
- Gate 5's stateless refusal is terminal. **There is no expert override, in 0.2.0 or
  later** (ratified Q24, which explicitly narrowed the wave-1 Q11 recommendation this line
  used to quote). One sub-item is settled at m6: whether the refusal covers all stateless
  multisig signing or only change claims. The gate-5 row scopes it to any multisig input
  OR output; three other places in this document and in UX-SCREENS scope it to change
  claims. The recommended answer is the broader one, because without a registration the
  input's witness-script membership is unverifiable too, which makes a stateless multisig
  signature unverifiable regardless of outputs.
- Unknown PSBT fields are preserved byte-for-byte through signing and re-emission and are
  never trusted for any decision. A PSBT carrying them earns
  `Warning{UnknownPsbtFieldsPresent}` so the review screen can say so.

How a refusal reaches the user (the "displayed rather than swallowed" requirement):

1. `evaluate` returns `Verdict::Refuse(Refusal)`. `Verdict` is `#[must_use]` and has no
   `unwrap`-shaped accessor, so ignoring it is a warning at the call site.
2. The firmware moves the `Refusal` into a `UiRequest` response; notyas-ui renders
   `headline()`, `explain()`, `next_step()` and the evidence rows verbatim. The UI writes no
   copy of its own - one pipeline, many renderers, the report.rs rationale extended to
   signing (ARCHITECTURE.md 5.3).
3. Every `RefusalCode` has a golden-text test asserting the exact rendered strings (m6 test
   gate: "every corpus case triggers its exact expected verdict and rendered text").
4. `RefusalCode` is a plain enum matched exhaustively in the UI, so adding a refusal without
   a screen does not compile.

---

## 4. Error taxonomy

Five kinds, and the distinction between them is the point: the user must be able to tell
"the device refused on purpose" from "that file is not a PSBT" from "the flash misbehaved"
from "we have a bug".

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Policy said no. Expected, safe, fully displayable, carries what to do next.
    /// The device is fine; the request was not acceptable.
    Refused(policy::Refusal),

    /// Untrusted input did not parse or violated a format rule before any policy ran.
    /// "This file is not a PSBT", "this descriptor's checksum is wrong". Never quotes more
    /// than a bounded, secret-free excerpt of the offending bytes.
    Malformed(Malformed),

    /// A lifecycle rule was violated: locked or expired session, wrong PIN, slots full,
    /// wallet not found, confirmation not typed. The caller can fix this by doing
    /// something different.
    Denied(Denied),

    /// The platform misbehaved: a Storage read/write/erase error, the HMAC peripheral
    /// failing, scratch memory the board could not provide. Serviceable, honest, and
    /// surfaced - never retried silently (no silent background failure).
    Fault(Fault),

    /// Our bug. A state the code believes impossible was reached anyway. Returned instead
    /// of panicking on every path untrusted input can reach; carries a stable code the
    /// Verify screen and a bug report can quote, and never carries data.
    Invariant(Invariant),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Malformed {
    NotAPsbt,
    PsbtTruncated { at: usize },
    PsbtVersionUnsupported { version: u32 },
    EncodingUndetectable,
    DescriptorSyntax { at: usize },
    DescriptorChecksum { expected: alloc::string::String, found: alloc::string::String },
    ColdcardTxtUnrecognized { line: u16 },
    LabelCharset,
    LabelLength { max: usize },
    AddressSyntax,
    RecordFormat { format: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    SessionExpired,
    WrongSession,                      // a session that does not match this vault mount
    WalletNotFound(wallet::WalletId),
    RegistrationNotFound(registry::RegistrationId),
    SlotsFull { capacity: u8 },
    RegistrationsFull { capacity: u8 },
    ConfirmationRequired,
    NotSupportedStateless,             // operation needs a vault; this session has none
    VaultBlank,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    StorageRead { area: store::Area, sector: u32 },
    StorageWrite { area: store::Area, sector: u32 },
    StorageErase { area: store::Area, sector: u32 },
    ReadbackMismatch { area: store::Area, sector: u32 },
    Binding,                            // the HMAC peripheral call failed
    ScratchUnavailable { needed: usize },
    KdfFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invariant { pub code: InvariantCode }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvariantCode {
    PlanPathNotInWallet,        // the signing plan named a path this wallet cannot derive
    ApprovalWithoutPlan,
    DescriptorCacheDesync,
    RecordLengthMismatch,
    SeqWentBackwards,
    GateOrderViolated,
}
```

Making illegal states unrepresentable, concretely - each of these removes a runtime check
that would otherwise have to be right everywhere:

| Illegal state | How the type system forbids it |
|---|---|
| Signing a PSBT nobody reviewed | `signer::sign` requires an `Approval`, which only `policy::evaluate` constructs |
| Signing a different PSBT than the one reviewed | `Approval` carries `PsbtDigest`; `sign` recomputes and compares |
| Reusing an approval for a second signature | `Approval` is not `Clone` and is taken by value |
| Deriving a key during policy evaluation | `evaluate` takes `WalletView`, which has no path to seed material |
| Deriving a key the approval did not plan | the `GetKey` adapter is built from the plan and returns `None` for anything else |
| Trusting a descriptor nobody verified | `OwnedDescriptor` has no public string constructor; multisig ones come only from `VerifiedRegistration` |
| Storing an unverified registration | `Vault::register` accepts only `VerifiedRegistration`, produced only by `Pending::verify` |
| Using the network the PSBT claims | `Summary.network` and every check read it from `WalletView`, which reads it from the record |
| Touching sealed data without a PIN | every secret-bearing `Vault` method requires `&Session` |
| Using a session after a PIN change | `change_pin` consumes the old `Session` and returns a new one |
| Deleting a wallet without confirmation | `Vault::delete` requires `TypedName`, constructible only by matching the live label |
| A slot index out of range | `SlotId::new` is the only constructor (the `ChildIndex` pattern from notyas-core) |
| A child index in the hardened half | `notyas_core::derive::ChildIndex`, reused rather than re-invented |
| A refusal with no screen | `RefusalCode` is matched exhaustively in notyas-ui |

---

## 5. Test strategy

### 5.1 Host unit tests, zero hardware (the bulk of it)

Everything in this crate is reachable from a host test through `testkit`:

```rust
#[cfg(feature = "testkit")]
pub mod testkit {
    /// RAM-backed flash with the real geometry, per-area write granularity, and
    /// programmable failure injection (fail at write N, truncate mid-write, flip a bit).
    pub struct MemStorage { /* ... */ }
    impl MemStorage {
        pub fn new(geometry: Geometry) -> MemStorage;
        pub fn fail_after(&mut self, writes: u32);
        pub fn truncate_next_write(&mut self, bytes: usize);
        pub fn image(&self) -> &[u8];              // for "no bytes were written" assertions
    }
    /// HMAC-SHA256 under a fixed test key - the eFuse peripheral's contract without the
    /// peripheral. Vectors are pinned so host and device results are comparable.
    pub struct StubBinding { /* ... */ }
    /// Vec-backed Argon2 scratch.
    pub struct VecScratch { /* ... */ }
}
```

Covered on host, no board involved:

- Key ladder KATs: fixed PIN + fixed device key + fixed params -> fixed `Bound`, fixed
  record ciphertext, fixed tag (m3 gate). `KdfParams::REDUCED` keeps the suite fast; one
  test runs `PINNED` and is `#[ignore]`d by default.
- Nonce-uniqueness properties: no two seals in a device's lifetime share (key, nonce);
  bumping `wipe_epoch` changes the key for the same slot and seq; re-sealing identical
  plaintext yields unrelated ciphertext (invariant 3's structural claim, ARCH 2.4).
- Two-slot commit and power-loss fuzz: truncate or corrupt the write stream at every byte
  offset and after every erase; property - mount yields the previous record or the new one,
  never garbage, never a panic. Includes the erase-after-commit window of a PIN change
  (ARCH 2.6, m3 gate).
- Counter semantics: decrement-before-attempt, clear-on-success, guard-bit corruption
  detection, wipe at N, epoch monotonicity, seq high-water reconciliation after a torn
  counter write.
- Statelessness: `Vault::mount` on a blank image followed by any read-only operation leaves
  `MemStorage::image()` byte-identical. This is the 0.1.0 identity as a unit test.
- Descriptor round trips: canonical text with checksum in, same text out; multipath
  expansion; `script_at` against BIP-380/BIP-389 and rust-miniscript vectors; Coldcard
  `.txt` -> descriptor conversion for every documented field ordering.
- Registration verification: our-key membership, duplicate xpub, duplicate fingerprint,
  wrong M/N, wrong script type, wrong network, xpub substituted for ours (the 2021 case).
- Policy engine: the corpus below, each case asserting the exact `Gate`, `RefusalCode`,
  evidence rows, warnings, page list, and rendered strings.
- Transport: encoding autodetect for binary/base64/hex including whitespace and trailing
  newline variants; output-name generation; UR2 frame round trip through the decoder side
  of foundation-ur.
- Zeroize discipline: for each secret-bearing type, a test that drops it and asserts the
  backing buffer is zero (the pattern desktop BigDice uses), plus a `Debug`-output test
  asserting no secret substring appears - the same style as notyas-ui's masking tests.

### 5.2 The PSBT corpus (named sources)

The corpus is a directory of files plus an expectation manifest; one test iterates it, so
adding an attack is adding a file. Sources, in the order they are worth having:

1. **BIP-174 test vectors** (bitcoin/bips, bip-0174.mediawiki) - the invalid-PSBT set is a
   free parser-hardening suite for gate 0/1; the valid set proves we do not refuse
   well-formed input.
2. **rust-bitcoin's own PSBT tests and serde fixtures** (rust-bitcoin/rust-bitcoin,
   `bitcoin/src/psbt/`) - the pinned version's own edge cases; if the crate we depend on
   thinks a case matters, so do we.
3. **BIP-143 and BIP-341 sighash vectors** - via notyas-core's m2 tests, re-run here through
   the full pipeline so gate 11's independent recomputation is vector-checked, not just
   self-consistent.
4. **BIP-340 official Schnorr vectors** - no-aux-rand determinism, which is what invariant 4
   claims for Schnorr.
5. **Coldcard firmware test data** (github.com/Coldcard/firmware, `testing/data/` and the
   multisig test files referenced from `testing/test_multisig.py`) - published under their
   repo's terms; the multisig registration files and adversarial PSBTs there map directly
   onto gates 4-6. Any file whose license does not permit redistribution is regenerated
   equivalently rather than copied, and the manifest records which.
6. **Coordinator-generated round trips**: Sparrow, Electrum, Specter and Bitcoin Core
   `walletcreatefundedpsbt` output on regtest/testnet for all four script types plus 2-of-3
   P2WSH. These prove interop, which no synthetic corpus does.
7. **Hand-built adversarial cases** (ours, one per historical attack, m6/m7 gates): output
   substitution, fee inflation via a lying `witness_utxo`, change-path ransom, wrong
   network, SIGHASH_SINGLE/NONE/ANYONECANPAY, duplicate inputs, pre-finalized inputs,
   missing prev-tx, oversized and truncated files, xpub substitution, multisig change
   confusion, taproot annex present, unknown-leaf script path, PSBT v2.

### 5.3 Differential testing

- **Bitcoin Core on regtest** (CI, m6 gate): `walletprocesspsbt` and `testmempoolaccept`
  must verify and accept our signatures; `decodepsbt` intermediates and our computed
  sighashes must match byte-for-byte. Byte-equality against Core's own signature bytes is
  claimed for ECDSA only and only if OPEN-QUESTIONS Q13 adopts low-R grinding, never for
  Schnorr (Core randomizes aux-rand) - SECURITY.md invariant 4.
- **A second independent signer** for the same PSBT corpus, to catch "we and rust-bitcoin
  agree because we are both wrong": HWI's or Trezor's Python signing path, or Coldcard's
  simulator, run over the multisig cases. The valuable comparison is not the signature bytes
  but the *verdict*: for each adversarial case, does the other signer also refuse? A case
  where we sign and they refuse is a finding either way.
- **Descriptor cross-check**: our `first_address` for a registered descriptor against
  Bitcoin Core `deriveaddresses` and Sparrow's display of the same descriptor. This is the
  automated version of the manual cross-device comparison the multisig UX asks the user for.

### 5.4 Hardware-only

These cannot be proven on host and must not be claimed until a board says so (m4a, m6-m8
gates):

- Argon2id timing with flash+PSRAM encryption enabled on rev v1.3 silicon - the number that
  pins `KdfParams::PINNED` (ARCH 2.3).
- The eFuse HMAC binding: that a read-protected key really is unreadable, that
  `esp_hmac_calculate` produces the value our stub models, and that moving the flash to
  another board makes the records unopenable (the honest downside stated in SECURITY.md).
- Real flash behavior: torn writes at true sector boundaries, the encrypted partition's
  16-byte granularity, bit-clear programming actually working in the plaintext counters
  area, and a power cut mid-decrement leaving the counter interpretable.
- The full SD round trip with Sparrow on testnet, all four script types plus 2-of-3 P2WSH,
  including a deliberately hostile PSBT refused with the right screen (m6/m7 gates).
- UR2 frames actually scanning: Sparrow webcam reading a signed multisig PSBT off both
  verified boards at default and lowest density (m8 gate).
- The boot self-test's reduced-cost seal/unseal vector and pinned PSBT-sign known-answer
  check rendering on the Verify screen.

---

## 6. Not in this crate

| Not here | Where it lives | Why |
|---|---|---|
| Any file, flash, SD or peripheral access | firmware (`Storage`, `DeviceBinding`, `KdfScratch` impls; ESP-SEAL.md) | keeps the crate no_std, host-testable and fuzzable |
| FATFS/VFS mount lifecycle, file listing, filename rendering | firmware (m5) | untrusted-media C surface stays behind one mount-on-demand module |
| Any RNG, anywhere, for anything | nowhere - it does not exist in the build graph | SECURITY.md invariant 3; enforced by the dependency-graph CI check |
| Entropy collection, dice parsing, BIP39 encoding, BIP32 derivation, seed computation | notyas-core | the small, BigDice-equivalent audit surface stays small; this crate calls it |
| The secp256k1 context, ECDSA/Schnorr signing, sighash computation, taproot tweak | rust-bitcoin via notyas-core | never hand-roll crypto |
| Descriptor parsing/derivation, PSBT finalization, the interpreter | miniscript | same |
| Argon2/ChaCha20-Poly1305/HKDF/HMAC/SHA256 implementations | RustCrypto | same; this crate owns only the construction that composes them |
| Drawing, layout, masking, touch handling, page traversal enforcement | notyas-ui | this crate produces the model, that crate renders and gates interaction (D3, D5) |
| QR rasterization | notyas-core `qr` (std) via the existing `UiRequest` seam | already solved in 0.1.0; UR2 supplies the payload strings, not the pixels |
| Wall-clock time, timers, tick generation | firmware main loop; arrives as `elapsed_ms` | a clock is I/O |
| eFuse burning, read-protection, secure boot, anti-rollback, partition table | firmware provisioning + ESP-SEAL.md + BOARDS.md | board and lifecycle concerns |
| Argon2 memory allocation policy (PSRAM vs SRAM) | firmware via `KdfScratch` | 64 MiB is a board decision |
| PIN pad randomization, PIN entry, anti-phishing word *display* | notyas-ui | the derivation of the words is here; the pad is interaction |
| Board specifics (SD width, kill GPIO, panel) | firmware + BOARDS.md | unchanged from 0.1.0 |
| BIP-85, Seed XOR, message signing, BIP-322, address explorer search | later milestones; BIP-85/XOR belong in notyas-core (pure seed math), message signing in this crate when scheduled | PARITY.md rows, not 0.2.0 scope |

---

## 7. Decisions and open items

Decisions taken here (the plan did not settle them; reasoning is at the cited section):

- **D1** miniscript feature spelling verified at m6 against pinned 13.1 metadata (0).
- **D2** singlesig and multisig share one `OwnedDescriptor` ownership mechanism; one
  classification path, not two (2.6).
- **D3** full-traversal enforcement in notyas-ui, page-set definition in `Approval::pages()`
  (2.8).
- **D4** derivable-but-unanchored self-sends are `OwnNotChange` + warning, not a refusal
  (2.8).
- **D5** the UI receives render models only; `Session`/`OpenWallet`/`Pin` never cross into
  notyas-ui (2.11).
- **D6** three narrow platform traits rather than one `Platform` supertrait, so the storage
  fuzzer and the seal KAT suite can stub independently (2.2).
- **D7** `Verdict` is not a `Result`: a refusal is an outcome, and `?` must not be able to
  discard the reason (2.8, 3).
- **D8** `evaluate` stops at the first refusal rather than collecting all of them (3).
- **D9** the post-sign sighash recomputation is code-path-independent from signing, by
  contract; merging them is review-blocking (3).
- **D10** device-wide registration capacity of 8 records, each bound to a wallet slot, per
  ARCHITECTURE.md 2.6's fixed slot budget (2.7).
- **D11** anti-phishing word derivation lives here (deterministic, host-testable) and only
  the display lives in notyas-ui (2.1).

Items that need the user. The reconciliation agent should pull these into
OPEN-QUESTIONS.md; they do not duplicate Q1-Q13, and each cites the existing question it
sits next to.

**OPEN: W1 - does a sealed wallet record store the BIP39 passphrase?**
The record as specified holds entropy and metadata (ARCHITECTURE.md 2.2); it is silent on
the passphrase. Coldcard never stores one internally (PARITY.md section 1). RECOMMENDATION:
do not store it - the passphrase is typed per session and is what makes a hidden wallet
hidden - but DO store `passphrase_check`, the fingerprint of the passphrase-applied root, so
the device can confirm "this is the wallet you saved" instead of silently opening a
different one (UX.md commandment 8). The check value leaks nothing an attacker who already
holds the entropy does not have. If the user wants a passphrase-free unlock experience
instead, the alternative is Coldcard's "Lock Down Seed" (destructively fold the passphrase
into the stored entropy), which is a separate feature, not a default.

**OPEN: W2 - change gap bounds and whether the device persists an index high-water.**
Gate 6 needs an anchor to decide whether an internal-keychain index is plausible. An
airgapped device has no chain view, so the candidates are: (a) anchor on the highest index
among this PSBT's own inputs for this descriptor, plus `forward`; (b) additionally persist a
per-wallet high-water in the record. RECOMMENDATION: (a) only, with
`GapBounds { forward: 200, ceiling: 100_000 }`. (b) means a flash write on every signature -
wear, latency, and a write the user did not ask for, against UX.md commandment 6 - to buy a
tighter bound on a case that D4 already handles with a warning rather than a refusal. The
two constants should be reviewed against real coordinator behavior at m6.

RESOLVED 2026-08-17 (OPEN-QUESTIONS Q24): **neither ships, and neither ever will** - the
recommendation below is ratified verbatim and is now the governing line for the whole
project: an expert toggle may adjust WARNING thresholds, and no override ever disables a
REFUSAL. Six places carried the opposite licence and have been corrected: ARCHITECTURE 5.3
check 7's "(expert-gated otherwise)", UX-SCREENS' S-31 "Hold to sign anyway" branch and
its stateless override badge, S-33's unknown-script override, S-40's "shown as UNVERIFIED
instead of refused" card, S-44's copy ("Expert options let you sign transactions this
device would otherwise refuse"), and CORPUS A5/A21. SECURITY invariant 7 is written
without exceptions and is what makes this non-negotiable.

OPEN (resolved): **W3 - is there an expert override for the sighash whitelist and for
stateless multisig?**
ARCHITECTURE.md 5.3 check 7 says "expert-gated otherwise" and Q11 suggests an override for
stateless multisig change. RECOMMENDATION: neither ships in 0.2.0. `SighashPolicy::AllOnly`
and `SigningMode::Stateless` refusing multisig claims are hard rules; the enum variants
exist so the future is expressible, but no Settings screen turns them on. A setting that
disables the check that stops output substitution is a setting an attacker will talk a user
into using, and the device has no way to detect that conversation.

**OPEN: W4 - the accepted PSBT size cap.**
`Limits::max_psbt_bytes` bounds RAM on a device whose PSRAM budget also holds a 720x720
framebuffer and the Argon2 arena. Requiring full previous transactions (gate 3) makes real
PSBTs large. RECOMMENDATION: 1 MiB accepted file, measured and re-pinned at m6 with the
worst realistic case (a many-input consolidation with full prev-txs); the refusal must say
"this transaction is too large for the device: N inputs" and suggest splitting, not just
"too large".

**OPEN: W5 - `-final.txn` content format.**
Coldcard's convention is what coordinators expect, and the plan cites it without pinning the
byte format. RECOMMENDATION: hex text of the raw transaction (Coldcard's own behavior), with
the exact bytes confirmed against a real Coldcard output file or their docs at m6 before the
writer ships. Getting this wrong is a silent interop failure, so it is a corpus item, not a
code comment.
