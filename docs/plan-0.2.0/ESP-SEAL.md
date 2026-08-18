# esp-seal - sealed secret storage for ESP32 (crate design)

Status: PLAN, written 2026-08-17. This document turns the storage architecture already
chosen and red-teamed in `plan-0.2.0/ARCHITECTURE.md` sections 2.1-2.7 into an
implementable crate design. It does not re-open the scheme: Argon2id over the PIN, an
HMAC peripheral keyed by a read-protected eFuse block, HKDF, ChaCha20-Poly1305, a raw
two-slot A/B partition, a plaintext counters partition with guarded bit-log counters,
`wipe_epoch` as a mandatory KDF input, deterministic nonces, NVS never mounted. All of
that is settled. What this document adds is the byte-level format, the operation-level
power-loss analysis, the public API, the provisioning story, and the test plan.

Normative parents: `plan-0.2.0/ARCHITECTURE.md` 2.x (scheme), `plan-0.2.0/SECURITY.md`
(guarantee tiers and the "attacker with the device" section), `plan-0.2.0/PLATFORM.md`
section 5 item 1 (the contribution framing) and section 6 (licensing), `docs/HARDWARE.md`
and `docs/BOARDS.md` (P4 facts, rev v1.3 bench units, 16 MB vs 32 MB flash split).

Where this document makes a call the parent plan did not settle, it is marked
**DECISION** with the reasoning. Genuine user decisions are marked **OPEN:** and are
greppable for the reconciliation pass.

---

## 1. Scope and the honest pitch

### 1.1 What esp-seal is

esp-seal answers one question for any ESP32 project: *how do I keep a secret in flash
that only comes back when the user types the right PIN on this specific board?*

The crate provides:

- **Seal and unseal an opaque byte payload under a PIN.** The payload is whatever the
  embedder wants: a BIP39 entropy blob (notyas), a device certificate private key, a
  Matter fabric credential, an API token, a config bundle.
- **Device binding that costs the attacker the physical board.** Every PIN guess must
  pass through the ESP32 HMAC peripheral keyed by a read-protected eFuse block.
  Software - including attacker-supplied firmware - cannot read that key, so an offline
  guess against a flash dump alone is impossible.
- **A memory-hard first wall.** Argon2id over the PIN before the HMAC step, so if the
  eFuse key is eventually extracted the attack degrades to memory-hard offline guessing
  rather than instant recovery.
- **A fault-hardened attempt counter with erase-at-zero.** Guarded bit-log counters,
  decrement before check, destroy the sealed records at N consecutive failures.
- **Power-loss-safe storage.** A raw two-slot A/B record format with a single-write
  commit point per operation, plus two ledger commit tokens for the two multi-record
  operations (wipe and PIN change). No NVS, no filesystem, no partial states.
- **A hardware-abstraction trait pair**, so the whole thing is host-testable with zero
  silicon and portable to any ESP32 variant with an eFuse-keyed MAC.

### 1.2 Why there is no Rust equivalent today

Verified in PLATFORM.md section 1 and re-stated here because it is the pitch:

- `esp-idf-sys`'s default bindgen header includes `esp_efuse.h` and `nvs.h` but **not**
  `esp_hmac.h`, `esp_ds.h`, or `esp_key_mgr.h`. There are no raw bindings out of the box.
- `esp-hal` has HMAC drivers for S2/S3/C3/C6/H2 and **none for P4**; it has no sealing
  layer on top of them for any chip.
- `esp-idf-hal` wraps gpio/i2c/spi and none of the security peripherals.
- IDF's own NVS encryption is key management only. It is not PIN-gated, it has no attempt
  counter, and it drags a large C key-value store into the trusted computing base.
- The two production designs worth learning from are C and copyleft: Blockstream Jade's
  `storage.c` (single-byte counter in NVS, blob erased at zero, PIN strengthened by a
  networked oracle we cannot copy on an airgapped device) and Trezor's NORCOW plus their
  storage PIN scheme.

Nothing in Rust today gives an ESP32 project "seal a secret under a PIN plus a
silicon-bound key with attempt limiting and power-loss safety". That is the gap.

### 1.3 What esp-seal explicitly does NOT promise

This section is the crate's README top matter, not a footnote. It is written before the
API on purpose.

**esp-seal is not a secure element.** It does not provide, and cannot provide on this
silicon:

- a key store hardened against fault injection,
- a monotonic counter the CPU cannot reach,
- a rate limit enforced outside the attacker-controllable processor.

Those are exactly the three properties a real secure element sells, and their absence is
the reason the guarantee is tiered rather than absolute.

**The guarantee tiers, plainly** (generalised from SECURITY.md's "An attacker with the
device"):

| Tier | Attacker | What esp-seal delivers | What it does not |
|---|---|---|---|
| 0 | Reads the flash, never holds the board | Nothing useful. On a release unit the flash is XTS-AES encrypted; inside it, an AEAD-sealed record whose key cannot be derived without the board's eFuse key. | - |
| 1 | Holds the board, dumps flash, has a programmer, no fault-injection lab | Every guess must run on this board through the HMAC peripheral. On-device guessing meets the attempt counter, which destroys the records at N consecutive failures. | The counter is rollback-able by full-flash snapshot and restore: see 7.2. The honest rate limit is "N guesses per full-flash restore cycle", not "N guesses ever". |
| 2 | Fault-injection lab, eventually extracts the eFuse key | The attack collapses to offline Argon2id-stretched guessing. The wall is now the user's PIN or passphrase entropy, nothing else. | Nothing. Assume the eFuse key is gone. The whole ESP32 family has a published history of eventually falling to fault injection; no P4 result is published, and we treat the P4 as not proven resistant. |
| 3 | Malicious firmware flashed onto the board before the user types the PIN | Nothing. esp-seal runs inside the firmware. | Secure Boot v2 plus verified-firmware UX is the embedder's job, not esp-seal's. |

Additional non-promises, stated once and loudly:

- **It does not protect RAM.** Once unsealed, the plaintext lives in the embedder's
  memory. esp-seal zeroizes everything it owns; it cannot zeroize what it handed you.
- **It is not a backup.** A dead SoC with an intact flash chip is not recoverable by
  moving the flash to another board. That is by design (device binding) and it means the
  embedder must have an independent recovery story.
- **It does not defend a weak PIN.** Post-extraction, a 6-digit PIN is a days-to-weeks
  problem for a funded attacker regardless of Argon2 parameters. The crate exposes a
  PIN-entropy helper and a documented recommendation; it cannot enforce user behaviour.
- **On chips without an HMAC peripheral** (original ESP32, C2), esp-seal falls back to a
  software MAC over a software-readable eFuse key. That is a strictly weaker tier and the
  API reports it as `KeyProvenance::EfuseReadable`. Products must surface it.
- **No timing-attack resistance against a physical attacker.** Power and EM side channels
  on Argon2id's data-dependent phase and on the HMAC peripheral are unmitigated (7.4).

---

## 2. Layered design

### 2.1 Crate split

Four crates, split along dependency-surface boundaries rather than along feature lines.
The split exists so that no crate drags a dependency into a graph that must not contain
it: the host test graph must not contain `esp-idf-sys`, and the firmware graph must not
contain the simulator.

| Crate | `no_std` | alloc | Contents | Dependencies |
|---|---|---|---|---|
| `esp-seal` | yes | **no** | The whole thing: traits, format, KDF chain, state machine, counters, A/B commit, error taxonomy. Zero I/O, zero time, zero RNG. | `argon2`, `chacha20poly1305`, `hkdf`, `hmac`, `sha2`, `zeroize`, `subtle` - all `default-features = false` |
| `esp-seal-idf` | no (std, ESP-IDF) | yes | `Flash` over `esp_partition_*`, `DeviceMac` over `esp_hmac_calculate`, eFuse state readout, optional `Provisioner`. | `esp-seal`, `esp-idf-svc`/`esp-idf-sys` with an `extra_components` `bindings_header` for `esp_hmac.h` |
| `esp-seal-sim` | no (host) | yes | NOR-accurate in-memory `Flash` with power-cut and partial-program injection; `SoftMac` with a fixed test key; the power-loss fuzzer driver. **Dev-dependency only.** | `esp-seal`, `hmac`, `sha2` |
| `esp-seal-hal` | yes | no | Planned, not in 0.2.0: `DeviceMac` over `esp-hal`'s HMAC driver for S2/S3/C3/C6/H2. | `esp-seal`, `esp-hal` |

`esp-seal` requiring **no alloc** is deliberate and is a selling point for the `esp-hal`
audience. It is achievable because `argon2` exposes `hash_password_into_with_memory` over
a caller-supplied block slice and `chacha20poly1305` exposes `encrypt_in_place_detached`.
The one large buffer the crate needs (Argon2 working memory) is passed in by the caller,
so the embedder decides whether it comes from PSRAM, internal SRAM, or a host `Vec`.

DECISION: the Argon2 working memory is a caller-supplied `Scratch<'_>` wrapping
`&mut [u64]`, not an internal allocation. Reasons: (a) it keeps the core alloc-free;
(b) on the P4 the buffer must land in PSRAM and only the embedder knows how to get it
there; (c) it makes the 64 MiB cost visible in the caller's code rather than hidden in a
library; (d) `&mut [u64]` guarantees the 8-byte alignment `argon2::Block` needs without
exposing the `argon2` types in our public API.

### 2.2 The two backend traits

The entire hardware surface is two traits. Everything else in `esp-seal` is generic over
them.

```rust
/// Byte-addressable NOR flash, split into the two regions esp-seal owns.
pub trait Flash {
    type Error: core::fmt::Debug;

    fn geometry(&self) -> Geometry;

    /// Logical read. On an ESP-IDF encrypted partition this is `esp_partition_read`,
    /// i.e. it returns DECRYPTED bytes.
    fn read(&mut self, region: Region, offset: u32, buf: &mut [u8]) -> Result<(), Self::Error>;

    /// Logical write. On an encrypted partition, `offset` and `data.len()` must both be
    /// multiples of `geometry().cipher_block` (16 on ESP-IDF XTS partitions), and any
    /// given cipher block may be written AT MOST ONCE between erases.
    fn write(&mut self, region: Region, offset: u32, data: &[u8]) -> Result<(), Self::Error>;

    fn erase_sector(&mut self, region: Region, sector: u32) -> Result<(), Self::Error>;

    /// True iff every raw flash byte in the range is 0xFF.
    ///
    /// MUST be implemented against the RAW (undecrypted) view. This is not a
    /// convenience method: on an encrypted partition, erased flash DECRYPTS TO
    /// PSEUDORANDOM BYTES, so `read()` can never be used to test for erasure.
    fn is_erased(&mut self, region: Region, offset: u32, len: u32) -> Result<bool, Self::Error>;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Region {
    /// Sealed records. `encrypted` on release units. Write-once-per-erase.
    Records,
    /// Guarded bit-log counters. Plaintext by necessity. Progressive bit clearing.
    Ledger,
}

#[derive(Clone, Copy, Debug)]
pub struct Geometry {
    pub sector_size: u32,        // 4096 on all ESP32 parts
    pub records_sectors: u32,    // 64 for a 256 KiB partition
    pub ledger_sectors: u32,     // 4 for a 16 KiB partition
    pub cipher_block: u32,       // 16 when Records is XTS-encrypted, else write_gran
    pub write_gran: u32,         // 4 for a plaintext partition on ESP-IDF
}

/// HMAC-SHA256 under a key that software cannot read.
pub trait DeviceMac {
    type Error: core::fmt::Debug;

    /// MUST be constant-time with respect to `msg`.
    /// MUST fail rather than silently substitute a key if the eFuse block is unset.
    fn hmac(&mut self, msg: &[u8], out: &mut [u8; 32]) -> Result<(), Self::Error>;

    /// Reported to the caller and mixed into every derivation. Never a constant.
    fn provenance(&self) -> KeyProvenance;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyProvenance {
    /// eFuse key block burned, purpose HMAC_UP, read-protected AND write-protected.
    EfuseReadProtected = 0,
    /// eFuse key present but software-readable (chips with no HMAC peripheral, or a
    /// block that was never read-protected). Weaker tier; the product must say so.
    EfuseReadable = 1,
    /// Compiled-in development key. NOT SECURE. See section 6.4.
    Emulated = 2,
}
```

That is the whole hardware surface. Two traits, six methods.

### 2.3 How the pure core is tested with zero hardware - exactly

The core is a pure function of `(flash bytes, MAC responses, caller inputs)`. There is no
clock, no RNG, no interrupt, no allocator, no `std`. Given that, host testing works like
this, concretely:

1. **`SimFlash` enforces real NOR semantics, not convenient ones.** Backing store is a
   `Vec<u8>` initialised to `0xFF`. `erase_sector` writes `0xFF` over one sector.
   `write` asserts `new & !old == 0` for every byte (programming can only clear bits) and
   panics the test on violation, asserts offset and length alignment against
   `cipher_block` for `Region::Records`, and maintains a per-cipher-block
   "programmed since last erase" bitmap so a second write to the same block is a test
   failure rather than the silent corruption real XTS hardware would produce. It also
   counts partial-page programs per 256-byte page so the ledger's bit-clear usage can be
   checked against a configurable device limit (see 8.3).
2. **`SimFlash` can be configured as encrypted.** In that mode `read()` returns
   `raw XOR keystream(offset)` for a fixed test keystream, so erased sectors decrypt to
   non-`0xFF` garbage exactly as they do on hardware, and any code path that tries to
   detect erasure via `read()` fails immediately in tests instead of on release silicon.
3. **`SoftMac` is HMAC-SHA256 under a fixed 32-byte test key** and reports a caller-chosen
   `KeyProvenance`. Every derivation in the crate therefore becomes a deterministic
   function of the test vectors, which is what makes known-answer testing possible at all.
4. **`KdfParams::TEST_ONLY`** (m = 32 KiB, t = 1, p = 1) makes the ~40k-case power-loss
   fuzz corpus run in seconds. Production parameters are exercised separately by a small
   number of `#[ignore]`-gated known-answer tests that CI runs in release mode.
5. **Every test drives the crate through the public API only.** No `pub(crate)` test
   hooks, no `#[cfg(test)]` back doors into the state machine. The consequence is that the
   test suite doubles as the usage documentation and that a refactor cannot quietly change
   observable behaviour.
6. **The power-cut model is a counter, not a thread.** `SimFlash` takes a
   `cut_after: Option<u32>` op budget; each `erase_sector` and each `cipher_block`-sized
   program decrements it, and at zero the op is applied *partially* (a configurable prefix
   of the bytes, with a deterministic bit-rot variant) and every subsequent op returns
   `SimError::PowerCut`. Enumerating `cut_after` over `0..ops(op_under_test)` gives
   exhaustive coverage of every step boundary with no concurrency and no flakiness.
7. **`cargo miri test`** runs on the core because there is no FFI in it. **`cargo fuzz`**
   runs `mount()` over arbitrary partition images (8.1).

Portability across ESP32 variants falls out of the same trait boundary: P4 via
`esp-seal-idf`, S3/C6/C3/H2 via the planned `esp-seal-hal`, and chips without an HMAC
peripheral via a `DeviceMac` implementation that MACs in software over a readable eFuse
key and reports `EfuseReadable`.

### 2.4 Boundary with notyas-wallet

esp-seal stores **opaque bytes**. It knows nothing about BIP39, descriptors, or wallets.
notyas-wallet keeps the wallet record schema, the registry semantics, the session type,
and every policy decision; it calls esp-seal for seal, unseal, and counter state.

RESOLVED 2026-08-17 (OPEN-QUESTIONS Q44): **there is no separate crate.** The owner
answered Q8 GPL-3.0-or-later for everything, and section 9.1's own stated consequence
therefore applies - a GPL3 sealing crate the permissive ESP32/Rust ecosystem will not
depend on is worse than an honest internal module. The sealing layer is a module inside
notyas-wallet; ARCHITECTURE.md section 1's crate table stands unchanged; WALLET-API.md's
`seal` and `store` modules keep the ground they claim; and **this document remains
authoritative for the DESIGN of that module** - the byte-exact format, the state machine,
the power-loss guarantees and the attack analysis are all still normative. Only the
address changed. The original item is kept below because its reasoning is why the
boundary inside notyas-wallet is still drawn where it is.

OPEN (resolved): **esp-seal vs notyas-wallet crate boundary.** ARCHITECTURE.md section 1 currently
assigns "seal/unseal (PIN KDF ladder + AEAD), two-slot storage record format" to
notyas-wallet. This document proposes those move into esp-seal and that notyas-wallet
depend on it, keeping only the payload schema.
RECOMMENDATION: adopt the split. It is the whole point of extracting the crate - a
sealing layer that cannot be used without a Bitcoin wallet crate is not a platform
contribution - and it shrinks notyas-wallet's audit surface. Cost: one more crate
boundary and a version-pin discipline between the two. If rejected, everything in this
document still applies verbatim as a module layout inside notyas-wallet.

---

## 3. On-flash format

### 3.1 Constraints that dictate the format

These are not preferences; they are what the silicon and IDF impose.

1. **Erase granularity is one 4 KiB sector.** Nothing smaller can be returned to `0xFF`.
2. **XTS-encrypted partitions require 16-byte-aligned offsets and 16-byte-multiple
   lengths** for `esp_partition_write`, and a given 16-byte cipher block **must not be
   written twice between erases** - the tweak is address-derived and a second program
   produces garbage, not an update.
3. **Therefore progressive bit clearing is impossible in the encrypted region.** This is
   the red-team finding that forces the counters into their own plaintext partition: the
   Trezor-style bit-log is built entirely on 1 -> 0 reprogramming.
4. **Erased flash in an encrypted partition does not read back as `0xFF`.**
   `esp_partition_read` decrypts, so an erased sector decrypts to pseudorandom bytes.
   Erasure can only be tested through the raw view - hence `Flash::is_erased`.
5. **The plaintext ledger partition is NOT covered by flash encryption.** An attacker with
   a programmer can read and rewrite it without breaking any key. Its content is therefore
   non-secret by construction, and its integrity rests on device-bound guard MACs plus the
   witness rule in 4.2. See 7.2 for the honest consequence.
6. **Partial-page programming has a device-specific limit.** SPI NOR parts specify a
   maximum number of programs per page between erases. The ledger design programs 8- and
   16-byte cells inside 256-byte pages, i.e. up to 32 programs per page. This must be
   checked against the actual flash parts on both bench boards before the format is
   frozen (8.3, measurement task M6).

Two format-wide invariants follow, and they are the reason the format looks the way it
does:

> **RECORDS INVARIANT.** Every byte of the `Records` region is programmed at most once
> between erases. No in-place updates, ever.
>
> **LEDGER INVARIANT.** The `Ledger` region is only ever advanced by programming a
> previously erased cell, or reset by erasing a whole sector. No cell is ever
> reprogrammed.

### 3.2 Records region map (256 KiB, 64 sectors of 4 KiB)

```
sector  0..1    superblock              A/B pair                       2 sectors
sector  2..9    canary slots 0..3       A/B pair, 1 sector per side    8 sectors
sector 10..25   payload slots 0..7      A/B pair, 1 sector per side   16 sectors
sector 26..57   registry slots 0..7     A/B pair, 2 sectors per side  32 sectors
sector 58..63   reserved (MBZ, erased)                                 6 sectors
```

Geometry is compile-time in `Config` and is recorded in the superblock; a mismatch
between the two is a hard mount failure, not a best-effort reinterpretation. That is what
lets a future firmware change the layout safely: it refuses rather than misreads.

Slot classes:

| Class | id | Sides | Bytes per side | Body capacity | Max payload |
|---|---|---|---|---|---|
| Superblock | 0 | 2 | 4096 | 4016 | n/a (plaintext body, not AEAD) |
| Canary | 1 | 2 | 4096 | 4016 | 3996 (uses ~64) |
| Payload | 2 | 2 | 4096 | 4016 | 3996 |
| Registry | 3 | 2 | 8192 | 8112 | 8092 |

Capacity arithmetic: `body_capacity = side_bytes - 80` (the header), and
`max_payload = body_capacity - 16 (AEAD tag) - 4 (in-AEAD length prefix)`.
`4016 = 16 x 251` and `8112 = 16 x 507`, so both satisfy constraint 2.

DECISION: **four canary slots, one per PIN identity, each a full A/B sector pair.** This
wastes 32 KiB on ~256 bytes of content. It is worth it: a uniform "every slot is an A/B
pair of the same shape" rule removes an entire class of special-case code from the
election and cleanup paths, erase granularity forces a whole sector per side anyway, and
the reserved identities let the Q2 duress decision be made later without a format change.
The format supports duress; whether the product exposes it is Q2's call, not this
document's.

DECISION: **`identities = 4` is fixed in the format, not configurable per product.** A
configurable K would make the on-flash layout depend on a build-time constant, which is
exactly the kind of thing that turns a firmware update into silent data loss. Unused
canary slots hold device-derived filler (3.6).

### 3.3 Record header (80 bytes, little-endian, written LAST)

Every slot side, in every class, starts with the same 80-byte header.

```
off  len  field           notes
0x00   4  magic           b"ESLR"
0x04   2  format_ver      u16, = 1
0x06   2  suite_id        u16, = 1 (argon2id + hmac-efuse + hkdf-sha256 + chacha20poly1305)
0x08   1  slot_class      0 superblock, 1 canary, 2 payload, 3 registry
0x09   1  slot_index      0..=7
0x0A   1  slot_side       0 = A, 1 = B
0x0B   1  flags           bit0 EMULATED_KEY, bit1 READABLE_KEY, bits2-7 MBZ
0x0C   4  argon2_m_kib    u32
0x10   4  argon2_t        u32
0x14   1  argon2_p        u8
0x15   3  MBZ
0x18   8  seal_seq        u64, device-global monotonic
0x20   8  wipe_epoch      u64, one-way
0x28   4  pin_gen         u32, global PIN-change generation (MBZ for superblock)
0x2C   4  body_capacity   u32
---- 0x30: end of the AEAD associated data (48 bytes) ----
0x30  16  body_digest     HMAC(hdr_key, b"ESLB" || class || index || side || body_region)[0..16]
0x40  16  header_mac      HMAC(hdr_key, b"ESLH" || header[0x00..0x40])[0..16]
0x50 ---  body_region begins, body_capacity bytes
```

**AEAD associated data = header bytes `0x00..0x30`, exactly 48 bytes.** What that binds,
and why each field is in there:

| Bound field | Attack it stops |
|---|---|
| `format_ver`, `suite_id` | Downgrade to a future weaker suite by rewriting the header. |
| `slot_class`, `slot_index` | Moving a registry record into a payload slot, or wallet 3's record into wallet 0's slot. |
| `slot_side` | Copying the A-side ciphertext into the B side to resurrect it with a forged sequence. |
| `flags` | Passing a development-key record off as a production one, or vice versa. |
| `argon2_m_kib`, `argon2_t`, `argon2_p` | Cost downgrade: rewriting the header to m=8 KiB so the attacker's offline grind is cheap. Detected at open, not silently honoured. |
| `seal_seq` | Replaying an older sealing of the same slot. |
| `wipe_epoch` | The mandated one: a post-wipe re-save under the same PIN and slot cannot repeat a `(key, nonce)` pair against a pre-wipe flash snapshot. |
| `pin_gen` | Mixing pre- and post-PIN-change records; it is also the batch commit discriminator (4.6). |
| `body_capacity` | Truncation: claiming a shorter body so the digest and tag cover less. |

`body_digest` is deliberately **outside** the AAD. It cannot be inside: it is a function
of the ciphertext, which is a function of the AAD, which would be circular. It is covered
by `header_mac` instead. Its job is torn-write and glitch detection, not confidentiality,
and any real modification of the body is caught by the AEAD tag anyway.

**The commit point of a single-record operation is the `header_mac` write.** A slot side
is committed if and only if its `header_mac` verifies. Because the header is written last
and any partial header write fails the MAC, a valid header proves the body was fully
written. That single sentence is the whole power-loss story for `seal`.

### 3.4 Body region

```
body_region = ciphertext || tag(16) || zero_pad_to(body_capacity)
plaintext   = u32_le(true_len) || payload || zero_pad_to(body_capacity - 16)
```

**Every record is padded to the full slot capacity and the true length lives inside the
AEAD.** Two reasons: the sector is erased and rewritten wholesale regardless, so padding
is free; and a plaintext length visible in the header would leak label lengths and
cosigner counts, and would make filler slots distinguishable from real ones. Padding
bytes are checked to be zero at open; a non-zero pad is `Corruption::Padding`.

`body_capacity` in the header is therefore always the slot class constant. It is retained
as an explicit field so a future format revision can shrink or grow a class without
ambiguity.

### 3.5 Superblock body (plaintext, no AEAD - there is no PIN at mount time)

```
off  len  field
0x00   4  magic b"ESLS"
0x04   2  layout_ver u16
0x06   2  MBZ
0x08  16  domain_tag           embedder-chosen, also mixed into every derivation
0x18   8  device_tag           HMAC_efuse(0x01 || domain_tag)[0..8]
0x20   1  n_canary_slots
0x21   1  n_payload_slots
0x22   1  n_registry_slots
0x23   1  payload_slot_sectors
0x24   1  registry_slot_sectors
0x25   1  identities
0x26   1  wipe_after           N, the attempt limit this store was formatted with
0x27   1  occupancy            0 = Sparse, 1 = AlwaysFilled
0x28   4  argon2_m_kib         store-wide parameters
0x2C   4  argon2_t
0x30   1  argon2_p
0x31   1  suite_id
0x32   2  MBZ
0x34   4  MBZ
0x38   8  formatted_at_epoch
0x40 ...  MBZ to body_capacity
```

`device_tag` is a stable 8-byte device fingerprint. It exists so that "this flash came
from a different board" is distinguishable from "this flash is corrupt", which matters a
great deal in the field. Honest cost: on a dev board with flash encryption off it is a
stable identifier readable from a flash dump. On a release unit it is inside the XTS
partition. Recorded, not hidden.

KDF parameters appear both here and in every record header. The superblock copy is the
store-wide truth used to compute the single Argon2id prestretch per unlock; the per-record
copies are AAD bindings. **All records in a store must carry identical parameters**; a
record whose header disagrees with the superblock is `Corruption::ParamMismatch`. Changing
parameters is a full re-seal batch using the same machinery as a PIN change (4.6).

### 3.6 Filler

An unoccupied slot under `Occupancy::AlwaysFilled` is not erased; it holds a genuine AEAD
record sealed under a **device-derived** key rather than a PIN-derived one:

```
filler_key, filler_nonce = HKDF-SHA256(ikm = filler_root, salt = kdf_salt,
                                       info = RecordInfo)[0..44]
plaintext                = u32_le(0) || zeroes
```

Consequences, all of them intentional:

- The device can identify filler without a PIN, with one HKDF and one AEAD open per slot -
  microseconds. So "empty" is never confused with "wrong PIN".
- An attacker without the eFuse key cannot distinguish filler from a real record. This is
  the mechanism Q2 option (a) needs, available at zero marginal format cost.
- Filler records carry the same header shape, the same `pin_gen` as identity 0, and
  consume `seal_seq` values like any other record, so sequence-number gaps do not betray
  occupancy either.

Under `Occupancy::Sparse` an unoccupied slot is simply erased on both sides. **The format
is identical either way**; only the content of an unoccupied slot differs. That is why
Q2 can be decided after the format is frozen.

### 3.7 Ledger region (16 KiB, 4 sectors of 4 KiB, plaintext)

Two sectors are the A/B rotation pair for the live ledger; two are reserved for a future
second log class. Exactly one sector is live at any time; the other three are erased.

**Ledger sector layout (4096 bytes):**

```
off     len   contents
0x0000   128  head
0x0080   256  epoch_log         32 cells x 8 B   (wipe_epoch)
0x0180   512  seq_log           64 cells x 8 B   (seal_seq high-water, 256 seals per cell)
0x0380  1024  attempt_entry     128 cells x 8 B
0x0780  1024  attempt_success   128 cells x 8 B
0x0B80  1024  pin_gen_log       64 cells x 16 B
0x0F80   128  reserved (MBZ, erased)
```

**Head (128 bytes):**

```
off  len  field
0x00   4  magic b"ESLC"
0x04   2  format_ver u16
0x06   1  side (0 = A, 1 = B)
0x07   1  MBZ
0x08   4  rotation_ctr u32          strictly increases on every rotation
0x0C   4  MBZ
0x10   8  epoch_base u64            carried forward at rotation
0x18   8  seq_base u64              in units of SEQ_RESERVE = 256
0x20  32  pin_gen_current[4] u64    per-identity generation at rotation time
0x40  48  MBZ
0x70  16  head_mac = HMAC(guard_key, head[0x00..0x70])[0..16]
```

**Guarded bit-log cell encoding.** An 8-byte cell is either erased (`FF FF FF FF FF FF FF
FF`, tick not taken) or committed, in which case it holds

```
cell[i] = HMAC(guard_key, b"ESLG" || side || rotation_ctr || log_id || u16_le(i))[0..8]
```

Because erased flash is all ones, any 8-byte pattern can be programmed onto it; the guard
value has roughly half its bits clear, so a glitch that interrupts the program leaves a
value that matches neither the erased pattern nor the expected guard. That is the whole
point of the guard: **a single fault must corrupt data and guard pattern consistently, and
it cannot, because the guard is keyed by a device-bound key the attacker does not have.**

The 16-byte `pin_gen_log` cell carries data as well as a guard:

```
cell[i] = u8 identity | u8[3] MBZ | u32_le new_gen | HMAC(guard_key,
              b"ESLP" || side || rotation_ctr || u16_le(i) || identity || new_gen)[0..8]
```

**Log scanning and the fail-closed rule.** A log's length is read by scanning cells from
index 0. Three outcomes per cell: erased, valid guard, or malformed. The resolution rule
is asymmetric and always resolves in the direction that *increases* the apparent failure
count:

| Log | Malformed cell | Non-erased cell after the first erased cell |
|---|---|---|
| `attempt_entry` | counts as consumed | length = highest non-erased index + 1 (counts them all) |
| `attempt_success` | truncates the log there (counts as NOT consumed) | truncate at the first erased cell (ignore the rest) |
| `epoch_log`, `seq_log` | counts as consumed | length = highest non-erased index + 1 |
| `pin_gen_log` | ignore the cell, flag tamper | flag tamper, ignore |

Any malformed cell or hole sets a `TamperKind` flag that mount reports to the embedder.
It is a signal, not an automatic wipe: a genuine mid-program power cut produces exactly
this, and destroying a user's wallet because the battery died is a worse failure than
counting one extra attempt.

Derived quantities:

```
wipe_epoch      = head.epoch_base + len(epoch_log)
seq_high_water  = (head.seq_base + len(seq_log)) * SEQ_RESERVE
failures        = len(attempt_entry) - len(attempt_success)
pin_gen[i]      = last pin_gen_log cell with identity == i, else head.pin_gen_current[i]
pin_gen_next    = 1 + max over all identities and all log cells of new_gen
```

Capacity per rotation generation: 32 wipes, 16384 seals, 128 unlock attempts, 64 PIN
changes. Rotation (4.8) carries all bases forward, so capacity is bounded only by flash
endurance: at roughly one rotation per 103 unlocks and 100k erase cycles per sector, that
is on the order of ten million unlocks.

**`SEQ_RESERVE = 256` and reserve-ahead.** Advancing the high-water mark on every seal
would burn the log. Instead the invariant is *every sequence number ever used is strictly
below `seq_high_water`*: before sealing with sequence `S`, if `S >= seq_high_water` the
log is advanced until it is not, and only then is the record written. A crash between the
advance and the write loses up to 256 sequence numbers, which costs nothing - sequence
numbers need to be unique and monotonic, not dense.

---

## 4. State machine and operations

### 4.1 The key ladder, byte-exact

```
hmac_efuse(tag, msg)  = HMAC-SHA256_{eFuse key}( tag || msg )      // tag is one byte

device_binding = hmac_efuse(0x01, domain_tag)                                    32 B
guard_key      = HKDF-SHA256(ikm=device_binding, salt=domain_tag, info=b"esp-seal/guard/v1")
hdr_key        = HKDF-SHA256(ikm=device_binding, salt=domain_tag, info=b"esp-seal/hdr/v1")
filler_root    = HKDF-SHA256(ikm=device_binding, salt=domain_tag, info=b"esp-seal/filler/v1")
user_root      = HKDF-SHA256(ikm=device_binding, salt=domain_tag, info=b"esp-seal/user/v1")

kdf_salt       = SHA256(domain_tag || b"esp-seal/salt/v1" || device_binding)     32 B

prestretch     = Argon2id(pwd = pin_normalized, salt = kdf_salt,
                          m = m_kib, t = t, p = 1, out = 32)                     32 B
bound          = hmac_efuse(0x02, prestretch)                                    32 B
                 // ^ the per-unlock session secret; the ONLY thing a Session holds

okm            = HKDF-SHA256(ikm = bound, salt = kdf_salt, info = RecordInfo)    44 B
key            = okm[0..32]
nonce          = okm[32..44]
ct, tag        = ChaCha20-Poly1305.seal(key, nonce, aad = header[0x00..0x30], pt)
```

`RecordInfo` is a fixed 40-byte little-endian encoding, never a concatenation of
variable-length pieces:

```
b"ESL1"(4) | suite_id u16 | format_ver u16 | slot_class u8 | slot_index u8
           | slot_side u8 | provenance u8 | wipe_epoch u64 | pin_gen u32
           | seal_seq u64 | domain_tag[0..8]
```

**DECISION: the Argon2id salt does NOT include the slot index.** ARCHITECTURE 2.4 writes
`kdf_salt = SHA256("notyas-salt-v1" || device_binding || slot_id)`. Read literally, that
makes the memory-hard prestretch per-slot, so unlocking a device with eight wallets would
cost eight Argon2id evaluations - eight seconds at the target parameters. Slot separation
belongs entirely in the HKDF `info`, which already carries `slot_class` and `slot_index`.
The salt's stated job (defeating cross-device precomputation) is fully delivered by
`device_binding`. One memory-hard evaluation per unlock; per-slot keys still unrelated.
This refines ARCHITECTURE 2.4's formula and changes nothing about its security argument.

**DECISION: every call into the eFuse-keyed HMAC is domain-separated by a fixed leading
tag byte, and user-influenced inputs are length-prefixed.** The same eFuse key serves
internal derivations *and* embedder-facing ones - notyas's anti-phishing words are
`HMAC_efuse(partial PIN)`, i.e. attacker-chosen input to the key that also produces
`bound`. Without separation, a chosen-prefix query could be steered to collide with
`0x02 || prestretch`. Rule: internal tags `0x01..0x0F` are followed by fixed-length
payloads only; every embedder-facing derivation goes through `device_derive`, which
computes `hmac_efuse(0x7F, u16_le(label.len()) || label || u16_le(data.len()) || data)`.
Fixed-length internal messages cannot collide with length-prefixed external ones.

**Nonce uniqueness argument, stated as the invariant the fuzzer checks.** `nonce` is a
pure function of `RecordInfo`, which contains `seal_seq`. `seal_seq` is device-global,
strictly increasing, and bounded below by a one-way flash high-water mark that is advanced
*before* use. `wipe_epoch` is one-way and covers the case where sequence state is
destroyed. Therefore no `(key, nonce)` pair is ever reused across the life of the device,
including across wipes, PIN changes, and arbitrary power loss. Test 8.1 asserts this
globally rather than trusting the argument.

### 4.2 MOUNT (no PIN required)

```
M1  Read ledger sector A and B heads. Validate magic, format_ver, and head_mac.
M2  Live ledger = the valid head with the greatest rotation_ctr.
      - none valid + Records region blank         -> StoreState::Blank
      - none valid + Records region NOT blank     -> TamperSuspected(LedgerMissing)   [fail closed]
      - both valid with equal rotation_ctr        -> TamperSuspected(LedgerAmbiguous)
M3  If the non-live ledger sector is not erased, erase it. (Completes an interrupted
      rotation. Idempotent.)
M4  Scan the five logs of the live sector -> wipe_epoch, seq_high_water, failures,
      pin_gen[0..4], pin_gen_next, plus any TamperKind flags.
M5  Read both superblock sides; elect by (valid header_mac, greatest seal_seq).
      Validate layout against the compile-time Config: geometry, identities, suite,
      domain_tag, and device_tag. Mismatch -> MountError::Foreign / GeometryMismatch.
M6  For every slot, read both sides' headers. A side is a CANDIDATE iff:
      header_mac valid AND wipe_epoch == current AND
      (slot_class == Superblock OR pin_gen is one of the current pin_gen[0..4]).
      Elect the candidate with the greatest seal_seq.
M7  next_seq = max(seq_high_water, greatest elected seal_seq + 1).
      WITNESS CHECK: if any elected record's seal_seq >= seq_high_water, or any elected
      record's wipe_epoch > ledger wipe_epoch, the ledger has been rolled back
      independently of the records -> TamperSuspected(LedgerRollback).
M8  If failures >= wipe_after, run WIPE (4.7) now, before any unlock is possible.
M9  CLEANUP: erase every slot side that is non-erased and is not the elected candidate.
      Bounded by 2 x slot count erases. Idempotent and restartable.
M10 Return StoreState.
```

Step M7's witness check is the one defence available against a *partial* rollback: the
records region cannot be edited without the flash-encryption key on a release unit, but
the plaintext ledger can be rewritten freely, so an attacker restoring only an old ledger
to reset the attempt counter is caught by the records that outrank it. A full-flash
restore defeats it; see 7.2 and do not overclaim.

**Power loss during mount:** M3 and M9 are the only writes and both are idempotent erases
of data that has already been superseded. A cut anywhere re-runs harmlessly on the next
boot. Mount performs no other writes and never advances a counter.

### 4.3 PROVISION (factory, one time, irreversible)

Provisioning is split from formatting because only the first half is irreversible.

```
P1  Host generates a 32-byte key from the host OS CSPRNG.
P2  espefuse.py burn_key BLOCK_KEYn <keyfile> HMAC_UP
P3  espefuse.py write_protect_efuse KEY_PURPOSE_n ; read_protect_efuse BLOCK_KEYn
P4  Host shreds the key file. There is no escrow, by design.
P5  Firmware boots, computes device_binding, and writes it into the superblock as
      device_tag during FORMAT.
```

**Irreversible after P2:** the key block is consumed permanently. **Irreversible after
P3:** the key value can never be read or changed by anything, including a JTAG-attached
debugger. Everything before P2 is a no-op on the board.

**DECISION: the device does not generate its own eFuse key, and release firmware contains
no eFuse-burn code at all.** Two reasons, both load-bearing. First, invariant 3: notyas
has no RNG anywhere, and a device-unique key must be unpredictable, so it must come from
outside. The host CSPRNG is a trust dependency we can name and audit; the P4 TRNG is one
we have already declared distrusted. Second, a firmware that cannot burn eFuses cannot
brick a board through a bug and offers no eFuse-burn code path for a glitch to steer.
This refines ARCHITECTURE 2.2's "burned at first save".

`esp-seal-idf` still ships a `Provisioner` behind a non-default `provisioning` feature,
because a general-purpose crate must serve products that provision in the field. notyas
release builds do not enable it, and the build-graph check asserts that.

RESOLVED 2026-08-17 (OPEN-QUESTIONS Q45): **factory provisioning, as recommended.** No
eFuse-burn code ships in release firmware; the `Provisioner` stays behind a non-default
`provisioning` feature and the build-graph check asserts it is off. Five requirements were
added when the decision was ratified, because this section did not name them: a real
`StoreState::Unprovisioned` and an absent tier on `KeyProvenance` (the state diagram
already draws the state but neither enum can express it, so the refusal would otherwise
degrade into a generic hardware fault); specified behaviour for the PIN-pad permutation
and the backup-quiz distractors, both of which are HMAC_efuse-derived and so cannot run
unprovisioned; a refusal on the RESTORE path, not only on first save
(BACKUP-FEATURES.md 2.6 currently burns there); the burn ORDER written into the runbook -
HMAC key before flash encryption and secure boot, because Release-mode flash encryption
disables the UART download path `espefuse.py` uses - to be worded jointly with the
secure-boot key-ownership question (Q32); and a rename, because `Vault::provision()`
currently means "format" while PROVISION now means the irreversible host ceremony. The
original item is kept below.

OPEN (resolved): **in-app provisioning for notyas.** ARCHITECTURE 2.2 says the HMAC key is "burned at
first save"; this document proposes a factory step with `espefuse.py` instead, and no burn
code in release firmware.
RECOMMENDATION: factory provisioning. It preserves invariant 3 without argument, removes a
brick class, and matches how the release runbook already treats secure boot and flash
encryption. Cost: a device cannot be provisioned by a user who builds their own firmware
from source without running one extra documented command - which is acceptable for a
device whose whole story is "verify your firmware".

**Power loss during provisioning:** P2 and P3 are single eFuse burn operations performed
by the host tool, which verifies each one before proceeding. A cut between P2 and P3
leaves a burned but software-readable key: the next boot reports
`KeyProvenance::EfuseReadable`, the product refuses to format, and the operator re-runs
P3. A cut during P2 itself leaves a partially burned block, which espefuse detects on
re-read; the block is then unusable and the operator moves to the next one. Six blocks
exist; the budget is in 6.1.

### 4.4 FORMAT (first PIN, reversible)

```
F1  Require StoreState::Blank or Wiped, and provenance is acceptable to the product.
F2  Erase all ledger sectors. Write ledger head into side A with rotation_ctr = 1,
      all bases 0.                                        <- LEDGER EXISTS
F3  Compute prestretch, bound.
F4  Erase superblock side A; write body; write header.    <- COMMIT (superblock exists)
F5  For identity 0: seal the canary record into canary slot 0 side A.  <- COMMIT
F6  For identities 1..3 and for every unoccupied slot under AlwaysFilled: write filler.
F7  Verify: re-mount from flash and confirm the canary opens with `bound`.
```

Canary plaintext (fixed 64 bytes, all inside the AEAD):

```
b"ESLK"(4) | identity u8 | MBZ u8 | visible_slot_mask u16 | created_epoch u64
           | label[16] (embedder-supplied, zero-padded) | MBZ[32]
```

`visible_slot_mask` is a UI aid for the duress case, not a security control: cryptography
decides what a given identity can open, the mask only decides what the product should
bother displaying.

**Power loss:** before F2, nothing happened and the store is `Blank`. Between F2 and F4 a
valid ledger exists with a blank records region, which M2 classifies as `Blank` with a live
ledger - not `LedgerMissing`, which requires records to be present - and format resumes at
F4. Between F4 and F5 a superblock exists with no canary: `Formatted { identities_present:
0 }`, and format resumes at F5. After F5 the store is usable; F6 is cosmetic and is re-run
at the next mount. No state in this sequence is unrecoverable, and none of it can lose a
user secret because there is no user secret yet.

### 4.5 UNLOCK / VERIFY-PIN, and the counter

This is the operation the attempt counter exists for, so the boundaries are drawn
explicitly.

```
U1  Pre-checks, NO attempt consumed:
      store formatted? failures < wipe_after? at least one canary header valid
      (header_mac, epoch, pin_gen, body_digest)? scratch large enough?
      Any failure here returns before the counted region.
U2  prestretch = Argon2id(pin, kdf_salt, params, scratch)        [expensive, uncounted]
U3  bound      = hmac_efuse(0x02, prestretch)
U4  === COUNTED REGION BEGINS ===
      Program attempt_entry[len]. Read it back; a mismatch is HardwareFault and the
      attempt still counts.
U5  For each identity 0..3: derive okm from `bound` and that canary's header, AEAD-open.
      First success gives the identity. (4 HKDF + 4 AEAD opens: microseconds.)
U6  If none opened -> WrongPin. If failures now >= wipe_after -> run WIPE, return Wiped.
U7  Program attempt_success[j] for every j in len(success)..len(entry)-1  (catch-up).
    === COUNTED REGION ENDS ===
U8  Zeroize prestretch and the scratch buffer. Return a Session owning `bound`.
```

**Why Argon2id is outside the counted region.** The counter must be decremented before the
*verification*, not before the *computation*. An attacker who cuts power between U2 and U4
has spent the full Argon2 time and learned nothing; they cannot obtain an uncounted
verification, because the verification is strictly after U4.

**Why the catch-up loop in U7 exists.** Without it, an interrupted unlock leaves
`entry = success + 1` permanently: the next success would program one success cell and the
gap would never close, so the device would slowly accumulate phantom failures until it
wiped itself. Programming every outstanding success cell is what Trezor's paired-log design
does and it is required, not an optimisation. A cut inside the catch-up loop leaves a
smaller failure count than before but never a negative one, and the next success finishes
the job. The loop only runs after a genuine success, so it is not an attacker-reachable
counter reset.

**Power loss, step by step:**

| Cut at | Result |
|---|---|
| before U4 | No flash write occurred. Free retry. Attacker gains nothing; they still paid the Argon2 cost. |
| during U4's cell program | The cell is malformed. The fail-closed scan rule counts it as consumed. One attempt lost to a power cut, which is correct: a guess was in flight. |
| between U4 and U7 | The attempt is consumed. Deliberate and fail-closed: a cut in the middle of a verification must cost a guess, or power-cutting becomes a free oracle. |
| during U7's catch-up | Some success cells are programmed. `failures` is between 0 and its pre-unlock value. The next successful unlock completes the catch-up. Never negative, never an attacker win. |
| after U7 | Unlock is complete and durable. |

**`verify_pin` on a locked store is the same sequence and does consume an attempt** -
anything else would be a free oracle. **`Session::confirm_pin` consumes nothing**: it
recomputes the ladder and compares the result against the session's `bound` in constant
time, touching no flash. The session already proves the PIN was known, so re-proving it
inside the session is not a new guess. Products should use `confirm_pin` for
"type your PIN to confirm this destructive action" and never `verify_pin`.

### 4.6 SEAL (write one record) and CHANGE-PIN (batch)

**SEAL, single record:**

```
S1  seq = next_seq. If seq >= seq_high_water, program seq_log cells until it is not.
      RESERVE-AHEAD: the high-water mark is advanced BEFORE the sequence is used.
S2  next_seq = seq + 1 (RAM only).
S3  Derive okm TWICE by independent invocations; compare in constant time. A mismatch
      is HardwareFault and nothing is written. (Fault-injection countermeasure, 7.3.)
S4  Build the padded plaintext; seal in place with aad = header[0x00..0x30].
S5  Ensure the target (inactive) side is erased: is_erased() and, if not, erase it.
S6  Write body_region at slot_offset + 0x50.
S7  Write the 80-byte header (fields, body_digest, header_mac).      <-- COMMIT POINT
S8  VERIFY: re-read the whole side FROM FLASH; recheck header_mac and body_digest;
      re-derive okm a third time from the flash-resident header; AEAD-open; compare the
      recovered plaintext to the source in constant time. Any failure: erase this side
      and return HardwareFault(WriteVerify) with nothing committed.
S9  Erase the now-stale other side.
```

| Cut at | Result | Why nothing is lost |
|---|---|---|
| S1 | High-water mark may have advanced with no record written. | Sequence numbers are allowed to skip. Monotonicity is preserved; reuse is impossible. |
| S2-S4 | Nothing written. | Pure computation. |
| S5 | Target side blank or partially erased. | It was not the elected side. Mount's cleanup re-erases it. |
| S6 | Body partially written, no header. | Without a valid `header_mac` the side is not a candidate. Mount erases it. The old record is still elected. |
| S7 | Either the header MAC verifies or it does not. | This is the commit point. Verifies: the new record wins on `seal_seq`. Does not: the old record wins. There is no third outcome and no window where both or neither are valid. |
| S8 | Same as S7 - verification is read-only until it decides to erase. | |
| S9 | Two committed sides with different sequence numbers. | Election by `seal_seq` picks the new one deterministically; mount's cleanup erases the stale one on the next boot. |

Note the honest residual in the S9 window: between the commit and the stale-side erase,
the previous ciphertext for that slot still exists on flash. For an ordinary re-save that
is the same PIN's ciphertext and is uninteresting. For a PIN change it is old-PIN
ciphertext, which is exactly what ARCHITECTURE 2.6's stale-ciphertext rule is about, so the
batch below erases eagerly and mount's cleanup is only the crash-recovery path.

**CHANGE-PIN, batch of records, atomic:**

The problem the design has to solve is that a PIN change re-seals every record under a new
key, and a power cut mid-batch must not leave a device where some records open with the
old PIN and some with the new one. The commit token is one 16-byte ledger cell.

```
C1  Compute bound_new (Argon2id + HMAC) for the new PIN. Nothing written.
C2  G = pin_gen_next (from the ledger; globally unique across identities).
C3  For each occupied slot belonging to this identity, one at a time:
      decrypt with bound_old, re-seal with bound_new and pin_gen = G into the
      INACTIVE side, following S1-S8 in full including the read-back verification.
      Plaintext for exactly one record is in RAM at a time.
C4  Re-seal this identity's canary the same way, into its inactive side, pin_gen = G.
C5  Program one pin_gen_log cell {identity, new_gen = G}.        <-- COMMIT POINT
C6  Erase every side whose pin_gen is no longer current for any identity.
```

`pin_gen` values come from a single device-global monotonic sequence, so a value is never
in the current set until its own commit cell is programmed. Mount's rule from M6 - a side
is a candidate iff its `pin_gen` is one of the current per-identity generations - is then
sufficient, and the per-slot election by `seal_seq` breaks the remaining tie in favour of
the newer record because sequence numbers strictly increase. Identity indices are
deliberately **not** stored in record headers, so the number of records per identity does
not leak.

| Cut at | Result |
|---|---|
| C1-C2 | Nothing written. Old PIN works. |
| anywhere in C3 or C4 | Some sides carry `pin_gen = G`, which is not yet in the current set, so mount rejects them as candidates and erases them in cleanup. **The old PIN still works and no record is lost.** |
| during C5's cell program | The cell is malformed. The `pin_gen_log` rule ignores malformed cells and flags tamper, so `G` does not enter the set: the old PIN works, the new records are cleaned up, and the user re-runs the change. Fail-closed toward "nothing happened". |
| after C5, before C6 | The new PIN works. Old-PIN ciphertext still exists on flash for the un-erased sides until C6 or the next mount's cleanup, whichever comes first. Bounded, documented, and cleaned unconditionally before any unlock is possible. |
| during C6 | Some stale sides remain; mount cleanup finishes. |

The same machinery serves a **KDF parameter migration**: re-seal every record with new
`argon2_*` header values under a new `pin_gen`, commit, update the superblock, erase the
stale sides.

### 4.7 WIPE

```
W1  Program the next epoch_log cell.                              <-- COMMIT POINT
W2  Erase every record slot side (canary, payload, registry) and both superblock sides.
W3  Re-write the superblock (geometry, domain_tag, device_tag, formatted_at_epoch)
      so the store is provisioned-but-PIN-less rather than blank.
W4  Under AlwaysFilled, write filler into every slot.
```

**The commit point of a wipe is a single 8-byte cell program, and everything after it is
lazy cleanup.** That is the strongest property in the design and it comes from one mount
rule: a record whose `wipe_epoch` does not equal the current epoch is not a candidate.
Bumping the epoch therefore destroys every record logically and instantaneously; physical
erasure is housekeeping.

| Cut at | Result |
|---|---|
| before W1 | No wipe happened. Records intact. `failures` is still at or above the limit, so the next mount re-triggers the wipe at M8. Deterministic, not a bypass. |
| during W1's cell program | Malformed cell; the fail-closed rule for `epoch_log` counts it as consumed, so the epoch has advanced and the wipe is committed. Erring toward "the wipe happened" is the correct direction for a security control. |
| after W1, any point in W2-W4 | The wipe is complete as far as any observer is concerned: every surviving record carries a stale epoch, cannot be elected, and cannot be opened. Mount erases them. Crucially, a subsequent re-save under the same PIN and slot derives a different key because `wipe_epoch` is in `RecordInfo`, so no `(key, nonce)` pair can repeat against a pre-wipe flash snapshot. |

Bump-before-erase is mandatory and the reverse order is a real vulnerability: erasing
first and losing power before the bump would allow a re-save to collide with a pre-wipe
snapshot's keystream. That is precisely the red-team amendment `wipe_epoch` exists for.

### 4.8 LEDGER ROTATION

Triggered on the first **successful** unlock at which `len(attempt_entry) >= 128 - 25`,
where 25 is the maximum permitted `wipe_after`. The tail reserve guarantees that an
in-flight failure streak can never overflow the log, because a streak long enough to reach
the end would have triggered a wipe first.

```
R1  Target = the non-live ledger sector. Erase it (idempotent).
R2  Write the target head: rotation_ctr + 1, epoch_base = current wipe_epoch,
      seq_base = current high-water / SEQ_RESERVE, pin_gen_current = current values.
                                                                  <-- COMMIT POINT
R3  Erase the source sector.
```

| Cut at | Result |
|---|---|
| R1 | Target partially erased, no valid head. The live sector is unchanged. Retried later. |
| R2 | The head MAC either verifies or it does not. Verifies: the target is live (greater `rotation_ctr`). Does not: the source stays live. |
| R3 | Two valid heads. M2 picks the greater `rotation_ctr` and M3 erases the loser. Both represent `failures = 0` because rotation only happens right after a success, so either choice is safe and the choice is deterministic. |

Rotation requires a correct PIN, so it is not an attacker-reachable counter reset.

### 4.9 State machine summary

```
                 provision (host, irreversible)
   Unprovisioned ------------------------------> Blank
                                                   |
                                                   | format(pin)
                                                   v
   Wiped <---- wipe / N failures ------------  Locked  <----+
     |                                            |         |
     | format(pin)                        unlock(pin)       | lock() / drop / timeout
     +------------------------------------------> Unlocked -+
                                                   |
                                            change_pin(new)
                                                   |
                                                   v
                                               Unlocked'
```

`TamperSuspected` and `Inconsistent` are terminal states reachable from any of the above;
they refuse every operation except `wipe` and a fresh `format`, and they carry the
`TamperKind` for the product to display.

---

## 5. Public API

### 5.1 Types and construction

```rust
#![no_std]
// no alloc, no std, no RNG, no clock.

pub const FORMAT_VERSION: u16 = 1;
pub const SUITE_ID: u16 = 1;
pub const SEQ_RESERVE: u64 = 256;
pub const MAX_IDENTITIES: u8 = 4;

pub struct Config {
    pub domain_tag: [u8; 16],
    pub kdf: KdfParams,
    pub layout: Layout,
    /// Consecutive failures that destroy the store. 3..=25 (OPEN-QUESTIONS Q5, ratified;
    /// the floor was 1 here, which would have let one mistyped PIN destroy a device, and
    /// 3 is what the product-level decision specifies). The CEILING of 25 is a frozen
    /// format constant, not a preference: the ledger's tail reserve is sized to it.
    pub wipe_after: u8,
    pub occupancy: Occupancy,
    /// Provenance values this product is willing to run with. A release build passes
    /// `&[KeyProvenance::EfuseReadProtected]`; anything else refuses to mount.
    pub accept_provenance: &'static [KeyProvenance],
}

#[derive(Clone, Copy)]
pub struct KdfParams { pub m_kib: u32, pub t: u32, pub p: u8 }

impl KdfParams {
    /// m = 32 KiB, t = 1. Host tests only; `Config::validate` rejects it when
    /// `accept_provenance` contains only `EfuseReadProtected`.
    pub const TEST_ONLY: Self;
    /// Number of u64 words the Argon2id working buffer needs for these parameters.
    pub const fn scratch_words(&self) -> usize;
}

#[derive(Clone, Copy)]
pub enum Occupancy { Sparse, AlwaysFilled }

/// Borrowed Argon2id working memory. Zeroized by esp-seal before every return.
pub struct Scratch<'a>(&'a mut [u64]);
impl<'a> Scratch<'a> {
    pub fn new(buf: &'a mut [u64]) -> Self;
    pub fn fits(&self, p: &KdfParams) -> bool;
}

/// A normalized PIN or passphrase, 1..=64 bytes. Zeroize-on-drop, redacting Debug.
/// esp-seal does NOT normalize: Unicode tables do not belong in a low-level crate and
/// the embedder already owns the NFKD discipline. Pass NFKD-normalized UTF-8.
pub struct Pin { /* [u8; 64] + len, ZeroizeOnDrop */ }
impl Pin {
    pub fn from_normalized_utf8(s: &str) -> Result<Self, PinError>;
    pub fn from_normalized_bytes(b: &[u8]) -> Result<Self, PinError>;
    /// Shannon-style estimate over the observed character classes. Advisory; exposed so
    /// products can show an honest entropy meter at PIN creation.
    pub fn estimated_bits(&self) -> u16;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SlotId { pub class: SlotClass, pub index: u8 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotClass { Payload = 2, Registry = 3 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotState { Empty, Occupied { len: u16 }, Opaque }
```

### 5.2 The locked store

```rust
pub struct SealStore<F: Flash, M: DeviceMac> { /* ... */ }

impl<F: Flash, M: DeviceMac> SealStore<F, M> {
    /// Reads the ledger and every slot header, completes any interrupted operation,
    /// and elects the authoritative side of every slot. Requires no PIN and performs
    /// no key derivation beyond the device-bound header and guard keys.
    pub fn mount(flash: F, mac: M, cfg: &Config) -> Result<Self, MountError<F::Error, M::Error>>;

    pub fn state(&self) -> StoreState;
    pub fn attempts_remaining(&self) -> u8;
    pub fn wipe_epoch(&self) -> u64;
    pub fn key_provenance(&self) -> KeyProvenance;
    pub fn tamper_flags(&self) -> TamperFlags;
    /// Slot occupancy WITHOUT a PIN: Empty (filler or erased) vs Occupied. Products
    /// that ship duress must not surface this; see Q2.
    pub fn occupancy(&self) -> SlotMap;

    /// First PIN. Requires `StoreState::Blank` or `StoreState::Wiped`.
    pub fn format(&mut self, pin: &Pin, label: &[u8], scratch: Scratch<'_>)
        -> Result<Session<'_, F, M>, FormatError<F::Error, M::Error>>;

    /// Consumes one attempt. Returns a session on success.
    pub fn unlock(&mut self, pin: &Pin, scratch: Scratch<'_>)
        -> Result<Session<'_, F, M>, UnlockError<F::Error, M::Error>>;

    /// Consumes one attempt. Use `Session::confirm_pin` inside a session instead.
    pub fn verify_pin(&mut self, pin: &Pin, scratch: Scratch<'_>)
        -> Result<Identity, UnlockError<F::Error, M::Error>>;

    /// Destroys every record and bumps the one-way epoch. Needs no PIN: it only
    /// destroys. Idempotent and restartable.
    pub fn wipe(&mut self) -> Result<(), StorageError<F::Error, M::Error>>;

    /// Domain-separated device-bound derivation for embedder use: anti-phishing words,
    /// lock-screen words, per-device stream keys. Never collides with any internal
    /// derivation (4.1). Requires no PIN.
    pub fn device_derive(&mut self, label: &[u8], data: &[u8], out: &mut [u8])
        -> Result<(), StorageError<F::Error, M::Error>>;

    pub fn into_parts(self) -> (F, M);
}

#[derive(Clone, Copy, Debug)]
pub enum StoreState {
    Blank,
    Formatted { identities_present: u8, occupied_slots: u8 },
    Wiped { epoch: u64 },
    Inconsistent(TamperKind),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Identity(pub u8);
```

### 5.3 The session

```rust
/// Owns exactly one secret: the 32-byte `bound` value. Zeroized on drop.
/// No Clone, no Copy, no Debug that reveals anything.
pub struct Session<'s, F: Flash, M: DeviceMac> { /* ... */ }

impl<'s, F: Flash, M: DeviceMac> Session<'s, F, M> {
    pub fn identity(&self) -> Identity;
    pub fn visible_slots(&self) -> SlotMap;

    /// Copies the plaintext into `out` and returns its true length.
    /// `out` must be at least `SlotClass::max_payload()` bytes.
    pub fn read(&mut self, slot: SlotId, out: &mut [u8])
        -> Result<usize, ReadError<F::Error, M::Error>>;

    pub fn slot_state(&mut self, slot: SlotId)
        -> Result<SlotState, ReadError<F::Error, M::Error>>;

    /// Seal-verify-erase, per 4.6 S1-S9. Returns only after the read-back verification
    /// has succeeded, so a successful return means the record is durable.
    pub fn write(&mut self, slot: SlotId, plaintext: &[u8])
        -> Result<(), WriteError<F::Error, M::Error>>;

    /// Erases (Sparse) or overwrites with filler (AlwaysFilled).
    pub fn clear(&mut self, slot: SlotId)
        -> Result<(), WriteError<F::Error, M::Error>>;

    /// Re-seals every record of this identity under the new PIN, commits with one
    /// ledger cell, then erases the stale sides (4.6 C1-C6). Consumes and returns a
    /// session so a caller cannot keep using the old key by accident.
    pub fn change_pin(self, new_pin: &Pin, scratch: Scratch<'_>)
        -> Result<Session<'s, F, M>, ChangePinError<F::Error, M::Error>>;

    /// Adds a duress identity. Behaviour gated by the product; format always supports it.
    pub fn add_identity(&mut self, idx: Identity, pin: &Pin, visible: SlotMap,
                        scratch: Scratch<'_>)
        -> Result<(), WriteError<F::Error, M::Error>>;

    /// Constant-time re-derivation compared against the live session secret.
    /// Touches no flash and consumes NO attempt.
    pub fn confirm_pin(&mut self, pin: &Pin, scratch: Scratch<'_>)
        -> Result<bool, StorageError<F::Error, M::Error>>;

    /// Explicit lock. Equivalent to drop, but greppable at the call site.
    pub fn lock(self);
}

impl<F: Flash, M: DeviceMac> Drop for Session<'_, F, M> { /* zeroizes `bound` */ }
```

### 5.4 Error taxonomy

The central requirement is that **wrong PIN, corrupt record, and hardware fault are three
different things**, because they lead to three different product behaviours: try again,
restore from backup, stop trusting this board.

```rust
#[derive(Debug)]
pub enum UnlockError<FE, ME> {
    /// The AEAD tag did not verify for any identity. AN ATTEMPT WAS CONSUMED.
    WrongPin { attempts_remaining: u8 },
    /// This attempt was the last one; every record has been destroyed and the epoch
    /// bumped. AN ATTEMPT WAS CONSUMED.
    Wiped { epoch: u64 },
    /// No canary could be parsed. NO ATTEMPT CONSUMED - this is not a guess.
    Corrupt { slot: SlotId, detail: Corruption },
    /// Structural evidence of interference. NO ATTEMPT CONSUMED. Fail-closed: refuse.
    Tamper(TamperKind),
    NotFormatted,
    /// Store is already at zero attempts and awaiting its wipe.
    Locked,
    /// `Scratch` too small for the store's parameters.
    Scratch { required_words: usize },
    /// Provenance not in `Config::accept_provenance`.
    Provenance(KeyProvenance),
    /// The backend or the silicon misbehaved. May or may not have consumed an attempt;
    /// `attempt_consumed` says which, and it is never a guess about the PIN.
    Hardware { source: HardwareFault<FE, ME>, attempt_consumed: bool },
}

#[derive(Debug, Clone, Copy)]
pub enum Corruption {
    HeaderMac,      // header torn, forged, or from another device
    BodyDigest,     // body torn or bit-rotted; detected BEFORE any Argon2 spend
    Padding,        // non-zero pad inside the AEAD
    LengthPrefix,   // in-AEAD length exceeds capacity
    EpochStale,     // wipe_epoch != current: superseded by a wipe
    PinGenStale,    // pin_gen not in the current set: superseded by a PIN change
    ParamMismatch,  // record KDF params disagree with the superblock
    Magic, Version, Geometry,
}

#[derive(Debug, Clone, Copy)]
pub enum TamperKind {
    LedgerMissing,    // records present, ledger blank: the cheap counter-reset attack
    LedgerAmbiguous,  // two live ledger sectors with equal rotation counters
    LedgerRollback,   // records outrank the ledger's high-water marks (M7)
    GuardMismatch,    // a bit-log cell failed its keyed guard
    LogHole,          // a non-erased cell after the first erased one
    ForeignDevice,    // device_tag mismatch: this flash came from another board
}

#[derive(Debug)]
pub enum HardwareFault<FE, ME> {
    Flash(FE),
    Mac(ME),
    /// The two independent okm derivations disagreed (4.6 S3). Glitch suspected.
    DerivationMismatch,
    /// The record read back from flash did not match what was written (4.6 S8).
    WriteVerify,
    /// A ledger cell read back differently from what was programmed.
    CellVerify,
}
```

The rule the implementation enforces structurally: **`attempt_entry` is programmed at
exactly one place in the entire crate, and `attempt_success` at exactly one other.**
Everything reachable before the first or after the second consumes nothing, and that is a
property a reviewer can check by grepping for two function calls.

### 5.5 Zeroize discipline

| Secret | Owner | Lifetime | Wipe point |
|---|---|---|---|
| `Pin` bytes | caller, passed by reference | caller's | `ZeroizeOnDrop` on `Pin` |
| Argon2id scratch (up to 64 MiB) | caller, borrowed as `Scratch` | one operation | esp-seal zeroizes on **every** return path, including error paths, via an internal drop guard |
| `prestretch` | esp-seal stack | U2-U3 | drop guard, immediately after `bound` is computed |
| `bound` | `Session` | the session | `Session::drop` |
| `okm` (key + nonce) | esp-seal stack | one record op | drop guard |
| plaintext staging buffer | esp-seal stack | one record op | drop guard |
| caller's `out` buffer in `read` | caller | caller's | caller's responsibility, documented |

Mechanics: `zeroize::Zeroizing` and `#[derive(ZeroizeOnDrop)]` for volatile writes plus a
compiler fence; `subtle::ConstantTimeEq` for every secret comparison; no `Clone`, no
`Copy`, and no derived `Debug` on any secret type - each gets a hand-written `Debug` that
prints `Pin(<redacted>)`. Panics are a zeroization hazard, so the crate is
`#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing,
clippy::panic, clippy::arithmetic_side_effects)]` and every buffer access goes through
checked accessors. `#![forbid(unsafe_code)]` in `esp-seal`; the backends need `unsafe` for
FFI and are exempt.

DECISION: the scratch buffer is zeroized unconditionally, even though a 64 MiB PSRAM memset
is not free. It is the largest secret-bearing region in the system and leaving Argon2
state in PSRAM after an unlock would hand a cold-boot or fault attacker exactly the
intermediate values the ladder exists to protect. Cost is a measurement task (M5).

---

## 6. eFuse budget and provisioning

### 6.1 Budget

The ESP32-P4 has six 256-bit eFuse key blocks (`BLOCK_KEY0`..`BLOCK_KEY5`), each with an
associated write-once `KEY_PURPOSE` field.

| Consumer | Blocks | Purpose | Set by |
|---|---|---|---|
| Secure Boot v2 (RSA-3072) public-key digest | 1 | `SECURE_BOOT_DIGEST0` | release provisioning |
| Flash encryption XTS-AES-128 key | 1 | `XTS_AES_128_KEY` | release provisioning |
| **esp-seal** | **1** | **`HMAC_UP` (purpose value 8)** | **esp-seal provisioning** |
| spare | 3 | - | - |

**esp-seal consumes exactly one key block and never more.** It requires that block to be
read-protected (`RD_DIS`) and write-protected (`WR_DIS`), and the `KEY_PURPOSE` field to be
write-protected so the block cannot later be repurposed. Note that Secure Boot v2 can
occupy up to three digest slots if multiple signing keys are enrolled; with one signing key
the budget above holds and leaves three spares, which matches ARCHITECTURE 2.7.

Irreversibility ladder, in order:

1. Burning the key block: **irreversible**, one of six consumed.
2. Setting `KEY_PURPOSE` to `HMAC_UP`: **irreversible**, the block can never serve another
   purpose.
3. Read-protecting the block: **irreversible**, the key value is gone from every
   perspective including JTAG. This is the point of no return.
4. Write-protecting the block and its purpose: **irreversible**, belt and braces.

Burning an HMAC key does **not** brick a board. It consumes a block. A dev board can be
re-provisioned into a fresh block up to the remaining budget, which is why the recommended
dev allocation below only ever spends blocks deliberately.

### 6.2 What actually bricks a dev board

Not eFuse key burning. The brick risks are elsewhere and must be stated so nobody
conflates them:

- **Flash encryption in Release mode** disables the UART download-mode path for writing
  plaintext firmware. A dev board in Release mode can only be updated by a signed,
  encrypted image produced by the same toolchain and keys. Get that wrong and the board
  is a paperweight.
- **Secure Boot v2 enabled with a lost or mismatched signing key** is unrecoverable.
- **Flash encryption in Development mode** permits a limited number of plaintext
  re-flashes, governed by a chip-specific eFuse counter field. The exact permitted count on
  the P4 must be read from the P4 TRM before the first burn (measurement task M7). Do not
  assume the ESP32-classic number.

### 6.3 Dev-board allocation, given exactly two boards

Both bench units are rev v1.3 (`docs/HARDWARE.md`, `docs/BOARDS.md`). The allocation:

| Board | Role | eFuse state | Flash encryption | esp-seal mode |
|---|---|---|---|---|
| Waveshare 4B (COM3, 32 MB) | daily driver, UI and logic work | **never burned** | off | `KeyProvenance::Emulated` |
| Elecrow 5 (COM6, 16 MB) | release-equivalent sacrificial unit | HMAC_UP burned and read-protected | **Development mode, on** | `EfuseReadProtected` |

This allocation is not arbitrary. ARCHITECTURE 2.3 requires the Argon2id benchmark to run
with flash and PSRAM encryption enabled, because the P4 encrypts external PSRAM traffic
with the same XTS machinery whenever flash encryption is on, and release units pay a
latency cost the bare dev board does not. That benchmark needs a unit in the encrypted
configuration, and the 16 MB Elecrow is the right sacrifice because the partition table is
sized to fit 16 MB anyway (BOARDS.md flash section) so it exercises the binding constraint.

### 6.4 Development mode, and how it is kept out of release builds

`KeyProvenance::Emulated` means the `DeviceMac` implementation uses a compiled-in constant
key instead of the eFuse. It exists so a developer can iterate on storage logic on real
hardware without spending an irreversible resource. It is also, obviously, a complete
break of the security model, so it is fenced five ways. Any one of them would probably be
enough; all five are cheap.

1. **Cargo feature, non-default, deliberately ugly.**
   `esp-seal-idf/unsafe-emulated-key`. Cargo feature unification means a transitive
   dependency could turn it on, so the feature alone is not the control.
2. **Build-script hard failure in release.** `esp-seal-idf/build.rs` fails the build when
   the feature is enabled and `PROFILE == "release"`. No environment-variable override
   exists; the escape hatch is to build in debug, which is itself a visible signal.
3. **The provenance is mixed into every derivation.** `RecordInfo` carries a `provenance`
   byte and the header carries an `EMULATED_KEY` flag inside the AEAD's associated data.
   A record sealed in emulated mode therefore **cannot be opened in production mode and
   vice versa** - not "should not", cannot. A dev-mode wallet can never be mistaken for a
   real one, and a real one is not silently readable by dev firmware.
4. **`Config::accept_provenance` refuses to mount.** The notyas release build passes
   `&[KeyProvenance::EfuseReadProtected]`, so a release firmware that somehow got an
   emulated backend fails at `mount()` with `UnlockError::Provenance` rather than sealing
   anything.
5. **CI and the release runbook.** The invariant-1 build-graph walk (MILESTONES m1) is
   extended to assert that `esp-seal-sim` is absent from the firmware graph, that
   `unsafe-emulated-key` is off, and that `provisioning` is off. `release.ps1` refuses to
   produce an artefact otherwise.

And one runtime control that is not a build gate: the product **must** display the true
provenance. notyas's Verify screen already reports eFuse state as actually read rather
than as a constant (SECURITY.md invariant 5), and `SealStore::key_provenance()` is the
value it reads. Anything other than `EfuseReadProtected` gets an undismissable banner.

---

## 7. Attack analysis

Each item states the residual risk rather than the mitigation, because the mitigations are
already in the design above.

### 7.1 Brute force

On-device, the rate is one guess per `Argon2id(m, t) + HMAC + AEAD`, which is dominated by
Argon2id. **The parameters and therefore the rate are not yet known and this document does
not invent them.** ARCHITECTURE 2.3 sets the target at 0.5-2 s per unlock with a starting
point of m = 64 MiB in PSRAM, t = 3, p = 1, and a fallback of m = 16 MiB in internal SRAM at
higher t. Measurement task M1 pins the real numbers, and it must be measured with flash and
PSRAM encryption enabled or the pinned parameters will overshoot on release hardware.

On-device guessing also meets the attempt counter, so the practical bound is
`wipe_after` guesses per counter reset, not per second. See 7.2 for what a counter reset
costs an attacker.

Offline, after eFuse key extraction (tier 2), the bound is the user's PIN entropy against
memory-hard grinding on the attacker's hardware. Residual, stated as SECURITY.md already
states it: a 6-digit PIN falls; an alphanumeric passphrase does not. esp-seal exposes
`Pin::estimated_bits` so products can say so at PIN creation, and can do nothing more.

### 7.2 Flash snapshot and restore

This is the attack the honest claim has to be built around, and the analysis here is
sharper than ARCHITECTURE 2.5's summary.

The counters live in a **plaintext** partition. Flash encryption does not cover them - it
cannot, because bit-clear counters are incompatible with XTS write granularity. So an
attacker with a programmer can read and rewrite the ledger without breaking any key. Two
sub-cases:

- **Ledger-only rollback** (restore an old ledger, keep current records) is **detected**.
  Mount's witness check (M7) compares the ledger's `seq_high_water` and `wipe_epoch`
  against the records that outrank them, and the guard MACs prevent forging fresh cells
  without the eFuse key. Erasing the ledger outright is also detected: blank ledger with a
  non-blank records region is `TamperKind::LedgerMissing`, and esp-seal refuses rather than
  silently re-initialising, which is what would otherwise make counter reset free.
- **Full-flash snapshot and restore** (both partitions, consistent) is **not detectable and
  not preventable.** Restoring the records partition needs no key: the attacker writes back
  the same ciphertext bytes.

Therefore the honest statement of what the attempt counter buys, which products should use
instead of the phrase "attempt limited":

> The attempt counter converts "unlimited guesses" into "`wipe_after` guesses per
> full-flash snapshot-and-restore cycle". Against a thief with a hot-air station and a
> programmer that is a real slowdown of several orders of magnitude. It is not a wall, and
> nothing on rev v1.3 P4 silicon can make it one, because the chip has no monotonic counter
> the CPU cannot reach. That is the gap a secure element fills.

Residual: fully conceded, and it is the same concession SECURITY.md tier 3 already makes.

### 7.3 Fault injection

Deterministic nonces are the textbook fault-injection target, and this design uses them
deliberately (ARCHITECTURE 2.4, invariant 3). Named glitch targets and what stands in the
way:

| Target | Countermeasure | Residual |
|---|---|---|
| Skip the `attempt_entry` program | The counted region is a straight line with a read-back verification of the programmed cell; a skipped or corrupted program is `HardwareFault` and the attempt still counts. | A glitch that also defeats the read-back. Conceded at tier 2. |
| Corrupt the HKDF so a stale nonce is reused | `okm` is derived twice by independent invocations and compared in constant time before use (S3), and a third time from the flash-resident header during post-write verification (S8). A single fault must corrupt all three identically. | A multi-fault attacker. Conceded. |
| Force the AEAD tag comparison to succeed | Tag comparison is inside `chacha20poly1305` and is constant-time; a forced success yields a garbage plaintext, and for the canary that garbage fails the fixed `b"ESLK"` magic and the zero-pad check. | A glitch that lands on the magic check too. |
| Corrupt a ledger cell mid-program | Keyed guard patterns: a partial program almost certainly matches neither erased nor expected, and forging a valid cell needs the eFuse key. Asymmetric fail-closed resolution always resolves toward more failures. | Conceded at tier 2. |
| Extract the eFuse key itself | None available on this silicon. | Fully conceded; this is tier 2 by definition, and Argon2id is the second wall behind it. |

The **independent post-operation verification path** the red team required is S8, and its
independence properties are specific: it re-reads from flash rather than trusting RAM, it
re-derives the key material from the flash-resident header rather than from the in-memory
header, and it compares the recovered plaintext to the source in constant time. Its
failure action is to erase the just-written side, so a faulted write cannot become the
elected record.

### 7.4 Side channels

- **Argon2id's data-dependent phase** leaks memory access patterns. Against a remote or
  co-resident attacker that is a real concern; there is neither on a single-application
  airgapped device. Against a physical attacker with an EM probe or a shunt resistor it is
  unmitigated and unmitigable in software at this cost point. Stated, not solved.
- **The HMAC peripheral** is a hardware block with no published DPA-resistance claim. Every
  guess drives it with attacker-influenced input. Unmitigated.
- **Software comparisons** are constant-time via `subtle`, and the AEAD tag comparison is
  constant-time inside the AEAD crate. This closes the cheap timing channels and does
  nothing about the physical ones.
- **Unlock wall-clock time** is deliberately constant-ish (dominated by Argon2id) and
  independent of how many slots are occupied, because per-slot work is a handful of HKDF
  and AEAD operations. A product that showed a progress bar whose duration varied with
  occupancy would leak occupancy; esp-seal's timing does not.

Residual: any physical side-channel attacker is a tier 2 attacker, and tier 2 already
assumes the eFuse key is lost.

### 7.5 Evil maid

An attacker with temporary access can flash their own firmware, which then sees the PIN in
plaintext when the user next types it. esp-seal cannot defend this and does not claim to;
Secure Boot v2 plus the reproducible-build and Verify-screen story is the defence, and it
belongs to the product.

What esp-seal contributes: `device_derive` gives the product a device-bound, domain-
separated derivation for anti-phishing words and lock-screen words with no additional key
management. The known limit is Coldcard's and it is stated in ARCHITECTURE 3: an attacker
who **held** the device can enumerate prefixes and replay the words on a look-alike, so the
words defeat substitution by a stranger, not substitution by someone who had your board.

Residual specific to esp-seal: `device_tag` in the superblock is a stable device
fingerprint, readable from a flash dump on a dev board with encryption off. Recorded in 3.5.

---

## 8. Test plan

### 8.1 Host tests with the simulated backend

**Known-answer vectors.** A committed JSON vector file drives seal and unseal at fixed
`SoftMac` key, fixed domain tag, fixed PIN, fixed sequence and epoch and generation, at
both `KdfParams::TEST_ONLY` and the pinned production parameters. Vectors cover the full
chain: `device_binding`, `guard_key`, `hdr_key`, `kdf_salt`, `prestretch`, `bound`, `okm`,
the 48-byte AAD, the 80-byte header, and the sealed body. Publishing the vector file is
part of the contribution: it lets any reimplementation prove compatibility.

**The power-loss fuzzer.** The centrepiece. For every operation `O` in {format, seal, clear,
unlock-success, unlock-failure, change-pin over 0..8 records, wipe, rotation, mount-cleanup}
and for every step boundary `k` in `0..ops(O)`:

1. Build a store in a known state.
2. Run `O` with `SimFlash::cut_after(k)`, in three variants: clean truncation at the op
   boundary, partial program of a prefix of the block, and a deterministic bit-rot
   variant where a fixed subset of bits fails to clear.
3. Re-`mount()` and assert the invariant set.

The invariant set, asserted after every single case:

| # | Invariant |
|---|---|
| I1 | `mount()` returns `Ok` or a `TamperKind`; it never panics and never returns garbage. |
| I2 | Every slot reads back as exactly the pre-operation record or exactly the post-operation record. Never a mixture, never a truncated one. |
| I3 | `failures` never decreases across a cut. |
| I4 | `wipe_epoch` never decreases. |
| I5 | `pin_gen` never decreases for any identity, and the current set never contains an uncommitted value. |
| I6 | **No `(key, nonce)` pair is ever derived twice.** The harness records every pair derived over the entire life of the simulated device, across every cut, wipe, and PIN change, in one global set, and fails on any duplicate. |
| I7 | After a committed PIN change, no record anywhere on the simulated flash opens under the old PIN once mount cleanup has run. |
| I8 | The RECORDS INVARIANT holds: `SimFlash` never saw a second program of any cipher block between erases. |
| I9 | Attempt accounting: exactly the operations documented in 4.5 consumed an attempt. |

I6 is the reason the fuzzer exists. Every other invariant protects data; I6 protects the
cryptography, and it is the one property an argument on paper is least able to guarantee.

**Model-based sequence testing.** `proptest` generates random sequences of operations
against both the real implementation and a simple reference model (a `HashMap` plus
counters) and asserts observational equivalence, with random cuts injected between
operations.

**Parser fuzzing.** `cargo fuzz` targets `mount()` over arbitrary 256 KiB + 16 KiB byte
images and over arbitrary single-record byte strings. Property: no panic, no unbounded
loop, no out-of-bounds. `cargo miri test` runs the whole core suite for UB.

**Negative tests, one per AAD field.** For each field bound into the associated data (3.3),
flip it on disk and assert the specific error: cost downgrade, slot transplant, side copy,
epoch replay, generation replay, provenance mismatch. Each of those is a row in the AAD
table and each row gets a test.

### 8.2 Hardware tests

On both bench boards where applicable, and on the sacrificial encrypted unit for anything
involving flash encryption:

- Create, power cycle, unlock. Wrong PIN decrements and the decrement survives a reboot.
- **Automated power-cut rig**: a USB power relay under script control cutting the rail at
  pseudo-random times during seal, unlock, change-pin, and wipe, thousands of cycles, with
  invariant checks I1-I5 and I7 verified at each boot. This is the hardware analogue of
  8.1 and it is the only way to catch flash-driver behaviour the simulator models wrongly.
- Wipe-on-N destroys every record and bumps the epoch; verified by raw flash readback.
- PIN change leaves no old-PIN ciphertext; verified by raw flash readback plus an offline
  attempt to open every 4 KiB sector with the old PIN's ladder.
- eFuse read protection is real: attempt to read the key block from firmware and from
  espefuse, expect failure both ways.
- Emulated-mode records refuse to open in production mode and vice versa.
- Stateless path writes nothing: full flash readback diff before and after a session that
  never saves.
- Foreign-flash detection: move a flashed image from one board to the other, expect
  `TamperKind::ForeignDevice`.

### 8.3 Measurements required before parameters are frozen

None of these numbers exist yet, and no number in this document is invented in their place.

| # | Measurement | Why it is load-bearing |
|---|---|---|
| M1 | Argon2id wall time on rev v1.3 P4 at m = 64/32/16 MiB and t = 1..6, in PSRAM and in internal SRAM, **with and without** flash+PSRAM encryption. | Pins the KDF parameters. ARCHITECTURE 2.3. Release units pay an XTS cost the bare dev board does not. |
| M2 | PSRAM random-access bandwidth under XTS. | Predicts M1 and tells us whether the 64 MiB target is viable at all. |
| M3 | `esp_hmac_calculate` call latency. | Bounds the per-slot and per-mount cost; mount does up to ~40 MAC operations. |
| M4 | 4 KiB sector erase and 256-byte page program times. | Sizes the power-loss window and the seal wall time. |
| M5 | 64 MiB PSRAM zeroization time. | Decides whether the unconditional scratch wipe (5.5) needs a progress indicator. |
| M6 | **Maximum partial-page programs between erases for the actual NOR parts on both boards.** | The ledger programs up to 32 cells per 256-byte page. If the part specifies fewer, the cell size or the page layout must change. This is a datasheet read plus an empirical soak test, and it is the single most likely reason the format would need revising. |
| M7 | The P4's Development-mode flash-encryption re-flash count eFuse field. | Determines how many times the sacrificial board can be re-flashed before it is consumed. |
| M8 | Full unlock wall time end to end, cold boot to session. | The UX budget in UX.md depends on it. |
| M9 | ~~`esp-seal` crate name availability on crates.io.~~ **WITHDRAWN 2026-08-17**: under OPEN-QUESTIONS Q8/Q44/Q46 there is no crate and nothing is published, so there is no name to check. |

---

## 9. Licensing and clean-room

### 9.1 The choice for this crate specifically

PLATFORM.md section 6 presents the tradeoff and defers the decision. Restated for esp-seal
rather than in general:

- **(a) GPL-3.0-or-later.** Preserves reciprocity on the sealing code. Practical
  consequence: the ecosystems esp-seal exists to serve are permissively licensed
  throughout - `esp-hal` and the `esp-idf-*` stack are MIT/Apache-2.0, as are `ur`,
  `bbqr`, and `gt911` - and they do not take GPL dependencies. A GPL esp-seal would be
  usable by notyas and by essentially nobody else.
- **(b) MIT OR Apache-2.0.** The Rust ecosystem norm. Maximises reuse, which is the entire
  stated purpose of extracting the crate. Foundation Devices relicensed their API crates
  this way for exactly this reason. The GPL-3 notyas firmware consumes a permissive
  dependency freely, so nothing in the product changes. Cost: forfeits copyleft on the
  crate.

The specific argument for this crate: the thing worth protecting here is the **design**,
and the design is published in this document either way. The implementation is on the order
of three thousand lines of well-trodden construction over vetted primitives. Copyleft on
those three thousand lines protects little and costs the crate its reason to exist.
PLATFORM.md floats a per-crate split with "permissive for the interop formats, GPL3 for
esp-seal"; that is precisely backwards for adoption, because esp-seal is the item on the
shortlist with the largest audience outside Bitcoin - every ESP32 product that holds a
secret is a potential user, not just wallets.

RESOLVED 2026-08-17 by the project owner (OPEN-QUESTIONS Q8): **GPL-3.0-or-later.** The
owner's position is that for wallet firmware copyleft prevents closed forks of code that
handles user keys, and the adoption cost on the low-level pieces is accepted. This
section's own analysis is therefore not overturned - it is accepted and its stated
consequence is applied: **the crate is not extracted at all** (Q44), and the design in
this document is the contribution instead, published in-repo so any project can read the
format, the power-loss analysis and the attack analysis and reimplement freely. A
document does not impose its licence on an independent implementation of the ideas it
describes, so the argument that "the thing worth protecting here is the design, and the
design is published either way" holds under the answer that was given. The original item
is kept below.

OPEN (resolved): **esp-seal licence.** GPL-3.0-or-later versus dual MIT OR Apache-2.0.
RECOMMENDATION: **dual MIT OR Apache-2.0** for `esp-seal`, `esp-seal-idf`, `esp-seal-sim`,
and the future `esp-seal-hal`, with the published test vectors under CC0-1.0 so any
implementation may validate against them. notyas firmware stays GPL-3.0-or-later and is
unaffected. If the answer is GPL3 instead, the crate should not be extracted at all -
it should stay a module in notyas-wallet, because a GPL3 "platform contribution" that no
platform can adopt is worse than an honest internal module.

RESOLVED 2026-08-17 (OPEN-QUESTIONS Q46): **in-tree for the life of 0.2.0, never
published.** Publication is not deferred, it is withdrawn, because Q8/Q44 leave no crate
to publish. Measurement M9 (crate-name availability on crates.io) is withdrawn with it.
The original item is kept below.

OPEN (resolved): **where esp-seal lives and when it is published.** In-tree under `crates/esp-seal*`
during 0.2.0, or a separate repository from day one.
RECOMMENDATION: develop in-tree through m3 and m4a where the API is still moving, extract
to its own repository and publish at the 0.2.0 release, with notyas pinning an exact
version. Extracting early costs a two-repo edit cycle during the phase with the most churn;
extracting late costs nothing because the licence headers and the crate boundary are
correct from the first commit either way. The licence decision above must be made *before*
the first commit regardless, because relicensing after external contributions arrive
requires their consent.

### 9.2 Clean-room constraint

Prior art was consulted, and the boundary matters because both sources are copyleft.

**What was consulted, and only this:**

- Trezor's published storage design documentation (`docs.trezor.io/trezor-firmware/storage`)
  for the NORCOW append-only concept, the paired one-way bit-log counter with guard bits,
  and the documented lesson that their earlier 32-word counter design was
  fault-injection-vulnerable.
- Blockstream's help-centre article on Jade's oracle-enforced PIN protection, and
  PLATFORM.md's summary of `storage.c`'s behaviour (encrypted keychain blob in NVS,
  single-byte counter, blob erased at zero).

**What was not, and must not be:** no source file from `trezor-firmware` or `Jade` may be
read by anyone writing esp-seal code. The process rule, to be recorded in the crate's
`CONTRIBUTING.md`:

1. Design inputs are published prose only: specification pages, blog posts, papers.
2. Anyone who has read `norcow.c`, `storage.c`, or the Trezor storage implementation must
   not write the corresponding esp-seal module. They may review it.
3. Every contributor attests to (1) and (2) in the pull request template.

Ideas - bit-clear counters, guard bits, A/B commit, epoch invalidation - are not
copyrightable, and esp-seal's format differs substantially from both prior designs anyway
(neither has an epoch in the KDF, a device-MACed header as the commit token, or a global
generation counter as a batch commit token). The clean-room process is not because the
ideas are encumbered; it is so that the claim is defensible without argument.

---

## 10. Reconciliation notes

Items in this document that touch text owned by other plan files. Listed for the
reconciliation pass; **not** edited here.

| This document | Parent text affected | Nature |
|---|---|---|
| 2.4 crate boundary (OPEN) | ARCHITECTURE.md 1, crate table | notyas-wallet delegates sealing to esp-seal |
| 4.1 salt formula (DECISION) | ARCHITECTURE.md 2.4 | `kdf_salt` drops `slot_id`; slot separation moves entirely into the HKDF info. One Argon2id run per unlock instead of one per slot. |
| 4.3 provisioning (OPEN) | ARCHITECTURE.md 2.2 | "burned at first save" becomes a host-side factory step; no eFuse-burn code in release firmware |
| 3.2 slot map (refinement) | ARCHITECTURE.md 2.6 | 8 payload + 8 registry pairs confirmed, plus 4 canary pairs and a superblock pair; registry sides are two sectors |
| 3.6 filler (format-ready) | OPEN-QUESTIONS Q2 | The format supports the full deniability package at zero marginal cost; Q2 decides behaviour only, and can be decided after the format is frozen |
| 7.2 counter honesty | ARCHITECTURE.md 2.5, SECURITY.md tier 3 | Sharpens "flash encryption raises the cost": the counters partition is plaintext, so a counter rollback costs a flash restore cycle, not a key break. Ledger-only rollback is detected; full-snapshot rollback is not. |
| 9.1 licence (OPEN) | PLATFORM.md 6, OPEN-QUESTIONS | Recommends dual MIT/Apache for esp-seal specifically, against PLATFORM.md's floated "GPL3 for esp-seal" split |
| 8.3 measurements | MILESTONES m1 | Adds M3-M9 to the m1 benchmark harness, in particular M6 (NOR partial-page program limit), which can invalidate the ledger cell layout |
```
