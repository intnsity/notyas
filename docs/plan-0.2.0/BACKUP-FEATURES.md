# BACKUP-FEATURES.md - seed lifecycle feature cluster for notyas 0.2.0

Status: PLAN, wave-2 planning input. Companion documents in this directory:
PARITY.md (the rows this file resolves), ARCHITECTURE.md (crypto stack, key
ladder, randomness policy, storage record format), SECURITY.md (invariants and
the honest-claims rule), UX.md (screen inventory, the ten commandments),
CAMERA.md (camera capture path; some task briefs name it CAMERA-HW.md - if both
exist, the camera hardware document is the authority for capture and the name
used here is CAMERA.md), OPEN-QUESTIONS.md and MILESTONES.md (parallel
workflow), PLATFORM.md (the seedqr crate this file depends on).

This file covers the seed-lifecycle cluster: everything between "the device can
store a seed" and "the device can sign", which Coldcard parity requires and
which no single other plan document owns. Individually these are small
features. Collectively they decide whether a notyas owner can move, split,
derive, back up and restore their own keys without a Coldcard - which is the
difference between a demo and an alternative.

Effort tiers used throughout: **S** = a few days including vectors and tests,
**M** = one to two weeks, **L** = three weeks or more. Tiers are implementation
plus its test corpus, not implementation alone; a seed feature without pinned
vectors is not done.

---

## 0. The gating rule

Most of this cluster is dangerous in the hands of a user who has not asked for
it. The rule this document applies everywhere:

> A feature that can produce a **valid-looking wallet that is not the user's
> wallet**, or a **second copy of key material**, lives behind one **Advanced /
> Seed Tools** menu, reached from wallet settings, behind a one-time
> explanation screen the user must page to the end of. The main flows
> (create, restore, receive, sign, export xpub) never surface it.

Seed XOR, BIP-85, saved passphrases, Lock Down Seed and the seed-bearing backup
profile are all inside that gate. (SeedQR display was in this list and is removed:
OPEN-QUESTIONS Q17 is ratified and display-out is not shipped at all, so there is
nothing to gate.) Encrypted backup of
settings and registrations, the backup password quiz, restore, and the
final-word calculator are not: they are ordinary recovery, and hiding recovery
is its own footgun.

Second rule, from UX commandment 6: every one of these features that writes to
SD or flash announces the write, in plain words, before it happens.

---

## 1. The cluster at a glance

Deps column: **STO** = 0.2.0 storage layer (MILESTONES m3/m4a), **SD** = SD
subsystem (m5), **MS** = multisig registry (m7), **CAM** = camera (CAMERA.md
path 1), **CORE** = notyas-core signing/derivation extension (m2), **QR** =
notyas-core qr.rs mode/ECC extension (section 6.1).

| # | Feature | PARITY row / class | What it does | Deps | Tier | Security risk | Call |
|---|---|---|---|---|---|---|---|
| B1 | Encrypted backup container - seedless profile (settings + multisig registrations + wallet metadata, NO key material) | 6 "Encrypted backups" / a | Writes one AEAD-sealed file to SD holding everything 0.2.0 adds that a mnemonic cannot re-derive | STO, SD, MS | M | Low. No key material in the file; xpubs and descriptors are a privacy leak, labeled | **0.2.0**, default backup offer |
| B2 | Encrypted backup - full profile (adds BIP-39 entropy for selected wallets) | 6 "Encrypted backups" / a | Same container, manifest flag, adds the seeds | B1 | S on top of B1 | High. A second offline-attackable copy of the seed; only the password protects it | **0.2.0, advanced menu**, never the default |
| B3 | Backup password: dice-derived 12 words + spot-check quiz | 6 "Encrypted backups" / a | 128-bit backup password generated from user dice rolls, quizzed before the file is written | B1 | S | Medium. Password loss = file loss (not fund loss, if the seed backup exists) | **0.2.0** |
| B4 | Restore, including onto a different device | 6 "Encrypted backups" / a | Reads the file, reviews contents, re-seals under the NEW device's PIN and eFuse binding | B1, STO | S-M | Medium. Hostile-file parsing surface; see 2.8 | **0.2.0** |
| B5 | Clone device (ECDH over SD, target writes pubkey, source encrypts to it) | 6 "Clone device" / a | Fleet setup without a shared password | B1, SD | M | Medium | **Later (0.3.x).** B1+B4 already reach the outcome; clone is a convenience protocol |
| B6 | Seed XOR split, dice-generated parts | 1 "Seed XOR" / a | Split a seed into 2-4 BIP-39-valid parts, information-theoretically secure | CORE | S | High footgun (N-of-N, see 3.3) | **0.2.0, advanced menu** |
| B7 | Seed XOR split, deterministic parts (Coldcard construction) | 1 "Seed XOR" / a | Reproducible split; interop-testable against Coldcard | B6 | S | As B6, plus: computational secrecy only (3.2) | **0.2.0, advanced menu, second option** - cheap once B6 exists |
| B8 | Seed XOR recombine | 1 "Seed XOR" / a | Enter 2-4 parts, XOR, show resulting XFP, use as session seed or save | B6 | S | Medium: any wrong subset yields a valid wallet (3.3) | **0.2.0, advanced menu** |
| B9 | SLIP-39 / Shamir | (not a Coldcard row) | True M-of-N threshold backup | - | L | Medium | **No.** See 3.5 |
| B10 | BIP-85 app 39' - child BIP-39 seeds (12/18/24 words) | 1 "BIP-85 derived seeds" / a | Deterministic child seeds from the master | CORE | S | High footgun (child looks like an independent wallet, is not) | **0.2.0, advanced menu** |
| B11 | BIP-85 app 32' - child XPRV | 1 "BIP-85 derived seeds" / a | Child BIP-32 root | B10 | S | As B10 | **0.2.0, advanced menu** |
| B12 | BIP-85 app 128169' - hex entropy | 1 "BIP-85 derived seeds" / a | 16-64 raw bytes | B10 | S | Medium | 0.2.x |
| B13 | BIP-85 app 2' - HD-Seed WIF | 1 "BIP-85 derived seeds" / a | A single loose private key | B10 | S | High: encourages loose-key handling, matches the deferred WIF Store row | Later |
| B14 | BIP-85 apps 707764'/707785' - passwords | 1 "BIP-85 passwords + HID" / d | Deterministic passwords, **display only** - the "and QR" clause is struck 2026-08-17, because a QR of a BIP-85 password is a secret QR and the ratified Q17 declines those | B10 | S | Medium; scope creep into password management | Later. **USB HID typing: rejected**, it contradicts the no-USB-data posture |
| B15 | BIP-85 app 89101' - dice rolls | 1 "BIP-85 derived seeds" / a | BIP85-DRNG dice stream | B10 | S | Low; no use case on a device whose entropy is real dice | Later, low priority |
| B16 | Use a BIP-85 child as the active session seed | 1 "Temporary seeds" / a | Sign with a child without saving it | B10, Q11 | S | Medium | **0.2.0** if Q11 (stateless signing) is accepted |
| B17 | Passphrase wallets: multiple, fingerprint-verify-only slots | 1 "BIP-39 passphrase" / a | A named slot stores the parent reference and the EXPECTED XFP, not the passphrase; typo detection without holding the secret | STO | S-M | Low. Best-in-class answer to the wrong-passphrase problem | **0.2.0**, default |
| B18 | Passphrase saved inside the sealed slot | 1 "BIP-39 passphrase" / a | Convenience: device holds the whole wallet | B17 | S | Medium: removes the "the passphrase is not on the device" property the user may believe they have | **0.2.0, advanced menu**, off by default, explicitly labeled |
| B19 | Passphrase saved to SD, bound to card serial (Coldcard model) | 1 "BIP-39 passphrase" / a | Encrypted passphrase file on a specific card | SD | S | Medium | Later. B17/B18 cover the need without a third secret artifact |
| B20 | Seed Vault (Coldcard construction: seeds encrypted under the master seed's key) | 1 "Seed Vault" / b | - | - | - | - | **Rejected as a construction** (5.4). The 8-slot PIN-sealed wallet list already IS the vault; its UX affordances are adopted |
| B21 | Lock Down Seed | 1 "Lock Down Seed" / b | Destructively replace the master seed with the passphrase-derived secret | STO | S | High: irreversible, and its main benefit is covered by B17 | Later (0.2.x), typed-name confirmation |
| B22 | **DROPPED (Q17 ratified 2026-08-17: display-out declined)** SeedQR display (standard, numeric) | 1 "Scan seed via QR" / c-b | Render the seed as a SeedSigner-compatible QR for transcription or backup | QR | S | **Highest-risk display in the product**: a camera-readable seed on screen | **0.2.0, advanced menu**, subject to OPEN-B5 |
| B23 | **DROPPED (Q17 ratified 2026-08-17)** CompactSeedQR display (binary) | 1 "Scan seed via QR" / c-b | 21x21 / 25x25 transcription-friendly form | QR (byte API) | S | As B22 | **0.2.0, advanced menu**, subject to OPEN-B5 |
| B24 | **DROPPED (Q17 ratified 2026-08-17; it is polish on top of B23 and inherits the secret-QR screen class B23 no longer has)** Guided transcription flow (grid template, module by module) | 1 "Scan seed via QR" / c-b | Walks the user through inking a paper/metal grid | B23 | M | As B22 | dropped, not 0.2.x |
| B25 | SeedQR / CompactSeedQR scan-in | 1 "Scan seed via QR" / c base, b with camera | Restore a seed by scanning | CAM, QR | M | Medium (camera path is the trust boundary; CAMERA.md section 4) | **0.2.0 iff the camera path is approved**, otherwise 0.3.0 |
| B26 | Manual word entry with prefix completion | 1 "Import seed by word entry" / a | Already in notyas-core (`words_with_prefix`, `check_phrase`); m4b/m6 wire the keyboard | - | done/S | Low | **0.2.0** (already planned) |
| B27 | Final-word (checksum) calculator | 1 "Import seed by word entry" / a | Given the first 11/14/17/20/23 words, list every valid last word | CORE | S | Low, with one wording trap (6.4) | **0.2.0** |
| B28 | Duress wallet on a decoy PIN + the deniability padding package | 2 "Trick PINs" / b-d | See section 7 | STO, Q2 | L | See section 7 | **Deferred to OPEN-QUESTIONS Q2**; not re-decided here |
| B29 | Backup/duress interaction: fixed-size backup plaintext | - | Constant-size backup file so the ciphertext length cannot betray the wallet count | B1 | S | - | **0.2.0** regardless of Q2 (2.2, it costs nothing) |

Adjacent PARITY rows this cluster disposes of, for completeness:

- **Key Teleport** (1, class c base): receive needs a camera. Once CAMERA.md
  path 1 lands, the honest notyas equivalent is B1+B4 over SD plus, later, B5.
  Not a 0.2.0 item.
- **Destroy Seed / View Seed Words** (1, class a): storage-layer danger-zone
  items, owned by UX.md screen 15 and MILESTONES m4b, not by this file.
- **Nuke Device** (6, class c): crypto-erase, ARCHITECTURE 2.5 wipe path.
- **Paper wallets** (5, class d): recommend **reject**. Coldcard's own docs
  discourage them, and a dice-only variant is a novelty that adds a second
  loose-key surface to a signer. If ever built: dice entropy only, advanced
  menu, no exceptions.
- **WIF Store** (5, class d) and **Secure Notes and Passwords** (5, class b-d):
  out of this cluster and recommended deferred; B13/B14 are the only places
  they touch it.

---

## 2. Encrypted backup and restore

Source of the model: https://coldcard.com/docs/backups/

### 2.0 Why this reopens OPEN-QUESTIONS Q8

Q8 currently recommends **no** encrypted SD backup in 0.2.0, on the grounds
that the mandatory backup-verify quiz plus deterministic re-derivation is the
backup story, and a second sealed artifact dilutes "SD is untrusted, your
mnemonic is the backup".

That reasoning was written against a seed-only device. 0.2.0 is not one. It
adds state that **the mnemonic cannot re-derive**:

- multisig registrations (descriptors, cosigner xpubs) - the thing the whole
  2021 Coldcard xpub-substitution defense depends on (ARCHITECTURE 5.3 check 4);
- wallet labels, network, account list, backup-verified flags;
- settings the user has tuned: fee thresholds, auto-lock, QR defaults,
  lock-screen word, expert gates.

With wipe-on-N defaulting to 10 (Q3) and a deliberately aggressive
deterministic-wipe posture (SECURITY.md), a notyas owner who fat-fingers their
PIN eleven times keeps their coins and loses their multisig setup. Telling that
user to go re-import descriptors from their coordinator is not parity, and
PARITY.md classifies encrypted backup as **class a** - directly portable, on
the daily-use surface.

The resolution proposed here keeps Q8's concern intact by splitting the
artifact rather than the format:

> **One container, two content profiles.** The **seedless** profile (B1) is the
> default offer and contains no key material at all. The **full** profile (B2)
> adds BIP-39 entropy and lives behind the advanced gate with its own warning
> screen. Same code path, same crypto, one manifest byte apart.

That gives the non-re-derivable state a home without pushing a second copy of
anyone's seed onto a memory card by default. **OPEN-B1** below asks the user to
ratify or overrule.

### 2.1 What a backup contains, and what it must never contain

Contained, seedless profile:

- format version, profile flag, creation counter (no wall clock exists on this
  device - do not invent one);
- per wallet slot: label, network, script type / default derivation, account
  index list, backup-verified flag, parent-XFP and expected-XFP for passphrase
  slots (B17), and the slot's registered-descriptor references;
- multisig registry: the canonical descriptor string with checksum for each
  registration, plus the M/N/script-type/derivation the device verified at
  import (ARCHITECTURE section 4);
- device settings: brightness, auto-lock timeout, wipe-counter policy, QR
  defaults, fee thresholds, expert-gate flags, device nickname, the
  user-chosen lock-screen word.

Contained, full profile: everything above, plus, **for the wallets the user
explicitly selects on a per-wallet review screen**, the BIP-39 entropy bytes
(not the 64-byte seed - ARCHITECTURE 2.2 keeps entropy so the mnemonic remains
re-displayable) and, only if B18 was used for that slot, the stored passphrase.

Never contained, and this list is normative:

- **the device PIN**, or any PIN-derived value. Coldcard is explicit that "the
  device PIN code is not preserved during backup"
  (https://coldcard.com/docs/backups/) and notyas matches: a backup that
  carried the PIN would turn a stolen memory card into a device credential.
- **the eFuse HMAC key or `device_binding`** (ARCHITECTURE 2.4). It cannot
  leave the chip by construction and must not be reconstructed in a file.
- **anti-phishing word state.** Those words are `HMAC_efuse(pin_prefix)`, a
  function of a key that does not travel. See 2.6 for the UX consequence.
- **counters partition state**: attempt/guard bits, `seal_seq`, `wipe_epoch`.
  Device state, not user data, and restoring a counter would be a rollback
  primitive handed to an attacker.
- **duress configuration**, pending Q2. See section 7.
- logs of any kind. There are none.

### 2.2 Container format

Rejected: **7z AES-256**. Coldcard's choice is good for Coldcard - a standard
archive any desktop tool opens - but it does not transfer:

- 7z's AES codec is CBC (Coldcard's own doc names CBC and the 16-byte IV,
  https://coldcard.com/docs/backups/) and CBC is not an authenticated mode; the
  .7z container's integrity field is CRC32
  (https://py7zr.readthedocs.io/en/latest/archive_format.html), which is a
  checksum, not a MAC. A tampered backup is therefore not reliably detectable
  by the format itself. Our sealed-storage design went the other way on purpose
  (ARCHITECTURE 2.2: the AEAD tag *is* the wrong-key detector).
- It would add an archive parser and a compression codec to a device that
  restores files from untrusted media. ARCHITECTURE and SECURITY both spend
  paragraphs minimising exactly this kind of C-or-large-Rust surface; PARITY
  names `sevenz-rust` as the available crate, and even a good one is a large
  new dependency for a format we would use once.
- 7z generates its salt and IV randomly. We have no RNG (invariant 3).

Chosen: **a minimal AEAD container built from the primitives already in the
0.2.0 graph** - argon2, chacha20poly1305, hkdf, sha2. Zero new dependencies.

```
notyas-backup-v1  (all integers little-endian, all fields fixed width)

header (plaintext on the card, and the AEAD's AAD in full):
    magic        8   "NOTYASBK"
    version      2   = 1
    profile      1   0 = seedless, 1 = full
    kdf_id       1   1 = Argon2id
    m_kib        4   Argon2id memory
    t_cost       4   Argon2id iterations
    p_lanes      4   Argon2id parallelism (= 1)
    salt        32
    nonce       12
    body_len     4   fixed by construction (see padding below)
body:
    ct[body_len] || tag[16]      ChaCha20-Poly1305
```

The body plaintext is a canonical, length-prefixed, deterministic
serialization - no compression, no self-describing container, no field
reordering - **padded to a constant size** covering the maximum configuration
(8 wallet slots, 8 registry records, settings; approximately 11 KiB). Constant
size is B29: the file length then reveals nothing about how many wallets exist,
which is the same leak the duress padding package (Q2) closes in flash. It
costs a fixed 11 KiB on a memory card and buys a property for free, so it is
adopted whether or not Q2 accepts duress.

Format publication is part of the deliverable, not a follow-up: the container
is specified in SPEC with known-answer vectors, and **a host-side reference
decoder ships in `tools/` with the 0.2.0 release**, GPL3 and reproducible. That
is how notyas keeps the property Coldcard gets from using 7z - your backup is
openable without the vendor's device - without adopting 7z. Shipping the format
without the decoder would be lock-in; it is a release gate, not a nice-to-have.

Interop honesty: this file is a notyas file. The interoperable backups are the
mnemonic and the exported descriptors, and the backup screen says so.

### 2.3 The backup key without an RNG - resolution

This is the real design problem in the cluster, and it has a clean answer.

**First, the thing that must not be copied from the storage ladder.** The
sealed-storage key (ARCHITECTURE 2.2) passes through `HMAC-SHA256_efuse`, which
is precisely what forces every PIN guess onto the physical device. A backup
must decrypt on a *different* device, so the backup ladder **deliberately
omits the eFuse binding**. Consequences, stated plainly rather than discovered
later:

- a stolen backup file is attackable fully offline, in parallel, with no
  attempt counter and nothing that can ever be made to rate-limit it;
- therefore Argon2id and the password's own entropy are the *entire* wall;
- therefore the backup password cannot be a 6-digit PIN. It must carry real
  entropy, which is why B3 generates it from dice rather than asking the user
  to invent one.

**Second, uniqueness without randomness.** The requirement is that no two
backup files ever share a (key, nonce) pair, because ChaCha20-Poly1305 fails
catastrophically under nonce reuse and is not misuse-resistant. Three layers,
in order of strength:

```
device_binding = HMAC_efuse("notyas-device-id")            # ARCHITECTURE 2.4
salt   = SHA256("notyas-backup-salt-v1" || device_binding
                || wipe_epoch || backup_seq)
mk     = Argon2id(NFKD(password), salt, m_kib, t_cost, p=1) -> 32 bytes
okm    = HKDF-SHA256(ikm = mk, salt = salt,
                     info = "notyas-backup-v1" || version || profile
                            || SHA256(body_plaintext))
key    = okm[0..32]
nonce  = okm[32..44]
ct||tag = ChaCha20Poly1305.seal(key, nonce, aad = header, pt = body_plaintext)
```

1. **The key is unique per file because the salt is.** `backup_seq` is a
   one-way monotonic counter in the plaintext `counters` partition, alongside
   `seal_seq` and `wipe_epoch` and maintained by the same rules (ARCHITECTURE
   2.5): never decremented, high-water recovered on mount, and `wipe_epoch`
   covers the case where a wipe erases the counter state. `device_binding`
   makes the salt device-unique, so two notyas devices cannot collide even at
   the same sequence number, and no cross-device precomputation is possible.
   A different salt means a different Argon2id output means a different key,
   so the nonce is not carrying uniqueness on its own.
2. **The nonce is bound to the plaintext.** `SHA256(body_plaintext)` is inside
   the HKDF info, so even in the one scenario that could repeat a salt - an
   attacker who restores a full pre-wipe flash snapshot including the counters
   partition, the tier-3 attacker SECURITY.md already concedes - two *different*
   backups still get different nonces. Keystream reuse across different
   plaintexts is structurally impossible, not merely improbable. This is the
   deterministic-nonce discipline that misuse-resistant AEAD designs formalize
   (rationale: https://www.rfc-editor.org/rfc/rfc8452.html); we get the same
   protection by derivation because we cannot get it from the primitive.
3. **The residual leak is disclosed, not hidden.** Deterministic derivation
   means two backups of byte-identical content, taken under the same password
   on the same device at the same counter value, produce byte-identical files.
   An observer holding both learns "nothing changed between these two cards".
   Because `backup_seq` advances on every backup, this only arises from a
   deliberate counter rollback; it leaks no key material and no wallet content.
   Recorded here so no one has to rediscover it during review.

The salt is in the file in the clear. That leaks nothing: it is a SHA-256
image, `device_binding` is a 256-bit HMAC output nobody can guess, and two
backups from the same device carry different salts, so files are not even
linkable to a common device.

Also note what this construction does **not** do: it never derives the backup
key from the master seed. A BIP-85-derived backup password would be elegant and
is exactly the wrong answer - you would need the seed to open the file that
holds the seed. **DECISION: no seed-derived backup passwords in 0.2.0**, in any
flow, because the moment one exists a user will believe they have a backup they
cannot open.

### 2.4 The backup password model versus the device PIN

These are different credentials with different jobs, and conflating them is how
users end up with a 128-bit PIN they cannot type and a 6-digit backup password
protecting their seed on a memory card.

| | Device PIN (ARCHITECTURE 2.2) | Backup password (this file) |
|---|---|---|
| Protects | this device's sealed storage | a file that must open anywhere |
| Entropy source | user-chosen, nudged toward passphrases | **device-guided dice**, 12 BIP-39 words, 128 bits |
| Stretching | Argon2id **plus HMAC-eFuse binding** | Argon2id only |
| Attack model | must execute on this physical device until a fault-injection lab extracts the eFuse key (SECURITY tier 2) | fully offline and parallel from the moment the card is taken |
| Rate limiting | wipe-on-N (Q5, default 15) | none, ever, by construction |
| Floor | 4 characters (Q4) | 128 bits, not user-lowerable |
| Ever stored | no | no |
| Ever in a backup | **no** | no |
| Recovery if lost | wipe and restore from mnemonic | the file is gone; the mnemonic is still the recovery path |

B3's generator is the 0.1.0 dice flow reused verbatim at a different call site:
50 rolls for 128 bits, `mnemonic_from_dice` at 12 words, `Checksum::Valid` by
construction. The words are a BIP-39 phrase for typability and quiz reuse only;
they are **not a wallet**, they derive no keys, and the screen says exactly that
in the same breath as it shows them - otherwise some fraction of users will send
coins to a backup password.

Advanced alternative: a typed passphrase, accepted with the same entropy meter
the PIN screen uses and a blunter warning, because unlike the PIN it has no
device binding behind it. Recommended default remains dice.

### 2.5 Where backups are written

SD only. Flash is not an option: a backup stored on the device it backs up is
not a backup, and it would break the enumerated-writes invariant (SECURITY 2b)
for no benefit.

- Filename `notyas-backup-<seq>.nbk`, where `<seq>` is `backup_seq`. **No
  fingerprint in the filename**: an XFP on a shared memory card identifies the
  owner's wallet to anyone who reads the card, and a multi-wallet backup has no
  single XFP anyway.
- Never silently overwrite. If the name exists, the device says so and offers
  the next sequence number.
- The write is announced before it happens, naming the file and stating in one
  sentence what it contains for the chosen profile ("settings and multisig
  setups, no keys" / "**your seed**, encrypted with the backup password").
- SECURITY.md invariant 2b's SD enumeration gains `notyas-backup-*.nbk` -
  explicitly labeled ciphertext - if OPEN-B1 is accepted. The invariant text
  already reserves the slot for it.

### 2.6 Restore, including onto a different device

Flow: pick file -> password entry -> Argon2id -> AEAD open (tag failure is
reported as "wrong password or damaged file", with no oracle distinguishing
them) -> **review screen** -> selection -> write.

Rules:

- **Restore is additive and reviewed, never destructive.** It lists every
  incoming wallet by label and fingerprint and every incoming registration by
  M-of-N and descriptor checksum, and the user chooses what to import. A
  restore never wipes an existing slot as a side effect. Fingerprint collisions
  with slots already present are shown and skipped by default.
- **Capacity is checked before anything is written**, and if the incoming set
  does not fit in 8 slots the device names exactly what did not fit rather than
  half-restoring.
- **Everything imported is re-sealed under the new device's ladder**: new PIN,
  new `device_binding`, new `kdf_salt`, new `seal_seq`. Nothing from the old
  device's key hierarchy survives the crossing, which is the point.
- **Restore as a temporary seed** (Coldcard's option, and the notyas stateless
  posture) is offered for the full profile: open the file, run a session, write
  nothing. This is the right default for "I just need to sign one thing on a
  borrowed device".
- **The anti-phishing words change, and the device must say so.** They derive
  from the destination device's eFuse key (ARCHITECTURE section 3), so a
  restored wallet on new hardware shows different words. If the restore screen
  does not warn about this, the user either panics or - much worse - learns
  that changed anti-phishing words are normal, which trains away the exact
  reflex the feature exists to build. The user-chosen lock-screen word does
  travel in settings; the anti-phishing words cannot.
- Restore onto a device that has never been provisioned **refuses**, and says so:
  "This device has not been provisioned. Run the provisioning step from the setup
  guide, then restore." **Amended 2026-08-17 by the ratified OPEN-QUESTIONS Q45** - it
  previously said the restore burns the eFuse HMAC key and sets a PIN, reusing the
  first-save provisioning path, and release firmware now contains no eFuse-burn code at
  all. Q45's blast radius named the first-save path but not this one; both refuse.

### 2.7 The password quiz - adapting Coldcard's

Coldcard shows 12 generated words and quizzes the user before proceeding, and
its own documentation notes the quiz "does not verify every word"
(https://coldcard.com/docs/backups/). notyas's UX commandment 3 demands the
opposite for the *seed*: every word, 5 candidates (BitBox02 pattern, UX.md
screen 5).

**DECISION: the every-word quiz stays mandatory for the seed; the backup
password gets a 4-of-12 spot check with the same 5-candidate widget, plus one
sentence of framing.** Reasoning: the two artifacts have different loss
consequences. Losing the seed backup loses the coins; losing the backup
password loses a convenience file whose contents are re-creatable from the seed
(seedless profile: re-import descriptors; full profile: re-derive from the
mnemonic). Grading friction to consequence is commandment 2, and applying
maximum friction everywhere is how users learn to bulldoze through it.

The framing sentence, on the same screen as the quiz, is load-bearing: "this
password opens the backup file. It is not your wallet backup - your seed words
are." A user who believes the .nbk file is their backup has quietly adopted a
worse recovery plan than the one 0.1.0 gave them for free.

For the **full** profile only, the quiz is upgraded to every-word: at that point
the file genuinely does contain the coins and the consequence has changed.

### 2.8 Hostile-file hardening

The restore path parses attacker-supplied data from removable media before any
password is even correct. Non-negotiables:

- **Clamp the header before allocating anything.** `m_kib`, `t_cost`,
  `p_lanes` and `body_len` come from the file. An unclamped `m_kib` is a
  one-byte denial of service and a possible OOM on a device with a fixed PSRAM
  budget. Bounds are pinned in SPEC (upper bound at or below the on-device
  Argon2id parameters chosen in m1) and violations are refused with plain words
  before a single allocation.
- **Reject unknown major versions explicitly**, naming the version and the
  firmware version, rather than attempting a partial parse.
- The AAD covers the whole header, so downgrading `m_kib` or flipping `profile`
  invalidates the tag.
- The body parser is the same style as the sealed record parser: fixed widths,
  length-prefixed, no recursion, every length checked against the remaining
  buffer, and it runs on the *decrypted* body only - a wrong password never
  reaches it.
- Descriptor strings from a backup are re-validated through miniscript and
  re-verified for our-key membership exactly as a fresh import is
  (ARCHITECTURE section 4). A backup is not a trusted channel just because it
  authenticated: the person who holds the password may not be the person who
  made the file.
- Host fuzz corpus: truncation at every offset, bit flips in header and body,
  absurd parameter values, capacity overflow, duplicate XFPs. Same discipline
  as the storage power-loss fuzzer (MILESTONES m3).

---

## 3. Seed XOR

Sources: https://coldcard.com/docs/seedxor/ , https://seedxor.com ,
https://github.com/Coldcard/firmware/blob/master/docs/seed-xor.md

### 3.1 The exact scheme

- Split applies to the **entropy**, not the mnemonic: 16, 24 or 32 bytes for a
  12-, 18- or 24-word seed. All parts and the original must be the same length.
- The BIP-39 checksum bits are **excluded from the XOR** and recomputed per
  part: "for the 'parts' (sometimes called 'shares') this checksum is
  calculated as normal for BIP-39, but those final bits are not used in the XOR
  process". Concretely, the checksum is the last 4 bits of a 12-word phrase and
  the last 8 bits of a 24-word phrase, and each part is therefore a
  fully-valid, checksum-correct BIP-39 mnemonic in its own right.
- Coldcard supports **2, 3 or 4 parts**, and parts combine in any order
  (XOR is commutative and associative).
- Part generation, Coldcard's two modes:
  - **deterministic**: double-SHA256 over a fixed string (`Batshitoshi`), the
    master secret, and the per-part index text (for example `0 of 4 parts`,
    0-based);
  - **random**: bytes from the TRNG, then double-SHA256.
- In both modes the **last part is the XOR of the secret with all other
  parts**, so it is not independently generated and carries the same entropy.

Implementation is trivial: byte XOR over entropy plus the existing
`mnemonic_from_entropy` / `check_phrase` paths in notyas-core. No new
dependency, no new primitive. The work is entirely in vectors and UX.

### 3.2 What notyas does about the RNG, and the property that changes

The random mode is unavailable to us (invariant 3). Two RNG-free options exist,
and they are **not** security-equivalent:

- **B6, dice-generated parts (recommended default).** The user rolls entropy
  for parts 1..N-1 exactly as they do for a seed; part N is the XOR. Parts
  1..N-1 are then uniform and independent of the secret, so any N-1 parts
  reveal *nothing* about the seed - the information-theoretic, one-time-pad
  property that is the whole reason XOR splitting is interesting.
- **B7, Coldcard's deterministic mode.** Every part is a function of the master
  secret. An adversary holding N-1 parts therefore holds enough information to
  determine the seed uniquely; the only thing standing in the way is the
  preimage resistance of double-SHA256. That is a strong wall, but it is a
  **computational** wall where B6 gives an **information-theoretic** one. This
  distinction is not in Coldcard's documentation and it should be in ours.
  Coldcard does record the related consequence: the deterministic approach
  "allows attackers to verify they have a seed that was split by Coldcard".

**DECISION (OPEN-B2 -> OPEN-QUESTIONS Q33, RATIFIED 2026-08-17): dice parts are
the default; deterministic parts ship as the clearly labeled second option -
but behind their OWN confirmation screen, not a one-line label on the same
screen.** The amendment was made when Q33 was ratified, and the reason is the
incentive gradient: only N-1 parts are rolled, so a 24-word seed costs 99 rolls
for 2 parts, 198 for 3 and 297 for 4, while the weaker mode costs zero - which
puts the cheap button in front of the user exactly when they are most fatigued,
and a downgrade from information-theoretic to computational secrecy is not
proportionate to one line of label text. The confirmation screen names the
downgrade in the same style B18 already gets. The label wording stands as the
summary line: "reproducible from your seed; protected by hashing rather than by
mathematics". B7 is worth shipping anyway because it gives (a) reproducibility
- a user who still has the seed can regenerate a lost part - and (b) a
byte-level interop vector against Coldcard, which is exactly the kind of
verifiable equivalence claim this project makes elsewhere. **OPEN-B2** if the
user wants the defaults the other way round.

Cost of dice parts, stated so nobody is surprised: a 3-part split of a 24-word
seed needs two independent 256-bit dice sessions, 99 rolls each. That is the
notyas identity, not an accident, and the screen shows the roll budget up front.

### 3.3 The footguns, plainly

1. **XOR is not Shamir. N-of-N, always.** One lost part is total loss. There is
   no threshold, no recovery, no "3 of 5".
2. **Every part is a valid, fundable wallet.** That is the deniability feature
   and it is also the hazard: a part holder can scan it, see a real wallet, and
   send coins to it. The split screen must state that parts are not wallets and
   must never be funded, and each part's display must be labeled `PART i of N`
   in the same visual weight as the words themselves.
3. **Any wrong subset also produces a valid wallet.** Combining 2 of 3 parts
   yields a perfectly good BIP-39 seed for a wallet with no coins in it, and
   the device cannot tell the user they got it wrong. The only defense is the
   fingerprint: recombine **must** show the resulting XFP and require the user
   to compare it with a value they recorded at split time. The split flow
   therefore prints the original XFP on the completion screen and instructs
   the user to record it with the parts - a split without a recorded XFP is a
   trap set for the user's future self.
4. **Storage correlation.** Two parts in the same fire safe is a one-part
   scheme with extra steps. Said once, in plain words, on the completion screen.
5. **Interaction with passphrases.** Splitting a passphrase-protected wallet
   splits the *seed*, not the passphrase. The parts plus a wrong passphrase is
   a different wallet. Stated on the split screen for any slot that has a
   passphrase attached.

### 3.4 UX implications

- Display: one part per page, mono, numbered words, the same masking and
  no-photograph discipline as the master mnemonic display, plus `PART i of N`
  and the original XFP repeated on every page.
- Re-entry: the existing restore keyboard with prefix completion, run N times,
  with a running "part 2 of 3 accepted" state and per-part checksum validation
  on entry (a mistyped part is caught immediately by its own BIP-39 checksum -
  this is the practical benefit of the checksum-per-part design).
- Result: XFP first, before anything else, then the fork "use as session seed"
  / "save to a slot".
- Part count: **2, 3 and 4 only**, matching Coldcard. There is no reason to
  invent a fifth.

### 3.5 SLIP-39 / Shamir - compare and recommend

SLIP-39 (https://github.com/satoshilabs/slips/blob/master/slip-0039.md) is the
real threshold scheme: Shamir over GF(256) with a two-level group/threshold
structure, the master secret wrapped in a four-round Feistel network keyed by
PBKDF2-HMAC-SHA256, and shares encoded as 20-word (128-bit) or 33-word
(256-bit) mnemonics from a **1024-word** wordlist that is not BIP-39's.

Against notyas it fails on four counts:

1. **It requires a CSPRNG.** The spec is explicit that generation randomizes
   the identifier and the polynomial coefficients and that the randomness
   "MUST be suitable for generating cryptographic keys". A deterministic
   variant is constructible (derive the identifier and coefficients by HKDF
   from the secret) and would still emit standards-valid shares - but it would
   carry the same information-theoretic-to-computational downgrade as 3.2, on
   a scheme whose entire selling point is its mathematics.
2. **It is not BIP-39 compatible.** Converting a BIP-39 seed into SLIP-39
   requires going through PBKDF2-SHA-512 first, yielding 59-word shares, and
   the reverse is impossible. A notyas user's seed cannot be Shamir-split and
   later re-entered as words on any other device.
3. **Effort is L**: GF(256) arithmetic, the Feistel wrapper, a second
   1024-word wordlist in flash, share digests, group logic, and a full vector
   suite - for a feature the target ecosystem (Sparrow, Specter, Core,
   Coldcard) does not consume.
4. **Ecosystem fit**: SLIP-39 is Trezor's world; Coldcard parity does not
   include it, and PARITY.md has no row for it.

**Recommendation: no SLIP-39 in 0.2.0, and no promise of it.** Ship Seed XOR,
document honestly that it is N-of-N and not a threshold scheme, and point users
who need M-of-N at **multisig**, which notyas does support and which is the
better answer to that requirement anyway. Revisit at 0.3.x only if real demand
appears.

---

## 4. BIP-85 deterministic child seeds

Spec: https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki
Coldcard behavior: https://coldcard.com/docs/bip85/

### 4.1 The math and the paths

Derive the hardened path from the master root with BIP-32, take the child
private key `k`, then

```
entropy = HMAC-SHA512(key = "bip-entropy-from-k", msg = k)     # 64 bytes
```

and slice per application. Paths:

| Application | Path | Slice |
|---|---|---|
| BIP-39 words (39') | `m/83696968'/39'/{language}'/{words}'/{index}'` | leading 16/24/32 bytes for 12/18/24 words |
| XPRV (32') | `m/83696968'/32'/{index}'` | first 32 bytes chain code, second 32 bytes private key |
| HD-Seed WIF (2') | `m/83696968'/2'/{index}'` | most significant 256 bits as the secret exponent, compressed WIF |
| Hex (128169') | `m/83696968'/128169'/{num_bytes}'/{index}'` | leading `num_bytes`, 16-64 |
| Password base64 (707764') | `m/83696968'/707764'/{pwd_len}'/{index}'` | base64 of all 64 bytes, sliced to length 20-86 |
| Password base85 (707785') | `m/83696968'/707785'/{pwd_len}'/{index}'` | base85 of all 64 bytes, sliced to length 10-80 |
| Dice (89101') | `m/83696968'/89101'/{sides}'/{rolls}'/{index}'` | BIP85-DRNG with rejection sampling |

Everything is hardened. Language is `0'` for English.

Implementation cost is genuinely small: `derive_path()` arrives in MILESTONES
m2, and `hmac`/`sha2` are already in notyas-core's graph. BIP-85 is roughly
forty lines plus the spec's test vectors, which are the actual deliverable.
**Zero new dependencies.**

### 4.2 Which applications 0.2.0 ships

**DECISION: 39' and 32' in 0.2.0; 128169' in 0.2.x; the rest later or never.**
Reasoning, application by application:

- **39' (B10)** is the one users actually want: a child seed to put in a
  second device, a passphrase-free way to run separate wallets from one backup,
  and the mechanism Coldcard's duress wallets are built on (section 7).
- **32' (B11)** falls out of the same code and covers "give me a child BIP-32
  root" without a mnemonic round-trip.
- **128169' hex (B12)** is a two-line addition once the others exist; no
  urgency, no harm.
- **2' WIF (B13)**: a loose single private key is the same anti-pattern that
  made PARITY classify the WIF Store row as a judgment call. Defer, and if it
  ever ships it ships next to that row's decision, not before it.
- **707764'/707785' passwords (B14)**: display and QR only if ever built.
  The **USB HID keystroke leg is rejected outright** - PARITY marks it class d
  precisely because it reopens the USB data path that the notyas airgap posture
  closes, and no password feature is worth that.
- **89101' dice (B15)**: charming on a dice device and useless there. The user
  has actual dice.

Index range: 0-9999 in the UI, matching Coldcard's default, with an advanced
override. Index selection is a numeric entry, not a list.

### 4.3 Displaying a child seed safely

A BIP-85 child is a full-power seed. It gets the master mnemonic's entire
display discipline - fixed-length masking, paged reveal, no screenshots, wipe
on screen exit - and three additions that the master display does not need:

1. **Provenance is on the screen with the words**: parent XFP, the full
   derivation path, the application and index, and the child XFP. A child seed
   shown without its path is unreproducible, and the user will not remember
   `m/83696968'/39'/0'/12'/7'` from memory.
2. **The relationship warning, stated once and stated bluntly**: this child is
   backed up by the parent's backup and by nothing else; there is no way back
   from the child to the parent; and if the parent has a passphrase, the same
   passphrase is required to ever re-derive this child.
3. **Export routes are display-only in 0.2.0**: on-screen words and, subject to
   OPEN-B5, a SeedQR. No SD write of a child seed - a plaintext seed on
   removable media contradicts SECURITY invariant 2b's enumeration, and no
   parity row requires it.

Then the fork: "use as the session seed now" (B16, Q11-dependent) or "save to a
slot", where saving records the derivation path in the slot metadata so the
wallet list can show the child as what it is rather than as an orphan.

---

## 5. BIP-39 passphrase management beyond 0.1.0

Source: https://coldcard.com/docs/passphrase/ and
https://coldcard.com/docs/temporary-seeds/

### 5.1 The problem being solved

Coldcard states it exactly: each unique passphrase generates an entirely
separate wallet, and "there is no validation performed on your passphrase" -
a mistyped passphrase silently opens an empty wallet with no error. This is one
of the top ways competent users lose funds, and UX.md already makes it
commandment 8 ("a wrong passphrase is a different wallet"). 0.1.0 echoes the
fingerprint, which is the right primitive but leaves the comparison entirely to
the user's memory and notebook.

### 5.2 The 0.2.0 answer: fingerprint-verify-only passphrase slots (B17)

**A named passphrase wallet is a storage slot that holds the parent wallet
reference and the EXPECTED extended fingerprint - and not the passphrase.**

On open: the user types the passphrase, the device derives, compares, and says
**MATCH** or **NO MATCH - this is a different wallet** before any address or
signing screen is reachable. That single comparison converts a silent failure
into a loud one, and it does it without the device ever holding the secret the
user deliberately kept out of it.

This is strictly better than either Coldcard option for the common case:
storing the passphrase (Seed Vault, or the SD passphrase file) puts the whole
wallet on the device, and storing nothing leaves the typo undetected. Storing
only the XFP detects the typo and holds no secret. The XFP does live inside the
AEAD-sealed record, so it is only visible after PIN entry; a coercer with the
locked device learns nothing from it.

**B18** offers the other behavior for users who want it - save the passphrase
inside the sealed slot, making it an ordinary wallet slot - behind the advanced
gate, off by default, with the honest label: "the device will hold your
passphrase. Anyone who has your device and your PIN has this wallet." Note the
marginal-loss argument in the other direction: if a slot already holds the
BIP-39 entropy, adding the passphrase next to it costs nothing incremental. The
default is still verify-only, because for many users the point of a passphrase
is precisely that it is not on the device, and a default that quietly removes
that property is a lie by configuration.

**B19** (Coldcard's SD passphrase file, AES-256-CTR keyed by seed words plus a
hash of the card's serial) is a clean design and a third secret artifact we do
not need once B17/B18 exist. Deferred.

### 5.3 Presentation

- Wallet list cards for passphrase wallets are visually distinct and always
  show **both** fingerprints: parent XFP and this wallet's XFP.
- Creating a passphrase wallet from an existing slot shows the resulting XFP
  and requires the user to confirm it before the slot is written - the same
  "own the fingerprint" gesture UX.md already specifies for restore.
- The empty-wallet trap gets a named screen: opening a passphrase slot whose
  derived XFP does not match the recorded one is a **refusal**, in the same
  refusal-screen family as a policy rejection (UX commandment 10), not a
  warning banner the user can walk past.
- Passphrase entry is the full keyboard, NFKD-normalized on the same discipline
  as the PIN (ARCHITECTURE 2.2) and as BIP-39 requires.

### 5.4 Seed Vault: adopt the UX, reject the construction

Coldcard's Seed Vault stores multiple secrets - TRNG, dice, Seed XOR, TAPSIGNER
backups, BIP-85 children, passphrase wallets, duress wallets - as AES-256-CTR
blobs "encrypted with your master seed's key", with labels and quick switching.

**DECISION: notyas does not build a Seed Vault. The 8-slot PIN-sealed wallet
list already is one, and it is a better one.**

- The construction is the problem: keying stored seeds with *another seed's*
  key creates a compromise chain - whoever recovers the master seed recovers
  every secret in the vault, including ones the user deliberately kept
  separate. notyas's slots are keyed by the PIN ladder (Argon2id + HMAC-eFuse +
  HKDF, ARCHITECTURE 2.2), so slot A's compromise is not slot B's, and no slot
  depends on another slot's secrecy. Adopting Coldcard's construction here
  would be a strict downgrade of a design we already have.
- The UX is worth taking wholesale, and mostly already is in UX.md screen 3:
  labels (40-char cap is a sensible bound), fingerprint as the default label,
  an active-wallet indicator, and one-tap switching. What we add from Seed
  Vault's inventory is that **anything** which produces a seed - Seed XOR
  recombine, BIP-85 child, restored backup, passphrase wallet - ends at the
  same fork: "use once" or "save to a slot". One fork, one save path, one
  storage format.
- Coldcard's own caution transfers verbatim and belongs on the fork screen:
  "we do not recommend handling unencrypted seed material on a regular basis".

**B21 Lock Down Seed** (destructively promote the passphrase-derived secret to
master) is deferred to 0.2.x. It is small, but it is irreversible, its benefit
is mostly covered by B17, and it needs the typed-name danger grade plus its own
"what exactly is destroyed" screen. It should land when there is room to do it
carefully, not as a checkbox.

---

## 6. Seed import and export paths

### 6.1 SeedQR and CompactSeedQR - display

Spec and test vectors:
https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md

- **Standard SeedQR**: each word's BIP-39 index as a zero-padded 4-digit
  number, concatenated (48 digits for 12 words, 96 for 24), encoded in QR
  **numeric** mode at ECC level **L**: 25x25 for 12 words, 29x29 for 24.
- **CompactSeedQR**: the 11-bit indices concatenated as a bitstream with the
  checksum bits dropped (they are recomputable), giving exactly 16 bytes for 12
  words and 32 bytes for 24 - the raw entropy - encoded in QR **byte** mode at
  ECC level L: 21x21 for 12 words, 25x25 for 24.

Matching those exact sizes matters and is not cosmetic: 21x21 and 25x25 are the
grids SeedSigner publishes printable transcription templates for
(https://github.com/SeedSigner/seedsigner/tree/dev/docs/seed_qr), so a symbol
that lands one version larger is un-transcribable onto the paper the user has.

**Concrete dependency on notyas-core (QR):** today `qr::matrix(data: &str)`
encodes byte mode at ECC level M and searches for the smallest version. Neither
SeedQR form can be produced through it - numeric mode and level L are not
selectable, and CompactSeedQR needs arbitrary bytes including `0x00`, `\n` and
`\r` (the SeedSigner vectors deliberately include those cases), which a `&str`
parameter cannot carry. The `qrcode` crate's `Bits` API already exposes numeric
and byte data pushes and explicit versions, so this is an additive API on
qr.rs - a bytes-and-mode entry point alongside the existing string one - not a
new dependency. PLATFORM.md's shortlist item 3 (`seedqr` crate) is where the
index packing itself should live, validated against the published vectors.

**Security note, and this is the one that needs a decision.** UX.md section 4
carries a 0.1.0 masking discipline: "no-QR-from-secret screens". A SeedQR is by
definition a machine-readable QR of the seed. It is the single most dangerous
thing this device can put on a screen: a camera across the room, a phone in a
pocket, a reflection - all of which defeat the mono-font mnemonic display's
implicit protection that a human has to read and transcribe it. Adopting B22/B23
means writing an exception into a stated discipline, which is exactly the sort
of thing SECURITY.md says must be decided deliberately. Proposed shape if
accepted (**OPEN-B5**):

- a distinct **secret-QR screen class**, reachable only from Advanced / Seed
  Tools, never from any flow that untrusted input can steer;
- an explicit "this QR is your seed - anything that can see this screen can
  take your coins" screen the user must pass;
- hold-to-reveal, and a short auto-blank timeout with no keep-alive;
- a golden-image test asserting the screen is unreachable from every other
  path, in the same style as the existing masking pixel tests.

### 6.2 SeedQR scan-in (B25)

Camera-dependent; see CAMERA.md (recommended path 1: CSI + OV5647 on the
Waveshare 4B, `rqrr` for decode). Scanning is the easy half - the decoder hands
back either a digit string or 16/32 raw bytes, both of which map directly to
the same index-unpacking code that produced them. The rule: a scanned seed
follows **exactly** the same path as a typed one - checksum validated, XFP
displayed, "use once / save" fork - with no shortcut for having arrived by
camera. If the camera path is not approved, B25 slips to 0.3.0 and PARITY's
"Scan seed via QR" row stays class c for one more release, which CAMERA.md
already treats as an acceptable outcome.

### 6.3 Guided transcription (B24)

SeedSigner's flow walks the user through inking a printed grid module by
module. It is the reason CompactSeedQR exists at all - a 21x21 grid is 441
cells, transcribable by hand onto paper or a metal plate in a sitting; a 29x29
is 841 and is not. notyas has a far better screen for this than a SeedSigner
does: 720x720 can show a readable magnified region with row and column rulers
and a "you are here" cursor.

Tier M, 0.2.x. It is polish on top of B23 and should not compete with the
backup work for 0.2.0 slots. It inherits the entire secret-QR screen class.

### 6.4 Manual entry and the final-word calculator (B26, B27)

What notyas-core already has: `words_with_prefix` (live prefix filtering to
valid BIP-39 words), `current_word_fragment`, `check_phrase` (word count,
unknown words, checksum verdict, and the recovered entropy, all zeroized on
drop). UX.md screen 6 wires these into the restore keyboard.

What it does **not** yet have, despite being one function away: the final-word
enumerator. Given the first `n-1` words, the last word carries `11 - CS` free
entropy bits and `CS` checksum bits, so the number of valid last words is
`2^(11-CS)`:

| Phrase | ENT | CS | Valid last words |
|---|---|---|---|
| 12 words | 128 | 4 | 128 |
| 15 words | 160 | 5 | 64 |
| 18 words | 192 | 6 | 32 |
| 21 words | 224 | 7 | 16 |
| 24 words | 256 | 8 | 8 |

Implementation is a loop over the 2048 candidate indices reusing the existing
checksum code, returning the ones that validate. Tier S, no new dependency, and
it belongs in notyas-core with the rest of the BIP-39 surface so BigDice
equivalence testing covers it.

The wording trap, and it is the whole risk of this feature: a user who
**picks** a last word from the list gets a *different wallet* from the one whose
last word they were trying to recover. The calculator's legitimate uses are
recovering a smudged or ambiguous final word (where the user checks which
candidate matches what they can still read) and completing a hand-built seed.
The screen must therefore lead with "these are the words that would make a valid
phrase - only one of them is your wallet", show the resulting XFP for whichever
candidate is selected, and never present the list as a menu of equivalent
choices. Two lines of copy separate a recovery tool from a fund-loss machine.

---

## 7. Duress and plausible deniability - restated, not re-decided

This section exists to record what an honest duress feature costs and how it
collides with the rest of this cluster. **The decision belongs to
OPEN-QUESTIONS Q2 and is not reopened here.**

What Coldcard does: a Trick PIN opens a duress wallet derived from the master
seed, so it needs no separate storage - modern duress wallets are BIP-85
children (indices 1001/1002/1003 for a 24-word master, 2001/2002/2003 for
12-word), with a legacy fixed path `m/2147431408'/0'/0'` where 2147431408 =
0x80000000 - 0xCC10 (https://coldcard.com/docs/pins/). That derivation is a
free ride on B10 - if BIP-85 ships, the duress *wallet* costs nothing.

What is not free is the **deniability**, and the red-team pass established that
the drafted design does not have it. Two independent leaks, both recorded in
Q2 and SECURITY.md:

1. **Slot occupancy is visible in a pre-PIN flash dump.** A coercer who sees
   three occupied slots and is shown one decoy wallet knows they are being
   played.
2. **The Verify screen reports the true wallet count** ("N sealed slots"), to
   anyone holding the device, with no PIN.

The honest price of fixing them, per Q2 option (a): unused slots permanently
filled with device-bound pseudorandom filler; wipe and delete rewriting filler
rather than leaving erased-flash signatures; and the Verify screen's storage
readout permanently degraded to "present / blank" **for every user**, whether
or not they ever enable duress - because a readout that changes when duress is
enabled is itself the marker. That last item is a real, permanent cost to
SECURITY.md invariant 5's honesty, paid by everyone, to buy a property some
users need.

**This cluster adds one item to Q2's package, and it is cheap: the backup file
has the same leak.** A variable-length backup whose size tracks the number of
wallets betrays the count to anyone who reads the card, which would undo the
flash padding for any user who ever makes a backup. B29 closes it by padding
the backup plaintext to a constant size (2.2) - roughly 11 KiB regardless of
contents. Because it costs nothing and requires no decision, **B29 ships
whether or not Q2 accepts duress**; it is simply free metadata hygiene.

Two further interactions to record for whoever closes Q2:

- **Whether the duress configuration itself travels in a backup.** If it does,
  the backup betrays the duress wallet's existence to anyone who compels the
  backup password - which is the same person the feature exists to defeat. If
  it does not, a restored device silently loses the duress setup and the user
  may not notice. Recommendation for Q2's author: exclude duress configuration
  from the standard backup, and say so on the restore review screen.
- **Seed XOR is the low-tech deniability feature that needs no package at all.**
  A single XOR part is a valid, fundable, plausible wallet held on paper, with
  no device state, no slot occupancy, and nothing for a flash dump to reveal
  (seedxor.com frames it exactly this way). If Q2 lands on option (c) - drop
  duress - B6/B8 remain a real, honest answer to the same user need, and that
  is worth weighing in the Q2 decision rather than treating the two as
  unrelated features.

---

## 8. Where this lands in the schedule

MILESTONES.md is owned elsewhere; this is a recommendation for its
reconciliation, not an edit.

- **B26, B27** (manual entry, final-word calculator): m4b, with the restore
  keyboard. Both are notyas-core plus UI.
- **B6, B7, B8, B10, B11, B16, B17, B18** (Seed XOR, BIP-85, passphrase
  slots): one **Advanced / Seed Tools** screen introduced after m4b, since all
  of them need storage and the session type and none of them need SD, PSBT or
  multisig. This is the natural "m4c" and it is mostly notyas-core math plus
  one menu.
- **B22, B23, B24** (SeedQR display and its transcription flow): **dropped.** Q17 is
  ratified and display-out is declined; PARITY's SeedQR row is satisfied by scan-in
  (B25) and documented as deliberately declined for output.
- **B1-B4, B29** (backup and restore): **after m7**, because the backup's
  headline content is the multisig registry and there is no point serializing a
  registry format twice. Its own milestone slot, roughly m7b, ahead of m8's
  UR2 work.
- **B25** (SeedQR scan): with the camera bring-up, wherever CAMERA.md lands.
- **B28** (duress): m9, per Q2.
- **B5, B12, B13, B14, B19, B21**: 0.2.x and later, in that rough order. (B24 was in
  this list and is dropped with B22/B23 under the ratified Q17.)

Total new dependencies added by this entire cluster: **zero**. Everything here
is arithmetic over primitives ARCHITECTURE already admits (sha2, hmac, argon2,
chacha20poly1305, hkdf, bitcoin) plus an additive API on the existing `qrcode`
usage. That is a deliberate property, and it is worth protecting during
implementation: if a feature in this cluster starts asking for a crate, the
feature is wrong, not the rule.

---

## 9. Open items - status after the 2026-08-17 ratification

**Status line, so nobody has to cross-reference:** OPEN-B1 -> **OPEN-QUESTIONS Q14,
STILL OPEN and the project owner's** (it would amend the invariant that forbids key
material on removable media, which is a doctrine change). OPEN-B2 -> Q33, **RATIFIED**
(dice default, deterministic behind its own confirmation screen). OPEN-B3/B5 -> Q17,
**RATIFIED AGAINST this document's recommendation** (display-out declined; B22-B24
dropped; the invariant-2 QR corollary restored to plan-0.2.0/SECURITY.md 2a, which had
silently lost it). OPEN-B4 -> Q34, **STILL OPEN and the project owner's** (publishing a
format is a standing compatibility commitment); its crate half is answered by Q8 -
GPL-3.0-or-later, nothing published, so it is a document, not a crate.

**OPEN-B1. Ship encrypted backup and restore in 0.2.0, reversing
OPEN-QUESTIONS Q8 [wave-1 numbering; the question is now Q14]?** Q8 currently recommends deferral, on reasoning written
before the plan added multisig registrations and settings - state that no
mnemonic can re-derive (2.0). RECOMMENDATION: **yes**, with the two-profile
split - seedless as the default offer, seed-bearing behind the advanced gate -
so Q8's "do not push a second copy of the seed onto SD" concern is preserved
while the non-re-derivable state gets a recovery path. If overruled, B1-B4 slip
to 0.2.x and the wipe-on-N setup screen must be amended to state that a wipe
also destroys multisig registrations.

**OPEN-B2. Seed XOR default part-generation mode.** Dice parts give
information-theoretic secrecy at the cost of 50-99 rolls per part; Coldcard's
deterministic mode is reproducible and interop-testable but downgrades the
guarantee to preimage resistance (3.2). RECOMMENDATION: dice default,
deterministic as the labeled second option, both shipped.

**OPEN-B3. SeedQR display as an exception to the "no QR from secret screens"
discipline** (6.1). RECOMMENDATION: accept, with the secret-QR screen class -
explicit warning gate, hold-to-reveal, auto-blank, reachability test. If
rejected, B22-B24 are dropped and PARITY's SeedQR rows are documented as
deliberately declined rather than pending, which is a defensible position for a
device with a 720x720 mnemonic display.

**OPEN-B4. Publish the backup container format and its reference decoder as a
public spec (and the `seedqr` crate per PLATFORM.md shortlist item 3)?** The
in-repo decoder tool is a release gate either way (2.2); the question is
whether the format is also written up for other implementers.
RECOMMENDATION: yes for the format document, since a backup format nobody else
can read is lock-in by omission; the crate decision follows PLATFORM.md's
licensing question.

Deferred to existing questions rather than duplicated here: duress and its
padding package (Q2, with the backup-padding addendum in section 7),
stateless-session use of BIP-85 children (Q11), Argon2id parameters that the
backup header inherits (m1 benchmark).

---

Sources cited in this document:
https://coldcard.com/docs/backups/ ,
https://coldcard.com/docs/seedxor/ ,
https://seedxor.com ,
https://github.com/Coldcard/firmware/blob/master/docs/seed-xor.md ,
https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki ,
https://coldcard.com/docs/bip85/ ,
https://coldcard.com/docs/passphrase/ ,
https://coldcard.com/docs/temporary-seeds/ ,
https://coldcard.com/docs/pins/ ,
https://github.com/satoshilabs/slips/blob/master/slip-0039.md ,
https://github.com/SeedSigner/seedsigner/blob/dev/docs/seed_qr/README.md ,
https://github.com/SeedSigner/seedsigner/tree/dev/docs/seed_qr ,
https://py7zr.readthedocs.io/en/latest/archive_format.html ,
https://www.rfc-editor.org/rfc/rfc8452.html

Input to: MILESTONES.md and OPEN-QUESTIONS.md reconciliation
