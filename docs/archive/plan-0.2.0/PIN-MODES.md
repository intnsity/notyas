# notyas 0.2.0 - PIN and wipe: the three device states

Owner-directed design, 2026-08-17. This file is authoritative for the PIN / wipe /
stateless behaviour and supersedes any earlier text in ARCHITECTURE.md 2.x,
UX-SCREENS.md S-06/S-08/S-44 or OPEN-QUESTIONS Q4/Q5 that conflicts with it.

The owner's requirement: a person must be able to run the wallet with no PIN and no
wiping if that is what they want, the protective settings should be the defaults, and
turning the PIN off must sit behind a modal that stops a careless tap.

## The distinction that must not be inverted

There are two different "off" switches here and they carry opposite kinds of risk. A
design that treats them as one setting will teach users the wrong lesson about their own
device.

- **No PIN** means **no stored secret**. There is nothing on the device to brute-force
  and nothing to extract. This is the safest state the hardware can be in. Its cost is
  convenience, not security.
- **PIN set, wipe disabled** means a secret **is** stored and is defended only by how
  long guessing takes. This is the only genuinely weakened configuration, and it is
  where a warning belongs.

## The three states

### State 1 - Stateless (default)

No PIN, nothing written. Identical to 0.1.0 behaviour: the seed exists in RAM for the
session and is gone at power-off. A device that has never saved a wallet is in this
state and never asks for a PIN.

Supported permanently and as a first-class mode, not a degraded one. It is the
SeedSigner model and it is a legitimate way to own this device.

### State 2 - PIN set, wipe on (default once anything is saved)

The PIN is introduced at the moment the user first chooses to save a wallet, not at
first boot. Wipe-after-15 is on by default from that point. This is the recommended
configuration and the one the documentation leads with.

### State 3 - PIN set, wipe off

Permitted. The stored secret is then protected only by guess resistance, and the
eFuse-bound key ladder does not help here: it defeats *offline* attack, but someone
holding the device can guess on the device itself. At the 4-digit floor that is on the
order of 10,000 attempts at Argon2id speed.

The warning shown when disabling wipe must be computed from the user's **actual** PIN
length, which the device knows, rather than stated in the abstract. A 4-digit PIN and a
12-character PIN are not the same decision and should not produce the same sentence.

DECIDED 2026-08-17 by the owner: disabling wipe does NOT require a longer PIN. The
4-digit floor applies in every state. The warning still states the concrete guess count
for the PIN length in use, so the user makes the trade knowingly; the device does not
withhold the setting from them.

## Non-negotiable: the policy lives inside the AEAD

The wipe policy (N, and whether wipe is enabled at all) MUST be authenticated inside the
sealed record, covered by the AEAD's associated data alongside `wipe_epoch` and
`seal_seq`. If policy can be altered without the PIN, an attacker holding the device
turns wipe off and then guesses freely, and the attempt counter was never protection at
all - it was theatre.

This makes a user-settable N a change-PIN-class operation: it re-seals under the
existing PIN, commits power-loss-safely by the same rules, and cannot be performed from
a locked device. The m3 format freeze must carry it.

## Modal design

**Turning the PIN off** is primarily a **data-loss** event, not a security downgrade,
and the copy must say so accurately. It destroys every sealed wallet, multisig
registration, label and setting, because the key that decrypts them is derived from the
PIN being removed. The modal must:

- name what is destroyed, with counts read from the store (for example the number of
  wallets and registrations), not a generic phrase;
- state that the device will return to storing nothing at all;
- require a typed confirmation, not a single tap;
- NOT claim the device is becoming less secure. It is becoming a device that stores
  nothing, which is the safest state available. Saying otherwise is false and teaches
  the wrong instinct.

**Disabling wipe** is the inverse: no data is lost, and the security consequence is
real. That modal states the concrete guess count for the PIN length in use, and offers
the longer-PIN path rather than only an accept/cancel choice.

**Setting a PIN for the first time** needs no warning modal. It is the protective
direction and should feel routine.

## Consequences for other documents

- UX-SCREENS.md: S-06 (PIN create) is reached from the save-a-wallet flow, not from
  first boot. S-44 (settings) carries the two modals above with distinct copy. The
  post-wipe screen already exists and applies to the PIN-off path.
- SECURITY.md: the guarantee tiers must describe all three states. State 1 has no
  stored-secret threat surface to describe, and saying so plainly is more useful than
  omitting it.
- ESP-SEAL.md: `wipe_after` gains a disabled sentinel, and policy joins the AEAD's
  associated data. The floor of 3 stands for enabled values.
- The release documentation should present State 1 and State 2 as two supported ways to
  use the device, chosen by whether the user ever saves a wallet.
