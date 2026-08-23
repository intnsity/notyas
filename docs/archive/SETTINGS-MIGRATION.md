# Migrating a board to the 0.2.0 partition table (the `settings` region)

Status: operator procedure, written 2026-08-19. Read the whole page before touching a
board; it is four commands and one thing you must not misunderstand about eFuses.

## What changed, in one paragraph

0.2.0 appends one partition to `firmware/partitions.csv`:

```
settings, data, undefined, 0x460000, 64K
```

It holds the public values the device has to read BEFORE a PIN - the device name the lock
screen draws, and the network choice. Until now those lived in RAM and did not survive a
power cycle, because the table had nowhere to put them: the sealed store is unreadable
until the unlock the name is displayed in front of, and there is deliberately no NVS.

**Nothing that already existed moves.** `factory` stays at `0x10000`, `wallets` at
`0x410000`, `counters` at `0x450000`. The new region is appended into space no partition
has ever described. The Verify screen's running-partition SHA256 procedure is unchanged
because the app offset is unchanged.

| Name | Offset | Size | End |
| --- | --- | --- | --- |
| `factory` | `0x10000` | 4 MiB | `0x410000` |
| `wallets` | `0x410000` | 256 KiB | `0x450000` |
| `counters` | `0x450000` | 16 KiB | `0x454000` |
| *(gap - alignment reserve)* | `0x454000` | 48 KiB | `0x460000` |
| `settings` | `0x460000` | 64 KiB | `0x470000` |

## The eFuse question, answered first because it is the one that cannot be undone

**The Elecrow's provisioning survives this, and survives a full chip erase.** The
device-binding key lives in eFuse `BLOCK_KEY5`, burned and read-protected. eFuses are
one-way silicon; a partition-table reflash does not touch them and neither does
`espflash erase-flash`. After either, the first boot recomputes
`device_binding = hmac_efuse(0x01, domain_tag)` from the burned key, `KeyProvenance` still
reads `EfuseReadProtected`, and a fresh FORMAT writes that binding into the new superblock
as `device_tag`. There is no step in this procedure that can cost you the key.

The Waveshare is unprovisioned by design and runs the emulated key
(`--features unsafe-emulated-key`). It has nothing to lose either.

**What CAN be lost is the sealed store contents** - the dev wallets on the bench boards -
and only if you choose the clean-slate path in step 3. The owner has said those are
expendable. This change does not force it: no offset moved, so a device reaching this table
by reflash keeps its store mountable.

## The procedure

### 1. Build

From the repository root:

```powershell
.\tools\build.ps1 -Board elecrow-5    --features hil-console
.\tools\build.ps1 -Board waveshare-4b --features unsafe-emulated-key
```

### 2. Flash each board

```powershell
.\tools\flash.ps1 -Board elecrow-5    -Port <port>
.\tools\flash.ps1 -Board waveshare-4b -Port <port>
```

`flash.ps1` hands `firmware/partitions.csv` to espflash directly, so the updated table
lands at `0x8000` with the app and the bootloader.

**The new region needs no erase, and this does not depend on it being blank.** Nothing has
ever written above `0x454000` on either bench board - the app partition ends at `0x410000`
and no image reaches past it - so `0x460000-0x470000` is expected to read `0xff`, but the
firmware does not rely on that expectation: blank, zeroed, or full of some previous
experiment's bytes, the reader validates magic, length and CRC and treats anything that
fails as "no valid slot", which is the same state as "defaults". (The m4a 40-scan evidence
is sometimes cited for this span; it is not evidence about it - those scans cover the
`wallets` region's 64 sectors, including its reserved tail, and nothing above `0x450000`.)
The board boots straight into an unnamed device on mainnet either way.

### 3. Optional clean slate

Only if you want the dev wallets gone as well:

```powershell
espflash erase-flash --port <port>
```

Then flash as in step 2. The store then reports `NotProvisioned` / blank and a fresh FORMAT
runs at PIN setup. eFuses are untouched (see above).

### 4. Confirm it worked

1. Boot the board. The log line to look for is
   `settings: device name <unnamed> | network Mainnet` - it is printed before the first
   frame, which is the proof that the read happens pre-PIN and needs no key.
2. Settings -> Device name, type a name, Save.
3. Power-cycle the board. **The name must be on the lock screen.** That is the whole point
   of this change.
4. Toggle the network on the Settings screen, power-cycle, confirm it stuck.
5. Verify screen: the running-partition SHA256 procedure is unchanged and its rows should
   read exactly as they did before this table.

## Rolling back

Flash a pre-0.2.0 build and its table. The `settings` region simply stops being looked up;
its bytes sit in a span the old table does not describe, and the old firmware neither reads
nor writes them. Nothing in the sealed store depends on it.

## What a device without the region does

Nothing bad, and this is tested rather than asserted: an absent partition, a blank region,
a torn write and a corrupted record all resolve to the same defaults. A board still running
an older table boots unnamed on mainnet with no error on the panel, and a name typed on it
works for the life of the power-up exactly as it did before the region existed. The panel
only reports a failure when the region IS present and the write to it failed, because that
is the only case an operator can act on.

## Two things not to do to this region

- **Do not put anything in it that an attacker rewriting it would gain from.** It is
  plaintext and unauthenticated, and no MAC would change that. The rule and the exclusion
  list - wipe policy, attempts-left, boot counter, wallet occupancy, device words,
  provisioning state - are in `crates/notyas-wallet/src/settings.rs` and in
  OPEN-QUESTIONS Q64.
- **Do not move it to make the map rounder.** Its end at `0x470000` is 64 KiB aligned so
  that 0.3.0's `otadata` and second app slot can be appended there without moving anything
  that has shipped (SECUREBOOT.md 7, 8.2).
