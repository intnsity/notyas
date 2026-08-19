# notyas - eFuse provisioning (PROVISION ceremony)

One command burns one eFuse key block per device. It is irreversible. This file is the
concrete, verified form of ESP-SEAL.md 4.3 (P1-P5) and ratified OPEN-QUESTIONS Q45, and it
exists because Q45 required the block-selection rule and the retry budget to live in a
user-facing document rather than in a design note.

Release firmware contains no eFuse-burn code. Provisioning is a host step, performed once
per device with `espefuse`, and 0.2.0 performs exactly one burn (ratified Q63 (a)): no
secure-boot digest, no anti-rollback fuse, no flash-encryption key.

## What gets burned

A 32-byte host-CSPRNG key into one of the six 256-bit key blocks, with `KEY_PURPOSE` set
to `HMAC_UP`. The sealed-storage device binding is rooted in it: `device_binding =
hmac_efuse(0x01, domain_tag)`, which is what makes every PIN guess require this physical
board.

The firmware does not hardcode a block index. `esp_idf_hmac::key_block::require` calls
`esp_efuse_find_purpose`, so it discovers whichever block carries `HMAC_UP`. Any block
therefore works, which is why the selection rule below is about future budget and not
about correctness.

## Block-selection rule

**Burn `BLOCK_KEY5`, working downward if it is already spent.**

The reasoning is the 0.3.0 budget, not this release. Secure Boot v2 can enrol up to three
signing keys and therefore up to three digest slots, so `BLOCK_KEY0`, `BLOCK_KEY1` and
`BLOCK_KEY2` are held for `SECURE_BOOT_DIGEST0..2`; `BLOCK_KEY3` is held for a possible
flash-encryption XTS key. Taking the top block leaves the whole low range contiguous and
uncommitted.

**Retry budget, stated plainly because it is thinner than "six blocks" suggests.** With
one secure-boot signing key the allocation is one digest slot, one XTS key, one HMAC_UP
key, three spare. With three signing keys enrolled it is one spare. A block can never be
re-burned: recovery from a failed burn is always a different block and a freshly generated
key.

Burning an HMAC key does not brick a board. It consumes a block.

## The ceremony

Substitute the port for the device you are provisioning. Board identity is worth checking
before an irreversible step: `esptool --chip esp32p4 -p COM6 flash-id` prints the flash
size and MAC, and the two bench boards differ (Waveshare 4B is 32 MB, Elecrow 5 is 16 MB).

```
P1  Generate 32 bytes from the host OS CSPRNG into a file on LOCAL disk.
P2  espefuse --chip esp32p4 -p <PORT> burn-key BLOCK_KEY5 <keyfile> HMAC_UP
P3  (already done by P2 - see below)
P4  Shred the key file. There is no escrow, by design.
P5  Firmware boots, computes device_binding, and writes it into the superblock as
      device_tag during FORMAT.
```

**P3 is not a separate step with espefuse v5.3.1, and ESP-SEAL 4.3's `write_protect_efuse`
plus `read_protect_efuse` pair is redundant against this tool version.** `burn-key`
already write-protects the key purpose, read-protects the block and write-protects the
block in the same operation, unless `--no-read-protect` or `--no-write-protect` is passed.
Verified against the real end state, not inferred from the help text. Do not pass either
flag: a block that was burned but never read-protected produces the weaker
`KeyProvenance` tier, and the product must then say so.

The key file must not be written anywhere that is mirrored, synchronised or backed up. It
is worthless after the burn - the block is unreadable to everything including a
JTAG-attached debugger - but it is a live secret between P1 and P4.

## Rehearsing without hardware

`espefuse --virt --chip esp32p4 --path-efuse-file <file>` runs the entire ceremony against
a virtual chip and leaves an inspectable eFuse image. Rehearse there and diff the end
state against the acceptance table below before touching a board. This costs nothing and
it is the only way to be sure of an irreversible command.

## Acceptance check

After the burn, `espefuse --chip esp32p4 -p <PORT> summary` must show all of:

| Field | Required value | Meaning |
|---|---|---|
| `KEY_PURPOSE_5` | `HMAC_UP (0x8)`, shown `R/-` | purpose set and write-protected, so the block can never be repurposed |
| `RD_DIS` | bit for that block set (`0b0100000` for KEY5) | block is read-protected |
| `WR_DIS` | block and purpose bits set (`0x10002000` for KEY5) | block and purpose are write-protected |
| `SECURE_BOOT_EN` | `False` | 0.2.0 burns no secure boot (Q32) |
| `SPI_BOOT_CRYPT_CNT` | `Disable` | 0.2.0 burns no flash-encryption key (Q63) |
| `DIS_DOWNLOAD_MODE` | `False` | the board is still reflashable, which the release depends on |

**A zero readback does not prove read protection on its own.** Dumping the block after the
burn returns 32 zero bytes, but so does a block that was never burned. The discriminating
evidence is `RD_DIS` carrying that block's bit, together with the burn's own
`BURN BLOCK9 - OK (write block == read block)` verification, which happens before read
protection is applied. Check the fuse, not the dump.

## Irreversibility ladder

1. Burning the key block - one of six consumed.
2. Setting `KEY_PURPOSE` to `HMAC_UP` - the block can never serve another purpose.
3. Read-protecting the block - the key value is gone from every perspective. Point of no
   return.
4. Write-protecting the block and its purpose - belt and braces.

## After the burn: the existing store mounts as Foreign

Verified on board B, 2026-08-18, immediately after the `BLOCK_KEY5` burn. Expect it, it is
correct behaviour, and clearing it takes the host rather than the device.

The device binding is `hmac_efuse(0x01, domain_tag)`, so the burn CHANGES it. A store
formatted earlier under `KeyProvenance::Emulated` carries a `device_tag` the board no
longer computes, and `Vault::mount` refuses it as `Foreign`. That refusal is the design
doing its job - it is what stops a moved board or a transplanted flash chip from silently
reinterpreting someone's records - but the practical effect on the bench is a device that
falls back to the stateless flow with no store at all.

The obvious recovery does not work. With the mount refused the firmware holds no store, and
the HIL console rejects every store command, `erase` included, with `err=store_unavailable`
(docs/KNOWN-ISSUES.md K3). Until K3 is closed, recovery is host-side.

Erase the two data partitions and let the firmware format a fresh store. **Take the offsets
from `firmware/partitions.csv`**, which is the table `tools/flash.ps1` hands to espflash and
therefore the one on the board - not from ARCHITECTURE 2.7, whose table is marked SUPERSEDED
and does not match what is flashed today. For the current table:

```
esptool --chip esp32p4 -p COM6 erase-region 0x410000 0x40000   # wallets,  256 KiB
esptool --chip esp32p4 -p COM6 erase-region 0x450000 0x4000    # counters,  16 KiB
```

Then power-cycle the board and run `format <pin>` on the HIL console. Both commands are
esptool v5.3.1 spelling (`erase-region`, hyphenated); v4 spells it `erase_region`. The end
state to expect is the `status` line reporting provenance `eFuse HMAC_UP key,
read-protected` and a state of `formatted` with one PIN identity, which is what board B
reported after this procedure.

Two cautions, because this is a destructive procedure that looks routine.

- Erasing `wallets` destroys every sealed record permanently. A seed is re-derivable from
  the user's own dice rolls or mnemonic; labels, settings and multisig registrations are
  not, and 0.2.0 has no backup for them (SECURITY.md wipe posture). This is a bench
  procedure for a store you already know to be worthless, never a field recovery.
- Erasing `counters` resets the attempt log and the boot counter. On a product unit that is
  precisely the tamper those counters exist to reveal. It is acceptable here only because
  the store they counted for is being discarded in the same breath.

## Provisioning record

| Date | Board | Port | Flash | MAC | Block | Purpose | Outcome |
|---|---|---|---|---|---|---|---|
| 2026-08-18 | B - Elecrow CrowPanel 5inch | COM6 | 16 MB (GigaDevice, dev 0x4018) | `e8:f6:0a:e1:a4:9e` | `BLOCK_KEY5` | `HMAC_UP` | burned, read- and write-protected, acceptance table green |

Board A (Waveshare 4B, COM3, 32 MB) is deliberately **never burned** and runs
`KeyProvenance::Emulated` for UI and logic work, per ESP-SEAL 6.3.
