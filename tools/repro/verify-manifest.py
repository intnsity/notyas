#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# notyas - verify-manifest.py
#
# Produces and checks notyas-<ver>-<board>-VERIFY.json, the per-board release
# verification manifest (docs/plan-0.2.0/VERIFY.md 7.3, ratified Q52).
#
# Why this tool exists at all, in one sentence: the number the device prints for
# its app image is the digest of the image CONTENT, while the number in
# SHA256SUMS.txt is the digest of the FILE, the two differ by the 32 appended
# bytes, and VERIFY.md calls confusing them the single most likely way an honest
# verification attempt fails. Publishing both numbers, signed, removes the
# arithmetic from the user's path.
#
# Why Python and not Rust, which is this project's default: this file must run
# unchanged inside the ESP-IDF release container (which ships a Python and no
# cargo registry), on a verifier's machine with nothing installed, and on the
# Windows bench. It uses the standard library only. Adding a workspace crate
# would also put release tooling into the dependency graph that
# tools/build-graph-check.sh polices, for no gain.
#
# Everything here is derived from the artifacts. Nothing is taken on trust and
# nothing is passed in that can be recomputed: offsets come out of the partition
# table, the app version comes out of the image's own descriptor, and every
# digest is taken over bytes read from the file.

from __future__ import print_function

import argparse
import binascii
import hashlib
import json
import os
import struct
import sys

# ---------------------------------------------------------------------------
# Constants. Each is a fact about the ESP32-P4 boot layout or about a frozen
# notyas format, not a preference.

IMAGE_MAGIC = 0xE9  # esp_image_header_t.magic
APP_DESC_MAGIC = 0xABCD5432  # esp_app_desc_t.magic_word
BOOTLOADER_DESC_MAGIC = 0x9B  # esp_bootloader_desc_t.magic_byte
PT_MAGIC = 0x50AA  # ESP_PARTITION_MAGIC
PT_MD5_MAGIC = 0xEBEB  # ESP_PARTITION_MAGIC_MD5
PT_ENTRY_LEN = 32  # sizeof(esp_partition_info_t)
PT_MAX_LEN = 0xC00  # ESP_PARTITION_TABLE_MAX_LEN

# ESP32-P4 puts the second-stage bootloader at 0x2000, not 0x0 and not 0x1000:
# the first two sectors are reserved for the Key Manager (VERIFY.md 2.2, quoting
# bootloader/Kconfig.projbuild). The ROM decides this; it is not settable.
BOOTLOADER_OFFSET = 0x2000
PT_OFFSET = 0x8000

# VERIFY.md 2.4. An 18-byte ASCII tag, a terminator, then three
# (u32le length, 32-byte digest) pairs in ascending offset order.
FW_DIGEST_TAG = b"notyas-fw-digest/1"

MANIFEST_FORMAT = "notyas-verify-manifest/1"
READOUT_FORMAT = "notyas-verify/1"

# The frozen key order of VERIFY.md 7.3, plus the partition table's file digest
# that section 2.3 requires beside its used-length digest, for the same
# both-numbers reason the app image needs. The order is frozen because the
# manifest is read by humans and by diff, and because reordering a signed
# artifact is an invisible change.
MANIFEST_KEYS = [
    "format",
    "version",
    "board",
    "app_image_sha256",
    "app_image_len",
    "app_file_sha256",
    "app_offset",
    "bootloader_image_sha256",
    "bootloader_image_len",
    "bootloader_offset",
    "bootloader_file_sha256",
    "partition_table_sha256",
    "partition_table_len",
    "partition_table_offset",
    "partition_table_file_sha256",
    "partition_table_csv_sha256",
    "firmware_digest",
    "secure_version",
    "partitions",
]


class Fail(Exception):
    """A refusal to produce or accept a manifest. Never a warning in disguise."""


def hexs(b):
    return binascii.hexlify(b).decode("ascii")


def hexoff(n):
    # 0x00010000, the form the device readout prints (VERIFY.md 7.2), so a
    # manifest field and a screen field compare as strings without reformatting.
    return "0x%08x" % n


def u16(b, off):
    return struct.unpack_from("<H", b, off)[0]


def u32(b, off):
    return struct.unpack_from("<I", b, off)[0]


def byte_at(b, off):
    # bytes[i] is an int on py3 and a str on py2; this file targets py3 but the
    # container's python is not ours to choose, so index defensively.
    v = b[off]
    return v if isinstance(v, int) else ord(v)


def cstr(b, off, size):
    raw = b[off:off + size]
    end = raw.find(b"\x00")
    if end >= 0:
        raw = raw[:end]
    return raw.decode("ascii", "replace")


def read_file(path):
    with open(path, "rb") as fh:
        return fh.read()


def sha256_file(path):
    return hashlib.sha256(read_file(path)).hexdigest()


# ---------------------------------------------------------------------------
# ESP image parsing.
#
# Layout: esp_image_header_t (24 B), then per segment an
# esp_image_segment_header_t (8 B) and its data, then padding and a one-byte
# checksum such that the length up to and including the checksum is a multiple
# of 16, then - when the header says so - a 32-byte SHA-256 over everything
# before it.
#
# This is reimplemented rather than shelled out to esptool because the manifest
# must be produceable by a verifier who has only this file, and because a second
# implementation that agrees with esptool is worth more than a wrapper around
# it. The build script cross-checks against esptool image_info anyway.

def parse_esp_image(blob, what):
    if len(blob) < 24:
        raise Fail("%s: too short to be an ESP image (%d bytes)" % (what, len(blob)))
    if byte_at(blob, 0) != IMAGE_MAGIC:
        raise Fail("%s: bad image magic 0x%02x, expected 0xe9" % (what, byte_at(blob, 0)))

    segment_count = byte_at(blob, 1)
    chip_id = u16(blob, 12)
    hash_appended = byte_at(blob, 23)

    off = 24
    checksum = 0xEF  # ESP_ROM_CHECKSUM_INITIAL
    for i in range(segment_count):
        if off + 8 > len(blob):
            raise Fail("%s: segment %d header runs past the end of the file" % (what, i))
        _load_addr, seg_len = struct.unpack_from("<II", blob, off)
        off += 8
        if off + seg_len > len(blob):
            raise Fail("%s: segment %d data runs past the end of the file" % (what, i))
        for k in range(off, off + seg_len):
            checksum ^= byte_at(blob, k)
        off += seg_len

    # The checksum is the last byte of the 16-byte block that ends after the
    # final segment. When the segments already end on a boundary a further whole
    # block is added, which is why this rounds up from off+16 rather than off.
    end_with_checksum = (off + 16) & ~0xF
    if end_with_checksum > len(blob):
        raise Fail("%s: the file ends before the image checksum" % what)
    stored_ck = byte_at(blob, end_with_checksum - 1)
    if stored_ck != (checksum & 0xFF):
        raise Fail("%s: image checksum mismatch (stored 0x%02x, computed 0x%02x)"
                   % (what, stored_ck, checksum & 0xFF))

    image_len = end_with_checksum
    if hash_appended:
        image_len += 32
        if image_len > len(blob):
            raise Fail("%s: the header claims an appended digest that is not present" % what)

    content_len = image_len - 32 if hash_appended else image_len
    content_sha = hashlib.sha256(blob[:content_len]).hexdigest()

    if hash_appended:
        stored = hexs(blob[image_len - 32:image_len])
        if stored != content_sha:
            # The tripwire, not a formatting problem: either the file is damaged
            # or this parser's idea of where the image ends is wrong, and both
            # are reasons to refuse to publish a number.
            raise Fail("%s: the appended digest %s does not match the content digest %s"
                       % (what, stored, content_sha))

    return {
        "chip_id": chip_id,
        "hash_appended": bool(hash_appended),
        "image_len": image_len,
        "content_len": content_len,
        "content_sha256": content_sha,
        "trailing": len(blob) - image_len,
    }


def parse_app_desc(blob):
    """esp_app_desc_t, immediately after the image header and the first segment
    header, i.e. at offset 32. Returns None when the magic is absent."""
    off = 32
    if len(blob) < off + 176 or u32(blob, off) != APP_DESC_MAGIC:
        return None
    return {
        "secure_version": u32(blob, off + 4),
        "version": cstr(blob, off + 16, 32),
        "project_name": cstr(blob, off + 48, 32),
        "time": cstr(blob, off + 80, 16),
        "date": cstr(blob, off + 96, 16),
        "idf_ver": cstr(blob, off + 112, 32),
        "app_elf_sha256": hexs(blob[off + 144:off + 176]),
    }


def parse_bootloader_desc(blob):
    """esp_bootloader_desc_t, same placement. Best effort: its only use here is
    the stale-bootloader assertion, and an older bootloader carries none."""
    off = 32
    if len(blob) < off + 64 or byte_at(blob, off) != BOOTLOADER_DESC_MAGIC:
        return None
    return {
        "version": u32(blob, off + 4),
        "idf_ver": cstr(blob, off + 8, 32),
        "date_time": cstr(blob, off + 40, 24),
    }


# ---------------------------------------------------------------------------
# Partition table parsing (VERIFY.md 2.3).

def parse_partition_table(blob):
    if len(blob) < PT_ENTRY_LEN:
        raise Fail("partition table: too short (%d bytes)" % len(blob))

    entries = []
    i = 0
    md5_stored = None
    used_len = None
    while i + PT_ENTRY_LEN <= len(blob):
        magic = u16(blob, i)
        if magic == PT_MAGIC:
            entries.append({
                "name": cstr(blob, i + 12, 16),
                "type": byte_at(blob, i + 2),
                "subtype": byte_at(blob, i + 3),
                "offset": hexoff(u32(blob, i + 4)),
                "size": hexoff(u32(blob, i + 8)),
                "flags": u32(blob, i + 28),
            })
            i += PT_ENTRY_LEN
            continue
        if magic == PT_MD5_MAGIC:
            md5_stored = blob[i + 16:i + 32]
            # VERIFY.md 2.3: the used length is (num_parts + 1) * 32 with
            # CONFIG_PARTITION_TABLE_MD5=y, i.e. the entries plus this record.
            used_len = i + PT_ENTRY_LEN
            break
        if blob[i:i + PT_ENTRY_LEN] == b"\xff" * PT_ENTRY_LEN:
            used_len = i
            break
        raise Fail("partition table: unrecognised record at offset 0x%x (magic 0x%04x)"
                   % (i, magic))

    if used_len is None:
        raise Fail("partition table: no MD5 record and no blank terminator")
    if not entries:
        raise Fail("partition table: no entries")

    if md5_stored is not None:
        computed = hashlib.md5(blob[:used_len - PT_ENTRY_LEN]).digest()
        if computed != md5_stored:
            raise Fail("partition table: the MD5 record does not cover the entries "
                       "(stored %s, computed %s)" % (hexs(md5_stored), hexs(computed)))

    tail = blob[used_len:]
    trailing_note = None
    if tail and tail.strip(b"\xff"):
        trailing_note = ("partition table: %d bytes after the table are not 0xff"
                         % len(tail.strip(b"\xff")))

    return {
        "entries": entries,
        "used_len": used_len,
        "sha256": hashlib.sha256(blob[:used_len]).hexdigest(),
        "has_md5": md5_stored is not None,
        "trailing_note": trailing_note,
    }


def find_app_partition(entries):
    """The factory app entry: type 0 (app), subtype 0 (factory)."""
    for e in entries:
        if e["type"] == 0 and e["subtype"] == 0:
            return e
    raise Fail("partition table: no factory app partition (type 0, subtype 0)")


# ---------------------------------------------------------------------------
# The composite firmware digest (VERIFY.md 2.4).

def firmware_digest(bl_len, bl_sha_hex, pt_len, pt_sha_hex, app_len, app_sha_hex):
    h = hashlib.sha256()
    h.update(FW_DIGEST_TAG)
    h.update(b"\x00")
    for length, digest_hex in ((bl_len, bl_sha_hex),
                               (pt_len, pt_sha_hex),
                               (app_len, app_sha_hex)):
        h.update(struct.pack("<I", length))
        h.update(binascii.unhexlify(digest_hex))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Manifest construction.

def dump_manifest(manifest):
    """Serialise deterministically. The manifest is itself a published artifact
    that must rebuild bit-identically, so the encoding is pinned here rather
    than left to json.dumps defaults changing under a future Python."""
    extra = [k for k in manifest if k not in MANIFEST_KEYS]
    if extra:
        raise Fail("manifest carries unknown key(s): %s" % ", ".join(sorted(extra)))
    ordered = [(key, manifest[key]) for key in MANIFEST_KEYS]
    # dict preserves insertion order (py3.7+), which is the ordering guarantee
    # this relies on; sort_keys stays off so MANIFEST_KEYS is the only order.
    text = json.dumps(dict(ordered), indent=2, sort_keys=False,
                      separators=(",", ": "), ensure_ascii=True)
    return text + "\n"


def build_manifest(args):
    app_blob = read_file(args.app)
    bl_blob = read_file(args.bootloader)
    pt_blob = read_file(args.partition_table)

    app = parse_esp_image(app_blob, "app image")
    bl = parse_esp_image(bl_blob, "bootloader image")
    pt = parse_partition_table(pt_blob)

    warnings = []
    if pt["trailing_note"]:
        # The partition-table artifact is padded to ESP_PARTITION_TABLE_MAX_LEN
        # by its generator, so 0xff after the table is expected; anything else
        # there is not.
        warnings.append(pt["trailing_note"])
    if bl["trailing"]:
        warnings.append("bootloader image: %d bytes follow the image" % bl["trailing"])
    if app["trailing"] and not getattr(args, "allow_trailing", False):
        # A padded app.bin is a release artifact with megabytes of filler whose
        # file digest is dominated by 0xff, and the reason is always a producer
        # option rather than the firmware. Name the remedy instead of shipping it.
        raise Fail("the app image is followed by %d bytes of padding; pass "
                   "--skip-padding to espflash save-image, or --allow-trailing "
                   "here if the padding is deliberate" % app["trailing"])
    if app["trailing"]:
        warnings.append("app image: %d bytes follow the image; the file digest covers "
                        "them, the image digest does not" % app["trailing"])

    if not app["hash_appended"]:
        # esp_partition_get_sha256() returns the stored digest when one is
        # appended. Without it the device's number and this manifest's number
        # come from different code paths, and the comparison the manifest exists
        # for becomes a guess.
        raise Fail("the app image has no appended SHA-256, so the device readout "
                   "cannot be compared against this manifest")

    desc = parse_app_desc(app_blob)
    if desc is None:
        raise Fail("the app image carries no esp_app_desc_t at offset 32")

    if desc["version"] != args.version:
        raise Fail("the app descriptor version %r does not match --version %r; set "
                   "CONFIG_APP_PROJECT_VER_FROM_CONFIG=y and CONFIG_APP_PROJECT_VER"
                   % (desc["version"], args.version))

    # CONFIG_APP_REPRODUCIBLE_BUILD blanks the compile date and time. A
    # non-empty value means the option is off, which means this image cannot
    # reproduce, and publishing its hash would be a claim we could not keep.
    if desc["time"] or desc["date"]:
        raise Fail("the app descriptor carries a build timestamp (%r %r), so "
                   "CONFIG_APP_REPRODUCIBLE_BUILD is not enabled"
                   % (desc["date"], desc["time"]))

    if args.expect_idf and desc["idf_ver"] != args.expect_idf:
        raise Fail("the app was linked against IDF %r, expected %r"
                   % (desc["idf_ver"], args.expect_idf))

    bl_desc = parse_bootloader_desc(bl_blob)
    if bl_desc is not None and args.expect_idf and bl_desc["idf_ver"] != args.expect_idf:
        raise Fail("the bootloader was built by IDF %r, expected %r - this is the "
                   "stale-bootloader fault tools/flash.ps1 warns about"
                   % (bl_desc["idf_ver"], args.expect_idf))

    app_part = find_app_partition(pt["entries"])
    app_offset = int(app_part["offset"], 16)
    app_part_size = int(app_part["size"], 16)
    if app["image_len"] > app_part_size:
        raise Fail("the app image is %d bytes and does not fit the %d-byte factory "
                   "partition" % (app["image_len"], app_part_size))
    if BOOTLOADER_OFFSET + bl["image_len"] > PT_OFFSET:
        raise Fail("the bootloader image is %d bytes and overruns the partition table "
                   "at 0x8000" % bl["image_len"])

    manifest = {
        "format": MANIFEST_FORMAT,
        "version": args.version,
        "board": args.board,
        "app_image_sha256": app["content_sha256"],
        "app_image_len": app["content_len"],
        "app_file_sha256": hashlib.sha256(app_blob).hexdigest(),
        "app_offset": hexoff(app_offset),
        "bootloader_image_sha256": bl["content_sha256"],
        "bootloader_image_len": bl["content_len"],
        "bootloader_offset": hexoff(BOOTLOADER_OFFSET),
        "bootloader_file_sha256": hashlib.sha256(bl_blob).hexdigest(),
        "partition_table_sha256": pt["sha256"],
        "partition_table_len": pt["used_len"],
        "partition_table_offset": hexoff(PT_OFFSET),
        "partition_table_file_sha256": hashlib.sha256(pt_blob).hexdigest(),
        "partition_table_csv_sha256": sha256_file(args.partitions_csv),
        "firmware_digest": firmware_digest(
            bl["content_len"], bl["content_sha256"],
            pt["used_len"], pt["sha256"],
            app["content_len"], app["content_sha256"]),
        "secure_version": desc["secure_version"],
        "partitions": pt["entries"],
    }
    return manifest, desc, warnings


def cmd_emit(args):
    manifest, desc, warnings = build_manifest(args)
    for w in warnings:
        sys.stderr.write("note: %s\n" % w)
    text = dump_manifest(manifest)
    if args.out == "-":
        sys.stdout.write(text)
    else:
        with open(args.out, "w") as fh:
            fh.write(text)
        print("wrote %s" % args.out)
    print("  app image       %s  %d B at %s"
          % (manifest["app_image_sha256"], manifest["app_image_len"], manifest["app_offset"]))
    print("  bootloader      %s  %d B at %s"
          % (manifest["bootloader_image_sha256"], manifest["bootloader_image_len"],
             manifest["bootloader_offset"]))
    print("  partition table %s  %d B at %s"
          % (manifest["partition_table_sha256"], manifest["partition_table_len"],
             manifest["partition_table_offset"]))
    print("  firmware_digest %s" % manifest["firmware_digest"])
    print("  project %s, idf %s, secure_version %d"
          % (desc["project_name"], desc["idf_ver"], desc["secure_version"]))
    return 0


# ---------------------------------------------------------------------------
# Checking.

def artifact(version, board, suffix):
    return "notyas-%s-%s-%s" % (version, board, suffix)


def load_manifest(path):
    with open(path, "r") as fh:
        text = fh.read()
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise Fail("%s is not valid JSON: %s" % (path, exc))
    if data.get("format") != MANIFEST_FORMAT:
        raise Fail("%s declares format %r; this tool understands %r"
                   % (path, data.get("format"), MANIFEST_FORMAT))
    missing = [k for k in MANIFEST_KEYS if k not in data]
    if missing:
        raise Fail("%s is missing field(s): %s" % (path, ", ".join(missing)))
    return data, text


class Report(object):
    """Accumulates comparisons so a verifier sees every mismatch at once. A
    checker that stops at the first difference makes the reader run it N times."""

    def __init__(self):
        self.rows = []

    def compare(self, label, expected, actual):
        ok = expected == actual
        self.rows.append((ok, label, expected, actual))
        return ok

    def note(self, label, value):
        self.rows.append((None, label, value, value))

    def failures(self):
        return sum(1 for ok, _l, _e, _a in self.rows if ok is False)

    def emit(self):
        for ok, label, expected, actual in self.rows:
            if ok is None:
                print("  note %-28s %s" % (label, expected))
            elif ok:
                print("  ok   %-28s %s" % (label, actual))
            else:
                print("  FAIL %-28s" % label)
                print("       manifest: %s" % expected)
                print("       actual:   %s" % actual)
        return self.failures()


def check_against_dir(manifest, directory, report):
    version = manifest["version"]
    board = manifest["board"]
    names = {
        "app": artifact(version, board, "app.bin"),
        "bootloader": artifact(version, board, "bootloader.bin"),
        "partition_table": artifact(version, board, "partition-table.bin"),
    }
    paths = {}
    for key in sorted(names):
        path = os.path.join(directory, names[key])
        if not os.path.exists(path):
            raise Fail("%s not found in %s" % (names[key], directory))
        paths[key] = path

    app_blob = read_file(paths["app"])
    bl_blob = read_file(paths["bootloader"])
    pt_blob = read_file(paths["partition_table"])

    app = parse_esp_image(app_blob, "app image")
    bl = parse_esp_image(bl_blob, "bootloader image")
    pt = parse_partition_table(pt_blob)

    report.compare("app_image_sha256", manifest["app_image_sha256"], app["content_sha256"])
    report.compare("app_image_len", manifest["app_image_len"], app["content_len"])
    report.compare("app_file_sha256", manifest["app_file_sha256"],
                   hashlib.sha256(app_blob).hexdigest())
    report.compare("bootloader_image_sha256", manifest["bootloader_image_sha256"],
                   bl["content_sha256"])
    report.compare("bootloader_image_len", manifest["bootloader_image_len"], bl["content_len"])
    report.compare("bootloader_file_sha256", manifest["bootloader_file_sha256"],
                   hashlib.sha256(bl_blob).hexdigest())
    report.compare("partition_table_sha256", manifest["partition_table_sha256"], pt["sha256"])
    report.compare("partition_table_len", manifest["partition_table_len"], pt["used_len"])
    report.compare("partition_table_file_sha256", manifest["partition_table_file_sha256"],
                   hashlib.sha256(pt_blob).hexdigest())
    report.compare("partitions", manifest["partitions"], pt["entries"])
    report.compare("firmware_digest", manifest["firmware_digest"],
                   firmware_digest(bl["content_len"], bl["content_sha256"],
                                   pt["used_len"], pt["sha256"],
                                   app["content_len"], app["content_sha256"]))

    desc = parse_app_desc(app_blob)
    if desc is not None:
        report.compare("app descriptor version", manifest["version"], desc["version"])
        report.compare("secure_version", manifest["secure_version"], desc["secure_version"])


def parse_readout(path):
    """The notyas-verify/1 payload from the device Verify screen (VERIFY.md 7.2):
    line-oriented key=value ASCII, the first line being the format id."""
    with open(path, "r") as fh:
        raw = fh.read()
    lines = [ln.strip() for ln in raw.replace("\r\n", "\n").split("\n")]
    lines = [ln for ln in lines if ln]
    if not lines or lines[0] != READOUT_FORMAT:
        raise Fail("%s does not start with %r" % (path, READOUT_FORMAT))
    fields = {}
    for ln in lines[1:]:
        if "=" not in ln:
            raise Fail("%s: line without '=': %r" % (path, ln))
        key, value = ln.split("=", 1)
        fields[key.strip()] = value.strip()
    return fields


# The device readout names a region's content digest <region>_sha256 and its
# content length <region>_len; the manifest spells the same two values
# <region>_image_sha256 and <region>_image_len because it also carries file
# digests, which a device has no notion of. This table is the whole translation.
READOUT_MAP = [
    ("version", "version"),
    ("board", "board"),
    ("firmware_digest", "firmware_digest"),
    ("app_offset", "app_offset"),
    ("app_len", "app_image_len"),
    ("app_sha256", "app_image_sha256"),
    ("bootloader_offset", "bootloader_offset"),
    ("bootloader_len", "bootloader_image_len"),
    ("bootloader_sha256", "bootloader_image_sha256"),
    ("partition_table_offset", "partition_table_offset"),
    ("partition_table_len", "partition_table_len"),
    ("partition_table_sha256", "partition_table_sha256"),
]

# Without these three the readout says nothing about which firmware is running,
# so their absence is a refusal rather than a skipped row.
READOUT_REQUIRED = ("firmware_digest", "app_sha256", "app_len")


def check_against_readout(manifest, path, report):
    fields = parse_readout(path)
    missing = [k for k in READOUT_REQUIRED if k not in fields]
    if missing:
        raise Fail("the device readout is missing %s" % ", ".join(missing))
    for readout_key, manifest_key in READOUT_MAP:
        if readout_key not in fields:
            # A row the device does not print is not a mismatch. Every row it
            # does print is compared.
            report.note("%s (not in readout)" % readout_key, "skipped")
            continue
        expected = manifest[manifest_key]
        actual = fields[readout_key]
        if isinstance(expected, int):
            try:
                actual_cmp = int(actual, 0)
            except ValueError:
                raise Fail("the device readout %s=%r is not a number" % (readout_key, actual))
            report.compare(readout_key, expected, actual_cmp)
        else:
            report.compare(readout_key, expected, actual)


def cmd_check(args):
    manifest, _text = load_manifest(args.manifest)
    print("manifest %s: notyas %s, board %s"
          % (args.manifest, manifest["version"], manifest["board"]))
    report = Report()
    if not args.dir and not args.readout:
        raise Fail("nothing to check against: pass --dir, --readout, or both")
    if args.dir:
        print("against the artifacts in %s:" % args.dir)
        check_against_dir(manifest, args.dir, report)
    if args.readout:
        print("against the device readout %s:" % args.readout)
        check_against_readout(manifest, args.readout, report)
    bad = report.emit()
    if bad:
        print("")
        print("verify-manifest: FAILED - %d mismatch(es)" % bad)
        print("Do not flash an image whose manifest does not match. See VERIFYING.md, "
              "'If something does not match'.")
        return 1
    print("")
    print("verify-manifest: OK")
    return 0


# ---------------------------------------------------------------------------
# Self-test. Builds synthetic artifacts with the exact on-flash layouts above,
# round-trips them through emit and check, and then proves the checker refuses
# the faults it exists to catch. Needs no ESP toolchain and no hardware, which
# is what lets CI run it on every push.

def _synth_app_desc(version, project, idf_ver, secure_version, date="", time=""):
    desc = bytearray(256)
    struct.pack_into("<I", desc, 0, APP_DESC_MAGIC)
    struct.pack_into("<I", desc, 4, secure_version)
    desc[16:16 + len(version)] = version.encode("ascii")
    desc[48:48 + len(project)] = project.encode("ascii")
    desc[80:80 + len(time)] = time.encode("ascii")
    desc[96:96 + len(date)] = date.encode("ascii")
    desc[112:112 + len(idf_ver)] = idf_ver.encode("ascii")
    return bytes(desc)


def _synth_bootloader_desc(idf_ver):
    desc = bytearray(80)
    desc[0] = BOOTLOADER_DESC_MAGIC
    struct.pack_into("<I", desc, 4, 1)
    desc[8:8 + len(idf_ver)] = idf_ver.encode("ascii")
    return bytes(desc)


def _synth_image(segments, hash_appended=True):
    header = bytearray(24)
    header[0] = IMAGE_MAGIC
    header[1] = len(segments)
    struct.pack_into("<H", header, 12, 0x12)  # ESP32-P4 chip id
    header[23] = 1 if hash_appended else 0
    out = bytearray(header)
    checksum = 0xEF
    for load_addr, data in segments:
        out += struct.pack("<II", load_addr, len(data))
        out += data
        for byte in bytearray(data):
            checksum ^= byte
    end = (len(out) + 16) & ~0xF
    out += b"\x00" * (end - len(out) - 1)
    out.append(checksum & 0xFF)
    if hash_appended:
        out += hashlib.sha256(bytes(out)).digest()
    return bytes(out)


def _synth_partition_table(rows):
    out = bytearray()
    for name, ptype, subtype, offset, size, flags in rows:
        entry = bytearray(32)
        struct.pack_into("<H", entry, 0, PT_MAGIC)
        entry[2] = ptype
        entry[3] = subtype
        struct.pack_into("<I", entry, 4, offset)
        struct.pack_into("<I", entry, 8, size)
        entry[12:12 + len(name)] = name.encode("ascii")
        struct.pack_into("<I", entry, 28, flags)
        out += entry
    md5 = bytearray(b"\xff" * 32)
    struct.pack_into("<H", md5, 0, PT_MD5_MAGIC)
    md5[16:32] = hashlib.md5(bytes(out)).digest()
    out += md5
    out += b"\xff" * (PT_MAX_LEN - len(out))
    return bytes(out)


def _selftest_write(tmpdir, version, board, date="", time=""):
    if not os.path.isdir(tmpdir):
        os.mkdir(tmpdir)
    app_desc = _synth_app_desc(version, "notyas-firmware", "v5.5.4", 0, date, time)
    app = _synth_image([(0x3C000020, app_desc + b"app payload." * 97),
                        (0x4FF00000, b"\x11\x22\x33\x44" * 64)])
    bl = _synth_image([(0x4FF20000, _synth_bootloader_desc("v5.5.4") + b"boot" * 313)])
    pt = _synth_partition_table([
        ("factory", 0, 0, 0x10000, 0x400000, 0),
        ("wallets", 1, 6, 0x410000, 0x40000, 1),
        ("counters", 1, 6, 0x450000, 0x4000, 0),
    ])
    csv = b"# synthetic\nfactory, app, factory, 0x10000, 4M\n"
    paths = {}
    for suffix, blob in (("app.bin", app), ("bootloader.bin", bl),
                         ("partition-table.bin", pt)):
        path = os.path.join(tmpdir, artifact(version, board, suffix))
        with open(path, "wb") as fh:
            fh.write(blob)
        paths[suffix] = path
    csv_path = os.path.join(tmpdir, "partitions.csv")
    with open(csv_path, "wb") as fh:
        fh.write(csv)
    paths["csv"] = csv_path
    return paths


class _Args(object):
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _emit_args(version, board, paths, expect_idf="v5.5.4", allow_trailing=False):
    return _Args(version=version, board=board, app=paths["app.bin"],
                 bootloader=paths["bootloader.bin"],
                 partition_table=paths["partition-table.bin"],
                 partitions_csv=paths["csv"], expect_idf=expect_idf,
                 allow_trailing=allow_trailing)


def cmd_selftest(_args):
    import shutil
    import tempfile

    version, board = "0.2.0", "selftest-board"
    tmpdir = tempfile.mkdtemp(prefix="notyas-repro-selftest-")
    failures = []
    checks = 0
    try:
        good = os.path.join(tmpdir, "good")
        paths = _selftest_write(good, version, board)
        manifest, _desc, _warn = build_manifest(_emit_args(version, board, paths))
        text = dump_manifest(manifest)
        checks += 1
        print("1. emit produced a manifest (%d bytes)" % len(text))

        again, _d2, _w2 = build_manifest(_emit_args(version, board, paths))
        checks += 1
        if dump_manifest(again) != text:
            failures.append("re-emitting the same inputs produced different bytes")
        else:
            print("2. re-emit is byte-identical")

        report = Report()
        check_against_dir(json.loads(text), good, report)
        checks += 1
        if report.failures():
            failures.append("checking a good tree reported %d mismatch(es)"
                            % report.failures())
        else:
            print("3. check against the artifacts passes (%d comparisons)"
                  % len(report.rows))

        # The composite is meant to be reconstructible by hand from the three
        # published numbers, so recompute it outside build_manifest.
        expect = firmware_digest(manifest["bootloader_image_len"],
                                 manifest["bootloader_image_sha256"],
                                 manifest["partition_table_len"],
                                 manifest["partition_table_sha256"],
                                 manifest["app_image_len"],
                                 manifest["app_image_sha256"])
        checks += 1
        if expect != manifest["firmware_digest"]:
            failures.append("firmware_digest is not the documented construction")
        else:
            print("4. firmware_digest matches the VERIFY.md 2.4 construction")

        readout_path = os.path.join(tmpdir, "readout.txt")
        with open(readout_path, "w") as fh:
            fh.write(READOUT_FORMAT + "\n")
            fh.write("version=%s\nboard=%s\n" % (version, board))
            fh.write("firmware_digest=%s\n" % manifest["firmware_digest"])
            fh.write("app_offset=%s\napp_len=%d\napp_sha256=%s\n"
                     % (manifest["app_offset"], manifest["app_image_len"],
                        manifest["app_image_sha256"]))
            fh.write("bootloader_offset=%s\nbootloader_len=%d\nbootloader_sha256=%s\n"
                     % (manifest["bootloader_offset"], manifest["bootloader_image_len"],
                        manifest["bootloader_image_sha256"]))
        report = Report()
        check_against_readout(json.loads(text), readout_path, report)
        checks += 1
        if report.failures():
            failures.append("checking a matching device readout reported %d mismatch(es)"
                            % report.failures())
        else:
            print("5. check against a matching device readout passes")

        # Negative cases. Each is a fault the tool exists to catch, so each is
        # asserted to fail rather than assumed to.
        bad_dir = os.path.join(tmpdir, "tampered")
        os.mkdir(bad_dir)
        for suffix in ("app.bin", "bootloader.bin", "partition-table.bin"):
            shutil.copy(paths[suffix], os.path.join(bad_dir, os.path.basename(paths[suffix])))
        tampered = bytearray(read_file(paths["app.bin"]))
        tampered[400] ^= 0x01
        with open(os.path.join(bad_dir, artifact(version, board, "app.bin")), "wb") as fh:
            fh.write(bytes(tampered))
        checks += 1
        try:
            check_against_dir(json.loads(text), bad_dir, Report())
            failures.append("a flipped bit in app.bin was not detected")
        except Fail:
            print("6. a flipped bit in app.bin is refused at parse time")

        stamped = _selftest_write(os.path.join(tmpdir, "stamped"), version, board,
                                  date="Jan  1 2026", time="12:00:00")
        checks += 1
        try:
            build_manifest(_emit_args(version, board, stamped))
            failures.append("an image carrying a build timestamp was accepted")
        except Fail:
            print("7. an image carrying a build timestamp is refused "
                  "(CONFIG_APP_REPRODUCIBLE_BUILD off)")

        checks += 1
        try:
            build_manifest(_emit_args("0.9.9", board, paths))
            failures.append("a version that disagrees with the app descriptor was accepted")
        except Fail:
            print("8. a --version that disagrees with the app descriptor is refused")

        checks += 1
        try:
            build_manifest(_emit_args(version, board, paths, expect_idf="v5.5.5"))
            failures.append("an IDF version that disagrees with the pin was accepted")
        except Fail:
            print("9. an IDF version that disagrees with the pin is refused")

        bad_readout = os.path.join(tmpdir, "bad-readout.txt")
        with open(bad_readout, "w") as fh:
            fh.write(READOUT_FORMAT + "\n")
            fh.write("firmware_digest=%s\n" % ("00" * 32))
            fh.write("app_len=%d\napp_sha256=%s\n"
                     % (manifest["app_image_len"], manifest["app_image_sha256"]))
        report = Report()
        check_against_readout(json.loads(text), bad_readout, report)
        checks += 1
        if not report.failures():
            failures.append("a device readout with a wrong firmware_digest was accepted")
        else:
            print("10. a device readout with a wrong firmware_digest is reported")

        # A padded app.bin is the failure mode of an image producer's default
        # options rather than of the firmware, and it must not reach a release.
        padded = _selftest_write(os.path.join(tmpdir, "padded"), version, board)
        with open(padded["app.bin"], "ab") as fh:
            fh.write(b"\xff" * 4096)
        checks += 1
        try:
            build_manifest(_emit_args(version, board, padded))
            failures.append("an app.bin padded past its image was accepted")
        except Fail:
            print("11. an app.bin padded past the end of its image is refused")
        checks += 1
        try:
            build_manifest(_emit_args(version, board, padded, allow_trailing=True))
            print("12. the same padding is accepted under --allow-trailing")
        except Fail as exc:
            failures.append("--allow-trailing did not accept a padded app.bin: %s" % exc)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    if failures:
        print("")
        print("selftest: FAILED")
        for f in failures:
            print("  - %s" % f)
        return 1
    print("")
    print("selftest: OK - %d checks" % checks)
    return 0


# ---------------------------------------------------------------------------

def main(argv):
    parser = argparse.ArgumentParser(
        prog="verify-manifest.py",
        description="Produce and check the notyas per-board release verification manifest.")
    sub = parser.add_subparsers(dest="cmd")

    p_emit = sub.add_parser("emit", help="write VERIFY.json from a built artifact set")
    p_emit.add_argument("--version", required=True, help="release version, e.g. 0.2.0")
    p_emit.add_argument("--board", required=True, help="board slug, e.g. waveshare-4b")
    p_emit.add_argument("--app", required=True)
    p_emit.add_argument("--bootloader", required=True)
    p_emit.add_argument("--partition-table", required=True, dest="partition_table")
    p_emit.add_argument("--partitions-csv", required=True, dest="partitions_csv")
    p_emit.add_argument("--expect-idf", default=None, dest="expect_idf",
                        help="assert the linked ESP-IDF version, e.g. v5.5.4")
    p_emit.add_argument("--allow-trailing", action="store_true", dest="allow_trailing",
                        help="accept an app.bin padded past the end of its image")
    p_emit.add_argument("--out", default="-", help="output path, or - for stdout")
    p_emit.set_defaults(func=cmd_emit)

    p_check = sub.add_parser("check",
                             help="check a manifest against artifacts and/or a device readout")
    p_check.add_argument("--manifest", required=True)
    p_check.add_argument("--dir", default=None, help="directory holding the named artifacts")
    p_check.add_argument("--readout", default=None,
                         help="notyas-verify/1 text captured from the device Verify screen")
    p_check.set_defaults(func=cmd_check)

    p_self = sub.add_parser("selftest",
                            help="run the built-in tests (no hardware, no toolchain)")
    p_self.set_defaults(func=cmd_selftest)

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except Fail as exc:
        sys.stderr.write("verify-manifest: %s\n" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
