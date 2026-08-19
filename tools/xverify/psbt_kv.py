# Copyright (C) 2026 intnsity
# SPDX-License-Identifier: GPL-3.0-or-later
"""BIP-174 at the key-value layer, with no idea what any of the values mean.

Two jobs, and both of them need a reader that is deliberately more primitive than a
PSBT library:

1.  **Building hostile-but-legal material.** A case that proves a signer passes unknown
    key-value pairs through has to contain unknown key-value pairs, and no PSBT library
    will write one: a library only serializes fields it has a type for. This module
    writes bytes, so it can put a pair of a type nothing has ever heard of into any map.

2.  **Diffing what came back.** The claim "we add signatures and nothing else" is a claim
    about pairs, so the comparison has to be over pairs. Doing it through a library would
    ask the library which fields it recognises, and a pair it dropped on the way in would
    then be invisible to the comparison as well - the exact shape of the failure this
    whole cross-check exists to rule out.

Structure, from BIP-174: `<magic 0x70736274 0xff>` then one key-value map for the
globals, then one per input and one per output of the unsigned transaction, each map a
run of `<keylen><key><valuelen><value>` ended by a zero-length key. A key is its type
(a compact-size uint) followed by its key data; this module keeps the key whole and
uninterpreted, because a type it split off would be a type it could get wrong.

PSBT v2 (BIP-370) is out of scope here, as it is for the device: v2 moves the input and
output counts into the global map, and this reader would misread one. It reads the
counts out of the unsigned transaction, so a v2 file fails as a parse error rather than
being quietly misparsed.
"""

MAGIC = b"\x70\x73\x62\x74\xff"


class PsbtFormatError(Exception):
    """The bytes are not a v0 PSBT. Raised rather than repaired, always."""


# ---------------------------------------------------------------------------------------
# compact size
# ---------------------------------------------------------------------------------------


def read_compact(data, pos):
    """Return (value, new_pos) for the compact-size uint at pos."""
    if pos >= len(data):
        raise PsbtFormatError("truncated compact size")
    first = data[pos]
    if first < 0xFD:
        return first, pos + 1
    if first == 0xFD:
        return int.from_bytes(data[pos + 1 : pos + 3], "little"), pos + 3
    if first == 0xFE:
        return int.from_bytes(data[pos + 1 : pos + 5], "little"), pos + 5
    return int.from_bytes(data[pos + 1 : pos + 9], "little"), pos + 9


def write_compact(value):
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


# ---------------------------------------------------------------------------------------
# maps
# ---------------------------------------------------------------------------------------


def read_map(data, pos):
    """Read one key-value map. Returns (pairs, new_pos), pairs in FILE order."""
    pairs = []
    while True:
        if pos >= len(data):
            raise PsbtFormatError("map is not terminated")
        keylen, pos = read_compact(data, pos)
        if keylen == 0:
            return pairs, pos
        key = data[pos : pos + keylen]
        if len(key) != keylen:
            raise PsbtFormatError("truncated key")
        pos += keylen
        vallen, pos = read_compact(data, pos)
        value = data[pos : pos + vallen]
        if len(value) != vallen:
            raise PsbtFormatError("truncated value")
        pos += vallen
        pairs.append((key, value))


def write_map(pairs):
    out = bytearray()
    for key, value in pairs:
        out += write_compact(len(key)) + key
        out += write_compact(len(value)) + value
    out += b"\x00"
    return bytes(out)


# ---------------------------------------------------------------------------------------
# the file
# ---------------------------------------------------------------------------------------


class Psbt:
    """A PSBT as three lists of key-value maps and nothing else.

    `globals` is one map, `inputs` and `outputs` are one map each. No field is named, no
    value is decoded, and nothing is validated beyond the framing: this type cannot
    normalize a file, which is exactly why it is trustworthy as a witness to what a file
    contained.
    """

    def __init__(self, globals_map, inputs, outputs):
        self.globals = globals_map
        self.inputs = inputs
        self.outputs = outputs

    @classmethod
    def parse(cls, data):
        if not data.startswith(MAGIC):
            raise PsbtFormatError("wrong magic")
        pos = len(MAGIC)
        globals_map, pos = read_map(data, pos)
        unsigned = None
        for key, value in globals_map:
            if key == b"\x00":
                unsigned = value
        if unsigned is None:
            raise PsbtFormatError("no unsigned transaction in the global map")
        n_in, n_out = count_inputs_outputs(unsigned)
        inputs = []
        for _ in range(n_in):
            pairs, pos = read_map(data, pos)
            inputs.append(pairs)
        outputs = []
        for _ in range(n_out):
            pairs, pos = read_map(data, pos)
            outputs.append(pairs)
        if pos != len(data):
            raise PsbtFormatError(
                "trailing bytes after the last map: %d left over" % (len(data) - pos)
            )
        return cls(globals_map, inputs, outputs)

    def serialize(self):
        out = bytearray(MAGIC)
        out += write_map(self.globals)
        for pairs in self.inputs:
            out += write_map(pairs)
        for pairs in self.outputs:
            out += write_map(pairs)
        return bytes(out)

    def maps(self):
        """(label, pairs) for every map in the file, in file order."""
        yield "global", self.globals
        for i, pairs in enumerate(self.inputs):
            yield "input[%d]" % i, pairs
        for i, pairs in enumerate(self.outputs):
            yield "output[%d]" % i, pairs


def count_inputs_outputs(tx):
    """Input and output counts of an unsigned legacy transaction.

    PSBT v0 requires the global transaction to carry no witnesses and empty scriptSigs,
    so this walks the legacy encoding only. A file that put a witness-serialized
    transaction there is malformed, and the marker byte makes it look like a zero-input
    transaction, so that case is rejected by name rather than silently believed.
    """
    pos = 4  # version
    n_in, pos = read_compact(tx, pos)
    if n_in == 0:
        raise PsbtFormatError(
            "unsigned transaction has no inputs, or is witness-serialized "
            "(BIP-174 forbids both)"
        )
    for _ in range(n_in):
        pos += 36  # outpoint
        script_len, pos = read_compact(tx, pos)
        pos += script_len + 4  # scriptSig and sequence
    n_out, pos = read_compact(tx, pos)
    for _ in range(n_out):
        pos += 8  # value
        script_len, pos = read_compact(tx, pos)
        pos += script_len
    if pos + 4 != len(tx):
        raise PsbtFormatError("unsigned transaction does not end where its fields say")
    return n_in, n_out


# ---------------------------------------------------------------------------------------
# the delta
# ---------------------------------------------------------------------------------------


class MapDelta:
    """What changed between one map of a file and the same map of its successor."""

    def __init__(self, label, before, after):
        self.label = label
        before_keys = dict(before)
        after_keys = dict(after)
        self.dropped = sorted(k for k in before_keys if k not in after_keys)
        self.added = sorted(k for k in after_keys if k not in before_keys)
        self.altered = sorted(
            k for k in before_keys if k in after_keys and before_keys[k] != after_keys[k]
        )
        self.reordered = [k for k, _ in before if k in after_keys] != [
            k for k, _ in after if k in before_keys
        ]

    def touched(self):
        return bool(self.dropped or self.altered)

    def describe(self):
        parts = []
        for name, keys in (
            ("dropped", self.dropped),
            ("altered", self.altered),
            ("added", self.added),
        ):
            if keys:
                parts.append("%s %s" % (name, [k.hex() for k in keys]))
        if self.reordered:
            parts.append("reordered")
        return "%s: %s" % (self.label, "; ".join(parts) if parts else "unchanged")


def delta(before, after):
    """One MapDelta per map. Raises if the two files do not have the same map shape."""
    before_maps = list(before.maps())
    after_maps = list(after.maps())
    if len(before_maps) != len(after_maps):
        raise PsbtFormatError(
            "map count changed: %d in, %d out" % (len(before_maps), len(after_maps))
        )
    return [
        MapDelta(label, pairs, after_pairs)
        for (label, pairs), (_, after_pairs) in zip(before_maps, after_maps)
    ]
