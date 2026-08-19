# Copyright (C) 2026 intnsity
# SPDX-License-Identifier: GPL-3.0-or-later
"""Drive two independent implementations against what this tree derives and signs.

# Why this exists

Everything this project produces is checked, today, by this project's code against
vectors this project chose. That is how an implementation and its tests come to be wrong
together, and it has already happened here twice: a BIP-174 vector with a transposed key
type whose assertion agreed with it, and a relaxed check that passed while reopening a
demonstrated loss. MILESTONES.md section 9 clause 2 states the release bar in the only
terms that close it: sign it, and hand the result to a coordinator that ACCEPTS it.

# The two oracles, and why two

- **Bitcoin Core** (regtest, no network peers). The strongest available answer to "would
  a coordinator accept this", because `finalizepsbt` runs the finalizer role and
  `testmempoolaccept` runs consensus and policy over the extracted transaction. It is the
  only oracle here that can say a signature is INVALID rather than merely unfamiliar.
- **embit** (pure Python, the signer library behind SeedSigner, Krux and Specter DIY). An
  independent PSBT parser, sighash and secp256k1 binding, and the closest analogue in
  lineage to what this device is. It shares no code with Core and none with rust-bitcoin.

Two, because CORPUS.md 3.0's rule for the hermetic layer is that no expected value is
written down until two implementations that share no code agree, and signing does not get
a weaker rule than key generation did. They also fail differently: Core rejects a bad
signature by refusing the transaction, embit by returning False from a verification over
a sighash it computed itself, and only the second of those tells you WHICH input.

# The shape

`tools/xverify/xverify-device` (a Rust binary outside the workspace) is the notyas side.
It derives, signs, re-encodes and reports; it decides nothing. This driver builds the
material, puts it through that binary, and puts the results in front of the oracles.
Nothing in this file is on the device's dependency graph, and nothing in this file is
imported by anything that ships.

# How this is stopped from passing vacuously

A cross-check that quietly does nothing is worse than none, because the suite goes green
and everyone believes it ran. Five mechanisms, in order of how much they are worth:

1.  **Absence is loud and recorded.** Missing tools are never a skip inside a case. The
    run stops, prints a banner, and writes an attestation whose status is "skipped" with
    the reason. tools/ci/check-xverify.sh decides what that costs; the release gate
    treats it as a failure (see that script and tools/release.sh).
2.  **The negatives are mandatory, not optional.** Every positive claim has a paired case
    that corrupts exactly one thing and REQUIRES the third party to reject it. An oracle
    that had been stubbed out, mocked, or pointed at the wrong file passes the positives
    and fails the negatives immediately.
3.  **The manifest of expected cases is checked at the end.** `EXPECTED` lists every case
    name this driver is supposed to record. A name missing from the results is a failure
    with the same weight as a wrong answer, so a case lost to an early `return` cannot
    quietly reduce the suite.
4.  **Preconditions are asserted before the claim that rests on them.** "Every unknown
    key-value pair survived" is vacuous over a file with no unknown pairs, so the count is
    asserted non-zero first, out of the device's own census AND out of this driver's
    independent reader.
5.  **The oracles are identified in the attestation.** Versions of bitcoind and embit, and
    the digest of the tree that was checked, so a green record cannot be inherited by a
    tree that has since changed.

# Material

Three published BIP-39 test mnemonics and nothing else (CORPUS.md 2.3), on regtest. The
device binary enforces the same list from its side, so no run of this harness can involve
a seed that is not already public.
"""

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import psbt_kv  # noqa: E402  (deliberate: sibling module, no package on purpose)

# ---------------------------------------------------------------------------------------
# Material
# ---------------------------------------------------------------------------------------

# CORPUS.md 2.3: every corpus wallet derives from a PUBLISHED test mnemonic. These three.
DEVICE_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon about"
)
COSIGNER_B_MNEMONIC = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
COSIGNER_C_MNEMONIC = (
    "legal winner thank year wave sausage worth useful legal winner thank yellow"
)

NETWORK = "regtest"
# BIP-48 P2WSH, coin type 1 (everything that is not mainnet). The device's own
# derive::coin_type makes the same choice, and a disagreement would surface as a
# registration refusal rather than as a wrong address, which is why it is stated once here.
MULTISIG_ORIGIN = "m/48h/1h/0h/2h"
ADDRESS_COUNT = 5

# The unknown and proprietary pairs injected into the round-trip case. Types chosen from
# the ranges BIP-174 leaves undefined for a v0 global, input and output map, so a signer
# that understood any of them would be reading a field that does not exist.
#
# 0xfc is the proprietary type byte, and its key data is <identifier len><identifier>
# <subtype><data>, so these two are structurally proprietary keys as well as unknown ones.
UNKNOWN_PAIRS = [
    (bytes([0x7A]) + b"\x01\x02", b"unknown-global-value"),
    (bytes([0xFC]) + b"\x07notyas\x00" + b"\x01", b"proprietary-value"),
]

# Every case name this driver is supposed to record. Checked at the end: a name that did
# not report is a failure, so a case skipped by an early exit cannot shrink the suite
# without the shrinkage being the loudest thing in the output.
EXPECTED = [
    "descriptor.singlesig.checksum",
    "addresses.singlesig.three_way",
    "descriptor.multisig.registration",
    "addresses.multisig.three_way",
    "bip67.cosigner_order_irrelevant",
    "bip67.unsorted_differs",
    "roundtrip.unknown_fields_survive",
    "roundtrip.third_party_decoders_agree",
    "roundtrip.detector_is_alive",
    "sign.singlesig.embit_verifies",
    "sign.singlesig.core_accepts",
    "sign.singlesig.corrupt_signature_rejected",
    "sign.singlesig.corrupt_signature_rejected_at_consensus",
    "sign.singlesig.mutated_transaction_rejected",
    "sign.singlesig.amount_lie_refused_by_device",
    "sign.singlesig.amount_lie_rejected_by_core",
    "sign.multisig.embit_verifies",
    "sign.multisig.ceremony_accepted",
    "sign.multisig.corrupt_signature_rejected",
    "sign.multisig.corrupt_signature_rejected_at_consensus",
    "sign.multisig.unknown_fields_survive_signing",
]


class ToolMissing(Exception):
    """A tool this harness cannot proceed without. Never caught by a case."""


class CheckFailed(Exception):
    """An oracle disagreed. Carries the sentence that goes in the report."""


# ---------------------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------------------


class Results:
    """The record of what ran, what it concluded, and on whose authority.

    `oracle` is not decoration. A result nobody can attribute to an implementation outside
    this tree is not evidence of anything, so every record names the implementations that
    produced it, and the attestation carries their versions.
    """

    def __init__(self):
        self.records = []

    def passed(self, name, oracle, detail):
        self.records.append(
            {"case": name, "status": "pass", "oracle": oracle, "detail": detail}
        )
        print("  PASS  %-46s %s" % (name, detail))

    def failed(self, name, oracle, detail):
        self.records.append(
            {"case": name, "status": "FAIL", "oracle": oracle, "detail": detail}
        )
        print("  FAIL  %-46s %s" % (name, detail))

    def failures(self):
        return [r for r in self.records if r["status"] != "pass"]

    def missing(self):
        recorded = {r["case"] for r in self.records}
        return [name for name in EXPECTED if name not in recorded]


def case(results, name, oracle):
    """Run one case, and turn any disagreement into a recorded failure.

    Only CheckFailed is caught. A ToolMissing tears the run down, because a case that
    could not reach its oracle has proven nothing and must never be recorded as anything.
    Any other exception is a defect in this harness and is left to propagate, because a
    harness that swallowed its own bugs would be the vacuous cross-check this file exists
    to make impossible.
    """

    def run(fn):
        try:
            detail = fn()
        except CheckFailed as failure:
            results.failed(name, oracle, str(failure))
            return False
        results.passed(name, oracle, detail)
        return True

    return run


def require(condition, message):
    if not condition:
        raise CheckFailed(message)


# ---------------------------------------------------------------------------------------
# Bitcoin Core
# ---------------------------------------------------------------------------------------


class Core:
    """A regtest bitcoind with no peers, and the RPCs this harness asks of it.

    Offline by construction: `-noconnect`, `-listen=0`, `-dnsseed=0`. The airgap posture
    this project ships under would be poorly served by a verification harness that opened
    a connection to the Bitcoin network, and regtest has nothing to sync anyway.
    """

    def __init__(self, bitcoind, cli, datadir, port):
        self.bitcoind = bitcoind
        self.cli = cli
        self.datadir = datadir
        self.port = port
        self.process = None

    def start(self):
        if os.path.exists(self.datadir):
            shutil.rmtree(self.datadir, ignore_errors=True)
        os.makedirs(self.datadir)
        self.process = subprocess.Popen(
            [
                self.bitcoind,
                "-regtest",
                "-datadir=" + self.datadir,
                "-noconnect",
                "-listen=0",
                "-dnsseed=0",
                "-upnp=0",
                "-natpmp=0",
                "-server",
                "-rpcbind=127.0.0.1",
                "-rpcallowip=127.0.0.1",
                "-rpcport=%d" % self.port,
                # Regtest has no fee history, and walletcreatefundedpsbt refuses to guess.
                "-fallbackfee=0.0002",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        # -rpcwait alone is not enough. It waits for the RPC socket, but cookie
        # authentication needs .cookie to exist as well, and on a cold datadir the socket
        # can answer first - which surfaces as "Could not locate RPC credentials" and is
        # a startup race, not a failure. So: retry, and give up only when the daemon is
        # gone or the clock runs out.
        deadline = time.time() + 90
        last = ""
        while time.time() < deadline:
            if self.process.poll() is not None:
                raise ToolMissing(
                    "bitcoind exited during startup: %s"
                    % (self.process.stderr.read().decode(errors="replace").strip())
                )
            proc = subprocess.run(
                self._cli_base() + ["-rpcwait", "-rpcwaittimeout=15", "getblockchaininfo"],
                capture_output=True,
                text=True,
            )
            if proc.returncode == 0:
                return
            last = (proc.stderr or proc.stdout or "").strip()
            time.sleep(0.5)
        raise ToolMissing(
            "bitcoind did not come up on port %d: %s" % (self.port, last)
        )

    def stop(self):
        if self.process is None:
            return
        try:
            self.rpc("stop")
        except Exception:  # noqa: BLE001 - shutting down is best effort by definition
            self.process.terminate()
        try:
            self.process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.process.kill()

    def _cli_base(self):
        return [
            self.cli,
            "-regtest",
            "-datadir=" + self.datadir,
            "-rpcport=%d" % self.port,
        ]

    def rpc(self, *args, wallet=None):
        command = self._cli_base()
        if wallet is not None:
            command.append("-rpcwallet=" + wallet)
        command += [str(a) for a in args]
        proc = subprocess.run(command, capture_output=True, text=True)
        if proc.returncode != 0:
            raise CoreRefused((proc.stderr or proc.stdout).strip())
        text = proc.stdout.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # getnewaddress and friends answer with a bare string.
            return text


class CoreRefused(Exception):
    """Core said no. A result in its own right for a negative case."""


# ---------------------------------------------------------------------------------------
# The device under test
# ---------------------------------------------------------------------------------------


class Device:
    """The notyas signing engine, over a process boundary.

    Every method returns the binary's own JSON report. `refuses` is the counterpart used
    by the negative cases: a refusal is an outcome to assert on, not an error to hide.
    """

    def __init__(self, binary, workdir):
        self.binary = binary
        self.workdir = workdir

    def run(self, *args):
        proc = subprocess.run(
            [self.binary] + [str(a) for a in args], capture_output=True, text=True
        )
        if proc.returncode != 0:
            raise DeviceRefused((proc.stderr or proc.stdout).strip())
        return json.loads(proc.stdout)

    def refuses(self, *args):
        """Return the refusal text, or raise CheckFailed if the device did NOT refuse."""
        try:
            self.run(*args)
        except DeviceRefused as refusal:
            return str(refusal)
        raise CheckFailed("the device accepted material it was supposed to refuse")

    def path(self, name):
        return os.path.join(self.workdir, name)


class DeviceRefused(Exception):
    """The notyas engine refused. Also a result in its own right."""


# ---------------------------------------------------------------------------------------
# embit
# ---------------------------------------------------------------------------------------


def load_embit():
    try:
        import embit  # noqa: F401
        from embit import bip32, bip39, script  # noqa: F401
        from embit.descriptor import Descriptor  # noqa: F401
        from embit.ec import Signature  # noqa: F401
        from embit.networks import NETWORKS  # noqa: F401
        from embit.psbt import PSBT  # noqa: F401
    except ImportError as missing:
        raise ToolMissing(
            "embit is not importable by %s (%s). Install it into the interpreter that "
            "runs this harness: python -m pip install embit" % (sys.executable, missing)
        )
    return sys.modules["embit"]


def embit_version():
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "show", "embit"], capture_output=True, text=True
    )
    for line in proc.stdout.splitlines():
        if line.lower().startswith("version:"):
            return "embit " + line.split(":", 1)[1].strip()
    return "embit (version unknown)"


def embit_root(mnemonic):
    from embit import bip32, bip39
    from embit.networks import NETWORKS

    seed = bip39.mnemonic_to_seed(mnemonic)
    return bip32.HDKey.from_seed(seed, version=NETWORKS[NETWORK]["xprv"])


def embit_account(mnemonic, path):
    from embit.networks import NETWORKS

    root = embit_root(mnemonic)
    account = root.derive(path).to_public()
    return root.my_fingerprint.hex(), account.to_base58(version=NETWORKS[NETWORK]["xpub"])


def embit_verify_input(psbt_bytes, index, pubkey_hex, signature_hex):
    """True if embit, computing the sighash itself, accepts this signature.

    The sighash comes from embit's own reading of the PSBT - its own prevout selection,
    its own scriptCode derivation, its own BIP-143 serialization. Nothing about the digest
    is taken from the device, which is the whole value of the check.
    """
    from embit.ec import PublicKey, Signature
    from embit.psbt import PSBT

    parsed = PSBT.parse(psbt_bytes)
    digest = parsed.sighash(index)
    pubkey = PublicKey.parse(bytes.fromhex(pubkey_hex))
    raw = bytes.fromhex(signature_hex)
    try:
        signature = Signature.parse(raw[:-1])
    except Exception:  # noqa: BLE001 - a signature embit cannot even parse is a rejection
        return False, digest.hex()
    return pubkey.verify(signature, digest), digest.hex()


# ---------------------------------------------------------------------------------------
# Helpers over the material
# ---------------------------------------------------------------------------------------


def read(path):
    with open(path, "rb") as handle:
        return handle.read()


def write(path, data):
    with open(path, "wb") as handle:
        handle.write(data)
    return path


def to_base64(data):
    import base64

    return base64.b64encode(data).decode("ascii")


def from_base64(text):
    import base64

    return base64.b64decode(text)


def inject_unknown_pairs(data):
    """Put an unknown pair and a proprietary pair into every map of a PSBT.

    Into EVERY map, because BIP-174's pass-through obligation is about each of them
    separately: a serializer that kept the global ones and dropped the output ones would
    satisfy any whole-file count.
    """
    parsed = psbt_kv.Psbt.parse(data)
    for pairs in [parsed.globals] + parsed.inputs + parsed.outputs:
        for key, value in UNKNOWN_PAIRS:
            pairs.append((key, value))
    return parsed.serialize()


def count_unknown(data):
    """How many of the injected pairs this file actually contains, counted independently.

    The device reports its own census. This is the second opinion, from the reader in
    psbt_kv, and the two are compared: a device census that disagreed with the bytes on
    disk would be a defect in exactly the layer under test.
    """
    parsed = psbt_kv.Psbt.parse(data)
    injected = {key for key, _ in UNKNOWN_PAIRS}
    return sum(
        1 for _, pairs in parsed.maps() for key, _ in pairs if key in injected
    )


def flip_signature_byte(data, index=0):
    """Corrupt one byte inside the first partial signature of one input.

    Surgical on purpose: everything else about the file stays valid, so a rejection can
    only be about the signature. The key type for a partial signature is 0x02.
    """
    parsed = psbt_kv.Psbt.parse(data)
    pairs = parsed.inputs[index]
    for position, (key, value) in enumerate(pairs):
        if key[0] == 0x02:
            corrupted = bytearray(value)
            # Byte 10 is inside the r value of the DER encoding for every signature this
            # engine produces, so the result stays DER-shaped and fails on the maths.
            corrupted[10] ^= 0x01
            pairs[position] = (key, bytes(corrupted))
            return parsed.serialize()
    raise CheckFailed("no partial signature to corrupt: the case is not testing anything")


def replace_partial_sig(data, index, old_hex, new_hex):
    """Swap one exact partial signature for another, by value.

    By value rather than by position: a file that has been through two signers carries
    several signatures, and a negative case that corrupts whichever one happens to be
    first is a case whose subject changes with the map ordering.
    """
    parsed = psbt_kv.Psbt.parse(data)
    old = bytes.fromhex(old_hex)
    for position, (key, value) in enumerate(parsed.inputs[index]):
        if key[0] == 0x02 and value == old:
            parsed.inputs[index][position] = (key, bytes.fromhex(new_hex))
            return parsed.serialize()
    raise CheckFailed(
        "the signature this case means to corrupt is not in the file, so it would corrupt "
        "nothing"
    )


def bump_output_value(data, delta_sat=1):
    """Move one satoshi from the fee to the first output, after signing.

    The unsigned transaction is inside the global map, so this rewrites the committed
    transaction without touching a single signature. Every signature in the file now
    commits to a transaction that no longer exists.
    """
    parsed = psbt_kv.Psbt.parse(data)
    for position, (key, value) in enumerate(parsed.globals):
        if key == b"\x00":
            tx = bytearray(value)
            offset = output_value_offset(bytes(tx))
            current = int.from_bytes(tx[offset : offset + 8], "little")
            tx[offset : offset + 8] = (current + delta_sat).to_bytes(8, "little")
            parsed.globals[position] = (key, bytes(tx))
            return parsed.serialize()
    raise CheckFailed("no unsigned transaction in the file")


def output_value_offset(tx):
    """Byte offset of the first output's value in a legacy transaction encoding."""
    pos = 4
    n_in, pos = psbt_kv.read_compact(tx, pos)
    for _ in range(n_in):
        pos += 36
        script_len, pos = psbt_kv.read_compact(tx, pos)
        pos += script_len + 4
    _, pos = psbt_kv.read_compact(tx, pos)
    return pos


def set_witness_utxo_value(data, index, value_sat):
    """Rewrite the amount an input's witness_utxo claims, leaving the prev tx alone.

    This is the Trezor 2020 segwit fee attack in one function: BIP-143 commits to the
    amount, the amount arrives as a claim, and a signer that believes the claim signs
    away the difference. ARCHITECTURE.md check 2 exists for it.
    """
    parsed = psbt_kv.Psbt.parse(data)
    for position, (key, value) in enumerate(parsed.inputs[index]):
        if key == b"\x01":  # PSBT_IN_WITNESS_UTXO
            rewritten = value_sat.to_bytes(8, "little") + value[8:]
            parsed.inputs[index][position] = (key, rewritten)
            return parsed.serialize()
    raise CheckFailed("input has no witness_utxo to lie about")


def drop_non_witness_utxo(data, index):
    parsed = psbt_kv.Psbt.parse(data)
    parsed.inputs[index] = [
        (key, value) for key, value in parsed.inputs[index] if key != b"\x00"
    ]
    return parsed.serialize()


def descriptor_body(text):
    return text.split("#")[0]


# ---------------------------------------------------------------------------------------
# The cases
# ---------------------------------------------------------------------------------------


def singlesig_cases(results, core, device, state):
    """Derivation, then a full spend, on a wallet with one key."""
    report = device.run(
        "wallet",
        "--mnemonic",
        DEVICE_MNEMONIC,
        "--network",
        NETWORK,
        "--scheme",
        "bip84",
        "--count",
        ADDRESS_COUNT,
    )
    ours = report["descriptor"]
    state["singlesig_descriptor"] = ours

    def checksum():
        info = core.rpc("getdescriptorinfo", ours)
        require(
            info["checksum"] == ours.split("#")[1],
            "Core computes checksum %s, we wrote %s" % (info["checksum"], ours),
        )
        require(info["issolvable"], "Core says our own descriptor is not solvable")
        return "checksum %s, solvable, %d multipath branches" % (
            info["checksum"],
            len(info.get("multipath_expansion", [])),
        )

    case(results, "descriptor.singlesig.checksum", "bitcoin core")(checksum)

    def addresses():
        from embit.descriptor import Descriptor

        derived = core.rpc("deriveaddresses", ours, json.dumps([0, ADDRESS_COUNT - 1]))
        embit_descriptor = Descriptor.from_string(descriptor_body(ours))
        compared = 0
        for chain, keychain in ((0, "receive"), (1, "change")):
            for row in report[keychain]:
                index = row["index"]
                theirs = derived[chain][index]
                mine = embit_descriptor.derive(index, branch_index=chain).address(
                    embit_network()
                )
                require(
                    row["address"] == theirs,
                    "%s/%d: we say %s, Core says %s"
                    % (keychain, index, row["address"], theirs),
                )
                require(
                    row["address"] == mine,
                    "%s/%d: we say %s, embit says %s"
                    % (keychain, index, row["address"], mine),
                )
                compared += 1
        return "%d addresses, three implementations, no disagreement" % compared

    case(results, "addresses.singlesig.three_way", "bitcoin core + embit")(addresses)

    # The wallet Core watches on our behalf. disable_private_keys: Core is the coordinator
    # in this ceremony and never the signer, which is the arrangement being verified.
    core.rpc(
        "-named",
        "createwallet",
        "wallet_name=device",
        "disable_private_keys=true",
        "blank=true",
    )
    core.rpc(
        "importdescriptors",
        json.dumps(
            [{"desc": ours, "active": True, "range": [0, 20], "timestamp": "now"}]
        ),
        wallet="device",
    )
    fund(core, "device", 1.0)

    unsigned = write(device.path("single-unsigned.psbt"), create_psbt(core, "device"))
    signed_report = device.run(
        "sign",
        "--mnemonic",
        DEVICE_MNEMONIC,
        "--network",
        NETWORK,
        "--in",
        unsigned,
        "--out",
        device.path("single-signed.psbt"),
    )
    signed = read(device.path("single-signed.psbt"))
    state["single_signed"] = signed
    state["single_report"] = signed_report

    def embit_verifies():
        require(
            len(signed_report["signatures"]) == 1,
            "expected exactly one signature, got %d"
            % len(signed_report["signatures"]),
        )
        entry = signed_report["signatures"][0]
        ok, digest = embit_verify_input(
            signed, entry["input"], entry["pubkey"], entry["signature"]
        )
        require(ok, "embit rejected our signature over its own sighash %s" % digest)
        return "embit sighash %s, signature verifies" % digest[:16]

    case(results, "sign.singlesig.embit_verifies", "embit")(embit_verifies)

    def core_accepts():
        analysis = core.rpc("analyzepsbt", to_base64(signed))
        require(
            analysis["next"] == "finalizer",
            "Core says the next role is %s, not finalizer" % analysis["next"],
        )
        txid = accept(core, signed)
        return "analyzepsbt next=finalizer, testmempoolaccept allowed, txid %s" % txid[:16]

    case(results, "sign.singlesig.core_accepts", "bitcoin core")(core_accepts)

    def corrupt_rejected():
        corrupted = flip_signature_byte(signed)
        entry = signed_report["signatures"][0]
        parsed = psbt_kv.Psbt.parse(corrupted)
        bad_hex = next(
            value.hex() for key, value in parsed.inputs[0] if key[0] == 0x02
        )
        ok, _ = embit_verify_input(corrupted, 0, entry["pubkey"], bad_hex)
        require(not ok, "embit accepted a signature with a flipped byte")
        rejection = rejects(core, corrupted)
        return "embit says false; Core says %s" % rejection

    case(results, "sign.singlesig.corrupt_signature_rejected", "bitcoin core + embit")(
        corrupt_rejected
    )

    def corrupt_rejected_at_consensus():
        good = signed_report["signatures"][0]["signature"]
        tx = swap_witness_item(final_tx(core, signed), good, corrupt_der(good))
        return "testmempoolaccept: %s" % rejects_tx(core, tx)

    case(
        results,
        "sign.singlesig.corrupt_signature_rejected_at_consensus",
        "bitcoin core",
    )(corrupt_rejected_at_consensus)

    def mutated_rejected():
        mutated = bump_output_value(signed)
        entry = signed_report["signatures"][0]
        ok, _ = embit_verify_input(
            mutated, entry["input"], entry["pubkey"], entry["signature"]
        )
        require(not ok, "embit accepted a signature over a transaction that changed")
        rejection = rejects(core, mutated)
        return "one satoshi moved after signing; embit says false, Core says %s" % rejection

    case(results, "sign.singlesig.mutated_transaction_rejected", "bitcoin core + embit")(
        mutated_rejected
    )

    amount_lie_cases(results, core, device, read(unsigned), signed, signed_report)


def amount_lie_cases(results, core, device, unsigned, honest_signed, honest_report):
    """The BIP-143 fee attack, from both ends.

    First that this device refuses the file, which is ARCHITECTURE.md check 2 doing its
    job. Then that the attack would have worked if it had not: the same lie signed by a
    signer that believes claimed amounts produces a transaction Bitcoin Core rejects. The
    second half is what makes the first half worth having, and it is the only way to show
    that the check is defending against something real rather than being a check.
    """
    true_value = witness_utxo_value(unsigned, 0)
    lie = set_witness_utxo_value(unsigned, 0, true_value * 100)

    def device_refuses():
        both = write(device.path("lie-both.psbt"), lie)
        refusal = device.refuses(
            "sign",
            "--mnemonic",
            DEVICE_MNEMONIC,
            "--network",
            NETWORK,
            "--in",
            both,
            "--out",
            device.path("lie-both-out.psbt"),
        )
        # The prev tx is still in the file, so the device can see the contradiction. Strip
        # it and the claim is unbacked instead of contradicted; both must be refused, and
        # the second is the case a signer that only checks consistency would sign.
        stripped = write(
            device.path("lie-stripped.psbt"), drop_non_witness_utxo(lie, 0)
        )
        second = device.refuses(
            "sign",
            "--mnemonic",
            DEVICE_MNEMONIC,
            "--network",
            NETWORK,
            "--in",
            stripped,
            "--out",
            device.path("lie-stripped-out.psbt"),
        )
        require(
            "refused" in first_line(refusal) or "refused" in first_line(second),
            "the device refused, but not with a refusal: %s / %s" % (refusal, second),
        )
        return "contradicted claim: %s | unbacked claim: %s" % (
            first_line(refusal),
            first_line(second),
        )

    case(results, "sign.singlesig.amount_lie_refused_by_device", "notyas engine")(
        device_refuses
    )

    def core_rejects_the_attack():
        from embit.psbt import PSBT

        # embit signs the lie without complaint - it is a library, not a policy engine,
        # and here it stands in for a signer that trusts the amount it was handed.
        attacked = PSBT.parse(lie)
        signatures = attacked.sign_with(embit_root(DEVICE_MNEMONIC))
        require(signatures == 1, "the stand-in signer produced %d signatures" % signatures)
        forged = next(iter(attacked.inputs[0].partial_sigs.values())).hex()
        honest = honest_report["signatures"][0]["signature"]
        require(
            forged != honest,
            "the signature over the lied amount is identical to the honest one, which "
            "would mean the amount is not in the digest at all",
        )
        # Drop the forged signature into the transaction the honest run produced. The
        # node now sees a transaction spending a real 1 BTC output, authorized by a
        # signature that committed to 100 BTC. This is the Trezor 2020 fee attack as a
        # transaction, and what happens next is the whole reason check 2 exists.
        tx = swap_witness_item(final_tx(core, honest_signed), honest, forged)
        return "signature over a lied amount, at consensus: %s" % rejects_tx(core, tx)

    case(results, "sign.singlesig.amount_lie_rejected_by_core", "bitcoin core + embit")(
        core_rejects_the_attack
    )


def multisig_cases(results, core, device, state):
    """2-of-3 P2WSH sortedmulti: the shape where a disagreement loses the money quietly.

    A wrong single-sig address is a refused signature or an unspendable receive. A wrong
    BIP-67 ordering is a DIFFERENT ADDRESS that every cosigner will happily pay into and
    none of them can spend from, and nothing on the way there raises an error.
    """
    cosigners = [
        embit_account(DEVICE_MNEMONIC, MULTISIG_ORIGIN),
        embit_account(COSIGNER_B_MNEMONIC, MULTISIG_ORIGIN),
        embit_account(COSIGNER_C_MNEMONIC, MULTISIG_ORIGIN),
    ]
    origin = MULTISIG_ORIGIN[2:]
    keys = [
        "[%s/%s]%s/<0;1>/*" % (fingerprint, origin, xpub)
        for fingerprint, xpub in cosigners
    ]
    # Deliberately NOT in BIP-67 order. sortedmulti sorts at derivation time, so a
    # descriptor written in any order must produce the same address; writing it sorted
    # would let a signer that never sorts pass this case by accident.
    unsorted_keys = sorted(keys, key=lambda k: k.split("]")[1], reverse=True)
    body = "wsh(sortedmulti(2,%s))" % ",".join(unsorted_keys)
    descriptor = "%s#%s" % (body, core.rpc("getdescriptorinfo", body)["checksum"])
    descriptor_file = os.path.join(device.workdir, "multisig.desc")
    with open(descriptor_file, "w") as handle:
        handle.write(descriptor)

    report = device.run(
        "multisig",
        "--mnemonic",
        DEVICE_MNEMONIC,
        "--network",
        NETWORK,
        "--descriptor-file",
        descriptor_file,
        "--count",
        ADDRESS_COUNT,
    )
    canonical = report["descriptor"]

    def registration():
        require(
            report["threshold"] == 2 and report["cosigners"] == 3,
            "we registered a %d-of-%d" % (report["threshold"], report["cosigners"]),
        )
        info = core.rpc("getdescriptorinfo", canonical)
        require(
            info["issolvable"],
            "Core cannot solve the descriptor we canonicalized to: %s" % canonical,
        )
        require(
            info["checksum"] == canonical.split("#")[1],
            "our checksum %s, Core says %s"
            % (canonical.split("#")[1], info["checksum"]),
        )
        return "registered as %s, our position %d of 3, Core agrees the form is solvable" % (
            report["registration_id"],
            report["our_position"],
        )

    case(results, "descriptor.multisig.registration", "bitcoin core")(registration)

    def addresses():
        from embit.descriptor import Descriptor

        derived = core.rpc(
            "deriveaddresses", descriptor, json.dumps([0, ADDRESS_COUNT - 1])
        )
        embit_descriptor = Descriptor.from_string(descriptor_body(descriptor))
        compared = 0
        for chain, keychain in ((0, "receive"), (1, "change")):
            for row in report[keychain]:
                index = row["index"]
                theirs = derived[chain][index]
                mine = embit_descriptor.derive(index, branch_index=chain).address(
                    embit_network()
                )
                require(
                    row["address"] == theirs,
                    "%s/%d: we say %s, Core says %s"
                    % (keychain, index, row["address"], theirs),
                )
                require(
                    row["address"] == mine,
                    "%s/%d: we say %s, embit says %s"
                    % (keychain, index, row["address"], mine),
                )
                compared += 1
        return "%d P2WSH addresses, three implementations, no disagreement" % compared

    case(results, "addresses.multisig.three_way", "bitcoin core + embit")(addresses)

    def order_irrelevant():
        # The device canonicalizes the cosigner order. If sorting were not really
        # happening on both sides, the canonical form and the file we handed over would
        # derive different addresses, and every cosigner would still agree with itself.
        derived_theirs = core.rpc(
            "deriveaddresses", descriptor, json.dumps([0, ADDRESS_COUNT - 1])
        )
        derived_ours = core.rpc(
            "deriveaddresses", canonical, json.dumps([0, ADDRESS_COUNT - 1])
        )
        require(
            descriptor_body(descriptor) != descriptor_body(canonical),
            "the two descriptors are textually the same, so this case proves nothing",
        )
        require(
            derived_theirs == derived_ours,
            "Core derives different addresses from two orderings of the same sortedmulti",
        )
        return "two cosigner orderings, identical addresses, on Core's arithmetic"

    case(results, "bip67.cosigner_order_irrelevant", "bitcoin core")(order_irrelevant)

    def unsorted_differs():
        # The negative control on the sorting itself. multi() keeps the written order, so
        # unless BIP-67 is really being applied the two must disagree somewhere.
        plain = body.replace("sortedmulti(", "multi(")
        plain = "%s#%s" % (plain, core.rpc("getdescriptorinfo", plain)["checksum"])
        sorted_addresses = core.rpc(
            "deriveaddresses", descriptor, json.dumps([0, ADDRESS_COUNT - 1])
        )
        plain_addresses = core.rpc(
            "deriveaddresses", plain, json.dumps([0, ADDRESS_COUNT - 1])
        )
        differences = sum(
            1
            for chain in (0, 1)
            for i in range(ADDRESS_COUNT)
            if sorted_addresses[chain][i] != plain_addresses[chain][i]
        )
        require(
            sorted_addresses[0][0] != plain_addresses[0][0],
            "sortedmulti and multi derive the SAME first receive address, so nothing here "
            "is testing BIP-67 ordering",
        )
        return (
            "%d of %d leaves differ from the unsorted form (the rest coincide because "
            "those keys were already in order)"
            % (differences, 2 * ADDRESS_COUNT)
        )

    case(results, "bip67.unsorted_differs", "bitcoin core")(unsorted_differs)

    # The ceremony.
    core.rpc(
        "-named",
        "createwallet",
        "wallet_name=multisig",
        "disable_private_keys=true",
        "blank=true",
    )
    core.rpc(
        "importdescriptors",
        json.dumps(
            [{"desc": descriptor, "active": True, "range": [0, 20], "timestamp": "now"}]
        ),
        wallet="multisig",
    )
    fund(core, "multisig", 2.0)

    # The unknown-field injection rides along on the multisig case rather than getting a
    # transaction of its own: a signer that preserved unknown pairs only when it had
    # nothing else to do would not be preserving them.
    base = create_psbt(core, "multisig")
    unsigned = write(device.path("multi-unsigned.psbt"), inject_unknown_pairs(base))
    signed_report = device.run(
        "sign",
        "--mnemonic",
        DEVICE_MNEMONIC,
        "--network",
        NETWORK,
        "--descriptor-file",
        descriptor_file,
        "--in",
        unsigned,
        "--out",
        device.path("multi-device.psbt"),
    )
    signed = read(device.path("multi-device.psbt"))

    def embit_verifies():
        entry = signed_report["signatures"][0]
        ok, digest = embit_verify_input(
            signed, entry["input"], entry["pubkey"], entry["signature"]
        )
        require(ok, "embit rejected our P2WSH signature over its own sighash %s" % digest)
        return "embit sighash %s over the witness script, signature verifies" % digest[:16]

    case(results, "sign.multisig.embit_verifies", "embit")(embit_verifies)

    def fields_survive():
        before = psbt_kv.Psbt.parse(read(unsigned))
        after = psbt_kv.Psbt.parse(signed)
        injected = count_unknown(read(unsigned))
        require(
            injected == len(UNKNOWN_PAIRS) * len(list(before.maps())),
            "the case did not carry the pairs it claims to: %d found" % injected,
        )
        require(
            count_unknown(signed) == injected,
            "unknown pairs went in %d, came out %d" % (injected, count_unknown(signed)),
        )
        touched = [d.describe() for d in psbt_kv.delta(before, after) if d.touched()]
        require(not touched, "signing altered or dropped pairs: %s" % "; ".join(touched))
        return "%d unknown and proprietary pairs across %d maps, none dropped or altered" % (
            injected,
            len(list(before.maps())),
        )

    case(
        results, "sign.multisig.unknown_fields_survive_signing", "independent kv reader"
    )(fields_survive)

    def ceremony():
        from embit.psbt import PSBT

        cosigned = PSBT.parse(signed)
        added = cosigned.sign_with(embit_root(COSIGNER_B_MNEMONIC))
        require(added == 1, "the cosigner added %d signatures, expected 1" % added)
        complete = cosigned.serialize()
        state["multi_two_sigs"] = complete
        analysis = core.rpc("analyzepsbt", to_base64(complete))
        require(
            analysis["next"] == "finalizer",
            "with two of three signatures Core says next is %s" % analysis["next"],
        )
        txid = accept(core, complete)
        return (
            "notyas signature plus one embit cosigner: Core finalizes, extracts and "
            "accepts, txid %s" % txid[:16]
        )

    case(results, "sign.multisig.ceremony_accepted", "bitcoin core + embit")(ceremony)

    def corrupt_rejected():
        complete = state.get("multi_two_sigs")
        require(complete is not None, "the ceremony did not run, so this cannot")
        entry = signed_report["signatures"][0]
        broken = corrupt_der(entry["signature"])
        corrupted = replace_partial_sig(complete, 0, entry["signature"], broken)
        # Establish that the corruption landed BEFORE asking Core about it. Without this,
        # a mutation that happened to produce a valid signature would be reported as the
        # oracle accepting corrupt material, which blames the wrong component.
        still_valid, _ = embit_verify_input(corrupted, 0, entry["pubkey"], broken)
        require(
            not still_valid,
            "the corrupted signature still verifies, so this case would prove nothing",
        )
        rejection = rejects(core, corrupted)
        return "our signature corrupted in a completed 2-of-3: Core says %s" % rejection

    case(results, "sign.multisig.corrupt_signature_rejected", "bitcoin core")(
        corrupt_rejected
    )

    def corrupt_rejected_at_consensus():
        complete = state.get("multi_two_sigs")
        require(complete is not None, "the ceremony did not run, so this cannot")
        ours = signed_report["signatures"][0]["signature"]
        tx = swap_witness_item(final_tx(core, complete), ours, corrupt_der(ours))
        return "our signature corrupted inside a complete 2-of-3 witness: %s" % (
            rejects_tx(core, tx)
        )

    case(
        results,
        "sign.multisig.corrupt_signature_rejected_at_consensus",
        "bitcoin core",
    )(corrupt_rejected_at_consensus)


def roundtrip_cases(results, core, device, state):
    """BIP-174's pass-through obligation, isolated from signing.

    "If the signer encounters key-value pairs that it does not understand, it must pass
    those key-value pairs through when re-serializing the transaction."
    """
    base = state["single_unsigned"]
    injected = inject_unknown_pairs(base)
    source = write(device.path("roundtrip-in.psbt"), injected)
    report = device.run(
        "roundtrip", "--in", source, "--out", device.path("roundtrip-out.psbt")
    )
    returned = read(device.path("roundtrip-out.psbt"))

    def survive():
        before = psbt_kv.Psbt.parse(injected)
        after = psbt_kv.Psbt.parse(returned)
        maps = len(list(before.maps()))
        expected = len(UNKNOWN_PAIRS) * maps
        # Precondition first: "every unknown pair survived" is vacuously true of a file
        # with no unknown pairs, and the device's own census has to agree with the bytes.
        require(
            count_unknown(injected) == expected,
            "the case carries %d injected pairs, not the %d it claims"
            % (count_unknown(injected), expected),
        )
        census = report["fields"]
        counted = (
            census["global_unknown"]
            + census["global_proprietary"]
            + census["input_unknown"]
            + census["input_proprietary"]
            + census["output_unknown"]
            + census["output_proprietary"]
        )
        require(
            counted == expected,
            "the device counted %d unknown pairs where the file has %d"
            % (counted, expected),
        )
        deltas = psbt_kv.delta(before, after)
        touched = [d.describe() for d in deltas if d.touched()]
        require(not touched, "the round trip changed pairs: %s" % "; ".join(touched))
        added = [d.describe() for d in deltas if d.added]
        require(not added, "the round trip invented pairs: %s" % "; ".join(added))
        reordered = [d.label for d in deltas if d.reordered]
        # Order is not owed and the tree says so (psbt.rs on `encode`): BIP-174 fixes no
        # order on pairs. Reported, never asserted, so this file cannot start failing over
        # something the specification does not require.
        note = " (canonical reordering in %s)" % ",".join(reordered) if reordered else ""
        return "%d pairs across %d maps returned intact%s" % (expected, maps, note)

    case(results, "roundtrip.unknown_fields_survive", "independent kv reader")(survive)

    def detector_alive():
        # A preservation check that has never been seen failing is not known to work.
        # Drop one pair from the returned file and require the comparison to notice.
        damaged = psbt_kv.Psbt.parse(returned)
        dropped = None
        for key, value in list(damaged.outputs[0]):
            if key in {k for k, _ in UNKNOWN_PAIRS}:
                damaged.outputs[0].remove((key, value))
                dropped = key
                break
        require(dropped is not None, "nothing to drop: the injection did not reach here")
        deltas = psbt_kv.delta(psbt_kv.Psbt.parse(injected), damaged)
        touched = [d for d in deltas if d.touched()]
        require(
            len(touched) == 1 and dropped in touched[0].dropped,
            "the comparison did not notice a dropped pair, so it would not have noticed "
            "a real one either",
        )
        return "dropping %s from output[0] is detected: %s" % (
            dropped.hex(),
            touched[0].describe(),
        )

    case(results, "roundtrip.detector_is_alive", "independent kv reader")(detector_alive)

    def third_party_decoders():
        """The same claim, put to the two decoders rather than to a reader of raw pairs.

        A byte-level diff can only say the pairs are the same bytes. This says an
        implementation that is not us reads them back as the same FIELDS: Core reports the
        unknown map and the proprietary entries of every scope, and embit exposes its own
        unknown dictionary per scope. Both are asked about the input and about what came
        back, and the answers have to match.
        """
        from embit.psbt import PSBT

        before = core.rpc("decodepsbt", to_base64(injected))
        after = core.rpc("decodepsbt", to_base64(returned))
        scopes = 0
        for label, left, right in scope_pairs(before, after):
            require(
                left.get("unknown") == right.get("unknown"),
                "Core reads a different unknown map in %s after the round trip: %s vs %s"
                % (label, left.get("unknown"), right.get("unknown")),
            )
            require(
                left.get("proprietary") == right.get("proprietary"),
                "Core reads different proprietary entries in %s: %s vs %s"
                % (label, left.get("proprietary"), right.get("proprietary")),
            )
            require(
                left.get("unknown") or left.get("proprietary"),
                "%s carries neither an unknown nor a proprietary pair according to Core, "
                "so this case is not testing anything there" % label,
            )
            scopes += 1

        parsed = PSBT.parse(returned)
        injected_pairs = {key: value for key, value in UNKNOWN_PAIRS}
        for label, scope in [("global", parsed)] + [
            ("input[%d]" % i, s) for i, s in enumerate(parsed.inputs)
        ] + [("output[%d]" % i, s) for i, s in enumerate(parsed.outputs)]:
            for key, value in injected_pairs.items():
                require(
                    scope.unknown.get(key) == value,
                    "embit does not see %s intact in %s" % (key.hex(), label),
                )
        return (
            "Core reads identical unknown and proprietary entries in all %d scopes; "
            "embit sees every injected pair in every scope" % scopes
        )

    case(
        results, "roundtrip.third_party_decoders_agree", "bitcoin core + embit"
    )(third_party_decoders)


# ---------------------------------------------------------------------------------------
# Core plumbing used by the cases
# ---------------------------------------------------------------------------------------


def fund(core, wallet, amount):
    """Put one confirmed coin of `amount` into `wallet`, mining what that needs."""
    if "miner" not in core.rpc("listwallets"):
        core.rpc("-named", "createwallet", "wallet_name=miner")
        core.rpc("generatetoaddress", 101, core.rpc("getnewaddress", wallet="miner"))
    target = core.rpc("getnewaddress", wallet=wallet)
    core.rpc("sendtoaddress", target, amount, wallet="miner")
    core.rpc("generatetoaddress", 1, core.rpc("getnewaddress", wallet="miner"))
    return target


def create_psbt(core, wallet):
    """A funded, unsigned PSBT spending `wallet`, paying somewhere else.

    Built by Bitcoin Core, deliberately (CORPUS.md 2.2): a base produced by the library
    under test would be normalized by the library under test on the way in.
    """
    destination = core.rpc("getnewaddress", wallet="miner")
    created = core.rpc(
        "-named",
        "walletcreatefundedpsbt",
        "outputs=" + json.dumps([{destination: 0.4}]),
        "fee_rate=10",
        wallet=wallet,
    )
    return from_base64(created["psbt"])


def accept(core, psbt_bytes):
    """Finalize, extract and submit to testmempoolaccept. Returns the txid.

    This is the sentence MILESTONES.md section 9 clause 2 asks for, in one call: a
    coordinator took what we signed, completed it, and the consensus rules accepted the
    transaction that came out.
    """
    finalized = core.rpc("finalizepsbt", to_base64(psbt_bytes))
    require(finalized.get("complete"), "Core could not finalize: %s" % finalized)
    verdicts = core.rpc("testmempoolaccept", json.dumps([finalized["hex"]]))
    verdict = verdicts[0]
    require(
        verdict["allowed"],
        "testmempoolaccept refused: %s" % verdict.get("reject-reason"),
    )
    return verdict["txid"]


def rejects(core, psbt_bytes):
    """Require Core to refuse this file, and return the words it refused with.

    Two ways to refuse are acceptable and both are real: the finalizer cannot assemble a
    witness at all, or it can and the resulting transaction fails script verification.
    Anything else - an accepted transaction - is the failure this case exists to catch.
    """
    try:
        finalized = core.rpc("finalizepsbt", to_base64(psbt_bytes))
    except CoreRefused as refusal:
        return "finalizepsbt refused (%s)" % first_line(str(refusal))
    if not finalized.get("complete"):
        return "finalizepsbt could not complete the transaction"
    verdicts = core.rpc("testmempoolaccept", json.dumps([finalized["hex"]]))
    verdict = verdicts[0]
    require(
        not verdict["allowed"],
        "Bitcoin Core ACCEPTED material this case corrupted on purpose. Either the "
        "corruption did not land or the oracle is not looking.",
    )
    return "testmempoolaccept: %s" % verdict.get("reject-reason", "rejected")


def final_tx(core, psbt_bytes):
    """The extracted transaction hex for a PSBT Core can finalize."""
    finalized = core.rpc("finalizepsbt", to_base64(psbt_bytes))
    require(finalized.get("complete"), "Core could not finalize: %s" % finalized)
    return finalized["hex"]


def swap_witness_item(tx_hex, old_item, new_item):
    """Replace one length-prefixed witness item in a serialized transaction.

    Substituting into the FINAL transaction rather than into the PSBT is what moves a
    negative case from the finalizer to the script interpreter. Core's finalizer checks
    signatures before it assembles a witness, so a corrupted PSBT is refused there and
    `testmempoolaccept` never sees it - which proves Core noticed, but not that the
    consensus rules would have. A witness this function built goes straight to
    `testmempoolaccept` and is judged by the same code that judges a block.

    The length prefix is part of both the search and the replacement, so a substitute of a
    different length still produces a well-formed transaction (DER signatures are 70, 71
    or 72 bytes, and which one you get is not under anyone's control).
    """
    old_framed = "%02x%s" % (len(old_item) // 2, old_item)
    new_framed = "%02x%s" % (len(new_item) // 2, new_item)
    require(
        old_framed in tx_hex,
        "the item to replace is not in the transaction, so this case would prove nothing",
    )
    return tx_hex.replace(old_framed, new_framed, 1)


def rejects_tx(core, tx_hex):
    """Require testmempoolaccept to refuse this transaction, and return why.

    This is the strongest rejection available anywhere in this harness: the same
    consensus and policy checks a node applies to a transaction it hears from the network.
    """
    verdict = core.rpc("testmempoolaccept", json.dumps([tx_hex]))[0]
    require(
        not verdict["allowed"],
        "Bitcoin Core ACCEPTED a transaction this case corrupted on purpose. Either the "
        "corruption did not land or the oracle is not looking.",
    )
    return verdict.get("reject-reason", "rejected")


def corrupt_der(signature_hex):
    """One byte flipped inside the r value: still DER, no longer a signature."""
    raw = bytearray(bytes.fromhex(signature_hex))
    raw[10] ^= 0x01
    return bytes(raw).hex()


def scope_pairs(before, after):
    """(label, before, after) for the global scope and every input and output scope.

    Over Core's decodepsbt output, so the comparison is between what Core read from the
    file that went in and what it read from the file that came back.
    """
    yield "global", before, after
    for i, (left, right) in enumerate(zip(before["inputs"], after["inputs"])):
        yield "input[%d]" % i, left, right
    for i, (left, right) in enumerate(zip(before["outputs"], after["outputs"])):
        yield "output[%d]" % i, left, right


def witness_utxo_value(data, index):
    parsed = psbt_kv.Psbt.parse(data)
    for key, value in parsed.inputs[index]:
        if key == b"\x01":
            return int.from_bytes(value[:8], "little")
    raise CheckFailed("input %d has no witness_utxo" % index)


def embit_network():
    from embit.networks import NETWORKS

    return NETWORKS[NETWORK]


def first_line(text):
    return text.strip().splitlines()[0] if text.strip() else ""


# ---------------------------------------------------------------------------------------
# Attestation
# ---------------------------------------------------------------------------------------


def tree_digest(repo):
    """A digest over the sources whose behaviour this run attests to.

    Not the whole tree: an attestation that went stale when a document was edited would be
    re-run so often that nobody would read it, and one that never went stale would be
    worthless. These are the files that decide what gets derived, what gets signed and
    what gets written out, plus the harness itself, because a cross-check is only evidence
    about the code it actually exercised.
    """
    tracked = []
    for relative in (
        "crates/notyas-core/src",
        "crates/notyas-wallet/src",
        "tools/xverify",
    ):
        root = os.path.join(repo, relative)
        for base, _, files in os.walk(root):
            for name in sorted(files):
                if name.endswith((".rs", ".py", ".toml")):
                    tracked.append(os.path.join(base, name))
    digest = hashlib.sha256()
    for path in sorted(tracked):
        digest.update(os.path.relpath(path, repo).replace("\\", "/").encode())
        digest.update(hashlib.sha256(read(path)).digest())
    return digest.hexdigest(), len(tracked)


def write_attestation(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path


# ---------------------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------------------


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="cross-check notyas PSBT output against Bitcoin Core and embit"
    )
    parser.add_argument("--bitcoind", default=os.environ.get("NOTYAS_XVERIFY_BITCOIND"))
    parser.add_argument(
        "--bitcoin-cli", default=os.environ.get("NOTYAS_XVERIFY_BITCOIN_CLI")
    )
    parser.add_argument("--device", default=os.environ.get("NOTYAS_XVERIFY_DEVICE"))
    parser.add_argument("--workdir", default=os.environ.get("NOTYAS_XVERIFY_WORKDIR"))
    parser.add_argument("--attestation", default=None)
    parser.add_argument(
        "--keep-node",
        action="store_true",
        help="leave the regtest node running for inspection after the run",
    )
    args = parser.parse_args(argv)

    repo = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    # Never inside the tree. A regtest datadir is thousands of small files, the working
    # tree is canonical on a network share on at least one machine this runs on, and the
    # only artifact of a run that belongs in the repository is the attestation.
    workdir = args.workdir or os.path.join(tempfile.gettempdir(), "notyas-xverify")
    attestation_path = args.attestation or os.path.join(
        repo, "out", "xverify", "attestation.json"
    )
    digest, file_count = tree_digest(repo)
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def record_skip(reason):
        # `tree_digest` is populated only by a run that really checked a tree. On a skip it
        # is null and the digest goes into a field whose NAME says it attests to nothing:
        # a 64-hex string sitting next to status "skipped" is exactly the shape a report
        # generator or a careless `jq .tree_digest` turns back into a claim. Same reason
        # for the bare "verified" boolean, which is the one field a consumer cannot
        # misread. tools/ci/check-xverify.sh writes this same shape for the skips that
        # happen before this file is even loaded.
        write_attestation(
            attestation_path,
            {
                "status": "skipped",
                "verified": False,
                "conclusion": "NOT VERIFIED - the cross-check did not run",
                "reason": reason,
                "when": started,
                "written_by": "tools/xverify/xverify.py",
                "harness_exit_code": 3,
                "tree_digest": None,
                "attests_to": None,
                "tree_digest_not_checked": digest,
                "tree_files": file_count,
                "cases_verified": 0,
                "cases_expected": len(EXPECTED),
                "cases_expected_names": EXPECTED,
            },
        )
        sys.stderr.write(
            "\n"
            + "!" * 78
            + "\n!! THE THIRD-PARTY CROSS-CHECK DID NOT RUN\n!!\n!! %s\n!!\n"
            "!! Nothing in this tree has been checked against an implementation outside\n"
            "!! it. See tools/xverify/README.md. Recorded as skipped in\n!! %s\n"
            % (reason, attestation_path)
            + "!" * 78
            + "\n"
        )

    try:
        tools = resolve_tools(args)
    except ToolMissing as missing:
        record_skip(str(missing))
        return 3

    os.makedirs(workdir, exist_ok=True)
    core = Core(
        tools["bitcoind"],
        tools["bitcoin_cli"],
        os.path.join(workdir, "regtest"),
        free_port(),
    )
    device = Device(tools["device"], workdir)
    results = Results()
    state = {}

    print("notyas cross-check")
    print("  bitcoind : %s" % tools["bitcoind_version"])
    print("  embit    : %s" % tools["embit_version"])
    print("  device   : %s" % tools["device"])
    print("  tree     : %s (%d files)" % (digest[:16], file_count))
    print()

    try:
        core.start()
        singlesig_cases(results, core, device, state)
        state["single_unsigned"] = read(device.path("single-unsigned.psbt"))
        roundtrip_cases(results, core, device, state)
        multisig_cases(results, core, device, state)
    except ToolMissing as missing:
        record_skip(str(missing))
        return 3
    finally:
        if not args.keep_node:
            core.stop()

    missing_cases = results.missing()
    for name in missing_cases:
        results.failed(name, "none", "this case did not run, and an unrun case is not a "
                                     "passed case")

    failures = results.failures()
    passed = not failures
    status = "passed" if passed else "FAILED"
    # `verified` is true on exactly one path in this whole tool: every expected case ran
    # and both oracles agreed. A FAILED run keeps its tree_digest, because a tree really
    # was checked and the disagreement is a fact about that tree.
    write_attestation(
        attestation_path,
        {
            "status": status,
            "verified": passed,
            "conclusion": (
                "VERIFIED - %d cases, 0 failures, against Bitcoin Core and embit"
                % len(results.records)
                if passed
                else "FAILED - %d of %d cases disagreed with an oracle"
                % (len(failures), len(results.records))
            ),
            "when": started,
            "written_by": "tools/xverify/xverify.py",
            "harness_exit_code": 0 if passed else 1,
            "tree_digest": digest,
            "attests_to": "crates/notyas-core/src, crates/notyas-wallet/src, tools/xverify",
            "tree_files": file_count,
            "oracles": {
                "bitcoind": tools["bitcoind_version"],
                "embit": tools["embit_version"],
            },
            "cases_verified": len(results.records) - len(failures),
            "cases_expected": len(EXPECTED),
            "cases_expected_names": EXPECTED,
            "results": results.records,
        },
    )

    print()
    print(
        "%d cases, %d failed. Attestation: %s"
        % (len(results.records), len(failures), attestation_path)
    )
    return 0 if not failures else 1


def resolve_tools(args):
    """Find the oracles, or say precisely which one is missing.

    No filesystem search. Either a flag, an environment variable or PATH names the tool,
    or it is missing - a harness that went looking for a bitcoind would be slow when it
    worked and terrifying when it did not.
    """
    bitcoind = args.bitcoind or shutil.which("bitcoind")
    cli = args.bitcoin_cli or shutil.which("bitcoin-cli")
    if not bitcoind or not os.path.exists(bitcoind):
        raise ToolMissing(
            "bitcoind was not found. Pass --bitcoind, set NOTYAS_XVERIFY_BITCOIND, or "
            "put it on PATH."
        )
    if not cli or not os.path.exists(cli):
        raise ToolMissing(
            "bitcoin-cli was not found. Pass --bitcoin-cli, set "
            "NOTYAS_XVERIFY_BITCOIN_CLI, or put it on PATH."
        )
    device = args.device
    if not device or not os.path.exists(device):
        raise ToolMissing(
            "the xverify-device binary was not found (looked at %r). Build it: "
            "cargo build --manifest-path tools/xverify/Cargo.toml" % device
        )
    load_embit()
    version = subprocess.run([bitcoind, "-version"], capture_output=True, text=True)
    return {
        "bitcoind": bitcoind,
        "bitcoin_cli": cli,
        "device": device,
        "bitcoind_version": first_line(version.stdout),
        "embit_version": embit_version(),
    }


if __name__ == "__main__":
    sys.exit(main())
