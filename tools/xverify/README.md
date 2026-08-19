# xverify - cross-checking what this tree signs against implementations that are not it

Everything notyas produces is checked, elsewhere in this repository, by notyas code
against vectors notyas chose. That is how an implementation and its tests come to be wrong
together, and it has happened here twice already: a BIP-174 vector carrying a transposed
key type whose assertion agreed with it, and a relaxed check that passed every test while
reopening a demonstrated 1 BTC loss.

This directory is the answer to that. It hands what this tree derives and signs to two
implementations that share no code with it and none with each other, and lets them decide.

```
tools/xverify/
  Cargo.toml     xverify-device: the notyas side. NOT a workspace member.
  src/main.rs      derives, signs, re-encodes and reports. Decides nothing.
  xverify.py     the driver: builds the material, runs the oracles, reports and attests.
  psbt_kv.py     BIP-174 at the key-value layer, for building and diffing raw pairs.
tools/ci/check-xverify.sh   the gate, and the policy for what a missing oracle costs.
```

## The oracles

| | What it is | What only it can say |
|---|---|---|
| **Bitcoin Core** 29.x, regtest, no peers | The reference implementation | Whether the transaction we signed is CONSENSUS- and POLICY-valid: `finalizepsbt`, then `testmempoolaccept` over the extracted transaction |
| **embit** 0.8 (MIT, the signer library behind SeedSigner, Krux and Specter DIY) | An independent PSBT parser, sighash and secp256k1 binding, from the embedded-signer lineage | Whether a signature verifies against a sighash IT computed, per input, with a reason a person can read |

Two rather than one because CORPUS.md 3.0 already made that the rule for key generation:
no expected value is written down until two implementations that share no code agree.
Signing does not get the weaker rule.

**How this differs from `tools/psbtgen`.** psbtgen is the operator-facing half of
MILESTONES.md section 9 clause 2: it builds the files a human carries to a device on an SD
card and re-checks what comes back. It is excellent at that and it is built on
`notyas-core`, which means every sighash it recomputes and every signature it verifies is
computed by the same library that produced them. The two tools answer different questions.
psbtgen answers "is this file well formed and self-consistent". xverify answers "does
something that is not us accept it".

## Running it

```
bash tools/ci/check-xverify.sh            # skip loudly if the oracles are absent
bash tools/ci/check-xverify.sh --require  # absence is a failure (CI and the release gate)
bash tools/ci/check-xverify.sh --probe    # exit 0 if the oracles are here, 3 if not
```

Every run writes `out/xverify/attestation.json`: the status, the oracle versions, the
digest of the sources it attests to, and one record per case.

### Installing the oracles

Bitcoin Core, pinned and checksummed (any recent release works; this is the one the
attestations in this tree were produced with):

```
curl -O https://bitcoincore.org/bin/bitcoin-core-29.4/bitcoin-29.4-win64.zip
# 31e03b841bf2bbe711cf0179d3466678989fcbd46e5ef9bef957a20fa32e0e42
```

embit, into whichever interpreter will run the harness:

```
python -m pip install embit
```

Then either put `bitcoind`/`bitcoin-cli` on PATH, or name them:

```
NOTYAS_XVERIFY_BITCOIND=.../bitcoind.exe
NOTYAS_XVERIFY_BITCOIN_CLI=.../bitcoin-cli.exe
NOTYAS_XVERIFY_PYTHON=.../python.exe      # one that can import embit
NOTYAS_XVERIFY_WORKDIR=...                # regtest datadir; defaults to a temp directory
```

The node runs `-regtest -noconnect -listen=0 -dnsseed=0` on an ephemeral datadir and a
free port, and is stopped when the run ends. It never contacts a network peer.

## What is checked

Twenty-one cases. Nine of them are negatives, and they are not optional.

**Derivation and descriptors**
- our BIP-380 descriptor checksum against Core's `getdescriptorinfo`
- ten single-sig addresses against Core's `deriveaddresses` and embit's descriptor
- a 2-of-3 `wsh(sortedmulti(...))` registration: we register a descriptor the DRIVER
  composed from embit-derived cosigner xpubs, and Core agrees the canonical form we store
  is solvable and carries the checksum we computed
- ten P2WSH addresses, three implementations
- BIP-67: two cosigner orderings of the same `sortedmulti` derive identical addresses,
  and the `multi()` form of the same keys does NOT. The second is the one that matters -
  without it, an implementation that never sorted would pass the first

**Round trip (BIP-174's pass-through obligation)**
- an unknown pair and a proprietary pair injected into EVERY map of a real PSBT come back
  byte-identical, counted twice: by the device's own census and by an independent reader
- and read back as the same FIELDS by the two decoders: Core's `decodepsbt` reports the
  same `unknown` map and the same `proprietary` entries in every scope before and after,
  and embit sees every injected pair in every scope
- the comparison is then shown catching a deliberately dropped pair

**Signing**
- our ECDSA signature verifies under embit, over a sighash embit computed itself, for
  P2WPKH and for P2WSH multisig
- Core's `analyzepsbt` says the next role is the finalizer, `finalizepsbt` completes, and
  `testmempoolaccept` allows the extracted transaction
- a full 2-of-3 ceremony: notyas signs, an embit cosigner signs, Core finalizes, extracts
  and accepts
- unknown and proprietary pairs survive SIGNING, not merely a round trip

**And the negatives**
- a flipped byte in one of our signatures: embit says false, Core's finalizer refuses, and
  the same corruption spliced into the final witness is rejected by `testmempoolaccept`
  with a script-verify failure
- one satoshi moved between outputs after signing: both oracles reject
- the BIP-143 fee attack from both ends. First this device REFUSES the file, twice: once
  where the claimed amount contradicts the prev tx (`PrevAmountMismatch`), once where the
  prev tx has been stripped so the claim is merely unbacked (`MissingPreviousTransaction`).
  Then embit, standing in for a signer that believes claimed amounts, signs the lie, its
  signature is spliced into the real transaction, and Bitcoin Core rejects it at consensus.
  That last step is what makes the refusal worth having: it shows the check is defending
  against something a node really would refuse, rather than being a check.

## Proving the cross-check can fail

A check never observed failing is not known to work, so it has been observed failing. A
copy of `xverify-device` was built outside the repository with one line added: after the
post-sign gate has passed, flip one bit of every signature it produces. Pointing the
harness at that binary with `--device` turns **9 of the 21 cases red** and exits 1 -
embit rejects both signatures over its own sighashes, Core's `analyzepsbt` says the file
still needs a signer rather than a finalizer, and the 2-of-3 ceremony never completes.

The derivation and round-trip cases stay green under that fault, which is correct: a
signer that derives the right keys and preserves every field, and signs wrongly, is
exactly what a one-bit signature fault produces.

The nine negatives are the same evidence in permanent form. Each one corrupts exactly one
thing about material this tree really produced and requires an implementation outside it
to say no, so an oracle that had been stubbed, mocked or pointed at the wrong file fails
the suite on the run that broke it rather than on the release that needed it.

## Why absence is loud, and what it costs

A cross-check that silently skips when its tools are absent is worse than no cross-check,
because the suite goes green and everyone believes it ran. So:

- **No case ever skips.** A missing tool stops the run before any case reports.
- **The banner is unmissable**, and it is not the record. `out/xverify/attestation.json`
  is written on every path, including the one where nothing ran, with the reason.
- **The cost of absence depends on who is asking.** On a developer's machine it is a
  warning: making an unbuildable tree the price of not having installed a Bitcoin node
  would end with somebody deleting the gate. In CI it is a failure, because CI installs
  the oracles (see `.github/workflows/ci.yml`). At release it is a failure, because
  "we could not check" is not an answer a release may give; `tools/release.sh gates` runs
  `--require`, and the existing `gate_unavailable` machinery forces the releaser to name
  where it did run if it could not run there.

## Why it lives outside the workspace

`tools/xverify/Cargo.toml` declares an empty `[workspace]`, which makes it its own
workspace root. Nothing in the tree depends on it, it cannot appear in the root
`Cargo.lock` or in `cargo tree -p notyas-core`, and `tools/build-graph-check.sh` sees the
same graph it saw before.

This follows the m8 precedent, where the transport encoders were cross-checked by decoding
every emitted frame with `foundation-ur` and `bbqr` in a throwaway crate outside the tree,
because `foundation-ur` reaches an RNG through `rand_xoshiro` and SECURITY.md invariant 3
bans one at any depth in the device image. Here the dependency argument is not needed -
neither oracle is a Rust crate - but the placement rule is the same and it has a second
reason of its own: an oracle inside the tree under test is not an oracle.

## Material

Three published BIP-39 test mnemonics (CORPUS.md 2.3) and regtest coins. Both halves
enforce it: `xverify-device` refuses any mnemonic that is not on the list, and refuses
mainnet for all but the all-zero `abandon` wallet. No run of this harness can touch a seed
that is not already public.
