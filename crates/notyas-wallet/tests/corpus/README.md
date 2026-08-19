# transport corpus - signed PSBTs, generated

Two PSBTs that `notyas-core`'s signing engine produced, in hex, one per file, wrapped at
80 columns. They exist so that `crates/notyas-wallet/src/transport/`'s round-trip tests
carry something the device would really emit rather than a pattern invented to be easy.

**These are GENERATED, not published vectors.** Nothing in BIP-174 or in the UR2
specification pins them, and they carry no authority beyond "this is what this tree's
signer produced from this seed". The published vectors this module is held to are
`bc-ur`'s, pinned in `src/transport/ur.rs`, and BBQr's, pinned in `src/transport/bbqr.rs`.

| File | Bytes | What it is |
|---|---|---|
| `signed-psbt-p2wpkh.hex` | 379 | one P2WPKH input, one signature, from `notyas_core::psbt::fixture::p2wpkh_psbt` |
| `signed-psbt-multisig.hex` | 643 | one 2-of-3 P2WSH `sortedmulti` input carrying this device's one partial signature, from `notyas_core::psbt::fixture::multisig_psbt` and the fixture registration |

## Provenance and how to regenerate

Both derive from the fixed fixture seed `[0x2a; 64]`
(`notyas_core::psbt::fixture::SEED`), on mainnet, and signing in this tree consumes no
randomness (SECURITY.md invariant 3, and ECDSA nonces are RFC-6979 with the low-R
grinding of the ratified Q3), so the bytes are reproducible. To regenerate, add a
temporary test beside `notyas_core::psbt::signer`'s own tests that signs the fixture,
`crate::psbt::encode`s the result and prints it as hex, run it with `--nocapture`, and
delete the test again. The signing calls are exactly the ones
`signer.rs`'s `sign_fixture` and `sign_multisig` helpers make.

If a change to the signing engine moves these bytes, that is a signing-engine finding to
investigate first - a signature is not supposed to move - and only then a corpus to
refresh. The transport tests re-parse each file with `notyas_core::psbt::decode` before
using it, so a corrupt or truncated file fails as a corpus error rather than as a
transport one.
