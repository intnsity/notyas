# UI screenshots (generated - do not edit)

Rendered by `tools/uisim` from `crates/notyas-ui`, on the primary 720x720 panel and, where
the shorter panel reflows into a different ARRANGEMENT rather than a compression, on
800x480 as well. Deterministic: same input -> same PNG bytes; the tool renders each frame
twice and refuses to write on any divergence.

These pictures are the HUMAN surface, not the regression gate, and they are a subset of
what is gated. `tools/uisim/src/catalog.rs` declares every screen in every state it has,
and `tools/uisim/tests/gate.rs` renders all of them on all five shipped panel geometries
on every `cargo test`; what is committed here is the curated set worth looking at. A
picture per gated frame would be roughly 10 MB of binary churn per layout change, so the
rest is committed as text in `tools/uisim/goldens.txt`.

Do not regenerate these by hand. Approve them, which re-runs the bounds and coverage gates
first and refuses to write if either fails:

    cargo run -p uisim -- approve
    git add docs/screenshots/ui tools/uisim/goldens.txt

`cargo run -p uisim -- diff` writes a before/after image per file below into
`target/uigate/` if you want to see which pixels moved.

Sample data - all of it public test-vector material, none of it a real seed:

- Dice input: 64 sixes. A six maps to digit 0 (SPEC step 2), so RAW mode yields the
  all-zeros 128-bit entropy of BIP39 test vector #1; the mnemonic shown revealed is the
  well-known "abandon abandon ... about".
- Passphrase: "TREZOR", the official BIP39 test-vector passphrase, so the schemes
  screen shows keys checkable against the published vectors.
- Phrase-entry screen: "zoo zoo ... zoo wrong" (Trezor vector #4, valid checksum).
- Verify screen: placeholder values, each prefixed DUMMY; on hardware the firmware
  fills them from what it actually read.

Each stem is a picture of one frame on one panel. A stem with no suffix is the 720x720
Waveshare 4B; a stem ending `-800x480` is the Elecrow 5inch. Most frames have only the
720x720 file, and that means the shorter panel shows the same arrangement. A second file is
committed where what the shorter panel does is worth seeing on its own: usually because the
screen rearranges, sometimes because it does not and the content runs past the fold instead.
The other three shipped geometries are gated and not pictured.

**[INDEX.md](INDEX.md) says what every file shows.** It is generated from
`tools/uisim/src/index.rs` by the same `tour` that writes the pictures, and it carries the
catalogue frame each one came from, so a picture leads back to the state that produced it
and to `cargo run -p uisim -- render <frame>`. Match on the whole stem and never on the
leading number: five prefixes name two different screens each (72, 73, 74, 90 and 91).

Recordings of routes through these screens, rather than single states, are in
[docs/media/](../../media) and are embedded from [docs/TOUR.md](../../TOUR.md).
