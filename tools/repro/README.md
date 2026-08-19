# tools/repro - the notyas release build

The normative way a notyas firmware image is produced. A file that some other
command produced is not a release artifact, however identical it looks, because
the whole point is that a stranger can run this and get the same bytes.

Verifier-facing instructions are [VERIFYING.md](../../VERIFYING.md) at the
repository root. The design and the reasoning - every source of
nonreproducibility in this stack, named, with its fix - are
`docs/plan-0.2.0/REPRODUCIBLE.md`.

## Files

| File | What it is | Licence |
| --- | --- | --- |
| `Dockerfile` | the release container: `espressif/idf` pinned by digest, the pinned Rust nightly with `rust-src`, and exact `=` pins for the host tools that sit in the artifact path | MIT OR Apache-2.0 |
| `build.sh` | the build itself, and the image's entrypoint: clean environment, lock assertions, `git archive` of the committed tree, the cargo and image steps, then the artifacts | MIT OR Apache-2.0 |
| `toolchain.lock` | every version that can change a byte, asserted before anything is compiled | MIT OR Apache-2.0 |
| `check-repro.sh` | builds each board twice under deliberately different conditions and compares every byte | GPL-3.0-or-later |
| `verify-manifest.py` | produces and checks `notyas-<ver>-<board>-VERIFY.json`, the signed per-board manifest that lets a user compare their device against a release | GPL-3.0-or-later |

The container definition and the CI workflow (`.github/workflows/repro.yml`) are
permissively licensed on purpose: their entire value is that another project can
lift them, and a snippet a reader has to licence-audit before pasting is a
snippet nobody uses. Everything else in notyas is GPL-3.0-or-later.

## Building a release

```sh
# From the repository root, on an x86-64 Linux host with Docker.
docker build -t notyas-repro -f tools/repro/Dockerfile .

# One invocation per board, sharing one output directory. The source is mounted
# read-only; the script takes a `git archive` of HEAD, so an ignored build
# directory or a stray untracked file can never become a build input.
docker run --rm -v "$PWD":/mnt/src:ro -v "$PWD/out":/out notyas-repro waveshare-4b
docker run --rm -v "$PWD":/mnt/src:ro -v "$PWD/out":/out notyas-repro elecrow-5

# Prove it reproduces rather than assuming it: two builds per board, from two
# host paths, at different times, the second handed a hostile environment.
tools/repro/check-repro.sh

# Sign the hash list. On the maintainer's machine, never on a runner.
gpg --armor --detach-sign out/SHA256SUMS.txt
```

`out/SHA256SUMS.txt` is regenerated from the contents of the output directory
rather than from a list written down somewhere, so a new artifact cannot quietly
escape being hashed - which is exactly the hole that a published-but-not-reproduced
file would be.

## The first run on a new machine

`toolchain.lock` ships with some entries set to `pending`: the versions that can
only be read off the container, on a host that has Docker. `build.sh` refuses to
produce release artifacts while any entry is pending, because a lock that
asserts nothing is worse than no lock. To fill them in:

```sh
docker run --rm -v "$PWD":/mnt/src:ro -v "$PWD/out":/out \
    notyas-repro waveshare-4b --bootstrap
```

It prints every observed value in the lock's own format. Paste them over the
pending lines, commit, and every later build asserts them.

## What it does not do

It does not sign images for Secure Boot and it does not encrypt flash: 0.2.0
ships with neither, deliberately, so a verifier flashes exactly what they built.
It does not burn eFuses; the one burn 0.2.0 performs is the sealed-storage HMAC
key, which is a separate host-side ceremony documented in `docs/PROVISIONING.md`.

## Lifting this into another project

The parts worth copying are the Dockerfile, `build.sh` and the pattern in
`toolchain.lock`. Four things in them are load-bearing and easy to leave out:

1. **`-Zbuild-std` makes the standard library a local build input**, so cargo
   `trim-paths` is not optional - without it your sysroot path, including your
   user name, ends up in the binary.
2. **`cc`-built C dependencies are outside the IDF prefix maps**, because they
   are compiled by cargo rather than by the IDF CMake build. They need their own
   `-ffile-prefix-map`.
3. **ESP-IDF resolves the project version with `git describe`** inside a
   generated CMake project whose git context is undefined. Pin it explicitly, or
   your image carries a version string that depends on how the checkout was made.
4. **Managed ESP-IDF components use caret ranges.** Commit the component lock and
   fail the build if it changes; otherwise a component publisher can alter tens
   of kilobytes of C inside your image without anyone touching your repository.
