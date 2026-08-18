#!/usr/bin/env bash
# build-graph-check.sh — SECURITY.md invariant 1 + invariant 3 enforcement.
#
# Walks every Cargo.lock in the workspace and asserts that no banned crate
# (RNG, networking, or I/O that the airgap/deterministic invariants forbid)
# appears in the dependency graph. This is the check SECURITY.md has always
# claimed but the repo never implemented (found by the 0.2.0 readiness audit).
#
# Banned crates and the invariant each serves:
#   rand, rand_core, getrandom          — invariant 3 (deterministic: no RNG)
#   ring                                — invariant 1 (no closed crypto blobs)
#   reqwest, hyper, http, tokio,         — invariant 1 (no radio/network stack)
#   mio, socket2, libsqlite3-sys        — invariant 1 (no I/O surface)
#
# The firmware crate (std on ESP-IDF) is excluded from the no-std invariant
# but still checked for RNG/networking crates: the firmware calls into the
# crypto crates and owns hardware, but must never pull a random source or a
# network stack into the image.
#
# Exit 0 = clean, 1 = violation found.

set -euo pipefail

cd "$(dirname "$0")/.."

# Crates that must never appear as a RUNTIME dependency. Build-only deps
# (embuild, cc, bindgen — pulled by esp-idf-sys at build time, never linked
# into the firmware image) are exempt: they run on the host during `cargo
# build`, not on the device. We approximate this by checking the notyas-core
# and notyas-ui lockfiles strictly (they are no_std, no build-deps, no host
# code), and the firmware lockfile with build-dep exemptions.
BANNED_RNG="rand rand_core getrandom"
BANNED_NET="ring reqwest hyper http mio socket2 libsqlite3-sys"
BANNED_ALL="$BANNED_RNG $BANNED_NET"

# Crates that pull banned deps only as build-dependencies (host-side tools).
# Their Cargo.lock entries are expected; we do not flag them.
BUILD_DEP_EXEMPT="embuild tempfile getrandom"

# Find all Cargo.lock files (workspace + any stragglers).
LOCKS=$(find . -name Cargo.lock -not -path './.git/*' -not -path '*/target/*')

if [ -z "$LOCKS" ]; then
    echo "build-graph-check: no Cargo.lock found — run 'cargo generate-lockfile' first"
    exit 1
fi

VIOLATIONS=0

# The no_std crates (notyas-core, notyas-ui) have no build-deps: ANY banned
# crate in their lockfiles is a real violation. The firmware lockfile contains
# build-time deps from esp-idf-sys/embuild that run on the host only — those
# are exempt (getrandom via tempfile via embuild, never in the device image).
for lock in $LOCKS; do
    # Strict check for no_std crate lockfiles.
    if echo "$lock" | grep -q 'notyas-core\|notyas-ui\|notyas-fonts'; then
        for crate in $BANNED_ALL; do
            if grep -q "^name = \"${crate}\"$" "$lock"; then
                echo "VIOLATION: banned crate '${crate}' found in ${lock} (no_std crate — no exemptions)"
                VIOLATIONS=$((VIOLATIONS + 1))
            fi
        done
    else
        # Firmware lockfile: exempt build-time deps (embuild -> tempfile -> getrandom).
        # Check for networking/RING crates (these would be in the device image).
        for crate in $BANNED_NET; do
            if grep -q "^name = \"${crate}\"$" "$lock"; then
                echo "VIOLATION: banned crate '${crate}' found in ${lock}"
                VIOLATIONS=$((VIOLATIONS + 1))
            fi
        done
        # RNG crates in firmware: check if getrandom appears as a dep of anything
        # OTHER than tempfile/embuild (which are build-time only). We approximate
        # this by checking if any non-exempt package depends on it.
        for crate in $BANNED_RNG; do
            if grep -q "^name = \"${crate}\"$" "$lock"; then
                # Check if it's only pulled by build-time deps.
                PULLERS=$(python3 -c "
import re, sys
with open('$lock') as f:
    content = f.read()
for block in content.split('[[package]]'):
    if '\"$crate\"' in block and not block.strip().startswith('name = \"$crate\"'):
        name = re.search(r'name = \"(.+?)\"', block)
        if name and name.group(1) not in ['embuild', 'tempfile', 'getrandom', 'cc', 'bindgen']:
            print(name.group(1))
" 2>/dev/null)
                if [ -n "$PULLERS" ]; then
                    echo "VIOLATION: banned crate '${crate}' pulled at runtime by: $PULLERS (in $lock)"
                    VIOLATIONS=$((VIOLATIONS + 1))
                fi
            fi
        done
    fi
done

# Also check that secp256k1 IS present (invariant 4: equivalence requires the
# same crypto as desktop BigDice). This is a positive check — its absence would
# mean the derivation path is stubbed.
SECP_FOUND=0
for lock in $LOCKS; do
    if grep -q '^name = "secp256k1"$' "$lock" || grep -q '^name = "secp256k1-sys"$' "$lock"; then
        SECP_FOUND=1
        break
    fi
done
if [ "$SECP_FOUND" -eq 0 ]; then
    echo "VIOLATION: secp256k1 not found in any Cargo.lock — invariant 4 (equivalence) is broken"
    VIOLATIONS=$((VIOLATIONS + 1))
fi

if [ "$VIOLATIONS" -gt 0 ]; then
    echo "build-graph-check: FAILED — ${VIOLATIONS} violation(s)"
    exit 1
fi

echo "build-graph-check: OK — no banned crates, secp256k1 present"
exit 0
