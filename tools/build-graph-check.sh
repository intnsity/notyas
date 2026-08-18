#!/usr/bin/env bash
# build-graph-check.sh - SECURITY.md invariant 1 + invariant 3 enforcement.
#
# Walks every Cargo.lock in the workspace and asserts that no banned crate
# (RNG, networking, or I/O that the airgap/deterministic invariants forbid)
# appears in the dependency graph. This is the check SECURITY.md has always
# claimed but the repo never implemented (found by the 0.2.0 readiness audit).
#
# Banned crates and the invariant each serves:
#   rand, rand_core, getrandom          - invariant 3 (deterministic: no RNG)
#   ring                                - invariant 1 (no closed crypto blobs)
#   reqwest, hyper, http, tokio,         - invariant 1 (no radio/network stack)
#   mio, socket2, libsqlite3-sys        - invariant 1 (no I/O surface)
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
# (embuild, cc, bindgen - pulled by esp-idf-sys at build time, never linked
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

# The crates that link into the device image and are no_std by contract. Their
# dependency SUBTREES admit no exemption at all - see the strict section at the
# bottom of this script for why the rule lives there rather than here.
STRICT_PACKAGES="notyas-core notyas-ui notyas-fonts notyas-wallet"

# Find all Cargo.lock files (workspace + any stragglers).
# -prune, not -not -path: the filter form still DESCENDS into every pruned
# directory and discards the results afterwards, which means walking the whole
# build tree - thousands of files, over SMB - on every run of this gate.
LOCKS=$(find . \( -name .git -o -name target \) -prune -o -name Cargo.lock -print)

if [ -z "$LOCKS" ]; then
    echo "build-graph-check: no Cargo.lock found - run 'cargo generate-lockfile' first"
    exit 1
fi

VIOLATIONS=0

# Lockfile-wide rules. A lockfile covers the WHOLE resolution, host build tools
# included, so it cannot on its own distinguish "in the device image" from "runs
# on the maintainer's machine during a build": networking and closed-crypto
# crates are banned outright, and RNG crates are banned unless the only thing
# pulling them is one of the host-side build tools. The per-crate strict rules,
# which admit no exemption, are at the bottom of this script.
#
# (Until 0.1.0 this loop had a second arm that applied the strict rules to
# crates/notyas-*/Cargo.lock. The workspace unification - commit dd374cb - left
# exactly one lockfile at the root, so that arm's path test stopped matching
# anything and the strict rules silently stopped running. They were rewritten
# against the resolved dependency subtrees instead, where there is no path to go
# stale; see the strict section below.)
for lock in $LOCKS; do
        for crate in $BANNED_NET; do
            if grep -q "^name = \"${crate}\"$" "$lock"; then
                echo "VIOLATION: banned crate '${crate}' found in ${lock}"
                VIOLATIONS=$((VIOLATIONS + 1))
            fi
        done
        # RNG crates: flag them unless the only packages depending on them are
        # the host-side build tools (embuild -> tempfile -> getrandom, which
        # never reaches the device image).
        #
        # Implemented in awk, not python: this check must run identically on a CI
        # runner, a maintainer's Windows shell and a minimal container. A silently
        # missing interpreter used to abort the whole script under `set -e` with no
        # message, which is the worst possible failure mode for a security gate.
        for crate in $BANNED_RNG; do
            if grep -q "^name = \"${crate}\"$" "$lock"; then
                # Every package whose `dependencies` list names $crate, minus the
                # host-side build-tool exemptions. Lockfile dependency entries are
                # either "name" or "name version (source)", so the first
                # whitespace-separated token is the crate name.
                PULLERS=$(awk -v crate="$crate" -v exempt=" $BUILD_DEP_EXEMPT cc bindgen " '
                    /^\[\[package\]\]/ { name = ""; indeps = 0; next }
                    /^name = "/        { name = $0; sub(/^name = "/, "", name);
                                         sub(/"$/, "", name); next }
                    /^dependencies = \[/ { indeps = 1; next }
                    indeps && /^\]/    { indeps = 0; next }
                    indeps {
                        dep = $0
                        sub(/^[ \t]*"/, "", dep)
                        sub(/",?$/, "", dep)
                        split(dep, parts, " ")
                        if (parts[1] == crate && name != crate &&
                            index(exempt, " " name " ") == 0) seen[name] = 1
                    }
                    END { for (n in seen) print n }
                ' "$lock" | sort | tr '\n' ' ')
                if [ -n "$PULLERS" ]; then
                    echo "VIOLATION: banned crate '${crate}' pulled at runtime by: $PULLERS (in $lock)"
                    VIOLATIONS=$((VIOLATIONS + 1))
                fi
            fi
        done
done

# --- strict: the crates that link into the device image ----------------------
#
# notyas-core, notyas-ui and notyas-fonts are no_std by contract and carry no
# build dependencies, so nothing in their subtrees has a host-only excuse: ANY
# banned crate anywhere under them is a violation, full stop. The subtree is
# read from cargo rather than from the lockfile because the lockfile is one flat
# resolution of the whole workspace - it cannot tell which package pulled what,
# which is precisely how a `rand` reaching the crypto core would hide behind a
# host tool's exemption above.
#
# The default feature set is used deliberately: it is the set the firmware links
# (notyas-core's `qr`, for instance), so it is the set the invariant is about.
if ! command -v cargo >/dev/null 2>&1; then
    echo "VIOLATION: cargo not found - the per-crate strict check cannot run, and a"
    echo "           security gate that skips silently is worse than no gate at all"
    VIOLATIONS=$((VIOLATIONS + 1))
else
    for pkg in $STRICT_PACKAGES; do
        if ! TREE=$(cargo tree --locked --package "$pkg" --edges normal --prefix none 2>&1); then
            echo "VIOLATION: cannot resolve ${pkg}'s dependency tree:"
            echo "$TREE" | sed 's/^/           /'
            VIOLATIONS=$((VIOLATIONS + 1))
            continue
        fi
        for crate in $BANNED_ALL; do
            if printf '%s\n' "$TREE" | grep -q "^${crate} v"; then
                echo "VIOLATION: banned crate '${crate}' in ${pkg}'s dependency tree"
                echo "           (no_std crate that links into the device image - no exemptions)"
                printf '%s\n' "$TREE" | grep -n "^${crate} v" | sed 's/^/           /'
                VIOLATIONS=$((VIOLATIONS + 1))
            fi
        done
    done
fi

# --- the sealing engine's host-only feature must never enter the firmware -----
#
# notyas-wallet's `testkit` feature pulls in the NOR simulator, the power-loss harness and
# `extern crate std`. A firmware build that enabled it would link a fake flash backend and
# a compiled-in test MAC key beside the real ones, which is the shape of ESP-SEAL.md 6.4's
# development-key hazard. Cargo feature unification means a transitive dependency could
# turn it on without anyone editing the firmware manifest, so it is checked rather than
# assumed. The default feature set is the one the firmware links, so that is the one asked.
if command -v cargo >/dev/null 2>&1; then
    if TREE=$(cargo tree --locked --package notyas-wallet --edges normal --prefix none               --format '{p} {f}' 2>&1); then
        if printf '%s
' "$TREE" | grep -q '^notyas-wallet .*testkit'; then
            echo "VIOLATION: notyas-wallet's 'testkit' feature is enabled in the default"
            echo "           graph - the host simulator and its fixed MAC key must never"
            echo "           be linkable into a firmware image"
            VIOLATIONS=$((VIOLATIONS + 1))
        fi
    else
        echo "VIOLATION: cannot resolve notyas-wallet's feature set:"
        echo "$TREE" | sed 's/^/           /'
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
fi

# Also check that secp256k1 IS present (invariant 4: equivalence requires the
# same crypto as desktop BigDice). This is a positive check - its absence would
# mean the derivation path is stubbed.
SECP_FOUND=0
for lock in $LOCKS; do
    if grep -q '^name = "secp256k1"$' "$lock" || grep -q '^name = "secp256k1-sys"$' "$lock"; then
        SECP_FOUND=1
        break
    fi
done
if [ "$SECP_FOUND" -eq 0 ]; then
    echo "VIOLATION: secp256k1 not found in any Cargo.lock - invariant 4 (equivalence) is broken"
    VIOLATIONS=$((VIOLATIONS + 1))
fi

if [ "$VIOLATIONS" -gt 0 ]; then
    echo "build-graph-check: FAILED - ${VIOLATIONS} violation(s)"
    exit 1
fi

echo "build-graph-check: OK - no banned crates, secp256k1 present"
exit 0
