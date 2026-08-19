#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# check-supply-chain.sh - the dependency set is exactly what the lock says it is.
#
# The published claim is that a third party can rebuild this firmware and get the
# same bytes. That claim rests entirely on the dependency set being pinned and
# content-addressed: a git dependency has no checksum, a [patch] section silently
# substitutes a crate the lock still names, and a path dependency pointing outside
# the workspace makes the build depend on the builder's disk. None of those show up
# as a build failure. They show up as a different binary.
#
# This gate is deliberately a SEPARATE file from tools/build-graph-check.sh. That
# script answers "what is in the graph"; this one answers "where did it come from,
# and can I prove it". They fail for different reasons and a reader should not have
# to disentangle which half broke.
#
# Three assertions, in the order a supply-chain attack would have to defeat them:
#
#   1. PROVENANCE - every external package resolves to crates.io and nowhere else,
#                   and every package with no source is a declared workspace
#                   member. No git, no alternate registry, no path escape.
#   2. INTEGRITY  - every external package carries a 64-hex SHA-256 checksum, and
#                   no manifest or cargo config patches, replaces or
#                   source-replaces anything.
#   3. CONTENT    - no banned crate appears at ANY depth under any crate that
#                   links into the device image, evaluated over EVERY target
#                   rather than the runner's host target.
#
# On (3), two things this gate does that its sibling does not, both load-bearing
# for SECURITY.md invariant 3:
#
#   * --target all. Without it, cargo tree evaluates cfg() for the HOST, and a
#     dependency written [target.'cfg(target_os = "espidf")'.dependencies] - the
#     exact form crates/esp-idf-hmac/Cargo.toml uses - is invisible on a Linux CI
#     runner, where that crate's whole subtree collapses to a single line. The
#     subtree that exists only on the device is precisely the subtree the
#     invariant is about, so it is the one that must be walked.
#   * notyas-firmware and esp-idf-hmac are checked. They ARE the device image;
#     omitting them leaves the image's own graph covered only by the flat-lockfile
#     scan, which cannot distinguish a build dependency from a runtime one and so
#     has to grant blanket exemptions to host tools. --edges normal makes that
#     distinction structurally, so no exemption list is needed here, and none is
#     granted.
#
# The banned list is wider than the invariant's headline names on purpose: an
# accidental RNG arrives as whatever crate the new dependency happened to pick,
# and fastrand is already in this lock (under tempfile, under embuild, on the
# build side) without appearing on any existing ban list.
#
# Exit 0 = clean, 1 = violation.

set -euo pipefail

cd "$(dirname "$0")/../.."

LOCK=Cargo.lock
CRATES_IO="registry+https://github.com/rust-lang/crates.io-index"

# Every crate that links into the device image, plus the firmware itself.
IMAGE_PACKAGES="notyas-core notyas-ui notyas-fonts notyas-wallet esp-idf-hmac notyas-firmware"

# Invariant 3 (no RNG) and invariant 1 (no radio, no network, no closed crypto).
# Names, not categories, because names are all a dependency graph offers - so the
# list must enumerate the plausible arrivals, not only the famous ones.
BANNED="rand rand_core rand_chacha rand_hc rand_os rand_jitter getrandom fastrand
        oorandom nanorand wyrand tinyrand rdrand ring reqwest hyper h2 tokio mio
        socket2 libsqlite3-sys native-tls openssl openssl-sys rustls"

FAILURES=0
CHECKS=0
ok()  { CHECKS=$((CHECKS + 1)); printf '  ok    %s\n' "$*"; }
bad() { CHECKS=$((CHECKS + 1)); FAILURES=$((FAILURES + 1)); printf '  FAIL  %s\n' "$*"; }

if [ ! -f "$LOCK" ]; then
    printf 'check-supply-chain: %s is missing - run cargo generate-lockfile first\n' "$LOCK" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 1 + 2. Provenance and integrity of every entry in the lock.
# ---------------------------------------------------------------------------
printf 'lockfile provenance and integrity\n'

# The set of package names cargo is allowed to resolve from a path: the workspace
# members, read from the root manifest rather than hard-coded, so adding a member
# does not silently widen what this gate permits.
MEMBER_NAMES=$(
    sed -n '/^members *= *\[/,/^]/p' Cargo.toml |
    sed -n 's/^ *"\([^"]*\)".*/\1/p' |
    while read -r dir; do
        if [ -f "$dir/Cargo.toml" ]; then
            sed -n 's/^name *= *"\([^"]*\)".*/\1/p' "$dir/Cargo.toml" | head -n 1
        fi
    done | sort -u | tr '\n' ' '
)
if [ -z "$MEMBER_NAMES" ]; then
    bad "could not read the workspace member list from Cargo.toml"
else
    ok "workspace members: $MEMBER_NAMES"
fi

# One awk pass over the lock. Parsing it here rather than shelling out to
# cargo metadata keeps this half of the gate runnable in a container with no
# toolchain, which is where a suspected mirror substitution gets investigated.
LOCK_REPORT=$(
    awk -v crates_io="$CRATES_IO" -v members=" $MEMBER_NAMES " '
        function flush() {
            if (name == "") return
            if (source == "") {
                if (index(members, " " name " ") == 0)
                    printf "PATH_OUTSIDE_WORKSPACE %s %s\n", name, version
                else
                    printf "MEMBER %s %s\n", name, version
            } else if (source ~ /^git\+/) {
                printf "GIT_DEPENDENCY %s %s %s\n", name, version, source
            } else if (source != crates_io) {
                printf "FOREIGN_REGISTRY %s %s %s\n", name, version, source
            } else if (checksum == "") {
                printf "NO_CHECKSUM %s %s\n", name, version
            } else if (checksum !~ /^[0-9a-f][0-9a-f]*$/ || length(checksum) != 64) {
                printf "BAD_CHECKSUM %s %s %s\n", name, version, checksum
            } else {
                printf "OK %s %s\n", name, version
            }
            name = ""; version = ""; source = ""; checksum = ""
        }
        /^\[\[package\]\]/ { flush(); next }
        /^name = "/        { name     = substr($0, 9,  length($0) - 9);  next }
        /^version = "/     { version  = substr($0, 12, length($0) - 12); next }
        /^source = "/      { source   = substr($0, 11, length($0) - 11); next }
        /^checksum = "/    { checksum = substr($0, 13, length($0) - 13); next }
        END { flush() }
    ' "$LOCK"
)

CLEAN=$(printf '%s\n' "$LOCK_REPORT" | grep -c '^OK ' || true)
MEMBERS=$(printf '%s\n' "$LOCK_REPORT" | grep -c '^MEMBER ' || true)
BADS=$(printf '%s\n' "$LOCK_REPORT" | grep -vE '^(OK|MEMBER) ' | grep -c . || true)

if [ "$BADS" -eq 0 ]; then
    ok "$CLEAN external packages: every one from crates.io with a SHA-256 checksum"
    ok "$MEMBERS path packages: every one a declared workspace member"
else
    # Fed by a here-string rather than a pipe: a pipeline would run the loop in a
    # subshell and the FAILURES it raised would be discarded at the closing done.
    while read -r kind rest; do
        case "$kind" in
        GIT_DEPENDENCY)         bad "git dependency (no checksum, mutable ref): $rest" ;;
        FOREIGN_REGISTRY)       bad "package from a registry other than crates.io: $rest" ;;
        NO_CHECKSUM)            bad "package has no checksum: $rest" ;;
        BAD_CHECKSUM)           bad "checksum is not a 64-hex SHA-256: $rest" ;;
        PATH_OUTSIDE_WORKSPACE) bad "path package that is not a workspace member: $rest" ;;
        *)                      bad "unrecognised lock finding: $kind $rest" ;;
        esac
    done <<< "$(printf '%s\n' "$LOCK_REPORT" | grep -vE '^(OK|MEMBER) ' | grep .)"
fi

# ---------------------------------------------------------------------------
# Source overrides. A lock entry can name crates.io and still be built from
# somewhere else: [patch] rewrites the source behind the name, [replace] swaps the
# version, and a cargo config's [source.crates-io] replace-with redirects the whole
# registry. None of the three changes the lock's source line.
# ---------------------------------------------------------------------------
printf '\nsource overrides\n'

MANIFESTS=$(sed -n '/^members *= *\[/,/^]/p' Cargo.toml |
            sed -n 's|^ *"\([^"]*\)".*|\1/Cargo.toml|p')
MANIFESTS="Cargo.toml $MANIFESTS"
CONFIGS=".cargo/config.toml firmware/.cargo/config.toml"

OVERRIDES=0
for f in $MANIFESTS; do
    if [ ! -f "$f" ]; then continue; fi
    if grep -qE '^\[patch' "$f"; then
        bad "$f declares a [patch] section"; OVERRIDES=$((OVERRIDES + 1))
    fi
    if grep -qE '^\[replace\]' "$f"; then
        bad "$f declares a [replace] section"; OVERRIDES=$((OVERRIDES + 1))
    fi
    if grep -qE '(^|[,{[:space:]])git[[:space:]]*=[[:space:]]*"' "$f"; then
        bad "$f declares a git dependency"; OVERRIDES=$((OVERRIDES + 1))
    fi
done
if [ "$OVERRIDES" -eq 0 ]; then
    ok "no [patch], [replace] or git dependency in any workspace manifest"
fi

OVERRIDES=0
for f in $CONFIGS; do
    if [ ! -f "$f" ]; then continue; fi
    if grep -qE '^\[source\.' "$f"; then
        bad "$f replaces a cargo source registry"; OVERRIDES=$((OVERRIDES + 1))
    fi
    if grep -qE '^[[:space:]]*(replace-with|paths)[[:space:]]*=' "$f"; then
        bad "$f declares a source or path override"; OVERRIDES=$((OVERRIDES + 1))
    fi
done
if [ "$OVERRIDES" -eq 0 ]; then
    ok "no source or path override in the cargo configs"
fi

# Path dependencies must stay inside the repository. A path = "../../elsewhere"
# still produces a lock entry with no source, and the member-name check above
# catches that only if the crate it points at has an undeclared name - which an
# attacker writing the manifest controls. So check the paths themselves.
ESCAPES=$(
    for f in $MANIFESTS; do
        if [ ! -f "$f" ]; then continue; fi
        dir=$(dirname "$f")
        sed -n 's|.*[[:space:]]path[[:space:]]*=[[:space:]]*"\([^"]*\)".*|\1|p' "$f" |
        while read -r p; do
            case "$p" in
            /*|[A-Za-z]:*)
                printf 'absolute %s %s\n' "$f" "$p"
                ;;
            *)
                # Resolve textually: the tree may not be a git checkout, and the
                # target may legitimately not exist yet when this runs.
                printf '%s/%s\n' "$dir" "$p" | awk -v f="$f" -v p="$p" -F/ '{
                    n = 0
                    for (i = 1; i <= NF; i++) {
                        if ($i == "" || $i == ".") continue
                        if ($i == "..") {
                            if (n > 0) { n-- } else { print "escaping " f " " p; exit }
                        } else { st[++n] = $i }
                    }
                }'
                ;;
            esac
        done
    done
)
if [ -n "$ESCAPES" ]; then
    while read -r kind file p; do
        bad "$file has a path dependency outside the workspace ($kind): $p"
    done <<< "$ESCAPES"
else
    ok "every path dependency resolves inside the repository"
fi

# ---------------------------------------------------------------------------
# 3. No banned crate at any depth, on any target, under anything that ships.
# ---------------------------------------------------------------------------
printf '\nbanned crates at any depth (--edges normal --target all)\n'

if ! command -v cargo > /dev/null 2>&1; then
    bad "cargo not found - the depth check cannot run, and a security gate that skips silently is worse than no gate at all"
else
    for pkg in $IMAGE_PACKAGES; do
        if ! TREE=$(cargo tree --locked --package "$pkg" --edges normal \
                               --target all --prefix none 2>&1); then
            bad "cannot resolve ${pkg}'s dependency tree:"
            printf '%s\n' "$TREE" | sed 's/^/          /'
            continue
        fi
        HITS=""
        for crate in $BANNED; do
            if printf '%s\n' "$TREE" | grep -q "^${crate} v"; then
                HITS="$HITS $crate"
            fi
        done
        if [ -n "$HITS" ]; then
            bad "$pkg pulls banned crate(s) at some depth:$HITS"
        else
            DEPTH=$(printf '%s\n' "$TREE" | sed 's/ (\*)$//' | sort -u | grep -c . || true)
            ok "$pkg: $DEPTH distinct packages in the runtime graph, none banned"
        fi
    done
fi

printf '\n'
if [ "$FAILURES" -gt 0 ]; then
    printf 'check-supply-chain: FAILED - %d of %d checks\n' "$FAILURES" "$CHECKS"
    exit 1
fi
printf 'check-supply-chain: OK - %d checks\n' "$CHECKS"
