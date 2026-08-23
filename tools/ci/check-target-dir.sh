#!/bin/sh
# Refuse to build when artifacts would land on a network share.
#
# Build artifacts on an SMB share cost the kernel a file object per open in the
# redirector, and a build is the heaviest open/close workload this project has. A
# bare `cargo test` run from the root of a share-hosted checkout once left a 391 MB,
# 3257-entry target/ tree there. That measurement is the whole reason this gate exists.
#
# The development workstation carries an untracked .cargo/config.toml pinning target-dir
# to local disk, which prevents that class of mistake in the first place. It is
# deliberately not in the repository: the path in it is a Windows absolute path that
# exists on one machine, and on Linux or macOS cargo would read it as a relative one and
# build into a literal "C:" directory inside the clone. A clone builds into its own
# target/ like any other Rust project. This gate is what the repository ships instead,
# and it is correct whether or not a pin is in effect: it asks where the artifacts
# actually go, not what the configuration claims.
#
# The effective target directory is resolved from cargo itself rather than read
# out of the environment, because the environment is exactly what goes wrong.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
FAIL=0

is_unc() {
    case "$1" in
        //*|\\*) return 0 ;;
        *) return 1 ;;
    esac
}

# One cargo invocation, two answers. Both come back in cargo's own path spelling, so
# they can be compared to each other; neither can be compared to $ROOT, which the shell
# spells its own way. The sed undoes JSON's backslash doubling and lands on forward
# slashes in one pass, which leaves a UNC path with the two leading slashes is_unc
# looks for.
METADATA=$(cargo metadata --format-version 1 --no-deps 2>/dev/null || true)

TARGET=$(printf '%s' "$METADATA" \
    | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p' \
    | sed 's/\\\\/\//g')

WSROOT=$(printf '%s' "$METADATA" \
    | sed -n 's/.*"workspace_root":"\([^"]*\)".*/\1/p' \
    | sed 's/\\\\/\//g')

if [ -z "$TARGET" ] || [ -z "$WSROOT" ]; then
    echo "check-target-dir: could not resolve target_directory from cargo metadata" >&2
    exit 1
fi

if is_unc "$TARGET"; then
    echo "check-target-dir: FAIL - target directory is a UNC path: $TARGET" >&2
    FAIL=1
fi

if is_unc "$ROOT"; then
    case "$TARGET" in
        "$ROOT"*)
            echo "check-target-dir: FAIL - target directory is inside the share: $TARGET" >&2
            FAIL=1 ;;
    esac
fi

# The durable arm. This catches the mistake after the fact even when someone bypasses
# cargo config entirely, and it is the exact artifact the 2026-08-18 incident left
# behind: a 391 MB tree written to the share by a bare `cargo test` run from the
# repository root.
#
# It fires on debris, not on existence. A target/ tree at the repository root that is NOT
# the directory this build resolves to was written by something that ignored the current
# configuration, and on a pinned tree that is every such tree. Where no pin is in effect -
# any clone - cargo resolves to <workspace root>/target, that tree IS the build, and the
# two arms above are what still stand between it and a share.
if [ -e "$ROOT/target" ] && [ "$TARGET" != "$WSROOT/target" ]; then
    echo "check-target-dir: FAIL - artifact tree at \$ROOT/target is not the one this build uses" >&2
    echo "  builds resolve to: $TARGET" >&2
    echo "  Remove the stale tree:" >&2
    echo "    rm -rf '$ROOT/target'" >&2
    FAIL=1
fi

[ "$FAIL" -eq 0 ] || exit 1
echo "check-target-dir: ok ($TARGET)"
