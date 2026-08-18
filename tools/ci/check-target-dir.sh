#!/bin/sh
# Refuse to build when artifacts would land on the network share.
#
# The working tree is canonical on a NAS share. Build artifacts on that share
# cost the kernel a file object per open in the SMB redirector, and a build is
# the heaviest open/close workload this project has. .cargo/config.toml pins
# target-dir to local disk; this gate is the tripwire for the cases config
# cannot reach - a hand-run cargo with CARGO_TARGET_DIR set, or an artifact tree
# left behind by an earlier mistake.
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

TARGET=$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
    | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p' \
    | sed 's/\\/\//g')

if [ -z "$TARGET" ]; then
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

# The durable arm. This catches the mistake after the fact even when someone
# bypasses cargo config entirely, and it is the exact artifact the 2026-08-18
# incident left behind: a 391 MB tree written to the share by a bare
# `cargo test` run from the repository root.
if [ -e "$ROOT/target" ]; then
    echo "check-target-dir: FAIL - stale artifact tree at \$ROOT/target" >&2
    echo "  Build artifacts must not live on the share. Remove it:" >&2
    echo "    rm -rf '$ROOT/target'" >&2
    FAIL=1
fi

[ "$FAIL" -eq 0 ] || exit 1
echo "check-target-dir: ok ($TARGET)"
