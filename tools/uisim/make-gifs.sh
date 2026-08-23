#!/usr/bin/env bash
# Copyright (C) 2026 intnsity
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Record the UI flows and assemble one GIF per flow into docs/media/.
#
# Usage: tools/uisim/make-gifs.sh [flow ...]     (no argument: every flow)
#
# The division of labour is the point. `uisim record` walks the flow, renders every step
# and writes the per-step dwell into an ffmpeg concat script, so the pictures AND their
# timing come out of tools/uisim/src/flows.rs and are reviewable as Rust. This script owns
# exactly two things ffmpeg has to be told and Rust cannot say: the palette pass and the
# size ceiling. There is no frame rate here, and no list of flows.
#
# Palette: generate one from the whole recording, then apply it with dithering OFF. GIF's
# 256 colours cannot hold a frame of this UI exactly - antialiased text runs to about 350
# distinct values - and ffmpeg's default dither hides that by scattering noise through the
# flat paper, which costs both legibility at small type and a large fraction of the file
# size, since noise does not compress. Quantising cleanly is the better trade for a screen
# that is mostly flat colour.
#
# Not scaled, deliberately. Downscaling was measured and it makes these FILES BIGGER as
# well as harder to read: a resampled edge invents intermediate colours where a native one
# has two, and the run lengths GIF compresses collapse. Native panel pixels are both the
# smallest and the sharpest thing to publish here.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
out_dir="$repo/docs/media"

# Half a megabyte per GIF. Well under the megabyte a public repository can afford, and
# comfortably above what these recordings actually weigh, so it fails on a step list that
# ran away rather than on a normal edit.
readonly MAX_BYTES=$((512 * 1024))

FFMPEG=${FFMPEG:-ffmpeg}
if ! command -v "$FFMPEG" >/dev/null 2>&1; then
    for candidate in /c/ffmpeg/bin/ffmpeg.exe "C:/ffmpeg/bin/ffmpeg.exe"; do
        if [ -x "$candidate" ]; then FFMPEG=$candidate; break; fi
    done
fi
if ! command -v "$FFMPEG" >/dev/null 2>&1; then
    echo "make-gifs: no ffmpeg. Install it, or set FFMPEG to the binary." >&2
    exit 1
fi

# The recorder writes into the ACTIVE cargo target directory, which is cargo's to choose
# and this script has no way to ask for. So it prints it, on the first line, and this reads
# it back rather than guessing at a path that .cargo/config.toml can move.
record_log=$(cd "$repo" && cargo run --locked --quiet -p uisim -- record "$@")
echo "$record_log"
root=$(printf '%s\n' "$record_log" | sed -n 's/^flows: //p' | head -1)
if [ -z "$root" ]; then
    echo "make-gifs: uisim record printed no flows directory" >&2
    exit 1
fi
if command -v cygpath >/dev/null 2>&1; then root=$(cygpath -u "$root"); fi

mkdir -p "$out_dir"
if [ "$#" -gt 0 ]; then
    scripts=()
    for flow in "$@"; do scripts+=("$root/$flow/flow.ffconcat"); done
else
    scripts=("$root"/*/flow.ffconcat)
fi

echo
status=0
for script in "${scripts[@]}"; do
    flow=$(basename "$(dirname "$script")")
    gif="$out_dir/$flow.gif"
    "$FFMPEG" -y -loglevel error \
        -f concat -safe 0 -i "$script" \
        -filter_complex "[0:v]split[a][b];[a]palettegen=stats_mode=full[p];[b][p]paletteuse=dither=none" \
        -fps_mode vfr -loop 0 "$gif"
    bytes=$(wc -c <"$gif" | tr -d ' ')
    printf '%-24s %8s bytes  %s\n' "$flow" "$bytes" "$gif"
    if [ "$bytes" -gt "$MAX_BYTES" ]; then
        echo "  OVER the $MAX_BYTES byte ceiling. Shorten the flow or drop steps from it." >&2
        status=1
    fi
done
exit $status
