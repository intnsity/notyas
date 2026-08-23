#!/usr/bin/env bash
# check-ascii-prose.sh - no byte above 0x7F in published prose.
#
# check-dashes.sh forbids two specific characters. This one forbids the class
# they belong to, in the files a stranger actually reads: README.md and docs/.
#
# The two gates are deliberately separate rather than merged. check-dashes runs
# over the whole tree, including code and comments, and names the one substitution
# it wants. This one runs over prose only and admits no exceptions at all, because
# the failure it catches is different in kind: an emoji, a smart quote, a
# non-breaking space or a typographic ellipsis arrives invisibly with pasted text,
# renders correctly in the editor that produced it, and is then indistinguishable
# from the ASCII it displaces until something downstream mangles it.
#
# Scope is prose, not the tree, because source files legitimately carry non-ASCII:
# BIP-39 wordlists, test vectors and font tables all contain bytes above 0x7F on
# purpose. A gate that forbade those would be turned off within a week.
#
# Usage:  tools/ci/check-ascii-prose.sh
#
# Tracked AND untracked-but-not-ignored, for the reason check-dashes.sh gives in
# its own header: a gate exists to catch a violation before it lands, so a file
# that has not been committed yet is exactly the file worth scanning.
set -euo pipefail
cd "$(dirname "$0")/../.."

FILES=$({ git ls-files -z -- 'README.md' 'docs/*.md' 'docs/**/*.md'; \
          git ls-files -z --others --exclude-standard -- 'README.md' 'docs/*.md' 'docs/**/*.md'; } \
        | tr '\0' '\n' | sort -u)

[ -n "$FILES" ] || { echo "check-ascii-prose: no prose files found - is this the repository root?" >&2; exit 1; }

COUNT=$(printf '%s\n' "$FILES" | wc -l | tr -d ' ')
HITS=$(printf '%s\n' "$FILES" | xargs grep -nHP '[^\x00-\x7F]' 2>/dev/null || true)

if [ -n "$HITS" ]; then
    echo "check-ascii-prose: FAILED - a byte above 0x7F in published prose" >&2
    echo "" >&2
    printf '%s\n' "$HITS" | head -40 >&2
    echo "" >&2
    echo "  Every one of these is a character someone can neither type reliably nor" >&2
    echo "  see the difference of. Replace it with its ASCII equivalent: a hyphen for" >&2
    echo "  any dash, a straight quote for any curly one, a space for a non-breaking" >&2
    echo "  space, three dots for an ellipsis, and words for an emoji." >&2
    exit 1
fi

echo "check-ascii-prose: OK - $COUNT prose file(s), no byte above 0x7F"
exit 0
