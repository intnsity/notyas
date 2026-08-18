#!/usr/bin/env bash
# check-dashes.sh - ASCII hyphens only, everywhere in the tracked tree.
#
# The house style is a plain ASCII hyphen. An em dash (U+2014) or an en dash
# (U+2013) is forbidden in documentation, in code, in comments and in tool
# output. Two reasons it is worth a gate rather than a proofread: the characters
# are visually near-identical to a hyphen in most editors, so they survive review
# indefinitely, and they arrive in bulk (one paste of reflowed prose can carry
# dozens) which makes the cleanup commit large and the diff unreadable.
#
# Usage:  tools/ci/check-dashes.sh
#
# Only TRACKED files are scanned, and binary files are skipped by grep's own
# detection (-I): a PNG that happens to contain the byte sequence is not prose.
# The two patterns are built from their UTF-8 bytes with printf rather than
# written literally, so this file passes its own check.

set -euo pipefail

cd "$(dirname "$0")/../.."

EM=$(printf '\xe2\x80\x94') # U+2014 EM DASH
EN=$(printf '\xe2\x80\x93') # U+2013 EN DASH

# `|| true`: grep exits 1 when nothing matches, which is the success case here,
# and xargs propagates that. A real error would show up as output on stderr.
HITS=$(git ls-files -z | xargs -0 grep -nIHF -e "$EM" -e "$EN" 2>/dev/null || true)

if [ -n "$HITS" ]; then
    echo "DASH CHARACTER VIOLATION"
    echo
    printf '%s\n' "$HITS" | sed 's/^/  /'
    echo
    COUNT=$(printf '%s\n' "$HITS" | wc -l | tr -d ' ')
    cat <<'EOF'
Replace every em dash (U+2014) and en dash (U+2013) above with an ASCII hyphen.
An em dash between clauses usually wants " - " (spaces on both sides); an en
dash in a range wants a bare "-" (2026-2027, 3-5 minutes).

Fix them all in one pass (GNU sed):
  git ls-files -z | xargs -0 sed -i 's/\xe2\x80\x94/-/g; s/\xe2\x80\x93/-/g'
then re-read the diff: a mechanical replacement sometimes leaves doubled spaces
or a hyphen where the sentence wanted a comma.
EOF
    echo
    echo "check-dashes: FAILED - ${COUNT} line(s)"
    exit 1
fi

echo "check-dashes: OK - no em dash or en dash in any tracked text file"
exit 0
