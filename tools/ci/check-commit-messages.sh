#!/usr/bin/env bash
# check-commit-messages.sh - the authorship rule, enforced.
#
# The project owner is the sole author of every commit in this repository. No
# co-author trailer, and no tool or vendor name, may appear in any commit
# message. This is not a style preference: it has already been violated once and
# the fix was a history rewrite, which is expensive, disruptive to anyone who has
# cloned, and entirely avoidable by catching the message before it is pushed.
#
# Usage:  tools/ci/check-commit-messages.sh <range>
#
#   <range> is anything `git rev-list` accepts. CI passes the pushed range
#   (before..after, or base..head on a pull request); a bare ref such as HEAD
#   expands to the whole history, which is the right default when there is no
#   before-image (a newly created branch) because the history is clean today and
#   staying that way is the point.
#
# Every commit in the range is checked, not just the tip: a bad message cannot be
# corrected by a later commit, only by rewriting the one that carries it.
#
# The forbidden tokens are stored as hex and decoded at run time. That is not
# obfuscation for its own sake - the same rule forbids these strings anywhere in
# the tree, so a checker that spells them out would be the first file to violate
# the rule it enforces (and the first false positive of any audit grep). The
# `unhex` helper below decodes them; run the script to see them in its output.

set -euo pipefail

cd "$(dirname "$0")/../.."

RANGE="${1:-HEAD}"

# Hex -> string, using only printf and sed (no xxd: it is not installed
# everywhere, and a security gate that silently skips is worse than none).
unhex() {
    printf '%b' "$(printf %s "$1" | sed 's/../\\x&/g')"
}

# The three forbidden tokens, matched case-insensitively anywhere in the message.
TOKENS=(
    "436f2d417574686f7265642d4279"
    "436c61756465"
    "416e7468726f706963"
)

if ! COMMITS=$(git rev-list "$RANGE" 2>&1); then
    echo "check-commit-messages: cannot resolve range '$RANGE'" >&2
    echo "  git said: $COMMITS" >&2
    echo "  (in CI this needs actions/checkout with fetch-depth: 0)" >&2
    exit 1
fi

COUNT=0
VIOLATIONS=0

for sha in $COMMITS; do
    COUNT=$((COUNT + 1))
    message=$(git log -1 --format=%B "$sha")
    for hex in "${TOKENS[@]}"; do
        token=$(unhex "$hex")
        if printf '%s' "$message" | grep -qiF -- "$token"; then
            VIOLATIONS=$((VIOLATIONS + 1))
            echo
            echo "COMMIT MESSAGE POLICY VIOLATION"
            echo "  commit:  $(git log -1 --format='%h %s' "$sha")"
            echo "  token:   $token"
            printf '%s' "$message" | grep -inF -- "$token" | sed 's/^/  line:    /'
        fi
    done
done

if [ "$VIOLATIONS" -gt 0 ]; then
    cat <<'EOF'

The owner is the sole author of every commit here. Remove the offending text
from the commit MESSAGE - a follow-up commit does not fix it, because this check
reads every commit in the pushed range.

How to fix, cheapest first:

  * the tip commit only
      git commit --amend                  # delete the offending line, save
      git push --force-with-lease

  * an older commit in this push
      git rebase -i <commit-before-it>    # mark it 'reword', save, edit
      git push --force-with-lease

  * several commits at once
      git rebase -i <base>                # 'reword' each one
      git push --force-with-lease

Then re-run this script locally before pushing:
      bash tools/ci/check-commit-messages.sh <base>..HEAD

Committing with the right identity in the first place avoids all of it:
      git -c user.name="intnsity" -c user.email="at@intnsity.com" commit -m "..."
EOF
    echo
    echo "check-commit-messages: FAILED - ${VIOLATIONS} violation(s) in ${COUNT} commit(s)"
    exit 1
fi

echo "check-commit-messages: OK - ${COUNT} commit(s) in '${RANGE}', no forbidden token"
exit 0
