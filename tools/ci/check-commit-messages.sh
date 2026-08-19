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

# Identities permitted to author or commit here: the owner, in the two spellings
# git and GitHub use for him, plus GitHub's own web-UI committer, which is what
# signs a commit made through the web editor or the merge button.
#
# This list exists because the message check alone is NOT sufficient, and the gap
# was found the expensive way. A commit can carry a perfectly clean message and
# still be AUTHORED by a tool identity, and GitHub builds its contributor list
# from the author and co-author fields rather than from the prose. Checking the
# words without checking the name leaves the exact hole that matters.
ALLOWED_IDENTITIES=(
    "intnsity <at@intnsity.com>"
    "intnsity <85849955+intnsity@users.noreply.github.com>"
    "GitHub <noreply@github.com>"
)

identity_allowed() {
    local who="$1"
    local ok
    for ok in "${ALLOWED_IDENTITIES[@]}"; do
        [ "$who" = "$ok" ] && return 0
    done
    return 1
}

for sha in $COMMITS; do
    COUNT=$((COUNT + 1))
    message=$(git log -1 --format=%B "$sha")

    # Authorship is checked per commit for the same reason the message is: a
    # later commit cannot correct an earlier one's author field.
    author=$(git log -1 --format="%an <%ae>" "$sha")
    committer=$(git log -1 --format="%cn <%ce>" "$sha")
    for role_and_who in "author:$author" "committer:$committer"; do
        role="${role_and_who%%:*}"
        who="${role_and_who#*:}"
        if ! identity_allowed "$who"; then
            VIOLATIONS=$((VIOLATIONS + 1))
            echo
            echo "COMMIT IDENTITY POLICY VIOLATION"
            echo "  commit:    $(git log -1 --format="%h %s" "$sha")"
            echo "  $role:    $who"
            echo "  allowed:   ${ALLOWED_IDENTITIES[*]}"
            echo
            echo "  Fix by rewriting that commit's identity, not by a follow-up:"
            echo "    git rebase -i <commit-before-it>"
            echo "    git commit --amend --author=\"intnsity <at@intnsity.com>\" --no-edit"
            echo "    git push --force-with-lease"
        fi
    done
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

echo "check-commit-messages: OK - ${COUNT} commit(s) in '${RANGE}', no forbidden token, no foreign identity"
exit 0
