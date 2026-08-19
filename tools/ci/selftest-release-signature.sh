#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# selftest-release-signature.sh - prove that the release path's signature check can say no.
#
# WHAT IT IS FOR
#
# tools/release.sh verifies a signature three times: on the tag it has just made, on
# SHA256SUMS.txt it has just signed, and on both again in the seconds before the push.
# Until 0.2.0 all three were `gpg --verify` and `git tag -v`, which answer "is the key
# that signed this in my keyring", and print
#
#     gpg: Good signature from "intnsity <at@intnsity.com>" [ultimate]
#
# with exit 0 for ANY such key. A uid is a string whoever made the key typed into it, so
# that line is not a statement about which key signed - it is a statement about what the
# signer decided to be called. On a machine holding one secret key the difference is
# invisible; every machine that can cut a release holds more than one.
#
# This fixture builds the adversary: a throwaway ed25519 key whose uid copies the release
# identity, in a keyring of its own, and asserts that
#
#   - the check accepts a signature from the key it was pinned to,      and
#   - refuses the same signature when pinned to a different fingerprint - including the
#     real release fingerprint, which is the case that matters - for a detached signature
#     and for an annotated tag alike,                                   and
#   - refuses a docs/keys/<fpr>.asc that is not the release key, or is not only the
#     release key, which is the same question asked about the file a stranger imports
#     before running either of the checks above.
#
# Both halves are the point. A check that always refuses passes the second half and is
# useless; a check that always accepts passes the first and is what this replaced.
#
# WHY IT IS A GATE RATHER THAN A TEST SOMEBODY REMEMBERS TO RUN
#
# tools/release.sh runs it in the 'gates' stage, for the reason it runs
# selftest-release-symbols.sh in 'build': the real check has never once refused anything
# in this tree, because every signature made here has been the right one. A check that has
# only ever said yes is indistinguishable from a check that cannot say no, and the whole
# value of the pinned verifier is what it does on the day something is wrong.
#
# It never touches the real keyring. GNUPGHOME points at a directory made by mktemp, the
# keys live and die there, and the agent started for them is killed on the way out.

set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

command -v gpg > /dev/null 2>&1 || {
    printf 'selftest-release-signature: gpg is not on PATH.\n' >&2
    printf 'The tag and SHA256SUMS.txt are signed with it, so a machine without gpg\n' >&2
    printf 'cannot make a release and cannot prove this check works either.\n' >&2
    exit 3
}
command -v git > /dev/null 2>&1 || {
    printf 'selftest-release-signature: git is not on PATH\n' >&2
    exit 3
}

# A short home, deliberately: gpg-agent talks over a socket whose path has a length limit,
# and a fixture nested under a long scratch directory fails to start an agent at all.
FIX=$(mktemp -d)
export GNUPGHOME="$FIX/gnupg"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME" 2> /dev/null || true

cleanup() {
    gpgconf --homedir "$GNUPGHOME" --kill all > /dev/null 2>&1 || true
    rm -rf "$FIX"
}
trap cleanup EXIT

# The fingerprint comes from gpg's own status stream rather than from a lookup by uid,
# because the two keys below share a uid on purpose: a lookup would hand back the first
# of them twice, and the fixture would quietly stop testing anything.
genkey() {
    gpg --batch --yes --quiet --passphrase '' --pinentry-mode loopback --status-fd 3 \
        --quick-generate-key "$1" ed25519 sign never 3>&1 > /dev/null 2> /dev/null \
        | awk '/^\[GNUPG:\] KEY_CREATED /{ print $4; exit }'
}

printf 'selftest-release-signature: building the adversary in %s\n' "$GNUPGHOME"

# Two keys, same uid, same keyring. This is the situation the check has to survive: the
# signature is good, the key is present, the name is right, and it is the wrong key.
IMPOSTOR=$(genkey 'intnsity <at@intnsity.com>')
OTHER=$(genkey 'intnsity <at@intnsity.com>')
[ -n "$IMPOSTOR" ] && [ -n "$OTHER" ] || { printf 'selftest-release-signature: could not generate fixture keys\n' >&2; exit 1; }
printf '  impostor key : %s (uid "intnsity <at@intnsity.com>")\n' "$IMPOSTOR"
printf '  second key   : %s (same uid)\n' "$OTHER"

# The release fingerprint is read out of release.sh below, but the sourcing overwrites
# RELEASE_KEY_FPR per case, so keep a copy of the value under test.
mkdir -p "$FIX/art"
printf '%s  notyas-0.2.0-waveshare-4b-app.bin\n' \
    "0000000000000000000000000000000000000000000000000000000000000000" > "$FIX/art/SHA256SUMS.txt"
gpg --batch --yes --quiet --pinentry-mode loopback --armor --detach-sign \
    --local-user "$IMPOSTOR" "$FIX/art/SHA256SUMS.txt"

# A tag signed by the same impostor, in a repository that exists for the next ten seconds.
# git is asked to reach the fixture keyring through a wrapper rather than GNUPGHOME:
# git and gpg do not always agree about what a path looks like when one of them is a
# native Windows program and the other is not, and a wrapper says it in one place.
cat > "$FIX/gpg-wrapper" <<WRAPEOF
#!/usr/bin/env bash
exec gpg --homedir "$GNUPGHOME" "\$@"
WRAPEOF
chmod +x "$FIX/gpg-wrapper"

git init -q "$FIX/repo"
(
    cd "$FIX/repo"
    git config user.name "intnsity"
    git config user.email "at@intnsity.com"
    git config gpg.program "$FIX/gpg-wrapper"
    printf 'fixture\n' > a.txt
    git add a.txt
    git commit -q -m "fixture" --no-gpg-sign
    git tag -s -u "$IMPOSTOR" v0.0.0-fixture -m "notyas 0.0.0"
) > /dev/null 2>&1

# The functions under test, loaded from the file that ships them. Sourcing rather than
# copying: a self-test that reimplements the check proves something about the copy.
# shellcheck source=../release.sh
. "$REPO/tools/release.sh"
RELEASE_PIN=$RELEASE_KEY_FPR

FAIL=0
CASES=0

# want=accept|refuse. The command runs with RELEASE_KEY_FPR set to the pin under test,
# which is the single knob that decides the answer.
case_is() {
    local want=$1 pin=$2 desc=$3; shift 3
    local rc=0 out
    CASES=$((CASES + 1))
    out=$(mktemp)
    RELEASE_KEY_FPR=$pin
    "$@" > "$out" 2>&1 || rc=$?
    if { [ "$want" = accept ] && [ "$rc" -eq 0 ]; } || { [ "$want" = refuse ] && [ "$rc" -ne 0 ]; }; then
        printf '  ok    %s\n' "$desc"
    else
        printf '  FAIL  %s (wanted %s, exit %d)\n' "$desc" "$want" "$rc"
        sed 's/^/          /' "$out"
        FAIL=$((FAIL + 1))
    fi
    rm -f "$out"
}

printf '\nthe detached signature over a hash list:\n'
case_is accept "$IMPOSTOR" "accepted when pinned to the key that signed it" \
    verify_detached_signature "$FIX/art/SHA256SUMS.txt.asc" "$FIX/art/SHA256SUMS.txt"
case_is refuse "$OTHER" "refused when pinned to another key in the same keyring, with the same uid" \
    verify_detached_signature "$FIX/art/SHA256SUMS.txt.asc" "$FIX/art/SHA256SUMS.txt"
case_is refuse "$RELEASE_PIN" "refused when pinned to the release key $RELEASE_PIN" \
    verify_detached_signature "$FIX/art/SHA256SUMS.txt.asc" "$FIX/art/SHA256SUMS.txt"

# The bytes, not just the key. A signature that verifies against different content is the
# other way a hash list gets published with something else's signature beside it.
printf '%s  notyas-0.2.0-waveshare-4b-app.bin\n' \
    "1111111111111111111111111111111111111111111111111111111111111111" > "$FIX/art/TAMPERED.txt"
cp "$FIX/art/SHA256SUMS.txt.asc" "$FIX/art/TAMPERED.txt.asc"
case_is refuse "$IMPOSTOR" "refused over bytes it does not cover" \
    verify_detached_signature "$FIX/art/TAMPERED.txt.asc" "$FIX/art/TAMPERED.txt"

printf '\nthe signature on an annotated tag:\n'
cd "$FIX/repo"
case_is accept "$IMPOSTOR" "accepted when pinned to the key that signed the tag" \
    verify_tag_signature v0.0.0-fixture
case_is refuse "$OTHER" "refused when pinned to another key in the same keyring, with the same uid" \
    verify_tag_signature v0.0.0-fixture
case_is refuse "$RELEASE_PIN" "refused when pinned to the release key $RELEASE_PIN" \
    verify_tag_signature v0.0.0-fixture
cd "$REPO"

# --- the key a verifier fetches -------------------------------------------------------
#
# The third place the release path answers "which key", and the one that used to be a
# check on a filename. docs/keys/<fpr>.asc is what docs/VERIFYING.md tells a stranger to
# import before checking anything, so a wrong key there is a wrong answer to every check
# they then run - and their gpg reports a good signature throughout.
#
# The real committed key is asserted here as well as the forgeries. That half is what
# proves the pinned facts in release.sh - RSA-4096, created 2026-08-15 - describe the key
# actually in the tree rather than a number somebody typed.
printf '\nthe key file a verifier fetches:\n'

REAL_KEY="$REPO/docs/keys/$RELEASE_PIN.asc"
gpg --batch --yes --quiet --armor --export "$IMPOSTOR" > "$FIX/impostor.asc"

case_is accept "$RELEASE_PIN" "the committed key file is the release key, RSA-4096, created 2026-08-15" \
    assert_committed_key "$REAL_KEY" "committed key"

# The finding in the shape it would really arrive: a key file under the release
# fingerprint's own name, holding something else.
cp "$FIX/impostor.asc" "$FIX/$RELEASE_PIN.asc"
case_is refuse "$RELEASE_PIN" "a foreign key exported under the release fingerprint's filename" \
    assert_committed_key "$FIX/$RELEASE_PIN.asc" "committed key"

# The real key with a second one appended. Importing this hands the verifier's keyring a
# key nobody named, and gpg reports a good signature for that one too.
cat "$REAL_KEY" "$FIX/impostor.asc" > "$FIX/two-keys.asc"
case_is refuse "$RELEASE_PIN" "the release key with a second key smuggled in beside it" \
    assert_committed_key "$FIX/two-keys.asc" "committed key"

printf 'not a key at all\n' > "$FIX/garbage.asc"
case_is refuse "$RELEASE_PIN" "a file gpg cannot read a key out of" \
    assert_committed_key "$FIX/garbage.asc" "committed key"

case_is refuse "$RELEASE_PIN" "no key file at all" \
    assert_committed_key "$FIX/absent.asc" "committed key"

# What the old check said about the very same files, printed rather than asserted: it is
# the reason this file exists, and a reader who has not seen it will not believe it.
# The exit status is MEASURED, not printed as a constant: this paragraph's whole claim is
# that the unpinned check says yes to the impostor, and a hard-coded 0 would go on saying
# so on the day it stopped being true. Nothing is asserted about it - the comparison is
# here to be read, not to gate - so an unexpected status is reported rather than fatal.
printf '\nfor comparison, what an unpinned check says about the impostor signature:\n'
UNPINNED_RC=0
gpg --verify "$FIX/art/SHA256SUMS.txt.asc" "$FIX/art/SHA256SUMS.txt" > "$FIX/unpinned.txt" 2>&1 \
    || UNPINNED_RC=$?
sed 's/^/          /' "$FIX/unpinned.txt"
printf '          gpg exit status: %d\n' "$UNPINNED_RC"
if [ "$UNPINNED_RC" -eq 0 ]; then
    printf '          gpg exited 0 for a key this release must refuse, which is the point.\n'
else
    printf '          gpg did not exit 0 here, so this fixture no longer shows the unpinned\n'
    printf '          check accepting the impostor. Read the output above before citing it.\n'
fi

printf '\n'
if [ "$FAIL" -ne 0 ]; then
    printf 'selftest-release-signature: %d of %d cases FAILED. The release path cannot tell\n' "$FAIL" "$CASES" >&2
    printf 'the release key from a key made this morning, and every "the signature verifies"\n' >&2
    printf 'in tools/release.sh means only "something signed it".\n' >&2
    exit 1
fi
printf 'selftest-release-signature: %d cases. The check follows its pin: it accepts the key it\n' "$CASES"
printf 'was told to expect and refuses every other one, whatever uid that key wears - including\n'
printf 'when the pin is the real release fingerprint %s.\n' "$RELEASE_PIN"
