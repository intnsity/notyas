#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# release.sh - the notyas release driver.
#
# This script does not build a firmware image and does not compute a hash. Those
# belong to tools/repro/, which is the normative definition of a release artifact
# (tools/repro/build.sh, "this script IS the definition"). What this one owns is
# the ORDER: which gate runs before which, what evidence each one leaves behind,
# and the refusal to move to the next stage while the previous stage has not been
# passed at THIS commit.
#
# Ordering is the whole point, so it is worth stating why it is this order:
#
#   1. Cheap gates before expensive ones. A pin mismatch found in six seconds is
#      the same finding as a pin mismatch found after an hour of container build.
#   2. Every gate before the tag. A signed tag is a public claim about a commit;
#      moving one is a history rewrite, and this project has paid for one already.
#   3. The tag before the build. The artifacts are a function of the committed
#      tree, so the tag names the tree the artifacts came from rather than being
#      applied afterwards to whatever produced a good result.
#   4. Reproduction before signature, and reproduction OF THE BYTES BEING SIGNED.
#      Signing a build nobody has reproduced voids the entire chain
#      docs/VERIFYING.md asks a stranger to walk: the signature would attest to
#      bytes whose provenance nobody checked. A double build that is never compared
#      to the artifact directory is that same void wearing a green stamp, so the
#      reproduce stage compares them and the later stages re-assert the comparison
#      against the directory in front of them. See the block above
#      reproduction_covers_artifacts.
#   5. Signature before publication, on a machine that is not a CI runner. The
#      release key does not touch hosted infrastructure (REPRODUCIBLE.md 6.3).
#   6. Re-checked at the irreversible boundary, not merely earlier. A stamp binds a
#      stage to a commit; it cannot bind a tag object, a file on disk or a JSON
#      verdict in out/ to the one that was checked. So the publish stage re-runs the
#      tag signature, the hash-list signature, EVERY check the build stage made
#      against the artifact directory, the published key file as the commit carries
#      it, and the cross-check's attestation, in the seconds before origin learns
#      about any of it. Not a subset of them: publish once re-ran `sha256sum -c`
#      without the count equality beside it, which let a file that appeared after
#      the build be published unlisted and unsigned.
#   7. Which key, at every one of those checks. `gpg --verify` and `git tag -v` exit
#      0 for any key in the keyring and name the signer by a uid the signer chose,
#      so both are answered here from gpg's status stream against one pinned
#      fingerprint. See the block above assert_valid_sig. The key a verifier fetches
#      is asserted the same way rather than by its filename: see assert_committed_key.
#
# Usage:
#   tools/release.sh                    # print the stage plan and where it stands
#   tools/release.sh preflight
#   tools/release.sh gates [--ci-evidence TEXT]
#   tools/release.sh hardware --ack "gauntlet passed, both boards, <date>"
#   tools/release.sh tag
#   tools/release.sh build
#   tools/release.sh reproduce [--attestation FILE | --no-second-machine]
#   tools/release.sh sign
#   tools/release.sh publish --confirm
#
# Every stage is idempotent and re-runnable. A stage writes its stamp only when
# everything it checked passed, and a stamp made at a different commit does not
# count, so amending anything sends the sequence back to the stage that covered it.
#
# The owner-facing runbook, with the reasoning and the hardware gates this script
# cannot run, is docs/RELEASE-0.2.0.md. The verifier-facing counterpart, which is
# what these artifacts have to satisfy in a stranger's hands, is docs/VERIFYING.md.

set -euo pipefail
# BASH_SOURCE rather than $0, because tools/ci/selftest-release-signature.sh sources
# this file to drive the signature check against a throwaway key. Under $0 that
# selftest would move the repository root to tools/, and the dispatch at the foot of
# this file only runs when the file was executed rather than sourced.
cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO=$PWD

# ---------------------------------------------------------------------------
# Facts that are not preferences.

# The notyas release identity: OpenPGP RSA-4096 "intnsity", created 2026-08-15.
# It is the maintainer's single release identity and desktop BigDice signs with
# the same key - SECUREBOOT.md section 4 and REPRODUCIBLE.md 5.2 are the
# authorities, and docs/SECURITY.md states it in the normative file.
#
# The key that must never be offered as this one is the RSA-3072 "intnsity-esp"
# identity, generated 2026-08-18 and retired 2026-08-19 with its secret half
# destroyed (SECUREBOOT.md section 4). A document that still calls the release
# identity RSA-3072 sends a verifier to a key that signs nothing;
# tools/ci/check-ratified.sh [KEY] is the detector for that, over the whole tree,
# and the gates stage below runs it.
RELEASE_KEY_FPR=A1E953B25C6A623B77A1D5223AC4BBCFE51AB37D

# The same identity, stated as the facts a parser can check rather than as one
# string. docs/keys/<fpr>.asc is the copy a verifier fetches, and until 0.2.0 this
# script asserted only that a file of that NAME was in the tree - which is a check
# on a filename, and a filename is chosen by whoever wrote the file. Any key at
# all, exported to that path, was published as the release key.
#
# These three make the retired identity unrepresentable here rather than merely
# unexpected: it is RSA-3072, created 2026-08-18, under a different fingerprint,
# so it fails each of them independently. Algorithm 1 is RSA in gpg's colon
# output; the creation time is the same 2026-08-15 the header above states, in the
# form gpg reports it.
RELEASE_KEY_ALGO=1
RELEASE_KEY_BITS=4096
RELEASE_KEY_CREATED=1786752462

# Every file that must name that fingerprint before a release goes out. A key a
# verifier cannot find in two independent places is a key they cannot check, and
# a document that still names the old one sends them to the wrong key entirely.
KEY_DOCS="docs/VERIFYING.md docs/RELEASE-0.2.0.md docs/SECURITY.md docs/plan-0.2.0/REPRODUCIBLE.md"

# The version is read from the firmware crate rather than passed in, because that
# is the value that lands in the app descriptor, in every artifact name, and in
# the VERIFY.json a device is compared against. A release whose tag and image
# disagree is unverifiable in exactly the way this project exists to prevent.
VERSION=$(awk '/^\[package\]/ { in_pkg = 1; next } /^\[/ { in_pkg = 0 } in_pkg && /^version *=/ { gsub(/[",]/, "", $3); print $3; exit }' firmware/Cargo.toml)
TAG="v$VERSION"

OUT="$REPO/out/release/$VERSION"
ARTIFACTS="$OUT/artifacts"
STAMPS="$OUT/stamps"

# Build A of the double build, one directory per board, as tools/repro/check-repro.sh
# leaves it behind. That script owns the path and deletes the tree at the start of its
# next run; it is named here because the reproduce stage compares it against $ARTIFACTS,
# which is the comparison that makes "reproduction before signature" mean anything.
CHECK_REPRO_A="$REPO/out/check-repro/a"

IMAGE="notyas-repro:$VERSION"

# ---------------------------------------------------------------------------
# Output and evidence.

die()  { printf '\nrelease: %s\n' "$*" >&2; exit 1; }
step() { printf '\n=== %s ===\n\n' "$*"; }
ok()   { printf '  ok    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; }
note() { printf '        %s\n' "$*"; }

HEAD_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo unknown)

# A stamp records the commit it was made at. Checking the commit rather than mere
# existence is what makes the sequence honest: an amended commit, a rebase or a
# late fix invalidates every stage that ran before it, and the operator finds out
# from the tool rather than from a verifier.
stamp_write() {
    local stage=$1; shift
    local line
    mkdir -p "$STAMPS"
    {
        printf 'stage = %s\n' "$stage"
        printf 'commit = %s\n' "$HEAD_COMMIT"
        printf 'version = %s\n' "$VERSION"
        printf 'when = %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'host = %s\n' "$(hostname 2>/dev/null || echo unknown)"
        for line in "$@"; do printf '%s\n' "$line"; done
    } > "$STAMPS/$stage"
    printf '\nrelease: stage %s passed, stamped at %s\n' "$stage" "$HEAD_COMMIT"
}

stamp_commit() { [ -f "$STAMPS/$1" ] && sed -n 's/^commit = //p' "$STAMPS/$1" || true; }

stamp_require() {
    local want
    for want in "$@"; do
        local at
        at=$(stamp_commit "$want")
        [ -n "$at" ] || die "stage '$want' has not passed. Run: tools/release.sh $want"
        [ "$at" = "$HEAD_COMMIT" ] || die "stage '$want' passed at $at but HEAD is now $HEAD_COMMIT. The tree moved; re-run from '$want'."
    done
}

# Gate bookkeeping. UNAVAILABLE is deliberately not the same as PASS: a gate that
# could not run on this host has proven nothing, and the only way past it is to
# name where it did run.
GATE_FAIL=0
GATE_UNAVAILABLE=""
gate() {
    local name=$1; shift
    printf '\n--- %s\n' "$name"
    if "$@"; then ok "$name"; else bad "$name"; GATE_FAIL=$((GATE_FAIL + 1)); fi
}
gate_unavailable() {
    bad "$1 could not run here: $2"
    GATE_UNAVAILABLE="$GATE_UNAVAILABLE $1"
}

boards() { bash tools/repro/build.sh --list-boards; }

# A sha256sum-format hash list reduced to "<hash> <basename>", sorted. Two
# builders run in different directories and may list in a different order, and
# neither difference is a difference in the artifacts; a difference in this
# output is one. Comparing the reduced form rather than the file keeps the
# question "are the bytes the same" separate from "did they type the same path".
#
# The path is stripped from the NAME only, never from the whole line: a
# line-wide substitution eats the digest as well, which reduces every comparison
# to "the two builders produced the same filenames" and passes a real byte
# difference. That is not hypothetical - it is what the first version of this
# function did, and it is why hash_list_pairs is a named function with a test
# rather than a pipeline inline in the reproduce stage.
hash_list_pairs() {
    awk '{
        hash = $1
        name = $0
        sub(/^[0-9a-fA-F]+[ \t]+\*?/, "", name)   # sha256sum: digest, spaces, optional binary marker
        sub(/.*\//, "", name)                     # and the directory the builder happened to run in
        print hash, name
    }' "$1" | LC_ALL=C sort
}

artifact() { printf 'notyas-%s-%s-%s' "$VERSION" "$1" "$2"; }

# ---------------------------------------------------------------------------
# Signatures: WHICH key, not whether something signed.
#
# `gpg --verify` and `git tag -v` both exit 0 for a good signature made by ANY key
# in the verifier's keyring, and both print "Good signature from <uid>". A uid is a
# string whoever made the key typed into it. An ed25519 key generated in under a
# minute with the uid "intnsity <at@intnsity.com>" produces, on a keyring that also
# holds the real release key:
#
#     gpg: Good signature from "intnsity <at@intnsity.com>" [ultimate]
#     exit 0
#
# Every machine that can sign a release holds more than one secret key, so until
# 0.2.0 the checks in 'tag', 'sign' and 'publish' asserted "something signed this",
# not "the release key signed this". Those are different claims and only the second
# one is a verification. A human reading the line above is reading a uid.
#
# The fingerprint is the only field that names the key instead of describing it,
# and gpg's status stream is the only place it appears in a form a program can
# compare:
#
#     [GNUPG:] VALIDSIG <signing-key-fpr> <date> <ts> ... <primary-key-fpr>
#
# Field 1 is the key that made the signature; field 10 is its primary key. They
# differ when a signing subkey was used, so either one equal to the pin is the
# release key, and nothing else is. Human output is never parsed: it is localised,
# it is written for a person, and every part of it that names anybody is chosen by
# whoever made the key.
#
# tools/ci/selftest-release-signature.sh proves this refuses a foreign key, for
# both the detached signature and the tag, with fixtures. The 'gates' stage runs it,
# for the reason the Q41 self-test is run in 'build': a check that has only ever
# said yes is indistinguishable from a check that cannot say no.

sig_stream_note() { head -40 "$1" | sed 's/^/          /' >&2; }

# The one place this script decides whether a signature is the release key's.
# Returns nonzero rather than dying, so a self-test can drive it; every caller on
# the release path treats a refusal as fatal.
assert_valid_sig() {
    local what=$1 stream=$2
    local rejected good valid line signer primary

    # EXPKEYSIG and REVKEYSIG arrive WITH a VALIDSIG line and a zero exit status:
    # gpg is saying "the signature is good and the key behind it is expired or
    # revoked". For a release key those are refusals. The retired 2026-08-18
    # rsa3072 identity is exactly the case that must never verify anything.
    rejected=$(grep -Ec '^\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG)' "$stream" || true)
    if [ "$rejected" -ne 0 ]; then
        bad "$what: gpg reported a signature state a release must not accept"
        sig_stream_note "$stream"
        return 1
    fi

    good=$(grep -Ec '^\[GNUPG:\] GOODSIG ' "$stream" || true)
    valid=$(grep -Ec '^\[GNUPG:\] VALIDSIG ' "$stream" || true)
    if [ "$good" -ne 1 ] || [ "$valid" -ne 1 ]; then
        bad "$what: expected exactly one good signature; gpg reported $good GOODSIG and $valid VALIDSIG"
        note "the sign stage makes one signature from one key, and that is what"
        note "docs/VERIFYING.md tells a stranger to check. Anything else is unexplained,"
        note "and a second signature next to the right one is how a wrong key gets read"
        note "as the right one."
        sig_stream_note "$stream"
        return 1
    fi

    line=$(sed -n 's/^\[GNUPG:\] VALIDSIG //p' "$stream")
    signer=$(printf '%s\n' "$line" | awk '{print $1}')
    primary=$(printf '%s\n' "$line" | awk '{print $10}')
    if [ "$signer" != "$RELEASE_KEY_FPR" ] && [ "$primary" != "$RELEASE_KEY_FPR" ]; then
        bad "$what: signed by $signer, which is not the release key"
        note "expected   $RELEASE_KEY_FPR"
        note "signed by  $signer"
        note "primary    ${primary:-not reported by gpg}"
        note "gpg would have exited 0 and printed a good signature for this, because it"
        note "answers 'is this key in my keyring', not 'is this the key'. The uid and the"
        note "key id in that message are chosen by whoever made the key; the fingerprint"
        note "above is the only part that names it."
        return 1
    fi
    if [ "$signer" != "$RELEASE_KEY_FPR" ]; then
        ok "$what: signed by subkey $signer of the release key $RELEASE_KEY_FPR"
    else
        ok "$what: signed by the release key $RELEASE_KEY_FPR"
    fi
    return 0
}

# A detached OpenPGP signature over a file, pinned. Status on fd 3 so that gpg's
# prose cannot be mistaken for it and a locale cannot change what is read.
verify_detached_signature() {
    local sig=$1 data=$2 stream human rc=0
    stream=$(mktemp); human=$(mktemp)
    gpg --batch --status-fd 3 --verify "$sig" "$data" 3>"$stream" > /dev/null 2>"$human" || rc=$?
    if [ "$rc" -eq 0 ]; then
        assert_valid_sig "$(basename "$data")" "$stream" || rc=1
    else
        bad "gpg exited $rc verifying $(basename "$data")"
        sig_stream_note "$human"
        sig_stream_note "$stream"
    fi
    rm -f "$stream" "$human"
    return "$rc"
}

# The signature on an annotated tag, pinned. `--raw` makes git hand back gpg's
# status stream on stderr instead of its own prose, so the same assertion covers
# both kinds of signature this release makes. gpg.format is pinned to openpgp so a
# machine configured for ssh or x509 signing cannot answer this question in a
# different scheme, where there is no VALIDSIG line and no fingerprint to compare.
verify_tag_signature() {
    local tag=$1 stream rc=0
    stream=$(mktemp)
    git -c gpg.format=openpgp verify-tag --raw "$tag" > /dev/null 2>"$stream" || rc=$?
    if [ "$rc" -eq 0 ]; then
        assert_valid_sig "tag $tag" "$stream" || rc=1
    else
        bad "git could not verify the signature on $tag (exit $rc)"
        sig_stream_note "$stream"
    fi
    rm -f "$stream"
    return "$rc"
}

# The key a stranger will fetch, parsed rather than merely present.
#
# docs/VERIFYING.md tells the reader to compare the fingerprint against at least two
# independent sources and names docs/keys/<fpr>.asc as one of them. That file is
# therefore part of the release path: a verifier who imports it and gets a good
# signature has verified whatever key it contains, not the release key. Checking that
# a file of that name exists checks the name.
#
# So it is read. --show-keys parses a key file WITHOUT importing it, so nothing here
# touches the keyring, and --with-colons is the only output gpg produces that is meant
# for a program. Every field compared is one the key carries; none of them is a uid.
#
# Exactly one primary key, too: a file holding the release key AND a second key is one
# whose import hands the verifier's keyring a key nobody named, and after that
# `gpg --verify` says "Good signature" for that one as well.
assert_committed_key() {
    local file=$1 what=$2 colons pub fpr validity bits algo created expiry pubs now

    if ! command -v gpg > /dev/null 2>&1; then
        bad "$what: gpg is not on PATH, so the published key file cannot be read"
        note "this is the file docs/VERIFYING.md sends a verifier to. Unread, the release"
        note "would ship a key nobody here has looked at. Install gpg and re-run."
        return 1
    fi
    if [ ! -f "$file" ]; then
        bad "$what: $file does not exist"
        note "docs/VERIFYING.md names docs/keys/ as one of the two independent sources a"
        note "verifier compares the fingerprint against."
        note "Export it: gpg --armor --export $RELEASE_KEY_FPR > docs/keys/$RELEASE_KEY_FPR.asc"
        return 1
    fi
    if ! colons=$(gpg --batch --with-colons --with-fingerprint --show-keys "$file" 2>/dev/null) \
       || [ -z "$colons" ]; then
        bad "$what: gpg could not read a key out of $file"
        note "a verifier who runs 'gpg --import' on it gets the same result, and then has"
        note "no key to check the release against at all."
        return 1
    fi

    pubs=$(printf '%s\n' "$colons" | grep -c '^pub:' || true)
    if [ "$pubs" -ne 1 ]; then
        bad "$what: expected exactly one primary key in $file, found $pubs"
        note "importing it puts every one of them in the verifier's keyring, and after that"
        note "'gpg --verify' answers yes for all of them."
        return 1
    fi

    pub=$(printf '%s\n' "$colons" | grep '^pub:' | head -1)
    # The primary key's own fingerprint: the first fpr record after the pub record.
    # Taking the last one instead would name a signing subkey, which is a different key.
    fpr=$(printf '%s\n' "$colons" | awk -F: '/^pub:/ { p = 1; next } p && /^fpr:/ { print $10; exit }')
    validity=$(printf '%s' "$pub" | cut -d: -f2)
    bits=$(printf '%s' "$pub" | cut -d: -f3)
    algo=$(printf '%s' "$pub" | cut -d: -f4)
    created=$(printf '%s' "$pub" | cut -d: -f6)
    expiry=$(printf '%s' "$pub" | cut -d: -f7)

    if [ "$fpr" != "$RELEASE_KEY_FPR" ]; then
        bad "$what: $file is named for $RELEASE_KEY_FPR and contains ${fpr:-no fingerprint at all}"
        note "the name of a file is written by whoever wrote the file. This is the copy a"
        note "verifier imports before checking anything, so a release verified against it"
        note "is a release verified against whatever key it holds."
        return 1
    fi

    case "$validity" in
        r) bad "$what: the release key in $file is REVOKED"
           note "a revoked key still produces good signatures and gpg still exits 0 for them."
           return 1 ;;
        e) bad "$what: the release key in $file is EXPIRED"
           return 1 ;;
        i) bad "$what: gpg reports the key in $file as invalid"
           return 1 ;;
    esac

    if [ "$algo" != "$RELEASE_KEY_ALGO" ] || [ "$bits" != "$RELEASE_KEY_BITS" ] \
       || [ "$created" != "$RELEASE_KEY_CREATED" ]; then
        bad "$what: the key in $file is not the ratified release identity"
        note "expected  algorithm $RELEASE_KEY_ALGO, $RELEASE_KEY_BITS bits, created $RELEASE_KEY_CREATED"
        note "found     algorithm ${algo:-?}, ${bits:-?} bits, created ${created:-?}"
        note "SECUREBOOT.md section 4 ratifies RSA-4096 created 2026-08-15. The identity"
        note "that must never appear is the RSA-3072 'intnsity-esp' key of 2026-08-18,"
        note "whose secret half was destroyed on 2026-08-19."
        return 1
    fi

    if [ -n "$expiry" ]; then
        now=$(date -u +%s)
        if [ "$expiry" -le "$now" ]; then
            bad "$what: the release key in $file expired at $expiry"
            return 1
        fi
        note "the key carries an expiry at $expiry; docs/VERIFYING.md must not outlive it"
    fi

    # The creation date in the form docs/VERIFYING.md prints it, because this line is
    # read by a person comparing the two. The epoch is what gpg reports and what the
    # pin above compares; the date is the same fact, legibly.
    local created_on
    created_on=$(date -u -d "@$created" +%Y-%m-%d 2> /dev/null || printf 'epoch %s' "$created")
    ok "$what: $file holds $RELEASE_KEY_FPR, RSA-$bits, created $created_on, not revoked or expired"
    return 0
}

# ---------------------------------------------------------------------------
# The third-party cross-check's evidence.
#
# tools/ci/check-xverify.sh leaves one artefact behind, out/xverify/attestation.json,
# and a JSON file on disk carries no statement about when it was written or by whom.
# A planted {"status": "verified"} used to survive this entire script untouched: the
# 'gates' stage asks --probe first, --probe deliberately writes nothing, and nothing
# downstream ever read the file. Anyone reading it beside a release - the operator,
# a reviewer, a report generator - reads it as this release's cross-check.
#
# So the file is no longer believed on its own. check-xverify.sh writes a binding
# beside it (attestation.json.run) naming the run id this script generated, the
# digest of the sources that were cross-checked and the digest of the attestation's
# own bytes, and it writes that binding only at the end of a run it witnessed. A
# leftover from yesterday, a copy from another tree and a hand-written verdict all
# fail to carry it.
#
# What this does not defend against, stated plainly: anything that can write to out/
# at the moment of the check can write the binding too, and can edit these scripts
# besides. What it closes is the stale and the planted file, which is what was found.
#
# And the strength is in the id being FRESH, not in the binding existing. Asking
# --assert-fresh about an id that has itself been read back off disk proves only that
# the files agree with each other: whoever could plant the attestation could read that
# id and write a binding naming it. That is why 'gates' generates the id here, seconds
# before it is used, and why the push re-runs the cross-check when it can rather than
# re-reading the id it recorded. See xverify_evidence_at_publish.

# An unguessable name for one run of this script.
new_run_id() {
    if [ -r /dev/urandom ]; then
        head -c 64 /dev/urandom | sha256sum | cut -c1-32
    else
        printf '%s-%s-%s' "$(date -u +%s)" "$$" "${RANDOM}${RANDOM}" | sha256sum | cut -c1-32
    fi
}

# The cross-check ran here: the attestation must be the one it just wrote.
xverify_attestation_is_this_run() {
    bash tools/ci/check-xverify.sh --assert-fresh "$1"
}

# The cross-check did not run here: nothing in out/xverify may claim otherwise. The
# id handed over is a fresh nonce that no binding can match, so "this run wrote it"
# is not merely unexpected but impossible, and the only acceptable answer is 4,
# meaning there is no attestation at all.
xverify_attestation_absent() {
    local rc=0
    bash tools/ci/check-xverify.sh --assert-fresh "$(new_run_id)" || rc=$?
    [ "$rc" -eq 4 ] && return 0
    bad "out/xverify holds a cross-check verdict this release run did not produce"
    note "the cross-check did not run on this machine, so anything in"
    note "out/xverify/attestation.json is about another run, another tree, or nobody -"
    note "and a reader who finds it beside a release reads it as this release's evidence."
    note "Read it, then remove it:"
    note "  rm -f out/xverify/attestation.json out/xverify/attestation.json.run"
    return 1
}

# ---------------------------------------------------------------------------
# What a cross-check verdict is worth at the push, and what a STORED run id is not.
#
# The question 'gates' asks is sound. It generates an id from /dev/urandom, hands it
# to check-xverify.sh, and asks --assert-fresh about it seconds later: at the moment
# the binding is written that id has never been on disk, so nothing already sitting
# in out/ - a leftover verdict, a hand-written one, a binding typed in advance - can
# name it.
#
# Reading the same id back out of $STAMPS/gates at the push is a different question
# and a far weaker one. The stamp is plaintext, in the same out/ tree that holds the
# attestation and its binding, and whoever can write one can read the other. An
# adversary did exactly that here: a hand-written {"status":"passed","verified":true}
# beside a binding carrying the stamp's run id, the tree's real digest and the digest
# of the verdict just written. All three comparisons in --assert-fresh held and it
# exited 0. What a pass there proves is that the three files agree with each other.
# It does not prove a cross-check ran.
#
# That cannot be repaired from stored evidence. Everything the push could consult
# lives in the directory the adversary already writes to, and there is no secret on
# this machine to bind it with: the release key signs the tag and the hash list, and
# neither existed when 'gates' ran, so neither can vouch for what 'gates' saw. A
# machine that can rewrite out/ between the two stages can rewrite anything derived
# from out/ as well.
#
# So the push does not try to repair it - it re-measures, which is what every other
# assertion in cmd_publish does and for the same reason. When the oracles are on this
# machine the cross-check is RUN AGAIN here against an id generated in this process
# and not yet written anywhere, and that answer is exactly as strong as the one
# 'gates' got. Only when the oracles are absent does the stored id carry the claim,
# and then the paragraph above is printed where the operator cannot miss it, rather
# than left as a green line that means less than it looks like.
xverify_evidence_at_publish() {
    local recorded=$1 fresh

    # The stored-id question first, weak as it is, because a NO here is still a
    # finding worth stopping for: something rewrote the attestation, its binding or
    # the stamp between 'gates' and now. The re-measurement below writes a fresh
    # verdict over the old one, so asking afterwards would destroy that evidence.
    xverify_attestation_is_this_run "$recorded" || return 1

    if bash tools/ci/check-xverify.sh --probe; then
        fresh=$(new_run_id)
        note "re-running the cross-check here rather than believing the stored verdict:"
        note "the id it is bound to was generated in this process and is on no disk yet."
        bash tools/ci/check-xverify.sh --require --run-id "$fresh" || return 1
        xverify_attestation_is_this_run "$fresh" || return 1
        ok "the third-party cross-check ran again at the push, and verified"
        return 0
    fi

    printf '\n'
    printf '  LIMIT the cross-check could not be re-run here, so what stands behind it is a\n'
    printf '        record, not a proof.\n'
    note "the run id was read in plaintext from"
    note "  $STAMPS/gates"
    note "which is in the same out/ tree that holds the attestation and its binding."
    note "Anyone able to write the attestation can read that id and write a binding"
    note "to match it, and the check above then passes: what it establishes is that"
    note "those files agree with each other."
    note "It is the 'gates' run that is evidence a cross-check happened - there"
    note "the id was fresh and had never been on disk, so nothing already written"
    note "could have named it."
    note "To get that strength here too, install the oracles (tools/xverify/README.md)"
    note "and re-run publish: the cross-check is then run again against an id generated"
    note "in this process."
    note "Publishing anyway rests the cross-check claim on the 'gates' run and on this"
    note "machine not having been tampered with since."
    return 0
}

# ---------------------------------------------------------------------------
# The artifacts on disk, asserted in full.
#
# 'build' calls this the moment the container has produced them; 'publish' calls it
# again in the seconds before the push, with the same list. The two are separated by
# 'reproduce', which is hours of building, and by 'sign', which is a human at a
# keyboard and plausibly on another day. A stamp binds a STAGE to a commit; it cannot
# bind a file on disk to the bytes somebody checked. Whatever lands in $ARTIFACTS in
# that window - the leftovers of a second build, a copied-in file, an editor backup,
# a malicious write - is a file the release page is about to serve.
#
# One function rather than two lists, because the two lists drifted, and the half
# that went missing was the half that matters most: 'build' asserted `sha256sum -c`
# AND a count equality, while 'publish' re-ran only `sha256sum -c`. They answer
# different questions. `sha256sum -c` asks whether every LISTED file still hashes to
# its listed value, and says nothing at all about a file nobody listed; the count
# equality is what notices one. A file that appeared between the two stages was
# therefore pushed unlisted, unhashed and unsigned, in silence.
check_artifacts() {
    local stage=$1 board manifest elf python=python3
    command -v python3 > /dev/null 2>&1 || python=python
    [ -d "$ARTIFACTS" ] || die "$stage: there is no artifact directory at $ARTIFACTS. Run: tools/release.sh build"

    step "checking what is in $ARTIFACTS"
    GATE_FAIL=0

    # Q41's gate, put in front of images it MUST reject, before the run whose green
    # verdict this release then rests on. check-release-symbols.sh has never once
    # printed a finding in this tree, because every image built here has been
    # console-free, and a gate that has only ever passed is indistinguishable from a
    # gate that cannot fail. The self-test synthesises the artefact nobody wants
    # lying around - a console-bearing ELF, and a stripped one - and asserts the
    # real gate rejects each of them, so the per-board pass below is evidence rather
    # than silence.
    #
    # Once, not per board: its subject is the gate, which is the same file whichever
    # board is being checked.
    #
    # A failure here stops the stage on the spot rather than being counted with the
    # rest. Every per-board Q41 verdict printed after a gate that cannot fail would
    # be an unsupported claim about the shipped image, and printing "ok" beside it is
    # the exact outcome these two scripts exist to prevent.
    #
    # This is also why it is here rather than in .github/workflows/ci.yml: it builds
    # its fixtures with riscv32-esp-elf gcc, strip and nm - the same toolchain the
    # gate needs below - and that file's own header records that nothing about a
    # linked image can be checked on a hosted runner.
    gate "the Q41 symbol gate still fails when it should (self-test)" \
        bash tools/ci/selftest-release-symbols.sh
    [ "$GATE_FAIL" -eq 0 ] || die "$stage: the Q41 gate did not reject an image carrying the HIL console. Until tools/ci/selftest-release-symbols.sh passes, a clean report from tools/ci/check-release-symbols.sh proves nothing, and this release has no evidence for Q41."

    for board in $(boards); do
        manifest="$ARTIFACTS/$(artifact "$board" VERIFY.json)"
        elf="$ARTIFACTS/notyas-$VERSION-$board.elf"

        # The manifest against the artifacts it describes. This is the same command
        # docs/VERIFYING.md hands the verifier, run here so a mismatch is found
        # before publication rather than by them.
        gate "$board: VERIFY.json matches the artifacts" \
            "$python" tools/repro/verify-manifest.py check --manifest "$manifest" --dir "$ARTIFACTS"

        # The airgap image tier. The source tier ran in 'gates' and proves the tree
        # asks for no radio; only this one proves the shipped image contains none,
        # and it needs the ELF that only exists once the container has run.
        if [ -f "$elf" ]; then
            gate "$board: airgap image tier (invariant 1 as it SHIPS)" \
                bash tools/ci/check-airgap.sh --image "$elf"

            # Q41, against the artifact. Same reasoning as the tier above and it
            # belongs to the same stage for the same reason: firmware/build.rs and
            # firmware/src/hil.rs both refuse the console in a product image, and
            # both are statements about a build we asked for rather than findings
            # about a file. Three such fences have now been broken with real cargo,
            # each time by a profile shape the build script could not see - the last
            # one dev-rooted with fat LTO and `strip = "symbols"`. This gate reads
            # the linked ELF, so what it reports is what was emitted.
            #
            # What it would catch is not a cosmetic slip: the console formats, seals,
            # erases, registers wallets and SIGNS, on UART0, with no PIN. An image
            # carrying it is a signer that anyone holding the device can drive.
            #
            # No probe-first pattern here, unlike the xverify gate in 'gates'. If the
            # RISC-V nm is missing, that script exits nonzero and this stage fails,
            # which is the intended behaviour: 'gates' can defer an unavailable check
            # to named CI evidence because the tree it checks is public, but nothing
            # outside this machine has the artifact that was just built, so there is
            # nowhere else this could have run. An unavailable gate is not a passed
            # gate, and here it is not a deferrable one either.
            gate "$board: no HIL test console in the shipped image (Q41)" \
                bash tools/ci/check-release-symbols.sh --image "$elf"
        else
            bad "$board: no ELF at $elf"
            GATE_FAIL=$((GATE_FAIL + 1))
        fi
    done

    gate "SHA256SUMS.txt describes this directory exactly" artifacts_fully_hashed

    printf '\n'
    [ "$GATE_FAIL" -eq 0 ] || die "$stage: $GATE_FAIL check(s) failed against the artifacts in $ARTIFACTS."
}

# Both halves of "SHA256SUMS.txt describes this directory", together, because
# neither half means anything alone. Kept in one function so that no caller can
# take one of them: that is the drift this fixes.
#
# "This directory" means the whole tree under $ARTIFACTS, and it did not always.
# The listing used to stop at maxdepth 1 because that is where tools/repro/build.sh
# stops when it WRITES the list, and copying that expression made this gate agree
# with the list about where to look instead of asking what is there. A file one
# directory down was unlisted, unhashed, unsigned and invisible to the one gate
# whose whole subject is unlisted files - at all three call sites, build, sign and
# publish - while publish's own closing instruction is "Attach every file in
# $ARTIFACTS", which is what an operator with a file manager does.
#
# The two exemptions are by exact path rather than by name pattern: SHA256SUMS.txt
# is the list and SHA256SUMS.txt.asc is the signature over the list, so neither can
# be one of the things the list covers. Anything else wearing that name - a copy of
# it a directory down, an editor's SHA256SUMS.txt.bak - is a file the signature does
# not reach, and is reported like any other.
artifacts_fully_hashed() {
    (
        cd "$ARTIFACTS" || return 1
        # Every comparison below is byte-wise, and `sort` and `comm` only agree about
        # what "sorted" means when both are told the same thing. In a UTF-8 locale they
        # do not, and comm answers a question nobody asked.
        export LC_ALL=C
        sha256sum -c SHA256SUMS.txt --quiet || return 1

        local listed present extra missing nested
        listed=$(mktemp); present=$(mktemp)
        # sha256sum's own format: the digest, whitespace, an optional '*' marking
        # binary mode, then the name. The digest is stripped from the NAME only.
        sed -e 's/^[0-9a-fA-F]*[[:space:]]*\*\{0,1\}//' SHA256SUMS.txt | sort > "$listed"
        # Everything that is not a directory, at any depth. Not -type f: a symlink, a
        # fifo and a regular file are all things an upload reads or follows, and -type f
        # answers about the last of them only. An empty directory is left out because
        # there is nothing in it to publish.
        find . -mindepth 1 ! -type d \
            ! -path './SHA256SUMS.txt' ! -path './SHA256SUMS.txt.asc' \
            -printf '%P\n' | sort > "$present"
        extra=$(comm -13 "$listed" "$present")
        missing=$(comm -23 "$listed" "$present")
        nested=$(grep '/' "$present" || true)
        rm -f "$listed" "$present"

        # Answered before the general case because it has its own answer. A release
        # page is one flat list of assets, and docs/VERIFYING.md has the verifier run
        # sha256sum -c in one directory, so a file below the top level cannot be
        # published under the name it has here whatever SHA256SUMS.txt says about it.
        if [ -n "$nested" ]; then
            printf '        these files are below the top level of %s:\n' "$ARTIFACTS"
            printf '%s\n' "$nested" | sed 's/^/          /'
            printf '        A release page is a flat list of assets and docs/VERIFYING.md has the\n'
            printf '        verifier run sha256sum -c in one directory, so a nested file cannot be\n'
            printf '        published under the name it has here. Move it out or remove it; do not\n'
            printf '        sign a hash list that is silent about it.\n'
            return 1
        fi
        if [ -n "$extra" ]; then
            printf '        SHA256SUMS.txt does not list these files, and they are here:\n'
            printf '%s\n' "$extra" | sed 's/^/          /'
            printf '        The signature covers SHA256SUMS.txt and nothing else, so a file that is\n'
            printf '        not named in it is published with nothing vouching for it at all.\n'
            return 1
        fi
        if [ -n "$missing" ]; then
            printf '        SHA256SUMS.txt names files that are not here:\n'
            printf '%s\n' "$missing" | sed 's/^/          /'
            return 1
        fi
    )
}

# ---------------------------------------------------------------------------
# The tie between what was reproduced and what gets signed.
#
# tools/repro/check-repro.sh answers one question: does this recipe reproduce. It
# builds twice, into out/check-repro/a and out/check-repro/b, and compares those
# two trees against each other. It has never heard of $ARTIFACTS, which is the
# directory 'sign' signs and 'publish' hands over.
#
# Until this was written the reproduce stage ran that script, read nothing it left
# behind, and stamped a pass. The only comparison ever made against $ARTIFACTS was
# the optional second-machine attestation, so with --no-second-machine the stage
# proved the recipe reproduces and proved nothing whatever about the bytes the
# signature was about to make authoritative. Ordering rule 4 at the top of this
# file - "signing a build nobody has reproduced voids the entire chain" - was being
# enforced against a build, not against the release.
#
# What that permitted is not exotic. Anything that rewrote an artifact after the
# build stage and regenerated SHA256SUMS.txt from the directory, the way
# tools/repro/build.sh writes it - a stray container run against a modified mount,
# a sync tool, a tamper in the window cmd_publish's header names - passed every
# later check. artifacts_fully_hashed asks whether the list and the directory agree
# with each other, and after such a rewrite they do.
#
# So the rebuild is compared to the artifact directory, through the hashes, in both
# directions:
#
#   every artifact the rebuild produced is in the hash list about to be signed,
#   with the same digest        - or the bytes being signed are not reproduced ones
#   every entry in that hash list came out of the rebuild
#                               - or something rides along that no rebuild made
#
# and the reduced list is digested into the reproduce stamp, so that 'sign' and
# 'publish' can re-ask it about the directory as it stands at THAT moment. The
# stamp half is not decoration: the reproduce stage can only speak for the
# directory as it was while the stage ran, and the window in question opens after
# it and closes at the push.
#
# The stated limit is the one the xverify binding carries for the same reason:
# anything that can write out/ can rewrite the stamp beside the artifacts, and can
# edit this file besides. What this closes is the accidental rewrite and the stale
# directory, not a host that is already owned. tools/ci/selftest-reproduce-binding.sh
# is the proof that both halves can say no, and the reproduce stage runs it before
# the double build for the reason cmd_build runs the Q41 self-test: a check that
# has only ever passed is indistinguishable from a check that cannot fail.

# "<sha256> <basename>" for every artifact one board's rebuild produced, sorted.
#
# Recomputed from the files rather than read out of the SHA256SUMS.txt the container
# wrote beside them. A hash list is a claim about a directory; the claim under test
# here is about bytes, and a list that lies about its neighbours reproduces exactly
# as well as one that does not. Reduced through hash_list_pairs, the one place in
# this script that turns hashes into comparable pairs, because the subtle way to
# break this comparison is to reduce it differently - see the note on that function.
rebuilt_pairs() {
    local dir=$1 raw rc=0
    raw=$(mktemp)
    # -r: an empty board directory would otherwise run sha256sum with no arguments,
    # which reads stdin and hangs a release stage forever. -d '\n': one name per
    # line, so a name carrying a space is hashed rather than split into two files
    # that do not exist - which would fail here rather than pass, but would name the
    # wrong fault.
    if ( cd "$dir" && find . -maxdepth 1 ! -type d ! -name 'SHA256SUMS.txt*' -printf '%P\n' \
            | LC_ALL=C sort | xargs -r -d '\n' sha256sum ) > "$raw"; then
        hash_list_pairs "$raw"
    else
        rc=1
    fi
    rm -f "$raw"
    return "$rc"
}

# One line standing for "this exact set of artifacts, with these exact digests". It
# is what the reproduce stamp carries, so the later stages can ask whether the
# directory is still the one that was tied to the rebuild without needing the
# rebuild tree, which check-repro.sh deletes at the start of its next run.
artifact_pairs_digest() {
    hash_list_pairs "$1" | sha256sum | cut -d' ' -f1
}

# The comparison itself. Arguments rather than globals so the self-test can drive it
# against fixtures.
#
#   $1  the rebuild tree, one directory per board, as check-repro.sh leaves it
#   $2  the hash list that is about to be signed
#   $3+ the boards that must be in that tree
reproduction_covers_artifacts() {
    local root=$1 sums=$2; shift 2
    local board rebuilt signed dup missing extra rc=0

    [ -f "$sums" ] || { bad "there is no hash list at $sums"; return 1; }
    [ $# -gt 0 ]   || { bad "no boards were named, so this would compare the artifacts against nothing"; return 1; }

    rebuilt=$(mktemp); signed=$(mktemp)
    for board in "$@"; do
        if [ -d "$root/$board" ]; then
            rebuilt_pairs "$root/$board" >> "$rebuilt" || rc=1
        else
            bad "the rebuild left no tree for board $board at $root/$board"
            note "The reproduce stage builds every release board; a tree that is missing one"
            note "is an old out/check-repro, not a reproduction of this release."
            rc=1
        fi
    done

    if [ "$rc" -ne 0 ] || [ ! -s "$rebuilt" ]; then
        [ -s "$rebuilt" ] || bad "the rebuild produced no artifacts at all, so there is nothing here that could vouch for $sums"
        rm -f "$rebuilt" "$signed"
        return 1
    fi

    LC_ALL=C sort -u -o "$rebuilt" "$rebuilt"

    # The source archive and the components archive are written by every board build
    # under one name, so a basename legitimately appears in more than one rebuilt
    # tree - with the same bytes. Two boards that disagree about it would otherwise
    # surface below as "the rebuild made something the list does not carry", which
    # names the symptom and hides the fault.
    dup=$(awk '{ print $2 }' "$rebuilt" | LC_ALL=C uniq -d)
    if [ -n "$dup" ]; then
        bad "two boards' rebuilds disagree about the bytes of the same artifact:"
        printf '%s\n' "$dup" | sed 's/^/          /'
        rm -f "$rebuilt" "$signed"
        return 1
    fi

    hash_list_pairs "$sums" > "$signed"
    missing=$(LC_ALL=C comm -23 "$rebuilt" "$signed")
    extra=$(LC_ALL=C comm -13 "$rebuilt" "$signed")
    rm -f "$rebuilt" "$signed"

    if [ -n "$missing" ]; then
        bad "the rebuild produced these, and the hash list about to be signed does not carry them:"
        printf '%s\n' "$missing" | sed 's/^/          /'
    fi
    if [ -n "$extra" ]; then
        bad "the hash list about to be signed carries these, and no rebuild produced them:"
        printf '%s\n' "$extra" | sed 's/^/          /'
    fi
    [ -z "$missing$extra" ] || return 1
    return 0
}

# The same claim, re-asked by 'sign' and by 'publish' against the artifact directory
# as it stands in front of them. Same reasoning as every other re-measurement in
# cmd_publish: a stamp binds a STAGE to a commit, and cannot bind a file on disk to
# the bytes somebody checked hours ago. Beside artifacts_fully_hashed, which proves
# the list still describes the directory, this proves the list is still the one the
# rebuild vouched for - and the two together are what "these bytes were reproduced"
# requires. Either alone is satisfied by a directory and a list rewritten together.
artifacts_match_reproduce_stamp() {
    local stage=$1 want now
    want=$(sed -n 's/^reproduced_artifacts_sha256 = //p' "$STAMPS/reproduce" 2> /dev/null)
    [ -n "$want" ] || die "$stage: the reproduce stamp does not record which artifacts were reproduced. It was written by an older release.sh, from before the double build was tied to the bytes being signed, so nothing here can tell these artifacts apart from ones no rebuild produced. Re-run: tools/release.sh reproduce"

    now=$(artifact_pairs_digest "$ARTIFACTS/SHA256SUMS.txt")
    if [ "$now" = "$want" ]; then
        ok "the artifacts are still the ones the double build reproduced ($want)"
        return 0
    fi
    die "$stage: $ARTIFACTS no longer holds the artifacts the reproduce stage tied to the double build - reproduced $want, here now $now. STOP. This is the finding the release process exists to make, not an inconvenience to work around: something rewrote the artifact directory after it was reproduced, and SHA256SUMS.txt was regenerated alongside it, which is why every other check here is green. Re-run from 'build' and do not sign anything in that directory."
}

# ---------------------------------------------------------------------------
# plan - the default. Prints the order and where this release stands.

cmd_plan() {
    printf 'notyas release driver\n'
    printf '  version (firmware/Cargo.toml) : %s\n' "$VERSION"
    printf '  tag                           : %s\n' "$TAG"
    printf '  head                          : %s\n' "$HEAD_COMMIT"
    printf '  artifacts                     : %s\n' "$ARTIFACTS"
    printf '  release key                   : %s\n' "$RELEASE_KEY_FPR"
    printf '\nstages, in the only order they are allowed to run:\n\n'
    local s
    for s in preflight gates hardware tag build reproduce sign publish; do
        local at status
        at=$(stamp_commit "$s")
        if [ -z "$at" ]; then
            status="not run"
        elif [ "$at" = "$HEAD_COMMIT" ]; then
            status="passed at HEAD"
        else
            status="STALE (passed at ${at:0:12}, HEAD is ${HEAD_COMMIT:0:12})"
        fi
        printf '  %-10s %-40s %s\n' "$s" "$(stage_blurb "$s")" "$status"
    done
    cat <<'PLANEOF'

What this script does not do, and who does:
  the hardware gauntlet          the owner, by hand, on both boards (docs/QA.md)
  the eFuse provisioning burn    the owner, per unit (docs/PROVISIONING.md)
  the firmware build itself      tools/repro/build.sh, inside the release container
  the reproducibility comparison tools/repro/check-repro.sh
  the manifest and its checks    tools/repro/verify-manifest.py

Read docs/RELEASE-0.2.0.md before starting. It carries the gate list in full, what
ships, what deliberately does not, and the limitations the release notes must state.
PLANEOF
}

stage_blurb() {
    case "$1" in
        preflight) printf 'tree, version, key and doc consistency' ;;
        gates)     printf 'the host suite and the mechanical invariants' ;;
        hardware)  printf 'the owner acknowledges the hardware gauntlet' ;;
        tag)       printf 'signed annotated tag at this commit' ;;
        build)     printf 'container build of every release board' ;;
        reproduce) printf 'built twice, tied to what gets signed' ;;
        sign)      printf 'detached signature over SHA256SUMS.txt' ;;
        publish)   printf 'push the tag and hand over the artifacts' ;;
    esac
}

# ---------------------------------------------------------------------------
# preflight - everything that is free to check and expensive to discover late.

cmd_preflight() {
    step "preflight"
    GATE_FAIL=0

    printf '\n--- repository state\n'
    if [ -z "$(git status --porcelain)" ]; then
        ok "working tree is clean"
    else
        bad "working tree has uncommitted or untracked files"
        note "the container build takes 'git archive' of HEAD, so an untracked file"
        note "is invisible to it: the release would silently lack a file you can see."
        git status --porcelain | sed 's/^/          /'
        GATE_FAIL=$((GATE_FAIL + 1))
    fi

    if git rev-parse -q --verify "refs/tags/$TAG" > /dev/null; then
        bad "$TAG already exists"
        note "a tag is a public claim about a commit; move it only by deleting a"
        note "release nobody has downloaded, and never one that has been announced."
        GATE_FAIL=$((GATE_FAIL + 1))
    else
        ok "$TAG does not exist yet"
    fi

    printf '\n--- version\n'
    if [ -n "$VERSION" ]; then
        ok "firmware/Cargo.toml declares $VERSION, so artifacts will be named notyas-$VERSION-<board>-*"
        note "this value lands in the app descriptor and therefore in VERIFY.json and on the device"
    else
        bad "could not read a version out of firmware/Cargo.toml"
        GATE_FAIL=$((GATE_FAIL + 1))
    fi

    printf '\n--- the release key, as the documents promise it\n'
    local pretty f
    # The fingerprint as a verifier reads it, in groups of four, which is the form
    # docs print and the form a person compares by eye.
    pretty=$(printf '%s' "$RELEASE_KEY_FPR" | sed 's/..../& /g; s/ $//')
    for f in $KEY_DOCS; do
        if [ ! -f "$f" ]; then
            bad "$f is missing, and docs/VERIFYING.md sends a verifier to it"
            GATE_FAIL=$((GATE_FAIL + 1))
        elif grep -qF "$pretty" "$f" || grep -qF "$RELEASE_KEY_FPR" "$f"; then
            ok "$f names the release key"
        else
            bad "$f does not name $pretty"
            note "a document that names a different key sends a verifier to the wrong key,"
            note "which is worse than naming none at all."
            GATE_FAIL=$((GATE_FAIL + 1))
        fi
    done

    # There is no second fingerprint to hunt for here. This script used to scan the
    # tree for the first sixteen digits of "the desktop BigDice key" as a distinct
    # identity, which is the SAME key (SECUREBOOT.md section 4, REPRODUCIBLE.md 5.2):
    # the needle was a prefix of RELEASE_KEY_FPR, so it listed every document that
    # names the release key CORRECTLY - twelve of them on 2026-08-19 - and could
    # never have found anything else. An advisory whose every hit is a false positive
    # teaches the operator to skim past this stage, which is a worse outcome than not
    # printing it at all.
    #
    # The live hazard is the retired RSA-3072 "intnsity-esp" identity, and it is a
    # claim about the key's TYPE rather than a fingerprint to grep for: that key was
    # never published and this tree records no fingerprint for it. The detector is
    # tools/ci/check-ratified.sh [KEY], which has fixtures proving it fires, and the
    # gates stage runs it.

    printf '\n--- the key as a verifier will fetch it\n'
    assert_committed_key "docs/keys/$RELEASE_KEY_FPR.asc" "the published key" || GATE_FAIL=$((GATE_FAIL + 1))

    printf '\n--- the signing key itself\n'
    if command -v gpg > /dev/null 2>&1; then
        if gpg --list-secret-keys --with-colons "$RELEASE_KEY_FPR" > /dev/null 2>&1; then
            ok "the secret key is available on this machine"
        else
            note "the secret key is not on this machine. That is fine here, and fatal at"
            note "the 'sign' stage, which must run where the key is."
        fi
    else
        note "gpg is not on PATH here. The 'sign' stage needs it."
    fi

    printf '\n--- the toolchain the Q41 gate needs\n'
    # The same two places tools/ci/check-release-symbols.sh looks, asked here where
    # the answer is still cheap. That gate and its self-test are the only evidence
    # behind Q41, they read a linked ELF with riscv32-esp-elf-nm, and neither can be
    # deferred to CI the way an unavailable gate in 'gates' can: no other machine has
    # the artifact. Finding the toolchain missing here costs a second; finding it
    # missing in 'build' costs a container build, and by then the tag exists.
    if command -v riscv32-esp-elf-nm > /dev/null 2>&1; then
        ok "riscv32-esp-elf-nm is on PATH, so the Q41 image gate can run here"
    elif ls "$HOME"/.espressif/tools/riscv32-esp-elf/*/riscv32-esp-elf/bin/riscv32-esp-elf-nm* > /dev/null 2>&1; then
        ok "the ESP-IDF riscv32-esp-elf toolchain is under ~/.espressif, where that gate looks"
    else
        note "no riscv32-esp-elf-nm on PATH or under ~/.espressif. That is a note here and"
        note "fatal in 'build': without it neither tools/ci/check-release-symbols.sh nor its"
        note "self-test can read the shipped ELF, and Q41 has no evidence at all."
    fi

    printf '\n--- the documents this release promises\n'
    for f in docs/VERIFYING.md docs/RELEASE-0.2.0.md docs/PROVISIONING.md docs/KNOWN-ISSUES.md; do
        if [ -f "$f" ]; then ok "$f"; else bad "$f is missing"; GATE_FAIL=$((GATE_FAIL + 1)); fi
    done

    printf '\n'
    [ "$GATE_FAIL" -eq 0 ] || die "preflight: $GATE_FAIL problem(s). None of them is expensive to fix and all of them are expensive to find later."
    stamp_write preflight
}

# ---------------------------------------------------------------------------
# gates - the mechanical half of docs/QA.md's per-milestone gate, run over the
# whole tree at the release commit. Nothing here needs hardware.

cmd_gates() {
    local ci_evidence=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --ci-evidence) ci_evidence=${2:-}; shift 2 ;;
            *) die "gates: unknown argument $1" ;;
        esac
    done

    step "host gates"
    stamp_require preflight
    GATE_FAIL=0
    GATE_UNAVAILABLE=""

    # Order inside the stage is also cheapest-first: hygiene and graph checks are
    # seconds, the suites are minutes, the power-loss corpora are minutes more.
    gate "hygiene: no em dash or en dash, tracked or untracked" bash tools/ci/check-dashes.sh
    # A bare ref expands to the whole history in that script, which is what a
    # release wants: every commit that ships, not the tip that happens to be here.
    gate "hygiene: no forbidden token in any commit message" bash tools/ci/check-commit-messages.sh HEAD
    gate "build graph: SECURITY.md invariants 1 and 3" bash tools/build-graph-check.sh
    gate "supply chain: every dependency pinned and content addressed" bash tools/ci/check-supply-chain.sh
    # The ratified answers, [KEY] among them: that the release identity is the rsa4096
    # fingerprint this file signs with, and that every KEY_DOCS entry names it. It reads
    # RELEASE_KEY_FPR and KEY_DOCS out of this script, so the two cannot drift, and it is
    # the only gate on the release path that compares the tree against an owner DECISION
    # rather than against itself. Its exit 2 - an assertion it could not evaluate - is a
    # failure here for the same reason an unavailable gate is: nobody checked.
    gate "ratified decisions: the tree agrees with every owner decision" bash tools/ci/check-ratified.sh
    # Both of these prove that a check on the release path can still say no. The
    # first drives this script's own signature verification against a throwaway key
    # whose uid mimics the release identity - the case where `gpg --verify` exits 0
    # and prints "Good signature from intnsity". The second plants the attestation
    # the cross-check leaves behind and asserts the release path refuses it. Same
    # argument as the Q41 self-test in 'build': a check that has only ever passed is
    # indistinguishable from one that cannot fail, and both of these guard a claim
    # that is otherwise made by silence.
    gate "the signature check still refuses every key but the release key (self-test)" \
        bash tools/ci/selftest-release-signature.sh
    gate "a cross-check verdict is not believed unless this run wrote it (self-test)" \
        bash tools/ci/selftest-xverify-binding.sh
    # Source tier only, because no release ELF exists yet. The image tier is the
    # one that proves invariant 1 about what SHIPS, and it runs in 'build', against
    # the artifact rather than against the tree that asked for it.
    gate "airgap: source tier (invariant 1 as the tree asks for it)" bash tools/ci/check-airgap.sh --source-only
    gate "reproducible-build pins agree across all four files" bash tools/ci/check-repro-pins.sh
    gate "screenshots are current and deterministic" bash tools/ci/check-screenshots.sh
    gate "host suite" cargo test --locked
    gate "clippy, every host crate, warnings denied" cargo clippy --locked --all-targets --all-features -- -D warnings
    gate "power-loss fuzzer (the m3 storage exit gate)" \
        cargo test --locked --release -p notyas-wallet --test powerloss -- --ignored --nocapture

    # The third-party cross-check. MILESTONES.md section 9 clause 2 - "hand the
    # result to a coordinator that ACCEPTS it" - is the one release bar that
    # nothing inside this tree can answer, because every other suite here checks
    # notyas code against vectors notyas chose. tools/xverify puts Bitcoin Core
    # and embit on the other side of it.
    #
    # --require, so an oracle that is not installed is a failure rather than a
    # warning. --probe first, so a bench without a Bitcoin node reports the gate
    # as UNAVAILABLE - which this script already refuses to treat as a pass - and
    # the releaser has to name where it did run, rather than the release being
    # blocked outright on a machine that was never going to have a node.
    printf '\n--- third-party cross-check (bitcoin core + embit)\n'
    # One nonce per release run, made here and passed down, so that the verdict this
    # stage leaves in out/xverify can be told apart from every other file of that
    # name. It goes into the stamp because 'publish' asks the same question again at
    # the irreversible boundary, where a file that appeared in between is exactly
    # what it is looking for.
    local xverify_run_id xverify_stamp
    xverify_run_id=$(new_run_id)
    if bash tools/ci/check-xverify.sh --probe; then
        gate "every derivation and signature accepted by two outside implementations" \
            bash tools/ci/check-xverify.sh --require --run-id "$xverify_run_id"
        gate "that verdict was written by THIS run, against THIS tree" \
            xverify_attestation_is_this_run "$xverify_run_id"
        xverify_stamp="xverify_run_id = $xverify_run_id"
    else
        gate_unavailable "third-party cross-check" "needs bitcoind, bitcoin-cli and a python that can import embit (tools/xverify/README.md)"
        note "this runs in .github/workflows/ci.yml job 'xverify' on every push, and"
        note "writes out/xverify/attestation.json wherever it does run."
        gate "no cross-check verdict is lying around claiming otherwise" \
            xverify_attestation_absent
        xverify_stamp="xverify_run_id = none"
    fi

    # no_std. A crate that quietly acquired std is a regression even when nothing
    # fails, and secp256k1-sys needs a RISC-V C toolchain to cross-compile, which
    # a Windows bench does not have. Unavailable is reported, never skipped.
    printf '\n--- no_std, bare metal (riscv32imac)\n'
    if rustup target list --installed 2>/dev/null | grep -qx riscv32imac-unknown-none-elf \
       && command -v riscv64-unknown-elf-gcc > /dev/null 2>&1; then
        gate "notyas-core builds without std" \
            cargo check --locked -p notyas-core --no-default-features --target riscv32imac-unknown-none-elf
        gate "notyas-ui builds without std" \
            cargo check --locked -p notyas-ui --target riscv32imac-unknown-none-elf
        gate "notyas-wallet builds without std" \
            cargo check --locked -p notyas-wallet --target riscv32imac-unknown-none-elf
    else
        gate_unavailable "no_std bare-metal checks" "needs the riscv32imac target and riscv64-unknown-elf-gcc"
        note "these run in .github/workflows/ci.yml job 'no_std' on every push."
    fi

    printf '\n'
    [ "$GATE_FAIL" -eq 0 ] || die "gates: $GATE_FAIL gate(s) failed. A release does not proceed past a red gate, and a gate is not waived."

    if [ -n "$GATE_UNAVAILABLE" ]; then
        if [ -z "$ci_evidence" ]; then
            printf 'These gates could not run here:%s\n\n' "$GATE_UNAVAILABLE"
            die "name where they did run: tools/release.sh gates --ci-evidence 'ci run <url>, green at $HEAD_COMMIT'. An unrun gate is not a passed gate."
        fi
        stamp_write gates "unavailable_here =$GATE_UNAVAILABLE" "external_evidence = $ci_evidence" "$xverify_stamp"
    else
        stamp_write gates "unavailable_here = none" "$xverify_stamp"
    fi
}

# ---------------------------------------------------------------------------
# hardware - the gates this script cannot run and must not pretend to.

cmd_hardware() {
    local ack=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --ack) ack=${2:-}; shift 2 ;;
            *) die "hardware: unknown argument $1" ;;
        esac
    done

    step "hardware gates"
    stamp_require preflight gates

    cat <<'HWEOF'
Everything below is performed by the owner, by hand, on BOTH verified boards.
No script in this repository can observe them, so this stage records an
acknowledgement and nothing more. It is deliberately not a checkbox list the
tool ticks for you.

  1. Every milestone exit gate in docs/plan-0.2.0/MILESTONES.md, green on both
     boards, evidence recorded in the milestone commit or MEASUREMENTS.md.
  2. The pre-handover gauntlet in docs/QA.md: every flow walked end to end, the
     power-cut robustness set, the adversarial PSBT corpus, both resolutions,
     the one hour idle soak.
  3. The whole-loop test from MILESTONES section 9 item 2: create or import a
     seed, save it under a PIN, power cycle, unlock, register a 2 of 3 P2WSH
     multisig, verify the first receive address against another signer, load a
     PSBT from SD, review it, sign it, and have a coordinator accept the result.
  4. A release unit walks docs/PROVISIONING.md and still passes every gate.
  5. The claims audit: every sentence in the shipped documents that implies
     Secure Boot, anti-rollback, a hardware-held signing key, third-party
     attestation, a backup, BSMS or taproot multisig is found and corrected.
     Each of those seven is false in 0.2.0.

HWEOF

    [ -n "$ack" ] || die "record what you observed: tools/release.sh hardware --ack 'gauntlet green on A and B, $(date -u +%Y-%m-%d), notes in docs/...'"
    stamp_write hardware "acknowledgement = $ack"
}

# ---------------------------------------------------------------------------
# tag - the first irreversible-in-public step.

cmd_tag() {
    step "signed tag $TAG"
    stamp_require preflight gates hardware

    # An `if` rather than `cmd && die`, because the latter is correct here only by
    # way of the set -e exemption for a non-final command in an && list. A guard
    # whose safety depends on that exemption is a guard the next edit breaks.
    if git rev-parse -q --verify "refs/tags/$TAG" > /dev/null; then
        die "$TAG already exists"
    fi
    command -v gpg > /dev/null 2>&1 || die "gpg is not on PATH; the tag is signed with the release key"
    gpg --list-secret-keys --with-colons "$RELEASE_KEY_FPR" > /dev/null 2>&1 \
        || die "the release secret key $RELEASE_KEY_FPR is not on this machine. Tag where the key is."

    # -u pins the key explicitly rather than trusting the default signing key of
    # whatever machine this is: the tag and SHA256SUMS.txt must carry the same
    # identity, and a verifier checks one fingerprint for both.
    git -c gpg.format=openpgp tag -s -u "$RELEASE_KEY_FPR" "$TAG" -F - <<TAGEOF
notyas $VERSION

An airgapped Bitcoin signer for ESP32-P4 touch panels.

Release notes, known limitations and what deliberately does not ship:
docs/RELEASE-0.2.0.md
How to verify this release yourself: docs/VERIFYING.md

Signed with the notyas release key $RELEASE_KEY_FPR.
TAGEOF

    # Not `git tag -v`, which prints "Good signature from <uid>" and exits 0 for a
    # signature from any key in this keyring. What has to be true is that THIS
    # fingerprint made it.
    verify_tag_signature "$TAG" \
        || die "$TAG was created but does not carry a signature from $RELEASE_KEY_FPR. Delete it (git tag -d $TAG), find out which key gpg used, and tag again."
    stamp_write tag "tag = $TAG" "signed_by = $RELEASE_KEY_FPR"
}

# ---------------------------------------------------------------------------
# build - call the normative build, once per board, and check the result.

cmd_build() {
    step "release build"
    stamp_require preflight gates hardware tag

    command -v docker > /dev/null 2>&1 || die "docker is not on PATH. The container build is the normative one (tools/repro/README.md); a host build is not a release artifact."
    [ "$(git rev-parse "$TAG^{commit}")" = "$HEAD_COMMIT" ] \
        || die "$TAG does not point at HEAD. Build the commit the tag names, or nothing downstream means anything."

    mkdir -p "$ARTIFACTS"
    # A stale artifact from an earlier attempt would be hashed into SHA256SUMS.txt
    # by build.sh, which lists the directory rather than a list of names. That is
    # the right behaviour there and it makes cleaning here mandatory.
    rm -rf "${ARTIFACTS:?}/"* 2> /dev/null || true

    step "building the release container"
    docker build -t "$IMAGE" -f tools/repro/Dockerfile .

    local board
    for board in $(boards); do
        step "board $board"
        docker run --rm -v "$REPO":/mnt/src:ro -v "$ARTIFACTS":/out "$IMAGE" "$board"
    done

    check_artifacts build
    # The Q41 verdict is recorded rather than left implicit in "the stage passed".
    # docs/RELEASE-0.2.0.md and the release notes both state that the shipped image
    # carries no test console, and this line is the evidence that claim rests on:
    # which tool decided it, about which files, at which commit.
    stamp_write build "artifacts = $ARTIFACTS" "boards = $(boards | tr '\n' ' ')" \
        "hil_console = absent from every board ELF (tools/ci/check-release-symbols.sh)" \
        "q41_gate_proved_failing = tools/ci/selftest-release-symbols.sh, this run, before the verdict above"
}

# ---------------------------------------------------------------------------
# reproduce - the gate the whole document set rests on.

cmd_reproduce() {
    local attestation="" no_second=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --attestation) attestation=${2:-}; shift 2 ;;
            --no-second-machine) no_second=1; shift ;;
            *) die "reproduce: unknown argument $1" ;;
        esac
    done

    step "reproducibility"
    stamp_require preflight gates hardware tag build

    # Settle the second-machine question BEFORE the double build, which is hours.
    # Discovering afterwards that the operator has no attestation to hand is a
    # refusal that costs the whole run rather than a second.
    if [ -n "$attestation" ]; then
        [ -f "$attestation" ] || die "no such attestation file: $attestation"
    elif [ "$no_second" -eq 0 ]; then
        die "supply the second machine's hash list (--attestation FILE) or state plainly that there is none (--no-second-machine). A reproducibility claim with one builder is a claim about one machine."
    fi

    # Before the hours, not after: the comparison this stage makes against
    # $ARTIFACTS has never refused anything in this tree, because every rebuild
    # here has matched, and a gate that has only ever said yes is indistinguishable
    # from one that cannot say no. Cheap gates before expensive ones, ordering rule
    # 1, applies inside a stage as well as between them.
    step "the reproduction/artifact tie can say no (self-test)"
    bash tools/ci/selftest-reproduce-binding.sh \
        || die "the check that ties the double build to the artifacts did not refuse artifacts no rebuild produced. Until tools/ci/selftest-reproduce-binding.sh passes, a green reproduce stage says nothing about the bytes that get signed."

    # Two builds on THIS machine, from two host paths, at different times, the
    # second handed a hostile environment. It is the check-repro.sh contract and
    # it is not reimplemented here.
    bash tools/repro/check-repro.sh

    # And now the question check-repro.sh does not ask: is what it just reproduced
    # what is about to be signed. See the block above reproduction_covers_artifacts
    # for what this stage used to leave unasserted, and for what a pass here means.
    step "the artifacts against the rebuild"
    local reproduced_digest
    # shellcheck disable=SC2046  # the board list is a list, and this script wrote it
    reproduction_covers_artifacts "$CHECK_REPRO_A" "$ARTIFACTS/SHA256SUMS.txt" $(boards) \
        || die "the artifacts in $ARTIFACTS are not the bytes the double build just produced. STOP. This is the finding the release process exists to make, not an inconvenience to work around: the two builds matched each other, so the recipe is sound and the artifact directory is not. Triage with docs/VERIFYING.md section 9 item 3, re-run from 'build', and do not sign anything in there."
    ok "every artifact about to be signed is byte-for-byte one the rebuild produced, and the hash list names nothing else"
    reproduced_digest=$(artifact_pairs_digest "$ARTIFACTS/SHA256SUMS.txt")

    local second_state
    if [ -n "$attestation" ]; then
        step "second machine"
        local mine theirs
        mine=$(mktemp); theirs=$(mktemp)
        hash_list_pairs "$ARTIFACTS/SHA256SUMS.txt" > "$mine"
        hash_list_pairs "$attestation" > "$theirs"
        if diff -u "$mine" "$theirs"; then
            ok "a second machine produced identical bytes for every artifact"
            second_state="second_machine = matched ($attestation)"
        else
            rm -f "$mine" "$theirs"
            die "the second machine's artifacts differ. STOP. This is the finding the release process exists to make, not an inconvenience to work around: triage with docs/VERIFYING.md section 9 item 3 and do not sign anything."
        fi
        rm -f "$mine" "$theirs"
    else
        cat <<'NOSECONDEOF'

  NO SECOND MACHINE.

  MILESTONES section 9 item 5 makes a second-machine reproduction a condition of
  the release being done, and docs/VERIFYING.md tells the reader that the release
  notes record whether it happened. Proceeding without it is therefore not a
  silent choice: the release notes MUST say, in the reproducibility section, that
  the two-machine run did not happen for this tag.

NOSECONDEOF
        second_state="second_machine = NOT RUN, and the release notes must say so"
    fi

    stamp_write reproduce "double_build = passed" \
        "reproduced_artifacts_sha256 = $reproduced_digest" "$second_state"
}

# ---------------------------------------------------------------------------
# sign - a human, on a machine that is not a runner.

cmd_sign() {
    step "signature"
    stamp_require preflight gates hardware tag build reproduce

    # REPRODUCIBLE.md 6.3: CI computes hashes, a human signs them. A key that has
    # been on a hosted runner is a key that has to be treated as disclosed.
    [ -z "${CI:-}" ] || die "refusing to sign inside CI. The release key does not touch hosted infrastructure."
    command -v gpg > /dev/null 2>&1 || die "gpg is not on PATH"
    gpg --list-secret-keys --with-colons "$RELEASE_KEY_FPR" > /dev/null 2>&1 \
        || die "the release secret key $RELEASE_KEY_FPR is not on this machine"

    local sums="$ARTIFACTS/SHA256SUMS.txt"
    [ -f "$sums" ] || die "no $sums; run the build stage"

    # Re-check before signing rather than trusting the file the build left behind.
    # The gap between building and signing is where a compromised host would act,
    # and it costs a second to close. Both halves, for the reason artifacts_fully_hashed
    # exists: this signature is about to make SHA256SUMS.txt the authority on what this
    # release consists of, and a file sitting in the directory that the list does not
    # name is one the signature will never cover.
    artifacts_fully_hashed \
        || die "SHA256SUMS.txt no longer describes $ARTIFACTS. Do not sign this."
    ok "every artifact still hashes to its listed value, and the list names every file here"

    # The half that check cannot answer. A directory and a list rewritten together
    # agree with each other perfectly, which is what an artifact rewritten since the
    # build looks like from here. This asks the other question: is this list still
    # the one the double build vouched for. Ordering rule 4 is about the bytes being
    # signed, and this is where it is asserted about them.
    artifacts_match_reproduce_stamp sign

    rm -f "$sums.asc"
    gpg --armor --detach-sign --local-user "$RELEASE_KEY_FPR" "$sums"

    # Verify what was just produced, rather than assuming the tool did what it was
    # asked - and verify it the way a stranger who checks the fingerprint will, not
    # the way `gpg --verify` alone would, which is satisfied by any key present here.
    verify_detached_signature "$sums.asc" "$sums" \
        || die "the signature just written is not from $RELEASE_KEY_FPR. Do not publish it; find out which key gpg used."

    stamp_write sign "signature = $sums.asc" "signed_by = $RELEASE_KEY_FPR"

    step "the line the release notes must carry"
    sed -n 's/^second_machine = /  reproducibility: /p' "$STAMPS/reproduce"
}

# ---------------------------------------------------------------------------
# publish - the last stage, and the only one that changes anything public.

cmd_publish() {
    local confirm=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --confirm) confirm=1; shift ;;
            *) die "publish: unknown argument $1" ;;
        esac
    done

    step "publish"
    stamp_require preflight gates hardware tag build reproduce sign

    [ "$confirm" -eq 1 ] || die "publication is the irreversible half. Re-run with --confirm when the artifacts and the release notes are ready to be public."

    # The push is the one step this script cannot take back, so every fact it makes
    # public is re-established HERE rather than trusted from the stage that
    # established it. A stamp binds a STAGE to a commit; it does not bind the tag
    # object to the one that was verified, the signature to the bytes on disk, the
    # artifact directory to the files that were hashed, or a JSON verdict in out/ to
    # a run that happened. A tag deleted and remade, an artifact touched, a file
    # copied in, a signature that never got written, an attestation planted - each of
    # those leaves every stamp valid and the release wrong, and the last moment to
    # find out is the moment before origin learns about it.
    #
    # "Every fact" is meant literally, and it was not always true: this stage used to
    # re-run three of the four checks the build stage made about the artifacts, and
    # the one it dropped was the count equality that notices a file nobody hashed.
    # Whatever is asserted before the tag has to be asserted again here, in full, or
    # the assertion is about a moment that has passed.
    #
    # These are seconds. The alternative to spending them is a signed public claim
    # about bytes nobody has looked at since the previous stage.
    step "what the push is about to make public"

    # An `if` rather than a `&&`/`||` chain, for the reason cmd_tag gives: a guard
    # whose safety rests on shell short-circuit rules is a guard the next edit breaks.
    if [ "$(git rev-parse "$TAG^{commit}")" = "$HEAD_COMMIT" ]; then
        ok "$TAG still points at HEAD"
    else
        die "$TAG no longer points at HEAD. The tag that would be pushed is not the one every stage above passed at."
    fi

    command -v gpg > /dev/null 2>&1 || die "gpg is not on PATH, so neither the tag nor the signature can be checked before the push"
    if ! verify_tag_signature "$TAG"; then
        die "$TAG does not carry a signature from $RELEASE_KEY_FPR. Do not push it."
    fi

    # The key file the push is about to publish, read out of the commit rather than
    # off disk. Preflight asserted the working copy, hours and several stages ago; what
    # a verifier will fetch is the blob at this commit, and docs/VERIFYING.md sends
    # them to it as one of the two places the fingerprint has to agree. A release whose
    # published key is not the key that signed it is unverifiable in the one direction
    # nobody checks, because every check here would still pass.
    local keyfile keyblob=docs/keys/$RELEASE_KEY_FPR.asc
    keyfile=$(mktemp)
    if git show "HEAD:$keyblob" > "$keyfile" 2>/dev/null; then
        if ! assert_committed_key "$keyfile" "the published key, as committed at HEAD"; then
            rm -f "$keyfile"
            die "the key file this push would publish is not $RELEASE_KEY_FPR. Do not push."
        fi
    else
        rm -f "$keyfile"
        die "$keyblob is not in the commit being pushed, and docs/VERIFYING.md sends every verifier to it."
    fi
    rm -f "$keyfile"

    local sums="$ARTIFACTS/SHA256SUMS.txt"
    [ -f "$sums" ]     || die "no $sums. The release page would carry artifacts nobody hashed."
    [ -f "$sums.asc" ] || die "no $sums.asc. An unsigned hash list is the one thing docs/VERIFYING.md tells a stranger to refuse."
    if ! verify_detached_signature "$sums.asc" "$sums"; then
        die "the hash list is not signed by $RELEASE_KEY_FPR. Do not push."
    fi

    # Everything 'build' asserted about the artifact directory, asserted again -
    # every check, not a subset. See check_artifacts for why the pair of hash
    # checks is one function now, and why the gap between the two stages is where
    # a file appears.
    check_artifacts publish
    ok "the signature verifies over a hash list that describes this directory exactly"

    # And that the hash list is still the one the double build reproduced, asked
    # again here for the same reason every other fact on this page is: 'sign' asked
    # it, and the answer it got was about a moment that has passed.
    artifacts_match_reproduce_stamp publish

    # The cross-check's evidence, re-asked here for the same reason: 'gates' ran
    # hours ago, and out/xverify/attestation.json is a file anything could have
    # written since. Read xverify_evidence_at_publish before trusting a pass from
    # this branch: the run id it starts from is plaintext in a directory anyone who
    # could plant the verdict can also write, so the id alone settles nothing, and
    # only the re-run inside that function does.
    local xverify_run_id
    xverify_run_id=$(sed -n 's/^xverify_run_id = //p' "$STAMPS/gates")
    case "$xverify_run_id" in
        "")
            die "the gates stamp records no cross-check run id: it was written by an older release.sh, from before the attestation could be bound to a run, so nothing here can tell that verdict apart from a planted one. Re-run: tools/release.sh gates"
            ;;
        none)
            xverify_attestation_absent \
                || die "the cross-check did not run at the gates stage, and out/xverify now holds a verdict anyway. Do not push."
            ok "no unexplained cross-check verdict is sitting beside this release"
            ;;
        *)
            xverify_evidence_at_publish "$xverify_run_id" \
                || die "out/xverify/attestation.json is not the verdict the gates stage produced at this commit, or the cross-check re-run here did not verify. Do not push."
            ;;
    esac

    git push origin HEAD
    git push origin "$TAG"

    cat <<PUBEOF

Pushed $TAG. What remains is manual, and in this order:

  1. Create the GitHub release from the tag $TAG.
  2. Attach every file in $ARTIFACTS, including SHA256SUMS.txt and
     SHA256SUMS.txt.asc. Attach nothing that is not in SHA256SUMS.txt: an
     unlisted file is an unsigned file.
  3. Paste the release notes from docs/RELEASE-0.2.0.md, including the known
     limitations and the interop change to already finalized cosigner inputs.
  4. Publish docs/keys/$RELEASE_KEY_FPR.asc and confirm the key is on
     keys.openpgp.org, so a verifier has two independent sources.
  5. Then walk docs/VERIFYING.md yourself, from a machine that has never held
     this repository, downloading only from the release page. Everything above
     was checked by someone who knew the answer; this is the first time anybody
     checks it the way a stranger will.

PUBEOF
}

# ---------------------------------------------------------------------------

# Sourced rather than executed - tools/ci/selftest-release-signature.sh does exactly
# that to drive assert_valid_sig against a fixture - this dispatch does not run.
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0

case "${1:-plan}" in
    plan|"")   cmd_plan ;;
    preflight) shift; cmd_preflight "$@" ;;
    gates)     shift; cmd_gates "$@" ;;
    hardware)  shift; cmd_hardware "$@" ;;
    tag)       shift; cmd_tag "$@" ;;
    build)     shift; cmd_build "$@" ;;
    reproduce) shift; cmd_reproduce "$@" ;;
    sign)      shift; cmd_sign "$@" ;;
    publish)   shift; cmd_publish "$@" ;;
    -h|--help|help) cmd_plan ;;
    *) die "unknown stage '$1'. Run tools/release.sh with no arguments for the plan." ;;
esac
