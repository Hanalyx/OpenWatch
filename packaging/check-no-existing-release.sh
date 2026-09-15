#!/usr/bin/env bash
# Refuse to build a tag that already has release assets.
#
# A candidate is built once. Its evidence (D1, F1 to F3, H1, and the checker's
# own digest verification) binds to the digests of that one build, so a second
# build under the same tag would replace the bytes the evidence describes
# while leaving the tag, the release page and the evidence looking unchanged.
# That is exactly the silent substitution the release contract forbids
# (release-ci-gates C-14). A candidate that must change is replaced under the
# procedure in docs/runbooks/RELEASING.md Stage 4, never rebuilt in place.
#
# Usage: RELEASE_REF=v0.8.0 bash packaging/check-no-existing-release.sh
# Needs: gh, authenticated with push access (drafts are only listed to it).
# Exit 0 when no release for the tag exists or it carries no assets; exit 1
# when assets exist; exit 2 when the release list could not be read, because
# "could not check" must not build either.
set -euo pipefail

ref="${RELEASE_REF:?RELEASE_REF is required (the tag being built)}"
repo="${GITHUB_REPOSITORY:-}"
if [ -z "$repo" ]; then
    repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
fi

if ! listing="$(gh api --paginate "repos/$repo/releases" \
        --jq ".[] | select(.tag_name == \"$ref\") | \"\\(.id)\\t\\(.draft)\\t\\(.assets | length)\"")"; then
    echo "check-no-existing-release: could not list releases for $repo; refusing to build blind" >&2
    exit 2
fi

if [ -z "$listing" ]; then
    echo "check-no-existing-release: OK, no release exists for $ref"
    exit 0
fi

while IFS=$'\t' read -r id draft count; do
    if [ "${count:-0}" -gt 0 ]; then
        state=published
        [ "$draft" = true ] && state=draft
        cat >&2 <<MSG
check-no-existing-release: REFUSING TO BUILD

  $ref already has a $state release (id $id) carrying $count assets.

A candidate is built once; its evidence binds to the digests of that build.
Building again would replace those bytes under the same tag and leave every
attestation describing artifacts that no longer exist. If this candidate must
change, replace it under RELEASING.md Stage 4 (delete the unpublished draft
and its tag, prepare a new final-version commit, cut again). A published
release is never rebuilt.
MSG
        exit 1
    fi
    echo "check-no-existing-release: OK, release $id for $ref carries no assets"
done <<< "$listing"
exit 0
