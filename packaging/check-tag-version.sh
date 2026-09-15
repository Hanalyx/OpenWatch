#!/usr/bin/env bash
# Assert that the release ref being built matches packaging/version.env.
#
# WHY THIS EXISTS: the pre-release identity of a build lives in two places and
# nothing compared them. The tag carries it on the way in (v0.7.0-rc.2) and
# packaging/version.env carries it on the way out (VERSION="0.7.0-rc.2"), and
# only the second reaches the package metadata.
#
# v0.7.0-rc.1 and v0.7.0-rc.2 were both tagged against a version.env of
# "0.7.0". The build scripts did nothing wrong: build-rpm.sh tilde-encodes a
# pre-release correctly, and there is a test asserting it does. The suffix
# simply never got as far as them. Both RCs therefore shipped as
#
#   openwatch-1:0.7.0-1.x86_64
#
# byte-different artifacts with one identity. `dnf upgrade` between them prints
# "Nothing to do" and leaves the host on the older build; `rpm -q` cannot tell
# them apart. The dangerous case is silent: install rc.1, "upgrade" to rc.2,
# test, sign off, having verified rc.1 the whole time. Only
# GET /api/v1/version, which reports the build commit, distinguishes them.
#
# Usage: RELEASE_REF=v0.7.0-rc.2 packaging/check-tag-version.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ref="${RELEASE_REF:-}"
if [ -z "$ref" ]; then
    echo "check-tag-version: RELEASE_REF is empty; expected a tag such as v0.7.0-rc.2" >&2
    exit 2
fi

# shellcheck source=/dev/null
. "$here/version.env"

# The tag is the semver prefixed with 'v'; version.env holds the bare semver.
tag_version="${ref#v}"

if [ "$tag_version" = "$VERSION" ]; then
    echo "check-tag-version: OK — tag $ref matches VERSION=$VERSION"
    exit 0
fi

case "$tag_version" in
    *-rc.[0-9]*)
        n="${tag_version##*-rc.}"
        next="${tag_version%-rc.*}-rc.$((n + 1))"
        advice="  this tag is now a record of a failed candidate and is never moved. Take
  the next unused number: set VERSION=\"$next\", README and CHANGELOG to
  $next, merge, then run the Stage 2 block on that merged commit; it will
  tag v$next."
        ;;
    *)
        advice="  this tag is now a record of a failed GA candidate and is never moved. A GA
  tag is cut from a final-version commit whose version.env says the same
  version, prepared through review and merged. Take the NEXT version number
  for that commit (RELEASING.md Stage 4, \"When a GA candidate fails\")."
        ;;
esac

cat >&2 <<EOF
check-tag-version: REFUSING TO BUILD

  tag                    $ref  (version $tag_version)
  packaging/version.env  VERSION="$VERSION"

These must be identical. VERSION is what reaches the RPM and DEB metadata, so
building this tag would publish a package whose version is not the one you
tagged.

A candidate names ONE version in four places: VERSION in version.env, the
README version phrase, the newest CHANGELOG heading (packaging/tests enforces
those three agree), and the tag, which RELEASING.md Stage 2 derives from
version.env rather than typing. Recover with ONE version in all four places:
$advice

Two pre-releases that share a VERSION produce two different builds with one
package identity, and dnf or apt will refuse to move between them.
EOF
exit 1
