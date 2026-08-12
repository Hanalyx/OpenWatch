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

cat >&2 <<EOF
check-tag-version: REFUSING TO BUILD

  tag                    $ref  (version $tag_version)
  packaging/version.env  VERSION="$VERSION"

These must be identical. VERSION is what reaches the RPM and DEB metadata, so
building this tag would publish a package whose version is not the one you
tagged.

If this is a release candidate, the pre-release suffix belongs in version.env
too, exactly as the v0.2.0 series did (0.2.0-rc.16, 0.2.0-rc.17, then 0.2.0 at
GA). Set VERSION="$tag_version", update the README version phrase and the
newest CHANGELOG heading to match (packaging/tests enforces all three agree),
then move the tag.

Two pre-releases that share a VERSION produce two different builds with one
package identity, and dnf or apt will refuse to move between them.
EOF
exit 1
