#!/usr/bin/env bash
# install-syft.sh: install the pinned syft release, verified by sha256.
#
# The release SBOMs are read by scripts/sbom-merge.py and validated against the
# CycloneDX 1.5 schema, so the tool that writes them is pinned by version and
# by the hash of its release tarball. Unpinned, syft moved to emitting
# CycloneDX 1.7 (CP bugs/OW-111). To upgrade: change both values below, from
# the release's syft_<version>_checksums.txt, and rerun the SBOM checks.
#
# Usage: install-syft.sh <bin-dir>   (linux amd64 runners only)
set -euo pipefail

SYFT_VERSION=1.54.0
SYFT_SHA256=54a87372498168b2d033e876fd41fa4e8035b872699e525a57046e1f2f09c860

dest="${1:?usage: install-syft.sh <bin-dir>}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tarball="syft_${SYFT_VERSION}_linux_amd64.tar.gz"
curl -sSfL -o "$work/$tarball" \
  "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/${tarball}"
echo "${SYFT_SHA256}  $work/$tarball" | sha256sum -c -
tar -xzf "$work/$tarball" -C "$work" syft
mkdir -p "$dest"
install -m 0755 "$work/syft" "$dest/syft"
# Capture, then match: a pipe into grep -q could die of SIGPIPE under pipefail.
reported="$("$dest/syft" version)"
[[ "$reported" =~ (^|$'\n')Version:\ +${SYFT_VERSION//./\\.}($'\n'|$) ]] || {
  echo "install-syft: installed syft does not report version ${SYFT_VERSION}" >&2
  exit 1
}
