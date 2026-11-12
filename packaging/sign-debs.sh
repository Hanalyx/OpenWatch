#!/usr/bin/env bash
# Sign every .deb in a directory with a detached, ASCII-armored GPG
# signature, written beside it as <deb>.asc, then verify each one.
#
#   GPG_PASSPHRASE=... bash packaging/sign-debs.sh DIR
#
# The release workflow runs this after the RPMs are signed and before the
# SBOMs and SHA256SUMS are made. It signs with the first secret key in the
# keyring, chosen the same way the RPM step chooses %_gpg_name, so the DEBs
# and the RPMs are signed by the same key and signing subkey.
#
# Operators verify a package with:
#   gpg --import KEYS
#   gpg --verify openwatch_X.Y.Z_amd64.deb.asc openwatch_X.Y.Z_amd64.deb
#
# Fails closed. It exits non-zero, and leaves no signature it could not
# verify, when DIR holds no .deb, the keyring holds no secret key, or any
# signature does not verify as a good signature by that key over its
# package. GPG_PASSPHRASE must be set; it may be empty for a key without a
# passphrase. GNUPGHOME is honored, which is how the tests use a throwaway
# key.
#
# Spec: release-package-build C-18.

set -euo pipefail

dir="${1:?usage: sign-debs.sh DIR}"

# A signature left from an earlier run is never trusted: remove every one
# first, so a failure below leaves no .asc at all.
shopt -s nullglob
for old in "$dir"/*.deb.asc; do
  rm -f -- "$old"
done

if [ "${GPG_PASSPHRASE+set}" != "set" ]; then
  echo "sign-debs: GPG_PASSPHRASE is not set (set it empty for a key without a passphrase)" >&2
  exit 1
fi

debs=("$dir"/*.deb)
if [ "${#debs[@]}" -eq 0 ]; then
  echo "sign-debs: no .deb in $dir" >&2
  exit 1
fi

secret="$(gpg --batch --list-secret-keys --with-colons)"
key_id="$(awk -F: '/^sec/{print $5; exit}' <<<"$secret")"
key_fpr="$(awk -F: '/^sec/{want=1; next} want && /^fpr/{print $10; exit}' <<<"$secret")"
if [ -z "$key_id" ] || [ -z "$key_fpr" ]; then
  echo "sign-debs: no secret key in the keyring" >&2
  exit 1
fi

for deb in "${debs[@]}"; do
  asc="$deb.asc"
  rm -f -- "$asc"
  printf '%s' "$GPG_PASSPHRASE" | gpg --batch --yes --pinentry-mode loopback \
    --passphrase-fd 0 --no-secmem-warning --digest-algo sha256 \
    --local-user "$key_id" --armor --detach-sign --output "$asc" -- "$deb"

  # A signature counts only if gpg exits 0 and reports a VALIDSIG whose
  # primary key is the one that signed. Anything else removes the .asc.
  status="$(gpg --batch --status-fd 1 --verify -- "$asc" "$deb" 2>/dev/null)" || {
    rm -f -- "$asc"
    echo "sign-debs: the signature on $deb does not verify" >&2
    exit 1
  }
  primary="$(awk '$2 == "VALIDSIG" {print $NF; exit}' <<<"$status")"
  if [ "$primary" != "$key_fpr" ]; then
    rm -f -- "$asc"
    echo "sign-debs: $deb was not signed by $key_fpr (got '${primary:-nothing}')" >&2
    exit 1
  fi
  echo "signed $(basename -- "$deb") -> $(basename -- "$asc") by $key_fpr"
done
