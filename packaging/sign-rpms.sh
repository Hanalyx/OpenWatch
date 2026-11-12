#!/usr/bin/env bash
# GPG-sign RPMs in their headers with one pinned key, then verify each one
# against KEYS alone.
#
#   fpr="$(bash packaging/release-signing-key.sh security/KEYS)"
#   GPG_PASSPHRASE=... bash packaging/sign-rpms.sh "$fpr" security/KEYS dist/*.rpm
#
# release.yml runs this first among the signing steps. It runs rpmsign with
# %_gpg_name set to FPR, the release key's 40-hex primary fingerprint from
# packaging/release-signing-key.sh, so gpg signs with that key's signing
# subkey. The macros and the passphrase go in private temporary files: the
# macros are loaded with --load, so ~/.rpmmacros is never written, and gpg
# reads the passphrase with --passphrase-file, so it is on no command line
# and may contain spaces (the previous inline step put it on gpg's command
# line unquoted). The default %__gpg points at gpg2, absent on Ubuntu
# runners, so it is set explicitly.
#
# Then every RPM is checked with `rpm -K` in a throwaway rpm database holding
# only KEYS: an RPM whose signature is not by a key in KEYS fails, which an
# operator's `rpm --import KEYS` and `rpm -K` would also report.
#
# Fails closed: it exits non-zero when FPR is not a full fingerprint, KEYS is
# unreadable, GPG_PASSPHRASE is not set, no RPM is named or one does not
# exist, rpmsign fails, or any check does not report "signatures OK".
#
# Spec: release-package-build C-19.

set -euo pipefail

fpr="${1:-}"
keys="${2:-}"
fail() {
  echo "sign-rpms: $*" >&2
  exit 1
}
[[ "$fpr" =~ ^[0-9A-F]{40}$ ]] || fail "usage: sign-rpms.sh FPR KEYS RPM...; FPR must be a 40-hex fingerprint, got '${fpr}'"
[ -r "$keys" ] || fail "cannot read KEYS file '${keys}'"
shift 2
[ "$#" -gt 0 ] || fail "no RPM to sign"
if [ "${GPG_PASSPHRASE+set}" != "set" ]; then
  fail "GPG_PASSPHRASE is not set (set it empty for a key without a passphrase)"
fi
for f in "$@"; do
  [ -f "$f" ] || fail "$f does not exist"
done

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
chmod 700 "$work"
gpg_bin="$(command -v gpg)"
(umask 077 && printf '%s' "$GPG_PASSPHRASE" >"$work/pass")
# rpm's own %__gpg_sign_cmd is kept, never overridden: rpm 4.18 (ubuntu-24.04)
# names the files %{__signature_filename} and %{__plaintext_filename}, while
# rpm 6.0 (ubuntu-26.04) passes them as %{1} and %{2}, so an override written
# for one breaks on the other. Both built-in commands read the digest from
# %_gpg_digest_algo and add %_gpg_sign_cmd_extra_args. The key is %_gpg_name
# on 4.18 and %_openpgp_sign_id on 6.0 (which defaults to %_gpg_name); both
# are set to FPR.
cat >"$work/macros" <<RPMMACROS
%__gpg ${gpg_bin}
%_signature gpg
%_openpgp_sign gpg
%_gpg_name ${fpr}
%_openpgp_sign_id ${fpr}
%_gpg_digest_algo sha256
%_gpg_sign_cmd_extra_args --batch --pinentry-mode loopback --passphrase-file ${work}/pass
RPMMACROS
chmod 600 "$work/macros"
rpmsign --load "$work/macros" --addsign "$@"

mkdir "$work/rpmdb"
rpm --dbpath "$work/rpmdb" --import "$keys"
for f in "$@"; do
  out="$(rpm --dbpath "$work/rpmdb" -K "$f" 2>&1)" || fail "rpm -K failed for $f: $out"
  case "$out" in
    *"NOT OK"* | *"not OK"*) fail "rpm -K reports a bad signature for $f: $out" ;;
    *"signatures OK"*) echo "signed $(basename -- "$f") by $fpr; $out" ;;
    *) fail "rpm -K does not report a signature for $f: $out" ;;
  esac
done
