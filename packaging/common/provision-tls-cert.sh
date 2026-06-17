#!/usr/bin/env bash
# Provision a self-signed demo TLS cert + key at install time, ONLY when
# absent. Invoked from the RPM %post and the DEB postinst.
#
# WHY this exists / GENERATE-IF-ABSENT: the cert lives at the production
# path /etc/openwatch/tls/{cert,key}.pem. If the package shipped it in the
# payload, dnf/apt would silently overwrite an operator's real certificate
# with a freshly-built demo cert on EVERY upgrade — the TLS files are not
# config files, so the package manager replaces them unconditionally and
# without a .rpmsave/.dpkg-dist backup. So the package ships only the empty
# tls/ directory and lays a demo cert down here only when it is missing.
# An operator who installed their own certificate keeps it across upgrades.
#
# This mirrors provision-identity-keys.sh (the JWT key + credential DEK use
# the same never-overwrite, not-in-payload model).
#
# Idempotent and operator-rerunnable: `bash /usr/lib/openwatch/provision-tls-cert.sh`.

set -euo pipefail

TLS_DIR="${OPENWATCH_TLS_DIR:-/etc/openwatch/tls}"
CERT="$TLS_DIR/cert.pem"
KEY="$TLS_DIR/key.pem"
OWNER_GROUP="${OPENWATCH_GROUP:-openwatch}"

if ! command -v openssl >/dev/null 2>&1; then
    echo "provision-tls-cert: openssl not found (it is a package dependency)" >&2
    exit 1
fi

# 0750 so the service (running as the openwatch user, in the openwatch
# group) can traverse it, but it is not world-readable.
install -d -m 0750 -o root -g "$OWNER_GROUP" "$TLS_DIR"

# Generate only when BOTH files are absent. A half-present pair means the
# operator is mid-rotation or supplied just one half — never clobber either.
if [ ! -e "$CERT" ] && [ ! -e "$KEY" ]; then
    # umask 077 so the key is never briefly group/world-readable between
    # creation and the explicit chmod below.
    ( umask 077
      openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
          -subj "/CN=openwatch-demo/O=Hanalyx/OU=demo cert" \
          -keyout "$KEY" \
          -out    "$CERT" \
          >/dev/null 2>&1 )
    # cert.pem is the public certificate (0644 root:openwatch); key.pem is
    # the private key the service reads as the openwatch user (0600).
    chown "root:$OWNER_GROUP" "$CERT"
    chmod 0644 "$CERT"
    chown "$OWNER_GROUP:$OWNER_GROUP" "$KEY"
    chmod 0600 "$KEY"
    echo "provision-tls-cert: generated a self-signed demo cert at $CERT"
    echo "provision-tls-cert: REPLACE it with your own certificate before production use"
fi
