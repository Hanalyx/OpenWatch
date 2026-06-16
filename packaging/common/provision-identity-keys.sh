#!/usr/bin/env bash
# Provision OpenWatch identity keys at install time. Invoked from the RPM
# %post and the DEB postinst.
#
# WHY this exists: in production the server deliberately refuses to
# auto-generate its signing material and exits if it is missing
# (cmd/openwatch/main.go: "There is no silent fallback to ephemeral — a
# binary with no signing key would 500 every login"). Auto-generation is
# a dev/test-only path. So the package — the production install boundary —
# must lay the keys down, exactly as it lays down the config and the unit.
#
# GENERATE-IF-ABSENT, never overwrite: regenerating jwt_private.pem would
# invalidate every issued token; regenerating credential.key would make
# every stored SSH credential and MFA secret permanently undecryptable. So
# both are created only when missing — this script is safe to re-run and
# safe across package upgrades.
#
# Idempotent and operator-rerunnable: `bash /usr/lib/openwatch/provision-identity-keys.sh`.

set -euo pipefail

KEYS_DIR="${OPENWATCH_KEYS_DIR:-/etc/openwatch/keys}"
JWT_KEY="$KEYS_DIR/jwt_private.pem"
DEK="$KEYS_DIR/credential.key"
OWNER_GROUP="${OPENWATCH_GROUP:-openwatch}"

if ! command -v openssl >/dev/null 2>&1; then
    echo "provision-identity-keys: openssl not found (it is a package dependency)" >&2
    exit 1
fi

# Key directory: 0750 so the service (running as the openwatch user, in the
# openwatch group) can traverse it, but it is not world-readable.
install -d -m 0750 -o root -g "$OWNER_GROUP" "$KEYS_DIR"

# JWT signing key — RSA 2048 PKCS#1 PEM (the loader accepts PKCS#1 or PKCS#8
# and requires >= 2048 bits). Mode 0640 root:openwatch: the service reads it
# via the group; root owns it.
if [ ! -f "$JWT_KEY" ]; then
    ( umask 077; openssl genrsa -out "$JWT_KEY" 2048 )
    chown "root:$OWNER_GROUP" "$JWT_KEY"
    chmod 0640 "$JWT_KEY"
    echo "provision-identity-keys: generated $JWT_KEY"
fi

# Credential DEK — exactly 32 raw bytes (AES-256). The loader REJECTS any
# group/other permission bits, so this must be 0600, owned by the service
# user so it can read its own key.
if [ ! -f "$DEK" ]; then
    ( umask 077; openssl rand -out "$DEK" 32 )
    chown "$OWNER_GROUP:$OWNER_GROUP" "$DEK"
    chmod 0600 "$DEK"
    echo "provision-identity-keys: generated $DEK"
fi
