# Secret rotation procedures

**Last updated:** 2026-07-30 · **Applies to:** OpenWatch v0.8.0 (Eyrie)

This guide describes how to rotate each secret used by OpenWatch on the current
single-binary stack: one `/usr/bin/openwatch` process that serves the REST API
and embedded UI over HTTPS on port `8443`, backed by PostgreSQL and run under
the `openwatch.service` systemd unit. There is no separate web tier, no
container runtime, and no Redis or message broker.

For install and first-time configuration, see the
[installation guide](../guides/INSTALLATION.md); this
guide assumes the service is already installed and running.

## Secrets at a glance

OpenWatch reads its secrets from three places: the TOML config
(`/etc/openwatch/openwatch.toml`), the systemd `EnvironmentFile`
(`/etc/openwatch/secrets.env`), and on-disk key/cert files under
`/etc/openwatch/`. The config layering order, highest precedence first, is CLI
flags, then `OPENWATCH_<SECTION>_<KEY>` environment variables, then the TOML
file, then built-in defaults.

| Secret | Where it lives | Loaded at | Rotation impact |
|--------|----------------|-----------|-----------------|
| Database DSN (incl. password) | `OPENWATCH_DATABASE_DSN` in `/etc/openwatch/secrets.env` | Service start, `migrate`, `create-admin` | Brief restart |
| JWT signing key (RSA private key) | `[identity].jwt_private_key` file (default `/etc/openwatch/keys/jwt_private.pem`) | Service start | Invalidates access tokens only. Browser sessions, refresh tokens and API tokens are database rows and survive; revoke them separately (see below) |
| Credential DEK (AES-256 key) | `[identity].credential_key_file` file (default `/etc/openwatch/keys/credential.key`) | Service start | Every stored SSH credential and MFA secret is readable only under the key that encrypted it. Never overwrite the file in place |
| TLS certificate and key | `[server].tls_cert` / `[server].tls_key` (default `/etc/openwatch/tls/{cert,key}.pem`) | Read on each TLS handshake | New connections pick up the new cert; restart to drop keep-alives |

> The server refuses to start if either the credential DEK or the JWT key path
> is empty or the file fails to load.

There is no separate "master key" or second "encryption key" on this stack. The
single credential DEK encrypts every at-rest secret (SSH credentials and MFA
secrets) with AES-256-GCM. The previous Python build's
`OPENWATCH_SECRET_KEY` / `OPENWATCH_MASTER_KEY` / `OPENWATCH_ENCRYPTION_KEY` /
`REDIS_PASSWORD` variables no longer exist.

## Before you rotate

1. Schedule a maintenance window. Every rotation here requires a service restart.
2. Back up the database with `pg_dump` before rotating the credential DEK or the
   JWT key. For the DEK that is not enough on its own: a database dump holds
   ciphertext, and ciphertext is only as recoverable as the key that made it.
   The DEK procedure below takes a verified copy of the key before anything
   else.
3. Record the current and new secret values in a secrets manager, not a plaintext
   file on the host.
4. Confirm the service is healthy first:

   ```bash
   curl -k https://localhost:8443/api/v1/health
   # {"status":"healthy","db_connected":true,"version":"<version>"}
   ```

## Rotate the database password

Impact: a brief restart while the service reconnects. The DSN lives in
`/etc/openwatch/secrets.env`, which the systemd unit loads via
`EnvironmentFile=-/etc/openwatch/secrets.env`.

1. Choose a new password and set it on the PostgreSQL role:

   ```bash
   sudo -u postgres psql -c "ALTER ROLE openwatch WITH PASSWORD 'new-strong-password';"
   ```

2. Replace only the DSN line in `/etc/openwatch/secrets.env`. The file can carry
   other `OPENWATCH_*` overrides (the credential key path after a DEK rotation,
   a logging level); rewriting the whole file drops them.

   ```bash
   sudo sed -i 's|^OPENWATCH_DATABASE_DSN=.*|OPENWATCH_DATABASE_DSN=postgres://openwatch:new-strong-password@127.0.0.1:5432/openwatch?sslmode=disable|' /etc/openwatch/secrets.env
   sudo chown root:openwatch /etc/openwatch/secrets.env
   sudo chmod 0640 /etc/openwatch/secrets.env
   grep -c '^OPENWATCH_DATABASE_DSN=' /etc/openwatch/secrets.env   # must print 1
   ```

   Use `sslmode=require` or stronger for any PostgreSQL that is not on the
   loopback interface.

3. Validate the resolved config before restarting:

   ```bash
   sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a; openwatch check-config'
   ```

   `check-config` prints the config with the DSN password redacted and exits
   non-zero on a malformed DSN.

4. Restart and verify:

   ```bash
   sudo systemctl restart openwatch
   sudo systemctl status openwatch
   curl -k https://localhost:8443/api/v1/health
   ```

## Rotate the JWT signing key

Impact: every **access token** stops verifying, so API clients holding a bearer
token get 401 and must obtain a new one. That is all the key rotation does.
Browser sessions (the `openwatch_session` cookie), refresh tokens and API
tokens are opaque values hashed into the `sessions`, `refresh_tokens` and
`api_tokens` tables; they are not signed with this key and remain valid after
it changes. Verified on 0.8.0-rc.3: after a key rotation and restart, the old
bearer token returned 401 while the same browser's session cookie and refresh
cookie both still returned 200. To force everyone to sign in again, rotate the
key **and** revoke the rows, as the last step below does.

The key is an RSA private key in PEM form (PKCS#1 or PKCS#8); the service
rejects keys smaller than 2048 bits at startup.

1. Generate the replacement at a new path. `/etc/openwatch/keys` is packaged as
   `root:openwatch 0750`, so the `openwatch` user cannot create files there;
   generate as root and install with the packaged ownership and mode
   (`root:openwatch 0640`, the same as the key the installer laid down):

   ```bash
   NEW_JWT="/etc/openwatch/keys/jwt_private-$(date -u +%Y%m%d).pem"
   sudo sh -c 'umask 077; openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /root/jwt_private.new.pem'
   sudo install -m 0640 -o root -g openwatch /root/jwt_private.new.pem "$NEW_JWT"
   sudo shred -u /root/jwt_private.new.pem
   ```

   The old key stays at its path for rollback until the new one is confirmed.

2. Point the config at the new key. Either set it in `/etc/openwatch/openwatch.toml`:

   ```toml
   [identity]
   jwt_private_key = "/etc/openwatch/keys/jwt_private-<date>.pem"
   ```

   or append one line to `/etc/openwatch/secrets.env` (append; do not rewrite
   the file):

   ```bash
   echo "OPENWATCH_IDENTITY_JWT_PRIVATE_KEY=$NEW_JWT" | sudo tee -a /etc/openwatch/secrets.env >/dev/null
   ```

3. Restart and verify:

   ```bash
   sudo systemctl restart openwatch
   sudo journalctl -u openwatch --since '1 min ago' | grep -i jwt
   curl -k https://localhost:8443/api/v1/health
   ```

   If the key is missing, unparseable, or under 2048 bits, the service logs
   `load jwt key failed` and exits: `journalctl -u openwatch` shows the reason.

4. Confirm a fresh sign-in works, and that a bearer token issued before the
   rotation is rejected (401).

5. Revoke the sessions and refresh tokens the rotation did not touch. This is
   the step that actually signs everyone out; without it, open browser tabs
   keep working. Run as the service user with the service's own environment
  :

   ```bash
   sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a;
     psql "$OPENWATCH_DATABASE_DSN" -c "UPDATE sessions SET revoked_at = now() WHERE revoked_at IS NULL;" \
                                   -c "UPDATE refresh_tokens SET revoked_at = now() WHERE revoked_at IS NULL;"'
   ```

   API tokens (`/api/v1/tokens`) are separate long-lived credentials; revoke
   the ones you intend to through that API. A per-user sign-out exists in the
   product (`RevokeAllSessionsForUser`) for the single-account case.

6. Once sign-in is confirmed on the new key, remove the old key file.

There is no dual-key (old + new) verification on this stack, so there is no
zero-downtime overlap window. Rotate during low usage to limit the number of
forced re-logins.

## Rotate the credential DEK

Impact: high. The DEK is a single 32-byte AES-256 key that directly encrypts
every stored SSH credential and every MFA secret with AES-256-GCM. There is no
per-credential wrapped key, so changing the DEK without re-encrypting every row
makes those secrets permanently unreadable.

> **Not yet implemented.** OpenWatch does not ship a re-encryption or rekey
> command. The CLI subcommands are `setup`, `serve`, `worker`, `migrate`,
> `create-admin`, and `check-config`: none re-wraps stored secrets. Rotating
> the DEK in place therefore requires either
> re-entering the affected secrets by hand or a one-off migration written for
> your deployment. An online rotation command is roadmap work; until it lands,
> treat DEK rotation as a manual, planned operation.

### Option A: re-enter secrets (no custom tooling)

This is the supported path when you have a manageable number of credentials.

**Never overwrite `/etc/openwatch/keys/credential.key` in place.** The
previous version of this procedure did, and told you afterwards to "keep the
old key file": by then it no longer existed, and a database dump cannot bring
it back. Verified on 0.8.0-rc.3: one in-place overwrite made every stored
credential fail with `message authentication failed`, and only an
out-of-band copy of the old key recovered them. Rotation is a new file plus a
config change, so the old key is never touched.

1. Back up the database (`pg_dump`), then take a verified copy of the current
   key to a root-only location and confirm the two are byte-identical:

   ```bash
   sudo install -m 0600 -o root -g root /etc/openwatch/keys/credential.key /root/credential.key.pre-rotation
   sudo sh -c 'sha256sum /etc/openwatch/keys/credential.key /root/credential.key.pre-rotation'
   ```

   Both digests must match. Do not continue until they do. Store that copy in
   your secrets manager as well; it is the only thing that can read the
   secrets you are about to abandon.

2. Generate the new key at a **distinct path**. The DEK file is owned by the
   service user, so generate as root and hand it over with mode `0600` (the
   loader rejects any key readable by group or other):

   ```bash
   NEW_DEK="/etc/openwatch/keys/credential-$(date -u +%Y%m%d).key"
   sudo sh -c "umask 077; openssl rand -out '$NEW_DEK' 32"
   sudo chown openwatch:openwatch "$NEW_DEK"
   sudo chmod 0600 "$NEW_DEK"
   ```

3. Point the service at the new key and restart. Add a line to
   `/etc/openwatch/secrets.env` (or set `[identity].credential_key_file` in
   the TOML):

   ```bash
   echo "OPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE=$NEW_DEK" | sudo tee -a /etc/openwatch/secrets.env >/dev/null
   sudo systemctl restart openwatch
   curl -k https://localhost:8443/api/v1/health
   ```

4. Re-create the SSH credentials and re-enroll MFA through the UI or API;
   secrets created before the swap fail to decrypt under the new key and must
   be replaced. **Administrator MFA first:** if the first admin has MFA
   enrolled, its secret is one of the rows that just became unreadable, so
   re-enroll it before signing out, or have a second administrator ready.

5. Rollback, at any point before you delete the old key: remove the
   `OPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE` line (or restore the TOML value)
   and restart. The old key was never modified, so every original secret
   decrypts again. Verified on 0.8.0-rc.3 in both directions.

6. Only after every secret is re-entered and an SSH-backed action succeeds
   (post-rotation checklist): delete the old key file and the root-only copy,
   and record the rotation in your secrets manager.

### Option B: offline re-encryption (custom)

For a large credential set, write a one-off program that opens the database,
decrypts each ciphertext column with the old DEK, re-encrypts it with the new
DEK, and updates the row, then swaps the key file and restarts. This is
deployment-specific code; there is no in-tree tool for it. Always run it against
a `pg_dump` restore first.

> Loss warning: if you change `credential_key_file` without re-encrypting and
> without keeping the old key, all stored SSH credentials and MFA secrets are
> unrecoverable. Back up before rotating.

## Rotate the TLS certificate

Impact: minimal. The server reads the cert and key on each TLS handshake, so new
connections use the new material immediately; restart to drop existing
keep-alive connections.

```bash
sudo cp /path/to/new-cert.pem /etc/openwatch/tls/cert.pem
sudo cp /path/to/new-key.pem  /etc/openwatch/tls/key.pem
sudo chown root:openwatch      /etc/openwatch/tls/cert.pem
sudo chown openwatch:openwatch /etc/openwatch/tls/key.pem
sudo chmod 0644                /etc/openwatch/tls/cert.pem
sudo chmod 0600                /etc/openwatch/tls/key.pem
sudo systemctl restart openwatch
```

See the "Replace the demo TLS cert" section of the install guide for the same
procedure in install context.

## Suggested rotation schedule

These intervals are guidance for compliance-driven environments, not values
enforced by the software.

| Secret | Suggested interval | Reference |
|--------|--------------------|-----------|
| Database password | 90 days | NIST SP 800-53 IA-5 |
| JWT signing key | 180 days, or on suspected compromise | Organization policy |
| Credential DEK | 365 days, or on suspected compromise | NIST SP 800-57 |
| TLS certificate | Before expiry | CA/Browser Forum (398-day maximum) |

## Post-rotation checklist

- [ ] `/health` reports healthy: `curl -k https://localhost:8443/api/v1/health`.
- [ ] The unit is active: `sudo systemctl status openwatch`.
- [ ] No startup errors: `sudo journalctl -u openwatch --since '5 min ago' -p err`.
- [ ] For a JWT rotation: a fresh sign-in succeeds, an old bearer token is
      rejected, and a browser tab that was open before the rotation is signed
      out (that is the session revocation, not the key).
- [ ] For a DEK rotation: an SSH-backed action (host liveness or a Kensa scan)
      succeeds against a host whose credential you re-entered, and the verified
      copy of the old key is still in your secrets manager until then.
- [ ] The `system.startup` audit event recorded the restart (visible in the
      audit log / `journalctl -u openwatch`).
- [ ] The new secret value is stored in your secrets manager and the rotation
      date and next-due date are recorded.
