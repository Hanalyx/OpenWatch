# Secret rotation procedures

**Last updated:** 2026-06-22 · **Applies to:** OpenWatch v0.3.0 (Go single-binary)

This guide describes how to rotate each secret used by OpenWatch on the current
single-binary stack: one `/usr/bin/openwatch` process that serves the REST API
and embedded UI over HTTPS on port `8443`, backed by PostgreSQL and run under
the `openwatch.service` systemd unit. There is no separate web tier, no
container runtime, and no Redis or message broker.

For install and first-time configuration, see the
[installation guide](INSTALLATION.md); this
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
| JWT signing key (RSA private key) | `[identity].jwt_private_key` file (default `/etc/openwatch/keys/jwt_private.pem`) | Service start | Invalidates all sessions; users re-authenticate |
| Credential DEK (AES-256 key) | `[identity].credential_key_file` file (default `/etc/openwatch/keys/credential.key`) | Service start | Stored SSH credentials and MFA secrets become unreadable unless re-encrypted |
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
   JWT key, so you can recover if re-encryption goes wrong.
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

2. Update the DSN in `/etc/openwatch/secrets.env` (keep the file mode at `0640`,
   owner `root:openwatch`):

   ```bash
   sudo tee /etc/openwatch/secrets.env >/dev/null <<'EOF'
   OPENWATCH_DATABASE_DSN=postgres://openwatch:new-strong-password@127.0.0.1:5432/openwatch?sslmode=disable
   EOF
   sudo chown root:openwatch /etc/openwatch/secrets.env
   sudo chmod 0640 /etc/openwatch/secrets.env
   ```

   Use `sslmode=require` or stronger for any PostgreSQL that is not on the
   loopback interface.

3. Validate the resolved config before restarting:

   ```bash
   sudo -u openwatch env $(cat /etc/openwatch/secrets.env | xargs) \
       openwatch check-config
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

Impact: all active sessions are invalidated and users must sign in again. The
key is an RSA private key in PEM form (PKCS#1 or PKCS#8), and the service rejects
keys smaller than 2048 bits at startup. Access tokens have a 30-minute lifetime,
but rotating the key invalidates the refresh tokens too, so plan for a full
re-login.

1. Generate a new 2048-bit (or larger) RSA key as the `openwatch` user, mode
   `0600`:

   ```bash
   sudo install -d -m 0750 -o root -g openwatch /etc/openwatch/keys
   sudo -u openwatch openssl genpkey -algorithm RSA \
       -pkeyopt rsa_keygen_bits:2048 \
       -out /etc/openwatch/keys/jwt_private.pem
   sudo chmod 0600 /etc/openwatch/keys/jwt_private.pem
   ```

   Write to a new path and update `[identity].jwt_private_key` if you prefer to
   keep the old key around for rollback.

2. Point the config at the key. Either set it in `/etc/openwatch/openwatch.toml`:

   ```toml
   [identity]
   jwt_private_key = "/etc/openwatch/keys/jwt_private.pem"
   ```

   or set `OPENWATCH_IDENTITY_JWT_PRIVATE_KEY` in `/etc/openwatch/secrets.env`.

3. Restart and verify:

   ```bash
   sudo systemctl restart openwatch
   sudo journalctl -u openwatch --since '1 min ago' | grep -i jwt
   curl -k https://localhost:8443/api/v1/health
   ```

   If the key is missing, unparseable, or under 2048 bits, the service logs
   `load jwt key failed` and exits—`journalctl -u openwatch` shows the reason.

4. Confirm users can sign in. Existing tokens are no longer accepted.

There is no dual-key (old + new) verification on this stack, so there is no
zero-downtime overlap window. Rotate during low usage to limit the number of
forced re-logins.

## Rotate the credential DEK

Impact: high. The DEK is a single 32-byte AES-256 key that directly encrypts
every stored SSH credential and every MFA secret with AES-256-GCM. There is no
per-credential wrapped key, so changing the DEK without re-encrypting every row
makes those secrets permanently unreadable.

> **Not yet implemented.** OpenWatch does not ship a re-encryption or rekey
> command. The CLI subcommands are `serve`, `worker`, `migrate`,
> `create-admin`, and `check-config`—none re-wraps stored secrets. Rotating
> the DEK in place therefore requires either
> re-entering the affected secrets by hand or a one-off migration written for
> your deployment. An online rotation command is roadmap work; until it lands,
> treat DEK rotation as a manual, planned operation.

### Option A—re-enter secrets (no custom tooling)

This is the supported path when you have a manageable number of credentials.

1. Back up the database (`pg_dump`) so you can roll back to the old DEK.
2. Generate a new 32-byte key, mode `0600` (the loader rejects any file readable
   by group or other):

   ```bash
   sudo -u openwatch sh -c 'umask 077; head -c 32 /dev/urandom > /etc/openwatch/keys/credential.key'
   sudo chmod 0600 /etc/openwatch/keys/credential.key
   ```

3. Point `[identity].credential_key_file` (or
   `OPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE`) at the new key and restart:

   ```bash
   sudo systemctl restart openwatch
   ```

4. Re-create the SSH credentials and re-enroll MFA through the UI or API
   (`/api/v1/...`); secrets created before the swap will fail to decrypt and must
   be replaced. Keep the old key file until you have confirmed every secret is
   re-entered, in case you need to roll back.

### Option B—offline re-encryption (custom)

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
- [ ] For a JWT rotation: a fresh sign-in succeeds and old tokens are rejected.
- [ ] For a DEK rotation: an SSH-backed action (host liveness or a Kensa scan)
      succeeds against a host whose credential you re-entered.
- [ ] The `system.startup` audit event recorded the restart (visible in the
      audit log / `journalctl -u openwatch`).
- [ ] The new secret value is stored in your secrets manager and the rotation
      date and next-due date are recorded.
