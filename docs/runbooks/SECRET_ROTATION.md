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
| Credential DEK (AES-256 key) | `[identity].credential_key_file` file (default `/etc/openwatch/keys/credential.key`) | Service start | Every stored SSH credential, MFA secret, notification channel config and SSO client secret is readable only under the key that encrypted it. The job-queue signing key is derived from it, so queued scan and remediation jobs fail after a change. Never overwrite the file in place |
| TLS certificate and key | `[server].tls_cert` / `[server].tls_key` (default `/etc/openwatch/tls/{cert,key}.pem`) | Read on each TLS handshake | New connections pick up the new cert; restart to drop keep-alives |

> The server refuses to start if either the credential DEK or the JWT key path
> is empty or the file fails to load.

There is no separate "master key" or second "encryption key" on this stack. The
single credential DEK encrypts every at-rest secret with AES-256-GCM:

- SSH credentials.
- MFA (TOTP) secrets.
- Notification channel configs: Slack and webhook URLs, and email settings
  including the SMTP password.
- SSO provider client secrets.

The service also derives the HMAC key that signs scan and remediation jobs on
the job queue from the DEK (HKDF-SHA256). The previous Python build's
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

Use the procedure in
[Rotate the database credential](SECURITY_INCIDENT.md#rotate-the-database-credential).
It is the same whether or not the password was exposed. It changes only the
password: it sets it on the role through the current DSN, proves the new
password connects, and only then rewrites the password inside the DSN in
`/etc/openwatch/secrets.env`. It keeps the host, port, database, `sslmode`, the
file's other lines, its mode and its owner. Neither password appears on a
command line.

Do not retype the whole DSN or rewrite it with `sed`. `openwatch setup` writes
a loopback DSN with `sslmode=disable`, and a PostgreSQL with SSL off refuses
`sslmode=require`, so a retyped DSN can break a working install.

Impact: a brief restart while the service reconnects. Recover by setting the
previous password back on the role and restoring the previous DSN line, then
restarting.

## Rotate the JWT signing key

> **Before you start**
> - **You need:** a maintenance window and a healthy service; a database backup if you will also revoke sessions.
> - **Run as:** root for the key file (packaging creates `/etc/openwatch/keys` `root:openwatch 0750`) and the restart; `psql` as the `openwatch` role for the revocation.
> - **What changes:** the RSA key file; every access token stops verifying. Sessions and refresh tokens survive unless you run the revocation step.
> - **Verify with:** an old bearer token answering `401` and a fresh login answering `200`.
> - **Recover by:** restoring the previous key file from your secrets manager and restarting; tokens issued under the new key then stop verifying instead.

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

3. Restart and verify with the first block in
   [Prove the restored service works](BACKUP_RECOVERY.md#prove-the-restored-service-works). It restarts the
   service itself. A health check alone does not prove the service works.
   Then check the key load:

   ```bash
   sudo journalctl -u openwatch --since '5 min ago' | grep -i jwt
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

> **Before you start**
> - **You need:** a verified copy of the current DEK at a distinct protected path, a database backup, the list of every SSH credential, MFA enrollment, notification channel and SSO provider whose secret you will re-enter, an empty job queue, and a maintenance window.
> - **Run as:** root for the key files, config and restart; for the re-entry, a user with `credential:write`, `notification:write` and `admin:sso_provider`.
> - **What changes:** the key path in `openwatch.toml`, then every stored secret as you re-enter it.
> - **Verify with:** a scan succeeding on a host whose credential was re-entered, MFA login for a re-enrolled user, a test message on each notification channel, and a sign-in through each SSO provider.
> - **Recover by:** switching the config back to the backed-up key path and restarting; the copy you verified first is what makes this possible.

Impact: high. The DEK is a single 32-byte AES-256 key that directly encrypts
every secret listed in [Secrets at a glance](#secrets-at-a-glance) with
AES-256-GCM. There is no per-secret wrapped key, so every secret stored before
the change stays readable only under the old key. Until you re-enter them:

- Scans and other SSH-backed actions fail for every host that uses an old
  credential.
- Users with MFA enrolled cannot complete the MFA step.
- Notification delivery stops for **every** channel, not only the unreadable
  ones: the dispatcher loads all enabled channels at once and gives up when
  one fails to decrypt. Re-enter or disable every enabled channel.
- Sign-in through an SSO provider with an old client secret fails.
- Every scan or remediation job queued before the change fails when a worker
  claims it, because its signature no longer matches. See step 1.

> **What this procedure is.** It replaces the DEK and requires you to
> re-enter, by hand, every secret the old key protected. It does not carry any
> secret forward. Rolling back is clean only until you re-enter the first
> secret (step 6).
>
> **Not supported: re-encryption.** OpenWatch has no re-encryption, rekey or
> rotation command. None of the [CLI subcommands](../guides/ENVIRONMENT_REFERENCE.md#cli-subcommands)
> re-wraps stored secrets, and the ciphertext format is not a documented
> interface. Rotating the DEK therefore means re-entering every secret it
> protects by hand. Treat it as a planned operation sized by that list.

**Never overwrite `/etc/openwatch/keys/credential.key` in place.** The
previous version of this procedure did, and told you afterwards to "keep the
old key file": by then it no longer existed, and a database dump cannot bring
it back. Verified on 0.8.0-rc.3: one in-place overwrite made every stored
credential fail with `message authentication failed`, and only an
out-of-band copy of the old key recovered them. Rotation is a new file plus a
config change, so the old key is never touched.

1. Let the job queue drain. A scan or remediation job carries an HMAC made
   with the key derived from the DEK, and the worker checks it before doing
   anything. After the change, every job queued under the old key fails: the
   row in `job_queue` ends `failed` with `last_error` set to
   `hmac_rejected: signature does not match payload`, a
   `scheduler.job.hmac_rejected` audit event records `"failure":
   "hmac_mismatch"`, and a scan's `scan_runs` row ends `failed` with
   `failure_reason` `hmac_rejected`. Nothing retries a rejected job; request
   any on-demand scan or remediation again after the rotation.

   Pause the adaptive scan scheduler. This needs `system:config_write`. The
   `GET` wraps the settings in `config`, and the `PUT` takes them unwrapped
   with every field present:

   ```bash
   curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:8443/api/v1/system/scan/config \
     | jq '.config | .maintenance_global = true' \
     | curl -sk -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
         --data-binary @- https://localhost:8443/api/v1/system/scan/config
   ```

   Start no on-demand scans or remediations. Then wait until this reports
   `(0 rows)`:

   ```bash
   sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a; psql "$OPENWATCH_DATABASE_DSN" -X' <<'SQL'
   SELECT job_type, status, count(*)
   FROM job_queue
   WHERE status IN ('pending', 'processing')
     AND job_type IN ('scan', 'remediation')
   GROUP BY 1, 2;
   SQL
   ```

   If you run a separate `openwatch worker` process, it derives its own key
   from its own DEK setting. Point it at the new key and restart it together
   with the service, or it rejects every job the service signs.

2. Back up the database (`pg_dump`), then take a verified copy of the current
   key to a root-only location and confirm the two are byte-identical:

   ```bash
   sudo install -m 0600 -o root -g root /etc/openwatch/keys/credential.key /root/credential.key.pre-rotation
   sudo sh -c 'sha256sum /etc/openwatch/keys/credential.key /root/credential.key.pre-rotation'
   ```

   Both digests must match. Do not continue until they do. Store that copy in
   your secrets manager as well; it is the only thing that can read the
   secrets you are about to abandon.

3. Generate the new key at a **distinct path**. The DEK file is owned by the
   service user, so generate as root and hand it over with mode `0600` (the
   loader rejects any key readable by group or other):

   ```bash
   NEW_DEK="/etc/openwatch/keys/credential-$(date -u +%Y%m%d).key"
   sudo sh -c "umask 077; openssl rand -out '$NEW_DEK' 32"
   sudo chown openwatch:openwatch "$NEW_DEK"
   sudo chmod 0600 "$NEW_DEK"
   ```

4. Point the service at the new key and restart. Add a line to
   `/etc/openwatch/secrets.env` (or set `[identity].credential_key_file` in
   the TOML):

   ```bash
   echo "OPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE=$NEW_DEK" | sudo tee -a /etc/openwatch/secrets.env >/dev/null
   ```

   Then restart and verify with the first block in
   [Prove the restored service works](BACKUP_RECOVERY.md#prove-the-restored-service-works). It restarts the
   service itself. A health check alone does not prove the service works.

5. Re-enter every secret through the UI or API; secrets created before the
   swap fail to decrypt under the new key and must be replaced.
   **Administrator MFA first:** if the first admin has MFA enrolled, its
   secret is one of the rows that just became unreadable, so re-enroll it
   before signing out, or have a second administrator ready.

   - SSH credentials: re-create them (`/api/v1/credentials`).
   - MFA: each enrolled user re-enrolls from a session that was open before
     the restart (`POST /api/v1/auth/mfa:enroll`, then `mfa:verify`).
     Sessions survive the restart. A user with no open session cannot pass
     the MFA step and so cannot re-enroll; OpenWatch has no administrator
     MFA reset.
   - Notification channels: edit each channel and re-enter its whole config
     (`PATCH /api/v1/notifications/channels/{id}`). For an email channel,
     type the SMTP password again; the edit cannot carry over a password it
     cannot decrypt.
   - SSO providers: enter each client secret again
     (`PUT /api/v1/sso/providers/{id}`). Then sign in through each provider.
     A provider whose secret cannot be decrypted sends the browser to
     `/login?sso_error=provider`, the same answer as an unreachable identity
     provider, and the audit event does not say which. Treat that answer after
     the rotation as a secret you have not re-entered yet.

   Then unpause the scan scheduler with the same command, setting
   `.maintenance_global = false`.

6. Rollback is clean only **before you re-enter the first secret**. Remove
   the `OPENWATCH_IDENTITY_CREDENTIAL_KEY_FILE` line (or restore the TOML
   value) and restart. The old key was never modified, so every original
   secret decrypts again. Every secret you re-entered in step 5 was encrypted
   under the new key, so after a rollback it becomes unreadable and must be
   entered again. Once you start step 5, finish it rather than roll back.

7. Only after every secret is re-entered and an SSH-backed action succeeds
   (post-rotation checklist): delete the old key file and the root-only copy,
   and record the rotation in your secrets manager.

**What was tested.** On 2026-10-05 this procedure ran against a disposable
OpenWatch instance, built from the 0.8.2 code, with a webhook channel, an SSO
provider and a scan job queued under the old key:

- **After the key change, before re-entry:**
  - the queued job failed with `hmac_rejected: signature does not match
    payload`;
  - the channel's test failed to decrypt its config;
  - the stored SSO secret decrypted only under the old key.
- **After re-entry:** both secrets decrypted only under the new key, the
  channel's test reached delivery, and a job queued under the new key passed
  the signature check.
- **Rollback:** before re-entry, every secret decrypted again. After re-entry,
  the re-entered secrets did not.

MFA, SSH credentials and whole-dispatch notification delivery were not part
of that run; their behavior here is taken from the code.

> Loss warning: if you change `credential_key_file` without keeping the old
> key, every secret it protected is unrecoverable: SSH credentials, MFA
> secrets, notification channel configs and SSO client secrets. Back up before
> rotating.

## Rotate the TLS certificate

> **Before you start**
> - **You need:** the new certificate and key files.
> - **Run as:** root.
> - **What changes:** `/etc/openwatch/tls/cert.pem` and `key.pem`; existing keep-alive connections drop on restart.
> - **Verify with:** `openssl s_client -connect localhost:8443` showing the new certificate's dates.
> - **Recover by:** putting the previous files back and restarting.

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
- [ ] For a DEK rotation: each notification channel delivers a test message
      (`POST /api/v1/notifications/channels/{id}:test`), and a sign-in through
      each SSO provider succeeds.
- [ ] For a DEK rotation: no `scheduler.job.hmac_rejected` audit event since
      the restart, and the scan scheduler is unpaused.
- [ ] The `system.startup` audit event recorded the restart (visible in the
      audit log / `journalctl -u openwatch`).
- [ ] The new secret value is stored in your secrets manager and the rotation
      date and next-due date are recorded.
