# Runbook: security incident response

**Severity**: P0 - Critical
**Last updated**: 2026-06-26
**Owner**: Security Engineering
**Estimated resolution time**: Hours to days depending on scope

OpenWatch runs as a single Go binary (`/usr/bin/openwatch`) managed by `systemd` (`openwatch.service`). It serves the REST API and the embedded UI over HTTPS on port `8443` and stores all data in PostgreSQL (there is no MongoDB, Redis, Celery, or container runtime). Audit events are written to the `audit_events` table; the service logs to the journal (`journalctl -u openwatch`). Adjust `psql` connection flags (`-h`, `-p`) for your deployment.

This runbook covers containment, investigation, and recovery for a suspected compromise. For install, config, and role definitions see the [installation guide](../guides/INSTALLATION.md) and [User roles](../guides/USER_ROLES.md).

---

## Symptoms

- Spike in failed-login audit events (`auth.login.failure`).
- Successful logins for accounts that should be inactive (`auth.login.success`).
- Permission-denied events on privileged endpoints (`authz.permission.denied`).
- Unexpected OpenWatch role grants (`authz.role.assigned`, `authz.role.created`) or account changes (`admin.user.created`, `admin.user.deleted`, `admin.user.enabled`, `admin.user.password_reset`).
- API tokens issued or revoked that nobody expected (`auth.api_token.issued`, `auth.api_token.revoked`).
- Operating-system accounts added or removed on a monitored host (`account.user.created`, `account.user.deleted`). These describe the host, not OpenWatch users.
- Threshold detections raised by the intelligence collector: `security.login.failed_threshold`, `security.login.new_source_ip`, `account.sudo.failure_threshold`.
- Credential changes (`credential.created`, `credential.deleted`) you did not authorize.
- Config-file tampering reported on a monitored host (`system.config.file_changed`).
- Compromised credentials reported by a user or external source.

The `security.*` and `account.*` threshold events above are produced by the OS intelligence collector for monitored hosts, not by the OpenWatch control plane itself. Verify the actor and host before acting on them.

---

## Immediate actions (first 15 minutes)

> **Before you start**
> - **You need:** shell access to the OpenWatch host and `psql` access to its database; a place outside the host to copy evidence to.
> - **Run as:** a sudo-capable administrator for the host; `psql` as the `openwatch` role using the DSN from `/etc/openwatch/secrets.env` (the `psql -U openwatch -d openwatch` form below assumes local peer or password access to that role).
> - **What changes:** nothing on the host in Steps 1 to 3; Step 4 isolates the host only if compromise is confirmed.
> - **Verify with:** the evidence copies exist off-host with recorded hashes before anything is changed.
> - **Recover by:** nothing to recover in the first 15 minutes; [Recovery](#recovery) comes after containment.

Contain the threat and preserve evidence. Do not restart the service yet; an in-progress restart can rotate the journal and end the current session you are inspecting.

### Step 1: Confirm the incident

Determine whether this is a true incident or a false positive. Review recent security-relevant audit events:

```bash
psql -U openwatch -d openwatch -c "
SELECT occurred_at, action, outcome, actor_label, actor_ip, resource_type, resource_id
FROM audit_events
WHERE action IN (
  'auth.login.failure','auth.login.success','authz.permission.denied',
  'authz.role.assigned','authz.role.removed','authz.role.created',
  'admin.user.created','admin.user.deleted','admin.user.disabled',
  'admin.user.enabled','admin.user.password_reset',
  'auth.api_token.issued','auth.api_token.revoked',
  'credential.created','credential.deleted'
)
  AND occurred_at > now() - interval '24 hours'
ORDER BY occurred_at DESC
LIMIT 100;
"
```

Look for repeated `auth.login.failure` from one `actor_ip`, `auth.login.success` for accounts that should not be active, and `authz.role.assigned` granting elevated roles.

### Step 2: Record the timeline

Note immediately: when the anomaly was first detected, who or what detected it (an audit query, a user report, a `security.*` collector event), and which specific events triggered the investigation. Capture wall-clock times in ISO 8601 (UTC).

### Step 3: Preserve evidence

Do not restart the service. Capture state to a working directory first:

```bash
INCIDENT_DIR="/var/tmp/incident-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$INCIDENT_DIR"

# Service journal (full history this boot)
journalctl -u openwatch --no-pager > "$INCIDENT_DIR/openwatch.journal.log"

# Service state and recent restarts
systemctl status openwatch --no-pager > "$INCIDENT_DIR/service-status.txt"

# Durable audit trail (last 7 days), as CSV
psql -U openwatch -d openwatch -c "\copy (
  SELECT occurred_at, action, outcome, severity,
         actor_type, actor_id, actor_label, actor_ip,
         actor_session_id, resource_type, resource_id, correlation_id, detail
  FROM audit_events
  WHERE occurred_at > now() - interval '7 days'
  ORDER BY occurred_at
) TO STDOUT WITH CSV HEADER" > "$INCIDENT_DIR/audit_events.csv"

# Current listening sockets on the application host
ss -tunapl > "$INCIDENT_DIR/sockets.txt" 2>/dev/null
```

The `correlation_id` ties together every event from a single request chain. Once you find one malicious event, pivot on its `correlation_id` to reconstruct the full request.

### Step 4: Isolate (only if active compromise is confirmed)

If data exfiltration or active intrusion is in progress, block the source at the host firewall rather than stopping the service (stopping it destroys evidence and denies you the audit trail):

```bash
# Block a confirmed attacker IP (replace ATTACKER_IP)
sudo iptables -I INPUT -s ATTACKER_IP -j DROP
```

Stop the service only as a last resort, after evidence is captured:

```bash
sudo systemctl stop openwatch
```

---

## Investigation

All durable evidence lives in PostgreSQL. The queries below assume the `openwatch` database.

### Authentication activity

```bash
# Failed logins by source IP in the last 24 hours
psql -U openwatch -d openwatch -c "
SELECT actor_ip, count(*) AS failures, max(occurred_at) AS last_seen
FROM audit_events
WHERE action = 'auth.login.failure'
  AND occurred_at > now() - interval '24 hours'
GROUP BY actor_ip
ORDER BY failures DESC
LIMIT 20;
"

# Successful logins (look for unexpected accounts or IPs)
psql -U openwatch -d openwatch -c "
SELECT occurred_at, actor_label, actor_ip, actor_session_id
FROM audit_events
WHERE action = 'auth.login.success'
  AND occurred_at > now() - interval '24 hours'
ORDER BY occurred_at DESC
LIMIT 50;
"
```

### Authorization and account changes

These are OpenWatch's own accounts, roles and API tokens. `resource_id` is
the user id, the role id or the API token id.

```bash
psql -U openwatch -d openwatch -c "
SELECT occurred_at, action, outcome, actor_label, actor_ip, resource_type, resource_id, detail
FROM audit_events
WHERE action IN (
  'authz.permission.denied','authz.role.assigned','authz.role.removed','authz.role.created',
  'admin.user.created','admin.user.deleted','admin.user.disabled',
  'admin.user.enabled','admin.user.password_reset',
  'auth.api_token.issued','auth.api_token.revoked'
)
  AND occurred_at > now() - interval '7 days'
ORDER BY occurred_at DESC
LIMIT 50;
"
```

Two ways to create an account write no `admin.user.created` or
`authz.role.assigned` event: `openwatch create-admin` on the host, and the
first SSO sign-in of a federated user. Compare the account list below against
these events, and treat an account with no matching event as unexplained until
you find its source.

`account.user.created` and `account.user.deleted` are different events. The
host intelligence collector records them when an operating-system account
appears or disappears on a monitored host, with `resource_type = 'host'`.
Query them separately when you suspect a monitored host:

```bash
psql -U openwatch -d openwatch -c "
SELECT occurred_at, action, resource_id AS host_id, detail
FROM audit_events
WHERE action IN ('account.user.created','account.user.deleted')
  AND occurred_at > now() - interval '7 days'
ORDER BY occurred_at DESC
LIMIT 50;
"
```

### Current user accounts and role grants

The `users` table has no `is_active` flag. A disabled account has `disabled_at` set and can be enabled again; a deleted account has `deleted_at` set. Roles live in `user_roles`, not on the user row.

```bash
# Recently created or modified accounts
psql -U openwatch -d openwatch -c "
SELECT id, username, email, created_at, updated_at, disabled_at, deleted_at
FROM users
ORDER BY created_at DESC
LIMIT 20;
"

# Who holds an elevated built-in role or any custom role right now
psql -U openwatch -d openwatch -c "
SELECT u.username, ur.role_id, r.is_built_in, r.permissions,
       ur.granted_at, ur.granted_by, u.disabled_at
FROM user_roles ur
JOIN users u ON u.id = ur.user_id
JOIN roles r ON r.id = ur.role_id
WHERE (ur.role_id IN ('admin','security_admin','ops_lead') OR NOT r.is_built_in)
  AND u.deleted_at IS NULL
ORDER BY ur.granted_at DESC;
"
```

The five built-in roles, in increasing privilege, are `viewer`, `auditor`, `ops_lead`, `security_admin`, and `admin`. See [User roles](../guides/USER_ROLES.md) for the full permission sets. A custom role (`is_built_in` false) carries its grants in `roles.permissions`; built-in roles leave that column empty because their grants are in the binary. The query lists every custom-role holder, so read each custom role's `permissions` to judge whether it is elevated.

### Active sessions and refresh tokens

```bash
# Live (unrevoked, unexpired) sessions
psql -U openwatch -d openwatch -c "
SELECT s.id, u.username, s.remote_addr, s.user_agent, s.created_at, s.expires_at
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.revoked_at IS NULL
  AND s.expires_at > now()
ORDER BY s.created_at DESC
LIMIT 50;
"

# Refresh-token reuse detection (a hallmark of token theft)
psql -U openwatch -d openwatch -c "
SELECT rt.id, u.username, rt.created_at, rt.reuse_detected_at
FROM refresh_tokens rt
JOIN users u ON u.id = rt.user_id
WHERE rt.reuse_detected_at IS NOT NULL
ORDER BY rt.reuse_detected_at DESC
LIMIT 20;
"
```

A non-null `reuse_detected_at` means a refresh token was presented after it had already been rotated: treat the owning account as compromised.

### Credential access

```bash
psql -U openwatch -d openwatch -c "
SELECT occurred_at, action, actor_label, actor_ip, resource_id, detail
FROM audit_events
WHERE action IN ('credential.created','credential.deleted')
  AND occurred_at > now() - interval '7 days'
ORDER BY occurred_at DESC
LIMIT 30;
"
```

Stored SSH credentials are encrypted at rest with the credential DEK (`[identity].credential_key_file`). The API never returns secret material, so audit events record only metadata.

---

## Containment

### Revoke sessions for a compromised account

Revoke at the database level so the change takes effect immediately, regardless of which node served the session:

```bash
# Revoke all live sessions for one user (replace USERNAME)
psql -U openwatch -d openwatch -c "
UPDATE sessions
SET revoked_at = now()
WHERE revoked_at IS NULL
  AND user_id = (SELECT id FROM users WHERE username = 'USERNAME' AND deleted_at IS NULL);
"

# Revoke that user's refresh tokens as well
psql -U openwatch -d openwatch -c "
UPDATE refresh_tokens
SET revoked_at = now()
WHERE revoked_at IS NULL
  AND user_id = (SELECT id FROM users WHERE username = 'USERNAME' AND deleted_at IS NULL);
"
```

### Disable a compromised account

Disable the account through the API. Disabling ends every interactive credential the user holds (sessions, refresh tokens and access tokens), is audited as `admin.user.disabled`, and can be reversed with `:enable`:

```bash
# Authenticated as an admin; replace TOKEN and USER_ID
curl -sk -X POST \
  -H "Authorization: Bearer TOKEN" \
  https://localhost:8443/api/v1/users/USER_ID:disable
```

Deleting the account (`DELETE /api/v1/users/USER_ID`, audited as `admin.user.deleted`) also ends its interactive credentials, but it removes the account from the active-uniqueness indexes and cannot be undone through the API. Prefer disable while the investigation is open.

If the API is unavailable, disable directly. Sign-in, the session and bearer binders, refresh tokens and the API tokens the user created all refuse a disabled account on every request. This path revokes no rows and writes no audit event, so revoke the user's sessions as above and record what you did. `POST /api/v1/users/USER_ID:enable` reverses it once the API is back:

```bash
psql -U openwatch -d openwatch -c "
UPDATE users SET disabled_at = now(), updated_at = now()
WHERE username = 'USERNAME' AND deleted_at IS NULL AND disabled_at IS NULL;
"
```

### Revoke every session (full re-authentication)

Four kinds of credential keep a user signed in. An access token names the
session that issued it, so revoking the session ends both.

| Credential | Where it lives | Ended by |
|---|---|---|
| Access token (bearer JWT, 30 minutes) | Signed with `jwt_private.pem`, not stored; carries its session id | Revoking its session row |
| Browser session (`openwatch_session` cookie) | `sessions` table, hashed | Setting `revoked_at` on the row |
| Refresh token (cookie or body) | `refresh_tokens` table, hashed | Setting `revoked_at` on the row |
| API token (`/api/v1/tokens`) | `api_tokens` table, hashed | Deleting it through `/api/v1/tokens/{id}`. Disabling or deleting the user who created it also stops it, until that user is re-enabled |

Rotating the signing key does not end a browser session or a refresh token.
An open tab stays signed in until its row is revoked.

To sign everyone out now, revoke the rows. This takes effect at once, on every
node, with no restart, and it ends the access tokens those sessions issued.
Rotate the signing key as well only if the key itself may be exposed: anyone
holding it can sign a token that names a live session and claims any role.

```bash
# 1. Sessions, their refresh tokens and their access tokens: immediate,
#    fleet-wide, no restart.
sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a;
  psql "$OPENWATCH_DATABASE_DSN" \
    -c "UPDATE sessions SET revoked_at = now() WHERE revoked_at IS NULL;" \
    -c "UPDATE refresh_tokens SET revoked_at = now() WHERE revoked_at IS NULL;"'

# 2. Only if the signing key may be exposed: rotate it at a NEW path (never
#    overwrite the old one, so you can roll back), point the service at it,
#    restart.
NEW_JWT="/etc/openwatch/keys/jwt_private-$(date -u +%Y%m%d)-incident.pem"
sudo sh -c 'umask 077; openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /root/jwt_private.new.pem'
sudo install -m 0640 -o root -g openwatch /root/jwt_private.new.pem "$NEW_JWT"
sudo shred -u /root/jwt_private.new.pem
echo "OPENWATCH_IDENTITY_JWT_PRIVATE_KEY=$NEW_JWT" | sudo tee -a /etc/openwatch/secrets.env >/dev/null
sudo systemctl restart openwatch
```

API tokens are not touched by either step; list and delete the ones that may
be exposed through `/api/v1/tokens`. The full procedure, with rollback, is in
the [secret rotation runbook](SECRET_ROTATION.md#rotate-the-jwt-signing-key).

Confirm the configured path before generating a new key: `openwatch check-config` prints the resolved configuration with secrets redacted. Load `secrets.env` first, because the key path can be set there:

```bash
sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a;
  /usr/bin/openwatch --config /etc/openwatch/openwatch.toml check-config'
```

> Do not rotate the credential DEK (`[identity].credential_key_file`) during an incident unless you have a re-entry plan. Changing that key makes every stored SSH credential, MFA secret, notification channel config and SSO client secret unreadable, and fails every scan or remediation job already queued. See [Rotate the credential DEK](SECRET_ROTATION.md#rotate-the-credential-dek).

### Rotate the database credential

If the database password may be exposed, change only the password. The
host, port, database name and `sslmode` in the existing DSN stay as they are.
`openwatch setup` writes a loopback DSN with `sslmode=disable`, and a
PostgreSQL with SSL off refuses `sslmode=require`, so retyping the whole DSN
can break a working install.

1. Put the new password in a root-only file, so it never appears on a command
   line or in shell history:

   ```bash
   sudo sh -c 'umask 077; cat > /root/openwatch-db.password'
   ```

   Type the password, press Enter, then Ctrl-D. The script below ignores the
   line break at the end.

2. Set the password on the role, prove it, and write it into the DSN. Run
   this as root. It connects as the role itself through the current DSN, so it
   works for a local or a remote PostgreSQL and needs no superuser. Neither
   password ever appears on a command line: `psql` gets the DSN without its
   password, and the password through `PGPASSWORD`. It sets the new password,
   then connects with it, and only then rewrites `secrets.env`. It
   percent-encodes the password inside the URL, and it keeps the file's other
   lines, its mode and its owner. It hashes the password as `scram-sha-256`, as
   `openwatch setup` does, whatever the server default.

   ```bash
   sudo python3 - <<'PY'
   import os, subprocess, sys, tempfile, urllib.parse

   ENV = "/etc/openwatch/secrets.env"
   KEY = "OPENWATCH_DATABASE_DSN="
   with open("/root/openwatch-db.password") as f:
       pw = f.read().rstrip("\r\n")
   if not pw:
       sys.exit("the password file is empty")
   with open(ENV) as f:
       lines = f.read().splitlines(keepends=True)
   hits = [i for i, line in enumerate(lines) if line.startswith(KEY)]
   if len(hits) != 1:
       sys.exit(f"expected one {KEY} line in {ENV}, found {len(hits)}")
   i = hits[0]
   old = lines[i][len(KEY):].rstrip("\r\n")
   dsn = urllib.parse.urlsplit(old)
   userinfo, at, hostport = dsn.netloc.rpartition("@")
   if dsn.scheme not in ("postgres", "postgresql") or not at or not userinfo:
       sys.exit("the DSN is not a postgres:// URL with a user name; edit it by hand")
   user, colon, old_quoted = userinfo.partition(":")
   if not colon or not old_quoted:
       sys.exit("the DSN holds no password; this procedure rotates the password in the DSN")
   old_pw = urllib.parse.unquote(old_quoted)
   bare = urllib.parse.urlunsplit(dsn._replace(netloc=f"{user}@{hostport}"))
   new = urllib.parse.urlunsplit(
       dsn._replace(netloc=f"{user}:{urllib.parse.quote(pw, safe='')}@{hostport}"))

   def psql(password, sql):
       # The DSN on the command line carries no password; PGPASSWORD does.
       return subprocess.run(["psql", "-X", "-q", "-tA", "-v", "ON_ERROR_STOP=1", bare],
                             input=sql, text=True, capture_output=True,
                             env=dict(os.environ, PGPASSWORD=password))

   # 1. Set the new password, connected as the role itself with the old one.
   literal = "'" + pw.replace("'", "''") + "'"
   r = psql(old_pw, "SET password_encryption = 'scram-sha-256';\n"
                    f"ALTER ROLE CURRENT_USER WITH PASSWORD {literal};\n")
   if r.returncode != 0:
       sys.exit("ALTER ROLE failed; secrets.env is unchanged\n" + r.stderr)

   # 2. Prove the new password connects before touching secrets.env.
   r = psql(pw, "SELECT current_user;\n")
   if r.returncode != 0:
       sys.exit("ALTER ROLE succeeded, but the new password did not connect. The role now has the "
                "NEW password and secrets.env still holds the OLD one. Do not restart; fix "
                "pg_hba.conf or set the DSN by hand first.\n" + r.stderr)

   # 3. Replace only the password in the DSN line. Keep mode and owner.
   lines[i] = KEY + new + "\n"
   st = os.stat(ENV)
   fd, tmp = tempfile.mkstemp(dir=os.path.dirname(ENV))
   with os.fdopen(fd, "w") as f:
       f.writelines(lines)
   os.chown(tmp, st.st_uid, st.st_gid)
   os.chmod(tmp, st.st_mode & 0o7777)
   os.replace(tmp, ENV)
   print(f"password changed and proven for {r.stdout.strip()}; user, host, port, database and options kept")
   PY
   ```

   The service accepts only a `postgres://` or `postgresql://` URL DSN
   (`check-config` enforces it), and that is the form the script edits. If
   PostgreSQL logs DDL (`log_statement` set to `ddl` or `all`), its log now
   holds the new password in clear text.

3. Check the config before restarting:

   ```bash
   sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a; openwatch --config /etc/openwatch/openwatch.toml check-config'
   ```

   `check-config` validates the DSN's form but does not connect. The script
   already proved the new password connects.

4. Restart, check health, and remove the password file once the password is
   in your secrets manager:

   ```bash
   sudo systemctl restart openwatch
   timeout 60 sh -c 'until curl -skf --max-time 5 https://localhost:8443/api/v1/health; do sleep 2; done' \
     && echo || echo "health did not answer within 60 seconds; read journalctl -u openwatch"
   sudo shred -u /root/openwatch-db.password
   ```

   Expect `"db_connected":true`. A restart takes a few seconds, so the
   check retries for up to 60 seconds. Then work through
   [Recovery verification](#recovery-verification).

`secrets.env` should be owned `root:openwatch` and mode `0640`. See the [installation guide](../guides/INSTALLATION.md) for the canonical secret-handling procedure.

### Block attacker IP addresses

```bash
sudo iptables -I INPUT -s ATTACKER_IP -j DROP
```

---

## Recovery

### Restore from backup (if data was modified)

If the attacker modified data, restore PostgreSQL from a known-good backup. The procedure depends on how your database is backed up (`pg_dump`/`pg_restore` or physical/PITR). For a `pg_dump` backup, follow the [restore procedure](BACKUP_RECOVERY.md#restore-procedure). Otherwise follow your backup tooling's restore steps, then re-run migrations to confirm the schema is current:

```bash
sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a;
  /usr/bin/openwatch --config /etc/openwatch/openwatch.toml migrate'
```

> A backup/restore tool is not part of the OpenWatch binary today; database backup is an operator responsibility. This is tracked as roadmap, not an implemented feature.

### Re-verify configuration

```bash
# Validate the resolved config (secrets redacted, listen address, TLS paths)
sudo -u openwatch sh -c 'set -a; . /etc/openwatch/secrets.env; set +a;
  /usr/bin/openwatch --config /etc/openwatch/openwatch.toml check-config'

# Confirm TLS material is in place and correctly owned
ls -l /etc/openwatch/tls/cert.pem /etc/openwatch/tls/key.pem
```

---

## Recovery verification

### 1. Service is active

```bash
systemctl status openwatch --no-pager
```

Expect `active (running)`.

### 2. Health endpoint reports healthy

```bash
curl -sk https://localhost:8443/api/v1/health | jq
```

Expect `"status": "healthy"`. Health alone does not prove the service works:
it stays `healthy` when the Kensa rule library failed to load (CP
`bugs/OW-094`). If you restarted OpenWatch or restored data during
containment or recovery, also run both blocks in
[Prove the restored service works](BACKUP_RECOVERY.md#prove-the-restored-service-works), using tokens that
were not revoked during containment. The service is recovered only when they
print `VERIFIED` and `SCANNED`.

### 3. No live sessions for disabled accounts

```bash
psql -U openwatch -d openwatch -c "
SELECT count(*) AS live_sessions_for_disabled_or_deleted_users
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.revoked_at IS NULL AND s.expires_at > now()
  AND (u.disabled_at IS NOT NULL OR u.deleted_at IS NOT NULL);
"
```

Expect `0`.

### 4. Audit logging is still functional

Generate a benign event (for example, a login from an authorized operator) and confirm it lands:

```bash
psql -U openwatch -d openwatch -c "
SELECT occurred_at, action, actor_label
FROM audit_events
ORDER BY occurred_at DESC
LIMIT 5;
"
```

### 5. Elevated role grants match expectations

Re-run the role-grant query from the Investigation section and confirm only authorized accounts hold `admin`, `security_admin`, `ops_lead`, or a custom role with elevated permissions.

---

## Escalation

Escalate immediately for any of:

- Confirmed data breach (PII, credentials, or compliance data exposed).
- Active data exfiltration in progress.
- Suspected exposure of the credential DEK or JWT signing key.
- Refresh-token reuse detected across multiple accounts.
- Lateral movement toward monitored hosts (SSH credential misuse).
- Inability to contain the attacker within 30 minutes.

**Escalation path**: Security Engineering lead, then Infrastructure lead, then executive leadership (if a breach is confirmed), then Legal/Compliance (if regulatory notification is required).

**Regulatory notification (verify against your authorization boundary)**:

| Framework | Requirement |
|-----------|-------------|
| FedRAMP | US-CERT/agency notification within 1 hour of a confirmed incident |
| CMMC / DFARS | Report to DIBNet within 72 hours |
| NIST SP 800-61 | Follow the incident response lifecycle |

---

## Post-incident actions

1. **Timeline**: Document detection time, actions taken, attack vector, data accessed or modified, containment time, and recovery time (ISO 8601, UTC).
2. **Root cause**: Determine how access was gained (stolen credentials, vulnerability, misconfiguration), which controls failed, and how long the attacker was active before detection.
3. **Control updates**: Patch the exploited weakness; enforce MFA on administrative accounts; tighten role assignments; add audit coverage for the vector used.
4. **Lessons learned**: Hold a blameless review within five business days; record action items with owners and deadlines; update this runbook.

---

## Prevention

- **Audit review**: Periodically query `audit_events` for `auth.login.failure` spikes, `authz.permission.denied` clusters, and unexpected `authz.role.assigned` events. The `idx_audit_occurred_at` and `idx_audit_severity` indexes keep these queries fast.
- **MFA**: Enroll all administrative accounts in TOTP MFA (`POST /api/v1/auth/mfa:enroll`).
- **Least privilege**: Grant the narrowest built-in role that fits each user; reserve `admin` for break-glass. Review role grants quarterly using the `user_roles` query above.
- **Session limits**: Sessions enforce a 15-minute inactivity timeout and a 12-hour absolute cap by default; refresh-token rotation flags reuse automatically.
- **Secret hygiene**: Keep `/etc/openwatch/secrets.env`, the JWT key, the credential DEK, and `/etc/openwatch/tls/key.pem` owned by `root`/`openwatch` with restrictive modes. Rotate the JWT and database credentials on a schedule.
- **TLS**: Replace the packaged self-signed certificate with a trusted one; the server reads the cert on every handshake, so swapping files needs no restart. See the [installation guide](../guides/INSTALLATION.md).
- **Backups**: Maintain and test PostgreSQL backups out-of-band; restoration is the only recovery path for data tampering.

---

## Not yet implemented

The following do not exist in the current Go build; do not rely on them during an incident:

- **Prometheus / metrics endpoint**: There is no Prometheus metric or `/metrics` scrape target. Use audit-event queries instead.
- **Account-lockout columns**: `users` has no failed-login counter or lockout timestamp. Brute-force containment is manual (block the IP, revoke sessions, disable the account). The `security.login.failed_threshold` event is a host-intelligence signal, not a control-plane lockout.
- **Admin session-management API**: There is no endpoint to list or revoke another user's sessions; `POST /api/v1/auth/logout` revokes only the caller's session. Use the database `UPDATE` statements above for administrative revocation.
- **Built-in backup/restore tooling**: Database backup and restore are operator responsibilities; the binary provides only `migrate`.
