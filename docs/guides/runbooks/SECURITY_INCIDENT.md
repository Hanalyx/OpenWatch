# Runbook: Security Incident Response

**Severity**: P0 - Critical
**Last Updated**: 2026-06-10
**Owner**: Security Engineering
**Estimated Resolution Time**: Hours to days depending on scope

OpenWatch runs as a single Go binary (`/usr/bin/openwatch`) managed by `systemd` (`openwatch.service`). It serves the REST API and the embedded UI over HTTPS on port `8443` and stores all data in PostgreSQL (there is no MongoDB, Redis, Celery, or container runtime). Audit events are written to the `audit_events` table; the service logs to the journal (`journalctl -u openwatch`). Adjust `psql` connection flags (`-h`, `-p`) for your deployment.

This runbook covers containment, investigation, and recovery for a suspected compromise. For install, config, and role definitions see [docs/guides/INSTALLATION.md](../INSTALLATION.md) and docs/engineering/rbac_registry.md.

---

## Symptoms

- Spike in failed-login audit events (`auth.login.failure`).
- Successful logins for accounts that should be inactive (`auth.login.success`).
- Permission-denied events on privileged endpoints (`authz.permission.denied`).
- Unexpected role grants (`authz.role.assigned`) or account changes (`account.user.created`, `account.user.deleted`).
- Threshold detections raised by the intelligence collector: `security.login.failed_threshold`, `security.login.new_source_ip`, `account.sudo.failure_threshold`.
- Credential changes (`credential.created`, `credential.deleted`) you did not authorize.
- Config-file tampering reported on a monitored host (`system.config.file_changed`).
- Compromised credentials reported by a user or external source.

The `security.*` and `account.*` threshold events above are produced by the OS intelligence collector for monitored hosts, not by the OpenWatch control plane itself. Verify the actor and host before acting on them.

---

## Immediate actions (first 15 minutes)

Contain the threat and preserve evidence. Do not restart the service yet; an in-progress restart can rotate the journal and end the current session you are inspecting.

### Step 1: Confirm the incident

Determine whether this is a true incident or a false positive. Review recent security-relevant audit events:

```bash
psql -U openwatch -d openwatch -c "
SELECT occurred_at, action, outcome, actor_label, actor_ip, resource_type, resource_id
FROM audit_events
WHERE action IN (
  'auth.login.failure','auth.login.success','authz.permission.denied',
  'authz.role.assigned','authz.role.removed',
  'account.user.created','account.user.deleted',
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

```bash
psql -U openwatch -d openwatch -c "
SELECT occurred_at, action, outcome, actor_label, actor_ip, resource_id, detail
FROM audit_events
WHERE action IN (
  'authz.permission.denied','authz.role.assigned','authz.role.removed',
  'account.user.created','account.user.deleted'
)
  AND occurred_at > now() - interval '7 days'
ORDER BY occurred_at DESC
LIMIT 50;
"
```

### Current user accounts and role grants

The `users` table has no `is_active` flag; disabled accounts are soft-deleted (`deleted_at` set). Roles live in `user_roles`, not on the user row.

```bash
# Recently created or modified accounts
psql -U openwatch -d openwatch -c "
SELECT id, username, email, created_at, updated_at, deleted_at
FROM users
ORDER BY created_at DESC
LIMIT 20;
"

# Who holds elevated roles right now
psql -U openwatch -d openwatch -c "
SELECT u.username, ur.role_id, ur.granted_at, ur.granted_by
FROM user_roles ur
JOIN users u ON u.id = ur.user_id
WHERE ur.role_id IN ('admin','security_admin','ops_lead')
  AND u.deleted_at IS NULL
ORDER BY ur.granted_at DESC;
"
```

The five built-in roles, in increasing privilege, are `viewer`, `auditor`, `ops_lead`, `security_admin`, and `admin`. See docs/engineering/rbac_registry.md for the full permission sets.

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

A non-null `reuse_detected_at` means a refresh token was presented after it had already been rotated — treat the owning account as compromised.

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

There is no `is_active` flag; disabling an account means soft-deleting it. Prefer the API so the action is itself audited (`account.user.deleted`):

```bash
# Authenticated as an admin; replace TOKEN and USER_ID
curl -sk -X DELETE \
  -H "Authorization: Bearer TOKEN" \
  https://localhost:8443/api/v1/users/USER_ID
```

If the API is unavailable, soft-delete directly. This also removes the account from the active-uniqueness indexes:

```bash
psql -U openwatch -d openwatch -c "
UPDATE users SET deleted_at = now()
WHERE username = 'USERNAME' AND deleted_at IS NULL;
"
```

### Revoke every session (full re-authentication)

To force all users to re-authenticate, rotate the JWT signing key. The signing key is a file referenced by `[identity].jwt_private_key` (or `OPENWATCH_IDENTITY_JWT_PRIVATE_KEY`). Replacing it invalidates every issued access token because existing tokens no longer verify:

```bash
# Back up the current key, generate a replacement (RSA, matching the existing key type)
sudo cp /etc/openwatch/identity/jwt_private_key.pem /etc/openwatch/identity/jwt_private_key.pem.bak
sudo openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out /etc/openwatch/identity/jwt_private_key.pem
sudo chown root:openwatch /etc/openwatch/identity/jwt_private_key.pem
sudo chmod 0640 /etc/openwatch/identity/jwt_private_key.pem

# The key is loaded at startup; restart to pick up the new key
sudo systemctl restart openwatch
```

Confirm the configured path before generating a new key — `openwatch check-config` prints the resolved configuration with secrets redacted:

```bash
sudo -u openwatch /usr/bin/openwatch check-config --config /etc/openwatch/openwatch.toml
```

> Do not rotate the credential DEK (`[identity].credential_key_file`) during an incident unless you have a re-encryption plan. Changing that key makes every stored SSH credential and MFA secret unreadable.

### Rotate the database credential

If the database password may be exposed:

```bash
# Set a new password in PostgreSQL
psql -U openwatch -d openwatch -c "ALTER ROLE openwatch WITH PASSWORD 'NEW_PASSWORD_HERE';"  # pragma: allowlist secret

# Update the DSN in the secrets file, then restart
sudo sed -i 's#OPENWATCH_DATABASE_DSN=.*#OPENWATCH_DATABASE_DSN=postgres://openwatch:NEW_PASSWORD_HERE@127.0.0.1:5432/openwatch?sslmode=require#' /etc/openwatch/secrets.env
sudo systemctl restart openwatch
```

`secrets.env` should be owned `root:openwatch` and mode `0640`. See [docs/guides/INSTALLATION.md](../INSTALLATION.md) for the canonical secret-handling procedure.

### Block attacker IP addresses

```bash
sudo iptables -I INPUT -s ATTACKER_IP -j DROP
```

---

## Recovery

### Restore from backup (if data was modified)

If the attacker modified data, restore PostgreSQL from a known-good backup. The procedure depends on how your database is backed up (`pg_dump`/`pg_restore` or physical/PITR); follow your backup tooling's restore steps, then re-run migrations to confirm the schema is current:

```bash
sudo -u openwatch /usr/bin/openwatch migrate --config /etc/openwatch/openwatch.toml
```

> A backup/restore tool is not part of the OpenWatch binary today; database backup is an operator responsibility. This is tracked as roadmap, not an implemented feature.

### Re-verify configuration

```bash
# Validate the resolved config (secrets redacted, listen address, TLS paths)
sudo -u openwatch /usr/bin/openwatch check-config --config /etc/openwatch/openwatch.toml

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
curl -sk https://localhost:8443/api/v1/health | python3 -m json.tool
```

Expect `"status": "healthy"`.

### 3. No live sessions for disabled accounts

```bash
psql -U openwatch -d openwatch -c "
SELECT count(*) AS live_sessions_for_deleted_users
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.revoked_at IS NULL AND s.expires_at > now()
  AND u.deleted_at IS NOT NULL;
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

Re-run the role-grant query from the Investigation section and confirm only authorized accounts hold `admin`, `security_admin`, or `ops_lead`.

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
- **MFA**: Enrol all administrative accounts in TOTP MFA (`POST /api/v1/auth/mfa:enroll`).
- **Least privilege**: Grant the narrowest built-in role that fits each user; reserve `admin` for break-glass. Review role grants quarterly using the `user_roles` query above.
- **Session limits**: Sessions enforce a 15-minute inactivity timeout and a 12-hour absolute cap by default; refresh-token rotation flags reuse automatically.
- **Secret hygiene**: Keep `/etc/openwatch/secrets.env`, the JWT key, the credential DEK, and `/etc/openwatch/tls/key.pem` owned by `root`/`openwatch` with restrictive modes. Rotate the JWT and database credentials on a schedule.
- **TLS**: Replace the packaged self-signed certificate with a trusted one; the server reads the cert on every handshake, so swapping files needs no restart. See [docs/guides/INSTALLATION.md](../INSTALLATION.md).
- **Backups**: Maintain and test PostgreSQL backups out-of-band; restoration is the only recovery path for data tampering.

---

## Not yet implemented

The following do not exist in the current Go build; do not rely on them during an incident:

- **Prometheus / metrics endpoint**: There is no `secureops_*` metric or `/metrics` scrape target. Use audit-event queries instead.
- **Account-lockout columns**: `users` has no failed-login counter or lockout timestamp. Brute-force containment is manual (block the IP, revoke sessions, soft-delete the account). The `security.login.failed_threshold` event is a host-intelligence signal, not a control-plane lockout.
- **Admin session-management API**: There is no endpoint to list or revoke another user's sessions; `POST /api/v1/auth/logout` revokes only the caller's session. Use the database `UPDATE` statements above for administrative revocation.
- **Built-in backup/restore tooling**: Database backup and restore are operator responsibilities; the binary provides only `migrate`.
