# Runbook: Security Incident Response

**Severity**: P0 - Critical
**Last Updated**: 2026-02-17
**Owner**: Security Engineering
**Estimated Resolution Time**: Hours to days depending on scope

---

## Symptoms

- Unauthorized access attempts detected in audit logs (`/openwatch/logs/audit.log`).
- Unusual API request patterns (high volume from a single source, access to admin endpoints).
- Monitoring alerts for elevated `secureops_security_events_total` metric.
- Failed authentication spike (multiple `SECURITY_AUTH_FAILURE` events).
- Privilege escalation events logged (`SECURITY_PRIVILEGE_ESCALATION`).
- Unexpected user accounts or role changes.
- Compromised credentials reported by a user or external source.
- Data exfiltration indicators (large data exports, bulk API queries).
- Unexpected configuration changes to security settings.

---

## Immediate Actions (First 15 Minutes)

**Priority: Contain the threat and preserve evidence. Do NOT restart services yet.**

### Step 1: Confirm the incident

Determine whether this is a true security incident or a false positive.

```bash
# Check recent audit log entries
docker exec openwatch-backend tail -200 /openwatch/logs/audit.log
```

Look for:
- Multiple `SECURITY_AUTH_FAILURE` events from the same IP.
- `SECURITY_AUTH_SUCCESS` for accounts that should not be active.
- `SECURITY_PRIVILEGE_ESCALATION` events.
- Access to sensitive endpoints (user management, credential management, system config).

### Step 2: Record the timeline

Document the following immediately:
- When the anomaly was first detected.
- Who detected it (monitoring alert, user report, manual observation).
- What specific events triggered the investigation.

### Step 3: Preserve evidence

**Do NOT restart containers** -- this destroys in-memory state and may overwrite log files.

Capture current state:

```bash
# Capture container logs (all containers)
mkdir -p /tmp/incident-$(date +%Y%m%d-%H%M%S)
INCIDENT_DIR=/tmp/incident-$(date +%Y%m%d-%H%M%S)

docker logs openwatch-backend > "${INCIDENT_DIR}/backend.log" 2>&1
docker logs openwatch-worker > "${INCIDENT_DIR}/worker.log" 2>&1
docker logs openwatch-celery-beat > "${INCIDENT_DIR}/celery-beat.log" 2>&1
docker logs openwatch-frontend > "${INCIDENT_DIR}/frontend.log" 2>&1
docker logs openwatch-db > "${INCIDENT_DIR}/database.log" 2>&1
docker logs openwatch-redis > "${INCIDENT_DIR}/redis.log" 2>&1

# Capture audit log from volume
docker cp openwatch-backend:/openwatch/logs/audit.log "${INCIDENT_DIR}/audit.log"

# Capture current container state
docker ps -a > "${INCIDENT_DIR}/containers.txt"
docker stats --no-stream > "${INCIDENT_DIR}/stats.txt"

# Capture network connections
docker exec openwatch-backend ss -tunapl > "${INCIDENT_DIR}/backend-connections.txt" 2>/dev/null
```

### Step 4: Isolate affected systems

If active compromise is confirmed:

```bash
# Option A: Block external access (if behind a firewall/load balancer)
# Update firewall rules to block the attacker's IP

# Option B: Disconnect the application from external network (severe)
# WARNING: This will make the application inaccessible to all users
# Only do this if active data exfiltration is occurring
docker network disconnect bridge openwatch-frontend
```

Do NOT disconnect internal Docker networks between containers unless lateral movement is confirmed.

---

## Investigation

### Check audit logs (PostgreSQL)

The `audit_logs` table contains durable audit records:

```bash
# Recent authentication failures
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT created_at, event_type, username, ip_address, details
FROM audit_logs
WHERE event_type LIKE '%AUTH_FAILURE%'
  AND created_at > now() - interval '24 hours'
ORDER BY created_at DESC
LIMIT 50;
"

# Recent authentication successes (look for unexpected accounts)
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT created_at, event_type, username, ip_address
FROM audit_logs
WHERE event_type LIKE '%AUTH_SUCCESS%'
  AND created_at > now() - interval '24 hours'
ORDER BY created_at DESC
LIMIT 50;
"

# Privilege escalation or role changes
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT created_at, event_type, username, ip_address, details
FROM audit_logs
WHERE event_type IN ('SECURITY_PRIVILEGE_ESCALATION', 'USER_ROLE_CHANGE', 'USER_CREATED', 'USER_DELETED')
  AND created_at > now() - interval '7 days'
ORDER BY created_at DESC
LIMIT 50;
"
```

### Check for unauthorized accounts

```bash
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT id, username, email, role, is_active, created_at, last_login
FROM users
ORDER BY created_at DESC
LIMIT 20;
"
```

Look for:
- Accounts created recently that are not recognized.
- Accounts with elevated roles (ADMIN, SUPERADMIN) that should not have them.
- Accounts that have logged in recently but should be inactive.

### Check API access patterns

```bash
# Check backend logs for unusual request patterns
docker logs openwatch-backend --since 24h 2>&1 | grep -E "POST /api/users|POST /api/auth|DELETE" | tail -50

# Check for high-volume requests from single IPs
docker logs openwatch-backend --since 24h 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -rn | head -20
```

### Check for data exfiltration

```bash
# Check for bulk data exports
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT id, format, status, file_size_bytes, requested_by, created_at
FROM audit_exports
WHERE created_at > now() - interval '7 days'
ORDER BY created_at DESC;
"

# Check for large API responses (if access logs include response sizes)
docker logs openwatch-backend --since 24h 2>&1 | grep -E "GET /api/(hosts|scans|compliance)" | tail -50
```

### Check SSH credential access

If SSH credentials may have been compromised:

```bash
# Check recent credential access in audit logs
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT created_at, event_type, username, details
FROM audit_logs
WHERE event_type LIKE '%CREDENTIAL%'
  AND created_at > now() - interval '7 days'
ORDER BY created_at DESC
LIMIT 30;
"
```

### Check for configuration changes

```bash
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT created_at, event_type, username, details
FROM audit_logs
WHERE event_type LIKE '%CONFIG%'
  AND created_at > now() - interval '7 days'
ORDER BY created_at DESC;
"
```

---

## Containment

### Revoke active sessions

Force all users to re-authenticate by rotating the JWT signing key:

```bash
# Generate a new secret key
NEW_SECRET=$(openssl rand -hex 32)

# Update the environment variable
# In .env file: OPENWATCH_SECRET_KEY=<new value>
# Then restart backend and worker to pick up the new key
docker restart openwatch-backend
docker restart openwatch-worker
docker restart openwatch-celery-beat
```

This invalidates all existing JWT access and refresh tokens immediately.

### Disable compromised accounts

```bash
# Disable a specific user account (replace USERNAME)
docker exec openwatch-db psql -U openwatch -d openwatch -c "
UPDATE users SET is_active = false WHERE username = 'COMPROMISED_USERNAME';
"
```

### Rotate application secrets

Rotate all secrets referenced in the environment. See `docs/guides/SECRET_ROTATION.md` if available, otherwise rotate the following:

1. **JWT secret key** (`OPENWATCH_SECRET_KEY`):
   ```bash
   openssl rand -hex 32
   ```

2. **Encryption key** (`OPENWATCH_ENCRYPTION_KEY`):
   ```bash
   # WARNING: Changing this key will make existing encrypted data
   # (SSH credentials, API keys) unreadable. Plan a re-encryption
   # migration before changing this key in production.
   openssl rand -hex 32
   ```

3. **Master key** (`MASTER_KEY`):
   ```bash
   openssl rand -hex 32
   ```

4. **PostgreSQL password** (`POSTGRES_PASSWORD`):
   ```bash
   # Generate new password
   openssl rand -base64 24

   # Update in PostgreSQL
   docker exec openwatch-db psql -U openwatch -d openwatch -c "
   ALTER ROLE openwatch WITH PASSWORD 'NEW_PASSWORD_HERE';  -- pragma: allowlist secret
   "

   # Update in .env and restart all services that connect to PostgreSQL
   ```

5. **Redis password** (`REDIS_PASSWORD`):
   ```bash
   # Generate new password
   openssl rand -base64 24

   # Update Redis password at runtime
   docker exec openwatch-redis redis-cli -a "${REDIS_PASSWORD}" CONFIG SET requirepass "NEW_PASSWORD_HERE"

   # Update in .env and restart all services that connect to Redis
   ```

After updating all secrets in the `.env` file:

```bash
docker compose down
docker compose up -d
```

### Block attacker IP addresses

If the attacker's IP is identified, block it at the network level:

```bash
# Using iptables (Linux)
iptables -I INPUT -s ATTACKER_IP -j DROP

# Or update the Docker network firewall
```

### Force password reset for affected users

```bash
# Mark all user passwords as requiring reset (application-level)
docker exec openwatch-db psql -U openwatch -d openwatch -c "
UPDATE users SET password_change_required = true WHERE is_active = true;
"
```

---

## Recovery

### Restore from backup (if data was modified)

If the attacker modified data (scan results, compliance findings, user records):

1. Identify the last known good backup timestamp.
2. Restore the PostgreSQL database from backup.
3. Verify data integrity after restore.

```bash
# List available backups (adjust path to your backup location)
ls -la /path/to/backups/

# Restore PostgreSQL from a backup file
docker exec -i openwatch-db psql -U openwatch -d openwatch < /path/to/backups/openwatch_backup.sql
```

### Re-verify security configuration

After containment and secret rotation, verify:

```bash
# Check that HTTPS is enforced
docker exec openwatch-backend printenv | grep REQUIRE_HTTPS

# Check that FIPS mode setting is correct
docker exec openwatch-backend printenv | grep FIPS_MODE

# Check that debug mode is disabled in production
docker exec openwatch-backend printenv | grep DEBUG

# Verify health endpoint works with new credentials
curl -s http://localhost:8000/health | python3 -m json.tool
```

### Verify security headers

```bash
curl -sI http://localhost:8000/health | grep -E "X-Content-Type|X-Frame|Strict-Transport|Content-Security"
```

Expected headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`

---

## Recovery Verification

### 1. All services are running and healthy

```bash
docker ps --filter "name=openwatch-" --format "table {{.Names}}\t{{.Status}}"
```

### 2. Health endpoint confirms all dependencies healthy

```bash
curl -s http://localhost:8000/health | python3 -m json.tool
```

### 3. No active unauthorized sessions

```bash
# Verify no unexpected active sessions after secret rotation
docker logs openwatch-backend --since 10m 2>&1 | grep "AUTH_SUCCESS"
```

Only expected administrative sessions should appear.

### 4. Audit logging is functional

```bash
# Verify audit log is being written
docker exec openwatch-backend tail -5 /openwatch/logs/audit.log
```

### 5. Compromised accounts are disabled

```bash
docker exec openwatch-db psql -U openwatch -d openwatch -c "
SELECT username, is_active FROM users WHERE username = 'COMPROMISED_USERNAME';
"
```

---

## Escalation

**Immediate escalation is required for**:
- Confirmed data breach (PII, credentials, compliance data exposed).
- Active data exfiltration in progress.
- Compromise of the master encryption key or SSH credentials.
- Lateral movement to target hosts detected.
- Inability to contain the attacker within 30 minutes.

**Escalation path**:
1. Security Engineering lead.
2. Infrastructure team lead.
3. Executive leadership (if data breach confirmed).
4. Legal/Compliance team (if regulatory notification is required).

**Regulatory notification requirements**:
- FedRAMP: US-CERT notification within 1 hour of confirmed incident.
- CMMC: Report within 72 hours to DIBNet.
- NIST SP 800-61: Follow the incident response lifecycle.

---

## Post-Incident Actions

### 1. Document the timeline

Create a timeline document covering:
- When the incident was first detected.
- What actions were taken and when.
- What was the attack vector.
- What data was accessed or modified.
- When containment was achieved.
- When recovery was complete.

### 2. Root cause analysis

Determine:
- How did the attacker gain access (stolen credentials, vulnerability, misconfiguration)?
- What controls failed to prevent or detect the attack?
- How long was the attacker active before detection?

### 3. Update security controls

Based on the root cause:
- Patch any exploited vulnerabilities.
- Strengthen authentication (enforce MFA if not already required).
- Tighten RBAC policies.
- Add additional audit logging for the attack vector used.
- Update rate limiting rules if brute-force was involved.
- Review and update network segmentation.

### 4. Update monitoring and alerting

Add detection rules for the specific attack pattern:

```yaml
# Example: Alert on authentication brute force
groups:
  - name: security-alerts
    rules:
      - alert: AuthBruteForce
        expr: rate(secureops_security_events_total{type="auth_failure"}[5m]) > 1
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Possible brute force attack detected"
```

### 5. Conduct lessons learned review

Schedule a blameless post-incident review within 5 business days covering:
- What went well in the response.
- What could be improved.
- Action items with owners and deadlines.
- Updates to this runbook if needed.

---

## Prevention

- **Audit log monitoring**: Configure alerts on `secureops_security_events_total` for auth failures, forbidden access, and rate limit violations.
- **Rate limiting**: OpenWatch enforces 100 requests per minute per user and 1000 per minute per IP. Review these limits periodically.
- **Session timeout**: Inactivity timeout is configurable (default 15 minutes). Ensure it is set appropriately for the environment.
- **Password policy**: Enforce minimum 12-character passwords with complexity requirements (configured in application settings).
- **MFA**: Enable multi-factor authentication for all administrative accounts.
- **Secret rotation schedule**: Rotate application secrets (JWT key, encryption key, database passwords) on a regular schedule (quarterly recommended).
- **Access reviews**: Conduct quarterly user access reviews. Remove accounts that are no longer needed and verify role assignments are appropriate.
- **Network segmentation**: The Docker network (172.20.0.0/16) isolates OpenWatch containers. Ensure no unnecessary ports are exposed to the host or external networks.
- **Backup verification**: Regularly test backup restoration to ensure recovery is possible in case of data corruption or destruction.
