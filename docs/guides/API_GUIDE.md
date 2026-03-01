# API Guide

Most operators use the **web UI** for daily work -- managing hosts, viewing
dashboards, reading scan results, and running remediations. This guide is for
**automation**: scripting repetitive tasks, integrating with CI/CD pipelines, or
building custom tooling on top of OpenWatch.

OpenWatch exposes 80+ REST endpoints under the `/api` prefix. This guide covers the
most common automation workflows organized by task. For the full schema reference,
see the Swagger UI at `http://localhost:8000/api/docs` (available when
`OPENWATCH_DEBUG=true`).

All endpoints require JWT Bearer tokens unless noted otherwise.

---

## Authentication

### Log In

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"yourpassword"}' | jq -r '.access_token')  # pragma: allowlist secret
```

Response includes `access_token` (1 hour) and `refresh_token` (7 days).

### Refresh Token

```bash
curl -s -X POST http://localhost:8000/api/auth/refresh \
  -H "Authorization: Bearer $TOKEN"
```

### Log Out

```bash
curl -s -X POST http://localhost:8000/api/auth/logout \
  -H "Authorization: Bearer $TOKEN"
```

### Current User

```
GET /api/auth/me
```

All subsequent examples assume `-H "Authorization: Bearer $TOKEN"`.

---

## Hosts

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/hosts/` | List all hosts |
| POST | `/api/hosts/` | Add a host |
| GET | `/api/hosts/{id}` | Get host details |
| PUT | `/api/hosts/{id}` | Update host |
| DELETE | `/api/hosts/{id}` | Delete host |
| POST | `/api/hosts/validate-credentials` | Test SSH connectivity |

All host IDs are UUIDs.

### Add a Host

```bash
curl -s -X POST http://localhost:8000/api/hosts/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "rhel9-web01.example.com",
    "ip_address": "10.0.1.50",
    "port": 22,
    "username": "openwatch",
    "auth_method": "key",
    "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."  # pragma: allowlist secret
  }'
```

---

## Host Groups

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/host-groups/` | List groups |
| POST | `/api/host-groups/` | Create group |
| PUT | `/api/host-groups/{id}` | Update group |
| DELETE | `/api/host-groups/{id}` | Delete group |
| POST | `/api/host-groups/{id}/hosts` | Assign hosts |
| POST | `/api/host-groups/{id}/scan` | Start group scan |

---

## Scanning

### Start a Kensa Compliance Scan

```bash
curl -s -X POST http://localhost:8000/api/scans/kensa/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "host_id": "550e8400-e29b-41d4-a716-446655440000",
    "framework": "cis-rhel9-v2.0.0"
  }'
```

Optional fields: `framework`, `severity` (list), `category`.

### Available Frameworks

```
GET /api/scans/kensa/frameworks
```

| Framework | Mapping ID | Rules |
|-----------|------------|-------|
| CIS RHEL 9 v2.0.0 | cis-rhel9-v2.0.0 | 271 |
| STIG RHEL 9 V2R7 | stig-rhel9-v2r7 | 338 |
| NIST 800-53 R5 | nist-800-53-r5 | 87 |
| PCI-DSS v4.0 | pci-dss-v4.0 | 45 |
| FedRAMP Moderate | fedramp-moderate | 87 |

### Other Scan Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/scans/kensa/health` | Engine health |
| GET | `/api/scans/kensa/compliance-state/{host_id}` | Latest compliance state |
| GET | `/api/scans/` | List all scans |
| GET | `/api/scans/{scan_id}` | Scan details |
| GET | `/api/scans/{scan_id}/results` | Scan results (pass/fail per rule) |
| GET | `/api/scans/{scan_id}/failed-rules` | Failed rules only |
| GET | `/api/scans/{scan_id}/report/json` | JSON report |
| GET | `/api/scans/{scan_id}/report/csv` | CSV report |
| GET | `/api/scans/{scan_id}/report/html` | HTML report |

---

## Compliance Posture

| Method | Endpoint | Purpose | License |
|--------|----------|---------|---------|
| GET | `/api/compliance/posture?host_id={id}` | Current posture | Free |
| GET | `/api/compliance/posture?host_id={id}&as_of=2026-01-15` | Historical posture | OpenWatch+ |
| GET | `/api/compliance/posture/history?host_id={id}&start_date=...&end_date=...` | Posture over time | OpenWatch+ |
| GET | `/api/compliance/posture/drift?host_id={id}&start_date=...&end_date=...` | Drift detection | OpenWatch+ |
| POST | `/api/compliance/posture/snapshot` | Create manual snapshot | Free |

---

## Compliance Exceptions

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/compliance/exceptions` | List exceptions |
| GET | `/api/compliance/exceptions/summary` | Exception statistics |
| POST | `/api/compliance/exceptions` | Request new exception |
| GET | `/api/compliance/exceptions/{id}` | Exception details |
| POST | `/api/compliance/exceptions/{id}/approve` | Approve (admin) |
| POST | `/api/compliance/exceptions/{id}/reject` | Reject (admin) |
| POST | `/api/compliance/exceptions/{id}/revoke` | Revoke (admin) |
| POST | `/api/compliance/exceptions/check` | Check if rule is excepted |

### Create Exception Request

```bash
curl -s -X POST http://localhost:8000/api/compliance/exceptions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "rule_id": "sshd-strong-ciphers",
    "host_id": "550e8400-e29b-41d4-a716-446655440000",
    "justification": "Legacy system requires weak cipher for 30 days",
    "duration_days": 30
  }'
```

---

## Alerts

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/compliance/alerts` | List alerts |
| GET | `/api/compliance/alerts/stats` | Alert statistics |
| GET | `/api/compliance/alerts/{id}` | Alert details |
| POST | `/api/compliance/alerts/{id}/acknowledge` | Acknowledge |
| POST | `/api/compliance/alerts/{id}/resolve` | Resolve |
| GET | `/api/compliance/alerts/thresholds` | Get thresholds |
| PUT | `/api/compliance/alerts/thresholds` | Update thresholds |

List endpoint query parameters: `status`, `severity`, `alert_type`, `host_id`,
`page`, `per_page`.

---

## Remediation (OpenWatch+)

Remediation requires an OpenWatch+ license. HTTP 402 is returned without one.

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/compliance/remediation` | Create remediation job |
| POST | `/api/compliance/remediation/plan` | Preview plan (dry-run) |
| POST | `/api/compliance/remediation/check-rules` | Check rule remediation support |
| GET | `/api/compliance/remediation` | List jobs |
| GET | `/api/compliance/remediation/summary` | Job statistics |
| GET | `/api/compliance/remediation/{job_id}` | Job details with results |
| GET | `/api/compliance/remediation/{job_id}/results/{result_id}/steps` | Step-level results |
| POST | `/api/compliance/remediation/{job_id}/cancel` | Cancel pending/running job |
| POST | `/api/compliance/remediation/rollback` | Rollback completed job |

### Create Remediation Job

```bash
curl -s -X POST http://localhost:8000/api/compliance/remediation \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "host_id": "550e8400-e29b-41d4-a716-446655440000",
    "rule_ids": ["sshd-disable-root-login", "sshd-strong-ciphers"]
  }'
```

Returns HTTP 202. The job executes asynchronously via Celery.

---

## Audit and Export

### Saved Queries

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/compliance/audit/queries` | List saved queries |
| POST | `/api/compliance/audit/queries` | Create saved query |
| GET | `/api/compliance/audit/queries/{id}` | Get query |
| PUT | `/api/compliance/audit/queries/{id}` | Update query |
| DELETE | `/api/compliance/audit/queries/{id}` | Delete query |
| POST | `/api/compliance/audit/queries/preview` | Preview results |
| POST | `/api/compliance/audit/queries/{id}/execute` | Execute saved query |
| POST | `/api/compliance/audit/queries/execute` | Execute ad-hoc query |

### Exports

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/compliance/audit/exports` | List exports |
| POST | `/api/compliance/audit/exports` | Create export (json, csv, pdf) |
| GET | `/api/compliance/audit/exports/{id}` | Export details |
| GET | `/api/compliance/audit/exports/{id}/download` | Download file |

```bash
curl -s -X POST http://localhost:8000/api/compliance/audit/exports \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query_id": "uuid-of-saved-query", "format": "csv"}'
```

---

## Rules Reference

Browse the Kensa rule library without running a scan.

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/rules/reference` | List rules (search, filter, paginate) |
| GET | `/api/rules/reference/{rule_id}` | Full rule details |
| GET | `/api/rules/reference/stats` | Rule statistics |
| GET | `/api/rules/reference/frameworks` | List frameworks |
| GET | `/api/rules/reference/categories` | List categories |
| GET | `/api/rules/reference/variables` | Configurable variables |
| POST | `/api/rules/reference/refresh` | Refresh cache |

List endpoint query parameters: `search`, `framework`, `category`, `severity`,
`has_remediation`, `page`, `per_page`.

---

## Administration

### User Management

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/users/` | List users |
| POST | `/api/users/` | Create user (SUPER_ADMIN) |
| GET | `/api/users/{id}` | Get user |
| PUT | `/api/users/{id}` | Update user |
| DELETE | `/api/users/{id}` | Delete user |

### SSH Configuration

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/ssh/settings/policy` | Get SSH policy |
| POST | `/api/ssh/settings/policy` | Update SSH policy |
| GET | `/api/ssh/settings/known-hosts` | List known hosts |
| POST | `/api/ssh/settings/known-hosts` | Add known host |
| DELETE | `/api/ssh/settings/known-hosts/{hostname}` | Remove known host |
| GET | `/api/ssh/settings/test-connectivity/{host_id}` | Test connectivity |

---

## System Endpoints

| Method | Endpoint | Auth | Purpose |
|--------|----------|------|---------|
| GET | `/health` | None | Application health, DB, Redis status |
| GET | `/security-info` | Admin | FIPS mode and encryption config |
| GET | `/metrics` | None | Prometheus metrics |

```bash
curl -s http://localhost:8000/health | jq
```

---

## Error Responses

| Code | Meaning |
|------|---------|
| 400 | Bad request -- invalid input or business rule violation |
| 401 | Unauthorized -- missing or expired token |
| 402 | Payment required -- OpenWatch+ license needed |
| 403 | Forbidden -- insufficient role or permission |
| 404 | Not found |
| 422 | Validation error -- Pydantic field-level detail included |
| 429 | Rate limit exceeded |
| 500 | Internal server error |

Validation errors (422) include field paths:

```json
{"detail": [{"loc": ["body", "host_id"], "msg": "field required", "type": "value_error.missing"}]}
```

---

## Rate Limits

- 100 requests per minute per authenticated user
- 1,000 requests per minute per source IP

---

## What's Next

- [Quickstart](QUICKSTART.md) -- first scan walkthrough
- [Scanning and Compliance](SCANNING_AND_COMPLIANCE.md) -- detailed scanning workflows
- [User Roles](USER_ROLES.md) -- role and permission reference
- [Hosts and Remediation](HOSTS_AND_REMEDIATION.md) -- host management and automated fixes
