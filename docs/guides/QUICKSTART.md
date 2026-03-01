# Quickstart Guide

Get from installation to your first compliance scan in 15 minutes.

---

## Prerequisites

- **OpenWatch running** with all containers healthy.
  See the [Installation Guide](INSTALLATION.md) if you have not deployed yet.
- **A Linux host reachable via SSH** from the OpenWatch server
  (RHEL 8/9, Rocky, or Alma for the examples below).
- **SSH credentials** for that host (username + password, or SSH key).

Default ports: Frontend on **3000**, Backend API on **8000**.

---

## Step 1: Verify the Deployment

Open a terminal and confirm the backend is healthy:

```bash
curl -s http://localhost:8000/health | jq .
```

Expected output:

```json
{
  "status": "healthy",
  "version": "1.2.0",
  "database": "healthy",
  "redis": "healthy"
}
```

If you get connection errors, check that containers are running:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}" | grep openwatch
```

Do not proceed until the health endpoint returns `"status": "healthy"`.

---

## Step 2: Log In

Open **http://localhost:3000** in your browser. You will see the login page.

![OpenWatch login page](../images/quickstart/login.png)

Enter the default credentials:

- **Username:** `admin`
- **Password:** `admin`

Click **Sign In**. You will land on the compliance dashboard.

> **Security notice:** Change the default password immediately. Go to your user
> profile (top-right menu) and update the password. Default credentials must
> never be used in production.

---

## Step 3: Add a Host

From the left sidebar, navigate to **Hosts**. Click the **Add Host** button.

![Add Host dialog](../images/quickstart/add-host.png)

Fill in the host details:

| Field | Example Value |
|-------|---------------|
| Hostname | `web-01` |
| IP Address | `192.168.1.10` |
| SSH Port | `22` |
| Display Name | `Web Server 01` (optional) |
| Operating System | `RHEL 9` (optional) |

Click **Save**. The host appears in the host list.

---

## Step 4: Configure SSH Credentials

OpenWatch needs SSH access to scan the host. On the host detail page, navigate
to the **Credentials** section.

![Credential configuration](../images/quickstart/credentials.png)

Choose an authentication method:

| Method | When to Use |
|--------|-------------|
| **SSH Key** (recommended) | Paste the private key. Stored encrypted with AES-256-GCM. |
| **Password** | Enter the SSH password. Stored encrypted. |
| **System Default** | Uses the credential configured in Settings > System Credentials. |

After saving credentials, use the **Test Connection** button to verify SSH
connectivity before scanning.

---

## Step 5: Run a Compliance Scan

From the host detail page, click **Run Scan**.

![Run Scan action](../images/quickstart/run-scan.png)

Select a compliance framework:

| Framework | Rules | Best For |
|-----------|-------|----------|
| CIS RHEL 9 v2.0.0 | 271 | Industry-standard hardening benchmarks |
| STIG RHEL 9 V2R7 | 338 | DoD and government environments |
| NIST 800-53 R5 | 87 | Federal information systems |
| PCI-DSS v4.0 | 45 | Payment card environments |
| FedRAMP Moderate | 87 | Cloud services for government |

Click **Start Scan**. The scan runs in the background and typically takes
1--5 minutes. You can navigate away and return later; the results will be
waiting.

---

## Step 6: View Scan Results

Once the scan completes, the host detail page shows the compliance results.

![Scan results with pass/fail breakdown](../images/quickstart/scan-results.png)

The results page shows:

- **Compliance score** -- percentage of rules passing (e.g., 72.2%)
- **Pass / Fail / Error counts** -- summary by status
- **Findings table** -- each rule with its status, severity, title, and detail
- **Severity breakdown** -- critical, high, medium, low counts

Click any finding to expand its detail, including the evidence (command
executed, expected value, actual value).

Use the **filters** to narrow results by severity, status, or search for
specific rule keywords.

---

## Step 7: Review the Compliance Dashboard

Navigate to the **Dashboard** from the left sidebar.

![Compliance dashboard overview](../images/quickstart/dashboard.png)

The dashboard shows:

- **Aggregate compliance posture** across all hosts
- **Host list** with last scan status and compliance scores
- **Trend data** showing compliance score over time
- **Active alerts** for compliance drift and threshold violations

This is your day-to-day starting point. The dashboard updates automatically
as new scans complete.

---

## Step 8: Next Steps

You have completed your first scan. Here is what to do next:

| Task | Where |
|------|-------|
| Add more hosts and organize into groups | [Hosts and Remediation Guide](HOSTS_AND_REMEDIATION.md) |
| Understand posture scores, drift, and alerts | [Scanning and Compliance Guide](SCANNING_AND_COMPLIANCE.md) |
| Set up team access with roles | [User Roles Guide](USER_ROLES.md) |
| Automate scanning via the API | [API Guide](API_GUIDE.md) |

---

## Troubleshooting

**Cannot reach http://localhost:3000** --
Frontend container may not be running. Check `docker ps | grep openwatch-frontend`
and `docker logs openwatch-frontend`.

**"Connection refused" on health check** --
Backend is not running. Check `docker ps` and `docker logs openwatch-backend`.

**Login fails with default credentials** --
Verify the backend started successfully. Check `docker logs openwatch-backend`
for initialization errors.

**Scan stuck in "queued"** --
The Celery worker may be down. Verify with `docker ps | grep openwatch-worker`
and confirm Redis is up: `docker exec openwatch-redis redis-cli ping` (expect
`PONG`).

**Scan fails immediately** --
Check the error on the scan results page. Common causes: SSH connection failure
(wrong credentials or network), unsupported OS on target, or Kensa rules not
loaded (`KENSA_RULES_PATH` not set).

---

## Appendix: API Alternative

For operators who prefer CLI or want to script these steps for automation,
here are the equivalent API calls.

### Authenticate

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.access_token')  # pragma: allowlist secret
```

### Add a Host

```bash
HOST_ID=$(curl -s -X POST http://localhost:8000/api/hosts/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "web-01",
    "ip_address": "192.168.1.10",
    "ssh_port": 22
  }' | jq -r '.id')
```

### Run a Scan

```bash
SCAN_ID=$(curl -s -X POST http://localhost:8000/api/scans/kensa/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"host_id\": \"$HOST_ID\",
    \"framework\": \"cis-rhel9-v2.0.0\"
  }" | jq -r '.scan_id')
```

### View Results

```bash
curl -s http://localhost:8000/api/scans/$SCAN_ID/results \
  -H "Authorization: Bearer $TOKEN" | jq '{compliance_percentage, total_rules, pass_count, fail_count}'
```

### Check Posture

```bash
curl -s "http://localhost:8000/api/compliance/posture?host_id=$HOST_ID" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

See the [API Guide](API_GUIDE.md) for the full endpoint reference.
