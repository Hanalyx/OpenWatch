# OpenWatch + AEGIS Integration Manual

> **For AEGIS Developers**: This document explains how OpenWatch uses AEGIS and our vision for compliance automation.

**Version**: 1.0.0
**Date**: 2026-02-12
**Maintainer**: OpenWatch Team

---

## Table of Contents

1. [What is OpenWatch?](#what-is-openwatch)
2. [The Compliance Operating System Vision](#the-compliance-operating-system-vision)
3. [How OpenWatch Uses AEGIS](#how-openwatch-uses-aegis)
4. [Integration Architecture](#integration-architecture)
5. [Data Flow and Storage](#data-flow-and-storage)
6. [Current Integration Implementation](#current-integration-implementation)
7. [What OpenWatch Needs from AEGIS](#what-openwatch-needs-from-aegis)
8. [Future Integration Plans](#future-integration-plans)
9. [API Contract and Stability](#api-contract-and-stability)
10. [Coordination Points](#coordination-points)

---

## What is OpenWatch?

### Mission

**"The Eye"** - OpenWatch provides complete visibility into security and compliance posture across enterprise infrastructure.

OpenWatch empowers System Administrators, System Engineers, and Security Analysts to:
- **See** - Gain comprehensive visibility into their environment's security state
- **Scan** - Automate compliance scanning against industry standards
- **Secure** - Identify and remediate security gaps before they become breaches

### Target Compliance Frameworks

| Framework | Use Case |
|-----------|----------|
| FedRAMP Moderate | Federal cloud deployments |
| CMMC Level 2 | Defense contractors |
| NIST SP 800-53 | Federal information systems |
| CIS Benchmarks | Industry best practices |
| DISA STIGs | DoD systems |
| PCI-DSS v4.0 | Payment card environments |
| ISO 27001 | Enterprise security management |

### Technology Stack

| Component | Technology |
|-----------|------------|
| Backend | FastAPI (Python 3.12) |
| Frontend | React 19 + TypeScript + Material-UI v7 |
| Database | PostgreSQL 15 (primary), Redis (cache) |
| Task Queue | Celery with Redis broker |
| Compliance Engine | **AEGIS** (via SSH) |
| Deployment | Docker/Podman, Kubernetes-ready |

---

## The Compliance Operating System Vision

### Paradigm Shift

OpenWatch is transforming from a "scan-on-demand compliance tool" into a **Compliance Operating System** - a platform where compliance is continuously measured, not periodically checked.

```
Traditional Compliance          OpenWatch OS
─────────────────────          ─────────────
Manual scan triggers    →      Automatic continuous scanning
Point-in-time snapshots →      Real-time compliance state
Reactive remediation    →      Proactive drift detection
Siloed scan data        →      Unified compliance intelligence
```

### Core Principles

1. **Auto-Scan Centric**
   - No manual "Run Scan" buttons
   - Adaptive scheduling based on compliance state
   - Maximum 48-hour interval between scans
   - Critical findings trigger immediate re-scans

2. **Server Intelligence**
   - Collect system context during scans (packages, services, users, network)
   - Understand the "why" behind compliance failures
   - Enable smarter remediation recommendations

3. **Temporal Compliance**
   - Point-in-time posture queries ("What was our compliance on Jan 15?")
   - Drift detection between dates
   - Compliance trend analysis

4. **Actionable Alerts**
   - Alert on compliance state changes, not just scan completion
   - Configurable thresholds (score drops, critical findings)
   - Integrate with enterprise notification systems

### Where AEGIS Fits

```
┌─────────────────────────────────────────────────────────────────────┐
│                    OpenWatch Compliance OS                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │  Scheduler  │  │   Alerts    │  │  Temporal   │  │ Exceptions  │ │
│  │  (When)     │  │  (React)    │  │  (History)  │  │  (Waive)    │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘ │
│         │                │                │                │        │
│         └────────────────┴────────────────┴────────────────┘        │
│                                   │                                  │
│                                   ▼                                  │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                     AEGIS Integration Layer                      ││
│  │   • Credential bridging    • Result transformation              ││
│  │   • Session management     • Evidence storage                   ││
│  └─────────────────────────────────────────────────────────────────┘│
│                                   │                                  │
│                                   ▼                                  │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                           AEGIS                                  ││
│  │              Pure Measurement Engine (via SSH)                   ││
│  │   • 338 YAML rules         • Framework mappings                 ││
│  │   • Evidence collection    • Handler-based checks               ││
│  └─────────────────────────────────────────────────────────────────┘│
│                                   │                                  │
│                                   ▼                                  │
│                          Target Hosts (SSH)                          │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**AEGIS is the measurement engine. OpenWatch is the operating system that orchestrates, stores, analyzes, and acts on those measurements.**

---

## How OpenWatch Uses AEGIS

### Responsibility Division

| Responsibility | Owner | Notes |
|----------------|-------|-------|
| SSH connection to hosts | AEGIS | Via `SSHSession` |
| Rule evaluation | AEGIS | 338 canonical rules |
| Evidence collection | AEGIS | Raw command output |
| Framework mapping | AEGIS | Multi-framework refs per rule |
| Credential management | OpenWatch | Encrypted storage, secure retrieval |
| Scan scheduling | OpenWatch | Adaptive compliance scheduler |
| Result storage | OpenWatch | PostgreSQL `scan_findings` table |
| Historical queries | OpenWatch | `posture_snapshots` table |
| Exception management | OpenWatch | Approval workflows, expiration |
| Alerting | OpenWatch | Threshold-based notifications |
| UI/Dashboard | OpenWatch | React frontend |
| User authentication | OpenWatch | JWT + RBAC |

### What OpenWatch DOES NOT Do

- **Does not** interpret OVAL or XCCDF (AEGIS handles this natively)
- **Does not** maintain rule definitions (AEGIS YAML rules are authoritative)
- **Does not** execute SSH commands directly for compliance (delegates to AEGIS)
- **Does not** duplicate AEGIS's framework mappings (uses AEGIS's `framework_refs`)

### What AEGIS DOES NOT Do

- **Does not** store results long-term (returns results, OpenWatch stores)
- **Does not** manage exceptions/waivers (AEGIS checks, OpenWatch waives)
- **Does not** provide UI (AEGIS is headless)
- **Does not** handle scheduling (AEGIS checks on-demand)
- **Does not** manage credentials (OpenWatch provides session)

---

## Integration Architecture

### Current Integration Pattern

```python
# OpenWatch's integration (app/plugins/aegis/)

from aegis import check_rules_from_path
from app.plugins.aegis.executor import AegisSessionFactory

# 1. OpenWatch retrieves encrypted credentials
factory = AegisSessionFactory(db)

# 2. OpenWatch creates AEGIS session with decrypted credentials
async with factory.create_session(host_id) as session:

    # 3. AEGIS executes compliance checks
    results = check_rules_from_path(
        session,
        rules_path="aegis/rules/",
        severity=["critical", "high"],
        category="access-control",
    )

    # 4. OpenWatch stores results in PostgreSQL
    for r in results:
        store_finding(
            scan_id=scan_id,
            rule_id=r.rule_id,
            title=r.title,
            severity=r.severity,
            passed=r.passed,
            detail=r.detail,
            evidence=r.evidence,  # Store for audit
            framework_refs=r.framework_refs,
        )
```

### Key Integration Files

| File | Purpose |
|------|---------|
| `backend/aegis/` | AEGIS engine (bundled or symlinked) |
| `backend/runner -> aegis/runner` | Symlink for imports |
| `backend/app/plugins/aegis/executor.py` | Credential bridge to AEGIS SSHSession |
| `backend/app/plugins/aegis/scanner.py` | ScannerFactory wrapper |
| `backend/app/plugins/aegis/config.py` | AEGIS configuration |
| `backend/app/tasks/aegis_scan_tasks.py` | Celery tasks for async scans |

---

## Data Flow and Storage

### Scan Execution Flow

```
1. Scheduler triggers scan
   │
   ▼
2. OpenWatch retrieves host credentials (encrypted in DB)
   │
   ▼
3. OpenWatch creates AEGIS SSHSession with credentials
   │
   ▼
4. AEGIS connects to host via SSH
   │
   ▼
5. AEGIS evaluates rules, collects evidence
   │
   ▼
6. AEGIS returns results with evidence + framework_refs
   │
   ▼
7. OpenWatch stores in scan_findings table
   │
   ▼
8. OpenWatch updates host compliance score
   │
   ▼
9. OpenWatch checks alert thresholds
   │
   ▼
10. OpenWatch schedules next scan based on compliance state
```

### PostgreSQL Storage Schema

```sql
-- Primary scan results storage
CREATE TABLE scan_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scans(id),
    rule_id VARCHAR(255) NOT NULL,
    title TEXT,
    severity VARCHAR(20),  -- critical, high, medium, low
    status VARCHAR(20),    -- pass, fail, error, skip
    detail TEXT,
    framework_section VARCHAR(100),

    -- Evidence (TODO: expand to full AEGIS Evidence)
    -- Currently stores detail only
    -- Plan: Add evidence JSONB with full Evidence object

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Daily compliance snapshots for temporal queries
CREATE TABLE posture_snapshots (
    id UUID PRIMARY KEY,
    host_id UUID NOT NULL,
    snapshot_date TIMESTAMP WITH TIME ZONE,
    compliance_score FLOAT,
    total_rules INT,
    passed INT,
    failed INT,
    rule_states JSONB,  -- {"rule_id": {"status": "pass", "severity": "high"}}
    created_at TIMESTAMP WITH TIME ZONE
);
```

### What OpenWatch Stores from AEGIS Results

| AEGIS Field | Stored? | Storage Location | Notes |
|-------------|---------|------------------|-------|
| `rule_id` | Yes | `scan_findings.rule_id` | Primary identifier |
| `title` | Yes | `scan_findings.title` | Display name |
| `severity` | Yes | `scan_findings.severity` | Risk level |
| `passed` | Yes | `scan_findings.status` | As 'pass'/'fail' |
| `skipped` | Yes | `scan_findings.status` | As 'skip' |
| `skip_reason` | Partial | `scan_findings.detail` | Included in detail |
| `detail` | Yes | `scan_findings.detail` | Explanation |
| `evidence.command` | **No** | - | **Gap: Should store** |
| `evidence.stdout` | **No** | - | **Gap: Should store** |
| `evidence.stderr` | **No** | - | **Gap: Should store** |
| `evidence.exit_code` | **No** | - | **Gap: Should store** |
| `evidence.expected` | **No** | - | **Gap: Should store** |
| `evidence.actual` | **No** | - | **Gap: Should store** |
| `framework_refs` | Partial | `scan_findings.framework_section` | Only stores one |

### Known Gaps (Planned Fixes)

1. **Full Evidence Storage**: Add `evidence JSONB` column to store complete Evidence object for audit compliance

2. **Multi-Framework Refs**: Change `framework_section VARCHAR` to `framework_refs JSONB` to store all framework mappings per rule

---

## Current Integration Implementation

### AEGIS Installation in OpenWatch

Currently bundled in `backend/aegis/` directory:

```
backend/
├── aegis/
│   ├── runner/      # AEGIS core engine
│   ├── rules/       # 338 YAML rules
│   ├── mappings/    # Framework mappings
│   └── config/      # defaults.yml
└── runner -> aegis/runner  # Symlink for imports
```

**Alternative (recommended by AEGIS team)**:
```bash
pip install "git+https://github.com/Hanalyx/aegis.git#egg=aegis[pdf]"
```

### API Endpoints Using AEGIS

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scans/aegis/` | POST | Trigger AEGIS scan |
| `/api/scans/aegis/compliance-state/{host_id}` | GET | Get current compliance state |
| `/api/scans/aegis/frameworks` | GET | List available frameworks |
| `/api/scans/aegis/health` | GET | AEGIS engine health check |
| `/api/rules/reference/` | GET | Browse AEGIS rules (UI) |
| `/api/rules/reference/{rule_id}` | GET | Rule details |

### AEGIS Features Used by OpenWatch

| Feature | Used? | Notes |
|---------|-------|-------|
| `check_rules_from_path()` | Yes | Primary scan function |
| `SSHSession` | Yes | Via credential bridge |
| `detect_capabilities()` | Yes | Capability-gated rules |
| `detect_platform()` | Yes | Platform detection |
| `evaluate_rule()` | Indirect | Via check_rules_from_path |
| `load_rules()` | Yes | For Rule Reference UI |
| `load_config()` | Yes | Variable resolution |
| Variable resolution | Yes | `{{ variable }}` templates |
| Framework mappings | Yes | For compliance reporting |
| Evidence collection | Partial | Storing detail only |
| Remediation | Not yet | Phase 4 planned |
| Rollback | Not yet | Phase 4 planned |

---

## What OpenWatch Needs from AEGIS

### Critical Dependencies

1. **Stable Python API**
   ```python
   # These imports must remain stable
   from runner.ssh import SSHSession
   from runner.detect import detect_capabilities, detect_platform
   from runner._orchestration import evaluate_rule
   from runner._loading import load_rules
   from aegis import check_rules_from_path
   ```

2. **Evidence Object Structure**
   ```python
   @dataclass
   class Evidence:
       method: str        # Handler name
       command: str       # Shell command
       stdout: str        # Raw output
       stderr: str        # Raw errors
       exit_code: int
       expected: str
       actual: str
       timestamp: datetime
   ```

3. **Result Object Structure**
   ```python
   @dataclass
   class CheckResult:
       rule_id: str
       title: str
       severity: str
       passed: bool
       skipped: bool
       skip_reason: Optional[str]
       detail: str
       evidence: Evidence
       framework_refs: Dict[str, str]  # {"cis_rhel9_v2": "5.1.12", ...}
   ```

4. **Framework Mappings**
   - CIS RHEL 9 v2.0.0 (cis-rhel9-v2.0.0)
   - STIG RHEL 9 V2R7 (stig-rhel9-v2r7)
   - NIST 800-53 R5 (nist-800-53-r5)
   - PCI-DSS v4.0 (pci-dss-v4.0)
   - FedRAMP Moderate (fedramp-moderate)

### Feature Requests for AEGIS

| Priority | Feature | OpenWatch Use Case |
|----------|---------|-------------------|
| P0 | Stable API contract | Avoid breaking changes |
| P1 | Full Evidence in all results | Audit compliance |
| P1 | Multi-framework refs per rule | Unified reporting |
| P2 | Remediation execution | Auto-fix findings |
| P2 | Rollback capability | Undo remediations |
| P3 | Delta scanning | Only check changed files |
| P3 | Parallel rule execution | Faster scans |

### API Stability Requirements

OpenWatch depends on these AEGIS APIs. Breaking changes require coordination:

```python
# CRITICAL - Used in production
check_rules_from_path(ssh, rules_path, severity=None, category=None)
SSHSession(hostname, user, password=None, key_filename=None, sudo=False)
detect_capabilities(ssh)
detect_platform(ssh)
load_rules(rules_path)
load_config(rules_path)

# IMPORTANT - Used for Rule Reference UI
rule.id, rule.title, rule.severity, rule.category
rule.description, rule.rationale, rule.remediation
rule.tags, rule.platforms, rule.variables
rule.framework_refs
```

---

## Future Integration Plans

### Phase 4: Remediation + Subscription (Planned)

```python
# OpenWatch will use AEGIS remediation
from aegis import remediate_rule, rollback_remediation

# Execute remediation
job = await remediate_rule(session, rule_id, dry_run=False)

# Track in OpenWatch
remediation_job = store_remediation_job(
    host_id=host_id,
    rule_id=rule_id,
    aegis_job_id=job.id,
    status="in_progress",
)

# Rollback if needed
await rollback_remediation(session, job.id)
```

### Phase 5: OTA Updates (Planned)

OpenWatch will support AEGIS rule updates without redeployment:

```python
# Check for rule updates
from aegis import check_for_updates, apply_updates

updates = await check_for_updates()
if updates.available:
    # OpenWatch+ license check
    if license.has_feature("priority_updates"):
        await apply_updates(updates)
```

### Evidence Storage Enhancement (Planned)

```sql
-- Future schema
ALTER TABLE scan_findings ADD COLUMN evidence JSONB;

-- Store full AEGIS evidence
UPDATE scan_findings SET evidence = '{
    "method": "config_value",
    "command": "grep -E ''^\\s*PermitRootLogin'' /etc/ssh/sshd_config",
    "stdout": "PermitRootLogin no\n",
    "stderr": "",
    "exit_code": 0,
    "expected": "no",
    "actual": "no",
    "timestamp": "2026-02-12T10:30:00Z"
}'::jsonb;
```

### Multi-Framework Storage Enhancement (Planned)

```sql
-- Future schema
ALTER TABLE scan_findings
    DROP COLUMN framework_section,
    ADD COLUMN framework_refs JSONB;

-- Store all framework mappings
UPDATE scan_findings SET framework_refs = '{
    "cis_rhel9_v2": "5.1.12",
    "stig_rhel9_v2r7": "V-257983",
    "nist_800_53": "AC-6, CM-6",
    "pci_dss_v4": "2.2.1"
}'::jsonb;
```

---

## API Contract and Stability

### Versioning Expectations

| AEGIS Version | OpenWatch Compatibility | Notes |
|---------------|------------------------|-------|
| 0.1.x | Full | Current production |
| 0.2.x | Expected compatible | Minor additions OK |
| 1.0.x | Review required | Potential breaking changes |

### Breaking Change Protocol

If AEGIS needs to make breaking changes:

1. **Notify OpenWatch team** with proposed changes
2. **Provide migration guide** for API changes
3. **Deprecation period**: Minimum 2 minor versions
4. **Version bump**: Major version for breaking changes

### Integration Testing

OpenWatch maintains integration tests for AEGIS:

```bash
# Run AEGIS integration tests
pytest backend/tests/integration/test_aegis_integration.py -v

# Test specific AEGIS features
pytest -k "test_aegis_scan" -v
pytest -k "test_aegis_evidence" -v
pytest -k "test_aegis_frameworks" -v
```

---

## Coordination Points

### Communication Channels

| Purpose | Channel |
|---------|---------|
| Breaking changes | GitHub issue + direct contact |
| Feature requests | GitHub issues |
| Bug reports | GitHub issues |
| Integration questions | GitHub discussions |

### Shared Repositories

| Repository | Purpose |
|------------|---------|
| `Hanalyx/aegis` | AEGIS engine |
| `Hanalyx/OpenWatch` | OpenWatch platform |

### Release Coordination

1. **AEGIS releases** should be tested against OpenWatch integration tests
2. **OpenWatch releases** should specify compatible AEGIS versions
3. **Joint testing** for major features (remediation, rollback)

### Documentation Sync

| Document | Owner | Sync |
|----------|-------|------|
| AEGIS Integration Guide (this doc) | OpenWatch | On OpenWatch changes |
| AEGIS API Reference | AEGIS | On AEGIS changes |
| Framework Mappings | AEGIS | On mapping updates |

---

## Summary

**AEGIS** is the pure measurement engine - SSH-based compliance checking with evidence collection.

**OpenWatch** is the Compliance Operating System - orchestration, storage, analysis, alerting, and user interface.

Together, they provide:
- Continuous compliance measurement (auto-scan)
- Auditable evidence (from AEGIS)
- Historical compliance queries (OpenWatch temporal)
- Exception management (OpenWatch governance)
- Actionable alerts (OpenWatch thresholds)
- Multi-framework reporting (AEGIS mappings + OpenWatch UI)

**The partnership**: AEGIS measures accurately. OpenWatch acts intelligently.

---

## Appendix: Quick Reference

### AEGIS Imports Used by OpenWatch

```python
# Primary scanning
from aegis import check_rules_from_path

# Session management
from runner.ssh import SSHSession

# Capability detection
from runner.detect import detect_capabilities, detect_platform

# Rule loading (for Rule Reference UI)
from runner._loading import load_rules, load_config

# Individual rule evaluation
from runner._orchestration import evaluate_rule
```

### OpenWatch Tables for AEGIS Data

| Table | Purpose |
|-------|---------|
| `scans` | Scan metadata (host, status, timestamps) |
| `scan_findings` | Per-rule results from AEGIS |
| `posture_snapshots` | Daily compliance snapshots |
| `compliance_exceptions` | Waived rules |
| `alerts` | Compliance alerts |
| `host_schedule` | Auto-scan scheduling |

### Key Configuration

```yaml
# OpenWatch AEGIS config (app/plugins/aegis/config.py)
aegis:
  rules_path: "aegis/rules/"
  max_concurrent_checks: 10
  default_timeout: 600  # seconds
  collect_evidence: true
  store_raw_output: false  # TODO: Enable for audit
```

---

**Document Version**: 1.0.0
**Last Updated**: 2026-02-12
**Next Review**: When AEGIS or OpenWatch major version changes
