# Alert Thresholds

**Status**: Complete (PR #281)

The alert system generates actionable notifications when compliance posture degrades, operational issues arise, or exceptions require attention.

## Architecture

```
Kensa Scan Completes
       |
       v
AlertGenerator.process_scan_results()
       |
       +-- Check critical findings
       +-- Check high findings
       +-- Check score drop
       +-- Check non-compliance threshold
       +-- Check degrading trend
       |
       v
AlertService.create_alert()
       |
       +-- Deduplication check (same host + rule + type)
       +-- If duplicate exists: skip
       +-- If new: insert into compliance_alerts table
```

## Alert Types

### Compliance Alerts

| Type | Trigger | Default Severity |
|------|---------|-----------------|
| `critical_finding` | Scan finds a rule with severity=critical that fails | Critical |
| `high_finding` | Scan finds a rule with severity=high that fails | High |
| `score_drop` | Compliance score drops by threshold within window | High |
| `non_compliant` | Compliance score below threshold | Medium |
| `degrading_trend` | Consecutive scans with declining scores | Medium |

### Operational Alerts

| Type | Trigger | Default Severity |
|------|---------|-----------------|
| `host_unreachable` | Consecutive failed SSH connection attempts | Critical |
| `scan_failed` | Scan execution fails | High |
| `scheduler_stopped` | Compliance scheduler is disabled | Medium |
| `scan_backlog` | Too many scans queued beyond age threshold | Medium |
| `host_not_scanned` | Host has not been scanned within max age | Medium |

### Exception Alerts

| Type | Trigger | Default Severity |
|------|---------|-----------------|
| `exception_expiring` | Exception within warning window of expiry | Low |
| `exception_expired` | Exception has expired | Medium |
| `exception_requested` | New exception requires approval | Info |

### Drift Alerts

| Type | Trigger | Default Severity |
|------|---------|-----------------|
| `configuration_drift` | Host configuration changed between scans | Medium |
| `unexpected_remediation` | Rule status changed without documented action | Low |
| `mass_drift` | Many hosts drifted simultaneously | High |

## Alert Lifecycle

```
ACTIVE  -->  ACKNOWLEDGED  -->  RESOLVED
  |                                 ^
  +--- (auto-resolve on next clean scan) ---+
```

- **Active**: Alert is new and requires attention
- **Acknowledged**: Operator has seen the alert and is working on it
- **Resolved**: Issue has been fixed or is no longer relevant

## Default Thresholds

```python
DEFAULT_THRESHOLDS = {
    "compliance": {
        "critical_finding": True,       # Alert on critical rule failures
        "high_finding": True,           # Alert on high rule failures
        "medium_finding": False,        # Do not alert on medium (too noisy)
        "low_finding": False,           # Do not alert on low
        "score_drop_threshold": 20,     # Alert if score drops 20+ points
        "score_drop_window_hours": 24,  # Within a 24-hour window
        "non_compliant_threshold": 80,  # Below 80% = non-compliant alert
        "degrading_trend_scans": 3,     # 3 consecutive declining scans
    },
    "operational": {
        "unreachable_checks": 3,        # 3 consecutive failures = alert
        "max_scan_age_hours": 48,       # No scan in 48h = alert
        "scan_queue_threshold": 20,     # 20+ queued scans = alert
        "scan_queue_age_minutes": 60,   # Queue items older than 1h
    },
    "exceptions": {
        "expiry_warning_days": 7,       # Warn 7 days before exception expires
    },
    "drift": {
        "mass_drift_threshold": 10,     # 10+ hosts drifted = mass drift
    },
}
```

Thresholds can be overridden per-host via `alert_settings` table.

## Deduplication

The `AlertGenerator` prevents alert storms by checking for existing active alerts before creating new ones. A new alert is suppressed if an active alert already exists for the same:
- `host_id`
- `rule_id` (for finding-based alerts)
- `alert_type`

## API Endpoints

All endpoints are under `/api/compliance/alerts`.

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/alerts` | List alerts (paginated, filterable) | Any user |
| GET | `/alerts/stats` | Alert statistics summary | Any user |
| GET | `/alerts/{id}` | Get alert by ID | Any user |
| POST | `/alerts/{id}/acknowledge` | Acknowledge alert | Any user |
| POST | `/alerts/{id}/resolve` | Resolve alert | Any user |
| GET | `/alerts/thresholds` | Get threshold configuration | Any user |
| PUT | `/alerts/thresholds` | Update thresholds | Admin only |

### Query Parameters for List

| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | int (>= 1) | Page number |
| `per_page` | int (1-100) | Items per page (default 20) |
| `status` | string | Filter: active, acknowledged, resolved |
| `severity` | string | Filter: critical, high, medium, low, info |
| `alert_type` | string | Filter by alert type |
| `host_id` | UUID | Filter by host |

### Statistics Response

```json
{
    "total_active": 12,
    "total_acknowledged": 5,
    "total_resolved": 230,
    "by_severity": {"critical": 2, "high": 5, "medium": 4, "low": 1},
    "by_type": {"critical_finding": 2, "score_drop": 3, "host_unreachable": 1},
    "recent_24h": 8
}
```

## Integration Points

- **Compliance Scheduler**: `AlertGenerator.process_scan_results()` is called after each scheduled Kensa scan completes
- **Exception Service**: Celery tasks check for expiring/expired exceptions and generate alerts
- **Temporal Compliance**: Score drop detection uses posture snapshot history

## Key Files

| File | Purpose |
|------|---------|
| `backend/app/services/compliance/alerts.py` | AlertService, AlertType/Severity/Status enums, DEFAULT_THRESHOLDS |
| `backend/app/services/compliance/alert_generator.py` | AlertGenerator -- processes scan results |
| `backend/app/routes/compliance/alerts.py` | API endpoints |
| `backend/app/schemas/alert_schemas.py` | Pydantic request/response models |
