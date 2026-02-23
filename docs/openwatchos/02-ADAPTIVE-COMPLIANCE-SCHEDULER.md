# Adaptive Compliance Scheduler

**Status**: Implemented
**Last Updated**: 2026-02-18

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Compliance States and Intervals](#compliance-states-and-intervals)
4. [Configuration](#configuration)
5. [Database Schema](#database-schema)
6. [Celery Tasks](#celery-tasks)
7. [API Endpoints](#api-endpoints)
8. [Integration with Kensa and AlertGenerator](#integration-with-kensa-and-alertgenerator)
9. [Workflow Diagram](#workflow-diagram)
10. [Maintenance Mode](#maintenance-mode)
11. [Failure Handling](#failure-handling)
12. [Key Files](#key-files)

---

## Overview

The Adaptive Compliance Scheduler is a core component of the OpenWatch OS transformation. It replaces the manual, on-demand scanning model with an automatic, continuous compliance scanning system. Every active host in OpenWatch is scanned on a recurring schedule, with scan frequency adapting based on the host's current compliance posture.

The fundamental design principle is that hosts in worse compliance states are scanned more frequently, while compliant hosts are scanned less often. This approach concentrates scanning resources where they are most needed while guaranteeing that no host goes more than 48 hours without a compliance check.

### Design Goals

- **Continuous visibility**: Every host is scanned at least once every 48 hours (the maximum interval ceiling).
- **Adaptive intervals**: Low-compliance and critical hosts are scanned as often as every hour.
- **Resource awareness**: A configurable `max_concurrent_scans` setting prevents overloading scan workers.
- **Scalability**: Hosts are distributed across time rather than scanned in batch, preventing thundering herd problems.
- **Server intelligence**: Each scheduled scan also collects system information (packages, services, users, network, firewall, routes, audit events, and metrics).
- **Alert integration**: Scan results are automatically evaluated by the AlertGenerator to produce compliance alerts.

---

## Architecture

The scheduler uses a dispatcher pattern built on Celery Beat:

1. **Celery Beat** calls the `dispatch_compliance_scans` task every **120 seconds** (2 minutes).
2. The **dispatcher** queries the `host_schedule` table for hosts where `next_scheduled_scan <= NOW()`, up to the `max_concurrent_scans` limit (default: 5).
3. For each host due, the dispatcher sends an individual `run_scheduled_kensa_scan` task to the `compliance_scanning` Celery queue, with a priority derived from the host's compliance state.
4. Each scan task runs Kensa against the target host via SSH, stores results in the `scans`, `scan_results`, and `scan_findings` PostgreSQL tables, and then updates the `host_schedule` row with a new `next_scheduled_scan` time based on the resulting compliance score.

A separate Celery Beat task, `expire_compliance_maintenance`, runs hourly to automatically end expired maintenance windows.

```
                        Celery Beat
                            |
                   every 120 seconds
                            |
                            v
                +-----------------------+
                | dispatch_compliance_  |
                | scans (dispatcher)    |
                +-----------+-----------+
                            |
             query host_schedule WHERE
             next_scheduled_scan <= NOW()
             LIMIT max_concurrent_scans
                            |
               +------------+------------+
               |            |            |
               v            v            v
        +----------+  +----------+  +----------+
        | run_     |  | run_     |  | run_     |
        | scheduled|  | scheduled|  | scheduled|
        | kensa_   |  | kensa_   |  | kensa_   |
        | scan     |  | scan     |  | scan     |
        +----+-----+  +----------+  +----------+
             |
             v
     +----------------+
     | Kensa Scanner  |---> SSH ---> Target Host
     +-------+--------+
             |
     +-------v--------+
     | Store results:  |
     | scans           |
     | scan_results    |
     | scan_findings   |
     +-------+---------+
             |
     +-------v---------+
     | Update           |
     | host_schedule    |
     | (next_scan_time) |
     +-------+----------+
             |
     +-------v---------+
     | AlertGenerator   |
     | (process_scan_   |
     |  results)        |
     +------------------+
```

---

## Compliance States and Intervals

Compliance state is derived from the host's latest scan results (stored in the `scans` and `scan_results` tables). The state determines both the scan interval and the Celery task priority.

### State Determination Logic

The compliance state is calculated using the following rules, evaluated in order:

1. If no scan results exist for the host: **unknown**
2. If `severity_critical_failed > 0` OR `severity_high_failed > 0`: **critical**
3. If score = 100: **compliant**
4. If score >= 80: **mostly_compliant**
5. If score >= 50: **partial**
6. If score >= 20: **low**
7. If score < 20: **critical**

### Default Intervals and Priorities

| State | Score Range | Condition | Default Interval | Priority |
|---|---|---|---|---|
| unknown | N/A | Never scanned | Immediate (0 min) | 10 (highest) |
| critical | 0-19% | Score < 20 OR critical/high findings | 60 minutes (1 hour) | 9 |
| low | 20-49% | Score >= 20 and < 50 | 120 minutes (2 hours) | 7 |
| partial | 50-79% | Score >= 50 and < 80 | 360 minutes (6 hours) | 6 |
| mostly_compliant | 80-99% | Score >= 80 and < 100 | 720 minutes (12 hours) | 4 |
| compliant | 100% | Score = 100, no critical findings | 1440 minutes (24 hours) | 3 |
| maintenance | N/A | Maintenance mode enabled | 2880 minutes (48 hours) | 1 (lowest) |

All intervals are capped at the `max_interval_minutes` ceiling, which defaults to **2880 minutes (48 hours)**.

Priority values range from 1 (lowest) to 10 (highest). Higher priority tasks are picked up first by Celery workers when multiple scans are queued.

---

## Configuration

The scheduler's configuration is stored in the `compliance_scheduler_config` PostgreSQL table as a singleton row (id=1). All fields have server defaults and can be modified at runtime through the API.

### Default Configuration

| Setting | Default Value | Description |
|---|---|---|
| `enabled` | `true` | Whether the scheduler dispatches scans |
| `interval_compliant` | 1440 (24h) | Minutes between scans for compliant hosts |
| `interval_mostly_compliant` | 720 (12h) | Minutes between scans for mostly compliant hosts |
| `interval_partial` | 360 (6h) | Minutes between scans for partially compliant hosts |
| `interval_low` | 120 (2h) | Minutes between scans for low compliance hosts |
| `interval_critical` | 60 (1h) | Minutes between scans for critical hosts |
| `interval_unknown` | 0 (immediate) | Minutes between scans for never-scanned hosts |
| `interval_maintenance` | 2880 (48h) | Interval for hosts in maintenance mode |
| `max_interval_minutes` | 2880 (48h) | Hard ceiling on all intervals |
| `max_concurrent_scans` | 5 | Maximum scans dispatched per cycle |
| `scan_timeout_seconds` | 600 (10 min) | Timeout for individual scan tasks |

### Priority Defaults

| Setting | Default Value |
|---|---|
| `priority_compliant` | 3 |
| `priority_mostly_compliant` | 4 |
| `priority_partial` | 6 |
| `priority_low` | 7 |
| `priority_critical` | 9 |
| `priority_unknown` | 10 |
| `priority_maintenance` | 1 |

### Configuration Caching

The `ComplianceSchedulerService` caches the configuration in memory with a TTL of **60 seconds**. This avoids querying the database on every dispatcher cycle. The cache is invalidated when configuration is updated through the API.

---

## Database Schema

### `host_schedule` Table

Originally created as `host_compliance_schedule` (migration `026`), then renamed to `host_schedule` (migration `032`). Compliance data columns (score, state, pass/fail counts) were removed in the rename migration because compliance data is now sourced from the `scans` and `scan_results` tables as the single source of truth.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | UUID | NOT NULL | `gen_random_uuid()` | Primary key |
| `host_id` | UUID (FK -> hosts.id) | NOT NULL | -- | One-to-one with hosts (UNIQUE) |
| `current_interval_minutes` | INTEGER | NOT NULL | 1440 | Current scan interval in minutes |
| `next_scheduled_scan` | TIMESTAMP WITH TIME ZONE | YES | NULL | When the next scan should run |
| `last_scan_completed` | TIMESTAMP WITH TIME ZONE | YES | NULL | When the last scan finished |
| `last_scan_id` | UUID | YES | NULL | ID of the most recent completed scan |
| `maintenance_mode` | BOOLEAN | NOT NULL | false | Whether host is in maintenance |
| `maintenance_until` | TIMESTAMP WITH TIME ZONE | YES | NULL | Auto-expiry time for maintenance |
| `scan_priority` | INTEGER | NOT NULL | 5 | Celery task priority (1-10) |
| `consecutive_scan_failures` | INTEGER | NOT NULL | 0 | Count of consecutive failures |
| `created_at` | TIMESTAMP WITH TIME ZONE | NOT NULL | `CURRENT_TIMESTAMP` | Row creation time |
| `updated_at` | TIMESTAMP WITH TIME ZONE | NOT NULL | `CURRENT_TIMESTAMP` | Last update time |

**Indexes**:

| Index Name | Columns | Condition |
|---|---|---|
| `ix_host_schedule_next_scan` | `next_scheduled_scan` | `WHERE maintenance_mode = false` |
| `ix_host_schedule_priority` | `scan_priority` | -- |

**Constraint**: `host_id` has a UNIQUE constraint enforcing one schedule row per host. The `ON DELETE CASCADE` foreign key ensures schedule rows are removed when a host is deleted.

### `compliance_scheduler_config` Table

Singleton configuration table with a single row (id=1).

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | INTEGER | NOT NULL | -- | Primary key (always 1) |
| `enabled` | BOOLEAN | NOT NULL | true | Master enable/disable switch |
| `interval_compliant` | INTEGER | NOT NULL | 1440 | Interval for compliant state (minutes) |
| `interval_mostly_compliant` | INTEGER | NOT NULL | 720 | Interval for mostly_compliant state |
| `interval_partial` | INTEGER | NOT NULL | 360 | Interval for partial state |
| `interval_low` | INTEGER | NOT NULL | 120 | Interval for low state |
| `interval_critical` | INTEGER | NOT NULL | 60 | Interval for critical state |
| `interval_unknown` | INTEGER | NOT NULL | 0 | Interval for unknown state |
| `interval_maintenance` | INTEGER | NOT NULL | 2880 | Interval for maintenance state |
| `max_interval_minutes` | INTEGER | NOT NULL | 2880 | Hard ceiling on all intervals |
| `priority_compliant` | INTEGER | NOT NULL | 3 | Celery priority for compliant |
| `priority_mostly_compliant` | INTEGER | NOT NULL | 4 | Celery priority for mostly_compliant |
| `priority_partial` | INTEGER | NOT NULL | 6 | Celery priority for partial |
| `priority_low` | INTEGER | NOT NULL | 7 | Celery priority for low |
| `priority_critical` | INTEGER | NOT NULL | 9 | Celery priority for critical |
| `priority_unknown` | INTEGER | NOT NULL | 10 | Celery priority for unknown |
| `priority_maintenance` | INTEGER | NOT NULL | 1 | Celery priority for maintenance |
| `max_concurrent_scans` | INTEGER | NOT NULL | 5 | Max scans per dispatcher cycle |
| `scan_timeout_seconds` | INTEGER | NOT NULL | 600 | Per-scan timeout |
| `updated_at` | TIMESTAMP WITH TIME ZONE | NOT NULL | `CURRENT_TIMESTAMP` | Last config change |

---

## Celery Tasks

All scheduler tasks are defined in `backend/app/tasks/compliance_scheduler_tasks.py` and routed to the `compliance_scanning` queue.

### dispatch_compliance_scans

- **Task name**: `app.tasks.dispatch_compliance_scans`
- **Schedule**: Every 120 seconds (2 minutes) via Celery Beat
- **Time limit**: 120 seconds hard / 90 seconds soft
- **Queue**: `compliance_scanning`
- **Beat priority**: 8

Queries `host_schedule` for hosts where `next_scheduled_scan <= NOW()`, excludes hosts in maintenance mode and inactive/down hosts. Results are ordered by `scan_priority DESC, next_scheduled_scan ASC NULLS FIRST`, limited to `max_concurrent_scans`. For each host, it dispatches a `run_scheduled_kensa_scan` task to the `compliance_scanning` queue.

If the scheduler is disabled (`enabled = false` in config), the task returns immediately without dispatching any scans.

### run_scheduled_kensa_scan

- **Task name**: `app.tasks.run_scheduled_kensa_scan`
- **Schedule**: On-demand (dispatched by the dispatcher)
- **Time limit**: 660 seconds hard (11 minutes) / 600 seconds soft (10 minutes)
- **Queue**: `compliance_scanning`
- **Arguments**: `host_id` (str), `priority` (int, default 5)

Executes a full Kensa compliance scan for a single host. The task performs the following steps in order:

1. Creates a scan record in the `scans` table with status `running` and `scan_options` set to `{"scanner": "kensa", "source": "scheduler"}`.
2. Initializes the KensaScanner and runs the scan with full server intelligence collection enabled (system info, packages, services, users, network, firewall, routes, audit events, metrics).
3. On completion, inserts results into `scan_results` (summary with severity breakdown) and `scan_findings` (individual rule results).
4. Saves server intelligence data via `SystemInfoService` and syncs OS information back to the `hosts` table.
5. Calls `compliance_scheduler_service.update_host_schedule()` to compute the next scan time based on the new compliance score.
6. Calls `AlertGenerator.process_scan_results()` to generate any compliance alerts triggered by the scan.

On failure, the task updates the scan record to `failed` status and calls `record_scan_failure()` to schedule a retry in 5 minutes.

### initialize_compliance_schedules

- **Task name**: `app.tasks.initialize_compliance_schedules`
- **Schedule**: On-demand (triggered via API)
- **Time limit**: 300 seconds hard / 240 seconds soft
- **Queue**: `compliance_scanning`

Bootstrap task that creates `host_schedule` rows for all active hosts that do not already have one. Each new row is initialized with `scan_priority = 10` and `next_scheduled_scan = NOW()`, meaning the host will be picked up for scanning on the next dispatcher cycle. This task should be run once after deploying the scheduler to an existing environment.

### expire_compliance_maintenance

- **Task name**: `app.tasks.expire_compliance_maintenance`
- **Schedule**: Hourly via Celery Beat (`crontab(minute=0)`)
- **Time limit**: 60 seconds hard / 45 seconds soft
- **Queue**: `compliance_scanning`

Finds all hosts where `maintenance_mode = true` AND `maintenance_until < NOW()`, sets their `maintenance_mode` to `false` and clears `maintenance_until`. This enables automatic expiry of time-bounded maintenance windows.

---

## API Endpoints

All endpoints are mounted under `/api/compliance/scheduler/`. The scheduler router uses the `compliance-scheduler` tag.

### Configuration

| Method | Path | Description | Required Role |
|---|---|---|---|
| `GET` | `/api/compliance/scheduler/config` | Get current scheduler configuration (intervals, priorities, concurrency) | GUEST and above |
| `PUT` | `/api/compliance/scheduler/config` | Update scheduler configuration (partial updates supported) | SECURITY_ADMIN, SUPER_ADMIN |
| `POST` | `/api/compliance/scheduler/toggle?enabled={bool}` | Enable or disable the scheduler | SECURITY_ADMIN, SUPER_ADMIN |

**PUT /config request body** (`SchedulerConfigUpdate`):

| Field | Type | Constraints | Description |
|---|---|---|---|
| `enabled` | bool (optional) | -- | Enable/disable scheduler |
| `interval_compliant` | int (optional) | 60-2880 | Minutes for compliant state |
| `interval_mostly_compliant` | int (optional) | 30-2880 | Minutes for mostly_compliant state |
| `interval_partial` | int (optional) | 30-2880 | Minutes for partial state |
| `interval_low` | int (optional) | 30-2880 | Minutes for low state |
| `interval_critical` | int (optional) | 15-2880 | Minutes for critical state |
| `interval_unknown` | int (optional) | 0-2880 | Minutes for unknown state |
| `max_concurrent_scans` | int (optional) | 1-20 | Max concurrent scans |
| `scan_timeout_seconds` | int (optional) | 60-3600 | Per-scan timeout in seconds |

### Status and Monitoring

| Method | Path | Description | Required Role |
|---|---|---|---|
| `GET` | `/api/compliance/scheduler/status` | Scheduler status: host counts by state, overdue scans, upcoming scans | GUEST and above |
| `GET` | `/api/compliance/scheduler/hosts-due?limit={n}` | List hosts currently due for scanning (default limit: 10) | GUEST and above |

### Per-Host Schedule

| Method | Path | Description | Required Role |
|---|---|---|---|
| `GET` | `/api/compliance/scheduler/hosts/{host_id}` | Get schedule details for a specific host, including compliance data from latest scan | GUEST and above |
| `PUT` | `/api/compliance/scheduler/hosts/{host_id}/maintenance` | Set or clear maintenance mode for a host | SECURITY_ANALYST and above |
| `POST` | `/api/compliance/scheduler/hosts/{host_id}/force-scan` | Force an immediate scan (bypasses schedule, priority 10) | SECURITY_ANALYST and above |

**PUT /hosts/{host_id}/maintenance request body** (`MaintenanceModeRequest`):

| Field | Type | Constraints | Description |
|---|---|---|---|
| `enabled` | bool | required | Enable or disable maintenance mode |
| `duration_hours` | int (optional) | 1-168 (max 1 week) | Auto-expiry duration in hours |

### Initialization

| Method | Path | Description | Required Role |
|---|---|---|---|
| `POST` | `/api/compliance/scheduler/initialize` | Bootstrap schedules for all hosts without one (queues Celery task) | SECURITY_ADMIN, SUPER_ADMIN |

---

## Integration with Kensa and AlertGenerator

### Kensa Scanner Integration

Each scheduled scan uses the `KensaScanner` class from `app.plugins.kensa.scanner`. The scanner is initialized and executed asynchronously. The task enables full server intelligence collection by passing the following flags:

- `collect_system_info=True`
- `collect_packages=True`
- `collect_services=True`
- `collect_users=True`
- `collect_network=True`
- `collect_firewall=True`
- `collect_routes=True`
- `collect_audit_events=True`
- `collect_metrics=True`

Server intelligence data is saved via `SystemInfoService` into the `host_packages`, `host_services`, `host_users`, `host_network`, and related tables. The host's `operating_system` and `os_version` columns in the `hosts` table are also synced from the collected system info.

Scan results are stored in the standard `scans`, `scan_results`, and `scan_findings` tables, maintaining full compatibility with the existing frontend scan views.

### AlertGenerator Integration

After each successful scan, the task calls `AlertGenerator.process_scan_results()` with the following data:

- `host_id`: UUID of the scanned host
- `compliance_score`: The scan's compliance percentage
- `passed` / `failed`: Rule pass/fail counts
- `results`: Full list of individual rule results
- `hostname`: Display name for alert messages

The AlertGenerator evaluates the results against configured thresholds and creates alerts for conditions such as critical findings, score drops, non-compliance, and degrading trends. The number of alerts generated is logged and returned in the task result.

---

## Workflow Diagram

### Scan Lifecycle

```
Host added to OpenWatch
        |
        v
initialize_compliance_schedules
(or automatic on host creation)
        |
        v
host_schedule row created
  next_scheduled_scan = NOW()
  scan_priority = 10 (unknown)
        |
        v
+---> dispatch_compliance_scans (every 2 min)
|       |
|       v
|     Query: next_scheduled_scan <= NOW()
|     AND maintenance_mode = false
|     AND host is_active = true
|     AND host status != 'down'
|     ORDER BY priority DESC, next_scan ASC
|     LIMIT max_concurrent_scans
|       |
|       v
|     run_scheduled_kensa_scan (per host)
|       |
|       +---> Kensa SSH scan + server intelligence
|       |
|       +---> Store results in scans/scan_results/scan_findings
|       |
|       +---> Update host_schedule:
|       |       - current_interval_minutes = f(score)
|       |       - next_scheduled_scan = NOW() + interval
|       |       - scan_priority = f(state)
|       |       - consecutive_scan_failures = 0
|       |
|       +---> AlertGenerator.process_scan_results()
|       |
|       v
+--- Wait for next_scheduled_scan to arrive
```

### Failure Recovery

```
run_scheduled_kensa_scan
        |
     [ERROR]
        |
        v
  Update scan record: status = 'failed'
        |
        v
  record_scan_failure():
    - consecutive_scan_failures += 1
    - next_scheduled_scan = NOW() + 5 minutes
        |
        v
  Host retried on next dispatcher cycle
  (after 5-minute wait)
```

---

## Maintenance Mode

Maintenance mode prevents a host from being scanned by the scheduler. It can be enabled with an optional auto-expiry duration.

### Setting Maintenance Mode

Use the `PUT /api/compliance/scheduler/hosts/{host_id}/maintenance` endpoint:

```json
{
    "enabled": true,
    "duration_hours": 4
}
```

The `duration_hours` field sets `maintenance_until` to `NOW() + duration_hours`. If omitted, maintenance mode stays active indefinitely until manually disabled.

### Automatic Expiry

The `expire_compliance_maintenance` Celery Beat task runs every hour and clears maintenance mode for any host where `maintenance_until < NOW()`. This ensures maintenance windows do not persist beyond their intended duration.

### Disabling Maintenance Mode

```json
{
    "enabled": false
}
```

When maintenance mode is disabled, the host becomes eligible for scanning on the next dispatcher cycle.

---

## Failure Handling

When a scheduled scan fails (Kensa error, SSH connection failure, timeout, etc.):

1. The scan record in the `scans` table is updated to `status = 'failed'` with the error message (truncated to 500 characters).
2. The `record_scan_failure()` method increments `consecutive_scan_failures` on the `host_schedule` row.
3. The `next_scheduled_scan` is set to **5 minutes** from the current time, allowing a quick retry without waiting for the full interval.
4. On the next dispatcher cycle (within 2 minutes of the retry time), the host will be picked up again for scanning.

The `consecutive_scan_failures` counter is reset to 0 on any successful scan completion.

---

## Key Files

| File | Purpose |
|---|---|
| `backend/app/services/compliance/compliance_scheduler.py` | ComplianceSchedulerService: config management, state calculation, interval logic, host schedule CRUD |
| `backend/app/tasks/compliance_scheduler_tasks.py` | Celery tasks: dispatcher, scan executor, schedule initializer, maintenance expiry |
| `backend/app/routes/compliance/scheduler.py` | API endpoints: config, status, per-host schedule, maintenance, force-scan, initialization |
| `backend/app/celery_app.py` | Celery Beat schedule definitions and queue configuration |
| `backend/alembic/versions/20260209_2200_026_add_compliance_scheduler_tables.py` | Initial migration: host_compliance_schedule and compliance_scheduler_config tables |
| `backend/alembic/versions/20260210_0600_032_rename_host_compliance_schedule.py` | Rename migration: host_compliance_schedule -> host_schedule, remove compliance cache columns |
