# Scheduler API Endpoints

The scheduler endpoints manage the automatic host monitoring functionality in OpenWatch.

## Endpoints

### GET /api/system/scheduler
Get the current scheduler status and configuration.

**Response:**
```json
{
  "enabled": true,
  "interval_minutes": 5,
  "status": "running",
  "jobs": [
    {
      "id": "host_monitoring",
      "name": "Host Monitoring Task",
      "next_run": "2025-08-31T18:24:14.413111+00:00",
      "trigger": "interval[0:05:00]"
    }
  ],
  "uptime": "Running"
}
```

### POST /api/system/scheduler/start
Start the host monitoring scheduler with a specified interval.

**Request Body:**
```json
{
  "interval_minutes": 10
}
```

**Response:**
```json
{
  "message": "Scheduler started successfully",
  "status": "running",
  "interval_minutes": 10
}
```

### POST /api/system/scheduler/stop
Stop the host monitoring scheduler.

**Response:**
```json
{
  "message": "Scheduler stopped successfully",
  "status": "stopped"
}
```

### PUT /api/system/scheduler
Update the scheduler interval while it's running.

**Request Body:**
```json
{
  "interval_minutes": 15
}
```

**Response:**
```json
{
  "message": "Scheduler interval updated to 15 minutes",
  "interval_minutes": 15,
  "status": "running"
}
```

## Authentication

All scheduler endpoints require:
- JWT Bearer token authentication
- `SYSTEM_MAINTENANCE` permission

## Notes

- The scheduler runs the `periodic_host_monitoring` task at the specified interval
- Valid interval range: 1-1440 minutes (1 minute to 24 hours)
- The scheduler state persists across application restarts
- When the interval is updated, existing jobs are rescheduled with the new interval

Last updated: 2025-08-31