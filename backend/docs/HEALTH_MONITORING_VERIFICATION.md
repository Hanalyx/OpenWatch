# Health Monitoring Schema Verification Guide

This guide provides step-by-step instructions to verify and test the MongoDB health monitoring schemas implementation.

## Overview

The health monitoring system consists of two main data types:
- **Service Health**: Operational monitoring (system resources, service status, performance)
- **Content Health**: Compliance effectiveness (rule coverage, framework implementation, content freshness)

## Prerequisites

1. MongoDB running and accessible
2. OpenWatch backend configured with MongoDB connection
3. Python environment with required dependencies

## Schema Structure

### Service Health Document
```
service_health
├── scanner_id (indexed)
├── health_check_timestamp
├── overall_status
├── uptime_seconds
├── core_services
│   ├── scanner_engine
│   ├── rule_processor
│   └── remediation_engine
├── data_services
│   ├── mongodb
│   └── redis
├── resource_usage
│   ├── system (CPU, memory)
│   └── storage
├── recent_operations
└── alerts
```

### Content Health Document
```
content_health
├── scanner_id (indexed)
├── health_check_timestamp
├── frameworks
│   ├── nist_800_53r5
│   ├── cis_controls_v8
│   └── [other frameworks]
├── benchmarks
│   ├── cis_rhel8_v2.0.0
│   └── [other benchmarks]
├── rule_statistics
├── content_integrity
├── performance_metrics
└── alerts_and_recommendations
```

## Verification Steps

### 1. Basic Connection Test

```bash
cd /home/rracine/hanalyx/openwatch/backend
python -m tests.test_health_monitoring
```

This will:
- Initialize MongoDB connection
- Create test health data
- Save to MongoDB
- Retrieve and verify data

### 2. API Endpoint Testing

Start the backend server:
```bash
cd /home/rracine/hanalyx/openwatch/backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Get authentication token:
```bash
# Login to get token
curl -X POST 'http://localhost:8000/api/auth/login' \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'

# Export token for subsequent requests
export TOKEN="<your-jwt-token>"
```

Test health monitoring endpoints:

```bash
# Get service health
curl -X GET 'http://localhost:8000/api/v1/health-monitoring/health/service' \
  -H "Authorization: Bearer $TOKEN" | jq .

# Get content health
curl -X GET 'http://localhost:8000/api/v1/health-monitoring/health/content' \
  -H "Authorization: Bearer $TOKEN" | jq .

# Get health summary
curl -X GET 'http://localhost:8000/api/v1/health-monitoring/health/summary' \
  -H "Authorization: Bearer $TOKEN" | jq .

# Force refresh all health data
curl -X POST 'http://localhost:8000/api/v1/health-monitoring/health/refresh' \
  -H "Authorization: Bearer $TOKEN" | jq .

# Get historical data (last 24 hours)
curl -X GET 'http://localhost:8000/api/v1/health-monitoring/health/history/service?hours=24' \
  -H "Authorization: Bearer $TOKEN" | jq .
```

### 3. MongoDB Direct Verification

Connect to MongoDB and verify collections:

```javascript
// Connect to MongoDB
use openwatch_rules

// Check collections
show collections
// Should include: service_health, content_health, health_summary

// Verify service health schema
db.service_health.findOne()

// Verify content health schema
db.content_health.findOne()

// Verify health summary
db.health_summary.findOne()

// Check indexes
db.service_health.getIndexes()
db.content_health.getIndexes()
db.health_summary.getIndexes()
```

### 4. Background Task Testing

If Celery is configured, verify scheduled tasks:

```bash
# Start Celery worker
celery -A app.celery_app worker --loglevel=info

# Start Celery beat (in another terminal)
celery -A app.celery_app beat --loglevel=info
```

Monitor logs for:
- `collect_service_health` task (every 5 minutes)
- `collect_content_health` task (every hour)
- `update_health_summary` task (every 5 minutes)
- `cleanup_old_health_data` task (daily at 2 AM)

### 5. Performance Testing

Test query performance:

```python
# Python script to test performance
import asyncio
from datetime import datetime, timedelta
from app.models.health_models import ServiceHealthDocument

async def test_performance():
    # Insert 1000 test documents
    start = datetime.utcnow()
    for i in range(1000):
        doc = ServiceHealthDocument(
            scanner_id="test_scanner",
            health_check_timestamp=start - timedelta(minutes=i*5),
            overall_status="healthy",
            uptime_seconds=i*300
        )
        await doc.save()

    # Test query performance
    query_start = datetime.utcnow()
    results = await ServiceHealthDocument.find(
        ServiceHealthDocument.scanner_id == "test_scanner",
        ServiceHealthDocument.health_check_timestamp >= start - timedelta(days=7)
    ).to_list()
    query_time = (datetime.utcnow() - query_start).total_seconds()

    print(f"Query returned {len(results)} documents in {query_time:.3f} seconds")
```

### 6. Schema Validation Testing

Test schema validation:

```python
# Test invalid data
from app.models.health_models import ServiceHealthDocument, HealthStatus

# This should fail validation (invalid percentage)
try:
    doc = ServiceHealthDocument(
        scanner_id="test",
        health_check_timestamp=datetime.utcnow(),
        overall_status=HealthStatus.HEALTHY,
        uptime_seconds=100,
        resource_usage={
            "system": {
                "memory_usage_percent": 150  # Invalid: > 100
            }
        }
    )
    await doc.save()
except Exception as e:
    print(f"Validation correctly failed: {e}")
```

## Expected Results

### Service Health Response
```json
{
  "scanner_id": "openwatch_hostname",
  "health_check_timestamp": "2025-09-14T12:30:00Z",
  "overall_status": "healthy",
  "uptime_seconds": 3600,
  "core_services": {
    "scanner_engine": {
      "status": "healthy",
      "version": "2.4.1",
      "memory_usage_mb": 256.7
    }
  },
  "resource_usage": {
    "system": {
      "memory_usage_percent": 54.4,
      "cpu_usage_percent": 23.4
    }
  }
}
```

### Content Health Response
```json
{
  "scanner_id": "openwatch_hostname",
  "health_check_timestamp": "2025-09-14T12:30:00Z",
  "frameworks": {
    "nist_800_53r5": {
      "version": "revision_5",
      "status": "active",
      "coverage_percentage": 89.2,
      "rule_count": 892
    }
  },
  "rule_statistics": {
    "summary": {
      "total_rules": 1567,
      "active_rules": 1523
    }
  }
}
```

## Troubleshooting

### MongoDB Connection Issues
```bash
# Check MongoDB is running
docker ps | grep mongo

# Test MongoDB connection
mongosh mongodb://localhost:27017/openwatch_rules --eval "db.stats()"
```

### Schema Not Found
```bash
# Ensure models are initialized
grep -r "ServiceHealthDocument" backend/app/
```

### API 404 Errors
```bash
# Verify routes are registered
curl http://localhost:8000/openapi.json | jq '.paths | keys | map(select(. | contains("health")))'
```

## Monitoring Best Practices

1. **Data Retention**: Configure cleanup task to maintain reasonable data volume
2. **Alert Thresholds**: Adjust alert generation logic based on your environment
3. **Collection Frequency**: Modify task schedules based on monitoring needs
4. **Index Optimization**: Add indexes for frequently queried fields
5. **Dashboard Integration**: Use health data for Grafana/Prometheus dashboards

## Next Steps

1. Configure Celery for automated collection
2. Set up alerting based on health metrics
3. Create dashboards for visualization
4. Implement custom health checks for your environment
5. Integrate with existing monitoring systems
