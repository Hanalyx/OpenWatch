# Phase 2 Testing Plan: Baseline & Drift Detection

**Date**: 2025-11-15
**Status**: Ready for Testing
**Test Environment**: Docker containers (all healthy)

---

## Testing Strategy

### Test Levels
1. **Backend Unit Tests**: Service logic validation
2. **API Integration Tests**: Endpoint functionality and security
3. **Database Tests**: Schema validation and constraints
4. **Frontend Component Tests**: UI functionality
5. **End-to-End Tests**: Complete workflow validation

---

## Pre-Test Verification

### Environment Status
```bash
# Verify all containers running
docker ps --filter "name=openwatch"

# Check database migration applied
docker exec openwatch-db psql -U openwatch -d openwatch -c "\d scan_baselines"
docker exec openwatch-db psql -U openwatch -d openwatch -c "\d scan_drift_events"

# Verify backend service healthy
curl http://localhost:8000/health
```

### Test Data Setup
1. At least 1 host with UUID
2. At least 2 completed scans for the host
3. Test user with `scan_manager` role
4. JWT token for authentication

---

## Test Cases

### 1. Database Schema Tests

#### Test 1.1: Verify scan_baselines Table
```sql
-- Check table structure
\d scan_baselines

-- Expected:
-- ✓ 24 columns total
-- ✓ id (UUID primary key)
-- ✓ host_id (UUID foreign key to hosts)
-- ✓ established_by (INTEGER foreign key to users)
-- ✓ 8 per-severity columns (baseline_critical_passed, etc.)
-- ✓ drift_threshold_major (default 10.0)
-- ✓ drift_threshold_minor (default 5.0)
-- ✓ is_active (boolean, default true)

-- Check indexes
\di scan_baselines*

-- Expected:
-- ✓ idx_scan_baselines_host_active
-- ✓ idx_scan_baselines_type
-- ✓ unique_active_baseline (EXCLUDE constraint)
```

#### Test 1.2: Verify scan_drift_events Table
```sql
-- Check table structure
\d scan_drift_events

-- Expected:
-- ✓ 18 columns total
-- ✓ drift_type with CHECK constraint
-- ✓ 8 per-severity delta columns
-- ✓ detected_at timestamp

-- Check constraints
SELECT conname, pg_get_constraintdef(oid)
FROM pg_constraint
WHERE conrelid = 'scan_drift_events'::regclass;

-- Expected:
-- ✓ valid_drift_type CHECK (drift_type IN ('major', 'minor', 'improvement', 'stable'))
```

#### Test 1.3: Test EXCLUDE Constraint
```sql
-- Test: Only one active baseline per host allowed
-- Should succeed
INSERT INTO scan_baselines (id, host_id, baseline_type, baseline_score,
  baseline_passed_rules, baseline_failed_rules, baseline_total_rules, is_active)
VALUES (gen_random_uuid(), '<test_host_id>', 'manual', 85.0, 85, 15, 100, true);

-- Should FAIL (duplicate active baseline for same host)
INSERT INTO scan_baselines (id, host_id, baseline_type, baseline_score,
  baseline_passed_rules, baseline_failed_rules, baseline_total_rules, is_active)
VALUES (gen_random_uuid(), '<same_host_id>', 'manual', 90.0, 90, 10, 100, true);

-- Clean up
DELETE FROM scan_baselines WHERE host_id = '<test_host_id>';
```

---

### 2. Backend Service Tests

#### Test 2.1: BaselineService.establish_baseline()
```python
# Test file: backend/tests/unit/test_baseline_service.py

import pytest
from uuid import uuid4
from backend.app.services.baseline_service import BaselineService
from backend.app.database import ScanBaseline

def test_establish_baseline_success(db_session, test_host, test_scan):
    """Test baseline establishment from valid scan"""
    service = BaselineService()

    baseline = service.establish_baseline(
        db=db_session,
        host_id=test_host.id,
        scan_id=test_scan.id,
        baseline_type="manual",
        established_by=1  # Admin user
    )

    assert baseline.id is not None
    assert baseline.host_id == test_host.id
    assert baseline.baseline_type == "manual"
    assert baseline.is_active == True
    assert baseline.baseline_score > 0
    assert baseline.baseline_total_rules > 0

def test_establish_baseline_supersedes_old(db_session, test_host, test_scan, existing_baseline):
    """Test new baseline supersedes existing active baseline"""
    service = BaselineService()

    new_baseline = service.establish_baseline(
        db=db_session,
        host_id=test_host.id,
        scan_id=test_scan.id,
        baseline_type="manual"
    )

    # Refresh old baseline
    db_session.refresh(existing_baseline)

    assert existing_baseline.is_active == False
    assert existing_baseline.superseded_by == new_baseline.id
    assert existing_baseline.superseded_at is not None
    assert new_baseline.is_active == True

def test_establish_baseline_invalid_scan(db_session, test_host):
    """Test baseline fails with non-existent scan"""
    service = BaselineService()

    with pytest.raises(ValueError, match="Scan .* not found"):
        service.establish_baseline(
            db=db_session,
            host_id=test_host.id,
            scan_id=uuid4(),  # Non-existent scan
            baseline_type="manual"
        )
```

#### Test 2.2: DriftDetectionService.detect_drift()
```python
# Test file: backend/tests/unit/test_drift_detection_service.py

import pytest
from backend.app.services.drift_detection_service import DriftDetectionService

def test_detect_major_drift(db_session, test_host, baseline_90pct, scan_75pct):
    """Test major drift detection (>10pp drop)"""
    service = DriftDetectionService()

    drift_event = service.detect_drift(
        db=db_session,
        host_id=test_host.id,
        scan_id=scan_75pct.id
    )

    assert drift_event is not None
    assert drift_event.drift_type == "major"
    assert drift_event.baseline_score == 90.0
    assert drift_event.current_score == 75.0
    assert drift_event.score_delta == -15.0
    assert drift_event.drift_magnitude == 15.0

def test_detect_minor_drift(db_session, test_host, baseline_90pct, scan_83pct):
    """Test minor drift detection (5-10pp drop)"""
    service = DriftDetectionService()

    drift_event = service.detect_drift(
        db=db_session,
        host_id=test_host.id,
        scan_id=scan_83pct.id
    )

    assert drift_event is not None
    assert drift_event.drift_type == "minor"
    assert drift_event.score_delta == -7.0

def test_detect_improvement(db_session, test_host, baseline_80pct, scan_90pct):
    """Test improvement detection (>5pp increase)"""
    service = DriftDetectionService()

    drift_event = service.detect_drift(
        db=db_session,
        host_id=test_host.id,
        scan_id=scan_90pct.id
    )

    assert drift_event is not None
    assert drift_event.drift_type == "improvement"
    assert drift_event.score_delta == 10.0

def test_detect_stable_no_event(db_session, test_host, baseline_85pct, scan_87pct):
    """Test stable compliance (no drift event created)"""
    service = DriftDetectionService()

    drift_event = service.detect_drift(
        db=db_session,
        host_id=test_host.id,
        scan_id=scan_87pct.id
    )

    assert drift_event is None  # No event for stable (<5pp change)

def test_no_baseline_no_drift(db_session, test_host_no_baseline, test_scan):
    """Test no drift detection when no baseline exists"""
    service = DriftDetectionService()

    drift_event = service.detect_drift(
        db=db_session,
        host_id=test_host_no_baseline.id,
        scan_id=test_scan.id
    )

    assert drift_event is None
```

#### Test 2.3: UnifiedAlertService.dispatch_alert()
```python
# Test file: backend/tests/unit/test_unified_alert_service.py

import pytest
from unittest.mock import Mock, patch
from backend.app.services.unified_alert_service import UnifiedAlertService

def test_dispatch_compliance_drift_alert(db_session, test_host, mock_webhook):
    """Test compliance drift alert dispatching"""
    service = UnifiedAlertService()

    with patch('requests.post') as mock_post:
        mock_post.return_value.status_code = 200

        success = service.dispatch_compliance_drift_alert(
            db=db_session,
            host_id=test_host.id,
            drift_type="major",
            baseline_score=90.0,
            current_score=75.0,
            score_delta=-15.0,
            scan_id=uuid4()
        )

        assert success == True
        assert mock_post.called

        # Verify webhook payload
        call_args = mock_post.call_args
        payload = call_args[1]['json']
        assert payload['alert_type'] == 'compliance_drift_major'
        assert payload['severity'] == 'high'
        assert payload['details']['score_delta'] == -15.0

def test_alert_disabled_no_dispatch(db_session, test_host):
    """Test alert not dispatched when disabled"""
    service = UnifiedAlertService()

    # Disable all drift alerts
    db_session.execute(
        text("UPDATE alert_settings SET compliance_drift_major_enabled = false")
    )
    db_session.commit()

    success = service.dispatch_alert(
        db=db_session,
        alert_type="compliance_drift_major",
        host_id=test_host.id,
        details={}
    )

    assert success == False  # Not dispatched (disabled)
```

---

### 3. API Endpoint Tests

#### Test 3.1: POST /api/hosts/{host_id}/baseline
```bash
# Setup
export HOST_ID="<test-host-uuid>"
export SCAN_ID="<completed-scan-uuid>"
export TOKEN="<jwt-token-with-scan-manager-role>"

# Test: Establish baseline successfully
curl -X POST "http://localhost:8000/api/hosts/${HOST_ID}/baseline" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "'${SCAN_ID}'",
    "baseline_type": "manual"
  }'

# Expected Response (201 Created):
# {
#   "id": "baseline-uuid",
#   "host_id": "host-uuid",
#   "baseline_type": "manual",
#   "established_at": "2025-11-15T...",
#   "established_by": 1,
#   "baseline_score": 87.5,
#   "baseline_passed_rules": 875,
#   "baseline_failed_rules": 125,
#   "baseline_total_rules": 1000,
#   "baseline_critical_passed": 45,
#   "baseline_critical_failed": 5,
#   ...
# }

# Test: Invalid scan ID (should fail)
curl -X POST "http://localhost:8000/api/hosts/${HOST_ID}/baseline" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "00000000-0000-0000-0000-000000000000",
    "baseline_type": "manual"
  }'

# Expected Response (400 Bad Request):
# {"detail": "Scan ... not found or not completed for host ..."}

# Test: Unauthorized user (analyst role)
curl -X POST "http://localhost:8000/api/hosts/${HOST_ID}/baseline" \
  -H "Authorization: Bearer ${ANALYST_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "'${SCAN_ID}'",
    "baseline_type": "manual"
  }'

# Expected Response (403 Forbidden):
# {"detail": "Insufficient permissions"}
```

#### Test 3.2: GET /api/hosts/{host_id}/baseline
```bash
# Test: Get active baseline
curl -X GET "http://localhost:8000/api/hosts/${HOST_ID}/baseline" \
  -H "Authorization: Bearer ${TOKEN}"

# Expected Response (200 OK):
# {
#   "id": "baseline-uuid",
#   "host_id": "host-uuid",
#   "baseline_type": "manual",
#   "baseline_score": 87.5,
#   ...
#   "is_active": true
# }

# Test: No baseline (should return null)
curl -X GET "http://localhost:8000/api/hosts/${HOST_WITHOUT_BASELINE}/baseline" \
  -H "Authorization: Bearer ${TOKEN}"

# Expected Response (200 OK):
# null

# Test: Analyst role can read baseline
curl -X GET "http://localhost:8000/api/hosts/${HOST_ID}/baseline" \
  -H "Authorization: Bearer ${ANALYST_TOKEN}"

# Expected Response (200 OK):
# {...} (baseline data)
```

#### Test 3.3: DELETE /api/hosts/{host_id}/baseline
```bash
# Test: Reset baseline successfully
curl -X DELETE "http://localhost:8000/api/hosts/${HOST_ID}/baseline" \
  -H "Authorization: Bearer ${TOKEN}"

# Expected Response (200 OK):
# {
#   "status": "success",
#   "message": "Baseline reset for host ...",
#   "host_id": "host-uuid"
# }

# Verify baseline is inactive
curl -X GET "http://localhost:8000/api/hosts/${HOST_ID}/baseline" \
  -H "Authorization: Bearer ${TOKEN}"

# Expected Response:
# null (no active baseline)

# Test: Delete non-existent baseline (should fail)
curl -X DELETE "http://localhost:8000/api/hosts/${HOST_WITHOUT_BASELINE}/baseline" \
  -H "Authorization: Bearer ${TOKEN}"

# Expected Response (404 Not Found):
# {"detail": "No active baseline found for host ..."}
```

---

### 4. Integration Tests

#### Test 4.1: End-to-End Drift Detection Workflow
```bash
# Step 1: Establish baseline from first scan
BASELINE_RESPONSE=$(curl -X POST \
  "http://localhost:8000/api/hosts/${HOST_ID}/baseline" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "'${SCAN1_ID}'",
    "baseline_type": "manual"
  }')

echo "Baseline established: $BASELINE_RESPONSE"

# Step 2: Run new scan with different score
# (Manually trigger scan via UI or API)

# Step 3: Check drift events table
docker exec openwatch-db psql -U openwatch -d openwatch -c \
  "SELECT id, drift_type, baseline_score, current_score, score_delta
   FROM scan_drift_events
   WHERE host_id = '${HOST_ID}'
   ORDER BY detected_at DESC
   LIMIT 1;"

# Expected Output:
# If score dropped >10pp: drift_type = 'major'
# If score dropped 5-10pp: drift_type = 'minor'
# If score increased >5pp: drift_type = 'improvement'
# If score changed <5pp: No event (stable)

# Step 4: Verify alert was dispatched
# Check backend logs
docker logs openwatch-backend --tail 50 | grep "ALERT_DISPATCHED"

# Expected Log:
# ALERT_DISPATCHED - Type: compliance_drift_major, Host: test-host, Severity: high
```

#### Test 4.2: Baseline Supersession Workflow
```bash
# Step 1: Establish first baseline
curl -X POST "http://localhost:8000/api/hosts/${HOST_ID}/baseline" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "'${SCAN1_ID}'", "baseline_type": "initial"}'

# Get baseline ID
BASELINE1_ID=$(curl -s -X GET \
  "http://localhost:8000/api/hosts/${HOST_ID}/baseline" \
  -H "Authorization: Bearer ${TOKEN}" | jq -r '.id')

echo "First baseline ID: $BASELINE1_ID"

# Step 2: Establish second baseline (should supersede first)
curl -X POST "http://localhost:8000/api/hosts/${HOST_ID}/baseline" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"scan_id": "'${SCAN2_ID}'", "baseline_type": "manual"}'

# Get new baseline ID
BASELINE2_ID=$(curl -s -X GET \
  "http://localhost:8000/api/hosts/${HOST_ID}/baseline" \
  -H "Authorization: Bearer ${TOKEN}" | jq -r '.id')

echo "Second baseline ID: $BASELINE2_ID"

# Step 3: Verify first baseline is superseded
docker exec openwatch-db psql -U openwatch -d openwatch -c \
  "SELECT id, is_active, superseded_at, superseded_by
   FROM scan_baselines
   WHERE id = '${BASELINE1_ID}';"

# Expected Output:
# is_active: false
# superseded_at: timestamp (not null)
# superseded_by: BASELINE2_ID

# Step 4: Verify only one active baseline exists
docker exec openwatch-db psql -U openwatch -d openwatch -c \
  "SELECT COUNT(*)
   FROM scan_baselines
   WHERE host_id = '${HOST_ID}' AND is_active = true;"

# Expected Output:
# count: 1
```

---

### 5. Frontend Component Tests

#### Test 5.1: BaselineEstablishDialog Component
**Manual Testing Steps**:
1. Navigate to host detail page
2. Click "Establish Baseline" button
3. Verify dialog opens with list of completed scans
4. Verify scan details show (score, timestamp, profile)
5. Select a scan
6. Choose baseline type (manual or initial)
7. Verify baseline summary displays correctly
8. Click "Establish Baseline"
9. Verify success message
10. Verify dialog closes

**Expected Behavior**:
- Only completed scans appear in list
- Scans sorted by completion time (newest first)
- Per-severity metrics displayed correctly
- Form validation prevents submission without selection
- Error handling for API failures

#### Test 5.2: DriftIndicator Component
**Manual Testing Steps**:
1. Create host with baseline
2. Run scan with significant drift
3. Navigate to host detail page
4. Verify drift indicator displays

**Expected Behavior**:
- Major drift: Red chip with warning icon
- Minor drift: Orange chip with trending down icon
- Improvement: Green chip with trending up icon
- Stable: Grey chip with horizontal line icon
- Tooltip shows detailed metrics
- Score delta formatted correctly (e.g., "-10.5pp")

#### Test 5.3: ComplianceTrendChart Component
**Manual Testing Steps**:
1. Navigate to host with multiple scans
2. View compliance trend chart
3. Verify baseline reference line displays
4. Verify drift events marked on chart
5. Hover over data points

**Expected Behavior**:
- X-axis shows dates (formatted as "Nov 15")
- Y-axis shows 0-100 scale
- Baseline displayed as dashed line
- Drift events highlighted with colored dots
- Tooltip shows score, rules passed/failed, drift type
- Chart responsive to window resize

#### Test 5.4: DriftAlertsWidget Component
**Manual Testing Steps**:
1. Navigate to dashboard
2. Verify drift alerts widget displays
3. Click refresh button
4. Click on drift event to navigate to host

**Expected Behavior**:
- Shows last 5 drift events
- Sorted by severity (major > minor > improvement)
- Each event shows hostname, drift indicator, score change, time ago
- Empty state when no drift events
- Loading indicator during fetch
- Error handling for API failures

---

## Test Execution Checklist

### Pre-Testing
- [ ] All Docker containers running and healthy
- [ ] Database migration applied successfully
- [ ] Test data prepared (hosts, scans, users)
- [ ] JWT tokens obtained for testing

### Database Tests
- [ ] scan_baselines table structure verified
- [ ] scan_drift_events table structure verified
- [ ] EXCLUDE constraint prevents duplicate active baselines
- [ ] Foreign key constraints working

### Backend Service Tests
- [ ] BaselineService.establish_baseline() tested
- [ ] BaselineService.get_active_baseline() tested
- [ ] BaselineService.reset_baseline() tested
- [ ] DriftDetectionService.detect_drift() tested
- [ ] DriftDetectionService drift classification tested
- [ ] UnifiedAlertService.dispatch_alert() tested

### API Endpoint Tests
- [ ] POST /api/hosts/{id}/baseline - success case
- [ ] POST /api/hosts/{id}/baseline - validation errors
- [ ] POST /api/hosts/{id}/baseline - RBAC enforcement
- [ ] GET /api/hosts/{id}/baseline - retrieval
- [ ] GET /api/hosts/{id}/baseline - no baseline case
- [ ] DELETE /api/hosts/{id}/baseline - reset
- [ ] DELETE /api/hosts/{id}/baseline - not found case

### Integration Tests
- [ ] End-to-end drift detection workflow
- [ ] Baseline supersession workflow
- [ ] Alert dispatching integration
- [ ] Webhook integration

### Frontend Tests
- [ ] BaselineEstablishDialog renders correctly
- [ ] DriftIndicator displays all drift types
- [ ] ComplianceTrendChart visualizes data
- [ ] DriftAlertsWidget shows events

---

## Known Issues / Expected Failures

1. **Black formatting not available in container**: Backend formatting skipped (will run in CI/CD)
2. **Multiple migration heads**: Resolved by direct upgrade to 20251115_baseline_drift
3. **Integer vs UUID user IDs**: Fixed - `established_by` uses Integer FK

---

## Test Results Template

```
Test Execution Report
Date: 2025-11-15
Tester: [Name]

Database Schema Tests:
- scan_baselines table: [ PASS / FAIL ]
- scan_drift_events table: [ PASS / FAIL ]
- EXCLUDE constraint: [ PASS / FAIL ]

Backend Service Tests:
- BaselineService: [ PASS / FAIL ]
- DriftDetectionService: [ PASS / FAIL ]
- UnifiedAlertService: [ PASS / FAIL ]

API Endpoint Tests:
- POST baseline: [ PASS / FAIL ]
- GET baseline: [ PASS / FAIL ]
- DELETE baseline: [ PASS / FAIL ]

Integration Tests:
- Drift detection workflow: [ PASS / FAIL ]
- Baseline supersession: [ PASS / FAIL ]

Frontend Tests:
- BaselineEstablishDialog: [ PASS / FAIL ]
- DriftIndicator: [ PASS / FAIL ]
- ComplianceTrendChart: [ PASS / FAIL ]
- DriftAlertsWidget: [ PASS / FAIL ]

Overall Status: [ PASS / FAIL ]
Notes: [Any issues or observations]
```

---

## Next Steps After Testing

1. **If All Tests Pass**:
   - Commit changes to git
   - Create pull request
   - Update documentation
   - Deploy to staging environment

2. **If Tests Fail**:
   - Document failures in test results
   - Create GitHub issues for bugs
   - Fix critical issues
   - Re-run failed tests

3. **Performance Testing** (Optional):
   - Baseline establishment with large scans (10k+ rules)
   - Drift detection with multiple concurrent scans
   - Frontend rendering with 100+ drift events

---

**Ready to Begin Testing**: All components implemented and database migrated successfully.
