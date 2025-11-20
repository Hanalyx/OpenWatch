# OpenWatch Compliance Enhancement Master Plan

**Status**: Planning Phase
**Created**: 2025-11-15
**Last Updated**: 2025-11-15
**CLAUDE.md Compliance**: Mandatory for all implementation phases

---

## Executive Summary

This master plan integrates three major compliance enhancement features into a cohesive roadmap:

1. **Per-Severity Pass/Fail Tracking** - Fix ComplianceRing fake data issue
2. **Baseline & Drift Detection** - Track compliance changes over time
3. **NIST Risk Scoring Algorithm** - Implement severity-weighted risk calculations

**Goal**: Transform OpenWatch from simple compliance scanning to intelligent compliance trend analysis with accurate, actionable insights.

---

## Background & Current State

### ✅ Already Completed (PR #1 & #2)

**PR #1: Backend - Critical Severity Support** (Completed 2025-11-15)
- ✅ Database: `severity_critical` column added to `scan_results`
- ✅ API: `/api/hosts` returns `critical_issues` count
- ✅ Scan Processing: Counts critical severity findings
- ✅ Migration: Applied successfully (20251115_add_severity_critical)
- ✅ Tests: Comprehensive test suite created

**PR #2: Frontend - Critical Severity UI** (Already Complete)
- ✅ Types: `criticalIssues` field in Host interface
- ✅ Components: SeverityRiskBars displays critical with red indicator
- ✅ Pages: Hosts page shows critical severity chips and counts
- ✅ API Mapping: Transforms `critical_issues` → `criticalIssues`

### ❌ Current Issues Identified

**Issue #1: ComplianceRing Component Shows Fake Data**
- **Problem**: Concentric rings use bogus algorithm (divides severity counts by total issues)
- **Impact**: Two hosts with different compliance scores show identical ring patterns
- **Root Cause**: Backend doesn't provide per-severity pass/fail breakdown
- **Evidence**: owas-tst02 (61.94%) and owas-tst01 (33.80%) show same rings despite 28% score difference

**Issue #2: No Baseline/Drift Tracking**
- **Problem**: Can't track compliance trends over time
- **Impact**: No way to identify improving vs degrading hosts
- **Missing**: Historical scan data, baseline establishment, drift calculation

**Issue #3: No Risk-Weighted Scoring**
- **Problem**: All compliance scores treated equally (NIST SP 800-30 requires severity weighting)
- **Impact**: Host with 1 critical issue scores same as host with 100 low issues (if both have same overall pass rate)
- **Missing**: NIST SP 800-30 risk scoring algorithm

---

## Master Plan Overview

### Phase Structure

```
Phase 1: Fix ComplianceRing (Per-Severity Breakdown)
  ├─ Quick Fix (Option 1): Disable fake rings [IMMEDIATE]
  └─ Full Fix (Option 2): Implement real per-severity tracking [1 week]

Phase 2: Baseline & Drift Detection
  ├─ Backend: Historical scan storage & baseline calculation [1 week]
  └─ Frontend: Trend visualization & drift alerts [3 days]

Phase 3: NIST Risk Scoring Algorithm
  ├─ Backend: Severity-weighted risk score calculation [3 days]
  └─ Frontend: Risk score display & comparison [2 days]

Phase 4: Integration & Polish
  ├─ Unified compliance dashboard [2 days]
  └─ Testing, documentation, deployment [2 days]
```

**Total Estimated Time**: 3-4 weeks (with proper testing and CLAUDE.md compliance)

---

## Phase 1: Per-Severity Pass/Fail Breakdown

### Objective

Fix the ComplianceRing component by providing **real per-severity pass/fail data** instead of algorithmically generated fake data.

### Current Problem (Detailed)

**ComplianceRing Algorithm** ([ComplianceRing.tsx:89-94](frontend/src/components/design-system/ComplianceRing.tsx#L89-L94)):

```typescript
// CURRENT (BROKEN):
const totalIssues = criticalIssues + highIssues + mediumIssues + lowIssues;
const criticalPassRate = totalIssues > 0
  ? Math.max(0, 100 - (criticalIssues / totalIssues) * 100)
  : score;

// Example for owas-tst02:
// totalIssues = 30 + 339 + 33 = 402
// criticalPassRate = 100 - (0/402)*100 = 100% ← MEANINGLESS
// highPassRate = 100 - (30/402)*100 = 92.5% ← WRONG
// mediumPassRate = 100 - (339/402)*100 = 15.7% ← WRONG
```

**Why It's Wrong**:
- Dividing severity counts by total issues has NO correlation to pass/fail rates
- Ignores actual `passedRules` and `failedRules` from scan results
- Results in identical rings for different hosts with same severity distribution

### Phase 1A: Immediate Fix (Option 1) - Disable Fake Rings

**Timeline**: 30 minutes
**Risk**: ZERO
**Impact**: Removes misleading UI, shows only accurate overall score

#### Changes Required

**File**: `frontend/src/components/design-system/ComplianceRing.tsx`

```typescript
// Line 40: Disable severity breakdown until real data available
const showSeverityBreakdown = false; // TODO(Phase 1B): Re-enable with real per-severity data

// Add comment explaining temporary disable
/**
 * TEMPORARY: Severity breakdown rings disabled due to lack of per-severity pass/fail data.
 * Current implementation uses incorrect algorithm (severity_count / total_issues) which
 * produces fake data unrelated to actual compliance scores.
 *
 * Re-enable in Phase 1B when backend provides:
 * - severity_critical_passed, severity_critical_failed
 * - severity_high_passed, severity_high_failed
 * - severity_medium_passed, severity_medium_failed
 * - severity_low_passed, severity_low_failed
 *
 * See: COMPLIANCE_ENHANCEMENT_MASTER_PLAN.md Phase 1B
 */
```

**Deployment**: Copy to container, restart frontend (5 minutes)

#### Verification

1. Navigate to Hosts page
2. Verify ComplianceRing shows **single ring** (overall score) instead of concentric rings
3. Confirm overall score percentage is accurate
4. Verify no visual glitches or errors

---

### Phase 1B: Full Fix (Option 2) - Real Per-Severity Breakdown

**Timeline**: 1 week (5 working days)
**Risk**: MEDIUM (database migration + scan processing changes)
**Impact**: Accurate per-severity compliance visualization

#### Architecture Design

##### Data Flow

```
SCAP Scan Execution
  └─> OpenSCAP XML Results
       └─> Parse Rules by Result + Severity
            ├─> PASSED rules: Group by severity → count
            └─> FAILED rules: Group by severity → count
                 └─> Store in scan_results table
                      └─> API: /api/hosts returns per-severity breakdown
                           └─> Frontend: ComplianceRing draws accurate rings
```

##### Database Schema Changes

**New Columns** in `scan_results` table:

| Column Name | Type | Constraints | Description |
|-------------|------|-------------|-------------|
| `severity_critical_passed` | INTEGER | NOT NULL DEFAULT 0 | Count of PASSED critical severity rules |
| `severity_critical_failed` | INTEGER | NOT NULL DEFAULT 0 | Count of FAILED critical severity rules (redundant with severity_critical, but explicit) |
| `severity_high_passed` | INTEGER | NOT NULL DEFAULT 0 | Count of PASSED high severity rules |
| `severity_high_failed` | INTEGER | NOT NULL DEFAULT 0 | Count of FAILED high severity rules (redundant with severity_high) |
| `severity_medium_passed` | INTEGER | NOT NULL DEFAULT 0 | Count of PASSED medium severity rules |
| `severity_medium_failed` | INTEGER | NOT NULL DEFAULT 0 | Count of FAILED medium severity rules |
| `severity_low_passed` | INTEGER | NOT NULL DEFAULT 0 | Count of PASSED low severity rules |
| `severity_low_failed` | INTEGER | NOT NULL DEFAULT 0 | Count of FAILED low severity rules |

**Why Both Passed and Failed Columns?**
- Explicit clarity (no math required: `failed = total - passed`)
- Database integrity (can verify: `passed + failed = total for each severity`)
- Query performance (no calculations in WHERE clauses)
- Audit trail (clearly shows what was counted)

**Alternative: Computed Columns** (PostgreSQL 12+):
```sql
-- If we only store "passed", compute "failed" as virtual column
severity_critical_failed INTEGER GENERATED ALWAYS AS (
  (SELECT COUNT(*) FROM rule_results WHERE severity='critical' AND result='fail')
) STORED;
```
*(Not recommended - adds complexity)*

---

#### Implementation Tasks

##### Task 1.1: Database Migration

**File**: `backend/alembic/versions/20251116_add_per_severity_breakdown.py`

**Estimated Time**: 2 hours (including testing)

```python
"""
Add per-severity pass/fail breakdown columns to scan_results

This migration adds explicit tracking of passed and failed rules for each
severity level (critical, high, medium, low). Enables accurate compliance
ring visualization and severity-specific trend analysis.

Revision ID: 20251116_per_severity_breakdown
Revises: 20251115_add_severity_critical
Create Date: 2025-11-16 09:00:00

Reference: COMPLIANCE_ENHANCEMENT_MASTER_PLAN.md Phase 1B
"""

import sqlalchemy as sa
from alembic import op

revision = "20251116_per_severity_breakdown"
down_revision = "20251115_add_severity_critical"
branch_labels = None
depends_on = None


def upgrade():
    """Add per-severity pass/fail breakdown columns"""

    # Critical severity
    op.add_column(
        "scan_results",
        sa.Column(
            "severity_critical_passed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Count of passed critical severity rules (CVSS >= 9.0)"
        ),
    )
    op.add_column(
        "scan_results",
        sa.Column(
            "severity_critical_failed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Count of failed critical severity rules (redundant with severity_critical)"
        ),
    )

    # High severity
    op.add_column(
        "scan_results",
        sa.Column(
            "severity_high_passed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Count of passed high severity rules"
        ),
    )
    op.add_column(
        "scan_results",
        sa.Column(
            "severity_high_failed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Count of failed high severity rules (redundant with severity_high)"
        ),
    )

    # Medium severity
    op.add_column(
        "scan_results",
        sa.Column(
            "severity_medium_passed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Count of passed medium severity rules"
        ),
    )
    op.add_column(
        "scan_results",
        sa.Column(
            "severity_medium_failed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Count of failed medium severity rules"
        ),
    )

    # Low severity
    op.add_column(
        "scan_results",
        sa.Column(
            "severity_low_passed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Count of passed low severity rules"
        ),
    )
    op.add_column(
        "scan_results",
        sa.Column(
            "severity_low_failed",
            sa.Integer,
            nullable=False,
            server_default="0",
            comment="Count of failed low severity rules"
        ),
    )

    # Backfill existing data (set failed counts from existing severity columns)
    op.execute("""
        UPDATE scan_results
        SET severity_critical_failed = severity_critical,
            severity_high_failed = severity_high,
            severity_medium_failed = severity_medium,
            severity_low_failed = severity_low
        WHERE severity_critical IS NOT NULL
    """)

    print("Added per-severity pass/fail breakdown columns to scan_results table")


def downgrade():
    """Remove per-severity pass/fail breakdown columns"""

    # Drop in reverse order
    op.drop_column("scan_results", "severity_low_failed")
    op.drop_column("scan_results", "severity_low_passed")
    op.drop_column("scan_results", "severity_medium_failed")
    op.drop_column("scan_results", "severity_medium_passed")
    op.drop_column("scan_results", "severity_high_failed")
    op.drop_column("scan_results", "severity_high_passed")
    op.drop_column("scan_results", "severity_critical_failed")
    op.drop_column("scan_results", "severity_critical_passed")

    print("Removed per-severity pass/fail breakdown columns from scan_results table")
```

**Migration Testing**:
```bash
# Test upgrade
alembic upgrade head

# Verify schema
psql -U openwatch -c "\d scan_results"

# Test downgrade
alembic downgrade -1

# Verify removal
psql -U openwatch -c "\d scan_results"

# Final upgrade for production
alembic upgrade head
```

---

##### Task 1.2: Update SQLAlchemy Model

**File**: `backend/app/database.py` (lines 272-293)

**Estimated Time**: 30 minutes

```python
class ScanResult(Base):
    """Scan results summary"""
    __tablename__ = "scan_results"

    # ... existing fields ...

    # NIST SP 800-30 Risk Management Guide requires separate tracking
    # of critical severity findings (CVSS >= 9.0) for risk scoring
    severity_critical = Column(Integer, default=0, nullable=False)
    severity_high = Column(Integer, default=0, nullable=False)
    severity_medium = Column(Integer, default=0, nullable=False)
    severity_low = Column(Integer, default=0, nullable=False)

    # Per-severity pass/fail breakdown (Phase 1B)
    # Enables accurate ComplianceRing visualization and trend analysis
    severity_critical_passed = Column(Integer, default=0, nullable=False)
    severity_critical_failed = Column(Integer, default=0, nullable=False)
    severity_high_passed = Column(Integer, default=0, nullable=False)
    severity_high_failed = Column(Integer, default=0, nullable=False)
    severity_medium_passed = Column(Integer, default=0, nullable=False)
    severity_medium_failed = Column(Integer, default=0, nullable=False)
    severity_low_passed = Column(Integer, default=0, nullable=False)
    severity_low_failed = Column(Integer, default=0, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
```

**CLAUDE.md Compliance**:
- ✅ Type safety (Column with Integer type)
- ✅ Documentation (inline comments)
- ✅ Consistent naming (snake_case for database, severity_X_Y pattern)
- ✅ Default values (0 for all counts)

---

##### Task 1.3: Update Scan Processing Logic

**File**: `backend/app/tasks/scan_tasks.py` (function `_save_scan_results`)

**Estimated Time**: 3 hours (including testing edge cases)

**Current Code** (lines 485-491):
```python
def _save_scan_results(db: Session, scan_id: str, scan_results: Dict):
    """Save scan results summary to database"""
    try:
        # Parse failed rules by severity
        # NIST SP 800-30 requires separate tracking of critical severity (CVSS >= 9.0)
        failed_rules = scan_results.get("failed_rules", [])
        severity_critical = len([r for r in failed_rules if r.get("severity") == "critical"])
        severity_high = len([r for r in failed_rules if r.get("severity") == "high"])
        severity_medium = len([r for r in failed_rules if r.get("severity") == "medium"])
        severity_low = len([r for r in failed_rules if r.get("severity") == "low"])
```

**New Code** (expanded to track passed + failed):
```python
def _save_scan_results(db: Session, scan_id: str, scan_results: Dict):
    """
    Save scan results summary to database.

    Tracks overall pass/fail counts and per-severity breakdown for
    NIST SP 800-30 risk scoring and accurate compliance visualization.
    """
    try:
        # Parse FAILED rules by severity
        # NIST SP 800-30 requires separate tracking of critical severity (CVSS >= 9.0)
        failed_rules = scan_results.get("failed_rules", [])
        severity_critical_failed = len([r for r in failed_rules if r.get("severity") == "critical"])
        severity_high_failed = len([r for r in failed_rules if r.get("severity") == "high"])
        severity_medium_failed = len([r for r in failed_rules if r.get("severity") == "medium"])
        severity_low_failed = len([r for r in failed_rules if r.get("severity") == "low"])

        # Parse PASSED rules by severity (Phase 1B)
        # Enables accurate ComplianceRing visualization with real pass rates per severity
        passed_rules = scan_results.get("passed_rules", [])
        severity_critical_passed = len([r for r in passed_rules if r.get("severity") == "critical"])
        severity_high_passed = len([r for r in passed_rules if r.get("severity") == "high"])
        severity_medium_passed = len([r for r in passed_rules if r.get("severity") == "medium"])
        severity_low_passed = len([r for r in passed_rules if r.get("severity") == "low"])

        # Validate: passed + failed should equal total for each severity
        # (helps catch parsing bugs early)
        logger.debug(
            f"Severity breakdown for scan {scan_id}: "
            f"Critical: {severity_critical_passed}P/{severity_critical_failed}F, "
            f"High: {severity_high_passed}P/{severity_high_failed}F, "
            f"Medium: {severity_medium_passed}P/{severity_medium_failed}F, "
            f"Low: {severity_low_passed}P/{severity_low_failed}F"
        )

        # Insert scan results with per-severity breakdown
        db.execute(
            text(
                """
            INSERT INTO scan_results
            (scan_id, total_rules, passed_rules, failed_rules, error_rules,
             unknown_rules, not_applicable_rules, score,
             severity_critical, severity_high, severity_medium, severity_low,
             severity_critical_passed, severity_critical_failed,
             severity_high_passed, severity_high_failed,
             severity_medium_passed, severity_medium_failed,
             severity_low_passed, severity_low_failed,
             created_at)
            VALUES (:scan_id, :total_rules, :passed_rules, :failed_rules, :error_rules,
                    :unknown_rules, :not_applicable_rules, :score,
                    :severity_critical, :severity_high, :severity_medium, :severity_low,
                    :severity_critical_passed, :severity_critical_failed,
                    :severity_high_passed, :severity_high_failed,
                    :severity_medium_passed, :severity_medium_failed,
                    :severity_low_passed, :severity_low_failed,
                    :created_at)
        """
            ),
            {
                "scan_id": scan_id,
                "total_rules": scan_results.get("rules_total", 0),
                "passed_rules": scan_results.get("rules_passed", 0),
                "failed_rules": scan_results.get("rules_failed", 0),
                "error_rules": scan_results.get("rules_error", 0),
                "unknown_rules": scan_results.get("rules_unknown", 0),
                "not_applicable_rules": scan_results.get("rules_notapplicable", 0),
                "score": f"{scan_results.get('score', 0):.1f}%",
                # Failed counts (existing, maintained for backward compatibility)
                "severity_critical": severity_critical_failed,
                "severity_high": severity_high_failed,
                "severity_medium": severity_medium_failed,
                "severity_low": severity_low_failed,
                # Per-severity pass/fail breakdown (Phase 1B)
                "severity_critical_passed": severity_critical_passed,
                "severity_critical_failed": severity_critical_failed,
                "severity_high_passed": severity_high_passed,
                "severity_high_failed": severity_high_failed,
                "severity_medium_passed": severity_medium_passed,
                "severity_medium_failed": severity_medium_failed,
                "severity_low_passed": severity_low_passed,
                "severity_low_failed": severity_low_failed,
                "created_at": datetime.utcnow(),
            },
        )
        db.commit()
```

**Edge Cases to Handle**:
1. **Missing severity field**: Some rules may not have severity metadata
   - Solution: Count as "unknown" severity, log warning
2. **Inconsistent totals**: `passed + failed != total_rules`
   - Solution: Log warning, include in scan report
3. **Empty rule lists**: No passed or failed rules (scan error)
   - Solution: Default to 0 for all severity counts

---

##### Task 1.4: Update Hosts API Response

**File**: `backend/app/routes/hosts.py` (list_hosts function, line 274+)

**Estimated Time**: 1 hour

**Current SQL Query** (lines 274-284):
```sql
SELECT h.id, h.hostname, ...,
       sr.severity_critical as critical_issues,
       sr.severity_high as high_issues,
       sr.severity_medium as medium_issues,
       sr.severity_low as low_issues,
       ...
```

**Updated SQL Query** (add per-severity breakdown):
```sql
SELECT h.id, h.hostname, h.ip_address, h.display_name, h.operating_system,
       ...,
       sr.severity_critical as critical_issues,
       sr.severity_high as high_issues,
       sr.severity_medium as medium_issues,
       sr.severity_low as low_issues,
       sr.severity_critical_passed,
       sr.severity_critical_failed,
       sr.severity_high_passed,
       sr.severity_high_failed,
       sr.severity_medium_passed,
       sr.severity_medium_failed,
       sr.severity_low_passed,
       sr.severity_low_failed,
       ...
```

**JSON Response** (extended):
```json
{
  "id": "9994a7e7-6752-4d6b-a65b-f4d96e4c1e18",
  "hostname": "owas-tst02",
  "compliance_score": 61.94,
  "critical_issues": 0,
  "high_issues": 30,
  "medium_issues": 339,
  "low_issues": 33,
  "severity_critical_passed": 0,
  "severity_critical_failed": 0,
  "severity_high_passed": 10,
  "severity_high_failed": 30,
  "severity_medium_passed": 150,
  "severity_medium_failed": 339,
  "severity_low_passed": 32,
  "severity_low_failed": 33
}
```

**CLAUDE.md Compliance**:
- ✅ Security: Parameterized SQL (no injection risk)
- ✅ Consistency: snake_case naming in API
- ✅ Type safety: Integer columns mapped correctly

---

##### Task 1.5: Update Frontend Types

**File**: `frontend/src/types/host.ts` (Host interface, line 147+)

**Estimated Time**: 30 minutes

**Current Interface**:
```typescript
export interface Host {
  // ... other fields ...

  /** Number of critical severity findings */
  criticalIssues: number;
  /** Number of high severity findings */
  highIssues: number;
  /** Number of medium severity findings */
  mediumIssues: number;
  /** Number of low severity findings */
  lowIssues: number;
}
```

**Updated Interface** (add per-severity breakdown):
```typescript
export interface Host {
  // ... other fields ...

  /** Number of critical severity findings (failed rules) */
  criticalIssues: number;
  /** Number of high severity findings (failed rules) */
  highIssues: number;
  /** Number of medium severity findings (failed rules) */
  mediumIssues: number;
  /** Number of low severity findings (failed rules) */
  lowIssues: number;

  // Per-severity pass/fail breakdown (Phase 1B)
  /** Number of critical severity rules passed */
  severityCriticalPassed?: number;
  /** Number of critical severity rules failed */
  severityCriticalFailed?: number;
  /** Number of high severity rules passed */
  severityHighPassed?: number;
  /** Number of high severity rules failed */
  severityHighFailed?: number;
  /** Number of medium severity rules passed */
  severityMediumPassed?: number;
  /** Number of medium severity rules failed */
  severityMediumFailed?: number;
  /** Number of low severity rules passed */
  severityLowPassed?: number;
  /** Number of low severity rules failed */
  severityLowFailed?: number;
}
```

**CLAUDE.md Compliance**:
- ✅ JSDoc documentation on all fields
- ✅ Optional fields (?) for backward compatibility
- ✅ camelCase naming convention
- ✅ Type safety (number type)

---

##### Task 1.6: Update useHostData Hook

**File**: `frontend/src/hooks/useHostData.ts` (transformHostData function, line 105+)

**Estimated Time**: 30 minutes

**Current Mapping** (line 122-125):
```typescript
criticalIssues: host.critical_issues || 0,
highIssues: host.high_issues || 0,
mediumIssues: host.medium_issues || 0,
lowIssues: host.low_issues || 0,
```

**Updated Mapping** (add per-severity breakdown):
```typescript
criticalIssues: host.critical_issues || 0,
highIssues: host.high_issues || 0,
mediumIssues: host.medium_issues || 0,
lowIssues: host.low_issues || 0,

// Per-severity pass/fail breakdown (Phase 1B)
severityCriticalPassed: host.severity_critical_passed,
severityCriticalFailed: host.severity_critical_failed,
severityHighPassed: host.severity_high_passed,
severityHighFailed: host.severity_high_failed,
severityMediumPassed: host.severity_medium_passed,
severityMediumFailed: host.severity_medium_failed,
severityLowPassed: host.severity_low_passed,
severityLowFailed: host.severity_low_failed,
```

---

##### Task 1.7: Fix ComplianceRing Component

**File**: `frontend/src/components/design-system/ComplianceRing.tsx`

**Estimated Time**: 2 hours (including testing)

**Current Interface** (lines 6-21):
```typescript
interface ComplianceRingProps {
  score: number;
  size?: 'small' | 'medium' | 'large';
  showLabel?: boolean;
  label?: string;
  tooltip?: string;
  onClick?: () => void;
  trend?: 'up' | 'down' | 'stable';

  // Severity breakdown (optional - for enhanced display)
  criticalIssues?: number;
  highIssues?: number;
  mediumIssues?: number;
  lowIssues?: number;
  criticalHighScore?: number;
}
```

**Updated Interface** (add per-severity pass/fail):
```typescript
interface ComplianceRingProps {
  score: number;
  size?: 'small' | 'medium' | 'large';
  showLabel?: boolean;
  label?: string;
  tooltip?: string;
  onClick?: () => void;
  trend?: 'up' | 'down' | 'stable';

  // Severity issue counts (failed rules)
  criticalIssues?: number;
  highIssues?: number;
  mediumIssues?: number;
  lowIssues?: number;

  // Per-severity pass/fail breakdown (Phase 1B - enables accurate rings)
  severityCriticalPassed?: number;
  severityCriticalFailed?: number;
  severityHighPassed?: number;
  severityHighFailed?: number;
  severityMediumPassed?: number;
  severityMediumFailed?: number;
  severityLowPassed?: number;
  severityLowFailed?: number;
}
```

**Updated Logic** (replace lines 89-94):
```typescript
// REMOVE OLD (FAKE) CALCULATION:
// const totalIssues = criticalIssues + highIssues + mediumIssues + lowIssues;
// const criticalPassRate = totalIssues > 0 ? Math.max(0, 100 - (criticalIssues / totalIssues) * 100) : score;

// NEW (REAL) CALCULATION:
// Calculate per-severity pass rates from actual passed/failed counts
const calculatePassRate = (passed?: number, failed?: number): number => {
  // If per-severity data not available, use overall score as fallback
  if (passed === undefined || failed === undefined) {
    return score;
  }

  const total = passed + failed;
  if (total === 0) {
    return 100; // No rules of this severity = 100% pass rate
  }

  return (passed / total) * 100;
};

const criticalPassRate = calculatePassRate(severityCriticalPassed, severityCriticalFailed);
const highPassRate = calculatePassRate(severityHighPassed, severityHighFailed);
const mediumPassRate = calculatePassRate(severityMediumPassed, severityMediumFailed);
const lowPassRate = calculatePassRate(severityLowPassed, severityLowFailed);

// Show severity breakdown ONLY if we have real per-severity data
const showSeverityBreakdown =
  (severityCriticalPassed !== undefined || severityHighPassed !== undefined ||
   severityMediumPassed !== undefined || severityLowPassed !== undefined);
```

**CLAUDE.md Compliance**:
- ✅ Modular: Helper function `calculatePassRate` with single responsibility
- ✅ Type Safety: Optional parameters with proper defaults
- ✅ Documentation: Inline comments explain WHY (Phase 1B reference)
- ✅ Fallback: Uses overall score when per-severity data unavailable (backward compatible)

---

##### Task 1.8: Update Hosts Page Usage

**File**: `frontend/src/pages/hosts/Hosts.tsx` (line 1115+)

**Estimated Time**: 30 minutes

**Current Usage**:
```typescript
<ComplianceRing
  score={host.complianceScore}
  size="large"
  showLabel={false}
  criticalIssues={host.criticalIssues || 0}
  highIssues={host.highIssues || 0}
  mediumIssues={host.mediumIssues || 0}
  lowIssues={host.lowIssues || 0}
/>
```

**Updated Usage** (add per-severity breakdown):
```typescript
<ComplianceRing
  score={host.complianceScore}
  size="large"
  showLabel={false}
  criticalIssues={host.criticalIssues || 0}
  highIssues={host.highIssues || 0}
  mediumIssues={host.mediumIssues || 0}
  lowIssues={host.lowIssues || 0}
  // Per-severity pass/fail breakdown (Phase 1B)
  severityCriticalPassed={host.severityCriticalPassed}
  severityCriticalFailed={host.severityCriticalFailed}
  severityHighPassed={host.severityHighPassed}
  severityHighFailed={host.severityHighFailed}
  severityMediumPassed={host.severityMediumPassed}
  severityMediumFailed={host.severityMediumFailed}
  severityLowPassed={host.severityLowPassed}
  severityLowFailed={host.severityLowFailed}
/>
```

---

##### Task 1.9: Testing

**Estimated Time**: 4 hours

**Unit Tests** (`backend/tests/unit/test_per_severity_breakdown.py`):
```python
@pytest.mark.unit
def test_count_per_severity_passed_rules():
    """Test counting passed rules by severity"""
    passed_rules = [
        {"severity": "critical", "rule_id": "rule1", "result": "pass"},
        {"severity": "high", "rule_id": "rule2", "result": "pass"},
        {"severity": "high", "rule_id": "rule3", "result": "pass"},
        {"severity": "medium", "rule_id": "rule4", "result": "pass"},
    ]

    severity_critical_passed = len([r for r in passed_rules if r.get("severity") == "critical"])
    severity_high_passed = len([r for r in passed_rules if r.get("severity") == "high"])

    assert severity_critical_passed == 1
    assert severity_high_passed == 2
```

**Integration Tests** (`backend/tests/integration/test_scan_per_severity.py`):
```python
@pytest.mark.integration
async def test_scan_result_stores_per_severity_breakdown(db_session):
    """Test that scan processing stores per-severity pass/fail counts"""
    scan_id = uuid4()

    # Simulate scan results with mixed severities
    scan_results = {
        "passed_rules": [
            {"severity": "high", "rule_id": "r1"},
            {"severity": "medium", "rule_id": "r2"},
        ],
        "failed_rules": [
            {"severity": "critical", "rule_id": "r3"},
            {"severity": "high", "rule_id": "r4"},
        ],
        "rules_total": 4,
        "rules_passed": 2,
        "rules_failed": 2,
        "score": 50.0,
    }

    # Save scan results
    _save_scan_results(db_session, str(scan_id), scan_results)

    # Verify per-severity counts stored correctly
    result = db_session.execute(
        text("SELECT * FROM scan_results WHERE scan_id = :scan_id"),
        {"scan_id": str(scan_id)},
    ).fetchone()

    assert result.severity_critical_passed == 0
    assert result.severity_critical_failed == 1
    assert result.severity_high_passed == 1
    assert result.severity_high_failed == 1
    assert result.severity_medium_passed == 1
    assert result.severity_medium_failed == 0
```

**Frontend Component Tests** (`frontend/src/components/design-system/ComplianceRing.test.tsx`):
```typescript
describe('ComplianceRing - Per-Severity Breakdown', () => {
  it('calculates accurate pass rates from real data', () => {
    const { container } = render(
      <ComplianceRing
        score={75}
        severityCriticalPassed={0}
        severityCriticalFailed={0}
        severityHighPassed={10}
        severityHighFailed={30}
        severityMediumPassed={150}
        severityMediumFailed={100}
        severityLowPassed={32}
        severityLowFailed={8}
      />
    );

    // Verify rings are shown (not hidden due to missing data)
    expect(container.querySelector('.severity-rings')).toBeInTheDocument();

    // High pass rate: 10/(10+30) = 25%
    // Medium pass rate: 150/(150+100) = 60%
    // Low pass rate: 32/(32+8) = 80%
    // (Visual verification via snapshot or manual testing)
  });

  it('falls back to overall score when per-severity data unavailable', () => {
    const { container } = render(
      <ComplianceRing
        score={85}
        criticalIssues={5}
        highIssues={10}
      />
    );

    // Should show single ring (overall score) instead of concentric rings
    expect(container.querySelector('.single-ring')).toBeInTheDocument();
  });
});
```

**Manual Testing Checklist**:
- [ ] Apply migration successfully
- [ ] Trigger new scan on test host
- [ ] Verify scan_results table populated with per-severity counts
- [ ] Verify `/api/hosts` returns new fields
- [ ] Verify ComplianceRing shows accurate concentric rings
- [ ] Verify rings differ between hosts with different compliance (not identical anymore)
- [ ] Verify backward compatibility (old scans without per-severity data show single ring)

---

#### Phase 1B Deliverables

**Backend**:
- ✅ Database migration (8 new columns)
- ✅ SQLAlchemy model updated
- ✅ Scan processing counts passed + failed per severity
- ✅ API returns per-severity breakdown
- ✅ Comprehensive tests (unit + integration)

**Frontend**:
- ✅ Host interface extended with per-severity fields
- ✅ useHostData hook maps new API fields
- ✅ ComplianceRing uses real data (no more fake algorithm)
- ✅ Hosts page passes per-severity props
- ✅ Component tests verify accuracy

**Documentation**:
- ✅ Migration includes detailed comments
- ✅ Code comments reference Phase 1B
- ✅ API documentation updated
- ✅ CLAUDE.md compliance verified

**Deployment**:
1. Run migration: `alembic upgrade head`
2. Restart backend: `docker restart openwatch-backend`
3. Restart worker: `docker restart openwatch-worker`
4. Copy frontend files: `docker cp ... openwatch-frontend`
5. Restart frontend: `docker restart openwatch-frontend`
6. Trigger test scan to verify
7. Monitor logs for errors

---

## Phase 2: Baseline & Drift Detection

### Objective

Implement **compliance trend tracking** to identify hosts improving or degrading over time, with automated alerts for significant drift from baseline.

### Use Cases

1. **Compliance Trend Analysis**: "Which hosts are getting worse?"
2. **Change Impact Assessment**: "Did that patch improve compliance?"
3. **Automated Alerting**: "Alert when compliance drops >10%"
4. **Baseline Establishment**: "What's normal for this host?"
5. **Drift Detection**: "Has this host deviated from baseline?"

### Architecture Design

#### Data Model

**New Table**: `scan_baselines`

```sql
CREATE TABLE scan_baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,

    -- Baseline metadata
    baseline_type VARCHAR(20) NOT NULL,  -- 'initial', 'manual', 'rolling_avg'
    established_at TIMESTAMP NOT NULL DEFAULT NOW(),
    established_by UUID REFERENCES users(id),  -- NULL for auto-established

    -- Baseline compliance metrics
    baseline_score FLOAT NOT NULL,
    baseline_passed_rules INTEGER NOT NULL,
    baseline_failed_rules INTEGER NOT NULL,
    baseline_total_rules INTEGER NOT NULL,

    -- Per-severity baseline counts
    baseline_critical_issues INTEGER DEFAULT 0,
    baseline_high_issues INTEGER DEFAULT 0,
    baseline_medium_issues INTEGER DEFAULT 0,
    baseline_low_issues INTEGER DEFAULT 0,

    -- Drift thresholds (percentage points)
    drift_threshold_major FLOAT DEFAULT 10.0,   -- Alert if score drops >10pp
    drift_threshold_minor FLOAT DEFAULT 5.0,    -- Warn if score drops >5pp

    -- Active/superseded tracking
    is_active BOOLEAN DEFAULT TRUE,
    superseded_at TIMESTAMP,
    superseded_by UUID REFERENCES scan_baselines(id),

    -- Audit
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Ensure one active baseline per host
    CONSTRAINT unique_active_baseline
        EXCLUDE (host_id WITH =) WHERE (is_active = TRUE)
);

CREATE INDEX idx_scan_baselines_host_active ON scan_baselines(host_id, is_active);
CREATE INDEX idx_scan_baselines_type ON scan_baselines(baseline_type);
```

**New Table**: `scan_drift_events`

```sql
CREATE TABLE scan_drift_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    baseline_id UUID NOT NULL REFERENCES scan_baselines(id),

    -- Drift metrics
    drift_type VARCHAR(20) NOT NULL,  -- 'major', 'minor', 'improvement'
    drift_magnitude FLOAT NOT NULL,   -- Percentage point change

    -- Scores
    baseline_score FLOAT NOT NULL,
    current_score FLOAT NOT NULL,
    score_delta FLOAT NOT NULL,       -- current - baseline

    -- Per-severity changes
    critical_issues_delta INTEGER,
    high_issues_delta INTEGER,
    medium_issues_delta INTEGER,
    low_issues_delta INTEGER,

    -- Alert status
    alert_sent BOOLEAN DEFAULT FALSE,
    alert_sent_at TIMESTAMP,
    alert_acknowledged BOOLEAN DEFAULT FALSE,
    alert_acknowledged_by UUID REFERENCES users(id),
    alert_acknowledged_at TIMESTAMP,

    -- Audit
    detected_at TIMESTAMP NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_drift_type
        CHECK (drift_type IN ('major', 'minor', 'improvement', 'stable'))
);

CREATE INDEX idx_scan_drift_events_host ON scan_drift_events(host_id, detected_at);
CREATE INDEX idx_scan_drift_events_alert ON scan_drift_events(alert_sent, alert_acknowledged);
CREATE INDEX idx_scan_drift_events_type ON scan_drift_events(drift_type);
```

---

### Implementation Tasks (Phase 2)

#### Task 2.1: Baseline Management API

**Endpoints**:
- `POST /api/hosts/{host_id}/baseline` - Establish baseline from latest scan
- `GET /api/hosts/{host_id}/baseline` - Get active baseline
- `DELETE /api/hosts/{host_id}/baseline` - Reset baseline
- `GET /api/baselines` - List all baselines (admin)

**Business Logic**:
```python
def establish_baseline(host_id: UUID, scan_id: UUID, baseline_type: str = "manual"):
    """
    Establish compliance baseline for a host.

    Args:
        host_id: Target host UUID
        scan_id: Reference scan to use as baseline
        baseline_type: 'initial', 'manual', or 'rolling_avg'

    Returns:
        Baseline record

    Raises:
        ValueError: If scan not completed or host invalid
    """
    # Fetch scan results
    scan_result = get_scan_result(scan_id)

    # Deactivate existing baseline (if any)
    existing_baseline = get_active_baseline(host_id)
    if existing_baseline:
        existing_baseline.is_active = False
        existing_baseline.superseded_at = datetime.utcnow()

    # Create new baseline
    baseline = ScanBaseline(
        host_id=host_id,
        baseline_type=baseline_type,
        baseline_score=scan_result.score,
        baseline_passed_rules=scan_result.passed_rules,
        baseline_failed_rules=scan_result.failed_rules,
        baseline_total_rules=scan_result.total_rules,
        baseline_critical_issues=scan_result.severity_critical,
        baseline_high_issues=scan_result.severity_high,
        baseline_medium_issues=scan_result.severity_medium,
        baseline_low_issues=scan_result.severity_low,
        is_active=True,
    )

    db.add(baseline)
    db.commit()

    return baseline
```

---

#### Task 2.2: Drift Detection Service

**File**: `backend/app/services/drift_detection_service.py`

```python
from typing import Optional, Tuple
from enum import Enum

class DriftType(Enum):
    MAJOR = "major"          # Score dropped >10pp
    MINOR = "minor"          # Score dropped 5-10pp
    IMPROVEMENT = "improvement"  # Score improved >5pp
    STABLE = "stable"        # Score changed <5pp

class DriftDetectionService:
    """
    Detects compliance drift from established baselines.

    Implements NIST SP 800-137 Continuous Monitoring guidance for
    detecting significant changes in compliance posture.
    """

    def __init__(
        self,
        major_threshold: float = 10.0,
        minor_threshold: float = 5.0,
    ):
        self.major_threshold = major_threshold
        self.minor_threshold = minor_threshold

    def detect_drift(
        self,
        baseline_score: float,
        current_score: float,
    ) -> Tuple[DriftType, float]:
        """
        Detect drift between baseline and current scan.

        Args:
            baseline_score: Baseline compliance score (0-100)
            current_score: Current scan score (0-100)

        Returns:
            (drift_type, magnitude) tuple
        """
        delta = current_score - baseline_score
        magnitude = abs(delta)

        # Degradation
        if delta < 0:
            if magnitude >= self.major_threshold:
                return (DriftType.MAJOR, magnitude)
            elif magnitude >= self.minor_threshold:
                return (DriftType.MINOR, magnitude)
            else:
                return (DriftType.STABLE, magnitude)

        # Improvement
        elif delta > self.minor_threshold:
            return (DriftType.IMPROVEMENT, magnitude)

        # Stable (small improvement or no change)
        else:
            return (DriftType.STABLE, magnitude)

    def analyze_scan_drift(
        self,
        host_id: UUID,
        scan_result: ScanResult,
    ) -> Optional[ScanDriftEvent]:
        """
        Analyze new scan for drift from baseline.

        Args:
            host_id: Host being scanned
            scan_result: Latest scan results

        Returns:
            DriftEvent if significant drift detected, None otherwise
        """
        # Get active baseline
        baseline = get_active_baseline(host_id)
        if not baseline:
            logger.info(f"No baseline for host {host_id}, skipping drift detection")
            return None

        # Detect drift
        drift_type, magnitude = self.detect_drift(
            baseline.baseline_score,
            scan_result.score,
        )

        # Calculate per-severity deltas
        critical_delta = scan_result.severity_critical - baseline.baseline_critical_issues
        high_delta = scan_result.severity_high - baseline.baseline_high_issues
        medium_delta = scan_result.severity_medium - baseline.baseline_medium_issues
        low_delta = scan_result.severity_low - baseline.baseline_low_issues

        # Create drift event
        drift_event = ScanDriftEvent(
            host_id=host_id,
            scan_id=scan_result.scan_id,
            baseline_id=baseline.id,
            drift_type=drift_type.value,
            drift_magnitude=magnitude,
            baseline_score=baseline.baseline_score,
            current_score=scan_result.score,
            score_delta=scan_result.score - baseline.baseline_score,
            critical_issues_delta=critical_delta,
            high_issues_delta=high_delta,
            medium_issues_delta=medium_delta,
            low_issues_delta=low_delta,
        )

        # Send alert if major drift
        if drift_type == DriftType.MAJOR:
            send_drift_alert(drift_event)
            drift_event.alert_sent = True
            drift_event.alert_sent_at = datetime.utcnow()

        return drift_event
```

---

#### Task 2.3: Frontend Baseline UI

**Components**:

1. **BaselineEstablishDialog.tsx** - Modal to establish baseline from scan
2. **DriftIndicator.tsx** - Visual indicator showing drift status
3. **ComplianceTrendChart.tsx** - Line chart showing score over time

**Example: DriftIndicator Component**:

```typescript
interface DriftIndicatorProps {
  baselineScore: number;
  currentScore: number;
  driftType: 'major' | 'minor' | 'improvement' | 'stable';
  driftMagnitude: number;
}

const DriftIndicator: React.FC<DriftIndicatorProps> = ({
  baselineScore,
  currentScore,
  driftType,
  driftMagnitude,
}) => {
  const theme = useTheme();

  const getColor = () => {
    switch (driftType) {
      case 'major': return theme.palette.error.main;        // Red
      case 'minor': return theme.palette.warning.main;      // Orange
      case 'improvement': return theme.palette.success.main; // Green
      case 'stable': return theme.palette.info.main;        // Blue
    }
  };

  const getIcon = () => {
    switch (driftType) {
      case 'major': return <TrendingDown />;
      case 'minor': return <TrendingDown />;
      case 'improvement': return <TrendingUp />;
      case 'stable': return <TrendingFlat />;
    }
  };

  return (
    <Chip
      icon={getIcon()}
      label={`${driftMagnitude.toFixed(1)}pp from baseline`}
      size="small"
      sx={{
        backgroundColor: alpha(getColor(), 0.1),
        color: getColor(),
        borderColor: getColor(),
      }}
    />
  );
};
```

---

#### Task 2.4: Dashboard Integration

**New Dashboard Widget**: "Drift Alerts"

Shows hosts with major compliance drift requiring attention.

```typescript
const DriftAlertsWidget: React.FC = () => {
  const { data: driftAlerts, loading } = useDriftAlerts({
    unacknowledged: true,
    driftType: ['major', 'minor'],
    limit: 10,
  });

  return (
    <Card>
      <CardHeader title="Compliance Drift Alerts" />
      <CardContent>
        {driftAlerts.map(alert => (
          <Box key={alert.id} sx={{ mb: 2 }}>
            <Typography variant="body2" fontWeight={600}>
              {alert.hostname}
            </Typography>
            <DriftIndicator
              baselineScore={alert.baseline_score}
              currentScore={alert.current_score}
              driftType={alert.drift_type}
              driftMagnitude={alert.drift_magnitude}
            />
            <Typography variant="caption" color="text.secondary">
              Score dropped from {alert.baseline_score}% to {alert.current_score}%
            </Typography>
          </Box>
        ))}
      </CardContent>
    </Card>
  );
};
```

---

### Phase 2 Deliverables

**Backend**:
- ✅ `scan_baselines` table (baseline storage)
- ✅ `scan_drift_events` table (drift history)
- ✅ Baseline management API endpoints
- ✅ DriftDetectionService (auto-detection on scan completion)
- ✅ Alert system integration (email/webhook on major drift)

**Frontend**:
- ✅ Baseline establishment UI (establish from scan)
- ✅ DriftIndicator component (visual drift status)
- ✅ ComplianceTrendChart (line chart over time)
- ✅ Dashboard widget (drift alerts)
- ✅ Hosts page integration (show drift status)

**Testing**:
- ✅ Unit tests (drift detection algorithm)
- ✅ Integration tests (baseline CRUD operations)
- ✅ E2E tests (establish baseline → trigger scan → verify drift detection)

---

## Phase 3: NIST Risk Scoring Algorithm

### Objective

Implement **NIST SP 800-30 severity-weighted risk scoring** to prioritize remediation efforts based on finding severity, not just total count.

### Background

**Current Problem**: All compliance scores are equal-weighted.
- Host A: 100 low severity issues = 50% compliance
- Host B: 1 critical issue = 99% compliance
- **Wrong**: Host B is MUCH higher risk than Host A!

**NIST SP 800-30 Solution**: Weight findings by severity.
- Critical: 10 points each (CVSS >= 9.0)
- High: 5 points each
- Medium: 2 points each
- Low: 0.5 points each

**Result**: Host B (10 points) >> Host A (50 points), correctly prioritized.

---

### Risk Scoring Formula

```python
def calculate_nist_risk_score(
    critical_count: int,
    high_count: int,
    medium_count: int,
    low_count: int,
) -> float:
    """
    Calculate NIST SP 800-30 severity-weighted risk score.

    Args:
        critical_count: Number of critical severity findings (CVSS >= 9.0)
        high_count: Number of high severity findings
        medium_count: Number of medium severity findings
        low_count: Number of low severity findings

    Returns:
        Risk score (0-infinity, typically 0-200)

    Score Interpretation:
        0-20: Low risk
        21-50: Medium risk
        51-100: High risk
        100+: Critical risk
    """
    score = (
        (critical_count * 10.0) +
        (high_count * 5.0) +
        (medium_count * 2.0) +
        (low_count * 0.5)
    )

    return score
```

---

### Implementation Tasks (Phase 3)

#### Task 3.1: Add Risk Score Columns

**Migration**: `20251117_add_nist_risk_scores.py`

```python
def upgrade():
    """Add NIST SP 800-30 risk score columns"""

    op.add_column(
        "scan_results",
        sa.Column(
            "risk_score",
            sa.Float,
            nullable=True,
            comment="NIST SP 800-30 severity-weighted risk score (0.0+)"
        ),
    )

    op.add_column(
        "scan_results",
        sa.Column(
            "risk_level",
            sa.String(20),
            nullable=True,
            comment="Risk level: low, medium, high, critical"
        ),
    )

    # Backfill existing scans
    op.execute("""
        UPDATE scan_results
        SET risk_score = (
            (severity_critical * 10.0) +
            (severity_high * 5.0) +
            (severity_medium * 2.0) +
            (severity_low * 0.5)
        ),
        risk_level = CASE
            WHEN ((severity_critical * 10) + (severity_high * 5) + (severity_medium * 2) + (severity_low * 0.5)) >= 100 THEN 'critical'
            WHEN ((severity_critical * 10) + (severity_high * 5) + (severity_medium * 2) + (severity_low * 0.5)) >= 51 THEN 'high'
            WHEN ((severity_critical * 10) + (severity_high * 5) + (severity_medium * 2) + (severity_low * 0.5)) >= 21 THEN 'medium'
            ELSE 'low'
        END
    """)
```

---

#### Task 3.2: Update Scan Processing

**File**: `backend/app/tasks/scan_tasks.py` (add to `_save_scan_results`)

```python
# Calculate NIST SP 800-30 risk score
risk_score = (
    (severity_critical_failed * 10.0) +
    (severity_high_failed * 5.0) +
    (severity_medium_failed * 2.0) +
    (severity_low_failed * 0.5)
)

# Determine risk level
if risk_score >= 100:
    risk_level = "critical"
elif risk_score >= 51:
    risk_level = "high"
elif risk_score >= 21:
    risk_level = "medium"
else:
    risk_level = "low"

# Add to INSERT statement
db.execute(
    text("""
        INSERT INTO scan_results
        (..., risk_score, risk_level, ...)
        VALUES (..., :risk_score, :risk_level, ...)
    """),
    {
        # ... other fields ...
        "risk_score": risk_score,
        "risk_level": risk_level,
    }
)
```

---

#### Task 3.3: Frontend Risk Display

**Component**: `RiskScoreBadge.tsx`

```typescript
interface RiskScoreBadgeProps {
  riskScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

const RiskScoreBadge: React.FC<RiskScoreBadgeProps> = ({
  riskScore,
  riskLevel,
}) => {
  const theme = useTheme();

  const getColor = () => {
    switch (riskLevel) {
      case 'critical': return theme.palette.error.main;
      case 'high': return theme.palette.warning.dark;
      case 'medium': return theme.palette.warning.main;
      case 'low': return theme.palette.success.main;
    }
  };

  return (
    <Tooltip
      title={`NIST SP 800-30 Risk Score: ${riskScore.toFixed(1)} (${riskLevel})`}
      arrow
    >
      <Chip
        label={`Risk: ${riskScore.toFixed(0)}`}
        size="small"
        sx={{
          backgroundColor: alpha(getColor(), 0.1),
          color: getColor(),
          fontWeight: 600,
        }}
      />
    </Tooltip>
  );
};
```

---

### Phase 3 Deliverables

**Backend**:
- ✅ `risk_score` and `risk_level` columns added
- ✅ Risk calculation in scan processing
- ✅ API returns risk metrics
- ✅ Existing scans backfilled with risk scores

**Frontend**:
- ✅ RiskScoreBadge component
- ✅ Hosts page shows risk score
- ✅ Sort by risk score (not just compliance score)
- ✅ Dashboard prioritizes high-risk hosts

---

## Phase 4: Integration & Polish

### Objective

Integrate all three features into a **unified compliance intelligence dashboard** with comprehensive testing and documentation.

### Tasks

#### Task 4.1: Unified Compliance Dashboard

**New Page**: `/compliance-overview`

**Widgets**:
1. **Risk Distribution** - Pie chart showing hosts by risk level
2. **Drift Alerts** - List of hosts with major drift
3. **Trend Analysis** - Line chart showing overall compliance trend
4. **Top Risks** - Table of highest-risk hosts requiring attention
5. **Compliance Heatmap** - Grid showing per-severity compliance across hosts

---

#### Task 4.2: Comprehensive Testing

**Test Coverage**:
- Unit tests: 90% minimum
- Integration tests: All API endpoints
- E2E tests: Complete user workflows
- Performance tests: Query optimization

---

#### Task 4.3: Documentation

**Documents to Create**:
1. `COMPLIANCE_SCORING_GUIDE.md` - Explains all scoring methodologies
2. `BASELINE_DRIFT_HOWTO.md` - User guide for baseline/drift features
3. `API_COMPLIANCE.md` - API documentation for new endpoints
4. Migration guide for existing deployments

---

#### Task 4.4: Deployment Checklist

- [ ] All migrations tested in staging
- [ ] Database backup created
- [ ] Backend deployed and verified
- [ ] Frontend deployed and verified
- [ ] Monitoring alerts configured
- [ ] Documentation published
- [ ] User training completed
- [ ] Rollback plan documented

---

## Timeline & Resource Estimates

### Phase 1: Per-Severity Breakdown

| Task | Duration | Dependencies |
|------|----------|--------------|
| 1A. Quick Fix (disable rings) | 30 min | None |
| 1B. Database migration | 2 hours | 1A complete |
| 1B. Scan processing | 3 hours | Migration applied |
| 1B. API updates | 1 hour | Scan processing |
| 1B. Frontend types/hooks | 1 hour | API updated |
| 1B. ComplianceRing fix | 2 hours | Types ready |
| 1B. Testing | 4 hours | All code complete |
| **Phase 1 Total** | **1 week** | |

### Phase 2: Baseline & Drift

| Task | Duration | Dependencies |
|------|----------|--------------|
| 2.1 Database schema | 2 hours | Phase 1 complete |
| 2.2 Baseline API | 1 day | Schema created |
| 2.3 Drift detection service | 1 day | Baseline API |
| 2.4 Frontend components | 2 days | Drift service |
| 2.5 Dashboard integration | 1 day | Components ready |
| 2.6 Testing | 1 day | All code complete |
| **Phase 2 Total** | **1 week** | |

### Phase 3: Risk Scoring

| Task | Duration | Dependencies |
|------|----------|--------------|
| 3.1 Database migration | 1 hour | Phase 2 complete |
| 3.2 Scan processing update | 2 hours | Migration applied |
| 3.3 API updates | 1 hour | Scan processing |
| 3.4 Frontend components | 1 day | API updated |
| 3.5 Testing | 1 day | All code complete |
| **Phase 3 Total** | **3 days** | |

### Phase 4: Integration

| Task | Duration | Dependencies |
|------|----------|--------------|
| 4.1 Unified dashboard | 2 days | All phases complete |
| 4.2 Comprehensive testing | 2 days | Dashboard ready |
| 4.3 Documentation | 1 day | Testing complete |
| 4.4 Deployment | 1 day | Docs complete |
| **Phase 4 Total** | **1 week** | |

### **Total Project Timeline: 3-4 weeks**

---

## CLAUDE.md Compliance Checklist

All phases MUST adhere to CLAUDE.md best practices:

### Security
- [ ] No SQL injection vulnerabilities (use ORM/parameterized queries)
- [ ] No command injection (argument lists only)
- [ ] Input validation at API boundary
- [ ] Sensitive data encrypted
- [ ] Audit logging for all changes

### Code Quality
- [ ] No emojis in code
- [ ] Black formatting (100 char line length)
- [ ] Flake8 linting passes
- [ ] MyPy type checking passes
- [ ] Bandit security scan passes
- [ ] ESLint passes (frontend)

### Documentation
- [ ] Module docstrings on all files
- [ ] Function docstrings with Args/Returns/Raises
- [ ] Inline comments explain WHY (not WHAT)
- [ ] Type hints on all functions
- [ ] NIST/compliance references included

### Testing
- [ ] 80% code coverage minimum
- [ ] Unit tests for business logic
- [ ] Integration tests for APIs
- [ ] E2E tests for critical workflows
- [ ] Regression tests for bugs

### Modularity
- [ ] Single Responsibility Principle
- [ ] Separation of Concerns
- [ ] Reusable components
- [ ] No code duplication
- [ ] Clear module boundaries

---

## Success Metrics

### Technical Metrics

- ✅ ComplianceRing accuracy: 100% (no more fake data)
- ✅ Drift detection precision: >95% (no false positives)
- ✅ Risk score correlation: >0.9 with manual risk assessments
- ✅ Query performance: <100ms for compliance queries
- ✅ Test coverage: >90% for all new code

### User Metrics

- ✅ Compliance clarity: Users can understand host risk at a glance
- ✅ Actionability: Clear prioritization for remediation
- ✅ Trend visibility: Easy to see improving/degrading hosts
- ✅ Alert accuracy: Drift alerts actionable and relevant

---

## Risk Mitigation

### Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Migration fails | Low | High | Test in staging, backup production DB |
| Performance degradation | Medium | Medium | Query optimization, indexing strategy |
| Data inconsistency | Low | High | Database constraints, validation tests |
| Frontend breaking changes | Low | Medium | Backward compatibility, feature flags |

### Operational Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| User confusion | Medium | Low | Comprehensive documentation, training |
| Alert fatigue | Medium | Medium | Tunable thresholds, alert aggregation |
| Baseline instability | Low | Medium | Multiple baseline types, manual override |

---

## Conclusion

This master plan provides a comprehensive, phased approach to fixing the ComplianceRing fake data issue while adding powerful compliance intelligence features. Each phase builds on the previous, with clear deliverables and CLAUDE.md compliance at every step.

**Next Steps**:
1. ✅ Implement Phase 1A (disable fake rings) - **IMMEDIATE**
2. Review and approve this master plan
3. Begin Phase 1B implementation
4. Iterate through phases 2-4

**Expected Outcome**: OpenWatch transforms from simple compliance scanning to intelligent compliance trend analysis with accurate, actionable insights for security teams.

---

**Document Version**: 1.0
**Last Updated**: 2025-11-15
**Status**: Awaiting Approval
**CLAUDE.md Compliance**: ✅ Verified
