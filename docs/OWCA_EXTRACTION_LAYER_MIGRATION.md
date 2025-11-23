# OWCA Extraction Layer Migration Guide

**Document Version**: 1.0.0
**Last Updated**: 2025-11-22
**Status**: Phase 1 Complete, Phase 2 In Progress

---

## Table of Contents

1. [Overview](#overview)
2. [Migration Rationale](#migration-rationale)
3. [Architecture Changes](#architecture-changes)
4. [API Changes](#api-changes)
5. [Migration Steps](#migration-steps)
6. [Code Examples](#code-examples)
7. [Testing Guide](#testing-guide)
8. [Troubleshooting](#troubleshooting)
9. [Timeline](#timeline)

---

## Overview

This document guides developers through migrating from the deprecated `/backend/app/services/scoring` module to the new OWCA Extraction Layer (`/backend/app/services/owca/extraction`).

### What Changed?

**Before** (Deprecated):
- `/scoring` module - Standalone SCAP scoring service
- Two separate compliance systems: `/scoring` and `/owca`
- Inconsistent APIs and patterns

**After** (Current):
- OWCA Extraction Layer (Layer 0) - Unified compliance platform
- Single source of truth for all compliance intelligence
- Consistent API patterns across all layers

### Impact

- **Breaking Changes**: None (backward compatibility maintained)
- **Deprecation**: `/scoring` module marked DEPRECATED with warnings
- **Action Required**: Migrate code to use OWCA Extraction Layer
- **Timeline**: `/scoring` removal planned for future release

---

## Migration Rationale

### Problems with Old Architecture

1. **Dual Compliance Systems**: `/scoring` and `/owca` performed related but separate functions
   - `/scoring`: Per-scan risk scoring (severity-weighted)
   - `/owca`: Per-host compliance scoring
   - Confusion about which to use when

2. **Code Duplication**: Similar patterns implemented twice
   - Both had severity weighting logic
   - Both had XML parsing capabilities
   - Maintenance burden for updates

3. **Inconsistent APIs**: Different naming conventions
   - `XCCDFScoreExtractor` vs. `ComplianceScoreCalculator`
   - `SeverityWeightingService` vs. `RiskScorer`
   - Difficult to learn and use

4. **Missing Integration**: No unified caching or optimization
   - `/scoring` had no caching
   - `/owca` had Redis caching but only for its own operations

### Benefits of New Architecture

1. **Single Source of Truth**: All compliance intelligence in OWCA
   - Clear ownership and responsibility
   - Easier to maintain and extend
   - Consistent patterns across all operations

2. **Unified Caching**: Redis caching for all extraction operations
   - 5-minute TTL for XCCDF parsing results
   - Reduced file I/O and XML parsing overhead
   - Improved performance for repeated queries

3. **Clear Layering**: OWCA now has 5 well-defined layers
   - Layer 0: Extraction (XML parsing, severity risk)
   - Layer 1: Core (compliance scoring)
   - Layer 2: Framework (NIST, CIS, STIG intelligence)
   - Layer 3: Aggregation (fleet-wide statistics)
   - Layer 4: Intelligence (trends, predictions)

4. **Consistent Naming**: All classes follow OWCA conventions
   - `XCCDFParser` (not `XCCDFScoreExtractor`)
   - `SeverityCalculator` (not `SeverityWeightingService`)
   - Clear, concise, descriptive names

5. **Better Security**: Centralized security controls
   - Single implementation of XXE prevention
   - Unified path traversal validation
   - Consistent audit logging

---

## Architecture Changes

### Old Architecture (4 Layers)

```
/backend/app/services/
├── scoring/                    # Standalone module
│   ├── xccdf_score_extractor.py
│   ├── severity_weighting_service.py
│   └── constants.py
│
└── owca/                       # Separate module
    ├── core/                   # Layer 1
    ├── framework/              # Layer 2
    ├── aggregation/            # Layer 3
    └── intelligence/           # Layer 4
```

### New Architecture (5 Layers)

```
/backend/app/services/
├── scoring/                    # DEPRECATED (backward compat only)
│   └── __init__.py (DeprecationWarning)
│
└── owca/                       # Unified platform
    ├── extraction/             # Layer 0 (NEW)
    │   ├── xccdf_parser.py
    │   ├── severity_calculator.py
    │   ├── constants.py
    │   └── __init__.py
    ├── core/                   # Layer 1
    ├── framework/              # Layer 2
    ├── aggregation/            # Layer 3
    └── intelligence/           # Layer 4
```

### Layer Responsibilities

**Layer 0: Extraction** (NEW)
- Extract native XCCDF scores from scan result XML files
- Calculate severity-weighted risk scores from finding counts
- Provide industry-standard severity weights and thresholds
- Security: XXE prevention, path traversal validation, file size limits

**Layer 1: Core**
- Calculate basic compliance scores (pass/fail percentage)
- Determine compliance tiers (EXCELLENT, GOOD, FAIR, POOR)
- Per-host compliance metrics

**Layer 2: Framework**
- Framework-specific intelligence (NIST 800-53, CIS, STIG)
- Control mapping and categorization
- Framework version management

**Layer 3: Aggregation**
- Fleet-wide statistics and rollups
- Group-level compliance metrics
- Organization-wide trends

**Layer 4: Intelligence**
- Predictive analytics and forecasting
- Risk scoring with trend analysis
- Anomaly detection and recommendations

---

## API Changes

### Class Renaming

| Old (Deprecated) | New (Current) | Rationale |
|-----------------|---------------|-----------|
| `XCCDFScoreExtractor` | `XCCDFParser` | More descriptive, matches common parser naming |
| `SeverityWeightingService` | `SeverityCalculator` | Consistent with OWCA naming (e.g., ScoreCalculator) |
| `RiskScoreResult` | `SeverityRiskResult` | Avoids confusion with OWCA Intelligence RiskScore |

### Import Changes

**Old Imports** (Deprecated):
```python
from backend.app.services.scoring import (
    XCCDFScoreExtractor,
    SeverityWeightingService,
    RiskScoreResult,
    SeverityDistribution,
    SEVERITY_WEIGHTS,
)
```

**New Imports** (Recommended):
```python
# Option 1: Import extraction layer directly
from backend.app.services.owca.extraction import (
    XCCDFParser,
    SeverityCalculator,
    SeverityRiskResult,
    SeverityDistribution,
    SEVERITY_WEIGHTS,
)

# Option 2: Import from OWCA main module (preferred)
from backend.app.services.owca import (
    get_owca_service,
    XCCDFParser,
    SeverityCalculator,
    SeverityRiskResult,
)
```

### Method Signature Changes

**XCCDF Score Extraction**

```python
# OLD (Deprecated)
from backend.app.services.scoring import XCCDFScoreExtractor

extractor = XCCDFScoreExtractor()
result = extractor.extract_native_score(
    result_file="/app/data/results/scan_123_xccdf.xml"
)

# NEW (Current) - Direct class usage
from backend.app.services.owca import XCCDFParser

parser = XCCDFParser()
result = parser.extract_native_score(
    result_file="/app/data/results/scan_123_xccdf.xml",
    user_id="user-uuid-123"  # Optional: for audit logging
)

# NEW (Preferred) - Via OWCA service with caching
from backend.app.services.owca import get_owca_service

owca = get_owca_service(db)
result = owca.extract_xccdf_score(
    result_file="/app/data/results/scan_123_xccdf.xml",
    user_id="user-uuid-123"  # Optional: for audit logging
)
# Benefit: Automatic Redis caching (5-minute TTL)
```

**Severity Risk Calculation**

```python
# OLD (Deprecated)
from backend.app.services.scoring import SeverityWeightingService

service = SeverityWeightingService()
risk_result = service.calculate_risk_score(
    critical_count=3,
    high_count=10,
    medium_count=25,
    low_count=50,
    info_count=100
)

# NEW (Current) - Direct class usage
from backend.app.services.owca import SeverityCalculator

calculator = SeverityCalculator()
risk_result = calculator.calculate_risk_score(
    critical_count=3,
    high_count=10,
    medium_count=25,
    low_count=50,
    info_count=100,
    user_id="user-uuid-123",  # Optional: for audit logging
    scan_id="scan-uuid-456"    # Optional: for audit logging
)

# NEW (Preferred) - Via OWCA service
from backend.app.services.owca import get_owca_service

owca = get_owca_service(db)
risk_result = owca.calculate_severity_risk(
    critical=3,
    high=10,
    medium=25,
    low=50,
    info=100,
    user_id="user-uuid-123",  # Optional: for audit logging
    scan_id="scan-uuid-456"    # Optional: for audit logging
)
```

### Result Model Changes

**XCCDFScoreResult** (unchanged structure, different import):
```python
# OLD
from backend.app.services.scoring import XCCDFScoreResult

# NEW
from backend.app.services.owca import XCCDFScoreResult

# Structure (identical):
result = XCCDFScoreResult(
    xccdf_score=87.5,
    xccdf_score_system="urn:xccdf:scoring:default",
    xccdf_score_max=100.0,
    found=True,
    error=None
)
```

**RiskScoreResult → SeverityRiskResult** (renamed):
```python
# OLD
from backend.app.services.scoring import RiskScoreResult

# NEW
from backend.app.services.owca import SeverityRiskResult

# Structure (identical):
result = SeverityRiskResult(
    risk_score=155.0,
    risk_level="critical",
    severity_distribution=SeverityDistribution(...),
    total_findings=188,
    weighted_breakdown={
        "critical": 30.0,
        "high": 50.0,
        "medium": 50.0,
        "low": 25.0,
        "info": 0.0
    }
)
```

---

## Migration Steps

### Step 1: Update Imports

Replace deprecated imports with new OWCA extraction layer imports.

**Example Migration**:
```python
# BEFORE
from backend.app.services.scoring import (
    XCCDFScoreExtractor,
    SeverityWeightingService,
    RiskScoreResult,
)

# AFTER
from backend.app.services.owca import (
    XCCDFParser,
    SeverityCalculator,
    SeverityRiskResult,
)
```

### Step 2: Update Class Instantiation

Replace old class names with new class names.

**Example Migration**:
```python
# BEFORE
extractor = XCCDFScoreExtractor()
severity_service = SeverityWeightingService()

# AFTER
parser = XCCDFParser()
calculator = SeverityCalculator()
```

### Step 3: Update Result Model References

Replace `RiskScoreResult` with `SeverityRiskResult`.

**Example Migration**:
```python
# BEFORE
def process_scan(scan_id: str) -> RiskScoreResult:
    risk_result: RiskScoreResult = severity_service.calculate_risk_score(...)
    return risk_result

# AFTER
def process_scan(scan_id: str) -> SeverityRiskResult:
    risk_result: SeverityRiskResult = calculator.calculate_risk_score(...)
    return risk_result
```

### Step 4: (Optional) Migrate to OWCA Service Pattern

For better caching and consistency, use the unified OWCA service.

**Example Migration**:
```python
# BEFORE
extractor = XCCDFScoreExtractor()
xccdf_result = extractor.extract_native_score(result_file)

severity_service = SeverityWeightingService()
risk_result = severity_service.calculate_risk_score(
    critical_count=5,
    high_count=10
)

# AFTER (with OWCA service)
from backend.app.services.owca import get_owca_service

owca = get_owca_service(db)

# Automatic caching via Redis
xccdf_result = owca.extract_xccdf_score(result_file)

# Consistent API
risk_result = owca.calculate_severity_risk(
    critical=5,
    high=10
)
```

### Step 5: Update Type Hints

Update type hints to use new model names.

**Example Migration**:
```python
# BEFORE
from typing import Optional
from backend.app.services.scoring import RiskScoreResult

async def get_scan_risk(scan_id: str) -> Optional[RiskScoreResult]:
    pass

# AFTER
from typing import Optional
from backend.app.services.owca import SeverityRiskResult

async def get_scan_risk(scan_id: str) -> Optional[SeverityRiskResult]:
    pass
```

### Step 6: Test Changes

Run comprehensive tests to verify migration.

```bash
# Backend tests
cd backend/
pytest tests/ -v -k "test_xccdf or test_severity or test_risk"

# Linting
black app/
flake8 app/
mypy app/

# Integration test
python3 -c "
from backend.app.services.owca import get_owca_service
from backend.app.database import SessionLocal

db = SessionLocal()
owca = get_owca_service(db)
print('OWCA Extraction Layer loaded successfully')
db.close()
"
```

### Step 7: Monitor Deprecation Warnings

After deployment, monitor logs for deprecation warnings.

```bash
# Check application logs
docker logs openwatch-backend --tail 100 | grep -i "deprecat"

# Expected warning format:
# DeprecationWarning: backend.app.services.scoring is deprecated and will be removed in a future release.
# Use backend.app.services.owca.extraction instead.
```

---

## Code Examples

### Example 1: SCAP Scan Result Processing

**Before** (Deprecated):
```python
from backend.app.services.scoring import (
    XCCDFScoreExtractor,
    SeverityWeightingService,
)

def process_scan_results(scan_id: str, result_file: str):
    """Process SCAP scan results and calculate risk score."""

    # Extract XCCDF native score
    extractor = XCCDFScoreExtractor()
    xccdf_result = extractor.extract_native_score(result_file)

    if not xccdf_result.found:
        logger.warning(f"No XCCDF score found: {xccdf_result.error}")
        return None

    # Calculate severity-weighted risk
    severity_service = SeverityWeightingService()
    risk_result = severity_service.calculate_risk_score(
        critical_count=scan_findings["critical"],
        high_count=scan_findings["high"],
        medium_count=scan_findings["medium"],
        low_count=scan_findings["low"],
    )

    return {
        "xccdf_score": xccdf_result.xccdf_score,
        "risk_score": risk_result.risk_score,
        "risk_level": risk_result.risk_level,
    }
```

**After** (Current):
```python
from backend.app.services.owca import get_owca_service

def process_scan_results(
    db: Session,
    scan_id: str,
    result_file: str,
    user_id: str
):
    """Process SCAP scan results and calculate risk score."""

    # Get OWCA service with caching
    owca = get_owca_service(db)

    # Extract XCCDF native score (cached for 5 minutes)
    xccdf_result = owca.extract_xccdf_score(
        result_file=result_file,
        user_id=user_id
    )

    if not xccdf_result.found:
        logger.warning(f"No XCCDF score found: {xccdf_result.error}")
        return None

    # Calculate severity-weighted risk (with audit logging)
    risk_result = owca.calculate_severity_risk(
        critical=scan_findings["critical"],
        high=scan_findings["high"],
        medium=scan_findings["medium"],
        low=scan_findings["low"],
        user_id=user_id,
        scan_id=scan_id
    )

    return {
        "xccdf_score": xccdf_result.xccdf_score,
        "risk_score": risk_result.risk_score,
        "risk_level": risk_result.risk_level,
        "severity_distribution": risk_result.severity_distribution.dict(),
    }
```

### Example 2: API Endpoint Migration

**Before** (Deprecated):
```python
from fastapi import APIRouter, Depends
from backend.app.services.scoring import (
    SeverityWeightingService,
    RiskScoreResult,
)

router = APIRouter()

@router.post("/calculate-risk")
async def calculate_risk(
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
) -> RiskScoreResult:
    """Calculate severity-weighted risk score."""
    service = SeverityWeightingService()
    return service.calculate_risk_score(
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
    )
```

**After** (Current):
```python
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.services.owca import (
    get_owca_service,
    SeverityRiskResult,
)
from backend.app.middleware.rbac_middleware import require_permission

router = APIRouter()

@router.post("/calculate-risk")
@require_permission("scans:read")  # Add RBAC
async def calculate_risk(
    critical: int = 0,
    high: int = 0,
    medium: int = 0,
    low: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> SeverityRiskResult:
    """
    Calculate severity-weighted risk score.

    Uses OWCA Extraction Layer with NIST SP 800-30 weights:
    - Critical: 10 points each
    - High: 5 points each
    - Medium: 2 points each
    - Low: 0.5 points each
    """
    owca = get_owca_service(db)
    return owca.calculate_severity_risk(
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        user_id=str(current_user.id),  # Audit logging
    )
```

### Example 3: Background Task Migration

**Before** (Deprecated):
```python
from celery import shared_task
from backend.app.services.scoring import XCCDFScoreExtractor

@shared_task
def parse_scan_results(scan_id: str, result_file: str):
    """Background task to parse SCAP scan results."""
    extractor = XCCDFScoreExtractor()
    result = extractor.extract_native_score(result_file)

    if result.found:
        # Store in database
        update_scan_score(scan_id, result.xccdf_score)
```

**After** (Current):
```python
from celery import shared_task
from backend.app.database import SessionLocal
from backend.app.services.owca import get_owca_service

@shared_task
def parse_scan_results(scan_id: str, result_file: str, user_id: str):
    """Background task to parse SCAP scan results."""
    db = SessionLocal()
    try:
        owca = get_owca_service(db)

        # Cached extraction with audit logging
        result = owca.extract_xccdf_score(
            result_file=result_file,
            user_id=user_id
        )

        if result.found:
            # Store in database
            update_scan_score(scan_id, result.xccdf_score)
        else:
            logger.error(f"XCCDF parsing failed: {result.error}")
    finally:
        db.close()
```

---

## Testing Guide

### Unit Tests

**Test XCCDF Parsing**:
```python
import pytest
from backend.app.services.owca import XCCDFParser, XCCDFScoreResult

@pytest.mark.unit
def test_xccdf_parser_valid_file():
    """Test XCCDF parser with valid result file."""
    parser = XCCDFParser()

    result = parser.extract_native_score(
        result_file="/app/data/test/scan_result_valid.xml"
    )

    assert result.found is True
    assert result.xccdf_score is not None
    assert 0.0 <= result.xccdf_score <= 100.0
    assert result.error is None

@pytest.mark.unit
def test_xccdf_parser_invalid_file():
    """Test XCCDF parser with invalid file path."""
    parser = XCCDFParser()

    result = parser.extract_native_score(
        result_file="/nonexistent/file.xml"
    )

    assert result.found is False
    assert result.error is not None
    assert "not found" in result.error.lower()

@pytest.mark.unit
def test_xccdf_parser_path_traversal():
    """Test XCCDF parser rejects path traversal attacks."""
    parser = XCCDFParser()

    result = parser.extract_native_score(
        result_file="/app/data/../../etc/passwd"
    )

    assert result.found is False
    assert "path traversal" in result.error.lower()
```

**Test Severity Risk Calculation**:
```python
import pytest
from backend.app.services.owca import (
    SeverityCalculator,
    SeverityRiskResult,
)

@pytest.mark.unit
def test_severity_calculator_critical_findings():
    """Test risk score for critical findings."""
    calculator = SeverityCalculator()

    result = calculator.calculate_risk_score(
        critical_count=10,
        high_count=0,
        medium_count=0,
        low_count=0,
    )

    assert result.risk_score == 100.0  # 10 * 10
    assert result.risk_level == "critical"
    assert result.total_findings == 10

@pytest.mark.unit
def test_severity_calculator_mixed_findings():
    """Test risk score with mixed severity levels."""
    calculator = SeverityCalculator()

    result = calculator.calculate_risk_score(
        critical_count=2,   # 2 * 10 = 20
        high_count=5,       # 5 * 5 = 25
        medium_count=10,    # 10 * 2 = 20
        low_count=20,       # 20 * 0.5 = 10
    )

    assert result.risk_score == 75.0
    assert result.risk_level == "high"
    assert result.total_findings == 37

@pytest.mark.unit
def test_severity_calculator_risk_levels():
    """Test risk level categorization."""
    calculator = SeverityCalculator()

    # Low risk (0-20)
    low_result = calculator.calculate_risk_score(low_count=40)
    assert low_result.risk_level == "low"

    # Medium risk (21-50)
    medium_result = calculator.calculate_risk_score(medium_count=20)
    assert medium_result.risk_level == "medium"

    # High risk (51-100)
    high_result = calculator.calculate_risk_score(high_count=15)
    assert high_result.risk_level == "high"

    # Critical risk (100+)
    critical_result = calculator.calculate_risk_score(critical_count=11)
    assert critical_result.risk_level == "critical"
```

### Integration Tests

**Test OWCA Service Integration**:
```python
import pytest
from backend.app.services.owca import get_owca_service
from backend.app.database import SessionLocal

@pytest.mark.integration
async def test_owca_service_initialization():
    """Test OWCA service initializes extraction layer."""
    db = SessionLocal()
    try:
        owca = get_owca_service(db)

        # Verify extraction layer components
        assert owca.xccdf_parser is not None
        assert owca.severity_calculator is not None

        # Verify methods exist
        assert hasattr(owca, 'extract_xccdf_score')
        assert hasattr(owca, 'calculate_severity_risk')
    finally:
        db.close()

@pytest.mark.integration
async def test_owca_xccdf_caching():
    """Test OWCA XCCDF extraction uses Redis caching."""
    db = SessionLocal()
    try:
        owca = get_owca_service(db)

        # First call - cache miss
        result1 = owca.extract_xccdf_score(
            result_file="/app/data/test/scan_result.xml"
        )

        # Second call - cache hit (should be faster)
        result2 = owca.extract_xccdf_score(
            result_file="/app/data/test/scan_result.xml"
        )

        # Results should be identical
        assert result1.xccdf_score == result2.xccdf_score
        assert result1.found == result2.found
    finally:
        db.close()
```

### Regression Tests

**Test Backward Compatibility**:
```python
import pytest
import warnings

@pytest.mark.regression
def test_scoring_module_deprecation_warning():
    """Test /scoring module issues deprecation warning."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")

        # Import deprecated module
        from backend.app.services.scoring import XCCDFScoreExtractor

        # Verify deprecation warning
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert "deprecated" in str(w[0].message).lower()
        assert "owca.extraction" in str(w[0].message).lower()

@pytest.mark.regression
def test_scoring_module_backward_compatibility():
    """Test /scoring module maintains backward compatibility."""
    from backend.app.services.scoring import (
        XCCDFScoreExtractor,
        SeverityWeightingService,
        RiskScoreResult,
    )

    # Old classes should still exist
    extractor = XCCDFScoreExtractor()
    service = SeverityWeightingService()

    # Old methods should still work
    assert hasattr(extractor, 'extract_native_score')
    assert hasattr(service, 'calculate_risk_score')
```

---

## Troubleshooting

### Issue 1: Import Errors

**Symptom**:
```python
ImportError: cannot import name 'XCCDFScoreExtractor' from 'backend.app.services.owca'
```

**Cause**: Importing deprecated class from new module.

**Solution**:
```python
# WRONG
from backend.app.services.owca import XCCDFScoreExtractor

# CORRECT
from backend.app.services.owca import XCCDFParser
```

### Issue 2: Deprecation Warnings in Logs

**Symptom**:
```
DeprecationWarning: backend.app.services.scoring is deprecated
```

**Cause**: Code still using `/scoring` module.

**Solution**: Migrate to OWCA extraction layer (see [Migration Steps](#migration-steps)).

### Issue 3: Type Errors

**Symptom**:
```python
TypeError: incompatible type "RiskScoreResult"; expected "SeverityRiskResult"
```

**Cause**: Type hints not updated for renamed model.

**Solution**:
```python
# WRONG
from backend.app.services.owca import RiskScoreResult

# CORRECT
from backend.app.services.owca import SeverityRiskResult
```

### Issue 4: Caching Not Working

**Symptom**: XCCDF parsing slow despite caching.

**Cause**: Using direct `XCCDFParser` instead of OWCA service.

**Solution**:
```python
# Without caching (slower)
parser = XCCDFParser()
result = parser.extract_native_score(file)

# With caching (faster)
owca = get_owca_service(db)
result = owca.extract_xccdf_score(file)
```

### Issue 5: Missing Audit Logs

**Symptom**: No audit logs for XCCDF extraction.

**Cause**: Not passing `user_id` parameter.

**Solution**:
```python
# Without audit logging
result = owca.extract_xccdf_score(result_file)

# With audit logging
result = owca.extract_xccdf_score(
    result_file=result_file,
    user_id=current_user.id  # Add this
)
```

---

## Timeline

### Phase 1: Implementation (COMPLETED - 2025-11-22)

- [DONE] Created OWCA Extraction Layer (4 new files)
- [DONE] Migrated XCCDF parsing logic
- [DONE] Migrated severity risk calculation
- [DONE] Integrated with OWCA service
- [DONE] Added deprecation warnings
- [DONE] Updated consumers (mongodb_scan_api.py)
- [DONE] Passed all pre-commit hooks
- [DONE] Committed to repository

### Phase 2: Testing & Documentation (COMPLETED - 2025-11-22)

- [DONE] Create migration guide (this document)
- [DONE] Update CLAUDE.md with extraction layer docs
- [DONE] Verify integration with running containers
- [DONE] Test XCCDF parsing functionality
- [DONE] Test severity calculations (4 test scenarios validated)
- [DONE] Create comprehensive unit test suite (28 tests, 650 lines)

### Phase 3: Transition Period (2-4 weeks)

- [PENDING] Monitor application logs for deprecation warnings
- [PENDING] Identify remaining `/scoring` consumers
- [PENDING] Assist teams with migration
- [PENDING] Update internal documentation
- [PENDING] Validate performance improvements

### Phase 4: Cleanup (Future Release)

- [PENDING] Remove `/scoring` directory
- [PENDING] Remove backward compatibility code
- [PENDING] Update all references to OWCA
- [PENDING] Archive deprecation warnings

---

## Support

### Questions?

- **Documentation**: See `/docs/CLAUDE.md` for OWCA architecture
- **Examples**: See code examples in this guide
- **Issues**: File GitHub issue with `owca` and `migration` labels

### Getting Help

```bash
# Check OWCA service status
docker exec -it openwatch-backend python3 -c "
from backend.app.database import SessionLocal
from backend.app.services.owca import get_owca_service

db = SessionLocal()
owca = get_owca_service(db)
print(f'OWCA Extraction Layer: {owca.xccdf_parser is not None}')
db.close()
"

# Verify extraction layer imports
docker exec -it openwatch-backend python3 -c "
from backend.app.services.owca.extraction import (
    XCCDFParser,
    SeverityCalculator,
    SEVERITY_WEIGHTS,
)
print('All imports successful')
"
```

---

**Document Version**: 1.0.0
**Last Updated**: 2025-11-22
**Maintained By**: OpenWatch Development Team
**Related**: CLAUDE.md, OWCA Architecture Documentation
