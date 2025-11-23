# OWCA Extraction Layer - Phase 4 Cleanup Checklist

**Document Version**: 1.0.0
**Last Updated**: 2025-11-23
**Status**: Planning Document (Phase 3 must complete first)
**Related**: [OWCA_EXTRACTION_LAYER_MIGRATION.md](OWCA_EXTRACTION_LAYER_MIGRATION.md)

---

## Overview

This document provides a comprehensive checklist for Phase 4 of the OWCA Extraction Layer migration - the final cleanup and removal of deprecated `/scoring` module code.

**IMPORTANT**: This phase should NOT begin until:
- ✅ Phase 3 transition period complete (2-4 weeks minimum)
- ✅ No deprecation warnings in production logs for 2+ weeks
- ✅ All application code migrated to OWCA extraction layer
- ✅ All teams notified and prepared for removal

---

## Table of Contents

1. [Pre-Cleanup Validation](#pre-cleanup-validation)
2. [Files to Remove](#files-to-remove)
3. [Code Changes Required](#code-changes-required)
4. [Tests to Update](#tests-to-update)
5. [Documentation Updates](#documentation-updates)
6. [Validation Steps](#validation-steps)
7. [Rollback Plan](#rollback-plan)

---

## Pre-Cleanup Validation

Before proceeding with Phase 4 cleanup, verify ALL of the following:

### Monitoring Requirements

- [ ] No deprecation warnings in production logs for 14+ consecutive days
- [ ] Monitoring script shows zero deprecated imports: `./scripts/monitor-owca-migration.sh --deprecations`
- [ ] All application code using OWCA extraction layer (not `/scoring`)
- [ ] Phase 3 transition period elapsed (minimum 2 weeks, recommended 4 weeks)

### Stakeholder Sign-off

- [ ] Development team notified of upcoming removal
- [ ] Operations team reviewed and approved
- [ ] No objections from security team
- [ ] Documentation updated and reviewed

### Testing Prerequisites

- [ ] All OWCA extraction layer tests passing (28+ tests in `test_owca_extraction.py`)
- [ ] Integration tests passing with OWCA extraction layer
- [ ] No regressions reported during Phase 3 monitoring
- [ ] Performance metrics stable or improved

### Backup and Safety

- [ ] Git branch created for cleanup work: `feature/owca-phase4-cleanup`
- [ ] Current production version tagged: `git tag -a v1.x.x-pre-cleanup -m "Before OWCA Phase 4 cleanup"`
- [ ] Rollback plan documented and tested (see [Rollback Plan](#rollback-plan))

---

## Files to Remove

### Core Deprecated Module Files

Remove the entire `/backend/app/services/scoring` directory:

```bash
# Files to be deleted
backend/app/services/scoring/
├── __init__.py                      # Backward compatibility shim with DeprecationWarning
├── xccdf_score_extractor.py         # Old XCCDF parser (replaced by XCCDFParser)
├── severity_weighting_service.py    # Old severity calculator (replaced by SeverityCalculator)
└── constants.py                     # Old constants (replaced by extraction/constants.py)
```

**Command to remove**:
```bash
# CAUTION: Only run after Phase 3 complete!
git rm -rf backend/app/services/scoring/
```

### Deprecated Test Files

Remove old test files for deprecated module:

```bash
# Files to be deleted
backend/tests/unit/test_xccdf_score_extractor.py           # Tests for deprecated XCCDFScoreExtractor
backend/tests/unit/test_severity_weighting_service.py      # Tests for deprecated SeverityWeightingService
```

**Command to remove**:
```bash
# CAUTION: Only run after Phase 3 complete!
git rm backend/tests/unit/test_xccdf_score_extractor.py
git rm backend/tests/unit/test_severity_weighting_service.py
```

**Note**: These tests are currently valuable for ensuring backward compatibility. Only remove after all application code migrated.

---

## Code Changes Required

### Remove Backward Compatibility Imports

**File**: `backend/app/services/owca/__init__.py`

**Before** (with backward compatibility):
```python
# Backward compatibility exports (Phase 3 only)
from backend.app.services.owca.extraction import (
    XCCDFParser as XCCDFScoreExtractor,  # Alias for old name
    SeverityCalculator as SeverityWeightingService,  # Alias for old name
)
```

**After** (Phase 4 cleanup):
```python
# Backward compatibility removed - use new names only
# Old imports will now fail with ImportError (intentional)
```

### Remove Deprecation Warnings

**File**: `backend/app/services/owca/__init__.py`

Remove any code related to deprecation warnings:

```python
# REMOVE THIS BLOCK in Phase 4
import warnings
warnings.warn(
    "backend.app.services.scoring is deprecated...",
    DeprecationWarning,
    stacklevel=2,
)
```

### Update Import Statements

Verify no code still imports from deprecated locations:

```bash
# Should return ZERO results after Phase 4
grep -r "from backend.app.services.scoring import" backend/ \
    --exclude-dir=__pycache__ \
    --exclude-dir=.pytest_cache

# Should return ZERO results after Phase 4
grep -r "XCCDFScoreExtractor" backend/ \
    --exclude-dir=__pycache__ \
    --exclude-dir=.pytest_cache \
    --exclude-dir=scoring

# Should return ZERO results after Phase 4
grep -r "SeverityWeightingService" backend/ \
    --exclude-dir=__pycache__ \
    --exclude-dir=.pytest_cache \
    --exclude-dir=scoring
```

---

## Tests to Update

### Remove Backward Compatibility Tests

Remove tests that specifically validate backward compatibility:

**File**: `backend/tests/unit/test_owca_extraction.py`

Remove or comment out backward compatibility test section:

```python
# REMOVE THIS CLASS in Phase 4
class TestBackwardCompatibility:
    """
    Tests for backward compatibility with deprecated /scoring module.

    NOTE: Remove this entire test class in Phase 4 cleanup.
    """

    @pytest.mark.regression
    def test_scoring_module_imports(self):
        # ...deprecated import tests...
```

### Update Test Documentation

Update test file docstrings to remove references to deprecated module:

```python
# BEFORE
"""
Tests OWCA Extraction Layer and backward compatibility with /scoring module.
"""

# AFTER
"""
Tests OWCA Extraction Layer (Layer 0) - XCCDF parsing and severity risk scoring.
"""
```

### Verify All Tests Pass

After cleanup, verify comprehensive test coverage:

```bash
# Run all OWCA extraction layer tests
pytest backend/tests/unit/test_owca_extraction.py -v

# Run all backend tests
pytest backend/tests/ -v

# Verify no import errors
python3 -c "from backend.app.services.owca import XCCDFParser, SeverityCalculator; print('SUCCESS')"
```

---

## Documentation Updates

### Update Migration Guide

**File**: `docs/OWCA_EXTRACTION_LAYER_MIGRATION.md`

Update Phase 4 status:

```markdown
### Phase 4: Cleanup (COMPLETED - YYYY-MM-DD)

- [DONE] Removed /scoring directory
- [DONE] Removed backward compatibility code
- [DONE] Updated all references to OWCA
- [DONE] Archived deprecation warnings
```

### Update CLAUDE.md

**File**: `CLAUDE.md`

Remove references to deprecated `/scoring` module:

**Search for**: `/scoring`, `XCCDFScoreExtractor`, `SeverityWeightingService`

**Replace with**: References to OWCA extraction layer only

### Update API Documentation

**File**: `backend/app/main.py` or relevant API docs

Remove any endpoint documentation referencing old `/scoring` module.

### Archive Migration Documentation

Create archive copy of migration guide:

```bash
# Preserve migration history
cp docs/OWCA_EXTRACTION_LAYER_MIGRATION.md \
   docs/archive/OWCA_EXTRACTION_LAYER_MIGRATION_COMPLETED_$(date +%Y%m%d).md
```

---

## Validation Steps

### Step 1: Verify No Deprecated Imports

```bash
# Run monitoring script - should show all PASS
./scripts/monitor-owca-migration.sh --deprecations

# Expected output:
# PASS: No deprecated /scoring imports found
# PASS: No XCCDFScoreExtractor usage found
# PASS: No SeverityWeightingService usage found
# PASS: No RiskScoreResult usage found
```

### Step 2: Verify OWCA Adoption

```bash
# Run monitoring script - should show positive numbers
./scripts/monitor-owca-migration.sh --usage

# Expected output:
# Found 29 references to XCCDFParser
# Found 32 references to SeverityCalculator
# Found 35 references to get_owca_service
# SUCCESS: All extraction layer files present
```

### Step 3: Run Full Test Suite

```bash
# Backend tests
cd backend/
pytest tests/ -v

# Should see 0 failures, 0 errors
# All OWCA extraction layer tests passing
```

### Step 4: Integration Testing

```bash
# Start OpenWatch services
./start-openwatch.sh --runtime docker

# Verify OWCA service operational
docker exec openwatch-backend python3 -c "
from backend.app.database import SessionLocal
from backend.app.services.owca import get_owca_service

db = SessionLocal()
owca = get_owca_service(db)
print('OWCA XCCDFParser:', owca.xccdf_parser is not None)
print('OWCA SeverityCalculator:', owca.severity_calculator is not None)
db.close()
"

# Expected output:
# OWCA XCCDFParser: True
# OWCA SeverityCalculator: True
```

### Step 5: Verify Import Errors

Confirm old imports now fail (as intended):

```bash
# This SHOULD fail after Phase 4
docker exec openwatch-backend python3 -c "
from backend.app.services.scoring import XCCDFScoreExtractor
" 2>&1 | grep -i "import\|error"

# Expected output: ImportError or ModuleNotFoundError
```

### Step 6: Check Application Logs

```bash
# Check for errors after cleanup
docker logs openwatch-backend --tail 100 | grep -i "error\|fail\|except"

# Should see no import errors or missing module errors
```

---

## Rollback Plan

If Phase 4 cleanup causes issues, follow this rollback procedure:

### Emergency Rollback (Quick)

```bash
# 1. Revert to pre-cleanup git tag
git checkout v1.x.x-pre-cleanup

# 2. Rebuild containers
./stop-openwatch.sh
./start-openwatch.sh --runtime docker --build

# 3. Verify services operational
curl http://localhost:8000/health
```

### Surgical Rollback (Restore /scoring only)

```bash
# 1. Restore /scoring directory from previous commit
git checkout HEAD~1 -- backend/app/services/scoring/

# 2. Restore deprecated test files
git checkout HEAD~1 -- backend/tests/unit/test_xccdf_score_extractor.py

# 3. Commit rollback
git add backend/app/services/scoring/ backend/tests/
git commit -m "rollback: Restore /scoring module (Phase 4 rollback)"

# 4. Deploy
./stop-openwatch.sh
./start-openwatch.sh --runtime docker
```

### Post-Rollback Actions

- [ ] Identify root cause of failure
- [ ] Document issue in migration guide
- [ ] Notify development team
- [ ] Extend Phase 3 transition period
- [ ] Re-plan Phase 4 timeline

---

## Cleanup Commit Message Template

Use this template when committing Phase 4 cleanup:

```
chore(owca): Phase 4 cleanup - Remove deprecated /scoring module

This commit completes Phase 4 of the OWCA Extraction Layer migration
by removing all deprecated code from the /scoring module.

Changes:
- Remove backend/app/services/scoring/ directory (4 files)
- Remove backend/tests/unit/test_xccdf_score_extractor.py
- Remove backward compatibility imports from owca/__init__.py
- Update documentation to remove /scoring references

Phase 4 Validation:
- Zero deprecation warnings for 14+ consecutive days
- All application code migrated to OWCA extraction layer
- 28 tests passing in test_owca_extraction.py
- Integration tests passing
- Performance metrics stable

Migration Timeline:
- Phase 1 (Implementation): COMPLETE - 2025-11-22
- Phase 2 (Testing/Docs): COMPLETE - 2025-11-22
- Phase 3 (Transition): COMPLETE - 2025-XX-XX
- Phase 4 (Cleanup): COMPLETE - 2025-XX-XX

Related:
- Migration Guide: docs/OWCA_EXTRACTION_LAYER_MIGRATION.md
- Phase 4 Checklist: docs/OWCA_PHASE4_CLEANUP_CHECKLIST.md
- Test Suite: backend/tests/unit/test_owca_extraction.py

Breaking Changes: YES
- Imports from backend.app.services.scoring will fail with ImportError
- Old class names (XCCDFScoreExtractor, SeverityWeightingService) no longer available
- All consumers MUST use OWCA extraction layer

Generated with Claude Code
https://claude.com/claude-code

Co-Authored-By: Claude <noreply@anthropic.com>
```

---

## Phase 4 Timeline Estimate

**Prerequisites**:
- Phase 3 transition period: 2-4 weeks minimum
- Zero deprecation warnings: 14+ consecutive days

**Phase 4 Execution**:
- Pre-validation: 1 hour
- Code cleanup: 2 hours
- Testing: 2 hours
- Documentation: 1 hour
- Deployment: 1 hour
- Post-deployment monitoring: 24 hours

**Total Duration**: 1-2 days (after Phase 3 prerequisites met)

---

## Sign-off Checklist

Before declaring Phase 4 complete, obtain sign-off from:

- [ ] Development Lead: Code reviewed and approved
- [ ] QA Lead: All tests passing, no regressions
- [ ] Operations Lead: Deployment successful, monitoring stable
- [ ] Security Lead: No security concerns, audit logs clean
- [ ] Technical Documentation: All docs updated

---

## Success Criteria

Phase 4 cleanup is considered complete when ALL of the following are true:

✅ `/backend/app/services/scoring` directory removed from repository
✅ No code references to `XCCDFScoreExtractor` or `SeverityWeightingService`
✅ All tests passing (0 failures, 0 errors)
✅ No import errors in application logs
✅ OWCA extraction layer operational in all environments
✅ Documentation updated to remove deprecated references
✅ Monitoring script shows 100% OWCA adoption
✅ Zero deprecation warnings in logs for 14+ days post-cleanup

---

## Support

### Questions During Phase 4?

- **Pre-cleanup concerns**: Review [Pre-Cleanup Validation](#pre-cleanup-validation)
- **Rollback needed**: Follow [Rollback Plan](#rollback-plan)
- **Import errors**: Verify [Code Changes Required](#code-changes-required)
- **Test failures**: Check [Validation Steps](#validation-steps)

### Post-Cleanup Issues

If issues arise after Phase 4 cleanup:

1. Check application logs: `docker logs openwatch-backend --tail 200`
2. Run monitoring script: `./scripts/monitor-owca-migration.sh`
3. Verify OWCA initialization: See [Validation Steps](#validation-steps)
4. If critical, execute [Emergency Rollback](#emergency-rollback-quick)

---

**Document Version**: 1.0.0
**Last Updated**: 2025-11-23
**Maintained By**: OpenWatch Development Team
**Related Documents**:
- [OWCA_EXTRACTION_LAYER_MIGRATION.md](OWCA_EXTRACTION_LAYER_MIGRATION.md)
- [CLAUDE.md](../CLAUDE.md)

---

## Appendix: Files Impacted by Phase 4

### Files to DELETE

```
backend/app/services/scoring/__init__.py
backend/app/services/scoring/xccdf_score_extractor.py
backend/app/services/scoring/severity_weighting_service.py
backend/app/services/scoring/constants.py
backend/tests/unit/test_xccdf_score_extractor.py
backend/tests/unit/test_severity_weighting_service.py (if exists)
```

### Files to MODIFY

```
backend/app/services/owca/__init__.py              # Remove backward compat imports
backend/tests/unit/test_owca_extraction.py         # Remove backward compat tests
docs/OWCA_EXTRACTION_LAYER_MIGRATION.md            # Update Phase 4 status
docs/CLAUDE.md                                     # Remove /scoring references
```

### Files to VERIFY (should have ZERO matches)

```bash
# After Phase 4, these greps should return nothing:
grep -r "from backend.app.services.scoring" backend/
grep -r "XCCDFScoreExtractor" backend/
grep -r "SeverityWeightingService" backend/
grep -r "RiskScoreResult" backend/
```

---

**END OF PHASE 4 CLEANUP CHECKLIST**
