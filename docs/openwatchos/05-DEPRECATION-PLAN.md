# MongoDB Deprecation Plan

**Current State**: MongoDB removed from docker-compose and CI pipeline (2026-02-16). Legacy code remains for import compatibility.

## Background

OpenWatch originally used MongoDB for compliance rules, rule intelligence, remediation scripts, and upload history. With the Aegis integration (338 YAML rules replacing SCAP/OVAL content), MongoDB's purpose has been eliminated:

| Former MongoDB Collection | Replacement |
|--------------------------|-------------|
| `compliance_rules` | Aegis YAML rules in `backend/aegis/rules/` |
| `rule_intelligence` | PostgreSQL JSONB columns |
| `remediation_scripts` | Aegis native remediation |
| `upload_history` | PostgreSQL table |

## Current State

- MongoDB container removed from `docker-compose.yml`
- MongoDB removed from CI pipeline (`.github/workflows/ci.yml`)
- MongoDB connection in `app/database.py` is a no-op when unavailable
- Python packages remain in `requirements.txt`: `motor==3.7.1`, `pymongo==4.16.0`, `beanie==1.26.0`
- **26 files** still contain MongoDB imports

## Affected Files

### Models (2 files)
- `app/models/mongo_models.py` -- Beanie Document models (delete entirely)
- `app/models/__init__.py` -- Re-exports MongoDB models (remove mongo imports)

### Repositories (4 files)
- `app/repositories/compliance_repository.py` -- MongoDB compliance rule queries
- `app/repositories/enhanced_repository.py` -- Enhanced MongoDB operations
- `app/repositories/intelligence_repository.py` -- Rule intelligence queries
- `app/repositories/remediation_repository.py` -- Remediation script queries

### Services (10 files)
- `app/services/mongo_integration_service.py` -- Legacy bridge service (delete entirely)
- `app/services/compliance_rules/upload.py` -- SCAP content upload to MongoDB
- `app/services/compliance_rules/dependency/graph.py` -- Rule dependency graph
- `app/services/compliance_rules/validation/deduplication.py` -- Duplicate rule detection
- `app/services/content/import_/importer.py` -- Content batch import
- `app/services/content/__init__.py` -- Content module init
- `app/services/content/transformation/__init__.py` -- Transformation init
- `app/services/content/transformation/transformer.py` -- MongoDB document transform
- `app/services/result_enrichment_service.py` -- Scan result enrichment
- `app/services/rules/service.py` -- Rule service (has mongo fallback)

### Routes (2 files)
- `app/routes/scans/compliance.py` -- Compliance scan routes
- `app/routes/scans/config.py` -- Scan configuration routes

### Infrastructure (3 files)
- `app/services/monitoring/health.py` -- Health check includes MongoDB status
- `app/services/framework/reporting.py` -- Framework report generation
- `app/tasks/health_monitoring_tasks.py` -- Health monitoring Celery tasks

### CLI Tools (3 files)
- `app/cli/load_compliance_rules.py` -- Load rules into MongoDB (obsolete)
- `app/cli/load_rules_fixed.py` -- Fixed rule loader (obsolete)
- `app/cli/migrate_oval_references.py` -- OVAL migration (obsolete)

### Other (2 files)
- `app/models/plugin_models.py` -- Plugin models with MongoDB references
- `app/services/engine/scanners/owscan.py` -- Scanner with MongoDB fallback

## Removal Plan

### Phase 1: Remove Dead CLI Tools (Low Risk)

Delete 3 CLI scripts that are fully obsolete:
- `app/cli/load_compliance_rules.py`
- `app/cli/load_rules_fixed.py`
- `app/cli/migrate_oval_references.py`

These are standalone scripts with no callers.

### Phase 2: Remove Dead Services (Low Risk)

Delete services that exist solely for MongoDB operations:
- `app/services/mongo_integration_service.py` -- Legacy bridge, no callers
- `app/services/content/transformation/transformer.py` -- MongoDB document transform
- `app/services/compliance_rules/upload.py` -- SCAP content upload (replaced by Aegis)
- `app/services/compliance_rules/dependency/graph.py` -- Rule dependency (not used with Aegis)
- `app/services/compliance_rules/validation/deduplication.py` -- MongoDB dedup

Update `__init__.py` files to remove re-exports.

### Phase 3: Clean Repositories (Medium Risk)

Remove or refactor repositories that have MongoDB paths:
- `app/repositories/compliance_repository.py` -- Remove MongoDB query methods
- `app/repositories/enhanced_repository.py` -- Delete if fully MongoDB-based
- `app/repositories/intelligence_repository.py` -- Delete (replaced by PostgreSQL JSONB)
- `app/repositories/remediation_repository.py` -- Delete (replaced by Aegis)

Verify no active code paths call the removed methods.

### Phase 4: Clean Routes and Services (Medium Risk)

Remove MongoDB fallback paths in services that have dual PostgreSQL/MongoDB code:
- `app/services/rules/service.py` -- Remove mongo fallback, keep Aegis path
- `app/services/engine/scanners/owscan.py` -- Remove MongoDB result storage
- `app/routes/scans/compliance.py` -- Remove MongoDB references
- `app/routes/scans/config.py` -- Remove MongoDB references
- `app/services/monitoring/health.py` -- Remove MongoDB health check
- `app/tasks/health_monitoring_tasks.py` -- Remove MongoDB monitoring

### Phase 5: Final Cleanup (Low Risk)

1. Delete `app/models/mongo_models.py`
2. Clean `app/models/__init__.py` -- remove mongo imports
3. Clean `app/models/plugin_models.py` -- remove mongo references
4. Remove from `requirements.txt`:
   - `motor==3.7.1`
   - `pymongo==4.16.0`
   - `beanie==1.26.0`
5. Remove MongoDB configuration from `app/config.py`
6. Remove Beanie initialization from `app/database.py` and `app/main.py`
7. Run full test suite to verify nothing breaks

## Verification

After each phase:
1. Run `pytest tests/ -x --timeout=30` -- all tests pass
2. Run `flake8 app/ --count` -- no import errors
3. Run `mypy app/ --ignore-missing-imports` -- no type errors
4. Search for remaining mongo imports: `grep -r "mongo\|beanie\|motor" app/ --include="*.py"`
5. Start the application and verify health check passes

After Phase 5:
- `pip install -r requirements.txt` should not install MongoDB packages
- Application starts without any MongoDB-related log messages
- All API endpoints functional
- Compliance scanning via Aegis works end-to-end

## Risk Assessment

| Phase | Risk | Mitigation |
|-------|------|------------|
| Phase 1 | None | CLI tools have no callers |
| Phase 2 | Low | Services are not imported by active code |
| Phase 3 | Medium | Verify no active routes call removed repo methods |
| Phase 4 | Medium | Test all scan and compliance endpoints after changes |
| Phase 5 | Low | Final cleanup after active code is already clean |

## Estimated Effort

- Phase 1: 30 minutes
- Phase 2: 1 hour
- Phase 3: 1-2 hours (need to trace callers)
- Phase 4: 2-3 hours (test-heavy)
- Phase 5: 30 minutes
- **Total**: ~5-7 hours across 1-2 sessions
