# Appendix B: File Inventory and Migration Plan

**Document**: B-FILE-INVENTORY.md
**Last Updated**: 2026-01-21

---

## 1. Route Files Migration

### 1.1 Files to DELETE (Duplicates)

| File | Lines | Duplicate Of | Action |
|------|-------|--------------|--------|
| routes/ssh_settings.py | ~400 | routes/ssh/settings.py | DELETE after merge |
| routes/ssh_debug.py | ~450 | routes/ssh/debug.py | DELETE after merge |
| routes/scan_config_api.py | ~600 | routes/scans/config.py | DELETE after merge |
| routes/hosts_legacy.py | ~1500 | routes/hosts/*.py | DELETE |

### 1.2 Files to MIGRATE

| Current Location | Target Location | Priority |
|------------------|-----------------|----------|
| routes/auth.py | routes/auth/login.py | P1 |
| routes/mfa.py | routes/auth/mfa.py | P1 |
| routes/api_keys.py | routes/auth/api_keys.py | P1 |
| routes/users.py | routes/admin/users.py | P2 |
| routes/audit.py | routes/admin/audit.py | P2 |
| routes/credentials.py | routes/admin/credentials.py | P2 |
| routes/rule_management.py | routes/rules/management.py | P1 |
| routes/rule_scanning.py | routes/rules/scanning.py | P1 |
| routes/compliance_rules_api.py | routes/rules/compliance.py | P1 |
| routes/content.py | routes/content/scap.py | P2 |
| routes/scap_import.py | routes/content/import_.py | P2 |
| routes/xccdf_api.py | routes/content/xccdf.py | P2 |
| routes/mongodb_scan_api.py | routes/scans/mongodb.py | P2 |

### 1.3 Routes to KEEP (Already Organized)

**routes/hosts/**
- crud.py
- discovery.py
- helpers.py
- models.py

**routes/scans/**
- crud.py
- config.py
- compliance.py
- rules.py
- templates.py
- reports.py
- validation.py
- bulk.py

**routes/compliance/**
- drift.py
- intelligence.py
- owca.py

**routes/ssh/**
- settings.py
- debug.py

**routes/integrations/**
- plugins.py
- webhooks.py

**routes/host_groups/**
- crud.py
- scans.py
- models.py

### 1.4 Routes to KEEP (Standalone)

| File | Reason |
|------|--------|
| routes/health.py | Standard health check |
| routes/version.py | Version endpoint |
| routes/monitoring.py | System monitoring |
| routes/health_monitoring.py | Health metrics |
| routes/capabilities.py | System capabilities |
| routes/terminal.py | Terminal service |

---

## 2. Service Files Migration

### 2.1 Create discovery/ Module

| Current File | Target File |
|--------------|-------------|
| services/host_discovery_service.py | services/discovery/host.py |
| services/host_compliance_discovery.py | services/discovery/compliance.py |
| services/host_network_discovery.py | services/discovery/network.py |
| services/host_security_discovery.py | services/discovery/security.py |

**New __init__.py exports**:
```python
from .host import HostDiscoveryService
from .compliance import ComplianceDiscoveryService
from .network import NetworkDiscoveryService
from .security import SecurityDiscoveryService
```

### 2.2 Create monitoring/ Module

| Current File | Target File |
|--------------|-------------|
| services/health_monitoring_service.py | services/monitoring/health.py |
| services/host_monitor.py | services/monitoring/host.py |
| services/host_monitoring_state.py | services/monitoring/state.py |
| services/drift_detection_service.py | services/monitoring/drift.py |
| services/integration_metrics.py | services/monitoring/metrics.py |
| services/adaptive_scheduler_service.py | services/monitoring/scheduler.py |

### 2.3 Create validation/ Module

| Current File | Target File |
|--------------|-------------|
| services/unified_validation_service.py | services/validation/unified.py |
| services/group_validation_service.py | services/validation/group.py |
| services/error_classification.py | services/validation/errors.py |
| services/error_sanitization.py | services/validation/sanitization.py |
| services/system_info_sanitization.py | services/validation/system_info.py |

### 2.4 Create infrastructure/ Module

| Current File | Target File |
|--------------|-------------|
| services/terminal_service.py | services/infrastructure/terminal.py |
| services/command_sandbox.py | services/infrastructure/sandbox.py |
| services/http_client.py | services/infrastructure/http.py |
| services/email_service.py | services/infrastructure/email.py |
| services/webhook_security.py | services/infrastructure/webhooks.py |

### 2.5 Create utilities/ Module

| Current File | Target File |
|--------------|-------------|
| services/session_migration_service.py | services/utilities/session_migration.py |
| services/key_lifecycle_manager.py | services/utilities/key_lifecycle.py |
| services/migration_runner.py | services/utilities/migration.py |

### 2.6 Consolidate into Existing Modules

| Current File | Target Module | Notes |
|--------------|---------------|-------|
| services/scan_intelligence.py | services/engine/ | Scan-related |
| services/secure_automated_fixes.py | services/remediation/ | Remediation-related |
| services/compliance_framework_mapper.py | services/framework/ | Framework mapping |

### 2.7 Services to KEEP (Already Organized)

**services/engine/** (v1.5.0)
- executors/ssh.py, local.py
- scanners/oscap.py, kubernetes.py, unified.py
- result_parsers/xccdf.py, arf.py
- discovery/platform.py
- integration/aegis.py
- orchestration/multi_scanner.py
- providers/

**services/content/** (v1.0.0)
- parsers/datastream.py, xccdf.py
- transformation/mongodb.py
- import_/batch.py

**services/ssh/**
- connection.py
- validation/
- policy/

**services/owca/** (v1.0.0)
- core/
- aggregation/
- extraction/
- cache/
- intelligence/
- framework/

**services/auth/**
- credential_manager.py

**services/authorization/** (v1.0.0)
- rbac.py
- resource_policy.py

**services/compliance_rules/** (v2.0.0)
- parsing/
- validation/
- versioning/
- dependency/

**services/plugins/**
- registry/
- lifecycle/
- analytics/
- execution/
- governance/
- marketplace/
- security/
- development/
- import_export/
- orchestration/

**services/rules/**
- service.py
- cache.py
- scanner.py
- association.py

**services/remediation/**
- recommendation/engine.py

**services/host_validator/**
- readiness_validator.py

**services/framework/**
- mapper.py
- engine.py
- reporting.py
- metadata.py

**services/xccdf/**
- generator.py

---

## 3. Documentation Migration

### 3.1 Files to ARCHIVE

**Phase Documentation** (→ archive/phases/):
- PHASE_1_*.md through PHASE_12_*.md
- All 30+ phase files

**Migration Documentation** (→ archive/migrations/):
- MIGRATION_*.md (completed)
- *_MIGRATION_*.md

**Weekly Reports** (→ changelog/{year}/weekly/):
- WEEKLY_*.md
- *_REPORT_*.md

**Completed PRs** (→ archive/prs/):
- PR_*.md

### 3.2 Files to MOVE to active/

| Current | Target |
|---------|--------|
| GETTING_STARTED_GUIDE.md | active/GETTING_STARTED.md |
| DEVELOPMENT_WORKFLOW.md | active/DEVELOPMENT.md |
| TESTING_STRATEGY.md | active/TESTING.md |
| (create new) | active/API_OVERVIEW.md |
| (create new) | active/SECURITY.md |

### 3.3 Files to MOVE to architecture/

| Current | Target |
|---------|--------|
| ARCHITECTURE_*.md | architecture/OVERVIEW.md |
| BACKEND_*.md | architecture/BACKEND_SERVICES.md |
| FRONTEND_*.md | architecture/FRONTEND_COMPONENTS.md |
| DATABASE_*.md | architecture/DATABASE_DESIGN.md |
| SECURITY_ARCHITECTURE_*.md | architecture/SECURITY_ARCHITECTURE.md |

### 3.4 Files to MOVE to api/

| Current | Target |
|---------|--------|
| API_*.md | api/ENDPOINTS.md |
| AUTHENTICATION_*.md | api/AUTHENTICATION.md |
| (consolidate) | api/SCHEMAS.md |
| (consolidate) | api/ERRORS.md |

### 3.5 Files to CREATE in guides/

| File | Priority | Content |
|------|----------|---------|
| PRODUCTION_DEPLOYMENT.md | P0 | Full deployment guide |
| ENVIRONMENT_REFERENCE.md | P0 | All env vars |
| DATABASE_MIGRATIONS.md | P1 | Alembic guide |
| MONITORING_SETUP.md | P1 | Monitoring guide |
| SECURITY_HARDENING.md | P1 | Security checklist |
| SCALING_GUIDE.md | P2 | Scaling advice |

### 3.6 Files to CREATE in decisions/

| File | Content |
|------|---------|
| README.md | ADR template and index |
| ADR-001-dual-database.md | PostgreSQL + MongoDB decision |
| ADR-002-repository-pattern.md | Repository pattern adoption |
| ADR-003-modular-services.md | Service module organization |

---

## 4. Frontend Files

### 4.1 Components to EXTRACT

**pages/scans/ScanDetail.tsx** (2,289 lines) →
```
pages/scans/ScanDetail/
├── index.tsx (~200)
├── ScanProgress.tsx (~300)
├── ResultsOverview.tsx (~400)
├── RuleResults.tsx (~500)
├── HostResults.tsx (~400)
├── ScanActions.tsx (~200)
├── types.ts (~100)
└── hooks/
    ├── useScanPolling.ts (~100)
    └── useScanResults.ts (~100)
```

**pages/hosts/Hosts.tsx** (2,014 lines) →
```
pages/hosts/Hosts/
├── index.tsx (~200)
├── HostTable.tsx (~400)
├── HostGrid.tsx (~300)
├── HostFilters.tsx (~300)
├── BulkImport.tsx (~400)
├── types.ts (~100)
└── hooks/
    └── useHostActions.ts (~200)
```

**pages/hosts/AddHost.tsx** (1,866 lines) →
```
pages/hosts/AddHost/
├── index.tsx (~200)
├── IdentificationStep.tsx (~400)
├── AuthenticationStep.tsx (~400)
├── ConfigurationStep.tsx (~400)
├── types.ts (~100)
└── hooks/
    └── useAddHostForm.ts (~300)
```

### 4.2 Services to CREATE

```
services/adapters/
├── index.ts
├── hostAdapter.ts
├── scanAdapter.ts
├── ruleAdapter.ts
└── frameworkAdapter.ts

services/storage.ts (centralize localStorage)
```

---

## 5. Migration Order

### Phase 1 (Week 1-2): Routes
1. Delete duplicate routes
2. Create auth/ package
3. Create rules/ package
4. Create admin/ package
5. Create content/ package
6. Update main.py

### Phase 2 (Week 3-4): Services
1. Create discovery/ module
2. Create monitoring/ module
3. Create validation/ module
4. Create infrastructure/ module
5. Create utilities/ module
6. Update imports

### Phase 3 (Week 5-6): Documentation
1. Create directory structure
2. Archive old docs
3. Create production guides
4. Move active docs
5. Update links

### Phase 4 (Week 7-8): Frontend
1. Create API adapters
2. Extract ScanDetail
3. Extract Hosts
4. Extract AddHost
5. Centralize storage

---

## 6. Verification Checklist

After each migration:

- [ ] All imports updated (grep for old paths)
- [ ] Tests pass
- [ ] Application starts
- [ ] API endpoints work
- [ ] Frontend works
- [ ] No deprecation warnings (or expected ones only)
