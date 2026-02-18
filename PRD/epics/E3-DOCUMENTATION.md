# Epic E3: Documentation Reorganization

**Epic ID**: E3
**Priority**: P1 (High)
**Phase**: 2-3 (Week 3-6)
**Owner**: AI (Claude) with Human review
**Status**: Complete
**Depends On**: None (can run parallel to E1/E2)

---

## 1. Epic Summary

Reorganize 249 documentation files into a structured hierarchy, archive stale content, and create missing production guides.

---

## 2. Problem Statement

The `docs/` directory contains:
- **249 markdown files** with no clear organization
- **Historical phase documentation** (PHASE_1 through PHASE_12)
- **Weekly reports** and migration notes
- **Missing production guides** critical for deployment

This creates:
- Difficulty finding relevant documentation
- Confusion about which docs are current
- Onboarding friction for new contributors
- Production deployment blockers

---

## 3. Goals

| Goal | Metric | Target |
|------|--------|--------|
| Organize active docs | Files in docs/active/ | 20-30 |
| Archive stale docs | Files in docs/archive/ | 200+ |
| Create production guides | New guides | 6 |
| Improve discoverability | Clear README index | Yes |

---

## 4. Proposed Structure

```
docs/
├── README.md                    # Index with navigation
├── active/                      # Current, maintained documentation
│   ├── GETTING_STARTED.md
│   ├── DEVELOPMENT.md
│   ├── TESTING.md
│   ├── API_OVERVIEW.md
│   └── SECURITY.md
│
├── guides/                      # Step-by-step guides
│   ├── PRODUCTION_DEPLOYMENT.md
│   ├── ENVIRONMENT_REFERENCE.md
│   ├── DATABASE_MIGRATIONS.md
│   ├── MONITORING_SETUP.md
│   ├── SCALING_GUIDE.md
│   └── SECURITY_HARDENING.md
│
├── architecture/                # System design documentation
│   ├── OVERVIEW.md
│   ├── BACKEND_SERVICES.md
│   ├── FRONTEND_COMPONENTS.md
│   ├── DATABASE_DESIGN.md
│   └── SECURITY_ARCHITECTURE.md
│
├── api/                         # API documentation
│   ├── ENDPOINTS.md
│   ├── AUTHENTICATION.md
│   ├── SCHEMAS.md
│   └── ERRORS.md
│
├── decisions/                   # Architecture Decision Records
│   ├── README.md
│   ├── ADR-001-dual-database.md
│   ├── ADR-002-repository-pattern.md
│   └── ADR-003-modular-services.md
│
├── changelog/                   # Historical records by year
│   ├── 2025/
│   │   ├── CHANGELOG.md
│   │   └── weekly/
│   └── 2026/
│       ├── CHANGELOG.md
│       └── weekly/
│
└── archive/                     # Obsolete/completed documentation
    ├── README.md               # Explanation of archived content
    ├── phases/                 # Phase-based development docs
    │   ├── PHASE_1.md
    │   ├── PHASE_2.md
    │   └── ...
    ├── migrations/             # Completed migration docs
    └── legacy/                 # Other historical docs
```

---

## 5. User Stories

### Story E3-S1: Create Documentation Index
**Priority**: P0 | **Points**: 2 | **Status**: Complete

**As a** contributor,
**I want** a clear index of all documentation,
**So that** I can find what I need quickly.

**Acceptance Criteria**:
- [ ] `docs/README.md` created with:
  - Overview of documentation structure
  - Quick links to most important docs
  - Table of contents for each section
  - Contribution guidelines for docs
- [ ] Links verified to work

**Template**:
```markdown
# OpenWatch Documentation

## Quick Start
- [Getting Started](active/GETTING_STARTED.md)
- [Development Setup](active/DEVELOPMENT.md)
- [API Overview](active/API_OVERVIEW.md)

## Production
- [Deployment Guide](guides/PRODUCTION_DEPLOYMENT.md)
- [Environment Reference](guides/ENVIRONMENT_REFERENCE.md)
- [Security Hardening](guides/SECURITY_HARDENING.md)

## Architecture
- [System Overview](architecture/OVERVIEW.md)
- [Backend Services](architecture/BACKEND_SERVICES.md)
- [Decision Records](decisions/README.md)

## For AI Assistants
- [CLAUDE.md](../CLAUDE.md)
- [Context Files](../context/)
- [PRD](../PRD/)
```

---

### Story E3-S2: Create Archive Structure
**Priority**: P1 | **Points**: 3 | **Status**: Complete (scope reduced - only 2 docs to relocate)

**As a** contributor,
**I want** stale documentation archived,
**So that** the docs directory is navigable.

**Acceptance Criteria**:
- [ ] `docs/archive/` directory created
- [ ] `docs/archive/README.md` explains what's archived and why
- [ ] Subdirectories: `phases/`, `migrations/`, `legacy/`
- [ ] All PHASE_*.md files moved to `archive/phases/`
- [ ] All completed migration docs moved to `archive/migrations/`
- [ ] Weekly reports moved to `changelog/{year}/weekly/`

**Files to Archive** (partial list):
```
PHASE_1_*.md through PHASE_12_*.md
MIGRATION_*.md (completed ones)
WEEKLY_REPORT_*.md
PR_*.md (completed PRs)
*_COMPLETE.md, *_COMPLETED.md
```

---

### Story E3-S3: Create Production Deployment Guide
**Priority**: P0 | **Points**: 5 | **Status**: Complete

**As a** system administrator,
**I want** a comprehensive deployment guide,
**So that** I can deploy OpenWatch to production.

**Acceptance Criteria**:
- [ ] `docs/guides/PRODUCTION_DEPLOYMENT.md` created
- [ ] Covers:
  - Prerequisites (hardware, software, network)
  - SSL/TLS certificate setup
  - Database setup (PostgreSQL, MongoDB)
  - Redis configuration
  - Docker/Podman deployment
  - Nginx configuration
  - Initial admin setup
  - Health verification
  - Troubleshooting common issues
- [ ] Step-by-step with exact commands
- [ ] Tested on clean system

**Content Sections**:
1. Prerequisites
2. Infrastructure Setup
3. Database Configuration
4. Application Deployment
5. SSL/TLS Setup
6. Nginx Reverse Proxy
7. Initial Configuration
8. Verification Steps
9. Troubleshooting
10. Next Steps

---

### Story E3-S4: Create Environment Variable Reference
**Priority**: P0 | **Points**: 4 | **Status**: Complete

**As a** developer/operator,
**I want** a complete reference of all environment variables,
**So that** I can configure OpenWatch correctly.

**Acceptance Criteria**:
- [ ] `docs/guides/ENVIRONMENT_REFERENCE.md` created
- [ ] Lists EVERY environment variable with:
  - Name
  - Description
  - Default value
  - Required/Optional
  - Valid values/format
  - Example
  - Security implications (if any)
- [ ] Organized by category (database, security, features, etc.)
- [ ] Cross-referenced with `.env.example` files

**Template**:
```markdown
## Database Configuration

### OPENWATCH_DATABASE_URL
- **Description**: PostgreSQL connection string
- **Required**: Yes
- **Default**: None
- **Format**: `postgresql://user:pass@host:port/dbname`
- **Example**: `postgresql://openwatch:secret@localhost:5432/openwatch`
- **Security**: Contains credentials, never commit to git
```

---

### Story E3-S5: Create Monitoring Setup Guide
**Priority**: P1 | **Points**: 4 | **Status**: Complete

**As an** operator,
**I want** documentation on setting up monitoring,
**So that** I can observe OpenWatch in production.

**Acceptance Criteria**:
- [ ] `docs/guides/MONITORING_SETUP.md` created
- [ ] Covers:
  - Health check endpoints
  - Prometheus metrics (if available)
  - Log aggregation
  - Alert configuration
  - Dashboard recommendations
- [ ] Integration examples (Grafana, ELK, etc.)

---

### Story E3-S6: Create Database Migration Guide
**Priority**: P1 | **Points**: 3 | **Status**: Complete

**As a** developer,
**I want** documentation on database migrations,
**So that** I can safely evolve the schema.

**Acceptance Criteria**:
- [ ] `docs/guides/DATABASE_MIGRATIONS.md` created
- [ ] Covers:
  - Alembic basics for PostgreSQL
  - Creating new migrations
  - Testing migrations
  - Production migration checklist
  - Rollback procedures
  - MongoDB schema evolution
- [ ] Step-by-step with exact commands

---

### Story E3-S7: Create Security Hardening Guide
**Priority**: P1 | **Points**: 4 | **Status**: Complete

**As a** security engineer,
**I want** security hardening documentation,
**So that** I can secure OpenWatch for production.

**Acceptance Criteria**:
- [ ] `docs/guides/SECURITY_HARDENING.md` created
- [ ] Covers:
  - Network security (firewalls, ports)
  - TLS configuration
  - Authentication hardening
  - Rate limiting configuration
  - Audit logging setup
  - Secret management
  - FIPS compliance verification
  - Regular security tasks
- [ ] Checklist format for audits

---

### Story E3-S8: Create Scaling Guide
**Priority**: P2 | **Points**: 3 | **Status**: Complete

**As an** operator,
**I want** documentation on scaling OpenWatch,
**So that** I can handle increased load.

**Acceptance Criteria**:
- [ ] `docs/guides/SCALING_GUIDE.md` created
- [ ] Covers:
  - Horizontal scaling strategies
  - Database scaling
  - Redis clustering
  - Celery worker scaling
  - Load balancing
  - Performance tuning

---

### Story E3-S9: Create Architecture Decision Records
**Priority**: P2 | **Points**: 3 | **Status**: Complete

**As a** developer,
**I want** documented architecture decisions,
**So that** I understand why things are built this way.

**Acceptance Criteria**:
- [ ] `docs/decisions/README.md` with ADR template
- [ ] `docs/decisions/ADR-001-dual-database.md`
- [ ] `docs/decisions/ADR-002-repository-pattern.md`
- [ ] `docs/decisions/ADR-003-modular-services.md`
- [ ] Each ADR includes: context, decision, consequences

**ADR Template**:
```markdown
# ADR-XXX: Title

## Status
Accepted | Proposed | Deprecated | Superseded

## Context
What is the issue that we're seeing that is motivating this decision?

## Decision
What is the change that we're proposing and/or doing?

## Consequences
What becomes easier or more difficult to do because of this change?
```

---

### Story E3-S10: Update Context Files
**Priority**: P1 | **Points**: 3 | **Status**: Complete

**As an** AI assistant,
**I want** updated and additional context files,
**So that** I can assist more effectively.

**Acceptance Criteria**:
- [ ] `context/QUICK_REFERENCE.md` created (single-page cheat sheet)
- [ ] `context/MODULE_BOUNDARIES.md` created (from E2)
- [ ] `context/DEBUGGING_GUIDE.md` created
- [ ] Existing context files reviewed and updated
- [ ] CLAUDE.md updated with new context files

---

### Story E3-S11: Categorize and Move Active Docs
**Priority**: P1 | **Points**: 4 | **Status**: Complete (scope reduced - 2 docs relocated to architecture/)

**As a** contributor,
**I want** active documentation properly categorized,
**So that** I can find current information.

**Acceptance Criteria**:
- [ ] All active docs moved to appropriate directories:
  - Development docs → `docs/active/`
  - Architecture docs → `docs/architecture/`
  - API docs → `docs/api/`
- [ ] All links within docs updated
- [ ] No broken links
- [ ] Index updated

**Files to Categorize**:
- `GETTING_STARTED_GUIDE.md` → `active/GETTING_STARTED.md`
- `DEVELOPMENT_WORKFLOW.md` → `active/DEVELOPMENT.md`
- `TESTING_STRATEGY.md` → `active/TESTING.md`
- `ARCHITECTURE_*.md` → `architecture/`
- `API_*.md` → `api/`
- `SECURITY_*.md` → `active/` or `architecture/`

---

## 6. Dependencies

```mermaid
graph TD
    S1[E3-S1: Index] --> S11[E3-S11: Move Active]
    S2[E3-S2: Archive] --> S11
    S3[E3-S3: Production Guide] --> S1
    S4[E3-S4: Env Reference] --> S1
    S5[E3-S5: Monitoring] --> S1
    S6[E3-S6: Migrations] --> S1
    S7[E3-S7: Security] --> S1
    S8[E3-S8: Scaling] --> S1
    S9[E3-S9: ADRs] --> S1
    S10[E3-S10: Context] --> S1
```

**Execution Order**:
1. S1 (Index) - Creates structure
2. S2 (Archive) - Clears clutter
3. S3, S4 (Critical guides - parallel)
4. S5, S6, S7 (Important guides - parallel)
5. S8, S9 (Nice-to-have - parallel)
6. S10 (Context files)
7. S11 (Final organization)

---

## 7. Risks and Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Broken links | Medium | High | Link checker before/after |
| Archiving needed docs | Medium | Medium | Review before archiving |
| Missing content in guides | High | Medium | Template-based writing |
| Outdated information | Medium | Medium | Review during writing |

---

## 8. Acceptance Criteria (Epic Level)

- [ ] Documentation index exists and is comprehensive
- [ ] 200+ files archived
- [ ] 6 production guides created
- [ ] All links work
- [ ] Context files updated
- [ ] Clear navigation structure

---

## 9. Definition of Done

- [ ] All stories completed
- [ ] Documentation reviewed for accuracy
- [ ] All links verified
- [ ] CLAUDE.md updated
- [ ] No broken references
- [ ] Committed with proper messages
