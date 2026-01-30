# OpenWatch Production Readiness PRD

**Version**: 1.0.0
**Status**: Draft
**Last Updated**: 2026-01-21
**Author**: Claude Opus 4.5 + Human Collaboration

---

## Document Index

This PRD is organized into modular documents for focused reading and maintenance.

### Core Documents

| Document | Description |
|----------|-------------|
| [01-OVERVIEW.md](01-OVERVIEW.md) | Problem statement, goals, success metrics, scope |
| [02-STAKEHOLDERS.md](02-STAKEHOLDERS.md) | Roles, responsibilities, RACI matrix |
| [03-AI-COLLABORATION.md](03-AI-COLLABORATION.md) | Human-AI collaboration model and guidelines |
| [04-TIMELINE.md](04-TIMELINE.md) | Phases, milestones, dependencies |
| [05-RISKS.md](05-RISKS.md) | Risk assessment and mitigation strategies |

### Epics

| Epic | Priority | Description |
|------|----------|-------------|
| [epics/E0-SCAN-ACCURACY.md](epics/E0-SCAN-ACCURACY.md) | **P0 BLOCKER** | Fix 35% scan discrepancy vs native OpenSCAP |
| [epics/E1-ROUTE-CONSOLIDATION.md](epics/E1-ROUTE-CONSOLIDATION.md) | P0 | ~~Eliminate duplicate routes, complete modular migration~~ **Complete** |
| [epics/E2-SERVICE-ORGANIZATION.md](epics/E2-SERVICE-ORGANIZATION.md) | P1 | ~~Consolidate 50 flat services into modules~~ **Complete** |
| [epics/E3-DOCUMENTATION.md](epics/E3-DOCUMENTATION.md) | P1 | Reorganize 249 docs, create production guides |
| [epics/E4-FRONTEND-REFACTOR.md](epics/E4-FRONTEND-REFACTOR.md) | P2 | ~~Extract large components, standardize state~~ **Complete** |
| [epics/E5-TESTING.md](epics/E5-TESTING.md) | P2 | Achieve 80% coverage, add regression tests |
| [epics/E6-PRODUCTION-HARDENING.md](epics/E6-PRODUCTION-HARDENING.md) | P1 | Deployment guides, monitoring, security audit |

> **CRITICAL**: E0 (Scan Accuracy) must be resolved before production deployment. A 35% compliance score discrepancy is unacceptable for a compliance scanning platform.

### User Stories

Individual stories are located in [stories/](stories/) directory, organized by epic.

### Appendices

| Document | Description |
|----------|-------------|
| [appendices/A-CURRENT-STATE.md](appendices/A-CURRENT-STATE.md) | Detailed current state analysis |
| [appendices/B-FILE-INVENTORY.md](appendices/B-FILE-INVENTORY.md) | Complete file listing and migration plan |
| [appendices/C-GLOSSARY.md](appendices/C-GLOSSARY.md) | Terms and definitions |

---

## Quick Links

- **Codebase Review**: [docs/CODEBASE_REVIEW_2026_01.md](../docs/CODEBASE_REVIEW_2026_01.md)
- **AI Development Guide**: [CLAUDE.md](../CLAUDE.md)
- **Context Files**: [context/](../context/)

---

## How to Use This PRD

### For Humans
1. Start with [01-OVERVIEW.md](01-OVERVIEW.md) for context
2. Review [04-TIMELINE.md](04-TIMELINE.md) for planning
3. Pick stories from epics based on priority

### For AI Assistants
1. Read [03-AI-COLLABORATION.md](03-AI-COLLABORATION.md) for guidelines
2. Reference specific epic when working on related tasks
3. Update story status as work progresses

### For Reviews
1. Check acceptance criteria in each epic
2. Verify against [05-RISKS.md](05-RISKS.md) before deployment
3. Update status in this README when phases complete

---

## Status Tracking

| Phase | Status | Target | Actual |
|-------|--------|--------|--------|
| Phase 0: Scan Accuracy | Not Started | Week 1-4 | - |
| Phase 1: Critical Fixes (E1) | Complete | Week 2-3 | 2026-01-30 |
| Phase 2: Consolidation (E2) | Complete | Week 4-5 | 2026-01-30 |
| Phase 3: Documentation (E3) | Not Started | Week 6-7 | - |
| Phase 4: Frontend (E4) | Complete | Week 8-9 | 2026-01-30 |
| Phase 5: Testing (E5) | Not Started | Week 10-11 | - |
| Phase 6: Hardening (E6) | Not Started | Week 12-14 | - |

> **Note**: Phase 0 runs in parallel with Phase 1. Total timeline extended to 14 weeks to accommodate scan accuracy work.

---

## Change Log

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.1.0 | 2026-01-30 | Claude Opus 4.5 | Mark E1, E2, E4 as Complete; update status tracking |
| 1.0.0 | 2026-01-21 | Claude Opus 4.5 | Initial PRD creation |
