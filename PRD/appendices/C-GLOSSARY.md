# Appendix C: Glossary

**Document**: C-GLOSSARY.md
**Last Updated**: 2026-01-21

---

## Project-Specific Terms

### OpenWatch Terms

| Term | Definition |
|------|------------|
| **OpenWatch** | Enterprise SCAP compliance scanning platform |
| **OWCA** | OpenWatch Compliance Algorithm - the scoring and analysis engine |
| **The Eye** | Vision metaphor for OpenWatch - complete visibility into security posture |

### Scanning Terms

| Term | Definition |
|------|------------|
| **SCAP** | Security Content Automation Protocol - standardized format for security content |
| **XCCDF** | Extensible Configuration Checklist Description Format - benchmark format |
| **OVAL** | Open Vulnerability and Assessment Language - system testing language |
| **ARF** | Asset Reporting Format - scan result format |
| **Datastream** | SCAP datastream - bundled XCCDF, OVAL, and other components |
| **Profile** | SCAP profile - collection of rules to check |
| **Rule** | Individual compliance check |
| **Benchmark** | Collection of rules organized by profile |
| **CCE** | Common Configuration Enumeration - configuration identifiers |
| **CPE** | Common Platform Enumeration - platform identifiers |

### Compliance Frameworks

| Term | Definition |
|------|------------|
| **STIG** | Security Technical Implementation Guide (DoD) |
| **CIS** | Center for Internet Security benchmarks |
| **NIST** | National Institute of Standards and Technology |
| **FedRAMP** | Federal Risk and Authorization Management Program |
| **CMMC** | Cybersecurity Maturity Model Certification |
| **PCI-DSS** | Payment Card Industry Data Security Standard |

---

## Technical Terms

### Architecture

| Term | Definition |
|------|------------|
| **Repository Pattern** | Data access abstraction layer |
| **QueryBuilder** | SQL query construction utility |
| **Service Layer** | Business logic encapsulation |
| **ODM** | Object-Document Mapper (Beanie for MongoDB) |
| **ORM** | Object-Relational Mapper (SQLAlchemy for PostgreSQL) |

### Security

| Term | Definition |
|------|------------|
| **FIPS 140-2** | Federal Information Processing Standard for cryptographic modules |
| **AES-256-GCM** | Advanced Encryption Standard, 256-bit, Galois/Counter Mode |
| **Argon2id** | Password hashing algorithm |
| **RS256** | RSA Signature with SHA-256 (JWT algorithm) |
| **PBKDF2** | Password-Based Key Derivation Function 2 |
| **RBAC** | Role-Based Access Control |
| **JWT** | JSON Web Token |
| **MFA** | Multi-Factor Authentication |

### Infrastructure

| Term | Definition |
|------|------------|
| **Celery** | Distributed task queue |
| **Redis** | In-memory data store (cache, message broker) |
| **Beanie** | Async MongoDB ODM for Python |
| **FastAPI** | Modern Python web framework |
| **Pydantic** | Data validation library |
| **Alembic** | Database migration tool |

---

## Acronyms

| Acronym | Full Form |
|---------|-----------|
| API | Application Programming Interface |
| CI/CD | Continuous Integration/Continuous Deployment |
| CORS | Cross-Origin Resource Sharing |
| CRUD | Create, Read, Update, Delete |
| E2E | End-to-End |
| LOC | Lines of Code |
| MVP | Minimum Viable Product |
| ORM | Object-Relational Mapping |
| PR | Pull Request |
| PRD | Product Requirements Document |
| REST | Representational State Transfer |
| SLA | Service Level Agreement |
| SRP | Single Responsibility Principle |
| SSH | Secure Shell |
| SSL/TLS | Secure Sockets Layer/Transport Layer Security |
| UUID | Universally Unique Identifier |

---

## PRD Terms

| Term | Definition |
|------|------------|
| **Epic** | Large body of work that can be broken into stories |
| **Story** | Single unit of work with acceptance criteria |
| **Acceptance Criteria** | Conditions that must be met for story completion |
| **Definition of Done** | Checklist for considering work complete |
| **RACI** | Responsible, Accountable, Consulted, Informed matrix |
| **ADR** | Architecture Decision Record |
| **Spike** | Time-boxed research task |

---

## Status Terms

| Status | Meaning |
|--------|---------|
| **Not Started** | Work has not begun |
| **In Progress** | Work is actively being done |
| **Blocked** | Work cannot proceed due to dependency |
| **In Review** | Work is complete, awaiting review |
| **Done** | Work is complete and approved |
| **Deferred** | Work postponed to future phase |

---

## Priority Levels

| Priority | Meaning | Response |
|----------|---------|----------|
| **P0** | Critical/Blocker | Must be done immediately |
| **P1** | High | Must be done this phase |
| **P2** | Medium | Should be done if time permits |
| **P3** | Low | Nice to have |

---

## File Naming Conventions

| Pattern | Usage | Example |
|---------|-------|---------|
| `snake_case.py` | Python files | `host_service.py` |
| `PascalCase.tsx` | React components | `HostTable.tsx` |
| `camelCase.ts` | TypeScript utilities | `hostAdapter.ts` |
| `SCREAMING_SNAKE.md` | Documentation | `GETTING_STARTED.md` |
| `kebab-case/` | URL paths | `/api/host-groups/` |

---

## Module Naming

| Suffix | Purpose | Example |
|--------|---------|---------|
| `*_service.py` | Business logic | `scan_service.py` |
| `*_repository.py` | Data access | `compliance_repository.py` |
| `*_api.py` | Route definitions | `hosts_api.py` |
| `*_models.py` | Data models | `mongo_models.py` |
| `*_tasks.py` | Celery tasks | `scan_tasks.py` |
| `*Slice.ts` | Redux slice | `hostSlice.ts` |
| `use*.ts` | React hook | `useHostData.ts` |
| `*Adapter.ts` | API adapter | `hostAdapter.ts` |
