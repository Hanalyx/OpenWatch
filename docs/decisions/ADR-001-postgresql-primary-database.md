# ADR-001: PostgreSQL as Primary Database

**Status**: Accepted
**Date**: 2026-02-10
**Deciders**: OpenWatch team

## Context

OpenWatch originally used a dual-database architecture:
- **PostgreSQL** for relational data (users, hosts, scans, audit logs)
- **MongoDB** for compliance content (rules, benchmarks, remediation scripts)

This dual-database approach introduced complexity:
- Two database connection managers and health checks
- Two migration strategies (Alembic for PostgreSQL, Beanie ODM for MongoDB)
- Data synchronization challenges between stores
- Operational overhead of maintaining two database containers
- Repository pattern required for MongoDB abstraction

With the adoption of Aegis as the compliance engine, compliance rules are now defined as YAML files bundled with Aegis rather than stored in MongoDB. The primary use case for MongoDB was eliminated.

## Decision

Consolidate on PostgreSQL as the sole database. Deprecate and remove MongoDB.

### Migration approach:
1. Stop writing new features against MongoDB
2. Remove MongoDB from `docker-compose.yml` and CI pipeline
3. Keep MongoDB Python packages (`motor`, `beanie`, `pymongo`) temporarily for import compatibility
4. Remove MongoDB code in a future cleanup pass

### PostgreSQL handles all data:
- Relational data (users, hosts, scans, credentials)
- Compliance findings (`scan_findings` table)
- Temporal posture snapshots (JSONB for rule states)
- Audit queries and exports
- Alert and exception management
- Server intelligence (packages, services, users, network)

JSONB columns are used where flexible schema is needed, providing MongoDB-like document storage within PostgreSQL.

## Consequences

**Benefits:**
- Single database to manage, back up, and monitor
- Simpler deployment (one fewer container)
- Alembic as the single migration tool
- ACID transactions across all data
- Joins between compliance data and relational data
- Reduced CI pipeline time

**Drawbacks:**
- Legacy MongoDB code remains in the codebase temporarily
- MongoDB packages still in `requirements.txt` for import compatibility
- Some services still import MongoDB models (non-functional)

**Status of removal:**
- MongoDB removed from `docker-compose.yml` and CI (2026-02-16)
- Legacy code retained for import compatibility
- Full code removal planned as separate cleanup
