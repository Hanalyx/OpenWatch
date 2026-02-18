# Database Migration Guide

This guide covers how to create, apply, and manage database migrations in OpenWatch using Alembic and PostgreSQL.

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Alembic Basics](#alembic-basics)
4. [Checking Current State](#checking-current-state)
5. [Creating Migrations](#creating-migrations)
6. [Migration Best Practices](#migration-best-practices)
7. [Applying Migrations](#applying-migrations)
8. [Rollback Procedures](#rollback-procedures)
9. [Production Migration Checklist](#production-migration-checklist)
10. [Troubleshooting](#troubleshooting)
11. [Migration History](#migration-history)

---

## Overview

OpenWatch uses [Alembic](https://alembic.sqlalchemy.org/) for managing PostgreSQL schema migrations. Alembic is a lightweight database migration tool built for use with SQLAlchemy. It tracks schema changes as versioned Python scripts, enabling the team to upgrade, downgrade, and audit the database schema in a controlled and repeatable way.

**Key facts:**

- **Database**: PostgreSQL 15+ with UUID primary keys on most tables
- **ORM**: SQLAlchemy 2.0 with `declarative_base()` (defined in `backend/app/database.py`)
- **Migration directory**: `backend/alembic/versions/`
- **Configuration file**: `backend/alembic.ini`
- **Environment runner**: `backend/alembic/env.py`
- **Current migration count**: ~47 migration files (including 2 merge migrations)

Each migration file contains an `upgrade()` function that applies the change and a `downgrade()` function that reverses it. Alembic stores the current migration revision in the `alembic_version` table inside the PostgreSQL database.

---

## Prerequisites

Before running migrations, verify:

1. **Docker containers are running** (PostgreSQL must be accessible):

   ```bash
   docker ps | grep openwatch-db
   ```

2. **The backend container is running** (migrations execute inside it):

   ```bash
   docker ps | grep openwatch-backend
   ```

3. **PostgreSQL is healthy**:

   ```bash
   docker exec openwatch-db psql -U openwatch -d openwatch -c "SELECT 1;"
   ```

4. **The `OPENWATCH_DATABASE_URL` environment variable is set** inside the backend container. This variable overrides the default connection string in `alembic.ini`.

---

## Alembic Basics

### Configuration: `alembic.ini`

The Alembic configuration lives at `backend/alembic.ini`. Key settings:

```ini
# Path to migration scripts
script_location = alembic

# Template used to generate migration file names
file_template = %%(year)d%%(month).2d%%(day).2d_%%(hour).2d%%(minute).2d_%%(rev)s_%%(slug)s

# Timezone for dates in filenames and migration files
timezone = UTC

# Max length of the slug portion of the filename
truncate_slug_length = 40

# Version location
version_locations = %(here)s/alembic/versions

# Default database URL (overridden at runtime by env.py)
sqlalchemy.url = postgresql://openwatch:password@localhost:5432/openwatch  # pragma: allowlist secret
```

The `file_template` setting produces filenames in the format `YYYYMMDD_HHMM_<revision>_<slug>`, for example: `20260209_1000_016_add_scan_findings_table.py`. This makes migrations easy to sort chronologically.

### Environment Runner: `env.py`

The `backend/alembic/env.py` file is the runtime entry point for Alembic. It performs several important tasks:

1. **Loads the database URL from application settings** via `app.config.get_settings()`. The `Settings` class uses the `OPENWATCH_` env prefix (configured in `pydantic_settings`), so the environment variable `OPENWATCH_DATABASE_URL` provides the connection string at runtime. This overrides the default `sqlalchemy.url` in `alembic.ini`.

2. **Imports the SQLAlchemy `Base` metadata** from `app.database`, which is required for autogenerate to detect model changes.

3. **Widens the `alembic_version` table** to `varchar(128)` if needed. Some revision IDs in the project exceed the default Alembic `varchar(32)` limit. The `run_migrations_online()` function creates or alters the `alembic_version` table to handle this before running any migrations.

4. **Supports offline mode** for generating SQL scripts without a live database connection.

---

## Checking Current State

### View the current migration revision

**Local** (from `backend/` directory):

```bash
cd backend && alembic current
```

**Docker**:

```bash
docker exec openwatch-backend alembic current
```

This shows which migration revision the database is currently at. If the database is up to date, it will show the latest revision with `(head)` appended.

### View migration history

**Local**:

```bash
cd backend && alembic history --verbose
```

**Docker**:

```bash
docker exec openwatch-backend alembic history --verbose
```

This lists all migrations in order. To see only the last few:

```bash
docker exec openwatch-backend alembic history -r -5:current
```

### Check for multiple heads

```bash
docker exec openwatch-backend alembic heads
```

If this returns more than one revision, the migration chain has diverged and a merge migration is needed (see [Troubleshooting](#troubleshooting)).

---

## Creating Migrations

### Autogenerate from model changes

After modifying SQLAlchemy models in the codebase, generate a migration that captures the diff:

**Local**:

```bash
cd backend && alembic revision --autogenerate -m "Add scan_metadata column"
```

**Docker**:

```bash
docker exec openwatch-backend alembic revision --autogenerate -m "Add scan_metadata column"
```

This creates a new file in `backend/alembic/versions/` named according to the `file_template` pattern. For example:

```
20260217_1430_abc123def456_add_scan_metadata_column.py
```

### Naming conventions

- Use a short, descriptive message after `-m` that explains the change
- The message becomes part of the filename (as the slug)
- Use lowercase with underscores
- Examples of good messages:
  - `"Add scan_findings table"`
  - `"Add severity column to alerts"`
  - `"Create host_packages_services tables"`
  - `"Merge alerts branches"`

### Migration file structure

A generated migration file follows this pattern:

```python
"""Add scan_findings table for per-rule scan results

Revision ID: 20260209_1000_016
Revises: 20260128_merge_heads
Create Date: 2026-02-09
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic
revision = "20260209_1000_016"
down_revision = "20260128_merge_heads"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Apply migration."""
    op.create_table(
        "scan_findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_id", sa.String(255), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
    )
    op.create_index("idx_scan_findings_scan_id", "scan_findings", ["scan_id"])


def downgrade() -> None:
    """Rollback migration."""
    op.drop_index("idx_scan_findings_scan_id", "scan_findings")
    op.drop_table("scan_findings")
```

Key elements:

- `revision` -- unique identifier for this migration
- `down_revision` -- the parent migration (forms the chain)
- `upgrade()` -- applies the schema change
- `downgrade()` -- reverses the schema change

### Create an empty migration (manual)

For data migrations or complex operations that autogenerate cannot detect:

```bash
docker exec openwatch-backend alembic revision -m "Backfill compliance scores"
```

This creates a migration file with empty `upgrade()` and `downgrade()` functions that you fill in manually.

---

## Migration Best Practices

### 1. Always review autogenerated output

Autogenerate is not perfect. It may:

- Miss certain changes (e.g., changes to `server_default`, check constraints, or custom types)
- Produce unnecessary operations (e.g., dropping and recreating an index that has not changed)
- Generate incorrect ordering for dependent objects

Always open the generated file and verify that `upgrade()` and `downgrade()` do exactly what you intend.

### 2. Test both upgrade and downgrade

Before committing a migration, verify that both directions work:

```bash
# Apply the migration
docker exec openwatch-backend alembic upgrade head

# Verify the change
docker exec openwatch-db psql -U openwatch -d openwatch -c "\d+ your_table_name"

# Roll it back
docker exec openwatch-backend alembic downgrade -1

# Verify the rollback
docker exec openwatch-db psql -U openwatch -d openwatch -c "\d+ your_table_name"

# Re-apply
docker exec openwatch-backend alembic upgrade head
```

### 3. Handle data migrations carefully

If a migration needs to move or transform existing data, separate the schema change from the data migration when possible. For data migrations, use `op.execute()` with parameterized SQL:

```python
def upgrade() -> None:
    # Step 1: Add the new column (nullable initially)
    op.add_column("hosts", sa.Column("compliance_state", sa.String(20), nullable=True))

    # Step 2: Backfill data
    op.execute("UPDATE hosts SET compliance_state = 'unknown' WHERE compliance_state IS NULL")

    # Step 3: Make it non-nullable now that data exists
    op.alter_column("hosts", "compliance_state", nullable=False)
```

### 4. Never modify existing migrations that have been applied

Once a migration has been applied to any shared environment (development, staging, production), do not edit it. Instead, create a new migration to make further changes. Modifying an applied migration causes checksum mismatches and breaks the migration chain for anyone who already ran the original version.

### 5. Use idempotent checks for safety

Several migrations in the OpenWatch codebase use existence checks to make them safe to re-run:

```python
def upgrade() -> None:
    conn = op.get_bind()
    result = conn.execute(
        sa.text(
            "SELECT EXISTS (SELECT FROM information_schema.tables "
            "WHERE table_name = 'posture_snapshots')"
        )
    )
    if result.scalar():
        return  # Table already exists, skip creation

    op.create_table("posture_snapshots", ...)
```

This pattern is useful when migrating databases that may have had tables created outside of Alembic.

### 6. Use UUID primary keys for new tables

OpenWatch uses UUID primary keys on most tables. Follow this pattern for new tables:

```python
sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True)
```

The baseline schema also enables the `uuid-ossp` extension:

```python
op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
```

### 7. Include indexes for foreign keys and common query columns

```python
op.create_index("idx_scan_findings_scan_id", "scan_findings", ["scan_id"])
op.create_index("idx_scan_findings_severity_status", "scan_findings", ["severity", "status"])
```

### 8. Drop indexes before dropping tables in downgrade

When writing `downgrade()`, drop indexes explicitly before dropping the table:

```python
def downgrade() -> None:
    op.drop_index("idx_scan_findings_severity_status", "scan_findings")
    op.drop_index("idx_scan_findings_scan_id", "scan_findings")
    op.drop_table("scan_findings")
```

---

## Applying Migrations

### Upgrade to the latest version

**Local**:

```bash
cd backend && alembic upgrade head
```

**Docker**:

```bash
docker exec openwatch-backend alembic upgrade head
```

### Upgrade one step at a time

```bash
docker exec openwatch-backend alembic upgrade +1
```

### Upgrade to a specific revision

```bash
docker exec openwatch-backend alembic upgrade 20260209_1000_016
```

### View the SQL that would be generated (without executing)

```bash
docker exec openwatch-backend alembic upgrade head --sql
```

This runs Alembic in offline mode and prints the SQL statements to stdout. Useful for reviewing what will happen before applying.

---

## Rollback Procedures

### Downgrade by one revision

```bash
docker exec openwatch-backend alembic downgrade -1
```

### Downgrade to a specific revision

```bash
docker exec openwatch-backend alembic downgrade 20260128_merge_heads
```

### Downgrade all the way to empty database

```bash
docker exec openwatch-backend alembic downgrade base
```

**WARNING**: This drops all tables managed by Alembic. Use with extreme caution. This is destructive and irreversible without a backup.

### When to rollback

- A migration was applied that contains an error
- A schema change is causing application failures
- You need to return to a known-good state before debugging

Always verify the current revision after a rollback:

```bash
docker exec openwatch-backend alembic current
```

---

## Production Migration Checklist

Follow this checklist when applying migrations to production or staging environments.

### Before applying

- [ ] **Back up the database**

  ```bash
  docker exec openwatch-db pg_dump -U openwatch -d openwatch > backup_$(date +%Y%m%d_%H%M%S).sql
  ```

- [ ] **Check the current revision**

  ```bash
  docker exec openwatch-backend alembic current
  ```

- [ ] **Verify there is a single head** (no divergent branches)

  ```bash
  docker exec openwatch-backend alembic heads
  ```

- [ ] **Review the migration chain** from current to head

  ```bash
  docker exec openwatch-backend alembic history -r current:head
  ```

- [ ] **Read each pending migration file** and confirm the changes are expected

- [ ] **Dry run** -- generate SQL without executing

  ```bash
  docker exec openwatch-backend alembic upgrade head --sql
  ```

### Applying

- [ ] **Apply the migration**

  ```bash
  docker exec openwatch-backend alembic upgrade head
  ```

- [ ] **Verify the new revision**

  ```bash
  docker exec openwatch-backend alembic current
  ```

### After applying

- [ ] **Verify tables and columns** exist as expected

  ```bash
  docker exec openwatch-db psql -U openwatch -d openwatch -c "\dt"
  docker exec openwatch-db psql -U openwatch -d openwatch -c "\d+ <table_name>"
  ```

- [ ] **Run application health checks**

  ```bash
  curl http://localhost:8000/health
  ```

- [ ] **Verify the application can read and write data** by testing a few API endpoints

- [ ] **Document the migration** -- record what was applied, when, and by whom

---

## Troubleshooting

### Multiple heads (branched migration chain)

**Symptom**: `alembic upgrade head` fails with an error about multiple heads.

**Diagnosis**:

```bash
docker exec openwatch-backend alembic heads
```

If multiple revisions are listed, the chain has branched.

**Resolution**: Create a merge migration:

```bash
docker exec openwatch-backend alembic merge heads -m "Merge branches"
```

This creates a migration with `down_revision` set to a tuple of the two (or more) head revisions. The merge migration typically has empty `upgrade()` and `downgrade()` functions:

```python
revision = "035_merge_alerts"
down_revision = ("034_remove_scap_fields", "033b_alerts_full")

def upgrade() -> None:
    pass

def downgrade() -> None:
    pass
```

OpenWatch has needed merge migrations twice: once at `20260128_merge_heads` (merging 3 branches) and again at `035_merge_alerts` (merging 2 branches). This is common in projects with parallel feature branches.

### Failed migration leaves database in partial state

**Symptom**: A migration fails partway through and the database is in an inconsistent state.

**Diagnosis**: Check what revision Alembic thinks it is at:

```bash
docker exec openwatch-backend alembic current
```

Check the actual database state:

```bash
docker exec openwatch-db psql -U openwatch -d openwatch -c "\dt"
```

**Resolution**:

1. If the migration partially applied, you may need to manually fix the database to match either the pre-migration or post-migration state.
2. If you need to force Alembic to a specific revision (after manually fixing the schema):

   ```bash
   docker exec openwatch-db psql -U openwatch -d openwatch \
     -c "UPDATE alembic_version SET version_num = '<target_revision>';"
   ```

   Use this only as a last resort and only after confirming the database schema matches the target revision.

### "Target database is not up to date" error

**Symptom**: `alembic revision --autogenerate` fails because the database is behind.

**Resolution**: Apply pending migrations first:

```bash
docker exec openwatch-backend alembic upgrade head
```

Then retry the autogenerate.

### "Can't locate revision" error

**Symptom**: Alembic cannot find a revision referenced in the migration chain.

**Possible causes**:

- A migration file was deleted or renamed
- The `down_revision` in a migration file points to a revision that does not exist

**Resolution**: Check the migration chain for gaps:

```bash
docker exec openwatch-backend alembic history --verbose
```

Look for missing revisions. If a file was accidentally deleted, restore it from version control.

### `version_num` column too narrow

**Symptom**: Alembic fails with a database error about the `version_num` column being too short.

**Resolution**: The OpenWatch `env.py` automatically handles this by widening the `alembic_version.version_num` column to `varchar(128)` on each run. If you encounter this error, verify that `env.py` has the `CREATE TABLE IF NOT EXISTS` and `ALTER COLUMN` logic in `run_migrations_online()`.

### Migration file not detected

**Symptom**: A new migration file exists in `alembic/versions/` but Alembic does not see it.

**Check**:

- The file is a valid Python file (`.py` extension, no syntax errors)
- The `revision` identifier in the file is unique
- The `down_revision` correctly points to an existing revision
- The `sourceless = false` setting in `alembic.ini` means `.pyc` files alone are not detected -- source `.py` files must be present

---

## Migration History

The OpenWatch project has accumulated approximately 47 migration files in `backend/alembic/versions/`. The migration history spans from August 2025 (baseline schema) through February 2026 (current).

### Notable milestones

| Revision | Date | Description |
|----------|------|-------------|
| `001` | 2025-08-17 | Baseline schema (users, hosts, scans, host groups, credentials) |
| `002` - `015` | 2025-08 to 2025-11 | MFA support, compliance mappings, scan sessions, monitoring, risk scores, drift tables, system settings |
| `20260128_merge_heads` | 2026-01-28 | First merge migration -- consolidated 3 parallel branches into a single chain |
| `016` - `026` | 2026-02-09 | Aegis integration tables: scan findings, rules, framework mappings, posture snapshots, exceptions, scheduler, audit queries |
| `027` - `032` | 2026-02-10 | Server intelligence tables: system info, packages, services, users, network, audit events, metrics |
| `033` - `034` | 2026-02-10 to 2026-02-11 | Alerts tables, SCAP field removal |
| `035_merge_alerts` | 2026-02-16 | Second merge migration -- merged the main branch and alerts feature branch |

### Migration chain shape

The chain is currently linear with a single head at `035_merge_alerts`. Two merge points exist in the history where parallel branches were consolidated:

```
001 (baseline)
 |
 v
002 ... 015 (incremental additions)
 |          \         \
 v           v         v
drift    platform    scheduler
 |          |         |
 +----------+---------+
 |
 v
20260128_merge_heads
 |
 v
016 ... 031 (Aegis + Server Intelligence)
 |               \
 v                v
033 ... 034     033b (alerts)
 |                |
 +----------------+
 |
 v
035_merge_alerts (current head)
```
