# OpenWatch Coding Standards Context

> **Purpose**: This document provides essential coding standards and quality requirements for all OpenWatch development work. Include this context in prompts to ensure consistent, high-quality code output.

---

## Code Quality Requirements

All code must follow CLAUDE.md best practices:

### Documentation Standards
- **Descriptive docstrings**: All public functions, classes, and modules must have comprehensive docstrings
- **Comprehensive comments**: Explain WHY decisions were made, not WHAT the code does
- **No emojis**: Never use emojis in code, comments, logs, or error messages

### Type Safety
- **Type hints**: All function parameters and return values must have type annotations
- **Strict typing**: Use `Optional`, `Union`, `List`, `Dict` from typing module appropriately

### Defensive Coding
- **Graceful error handling**: All operations that can fail must have proper try/except blocks
- **Input validation**: Validate all inputs at API boundaries using Pydantic models
- **Fail safely**: Return meaningful error messages without exposing internal details

### Architecture Principles
- **Modular design**: Each module has ONE clear responsibility
- **Single responsibility**: Functions do one thing well
- **Dependency injection**: Pass dependencies explicitly, avoid global state
- **Absolute imports only**: Always use absolute imports (`from backend.app.services.auth_service import AuthService`), never relative imports (`from ...services.auth_service import AuthService`). This ensures consistency, clarity, and makes refactoring easier.

### Security-First Development
- **No SQL injection**: Use QueryBuilder or SQLAlchemy ORM with parameterized queries
- **No shell injection**: Never use `shell=True` in subprocess calls; use argument lists
- **No secrets in code**: All sensitive data via environment variables
- **Input sanitization**: Validate and sanitize all user inputs

---

## Data Access Patterns

### PostgreSQL (Relational Data)
Use **QueryBuilder** for all PostgreSQL queries:

```python
from backend.app.utils.query_builder import QueryBuilder
from sqlalchemy import text

builder = (
    QueryBuilder("hosts")
    .select("id", "hostname", "status")
    .where("status = :status", "online", "status")
    .order_by("created_at", "DESC")
    .paginate(page=1, per_page=20)
)
query, params = builder.build()
result = db.execute(text(query), params)
```

### MongoDB (Document Store)
Use **Repository Pattern** for all MongoDB operations:

```python
from backend.app.repositories.compliance_repository import ComplianceRuleRepository

repo = ComplianceRuleRepository()
rules = await repo.find_by_framework("nist_800_53")
```

---

## Abstraction-Focused Naming Convention

**CRITICAL**: All API endpoints, classes, functions, and variables must use abstraction-focused naming rather than application or database-specific naming.

### Why This Matters
1. **Future-proofing**: If we migrate from MongoDB to another document store (CouchDB, DynamoDB, etc.), we won't have misleading names
2. **Clean abstractions**: Names describe WHAT functionality does, not HOW it's implemented
3. **Professional API design**: External consumers shouldn't know or care about internal database choices
4. **Maintainability**: Code remains clear and accurate even as implementations change

### Naming Guidelines

| Category | Bad (Implementation-Specific) | Good (Abstraction-Focused) |
|----------|------------------------------|---------------------------|
| **Endpoints** | `/api/mongodb-rules` | `/api/compliance-rules` |
| **Endpoints** | `/api/postgres-users` | `/api/users` |
| **Classes** | `MongoDBRuleService` | `ComplianceRuleService` |
| **Classes** | `PostgresHostRepository` | `HostRepository` |
| **Functions** | `query_mongodb_rules()` | `get_compliance_rules()` |
| **Functions** | `insert_into_postgres()` | `create_record()` |
| **Variables** | `mongo_client` | `document_store` or `db_client` |
| **Variables** | `postgres_session` | `db_session` |

### Exceptions
Internal implementation details (not exposed in public APIs) may reference specific technologies when necessary for clarity:
- Private helper methods
- Configuration classes
- Database initialization code

---

## Container Health Verification

Before completing any task, verify all containers are operational:

```
openwatch-frontend    - healthy
openwatch-backend     - healthy
openwatch-worker      - healthy
openwatch-celery-beat - running
openwatch-db          - healthy
openwatch-mongodb     - healthy
openwatch-redis       - healthy
```

Verification command:
```bash
docker ps --format "table {{.Names}}\t{{.Status}}" | grep openwatch
```

---

## Quick Reference Checklist

Before submitting code, verify:

- [ ] All functions have docstrings with Args, Returns, Raises
- [ ] All function signatures have type hints
- [ ] No raw SQL strings (use QueryBuilder or ORM)
- [ ] No `shell=True` in subprocess calls
- [ ] Error handling with meaningful messages
- [ ] No emojis anywhere in the code
- [ ] Names are abstraction-focused, not implementation-specific
- [ ] All imports are absolute (not relative)
- [ ] All containers remain healthy after changes

---

## Usage

Include this file in prompts with:
```
See context/CODING_STANDARDS.md for coding requirements.
```

Or copy the key sections directly into your prompt for specific guidance.
