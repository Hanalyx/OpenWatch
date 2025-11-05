# QueryBuilder for OpenWatch

**Created**: 2025-10-19
**Last Updated**: 2025-11-04
**Status**: Phase 1, 2, 3 & 4 Complete - 16 Endpoints Migrated
**Related PRs**: #115 (Infrastructure), #116 (Phase 1), #121 (Phase 2), #122 (Phase 3)

## What is QueryBuilder?

QueryBuilder is a utility class that provides a **fluent interface for building SQL queries** in a safe, readable, and maintainable way.

---

## What Problem Does It Solve?

### Before QueryBuilder (Raw SQL)
```python
result = db.execute(text("""
    SELECT h.id, h.hostname, h.ip_address, h.display_name, h.operating_system,
           h.status, h.port, h.username, h.auth_method, h.created_at, h.updated_at,
           hg.id as group_id, hg.name as group_name
    FROM hosts h
    LEFT JOIN host_group_memberships hgm ON hgm.host_id = h.id
    LEFT JOIN host_groups hg ON hg.id = hgm.group_id
    WHERE h.id = :id
"""), {"id": host_uuid})
```

**Problems**:
- ❌ Hard to read and maintain
- ❌ Manual parameter management
- ❌ Error-prone (typos, syntax errors)
- ❌ Difficult to extend (add filters, pagination, etc.)
- ❌ SQL injection risk if parameters not handled correctly

### After QueryBuilder (Fluent Interface)
```python
builder = (QueryBuilder("hosts h")
    .select("h.id", "h.hostname", "h.ip_address", "h.display_name", "h.operating_system",
            "h.status", "h.port", "h.username", "h.auth_method", "h.created_at", "h.updated_at",
            "hg.id as group_id", "hg.name as group_name")
    .join("host_group_memberships hgm", "hgm.host_id = h.id", "LEFT")
    .join("host_groups hg", "hg.id = hgm.group_id", "LEFT")
    .where("h.id = :id", host_uuid, "id")
)
query, params = builder.build()
result = db.execute(text(query), params)
```

**Benefits**:
- ✅ Easy to read and understand
- ✅ Automatic parameter management
- ✅ Type-safe method chaining
- ✅ Easy to extend (just add more method calls)
- ✅ Built-in SQL injection protection

---

## Key Features

### 1. SQL Injection Protection 🔒
```python
# Malicious input
malicious_input = "'; DROP TABLE hosts; --"

# QueryBuilder automatically protects
builder = QueryBuilder("hosts").search("hostname", malicious_input)
query, params = builder.build()

# Generated SQL (SAFE):
# "SELECT * FROM hosts WHERE hostname ILIKE :search_hostname"
# Parameters: {"search_hostname": "%'; DROP TABLE hosts; --%"}
```

The malicious input is **safely parameterized**, not executed as SQL.

### 2. Method Chaining ⛓️

**Available Methods**:

| Method | Purpose | Example |
|--------|---------|---------|
| `.select(*columns)` | Specify columns to select | `.select("id", "hostname", "status")` |
| `.join(table, on, type)` | Add table joins | `.join("host_groups hg", "h.group_id = hg.id", "LEFT")` |
| `.where(condition, value, param_name)` | Add WHERE conditions | `.where("status = :status", "online", "status")` |
| `.search(column, search_term)` | Case-insensitive search | `.search("hostname", "web")` → `hostname ILIKE '%web%'` |
| `.order_by(column, direction)` | Sort results | `.order_by("created_at", "DESC")` |
| `.paginate(page, per_page)` | Add LIMIT/OFFSET | `.paginate(page=1, per_page=20)` |
| `.build()` | Generate SQL and params | Returns `(query, params)` tuple |
| `.count_query()` | Generate COUNT query | Returns `(count_query, params)` tuple |

### 3. Readability 📖

**Clear, Declarative Syntax**:
```python
# Easy to understand what this query does
query = (QueryBuilder("hosts")
    .select("id", "hostname", "ip_address", "status")
    .where("is_active = :active", True, "active")
    .search("hostname", "web")
    .order_by("created_at", "DESC")
    .paginate(page=1, per_page=20)
)
```

vs. Raw SQL:
```python
# Harder to read, more error-prone
query = """
    SELECT id, hostname, ip_address, status
    FROM hosts
    WHERE is_active = :active AND hostname ILIKE :search_hostname
    ORDER BY created_at DESC
    LIMIT 20 OFFSET 0
"""
params = {"active": True, "search_hostname": "%web%"}
```

### 4. Maintainability 🔧

**Easy to Modify**:
```python
# Need to add a filter? Just add another .where()
query = (QueryBuilder("hosts")
    .select("id", "hostname", "status")
    .where("is_active = :active", True, "active")
    .where("status = :status", "online", "status")  # ← New filter added
    .order_by("hostname", "ASC")
)

# Need pagination? Just add .paginate()
query = (QueryBuilder("hosts")
    .select("id", "hostname", "status")
    .where("is_active = :active", True, "active")
    .paginate(page=2, per_page=50)  # ← Pagination added
)
```

---

## Real Example in OpenWatch

### Endpoint: `GET /api/hosts/{host_id}` (Phase 1 - Complete)

**File**: `backend/app/routes/hosts.py` (lines 479-545)

**Purpose**: Retrieve a single host with its group information

**Status**: ✅ Feature flag removed (2025-11-04) - QueryBuilder always used

```python
@router.get("/{host_id}", response_model=Host)
async def get_host(
    host_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get host details by ID"""
    try:
        # OW-REFACTOR-001C: Use centralized UUID validation (eliminates duplication)
        host_uuid = validate_host_uuid(host_id)

        # OW-REFACTOR-001B: Use QueryBuilder for parameterized SELECT with JOINs
        # Why: Consistent with Phase 2 pattern, eliminates dual code paths, maintains SQL injection protection
        logger.info(
            f"Using QueryBuilder for get_host endpoint (host_id: {sanitize_id_for_log(host_id)})"
        )
        builder = (
            QueryBuilder("hosts h")
            .select(
                "h.id", "h.hostname", "h.ip_address", "h.display_name",
                "h.operating_system", "h.status", "h.port", "h.username",
                "h.auth_method", "h.created_at", "h.updated_at", "h.description",
                "hg.id as group_id", "hg.name as group_name",
                "hg.description as group_description", "hg.color as group_color",
            )
            .join("host_group_memberships hgm", "hgm.host_id = h.id", "LEFT")
            .join("host_groups hg", "hg.id = hgm.group_id", "LEFT")
            .where("h.id = :id", host_uuid, "id")
        )
        query, params = builder.build()
        result = db.execute(text(query), params)

        row = result.fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Host not found")

        return Host(
            id=str(row.id),
            hostname=row.hostname,
            # ... (rest of the response mapping)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get host: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve host"
        )
```

**Key Changes from Original**:
- ❌ Removed: `get_settings()` import and usage
- ❌ Removed: Feature flag conditional (`if settings.use_query_builder`)
- ❌ Removed: Duplicate raw SQL implementation (else branch)
- ✅ Kept: Only QueryBuilder implementation
- ✅ Added: CLAUDE.md-compliant comments explaining "why"
- 📊 Net change: -23 lines

---

## Current Status

### Deployment Status (Updated 2025-11-04)

| Component | Status | Details |
|-----------|--------|---------|
| **Infrastructure** | ✅ Deployed | PR #115 merged |
| **Phase 1 (GET Hosts)** | ✅ Complete | Feature flag removed (commit ae5d4a3) |
| **Phase 2 (POST/PUT/DELETE Hosts)** | ✅ Complete | PR #121 merged |
| **Phase 3 (Scan Endpoints)** | ✅ Complete | Issue #122 closed (commit d469046) |
| **Phase 4 (User Endpoints)** | ✅ Complete | Commit 3e6f240 merged |
| **Feature Flag** | ⚠️ DEPRECATED | Marked deprecated in config.py (commit 644b2c9) |
| **Production Status** | ✅ Active | 16 endpoints using QueryBuilder (94%) |

### Feature Flag (DEPRECATED)

**Status**: The `use_query_builder` feature flag has been **removed from code** as of 2025-11-04.

**Why Deprecated**:
- Phase 1 & 2 complete - all applicable endpoints now use QueryBuilder
- Feature flag no longer checked by any code
- Kept in config.py with deprecation notice for backward compatibility

**Migration Path**: The flag can be safely removed from config.py in a future cleanup.

### Endpoints Status

**✅ Hosts Endpoints - Using QueryBuilder (5/6 = 83%)**:

| Endpoint | Method | Status | Migration |
|----------|--------|--------|-----------|
| `/{host_id}` | GET | ✅ Active | Phase 1 (commit ae5d4a3) |
| `/` | POST | ✅ Active | Phase 2 (commit ac8376b) |
| `/{host_id}` | PUT | ✅ Active | Phase 2 (commit ac8376b) |
| `/{host_id}` | DELETE | ✅ Active | Phase 2 (commit ac8376b) |
| `/{host_id}/ssh-key` | DELETE | ✅ Active | Phase 2 (commit ac8376b) |
| `/` | GET | ❌ Raw SQL | Uses PostgreSQL LATERAL JOIN (complexity) |

**✅ Scans Endpoints - Using QueryBuilder (5/5 = 100%)**:

| Endpoint | Method | Status | Migration |
|----------|--------|--------|-----------|
| `/` | GET | ✅ Active | Phase 3 (commit d469046) |
| `/` | POST | ✅ Active | Phase 3 (commit d469046) |
| `/{scan_id}` | GET | ✅ Active | Phase 3 (commit d469046) |
| `/{scan_id}` | PATCH | ✅ Active | Phase 3 (commit d469046) |
| `/{scan_id}` | DELETE | ✅ Active | Phase 3 (commit d469046) |

**✅ Users Endpoints - Using QueryBuilder (6/6 = 100%)**:

| Endpoint | Method | Status | Migration |
|----------|--------|--------|-----------|
| `/roles` | GET | ✅ Active | Phase 4 (commit 3e6f240) |
| `/` | GET | ✅ Active | Phase 4 (commit 3e6f240) |
| `/` | POST | ✅ Active | Phase 4 (commit 3e6f240) |
| `/{user_id}` | GET | ✅ Active | Phase 4 (commit 3e6f240) |
| `/{user_id}` | PUT | ✅ Active | Phase 4 (commit 3e6f240) |
| `/{user_id}` | DELETE | ✅ Active | Phase 4 (commit 3e6f240) |

**Overall**: 16 out of 17 endpoints using QueryBuilder (94%)

---

## Testing

### Unit Tests

**File**: `backend/tests/test_query_builder.py` (280 lines)

**Test Coverage**: 100%

**Tests Include**:
- Basic SELECT queries
- WHERE conditions with parameters
- Case-insensitive ILIKE search
- Multiple JOIN operations
- Pagination (LIMIT/OFFSET)
- ORDER BY clauses
- COUNT queries
- SQL injection protection
- Complex multi-condition queries

**Run Tests**:
```bash
cd backend
pytest tests/test_query_builder.py -v
```

### Integration Tests

**Test Results** (from OW-REFACTOR-001B):
```
✅ Feature Flag OFF: Original SQL works correctly
✅ Feature Flag ON: QueryBuilder generates identical SQL
✅ Results Match: Both implementations return same data
```

**Test Script**: `/tmp/test_hosts_refactor.py`

---

## Security Benefits

### 1. Automatic SQL Injection Prevention

**How It Works**:
- All user input is automatically parameterized
- No string interpolation in SQL
- Parameters bound via SQLAlchemy's `text()` mechanism

**Example**:
```python
# User provides malicious search term
search_term = "admin'; DROP TABLE users; --"

# QueryBuilder safely handles it
builder = QueryBuilder("hosts").search("hostname", search_term)
query, params = builder.build()

# Generated SQL (SAFE):
# "SELECT * FROM hosts WHERE hostname ILIKE :search_hostname"
# Parameters: {"search_hostname": "%admin'; DROP TABLE users; --%"}
```

The malicious SQL is **treated as data**, not code.

### 2. Consistent Parameterization

**Before** (Manual - Error Prone):
```python
# Easy to forget parameterization
query = f"SELECT * FROM hosts WHERE hostname = '{hostname}'"  # UNSAFE!

# Must remember to use parameters
query = "SELECT * FROM hosts WHERE hostname = :hostname"
params = {"hostname": hostname}  # SAFE
```

**After** (Automatic - Always Safe):
```python
# QueryBuilder always parameterizes
query = QueryBuilder("hosts").where("hostname = :hostname", hostname, "hostname")
# Always safe, no manual parameter management needed
```

### 3. Type Safety

QueryBuilder validates:
- JOIN types (LEFT, INNER, RIGHT, FULL, CROSS)
- ORDER BY directions (ASC, DESC)
- Parameter names (prevents conflicts)

---

## Benefits for OpenWatch

### 1. Reduces Code Duplication
**Before**: Each endpoint writes its own SQL with similar patterns
**After**: Reusable QueryBuilder reduces duplication by ~60%

### 2. Easier to Extend
**Adding Search**:
```python
# Before: Modify raw SQL string
query = """SELECT * FROM hosts WHERE hostname ILIKE :search"""

# After: Just add .search()
query = QueryBuilder("hosts").search("hostname", search_term)
```

**Adding Pagination**:
```python
# Before: Calculate OFFSET manually
query = f"""SELECT * FROM hosts LIMIT {per_page} OFFSET {(page-1)*per_page}"""

# After: Just add .paginate()
query = QueryBuilder("hosts").paginate(page=page, per_page=per_page)
```

### 3. Consistent Patterns
- Same API across all endpoints
- Predictable behavior
- Easier onboarding for new developers

### 4. Better Testing
- Query logic can be unit tested
- Easier to mock and test query building
- Separate query construction from database execution

### 5. Self-Documenting Code
```python
# Clear what this query does without reading SQL
query = (QueryBuilder("hosts")
    .select("id", "hostname", "status")
    .where("is_active = :active", True, "active")
    .search("hostname", "web")
    .order_by("created_at", "DESC")
    .paginate(page=1, per_page=20)
)
```

---

## Files and Documentation

### Implementation Files

| File | Lines | Purpose |
|------|-------|---------|
| `backend/app/utils/query_builder.py` | 250 | QueryBuilder implementation |
| `backend/tests/test_query_builder.py` | 280 | Unit tests |
| `backend/docs/development/query-builder-guide.md` | 379 | Developer guide |
| `backend/app/routes/hosts.py` | 48 modified | Usage example |
| `backend/app/config.py` | 5 added | Feature flag |

### Documentation

1. **Developer Guide**: `backend/docs/development/query-builder-guide.md`
   - Complete usage examples
   - Security best practices
   - Migration strategy
   - Troubleshooting

2. **Test Suite**: `backend/tests/test_query_builder.py`
   - 10 test classes
   - 100% code coverage
   - SQL injection tests

3. **Validation Report**: `/tmp/OW-REFACTOR-001_VALIDATION_REPORT.md`
   - Production validation results
   - Performance analysis
   - Security audit

---

## Migration History

### ✅ Phase 1: GET Endpoint (Complete - 2025-10-19)
- **Endpoint**: `GET /api/hosts/{host_id}`
- **Commits**: fd2ed01, 27ddbf3
- **Approach**: Feature flag for safe rollout
- **Status**: Feature flag removed 2025-11-04 (commit ae5d4a3)

### ✅ Phase 2: POST/PUT/DELETE Endpoints (Complete - 2025-11-04)
- **Endpoints**:
  - `POST /api/hosts/` (create_host)
  - `PUT /api/hosts/{host_id}` (update_host)
  - `DELETE /api/hosts/{host_id}` (delete_host)
  - `DELETE /api/hosts/{host_id}/ssh-key` (delete_host_ssh_key)
- **Commits**: ac8376b, 28b019d
- **Approach**: Direct migration (no feature flag)
- **Issue**: #121 (closed)

## Future Roadmap

### ✅ Phase 3: Scan Management Endpoints (Complete - 2025-11-04)

**Status**: All 5 scan endpoints migrated (Issue #122 closed)

**Endpoints Migrated**:
1. ✅ `GET /api/scans/` - List scans with filters (complex 3-table JOIN)
2. ✅ `POST /api/scans/` - Create scan (with validation queries)
3. ✅ `GET /api/scans/{scan_id}` - Get scan details (2 INNER JOINs)
4. ✅ `PATCH /api/scans/{scan_id}` - Update scan (conditional UPDATE)
5. ✅ `DELETE /api/scans/{scan_id}` - Delete scan (cascade deletion)

**Commits**: d469046
**Issue**: #122 (closed)
**Approach**: Direct migration (no feature flag)

### ✅ Phase 4: User Management Endpoints (Complete - 2025-11-04)

**Status**: All 6 user management endpoints migrated

**Endpoints Migrated**:
1. ✅ `GET /api/users/roles` - List roles (complex CASE ORDER BY)
2. ✅ `GET /api/users` - List users (pagination + filtering)
3. ✅ `POST /api/users` - Create user (existence check + INSERT)
4. ✅ `GET /api/users/{user_id}` - Get user by ID
5. ✅ `PUT /api/users/{user_id}` - Update user (conditional UPDATE)
6. ✅ `DELETE /api/users/{user_id}` - Soft delete user (deactivation)

**Commits**: 3e6f240
**Approach**: Direct migration (no feature flag)

### Phase 5: Additional Endpoints (Future)

**Other Candidates**:
1. `GET /api/content/` - SCAP content listing
2. `GET /api/audit/` - Audit logs with search
3. Other route files with raw SQL queries

**Not Suitable for QueryBuilder**:
- `GET /api/hosts/` - Uses PostgreSQL LATERAL JOIN (too complex for QueryBuilder)

### Phase 5: Extended Features (Future)

**Potential Enhancements**:
1. **LATERAL JOIN Support**: Add support for PostgreSQL-specific features
2. **Subquery Support**: Build nested queries
3. **UNION Support**: Combine multiple queries
4. **Common Table Expressions (CTEs)**: WITH clause support
5. **Transaction Support**: Multi-query transactions

### Phase 6: ORM Integration (Future)

**Consideration**: Migrate to SQLAlchemy ORM for:
- Type-safe queries
- Automatic migrations
- Relationship management
- Better IDE support

---

## Related PRs and Issues

### Merged PRs

- **PR #115**: [OW-REFACTOR-001: Add QueryBuilder utility](https://github.com/Hanalyx/OpenWatch/pull/115)
  - Status: ✅ Merged
  - Infrastructure-only (no code changes)
  - Added QueryBuilder utility
  - Comprehensive tests
  - Developer documentation

- **PR #116**: [OW-REFACTOR-001B: Refactor hosts.py GET /{host_id}](https://github.com/Hanalyx/OpenWatch/pull/116)
  - Status: ✅ Merged
  - Refactored `GET /api/hosts/{host_id}` endpoint
  - Added feature flag for safe rollout
  - 100% test coverage
  - Zero breaking changes

### Commits

```
27ddbf3 OW-REFACTOR-001B: Refactor hosts.py GET /{host_id} with QueryBuilder
fd2ed01 OW-REFACTOR-001: Add QueryBuilder utility for SQL query construction
```

---

## Troubleshooting

### Issue: Feature Flag Not Working

**Symptom**: QueryBuilder not being used even when flag is set

**Solution**:
```bash
# Ensure environment variable is set correctly
echo $OPENWATCH_USE_QUERY_BUILDER

# Check .env file
grep QUERY_BUILDER backend/.env

# Restart backend to reload config
docker restart openwatch-backend

# Verify in logs
docker logs openwatch-backend | grep -i querybuilder
```

### Issue: SQL Syntax Error

**Symptom**: Database error when using QueryBuilder

**Solution**:
1. Check generated SQL:
   ```python
   query, params = builder.build()
   print(f"SQL: {query}")
   print(f"Params: {params}")
   ```

2. Validate JOIN syntax:
   - Ensure ON clause is correct
   - Check table aliases match

3. Check WHERE clause:
   - Parameter names must be unique
   - Use `:param_name` format

### Issue: Performance Degradation

**Symptom**: Queries slower with QueryBuilder

**Solution**:
1. Compare query plans:
   ```sql
   EXPLAIN ANALYZE <generated_query>
   ```

2. Check for missing indexes
3. Verify JOIN order is optimal
4. Disable feature flag and compare

---

## Best Practices

### 1. Use Descriptive Parameter Names
```python
# Good
.where("status = :host_status", status, "host_status")

# Avoid
.where("status = :param1", status, "param1")
```

### 2. Chain Methods for Readability
```python
# Good - Easy to read
query = (QueryBuilder("hosts")
    .select("id", "hostname")
    .where("is_active = :active", True, "active")
    .order_by("hostname", "ASC")
)

# Avoid - Hard to read
query = QueryBuilder("hosts").select("id", "hostname").where("is_active = :active", True, "active").order_by("hostname", "ASC")
```

### 3. Use .search() for User Input
```python
# Good - Automatic ILIKE and wildcards
.search("hostname", user_search_term)

# Avoid - Manual ILIKE
.where("hostname ILIKE :search", f"%{user_search_term}%", "search")
```

### 4. Always Use Feature Flags for New Code
```python
# Good - Safe rollout with feature flag
if settings.use_query_builder:
    # New QueryBuilder code
else:
    # Original SQL (fallback)
```

---

## Conclusion

QueryBuilder provides OpenWatch with:
- ✅ **Safer** SQL query construction
- ✅ **More readable** and maintainable code
- ✅ **Easier to extend** with new features
- ✅ **Consistent** patterns across endpoints
- ✅ **Better tested** query logic

**Current Status** (2025-11-04):
- Phase 1, 2, 3 & 4 complete - 16 endpoints migrated (94%)
- Feature flag removed - QueryBuilder always active
- Production-proven and stable
- Scans endpoints 100% migrated
- Users endpoints 100% migrated
- Hosts endpoints 83% migrated (1 remaining uses LATERAL JOIN)

---

**Last Updated**: 2025-11-04
**Maintained By**: OpenWatch Development Team
**Related Docs**:
- `backend/docs/development/query-builder-guide.md`
- `backend/docs/development/README.md`
**Related Issues**:
- Issue #121: Phase 2 migration (closed)
- Issue #122: Phase 3 scan endpoints (closed)
