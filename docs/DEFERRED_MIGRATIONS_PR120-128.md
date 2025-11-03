# Deferred QueryBuilder & Repository Pattern Migrations (PR-120 through PR-128)

**Status:** DEFERRED until after compliance content and scan workflow are well understood
**Date Deferred:** October 20, 2025
**Reason:** Need comprehensive understanding of `/content` (compliance content) and `/scans` (host compliance scanning) workflows before migrating database queries

---

## Overview

This document captures the detailed specifications for PRs 120-128, which migrate remaining endpoints to QueryBuilder (PostgreSQL) and Repository Pattern (MongoDB). These migrations are **DEFERRED** to ensure we fully understand the compliance scanning workflow before refactoring database access patterns.

**Deferred Migrations:**
- PR-120: Scans Endpoints Migration
- PR-121: Users & Authentication Endpoints Migration
- PR-122: Host Groups Endpoints Migration
- PR-123: Remediation Services MongoDB Migration
- PR-124: Credentials & SCAP Content Endpoints
- PR-125: Compliance & Audit Reporting
- PR-126: System Settings & Low-Priority Endpoints
- PR-127: CLI Tools & Background Tasks
- PR-128: Feature Flag Removal & Cleanup

---

## PR-120: Scans Endpoints Migration

### Status
**DEFERRED** - Critical to understand compliance scan workflow first

### Rationale for Deferral
The `/scans` endpoints are central to OpenWatch's core compliance scanning functionality. Before refactoring these queries:
1. Must understand SCAP content structure (`/content`)
2. Must understand scan orchestration flow
3. Must understand result storage and retrieval patterns
4. Risk of breaking core compliance functionality

### Scope
Migrate all `backend/app/routes/scans.py` endpoints to QueryBuilder.

### Files to Modify
- `backend/app/routes/scans.py`
- `backend/app/services/scan_orchestrator_service.py` (if direct SQL queries exist)

### Endpoints to Migrate

#### 1. GET /api/scans/ - List Scans
**Current Implementation:**
```python
# Likely uses complex JOIN with hosts, scan_results, scap_content
result = db.execute(text("""
    SELECT s.id, s.name, s.status, s.progress, s.started_at, s.completed_at,
           h.hostname, h.ip_address,
           sr.score, sr.failed_rules, sr.passed_rules
    FROM scans s
    JOIN hosts h ON h.id = s.host_id
    LEFT JOIN scan_results sr ON sr.scan_id = s.id
    WHERE s.status IN (:status1, :status2)
    ORDER BY s.started_at DESC
    LIMIT :limit OFFSET :offset
"""), {"status1": "running", "status2": "completed", "limit": 50, "offset": 0})
```

**QueryBuilder Implementation:**
```python
settings = get_settings()
if settings.use_query_builder:
    logger.info("Using QueryBuilder for list_scans endpoint")
    builder = (QueryBuilder("scans s")
        .select("s.id", "s.name", "s.status", "s.progress", "s.started_at", "s.completed_at")
        .select("h.hostname", "h.ip_address")
        .select("sr.score", "sr.failed_rules", "sr.passed_rules")
        .join("hosts h", "h.id = s.host_id")
        .left_join("scan_results sr", "sr.scan_id = s.id")
        .where_in("s.status", ["running", "completed"])
        .order_by("s.started_at", "DESC")
        .limit(50)
        .offset(0)
    )
    sql, params = builder.build()
    result = db.execute(text(sql), params)
else:
    # Original SQL
```

**Complexity:** Medium - JOIN queries with pagination

**Risks:**
- Scan listing is frequently used - performance critical
- Filtering by status, host, date range needs careful testing
- Pagination must work correctly

#### 2. GET /api/scans/{id} - Get Scan Details
**Current Implementation:**
```python
result = db.execute(text("""
    SELECT s.*, h.hostname, h.ip_address, h.operating_system,
           sr.score, sr.failed_rules, sr.passed_rules, sr.total_rules,
           sr.severity_critical, sr.severity_high, sr.severity_medium, sr.severity_low
    FROM scans s
    JOIN hosts h ON h.id = s.host_id
    LEFT JOIN scan_results sr ON sr.scan_id = s.id
    WHERE s.id = :scan_id
"""), {"scan_id": scan_id})
```

**QueryBuilder Implementation:**
```python
if settings.use_query_builder:
    logger.info(f"Using QueryBuilder for get_scan endpoint (scan_id: {scan_id})")
    builder = (QueryBuilder("scans s")
        .select("s.*")
        .select("h.hostname", "h.ip_address", "h.operating_system")
        .select("sr.score", "sr.failed_rules", "sr.passed_rules", "sr.total_rules")
        .select("sr.severity_critical", "sr.severity_high", "sr.severity_medium", "sr.severity_low")
        .join("hosts h", "h.id = s.host_id")
        .left_join("scan_results sr", "sr.scan_id = s.id")
        .where("s.id", scan_id)
    )
    sql, params = builder.build()
    result = db.execute(text(sql), params)
```

**Complexity:** Low - Simple JOIN with single WHERE clause

#### 3. POST /api/scans/ - Create Scan
**Current Implementation:**
```python
scan_id = str(uuid.uuid4())
db.execute(text("""
    INSERT INTO scans (id, name, host_id, scap_content_id, profile, status,
                       progress, started_at, started_by)
    VALUES (:id, :name, :host_id, :scap_content_id, :profile, :status,
            :progress, :started_at, :started_by)
"""), {
    "id": scan_id,
    "name": scan_data.name,
    "host_id": scan_data.host_id,
    "scap_content_id": scan_data.scap_content_id,
    "profile": scan_data.profile,
    "status": "pending",
    "progress": 0,
    "started_at": datetime.utcnow(),
    "started_by": current_user['id']
})
```

**QueryBuilder Implementation:**
```python
if settings.use_query_builder:
    logger.info(f"Using QueryBuilder for create_scan endpoint (host_id: {scan_data.host_id})")
    builder = (QueryBuilder("scans")
        .insert({
            "id": scan_id,
            "name": scan_data.name,
            "host_id": scan_data.host_id,
            "scap_content_id": scan_data.scap_content_id,
            "profile": scan_data.profile,
            "status": "pending",
            "progress": 0,
            "started_at": datetime.utcnow(),
            "started_by": current_user['id']
        })
    )
    sql, params = builder.build()
    db.execute(text(sql), params)
```

**Complexity:** Low - Simple INSERT

#### 4. PUT /api/scans/{id}/status - Update Scan Status
**Current Implementation:**
```python
db.execute(text("""
    UPDATE scans
    SET status = :status,
        progress = :progress,
        completed_at = :completed_at,
        updated_at = :updated_at
    WHERE id = :scan_id
"""), {
    "scan_id": scan_id,
    "status": status_update.status,
    "progress": status_update.progress,
    "completed_at": datetime.utcnow() if status_update.status == "completed" else None,
    "updated_at": datetime.utcnow()
})
```

**QueryBuilder Implementation:**
```python
if settings.use_query_builder:
    logger.info(f"Using QueryBuilder for update_scan_status endpoint (scan_id: {scan_id})")
    update_data = {
        "status": status_update.status,
        "progress": status_update.progress,
        "updated_at": datetime.utcnow()
    }
    if status_update.status == "completed":
        update_data["completed_at"] = datetime.utcnow()

    builder = (QueryBuilder("scans")
        .update(update_data)
        .where("id", scan_id)
    )
    sql, params = builder.build()
    db.execute(text(sql), params)
```

**Complexity:** Low - Simple UPDATE with conditional field

#### 5. DELETE /api/scans/{id} - Delete Scan
**Current Implementation:**
```python
# Delete scan_results first (foreign key constraint)
db.execute(text("DELETE FROM scan_results WHERE scan_id = :scan_id"), {"scan_id": scan_id})

# Delete scan
db.execute(text("DELETE FROM scans WHERE id = :scan_id"), {"scan_id": scan_id})
```

**QueryBuilder Implementation:**
```python
if settings.use_query_builder:
    logger.info(f"Using QueryBuilder for delete_scan endpoint (scan_id: {scan_id})")

    # Delete scan_results first
    results_builder = (QueryBuilder("scan_results")
        .delete()
        .where("scan_id", scan_id)
    )
    sql, params = results_builder.build()
    db.execute(text(sql), params)

    # Delete scan
    scan_builder = (QueryBuilder("scans")
        .delete()
        .where("id", scan_id)
    )
    sql, params = scan_builder.build()
    db.execute(text(sql), params)
```

**Complexity:** Low - Cascade DELETE

#### 6. GET /api/scans/stats - Scan Statistics
**Current Implementation:**
```python
result = db.execute(text("""
    SELECT
        COUNT(*) as total_scans,
        COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_scans,
        COUNT(CASE WHEN status = 'running' THEN 1 END) as running_scans,
        COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_scans,
        AVG(CASE WHEN status = 'completed'
            THEN EXTRACT(EPOCH FROM (completed_at - started_at))
            END) as avg_duration_seconds
    FROM scans
    WHERE started_at >= :since_date
"""), {"since_date": since_date})
```

**QueryBuilder Implementation:**
```python
if settings.use_query_builder:
    logger.info("Using QueryBuilder for get_scan_stats endpoint")
    builder = (QueryBuilder("scans")
        .select("COUNT(*) as total_scans")
        .select("COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_scans")
        .select("COUNT(CASE WHEN status = 'running' THEN 1 END) as running_scans")
        .select("COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_scans")
        .select("AVG(CASE WHEN status = 'completed' THEN EXTRACT(EPOCH FROM (completed_at - started_at)) END) as avg_duration_seconds")
        .where_raw("started_at >= :since_date", {"since_date": since_date})
    )
    sql, params = builder.build()
    result = db.execute(text(sql), params)
```

**Complexity:** Medium - Aggregate functions with CASE expressions

### Effort Estimate
**1-2 weeks** - Depends on complexity of actual implementation

### Testing Requirements
1. **Functional Testing:**
   - Create scan → verify in database
   - List scans → verify pagination, filtering
   - Get scan details → verify JOINs work correctly
   - Update scan status → verify progress tracking
   - Delete scan → verify cascade delete

2. **Performance Testing:**
   - List scans with 1000+ records
   - Statistics query performance
   - Ensure no N+1 query issues

3. **Integration Testing:**
   - Scan orchestration still works
   - Celery tasks can update scan status
   - Frontend receives correct scan data

### Deliverables
- [ ] All 6 scan endpoints use QueryBuilder
- [ ] Feature flag implementation complete
- [ ] Logging for query performance
- [ ] Unit tests for all endpoints
- [ ] Integration tests pass
- [ ] Documentation updated

---

## PR-121: Users & Authentication Endpoints Migration

### Status
**DEFERRED** - Lower priority, can be done after core compliance features

### Scope
Migrate `backend/app/routes/users.py` and `backend/app/routes/auth.py` endpoints to QueryBuilder.

### Files to Modify
- `backend/app/routes/users.py`
- `backend/app/routes/auth.py`
- `backend/app/services/auth_service.py` (if direct SQL exists)

### Endpoints to Migrate

#### Users Endpoints (routes/users.py)

1. **GET /api/users/** - List Users
```python
builder = (QueryBuilder("users")
    .select("id", "username", "email", "full_name", "is_active", "role", "created_at")
    .where("is_active", True)
    .order_by("username", "ASC")
)
```

2. **GET /api/users/{id}** - Get User Details
```python
builder = (QueryBuilder("users u")
    .select("u.id", "u.username", "u.email", "u.full_name", "u.role", "u.is_active")
    .select("u.created_at", "u.updated_at", "u.last_login")
    .where("u.id", user_id)
)
```

3. **POST /api/users/** - Create User
```python
builder = (QueryBuilder("users")
    .insert({
        "id": user_id,
        "username": user_data.username,
        "email": user_data.email,
        "password_hash": hashed_password,
        "full_name": user_data.full_name,
        "role": user_data.role or "viewer",
        "is_active": True,
        "created_at": datetime.utcnow()
    })
)
```

4. **PUT /api/users/{id}** - Update User
```python
builder = (QueryBuilder("users")
    .update({
        "username": user_update.username,
        "email": user_update.email,
        "full_name": user_update.full_name,
        "updated_at": datetime.utcnow()
    })
    .where("id", user_id)
)
```

5. **DELETE /api/users/{id}** - Delete User
```python
# Soft delete
builder = (QueryBuilder("users")
    .update({
        "is_active": False,
        "deleted_at": datetime.utcnow()
    })
    .where("id", user_id)
)
```

6. **PUT /api/users/{id}/role** - Update User Role
```python
builder = (QueryBuilder("users")
    .update({
        "role": role_update.role,
        "updated_at": datetime.utcnow()
    })
    .where("id", user_id)
)
```

#### Authentication Endpoints (routes/auth.py)

1. **POST /api/auth/login** - User Login
```python
# Lookup user
builder = (QueryBuilder("users")
    .select("id", "username", "email", "password_hash", "role", "is_active")
    .where("username", login_data.username)
    .where("is_active", True)
)

# Update last_login
update_builder = (QueryBuilder("users")
    .update({"last_login": datetime.utcnow()})
    .where("id", user_id)
)
```

2. **POST /api/auth/refresh** - Refresh Token
```python
# Validate user still exists and is active
builder = (QueryBuilder("users")
    .select("id", "username", "role", "is_active")
    .where("id", user_id)
    .where("is_active", True)
)
```

3. **POST /api/auth/logout** - User Logout
```python
# If tracking sessions in DB:
builder = (QueryBuilder("user_sessions")
    .delete()
    .where("user_id", user_id)
    .where("token_hash", token_hash)
)
```

### Complexity
**Low to Medium** - Straightforward CRUD operations, mostly single-table queries

### Security Considerations
- Password hashing remains unchanged (Argon2id)
- JWT token generation unchanged
- QueryBuilder only affects database queries, not auth logic
- Must ensure WHERE clauses include `is_active = true` checks

### Effort Estimate
**1-2 weeks**

### Deliverables
- [ ] All user CRUD operations use QueryBuilder
- [ ] Auth queries use QueryBuilder (user lookup, session management)
- [ ] Role management centralized
- [ ] Feature flag implementation
- [ ] Unit tests pass
- [ ] Security audit confirms no vulnerabilities introduced

---

## PR-122: Host Groups Endpoints Migration

### Status
**DEFERRED** - Lower priority, can be done after core compliance features

### Scope
Migrate all `backend/app/routes/host_groups.py` endpoints to QueryBuilder.

### Files to Modify
- `backend/app/routes/host_groups.py`

### Endpoints to Migrate

#### 1. GET /api/host-groups/ - List Host Groups
```python
builder = (QueryBuilder("host_groups hg")
    .select("hg.id", "hg.name", "hg.description", "hg.color", "hg.created_at")
    .select("COUNT(hgm.host_id) as host_count")
    .left_join("host_group_memberships hgm", "hgm.group_id = hg.id")
    .group_by("hg.id", "hg.name", "hg.description", "hg.color", "hg.created_at")
    .order_by("hg.name", "ASC")
)
```

#### 2. GET /api/host-groups/{id} - Get Group Details
```python
# Get group info
group_builder = (QueryBuilder("host_groups")
    .select("id", "name", "description", "color", "created_at", "updated_at")
    .where("id", group_id)
)

# Get member hosts
hosts_builder = (QueryBuilder("hosts h")
    .select("h.id", "h.hostname", "h.ip_address", "h.status")
    .join("host_group_memberships hgm", "hgm.host_id = h.id")
    .where("hgm.group_id", group_id)
)
```

#### 3. POST /api/host-groups/ - Create Group
```python
builder = (QueryBuilder("host_groups")
    .insert({
        "id": group_id,
        "name": group_data.name,
        "description": group_data.description,
        "color": group_data.color,
        "created_at": datetime.utcnow()
    })
)
```

#### 4. PUT /api/host-groups/{id} - Update Group
```python
builder = (QueryBuilder("host_groups")
    .update({
        "name": group_update.name,
        "description": group_update.description,
        "color": group_update.color,
        "updated_at": datetime.utcnow()
    })
    .where("id", group_id)
)
```

#### 5. DELETE /api/host-groups/{id} - Delete Group
```python
# Delete memberships first
memberships_builder = (QueryBuilder("host_group_memberships")
    .delete()
    .where("group_id", group_id)
)

# Delete group
group_builder = (QueryBuilder("host_groups")
    .delete()
    .where("id", group_id)
)
```

#### 6. POST /api/host-groups/{id}/hosts - Add Hosts to Group
```python
# Insert multiple memberships
for host_id in host_ids:
    builder = (QueryBuilder("host_group_memberships")
        .insert({
            "group_id": group_id,
            "host_id": host_id,
            "added_at": datetime.utcnow()
        })
    )
    sql, params = builder.build()
    db.execute(text(sql), params)
```

#### 7. DELETE /api/host-groups/{id}/hosts/{host_id} - Remove Host from Group
```python
builder = (QueryBuilder("host_group_memberships")
    .delete()
    .where("group_id", group_id)
    .where("host_id", host_id)
)
```

### Complexity
**Medium** - Many-to-many relationships require careful handling

### Special Considerations
- Many-to-many relationship queries
- Bulk operations (adding multiple hosts)
- GROUP BY aggregations (host counts)

### Effort Estimate
**1-2 weeks**

### Deliverables
- [ ] Host group operations use QueryBuilder
- [ ] Many-to-many relationship queries optimized
- [ ] Bulk operations implemented efficiently
- [ ] Feature flag implementation
- [ ] Unit tests pass

---

## PR-123: Remediation Services MongoDB Migration

### Status
**DEFERRED** - Critical to understand compliance scanning first

### Scope
Migrate remediation services to use `ComplianceRuleRepository` for MongoDB operations.

### Files to Modify
- `backend/app/services/remediation_orchestrator_service.py`
- `backend/app/services/bulk_remediation_service.py`
- `backend/app/services/remediation_workflow_service.py`
- `backend/app/services/post_remediation_verification_service.py`

### Current MongoDB Query Patterns

#### Rule Lookups in Remediation
```python
# Current: Direct MongoDB queries
rule = await ComplianceRule.find_one({"rule_id": rule_id})
rules = await ComplianceRule.find({"framework": framework}).to_list()
```

#### Repository Pattern Migration
```python
# After: Use ComplianceRuleRepository
settings = get_settings()
if settings.use_repository_pattern:
    repo = ComplianceRuleRepository()
    rule = await repo.find_one({"rule_id": rule_id})
    rules = await repo.find_many({"framework": framework})
else:
    # Direct MongoDB
    rule = await ComplianceRule.find_one({"rule_id": rule_id})
```

### Services to Migrate

#### 1. remediation_orchestrator_service.py
**MongoDB Queries:**
- Rule lookup by rule_id
- Batch rule lookups for remediation plans
- Framework-specific rule queries

**Migration:**
```python
async def get_remediation_script(self, rule_id: str) -> Optional[str]:
    settings = get_settings()
    if REPOSITORY_AVAILABLE and settings.use_repository_pattern:
        logger.info(f"Using ComplianceRuleRepository for get_remediation_script (rule_id: {rule_id})")
        repo = ComplianceRuleRepository()
        rule = await repo.find_one({"rule_id": rule_id})
    else:
        logger.debug(f"Using direct MongoDB for get_remediation_script (rule_id: {rule_id})")
        rule = await ComplianceRule.find_one({"rule_id": rule_id})

    if rule and rule.remediation:
        return rule.remediation.get("script")
    return None
```

#### 2. bulk_remediation_service.py
**MongoDB Queries:**
- Bulk rule lookups
- Framework-wide remediation queries
- Rule dependency resolution

**Migration:**
```python
async def get_rules_for_remediation(self, rule_ids: List[str]) -> List[ComplianceRule]:
    settings = get_settings()
    if REPOSITORY_AVAILABLE and settings.use_repository_pattern:
        logger.info(f"Using ComplianceRuleRepository for bulk rule lookup ({len(rule_ids)} rules)")
        repo = ComplianceRuleRepository()
        rules = await repo.find_many({"rule_id": {"$in": rule_ids}})
    else:
        logger.debug(f"Using direct MongoDB for bulk rule lookup ({len(rule_ids)} rules)")
        rules = await ComplianceRule.find({"rule_id": {"$in": rule_ids}}).to_list()

    return rules
```

#### 3. remediation_workflow_service.py
**MongoDB Queries:**
- Rule status lookups
- Pre/post-condition rule queries
- Workflow state tracking

#### 4. post_remediation_verification_service.py
**MongoDB Queries:**
- Rule verification criteria
- Expected state queries
- Compliance rule lookups for validation

### Complexity
**Medium** - Multiple services, MongoDB-specific queries

### Effort Estimate
**1-2 weeks**

### Deliverables
- [ ] All rule lookups use Repository Pattern
- [ ] Performance monitoring for remediation queries
- [ ] Feature flag implementation
- [ ] Unit tests pass
- [ ] Integration tests with scan/remediation workflow

---

## PR-124: Credentials & SCAP Content Endpoints

### Status
**DEFERRED** - SCAP content structure must be understood first

### Scope
Migrate credentials management and SCAP content management endpoints.

### Files to Modify
- `backend/app/routes/credentials.py` (if exists)
- `backend/app/routes/scap_content.py`
- `backend/app/routes/content.py` (if exists)

### SCAP Content Endpoints

#### 1. GET /api/scap-content/ - List SCAP Content
```python
builder = (QueryBuilder("scap_content")
    .select("id", "name", "version", "description", "content_type", "uploaded_at")
    .order_by("uploaded_at", "DESC")
)
```

#### 2. POST /api/scap-content/ - Upload SCAP Content
```python
builder = (QueryBuilder("scap_content")
    .insert({
        "id": content_id,
        "name": content_data.name,
        "version": content_data.version,
        "description": content_data.description,
        "content_type": content_data.content_type,
        "file_path": file_path,
        "uploaded_at": datetime.utcnow(),
        "uploaded_by": current_user['id']
    })
)
```

#### 3. DELETE /api/scap-content/{id} - Delete SCAP Content
```python
builder = (QueryBuilder("scap_content")
    .delete()
    .where("id", content_id)
)
```

### Credentials Endpoints (Unified Credentials System)

#### 1. GET /api/credentials/ - List Credentials
```python
builder = (QueryBuilder("unified_credentials")
    .select("id", "name", "scope", "target_id", "auth_method", "created_at")
    .where("is_active", True)
    .order_by("created_at", "DESC")
)
```

#### 2. POST /api/credentials/ - Create Credential
```python
builder = (QueryBuilder("unified_credentials")
    .insert({
        "id": cred_id,
        "name": cred_data.name,
        "scope": cred_data.scope,
        "target_id": cred_data.target_id,
        "auth_method": cred_data.auth_method,
        "encrypted_data": encrypted_cred_data,
        "created_at": datetime.utcnow(),
        "created_by": current_user['id']
    })
)
```

#### 3. DELETE /api/credentials/{id} - Delete Credential
```python
# Soft delete
builder = (QueryBuilder("unified_credentials")
    .update({
        "is_active": False,
        "deleted_at": datetime.utcnow()
    })
    .where("id", cred_id)
)
```

### Complexity
**Medium** - SCAP content structure needs understanding

### Critical Note
**MUST understand SCAP content workflow before migration:**
- How are profiles extracted?
- How are rules parsed?
- What metadata is stored?
- How does content relate to scans?

### Effort Estimate
**1-2 weeks**

### Deliverables
- [ ] Credential operations use QueryBuilder
- [ ] SCAP content queries use QueryBuilder
- [ ] Feature flag implementation
- [ ] Unit tests pass
- [ ] SCAP content workflow still works

---

## PR-125: Compliance & Audit Reporting

### Status
**DEFERRED** - Complex reporting queries need careful planning

### Scope
Migrate compliance reporting queries and audit log queries to QueryBuilder.

### Files to Modify
- `backend/app/routes/compliance.py` (if exists)
- `backend/app/routes/audit.py`
- `backend/app/routes/group_compliance.py`

### Compliance Reporting Endpoints

#### 1. GET /api/compliance/summary - Overall Compliance Summary
```python
builder = (QueryBuilder("scan_results sr")
    .select("COUNT(DISTINCT sr.scan_id) as total_scans")
    .select("AVG(sr.score) as avg_compliance_score")
    .select("SUM(sr.failed_rules) as total_failed_rules")
    .select("SUM(sr.passed_rules) as total_passed_rules")
    .join("scans s", "s.id = sr.scan_id")
    .where_raw("s.completed_at >= :since_date", {"since_date": since_date})
)
```

#### 2. GET /api/compliance/by-host - Compliance by Host
```python
builder = (QueryBuilder("hosts h")
    .select("h.id", "h.hostname", "h.ip_address")
    .select("sr.score as latest_score")
    .select("sr.failed_rules", "sr.passed_rules", "sr.total_rules")
    .select("s.completed_at as last_scan_date")
    .left_join("""
        LATERAL (
            SELECT s2.id, s2.completed_at
            FROM scans s2
            WHERE s2.host_id = h.id AND s2.status = 'completed'
            ORDER BY s2.completed_at DESC
            LIMIT 1
        ) s
    """, "true")
    .left_join("scan_results sr", "sr.scan_id = s.id")
)
```

#### 3. GET /api/compliance/by-framework - Compliance by Framework
```python
# This would use MongoDB Repository Pattern for compliance rules
# Combined with PostgreSQL for scan results

# PostgreSQL: Get scan statistics
builder = (QueryBuilder("scan_results sr")
    .select("sr.scan_id", "sr.score", "sr.failed_rules", "sr.passed_rules")
    .join("scans s", "s.id = sr.scan_id")
    .where("s.status", "completed")
)

# MongoDB: Get framework rules
repo = ComplianceRuleRepository()
framework_rules = await repo.find_by_framework(framework_name)
```

#### 4. GET /api/compliance/trends - Compliance Trends Over Time
```python
builder = (QueryBuilder("scan_results sr")
    .select("DATE_TRUNC('day', s.completed_at) as scan_date")
    .select("AVG(sr.score) as avg_score")
    .select("COUNT(*) as scan_count")
    .join("scans s", "s.id = sr.scan_id")
    .where("s.status", "completed")
    .where_raw("s.completed_at >= :since_date", {"since_date": since_date})
    .group_by("DATE_TRUNC('day', s.completed_at)")
    .order_by("scan_date", "ASC")
)
```

### Audit Log Endpoints

#### 1. GET /api/audit/logs - List Audit Logs
```python
builder = (QueryBuilder("audit_logs")
    .select("id", "timestamp", "user_id", "action", "resource_type", "resource_id", "ip_address")
    .where_raw("timestamp >= :since_date", {"since_date": since_date})
    .order_by("timestamp", "DESC")
    .limit(100)
    .offset(offset)
)
```

#### 2. GET /api/audit/logs/{id} - Get Audit Log Details
```python
builder = (QueryBuilder("audit_logs")
    .select("*")
    .where("id", log_id)
)
```

### Group Compliance Endpoints

#### 1. GET /api/group-compliance/{group_id} - Group Compliance Summary
```python
builder = (QueryBuilder("hosts h")
    .select("h.id", "h.hostname")
    .select("sr.score", "sr.failed_rules", "sr.passed_rules")
    .join("host_group_memberships hgm", "hgm.host_id = h.id")
    .left_join("""
        LATERAL (
            SELECT sr2.score, sr2.failed_rules, sr2.passed_rules
            FROM scan_results sr2
            JOIN scans s2 ON s2.id = sr2.scan_id
            WHERE s2.host_id = h.id AND s2.status = 'completed'
            ORDER BY s2.completed_at DESC
            LIMIT 1
        ) sr
    """, "true")
    .where("hgm.group_id", group_id)
)
```

### Complexity
**HIGH** - Complex JOIN queries, aggregations, time-series data

### Special Considerations
- LATERAL JOIN queries (PostgreSQL-specific)
- Time-series aggregations (DATE_TRUNC)
- Complex GROUP BY with multiple dimensions
- Performance critical (reporting dashboards)

### Effort Estimate
**1-2 weeks**

### Deliverables
- [ ] Reporting queries use QueryBuilder
- [ ] Complex JOIN queries optimized
- [ ] Audit log queries use QueryBuilder
- [ ] Feature flag implementation
- [ ] Performance benchmarks documented
- [ ] Unit tests pass

---

## PR-126: System Settings & Low-Priority Endpoints

### Status
**DEFERRED** - Lower priority, can be done last

### Scope
Migrate system settings, authorization routes, monitoring routes, webhook routes, and MFA routes.

### Files to Modify
- `backend/app/routes/system_settings_unified.py`
- `backend/app/routes/system_settings.py`
- `backend/app/routes/authorization.py`
- `backend/app/routes/monitoring.py`
- `backend/app/routes/webhooks.py`
- `backend/app/routes/mfa.py`

### System Settings Endpoints

#### 1. GET /api/settings/ - List Settings
```python
builder = (QueryBuilder("system_settings")
    .select("key", "value", "description", "category", "updated_at")
    .order_by("category", "ASC")
    .order_by("key", "ASC")
)
```

#### 2. PUT /api/settings/{key} - Update Setting
```python
builder = (QueryBuilder("system_settings")
    .update({
        "value": setting_update.value,
        "updated_at": datetime.utcnow(),
        "updated_by": current_user['id']
    })
    .where("key", setting_key)
)
```

### Monitoring Endpoints

#### 1. GET /api/monitoring/health - System Health Check
```python
# Database connection check
builder = (QueryBuilder("hosts")
    .select("COUNT(*) as host_count")
)

# Could also check scans, etc.
```

#### 2. GET /api/monitoring/metrics - System Metrics
```python
builder = (QueryBuilder("scans")
    .select("COUNT(*) as total_scans")
    .select("COUNT(CASE WHEN status = 'running' THEN 1 END) as running_scans")
    .select("COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_scans")
)
```

### Webhook Endpoints

#### 1. GET /api/webhooks/ - List Webhooks
```python
builder = (QueryBuilder("webhooks")
    .select("id", "name", "url", "events", "is_active", "created_at")
    .order_by("created_at", "DESC")
)
```

#### 2. POST /api/webhooks/ - Create Webhook
```python
builder = (QueryBuilder("webhooks")
    .insert({
        "id": webhook_id,
        "name": webhook_data.name,
        "url": webhook_data.url,
        "events": json.dumps(webhook_data.events),
        "is_active": True,
        "created_at": datetime.utcnow()
    })
)
```

### MFA Endpoints

#### 1. GET /api/mfa/status - Get MFA Status
```python
builder = (QueryBuilder("users")
    .select("id", "mfa_enabled", "mfa_method")
    .where("id", user_id)
)
```

#### 2. POST /api/mfa/enable - Enable MFA
```python
builder = (QueryBuilder("users")
    .update({
        "mfa_enabled": True,
        "mfa_secret": encrypted_secret,
        "mfa_method": mfa_data.method,
        "updated_at": datetime.utcnow()
    })
    .where("id", user_id)
)
```

### Complexity
**Low to Medium** - Mostly simple CRUD operations

### Effort Estimate
**1-2 weeks**

### Deliverables
- [ ] All remaining endpoints migrated
- [ ] System settings queries use QueryBuilder
- [ ] Monitoring queries optimized
- [ ] Webhook management uses QueryBuilder
- [ ] MFA queries use QueryBuilder
- [ ] Feature flag implementation
- [ ] Unit tests pass

---

## PR-127: CLI Tools & Background Tasks

### Status
**DEFERRED** - Can be done after API endpoints

### Scope
Migrate CLI tools to use Repository Pattern for MongoDB and QueryBuilder for PostgreSQL.

### Files to Modify
- `backend/app/cli/load_compliance_rules.py`
- `backend/app/cli/load_rules_fixed.py`
- `backend/app/tasks/*.py` (monitoring, scan, compliance tasks)

### CLI Tools Migration

#### 1. load_compliance_rules.py
**Current Implementation:**
```python
# Direct MongoDB operations
async def load_rules():
    rules_data = parse_scap_content(xml_file)
    for rule_data in rules_data:
        rule = ComplianceRule(**rule_data)
        await rule.insert()
```

**Repository Pattern Implementation:**
```python
async def load_rules():
    rules_data = parse_scap_content(xml_file)

    # Use Repository Pattern if available
    if REPOSITORY_AVAILABLE:
        repo = ComplianceRuleRepository()
        for rule_data in rules_data:
            # Use repository's insert or upsert method
            await repo.insert_or_update(rule_data)
    else:
        # Direct MongoDB
        for rule_data in rules_data:
            rule = ComplianceRule(**rule_data)
            await rule.insert()
```

### Background Tasks Migration

#### 1. Monitoring Tasks (tasks/monitoring.py)
```python
@celery_app.task
def check_host_connectivity(host_id: str):
    settings = get_settings()

    if settings.use_query_builder:
        # Get host info using QueryBuilder
        builder = (QueryBuilder("hosts")
            .select("id", "hostname", "ip_address", "port", "auth_method")
            .where("id", host_id)
        )
        sql, params = builder.build()
        result = db.execute(text(sql), params)
    else:
        # Direct SQL
        result = db.execute(text("SELECT * FROM hosts WHERE id = :id"), {"id": host_id})

    # ... connectivity check logic ...

    # Update host status
    if settings.use_query_builder:
        update_builder = (QueryBuilder("hosts")
            .update({
                "status": new_status,
                "last_check": datetime.utcnow()
            })
            .where("id", host_id)
        )
        sql, params = update_builder.build()
        db.execute(text(sql), params)
```

#### 2. Scan Tasks (tasks/scan.py)
```python
@celery_app.task
def update_scan_progress(scan_id: str, progress: int):
    settings = get_settings()

    if settings.use_query_builder:
        builder = (QueryBuilder("scans")
            .update({
                "progress": progress,
                "updated_at": datetime.utcnow()
            })
            .where("id", scan_id)
        )
        sql, params = builder.build()
        db.execute(text(sql), params)
    else:
        db.execute(text("""
            UPDATE scans SET progress = :progress, updated_at = :updated_at
            WHERE id = :scan_id
        """), {"progress": progress, "updated_at": datetime.utcnow(), "scan_id": scan_id})
```

#### 3. Compliance Tasks (tasks/compliance.py)
```python
@celery_app.task
async def update_compliance_statistics():
    settings = get_settings()

    if REPOSITORY_AVAILABLE and settings.use_repository_pattern:
        # Use Repository Pattern for MongoDB
        repo = ComplianceRuleRepository()
        stats = await repo.get_statistics()
    else:
        # Direct MongoDB aggregation
        stats = await ComplianceRule.aggregate([...]).to_list()

    # Store statistics
    if settings.use_query_builder:
        builder = (QueryBuilder("compliance_statistics")
            .insert({
                "timestamp": datetime.utcnow(),
                "total_rules": stats['total_rules'],
                "frameworks": stats['frameworks']
            })
        )
        sql, params = builder.build()
        db.execute(text(sql), params)
```

### Complexity
**Medium** - Mix of MongoDB and PostgreSQL operations

### Effort Estimate
**1 week**

### Deliverables
- [ ] CLI tools use Repository Pattern for MongoDB
- [ ] Background tasks use QueryBuilder/Repository
- [ ] Bulk operations optimized
- [ ] Logging implemented
- [ ] Feature flag support
- [ ] Integration tests pass

---

## PR-128: Feature Flag Removal & Cleanup

### Status
**DEFERRED** - Final cleanup step after all migrations complete

### Scope
Remove `use_query_builder` and `use_repository_pattern` feature flags, delete old code paths, finalize migration.

### Prerequisites
All PRs 115-127 must be completed and verified in production.

### Tasks

#### 1. Remove Feature Flags from Configuration
**Files:**
- `backend/app/config.py`
- `.env` files
- `docker-compose.yml`

**Changes:**
```python
# REMOVE these fields from Settings class
use_query_builder: bool = Field(default=False, ...)
use_repository_pattern: bool = Field(default=False, ...)
```

#### 2. Remove Dual Code Paths

**Before (with feature flag):**
```python
settings = get_settings()
if settings.use_query_builder:
    # QueryBuilder path
    builder = QueryBuilder("hosts").select("*").where("id", host_id)
    sql, params = builder.build()
    result = db.execute(text(sql), params)
else:
    # Direct SQL path
    result = db.execute(text("SELECT * FROM hosts WHERE id = :id"), {"id": host_id})
```

**After (QueryBuilder only):**
```python
# QueryBuilder is now the default and only implementation
builder = QueryBuilder("hosts").select("*").where("id", host_id)
sql, params = builder.build()
result = db.execute(text(sql), params)
```

#### 3. Remove Fallback Imports

**Before:**
```python
try:
    from ..utils.query_builder import QueryBuilder
    QUERY_BUILDER_AVAILABLE = True
except ImportError:
    QUERY_BUILDER_AVAILABLE = False
```

**After:**
```python
from ..utils.query_builder import QueryBuilder
# Always available now
```

#### 4. Remove Feature Flag Logging

**Before:**
```python
if settings.use_query_builder:
    logger.info("Using QueryBuilder for get_host endpoint")
else:
    logger.debug("Using direct SQL for get_host endpoint")
```

**After:**
```python
# Optional: Keep performance logging, remove feature flag mention
logger.debug("Executing get_host query using QueryBuilder")
```

#### 5. Update Documentation

**Files to Update:**
- `/docs/MIGRATION_ROADMAP.md` - Mark as COMPLETE
- `/docs/QUERYBUILDER_EXPLANATION.md` - Remove feature flag references
- `/docs/OW-REFACTOR-002_MONGODB_REPOSITORY.md` - Remove feature flag references
- `README.md` - Update with final architecture

#### 6. Performance Analysis Report

Create comprehensive report comparing before/after migration:

**Metrics to Include:**
- Query performance (avg execution time)
- Code reduction (lines of code eliminated)
- Security improvements (SQL injection vulnerabilities fixed)
- Maintainability improvements (cyclomatic complexity reduction)

**Example Report Structure:**
```markdown
# QueryBuilder Migration Performance Report

## Executive Summary
- 100% of endpoints migrated to QueryBuilder/Repository Pattern
- 0 SQL injection vulnerabilities detected
- 60% reduction in duplicated query code
- <5% performance overhead from QueryBuilder

## Query Performance Comparison

| Endpoint | Before (ms) | After (ms) | Change |
|----------|-------------|-----------|--------|
| GET /api/hosts/ | 45ms | 47ms | +4% |
| POST /api/hosts/ | 12ms | 13ms | +8% |
| GET /api/scans/ | 120ms | 118ms | -2% |

## Code Quality Metrics

- **Lines of Code Removed**: 2,450 lines (duplicated SQL queries)
- **Lines of Code Added**: 3,200 lines (QueryBuilder calls + feature flags)
- **Net After Cleanup**: -1,800 lines (26% reduction)
- **Cyclomatic Complexity**: Reduced from avg 8.2 to 5.4

## Security Improvements

- **SQL Injection Vulnerabilities Fixed**: 47 critical endpoints
- **Parameter Binding**: 100% of queries use parameterized queries
- **Input Validation**: Centralized in QueryBuilder class
```

### Complexity
**Medium** - Large-scale code cleanup

### Effort Estimate
**1-2 weeks**

### Deliverables
- [ ] QueryBuilder and Repository Pattern are default
- [ ] Old code removed (2,000+ lines deleted)
- [ ] Documentation updated
- [ ] Performance improvements documented
- [ ] Migration complete
- [ ] All tests passing
- [ ] Production deployment successful

---

## Migration Timeline (When Resumed)

### Phase 1: Core Compliance Features First
**Prerequisite:** Understand `/content` and `/scans` workflows thoroughly

1. **Week 1-2:** PR-120 (Scans endpoints)
2. **Week 3-4:** PR-123 (Remediation services)
3. **Week 5-6:** PR-124 (SCAP content)

### Phase 2: Supporting Features
4. **Week 7-8:** PR-125 (Compliance reporting)
5. **Week 9-10:** PR-121 (Users & Auth)
6. **Week 11-12:** PR-122 (Host groups)

### Phase 3: Infrastructure & Cleanup
7. **Week 13-14:** PR-126 (System settings)
8. **Week 15:** PR-127 (CLI tools & tasks)
9. **Week 16-17:** PR-128 (Feature flag removal)

**Total Timeline:** 16-17 weeks (~4 months)

---

## Decision Log

### Why Defer Now?

**Date:** October 20, 2025

**Reason:**
Before migrating the scan and remediation database queries, we need a comprehensive understanding of:

1. **SCAP Content Structure (`/content`)**
   - How SCAP XML files are parsed
   - What metadata is extracted and stored
   - How profiles relate to rules
   - What the compliance rule data model looks like

2. **Scan Workflow (`/scans`)**
   - How scans are orchestrated (Celery tasks)
   - How scan progress is tracked
   - How results are stored and retrieved
   - How remediation is triggered

3. **Risk of Premature Migration:**
   - Breaking core compliance functionality
   - Introducing subtle bugs in scan orchestration
   - Incorrect remediation rule lookups
   - Performance degradation in critical paths

**Decision:** Defer PRs 120-128 until compliance workflows are stable and well-documented.

### When to Resume?

Resume migration work when:

1. ✅ `/content` endpoints are stable and documented
2. ✅ `/scans` workflow is well understood
3. ✅ Compliance scanning has been tested end-to-end
4. ✅ Remediation workflow is documented
5. ✅ Team has bandwidth for 4-month migration project

---

## References

- **QueryBuilder Documentation:** `/docs/QUERYBUILDER_EXPLANATION.md`
- **Repository Pattern Documentation:** `/docs/OW-REFACTOR-002_MONGODB_REPOSITORY.md`
- **Migration Roadmap:** `/docs/MIGRATION_ROADMAP.md`
- **Completed Work:**
  - PR #115: QueryBuilder Infrastructure
  - PR #116: Initial QueryBuilder Migration (GET /api/hosts/{id})
  - PR #117: Repository Pattern Infrastructure
  - PR #131: Compliance Rules Repository Migration
  - PR #132: Health Monitoring Repository Migration
  - PR #133: Hosts CRUD Endpoints Migration

---

**Last Updated:** October 20, 2025
**Document Owner:** OpenWatch Development Team
**Status:** DEFERRED - To be resumed after compliance workflows are understood

---

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
