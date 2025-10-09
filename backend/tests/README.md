# OpenWatch Backend Tests

## Quick Start

```bash
# 1. Ensure PostgreSQL container is running
docker ps | grep postgres

# 2. Initialize test database (first time only)
python tests/setup_test_db.py

# 3. Run tests
pytest tests/ -v

# 4. Run specific test
pytest tests/test_regression_unified_credentials.py -v

# 5. Run with coverage
pytest tests/ --cov=app --cov-report=term-missing
```

## Test Database

**Connection:** `postgresql://openwatch:openwatch_secure_db_2025@localhost:5432/openwatch_test`

- Same PostgreSQL instance as dev
- Separate database (`openwatch_test`)
- Port exposed to localhost only (`127.0.0.1:5432`)
- **Production safe**: Not exposed to network

## Setup (First Time)

```bash
# Create test database
docker exec openwatch-db psql -U openwatch -d openwatch -c \
  "CREATE DATABASE openwatch_test OWNER openwatch;"

# Initialize schema
python tests/setup_test_db.py
```

## Current Tests

### Regression Tests
**File:** `test_regression_unified_credentials.py`

Protects the fix for the `unified_credentials` table issue (Oct 7, 2025):
- ✅ `test_unified_credentials_table_exists` - Table must exist
- ✅ `test_unified_credentials_schema` - Correct columns and types
- ✅ `test_scheduler_config_table_exists` - Host monitoring table
- ✅ `test_all_critical_tables_exist` - Smoke test for schema
- ⏭️ `test_ssh_credential_creation_api` - Integration (CI only)

## Troubleshooting

### Tests fail with "Connection refused"
```bash
# Check if PostgreSQL is running
docker ps | grep postgres

# Should show: 127.0.0.1:5432->5432/tcp

# If not, ensure port is mapped in docker-compose.yml:
# ports:
#   - "127.0.0.1:5432:5432"
```

### Tests fail with "table does not exist"
```bash
# Re-run schema initialization
python tests/setup_test_db.py
```

### Tests fail with "authentication failed"
```bash
# Verify password in conftest.py matches .env
grep POSTGRES_PASSWORD ../.env

# Update conftest.py TEST_DATABASE_URL if needed
```

## Adding New Tests

1. **Regression test** (bug fix):
   ```python
   # tests/test_regression_<feature>.py
   def test_<bug_description>(db_session):
       """Regression: <what broke and when>"""
       # Test that reproduces the bug (should fail without fix)
       assert expected_behavior
   ```

2. **Critical workflow**:
   ```python
   # tests/test_critical_workflows.py
   def test_user_can_<action>(client, admin_token):
       """User must be able to <critical action>"""
       response = client.post(...)
       assert response.status_code == 200
   ```

3. **API contract**:
   ```python
   # tests/test_api_contracts.py
   def test_<endpoint>_response_schema():
       """Frontend depends on this schema"""
       # Validate response structure doesn't change
   ```

## CI Integration

Tests run automatically in GitHub Actions:
- `.github/workflows/ci.yml`
- PostgreSQL 15.10-alpine service
- Test database auto-created
- Coverage reports uploaded as artifacts

## Security Note

**Port mapping `127.0.0.1:5432` is dev-safe:**
- Only localhost can connect
- NOT exposed to network (not `0.0.0.0:5432`)
- Same security as MongoDB (`127.0.0.1:27017`)
- For production: Remove port mapping entirely

## Resources

- **Testing Strategy:** `/docs/TESTING_STRATEGY.md`
- **Stop Breaking Things:** `/docs/STOP_BREAKING_THINGS.md`
- **Pytest Docs:** https://docs.pytest.org/
- **FastAPI Testing:** https://fastapi.tiangolo.com/tutorial/testing/
