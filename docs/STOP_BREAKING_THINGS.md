# How to Stop Breaking Working Features

## TL;DR - Start Here

**Problem:** We keep breaking things that worked yesterday.

**Root Cause:** Zero automated tests catching regressions.

**Solution:**
```bash
cd backend
pytest tests/test_regression_unified_credentials.py -v
```

If that passes, your recent fix is protected. **That's the first test.**

## The Fix You Just Made

**What broke:** Fresh OpenWatch installs failed with 500 error creating SSH credentials
**Why:** `unified_credentials` table didn't exist (no ORM model, migrations broken)
**Your fix:** Created `init_database_schema.py` to create non-ORM tables
**Protection:** `test_regression_unified_credentials.py` prevents this regression

## Three-Layer Defense Strategy

### Layer 1: Automated Tests (Catches issues before commit)

**Status:**
- ✅ CI/CD pipeline exists
- ❌ Zero actual tests (skips with `--passWithNoTests`)
- ✅ First regression test created today

**Quick wins this week:**

1. **Run existing test:**
   ```bash
   cd backend
   pip install pytest pytest-asyncio
   pytest tests/test_regression_unified_credentials.py -v
   ```

2. **Add to pre-commit hook:**
   ```bash
   cat > .git/hooks/pre-commit << 'EOF'
   #!/bin/bash
   cd backend && pytest tests/test_regression_unified_credentials.py -x
   [ $? -eq 0 ] || { echo "❌ Critical test failed!"; exit 1; }
   EOF
   chmod +x .git/hooks/pre-commit
   ```

3. **Update CI to actually fail:**
   ```yaml
   # .github/workflows/ci.yml line 101
   # Change from:
   pytest tests/ || echo "Some tests failed but continuing..."
   # To:
   pytest tests/ --cov=app --cov-fail-under=10
   ```

**Rule:** Every bug fix must include a regression test.

### Layer 2: Code Review Checklist

Before merging any PR, verify:

- [ ] Does this change affect database schema?
  - If yes: Add migration test
- [ ] Does this change API response format?
  - If yes: Add contract test
- [ ] Does this change authentication flow?
  - If yes: Add integration test
- [ ] Does this fix a bug?
  - **Required:** Add regression test that fails without the fix

**Example PR review comment:**
> This fixes the SSH credential 500 error. Where's the test that proves it won't break again?

### Layer 3: Monitoring Critical Paths

**5 Critical Workflows** that must always work:

1. ✅ **Health check** - `GET /health` returns 200
2. ✅ **Admin login** - Default admin/admin works on fresh install
3. ✅ **Create SSH credential** - POST `/api/system/credentials` succeeds
4. ✅ **Add host** - POST `/api/hosts` with valid data succeeds
5. ✅ **Database schema** - All critical tables exist after init

**Test coverage:** `backend/tests/test_regression_unified_credentials.py`

**CI enforcement:** Update `.github/workflows/ci.yml` line 101 to fail on test failure

## Incremental Testing Strategy

**Don't:** Try to achieve 100% coverage tomorrow (burnout)
**Do:** Add 5-10% coverage per week (sustainable)

### Week 1: Foundation
- ✅ Run `pytest tests/test_regression_unified_credentials.py`
- ✅ Add pre-commit hook
- ✅ Update CI to fail on test failure
- Target: 5 tests, 10% coverage

### Week 2: Critical Paths
- Add tests for 5 critical workflows
- Add database migration test
- Target: 15 tests, 25% coverage

### Week 3: API Contracts
- Add schema validation tests
- Test authentication flows
- Target: 25 tests, 40% coverage

### Week 4: Integration Tests
- Test SSH → Host → Scan workflow
- Test SCAP content upload → Scan
- Target: 35 tests, 50% coverage

**Metric:** Zero regressions in main branch

## What to Test (Priority Order)

### Priority 1: Regressions (Test bugs you just fixed)
```python
def test_unified_credentials_exists():
    """Regression: SSH credentials broke on Oct 7, 2025"""
    assert table_exists("unified_credentials")
```

### Priority 2: Critical User Workflows
```python
def test_user_can_scan_host():
    """Complete workflow: Login → Add Host → Scan"""
    token = login("admin", "admin")
    host_id = create_host(token, "192.168.1.100")
    scan_id = start_scan(token, host_id, "stig-rhel8")
    assert scan_status(scan_id) == "running"
```

### Priority 3: API Contracts
```python
def test_host_api_schema():
    """Frontend breaks if this schema changes"""
    host = get_host(host_id)
    assert "id" in host
    assert "hostname" in host
    assert "status" in host  # Must be "online", "offline", or "unknown"
```

### Priority 4: Edge Cases
```python
def test_create_host_with_invalid_ip():
    """Should return 400, not 500"""
    response = create_host(token, "not-an-ip")
    assert response.status_code == 400
```

## Common Patterns That Break Things

### ❌ Database Schema Changes Without Tests

**Bad:**
```python
# Add new column without testing
ALTER TABLE hosts ADD COLUMN new_field VARCHAR(255);
```

**Good:**
```python
# Add migration test first
def test_migration_adds_new_field():
    run_migration("add_new_field_to_hosts")
    assert column_exists("hosts", "new_field")
```

### ❌ API Changes Without Contract Tests

**Bad:**
```python
# Change API response format
return {"hostId": id}  # Was "id"
```

**Good:**
```python
def test_host_api_response_format():
    """Frontend depends on this exact format"""
    response = get_host(host_id)
    assert "id" in response  # Not "hostId"
```

### ❌ Environment-Specific Code

**Bad:**
```python
# Works on laptop, breaks on desktop
if os.path.exists("/home/rracine/data"):
    data_dir = "/home/rracine/data"
```

**Good:**
```python
# Use environment variables
data_dir = os.getenv("SCAP_CONTENT_DIR", "/app/data/scap")

# Test with different environments
def test_data_dir_from_env():
    os.environ["SCAP_CONTENT_DIR"] = "/tmp/test"
    assert get_data_dir() == "/tmp/test"
```

## Testing Anti-Patterns to Avoid

### ❌ Tests That Always Pass
```python
def test_something():
    assert True  # Useless
```

### ❌ Tests That Don't Test Anything
```python
def test_create_host():
    create_host("test-host")
    # No assertions! Did it work?
```

### ❌ Mocking Everything
```python
@mock.patch("database.create_host")
@mock.patch("ssh.connect")
@mock.patch("scanner.scan")
def test_scan(mock_scan, mock_ssh, mock_db):
    # Not testing real interactions
    pass
```

**Better:** Test real database, mock only external services (SSH to real servers)

### ❌ Flaky Tests
```python
def test_with_race_condition():
    start_async_task()
    time.sleep(1)  # Hope it finishes
    assert task_completed()  # Sometimes fails
```

**Better:** Use proper async testing with timeouts

## Practical Examples From Your Codebase

### Example 1: The Bug You Just Fixed

**Before:** No test, broke in production
```python
# init_roles.py created placeholder credential
# But unified_credentials table didn't exist
# Result: 500 error on fresh install
```

**After:** Test catches regression
```python
# tests/test_regression_unified_credentials.py
def test_unified_credentials_table_exists():
    assert table_exists("unified_credentials")
```

### Example 2: Future Bug Prevention

**Scenario:** Someone refactors `init_database_schema.py`

**Without test:**
- Accidentally removes `create_unified_credentials_table()` call
- Code compiles fine
- Application starts without error
- SSH credential creation fails with 500 error
- Users report bug
- You debug for 2 hours

**With test:**
- Developer runs `pytest` before committing
- Test fails immediately: "unified_credentials table does not exist"
- Developer realizes mistake
- Fixes before pushing
- **Total time lost: 30 seconds**

## Measuring Success

### Week 1 Goals
- ✅ First test passing
- ✅ CI fails when test fails
- ✅ Pre-commit hook runs tests

### Month 1 Goals
- ✅ 25+ tests covering critical paths
- ✅ 50% backend code coverage
- ✅ Zero test failures in main branch
- ✅ All PRs require passing tests

### Month 3 Goals
- ✅ 100+ tests across frontend/backend
- ✅ 70% code coverage
- ✅ All PRs include tests for new features
- ✅ Regression rate < 1 per month

## Quick Reference Commands

```bash
# Run all tests
pytest tests/ -v

# Run specific test
pytest tests/test_regression_unified_credentials.py -v

# Run with coverage
pytest tests/ --cov=app --cov-report=term-missing

# Run only fast tests (skip integration)
pytest tests/ -m "not integration"

# Run tests on file change (development)
pytest-watch tests/

# Check test coverage
pytest tests/ --cov=app --cov-report=html
# Open htmlcov/index.html
```

## Next Steps

1. **Today:** Run the regression test
   ```bash
   cd backend
   pytest tests/test_regression_unified_credentials.py -v
   ```

2. **This week:** Add pre-commit hook to run critical tests

3. **This month:** Add 5 tests for critical workflows

4. **Next month:** Achieve 50% coverage

## Resources

- **Testing Strategy:** [docs/TESTING_STRATEGY.md](TESTING_STRATEGY.md)
- **First Run Guide:** [docs/FIRST_RUN_SETUP.md](FIRST_RUN_SETUP.md)
- **CI Configuration:** [.github/workflows/ci.yml](../.github/workflows/ci.yml)
- **Example Tests:** [backend/tests/test_regression_unified_credentials.py](../backend/tests/test_regression_unified_credentials.py)

## Key Takeaway

**The answer to "how do we stop breaking things?" is:**

**Write one test for the bug you just fixed.**

Then write one more. Then one more.

That's it. Start small, build incrementally, never decrease coverage.

**You already have the first test. Run it now.**
