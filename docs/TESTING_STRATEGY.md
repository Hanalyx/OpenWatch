# Testing Strategy - Stop Breaking Working Features

## The Problem

**Current State:**
- ✅ CI/CD pipeline exists
- ✅ GitHub Actions configured
- ❌ **Zero actual tests written**
- ❌ Tests skip with `--passWithNoTests`
- ❌ **No protection against regressions**

**Result:** Every code change risks breaking working functionality.

## Practical Solution: Progressive Test Coverage

Start small, add tests incrementally, **never decrease coverage**.

### Phase 1: Critical Path Tests (Week 1)

**Goal:** Protect the 5 core workflows that must always work.

#### Backend Critical Tests

**File:** `backend/tests/test_critical_workflows.py`

```python
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_endpoint():
    """Health check must always work"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_user_login():
    """Admin login must always work"""
    response = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "admin"
    })
    assert response.status_code == 200
    assert "access_token" in response.json()

def test_create_ssh_credential(admin_token):
    """SSH credential creation must work (unified_credentials fix)"""
    response = client.post(
        "/api/system/credentials",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "test-ssh",
            "username": "testuser",
            "auth_method": "password",
            "password": "testpass"
        }
    )
    assert response.status_code == 201
    # Critical: This must NOT return 500 "unified_credentials does not exist"

def test_add_host(admin_token):
    """Adding a host must work"""
    response = client.post(
        "/api/hosts",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "hostname": "192.168.1.100",
            "ssh_port": 22
        }
    )
    assert response.status_code in [200, 201]

def test_database_schema_exists(db_session):
    """Critical tables must exist after initialization"""
    from sqlalchemy import text

    critical_tables = [
        "users", "roles", "hosts", "scans",
        "unified_credentials", "scheduler_config"
    ]

    for table in critical_tables:
        result = db_session.execute(text(f"""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = '{table}'
            )
        """))
        assert result.scalar() is True, f"Table {table} must exist"
```

**Fixtures:** `backend/tests/conftest.py`

```python
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base, get_db
from app.main import app

TEST_DATABASE_URL = "postgresql://openwatch:openwatch_test@localhost:5432/openwatch_test"

@pytest.fixture(scope="session")
def db_engine():
    engine = create_engine(TEST_DATABASE_URL)
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def db_session(db_engine):
    Session = sessionmaker(bind=db_engine)
    session = Session()
    yield session
    session.rollback()
    session.close()

@pytest.fixture
def admin_token(client):
    """Get admin JWT token for authenticated requests"""
    response = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "admin"
    })
    return response.json()["access_token"]
```

#### Frontend Critical Tests

**File:** `frontend/src/__tests__/critical-workflows.test.tsx`

```typescript
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { LoginPage } from '../pages/LoginPage';
import { HostsPage } from '../pages/HostsPage';

describe('Critical User Workflows', () => {
  test('user can login with admin credentials', async () => {
    render(<LoginPage />);

    await userEvent.type(screen.getByLabelText(/username/i), 'admin');
    await userEvent.type(screen.getByLabelText(/password/i), 'admin');
    await userEvent.click(screen.getByRole('button', { name: /login/i }));

    await waitFor(() => {
      expect(screen.getByText(/dashboard/i)).toBeInTheDocument();
    });
  });

  test('hosts page displays without errors', async () => {
    const { container } = render(<HostsPage />);

    // Critical: Must not show "InternalError" or 500 errors
    expect(screen.queryByText(/InternalError/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/500/i)).not.toBeInTheDocument();
  });
});
```

**Setup:** `frontend/src/setupTests.ts`

```typescript
import '@testing-library/jest-dom';
import { server } from './mocks/server';

beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());
```

### Phase 2: Database Migration Tests (Week 2)

**Why:** The `unified_credentials` issue happened because migrations weren't tested.

**File:** `backend/tests/test_database_schema.py`

```python
def test_init_database_schema_creates_all_tables():
    """Test the init_database_schema.py fix"""
    from app.init_database_schema import initialize_database_schema

    success = initialize_database_schema()
    assert success is True

    # Verify critical non-ORM tables exist
    from sqlalchemy import text
    result = db.execute(text("""
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_name IN ('unified_credentials', 'scheduler_config')
    """))
    tables = [row[0] for row in result]
    assert 'unified_credentials' in tables
    assert 'scheduler_config' in tables

def test_fresh_install_succeeds():
    """Simulate fresh install from GitHub clone"""
    # Drop all tables
    Base.metadata.drop_all(bind=engine)

    # Run initialization (as start-openwatch.sh does)
    from app.init_database_schema import initialize_database_schema
    success = initialize_database_schema()

    assert success is True

    # Verify admin user can be created
    from app.init_roles import initialize_rbac_system
    await initialize_rbac_system()

    # Login must work
    response = client.post("/api/auth/login", json={
        "username": "admin",
        "password": "admin"
    })
    assert response.status_code == 200
```

### Phase 3: Contract Tests (Week 3)

**Why:** API breaking changes break the frontend silently.

**File:** `backend/tests/test_api_contracts.py`

```python
def test_host_api_response_schema():
    """Frontend depends on this exact schema"""
    response = client.get("/api/hosts")
    hosts = response.json()

    if len(hosts) > 0:
        host = hosts[0]
        # Critical fields frontend expects
        assert "id" in host  # UUID as string
        assert "hostname" in host
        assert "status" in host  # "online", "offline", "unknown"
        assert "ssh_port" in host
        # Must NOT change these field names without frontend update

def test_scan_result_schema():
    """Scan results must have expected structure"""
    response = client.get("/api/scans/123/results")
    result = response.json()

    assert "scan_id" in result
    assert "rules" in result
    assert isinstance(result["rules"], list)

    if len(result["rules"]) > 0:
        rule = result["rules"][0]
        assert "rule_id" in rule
        assert "status" in rule  # "pass", "fail", "not_checked"
        assert "severity" in rule
```

### Phase 4: Integration Tests (Week 4)

**Why:** Components work individually but fail together.

**File:** `backend/tests/test_ssh_integration.py`

```python
@pytest.mark.integration
def test_ssh_credential_to_host_scan_workflow():
    """Full workflow: Create credential → Add host → Run scan"""

    # 1. Create SSH credential
    cred_response = client.post("/api/system/credentials", json={
        "name": "integration-test-ssh",
        "username": "testuser",
        "auth_method": "password",
        "password": "testpass123"
    })
    assert cred_response.status_code == 201
    cred_id = cred_response.json()["id"]

    # 2. Add host with credential
    host_response = client.post("/api/hosts", json={
        "hostname": "192.168.1.100",
        "ssh_port": 22,
        "credential_id": cred_id
    })
    assert host_response.status_code == 201
    host_id = host_response.json()["id"]

    # 3. Test SSH connectivity
    conn_response = client.post(f"/api/hosts/{host_id}/test-connection")
    assert conn_response.status_code == 200
    assert conn_response.json()["status"] == "success"

    # 4. Start scan (if test environment has oscap)
    scan_response = client.post("/api/scans", json={
        "host_id": host_id,
        "profile": "stig-rhel8"
    })
    # Accept 201 (created) or 503 (no SCAP content) in test env
    assert scan_response.status_code in [201, 503]
```

## Implementation Plan

### Week 1: Foundation
```bash
# Install test dependencies
cd backend
pip install pytest pytest-asyncio pytest-cov

# Create test directory
mkdir -p tests
touch tests/__init__.py
touch tests/conftest.py

# Write critical path tests (5 tests)
# Run: pytest tests/ -v

# Update CI to fail on test failure
# Remove: || echo "Some tests failed but continuing..."
```

### Week 2: Coverage Baseline
```bash
# Measure current coverage
pytest tests/ --cov=app --cov-report=term-missing

# Set minimum coverage requirement in CI
# Add to ci.yml: --cov-fail-under=50
```

### Week 3: Pre-commit Hook
```bash
# Prevent commits that break tests
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
cd backend
pytest tests/test_critical_workflows.py -x
if [ $? -ne 0 ]; then
    echo "❌ Critical tests failed! Fix before committing."
    exit 1
fi
EOF
chmod +x .git/hooks/pre-commit
```

### Week 4: Branch Protection
- GitHub Settings → Branches → Add rule for `main`
- ✅ Require status checks: `Backend CI`, `Frontend CI`
- ✅ Require tests to pass before merging
- ❌ Disable "Allow bypassing required pull requests"

## Testing Anti-Patterns to Avoid

❌ **Don't:**
- Write tests after code is broken
- Mock everything (test real interactions)
- Aim for 100% coverage immediately
- Write tests that pass when code is broken

✅ **Do:**
- Write tests for bugs before fixing them
- Test critical user workflows first
- Increase coverage incrementally (5% per week)
- Run tests locally before pushing

## Measuring Success

**Week 1 Metrics:**
- ✅ 5 critical tests passing
- ✅ CI fails when tests fail
- ✅ Developers run tests locally

**Month 1 Metrics:**
- ✅ 25+ tests covering critical paths
- ✅ 50%+ backend code coverage
- ✅ Zero test failures in main branch

**Month 3 Metrics:**
- ✅ 100+ tests across frontend/backend
- ✅ 70%+ code coverage
- ✅ All PRs include tests for new features
- ✅ Regression rate < 1 per release

## Tools and Resources

**Backend Testing:**
- pytest: https://docs.pytest.org/
- FastAPI testing: https://fastapi.tiangolo.com/tutorial/testing/
- SQLAlchemy testing: https://docs.sqlalchemy.org/en/20/orm/session_transaction.html

**Frontend Testing:**
- React Testing Library: https://testing-library.com/react
- Playwright: https://playwright.dev/ (already in CI)
- MSW (API mocking): https://mswjs.io/

**CI/CD:**
- GitHub Actions already configured
- Just need to add actual tests

## Quick Win: Add One Test Now

**Right now, add this single test to protect the fix you just made:**

```python
# backend/tests/test_unified_credentials_fix.py
def test_unified_credentials_table_exists():
    """Regression test: unified_credentials must exist after init"""
    from sqlalchemy import text
    from app.database import SessionLocal

    db = SessionLocal()
    result = db.execute(text("""
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_name = 'unified_credentials'
        )
    """))

    assert result.scalar() is True, (
        "unified_credentials table missing! "
        "This breaks SSH credential creation (500 error). "
        "Check init_database_schema.py"
    )
```

**Run it:**
```bash
cd backend
pytest tests/test_unified_credentials_fix.py -v
```

This single test prevents your recent fix from being broken again.

## Conclusion

**The answer to "how do we stop breaking things?" is:**

1. **Start with 5 critical tests** (this week)
2. **Add tests for every bug fix** (prevents regression)
3. **Require tests to pass in CI** (no bypassing)
4. **Increase coverage incrementally** (5-10% per week)
5. **Make testing easy** (good fixtures, fast tests)

**Not this:**
- ❌ Write 1000 tests before the next feature
- ❌ Aim for 100% coverage tomorrow
- ❌ Test everything including trivial code

**This:**
- ✅ Write 5 tests for critical workflows today
- ✅ Add 1 test per bug fix
- ✅ Run tests before every commit
- ✅ Increase coverage gradually

**Start now. Write one test today.**
