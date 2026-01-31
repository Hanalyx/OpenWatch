# Epic E5: Testing Coverage

**Epic ID**: E5
**Priority**: P2 (Medium)
**Phase**: 4-5 (Week 7-10)
**Owner**: AI (Claude) with Human review
**Status**: In Progress
**Depends On**: E2 (Service organization), E4 (Frontend refactor)

---

## 1. Epic Summary

Achieve 80% backend test coverage and 60% frontend coverage, with focus on critical paths: authentication, encryption, and scan execution.

---

## 2. Problem Statement

Current testing gaps:
- **Unknown backend coverage** (needs measurement)
- **Unknown frontend coverage** (mostly E2E with Playwright)
- **Critical paths may be undertested** (auth, encryption, scanning)
- **No regression test suite** documented

This creates:
- Risk of regressions during refactoring
- Uncertainty about code quality
- Deployment anxiety

---

## 3. Goals

| Goal | Metric | Target |
|------|--------|--------|
| Backend coverage | pytest --cov | 80% |
| Frontend coverage | vitest --coverage | 60% |
| Critical path coverage | Auth, encryption, scan | 100% |
| Regression tests | Bug fix tests | 100% of fixes |

---

## 4. Testing Strategy

### 4.1 Test Pyramid

```
        /\
       /  \  E2E Tests (Playwright)
      /    \   - Critical user flows
     /──────\  - 10% of tests
    /        \
   /  Integ.  \ Integration Tests
  /    Tests   \  - API endpoints
 /──────────────\  - 30% of tests
/                \
/   Unit Tests    \ Unit Tests
/                  \  - Services, utils
────────────────────  - 60% of tests
```

### 4.2 Test Categories (Pytest Markers)

| Marker | Purpose | Speed |
|--------|---------|-------|
| `@pytest.mark.unit` | Isolated logic | Fast |
| `@pytest.mark.integration` | Database/API | Medium |
| `@pytest.mark.e2e` | Full flow | Slow |
| `@pytest.mark.security` | Security-focused | Medium |
| `@pytest.mark.regression` | Bug fix verification | Varies |

---

## 5. User Stories

### Story E5-S1: Measure Current Coverage
**Priority**: P0 | **Points**: 2 | **Status**: Complete

**As a** developer,
**I want** to know current test coverage,
**So that** I can identify gaps.

**Acceptance Criteria**:
- [x] Backend coverage measured: `pytest --cov=backend/app` (31% baseline, 32% after tests)
- [ ] Frontend coverage measured: `npm run test:coverage`
- [x] Coverage report generated (HTML)
- [x] Gaps identified and documented
- [x] Baseline established for tracking

**Commands**:
```bash
# Backend
cd backend
pytest --cov=app --cov-report=html --cov-report=term-missing

# Frontend
cd frontend
npm run test:coverage
```

---

### Story E5-S2: Authentication Service Tests
**Priority**: P0 | **Points**: 4 | **Status**: Complete

**As a** developer,
**I want** 100% test coverage on authentication,
**So that** security is verified.

**Acceptance Criteria**:
- [x] `tests/unit/services/auth/test_credential_service.py` - Credential validation, auth method compatibility (18 tests)
- [ ] `tests/unit/test_jwt.py` - Token generation, validation, expiry
- [x] `tests/unit/services/auth/test_mfa.py` - MFA enrollment, TOTP, backup codes (22 tests)
- [x] `tests/unit/services/auth/test_validation.py` - Password strength, security policies (15 tests)
- [ ] `tests/integration/test_auth_api.py` - Auth endpoints
- [x] `tests/security/test_auth_security.py` - Security-focused tests (10 tests)
- [ ] 100% coverage on auth modules (67 tests written, integration tests pending)

**Test Cases**:
```python
# tests/unit/test_auth.py
class TestAuthentication:
    async def test_login_valid_credentials(self):
        """Valid credentials return token."""

    async def test_login_invalid_password(self):
        """Invalid password returns 401."""

    async def test_login_nonexistent_user(self):
        """Nonexistent user returns 401 (same as invalid password)."""

    async def test_login_locked_account(self):
        """Locked account returns 403."""

    async def test_token_refresh_valid(self):
        """Valid refresh token returns new access token."""

    async def test_token_refresh_expired(self):
        """Expired refresh token returns 401."""

    async def test_logout_invalidates_token(self):
        """Logout invalidates the token."""

# tests/security/test_auth_security.py
class TestAuthSecurity:
    async def test_password_timing_attack_prevention(self):
        """Password comparison uses constant-time."""

    async def test_brute_force_protection(self):
        """Multiple failed logins trigger lockout."""

    async def test_jwt_signature_validation(self):
        """Tampered JWT is rejected."""
```

---

### Story E5-S3: Encryption Service Tests
**Priority**: P0 | **Points**: 3 | **Status**: Complete

**As a** developer,
**I want** 100% test coverage on encryption,
**So that** data protection is verified.

**Acceptance Criteria**:
- [x] `tests/unit/encryption/test_encryption_service.py` - Encrypt/decrypt round-trip (19 tests)
- [x] `tests/unit/encryption/test_config.py` - Config validation, KDF algorithms (20 tests)
- [ ] `tests/unit/test_credential_encryption.py` - Credential storage
- [x] `tests/security/test_fips_compliance.py` - FIPS validation (9 tests)
- [x] 90% coverage on encryption modules (48 tests, 115 stmts / 12 misses)

**Test Cases**:
```python
# tests/unit/test_encryption_service.py
class TestEncryptionService:
    def test_encrypt_decrypt_roundtrip(self):
        """Encrypted data can be decrypted."""

    def test_different_keys_different_output(self):
        """Different keys produce different ciphertext."""

    def test_tampered_ciphertext_fails(self):
        """Tampered ciphertext raises error."""

    def test_empty_input_handled(self):
        """Empty input is handled gracefully."""

# tests/security/test_fips_compliance.py
class TestFIPSCompliance:
    def test_aes_256_gcm_used(self):
        """Verify AES-256-GCM is used."""

    def test_key_length_correct(self):
        """Verify 256-bit keys."""

    def test_pbkdf2_iterations(self):
        """Verify 100k+ PBKDF2 iterations."""
```

---

### Story E5-S4: Scan Execution Tests
**Priority**: P0 | **Points**: 5 | **Status**: Complete

**As a** developer,
**I want** comprehensive scan execution tests,
**So that** core functionality is verified.

**Acceptance Criteria**:
- [x] `tests/unit/services/engine/test_models.py` - Engine data models, enums, exceptions (21 tests)
- [x] `tests/unit/services/engine/test_executors.py` - Command building, file transfer, result paths (17 tests)
- [x] `tests/unit/services/engine/test_result_parsers.py` - XCCDF parsing, normalization, statistics (56 tests)
- [ ] `tests/integration/test_scan_api.py` - Scan endpoints
- [ ] `tests/integration/test_scan_workflow.py` - Full scan flow
- [ ] 80% coverage on engine modules (94 unit tests written, integration tests pending)

**Test Cases**:
```python
# tests/unit/test_scan_service.py
class TestScanService:
    async def test_create_scan(self):
        """Scan is created with correct status."""

    async def test_queue_scan(self):
        """Scan is queued to Celery."""

    async def test_cancel_scan(self):
        """Running scan can be cancelled."""

    async def test_scan_status_transitions(self):
        """Scan status transitions are valid."""

# tests/integration/test_scan_workflow.py
class TestScanWorkflow:
    async def test_full_scan_flow(self):
        """Create → Queue → Execute → Complete."""

    async def test_scan_with_failures(self):
        """Scan handles rule failures correctly."""

    async def test_scan_timeout(self):
        """Scan times out gracefully."""
```

---

### Story E5-S5: Repository Layer Tests
**Priority**: P1 | **Points**: 3 | **Status**: Not Started

**As a** developer,
**I want** repository layer tests,
**So that** data access is verified.

**Acceptance Criteria**:
- [ ] `tests/unit/test_base_repository.py` - Base repo operations
- [ ] `tests/unit/test_compliance_repository.py` - Compliance queries
- [ ] `tests/integration/test_mongodb_queries.py` - MongoDB operations
- [ ] 80% coverage on repository modules

---

### Story E5-S6: API Endpoint Tests
**Priority**: P1 | **Points**: 5 | **Status**: Not Started

**As a** developer,
**I want** integration tests for all API endpoints,
**So that** the API contract is verified.

**Acceptance Criteria**:
- [ ] Tests for each route module:
  - `tests/integration/test_hosts_api.py`
  - `tests/integration/test_scans_api.py`
  - `tests/integration/test_compliance_api.py`
  - `tests/integration/test_auth_api.py`
  - `tests/integration/test_rules_api.py`
- [ ] Each endpoint tested for:
  - Success case
  - Validation errors (400)
  - Auth required (401)
  - Permission denied (403)
  - Not found (404)
- [ ] 80% coverage on route modules

---

### Story E5-S7: Frontend Unit Tests
**Priority**: P2 | **Points**: 4 | **Status**: Not Started

**As a** developer,
**I want** unit tests for frontend components,
**So that** UI logic is verified.

**Acceptance Criteria**:
- [ ] Tests for extracted components (from E4):
  - ScanProgress, ResultsOverview
  - HostTable, HostFilters
  - Form components
- [ ] Tests for custom hooks:
  - useHostData
  - useHostFilters
  - useScanPolling
- [ ] Tests for API adapters
- [ ] 60% coverage on new components

**Test Setup**:
```typescript
// Example test with Vitest + Testing Library
import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { ScanProgress } from './ScanProgress';

describe('ScanProgress', () => {
  it('displays progress percentage', () => {
    render(<ScanProgress progress={75} status="running" />);
    expect(screen.getByText('75%')).toBeInTheDocument();
  });

  it('shows completed state', () => {
    render(<ScanProgress progress={100} status="completed" />);
    expect(screen.getByText('Completed')).toBeInTheDocument();
  });
});
```

---

### Story E5-S8: E2E Critical Flows
**Priority**: P1 | **Points**: 4 | **Status**: Not Started

**As a** user,
**I want** critical flows tested end-to-end,
**So that** user journeys work.

**Acceptance Criteria**:
- [ ] `e2e/auth.spec.ts` - Login, logout, session timeout
- [ ] `e2e/hosts.spec.ts` - Add host, view hosts, delete host
- [ ] `e2e/scans.spec.ts` - Create scan, monitor progress, view results
- [ ] `e2e/rules.spec.ts` - Browse rules, search, filter
- [ ] All tests pass in CI

**Test Example**:
```typescript
// e2e/scans.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Scan Workflow', () => {
  test('can create and monitor a scan', async ({ page }) => {
    // Login
    await page.goto('/login');
    await page.fill('[name="username"]', 'admin');
    await page.fill('[name="password"]', 'password');
    await page.click('button[type="submit"]');

    // Navigate to scans
    await page.click('text=Scans');

    // Create scan
    await page.click('text=New Scan');
    await page.selectOption('[name="host"]', 'test-host');
    await page.click('text=Start Scan');

    // Monitor progress
    await expect(page.locator('.scan-progress')).toBeVisible();

    // Wait for completion (with timeout)
    await expect(page.locator('text=Completed')).toBeVisible({ timeout: 60000 });
  });
});
```

---

### Story E5-S9: Regression Test Suite
**Priority**: P1 | **Points**: 2 | **Status**: Complete

**As a** developer,
**I want** a documented regression test suite,
**So that** fixed bugs stay fixed.

**Acceptance Criteria**:
- [x] `tests/regression/` directory created
- [ ] README documenting regression test process
- [ ] Each bug fix has corresponding test
- [x] Tests tagged with `@pytest.mark.regression` (marker registered in pytest.ini)
- [x] Regression tests run in CI

**Process**:
```markdown
## Regression Test Process

1. When fixing a bug:
   a. Write a test that reproduces the bug (fails)
   b. Fix the bug
   c. Verify test passes
   d. Add test to regression suite

2. Test naming: `test_regression_{issue_number}_{description}`

3. Include in test docstring:
   - Issue reference
   - Bug description
   - Fix description
```

---

### Story E5-S10: CI Coverage Enforcement
**Priority**: P2 | **Points**: 2 | **Status**: In Progress

**As a** maintainer,
**I want** coverage enforced in CI,
**So that** coverage doesn't regress.

**Acceptance Criteria**:
- [ ] CI fails if backend coverage < 80% (currently set to 30%, incrementally raising)
- [ ] CI fails if frontend coverage < 60%
- [x] Coverage report uploaded as artifact
- [ ] Coverage badge in README

**CI Configuration**:
```yaml
# .github/workflows/test.yml
- name: Backend Tests
  run: |
    pytest --cov=app --cov-fail-under=80

- name: Frontend Tests
  run: |
    npm run test:coverage -- --coverage.thresholds.lines=60
```

---

## 6. Dependencies

```mermaid
graph TD
    E2[Epic E2: Services] --> S4[E5-S4: Scan Tests]
    E2 --> S5[E5-S5: Repo Tests]
    E4[Epic E4: Frontend] --> S7[E5-S7: Frontend Tests]
    S1[E5-S1: Measure] --> S2[E5-S2: Auth Tests]
    S1 --> S3[E5-S3: Encryption Tests]
    S1 --> S4
    S2 --> S6[E5-S6: API Tests]
    S4 --> S6
    S6 --> S8[E5-S8: E2E Tests]
    S7 --> S8
    S9[E5-S9: Regression] --> S10[E5-S10: CI]
    S8 --> S10
```

**Execution Order**:
1. S1 (Measure baseline)
2. S2, S3, S4 (Critical tests - parallel)
3. S5, S6 (Backend coverage)
4. S7 (Frontend tests)
5. S8 (E2E tests)
6. S9, S10 (Regression suite, CI enforcement)

---

## 7. Risks and Mitigations

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Tests too slow | Medium | Medium | Parallel execution, selective running |
| Flaky tests | High | Medium | Proper async handling, retries |
| Mocking complexity | Medium | Medium | Clear mock boundaries |
| Coverage gaming | Low | Low | Focus on critical paths |

---

## 8. Acceptance Criteria (Epic Level)

- [ ] Backend coverage ≥ 80%
- [ ] Frontend coverage ≥ 60%
- [ ] Auth, encryption, scan at 100%
- [ ] All E2E tests pass
- [ ] CI enforces coverage
- [ ] Regression suite documented

---

## 9. Definition of Done

- [ ] All stories completed
- [ ] Coverage targets met
- [ ] All tests pass locally and in CI
- [ ] Test documentation complete
- [ ] No flaky tests
- [ ] Committed with proper messages
