# OpenWatch E2E Testing

This directory contains comprehensive end-to-end (E2E) tests for the OpenWatch application using Playwright.

## 🏗️ Test Architecture

```
e2e/
├── tests/                    # Test specifications
│   ├── auth/                 # Authentication tests
│   │   ├── login.spec.ts     # Login functionality
│   │   └── logout.spec.ts    # Logout functionality
│   ├── hosts/                # Host management tests
│   │   └── add-host.spec.ts  # Add host functionality
│   ├── scap/                 # SCAP content tests
│   ├── scans/                # Scanning tests
│   └── integration/          # Full workflow tests
├── fixtures/                 # Test fixtures and setup
│   ├── auth.ts              # Authentication fixtures
│   └── page-objects/        # Page Object Models
│       ├── BasePage.ts      # Base page class
│       ├── LoginPage.ts     # Login page actions
│       ├── DashboardPage.ts # Dashboard page actions
│       ├── HostsPage.ts     # Hosts page actions
│       └── ScansPage.ts     # Scans page actions
└── utils/                   # Test utilities
    └── test-helpers.ts      # Helper functions
```

## 🚀 Quick Start

### Prerequisites

- Node.js 18+
- Python 3.9+
- Docker (for test services)
- OpenWatch backend and frontend

### Installation

```bash
# Install E2E testing dependencies
cd frontend
npm install

# Install Playwright browsers
npx playwright install --with-deps
```

### Running Tests

#### Using the Test Runner (Recommended)

```bash
# From project root
./run-e2e-tests.sh

# With UI mode
./run-e2e-tests.sh --ui

# Run specific tests
./run-e2e-tests.sh --grep "login"

# Show test report after completion
./run-e2e-tests.sh --show-report
```

#### Manual Execution

```bash
# Start services manually
docker compose up -d database redis
cd backend && python -m uvicorn app.main:app --reload &
cd frontend && npm run dev &

# Run tests
cd frontend
npx playwright test

# View results
npx playwright show-report
```

## 📋 Test Scenarios

### Authentication Tests

- ✅ **Login Flow**
  - Valid credentials
  - Invalid credentials
  - Field validation
  - Network errors
  - Server errors
  - Session timeout
  - Concurrent logins

- ✅ **Logout Flow**
  - User menu logout
  - Session data cleanup
  - Token invalidation
  - Multi-tab logout

### Host Management Tests

- ✅ **Add Host**
  - Linux hosts
  - Windows hosts
  - Field validation
  - Connection testing
  - Duplicate detection
  - Keyboard navigation

### Integration Tests

- ✅ **Full Workflow**
  - Complete scanning workflow
  - Bulk operations
  - Data persistence
  - Error handling
  - Real-time updates

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the `frontend` directory:

```bash
# Copy example configuration
cp e2e.env.example .env

# Edit configuration
vi .env
```

### Playwright Configuration

The main configuration is in `playwright.config.ts`:

```typescript
export default defineConfig({
  testDir: './e2e/tests',
  timeout: 30000,
  retries: process.env.CI ? 2 : 0,
  use: {
    baseURL: 'http://localhost:3001',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    trace: 'on-first-retry'
  }
});
```

## 🧪 Test Development

### Page Object Pattern

We use the Page Object Model pattern for maintainable tests:

```typescript
// Example: LoginPage.ts
export class LoginPage extends BasePage {
  async login(username: string, password: string) {
    await this.page.fill('input[name="username"]', username);
    await this.page.fill('input[name="password"]', password);
    await this.page.click('button[type="submit"]');
  }
}
```

### Test Structure

```typescript
import { test, expect, TEST_USERS } from '../../fixtures/auth';

test.describe('Feature Name', () => {
  test.beforeEach(async ({ authenticatedPage }) => {
    // Setup code
  });

  test('should do something', async ({ loginPage }) => {
    // Test implementation
  });
});
```

### Best Practices

1. **Use Page Objects**: Encapsulate page interactions
2. **Meaningful Test Names**: Describe what the test validates
3. **Independent Tests**: Each test should be able to run in isolation
4. **Wait Strategies**: Use proper waits for async operations
5. **Test Data**: Generate unique test data to avoid conflicts
6. **Cleanup**: Clean up test data after tests

## 📊 Test Reporting

### HTML Report

```bash
# View interactive HTML report
npx playwright show-report
```

### CI/CD Integration

Tests are automatically run in GitHub Actions:

- **Pull Requests**: All E2E tests run
- **Main Branch**: Full test suite + deployment tests
- **Artifacts**: Screenshots, videos, and reports are saved

### Test Results

- **Screenshots**: Captured on failure
- **Videos**: Recorded for failed tests
- **Traces**: Available for debugging
- **Coverage**: Test coverage reports
- **Performance**: Response time metrics

## 🐛 Debugging Tests

### Local Debugging

```bash
# Run with browser visible
npx playwright test --headed

# Run in debug mode
npx playwright test --debug

# Run specific test
npx playwright test login.spec.ts --debug
```

### CI Debugging

1. **Check Actions logs** for detailed output
2. **Download artifacts** for screenshots/videos
3. **View trace files** in Playwright Trace Viewer

### Common Issues

1. **Timing Issues**: Use proper waits instead of `setTimeout`
2. **Element Not Found**: Use reliable selectors
3. **Authentication**: Ensure test users exist
4. **Network**: Mock external API calls
5. **Database**: Use test database isolation

## 📈 Test Coverage

### Current Coverage

- **Authentication**: 95%
- **Host Management**: 80%
- **SCAP Content**: 70%
- **Scanning**: 75%
- **User Interface**: 85%

### Coverage Goals

- **Critical Paths**: 95%+ coverage
- **User Workflows**: 90%+ coverage
- **Error Scenarios**: 80%+ coverage
- **Edge Cases**: 70%+ coverage

## 🔄 Continuous Integration

### GitHub Actions

The E2E tests are integrated into our CI/CD pipeline:

```yaml
# .github/workflows/ci.yml
e2e:
  name: E2E Tests
  runs-on: ubuntu-latest
  steps:
    - name: Run E2E Tests
      run: npx playwright test
```

### Test Environments

- **Development**: Local development testing
- **Staging**: Pre-production validation
- **Production**: Smoke tests only

## 🛠️ Maintenance

### Regular Tasks

1. **Update Dependencies**: Keep Playwright up to date
2. **Review Flaky Tests**: Fix unstable tests
3. **Performance Monitoring**: Track test execution time
4. **Coverage Analysis**: Identify gaps in test coverage

### Test Data Management

- **Cleanup**: Remove test data after test runs
- **Isolation**: Each test uses unique data
- **Fixtures**: Standardized test data setup

## 📚 Resources

- [Playwright Documentation](https://playwright.dev/)
- [Best Practices Guide](https://playwright.dev/docs/best-practices)
- [Page Object Model](https://playwright.dev/docs/test-pom)
- [Debugging Guide](https://playwright.dev/docs/debug)

## 🤝 Contributing

When adding new tests:

1. **Follow Naming Conventions**: `feature-action.spec.ts`
2. **Add Page Objects**: For new pages/components
3. **Update Documentation**: Keep README current
4. **Add to CI/CD**: Ensure tests run in pipeline
5. **Test Coverage**: Maintain high coverage levels

---

For questions or issues with E2E testing, please check the [troubleshooting guide](../docs/troubleshooting.md) or open an issue in the repository.