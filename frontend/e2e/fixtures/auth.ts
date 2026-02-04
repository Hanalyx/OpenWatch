import { test as base } from '@playwright/test';
import { LoginPage } from './page-objects/LoginPage';
import { DashboardPage } from './page-objects/DashboardPage';

// Test user credentials
export const TEST_USERS = {
  admin: {
    username: 'admin@openwatch.local',
    password: 'Admin123!@#',
    role: 'admin'
  },
  user: {
    username: 'user@openwatch.local', 
    password: 'User123!@#',
    role: 'user'
  },
  readOnly: {
    username: 'readonly@openwatch.local',
    password: 'ReadOnly123!@#',
    role: 'read_only'
  },
  invalid: {
    username: 'invalid@openwatch.local',
    password: 'wrongpassword',
    role: 'none'
  }
};

// Extend basic test with authentication fixtures
export const test = base.extend<{
  loginPage: LoginPage;
  dashboardPage: DashboardPage;
  authenticatedPage: LoginPage;
}>({
  // Page object fixtures
  loginPage: async ({ page }, use) => {
    const loginPage = new LoginPage(page);
    await use(loginPage);
  },

  dashboardPage: async ({ page }, use) => {
    const dashboardPage = new DashboardPage(page);
    await use(dashboardPage);
  },

  // Pre-authenticated page fixture
  authenticatedPage: async ({ page }, use) => {
    const loginPage = new LoginPage(page);

    // Perform login before test
    await loginPage.goto();
    await loginPage.login(TEST_USERS.admin.username, TEST_USERS.admin.password);

    // Wait for navigation to complete with extended timeout
    const loginSuccessful = await loginPage.isLoginSuccessful();

    if (!loginSuccessful) {
      // Check if there's an error message
      const errorMsg = await loginPage.getErrorMessage();
      console.error(`Login failed. Error: ${errorMsg || 'Unknown error'}`);
      console.error('This may indicate test user was not created in CI setup.');
      // Still allow test to continue - it will fail with clear assertion
    }

    await use(loginPage);

    // Cleanup: logout after test (only if logged in)
    if (loginSuccessful) {
      try {
        const dashboardPage = new DashboardPage(page);
        await dashboardPage.logout();
      } catch {
        // Ignore logout errors in cleanup
      }
    }
  }
});

export { expect } from '@playwright/test';

/**
 * Helper function to create authenticated context
 */
export async function createAuthenticatedContext(browser: any, user = TEST_USERS.admin) {
  const context = await browser.newContext();
  const page = await context.newPage();
  
  const loginPage = new LoginPage(page);
  await loginPage.goto();
  await loginPage.login(user.username, user.password);
  
  // Wait for dashboard to ensure login is complete
  const dashboardPage = new DashboardPage(page);
  await dashboardPage.isDashboardDisplayed();
  
  // Get auth token
  const authToken = await page.evaluate(() => localStorage.getItem('auth_token'));
  
  // Store auth state
  await context.storageState({ path: `auth-${user.role}.json` });
  
  return { context, page, authToken };
}

/**
 * Helper to setup test data via API
 */
export async function setupTestData(authToken: string) {
  // This would make API calls to set up test data
  // For now, it's a placeholder
  const apiUrl = process.env.API_URL || 'http://localhost:8000';
  
  // Example: Create test host
  const response = await fetch(`${apiUrl}/api/hosts`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${authToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      hostname: 'test-host-' + Date.now(),
      ip_address: '192.168.1.100',
      os_type: 'linux',
      ssh_port: 22
    })
  });
  
  return response.ok;
}