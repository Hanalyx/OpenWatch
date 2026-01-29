import { test, expect } from '../fixtures/auth';
import { TEST_USERS } from '../fixtures/auth';

/**
 * Authentication flow tests verify login, logout, and access control.
 * These tests exercise the core auth pipeline end-to-end.
 */
test.describe('Authentication Flow', () => {
  test('successful login navigates to dashboard', async ({ loginPage }) => {
    await loginPage.goto();

    await loginPage.login(TEST_USERS.admin.username, TEST_USERS.admin.password);

    const success = await loginPage.isLoginSuccessful();
    expect(success).toBe(true);
  });

  test('failed login shows error message', async ({ loginPage }) => {
    await loginPage.goto();

    await loginPage.login(TEST_USERS.invalid.username, TEST_USERS.invalid.password);

    const errorMessage = await loginPage.getErrorMessage();
    expect(errorMessage).not.toBeNull();
  });

  test('login form validates empty fields', async ({ loginPage, page }) => {
    await loginPage.goto();

    // Try to submit without filling in fields
    await loginPage.submitLogin();

    // Should still be on login page
    await expect(page).toHaveURL(/\/login/);
  });

  test('logout returns to login page', async ({ authenticatedPage, page }) => {
    // authenticatedPage fixture handles login
    const dashboardPage = (await import('../fixtures/page-objects/DashboardPage')).DashboardPage;
    const dashboard = new dashboardPage(page);

    await dashboard.logout();

    // Should be redirected to login
    await expect(page).toHaveURL(/\/login/);
  });

  test('auth token is stored in localStorage after login', async ({ loginPage, page }) => {
    await loginPage.goto();
    await loginPage.login(TEST_USERS.admin.username, TEST_USERS.admin.password);

    const success = await loginPage.isLoginSuccessful();
    if (success) {
      const token = await page.evaluate(() => localStorage.getItem('auth_token'));
      expect(token).not.toBeNull();
      expect(token!.length).toBeGreaterThan(0);
    }
  });

  test('auth token is cleared on logout', async ({ authenticatedPage, page }) => {
    const dashboardPage = (await import('../fixtures/page-objects/DashboardPage')).DashboardPage;
    const dashboard = new dashboardPage(page);

    // Verify token exists before logout
    const tokenBefore = await page.evaluate(() => localStorage.getItem('auth_token'));
    expect(tokenBefore).not.toBeNull();

    await dashboard.logout();

    // Token should be cleared after logout
    const tokenAfter = await page.evaluate(() => localStorage.getItem('auth_token'));
    expect(tokenAfter).toBeNull();
  });
});
