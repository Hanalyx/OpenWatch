import { test, expect } from '../fixtures/auth';
import { DashboardPage } from '../fixtures/page-objects/DashboardPage';

/**
 * Navigation tests verify that main menu items load correctly
 * and protected routes are accessible after authentication.
 *
 * Uses authenticatedPage fixture which handles login before each test.
 * Dashboard is at '/' (root), not '/dashboard'.
 */
test.describe('Navigation', () => {
  test('dashboard page loads after login', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    const dashboard = new DashboardPage(page);
    // Dashboard is at root path /
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    const isDisplayed = await dashboard.isDashboardDisplayed();
    expect(isDisplayed).toBe(true);
  });

  test('hosts page loads from navigation', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    const dashboard = new DashboardPage(page);
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await dashboard.navigateTo('hosts');

    // Should navigate to hosts page
    await expect(page).toHaveURL(/\/hosts/);

    // Page should have loaded (no error state)
    const response = await page.evaluate(() => document.readyState);
    expect(response).toBe('complete');
  });

  test('scans page loads from navigation', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    const dashboard = new DashboardPage(page);
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await dashboard.navigateTo('scans');

    await expect(page).toHaveURL(/\/scans/);
  });

  test('SCAP content page loads from navigation', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    const dashboard = new DashboardPage(page);
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await dashboard.navigateTo('content');

    await expect(page).toHaveURL(/\/content/);
  });

  test('settings page loads from navigation', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    const dashboard = new DashboardPage(page);
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await dashboard.navigateTo('settings');

    await expect(page).toHaveURL(/\/settings/);
  });

  test('browser back button works correctly', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    const dashboard = new DashboardPage(page);

    // Start at dashboard (root)
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Navigate to hosts
    await dashboard.navigateTo('hosts');
    await expect(page).toHaveURL(/\/hosts/);

    // Go back
    await page.goBack();

    // Should be back on root (dashboard)
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL(/^https?:\/\/[^/]+\/?$/);
  });
});
