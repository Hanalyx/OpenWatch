import { test, expect } from '../fixtures/auth';
import { DashboardPage } from '../fixtures/page-objects/DashboardPage';

/**
 * Navigation tests verify that main menu items load correctly
 * and protected routes are accessible after authentication.
 */
test.describe('Navigation', () => {
  test.beforeEach(async ({ authenticatedPage }) => {
    // authenticatedPage fixture handles login automatically
  });

  test('dashboard page loads after login', async ({ page }) => {
    const dashboard = new DashboardPage(page);
    const isDisplayed = await dashboard.isDashboardDisplayed();
    expect(isDisplayed).toBe(true);
  });

  test('hosts page loads from navigation', async ({ page }) => {
    const dashboard = new DashboardPage(page);
    await dashboard.navigateTo('hosts');

    // Should navigate to hosts page
    await expect(page).toHaveURL(/\/hosts/);

    // Page should have loaded (no error state)
    const response = await page.evaluate(() => document.readyState);
    expect(response).toBe('complete');
  });

  test('scans page loads from navigation', async ({ page }) => {
    const dashboard = new DashboardPage(page);
    await dashboard.navigateTo('scans');

    await expect(page).toHaveURL(/\/scans/);
  });

  test('SCAP content page loads from navigation', async ({ page }) => {
    const dashboard = new DashboardPage(page);
    await dashboard.navigateTo('content');

    await expect(page).toHaveURL(/\/scap-content/);
  });

  test('settings page loads from navigation', async ({ page }) => {
    const dashboard = new DashboardPage(page);
    await dashboard.navigateTo('settings');

    await expect(page).toHaveURL(/\/settings/);
  });

  test('browser back button works correctly', async ({ page }) => {
    const dashboard = new DashboardPage(page);

    // Navigate to hosts
    await dashboard.navigateTo('hosts');
    await expect(page).toHaveURL(/\/hosts/);

    // Go back
    await page.goBack();

    // Should be back on dashboard
    await expect(page).toHaveURL(/\/dashboard/);
  });
});
