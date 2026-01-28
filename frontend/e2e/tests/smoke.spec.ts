import { test, expect } from '@playwright/test';

/**
 * Smoke tests verify the application loads and core UI elements render.
 * These are the most basic E2E tests - if these fail, nothing else works.
 */
test.describe('Smoke Tests', () => {
  test('application loads without errors', async ({ page }) => {
    const response = await page.goto('/');

    // Page should return a successful HTTP status
    expect(response?.status()).toBeLessThan(400);
  });

  test('login page renders with form elements', async ({ page }) => {
    await page.goto('/login');

    // Login form should have username and password inputs
    await expect(page.locator('input[name="username"]')).toBeVisible();
    await expect(page.locator('input[name="password"]')).toBeVisible();

    // Login button should be present
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test('unauthenticated users are redirected to login', async ({ page }) => {
    // Attempting to access a protected route should redirect to login
    await page.goto('/dashboard');

    // Should end up on login page (URL contains /login)
    await expect(page).toHaveURL(/\/login/);
  });

  test('page has correct title', async ({ page }) => {
    await page.goto('/');

    // Page should have a non-empty title
    const title = await page.title();
    expect(title.length).toBeGreaterThan(0);
  });

  test('no console errors on initial load', async ({ page }) => {
    const consoleErrors: string[] = [];

    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    await page.goto('/login');

    // Wait for the page to settle
    await page.waitForLoadState('networkidle');

    // Filter out known benign errors (e.g., favicon 404)
    const criticalErrors = consoleErrors.filter(
      (err) => !err.includes('favicon') && !err.includes('404')
    );

    expect(criticalErrors).toHaveLength(0);
  });
});
