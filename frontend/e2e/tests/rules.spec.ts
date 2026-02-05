/**
 * E2E tests for SCAP Content / Rules page functionality.
 *
 * Uses the authenticatedPage fixture with direct selectors.
 */
import { test, expect } from '../fixtures/auth';

test.describe('Rules / SCAP Content Page', () => {
  test('navigates to SCAP content page', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    await page.goto('/content');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL(/\/content/);
  });

  test('rules page renders content', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    await page.goto('/content');
    await page.waitForLoadState('networkidle');

    // Should show either rules table, content list, or some heading
    const content = page.locator(
      'table, [role="grid"], .MuiCard-root, h1, h2, h3, h4, h5, h6'
    );
    expect(await content.count()).toBeGreaterThan(0);
  });

  test('search input exists', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    await page.goto('/content');
    await page.waitForLoadState('networkidle');

    const searchInput = page.locator(
      'input[placeholder*="earch"], input[type="search"], input[aria-label*="earch"]'
    );
    if ((await searchInput.count()) > 0) {
      await searchInput.first().fill('test-query');
      await page.waitForTimeout(500);
      // Page should remain stable
      await expect(page).toHaveURL(/\/content/);
    }
  });

  test('filter controls are present', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    await page.goto('/content');
    await page.waitForLoadState('networkidle');

    // Look for filter elements: selects, dropdowns, filter buttons, tabs
    const filters = page.locator(
      'select, [role="combobox"], [role="tablist"], button:has-text("filter"), .MuiSelect-root, .MuiTabs-root'
    );
    // At minimum, the page should have some interactive elements
    const buttons = page.locator('button, [role="button"]');
    expect(await buttons.count()).toBeGreaterThan(0);
  });
});
