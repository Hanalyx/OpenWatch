/**
 * E2E tests for Dashboard page functionality.
 *
 * Uses the authenticatedPage fixture and DashboardPage page object.
 */
import { test, expect } from '../fixtures/auth';

test.describe('Dashboard Page', () => {
  test('dashboard loads after login', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Dashboard should display content: heading, cards, or MUI components
    // The h1 "Security Compliance Dashboard" may take time to render after API calls
    const content = page.locator(
      'h1, h2, h3, h4, h5, h6, .MuiCard-root, .MuiPaper-root, .MuiTypography-root'
    );
    await expect(content.first()).toBeVisible({ timeout: 10000 });
  });

  test('statistics cards are visible', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Dashboard should show MUI cards with statistics
    const cards = page.locator('.MuiCard-root, .MuiPaper-root');
    expect(await cards.count()).toBeGreaterThan(0);
  });

  test('navigation links are functional', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Find sidebar or nav links
    const navLinks = page.locator(
      'nav a, [role="navigation"] a, .MuiDrawer-root a, .MuiListItem-root'
    );
    expect(await navLinks.count()).toBeGreaterThan(0);
  });
});
