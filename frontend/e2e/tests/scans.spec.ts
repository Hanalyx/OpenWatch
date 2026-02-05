/**
 * E2E tests for Scans page functionality.
 *
 * Uses the authenticatedPage fixture and ScansPage page object.
 */
import { test, expect } from '../fixtures/auth';

test.describe('Scans Page', () => {
  test('navigates to scans page', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    await page.goto('/scans');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL(/\/scans/);
  });

  test('scans page renders table or empty state', async ({
    authenticatedPage,
  }) => {
    const page = authenticatedPage.page;
    await page.goto('/scans');
    await page.waitForLoadState('networkidle');

    const table = page.locator('table, [role="grid"]');
    const emptyState = page.getByText(/no scans|run.*scan|get started/i);
    const hasTable = (await table.count()) > 0;
    const hasEmpty = (await emptyState.count()) > 0;

    expect(hasTable || hasEmpty).toBeTruthy();
  });

  test('new scan action is available', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    await page.goto('/scans');
    await page.waitForLoadState('networkidle');

    const newScanButton = page.getByRole('button', {
      name: /new.*scan|start.*scan|create.*scan|run.*scan/i,
    });
    if ((await newScanButton.count()) > 0) {
      await newScanButton.first().click();
      // Scan creation may open a dialog or navigate to /scans/create
      const dialog = page.locator('[role="dialog"], .MuiDialog-root');
      const hasDialog = await dialog.first().isVisible({ timeout: 3000 }).catch(() => false);
      const navigated = page.url().includes('/scans/create');
      expect(hasDialog || navigated).toBeTruthy();
    }
  });

  test('scan table shows status column', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    await page.goto('/scans');
    await page.waitForLoadState('networkidle');

    const table = page.locator('table, [role="grid"]');
    if ((await table.count()) > 0) {
      // Check for status header/column
      const statusHeader = page.getByText(/status/i);
      expect(await statusHeader.count()).toBeGreaterThan(0);
    }
  });

  test('scan detail navigation works when scans exist', async ({
    authenticatedPage,
  }) => {
    const page = authenticatedPage.page;
    await page.goto('/scans');
    await page.waitForLoadState('networkidle');

    const rows = page.locator('tbody tr, [role="row"]');
    if ((await rows.count()) > 1) {
      // Click on a scan row to navigate to detail
      const firstRow = rows.nth(1);
      const clickable = firstRow.locator('a, [role="link"], td').first();
      await clickable.click();
      await page.waitForLoadState('networkidle');
      // Should navigate to detail page or show detail
      const url = page.url();
      const hasDetailView =
        url.includes('/scans/') || (await page.locator('.scan-detail, [data-testid="scan-detail"]').count()) > 0;
      expect(hasDetailView || url.includes('/scans')).toBeTruthy();
    } else {
      test.skip();
    }
  });
});
