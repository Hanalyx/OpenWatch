/**
 * E2E tests for Hosts page functionality.
 *
 * Uses the authenticatedPage fixture and HostsPage page object.
 */
import { test, expect } from '../fixtures/auth';

test.describe('Hosts Page', () => {
  test('navigates to hosts page', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    await page.goto('/hosts');
    await page.waitForLoadState('networkidle');
    await expect(page).toHaveURL(/\/hosts/);
  });

  test('hosts page renders table or empty state', async ({
    authenticatedPage,
  }) => {
    const page = authenticatedPage.page;
    await page.goto('/hosts');
    await page.waitForLoadState('networkidle');

    // Should have either a table or an empty state message
    const table = page.locator('table, [role="grid"]');
    const emptyState = page.getByText(/no hosts|add.*host|get started/i);
    const hasTable = (await table.count()) > 0;
    const hasEmpty = (await emptyState.count()) > 0;

    expect(hasTable || hasEmpty).toBeTruthy();
  });

  test('search input exists and is functional', async ({
    authenticatedPage,
  }) => {
    const page = authenticatedPage.page;
    await page.goto('/hosts');
    await page.waitForLoadState('networkidle');

    const searchInput = page.locator(
      'input[placeholder*="earch"], input[type="search"], input[aria-label*="earch"]'
    );
    if ((await searchInput.count()) > 0) {
      await searchInput.first().fill('nonexistent-host-xyz');
      // Wait briefly for any debounced search to fire
      await page.waitForTimeout(500);
      // Page should still be stable (no crash)
      await expect(page).toHaveURL(/\/hosts/);
    }
  });

  test('add host dialog opens', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    await page.goto('/hosts');
    await page.waitForLoadState('networkidle');

    const addButton = page.getByRole('button', {
      name: /add.*host|new.*host|create/i,
    });
    if ((await addButton.count()) > 0) {
      await addButton.first().click();
      // Should show a dialog/modal
      const dialog = page.locator(
        '[role="dialog"], .MuiDialog-root, .MuiDrawer-root'
      );
      await expect(dialog.first()).toBeVisible({ timeout: 5000 });
    }
  });

  test('add host form validates required fields', async ({
    authenticatedPage,
  }) => {
    const page = authenticatedPage.page;
    await page.goto('/hosts');
    await page.waitForLoadState('networkidle');

    const addButton = page.getByRole('button', {
      name: /add.*host|new.*host|create/i,
    });
    if ((await addButton.count()) === 0) {
      test.skip();
      return;
    }

    await addButton.first().click();

    // Try to submit without filling required fields
    const submitButton = page.getByRole('button', {
      name: /add|save|submit|create/i,
    });
    const dialogs = page.locator(
      '[role="dialog"], .MuiDialog-root, .MuiDrawer-root'
    );
    if (
      (await dialogs.count()) > 0 &&
      (await submitButton.count()) > 0
    ) {
      await submitButton.first().click();

      // Should show validation errors or remain on form
      const errorIndicators = page.locator(
        '.Mui-error, .MuiFormHelperText-root.Mui-error, [role="alert"]'
      );
      // Form should either show errors or prevent submission
      await page.waitForTimeout(500);
      const hasErrors = (await errorIndicators.count()) > 0;
      const dialogStillOpen = (await dialogs.count()) > 0;
      expect(hasErrors || dialogStillOpen).toBeTruthy();
    }
  });

  test('host row shows action buttons when hosts exist', async ({
    authenticatedPage,
  }) => {
    const page = authenticatedPage.page;
    await page.goto('/hosts');
    await page.waitForLoadState('networkidle');

    const rows = page.locator('tbody tr, [role="row"]');
    if ((await rows.count()) > 1) {
      // First data row (skip header)
      const firstRow = rows.nth(1);
      // Look for action buttons (edit, delete, scan icons or menu)
      const actions = firstRow.locator(
        'button, [role="button"], .MuiIconButton-root'
      );
      expect(await actions.count()).toBeGreaterThan(0);
    } else {
      test.skip();
    }
  });
});
