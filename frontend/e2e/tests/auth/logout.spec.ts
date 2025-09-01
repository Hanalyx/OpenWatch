import { test, expect, TEST_USERS } from '../../fixtures/auth';

test.describe('Logout Flow', () => {
  test.beforeEach(async ({ loginPage, dashboardPage }) => {
    // Login before each test
    await loginPage.goto();
    await loginPage.login(TEST_USERS.admin.username, TEST_USERS.admin.password);
    await expect(dashboardPage.isDashboardDisplayed()).resolves.toBe(true);
  });

  test('should logout successfully from user menu', async ({ page, dashboardPage, loginPage }) => {
    // Verify we're logged in
    const tokenBefore = await loginPage.getAuthToken();
    expect(tokenBefore).toBeTruthy();
    
    // Perform logout
    await dashboardPage.logout();
    
    // Verify redirected to login
    await page.waitForURL('**/login');
    await expect(loginPage.isLoginPageDisplayed()).resolves.toBe(true);
    
    // Verify auth token is cleared
    const tokenAfter = await loginPage.getAuthToken();
    expect(tokenAfter).toBeNull();
  });

  test('should clear all session data on logout', async ({ page, dashboardPage, loginPage }) => {
    // Set some session data
    await page.evaluate(() => {
      localStorage.setItem('user_preferences', JSON.stringify({ theme: 'dark' }));
      sessionStorage.setItem('temp_data', 'test');
    });
    
    // Logout
    await dashboardPage.logout();
    
    // Verify all data is cleared
    const localStorage = await page.evaluate(() => Object.keys(localStorage));
    const sessionStorage = await page.evaluate(() => Object.keys(sessionStorage));
    
    expect(localStorage).toHaveLength(0);
    expect(sessionStorage).toHaveLength(0);
  });

  test('should prevent access to protected routes after logout', async ({ page, dashboardPage, loginPage }) => {
    // Logout
    await dashboardPage.logout();
    
    // Try to access protected routes
    const protectedRoutes = ['/dashboard', '/hosts', '/scans', '/settings'];
    
    for (const route of protectedRoutes) {
      await page.goto(route);
      await page.waitForURL('**/login');
      await expect(loginPage.isLoginPageDisplayed()).resolves.toBe(true);
    }
  });

  test('should handle logout API errors gracefully', async ({ page, dashboardPage, loginPage }) => {
    // Mock logout API failure
    await page.route('**/api/auth/logout', route => {
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'Logout failed' })
      });
    });
    
    // Attempt logout
    await dashboardPage.logout();
    
    // Should still redirect to login and clear token
    await page.waitForURL('**/login');
    const token = await loginPage.getAuthToken();
    expect(token).toBeNull();
  });

  test('should invalidate token on server after logout', async ({ page, dashboardPage, loginPage }) => {
    // Get current token
    const token = await loginPage.getAuthToken();
    expect(token).toBeTruthy();
    
    // Logout
    await dashboardPage.logout();
    
    // Try to use the old token
    const response = await page.request.get('/api/users/me', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    // Should be unauthorized
    expect(response.status()).toBe(401);
  });

  test('should handle concurrent logout from multiple tabs', async ({ context, page, dashboardPage, loginPage }) => {
    // Create second tab
    const page2 = await context.newPage();
    const dashboardPage2 = new DashboardPage(page2);
    
    // Navigate to dashboard in second tab
    await page2.goto('/dashboard');
    await expect(dashboardPage2.isDashboardDisplayed()).resolves.toBe(true);
    
    // Logout from first tab
    await dashboardPage.logout();
    
    // Second tab should detect logout and redirect
    await page2.reload();
    await page2.waitForURL('**/login');
    
    // Cleanup
    await page2.close();
  });

  test('should show confirmation dialog before logout', async ({ page, dashboardPage }) => {
    // Mock confirmation dialog
    page.on('dialog', dialog => {
      expect(dialog.type()).toBe('confirm');
      expect(dialog.message()).toContain('Are you sure you want to logout?');
      dialog.accept();
    });
    
    // Open user menu
    await dashboardPage.openUserMenu();
    
    // Click logout (assuming it shows confirmation)
    const logoutButton = page.locator('button:has-text("Logout")');
    await logoutButton.click();
  });

  test('should cleanup background tasks on logout', async ({ page, dashboardPage }) => {
    // Start a mock background task (e.g., polling)
    await page.evaluate(() => {
      window.pollingInterval = setInterval(() => {
        console.log('Polling...');
      }, 1000);
    });
    
    // Logout
    await dashboardPage.logout();
    
    // Verify interval is cleared
    const intervalCleared = await page.evaluate(() => {
      return window.pollingInterval === undefined;
    });
    
    expect(intervalCleared).toBe(true);
  });
});