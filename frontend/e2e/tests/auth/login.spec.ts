import { test, expect, TEST_USERS } from '../../fixtures/auth';
import { clearAppData } from '../../utils/test-helpers';

test.describe('Login Flow', () => {
  test.beforeEach(async ({ page, loginPage }) => {
    // Clear any existing auth data
    await clearAppData(page);
    await loginPage.goto();
  });

  test('should display login page correctly', async ({ loginPage }) => {
    // Check all elements are visible
    await expect(loginPage.page.locator('input[name="username"]')).toBeVisible();
    await expect(loginPage.page.locator('input[name="password"]')).toBeVisible();
    await expect(loginPage.page.locator('button:has-text("Login")')).toBeVisible();
    
    // Check branding
    await expect(loginPage.page.locator('text=OpenWatch')).toBeVisible();
    
    // Check links
    await expect(loginPage.page.locator('a:has-text("Forgot Password")')).toBeVisible();
    await expect(loginPage.page.locator('a:has-text("Register")')).toBeVisible();
  });

  test('should login successfully with valid credentials', async ({ loginPage, dashboardPage }) => {
    // Perform login
    await loginPage.login(TEST_USERS.admin.username, TEST_USERS.admin.password);
    
    // Verify successful login
    await expect(loginPage.isLoginSuccessful()).resolves.toBe(true);
    await expect(dashboardPage.isDashboardDisplayed()).resolves.toBe(true);
    
    // Verify auth token is stored
    const token = await loginPage.getAuthToken();
    expect(token).toBeTruthy();
    expect(token).toMatch(/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/); // JWT format
  });

  test('should show error with invalid credentials', async ({ loginPage }) => {
    // Attempt login with invalid credentials
    await loginPage.login(TEST_USERS.invalid.username, TEST_USERS.invalid.password);
    
    // Verify error is shown
    const errorMessage = await loginPage.getErrorMessage();
    expect(errorMessage).toBeTruthy();
    expect(errorMessage).toContain('Invalid username or password');
    
    // Verify still on login page
    await expect(loginPage.isLoginPageDisplayed()).resolves.toBe(true);
    
    // Verify no auth token
    const token = await loginPage.getAuthToken();
    expect(token).toBeNull();
  });

  test('should validate required fields', async ({ loginPage }) => {
    // Try to submit empty form
    await loginPage.submitLogin();
    
    // Check validation errors
    await expect(loginPage.hasValidationError('username')).resolves.toBe(true);
    await expect(loginPage.hasValidationError('password')).resolves.toBe(true);
    
    // Check error messages
    const usernameError = await loginPage.getValidationErrorMessage('username');
    const passwordError = await loginPage.getValidationErrorMessage('password');
    
    expect(usernameError).toContain('required');
    expect(passwordError).toContain('required');
  });

  test('should handle network errors gracefully', async ({ page, loginPage }) => {
    // Mock network failure
    await page.route('**/api/auth/login', route => route.abort('failed'));
    
    // Attempt login
    await loginPage.login(TEST_USERS.admin.username, TEST_USERS.admin.password);
    
    // Verify error message
    const errorMessage = await loginPage.getErrorMessage();
    expect(errorMessage).toBeTruthy();
    expect(errorMessage?.toLowerCase()).toMatch(/network|connection|error/);
  });

  test('should handle server errors gracefully', async ({ page, loginPage }) => {
    // Mock server error
    await page.route('**/api/auth/login', route => {
      route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'Internal server error' })
      });
    });
    
    // Attempt login
    await loginPage.login(TEST_USERS.admin.username, TEST_USERS.admin.password);
    
    // Verify error message
    const errorMessage = await loginPage.getErrorMessage();
    expect(errorMessage).toBeTruthy();
    expect(errorMessage).toContain('server error');
  });

  test('should redirect to login when accessing protected route without auth', async ({ page, loginPage }) => {
    // Try to access dashboard without auth
    await page.goto('/dashboard');
    
    // Should be redirected to login
    await page.waitForURL('**/login');
    await expect(loginPage.isLoginPageDisplayed()).resolves.toBe(true);
  });

  test('should preserve redirect URL after login', async ({ page, loginPage, dashboardPage }) => {
    // Try to access specific page
    await page.goto('/hosts');
    
    // Should be redirected to login
    await page.waitForURL('**/login?redirect=%2Fhosts');
    
    // Login
    await loginPage.login(TEST_USERS.admin.username, TEST_USERS.admin.password);
    
    // Should be redirected to originally requested page
    await page.waitForURL('**/hosts');
  });

  test('should handle session timeout', async ({ page, loginPage, dashboardPage }) => {
    // Login successfully
    await loginPage.login(TEST_USERS.admin.username, TEST_USERS.admin.password);
    await expect(dashboardPage.isDashboardDisplayed()).resolves.toBe(true);
    
    // Simulate expired token by clearing it
    await page.evaluate(() => {
      // Set an expired token
      const expiredToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjB9.4Adcj3UFYzPUVaVF43FmMab6RlaQD8A9V8wFzzht-KQ';
      localStorage.setItem('auth_token', expiredToken);
    });
    
    // Try to navigate
    await dashboardPage.navigateTo('hosts');
    
    // Should be redirected to login
    await page.waitForURL('**/login');
    await expect(loginPage.isLoginPageDisplayed()).resolves.toBe(true);
  });

  test('should handle concurrent login attempts', async ({ page, context }) => {
    // Create two pages
    const page1 = page;
    const page2 = await context.newPage();
    
    const loginPage1 = loginPage;
    const loginPage2 = new LoginPage(page2);
    
    // Navigate both to login
    await loginPage1.goto();
    await loginPage2.goto();
    
    // Login on both simultaneously
    await Promise.all([
      loginPage1.login(TEST_USERS.admin.username, TEST_USERS.admin.password),
      loginPage2.login(TEST_USERS.admin.username, TEST_USERS.admin.password)
    ]);
    
    // Both should succeed
    await expect(page1.url()).toContain('/dashboard');
    await expect(page2.url()).toContain('/dashboard');
    
    // Cleanup
    await page2.close();
  });
});