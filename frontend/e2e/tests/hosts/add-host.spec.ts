import { test, expect, TEST_USERS } from '../../fixtures/auth';
import { HostsPage } from '../../fixtures/page-objects/HostsPage';
import { generateTestData } from '../../utils/test-helpers';

test.describe('Add Host', () => {
  test.beforeEach(async ({ authenticatedPage }) => {
    const hostsPage = new HostsPage(authenticatedPage.page);
    await hostsPage.goto();
  });

  test('should add a new Linux host successfully', async ({ authenticatedPage }) => {
    const hostsPage = new HostsPage(authenticatedPage.page);
    
    const hostData = {
      hostname: generateTestData.hostname(),
      ipAddress: generateTestData.ipAddress(),
      username: 'testuser',
      password: 'TestPass123!',
      port: 22,
      osType: 'linux'
    };
    
    await hostsPage.addHost(hostData);
    
    // Verify host appears in table
    await expect(hostsPage.hasHost(hostData.hostname)).resolves.toBe(true);
    
    // Verify host count increased
    const hostCount = await hostsPage.getHostCount();
    expect(hostCount).toBeGreaterThan(0);
  });

  test('should add a new Windows host successfully', async ({ authenticatedPage }) => {
    const hostsPage = new HostsPage(authenticatedPage.page);
    
    const hostData = {
      hostname: generateTestData.hostname(),
      ipAddress: generateTestData.ipAddress(),
      username: 'administrator',
      password: 'AdminPass123!',
      port: 5985, // WinRM port
      osType: 'windows'
    };
    
    await hostsPage.addHost(hostData);
    await expect(hostsPage.hasHost(hostData.hostname)).resolves.toBe(true);
  });

  test('should validate required fields', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    const hostsPage = new HostsPage(page);
    
    // Open add host dialog
    await page.click('button:has-text("Add Host")');
    await page.waitForSelector('[role="dialog"]');
    
    // Try to submit without filling required fields
    await page.click('button:has-text("Add")');
    
    // Check for validation errors
    await expect(page.locator('.MuiFormHelperText-root.Mui-error')).toHaveCount(4); // hostname, ip, username, password
    
    // Verify error messages
    await expect(page.locator('text=Hostname is required')).toBeVisible();
    await expect(page.locator('text=IP address is required')).toBeVisible();
    await expect(page.locator('text=Username is required')).toBeVisible();
    await expect(page.locator('text=Password is required')).toBeVisible();
  });

  test('should validate IP address format', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    
    await page.click('button:has-text("Add Host")');
    await page.waitForSelector('[role="dialog"]');
    
    // Enter invalid IP addresses
    const invalidIPs = ['256.1.1.1', '1.1.1', 'invalid-ip', '1.1.1.-1'];
    
    for (const invalidIP of invalidIPs) {
      await page.fill('input[name="ip_address"]', invalidIP);
      await page.click('button:has-text("Add")');
      
      await expect(page.locator('text=Please enter a valid IP address')).toBeVisible();
      
      // Clear field for next test
      await page.fill('input[name="ip_address"]', '');
    }
  });

  test('should validate port range', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    
    await page.click('button:has-text("Add Host")');
    await page.waitForSelector('[role="dialog"]');
    
    // Test invalid ports
    const invalidPorts = ['0', '65536', '99999', '-1', 'abc'];
    
    for (const invalidPort of invalidPorts) {
      await page.fill('input[name="ssh_port"]', invalidPort);
      await page.click('button:has-text("Add")');
      
      await expect(page.locator('text=Port must be between 1 and 65535')).toBeVisible();
      await page.fill('input[name="ssh_port"]', '');
    }
  });

  test('should handle duplicate hostnames', async ({ authenticatedPage }) => {
    const hostsPage = new HostsPage(authenticatedPage.page);
    
    const hostData = {
      hostname: `duplicate-host-${Date.now()}`,
      ipAddress: generateTestData.ipAddress(),
      username: 'testuser',
      password: 'TestPass123!',
      port: 22,
      osType: 'linux'
    };
    
    // Add first host
    await hostsPage.addHost(hostData);
    
    // Try to add duplicate
    const page = authenticatedPage.page;
    await page.click('button:has-text("Add Host")');
    await page.waitForSelector('[role="dialog"]');
    
    await page.fill('input[name="hostname"]', hostData.hostname);
    await page.fill('input[name="ip_address"]', generateTestData.ipAddress());
    await page.fill('input[name="ssh_username"]', 'testuser2');
    await page.fill('input[name="ssh_password"]', 'TestPass123!');
    await page.click('button:has-text("Add")');
    
    // Should show error
    await expect(page.locator('text=Hostname already exists')).toBeVisible();
  });

  test('should test SSH connectivity during host creation', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    
    await page.click('button:has-text("Add Host")');
    await page.waitForSelector('[role="dialog"]');
    
    // Fill valid data
    await page.fill('input[name="hostname"]', generateTestData.hostname());
    await page.fill('input[name="ip_address"]', '192.168.1.100');
    await page.fill('input[name="ssh_username"]', 'testuser');
    await page.fill('input[name="ssh_password"]', 'TestPass123!');
    
    // Click test connection button
    await page.click('button:has-text("Test Connection")');
    
    // Mock connection test response
    await page.route('**/api/hosts/test-connection', route => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true, message: 'Connection successful' })
      });
    });
    
    // Should show success message
    await expect(page.locator('text=Connection successful')).toBeVisible();
  });

  test('should handle connection test failures', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    
    await page.click('button:has-text("Add Host")');
    await page.waitForSelector('[role="dialog"]');
    
    // Fill data
    await page.fill('input[name="hostname"]', generateTestData.hostname());
    await page.fill('input[name="ip_address"]', '192.168.1.100');
    await page.fill('input[name="ssh_username"]', 'wronguser');
    await page.fill('input[name="ssh_password"]', 'wrongpass');
    
    // Mock connection failure
    await page.route('**/api/hosts/test-connection', route => {
      route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Authentication failed' })
      });
    });
    
    await page.click('button:has-text("Test Connection")');
    
    // Should show error
    await expect(page.locator('text=Authentication failed')).toBeVisible();
  });

  test('should cancel host creation', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    const hostsPage = new HostsPage(page);
    
    const initialCount = await hostsPage.getHostCount();
    
    // Open dialog and fill some data
    await page.click('button:has-text("Add Host")');
    await page.waitForSelector('[role="dialog"]');
    
    await page.fill('input[name="hostname"]', 'cancelled-host');
    await page.fill('input[name="ip_address"]', '192.168.1.100');
    
    // Cancel
    await page.click('button:has-text("Cancel")');
    
    // Dialog should close
    await page.waitForSelector('[role="dialog"]', { state: 'hidden' });
    
    // Host count should remain same
    const finalCount = await hostsPage.getHostCount();
    expect(finalCount).toBe(initialCount);
  });

  test('should support keyboard navigation', async ({ authenticatedPage }) => {
    const page = authenticatedPage.page;
    
    await page.click('button:has-text("Add Host")');
    await page.waitForSelector('[role="dialog"]');
    
    // Tab through fields
    await page.keyboard.press('Tab'); // hostname
    await page.keyboard.type('tab-test-host');
    
    await page.keyboard.press('Tab'); // ip address
    await page.keyboard.type('192.168.1.100');
    
    await page.keyboard.press('Tab'); // username
    await page.keyboard.type('testuser');
    
    await page.keyboard.press('Tab'); // password
    await page.keyboard.type('TestPass123!');
    
    // Submit with Enter
    await page.keyboard.press('Enter');
    
    // Should attempt to create host
    await expect(page.locator('text=tab-test-host')).toBeVisible();
  });
});