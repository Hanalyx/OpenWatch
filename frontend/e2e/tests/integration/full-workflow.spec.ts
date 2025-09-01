import { test, expect, TEST_USERS } from '../../fixtures/auth';
import { generateTestData, uploadFile } from '../../utils/test-helpers';
import { HostsPage } from '../../fixtures/page-objects/HostsPage';
import { ScansPage } from '../../fixtures/page-objects/ScansPage';
import path from 'path';

test.describe('Full Application Workflow', () => {
  test('should complete full scanning workflow', async ({ page, loginPage, dashboardPage }) => {
    // Step 1: Login
    await loginPage.goto();
    await loginPage.login(TEST_USERS.admin.username, TEST_USERS.admin.password);
    await expect(dashboardPage.isDashboardDisplayed()).resolves.toBe(true);
    
    // Step 2: Navigate to Hosts
    await dashboardPage.navigateTo('hosts');
    const hostsPage = new HostsPage(page);
    
    // Step 3: Add a new host
    const testHost = {
      hostname: generateTestData.hostname(),
      ipAddress: generateTestData.ipAddress(),
      username: 'testuser',
      password: 'TestPass123!',
      port: 22,
      osType: 'linux'
    };
    
    await hostsPage.addHost(testHost);
    await expect(hostsPage.hasHost(testHost.hostname)).resolves.toBe(true);
    
    // Step 4: Upload SCAP content
    await dashboardPage.navigateTo('content');
    
    // Mock file upload since we don't have actual SCAP files in test
    await page.route('**/api/scap-content/upload', route => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          id: 'test-content-123',
          filename: 'test-scap-content.xml',
          profiles: ['xccdf_test_profile_1', 'xccdf_test_profile_2']
        })
      });
    });
    
    const uploadButton = page.locator('button:has-text("Upload SCAP Content")');
    await uploadButton.click();
    
    // Step 5: Create and run a scan
    await dashboardPage.navigateTo('scans');
    const scansPage = new ScansPage(page);
    
    await scansPage.createScan({
      name: `Test Scan ${Date.now()}`,
      hosts: [testHost.hostname],
      scapContent: 'test-scap-content.xml',
      profile: 'xccdf_test_profile_1'
    });
    
    // Step 6: Monitor scan progress
    await scansPage.waitForScanToComplete();
    
    // Step 7: View scan results
    await scansPage.viewLatestScanResults();
    
    // Verify results are displayed
    await expect(page.locator('text=Scan Results')).toBeVisible();
    await expect(page.locator('.scan-summary')).toBeVisible();
    
    // Step 8: Export results
    await page.locator('button:has-text("Export Results")').click();
    await page.locator('text=Export as PDF').click();
    
    // Verify download started
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.locator('button:has-text("Download")').click()
    ]);
    
    expect(download.suggestedFilename()).toMatch(/scan-results.*\.pdf/);
    
    // Step 9: Logout
    await dashboardPage.logout();
    await expect(loginPage.isLoginPageDisplayed()).resolves.toBe(true);
  });

  test('should handle bulk operations efficiently', async ({ page, loginPage, dashboardPage }) => {
    // Login
    await loginPage.goto();
    await loginPage.login(TEST_USERS.admin.username, TEST_USERS.admin.password);
    
    // Navigate to hosts
    await dashboardPage.navigateTo('hosts');
    const hostsPage = new HostsPage(page);
    
    // Add multiple hosts
    const hosts = Array.from({ length: 5 }, (_, i) => ({
      hostname: `bulk-host-${i}-${Date.now()}`,
      ipAddress: generateTestData.ipAddress(),
      username: 'bulkuser',
      password: 'BulkPass123!',
      port: 22,
      osType: 'linux'
    }));
    
    // Use bulk add if available, otherwise add individually
    for (const host of hosts) {
      await hostsPage.addHost(host);
    }
    
    // Select all hosts
    await hostsPage.selectAllHosts();
    
    // Perform bulk scan
    await hostsPage.bulkAction('scan');
    
    // Wait for scan dialog
    await page.waitForSelector('[role="dialog"]');
    
    // Configure bulk scan
    await page.selectOption('select[name="scapContent"]', { index: 1 });
    await page.selectOption('select[name="profile"]', { index: 1 });
    
    // Start bulk scan
    await page.click('button:has-text("Start Scan")');
    
    // Verify scan started for all hosts
    await dashboardPage.navigateTo('scans');
    
    // Check that scans are running
    const activeScans = await page.locator('.scan-status:has-text("Running")').count();
    expect(activeScans).toBeGreaterThanOrEqual(hosts.length);
  });

  test('should maintain data consistency across sessions', async ({ context, page, loginPage, dashboardPage }) => {
    // Session 1: Create data
    await loginPage.goto();
    await loginPage.login(TEST_USERS.admin.username, TEST_USERS.admin.password);
    
    // Add a host
    await dashboardPage.navigateTo('hosts');
    const hostsPage = new HostsPage(page);
    
    const testHost = {
      hostname: `persistent-host-${Date.now()}`,
      ipAddress: generateTestData.ipAddress(),
      username: 'persistuser',
      password: 'PersistPass123!',
      port: 22,
      osType: 'linux'
    };
    
    await hostsPage.addHost(testHost);
    
    // Logout
    await dashboardPage.logout();
    
    // Session 2: Verify data persists
    const page2 = await context.newPage();
    const loginPage2 = new LoginPage(page2);
    const dashboardPage2 = new DashboardPage(page2);
    const hostsPage2 = new HostsPage(page2);
    
    await loginPage2.goto();
    await loginPage2.login(TEST_USERS.user.username, TEST_USERS.user.password);
    
    await dashboardPage2.navigateTo('hosts');
    
    // Verify host exists
    await expect(hostsPage2.hasHost(testHost.hostname)).resolves.toBe(true);
    
    // Cleanup
    await page2.close();
  });

  test('should handle error scenarios gracefully', async ({ page, loginPage, dashboardPage }) => {
    await loginPage.goto();
    await loginPage.login(TEST_USERS.admin.username, TEST_USERS.admin.password);
    
    // Scenario 1: Network failure during scan
    await dashboardPage.navigateTo('scans');
    
    // Mock network failure
    await page.route('**/api/scans/*/start', route => route.abort());
    
    // Try to start scan
    await page.click('button:has-text("New Scan")');
    await page.fill('input[name="scanName"]', 'Failed Scan Test');
    await page.click('button:has-text("Start Scan")');
    
    // Should show error
    await expect(page.locator('.MuiAlert-root.MuiAlert-standardError')).toBeVisible();
    
    // Scenario 2: Invalid SCAP content
    await dashboardPage.navigateTo('content');
    
    await page.route('**/api/scap-content/upload', route => {
      route.fulfill({
        status: 400,
        contentType: 'application/json',
        body: JSON.stringify({
          detail: 'Invalid SCAP content format'
        })
      });
    });
    
    // Try to upload
    const uploadButton = page.locator('button:has-text("Upload SCAP Content")');
    await uploadButton.click();
    
    // Should show validation error
    await expect(page.locator('text=Invalid SCAP content format')).toBeVisible();
    
    // Scenario 3: Permission denied
    // Logout and login as read-only user
    await dashboardPage.logout();
    await loginPage.login(TEST_USERS.readOnly.username, TEST_USERS.readOnly.password);
    
    // Try to add host (should be disabled/hidden)
    await dashboardPage.navigateTo('hosts');
    const addHostButton = page.locator('button:has-text("Add Host")');
    
    // Button should either be disabled or not visible
    const isDisabled = await addHostButton.isDisabled();
    const isVisible = await addHostButton.isVisible();
    
    expect(isDisabled || !isVisible).toBe(true);
  });

  test('should handle real-time updates correctly', async ({ context, page, loginPage, dashboardPage }) => {
    // Login in two sessions
    await loginPage.goto();
    await loginPage.login(TEST_USERS.admin.username, TEST_USERS.admin.password);
    
    const page2 = await context.newPage();
    const loginPage2 = new LoginPage(page2);
    const dashboardPage2 = new DashboardPage(page2);
    
    await loginPage2.goto();
    await loginPage2.login(TEST_USERS.user.username, TEST_USERS.user.password);
    
    // Both navigate to dashboard
    await dashboardPage.goto();
    await dashboardPage2.goto();
    
    // Simulate real-time update (mock WebSocket or polling)
    await page.evaluate(() => {
      // Trigger a dashboard update event
      window.dispatchEvent(new CustomEvent('dashboard-update', {
        detail: { totalHosts: 10, activeScans: 2 }
      }));
    });
    
    // Both dashboards should reflect the update
    const stats1 = await dashboardPage.getStatistics();
    const stats2 = await dashboardPage2.getStatistics();
    
    expect(stats1.totalHosts).toBe(stats2.totalHosts);
    expect(stats1.activeScans).toBe(stats2.activeScans);
    
    // Cleanup
    await page2.close();
  });
});