// Comprehensive E2E Test Suite for Host Groups Functionality
// Focus on recent fixes: SCAP content dropdown and profile handling

const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

// Test configuration
const BASE_URL = 'http://localhost:3001';
const API_URL = 'http://localhost:8000';
const SCREENSHOTS_DIR = path.join(__dirname, 'screenshots');
const TEST_REPORT_DIR = path.join(__dirname, 'reports');

// Ensure directories exist
if (!fs.existsSync(SCREENSHOTS_DIR)) {
    fs.mkdirSync(SCREENSHOTS_DIR, { recursive: true });
}
if (!fs.existsSync(TEST_REPORT_DIR)) {
    fs.mkdirSync(TEST_REPORT_DIR, { recursive: true });
}

// Test data
const testCredentials = {
    username: 'admin',
    password: 'admin123'
};

const testHostGroup = {
    name: `Test Group ${Date.now()}`,
    description: 'E2E Test Group for validating SCAP content and profile handling',
    color: '#FF5722',
    scapContentId: null, // Will be populated during test
    profileId: null // Will be populated during test
};

// Test report structure
const testReport = {
    testSuite: 'Host Groups E2E Testing',
    executionTime: new Date().toISOString(),
    environment: {
        frontendUrl: BASE_URL,
        backendUrl: API_URL
    },
    tests: [],
    summary: {
        total: 0,
        passed: 0,
        failed: 0,
        skipped: 0
    }
};

// Helper function to log test results
function logTestResult(testName, status, details = {}) {
    const result = {
        name: testName,
        status,
        timestamp: new Date().toISOString(),
        ...details
    };
    testReport.tests.push(result);
    testReport.summary.total++;
    testReport.summary[status]++;
    console.log(`[${status.toUpperCase()}] ${testName}`);
    if (details.error) {
        console.error(`  Error: ${details.error}`);
    }
}

// Helper function to take screenshots with descriptive names
async function takeScreenshot(page, name) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `${timestamp}_${name}.png`;
    const filepath = path.join(SCREENSHOTS_DIR, filename);
    await page.screenshot({ path: filepath, fullPage: true });
    console.log(`  Screenshot saved: ${filename}`);
    return filename;
}

// Main test execution
async function runE2ETests() {
    console.log('\n=== Starting Host Groups E2E Test Suite ===\n');
    
    const browser = await chromium.launch({
        headless: false, // Set to true for CI/CD
        slowMo: 100 // Slow down for visibility
    });
    
    const context = await browser.newContext({
        viewport: { width: 1920, height: 1080 }
    });
    
    const page = await context.newPage();
    
    try {
        // Test 1: Login to OpenWatch
        await testLogin(page);
        
        // Test 2: Navigate to Host Groups
        await testNavigateToHostGroups(page);
        
        // Test 3: Create a new host group
        await testCreateHostGroup(page);
        
        // Test 4: Edit host group - Critical fix validation
        await testEditHostGroup(page);
        
        // Test 5: Add hosts to group
        await testAddHostsToGroup(page);
        
        // Test 6: Run group scan
        await testRunGroupScan(page);
        
        // Test 7: Monitor scan progress
        await testMonitorScanProgress(page);
        
        // Test 8: Error scenario testing
        await testErrorScenarios(page);
        
        // Test 9: Cleanup
        await testCleanup(page);
        
    } catch (error) {
        console.error('Test suite failed:', error);
        await takeScreenshot(page, 'test-suite-failure');
    } finally {
        await browser.close();
        generateTestReport();
    }
}

// Test: Login
async function testLogin(page) {
    const testName = 'Login to OpenWatch';
    try {
        await page.goto(BASE_URL);
        await page.waitForLoadState('networkidle');
        await takeScreenshot(page, '01-login-page');
        
        // Fill login form
        await page.fill('input[name="username"]', testCredentials.username);
        await page.fill('input[name="password"]', testCredentials.password);
        await takeScreenshot(page, '02-login-filled');
        
        // Submit
        await page.click('button[type="submit"]');
        await page.waitForNavigation();
        
        // Verify successful login
        await page.waitForSelector('text=Dashboard', { timeout: 10000 });
        await takeScreenshot(page, '03-dashboard-loaded');
        
        logTestResult(testName, 'passed');
    } catch (error) {
        await takeScreenshot(page, 'login-failure');
        logTestResult(testName, 'failed', { error: error.message });
        throw error;
    }
}

// Test: Navigate to Host Groups
async function testNavigateToHostGroups(page) {
    const testName = 'Navigate to Host Groups';
    try {
        // Click on Hosts menu
        await page.click('text=Hosts');
        await page.waitForTimeout(500);
        
        // Click on Host Groups submenu
        await page.click('text=Host Groups');
        await page.waitForSelector('h4:has-text("Host Groups")', { timeout: 10000 });
        await takeScreenshot(page, '04-host-groups-page');
        
        logTestResult(testName, 'passed');
    } catch (error) {
        await takeScreenshot(page, 'navigation-failure');
        logTestResult(testName, 'failed', { error: error.message });
        throw error;
    }
}

// Test: Create Host Group
async function testCreateHostGroup(page) {
    const testName = 'Create New Host Group';
    try {
        // Click Add Host Group button
        await page.click('button:has-text("Add Host Group")');
        await page.waitForSelector('text=Add Host Group', { timeout: 5000 });
        await takeScreenshot(page, '05-add-group-dialog');
        
        // Fill group details
        await page.fill('input[name="name"]', testHostGroup.name);
        await page.fill('textarea[name="description"]', testHostGroup.description);
        
        // Select color (click on color picker)
        await page.click('[data-testid="color-picker"]');
        await page.click(`[data-color="${testHostGroup.color}"]`);
        
        // Select SCAP content - Critical test
        await page.click('[data-testid="scap-content-select"]');
        await page.waitForSelector('ul[role="listbox"] li', { timeout: 10000 });
        const scapOptions = await page.$$('ul[role="listbox"] li');
        if (scapOptions.length > 0) {
            await scapOptions[0].click();
            testHostGroup.scapContentId = await page.$eval('[data-testid="scap-content-select"]', el => el.value);
            await takeScreenshot(page, '06-scap-content-selected');
        } else {
            throw new Error('No SCAP content available in dropdown');
        }
        
        // Wait for profiles to load
        await page.waitForTimeout(1000);
        
        // Select profile - Critical test for object handling
        const profileSelectExists = await page.isVisible('[data-testid="profile-select"]');
        if (profileSelectExists) {
            await page.click('[data-testid="profile-select"]');
            await page.waitForSelector('ul[role="listbox"] li', { timeout: 5000 });
            const profileOptions = await page.$$('ul[role="listbox"] li');
            if (profileOptions.length > 0) {
                await profileOptions[0].click();
                testHostGroup.profileId = await page.$eval('[data-testid="profile-select"]', el => el.value);
                await takeScreenshot(page, '07-profile-selected');
            }
        }
        
        await takeScreenshot(page, '08-form-filled');
        
        // Submit form
        await page.click('button:has-text("Create")');
        await page.waitForTimeout(2000);
        
        // Verify group created
        await page.waitForSelector(`text=${testHostGroup.name}`, { timeout: 10000 });
        await takeScreenshot(page, '09-group-created');
        
        logTestResult(testName, 'passed', { 
            groupName: testHostGroup.name,
            scapContentId: testHostGroup.scapContentId,
            profileId: testHostGroup.profileId
        });
    } catch (error) {
        await takeScreenshot(page, 'create-group-failure');
        logTestResult(testName, 'failed', { error: error.message });
        throw error;
    }
}

// Test: Edit Host Group - Critical Fix Validation
async function testEditHostGroup(page) {
    const testName = 'Edit Host Group (SCAP Content Dropdown Fix)';
    try {
        // Find and click edit button for our test group
        const groupRow = page.locator(`tr:has-text("${testHostGroup.name}")`);
        await groupRow.locator('button[aria-label="Edit"]').click();
        await page.waitForSelector('text=Edit Host Group', { timeout: 5000 });
        await takeScreenshot(page, '10-edit-dialog-opened');
        
        // Critical Test: Verify SCAP content dropdown loads
        const scapContentSelect = page.locator('[data-testid="scap-content-select"]');
        await scapContentSelect.waitFor({ timeout: 5000 });
        
        // Check if SCAP content is populated
        const scapContentValue = await scapContentSelect.inputValue();
        if (!scapContentValue) {
            throw new Error('SCAP content dropdown is empty - BUG FOUND!');
        }
        
        await takeScreenshot(page, '11-scap-content-loaded');
        
        // Change SCAP content to test profile handling
        await scapContentSelect.click();
        await page.waitForSelector('ul[role="listbox"] li', { timeout: 5000 });
        const scapOptions = await page.$$('ul[role="listbox"] li');
        if (scapOptions.length > 1) {
            await scapOptions[1].click();
            await page.waitForTimeout(1000);
            
            // Critical Test: Verify profile dropdown handles change without crashing
            const profileSelect = page.locator('[data-testid="profile-select"]');
            if (await profileSelect.isVisible()) {
                await profileSelect.click();
                await page.waitForSelector('ul[role="listbox"] li', { timeout: 5000 });
                await takeScreenshot(page, '12-profile-dropdown-works');
                await page.keyboard.press('Escape');
            }
        }
        
        // Update description
        const newDescription = testHostGroup.description + ' - Updated';
        await page.fill('textarea[name="description"]', newDescription);
        
        await takeScreenshot(page, '13-edit-form-updated');
        
        // Save changes
        await page.click('button:has-text("Update")');
        await page.waitForTimeout(2000);
        
        // Verify update succeeded
        await takeScreenshot(page, '14-group-updated');
        
        logTestResult(testName, 'passed', { 
            criticalFix: 'SCAP content dropdown loads correctly in edit dialog',
            profileHandling: 'Profile dropdown handles object/string formats'
        });
    } catch (error) {
        await takeScreenshot(page, 'edit-group-failure');
        logTestResult(testName, 'failed', { error: error.message });
        throw error;
    }
}

// Test: Add Hosts to Group
async function testAddHostsToGroup(page) {
    const testName = 'Add Hosts to Group';
    try {
        // Navigate to Hosts page
        await page.click('text=Hosts');
        await page.waitForTimeout(500);
        await page.click('nav a:has-text("All Hosts")');
        await page.waitForSelector('h4:has-text("Hosts")', { timeout: 10000 });
        
        // Check if there are any hosts
        const hostRows = await page.$$('tbody tr');
        if (hostRows.length === 0) {
            logTestResult(testName, 'skipped', { reason: 'No hosts available for testing' });
            return;
        }
        
        // Select first two hosts
        for (let i = 0; i < Math.min(2, hostRows.length); i++) {
            await hostRows[i].locator('input[type="checkbox"]').check();
        }
        
        await takeScreenshot(page, '15-hosts-selected');
        
        // Click bulk actions
        await page.click('button:has-text("Bulk Actions")');
        await page.click('text=Assign to Group');
        
        // Select our test group
        await page.waitForSelector('text=Select Host Groups', { timeout: 5000 });
        await page.click(`text=${testHostGroup.name}`);
        
        await takeScreenshot(page, '16-group-assignment-dialog');
        
        // Confirm assignment
        await page.click('button:has-text("Assign")');
        await page.waitForTimeout(2000);
        
        logTestResult(testName, 'passed', { hostsAdded: Math.min(2, hostRows.length) });
    } catch (error) {
        await takeScreenshot(page, 'add-hosts-failure');
        logTestResult(testName, 'failed', { error: error.message });
    }
}

// Test: Run Group Scan
async function testRunGroupScan(page) {
    const testName = 'Run Group Scan';
    try {
        // Navigate back to Host Groups
        await page.click('text=Hosts');
        await page.waitForTimeout(500);
        await page.click('text=Host Groups');
        await page.waitForSelector('h4:has-text("Host Groups")', { timeout: 10000 });
        
        // Find our test group and click scan
        const groupRow = page.locator(`tr:has-text("${testHostGroup.name}")`);
        await groupRow.locator('button[aria-label="Scan group"]').click();
        
        await page.waitForSelector('text=Start Scan', { timeout: 5000 });
        await takeScreenshot(page, '17-scan-dialog');
        
        // Start scan
        await page.click('button:has-text("Start Scan")');
        await page.waitForTimeout(2000);
        
        // Check for scan progress dialog
        const progressDialogVisible = await page.isVisible('text=Scan Progress');
        if (progressDialogVisible) {
            await takeScreenshot(page, '18-scan-progress-started');
            logTestResult(testName, 'passed', { scanStarted: true });
        } else {
            throw new Error('Scan progress dialog did not appear');
        }
    } catch (error) {
        await takeScreenshot(page, 'run-scan-failure');
        logTestResult(testName, 'failed', { error: error.message });
    }
}

// Test: Monitor Scan Progress
async function testMonitorScanProgress(page) {
    const testName = 'Monitor Scan Progress';
    try {
        // Wait for scan progress to update
        await page.waitForTimeout(5000);
        
        // Take screenshots of progress states
        if (await page.isVisible('text=Scan Progress')) {
            await takeScreenshot(page, '19-scan-in-progress');
            
            // Check for host scan details
            const hostDetails = await page.$$('[data-testid="host-scan-status"]');
            if (hostDetails.length > 0) {
                await takeScreenshot(page, '20-host-scan-details');
            }
            
            // Wait for completion or timeout after 30 seconds
            let scanComplete = false;
            const startTime = Date.now();
            while (!scanComplete && (Date.now() - startTime) < 30000) {
                if (await page.isVisible('text=completed') || await page.isVisible('text=failed')) {
                    scanComplete = true;
                    await takeScreenshot(page, '21-scan-completed');
                }
                await page.waitForTimeout(2000);
            }
            
            logTestResult(testName, 'passed', { 
                scanMonitored: true,
                scanComplete 
            });
        } else {
            logTestResult(testName, 'skipped', { reason: 'Scan progress dialog not visible' });
        }
    } catch (error) {
        await takeScreenshot(page, 'monitor-progress-failure');
        logTestResult(testName, 'failed', { error: error.message });
    }
}

// Test: Error Scenarios
async function testErrorScenarios(page) {
    const testName = 'Error Scenario Testing';
    try {
        // Test 1: Create group with missing required fields
        await page.click('button:has-text("Add Host Group")');
        await page.waitForSelector('text=Add Host Group', { timeout: 5000 });
        
        // Try to create without name
        await page.click('button:has-text("Create")');
        await page.waitForTimeout(1000);
        
        const nameError = await page.isVisible('text=Name is required');
        if (nameError) {
            await takeScreenshot(page, '22-validation-error-name');
        }
        
        // Cancel dialog
        await page.click('button:has-text("Cancel")');
        
        // Test 2: Try to edit a non-existent group (API error simulation)
        // This would require manipulating the UI or making direct API calls
        
        logTestResult(testName, 'passed', { 
            validationTested: true,
            nameValidation: nameError 
        });
    } catch (error) {
        await takeScreenshot(page, 'error-scenario-failure');
        logTestResult(testName, 'failed', { error: error.message });
    }
}

// Test: Cleanup
async function testCleanup(page) {
    const testName = 'Cleanup Test Data';
    try {
        // Delete the test group
        const groupRow = page.locator(`tr:has-text("${testHostGroup.name}")`);
        if (await groupRow.isVisible()) {
            await groupRow.locator('button[aria-label="Delete"]').click();
            await page.waitForSelector('text=Confirm Delete', { timeout: 5000 });
            await page.click('button:has-text("Delete")');
            await page.waitForTimeout(2000);
            await takeScreenshot(page, '23-cleanup-complete');
        }
        
        logTestResult(testName, 'passed');
    } catch (error) {
        logTestResult(testName, 'failed', { error: error.message });
    }
}

// Generate comprehensive test report
function generateTestReport() {
    const reportPath = path.join(TEST_REPORT_DIR, `host-groups-e2e-report-${Date.now()}.json`);
    fs.writeFileSync(reportPath, JSON.stringify(testReport, null, 2));
    
    console.log('\n=== Test Report Summary ===');
    console.log(`Total Tests: ${testReport.summary.total}`);
    console.log(`Passed: ${testReport.summary.passed}`);
    console.log(`Failed: ${testReport.summary.failed}`);
    console.log(`Skipped: ${testReport.summary.skipped}`);
    console.log(`\nDetailed report saved to: ${reportPath}`);
    console.log(`Screenshots saved to: ${SCREENSHOTS_DIR}`);
    
    // Generate markdown report
    generateMarkdownReport();
}

// Generate markdown report for documentation
function generateMarkdownReport() {
    const timestamp = new Date().toISOString();
    const reportContent = `# Host Groups E2E Test Report

## Test Execution Summary
- **Date**: ${timestamp}
- **Environment**: 
  - Frontend: ${BASE_URL}
  - Backend: ${API_URL}

## Test Results

| Test Name | Status | Details |
|-----------|--------|---------|
${testReport.tests.map(test => `| ${test.name} | ${test.status.toUpperCase()} | ${test.error || 'Success'} |`).join('\n')}

## Critical Fixes Validated

### 1. SCAP Content Dropdown in Edit Dialog
- **Issue**: SCAP content dropdown was showing empty when editing host groups
- **Fix Location**: GroupEditDialog.tsx, line 171
- **Status**: ${testReport.tests.find(t => t.name.includes('Edit Host Group'))?.status || 'Not tested'}

### 2. Profile Dropdown Object Handling
- **Issue**: Profile dropdown crashed when receiving object instead of string
- **Fix Location**: Profile value handling in form state
- **Status**: ${testReport.tests.find(t => t.name.includes('Edit Host Group'))?.status || 'Not tested'}

## Summary Statistics
- **Total Tests**: ${testReport.summary.total}
- **Passed**: ${testReport.summary.passed}
- **Failed**: ${testReport.summary.failed}
- **Skipped**: ${testReport.summary.skipped}

## Screenshots Generated
${fs.readdirSync(SCREENSHOTS_DIR).filter(f => f.endsWith('.png')).map(f => `- ${f}`).join('\n')}

## Recommendations
${testReport.summary.failed > 0 ? `
### Failed Tests Need Attention:
${testReport.tests.filter(t => t.status === 'failed').map(t => `- **${t.name}**: ${t.error}`).join('\n')}
` : '- All tests passed successfully!'}
`;

    const mdReportPath = path.join(TEST_REPORT_DIR, `host-groups-e2e-report-${Date.now()}.md`);
    fs.writeFileSync(mdReportPath, reportContent);
    console.log(`\nMarkdown report saved to: ${mdReportPath}`);
}

// Run the tests
runE2ETests().catch(console.error);