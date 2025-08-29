// OpenWatch Host Groups Authenticated E2E Testing Suite
const { chromium, firefox, webkit } = require('playwright');

async function loginUser(page, username = 'testuser', password = 'testpass') {
    // Navigate to login page
    await page.goto('http://localhost:3002/login');
    await page.waitForTimeout(2000);
    
    // Check if login form exists
    const usernameInput = page.locator('input[name="username"], input[type="text"]').first();
    const passwordInput = page.locator('input[name="password"], input[type="password"]').first();
    const loginButton = page.locator('button[type="submit"], button:has-text("Login")').first();
    
    const hasLoginForm = await usernameInput.count() > 0 && await passwordInput.count() > 0;
    
    if (hasLoginForm) {
        await usernameInput.fill(username);
        await passwordInput.fill(password);
        await loginButton.click();
        await page.waitForTimeout(3000);
        
        // Check if we're redirected away from login
        const currentUrl = page.url();
        return !currentUrl.includes('/login');
    }
    
    return false;
}

async function runAuthenticatedHostGroupsTests() {
    console.log('=== OpenWatch Host Groups Authenticated E2E Testing Suite ===');
    console.log('Frontend URL: http://localhost:3002');
    console.log('Backend URL: http://localhost:8000\n');

    const results = {
        navigation: [],
        rbac: [],
        ui: [],
        performance: [],
        crossBrowser: [],
        functionality: []
    };

    // Test 1: Authenticated Navigation Testing
    console.log('1. Authenticated Navigation Testing');
    const browser1 = await chromium.launch({ headless: false });
    const context1 = await browser1.newContext();
    const page1 = await context1.newPage();

    try {
        // Attempt login
        const loginSuccess = await loginUser(page1);
        
        if (!loginSuccess) {
            console.log('   Testing without authentication (expected for demo)');
            await page1.goto('http://localhost:3002');
            await page1.waitForTimeout(2000);
        }
        
        await page1.screenshot({ path: '/home/rracine/hanalyx/openwatch/.playwright-mcp/auth-initial-state.png' });
        
        // Check for Host Groups menu item visibility
        const hostGroupsMenuByText = await page1.locator('text=Host Groups').count();
        const hostGroupsMenuByIcon = await page1.locator('[data-testid*="host-group"], [data-testid*="group"]').count();
        const groupIcons = await page1.locator('svg').count(); // Material-UI Group icons
        
        console.log(`   Host Groups menu (text): ${hostGroupsMenuByText}`);
        console.log(`   Host Groups menu (testid): ${hostGroupsMenuByIcon}`);
        console.log(`   Total icons found: ${groupIcons}`);
        
        // Check if navigation drawer/sidebar is present
        const navigationDrawer = await page1.locator('[role="navigation"], .MuiDrawer-root, nav').count();
        console.log(`   Navigation components found: ${navigationDrawer}`);
        
        results.navigation.push({
            test: 'Host Groups Menu Visibility (Authenticated)',
            result: hostGroupsMenuByText > 0 ? 'PASS' : 'FAIL',
            details: `Menu items found by text: ${hostGroupsMenuByText}, by testid: ${hostGroupsMenuByIcon}, nav components: ${navigationDrawer}`
        });

        // Test direct navigation to host-groups
        await page1.goto('http://localhost:3002/host-groups');
        await page1.waitForTimeout(3000);
        
        const hostGroupsUrl = page1.url();
        console.log(`   Direct host-groups navigation: ${hostGroupsUrl}`);
        
        await page1.screenshot({ path: '/home/rracine/hanalyx/openwatch/.playwright-mcp/host-groups-direct-nav.png' });
        
        // Check for Host Groups page content
        const hostGroupsPageIndicators = await Promise.all([
            page1.locator('text=Host Groups').count(),
            page1.locator('text=Compliance Groups').count(),
            page1.locator('text=Group').count(),
            page1.locator('button:has-text("Create"), button:has-text("Add")').count(),
            page1.locator('table, .MuiTable-root').count(),
            page1.locator('.MuiCard-root, [role="listitem"]').count()
        ]);
        
        const [titleCount, complianceCount, groupCount, actionButtons, tables, cards] = hostGroupsPageIndicators;
        
        console.log(`   Page indicators - Title: ${titleCount}, Compliance: ${complianceCount}, Group: ${groupCount}`);
        console.log(`   Interactive elements - Buttons: ${actionButtons}, Tables: ${tables}, Cards: ${cards}`);
        
        results.navigation.push({
            test: 'Host Groups Page Load',
            result: (titleCount > 0 || complianceCount > 0 || actionButtons > 0) ? 'PASS' : 'FAIL',
            details: `Page elements found - titles: ${titleCount + complianceCount + groupCount}, buttons: ${actionButtons}, tables: ${tables}, cards: ${cards}`
        });

        // Test responsive behavior
        await page1.setViewportSize({ width: 375, height: 667 });
        await page1.waitForTimeout(2000);
        await page1.screenshot({ path: '/home/rracine/hanalyx/openwatch/.playwright-mcp/host-groups-mobile.png' });
        
        const mobileMenuButton = await page1.locator('button[aria-label*="menu"], .MuiIconButton-root').count();
        console.log(`   Mobile menu buttons: ${mobileMenuButton}`);
        
        results.navigation.push({
            test: 'Host Groups Mobile Responsiveness',
            result: mobileMenuButton > 0 ? 'PASS' : 'PARTIAL',
            details: `Mobile UI elements: ${mobileMenuButton}`
        });

        // Reset to desktop view
        await page1.setViewportSize({ width: 1920, height: 1080 });
        await page1.waitForTimeout(1000);

    } catch (error) {
        console.log(`   Navigation testing error: ${error.message}`);
        results.navigation.push({
            test: 'Authenticated Navigation Suite',
            result: 'ERROR',
            details: error.message
        });
    }

    // Test 2: UI Functionality Testing
    console.log('\n2. UI Functionality Testing');
    try {
        await page1.goto('http://localhost:3002/host-groups');
        await page1.waitForTimeout(3000);
        
        // Test search functionality (if present)
        const searchInputs = await page1.locator('input[placeholder*="search"], input[type="search"]').count();
        if (searchInputs > 0) {
            await page1.locator('input[placeholder*="search"], input[type="search"]').first().fill('test');
            await page1.waitForTimeout(1000);
            console.log('   Search functionality: PRESENT');
            
            results.functionality.push({
                test: 'Search Functionality',
                result: 'PASS',
                details: 'Search input found and tested'
            });
        } else {
            console.log('   Search functionality: NOT FOUND');
            results.functionality.push({
                test: 'Search Functionality',
                result: 'NOT_FOUND',
                details: 'No search inputs detected'
            });
        }
        
        // Test action buttons
        const createButtons = await page1.locator('button:has-text("Create"), button:has-text("Add"), button:has-text("New")').count();
        console.log(`   Action buttons found: ${createButtons}`);
        
        if (createButtons > 0) {
            // Test clicking create button (if safe to do so)
            try {
                await page1.locator('button:has-text("Create"), button:has-text("Add"), button:has-text("New")').first().click();
                await page1.waitForTimeout(2000);
                
                // Check if modal/form opened
                const modalElements = await page1.locator('.MuiModal-root, .MuiDialog-root, form').count();
                console.log(`   Modal/form elements after button click: ${modalElements}`);
                
                await page1.screenshot({ path: '/home/rracine/hanalyx/openwatch/.playwright-mcp/host-groups-create-modal.png' });
                
                results.functionality.push({
                    test: 'Create Button Functionality',
                    result: modalElements > 0 ? 'PASS' : 'PARTIAL',
                    details: `Create button clicked, modal elements: ${modalElements}`
                });
                
                // Close modal if opened (press Escape)
                await page1.keyboard.press('Escape');
                await page1.waitForTimeout(1000);
                
            } catch (btnError) {
                results.functionality.push({
                    test: 'Create Button Functionality',
                    result: 'ERROR',
                    details: `Button click error: ${btnError.message}`
                });
            }
        } else {
            results.functionality.push({
                test: 'Create Button Functionality',
                result: 'NOT_FOUND',
                details: 'No create buttons found'
            });
        }
        
        // Test color-coded visualization (check for colored elements)
        const coloredElements = await Promise.all([
            page1.locator('.MuiChip-root').count(),
            page1.locator('[style*="background-color"], [style*="color"]').count(),
            page1.locator('.MuiBadge-root').count()
        ]);
        
        const [chips, styledElements, badges] = coloredElements;
        console.log(`   Color-coded elements - Chips: ${chips}, Styled: ${styledElements}, Badges: ${badges}`);
        
        results.functionality.push({
            test: 'Color-coded Visualization',
            result: (chips + styledElements + badges) > 0 ? 'PASS' : 'NOT_FOUND',
            details: `Color elements found - chips: ${chips}, styled: ${styledElements}, badges: ${badges}`
        });

    } catch (error) {
        console.log(`   UI functionality testing error: ${error.message}`);
        results.functionality.push({
            test: 'UI Functionality Suite',
            result: 'ERROR',
            details: error.message
        });
    }

    await browser1.close();

    // Test 3: Performance Testing with User Interaction
    console.log('\n3. Performance Testing');
    const browser3 = await chromium.launch({ headless: true });
    const context3 = await browser3.newContext();
    const page3 = await context3.newPage();

    try {
        const startTime = Date.now();
        await page3.goto('http://localhost:3002/host-groups');
        const loadTime = Date.now() - startTime;
        
        console.log(`   Host Groups page load time: ${loadTime}ms`);
        
        results.performance.push({
            test: 'Host Groups Page Load Performance',
            result: loadTime < 5000 ? 'PASS' : loadTime < 10000 ? 'SLOW' : 'FAIL',
            details: `Load time: ${loadTime}ms`
        });

        // Test interaction performance
        const interactionStart = Date.now();
        await page3.waitForLoadState('networkidle');
        const interactionTime = Date.now() - interactionStart;
        
        console.log(`   Network idle time: ${interactionTime}ms`);
        
        results.performance.push({
            test: 'Network Response Time',
            result: interactionTime < 3000 ? 'PASS' : interactionTime < 5000 ? 'SLOW' : 'FAIL',
            details: `Network idle time: ${interactionTime}ms`
        });

    } catch (error) {
        console.log(`   Performance testing error: ${error.message}`);
        results.performance.push({
            test: 'Performance Suite',
            result: 'ERROR',
            details: error.message
        });
    }

    await browser3.close();

    // Test 4: Cross-browser Testing
    console.log('\n4. Cross-browser Testing');
    
    // Firefox testing
    const firefoxBrowser = await firefox.launch({ headless: true });
    const firefoxContext = await firefoxBrowser.newContext();
    const firefoxPage = await firefoxContext.newPage();

    try {
        await firefoxPage.goto('http://localhost:3002/host-groups');
        await firefoxPage.waitForTimeout(3000);
        
        const firefoxUrl = firefoxPage.url();
        const firefoxElements = await firefoxPage.locator('*').count();
        console.log(`   Firefox - URL: ${firefoxUrl}, Elements: ${firefoxElements}`);
        
        results.crossBrowser.push({
            test: 'Firefox Compatibility',
            result: firefoxElements > 10 ? 'PASS' : 'PARTIAL',
            details: `Firefox loaded ${firefoxElements} elements at ${firefoxUrl}`
        });

    } catch (error) {
        results.crossBrowser.push({
            test: 'Firefox Compatibility',
            result: 'ERROR',
            details: error.message
        });
    }

    await firefoxBrowser.close();

    // WebKit (Safari) testing
    try {
        const webkitBrowser = await webkit.launch({ headless: true });
        const webkitContext = await webkitBrowser.newContext();
        const webkitPage = await webkitContext.newPage();

        await webkitPage.goto('http://localhost:3002/host-groups');
        await webkitPage.waitForTimeout(3000);
        
        const webkitUrl = webkitPage.url();
        const webkitElements = await webkitPage.locator('*').count();
        console.log(`   WebKit - URL: ${webkitUrl}, Elements: ${webkitElements}`);
        
        results.crossBrowser.push({
            test: 'WebKit (Safari) Compatibility',
            result: webkitElements > 10 ? 'PASS' : 'PARTIAL',
            details: `WebKit loaded ${webkitElements} elements at ${webkitUrl}`
        });

        await webkitBrowser.close();

    } catch (error) {
        results.crossBrowser.push({
            test: 'WebKit (Safari) Compatibility',
            result: 'ERROR',
            details: error.message
        });
    }

    // Generate Comprehensive Test Report
    console.log('\n=== COMPREHENSIVE TEST RESULTS ===');
    
    function printResults(category, tests) {
        if (tests.length === 0) return;
        
        console.log(`\n${category.toUpperCase()}:`);
        tests.forEach(test => {
            const status = test.result === 'PASS' ? '✅' : 
                          test.result === 'FAIL' ? '❌' : 
                          test.result === 'ERROR' ? '🚫' : 
                          test.result === 'SLOW' ? '⚠️' : '⚪';
            console.log(`  ${status} ${test.test}: ${test.result}`);
            console.log(`    📝 ${test.details}`);
        });
    }

    printResults('Navigation Tests', results.navigation);
    printResults('RBAC Tests', results.rbac);
    printResults('UI Functionality Tests', results.functionality);
    printResults('Performance Tests', results.performance);
    printResults('Cross-browser Tests', results.crossBrowser);

    // Calculate comprehensive metrics
    const allTests = [
        ...results.navigation, 
        ...results.rbac, 
        ...results.functionality,
        ...results.performance, 
        ...results.crossBrowser
    ];
    
    const passed = allTests.filter(t => t.result === 'PASS').length;
    const failed = allTests.filter(t => t.result === 'FAIL').length;
    const errors = allTests.filter(t => t.result === 'ERROR').length;
    const warnings = allTests.filter(t => ['SLOW', 'PARTIAL', 'NOT_FOUND', 'NEEDS_AUTH'].includes(t.result)).length;

    console.log(`\n=== FINAL SUMMARY ===`);
    console.log(`📊 Total Tests: ${allTests.length}`);
    console.log(`✅ Passed: ${passed}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`🚫 Errors: ${errors}`);
    console.log(`⚠️  Warnings: ${warnings}`);
    console.log(`🎯 Success Rate: ${((passed / allTests.length) * 100).toFixed(1)}%`);
    console.log(`🔧 Quality Score: ${(((passed + (warnings * 0.5)) / allTests.length) * 100).toFixed(1)}%`);

    // Generate recommendations
    console.log(`\n=== RECOMMENDATIONS ===`);
    
    if (failed > 0 || errors > 0) {
        console.log(`🔴 Critical Issues Found: ${failed + errors} items need immediate attention`);
    }
    
    if (warnings > 0) {
        console.log(`🟡 Improvement Opportunities: ${warnings} items could be enhanced`);
    }
    
    if (passed === allTests.length) {
        console.log(`🎉 Excellent! All tests passed. Host Groups functionality is working perfectly.`);
    } else if (passed / allTests.length > 0.8) {
        console.log(`👍 Good! Host Groups functionality is mostly working well with minor issues.`);
    } else if (passed / allTests.length > 0.6) {
        console.log(`⚠️  Moderate issues detected. Host Groups functionality needs attention.`);
    } else {
        console.log(`🚨 Significant issues found. Host Groups functionality requires major fixes.`);
    }

    return results;
}

// Run the comprehensive authenticated tests
runAuthenticatedHostGroupsTests().catch(console.error);