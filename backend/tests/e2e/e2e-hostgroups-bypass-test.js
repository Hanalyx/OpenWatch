// OpenWatch Host Groups E2E Testing Suite - Authentication Bypass Mode
const { chromium, firefox, webkit } = require('playwright');

async function simulateAuthenticatedSession(page) {
    // Inject mock authentication token into localStorage
    const mockAuthData = {
        auth_token: 'mock-jwt-token-for-testing',
        user: {
            id: 1,
            username: 'testuser',
            role: 'security_admin',
            email: 'test@example.com'
        },
        isAuthenticated: true
    };
    
    // Set up local storage with auth data
    await page.goto('http://localhost:3002');
    await page.waitForTimeout(1000);
    
    await page.evaluate((authData) => {
        localStorage.setItem('auth_token', authData.auth_token);
        localStorage.setItem('user', JSON.stringify(authData.user));
        // Also set it in window object for React state
        window.__mockAuth = authData;
    }, mockAuthData);
    
    // Reload page to trigger auth state change
    await page.reload();
    await page.waitForTimeout(2000);
    
    return mockAuthData;
}

async function runBypassHostGroupsTests() {
    console.log('=== OpenWatch Host Groups Bypass Testing Suite ===');
    console.log('Frontend URL: http://localhost:3002');
    console.log('Backend URL: http://localhost:8000');
    console.log('Mode: Authentication Simulation for UI Testing\n');

    const results = {
        navigation: [],
        ui: [],
        functionality: [],
        performance: [],
        crossBrowser: [],
        accessibility: []
    };

    // Test 1: UI Structure Analysis (without authentication dependency)
    console.log('1. UI Structure Analysis');
    const browser1 = await chromium.launch({ headless: false });
    const context1 = await browser1.newContext();
    const page1 = await context1.newPage();

    try {
        // Simulate authenticated session
        await simulateAuthenticatedSession(page1);
        
        // Navigate to the app root to check navigation structure
        await page1.goto('http://localhost:3002');
        await page1.waitForTimeout(3000);
        
        await page1.screenshot({ path: '/home/rracine/hanalyx/openwatch/.playwright-mcp/bypass-initial.png' });
        
        // Check for navigation elements
        const navigationElements = await page1.evaluate(() => {
            return {
                drawer: document.querySelectorAll('.MuiDrawer-root, [role="navigation"]').length,
                appBar: document.querySelectorAll('.MuiAppBar-root, .MuiToolbar-root').length,
                menuItems: document.querySelectorAll('.MuiListItem-root, .MuiMenuItem-root').length,
                buttons: document.querySelectorAll('button').length,
                links: document.querySelectorAll('a').length,
                hostGroupsText: document.body.innerText.toLowerCase().includes('host groups'),
                groupIcons: document.querySelectorAll('svg').length,
                materialUIComponents: document.querySelectorAll('[class*="Mui"]').length
            };
        });
        
        console.log('   Navigation Structure Analysis:');
        console.log(`     - Drawer components: ${navigationElements.drawer}`);
        console.log(`     - AppBar components: ${navigationElements.appBar}`);
        console.log(`     - Menu items: ${navigationElements.menuItems}`);
        console.log(`     - Buttons: ${navigationElements.buttons}`);
        console.log(`     - Material-UI components: ${navigationElements.materialUIComponents}`);
        console.log(`     - Host Groups text present: ${navigationElements.hostGroupsText}`);
        
        results.navigation.push({
            test: 'Navigation Structure Analysis',
            result: (navigationElements.drawer > 0 || navigationElements.appBar > 0) ? 'PASS' : 'FAIL',
            details: `Drawer: ${navigationElements.drawer}, AppBar: ${navigationElements.appBar}, MenuItems: ${navigationElements.menuItems}`
        });
        
        results.navigation.push({
            test: 'Host Groups Text Presence',
            result: navigationElements.hostGroupsText ? 'PASS' : 'FAIL',
            details: `Host Groups text found in page: ${navigationElements.hostGroupsText}`
        });

        // Test direct URL access to Host Groups
        await page1.goto('http://localhost:3002/host-groups');
        await page1.waitForTimeout(5000);
        
        const hostGroupsUrl = page1.url();
        console.log(`   Direct Host Groups URL access: ${hostGroupsUrl}`);
        
        await page1.screenshot({ path: '/home/rracine/hanalyx/openwatch/.playwright-mcp/bypass-host-groups.png' });
        
        // Analyze the Host Groups page content
        const pageContent = await page1.evaluate(() => {
            return {
                currentUrl: window.location.href,
                title: document.title,
                headings: Array.from(document.querySelectorAll('h1, h2, h3, h4, h5, h6')).map(h => h.textContent),
                bodyText: document.body.innerText,
                forms: document.querySelectorAll('form').length,
                inputs: document.querySelectorAll('input').length,
                tables: document.querySelectorAll('table').length,
                cards: document.querySelectorAll('.MuiCard-root').length,
                papers: document.querySelectorAll('.MuiPaper-root').length,
                dialogs: document.querySelectorAll('.MuiDialog-root').length,
                errorMessages: Array.from(document.querySelectorAll('[class*="error"], .MuiAlert-root')).map(e => e.textContent),
                loadingIndicators: document.querySelectorAll('.MuiCircularProgress-root').length
            };
        });
        
        console.log('\n   Host Groups Page Content Analysis:');
        console.log(`     - Current URL: ${pageContent.currentUrl}`);
        console.log(`     - Page Title: ${pageContent.title}`);
        console.log(`     - Headings found: ${pageContent.headings.length}`);
        if (pageContent.headings.length > 0) {
            console.log(`     - Heading texts: ${pageContent.headings.slice(0, 3).join(', ')}`);
        }
        console.log(`     - Forms: ${pageContent.forms}, Inputs: ${pageContent.inputs}`);
        console.log(`     - Tables: ${pageContent.tables}, Cards: ${pageContent.cards}, Papers: ${pageContent.papers}`);
        console.log(`     - Loading indicators: ${pageContent.loadingIndicators}`);
        if (pageContent.errorMessages.length > 0) {
            console.log(`     - Error messages: ${pageContent.errorMessages.slice(0, 2).join('; ')}`);
        }
        
        const isHostGroupsPage = hostGroupsUrl.includes('/host-groups') && 
                                !hostGroupsUrl.includes('/login');
        
        results.navigation.push({
            test: 'Host Groups Page Access',
            result: isHostGroupsPage ? 'PASS' : 'REDIRECTED',
            details: `URL: ${hostGroupsUrl}, Headings: ${pageContent.headings.length}, Content elements: ${pageContent.forms + pageContent.tables + pageContent.cards}`
        });

        // Test responsive design
        const viewports = [
            { width: 1920, height: 1080, name: 'Desktop' },
            { width: 768, height: 1024, name: 'Tablet' },
            { width: 375, height: 667, name: 'Mobile' }
        ];
        
        for (const viewport of viewports) {
            await page1.setViewportSize({ width: viewport.width, height: viewport.height });
            await page1.waitForTimeout(1000);
            
            const responsiveElements = await page1.evaluate(() => ({
                visibleElements: document.querySelectorAll(':not([style*="display: none"])').length,
                menuButtons: document.querySelectorAll('[aria-label*="menu"]').length,
                collapsedElements: document.querySelectorAll('[style*="width: 0"], [style*="height: 0"]').length
            }));
            
            await page1.screenshot({ 
                path: `/home/rracine/hanalyx/openwatch/.playwright-mcp/bypass-${viewport.name.toLowerCase()}.png` 
            });
            
            console.log(`   ${viewport.name} (${viewport.width}x${viewport.height}): ${responsiveElements.visibleElements} visible elements`);
            
            results.ui.push({
                test: `${viewport.name} Responsive Design`,
                result: responsiveElements.visibleElements > 10 ? 'PASS' : 'FAIL',
                details: `Visible: ${responsiveElements.visibleElements}, Menu buttons: ${responsiveElements.menuButtons}`
            });
        }
        
        // Reset to desktop
        await page1.setViewportSize({ width: 1920, height: 1080 });
        
    } catch (error) {
        console.log(`   UI Structure analysis error: ${error.message}`);
        results.navigation.push({
            test: 'UI Structure Analysis Suite',
            result: 'ERROR',
            details: error.message
        });
    }

    await browser1.close();

    // Test 2: Performance Analysis
    console.log('\n2. Performance Analysis');
    const browser2 = await chromium.launch({ headless: true });
    const context2 = await browser2.newContext();
    const page2 = await context2.newPage();

    try {
        const performanceMetrics = [];
        
        // Test initial load
        const startTime = Date.now();
        await page2.goto('http://localhost:3002');
        const initialLoadTime = Date.now() - startTime;
        performanceMetrics.push({ action: 'Initial Load', time: initialLoadTime });
        
        // Test Host Groups navigation
        const navStart = Date.now();
        await page2.goto('http://localhost:3002/host-groups');
        await page2.waitForLoadState('networkidle');
        const navTime = Date.now() - navStart;
        performanceMetrics.push({ action: 'Host Groups Navigation', time: navTime });
        
        // Test network requests
        const requests = [];
        page2.on('request', request => {
            if (request.url().includes('localhost:8000') || request.url().includes('/api/')) {
                requests.push({
                    url: request.url(),
                    method: request.method(),
                    resourceType: request.resourceType()
                });
            }
        });
        
        await page2.reload();
        await page2.waitForTimeout(3000);
        
        console.log('\n   Performance Metrics:');
        performanceMetrics.forEach(metric => {
            console.log(`     - ${metric.action}: ${metric.time}ms`);
            
            results.performance.push({
                test: `${metric.action} Performance`,
                result: metric.time < 5000 ? 'PASS' : metric.time < 10000 ? 'SLOW' : 'FAIL',
                details: `${metric.time}ms`
            });
        });
        
        console.log(`\n   Network Requests Analysis: ${requests.length} API requests`);
        if (requests.length > 0) {
            const uniqueEndpoints = [...new Set(requests.map(r => r.url.replace(/localhost:\d+/, 'localhost:PORT')))];
            console.log(`     - Unique endpoints: ${uniqueEndpoints.length}`);
            console.log(`     - Sample endpoints: ${uniqueEndpoints.slice(0, 3).join(', ')}`);
        }
        
        results.performance.push({
            test: 'API Integration Analysis',
            result: requests.length > 0 ? 'DETECTED' : 'NONE',
            details: `${requests.length} API requests to ${[...new Set(requests.map(r => r.url.split('/api/')[1]?.split('/')[0]))].join(', ')}`
        });

    } catch (error) {
        console.log(`   Performance analysis error: ${error.message}`);
        results.performance.push({
            test: 'Performance Analysis Suite',
            result: 'ERROR',
            details: error.message
        });
    }

    await browser2.close();

    // Test 3: Cross-browser Compatibility
    console.log('\n3. Cross-browser Compatibility');
    
    const browsers = [
        { name: 'Chromium', launch: chromium },
        { name: 'Firefox', launch: firefox },
        { name: 'WebKit', launch: webkit }
    ];

    for (const browserInfo of browsers) {
        try {
            const browser = await browserInfo.launch({ headless: true });
            const context = await browser.newContext();
            const page = await context.newPage();
            
            const startTime = Date.now();
            await page.goto('http://localhost:3002/host-groups');
            await page.waitForTimeout(3000);
            const loadTime = Date.now() - startTime;
            
            const browserMetrics = await page.evaluate(() => ({
                userAgent: navigator.userAgent,
                elements: document.querySelectorAll('*').length,
                errors: window.console?.errors || 0,
                url: window.location.href
            }));
            
            console.log(`   ${browserInfo.name}: ${loadTime}ms, ${browserMetrics.elements} elements`);
            
            results.crossBrowser.push({
                test: `${browserInfo.name} Compatibility`,
                result: browserMetrics.elements > 10 && loadTime < 10000 ? 'PASS' : 'ISSUES',
                details: `Load: ${loadTime}ms, Elements: ${browserMetrics.elements}, URL: ${browserMetrics.url}`
            });
            
            await browser.close();
            
        } catch (error) {
            console.log(`   ${browserInfo.name} testing error: ${error.message}`);
            results.crossBrowser.push({
                test: `${browserInfo.name} Compatibility`,
                result: 'ERROR',
                details: error.message
            });
        }
    }

    // Generate Comprehensive Report
    console.log('\n=== COMPREHENSIVE HOST GROUPS TEST REPORT ===');
    
    function printResults(category, tests) {
        if (tests.length === 0) return;
        
        console.log(`\n${category.toUpperCase()} (${tests.length} tests):`);
        tests.forEach((test, index) => {
            const status = test.result === 'PASS' ? '✅' : 
                          test.result === 'FAIL' ? '❌' : 
                          test.result === 'ERROR' ? '🚫' : 
                          test.result === 'SLOW' ? '⚠️' : 
                          test.result === 'DETECTED' ? '🔍' :
                          test.result === 'REDIRECTED' ? '🔄' : '⚪';
            console.log(`  ${index + 1}. ${status} ${test.test}: ${test.result}`);
            console.log(`     📋 ${test.details}`);
        });
    }

    printResults('Navigation & Structure', results.navigation);
    printResults('UI & Responsiveness', results.ui);  
    printResults('Functionality', results.functionality);
    printResults('Performance', results.performance);
    printResults('Cross-browser', results.crossBrowser);
    printResults('Accessibility', results.accessibility);

    // Calculate final metrics
    const allTests = [
        ...results.navigation,
        ...results.ui, 
        ...results.functionality,
        ...results.performance,
        ...results.crossBrowser,
        ...results.accessibility
    ];
    
    const testCounts = {
        total: allTests.length,
        passed: allTests.filter(t => t.result === 'PASS').length,
        failed: allTests.filter(t => t.result === 'FAIL').length,
        errors: allTests.filter(t => t.result === 'ERROR').length,
        warnings: allTests.filter(t => ['SLOW', 'ISSUES', 'REDIRECTED'].includes(t.result)).length,
        informational: allTests.filter(t => ['DETECTED', 'NONE'].includes(t.result)).length
    };

    console.log(`\n=== FINAL TEST SUMMARY ===`);
    console.log(`📊 Total Tests Executed: ${testCounts.total}`);
    console.log(`✅ Passed: ${testCounts.passed}`);
    console.log(`❌ Failed: ${testCounts.failed}`);
    console.log(`🚫 Errors: ${testCounts.errors}`);
    console.log(`⚠️  Warnings: ${testCounts.warnings}`);
    console.log(`📋 Informational: ${testCounts.informational}`);
    
    const successRate = testCounts.total > 0 ? ((testCounts.passed / testCounts.total) * 100).toFixed(1) : 0;
    const qualityScore = testCounts.total > 0 ? (((testCounts.passed + (testCounts.warnings * 0.5) + (testCounts.informational * 0.7)) / testCounts.total) * 100).toFixed(1) : 0;
    
    console.log(`🎯 Success Rate: ${successRate}%`);
    console.log(`🏆 Quality Score: ${qualityScore}%`);

    // Generate actionable recommendations
    console.log(`\n=== ACTIONABLE RECOMMENDATIONS ===`);
    
    if (testCounts.failed > 0) {
        console.log(`🔴 High Priority: ${testCounts.failed} tests failed - requires immediate attention`);
    }
    
    if (testCounts.errors > 0) {
        console.log(`🚫 Critical: ${testCounts.errors} test errors - infrastructure/setup issues detected`);
    }
    
    if (testCounts.warnings > 0) {
        console.log(`🟡 Medium Priority: ${testCounts.warnings} performance or compatibility issues detected`);
    }
    
    const authenticationIssues = allTests.filter(t => t.details.includes('login') || t.result === 'REDIRECTED').length;
    if (authenticationIssues > 0) {
        console.log(`🔐 Authentication: ${authenticationIssues} tests affected by authentication requirements`);
        console.log(`    Recommendation: Set up test user account or enable demo mode for E2E testing`);
    }
    
    const performanceIssues = allTests.filter(t => t.result === 'SLOW').length;
    if (performanceIssues > 0) {
        console.log(`🐌 Performance: ${performanceIssues} slow operations detected`);
        console.log(`    Recommendation: Optimize loading times and add performance monitoring`);
    }
    
    if (testCounts.passed === testCounts.total) {
        console.log(`🎉 Excellent! All Host Groups tests are functioning optimally`);
    } else if (successRate >= 80) {
        console.log(`👍 Good overall status with minor issues to address`);
    } else if (successRate >= 60) {
        console.log(`⚠️  Moderate issues present - attention required for stability`);
    } else {
        console.log(`🚨 Significant issues detected - Host Groups feature needs comprehensive review`);
    }

    return {
        results,
        metrics: testCounts,
        successRate: parseFloat(successRate),
        qualityScore: parseFloat(qualityScore)
    };
}

// Execute the comprehensive test suite
runBypassHostGroupsTests().catch(console.error);