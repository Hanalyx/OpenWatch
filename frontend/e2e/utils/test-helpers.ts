import { Page } from '@playwright/test';

/**
 * Wait for network to be idle
 */
export async function waitForNetworkIdle(page: Page, timeout = 5000) {
  await page.waitForLoadState('networkidle', { timeout });
}

/**
 * Mock API response
 */
export async function mockApiResponse(page: Page, url: string | RegExp, response: any) {
  await page.route(url, async (route) => {
    await route.fulfill({
      status: response.status || 200,
      contentType: 'application/json',
      body: JSON.stringify(response.body || {})
    });
  });
}

/**
 * Upload file helper
 */
export async function uploadFile(page: Page, selector: string, filePath: string) {
  const fileInput = await page.locator(selector);
  await fileInput.setInputFiles(filePath);
}

/**
 * Generate random test data
 */
export const generateTestData = {
  hostname: () => `test-host-${Date.now()}-${Math.random().toString(36).substring(7)}`,
  ipAddress: () => {
    const octets = Array.from({ length: 4 }, () => Math.floor(Math.random() * 255));
    return octets.join('.');
  },
  username: () => `testuser${Date.now()}`,
  email: () => `test${Date.now()}@openwatch.local`,
  password: () => `Test${Date.now()}!@#`
};

/**
 * Retry helper for flaky operations
 */
export async function retry<T>(
  fn: () => Promise<T>,
  retries = 3,
  delay = 1000
): Promise<T> {
  let lastError: Error | undefined;
  
  for (let i = 0; i < retries; i++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;
      if (i < retries - 1) {
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  
  throw lastError;
}

/**
 * Check if element is in viewport
 */
export async function isInViewport(page: Page, selector: string): Promise<boolean> {
  return await page.evaluate((sel) => {
    const element = document.querySelector(sel);
    if (!element) return false;
    
    const rect = element.getBoundingClientRect();
    return (
      rect.top >= 0 &&
      rect.left >= 0 &&
      rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
      rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
  }, selector);
}

/**
 * Scroll to element
 */
export async function scrollToElement(page: Page, selector: string) {
  await page.evaluate((sel) => {
    const element = document.querySelector(sel);
    element?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }, selector);
  
  // Wait for scroll animation
  await page.waitForTimeout(500);
}

/**
 * Clear all application data
 */
export async function clearAppData(page: Page) {
  await page.evaluate(() => {
    localStorage.clear();
    sessionStorage.clear();
  });
  
  // Clear cookies
  const context = page.context();
  await context.clearCookies();
}

/**
 * Take annotated screenshot
 */
export async function takeAnnotatedScreenshot(
  page: Page,
  name: string,
  annotations?: { selector: string; text: string }[]
) {
  // Add annotations if provided
  if (annotations) {
    for (const annotation of annotations) {
      await page.evaluate(({ selector, text }) => {
        const element = document.querySelector(selector);
        if (element) {
          const badge = document.createElement('div');
          badge.textContent = text;
          badge.style.cssText = `
            position: absolute;
            background: red;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            z-index: 10000;
          `;
          element.appendChild(badge);
        }
      }, annotation);
    }
  }
  
  await page.screenshot({ 
    path: `test-results/screenshots/${name}.png`,
    fullPage: true 
  });
}

/**
 * Wait for element to be stable (not moving/animating)
 */
export async function waitForElementStable(page: Page, selector: string, timeout = 5000) {
  const element = page.locator(selector);
  await element.waitFor({ state: 'visible' });
  
  let previousBox = await element.boundingBox();
  const startTime = Date.now();
  
  while (Date.now() - startTime < timeout) {
    await page.waitForTimeout(100);
    const currentBox = await element.boundingBox();
    
    if (previousBox && currentBox &&
        previousBox.x === currentBox.x &&
        previousBox.y === currentBox.y &&
        previousBox.width === currentBox.width &&
        previousBox.height === currentBox.height) {
      return;
    }
    
    previousBox = currentBox;
  }
  
  throw new Error(`Element ${selector} did not stabilize within ${timeout}ms`);
}