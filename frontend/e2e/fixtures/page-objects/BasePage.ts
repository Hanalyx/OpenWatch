import { Page, expect } from '@playwright/test';

export class BasePage {
  constructor(protected page: Page) {}

  /**
   * Navigate to a specific URL
   */
  async goto(url: string) {
    await this.page.goto(url);
  }

  /**
   * Wait for page to be loaded
   */
  async waitForPageLoad() {
    await this.page.waitForLoadState('networkidle');
  }

  /**
   * Check if user is authenticated by looking for auth token
   */
  async isAuthenticated(): Promise<boolean> {
    const token = await this.page.evaluate(() => {
      return localStorage.getItem('auth_token');
    });
    return !!token;
  }

  /**
   * Get auth token from localStorage
   */
  async getAuthToken(): Promise<string | null> {
    return await this.page.evaluate(() => {
      return localStorage.getItem('auth_token');
    });
  }

  /**
   * Set auth token in localStorage
   */
  async setAuthToken(token: string) {
    await this.page.evaluate((token) => {
      localStorage.setItem('auth_token', token);
    }, token);
  }

  /**
   * Clear auth token from localStorage
   */
  async clearAuthToken() {
    await this.page.evaluate(() => {
      localStorage.removeItem('auth_token');
    });
  }

  /**
   * Wait for API response
   */
  async waitForApiResponse(urlPattern: string | RegExp) {
    return await this.page.waitForResponse(
      response => {
        const url = response.url();
        return (typeof urlPattern === 'string' ? url.includes(urlPattern) : urlPattern.test(url)) 
          && response.status() === 200;
      }
    );
  }

  /**
   * Take screenshot with descriptive name
   */
  async takeScreenshot(name: string) {
    await this.page.screenshot({ 
      path: `test-results/screenshots/${name}.png`,
      fullPage: true 
    });
  }

  /**
   * Check for error messages on page
   */
  async hasErrorMessage(message?: string): Promise<boolean> {
    if (message) {
      return await this.page.getByText(message).isVisible();
    }
    // Look for common error indicators
    const errorSelectors = [
      '[role="alert"]',
      '.MuiAlert-root',
      '[data-testid="error-message"]',
      '.error-message'
    ];
    
    for (const selector of errorSelectors) {
      const element = await this.page.locator(selector).first();
      if (await element.isVisible()) {
        return true;
      }
    }
    return false;
  }

  /**
   * Wait for snackbar notification
   */
  async waitForSnackbar(message?: string) {
    const snackbar = this.page.locator('.MuiSnackbar-root');
    await snackbar.waitFor({ state: 'visible' });
    
    if (message) {
      await expect(snackbar).toContainText(message);
    }
  }

  /**
   * Close snackbar notification
   */
  async closeSnackbar() {
    const closeButton = this.page.locator('.MuiSnackbar-root button[aria-label="close"]');
    if (await closeButton.isVisible()) {
      await closeButton.click();
    }
  }
}