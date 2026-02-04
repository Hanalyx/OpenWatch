import { Page, expect } from '@playwright/test';
import { BasePage } from './BasePage';

export class LoginPage extends BasePage {
  private readonly usernameInput = 'input[name="username"]';
  private readonly passwordInput = 'input[name="password"]';
  private readonly loginButton = 'button[type="submit"]:has-text("Sign In")';
  private readonly errorAlert = '[role="alert"]';
  private readonly forgotPasswordLink = 'a:has-text("Forgot Password")';
  private readonly registerLink = 'a:has-text("Register")';

  constructor(page: Page) {
    super(page);
  }

  /**
   * Navigate to login page
   */
  async goto() {
    await this.page.goto('/login');
    await this.waitForPageLoad();
  }

  /**
   * Fill login form
   */
  async fillLoginForm(username: string, password: string) {
    await this.page.fill(this.usernameInput, username);
    await this.page.fill(this.passwordInput, password);
  }

  /**
   * Submit login form
   */
  async submitLogin() {
    await this.page.click(this.loginButton);
  }

  /**
   * Complete login flow
   */
  async login(username: string, password: string) {
    await this.fillLoginForm(username, password);
    await this.submitLogin();
    
    // Wait for either successful navigation or error
    await Promise.race([
      this.page.waitForURL('**/dashboard', { timeout: 10000 }),
      this.page.waitForSelector(this.errorAlert, { timeout: 10000 })
    ]);
  }

  /**
   * Check if login was successful
   */
  async isLoginSuccessful(): Promise<boolean> {
    try {
      await this.page.waitForURL('**/dashboard', { timeout: 5000 });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get error message
   */
  async getErrorMessage(): Promise<string | null> {
    const errorElement = await this.page.locator(this.errorAlert).first();
    if (await errorElement.isVisible()) {
      return await errorElement.textContent();
    }
    return null;
  }

  /**
   * Check if login page is displayed
   */
  async isLoginPageDisplayed(): Promise<boolean> {
    return await this.page.locator(this.usernameInput).isVisible();
  }

  /**
   * Click forgot password link
   */
  async clickForgotPassword() {
    await this.page.click(this.forgotPasswordLink);
  }

  /**
   * Click register link
   */
  async clickRegister() {
    await this.page.click(this.registerLink);
  }

  /**
   * Check if form validation error is shown
   */
  async hasValidationError(field: 'username' | 'password'): Promise<boolean> {
    const input = field === 'username' ? this.usernameInput : this.passwordInput;
    const fieldElement = await this.page.locator(input);
    
    // Check for MUI error state
    const hasError = await fieldElement.evaluate((el) => {
      const muiInput = el.closest('.MuiTextField-root');
      return muiInput?.classList.contains('Mui-error') || false;
    });
    
    return hasError;
  }

  /**
   * Get validation error message
   */
  async getValidationErrorMessage(field: 'username' | 'password'): Promise<string | null> {
    const input = field === 'username' ? this.usernameInput : this.passwordInput;
    const errorText = await this.page.locator(`${input} ~ .MuiFormHelperText-root.Mui-error`).first();
    
    if (await errorText.isVisible()) {
      return await errorText.textContent();
    }
    return null;
  }
}