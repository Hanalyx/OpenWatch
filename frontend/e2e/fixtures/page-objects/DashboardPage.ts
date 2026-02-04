import { Page, expect } from '@playwright/test';
import { BasePage } from './BasePage';

export class DashboardPage extends BasePage {
  private readonly pageTitle = 'h4:has-text("Security Compliance Dashboard")';
  private readonly statsCards = '.MuiCard-root';
  private readonly quickActionsSection = 'text=Quick Actions';
  private readonly recentScansSection = 'text=Recent Scans';
  private readonly complianceOverviewSection = 'text=Compliance Overview';
  // Multiple selector fallbacks for better resilience
  private readonly logoutMenuItemSelectors = [
    '[role="menuitem"]:has-text("Logout")',
    '[role="menuitem"]:has-text("Log out")',
    '[role="menuitem"]:has-text("Sign out")',
    'li:has-text("Logout")',
  ];
  private readonly userMenuButtonSelectors = [
    '.MuiIconButton-root:has(.MuiAvatar-root)',
    '[data-testid="user-menu"]',
    '[aria-label*="account"]',
    '[aria-label*="profile"]',
    'button:has(.MuiAvatar-root)',
  ];
  
  // Navigation items - must match paths in Layout.tsx menuItems
  private readonly navItems = {
    dashboard: 'a[href="/"]',
    hosts: 'a[href="/hosts"]',
    hostGroups: 'a[href="/host-groups"]',
    content: 'a[href="/content"]',
    scans: 'a[href="/scans"]',
    users: 'a[href="/users"]',
    settings: 'a[href="/settings"]'
  };

  constructor(page: Page) {
    super(page);
  }

  /**
   * Navigate to dashboard (root path)
   */
  async goto() {
    await this.page.goto('/');
    await this.waitForPageLoad();
  }

  /**
   * Check if dashboard is displayed
   */
  async isDashboardDisplayed(): Promise<boolean> {
    return await this.page.locator(this.pageTitle).isVisible();
  }

  /**
   * Get dashboard statistics
   */
  async getStatistics() {
    const stats = {
      totalHosts: 0,
      activeScans: 0,
      failedScans: 0,
      complianceScore: 0
    };

    // Wait for stats to load
    await this.page.waitForSelector(this.statsCards);
    
    const cards = await this.page.locator(this.statsCards).all();
    
    for (const card of cards) {
      const title = await card.locator('.MuiTypography-h6').textContent();
      const value = await card.locator('.MuiTypography-h4').textContent();
      
      if (title?.includes('Total Hosts')) {
        stats.totalHosts = parseInt(value || '0');
      } else if (title?.includes('Active Scans')) {
        stats.activeScans = parseInt(value || '0');
      } else if (title?.includes('Failed Scans')) {
        stats.failedScans = parseInt(value || '0');
      } else if (title?.includes('Compliance Score')) {
        stats.complianceScore = parseFloat(value?.replace('%', '') || '0');
      }
    }
    
    return stats;
  }

  /**
   * Navigate to a specific section
   */
  async navigateTo(section: keyof typeof this.navItems) {
    await this.page.click(this.navItems[section]);
    await this.waitForPageLoad();
  }

  /**
   * Click on a quick action button
   */
  async clickQuickAction(actionName: string) {
    const quickActionButton = this.page.locator(`button:has-text("${actionName}")`);
    await quickActionButton.click();
  }

  /**
   * Get recent scans from dashboard
   */
  async getRecentScans() {
    const scans = [];
    const scanRows = await this.page.locator('table tbody tr').all();
    
    for (const row of scanRows) {
      const cells = await row.locator('td').all();
      if (cells.length >= 4) {
        scans.push({
          hostName: await cells[0].textContent(),
          scanType: await cells[1].textContent(),
          status: await cells[2].textContent(),
          timestamp: await cells[3].textContent()
        });
      }
    }
    
    return scans;
  }

  /**
   * Check if user menu is visible
   */
  async isUserMenuVisible(): Promise<boolean> {
    return await this.page.locator(this.userAvatar).isVisible();
  }

  /**
   * Open user menu with fallback selectors
   */
  async openUserMenu() {
    // Try each selector until one works
    for (const selector of this.userMenuButtonSelectors) {
      const element = this.page.locator(selector).first();
      if (await element.isVisible({ timeout: 1000 }).catch(() => false)) {
        await element.click();
        return;
      }
    }
    // Fallback to first selector with extended timeout
    await this.page.click(this.userMenuButtonSelectors[0], { timeout: 10000 });
  }

  /**
   * Logout from dashboard with fallback selectors
   */
  async logout() {
    await this.openUserMenu();
    // Wait for menu to appear
    await this.page.waitForTimeout(500);

    // Try each logout selector
    for (const selector of this.logoutMenuItemSelectors) {
      const element = this.page.locator(selector).first();
      if (await element.isVisible({ timeout: 1000 }).catch(() => false)) {
        await element.click();
        await this.page.waitForURL('**/login', { timeout: 10000 });
        return;
      }
    }
    // Fallback
    await this.page.click(this.logoutMenuItemSelectors[0], { timeout: 5000 });
    await this.page.waitForURL('**/login', { timeout: 10000 });
  }

  /**
   * Check if section is visible
   */
  async isSectionVisible(sectionName: 'quickActions' | 'recentScans' | 'complianceOverview'): Promise<boolean> {
    const sectionMap = {
      quickActions: this.quickActionsSection,
      recentScans: this.recentScansSection,
      complianceOverview: this.complianceOverviewSection
    };
    
    return await this.page.locator(sectionMap[sectionName]).isVisible();
  }

  /**
   * Get compliance chart data
   */
  async getComplianceChartData() {
    // This would interact with the chart component
    // For now, we'll check if the chart container exists
    const chartContainer = await this.page.locator('canvas').first();
    return await chartContainer.isVisible();
  }

  /**
   * Refresh dashboard data
   */
  async refreshDashboard() {
    await this.page.reload();
    await this.waitForPageLoad();
  }
}