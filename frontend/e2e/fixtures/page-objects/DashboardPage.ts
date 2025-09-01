import { Page, expect } from '@playwright/test';
import { BasePage } from './BasePage';

export class DashboardPage extends BasePage {
  private readonly pageTitle = 'h4:has-text("Security Compliance Dashboard")';
  private readonly statsCards = '.MuiCard-root';
  private readonly quickActionsSection = 'text=Quick Actions';
  private readonly recentScansSection = 'text=Recent Scans';
  private readonly complianceOverviewSection = 'text=Compliance Overview';
  private readonly logoutButton = 'button:has-text("Logout")';
  private readonly userAvatar = '[data-testid="user-avatar"]';
  
  // Navigation items
  private readonly navItems = {
    dashboard: 'a[href="/dashboard"]',
    hosts: 'a[href="/hosts"]',
    hostGroups: 'a[href="/host-groups"]',
    content: 'a[href="/scap-content"]',
    scans: 'a[href="/scans"]',
    users: 'a[href="/users"]',
    settings: 'a[href="/settings"]'
  };

  constructor(page: Page) {
    super(page);
  }

  /**
   * Navigate to dashboard
   */
  async goto() {
    await this.page.goto('/dashboard');
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
   * Open user menu
   */
  async openUserMenu() {
    await this.page.click(this.userAvatar);
  }

  /**
   * Logout from dashboard
   */
  async logout() {
    await this.openUserMenu();
    await this.page.click(this.logoutButton);
    await this.page.waitForURL('**/login');
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