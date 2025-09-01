import { Page, expect } from '@playwright/test';
import { BasePage } from './BasePage';

export class ScansPage extends BasePage {
  private readonly newScanButton = 'button:has-text("New Scan")';
  private readonly scanTable = 'table';
  private readonly scanStatusSelector = '.scan-status';
  
  constructor(page: Page) {
    super(page);
  }

  /**
   * Navigate to scans page
   */
  async goto() {
    await this.page.goto('/scans');
    await this.waitForPageLoad();
  }

  /**
   * Create a new scan
   */
  async createScan(scanData: {
    name: string;
    hosts: string[];
    scapContent: string;
    profile: string;
  }) {
    // Click new scan button
    await this.page.click(this.newScanButton);
    
    // Wait for dialog
    await this.page.waitForSelector('[role="dialog"]');
    
    // Fill scan details
    await this.page.fill('input[name="scanName"]', scanData.name);
    
    // Select hosts
    for (const host of scanData.hosts) {
      const hostCheckbox = this.page.locator(`input[type="checkbox"][value="${host}"]`);
      await hostCheckbox.click();
    }
    
    // Select SCAP content
    await this.page.selectOption('select[name="scapContent"]', scanData.scapContent);
    
    // Select profile
    await this.page.selectOption('select[name="profile"]', scanData.profile);
    
    // Start scan
    await this.page.click('button:has-text("Start Scan")');
    
    // Wait for scan to be created
    await this.waitForSnackbar('Scan started successfully');
    await this.page.waitForSelector('[role="dialog"]', { state: 'hidden' });
  }

  /**
   * Wait for scan to complete
   */
  async waitForScanToComplete(timeout = 300000) {
    // Poll for scan completion
    const startTime = Date.now();
    
    while (Date.now() - startTime < timeout) {
      const runningScans = await this.page.locator('.scan-status:has-text("Running")').count();
      
      if (runningScans === 0) {
        // Check for completed scans
        const completedScans = await this.page.locator('.scan-status:has-text("Completed")').count();
        if (completedScans > 0) {
          return;
        }
      }
      
      // Wait before next check
      await this.page.waitForTimeout(5000);
      
      // Refresh the page to get latest status
      await this.page.reload();
    }
    
    throw new Error(`Scan did not complete within ${timeout}ms`);
  }

  /**
   * View scan results
   */
  async viewScanResults(scanName: string) {
    const scanRow = this.page.locator(`tr:has-text("${scanName}")`);
    const viewButton = scanRow.locator('button:has-text("View Results")');
    await viewButton.click();
    
    // Wait for results page
    await this.page.waitForURL('**/scans/*/results');
  }

  /**
   * View latest scan results
   */
  async viewLatestScanResults() {
    const firstViewButton = this.page.locator('button:has-text("View Results")').first();
    await firstViewButton.click();
    
    // Wait for results page
    await this.page.waitForURL('**/scans/*/results');
  }

  /**
   * Get scan status
   */
  async getScanStatus(scanName: string): Promise<string> {
    const scanRow = this.page.locator(`tr:has-text("${scanName}")`);
    const status = await scanRow.locator('.scan-status').textContent();
    return status || '';
  }

  /**
   * Cancel a running scan
   */
  async cancelScan(scanName: string) {
    const scanRow = this.page.locator(`tr:has-text("${scanName}")`);
    const cancelButton = scanRow.locator('button:has-text("Cancel")');
    
    if (await cancelButton.isVisible()) {
      await cancelButton.click();
      await this.page.click('button:has-text("Confirm")');
      await this.waitForSnackbar('Scan cancelled');
    }
  }

  /**
   * Delete a scan
   */
  async deleteScan(scanName: string) {
    const scanRow = this.page.locator(`tr:has-text("${scanName}")`);
    const deleteButton = scanRow.locator('button[aria-label="Delete"]');
    await deleteButton.click();
    
    // Confirm deletion
    await this.page.click('button:has-text("Confirm")');
    await this.waitForSnackbar('Scan deleted successfully');
  }

  /**
   * Get scan count by status
   */
  async getScanCountByStatus(status: 'Running' | 'Completed' | 'Failed' | 'Cancelled'): Promise<number> {
    const scans = await this.page.locator(`.scan-status:has-text("${status}")`).count();
    return scans;
  }

  /**
   * Re-run a scan
   */
  async rerunScan(scanName: string) {
    const scanRow = this.page.locator(`tr:has-text("${scanName}")`);
    const rerunButton = scanRow.locator('button:has-text("Re-run")');
    await rerunButton.click();
    
    // Confirm re-run
    await this.page.click('button:has-text("Confirm")');
    await this.waitForSnackbar('Scan re-run initiated');
  }

  /**
   * Export scan results
   */
  async exportScanResults(scanName: string, format: 'pdf' | 'csv' | 'json') {
    const scanRow = this.page.locator(`tr:has-text("${scanName}")`);
    const exportButton = scanRow.locator('button[aria-label="Export"]');
    await exportButton.click();
    
    // Select format
    await this.page.click(`[role="menuitem"]:has-text("${format.toUpperCase()}")`);
    
    // Wait for download
    const [download] = await Promise.all([
      this.page.waitForEvent('download'),
      this.page.click('button:has-text("Download")')
    ]);
    
    return download;
  }

  /**
   * Schedule a scan
   */
  async scheduleScan(scanData: {
    name: string;
    hosts: string[];
    scapContent: string;
    profile: string;
    schedule: {
      frequency: 'daily' | 'weekly' | 'monthly';
      time: string;
      dayOfWeek?: number;
      dayOfMonth?: number;
    };
  }) {
    await this.page.click('button:has-text("Schedule Scan")');
    
    // Fill basic scan details
    await this.page.fill('input[name="scanName"]', scanData.name);
    
    // Configure schedule
    await this.page.selectOption('select[name="frequency"]', scanData.schedule.frequency);
    await this.page.fill('input[name="time"]', scanData.schedule.time);
    
    if (scanData.schedule.dayOfWeek !== undefined) {
      await this.page.selectOption('select[name="dayOfWeek"]', scanData.schedule.dayOfWeek.toString());
    }
    
    if (scanData.schedule.dayOfMonth !== undefined) {
      await this.page.fill('input[name="dayOfMonth"]', scanData.schedule.dayOfMonth.toString());
    }
    
    // Save schedule
    await this.page.click('button:has-text("Save Schedule")');
    await this.waitForSnackbar('Scan scheduled successfully');
  }
}