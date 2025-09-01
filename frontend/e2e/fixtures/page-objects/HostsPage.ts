import { Page, expect } from '@playwright/test';
import { BasePage } from './BasePage';

export class HostsPage extends BasePage {
  private readonly addHostButton = 'button:has-text("Add Host")';
  private readonly hostTable = 'table';
  private readonly selectAllCheckbox = 'input[type="checkbox"][aria-label="Select all"]';
  private readonly bulkActionsMenu = 'button:has-text("Bulk Actions")';
  
  constructor(page: Page) {
    super(page);
  }

  /**
   * Navigate to hosts page
   */
  async goto() {
    await this.page.goto('/hosts');
    await this.waitForPageLoad();
  }

  /**
   * Add a new host
   */
  async addHost(hostData: {
    hostname: string;
    ipAddress: string;
    username: string;
    password: string;
    port: number;
    osType: string;
  }) {
    // Click add host button
    await this.page.click(this.addHostButton);
    
    // Wait for dialog
    await this.page.waitForSelector('[role="dialog"]');
    
    // Fill form
    await this.page.fill('input[name="hostname"]', hostData.hostname);
    await this.page.fill('input[name="ip_address"]', hostData.ipAddress);
    await this.page.fill('input[name="ssh_username"]', hostData.username);
    await this.page.fill('input[name="ssh_password"]', hostData.password);
    await this.page.fill('input[name="ssh_port"]', hostData.port.toString());
    await this.page.selectOption('select[name="os_type"]', hostData.osType);
    
    // Submit
    await this.page.click('button:has-text("Add")');
    
    // Wait for success
    await this.waitForSnackbar('Host added successfully');
    await this.page.waitForSelector('[role="dialog"]', { state: 'hidden' });
  }

  /**
   * Check if a host exists in the table
   */
  async hasHost(hostname: string): Promise<boolean> {
    const hostRow = this.page.locator(`tr:has-text("${hostname}")`);
    return await hostRow.isVisible();
  }

  /**
   * Select all hosts
   */
  async selectAllHosts() {
    await this.page.click(this.selectAllCheckbox);
  }

  /**
   * Select a specific host
   */
  async selectHost(hostname: string) {
    const hostRow = this.page.locator(`tr:has-text("${hostname}")`);
    const checkbox = hostRow.locator('input[type="checkbox"]');
    await checkbox.click();
  }

  /**
   * Perform bulk action
   */
  async bulkAction(action: 'scan' | 'delete' | 'update') {
    await this.page.click(this.bulkActionsMenu);
    await this.page.click(`[role="menuitem"]:has-text("${action}")`);
  }

  /**
   * Edit a host
   */
  async editHost(hostname: string, updates: Partial<{
    hostname: string;
    ipAddress: string;
    username: string;
    password: string;
    port: number;
  }>) {
    const hostRow = this.page.locator(`tr:has-text("${hostname}")`);
    const editButton = hostRow.locator('button[aria-label="Edit"]');
    await editButton.click();
    
    // Wait for dialog
    await this.page.waitForSelector('[role="dialog"]');
    
    // Update fields
    if (updates.hostname) {
      await this.page.fill('input[name="hostname"]', updates.hostname);
    }
    if (updates.ipAddress) {
      await this.page.fill('input[name="ip_address"]', updates.ipAddress);
    }
    if (updates.username) {
      await this.page.fill('input[name="ssh_username"]', updates.username);
    }
    if (updates.password) {
      await this.page.fill('input[name="ssh_password"]', updates.password);
    }
    if (updates.port) {
      await this.page.fill('input[name="ssh_port"]', updates.port.toString());
    }
    
    // Save
    await this.page.click('button:has-text("Save")');
    await this.waitForSnackbar('Host updated successfully');
  }

  /**
   * Delete a host
   */
  async deleteHost(hostname: string) {
    const hostRow = this.page.locator(`tr:has-text("${hostname}")`);
    const deleteButton = hostRow.locator('button[aria-label="Delete"]');
    await deleteButton.click();
    
    // Confirm deletion
    await this.page.click('button:has-text("Confirm")');
    await this.waitForSnackbar('Host deleted successfully');
  }

  /**
   * Get host count
   */
  async getHostCount(): Promise<number> {
    const rows = await this.page.locator('tbody tr').all();
    return rows.length;
  }

  /**
   * Search for hosts
   */
  async searchHosts(query: string) {
    await this.page.fill('input[placeholder="Search hosts..."]', query);
    await this.page.waitForTimeout(500); // Debounce
  }

  /**
   * Filter hosts by OS type
   */
  async filterByOsType(osType: 'linux' | 'windows' | 'all') {
    await this.page.selectOption('select[aria-label="Filter by OS"]', osType);
  }

  /**
   * Sort hosts
   */
  async sortBy(column: 'hostname' | 'ip_address' | 'os_type' | 'last_scan') {
    const header = this.page.locator(`th:has-text("${column}")`);
    await header.click();
  }
}