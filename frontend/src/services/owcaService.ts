/**
 * OWCA (OpenWatch Compliance Algorithm) Service
 *
 * Provides TypeScript client for OWCA REST API endpoints.
 * OWCA is the single source of truth for all compliance calculations.
 *
 * Security: All requests use authenticated API client with JWT tokens.
 * OWCA endpoints require authentication and RBAC permissions.
 */

import { api } from './api';

/**
 * OWCA Compliance Tier Classifications
 *
 * Tiers are calculated by OWCA based on compliance score:
 * - EXCELLENT: 90-100% compliance
 * - GOOD: 75-89% compliance
 * - FAIR: 60-74% compliance
 * - POOR: <60% compliance
 */
export type ComplianceTier = 'excellent' | 'good' | 'fair' | 'poor';

/**
 * OWCA Drift Severity Levels
 *
 * Measures how far a host has drifted from its baseline:
 * - CRITICAL: >10% decline from baseline
 * - HIGH: 5-10% decline
 * - MEDIUM: 2-5% decline
 * - LOW: <2% change
 * - NONE: No significant drift
 */
export type DriftSeverity = 'critical' | 'high' | 'medium' | 'low' | 'none';

/**
 * Severity breakdown for compliance metrics
 *
 * Provides detailed breakdown of rules by severity level.
 * All totals are validated (total = passed + failed).
 */
export interface SeverityBreakdown {
  critical_passed: number;
  critical_failed: number;
  critical_total: number;
  high_passed: number;
  high_failed: number;
  high_total: number;
  medium_passed: number;
  medium_failed: number;
  medium_total: number;
  low_passed: number;
  low_failed: number;
  low_total: number;
}

/**
 * OWCA Compliance Score for a single host
 *
 * Canonical compliance score representation used throughout OpenWatch.
 * Calculated using OWCA's formula: (passed_rules / total_rules) * 100
 */
export interface ComplianceScore {
  entity_id: string;
  entity_type: 'host' | 'group' | 'organization';
  overall_score: number;
  tier: ComplianceTier;
  passed_rules: number;
  failed_rules: number;
  total_rules: number;
  severity_breakdown: SeverityBreakdown;
  calculated_at: string;
  scan_id?: string;
}

/**
 * Fleet-wide statistics across all hosts
 *
 * Aggregates compliance data for entire organization.
 * Used by Dashboard for high-level metrics.
 */
export interface FleetStatistics {
  total_hosts: number;
  online_hosts: number;
  offline_hosts: number;
  scanned_hosts: number;
  never_scanned: number;
  needs_scan: number;
  average_compliance: number;
  median_compliance: number;
  hosts_excellent: number;
  hosts_good: number;
  hosts_fair: number;
  hosts_poor: number;
  total_critical_issues: number;
  total_high_issues: number;
  total_medium_issues: number;
  total_low_issues: number;
  hosts_with_critical: number;
  calculated_at: string;
}

/**
 * Baseline drift analysis for a single host
 *
 * Compares current compliance against established baseline
 * per NIST SP 800-137 Continuous Monitoring guidelines.
 */
export interface BaselineDrift {
  host_id: string;
  baseline_id: string;
  current_score: number;
  baseline_score: number;
  drift_percentage: number;
  drift_severity: DriftSeverity;
  rules_changed: number;
  newly_failed: number;
  newly_passed: number;
  critical_regressions: number;
  high_regressions: number;
  detected_at: string;
}

/**
 * Priority host for remediation
 *
 * Hosts prioritized based on:
 * - Number of critical issues
 * - Number of high issues
 * - Overall compliance score
 */
export interface PriorityHost {
  rank: number;
  host_id: string;
  hostname: string;
  ip_address: string;
  compliance_score: number;
  critical_issues: number;
  high_issues: number;
  priority_score: number;
  last_scan: string;
}

/**
 * OWCA Service Class
 *
 * Provides methods to interact with OWCA REST API.
 * All methods use the authenticated API client.
 */
class OWCAService {
  /**
   * Get compliance score for a specific host
   *
   * Uses OWCA's canonical score calculation.
   * Returns null if host has no scans.
   *
   * Security: Requires authentication and read permission for hosts.
   *
   * @param hostId - UUID of the host
   * @returns ComplianceScore or null if no scans exist
   * @throws Error if API request fails
   */
  async getHostComplianceScore(hostId: string): Promise<ComplianceScore | null> {
    try {
      const response = await api.get<ComplianceScore>(`/api/owca/host/${hostId}/score`);
      return response || null;
    } catch (error) {
      console.error(`Failed to fetch OWCA score for host ${hostId}:`, error);
      throw error;
    }
  }

  /**
   * Get fleet-wide statistics
   *
   * Aggregates compliance data across all hosts.
   * Used by Dashboard for overview metrics.
   *
   * Security: Requires authentication and read permission for fleet data.
   *
   * @returns FleetStatistics with aggregated metrics
   * @throws Error if API request fails
   */
  async getFleetStatistics(): Promise<FleetStatistics> {
    try {
      const response = await api.get<FleetStatistics>('/api/owca/fleet/statistics');
      return response;
    } catch (error) {
      console.error('Failed to fetch OWCA fleet statistics:', error);
      throw error;
    }
  }

  /**
   * Detect baseline drift for a specific host
   *
   * Compares current compliance against active baseline.
   * Returns null if no active baseline exists.
   *
   * Security: Requires authentication and read permission for hosts.
   *
   * @param hostId - UUID of the host
   * @returns BaselineDrift analysis or null if no baseline
   * @throws Error if API request fails
   */
  async detectBaselineDrift(hostId: string): Promise<BaselineDrift | null> {
    try {
      const response = await api.get<BaselineDrift>(`/api/owca/host/${hostId}/drift`);
      return response || null;
    } catch (error) {
      console.error(`Failed to detect baseline drift for host ${hostId}:`, error);
      throw error;
    }
  }

  /**
   * Get hosts with significant baseline drift
   *
   * Returns hosts where compliance has drifted from baseline
   * by more than the specified severity threshold.
   *
   * Security: Requires authentication and read permission for fleet data.
   *
   * @param minSeverity - Minimum drift severity (default: medium)
   * @returns List of BaselineDrift objects sorted by severity
   * @throws Error if API request fails
   */
  async getHostsWithDrift(minSeverity: DriftSeverity = 'medium'): Promise<BaselineDrift[]> {
    try {
      const response = await api.get<BaselineDrift[]>(
        `/api/owca/fleet/drift?min_severity=${minSeverity}`
      );
      return response || [];
    } catch (error) {
      console.error('Failed to fetch hosts with drift:', error);
      throw error;
    }
  }

  /**
   * Get top priority hosts for remediation
   *
   * Hosts are prioritized based on:
   * - Number of critical issues
   * - Number of high issues
   * - Overall compliance score
   *
   * Security: Requires authentication and read permission for fleet data.
   *
   * @param limit - Maximum number of hosts to return (1-100, default: 10)
   * @returns List of priority hosts ranked by priority score
   * @throws Error if API request fails
   */
  async getTopPriorityHosts(limit: number = 10): Promise<PriorityHost[]> {
    try {
      const response = await api.get<PriorityHost[]>(
        `/api/owca/fleet/priority-hosts?limit=${limit}`
      );
      return response || [];
    } catch (error) {
      console.error('Failed to fetch top priority hosts:', error);
      throw error;
    }
  }

  /**
   * Get OWCA algorithm version
   *
   * Returns current OWCA version and metadata.
   * Useful for debugging and compatibility checks.
   *
   * Security: Requires authentication.
   *
   * @returns OWCA version information
   * @throws Error if API request fails
   */
  async getVersion(): Promise<{
    algorithm: string;
    version: string;
    description: string;
    layers: string[];
  }> {
    try {
      const response = await api.get('/api/owca/version');
      return response;
    } catch (error) {
      console.error('Failed to fetch OWCA version:', error);
      throw error;
    }
  }
}

// Export singleton instance
export const owcaService = new OWCAService();

// Export class for testing
export default OWCAService;
