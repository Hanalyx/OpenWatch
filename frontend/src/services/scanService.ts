/**
 * ScanService - Handles all scan-related API calls
 * Provides methods for individual scans and group scanning operations
 */

import { getAuthHeaders } from '../hooks/useAuthHeaders';

interface GroupScanRequest {
  scan_name?: string;
  profile_id: string;
  priority?: string;
  template_id?: string;
}

interface GroupScanSessionResponse {
  session_id: string;
  session_name: string;
  total_hosts: number;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  created_at: string;
  estimated_completion?: string;
}

interface ScanProgressResponse {
  session_id: string;
  session_name: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress_percent: number;
  total_hosts: number;
  completed_hosts: number;
  failed_hosts: number;
  running_hosts: number;
  started_at?: string;
  estimated_completion?: string;
  individual_scans: Array<{
    scan_id: string;
    scan_name: string;
    hostname: string;
    display_name: string;
    status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
    progress: number;
    started_at?: string;
    completed_at?: string;
    compliance_score?: number;
    failed_rules?: number;
    total_rules?: number;
  }>;
}

/**
 * SSH connection parameters for remote scan execution
 * Required to execute scans on target hosts via SSH instead of locally
 */
interface ConnectionParams {
  host_id: string;
  username: string;
  port: number;
  auth_method: 'ssh_key' | 'password';
}

/**
 * Compliance scan response from backend
 * Contains scan ID, execution status, and basic scan metadata
 */
interface ComplianceScanResponse {
  scan_id: string;
  status: 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  message?: string;
  host_id?: string;
  hostname?: string;
  framework?: string;
  platform?: string;
  created_at?: string;
  [key: string]: unknown;
}

/**
 * Legacy SCAP scan response from backend
 * Contains scan ID and basic status information
 */
interface LegacyScanResponse {
  id: string;
  scan_id?: string;
  status: 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  message?: string;
  host_id?: string;
  created_at?: string;
  [key: string]: unknown;
}

/**
 * Detailed scan information from backend
 * Includes scan configuration, progress, and result summary
 */
interface ScanDetailsResponse {
  id: string;
  scan_id?: string;
  name?: string;
  status: 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress?: number;
  host_id?: string;
  hostname?: string;
  profile_id?: string;
  framework?: string;
  platform?: string;
  started_at?: string;
  completed_at?: string;
  compliance_score?: number;
  passed_rules?: number;
  failed_rules?: number;
  total_rules?: number;
  scan_options?: unknown;
  error_message?: string;
  [key: string]: unknown;
}

/**
 * Scan results from backend
 * Contains compliance findings and rule evaluation results
 */
interface ScanResultsResponse {
  scan_id: string;
  results?: Array<{
    rule_id: string;
    result: 'pass' | 'fail' | 'error' | 'notapplicable' | 'notchecked';
    severity?: string;
    title?: string;
    description?: string;
    [key: string]: unknown;
  }>;
  summary?: {
    total_rules?: number;
    passed?: number;
    failed?: number;
    errors?: number;
    not_applicable?: number;
    compliance_score?: number;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

class ScanService {
  // Use centralized auth headers - no more direct localStorage access

  /**
   * Start a group scan for all hosts in the specified host group
   */
  static async startGroupScan(
    groupId: number,
    request: GroupScanRequest
  ): Promise<GroupScanSessionResponse> {
    const response = await fetch(`/api/host-groups/${groupId}/scan`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({
        scan_name: request.scan_name || `Group Scan - ${new Date().toLocaleString()}`,
        profile_id: request.profile_id,
        priority: request.priority || 'normal',
        template_id: request.template_id || 'auto',
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to start group scan');
    }

    return response.json();
  }

  /**
   * Get progress of a group scan session
   */
  static async getGroupScanProgress(
    groupId: number,
    sessionId: string
  ): Promise<ScanProgressResponse> {
    const response = await fetch(
      `/api/host-groups/${groupId}/scan-sessions/${sessionId}/progress`,
      {
        headers: getAuthHeaders(),
      }
    );

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to get scan progress');
    }

    return response.json();
  }

  /**
   * Cancel a running group scan session
   */
  static async cancelGroupScan(groupId: number, sessionId: string): Promise<void> {
    const response = await fetch(`/api/host-groups/${groupId}/scan-sessions/${sessionId}/cancel`, {
      method: 'POST',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to cancel group scan');
    }
  }

  /**
   * Get list of all scan sessions for a host group
   */
  static async getGroupScanSessions(groupId: number): Promise<GroupScanSessionResponse[]> {
    const response = await fetch(`/api/host-groups/${groupId}/scan-sessions`, {
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to get scan sessions');
    }

    return response.json();
  }

  /**
   * Start a compliance scan for a single host
   *
   * Uses MongoDB-backed compliance rules for scanning.
   * When connectionParams is provided, executes scan remotely via SSH.
   * Without connectionParams, scan executes locally (not typical for production).
   *
   * @param hostId - UUID of the host to scan
   * @param hostname - Hostname or IP address for scan execution
   * @param platform - Platform identifier (e.g., 'rhel', 'ubuntu')
   * @param platformVersion - Platform version (e.g., '8', '22.04')
   * @param framework - Compliance framework (e.g., 'nist_800_53', 'cis')
   * @param connectionParams - SSH connection parameters for remote execution
   * @param ruleIds - Optional array of specific rule IDs to scan
   * @returns Scan response with scan_id and status
   */
  static async startComplianceScan(
    hostId: string,
    hostname: string,
    platform: string,
    platformVersion: string,
    framework: string,
    connectionParams?: ConnectionParams,
    ruleIds?: string[]
  ): Promise<ComplianceScanResponse> {
    const response = await fetch('/api/scans/mongodb/start', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({
        host_id: hostId,
        hostname,
        platform,
        platform_version: platformVersion,
        framework,
        rule_ids: ruleIds,
        connection_params: connectionParams,
        include_enrichment: true,
        generate_report: true,
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to start compliance scan');
    }

    return response.json();
  }

  /**
   * @deprecated Use startComplianceScan() instead.
   * This alias is provided for backward compatibility during migration.
   */
  static async startMongoDBScan(
    hostId: string,
    hostname: string,
    platform: string,
    platformVersion: string,
    framework: string,
    ruleIds?: string[]
  ): Promise<ComplianceScanResponse> {
    return this.startComplianceScan(
      hostId,
      hostname,
      platform,
      platformVersion,
      framework,
      undefined,
      ruleIds
    );
  }

  /**
   * Start an individual scan for a single host (LEGACY)
   *
   * @deprecated Use startMongoDBScan() instead.
   * This method uses the old SCAP content file-based API which is being phased out.
   *
   * @param hostId - UUID of the host to scan
   * @param contentId - SCAP content file ID (deprecated)
   * @param profileId - SCAP profile ID
   * @returns Scan response
   */
  static async startHostScan(
    hostId: string,
    contentId: number,
    profileId: string
  ): Promise<LegacyScanResponse> {
    const response = await fetch('/api/scans/', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({
        name: `Manual Scan - ${new Date().toLocaleString()}`,
        host_id: hostId,
        content_id: contentId,
        profile_id: profileId,
        scan_options: {},
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to start host scan');
    }

    return response.json();
  }

  /**
   * Get scan details by scan ID
   */
  static async getScanDetails(scanId: string): Promise<ScanDetailsResponse> {
    const response = await fetch(`/api/scans/${scanId}`, {
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to get scan details');
    }

    return response.json();
  }

  /**
   * Cancel a running individual scan
   */
  static async cancelScan(scanId: string): Promise<void> {
    const response = await fetch(`/api/scans/${scanId}/cancel`, {
      method: 'POST',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to cancel scan');
    }
  }

  /**
   * Get scan results by scan ID
   */
  static async getScanResults(scanId: string): Promise<ScanResultsResponse> {
    const response = await fetch(`/api/scans/${scanId}/results`, {
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to get scan results');
    }

    return response.json();
  }
}

export { ScanService };
export type { ConnectionParams, ComplianceScanResponse };
