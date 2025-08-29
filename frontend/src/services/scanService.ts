/**
 * ScanService - Handles all scan-related API calls
 * Provides methods for individual scans and group scanning operations
 */

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

class ScanService {
  private static getAuthHeaders() {
    return {
      'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
      'Content-Type': 'application/json'
    };
  }

  /**
   * Start a group scan for all hosts in the specified host group
   */
  static async startGroupScan(groupId: number, request: GroupScanRequest): Promise<GroupScanSessionResponse> {
    const response = await fetch(`/api/host-groups/${groupId}/scan`, {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify({
        scan_name: request.scan_name || `Group Scan - ${new Date().toLocaleString()}`,
        profile_id: request.profile_id,
        priority: request.priority || 'normal',
        template_id: request.template_id || 'auto'
      })
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
  static async getGroupScanProgress(groupId: number, sessionId: string): Promise<ScanProgressResponse> {
    const response = await fetch(`/api/host-groups/${groupId}/scan-sessions/${sessionId}/progress`, {
      headers: this.getAuthHeaders()
    });

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
      headers: this.getAuthHeaders()
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
      headers: this.getAuthHeaders()
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to get scan sessions');
    }

    return response.json();
  }

  /**
   * Start an individual scan for a single host
   */
  static async startHostScan(hostId: string, contentId: number, profileId: string): Promise<any> {
    const response = await fetch('/api/scans/', {
      method: 'POST',
      headers: this.getAuthHeaders(),
      body: JSON.stringify({
        name: `Manual Scan - ${new Date().toLocaleString()}`,
        host_id: hostId,
        content_id: contentId,
        profile_id: profileId,
        scan_options: {}
      })
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
  static async getScanDetails(scanId: string): Promise<any> {
    const response = await fetch(`/api/scans/${scanId}`, {
      headers: this.getAuthHeaders()
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
      headers: this.getAuthHeaders()
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to cancel scan');
    }
  }

  /**
   * Get scan results by scan ID
   */
  static async getScanResults(scanId: string): Promise<any> {
    const response = await fetch(`/api/scans/${scanId}/results`, {
      headers: this.getAuthHeaders()
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to get scan results');
    }

    return response.json();
  }
}

export { ScanService };