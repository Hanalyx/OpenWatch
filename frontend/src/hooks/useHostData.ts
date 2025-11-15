/**
 * useHostData Hook
 *
 * Custom hook for managing host data fetching, auto-refresh, and loading states.
 * Centralizes all data fetching logic with automatic refresh intervals and
 * scan status detection for adaptive polling.
 *
 * Features:
 * - Automatic data fetching on mount
 * - Configurable auto-refresh intervals
 * - Adaptive polling (5s during active scans, 5min normal)
 * - Silent refresh support (no loading spinner)
 * - Last refresh timestamp tracking
 *
 * Used by:
 * - Hosts page (main host inventory)
 * - Dashboard (host summary cards)
 * - Host monitoring components
 *
 * @module hooks/useHostData
 */

import { useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import type { Host } from '../types/host';
import { REFRESH_INTERVALS } from '../constants/refresh';

/**
 * Return type for useHostData hook.
 *
 * @interface UseHostDataReturn
 */
export interface UseHostDataReturn {
  /** Array of host records */
  hosts: Host[];
  /** Loading state (true during initial fetch) */
  loading: boolean;
  /** Last successful refresh timestamp */
  lastRefresh: Date | null;
  /** Whether auto-refresh is enabled */
  autoRefreshEnabled: boolean;
  /** Current refresh interval in milliseconds */
  refreshInterval: number;
  /** Manually trigger data refresh */
  refreshHosts: (silent?: boolean) => Promise<void>;
  /** Enable/disable auto-refresh */
  setAutoRefreshEnabled: (enabled: boolean) => void;
  /** Update refresh interval */
  setRefreshInterval: (interval: number) => void;
}

/**
 * Custom hook for managing host data with auto-refresh.
 *
 * Handles data fetching, loading states, and automatic refresh based on
 * scan activity. Implements adaptive polling: 5s intervals when scans are
 * running, 5min intervals when idle.
 *
 * @param initialAutoRefresh - Whether to enable auto-refresh on mount (default: true)
 * @returns Host data and control functions
 *
 * @example
 * function HostsPage() {
 *   const {
 *     hosts,
 *     loading,
 *     refreshHosts,
 *     autoRefreshEnabled,
 *     setAutoRefreshEnabled
 *   } = useHostData();
 *
 *   return (
 *     <div>
 *       <button onClick={() => refreshHosts()}>Refresh</button>
 *       <button onClick={() => setAutoRefreshEnabled(!autoRefreshEnabled)}>
 *         Toggle Auto-Refresh
 *       </button>
 *       {loading ? <Spinner /> : <HostList hosts={hosts} />}
 *     </div>
 *   );
 * }
 */
export function useHostData(initialAutoRefresh: boolean = true): UseHostDataReturn {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [autoRefreshEnabled, setAutoRefreshEnabled] = useState(initialAutoRefresh);
  const [refreshInterval, setRefreshInterval] = useState(REFRESH_INTERVALS.NORMAL);

  /**
   * Fetch hosts from API.
   *
   * @param silent - If true, don't show loading spinner (for background refresh)
   */
  const fetchHosts = useCallback(async (silent: boolean = false) => {
    try {
      if (!silent) {
        setLoading(true);
      }

      const response = await api.get('/api/hosts/');
      const apiHosts = response.data;

      // Transform API response to match Host interface
      const transformedHosts: Host[] = apiHosts.map((host: any) => ({
        id: host.id,
        hostname: host.hostname,
        displayName: host.display_name || host.hostname,
        ipAddress: host.ip_address,
        operatingSystem: host.operating_system || 'Unknown',
        osVersion: host.os_version || '',
        status: host.status || 'unknown',
        cpuUsage: host.cpu_usage,
        memoryUsage: host.memory_usage,
        diskUsage: host.disk_usage,
        uptime: host.uptime,
        complianceScore: host.compliance_score,
        complianceTrend: host.compliance_trend || 'stable',
        lastScan: host.last_scan,
        lastCheck: host.last_check,
        nextScan: host.next_scan,
        criticalIssues: host.critical_issues || 0,
        highIssues: host.high_issues || 0,
        mediumIssues: host.medium_issues || 0,
        lowIssues: host.low_issues || 0,
        latestScanId: host.latest_scan_id,
        latestScanName: host.latest_scan_name,
        scanStatus: host.scan_status,
        scanProgress: host.scan_progress,
        failedRules: host.failed_rules || 0,
        passedRules: host.passed_rules || 0,
        totalRules: host.total_rules || 0,
        tags: host.tags || [],
        group: host.group || 'Ungrouped',
        group_id: host.group_id,
        group_name: host.group_name,
        group_description: host.group_description,
        group_color: host.group_color,
        owner: host.owner || 'Unknown',
        port: host.port || 22,
        username: host.username || '',
        authMethod: host.auth_method || 'ssh_key',
        sshKey: host.ssh_key || false,
        ssh_key_fingerprint: host.ssh_key_fingerprint,
        ssh_key_type: host.ssh_key_type,
        ssh_key_bits: host.ssh_key_bits,
        ssh_key_comment: host.ssh_key_comment,
        agent: host.agent || 'not_installed',
        profile: host.profile,
        lastBackup: host.last_backup,
      }));

      setHosts(transformedHosts);
      setLastRefresh(new Date());
    } catch (error) {
      console.error('Error fetching hosts:', error);
      setHosts([]);
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  }, []);

  /**
   * Public refresh function.
   * Wraps fetchHosts with explicit silent parameter.
   */
  const refreshHosts = useCallback(
    async (silent: boolean = false) => {
      await fetchHosts(silent);
    },
    [fetchHosts]
  );

  /**
   * Initial data fetch on component mount.
   */
  useEffect(() => {
    fetchHosts();
  }, [fetchHosts]);

  /**
   * Auto-refresh logic with adaptive intervals.
   *
   * Checks for running scans and adjusts refresh interval:
   * - 5 seconds if any host has scanStatus === 'running'
   * - Normal interval (5 minutes) otherwise
   */
  useEffect(() => {
    if (!autoRefreshEnabled) return;

    // Check if any host has an active scan
    const hasRunningScan = hosts.some(
      (host) => host.scanStatus === 'running' || host.scanStatus === 'pending'
    );

    // Use adaptive interval
    const interval = hasRunningScan
      ? REFRESH_INTERVALS.ACTIVE_SCAN // 5 seconds
      : refreshInterval; // 5 minutes (or custom)

    const timer = setInterval(() => {
      fetchHosts(true); // Silent refresh
    }, interval);

    return () => clearInterval(timer);
  }, [autoRefreshEnabled, hosts, refreshInterval, fetchHosts]);

  return {
    hosts,
    loading,
    lastRefresh,
    autoRefreshEnabled,
    refreshInterval,
    refreshHosts,
    setAutoRefreshEnabled,
    setRefreshInterval,
  };
}
