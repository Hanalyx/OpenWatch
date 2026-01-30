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
import { adaptHosts, type ApiHostResponse } from '../services/adapters';
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
 */
export function useHostData(initialAutoRefresh: boolean = true): UseHostDataReturn {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [autoRefreshEnabled, setAutoRefreshEnabled] = useState(initialAutoRefresh);
  const [refreshInterval, setRefreshInterval] = useState<number>(REFRESH_INTERVALS.NORMAL);

  /**
   * Fetch hosts from API and transform via adapter.
   *
   * @param silent - If true, don't show loading spinner (for background refresh)
   */
  const fetchHosts = useCallback(async (silent: boolean = false) => {
    try {
      if (!silent) {
        setLoading(true);
      }

      const apiHosts = await api.get<ApiHostResponse[]>('/api/hosts/');
      setHosts(adaptHosts(apiHosts));
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
