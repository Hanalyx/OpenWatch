/**
 * Auto-Refresh Interval Constants
 *
 * Centralized configuration for auto-refresh intervals throughout OpenWatch.
 * These values optimize the balance between real-time updates and server load.
 *
 * Design Principles:
 * - Adaptive intervals based on system activity
 * - Respect browser visibility (pause when tab hidden)
 * - Minimize server load during idle periods
 * - Provide responsive updates during active scans
 *
 * Used by:
 * - Hosts page (host status monitoring)
 * - Scans page (scan progress tracking)
 * - Dashboard (metrics updates)
 * - Host detail page (real-time status)
 *
 * @module constants/refresh
 */

/**
 * Auto-refresh interval constants (milliseconds).
 *
 * Adaptive refresh intervals based on system activity:
 * - ACTIVE_SCAN: Fast polling during scan execution (5 seconds)
 * - NORMAL: Standard polling for idle state (5 minutes)
 * - MANUAL: No auto-refresh (user must trigger manually)
 *
 * Why these specific values:
 * - 5 seconds (ACTIVE_SCAN): Provides near-real-time scan progress without overwhelming server
 * - 5 minutes (NORMAL): Balances freshness with server load (300 requests/hour max per user)
 * - Manual only: For development/debugging to prevent unwanted refreshes
 *
 * @constant
 * @readonly
 *
 * @example
 * import { REFRESH_INTERVALS } from '@/constants/refresh';
 *
 * const hasActiveScan = scans.some(s => s.status === 'running');
 * const interval = hasActiveScan
 *   ? REFRESH_INTERVALS.ACTIVE_SCAN
 *   : REFRESH_INTERVALS.NORMAL;
 *
 * setInterval(() => fetchData(), interval);
 */
export const REFRESH_INTERVALS = {
  /** Fast polling during active scans: 5 seconds (5,000ms) */
  ACTIVE_SCAN: 5000,

  /** Normal polling during idle state: 5 minutes (300,000ms) */
  NORMAL: 300000,

  /** Manual refresh only: Infinity (no auto-refresh) */
  MANUAL: Infinity,
} as const;

/**
 * Human-readable refresh interval labels.
 *
 * Display labels for refresh interval options in UI.
 *
 * @constant
 * @readonly
 *
 * @example
 * import { REFRESH_INTERVAL_LABELS } from '@/constants/refresh';
 *
 * <Select value={interval}>
 *   <MenuItem value={REFRESH_INTERVALS.ACTIVE_SCAN}>
 *     {REFRESH_INTERVAL_LABELS.ACTIVE_SCAN}
 *   </MenuItem>
 * </Select>
 */
export const REFRESH_INTERVAL_LABELS = {
  /** Label for 5-second active scan interval */
  ACTIVE_SCAN: '5 seconds (active scans)',

  /** Label for 5-minute normal interval */
  NORMAL: '5 minutes',

  /** Label for manual refresh only */
  MANUAL: 'Manual only',
} as const;

/**
 * Scan status check interval during execution.
 *
 * How frequently to poll for scan status updates when a scan is running.
 * More frequent than general refresh to provide responsive progress updates.
 *
 * @constant
 * @readonly
 */
export const SCAN_STATUS_POLL_INTERVAL = 2000; // 2 seconds

/**
 * Host health check interval for monitoring.
 *
 * How frequently to check host connectivity and health metrics.
 * Less frequent than scan polling to reduce network overhead.
 *
 * @constant
 * @readonly
 */
export const HOST_HEALTH_CHECK_INTERVAL = 60000; // 1 minute

/**
 * Maximum age for cached data before forcing refresh.
 *
 * Data older than this threshold is considered stale and will
 * trigger a refresh even if auto-refresh is disabled.
 *
 * @constant
 * @readonly
 */
export const MAX_CACHE_AGE = 900000; // 15 minutes

/**
 * Helper function to determine appropriate refresh interval based on context.
 *
 * Implements adaptive polling strategy:
 * - Fast polling during active scans
 * - Normal polling during idle periods
 * - Respect manual refresh preference
 *
 * @param hasActiveScan - Whether any scans are currently running
 * @param manualOnly - Whether auto-refresh is disabled
 * @returns Appropriate refresh interval in milliseconds
 *
 * @example
 * const interval = getRefreshInterval(
 *   scans.some(s => s.status === 'running'),
 *   !autoRefreshEnabled
 * );
 *
 * useEffect(() => {
 *   const timer = setInterval(() => fetchData(), interval);
 *   return () => clearInterval(timer);
 * }, [interval]);
 */
export function getRefreshInterval(hasActiveScan: boolean, manualOnly: boolean = false): number {
  if (manualOnly) return REFRESH_INTERVALS.MANUAL;
  return hasActiveScan ? REFRESH_INTERVALS.ACTIVE_SCAN : REFRESH_INTERVALS.NORMAL;
}

/**
 * Helper function to check if data is stale and needs refresh.
 *
 * @param lastFetchTime - Timestamp of last data fetch (Date or ISO string)
 * @param maxAge - Maximum acceptable age in milliseconds (default: MAX_CACHE_AGE)
 * @returns True if data is stale and should be refreshed
 *
 * @example
 * if (isDataStale(lastRefresh)) {
 *   await fetchFreshData();
 * }
 */
export function isDataStale(
  lastFetchTime: Date | string | null,
  maxAge: number = MAX_CACHE_AGE
): boolean {
  if (!lastFetchTime) return true;

  const fetchDate = typeof lastFetchTime === 'string' ? new Date(lastFetchTime) : lastFetchTime;

  const ageMs = Date.now() - fetchDate.getTime();
  return ageMs > maxAge;
}
