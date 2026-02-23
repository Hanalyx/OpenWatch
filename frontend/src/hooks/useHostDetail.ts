/**
 * Host Detail React Query Hooks
 *
 * Provides cached, automatically-refreshing data for the Host Detail page.
 * Uses React Query for optimal data fetching with background updates.
 *
 * Part of OpenWatch OS Transformation.
 *
 * @module hooks/useHostDetail
 */

import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  fetchComplianceState,
  fetchHostSchedule,
  fetchSchedulerStatus,
  fetchSystemInfo,
  fetchIntelligenceSummary,
  fetchPackages,
  fetchServices,
  fetchUsers,
  fetchNetwork,
  fetchFirewall,
  fetchRoutes,
  fetchScanHistory,
} from '../services/adapters/hostDetailAdapter';
import type {
  ComplianceState,
  HostSchedule,
  SchedulerStatus,
  SystemInfo,
  ServerIntelligenceSummary,
  PackagesResponse,
  ServicesResponse,
  UsersResponse,
  NetworkResponse,
  FirewallResponse,
  RoutesResponse,
  ScanHistoryResponse,
} from '../types/hostDetail';
import { REFRESH_INTERVALS } from '../constants/refresh';

// =============================================================================
// Query Keys
// =============================================================================

export const hostDetailKeys = {
  all: ['hostDetail'] as const,
  compliance: (hostId: string) => ['hostDetail', 'compliance', hostId] as const,
  schedule: (hostId: string) => ['hostDetail', 'schedule', hostId] as const,
  systemInfo: (hostId: string) => ['hostDetail', 'systemInfo', hostId] as const,
  intelligenceSummary: (hostId: string) => ['hostDetail', 'intelligenceSummary', hostId] as const,
  packages: (hostId: string, params?: object) =>
    ['hostDetail', 'packages', hostId, params] as const,
  services: (hostId: string, params?: object) =>
    ['hostDetail', 'services', hostId, params] as const,
  users: (hostId: string, params?: object) => ['hostDetail', 'users', hostId, params] as const,
  network: (hostId: string, params?: object) => ['hostDetail', 'network', hostId, params] as const,
  firewall: (hostId: string, params?: object) =>
    ['hostDetail', 'firewall', hostId, params] as const,
  routes: (hostId: string, params?: object) => ['hostDetail', 'routes', hostId, params] as const,
  scanHistory: (hostId: string) => ['hostDetail', 'scanHistory', hostId] as const,
};

export const schedulerKeys = {
  status: ['scheduler', 'status'] as const,
};

// =============================================================================
// Compliance State Hook
// =============================================================================

/**
 * Fetch and cache compliance state for a host.
 *
 * Provides rule findings, pass/fail counts, and severity breakdown
 * from the most recent Kensa scan.
 *
 * @param hostId - UUID of the host
 * @param enabled - Whether the query should run (default: true)
 */
export function useComplianceState(hostId: string | undefined, enabled: boolean = true) {
  return useQuery<ComplianceState>({
    queryKey: hostDetailKeys.compliance(hostId!),
    queryFn: () => fetchComplianceState(hostId!),
    enabled: !!hostId && enabled,
    staleTime: 60_000, // 1 minute
    refetchOnWindowFocus: true,
  });
}

// =============================================================================
// Schedule Hooks
// =============================================================================

/**
 * Fetch and cache host schedule from compliance scheduler.
 *
 * Provides auto-scan status, next scheduled time, and maintenance mode info.
 *
 * @param hostId - UUID of the host
 * @param enabled - Whether the query should run (default: true)
 */
export function useHostSchedule(hostId: string | undefined, enabled: boolean = true) {
  return useQuery<HostSchedule>({
    queryKey: hostDetailKeys.schedule(hostId!),
    queryFn: () => fetchHostSchedule(hostId!),
    enabled: !!hostId && enabled,
    staleTime: 30_000, // 30 seconds
    refetchOnWindowFocus: true,
  });
}

/**
 * Fetch and cache scheduler status for dashboard.
 *
 * Provides enabled status, host counts, and upcoming scans.
 *
 * @param enabled - Whether the query should run (default: true)
 */
export function useSchedulerStatus(enabled: boolean = true) {
  return useQuery<SchedulerStatus>({
    queryKey: schedulerKeys.status,
    queryFn: fetchSchedulerStatus,
    enabled,
    staleTime: 30_000, // 30 seconds
    refetchInterval: REFRESH_INTERVALS.NORMAL,
    refetchOnWindowFocus: true,
  });
}

// =============================================================================
// System Info Hooks
// =============================================================================

/**
 * Fetch and cache system info for a host.
 *
 * Provides OS, hardware, and security information collected during scans.
 *
 * @param hostId - UUID of the host
 * @param enabled - Whether the query should run (default: true)
 */
export function useSystemInfo(hostId: string | undefined, enabled: boolean = true) {
  return useQuery<SystemInfo | null>({
    queryKey: hostDetailKeys.systemInfo(hostId!),
    queryFn: () => fetchSystemInfo(hostId!),
    enabled: !!hostId && enabled,
    staleTime: 300_000, // 5 minutes - system info changes rarely
    refetchOnWindowFocus: false,
  });
}

/**
 * Fetch and cache server intelligence summary for a host.
 *
 * Provides counts of collected data (packages, services, users, etc.).
 *
 * @param hostId - UUID of the host
 * @param enabled - Whether the query should run (default: true)
 */
export function useIntelligenceSummary(hostId: string | undefined, enabled: boolean = true) {
  return useQuery<ServerIntelligenceSummary | null>({
    queryKey: hostDetailKeys.intelligenceSummary(hostId!),
    queryFn: () => fetchIntelligenceSummary(hostId!),
    enabled: !!hostId && enabled,
    staleTime: 60_000, // 1 minute
    refetchOnWindowFocus: true,
  });
}

// =============================================================================
// Intelligence Data Hooks
// =============================================================================

interface PackagesParams {
  search?: string;
  limit?: number;
  offset?: number;
}

/**
 * Fetch and cache packages for a host.
 *
 * @param hostId - UUID of the host
 * @param params - Search and pagination parameters
 * @param enabled - Whether the query should run (default: true)
 */
export function usePackages(
  hostId: string | undefined,
  params?: PackagesParams,
  enabled: boolean = true
) {
  return useQuery<PackagesResponse>({
    queryKey: hostDetailKeys.packages(hostId!, params),
    queryFn: () => fetchPackages(hostId!, params),
    enabled: !!hostId && enabled,
    staleTime: 300_000, // 5 minutes
    refetchOnWindowFocus: false,
  });
}

interface ServicesParams {
  search?: string;
  status?: string;
  limit?: number;
  offset?: number;
}

/**
 * Fetch and cache services for a host.
 *
 * @param hostId - UUID of the host
 * @param params - Search, status filter, and pagination parameters
 * @param enabled - Whether the query should run (default: true)
 */
export function useServices(
  hostId: string | undefined,
  params?: ServicesParams,
  enabled: boolean = true
) {
  return useQuery<ServicesResponse>({
    queryKey: hostDetailKeys.services(hostId!, params),
    queryFn: () => fetchServices(hostId!, params),
    enabled: !!hostId && enabled,
    staleTime: 300_000, // 5 minutes
    refetchOnWindowFocus: false,
  });
}

interface UsersParams {
  search?: string;
  includeSystem?: boolean;
  hasSudo?: boolean;
  limit?: number;
  offset?: number;
}

/**
 * Fetch and cache users for a host.
 *
 * @param hostId - UUID of the host
 * @param params - Search, filters, and pagination parameters
 * @param enabled - Whether the query should run (default: true)
 */
export function useUsers(
  hostId: string | undefined,
  params?: UsersParams,
  enabled: boolean = true
) {
  return useQuery<UsersResponse>({
    queryKey: hostDetailKeys.users(hostId!, params),
    queryFn: () => fetchUsers(hostId!, params),
    enabled: !!hostId && enabled,
    staleTime: 300_000, // 5 minutes
    refetchOnWindowFocus: false,
  });
}

interface NetworkParams {
  interfaceType?: string;
  isUp?: boolean;
  limit?: number;
  offset?: number;
}

/**
 * Fetch and cache network interfaces for a host.
 *
 * @param hostId - UUID of the host
 * @param params - Filters and pagination parameters
 * @param enabled - Whether the query should run (default: true)
 */
export function useNetwork(
  hostId: string | undefined,
  params?: NetworkParams,
  enabled: boolean = true
) {
  return useQuery<NetworkResponse>({
    queryKey: hostDetailKeys.network(hostId!, params),
    queryFn: () => fetchNetwork(hostId!, params),
    enabled: !!hostId && enabled,
    staleTime: 300_000, // 5 minutes
    refetchOnWindowFocus: false,
  });
}

interface FirewallParams {
  chain?: string;
  action?: string;
  firewallType?: string;
  limit?: number;
  offset?: number;
}

/**
 * Fetch and cache firewall rules for a host.
 *
 * @param hostId - UUID of the host
 * @param params - Filters and pagination parameters
 * @param enabled - Whether the query should run (default: true)
 */
export function useFirewall(
  hostId: string | undefined,
  params?: FirewallParams,
  enabled: boolean = true
) {
  return useQuery<FirewallResponse>({
    queryKey: hostDetailKeys.firewall(hostId!, params),
    queryFn: () => fetchFirewall(hostId!, params),
    enabled: !!hostId && enabled,
    staleTime: 300_000, // 5 minutes
    refetchOnWindowFocus: false,
  });
}

interface RoutesParams {
  isDefault?: boolean;
  limit?: number;
  offset?: number;
}

/**
 * Fetch and cache routes for a host.
 *
 * @param hostId - UUID of the host
 * @param params - Filters and pagination parameters
 * @param enabled - Whether the query should run (default: true)
 */
export function useRoutes(
  hostId: string | undefined,
  params?: RoutesParams,
  enabled: boolean = true
) {
  return useQuery<RoutesResponse>({
    queryKey: hostDetailKeys.routes(hostId!, params),
    queryFn: () => fetchRoutes(hostId!, params),
    enabled: !!hostId && enabled,
    staleTime: 300_000, // 5 minutes
    refetchOnWindowFocus: false,
  });
}

// =============================================================================
// Scan History Hook
// =============================================================================

/**
 * Fetch and cache scan history for a host.
 *
 * @param hostId - UUID of the host
 * @param enabled - Whether the query should run (default: true)
 */
export function useScanHistory(hostId: string | undefined, enabled: boolean = true) {
  return useQuery<ScanHistoryResponse>({
    queryKey: hostDetailKeys.scanHistory(hostId!),
    queryFn: () => fetchScanHistory(hostId!),
    enabled: !!hostId && enabled,
    staleTime: 30_000, // 30 seconds - scans update frequently
    refetchOnWindowFocus: true,
  });
}

// =============================================================================
// Invalidation Hook
// =============================================================================

/**
 * Hook to invalidate all host detail queries for a host.
 *
 * Useful after a scan completes or data is updated.
 */
export function useInvalidateHostDetail() {
  const queryClient = useQueryClient();

  return (hostId: string) => {
    queryClient.invalidateQueries({ queryKey: ['hostDetail', 'compliance', hostId] });
    queryClient.invalidateQueries({ queryKey: ['hostDetail', 'schedule', hostId] });
    queryClient.invalidateQueries({ queryKey: ['hostDetail', 'systemInfo', hostId] });
    queryClient.invalidateQueries({ queryKey: ['hostDetail', 'intelligenceSummary', hostId] });
    queryClient.invalidateQueries({ queryKey: ['hostDetail', 'scanHistory', hostId] });
  };
}
