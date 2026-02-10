/**
 * Temporal Compliance React Query Hooks
 *
 * Provides cached, automatically-refreshing data for temporal compliance features.
 * Uses React Query for optimal data fetching with background updates.
 *
 * Part of Phase 2: Temporal Compliance (Aegis Integration Plan)
 *
 * @module hooks/usePosture
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  fetchPosture,
  fetchPostureHistory,
  fetchDriftAnalysis,
  createSnapshot,
} from '../services/adapters/postureAdapter';
import type {
  PostureResponse,
  PostureHistoryResponse,
  DriftAnalysisResponse,
  PostureHistoryParams,
  DriftAnalysisParams,
  SnapshotCreateRequest,
  SnapshotCreateResponse,
} from '../types/posture';

// =============================================================================
// Query Keys
// =============================================================================

export const postureKeys = {
  all: ['posture'] as const,
  current: (hostId: string) => ['posture', 'current', hostId] as const,
  historical: (hostId: string, asOf: string) => ['posture', 'historical', hostId, asOf] as const,
  history: (hostId: string, params?: Partial<PostureHistoryParams>) =>
    ['posture', 'history', hostId, params] as const,
  drift: (hostId: string, startDate: string, endDate: string) =>
    ['posture', 'drift', hostId, startDate, endDate] as const,
};

// =============================================================================
// Current Posture Hook
// =============================================================================

/**
 * Fetch and cache current compliance posture for a host.
 *
 * @param hostId - UUID of the host
 * @param enabled - Whether the query should run (default: true)
 */
export function useCurrentPosture(hostId: string | undefined, enabled: boolean = true) {
  return useQuery<PostureResponse>({
    queryKey: postureKeys.current(hostId!),
    queryFn: () => fetchPosture({ host_id: hostId! }),
    enabled: !!hostId && enabled,
    staleTime: 60_000, // 1 minute
    refetchOnWindowFocus: true,
  });
}

// =============================================================================
// Historical Posture Hook
// =============================================================================

/**
 * Fetch and cache historical compliance posture for a host at a specific date.
 *
 * Requires OpenWatch+ subscription.
 *
 * @param hostId - UUID of the host
 * @param asOf - Date for historical query (YYYY-MM-DD)
 * @param includeRuleStates - Whether to include per-rule states
 * @param enabled - Whether the query should run (default: true)
 */
export function useHistoricalPosture(
  hostId: string | undefined,
  asOf: string | undefined,
  includeRuleStates: boolean = false,
  enabled: boolean = true
) {
  return useQuery<PostureResponse>({
    queryKey: postureKeys.historical(hostId!, asOf!),
    queryFn: () =>
      fetchPosture({
        host_id: hostId!,
        as_of: asOf!,
        include_rule_states: includeRuleStates,
      }),
    enabled: !!hostId && !!asOf && enabled,
    staleTime: 300_000, // 5 minutes - historical data doesn't change
    refetchOnWindowFocus: false,
  });
}

// =============================================================================
// Posture History Hook
// =============================================================================

/**
 * Fetch and cache posture history for a host over a time range.
 *
 * Requires OpenWatch+ subscription.
 *
 * @param params - Query parameters including host_id and optional date range
 * @param enabled - Whether the query should run (default: true)
 */
export function usePostureHistory(
  params: PostureHistoryParams | undefined,
  enabled: boolean = true
) {
  return useQuery<PostureHistoryResponse>({
    queryKey: postureKeys.history(params?.host_id ?? '', params),
    queryFn: () => fetchPostureHistory(params!),
    enabled: !!params?.host_id && enabled,
    staleTime: 300_000, // 5 minutes
    refetchOnWindowFocus: false,
  });
}

// =============================================================================
// Drift Analysis Hook
// =============================================================================

/**
 * Analyze compliance drift between two dates.
 *
 * Requires OpenWatch+ subscription.
 *
 * @param params - Query parameters including host_id and date range
 * @param enabled - Whether the query should run (default: true)
 */
export function useDriftAnalysis(params: DriftAnalysisParams | undefined, enabled: boolean = true) {
  return useQuery<DriftAnalysisResponse>({
    queryKey: postureKeys.drift(
      params?.host_id ?? '',
      params?.start_date ?? '',
      params?.end_date ?? ''
    ),
    queryFn: () => fetchDriftAnalysis(params!),
    enabled: !!params?.host_id && !!params?.start_date && !!params?.end_date && enabled,
    staleTime: 300_000, // 5 minutes
    refetchOnWindowFocus: false,
  });
}

// =============================================================================
// Create Snapshot Mutation
// =============================================================================

/**
 * Mutation hook to manually create a posture snapshot.
 */
export function useCreateSnapshot() {
  const queryClient = useQueryClient();

  return useMutation<SnapshotCreateResponse, Error, SnapshotCreateRequest>({
    mutationFn: createSnapshot,
    onSuccess: (data, variables) => {
      // Invalidate posture queries for this host
      queryClient.invalidateQueries({
        queryKey: ['posture', 'current', variables.host_id],
      });
      queryClient.invalidateQueries({
        queryKey: ['posture', 'history', variables.host_id],
      });
    },
  });
}

// =============================================================================
// Invalidation Hook
// =============================================================================

/**
 * Hook to invalidate all posture queries for a host.
 */
export function useInvalidatePosture() {
  const queryClient = useQueryClient();

  return (hostId: string) => {
    queryClient.invalidateQueries({ queryKey: ['posture', 'current', hostId] });
    queryClient.invalidateQueries({ queryKey: ['posture', 'historical', hostId] });
    queryClient.invalidateQueries({ queryKey: ['posture', 'history', hostId] });
    queryClient.invalidateQueries({ queryKey: ['posture', 'drift', hostId] });
  };
}
