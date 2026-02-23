/**
 * Posture API Adapter
 *
 * API adapter for temporal compliance posture endpoints.
 * Provides type-safe access to posture, history, and drift analysis.
 *
 * Part of Phase 2: Temporal Compliance (Kensa Integration Plan)
 *
 * @module services/adapters/postureAdapter
 */

import { api } from '../api';
import type {
  PostureResponse,
  PostureHistoryResponse,
  DriftAnalysisResponse,
  PostureQueryParams,
  PostureHistoryParams,
  DriftAnalysisParams,
  SnapshotCreateRequest,
  SnapshotCreateResponse,
} from '../../types/posture';

/**
 * Fetch current or historical compliance posture for a host.
 *
 * @param params - Query parameters including host_id and optional as_of date
 * @returns PostureResponse with compliance scores and rule states
 * @throws Error if no posture data available or subscription required for historical
 */
export async function fetchPosture(params: PostureQueryParams): Promise<PostureResponse> {
  const queryParams = new URLSearchParams();
  queryParams.set('host_id', params.host_id);

  if (params.as_of) {
    queryParams.set('as_of', params.as_of);
  }
  if (params.include_rule_states) {
    queryParams.set('include_rule_states', 'true');
  }

  // api.get() already returns response.data, not the full Axios response
  return api.get<PostureResponse>(`/api/compliance/posture?${queryParams.toString()}`);
}

/**
 * Fetch posture history for a host over a time range.
 *
 * Requires OpenWatch+ subscription for accessing historical data.
 *
 * @param params - Query parameters including host_id and date range
 * @returns PostureHistoryResponse with list of posture snapshots
 * @throws Error if subscription required
 */
export async function fetchPostureHistory(
  params: PostureHistoryParams
): Promise<PostureHistoryResponse> {
  const queryParams = new URLSearchParams();
  queryParams.set('host_id', params.host_id);

  if (params.start_date) {
    queryParams.set('start_date', params.start_date);
  }
  if (params.end_date) {
    queryParams.set('end_date', params.end_date);
  }
  if (params.limit) {
    queryParams.set('limit', params.limit.toString());
  }

  // api.get() already returns response.data, not the full Axios response
  return api.get<PostureHistoryResponse>(
    `/api/compliance/posture/history?${queryParams.toString()}`
  );
}

/**
 * Analyze compliance drift between two dates.
 *
 * Returns rules that changed status and overall drift metrics.
 * Requires OpenWatch+ subscription.
 *
 * @param params - Query parameters including host_id and date range
 * @returns DriftAnalysisResponse with drift metrics and events
 * @throws Error if dates invalid or subscription required
 */
export async function fetchDriftAnalysis(
  params: DriftAnalysisParams
): Promise<DriftAnalysisResponse> {
  const queryParams = new URLSearchParams();
  queryParams.set('host_id', params.host_id);
  queryParams.set('start_date', params.start_date);
  queryParams.set('end_date', params.end_date);

  // api.get() already returns response.data, not the full Axios response
  return api.get<DriftAnalysisResponse>(`/api/compliance/posture/drift?${queryParams.toString()}`);
}

/**
 * Manually create a posture snapshot for a host.
 *
 * Creates a snapshot of the current compliance posture for historical tracking.
 * Snapshots are normally created automatically via scheduled task.
 *
 * @param request - Snapshot creation request with host_id
 * @returns Snapshot creation result
 * @throws Error if no scan data available
 */
export async function createSnapshot(
  request: SnapshotCreateRequest
): Promise<SnapshotCreateResponse> {
  // api.post() already returns response.data, not the full Axios response
  return api.post<SnapshotCreateResponse>('/api/compliance/posture/snapshot', request);
}
