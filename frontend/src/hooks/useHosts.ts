/**
 * React Query hooks for host server state
 *
 * Provides cached, automatically-refreshing host data via React Query.
 * Replaces the pattern of Redux async thunks (hostSlice) and manual
 * useState/useEffect fetching for host CRUD operations.
 *
 * Adaptive polling: refetchInterval shortens to 5s when scans are active.
 *
 * @module hooks/useHosts
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../services/api';
import {
  adaptHosts,
  adaptHost,
  toCreateHostRequest,
  toUpdateHostRequest,
  type ApiHostResponse,
} from '../services/adapters';
import type { Host } from '../types/host';
import { REFRESH_INTERVALS } from '../constants/refresh';

/** Query key factory for host-related queries. */
export const hostKeys = {
  all: ['hosts'] as const,
  detail: (id: string) => ['hosts', id] as const,
};

/**
 * Fetch and cache the full host list.
 *
 * - Stale time: 30s (background refetch after this)
 * - Adaptive polling: 5s when any host is scanning, 5min otherwise
 *
 * @param enabled - Whether the query should run (default: true)
 */
export function useHosts(enabled: boolean = true) {
  const query = useQuery({
    queryKey: hostKeys.all,
    queryFn: async (): Promise<Host[]> => {
      const apiHosts = await api.get<ApiHostResponse[]>('/api/hosts/');
      return adaptHosts(apiHosts);
    },
    enabled,
    staleTime: 30_000,
    refetchInterval: (query) => {
      const hosts = query.state.data;
      if (!hosts) return REFRESH_INTERVALS.NORMAL;

      const hasActiveScan = hosts.some(
        (h) => h.scanStatus === 'running' || h.scanStatus === 'pending'
      );
      return hasActiveScan ? REFRESH_INTERVALS.ACTIVE_SCAN : REFRESH_INTERVALS.NORMAL;
    },
    refetchOnWindowFocus: true,
  });

  return query;
}

/**
 * Fetch a single host by ID.
 */
export function useHost(id: string | undefined) {
  return useQuery({
    queryKey: hostKeys.detail(id!),
    queryFn: async (): Promise<Host> => {
      const apiHost = await api.get<ApiHostResponse>(`/api/hosts/${id}`);
      return adaptHost(apiHost);
    },
    enabled: !!id,
    staleTime: 30_000,
  });
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

interface CreateHostForm {
  hostname: string;
  ipAddress: string;
  displayName?: string;
  operatingSystem: string;
  authMethod?: string;
  sshKey?: string;
  password?: string;
  port?: number;
  username?: string;
}

/**
 * Create a new host. Invalidates the host list cache on success.
 */
export function useCreateHost() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (form: CreateHostForm) => {
      const payload = toCreateHostRequest(form);
      return api.post<ApiHostResponse>('/api/hosts/', payload);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: hostKeys.all });
    },
  });
}

interface UpdateHostForm {
  hostname: string;
  displayName: string;
  ipAddress: string;
  operatingSystem: string;
  port: number;
  username: string;
  authMethod: string;
  sshKey: string;
  password: string;
}

/**
 * Update an existing host. Invalidates both list and detail caches.
 */
export function useUpdateHost() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({ id, form }: { id: string; form: UpdateHostForm }) => {
      const payload = toUpdateHostRequest(form);
      return api.put<ApiHostResponse>(`/api/hosts/${id}`, payload);
    },
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: hostKeys.all });
      queryClient.invalidateQueries({ queryKey: hostKeys.detail(variables.id) });
    },
  });
}

/**
 * Delete a host. Invalidates the host list cache on success.
 */
export function useDeleteHost() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id: string) => {
      return api.delete(`/api/hosts/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: hostKeys.all });
    },
  });
}
