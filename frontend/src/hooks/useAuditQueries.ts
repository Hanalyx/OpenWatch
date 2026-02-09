/**
 * Audit Query Hooks
 *
 * React Query hooks for audit query builder and exports.
 *
 * Part of Phase 6: Audit Queries (Aegis Integration Plan)
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { auditAdapter } from '../services/adapters/auditAdapter';
import type {
  AuditExportCreate,
  QueryDefinition,
  QueryPreviewRequest,
  SavedQueryCreate,
  SavedQueryUpdate,
} from '../types/audit';

// =============================================================================
// Query Keys
// =============================================================================

export const auditQueryKeys = {
  all: ['audit'] as const,
  queries: () => [...auditQueryKeys.all, 'queries'] as const,
  queryList: (params?: { page?: number; per_page?: number; include_shared?: boolean }) =>
    [...auditQueryKeys.queries(), 'list', params] as const,
  queryDetail: (id: string) => [...auditQueryKeys.queries(), 'detail', id] as const,
  queryStats: () => [...auditQueryKeys.queries(), 'stats'] as const,
  exports: () => [...auditQueryKeys.all, 'exports'] as const,
  exportList: (params?: { page?: number; per_page?: number; status?: string }) =>
    [...auditQueryKeys.exports(), 'list', params] as const,
  exportDetail: (id: string) => [...auditQueryKeys.exports(), 'detail', id] as const,
  exportStats: () => [...auditQueryKeys.exports(), 'stats'] as const,
};

// =============================================================================
// Saved Query Hooks
// =============================================================================

/**
 * Hook to list saved queries.
 */
export function useSavedQueries(params?: {
  page?: number;
  per_page?: number;
  include_shared?: boolean;
}) {
  return useQuery({
    queryKey: auditQueryKeys.queryList(params),
    queryFn: () => auditAdapter.listQueries(params),
    staleTime: 30000, // 30 seconds
  });
}

/**
 * Hook to get query statistics.
 */
export function useQueryStats() {
  return useQuery({
    queryKey: auditQueryKeys.queryStats(),
    queryFn: auditAdapter.getQueryStats,
    staleTime: 60000, // 1 minute
  });
}

/**
 * Hook to get a single saved query.
 */
export function useSavedQuery(queryId: string) {
  return useQuery({
    queryKey: auditQueryKeys.queryDetail(queryId),
    queryFn: () => auditAdapter.getQuery(queryId),
    enabled: !!queryId,
  });
}

/**
 * Hook to create a new saved query.
 */
export function useCreateQuery() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: SavedQueryCreate) => auditAdapter.createQuery(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: auditQueryKeys.queries() });
    },
  });
}

/**
 * Hook to update a saved query.
 */
export function useUpdateQuery() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ queryId, data }: { queryId: string; data: SavedQueryUpdate }) =>
      auditAdapter.updateQuery(queryId, data),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: auditQueryKeys.queries() });
      queryClient.invalidateQueries({
        queryKey: auditQueryKeys.queryDetail(variables.queryId),
      });
    },
  });
}

/**
 * Hook to delete a saved query.
 */
export function useDeleteQuery() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (queryId: string) => auditAdapter.deleteQuery(queryId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: auditQueryKeys.queries() });
    },
  });
}

// =============================================================================
// Query Execution Hooks
// =============================================================================

/**
 * Hook to preview query results.
 */
export function useQueryPreview() {
  return useMutation({
    mutationFn: (data: QueryPreviewRequest) => auditAdapter.previewQuery(data),
  });
}

/**
 * Hook to execute a saved query.
 */
export function useExecuteQuery() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({
      queryId,
      page,
      per_page,
    }: {
      queryId: string;
      page?: number;
      per_page?: number;
    }) => auditAdapter.executeQuery(queryId, { page, per_page }),
    onSuccess: () => {
      // Invalidate query stats as execution count changed
      queryClient.invalidateQueries({ queryKey: auditQueryKeys.queryStats() });
    },
  });
}

/**
 * Hook to execute an ad-hoc query.
 */
export function useExecuteAdhocQuery() {
  return useMutation({
    mutationFn: ({
      queryDefinition,
      page,
      per_page,
    }: {
      queryDefinition: QueryDefinition;
      page?: number;
      per_page?: number;
    }) => auditAdapter.executeAdhocQuery(queryDefinition, { page, per_page }),
  });
}

// =============================================================================
// Export Hooks
// =============================================================================

/**
 * Hook to list exports.
 */
export function useExports(params?: { page?: number; per_page?: number; status?: string }) {
  return useQuery({
    queryKey: auditQueryKeys.exportList(params),
    queryFn: () => auditAdapter.listExports(params),
    staleTime: 10000, // 10 seconds - more frequent for status updates
    refetchInterval: (query) => {
      // Poll more frequently if there are pending/processing exports
      const data = query.state.data;
      if (data?.items.some((e) => e.status === 'pending' || e.status === 'processing')) {
        return 5000; // 5 seconds
      }
      return false; // Stop polling
    },
  });
}

/**
 * Hook to get export statistics.
 */
export function useExportStats() {
  return useQuery({
    queryKey: auditQueryKeys.exportStats(),
    queryFn: auditAdapter.getExportStats,
    staleTime: 30000, // 30 seconds
  });
}

/**
 * Hook to get a single export.
 */
export function useExport(exportId: string) {
  return useQuery({
    queryKey: auditQueryKeys.exportDetail(exportId),
    queryFn: () => auditAdapter.getExport(exportId),
    enabled: !!exportId,
    refetchInterval: (query) => {
      const data = query.state.data;
      // Poll while pending/processing
      if (data?.status === 'pending' || data?.status === 'processing') {
        return 3000; // 3 seconds
      }
      return false;
    },
  });
}

/**
 * Hook to create a new export.
 */
export function useCreateExport() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: AuditExportCreate) => auditAdapter.createExport(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: auditQueryKeys.exports() });
    },
  });
}

/**
 * Hook to download an export file.
 */
export function useDownloadExport() {
  return useMutation({
    mutationFn: async ({ exportId, filename }: { exportId: string; filename: string }) => {
      const blob = await auditAdapter.downloadExport(exportId);

      // Create download link
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      return blob;
    },
  });
}

export default {
  // Query keys for external use
  queryKeys: auditQueryKeys,
  // Saved queries
  useSavedQueries,
  useQueryStats,
  useSavedQuery,
  useCreateQuery,
  useUpdateQuery,
  useDeleteQuery,
  // Execution
  useQueryPreview,
  useExecuteQuery,
  useExecuteAdhocQuery,
  // Exports
  useExports,
  useExportStats,
  useExport,
  useCreateExport,
  useDownloadExport,
};
