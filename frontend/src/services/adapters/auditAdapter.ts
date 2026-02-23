/**
 * Audit Query API Adapter
 *
 * Type-safe API calls for audit query builder and exports.
 *
 * Part of Phase 6: Audit Queries (Kensa Integration Plan)
 */

import { api } from '../api';
import type {
  AuditExport,
  AuditExportCreate,
  AuditExportListResponse,
  ExportStats,
  QueryDefinition,
  QueryExecuteRequest,
  QueryExecuteResponse,
  QueryPreviewRequest,
  QueryPreviewResponse,
  QueryStats,
  SavedQuery,
  SavedQueryCreate,
  SavedQueryListResponse,
  SavedQueryUpdate,
} from '../../types/audit';

const BASE_URL = '/api/compliance/audit';

// =============================================================================
// Saved Queries
// =============================================================================

export const auditAdapter = {
  /**
   * List saved queries accessible to the current user.
   */
  async listQueries(params?: {
    page?: number;
    per_page?: number;
    include_shared?: boolean;
  }): Promise<SavedQueryListResponse> {
    return api.get<SavedQueryListResponse>(`${BASE_URL}/queries`, {
      params,
    });
  },

  /**
   * Get query statistics for the current user.
   */
  async getQueryStats(): Promise<QueryStats> {
    return api.get<QueryStats>(`${BASE_URL}/queries/stats`);
  },

  /**
   * Create a new saved query.
   */
  async createQuery(data: SavedQueryCreate): Promise<SavedQuery> {
    return api.post<SavedQuery>(`${BASE_URL}/queries`, data);
  },

  /**
   * Get saved query by ID.
   */
  async getQuery(queryId: string): Promise<SavedQuery> {
    return api.get<SavedQuery>(`${BASE_URL}/queries/${queryId}`);
  },

  /**
   * Update a saved query.
   */
  async updateQuery(queryId: string, data: SavedQueryUpdate): Promise<SavedQuery> {
    return api.put<SavedQuery>(`${BASE_URL}/queries/${queryId}`, data);
  },

  /**
   * Delete a saved query.
   */
  async deleteQuery(queryId: string): Promise<void> {
    await api.delete(`${BASE_URL}/queries/${queryId}`);
  },

  // ===========================================================================
  // Query Execution
  // ===========================================================================

  /**
   * Preview query results (sample + count).
   */
  async previewQuery(data: QueryPreviewRequest): Promise<QueryPreviewResponse> {
    return api.post<QueryPreviewResponse>(`${BASE_URL}/queries/preview`, data);
  },

  /**
   * Execute a saved query with pagination.
   */
  async executeQuery(queryId: string, params?: QueryExecuteRequest): Promise<QueryExecuteResponse> {
    return api.post<QueryExecuteResponse>(`${BASE_URL}/queries/${queryId}/execute`, params || {});
  },

  /**
   * Execute an ad-hoc query with pagination.
   */
  async executeAdhocQuery(
    queryDefinition: QueryDefinition,
    params?: { page?: number; per_page?: number }
  ): Promise<QueryExecuteResponse> {
    return api.post<QueryExecuteResponse>(`${BASE_URL}/queries/execute`, queryDefinition, {
      params,
    });
  },

  // ===========================================================================
  // Exports
  // ===========================================================================

  /**
   * List exports for the current user.
   */
  async listExports(params?: {
    page?: number;
    per_page?: number;
    status?: string;
  }): Promise<AuditExportListResponse> {
    return api.get<AuditExportListResponse>(`${BASE_URL}/exports`, {
      params,
    });
  },

  /**
   * Get export statistics for the current user.
   */
  async getExportStats(): Promise<ExportStats> {
    return api.get<ExportStats>(`${BASE_URL}/exports/stats`);
  },

  /**
   * Create a new export request.
   */
  async createExport(data: AuditExportCreate): Promise<AuditExport> {
    return api.post<AuditExport>(`${BASE_URL}/exports`, data);
  },

  /**
   * Get export by ID.
   */
  async getExport(exportId: string): Promise<AuditExport> {
    return api.get<AuditExport>(`${BASE_URL}/exports/${exportId}`);
  },

  /**
   * Get download URL for an export.
   */
  getDownloadUrl(exportId: string): string {
    return `${BASE_URL}/exports/${exportId}/download`;
  },

  /**
   * Download export file.
   * Returns a blob for file download.
   */
  async downloadExport(exportId: string): Promise<Blob> {
    return api.get<Blob>(`${BASE_URL}/exports/${exportId}/download`, {
      responseType: 'blob',
    });
  },
};

export default auditAdapter;
