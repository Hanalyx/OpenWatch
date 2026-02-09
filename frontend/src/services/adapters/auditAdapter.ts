/**
 * Audit Query API Adapter
 *
 * Type-safe API calls for audit query builder and exports.
 *
 * Part of Phase 6: Audit Queries (Aegis Integration Plan)
 */

import api from '../api';
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
    const response = await api.get<SavedQueryListResponse>(`${BASE_URL}/queries`, {
      params,
    });
    return response.data;
  },

  /**
   * Get query statistics for the current user.
   */
  async getQueryStats(): Promise<QueryStats> {
    const response = await api.get<QueryStats>(`${BASE_URL}/queries/stats`);
    return response.data;
  },

  /**
   * Create a new saved query.
   */
  async createQuery(data: SavedQueryCreate): Promise<SavedQuery> {
    const response = await api.post<SavedQuery>(`${BASE_URL}/queries`, data);
    return response.data;
  },

  /**
   * Get saved query by ID.
   */
  async getQuery(queryId: string): Promise<SavedQuery> {
    const response = await api.get<SavedQuery>(`${BASE_URL}/queries/${queryId}`);
    return response.data;
  },

  /**
   * Update a saved query.
   */
  async updateQuery(queryId: string, data: SavedQueryUpdate): Promise<SavedQuery> {
    const response = await api.put<SavedQuery>(`${BASE_URL}/queries/${queryId}`, data);
    return response.data;
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
    const response = await api.post<QueryPreviewResponse>(`${BASE_URL}/queries/preview`, data);
    return response.data;
  },

  /**
   * Execute a saved query with pagination.
   */
  async executeQuery(queryId: string, params?: QueryExecuteRequest): Promise<QueryExecuteResponse> {
    const response = await api.post<QueryExecuteResponse>(
      `${BASE_URL}/queries/${queryId}/execute`,
      params || {}
    );
    return response.data;
  },

  /**
   * Execute an ad-hoc query with pagination.
   */
  async executeAdhocQuery(
    queryDefinition: QueryDefinition,
    params?: { page?: number; per_page?: number }
  ): Promise<QueryExecuteResponse> {
    const response = await api.post<QueryExecuteResponse>(
      `${BASE_URL}/queries/execute`,
      queryDefinition,
      { params }
    );
    return response.data;
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
    const response = await api.get<AuditExportListResponse>(`${BASE_URL}/exports`, {
      params,
    });
    return response.data;
  },

  /**
   * Get export statistics for the current user.
   */
  async getExportStats(): Promise<ExportStats> {
    const response = await api.get<ExportStats>(`${BASE_URL}/exports/stats`);
    return response.data;
  },

  /**
   * Create a new export request.
   */
  async createExport(data: AuditExportCreate): Promise<AuditExport> {
    const response = await api.post<AuditExport>(`${BASE_URL}/exports`, data);
    return response.data;
  },

  /**
   * Get export by ID.
   */
  async getExport(exportId: string): Promise<AuditExport> {
    const response = await api.get<AuditExport>(`${BASE_URL}/exports/${exportId}`);
    return response.data;
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
    const response = await api.get(`${BASE_URL}/exports/${exportId}/download`, {
      responseType: 'blob',
    });
    return response.data;
  },
};

export default auditAdapter;
