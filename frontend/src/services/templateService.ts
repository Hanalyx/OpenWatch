/**
 * Template Management Service
 * API client for scan configuration templates
 */

import { api } from './api';
import type {
  ScanTemplate,
  CreateTemplateRequest,
  UpdateTemplateRequest,
  ApplyTemplateRequest,
  TemplateStatistics,
  VariableDefaultValue,
  RuleFilter,
} from '@/types/scanConfig';

/**
 * Applied template response from backend
 * Contains the resolved scan configuration after applying template to a target
 */
interface AppliedTemplateResponse {
  template_id: string;
  template_name?: string;
  framework: string;
  framework_version: string;
  target_type: string;
  target_identifier: string;
  resolved_variables: Record<string, VariableDefaultValue>;
  rule_filter?: RuleFilter;
  rules_count?: number;
  applied_at?: string;
  [key: string]: unknown;
}

export const templateService = {
  /**
   * List templates with optional filters
   */
  list: async (params?: { framework?: string; tags?: string }): Promise<ScanTemplate[]> => {
    const response = await api.get<ScanTemplate[]>('/api/scans/templates', { params });
    return response || [];
  },

  /**
   * Get a single template by ID
   */
  get: async (id: string): Promise<ScanTemplate> => {
    return api.get<ScanTemplate>(`/api/scans/templates/${id}`);
  },

  /**
   * Create a new template
   */
  create: async (data: CreateTemplateRequest): Promise<ScanTemplate> => {
    return api.post<ScanTemplate>('/api/scans/templates', data);
  },

  /**
   * Update an existing template
   */
  update: async (id: string, data: UpdateTemplateRequest): Promise<ScanTemplate> => {
    return api.put<ScanTemplate>(`/api/scans/templates/${id}`, data);
  },

  /**
   * Delete a template
   */
  delete: async (id: string): Promise<void> => {
    await api.delete(`/api/scans/templates/${id}`);
  },

  /**
   * Apply a template to a target (returns scan configuration)
   */
  apply: async (id: string, request: ApplyTemplateRequest): Promise<AppliedTemplateResponse> => {
    return api.post<AppliedTemplateResponse>(`/api/scans/templates/${id}/apply`, request);
  },

  /**
   * Clone a template with a new name
   */
  clone: async (id: string, newName: string): Promise<ScanTemplate> => {
    return api.post<ScanTemplate>(
      `/api/scans/templates/${id}/clone?new_name=${encodeURIComponent(newName)}`
    );
  },

  /**
   * Set a template as the user's default
   */
  setDefault: async (id: string): Promise<void> => {
    await api.post(`/api/scans/templates/${id}/set-default`);
  },

  /**
   * Share a template (make public or share with specific users)
   */
  share: async (id: string, usernames?: string[]): Promise<void> => {
    await api.post(`/api/scans/templates/${id}/share`, {
      shared_with: usernames || [],
    });
  },

  /**
   * Get template statistics
   */
  getStatistics: async (): Promise<TemplateStatistics> => {
    return api.get<TemplateStatistics>('/api/scans/config/statistics');
  },

  /**
   * Get templates created by a specific user
   */
  getByUser: async (username: string): Promise<ScanTemplate[]> => {
    const response = await api.get<ScanTemplate[]>(`/api/scans/templates/user/${username}`);
    return response || [];
  },
};
