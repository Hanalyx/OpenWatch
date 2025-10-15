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
} from '@/types/scanConfig';

export const templateService = {
  /**
   * List templates with optional filters
   */
  list: async (params?: { framework?: string; tags?: string }): Promise<ScanTemplate[]> => {
    const response = await api.get('/scan-config/templates', { params });
    return response.data;
  },

  /**
   * Get a single template by ID
   */
  get: async (id: string): Promise<ScanTemplate> => {
    const response = await api.get(`/scan-config/templates/${id}`);
    return response.data;
  },

  /**
   * Create a new template
   */
  create: async (data: CreateTemplateRequest): Promise<ScanTemplate> => {
    const response = await api.post('/scan-config/templates', data);
    return response.data;
  },

  /**
   * Update an existing template
   */
  update: async (id: string, data: UpdateTemplateRequest): Promise<ScanTemplate> => {
    const response = await api.put(`/scan-config/templates/${id}`, data);
    return response.data;
  },

  /**
   * Delete a template
   */
  delete: async (id: string): Promise<void> => {
    await api.delete(`/scan-config/templates/${id}`);
  },

  /**
   * Apply a template to a target (returns scan configuration)
   */
  apply: async (id: string, request: ApplyTemplateRequest): Promise<any> => {
    const response = await api.post(`/scan-config/templates/${id}/apply`, request);
    return response.data;
  },

  /**
   * Clone a template with a new name
   */
  clone: async (id: string, newName: string): Promise<ScanTemplate> => {
    const response = await api.post(
      `/scan-config/templates/${id}/clone?new_name=${encodeURIComponent(newName)}`
    );
    return response.data;
  },

  /**
   * Set a template as the user's default
   */
  setDefault: async (id: string): Promise<void> => {
    await api.post(`/scan-config/templates/${id}/set-default`);
  },

  /**
   * Share a template (make public or share with specific users)
   */
  share: async (id: string, usernames?: string[]): Promise<void> => {
    await api.post(`/scan-config/templates/${id}/share`, {
      shared_with: usernames || [],
    });
  },

  /**
   * Get template statistics
   */
  getStatistics: async (): Promise<TemplateStatistics> => {
    const response = await api.get('/scan-config/statistics');
    return response.data;
  },

  /**
   * Get templates created by a specific user
   */
  getByUser: async (username: string): Promise<ScanTemplate[]> => {
    const response = await api.get(`/scan-config/templates/user/${username}`);
    return response.data;
  },
};
