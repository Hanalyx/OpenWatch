/**
 * Framework Discovery Service
 * API client for framework metadata, variables, and validation
 */

import { api } from './api';
import type { VariableDefaultValue } from '../types/scanConfig';
import type {
  Framework,
  FrameworkDetails,
  VariableDefinition,
  ValidationResult,
} from '@/types/scanConfig';

export const frameworkService = {
  /**
   * List all available compliance frameworks
   */
  listFrameworks: async (): Promise<Framework[]> => {
    const response = await api.get<Framework[]>('/api/scans/config/frameworks');
    return response || [];
  },

  /**
   * Get details for a specific framework version
   */
  getFrameworkDetails: async (framework: string, version: string): Promise<FrameworkDetails> => {
    return api.get<FrameworkDetails>(`/api/scans/config/frameworks/${framework}/${version}`);
  },

  /**
   * Get variable definitions for a framework version
   */
  getVariables: async (framework: string, version: string): Promise<VariableDefinition[]> => {
    const response = await api.get<VariableDefinition[]>(
      `/api/scans/config/frameworks/${framework}/${version}/variables`
    );
    return response || [];
  },

  /**
   * Validate variable values against framework constraints
   * Variables can be string, number, or boolean based on framework definition
   */
  validateVariables: async (
    framework: string,
    version: string,
    variables: Record<string, VariableDefaultValue>
  ): Promise<ValidationResult> => {
    const response = await api.post<ValidationResult>(
      `/api/scans/config/frameworks/${framework}/${version}/validate`,
      { variables }
    );
    return response || { valid: true, errors: {}, warnings: {} };
  },
};
