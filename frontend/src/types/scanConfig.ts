/**
 * Phase 1 - Scan Configuration Types
 * Types for framework discovery, variable customization, and template management
 */

export interface Framework {
  framework: string;
  display_name: string;
  versions: string[];
  description: string;
  rule_count: number;
  variable_count: number;
  categories?: string[];
  severities?: Record<string, number>;
}

export interface FrameworkDetails {
  framework: string;
  version: string;
  display_name: string;
  description: string;
  rule_count: number;
  variable_count: number;
  rules: string[];
  variables: string[];
  metadata: Record<string, any>;
}

export interface VariableConstraint {
  lower_bound?: number;
  upper_bound?: number;
  choices?: string[];
  match?: string;
}

export interface VariableDefinition {
  id: string;
  title: string;
  description: string;
  type: 'string' | 'number' | 'boolean';
  default: any;
  constraints?: VariableConstraint;
  interactive: boolean;
  category?: string;
}

export interface ScanTemplate {
  template_id: string;
  name: string;
  description?: string;
  framework: string;
  framework_version: string;
  target_type: string;
  variable_overrides: Record<string, string>;
  rule_filter?: Record<string, any>;
  created_by: string;
  created_at: string;
  updated_at: string;
  is_default: boolean;
  is_public: boolean;
  tags: string[];
  version: number;
  shared_with: string[];
}

export interface CreateTemplateRequest {
  name: string;
  description?: string;
  framework: string;
  framework_version: string;
  target_type: string;
  variable_overrides: Record<string, string>;
  rule_filter?: Record<string, any>;
  tags: string[];
  is_public: boolean;
}

export interface UpdateTemplateRequest {
  name?: string;
  description?: string;
  variable_overrides?: Record<string, string>;
  rule_filter?: Record<string, any>;
  tags?: string[];
  is_public?: boolean;
}

export interface ValidationResult {
  valid: boolean;
  errors: Record<string, string>;
  warnings: Record<string, string>;
}

export interface ApplyTemplateRequest {
  target: {
    type: string;
    identifier: string;
    credentials?: Record<string, any>;
  };
  variable_overrides?: Record<string, string>;
}

export interface TemplateStatistics {
  total_templates: number;
  user_templates: number;
  public_templates: number;
  default_template?: string;
  most_used_template?: string;
  frameworks: Record<string, number>;
}
