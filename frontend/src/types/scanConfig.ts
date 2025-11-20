/**
 * Phase 1 - Scan Configuration Types
 * Types for framework discovery, variable customization, and template management
 */

/**
 * Framework metadata - structured data about framework characteristics
 * Used for framework discovery and filtering
 */
export type FrameworkMetadata = Record<string, string | number | boolean | string[]>;

/**
 * Variable default value - can be string, number, or boolean based on variable type
 * Matches the type field in VariableDefinition
 */
export type VariableDefaultValue = string | number | boolean;

/**
 * Rule filter criteria for template-based rule selection
 * Supports filtering by severity, category, platform, and custom attributes
 */
export interface RuleFilter {
  severity?: string | string[];
  category?: string | string[];
  platform?: string | string[];
  tags?: string[];
  // Custom filter criteria as key-value pairs
  custom?: Record<string, string | number | boolean>;
}

/**
 * Credential data for scan target authentication
 * Structure matches backend credential models
 */
export interface CredentialData {
  username?: string;
  password?: string;
  ssh_key?: string;
  ssh_key_passphrase?: string;
  auth_method?: 'password' | 'ssh_key' | 'kerberos';
  sudo_password?: string;
  // Additional authentication parameters
  custom_params?: Record<string, string>;
}

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
  metadata: FrameworkMetadata;
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
  default: VariableDefaultValue;
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
  rule_filter?: RuleFilter;
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
  rule_filter?: RuleFilter;
  tags: string[];
  is_public: boolean;
}

export interface UpdateTemplateRequest {
  name?: string;
  description?: string;
  variable_overrides?: Record<string, string>;
  rule_filter?: RuleFilter;
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
    credentials?: CredentialData;
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
