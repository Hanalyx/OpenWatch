/**
 * Rule Reference Types
 *
 * TypeScript interfaces for the Rule Reference API and UI components.
 * These types match the backend Pydantic schemas with camelCase naming.
 */

// =============================================================================
// Framework Reference Types
// =============================================================================

export interface CISReference {
  section: string;
  level: string;
  type: string;
}

export interface STIGReference {
  vulnId: string;
  stigId: string;
  severity: string;
  cci: string[];
}

export interface FrameworkReferences {
  cis: Record<string, CISReference>;
  stig: Record<string, STIGReference>;
  nist80053: string[];
  pciDss4: string[];
  srg: string[];
}

// =============================================================================
// Check and Remediation Types
// =============================================================================

export interface CheckDefinition {
  method: string;
  path: string | null;
  key: string | null;
  expected: string | null;
  comparator: string | null;
  rule: string | null;
}

export interface RemediationDefinition {
  mechanism: string;
  path: string | null;
  key: string | null;
  value: string | null;
  reload: string | null;
  command: string | null;
}

export interface Implementation {
  capabilityRequired: string | null;
  isDefault: boolean;
  check: CheckDefinition;
  remediation: RemediationDefinition | null;
}

// =============================================================================
// Rule Types
// =============================================================================

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface RuleSummary {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  tags: string[];
  platforms: string[];
  frameworkCount: number;
  hasRemediation: boolean;
}

export interface RuleDetail {
  id: string;
  title: string;
  description: string;
  rationale: string;
  severity: Severity;
  category: string;
  tags: string[];
  platforms: Array<{ family: string; min_version?: number }>;
  references: FrameworkReferences;
  implementations: Implementation[];
  dependsOn: string[];
  conflictsWith: string[];
}

// =============================================================================
// List/Search Response Types
// =============================================================================

export interface RuleListResponse {
  rules: RuleSummary[];
  total: number;
  page: number;
  perPage: number;
  totalPages: number;
}

export interface RuleDetailResponse {
  rule: RuleDetail;
}

// =============================================================================
// Framework and Category Types
// =============================================================================

export interface FrameworkInfo {
  id: string;
  name: string;
  description: string;
  versions: string[];
  ruleCount: number;
}

export interface FrameworkListResponse {
  frameworks: FrameworkInfo[];
  total: number;
}

export interface CategoryInfo {
  id: string;
  name: string;
  description: string;
  ruleCount: number;
}

export interface CategoryListResponse {
  categories: CategoryInfo[];
  total: number;
}

// =============================================================================
// Variable Types
// =============================================================================

export interface VariableDefinition {
  name: string;
  defaultValue: number | string;
  description: string | null;
  frameworkOverrides: Record<string, number | string>;
  usedByRules: string[];
}

export interface VariableListResponse {
  variables: VariableDefinition[];
  total: number;
}

// =============================================================================
// Capability Probe Types
// =============================================================================

export interface CapabilityProbe {
  id: string;
  name: string;
  description: string;
  detectionMethod: string;
  rulesRequiring: number;
}

export interface CapabilityListResponse {
  capabilities: CapabilityProbe[];
  total: number;
}

// =============================================================================
// Statistics Types
// =============================================================================

export interface RuleStatistics {
  totalRules: number;
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
  byFramework: Record<string, number>;
  withRemediation: number;
  withoutRemediation: number;
}

// =============================================================================
// Search/Filter Types
// =============================================================================

export interface RuleSearchParams {
  search?: string;
  framework?: string;
  category?: string;
  severity?: string;
  capability?: string;
  tags?: string;
  platform?: string;
  hasRemediation?: boolean;
  page?: number;
  perPage?: number;
}
