/**
 * Rule Reference API Adapter
 *
 * Transforms snake_case backend API responses to camelCase frontend types
 * for the Rule Reference page. Provides access to Kensa compliance rules,
 * frameworks, categories, variables, and capability probes.
 *
 * Part of OpenWatch OS Transformation.
 *
 * @module services/adapters/ruleReferenceAdapter
 */

import { api } from '../api';
import type {
  RuleSummary,
  RuleDetail,
  RuleListResponse,
  RuleDetailResponse,
  FrameworkInfo,
  FrameworkListResponse,
  CategoryInfo,
  CategoryListResponse,
  VariableDefinition,
  VariableListResponse,
  CapabilityProbe,
  CapabilityListResponse,
  RuleStatistics,
  RuleSearchParams,
  FrameworkReferences,
  CISReference,
  STIGReference,
  Implementation,
  CheckDefinition,
  RemediationDefinition,
} from '../../types/ruleReference';

// =============================================================================
// API Response Types (snake_case from backend)
// =============================================================================

interface ApiCISReference {
  section: string;
  level: string;
  type: string;
}

interface ApiSTIGReference {
  vuln_id: string;
  stig_id: string;
  severity: string;
  cci: string[];
}

interface ApiFrameworkReferences {
  cis: Record<string, ApiCISReference>;
  stig: Record<string, ApiSTIGReference>;
  nist_80053: string[];
  pci_dss_4: string[];
  srg: string[];
}

interface ApiCheckDefinition {
  method: string;
  path: string | null;
  key: string | null;
  expected: string | null;
  comparator: string | null;
  rule: string | null;
}

interface ApiRemediationDefinition {
  mechanism: string;
  path: string | null;
  key: string | null;
  value: string | null;
  reload: string | null;
  command: string | null;
}

interface ApiImplementation {
  capability_required: string | null;
  is_default: boolean;
  check: ApiCheckDefinition;
  remediation: ApiRemediationDefinition | null;
}

interface ApiRuleSummary {
  id: string;
  title: string;
  severity: string;
  category: string;
  tags: string[];
  platforms: string[];
  framework_count: number;
  has_remediation: boolean;
}

interface ApiRuleDetail {
  id: string;
  title: string;
  description: string;
  rationale: string;
  severity: string;
  category: string;
  tags: string[];
  platforms: Array<{ family: string; min_version?: number }>;
  references: ApiFrameworkReferences;
  implementations: ApiImplementation[];
  depends_on: string[];
  conflicts_with: string[];
}

interface ApiRuleListResponse {
  rules: ApiRuleSummary[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

interface ApiRuleDetailResponse {
  rule: ApiRuleDetail;
}

interface ApiFrameworkInfo {
  id: string;
  name: string;
  description: string;
  versions: string[];
  rule_count: number;
}

interface ApiFrameworkListResponse {
  frameworks: ApiFrameworkInfo[];
  total: number;
}

interface ApiCategoryInfo {
  id: string;
  name: string;
  description: string;
  rule_count: number;
}

interface ApiCategoryListResponse {
  categories: ApiCategoryInfo[];
  total: number;
}

interface ApiVariableDefinition {
  name: string;
  default_value: number | string;
  description: string | null;
  framework_overrides: Record<string, number | string>;
  used_by_rules: string[];
}

interface ApiVariableListResponse {
  variables: ApiVariableDefinition[];
  total: number;
}

interface ApiCapabilityProbe {
  id: string;
  name: string;
  description: string;
  detection_method: string;
  rules_requiring: number;
}

interface ApiCapabilityListResponse {
  capabilities: ApiCapabilityProbe[];
  total: number;
}

interface ApiRuleStatistics {
  total_rules: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  by_framework: Record<string, number>;
  with_remediation: number;
  without_remediation: number;
}

// =============================================================================
// Transformation Functions
// =============================================================================

function adaptCISReference(ref: ApiCISReference): CISReference {
  return {
    section: ref.section,
    level: ref.level,
    type: ref.type,
  };
}

function adaptSTIGReference(ref: ApiSTIGReference): STIGReference {
  return {
    vulnId: ref.vuln_id,
    stigId: ref.stig_id,
    severity: ref.severity,
    cci: ref.cci,
  };
}

function adaptFrameworkReferences(refs: ApiFrameworkReferences): FrameworkReferences {
  const cisTransformed: Record<string, CISReference> = {};
  for (const [key, value] of Object.entries(refs.cis || {})) {
    cisTransformed[key] = adaptCISReference(value);
  }

  const stigTransformed: Record<string, STIGReference> = {};
  for (const [key, value] of Object.entries(refs.stig || {})) {
    stigTransformed[key] = adaptSTIGReference(value);
  }

  return {
    cis: cisTransformed,
    stig: stigTransformed,
    nist80053: refs.nist_80053 || [],
    pciDss4: refs.pci_dss_4 || [],
    srg: refs.srg || [],
  };
}

function adaptCheckDefinition(check: ApiCheckDefinition): CheckDefinition {
  return {
    method: check.method,
    path: check.path,
    key: check.key,
    expected: check.expected,
    comparator: check.comparator,
    rule: check.rule,
  };
}

function adaptRemediationDefinition(
  remediation: ApiRemediationDefinition | null
): RemediationDefinition | null {
  if (!remediation) return null;
  return {
    mechanism: remediation.mechanism,
    path: remediation.path,
    key: remediation.key,
    value: remediation.value,
    reload: remediation.reload,
    command: remediation.command,
  };
}

function adaptImplementation(impl: ApiImplementation): Implementation {
  return {
    capabilityRequired: impl.capability_required,
    isDefault: impl.is_default,
    check: adaptCheckDefinition(impl.check),
    remediation: adaptRemediationDefinition(impl.remediation),
  };
}

function adaptRuleSummary(rule: ApiRuleSummary): RuleSummary {
  return {
    id: rule.id,
    title: rule.title,
    severity: rule.severity as RuleSummary['severity'],
    category: rule.category,
    tags: rule.tags,
    platforms: rule.platforms,
    frameworkCount: rule.framework_count,
    hasRemediation: rule.has_remediation,
  };
}

function adaptRuleDetail(rule: ApiRuleDetail): RuleDetail {
  return {
    id: rule.id,
    title: rule.title,
    description: rule.description,
    rationale: rule.rationale,
    severity: rule.severity as RuleDetail['severity'],
    category: rule.category,
    tags: rule.tags,
    platforms: rule.platforms,
    references: adaptFrameworkReferences(rule.references),
    implementations: rule.implementations.map(adaptImplementation),
    dependsOn: rule.depends_on,
    conflictsWith: rule.conflicts_with,
  };
}

function adaptFrameworkInfo(fw: ApiFrameworkInfo): FrameworkInfo {
  return {
    id: fw.id,
    name: fw.name,
    description: fw.description,
    versions: fw.versions,
    ruleCount: fw.rule_count,
  };
}

function adaptCategoryInfo(cat: ApiCategoryInfo): CategoryInfo {
  return {
    id: cat.id,
    name: cat.name,
    description: cat.description,
    ruleCount: cat.rule_count,
  };
}

function adaptVariableDefinition(variable: ApiVariableDefinition): VariableDefinition {
  return {
    name: variable.name,
    defaultValue: variable.default_value,
    description: variable.description,
    frameworkOverrides: variable.framework_overrides,
    usedByRules: variable.used_by_rules,
  };
}

function adaptCapabilityProbe(cap: ApiCapabilityProbe): CapabilityProbe {
  return {
    id: cap.id,
    name: cap.name,
    description: cap.description,
    detectionMethod: cap.detection_method,
    rulesRequiring: cap.rules_requiring,
  };
}

function adaptRuleStatistics(stats: ApiRuleStatistics): RuleStatistics {
  return {
    totalRules: stats.total_rules,
    bySeverity: stats.by_severity,
    byCategory: stats.by_category,
    byFramework: stats.by_framework,
    withRemediation: stats.with_remediation,
    withoutRemediation: stats.without_remediation,
  };
}

// =============================================================================
// API Functions
// =============================================================================

/**
 * Build query string from search params
 */
function buildQueryString(params?: RuleSearchParams): string {
  if (!params) return '';

  const searchParams = new URLSearchParams();

  if (params.search) searchParams.append('search', params.search);
  if (params.framework) searchParams.append('framework', params.framework);
  if (params.category) searchParams.append('category', params.category);
  if (params.severity) searchParams.append('severity', params.severity);
  if (params.capability) searchParams.append('capability', params.capability);
  if (params.tags) searchParams.append('tags', params.tags);
  if (params.platform) searchParams.append('platform', params.platform);
  if (params.hasRemediation !== undefined) {
    searchParams.append('has_remediation', String(params.hasRemediation));
  }
  if (params.page) searchParams.append('page', String(params.page));
  if (params.perPage) searchParams.append('per_page', String(params.perPage));

  const qs = searchParams.toString();
  return qs ? `?${qs}` : '';
}

/**
 * Fetch paginated list of rules with optional filtering
 */
export async function fetchRules(params?: RuleSearchParams): Promise<RuleListResponse> {
  const queryString = buildQueryString(params);
  const data = await api.get<ApiRuleListResponse>(`/api/rules/reference${queryString}`);
  return {
    rules: data.rules.map(adaptRuleSummary),
    total: data.total,
    page: data.page,
    perPage: data.per_page,
    totalPages: data.total_pages,
  };
}

/**
 * Fetch detailed information for a specific rule
 */
export async function fetchRuleDetail(ruleId: string): Promise<RuleDetailResponse> {
  const data = await api.get<ApiRuleDetailResponse>(`/api/rules/reference/${ruleId}`);
  return {
    rule: adaptRuleDetail(data.rule),
  };
}

/**
 * Fetch rule statistics
 */
export async function fetchRuleStatistics(): Promise<RuleStatistics> {
  const data = await api.get<ApiRuleStatistics>('/api/rules/reference/stats');
  return adaptRuleStatistics(data);
}

/**
 * Fetch list of frameworks
 */
export async function fetchFrameworks(): Promise<FrameworkListResponse> {
  const data = await api.get<ApiFrameworkListResponse>('/api/rules/reference/frameworks');
  return {
    frameworks: data.frameworks.map(adaptFrameworkInfo),
    total: data.total,
  };
}

/**
 * Fetch list of categories
 */
export async function fetchCategories(): Promise<CategoryListResponse> {
  const data = await api.get<ApiCategoryListResponse>('/api/rules/reference/categories');
  return {
    categories: data.categories.map(adaptCategoryInfo),
    total: data.total,
  };
}

/**
 * Fetch list of variables
 */
export async function fetchVariables(): Promise<VariableListResponse> {
  const data = await api.get<ApiVariableListResponse>('/api/rules/reference/variables');
  return {
    variables: data.variables.map(adaptVariableDefinition),
    total: data.total,
  };
}

/**
 * Fetch list of capability probes
 */
export async function fetchCapabilities(): Promise<CapabilityListResponse> {
  const data = await api.get<ApiCapabilityListResponse>('/api/rules/reference/capabilities');
  return {
    capabilities: data.capabilities.map(adaptCapabilityProbe),
    total: data.total,
  };
}

/**
 * Refresh rule cache (admin only)
 */
export async function refreshRuleCache(): Promise<{ message: string; rule_count: number }> {
  const data = await api.post<{ message: string; rule_count: number }>(
    '/api/rules/reference/refresh'
  );
  return data;
}
