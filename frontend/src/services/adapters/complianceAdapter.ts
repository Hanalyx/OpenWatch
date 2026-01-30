/**
 * Compliance API Response Adapter
 *
 * Type definitions for compliance rule and framework API responses.
 * Content/compliance pages currently use snake_case interfaces directly;
 * these types centralize the API shape definitions for future refactoring.
 *
 * @module services/adapters/complianceAdapter
 */

// ---------------------------------------------------------------------------
// Backend response types (snake_case)
// ---------------------------------------------------------------------------

/** GET /api/compliance/rules response item (MongoDB document) */
export interface ApiComplianceRule {
  rule_id: string;
  title: string;
  description?: string;
  severity?: string;
  platform_implementations?: Record<string, unknown>;
  nist_r4_controls?: string[];
  nist_r5_controls?: string[];
  cis_controls?: string[];
  stigid?: string;
}

/** GET /api/compliance/rules paginated response */
export interface ApiComplianceRulesPage {
  data: ApiComplianceRule[];
  total_count: number;
  page: number;
  page_size: number;
}

/** Framework detail response */
export interface ApiFrameworkDetail {
  id: string;
  display_name: string;
  description?: string;
  rule_count: number;
  variable_count: number;
  version?: string;
}

/** Compliance template response */
export interface ApiComplianceTemplate {
  template_id: string;
  name: string;
  description?: string;
  framework_version?: string;
  variable_overrides?: Record<string, unknown>;
  is_default: boolean;
  is_public: boolean;
  created_by: string;
}

// ---------------------------------------------------------------------------
// Frontend types (camelCase) — for future use
// ---------------------------------------------------------------------------

export interface ComplianceRule {
  ruleId: string;
  title: string;
  description?: string;
  severity?: string;
  platformImplementations?: Record<string, unknown>;
  nistR4Controls?: string[];
  nistR5Controls?: string[];
  cisControls?: string[];
  stigId?: string;
}

export interface ComplianceRulesPage {
  data: ComplianceRule[];
  total: number;
  page: number;
  pageSize: number;
}

// ---------------------------------------------------------------------------
// Transformers
// ---------------------------------------------------------------------------

/** Transform a compliance rule from the backend API. */
export function adaptComplianceRule(rule: ApiComplianceRule): ComplianceRule {
  return {
    ruleId: rule.rule_id,
    title: rule.title,
    description: rule.description,
    severity: rule.severity,
    platformImplementations: rule.platform_implementations,
    nistR4Controls: rule.nist_r4_controls,
    nistR5Controls: rule.nist_r5_controls,
    cisControls: rule.cis_controls,
    stigId: rule.stigid,
  };
}

/** Transform a paginated compliance rules response. */
export function adaptComplianceRulesPage(page: ApiComplianceRulesPage): ComplianceRulesPage {
  return {
    data: page.data.map(adaptComplianceRule),
    total: page.total_count,
    page: page.page,
    pageSize: page.page_size,
  };
}
