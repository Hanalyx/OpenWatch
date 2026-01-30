/**
 * Scan API Response Adapter
 *
 * Type definitions and lightweight transformers for scan API responses.
 * ScanDetail.tsx currently uses snake_case interfaces directly from the API;
 * these types prepare for component extraction in S1 (Phase 3) by defining
 * the API shape and camelCase frontend equivalents in one place.
 *
 * @module services/adapters/scanAdapter
 */

// ---------------------------------------------------------------------------
// Backend response types (snake_case) — matches ScanDetail.tsx interfaces
// ---------------------------------------------------------------------------

/** GET /api/scans/:id response */
export interface ApiScanResponse {
  id: number;
  name: string;
  host_id: string;
  host_name: string;
  hostname: string;
  content_id: number;
  content_name: string;
  content_filename: string;
  profile_id: string;
  status: string;
  progress: number;
  result_file?: string;
  report_file?: string;
  error_message?: string;
  scan_options: unknown;
  started_at: string;
  completed_at?: string;
  started_by: number;
  results?: ApiScanResults;
}

export interface ApiScanResults {
  total_rules: number;
  passed_rules: number;
  failed_rules: number;
  error_rules: number;
  unknown_rules: number;
  not_applicable_rules: number;
  score: string;
  severity_high: number;
  severity_medium: number;
  severity_low: number;
  xccdf_score?: number;
  xccdf_score_max?: number;
  xccdf_score_system?: string;
  risk_score?: number;
  risk_level?: string;
}

/** Rule result from backend JSON report */
export interface ApiRuleResult {
  rule_id?: string;
  title?: string;
  severity?: string;
  result?: string;
  description?: string;
  rationale?: string;
  remediation?: string;
}

// ---------------------------------------------------------------------------
// Frontend types (camelCase) — to be used after S1 extraction
// ---------------------------------------------------------------------------

export type RuleSeverity = 'high' | 'medium' | 'low' | 'unknown';
export type RuleOutcome = 'pass' | 'fail' | 'error' | 'unknown' | 'notapplicable';

export interface RuleResult {
  ruleId: string;
  title: string;
  severity: RuleSeverity;
  result: RuleOutcome;
  description: string;
  rationale?: string;
  remediation?: string;
  markedForReview?: boolean;
}

// ---------------------------------------------------------------------------
// Transformers
// ---------------------------------------------------------------------------

const VALID_SEVERITIES = new Set<string>(['high', 'medium', 'low']);
const VALID_RESULTS = new Set<string>(['pass', 'fail', 'error', 'unknown', 'notapplicable']);

/** Normalize a rule result from the backend API. */
export function adaptRuleResult(rule: ApiRuleResult): RuleResult {
  const severity = VALID_SEVERITIES.has(rule.severity || '')
    ? (rule.severity as RuleSeverity)
    : 'unknown';

  const result = VALID_RESULTS.has(rule.result || '') ? (rule.result as RuleOutcome) : 'unknown';

  return {
    ruleId: rule.rule_id || 'unknown',
    title: rule.title || '',
    severity,
    result,
    description: rule.description || '',
    rationale: rule.rationale,
    remediation: rule.remediation,
  };
}

/** Normalize a list of rule results. */
export function adaptRuleResults(rules: ApiRuleResult[]): RuleResult[] {
  return rules.map(adaptRuleResult);
}
