/**
 * Shared type definitions for ScanDetail sub-components.
 * Extracted from ScanDetail.tsx for reuse across components.
 */

export interface ScanDetails {
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
  results?: ScanResults;
}

export interface ScanResults {
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

export interface BackendRuleResult {
  rule_id?: string;
  title?: string;
  severity?: string;
  result?: string;
  description?: string;
  rationale?: string;
  remediation?: string;
}

export interface RuleResult {
  rule_id: string;
  title: string;
  severity: 'high' | 'medium' | 'low' | 'unknown';
  result: 'pass' | 'fail' | 'error' | 'unknown' | 'notapplicable';
  description: string;
  rationale?: string;
  remediation?: string;
  markedForReview?: boolean;
}

export interface ScapCommand {
  description?: string;
  command: string;
  type?: string;
}

export interface ScapConfiguration {
  description?: string;
  setting: string;
}

export interface ScapRemediationData {
  fix_text?: string;
  description?: string;
  detailed_description?: string;
  commands?: ScapCommand[];
  configuration?: ScapConfiguration[];
  steps?: string[];
  complexity?: string;
  disruption?: string;
}

export interface RemediationStep {
  title: string;
  description: string;
  command?: string;
  type: 'command' | 'config' | 'manual';
  documentation?: string;
}

export type SnackbarState = {
  open: boolean;
  message: string;
  severity: 'success' | 'error' | 'warning' | 'info';
};
