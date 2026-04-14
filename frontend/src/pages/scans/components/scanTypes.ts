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

export interface RemediationCommand {
  description?: string;
  command: string;
  type?: string;
}

export interface RemediationConfiguration {
  description?: string;
  setting: string;
}

export interface RemediationData {
  fix_text?: string;
  description?: string;
  detailed_description?: string;
  commands?: RemediationCommand[];
  configuration?: RemediationConfiguration[];
  steps?: string[];
  complexity?: string;
  disruption?: string;
}

/** @deprecated Use RemediationCommand */
export type ScapCommand = RemediationCommand;
/** @deprecated Use RemediationConfiguration */
export type ScapConfiguration = RemediationConfiguration;
/** @deprecated Use RemediationData */
export type ScapRemediationData = RemediationData;

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
