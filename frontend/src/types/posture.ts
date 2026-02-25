/**
 * Temporal Compliance Types
 *
 * TypeScript types for compliance posture queries and responses.
 * Matches backend schemas from backend/app/schemas/posture_schemas.py.
 *
 * Part of Phase 2: Temporal Compliance (Kensa Integration Plan)
 *
 * @module types/posture
 */

/**
 * Severity-level pass/fail breakdown.
 */
export interface SeverityBreakdown {
  passed: number;
  failed: number;
}

/**
 * State of a single rule in a posture snapshot.
 */
export interface RuleState {
  rule_id: string;
  status: 'pass' | 'fail' | 'error' | 'notapplicable';
  severity: string;
  title?: string;
  category?: string;
  actual?: string | string[];
}

/**
 * Response model for compliance posture query.
 */
export interface PostureResponse {
  host_id: string;
  snapshot_date: string; // ISO 8601 datetime
  is_current: boolean;

  // Aggregate metrics
  total_rules: number;
  passed: number;
  failed: number;
  error_count: number;
  not_applicable: number;
  compliance_score: number; // 0-100

  // Per-severity breakdown
  severity_breakdown: Record<string, SeverityBreakdown>;

  // Rule-level details (optional, can be large)
  rule_states?: Record<string, RuleState>;

  // Source scan reference
  source_scan_id?: string;
}

/**
 * Response model for posture history query.
 */
export interface PostureHistoryResponse {
  host_id: string;
  snapshots: PostureResponse[];
  total_snapshots: number;
  date_range: {
    start: string | null;
    end: string | null;
  };
}

/**
 * A single compliance drift event (status changed).
 */
export interface DriftEvent {
  rule_id: string;
  rule_title?: string;
  previous_status: string;
  current_status: string;
  severity: string;
  detected_at: string; // ISO 8601 datetime
  direction: 'improvement' | 'regression';
  previous_value?: string;
  current_value?: string;
}

/**
 * A drift event where only the actual value changed (status unchanged).
 */
export interface ValueDriftEvent {
  rule_id: string;
  rule_title?: string;
  severity: string;
  status: string;
  previous_value?: string;
  current_value?: string;
  status_changed: boolean;
  detected_at: string; // ISO 8601 datetime
}

/**
 * Response model for drift analysis between two dates.
 */
export interface DriftAnalysisResponse {
  host_id: string;
  start_date: string; // ISO 8601 datetime
  end_date: string; // ISO 8601 datetime

  // Overall drift metrics
  start_score: number;
  end_score: number;
  score_delta: number; // Positive = improvement, negative = regression
  drift_magnitude: number; // Absolute value of score change
  drift_type: 'major' | 'minor' | 'improvement' | 'stable';

  // Rule-level changes
  rules_improved: number;
  rules_regressed: number;
  rules_unchanged: number;

  // Detailed drift events (status changed)
  drift_events: DriftEvent[];

  // Value-level drift events
  value_drift_events: ValueDriftEvent[];
  rules_value_changed: number;
}

/**
 * Request parameters for posture query.
 */
export interface PostureQueryParams {
  host_id: string;
  as_of?: string; // ISO 8601 date (YYYY-MM-DD)
  include_rule_states?: boolean;
}

/**
 * Request parameters for posture history query.
 */
export interface PostureHistoryParams {
  host_id: string;
  start_date?: string; // ISO 8601 date
  end_date?: string; // ISO 8601 date
  limit?: number;
}

/**
 * Request parameters for drift analysis.
 */
export interface DriftAnalysisParams {
  host_id: string;
  start_date: string; // ISO 8601 date
  end_date: string; // ISO 8601 date
  include_value_drift?: boolean;
}

/**
 * Per-rule drift summary across a host group.
 */
export interface GroupDriftRuleSummary {
  rule_id: string;
  rule_title?: string;
  severity: string;
  affected_host_count: number;
  total_host_count: number;
  status_changes: number;
  value_changes: number;
  sample_changes: Record<string, unknown>[];
}

/**
 * Response model for group-level drift analysis.
 */
export interface GroupDriftResponse {
  group_id: number;
  group_name: string;
  start_date: string;
  end_date: string;
  total_hosts: number;
  hosts_with_drift: number;
  rule_summaries: GroupDriftRuleSummary[];
}

/**
 * Request parameters for group drift analysis.
 */
export interface GroupDriftParams {
  group_id: number;
  start_date: string;
  end_date: string;
}

/**
 * Snapshot creation request.
 */
export interface SnapshotCreateRequest {
  host_id: string;
  source_scan_id?: string;
}

/**
 * Snapshot creation response.
 */
export interface SnapshotCreateResponse {
  success: boolean;
  snapshot_id: string;
  host_id: string;
  snapshot_date: string;
  compliance_score: number;
}
