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
 * A single compliance drift event.
 */
export interface DriftEvent {
  rule_id: string;
  rule_title?: string;
  previous_status: string;
  current_status: string;
  severity: string;
  detected_at: string; // ISO 8601 datetime
  direction: 'improvement' | 'regression';
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

  // Detailed drift events
  drift_events: DriftEvent[];
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
