/**
 * Remediation API Adapter
 *
 * Provides type-safe access to the remediation API endpoints.
 * Transforms snake_case backend responses to camelCase frontend types.
 *
 * Part of K-2: Remediation Workflow (Phase 1+2: Single-Host)
 *
 * @module services/adapters/remediationAdapter
 */

import { api } from '../api';

// =============================================================================
// Types (camelCase frontend)
// =============================================================================

export interface RemediationStep {
  id: string;
  resultId: string;
  stepIndex: number;
  mechanism: string;
  success: boolean;
  detail: string | null;
  preStateData: Record<string, unknown> | null;
  preStateCapturable: boolean | null;
  verified: boolean | null;
  verifyDetail: string | null;
  riskLevel: string | null;
  createdAt: string | null;
}

export interface EvidenceEntry {
  method?: string;
  command?: string;
  stdout?: string;
  stderr?: string;
  exit_code?: number;
  expected?: string;
  actual?: string;
  timestamp?: string;
}

export interface RemediationResult {
  id: string;
  jobId: string;
  ruleId: string;
  status: string;
  exitCode: number | null;
  stdout: string | null;
  stderr: string | null;
  durationMs: number | null;
  errorMessage: string | null;
  rollbackAvailable: boolean;
  rollbackExecuted: boolean;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
  remediated: boolean | null;
  remediationDetail: string | null;
  rolledBack: boolean | null;
  stepCount: number | null;
  riskLevel: string | null;
  evidence: EvidenceEntry[] | null;
  frameworkRefs: Record<string, string> | null;
}

export interface RemediationJob {
  id: string;
  hostId: string;
  scanId: string | null;
  ruleIds: string[];
  dryRun: boolean;
  status: string;
  progress: number;
  totalRules: number;
  completedRules: number;
  failedRules: number;
  skippedRules: number;
  errorMessage: string | null;
  rollbackAvailable: boolean;
  rollbackJobId: string | null;
  requestedBy: number;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
  durationSeconds: number | null;
}

export interface RemediationJobDetail {
  job: RemediationJob;
  results: RemediationResult[];
}

export interface RemediationJobList {
  items: RemediationJob[];
  total: number;
  page: number;
  perPage: number;
  totalPages: number;
}

export interface PlanRuleDetail {
  ruleId: string;
  title: string;
  severity: string;
  riskLevel: string;
  steps: Array<{
    stepIndex: number;
    mechanism: string;
    detail: string | null;
    riskLevel: string;
    verified: boolean | null;
  }>;
  estimatedDurationSeconds: number;
  requiresReboot: boolean;
  warnings: string[];
}

export interface RemediationPlan {
  hostId: string;
  ruleCount: number;
  rules: PlanRuleDetail[];
  estimatedDurationSeconds: number;
  warnings: string[];
  requiresReboot: boolean;
  dependencies: string[];
  riskSummary: Record<string, number>;
}

export interface RollbackResponse {
  rollbackJobId: string;
  originalJobId: string;
  status: string;
  rulesRolledBack: number;
  rulesFailed: number;
  message: string;
}

export interface CreateJobRequest {
  host_id: string;
  rule_ids: string[];
  scan_id?: string;
  dry_run?: boolean;
  framework?: string;
}

export interface RollbackRequest {
  job_id: string;
  rule_ids?: string[];
}

// =============================================================================
// Transformers (snake_case API -> camelCase frontend)
// =============================================================================

function transformJob(data: Record<string, unknown>): RemediationJob {
  return {
    id: data.id as string,
    hostId: data.host_id as string,
    scanId: (data.scan_id as string) || null,
    ruleIds: (data.rule_ids as string[]) || [],
    dryRun: data.dry_run as boolean,
    status: data.status as string,
    progress: (data.progress as number) || 0,
    totalRules: (data.total_rules as number) || 0,
    completedRules: (data.completed_rules as number) || 0,
    failedRules: (data.failed_rules as number) || 0,
    skippedRules: (data.skipped_rules as number) || 0,
    errorMessage: (data.error_message as string) || null,
    rollbackAvailable: (data.rollback_available as boolean) || false,
    rollbackJobId: (data.rollback_job_id as string) || null,
    requestedBy: data.requested_by as number,
    createdAt: data.created_at as string,
    startedAt: (data.started_at as string) || null,
    completedAt: (data.completed_at as string) || null,
    durationSeconds: (data.duration_seconds as number) || null,
  };
}

function transformResult(data: Record<string, unknown>): RemediationResult {
  return {
    id: data.id as string,
    jobId: data.job_id as string,
    ruleId: data.rule_id as string,
    status: data.status as string,
    exitCode: (data.exit_code as number) ?? null,
    stdout: (data.stdout as string) || null,
    stderr: (data.stderr as string) || null,
    durationMs: (data.duration_ms as number) ?? null,
    errorMessage: (data.error_message as string) || null,
    rollbackAvailable: (data.rollback_available as boolean) || false,
    rollbackExecuted: (data.rollback_executed as boolean) || false,
    createdAt: data.created_at as string,
    startedAt: (data.started_at as string) || null,
    completedAt: (data.completed_at as string) || null,
    remediated: (data.remediated as boolean) ?? null,
    remediationDetail: (data.remediation_detail as string) || null,
    rolledBack: (data.rolled_back as boolean) ?? null,
    stepCount: (data.step_count as number) ?? null,
    riskLevel: (data.risk_level as string) || null,
    evidence: (data.evidence as EvidenceEntry[]) || null,
    frameworkRefs: (data.framework_refs as Record<string, string>) || null,
  };
}

function transformStep(data: Record<string, unknown>): RemediationStep {
  return {
    id: data.id as string,
    resultId: data.result_id as string,
    stepIndex: data.step_index as number,
    mechanism: data.mechanism as string,
    success: data.success as boolean,
    detail: (data.detail as string) || null,
    preStateData: (data.pre_state_data as Record<string, unknown>) || null,
    preStateCapturable: (data.pre_state_capturable as boolean) ?? null,
    verified: (data.verified as boolean) ?? null,
    verifyDetail: (data.verify_detail as string) || null,
    riskLevel: (data.risk_level as string) || null,
    createdAt: (data.created_at as string) || null,
  };
}

function transformPlanRule(data: Record<string, unknown>): PlanRuleDetail {
  const steps = (data.steps as Array<Record<string, unknown>>) || [];
  return {
    ruleId: data.rule_id as string,
    title: data.title as string,
    severity: data.severity as string,
    riskLevel: data.risk_level as string,
    steps: steps.map((s) => ({
      stepIndex: (s.step_index as number) || 0,
      mechanism: s.mechanism as string,
      detail: (s.detail as string) || null,
      riskLevel: (s.risk_level as string) || 'na',
      verified: (s.verified as boolean) ?? null,
    })),
    estimatedDurationSeconds: (data.estimated_duration_seconds as number) || 5,
    requiresReboot: (data.requires_reboot as boolean) || false,
    warnings: (data.warnings as string[]) || [],
  };
}

function transformPlan(data: Record<string, unknown>): RemediationPlan {
  const rules = (data.rules as Array<Record<string, unknown>>) || [];
  return {
    hostId: data.host_id as string,
    ruleCount: data.rule_count as number,
    rules: rules.map(transformPlanRule),
    estimatedDurationSeconds: (data.estimated_duration_seconds as number) || 0,
    warnings: (data.warnings as string[]) || [],
    requiresReboot: (data.requires_reboot as boolean) || false,
    dependencies: (data.dependencies as string[]) || [],
    riskSummary: (data.risk_summary as Record<string, number>) || {},
  };
}

function transformRollbackResponse(data: Record<string, unknown>): RollbackResponse {
  return {
    rollbackJobId: data.rollback_job_id as string,
    originalJobId: data.original_job_id as string,
    status: data.status as string,
    rulesRolledBack: (data.rules_rolled_back as number) || 0,
    rulesFailed: (data.rules_failed as number) || 0,
    message: data.message as string,
  };
}

// =============================================================================
// API Response types for typed api calls
// =============================================================================

interface ApiJobResponse extends Record<string, unknown> {
  id: string;
}

interface ApiJobDetailResponse {
  job: Record<string, unknown>;
  results: Record<string, unknown>[];
}

interface ApiJobListResponse {
  items: Record<string, unknown>[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

// =============================================================================
// API Methods
// =============================================================================

const BASE_URL = '/api/compliance/remediation';

export const remediationAdapter = {
  /** Create a new remediation job. */
  async createJob(data: CreateJobRequest): Promise<RemediationJob> {
    const raw = await api.post<ApiJobResponse>(BASE_URL, data);
    return transformJob(raw);
  },

  /** Get remediation job details including results. */
  async getJob(jobId: string): Promise<RemediationJobDetail> {
    const raw = await api.get<ApiJobDetailResponse>(`${BASE_URL}/${jobId}`);
    return {
      job: transformJob(raw.job),
      results: (raw.results || []).map((r: Record<string, unknown>) => transformResult(r)),
    };
  },

  /** List remediation jobs with pagination and filtering. */
  async listJobs(params?: {
    hostId?: string;
    status?: string;
    page?: number;
    perPage?: number;
  }): Promise<RemediationJobList> {
    const raw = await api.get<ApiJobListResponse>(BASE_URL, {
      params: {
        host_id: params?.hostId,
        status: params?.status,
        page: params?.page || 1,
        per_page: params?.perPage || 20,
      },
    });
    return {
      items: (raw.items || []).map((j: Record<string, unknown>) => transformJob(j)),
      total: raw.total,
      page: raw.page,
      perPage: raw.per_page,
      totalPages: raw.total_pages,
    };
  },

  /** Get a remediation plan (dry-run preview). */
  async getPlan(data: CreateJobRequest): Promise<RemediationPlan> {
    const raw = await api.post<Record<string, unknown>>(`${BASE_URL}/plan`, data);
    return transformPlan(raw);
  },

  /** Cancel a pending or running remediation job. */
  async cancelJob(jobId: string): Promise<RemediationJob> {
    const raw = await api.post<Record<string, unknown>>(`${BASE_URL}/${jobId}/cancel`);
    return transformJob(raw);
  },

  /** Request rollback for a completed remediation job. */
  async requestRollback(data: RollbackRequest): Promise<RollbackResponse> {
    const raw = await api.post<Record<string, unknown>>(`${BASE_URL}/rollback`, data);
    return transformRollbackResponse(raw);
  },

  /** Get step-level results for a specific rule remediation. */
  async getSteps(jobId: string, resultId: string): Promise<RemediationStep[]> {
    const raw = await api.get<Record<string, unknown>[]>(
      `${BASE_URL}/${jobId}/results/${resultId}/steps`
    );
    return (raw || []).map((s: Record<string, unknown>) => transformStep(s));
  },

  /** Check which rules support auto-remediation. Returns { ruleId: boolean }. */
  async checkRules(ruleIds: string[]): Promise<Record<string, boolean>> {
    return api.post<Record<string, boolean>>(`${BASE_URL}/check-rules`, ruleIds);
  },
};
