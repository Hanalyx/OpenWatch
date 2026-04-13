/**
 * Transaction API Response Adapter
 *
 * Type definitions and API client for the /api/transactions endpoints.
 * Transactions represent compliance check executions (the new unified
 * model replacing scan findings).
 *
 * @module services/adapters/transactionAdapter
 */

import { api } from '../api';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Signed evidence bundle returned by the signing endpoint */
export interface SignedBundleResponse {
  envelope: Record<string, unknown>;
  signature: string;
  key_id: string;
  signed_at: string;
  signer: string;
}

/** Verification response from /api/signing/verify */
export interface VerifyResponse {
  valid: boolean;
}

/** Summary transaction returned in list responses */
export interface Transaction {
  id: string;
  host_id: string;
  rule_id: string | null;
  scan_id: string | null;
  phase: string;
  status: string;
  severity: string | null;
  initiator_type: string;
  initiator_id: string | null;
  evidence_envelope: Record<string, unknown> | null;
  framework_refs: Record<string, unknown> | null;
  started_at: string;
  completed_at: string | null;
  duration_ms: number | null;
}

/** Full transaction detail with state snapshots */
export interface TransactionDetail extends Transaction {
  pre_state: Record<string, unknown> | null;
  apply_plan: Record<string, unknown> | null;
  validate_result: Record<string, unknown> | null;
  post_state: Record<string, unknown> | null;
  baseline_id: string | null;
  remediation_job_id: string | null;
}

/** Paginated list response */
export interface TransactionListResponse {
  items: Transaction[];
  total: number;
  page: number;
  per_page: number;
}

/** Rule summary across all hosts */
export interface RuleSummary {
  rule_id: string;
  severity: string | null;
  host_count: number;
  hosts_passing: number;
  hosts_failing: number;
  hosts_skipped: number;
  change_count: number;
  last_checked_at: string | null;
  last_changed_at: string | null;
  total_checks: number;
}

/** Paginated rule summary list */
export interface RuleSummaryListResponse {
  items: RuleSummary[];
  total: number;
  page: number;
  per_page: number;
}

// ---------------------------------------------------------------------------
// API client
// ---------------------------------------------------------------------------

export const transactionService = {
  /** List transactions with optional filters */
  list: (params?: Record<string, string | number | boolean | undefined>) =>
    api.get<TransactionListResponse>('/api/transactions', { params }),

  /** Get a single transaction by ID */
  get: (id: string) => api.get<TransactionDetail>(`/api/transactions/${id}`),

  /** List transactions for a specific host */
  listByHost: (hostId: string, params?: Record<string, string | number | boolean | undefined>) =>
    api.get<TransactionListResponse>(`/api/hosts/${hostId}/transactions`, { params }),

  /** List rules with compliance state summary */
  listRules: (params?: Record<string, string | number | boolean | undefined>) =>
    api.get('/api/transactions/rules', { params }),

  /** List state-change transactions for a specific rule */
  getRuleTransactions: (
    ruleId: string,
    params?: Record<string, string | number | boolean | undefined>
  ) => api.get(`/api/transactions/rules/${ruleId}`, { params }),

  /** Sign a transaction's evidence envelope (SECURITY_ADMIN+) */
  sign: (id: string): Promise<SignedBundleResponse> =>
    api.post<SignedBundleResponse>(`/api/transactions/${id}/sign`),

  /** Verify a signed bundle against the signing key */
  verify: (
    envelope: Record<string, unknown>,
    signature: string,
    keyId: string,
  ): Promise<VerifyResponse> =>
    api.post<VerifyResponse>('/api/signing/verify', {
      envelope,
      signature,
      key_id: keyId,
    }),
};
