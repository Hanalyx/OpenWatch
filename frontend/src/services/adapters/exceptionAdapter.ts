/**
 * Exception API Adapter
 *
 * Type definitions and API client for the /api/compliance/exceptions endpoints.
 * Manages compliance exception requests, approvals, rejections, and revocations.
 *
 * Part of Phase 3: Governance Primitives (Kensa Integration Plan)
 *
 * @module services/adapters/exceptionAdapter
 */

import { api } from '../api';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Compliance exception response from the backend */
export interface ComplianceException {
  id: string;
  rule_id: string;
  host_id: string | null;
  host_group_id: number | null;

  justification: string;
  risk_acceptance: string | null;
  compensating_controls: string | null;
  business_impact: string | null;

  status: string; // pending, approved, rejected, expired, revoked
  requested_by: number;
  requested_at: string;
  approved_by: number | null;
  approved_at: string | null;
  rejected_by: number | null;
  rejected_at: string | null;
  rejection_reason: string | null;
  expires_at: string;
  revoked_by: number | null;
  revoked_at: string | null;
  revocation_reason: string | null;

  created_at: string;
  updated_at: string;

  is_active: boolean;
  days_until_expiry: number | null;
}

/** Paginated list response for exceptions */
export interface ExceptionListResponse {
  items: ComplianceException[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

/** Exception summary statistics */
export interface ExceptionSummary {
  total_pending: number;
  total_approved: number;
  total_rejected: number;
  total_expired: number;
  total_revoked: number;
  expiring_soon: number;
}

/** Request body for creating a new exception */
export interface ExceptionCreateRequest {
  rule_id: string;
  host_id?: string | null;
  host_group_id?: number | null;
  justification: string;
  risk_acceptance?: string | null;
  compensating_controls?: string | null;
  business_impact?: string | null;
  duration_days: number;
}

/** Query parameters for listing exceptions */
export interface ExceptionListParams {
  page?: number;
  per_page?: number;
  status?: string;
  rule_id?: string;
  host_id?: string;
}

// ---------------------------------------------------------------------------
// API client
// ---------------------------------------------------------------------------

export const exceptionService = {
  /** List exceptions with optional filters and pagination */
  list: (params?: ExceptionListParams) =>
    api.get<ExceptionListResponse>('/api/compliance/exceptions', { params }),

  /** Get exception summary statistics */
  summary: () => api.get<ExceptionSummary>('/api/compliance/exceptions/summary'),

  /** Get a single exception by ID */
  get: (id: string) => api.get<ComplianceException>(`/api/compliance/exceptions/${id}`),

  /** Request a new compliance exception */
  request: (data: ExceptionCreateRequest) =>
    api.post<ComplianceException>('/api/compliance/exceptions', data),

  /** Approve a pending exception (admin only) */
  approve: (id: string, comments?: string) =>
    api.post<ComplianceException>(`/api/compliance/exceptions/${id}/approve`, { comments }),

  /** Reject a pending exception (admin only) */
  reject: (id: string, reason: string) =>
    api.post<ComplianceException>(`/api/compliance/exceptions/${id}/reject`, { reason }),

  /** Revoke an approved exception (admin only) */
  revoke: (id: string, reason: string) =>
    api.post<ComplianceException>(`/api/compliance/exceptions/${id}/revoke`, { reason }),

  /** Check if a rule is currently excepted for a host */
  check: (ruleId: string, hostId: string) =>
    api.post<{ is_excepted: boolean; exception_id: string | null; expires_at: string | null }>(
      '/api/compliance/exceptions/check',
      { rule_id: ruleId, host_id: hostId }
    ),
};
