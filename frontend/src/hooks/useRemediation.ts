/**
 * React Query hooks for remediation operations.
 *
 * Provides mutations for job creation/rollback and queries for job
 * status polling and step-level results.
 *
 * Part of K-2: Remediation Workflow (Phase 1+2: Single-Host)
 *
 * @module hooks/useRemediation
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  remediationAdapter,
  type CreateJobRequest,
  type RemediationJobDetail,
  type RemediationStep,
  type RollbackRequest,
} from '../services/adapters/remediationAdapter';

/** Mutation for generating a dry-run remediation plan. */
export function useRemediationPlan() {
  return useMutation({
    mutationFn: (data: CreateJobRequest) => remediationAdapter.getPlan(data),
  });
}

/** Mutation for creating a remediation job (execute or dry-run). */
export function useCreateRemediationJob() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: CreateJobRequest) => remediationAdapter.createJob(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['remediation-jobs'] });
    },
  });
}

/**
 * Query for fetching a remediation job with auto-polling while running.
 *
 * Polls every 3 seconds while the job status is 'running' or 'pending'.
 * Stops polling once the job reaches a terminal state.
 */
export function useRemediationJob(jobId: string | null) {
  return useQuery<RemediationJobDetail>({
    queryKey: ['remediation-job', jobId],
    queryFn: () => remediationAdapter.getJob(jobId!),
    enabled: !!jobId,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return false;
      const status = data.job.status;
      if (status === 'running' || status === 'pending') return 3000;
      return false;
    },
  });
}

/** Query for fetching step-level results for a specific rule remediation. */
export function useRemediationSteps(jobId: string | null, resultId: string | null) {
  return useQuery<RemediationStep[]>({
    queryKey: ['remediation-steps', jobId, resultId],
    queryFn: () => remediationAdapter.getSteps(jobId!, resultId!),
    enabled: !!jobId && !!resultId,
  });
}

/** Mutation for requesting a rollback. */
export function useRollback() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (data: RollbackRequest) => remediationAdapter.requestRollback(data),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({
        queryKey: ['remediation-job', variables.job_id],
      });
      queryClient.invalidateQueries({ queryKey: ['remediation-jobs'] });
    },
  });
}

/** Mutation for cancelling a remediation job. */
export function useCancelRemediationJob() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (jobId: string) => remediationAdapter.cancelJob(jobId),
    onSuccess: (_data, jobId) => {
      queryClient.invalidateQueries({
        queryKey: ['remediation-job', jobId],
      });
      queryClient.invalidateQueries({ queryKey: ['remediation-jobs'] });
    },
  });
}
