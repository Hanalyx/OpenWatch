import { useQuery } from '@tanstack/react-query';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { components } from '@/api/schema';

type RemediationStep = components['schemas']['RemediationStep'];
type RemediationPhase = components['schemas']['RemediationPhase'];

// useRemediationSteps fetches one request's transaction journal: the
// Capture/Apply/Validate/Commit phases Kensa recorded, with the detail that
// says why each did what it did.
//
// Fetched on demand rather than with the request list. A host can carry many
// requests and the journal is only meaningful once someone opens one, so
// `enabled` gates the round-trip on the row actually being expanded.
//
// The query key sits under ['host', hostId] so the existing scan.completed SSE
// invalidation and the remediation mutations refresh it alongside the list,
// rather than leaving an expanded row showing a stale journal after a rollback.
export interface RemediationJournal {
  steps: RemediationStep[];
  isPending: boolean;
  isError: boolean;
  error: string | null;
}

export function useRemediationSteps(
  hostId: string,
  requestId: string,
  enabled: boolean,
): RemediationJournal {
  const q = useQuery({
    queryKey: ['host', hostId, 'remediation', requestId, 'steps'],
    enabled,
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/remediation/requests/{rid}/steps', {
        params: { path: { rid: requestId } },
      });
      if (error) {
        throw new Error(
          apiErrorMessage(error, `Could not load the transaction journal (${response.status})`),
        );
      }
      return data?.steps ?? [];
    },
  });

  return {
    steps: q.data ?? [],
    isPending: q.isPending,
    isError: q.isError,
    error: q.isError ? apiErrorMessage(q.error, 'Could not load the transaction journal.') : null,
  };
}

// phaseLabel names a phase for display.
//
// Kensa numbers steps but does not name them, and the mechanism (config_set,
// service_enabled) describes HOW a phase acted rather than WHICH phase it is.
// The transaction always runs Capture, Apply, Validate, then Commit or
// Rollback, so the index maps to the phase for the common four-step shape; a
// longer transaction (a rule with several apply steps) falls back to the
// mechanism, which is honest rather than inventing a name.
export function phaseLabel(phase: RemediationPhase, total: number): string {
  if (total === 4) {
    return ['Capture', 'Apply', 'Validate', 'Commit'][phase.index] ?? phase.mechanism;
  }
  return phase.mechanism;
}

// phaseNote returns the consequence an operator cannot infer from the outcome
// alone, or null when there is nothing unusual to say.
//
// These three flags each change what the operator should do next, and none of
// them is visible in the request's terminal status.
export function phaseNote(phase: RemediationPhase): string | null {
  if (phase.stranded) {
    return 'Not reversed by rollback. This step cannot capture pre-state, and it succeeded before a later step failed.';
  }
  if (phase.staged) {
    return 'Written, but the running host has not changed. A re-scan reports this rule failing until the host reboots.';
  }
  if (!phase.capturable && !phase.success) {
    return 'This step cannot capture pre-state, so it cannot be rolled back.';
  }
  return null;
}

// useRemediationPlan previews what a fix would do, before it does it.
//
// Fetched only when a row is expanded AND has no transaction yet, because
// planning reaches the host over SSH: it is a live call, not a cached read. A
// remembered plan would describe a host that has since moved on, which is the
// same staleness Kensa's PlanStaleError exists to prevent on the execute side.
//
// Deliberately no retry. A failed plan means the host could not be reached or
// authenticated, and hammering it on a schedule helps nobody.
export interface RemediationPlanView {
  plan: components['schemas']['RemediationPlan'] | null;
  isPending: boolean;
  isError: boolean;
  error: string | null;
}

export function useRemediationPlan(
  hostId: string,
  requestId: string,
  enabled: boolean,
): RemediationPlanView {
  const q = useQuery({
    queryKey: ['host', hostId, 'remediation', requestId, 'plan'],
    enabled,
    retry: false,
    staleTime: 0,
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/remediation/requests/{rid}/plan', {
        params: { path: { rid: requestId } },
      });
      if (error) {
        throw new Error(apiErrorMessage(error, `Could not plan this fix (${response.status})`));
      }
      return data ?? null;
    },
  });

  return {
    plan: q.data ?? null,
    isPending: q.isPending,
    isError: q.isError,
    error: q.isError ? apiErrorMessage(q.error, 'Could not plan this fix.') : null,
  };
}
