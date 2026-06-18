import { useQuery } from '@tanstack/react-query';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { components } from '@/api/schema';

type RemediationRequest = components['schemas']['RemediationRequest'];

// useHostRemediations fetches a host's remediation requests once and
// derives the views the host-detail surfaces need. The query key
// carries the ['host', hostId] prefix so the scan.completed SSE
// invalidation and remediation mutations both refresh it, and so the
// Compliance tab affordance and the Remediation tab share a single
// round-trip.
//
// Free-tier lifecycle: pending_approval -> approved | rejected. The
// act verbs (dry_run/execute/rollback) are OpenWatch+ only and never
// called from the free build; the matching statuses
// (dry_run_complete/executing/executed/rolled_back) can still arrive
// from a licensed deployment, so the open set accounts for them.
//
// openRuleIds annotates which rules already carry an in-flight
// remediation (so the per-rule affordance suppresses a duplicate
// request). It never mutates the lens verdict.
const OPEN_STATUSES: ReadonlySet<RemediationRequest['status']> = new Set([
  'pending_approval',
  'approved',
  'dry_run_complete',
  'executing',
]);

export interface HostRemediations {
  items: RemediationRequest[];
  openRuleIds: Set<string>;
  pendingRuleIds: Set<string>;
  pendingCount: number;
  isPending: boolean;
  isError: boolean;
  refetch: () => void;
}

export function useHostRemediations(hostId: string): HostRemediations {
  const query = useQuery({
    queryKey: ['host', hostId, 'remediations'],
    queryFn: async (): Promise<RemediationRequest[]> => {
      const { data, error, response } = await api.GET('/api/v1/remediation/requests', {
        params: { query: { host_id: hostId } },
      });
      if (error || !response.ok) {
        throw new Error(apiErrorMessage(error, `Failed to load (${response.status})`));
      }
      return data!.requests;
    },
    enabled: !!hostId,
  });

  const items = query.data ?? [];
  // Newest first: the list panel and any "already requested" lookup
  // both want the most recent request for a rule to win.
  const sorted = [...items].sort(
    (a, b) => new Date(b.requested_at).getTime() - new Date(a.requested_at).getTime(),
  );
  const open = sorted.filter((r) => OPEN_STATUSES.has(r.status));
  const pending = sorted.filter((r) => r.status === 'pending_approval');

  return {
    items: sorted,
    openRuleIds: new Set(open.map((r) => r.rule_id)),
    pendingRuleIds: new Set(pending.map((r) => r.rule_id)),
    pendingCount: pending.length,
    isPending: query.isPending,
    isError: query.isError,
    refetch: () => void query.refetch(),
  };
}
