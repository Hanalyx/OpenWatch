import { useQuery } from '@tanstack/react-query';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { components } from '@/api/schema';

type Exception = components['schemas']['Exception'];

// useHostExceptions fetches a host's open compliance exceptions
// (requested + approved) once and derives the views the host-detail
// surfaces need. The query key carries the ['host', hostId] prefix so
// the scan.completed SSE invalidation and exception mutations both
// refresh it, and so the Watchlist tile, the Server-intelligence tile,
// and the Compliance tab share a single round-trip.
//
// Overlay model: an exception never changes a rule's raw verdict
// (api-compliance-exceptions C-01). activeRuleIds annotates which
// failing rules are waived; it never mutates the lens data.
export interface HostExceptions {
  items: Exception[];
  activeRuleIds: Set<string>;
  pendingRuleIds: Set<string>;
  activeCount: number;
  pendingCount: number;
  isPending: boolean;
  isError: boolean;
  refetch: () => void;
}

export function useHostExceptions(hostId: string): HostExceptions {
  const query = useQuery({
    queryKey: ['host', hostId, 'exceptions'],
    queryFn: async (): Promise<Exception[]> => {
      const { data, error, response } = await api.GET('/api/v1/hosts/{id}/exceptions', {
        params: { path: { id: hostId } },
      });
      if (error || !response.ok) {
        throw new Error(apiErrorMessage(error, `Failed to load (${response.status})`));
      }
      return data!.exceptions;
    },
    enabled: !!hostId,
  });

  const items = query.data ?? [];
  const now = Date.now();
  const active = items.filter(
    (e) => e.status === 'approved' && (!e.expires_at || new Date(e.expires_at).getTime() > now),
  );
  const pending = items.filter((e) => e.status === 'requested');

  return {
    items,
    activeRuleIds: new Set(active.map((e) => e.rule_id)),
    pendingRuleIds: new Set(pending.map((e) => e.rule_id)),
    activeCount: active.length,
    pendingCount: pending.length,
    isPending: query.isPending,
    isError: query.isError,
    refetch: () => void query.refetch(),
  };
}
