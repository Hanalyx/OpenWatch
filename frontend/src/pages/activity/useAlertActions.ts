import { useMutation, useQueryClient } from '@tanstack/react-query';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';

// useAlertActions — the alert lifecycle mutations reachable from an
// activity row whose source is "alert" (its activity id IS the alert id;
// internal/activity/service.go selects the real alerts.id for that leg).
//
// Acknowledge / Silence / Resolve are the operator-facing subset of the
// alert state machine (active -> acknowledged -> silenced -> resolved).
// Silence is the prototype's "Mute" (indefinite here; a duration picker
// is a later refinement). On success we invalidate the activity feed and
// the alert detail so the drawer reflects the new state.
//
// Spec: frontend-activity. Backed by /alerts/{id}:action (already wired,
// gated server-side by alert:write).

export type AlertAction = 'acknowledge' | 'silence' | 'resolve';

export function useAlertActions() {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: async (vars: { id: string; action: AlertAction }) => {
      const path = `/api/v1/alerts/{id}:${vars.action}` as
        | '/api/v1/alerts/{id}:acknowledge'
        | '/api/v1/alerts/{id}:silence'
        | '/api/v1/alerts/{id}:resolve';
      const { error, response } = await api.POST(path, {
        params: { path: { id: vars.id } },
        body: {},
      });
      if (error || !response.ok) {
        throw new Error(apiErrorMessage(error, `Action failed (${response.status})`));
      }
    },
    onSuccess: (_data, vars) => {
      queryClient.invalidateQueries({ queryKey: ['activity'] });
      queryClient.invalidateQueries({ queryKey: ['alert', vars.id] });
    },
  });

  return mutation;
}
