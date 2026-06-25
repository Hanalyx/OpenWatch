import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/api/client';

// useNotifications — the durable, server-backed in-app notification feed (the
// bell). Replaces the old session-scoped report counter: the badge and the
// drawer read per-user notifications from GET /api/v1/notifications/feed, and
// read-state is persisted via the :read / :read-all endpoints.
//
// Polls on a modest interval so the badge stays current; useLiveEvents also
// invalidates ['notifications','feed'] on relevant SSE events for snappier
// updates. Spec system-notifications / frontend-notifications.

export const NOTIFICATIONS_KEY = ['notifications', 'feed'] as const;

export function useNotificationFeed() {
  return useQuery({
    queryKey: NOTIFICATIONS_KEY,
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/notifications/feed', {});
      if (error || !response.ok) throw new Error(`HTTP ${response.status}`);
      return data!;
    },
    // Background poll. AUTH-1 (c) marks this as background so it does not slide
    // the session idle window.
    refetchInterval: 30_000,
  });
}

export function useMarkNotificationRead() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const { error, response } = await api.POST('/api/v1/notifications/feed/{id}:read', {
        params: { path: { id } },
      });
      if (error || !response.ok) throw new Error(`HTTP ${response.status}`);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: NOTIFICATIONS_KEY }),
  });
}

export function useMarkAllNotificationsRead() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const { error, response } = await api.POST('/api/v1/notifications/feed:read-all', {});
      if (error || !response.ok) throw new Error(`HTTP ${response.status}`);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: NOTIFICATIONS_KEY }),
  });
}
