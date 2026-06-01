import { useEffect, useRef } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useAuthStore } from '@/store/useAuthStore';

// useLiveEvents — opens one SSE connection to /api/v1/events?topics=…
// and dispatches each incoming event to the right TanStack Query
// invalidation. Mount once at the app root; multiple call sites are
// harmless but wasteful (each opens its own connection).
//
// Spec: api-events-stream (Track B).
//
// Why not WebSocket? The data flow is one-way (server → browser); SSE
// is simpler over HTTP/1.1 and works through every proxy that handles
// chunked-transfer encoding.
//
// Auth: the cookie session set by /api/v1/auth/login is forwarded by
// the browser automatically. The handler enforces host:read via the
// same identity middleware the REST endpoints use. Bearer tokens via
// query string are intentionally NOT supported (logs leak credentials).
//
// Reconnect: EventSource handles reconnection automatically with a
// 3-5s backoff. If we ever need explicit backoff control we'll switch
// to a manual fetch + ReadableStream loop.

export const ALL_TOPICS = [
  'host.changed',
  'monitoring.band.changed',
] as const;

type Topic = (typeof ALL_TOPICS)[number];

type Envelope = {
  kind: Topic;
  timestamp: string;
  payload: Record<string, unknown>;
};

interface UseLiveEventsOptions {
  /** Topics to subscribe to. Default: all known. */
  topics?: readonly Topic[];
  /** Set false to keep the hook installed but the connection closed. */
  enabled?: boolean;
}

export function useLiveEvents(options: UseLiveEventsOptions = {}) {
  const { topics = ALL_TOPICS, enabled = true } = options;
  const queryClient = useQueryClient();
  // identity presence = HttpOnly session cookie is set. We key on the
  // user id so a logout/login swap drops the old EventSource cleanly.
  const userId = useAuthStore((s) => s.identity?.id ?? null);
  const evtSourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!enabled || !userId) {
      evtSourceRef.current?.close();
      evtSourceRef.current = null;
      return;
    }

    const url = `/api/v1/events?topics=${encodeURIComponent(topics.join(','))}`;
    const es = new EventSource(url, { withCredentials: true });
    evtSourceRef.current = es;

    // Each kind gets its own listener so the runtime doesn't have to
    // parse the `event:` field manually. EventSource matches against
    // addEventListener calls keyed by the event name.
    const handlers: Record<Topic, (e: MessageEvent) => void> = {
      'host.changed': (e) => {
        const env = parseEnvelope(e);
        if (!env) return;
        const hostId = (env.payload?.HostID ?? env.payload?.host_id) as
          | string
          | undefined;
        // List page always invalidates; detail page only when we have
        // a target id (CRUD events always carry one, but defensive).
        queryClient.invalidateQueries({ queryKey: ['hosts'] });
        if (hostId) {
          queryClient.invalidateQueries({ queryKey: ['host', hostId] });
        }
      },
      'monitoring.band.changed': (e) => {
        const env = parseEnvelope(e);
        if (!env) return;
        const hostId = (env.payload?.HostID ?? env.payload?.host_id) as
          | string
          | undefined;
        // Band changes refresh the list (StatusPill colors) and the
        // specific host's detail (liveness sub-object).
        queryClient.invalidateQueries({ queryKey: ['hosts'] });
        if (hostId) {
          queryClient.invalidateQueries({ queryKey: ['host', hostId] });
        }
      },
    };

    for (const k of topics) {
      es.addEventListener(k, handlers[k]);
    }
    es.onerror = (err) => {
      // EventSource reconnects automatically; log without spamming.
      // eslint-disable-next-line no-console
      console.debug('[useLiveEvents] SSE error (will auto-reconnect)', err);
    };

    return () => {
      for (const k of topics) {
        es.removeEventListener(k, handlers[k]);
      }
      es.close();
      evtSourceRef.current = null;
    };
  }, [enabled, userId, topics, queryClient]);
}

function parseEnvelope(e: MessageEvent): Envelope | null {
  try {
    return JSON.parse(e.data) as Envelope;
  } catch {
    return null;
  }
}
