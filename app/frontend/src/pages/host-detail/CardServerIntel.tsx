// CardServerIntel — Host detail left-column "Server intelligence" card.
//
// Replaces the "Not yet collected (BACKLOG)" empty-state with a real
// feed sourced from GET /api/v1/intelligence/events?host_id=X&limit=10.
// The query key matches the invalidation target used by
// useLiveEvents.ts (intelligence.event handler) so SSE-driven
// auto-refresh works without any polling.
//
// Three explicit visual states (loading / error+Retry / empty):
// operators need to distinguish "not loaded" from "no signal".
//
// Spec: frontend-host-detail-intelligence-feed v1.0.0.

import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { RefreshCw } from 'lucide-react';
import api from '@/api/client';

type EventSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

interface IntelligenceEvent {
  id: string;
  host_id: string;
  event_code: string;
  severity: EventSeverity;
  detail?: Record<string, unknown>;
  occurred_at: string;
  detected_at: string;
  correlation_id?: string;
}

interface IntelligenceEventsPage {
  items: IntelligenceEvent[];
  next_cursor?: string | null;
}

interface CardServerIntelProps {
  hostId: string;
}

const LIMIT = 10;

export function CardServerIntel({ hostId }: CardServerIntelProps) {
  // Spec C-01 + C-02: single endpoint, query key matches
  // useLiveEvents intelligence.event invalidation target.
  const query = useQuery({
    queryKey: ['host_intelligence_events', hostId],
    queryFn: async () => {
      const { data, error, response } = await api.GET(
        '/api/v1/intelligence/events',
        { params: { query: { host_id: hostId, limit: LIMIT } } },
      );
      if (error) throw error;
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return (data as unknown as IntelligenceEventsPage) ?? { items: [] };
    },
    retry: 0,
  });

  return (
    <CardServerIntelView
      isLoading={query.isLoading}
      isError={query.isError}
      items={query.data?.items ?? []}
      onRetry={() => query.refetch()}
    />
  );
}

// Pure view component — split out so component tests can mount it
// with explicit state without needing to mock useQuery internals.
// Spec AC-03..AC-06 exercise this directly.
interface CardServerIntelViewProps {
  isLoading: boolean;
  isError: boolean;
  items: IntelligenceEvent[];
  onRetry: () => void;
}

export function CardServerIntelView({
  isLoading,
  isError,
  items,
  onRetry,
}: CardServerIntelViewProps) {
  return (
    <Card title="Server intelligence">
      {isLoading ? (
        <div role="status" style={{ color: 'var(--ow-fg-2)', fontSize: 12 }}>
          Loading…
        </div>
      ) : isError ? (
        <ErrorState onRetry={onRetry} />
      ) : items.length === 0 ? (
        <EmptyState
          primary="No intelligence activity yet"
          secondary="The OS Intelligence collector populates this feed (package updates, service state changes, listening-port shifts). Each cycle that detects a change writes an event."
        />
      ) : (
        <ol
          style={{
            listStyle: 'none',
            padding: 0,
            margin: 0,
            display: 'flex',
            flexDirection: 'column',
            gap: 8,
          }}
        >
          {items.map((e) => (
            <EventRow key={e.id} event={e} />
          ))}
        </ol>
      )}
    </Card>
  );
}

function EventRow({ event }: { event: IntelligenceEvent }) {
  const sev = severityFor(event.severity);
  return (
    <li
      style={{
        display: 'flex',
        gap: 10,
        alignItems: 'flex-start',
        padding: '8px 0',
        borderBottom: '1px solid var(--ow-line)',
      }}
    >
      <span
        aria-hidden
        style={{
          width: 8,
          height: 8,
          marginTop: 6,
          borderRadius: '50%',
          background: sev.dot,
          flexShrink: 0,
        }}
      />
      <div style={{ minWidth: 0, flex: 1 }}>
        <div
          style={{
            color: 'var(--ow-fg-1)',
            fontSize: 12,
            fontFamily: 'var(--ow-font-mono)',
            wordBreak: 'break-word',
          }}
        >
          {event.event_code}
        </div>
      </div>
      <div
        style={{
          color: 'var(--ow-fg-3)',
          fontSize: 11,
          whiteSpace: 'nowrap',
        }}
      >
        {relativeTime(event.occurred_at)}
      </div>
    </li>
  );
}

function ErrorState({ onRetry }: { onRetry: () => void }) {
  return (
    <div
      role="alert"
      style={{
        color: 'var(--ow-crit)',
        fontSize: 12,
        display: 'flex',
        gap: 8,
        alignItems: 'center',
      }}
    >
      Failed to load intelligence events{' '}
      <button
        type="button"
        onClick={onRetry}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 4,
          padding: '2px 8px',
          background: 'transparent',
          color: 'var(--ow-fg-2)',
          border: '1px solid var(--ow-line)',
          borderRadius: 4,
          fontSize: 11,
          cursor: 'pointer',
        }}
      >
        <RefreshCw size={11} /> Retry
      </button>
    </div>
  );
}

function severityFor(s: EventSeverity): { dot: string } {
  switch (s) {
    case 'critical':
    case 'high':
      return { dot: 'var(--ow-crit)' };
    case 'medium':
      return { dot: 'var(--ow-warn)' };
    case 'low':
    case 'info':
    default:
      return { dot: 'var(--ow-fg-3)' };
  }
}

// relativeTime — "Xm ago" / "Xh ago" / "Xd ago" / "just now".
// Pure given a fixed Date.now(); jsdom freezes time per-test.
function relativeTime(iso: string): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '—';
  const minutes = Math.max(0, Math.round((Date.now() - t) / 60_000));
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

// ── Layout primitives ─────────────────────────────────────────────────────
// Mirror the CardSystem inline primitives — same comment applies: a
// deduping pass that moves Card / EmptyState into a shared module is
// a follow-up (BACKLOG).

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: 18,
      }}
    >
      <header style={{ marginBottom: 12, display: 'flex', justifyContent: 'space-between' }}>
        <h3 style={{ margin: 0, fontSize: 14, fontWeight: 600 }}>{title}</h3>
      </header>
      <div>{children}</div>
    </section>
  );
}

function EmptyState({
  primary,
  secondary,
}: {
  primary: string;
  secondary: string;
}) {
  return (
    <div
      role="status"
      style={{
        padding: '20px 0',
        textAlign: 'center',
        color: 'var(--ow-fg-2)',
      }}
    >
      <div style={{ color: 'var(--ow-fg-1)', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>
        {primary}
      </div>
      <div
        style={{
          fontSize: 11,
          color: 'var(--ow-fg-3)',
          maxWidth: 360,
          margin: '0 auto',
          lineHeight: 1.5,
        }}
      >
        {secondary}
      </div>
    </div>
  );
}
