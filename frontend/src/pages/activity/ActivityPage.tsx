import { useState } from 'react';
import { useInfiniteQuery } from '@tanstack/react-query';
import { useSearch } from '@tanstack/react-router';
import { Link } from '@tanstack/react-router';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useAuthStore } from '@/store/useAuthStore';
import type { components } from '@/api/schema';
import { ActivityDrawer, severityTone } from './ActivityDrawer';
import { useAlertActions } from './useAlertActions';

type Activity = components['schemas']['Activity'];
type Source = Activity['source'];
type Severity = Activity['severity'];

// ActivityPage — the unified activity feed at /activity.
//
// MVP (frontend-activity): a day-grouped event stream over
// GET /api/v1/activity with source + severity filters and cursor
// pagination, surfacing hidden_count (RBAC-suppressed rows). Alert-source
// rows carry quick lifecycle actions (the activity id is the alert id);
// clicking any row opens a detail drawer. The richer prototype surfaces
// (histogram, facet rail, "routed to", live tail, non-alert mutation) are
// backend-gated and deferred per docs/engineering/activity_page_scope.md.

const SOURCES: Source[] = ['alert', 'transaction', 'intelligence', 'audit', 'monitoring'];
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const TONE: Record<string, string> = {
  crit: 'var(--ow-crit)',
  warn: 'var(--ow-warn)',
  info: 'var(--ow-info)',
};

function dayLabel(iso: string): string {
  const d = new Date(iso);
  const now = new Date();
  const startOf = (x: Date) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diffDays = Math.round((startOf(now) - startOf(d)) / 86_400_000);
  if (diffDays === 0) return 'Today';
  if (diffDays === 1) return 'Yesterday';
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

interface ActivitySearch {
  host_id?: string;
}

export function ActivityPage() {
  const search = useSearch({ strict: false }) as ActivitySearch;
  const hostId = search.host_id;
  const hasPermission = useAuthStore((s) => s.hasPermission);
  const canAlertWrite = hasPermission('alert:write');

  const [source, setSource] = useState<Source | ''>('');
  const [severity, setSeverity] = useState<Severity | ''>('');
  const [selected, setSelected] = useState<Activity | null>(null);

  const query = useInfiniteQuery({
    queryKey: ['activity', source, severity, hostId],
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) => {
      const { data, error, response } = await api.GET('/api/v1/activity', {
        params: {
          query: {
            limit: 50,
            ...(source ? { source } : {}),
            ...(severity ? { severity } : {}),
            ...(hostId ? { host_id: hostId } : {}),
            ...(pageParam ? { cursor: pageParam } : {}),
          },
        },
      });
      if (error || !response.ok) {
        throw new Error(apiErrorMessage(error, `Failed to load (${response.status})`));
      }
      return data!;
    },
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });

  const items = query.data?.pages.flatMap((p) => p.items) ?? [];
  const hiddenCount = query.data?.pages[0]?.hidden_count ?? 0;

  return (
    <div style={{ padding: '20px 28px 60px' }}>
      <title>Activity · OpenWatch</title>

      <header style={{ marginBottom: 16 }}>
        <h1 style={{ margin: 0, fontSize: 22, fontWeight: 600, letterSpacing: '-0.01em' }}>
          Activity
        </h1>
        <div style={{ color: 'var(--ow-fg-2)', fontSize: 13, marginTop: 2 }}>
          Unified feed across alerts, compliance, intelligence, audit, and monitoring
          {hostId ? ' (filtered to one host)' : ''}
        </div>
      </header>

      {/* filters */}
      <div
        style={{
          display: 'flex',
          gap: 10,
          marginBottom: 14,
          flexWrap: 'wrap',
          alignItems: 'center',
        }}
      >
        <FilterSelect
          label="Source"
          value={source}
          onChange={(v) => setSource(v as Source | '')}
          options={SOURCES}
        />
        <FilterSelect
          label="Severity"
          value={severity}
          onChange={(v) => setSeverity(v as Severity | '')}
          options={SEVERITIES}
        />
        {(source || severity) && (
          <button
            type="button"
            onClick={() => {
              setSource('');
              setSeverity('');
            }}
            style={{
              background: 'none',
              border: 0,
              color: 'var(--ow-link)',
              fontSize: 12,
              cursor: 'pointer',
            }}
          >
            Clear
          </button>
        )}
        <div style={{ flex: 1 }} />
        {hiddenCount > 0 && (
          <span style={{ color: 'var(--ow-fg-3)', fontSize: 12 }}>
            {hiddenCount} hidden by permissions
          </span>
        )}
      </div>

      {/* stream */}
      <div
        style={{
          background: 'var(--ow-bg-1)',
          border: '1px solid var(--ow-line)',
          borderRadius: 'var(--ow-radius)',
          overflow: 'hidden',
        }}
      >
        {query.isError ? (
          <div role="alert" style={{ padding: '16px', color: 'var(--ow-crit)', fontSize: 13 }}>
            {apiErrorMessage(query.error, 'Failed to load activity')}
          </div>
        ) : query.isPending ? (
          <div role="status" style={{ padding: '16px', color: 'var(--ow-fg-2)', fontSize: 13 }}>
            Loading…
          </div>
        ) : items.length === 0 ? (
          <div
            role="status"
            style={{
              padding: '40px 16px',
              textAlign: 'center',
              color: 'var(--ow-fg-3)',
              fontSize: 13,
            }}
          >
            No events match these filters.
          </div>
        ) : (
          <Stream items={items} canAlertWrite={canAlertWrite} onSelect={setSelected} />
        )}
      </div>

      {query.hasNextPage && (
        <div style={{ textAlign: 'center', marginTop: 14 }}>
          <button
            type="button"
            disabled={query.isFetchingNextPage}
            onClick={() => query.fetchNextPage()}
            style={{
              height: 36,
              padding: '0 18px',
              background: 'var(--ow-bg-2)',
              color: 'var(--ow-fg-0)',
              border: '1px solid var(--ow-line)',
              borderRadius: 8,
              fontFamily: 'inherit',
              fontSize: 13,
              fontWeight: 600,
              cursor: query.isFetchingNextPage ? 'default' : 'pointer',
            }}
          >
            {query.isFetchingNextPage ? 'Loading…' : 'Load more'}
          </button>
        </div>
      )}

      <ActivityDrawer
        item={selected}
        canAlertWrite={canAlertWrite}
        onClose={() => setSelected(null)}
      />
    </div>
  );
}

function Stream({
  items,
  canAlertWrite,
  onSelect,
}: {
  items: Activity[];
  canAlertWrite: boolean;
  onSelect: (a: Activity) => void;
}) {
  const actions = useAlertActions();
  let lastDay: string | null = null;

  return (
    <>
      {items.map((a, i) => {
        const day = dayLabel(a.occurred_at);
        const divider = day !== lastDay ? day : null;
        lastDay = day;
        const tone = TONE[severityTone(a.severity)];
        const isAlert = a.source === 'alert';
        return (
          <div key={a.id}>
            {divider && (
              <div
                style={{
                  padding: '12px 16px 6px',
                  color: 'var(--ow-fg-3)',
                  fontSize: 11,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                  background: 'var(--ow-bg-2)',
                }}
              >
                {divider}
              </div>
            )}
            <div
              role="button"
              tabIndex={0}
              onClick={() => onSelect(a)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  onSelect(a);
                }
              }}
              style={{
                display: 'grid',
                gridTemplateColumns: '64px 1fr auto',
                gap: 14,
                alignItems: 'baseline',
                padding: '10px 16px',
                borderTop: i === 0 ? 'none' : '1px solid var(--ow-line)',
                cursor: 'pointer',
                borderLeft: `3px solid ${tone}`,
              }}
            >
              <span
                style={{
                  color: 'var(--ow-fg-3)',
                  fontSize: 12,
                  fontFamily: 'var(--ow-font-mono, monospace)',
                  whiteSpace: 'nowrap',
                }}
              >
                {new Date(a.occurred_at).toLocaleTimeString(undefined, {
                  hour: '2-digit',
                  minute: '2-digit',
                })}
              </span>
              <div style={{ minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                  <span style={{ fontWeight: 500, fontSize: 13, color: 'var(--ow-fg-0)' }}>
                    {a.title}
                  </span>
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 600,
                      padding: '1px 7px',
                      borderRadius: 3,
                      textTransform: 'uppercase',
                      letterSpacing: '0.03em',
                      background: 'var(--ow-bg-3)',
                      color: 'var(--ow-fg-2)',
                    }}
                  >
                    {a.source}
                  </span>
                </div>
                {a.summary && (
                  <div style={{ color: 'var(--ow-fg-2)', fontSize: 12, marginTop: 3 }}>
                    {a.summary}
                  </div>
                )}
                {a.host_id && (
                  <div style={{ marginTop: 4 }}>
                    <Link
                      to="/hosts/$hostId"
                      params={{ hostId: a.host_id }}
                      onClick={(e) => e.stopPropagation()}
                      style={{
                        color: 'var(--ow-link)',
                        fontSize: 11,
                        fontFamily: 'var(--ow-font-mono, monospace)',
                      }}
                    >
                      {a.host_id.slice(0, 8)}…
                    </Link>
                  </div>
                )}
              </div>
              <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                {isAlert && canAlertWrite && (
                  <>
                    <QuickAction
                      label="Ack"
                      disabled={actions.isPending}
                      onClick={(e) => {
                        e.stopPropagation();
                        actions.mutate({ id: a.id, action: 'acknowledge' });
                      }}
                    />
                    <QuickAction
                      label="Silence"
                      disabled={actions.isPending}
                      onClick={(e) => {
                        e.stopPropagation();
                        actions.mutate({ id: a.id, action: 'silence' });
                      }}
                    />
                    <QuickAction
                      label="Resolve"
                      disabled={actions.isPending}
                      onClick={(e) => {
                        e.stopPropagation();
                        actions.mutate({ id: a.id, action: 'resolve' });
                      }}
                    />
                  </>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: string[];
}) {
  return (
    <label
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        fontSize: 12,
        color: 'var(--ow-fg-2)',
      }}
    >
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        style={{
          height: 32,
          padding: '0 8px',
          background: 'var(--ow-bg-1)',
          color: 'var(--ow-fg-0)',
          border: '1px solid var(--ow-line)',
          borderRadius: 6,
          fontFamily: 'inherit',
          fontSize: 13,
        }}
      >
        <option value="">All</option>
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
}

function QuickAction({
  label,
  disabled,
  onClick,
}: {
  label: string;
  disabled: boolean;
  onClick: (e: React.MouseEvent) => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      style={{
        height: 26,
        padding: '0 9px',
        background: 'var(--ow-bg-2)',
        color: 'var(--ow-fg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 6,
        fontFamily: 'inherit',
        fontSize: 11,
        fontWeight: 600,
        cursor: disabled ? 'default' : 'pointer',
        opacity: disabled ? 0.6 : 1,
      }}
    >
      {label}
    </button>
  );
}
