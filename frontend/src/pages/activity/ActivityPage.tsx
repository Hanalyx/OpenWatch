import { useEffect, useRef, useState } from 'react';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { Link, useSearch } from '@tanstack/react-router';
import api from '@/api/client';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import { apiErrorMessage } from '@/api/errors';
import { useAuthStore } from '@/store/useAuthStore';
import type { components } from '@/api/schema';
import { ActivityDrawer, severityTone } from './ActivityDrawer';
import { useAlertActions } from './useAlertActions';

type Activity = components['schemas']['Activity'];
type Source = Activity['source'];
type Severity = Activity['severity'];

// ActivityPage — the unified activity feed at /activity, styled to the
// openwatch-v1 Activity.html prototype using only honest data.
//
// MVP (frontend-activity): a toolbar (client-side search, a time-range
// segment backed by the `since` param, a Live poll toggle, an
// Acknowledge-all over loaded alert rows, an event count), a restyled
// Source + Severity filter bar, and a day-grouped stream. Alert-source
// rows carry lifecycle actions (the activity id is the alert id) and any
// row opens the detail drawer. The prototype's histogram, Status/Group
// facets, dedup counts, and "routed to" panel are backend-gated and
// deferred per docs/engineering/activity_page_scope.md.

const SOURCES: Source[] = ['alert', 'transaction', 'intelligence', 'audit', 'monitoring'];
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const TONE: Record<string, string> = {
  crit: 'var(--ow-crit)',
  warn: 'var(--ow-warn)',
  info: 'var(--ow-info)',
};

// Cosmetic display category per source (the feed has no category
// taxonomy; this is a label, not a backend filter).
const CATEGORY: Record<Source, string> = {
  monitoring: 'HOST LIFECYCLE',
  transaction: 'COMPLIANCE & DRIFT',
  alert: 'ALERT',
  audit: 'AUDIT',
  intelligence: 'INTELLIGENCE',
};

// Range segment -> `since` lookback (ms). "all" sends no since.
const RANGES: { id: string; label: string; ms: number | null }[] = [
  { id: '1h', label: '1h', ms: 3_600_000 },
  { id: '24h', label: '24h', ms: 86_400_000 },
  { id: '7d', label: '7d', ms: 604_800_000 },
  { id: 'all', label: 'All', ms: null },
];

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
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);
  useEffect(() => {
    setCrumbs([{ label: 'Infrastructure' }, { label: 'Activity' }]);
    return () => setCrumbs([]);
  }, [setCrumbs]);

  const search = useSearch({ strict: false }) as ActivitySearch;
  const hostId = search.host_id;
  const hasPermission = useAuthStore((s) => s.hasPermission);
  const canAlertWrite = hasPermission('alert:write');

  const [source, setSource] = useState<Source | ''>('');
  const [severity, setSeverity] = useState<Severity | ''>('');
  const [range, setRange] = useState('24h');
  const [text, setText] = useState('');
  const [live, setLive] = useState(false);
  const [selected, setSelected] = useState<Activity | null>(null);

  const rangeMs = RANGES.find((r) => r.id === range)?.ms ?? null;
  const since = rangeMs ? new Date(Date.now() - rangeMs).toISOString() : undefined;

  const query = useInfiniteQuery({
    queryKey: ['activity', source, severity, range, hostId],
    initialPageParam: undefined as string | undefined,
    refetchInterval: live ? 15_000 : false,
    queryFn: async ({ pageParam }) => {
      const { data, error, response } = await api.GET('/api/v1/activity', {
        params: {
          query: {
            limit: 50,
            ...(source ? { source } : {}),
            ...(severity ? { severity } : {}),
            ...(hostId ? { host_id: hostId } : {}),
            ...(since ? { since } : {}),
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

  // Hostname map for entity pills (the feed carries host_id only).
  const hostsQuery = useQuery({
    queryKey: ['hosts', 'names'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/hosts', {});
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
  });
  const nameOf = (id: string) =>
    hostsQuery.data?.hosts.find((h) => h.id === id)?.hostname ?? `${id.slice(0, 8)}…`;

  const actions = useAlertActions();

  const allItems = query.data?.pages.flatMap((p) => p.items) ?? [];
  const hiddenCount = query.data?.pages[0]?.hidden_count ?? 0;
  const items = text
    ? allItems.filter((a) =>
        `${a.title} ${a.summary ?? ''} ${a.host_id ?? ''} ${a.source}`
          .toLowerCase()
          .includes(text.toLowerCase()),
      )
    : allItems;

  const ackAll = () => {
    if (!canAlertWrite) return;
    for (const a of items)
      if (a.source === 'alert') actions.mutate({ id: a.id, action: 'acknowledge' });
  };
  const hasLoadedAlerts = canAlertWrite && items.some((a) => a.source === 'alert');

  return (
    <div style={{ padding: '20px 28px 60px' }}>
      <title>Activity · OpenWatch</title>

      <header style={{ marginBottom: 14 }}>
        <h1 style={{ margin: 0, fontSize: 22, fontWeight: 600, letterSpacing: '-0.01em' }}>
          Activity
        </h1>
        <div style={{ color: 'var(--ow-fg-2)', fontSize: 13, marginTop: 2 }}>
          Unified feed across alerts, compliance, intelligence, audit, and monitoring
          {hostId ? ' (filtered to one host)' : ''}
        </div>
      </header>

      {/* toolbar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          marginBottom: 12,
          flexWrap: 'wrap',
        }}
      >
        <div
          style={{
            flex: 1,
            minWidth: 220,
            maxWidth: 380,
            height: 34,
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            padding: '0 10px',
            background: 'var(--ow-bg-1)',
            border: '1px solid var(--ow-line)',
            borderRadius: 7,
          }}
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="var(--ow-fg-3)"
            strokeWidth="2"
            aria-hidden="true"
          >
            <circle cx="11" cy="11" r="7" />
            <path d="m21 21-4.3-4.3" />
          </svg>
          <input
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Search loaded events, hosts, messages…"
            aria-label="Search loaded events"
            style={{
              flex: 1,
              background: 'transparent',
              border: 0,
              outline: 0,
              color: 'var(--ow-fg-0)',
              fontFamily: 'inherit',
              fontSize: 13,
            }}
          />
        </div>

        <Seg value={range} onChange={setRange} options={RANGES} />

        <button
          type="button"
          onClick={() => setLive((v) => !v)}
          aria-pressed={live}
          style={{
            height: 34,
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            padding: '0 12px',
            background: 'var(--ow-bg-1)',
            border: `1px solid ${live ? 'var(--ow-info)' : 'var(--ow-line)'}`,
            borderRadius: 7,
            color: live ? 'var(--ow-info)' : 'var(--ow-fg-1)',
            fontFamily: 'inherit',
            fontSize: 13,
            fontWeight: 500,
            cursor: 'pointer',
          }}
        >
          <span
            style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              background: live ? 'var(--ow-info)' : 'var(--ow-fg-3)',
            }}
          />
          Live
        </button>

        <div style={{ flex: 1 }} />

        <span style={{ color: 'var(--ow-fg-2)', fontSize: 12 }}>
          {items.length} event{items.length === 1 ? '' : 's'}
          {hiddenCount > 0 ? ` · ${hiddenCount} hidden` : ''}
        </span>

        {hasLoadedAlerts && (
          <button
            type="button"
            onClick={ackAll}
            disabled={actions.isPending}
            style={{
              height: 30,
              padding: '0 12px',
              background: 'var(--ow-bg-1)',
              border: '1px solid var(--ow-line)',
              borderRadius: 6,
              color: 'var(--ow-fg-0)',
              fontFamily: 'inherit',
              fontSize: 12,
              fontWeight: 600,
              cursor: actions.isPending ? 'default' : 'pointer',
            }}
          >
            Acknowledge all
          </button>
        )}
      </div>

      {/* filter bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          marginBottom: 14,
          flexWrap: 'wrap',
        }}
      >
        <FilterDropdown
          label="Severity"
          value={severity}
          onChange={(v) => setSeverity(v as Severity | '')}
          options={SEVERITIES}
        />
        <FilterDropdown
          label="Source"
          value={source}
          onChange={(v) => setSource(v as Source | '')}
          options={SOURCES}
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
            Clear all
          </button>
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
          <div role="alert" style={{ padding: 16, color: 'var(--ow-crit)', fontSize: 13 }}>
            {apiErrorMessage(query.error, 'Failed to load activity')}
          </div>
        ) : query.isPending ? (
          <div role="status" style={{ padding: 16, color: 'var(--ow-fg-2)', fontSize: 13 }}>
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
          <Stream
            items={items}
            canAlertWrite={canAlertWrite}
            actions={actions}
            nameOf={nameOf}
            onSelect={setSelected}
          />
        )}
      </div>

      {query.hasNextPage && !text && (
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
  actions,
  nameOf,
  onSelect,
}: {
  items: Activity[];
  canAlertWrite: boolean;
  actions: ReturnType<typeof useAlertActions>;
  nameOf: (id: string) => string;
  onSelect: (a: Activity) => void;
}) {
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
                  <span
                    style={{
                      fontFamily: 'var(--ow-font-mono, monospace)',
                      fontSize: 12,
                      fontWeight: 500,
                      color: tone,
                    }}
                  >
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
                    {CATEGORY[a.source]}
                  </span>
                </div>
                {a.summary && (
                  <div style={{ color: 'var(--ow-fg-1)', fontSize: 13, marginTop: 3 }}>
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
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 5,
                        padding: '0 6px',
                        height: 18,
                        borderRadius: 4,
                        background: 'var(--ow-bg-2)',
                        border: '1px solid var(--ow-line)',
                        color: 'var(--ow-fg-1)',
                        fontSize: 11,
                        fontFamily: 'var(--ow-font-mono, monospace)',
                        textDecoration: 'none',
                      }}
                    >
                      <svg
                        width="9"
                        height="9"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        aria-hidden="true"
                      >
                        <rect x="2" y="4" width="20" height="13" rx="2" />
                      </svg>
                      {nameOf(a.host_id)}
                    </Link>
                  </div>
                )}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {isAlert && canAlertWrite && (
                  <div style={{ display: 'flex', gap: 4 }}>
                    <IconAction
                      title="Acknowledge"
                      disabled={actions.isPending}
                      onClick={(e) => {
                        e.stopPropagation();
                        actions.mutate({ id: a.id, action: 'acknowledge' });
                      }}
                      path="M20 6 9 17l-5-5"
                    />
                    <IconAction
                      title="Silence"
                      disabled={actions.isPending}
                      onClick={(e) => {
                        e.stopPropagation();
                        actions.mutate({ id: a.id, action: 'silence' });
                      }}
                      path="M11 5 6 9H2v6h4l5 4zM23 9l-6 6M17 9l6 6"
                    />
                  </div>
                )}
                <span
                  style={{
                    color: 'var(--ow-fg-3)',
                    fontSize: 11,
                    fontFamily: 'var(--ow-font-mono, monospace)',
                  }}
                >
                  {a.source}
                </span>
              </div>
            </div>
          </div>
        );
      })}
    </>
  );
}

// Segmented control (range).
function Seg({
  value,
  onChange,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { id: string; label: string }[];
}) {
  return (
    <div
      role="group"
      aria-label="Time range"
      style={{
        display: 'inline-flex',
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 7,
        padding: 3,
        gap: 2,
      }}
    >
      {options.map((o) => {
        const active = value === o.id;
        return (
          <button
            key={o.id}
            type="button"
            aria-pressed={active}
            onClick={() => onChange(o.id)}
            style={{
              border: 0,
              background: active ? 'var(--ow-bg-3)' : 'transparent',
              color: active ? 'var(--ow-fg-0)' : 'var(--ow-fg-2)',
              fontFamily: 'inherit',
              fontSize: 12,
              fontWeight: 500,
              padding: '5px 11px',
              borderRadius: 5,
              cursor: 'pointer',
            }}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

// Dropdown-button single-select filter (All + options), styled to the
// prototype's filter bar.
function FilterDropdown({
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
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('click', onDoc);
    return () => document.removeEventListener('click', onDoc);
  }, [open]);

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        style={{
          height: 32,
          padding: '0 10px',
          display: 'inline-flex',
          alignItems: 'center',
          gap: 8,
          background: 'var(--ow-bg-1)',
          border: `1px solid ${value ? 'var(--ow-info)' : 'var(--ow-line)'}`,
          borderRadius: 6,
          color: value ? 'var(--ow-fg-0)' : 'var(--ow-fg-1)',
          fontFamily: 'inherit',
          fontSize: 13,
          fontWeight: 500,
          cursor: 'pointer',
        }}
      >
        {label}
        {value && (
          <span
            style={{
              background: 'var(--ow-bg-3)',
              color: 'var(--ow-info)',
              fontSize: 11,
              fontWeight: 600,
              padding: '1px 7px',
              borderRadius: 999,
            }}
          >
            {value}
          </span>
        )}
        <svg
          width="12"
          height="12"
          viewBox="0 0 24 24"
          fill="none"
          stroke="var(--ow-fg-3)"
          strokeWidth="2"
          aria-hidden="true"
        >
          <path d="m6 9 6 6 6-6" />
        </svg>
      </button>
      {open && (
        <div
          role="listbox"
          style={{
            position: 'absolute',
            top: 'calc(100% + 6px)',
            left: 0,
            minWidth: 180,
            background: 'var(--ow-bg-1)',
            border: '1px solid var(--ow-line)',
            borderRadius: 10,
            boxShadow: '0 16px 40px rgba(0,0,0,0.45)',
            padding: 6,
            zIndex: 50,
          }}
        >
          <Opt
            label="All"
            active={!value}
            onClick={() => {
              onChange('');
              setOpen(false);
            }}
          />
          {options.map((o) => (
            <Opt
              key={o}
              label={o}
              active={value === o}
              onClick={() => {
                onChange(o);
                setOpen(false);
              }}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function Opt({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      role="option"
      aria-selected={active}
      onClick={onClick}
      style={{
        display: 'block',
        width: '100%',
        textAlign: 'left',
        padding: '7px 8px',
        borderRadius: 6,
        border: 0,
        background: active ? 'var(--ow-bg-2)' : 'transparent',
        color: active ? 'var(--ow-fg-0)' : 'var(--ow-fg-1)',
        fontFamily: 'inherit',
        fontSize: 13,
        cursor: 'pointer',
      }}
    >
      {label}
    </button>
  );
}

function IconAction({
  title,
  disabled,
  onClick,
  path,
}: {
  title: string;
  disabled: boolean;
  onClick: (e: React.MouseEvent) => void;
  path: string;
}) {
  return (
    <button
      type="button"
      title={title}
      aria-label={title}
      onClick={onClick}
      disabled={disabled}
      style={{
        width: 26,
        height: 26,
        display: 'grid',
        placeItems: 'center',
        background: 'var(--ow-bg-2)',
        border: '1px solid var(--ow-line)',
        borderRadius: 6,
        color: 'var(--ow-fg-2)',
        cursor: disabled ? 'default' : 'pointer',
        opacity: disabled ? 0.6 : 1,
      }}
    >
      <svg
        width="12"
        height="12"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        aria-hidden="true"
      >
        <path d={path} />
      </svg>
    </button>
  );
}
