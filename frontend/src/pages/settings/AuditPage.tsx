import { Fragment, useEffect, useMemo, useState } from 'react';
import { useInfiniteQuery } from '@tanstack/react-query';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import { useAuthStore } from '@/store/useAuthStore';
import { SettingsLayout } from '@/components/settings/SettingsLayout';
import {
  PageHead,
  Section,
  SettingCard,
  Field,
  Btn,
  StatusPill,
} from '@/components/settings/primitives';
import { ForbiddenPage } from '@/pages/ForbiddenPage';
import { relativeTime, severityLabel } from '@/api/eventDisplay';
import type { components } from '@/api/schema';

type AuditEvent = components['schemas']['AuditEvent'];

// Settings -> Audit log.
//
// Filterable, cursor-paginated view of GET /api/v1/audit/events (newest
// first). Gated on audit:read. Each row expands to its raw detail JSON +
// any redactions. No write actions: the audit log is read-only by design.
//
// Spec: frontend-settings (AC-19), api-audit-events-query.

// localDateToRFC3339 converts a yyyy-mm-dd date input into an RFC3339
// instant. `end` pins to the end of the day so an inclusive "until" filter
// captures events recorded that day.
function localDateToRFC3339(value: string, end: boolean): string | undefined {
  if (!value) return undefined;
  const d = new Date(`${value}T${end ? '23:59:59' : '00:00:00'}`);
  if (Number.isNaN(d.getTime())) return undefined;
  return d.toISOString();
}

function severityTier(severity?: string): 'ok' | 'warn' | 'crit' {
  const s = (severity ?? '').toLowerCase();
  if (s === 'critical' || s === 'error' || s === 'high') return 'crit';
  if (s === 'warn' || s === 'warning' || s === 'medium') return 'warn';
  return 'ok';
}

export function AuditPage() {
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);
  const canRead = useAuthStore((s) => s.hasPermission)('audit:read');
  useEffect(() => {
    setCrumbs([{ label: 'Settings' }, { label: 'Audit log' }]);
    return () => setCrumbs([]);
  }, [setCrumbs]);

  // Draft filter inputs vs. the applied filters that key the query. The
  // query only re-runs when the operator clicks Apply (or Clear), so typing
  // never issues a request per keystroke.
  const [draftAction, setDraftAction] = useState('');
  const [draftActor, setDraftActor] = useState('');
  const [draftSince, setDraftSince] = useState('');
  const [draftUntil, setDraftUntil] = useState('');
  const [applied, setApplied] = useState<{
    action: string;
    actorType: string;
    since: string;
    until: string;
  }>({ action: '', actorType: '', since: '', until: '' });

  const sinceIso = useMemo(() => localDateToRFC3339(applied.since, false), [applied.since]);
  const untilIso = useMemo(() => localDateToRFC3339(applied.until, true), [applied.until]);

  const query = useInfiniteQuery({
    queryKey: ['audit', applied.action, applied.actorType, applied.since, applied.until],
    enabled: canRead,
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) => {
      const { data, error, response } = await api.GET('/api/v1/audit/events', {
        params: {
          query: {
            limit: 50,
            ...(applied.action ? { action: applied.action } : {}),
            ...(applied.actorType ? { actor_type: applied.actorType } : {}),
            ...(sinceIso ? { since: sinceIso } : {}),
            ...(untilIso ? { until: untilIso } : {}),
            ...(pageParam ? { cursor: pageParam } : {}),
          },
        },
      });
      if (error || !response.ok) {
        throw new Error(apiErrorMessage(error, `Failed to load audit events (${response.status})`));
      }
      return data!;
    },
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });

  if (!canRead) {
    // RBAC gate: the audit log requires audit:read. The backend is
    // authoritative; this mirrors it so the UI never shows a surface the
    // caller cannot load.
    return <ForbiddenPage />;
  }

  const events: AuditEvent[] = query.data?.pages.flatMap((p) => p.items) ?? [];

  function apply() {
    setApplied({
      action: draftAction.trim(),
      actorType: draftActor.trim(),
      since: draftSince,
      until: draftUntil,
    });
  }
  function clear() {
    setDraftAction('');
    setDraftActor('');
    setDraftSince('');
    setDraftUntil('');
    setApplied({ action: '', actorType: '', since: '', until: '' });
  }

  return (
    <SettingsLayout>
      <PageHead
        title="Audit log"
        description="Every authentication, policy change, and remediation action OpenWatch has recorded. Read-only, newest first."
      />

      <Section title="Filters">
        <SettingCard>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              apply();
            }}
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: 12,
              alignItems: 'flex-end',
              padding: 16,
            }}
          >
            <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <span style={labelStyle}>Action</span>
              <Field
                value={draftAction}
                onChange={setDraftAction}
                placeholder="e.g. auth.login"
                ariaLabel="Filter by action"
                width={200}
              />
            </label>
            <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <span style={labelStyle}>Actor type</span>
              <Field
                value={draftActor}
                onChange={setDraftActor}
                placeholder="e.g. user"
                ariaLabel="Filter by actor type"
                width={150}
              />
            </label>
            <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <span style={labelStyle}>From</span>
              <input
                type="date"
                value={draftSince}
                aria-label="Filter from date"
                onChange={(e) => setDraftSince(e.target.value)}
                style={dateInputStyle}
              />
            </label>
            <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <span style={labelStyle}>To</span>
              <input
                type="date"
                value={draftUntil}
                aria-label="Filter to date"
                onChange={(e) => setDraftUntil(e.target.value)}
                style={dateInputStyle}
              />
            </label>
            <Btn type="submit" variant="primary">
              Apply
            </Btn>
            <Btn type="button" onClick={clear}>
              Clear
            </Btn>
          </form>
        </SettingCard>
      </Section>

      <Section title="Events">
        <SettingCard>
          {query.isPending ? (
            <div style={emptyStyle}>Loading audit events.</div>
          ) : query.isError ? (
            <div role="alert" style={errorStyle}>
              <strong>Failed to load audit events.</strong> {apiErrorMessage(query.error, '')}{' '}
              <button type="button" onClick={() => query.refetch()} style={retryStyle}>
                Retry
              </button>
            </div>
          ) : events.length === 0 ? (
            <div style={emptyStyle}>No audit events match these filters.</div>
          ) : (
            <>
              <div role="table" aria-label="Audit events">
                <div
                  role="row"
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '150px 1fr 90px 150px 1fr',
                    gap: 12,
                    padding: '10px 20px',
                    borderBottom: '1px solid var(--ow-line)',
                    fontSize: 11,
                    textTransform: 'uppercase',
                    letterSpacing: '0.04em',
                    color: 'var(--ow-fg-3)',
                  }}
                >
                  <span role="columnheader">When</span>
                  <span role="columnheader">Event</span>
                  <span role="columnheader">Severity</span>
                  <span role="columnheader">Actor</span>
                  <span role="columnheader">Resource</span>
                </div>
                {events.map((ev) => (
                  <AuditRow key={ev.id} ev={ev} />
                ))}
              </div>
              {query.hasNextPage && (
                <div style={{ display: 'flex', justifyContent: 'center', padding: 16 }}>
                  <Btn
                    type="button"
                    onClick={() => query.fetchNextPage()}
                    disabled={query.isFetchingNextPage}
                  >
                    {query.isFetchingNextPage ? 'Loading.' : 'Load more'}
                  </Btn>
                </div>
              )}
            </>
          )}
        </SettingCard>
      </Section>
    </SettingsLayout>
  );
}

function AuditRow({ ev }: { ev: AuditEvent }) {
  const [open, setOpen] = useState(false);
  const hasDetail =
    (ev.detail && Object.keys(ev.detail).length > 0) || (ev.redactions && ev.redactions.length > 0);
  return (
    <Fragment>
      <div
        role="row"
        style={{
          display: 'grid',
          gridTemplateColumns: '150px 1fr 90px 150px 1fr',
          gap: 12,
          alignItems: 'center',
          padding: '12px 20px',
          borderTop: '1px solid var(--ow-line)',
        }}
      >
        <span style={{ fontSize: 12, color: 'var(--ow-fg-2)' }} title={ev.occurred_at}>
          {relativeTime(ev.occurred_at)}
        </span>
        <span style={{ minWidth: 0 }}>
          {/* Primary: the server-rendered readable sentence; the raw action
              code sits beneath as a small mono line for auditors who need it.
              The full envelope (UUIDs, detail) is in the expandable drawer. */}
          {hasDetail ? (
            <button
              type="button"
              onClick={() => setOpen((v) => !v)}
              aria-expanded={open}
              style={{
                background: 'transparent',
                border: 0,
                padding: 0,
                color: 'var(--ow-fg-0)',
                fontSize: 13,
                cursor: 'pointer',
                textAlign: 'left',
              }}
            >
              {open ? '▾' : '▸'} {ev.message || ev.action}
            </button>
          ) : (
            <span style={{ fontSize: 13, color: 'var(--ow-fg-0)' }}>{ev.message || ev.action}</span>
          )}
          <div style={{ fontFamily: 'var(--ow-font-mono)', fontSize: 11, color: 'var(--ow-fg-3)' }}>
            {ev.action}
          </div>
        </span>
        <span>
          <StatusPill tier={severityTier(ev.severity)}>
            {severityLabel(ev.severity || 'info')}
          </StatusPill>
        </span>
        <span style={{ fontSize: 12, color: 'var(--ow-fg-1)', minWidth: 0 }}>
          {ev.actor_label || actorTypeWord(ev.actor_type)}
        </span>
        <span style={{ fontSize: 12, color: 'var(--ow-fg-2)', minWidth: 0 }}>
          {ev.resource_type ? capitalize(ev.resource_type) : ''}
        </span>
      </div>
      {open && hasDetail && (
        <div
          role="row"
          style={{ padding: '0 20px 14px 20px', borderTop: '1px solid var(--ow-line)' }}
        >
          <div style={{ fontSize: 11, color: 'var(--ow-fg-3)', margin: '10px 0 4px' }}>
            correlation:{' '}
            <span style={{ fontFamily: 'var(--ow-font-mono)' }}>{ev.correlation_id}</span>
          </div>
          {ev.actor_id ? (
            <div style={{ fontSize: 11, color: 'var(--ow-fg-3)', marginBottom: 2 }}>
              actor id: <span style={{ fontFamily: 'var(--ow-font-mono)' }}>{ev.actor_id}</span>
            </div>
          ) : null}
          {ev.resource_id ? (
            <div style={{ fontSize: 11, color: 'var(--ow-fg-3)', marginBottom: 6 }}>
              resource id:{' '}
              <span style={{ fontFamily: 'var(--ow-font-mono)' }}>{ev.resource_id}</span>
            </div>
          ) : null}
          {ev.redactions && ev.redactions.length > 0 && (
            <div style={{ fontSize: 11, color: 'var(--ow-warn)', marginBottom: 6 }}>
              redacted fields: {ev.redactions.join(', ')}
            </div>
          )}
          <pre
            style={{
              margin: 0,
              padding: 12,
              background: 'var(--ow-bg-1)',
              border: '1px solid var(--ow-line)',
              borderRadius: 'var(--ow-radius)',
              fontFamily: 'var(--ow-font-mono)',
              fontSize: 12,
              lineHeight: 1.5,
              color: 'var(--ow-fg-1)',
              whiteSpace: 'pre',
              overflow: 'auto',
              maxHeight: 320,
            }}
          >
            {JSON.stringify(ev.detail ?? {}, null, 2)}
          </pre>
        </div>
      )}
    </Fragment>
  );
}

// capitalize a single word; actorTypeWord renders a readable actor type
// (the fallback when an event carries no actor_label).
function capitalize(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s;
}
function actorTypeWord(actorType: string): string {
  switch (actorType) {
    case 'system':
    case '':
      return 'The system';
    case 'scheduler':
      return 'The scheduler';
    case 'user':
      return 'A user';
    case 'api_key':
    case 'api_token':
      return 'An API token';
    default:
      return capitalize(actorType);
  }
}

const labelStyle = { fontSize: 11, color: 'var(--ow-fg-3)' } as const;
const dateInputStyle = {
  height: 32,
  background: 'var(--ow-bg-2)',
  border: '1px solid var(--ow-line)',
  borderRadius: 6,
  color: 'var(--ow-fg-0)',
  fontFamily: 'inherit',
  fontSize: 13,
  padding: '0 10px',
} as const;
const emptyStyle = {
  padding: 40,
  textAlign: 'center',
  color: 'var(--ow-fg-2)',
  fontSize: 13,
} as const;
const errorStyle = {
  padding: 20,
  color: 'var(--ow-fg-1)',
  background: 'var(--ow-crit-bg)',
  borderLeft: '3px solid var(--ow-crit)',
  fontSize: 13,
} as const;
const retryStyle = {
  marginLeft: 12,
  background: 'transparent',
  border: 0,
  color: 'var(--ow-info)',
  cursor: 'pointer',
  textDecoration: 'underline',
} as const;
