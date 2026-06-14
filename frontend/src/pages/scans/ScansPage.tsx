import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import api from '@/api/client';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import { apiErrorMessage } from '@/api/errors';

// ScansPage — the fleet scan overview at /scans, composed entirely from
// endpoints that already ship (no new backend):
//   - getFleetScanQueue   -> running / queued KPIs
//   - GET /hosts          -> per-host coverage (last_scan_at + summary)
//   - getFleetRecentChanges -> the compliance state-change history
//
// MVP (frontend-scans): a scan-queue header + Coverage and History tabs.
// A per-scan "Live" row list and the Rules/Config tabs from the
// openwatch-v1 Scans.html prototype are deferred: there is no scan-run
// listing endpoint (scan-queue is counts only) and scan config already
// lives under Settings.

const FRESH_MS = 48 * 3_600_000; // adaptive scheduler max interval

function ageLabel(iso: string | null | undefined): { text: string; tone: 'ok' | 'warn' | 'crit' } {
  if (!iso) return { text: 'never scanned', tone: 'crit' };
  const ms = Date.now() - new Date(iso).getTime();
  const h = Math.round(ms / 3_600_000);
  const text = h < 1 ? 'just now' : h < 24 ? `${h}h ago` : `${Math.round(h / 24)}d ago`;
  return { text, tone: ms <= FRESH_MS ? 'ok' : 'warn' };
}

const TONE = {
  ok: 'var(--ow-ok)',
  warn: 'var(--ow-warn)',
  crit: 'var(--ow-crit)',
};

export function ScansPage() {
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);
  useEffect(() => {
    setCrumbs([{ label: 'Infrastructure' }, { label: 'Scans' }]);
    return () => setCrumbs([]);
  }, [setCrumbs]);

  const [tab, setTab] = useState<'coverage' | 'history'>('coverage');

  const queueQ = useQuery({
    queryKey: ['fleet', 'scan_queue'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/fleet/scan-queue', {});
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
    refetchInterval: 15_000,
  });

  const hostsQ = useQuery({
    queryKey: ['hosts'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/hosts', {});
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
  });

  const hosts = hostsQ.data?.hosts ?? [];
  const fresh = hosts.filter(
    (h) => h.last_scan_at && Date.now() - new Date(h.last_scan_at).getTime() <= FRESH_MS,
  ).length;

  return (
    <div style={{ padding: '20px 28px 60px' }}>
      <title>Scans · OpenWatch</title>

      <header style={{ marginBottom: 16 }}>
        <h1 style={{ margin: 0, fontSize: 22, fontWeight: 600, letterSpacing: '-0.01em' }}>
          Scans
        </h1>
        <div style={{ color: 'var(--ow-fg-2)', fontSize: 13, marginTop: 2 }}>
          Fleet scan coverage and compliance change history
        </div>
      </header>

      {/* KPI row */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: 14,
          marginBottom: 18,
        }}
      >
        <Kpi
          label="Up to date"
          value={hostsQ.isPending ? '…' : `${fresh}`}
          unit={hostsQ.isPending ? '' : `/ ${hosts.length}`}
          tone={fresh === hosts.length ? 'ok' : 'warn'}
          sub="scanned within 48h"
        />
        <Kpi
          label="Running"
          value={queueQ.isPending ? '…' : `${queueQ.data?.running ?? 0}`}
          tone={(queueQ.data?.running ?? 0) > 0 ? 'info' : 'fg'}
          sub="scans in progress"
        />
        <Kpi
          label="Queued"
          value={queueQ.isPending ? '…' : `${queueQ.data?.queued ?? 0}`}
          tone="fg"
          sub="awaiting a worker"
        />
      </div>

      {/* tabs */}
      <div
        role="tablist"
        aria-label="Scan views"
        style={{ display: 'flex', gap: 4, marginBottom: 14 }}
      >
        <Tab id="coverage" active={tab === 'coverage'} onClick={() => setTab('coverage')}>
          Coverage
        </Tab>
        <Tab id="history" active={tab === 'history'} onClick={() => setTab('history')}>
          History
        </Tab>
      </div>

      {tab === 'coverage' ? (
        <CoverageTab
          hosts={hosts}
          isPending={hostsQ.isPending}
          isError={hostsQ.isError}
          error={hostsQ.error}
        />
      ) : (
        <HistoryTab
          hostName={(id: string) =>
            hosts.find((h) => h.id === id)?.hostname ?? `${id.slice(0, 8)}…`
          }
        />
      )}
    </div>
  );
}

function CoverageTab({
  hosts,
  isPending,
  isError,
  error,
}: {
  hosts: {
    id: string;
    hostname: string;
    last_scan_at?: string | null;
    compliance_summary?: { passing: number; total: number } | null;
  }[];
  isPending: boolean;
  isError: boolean;
  error: unknown;
}) {
  if (isError)
    return (
      <Panel>
        <State kind="error" text={apiErrorMessage(error, 'Failed to load hosts')} />
      </Panel>
    );
  if (isPending)
    return (
      <Panel>
        <State kind="loading" />
      </Panel>
    );
  if (hosts.length === 0)
    return (
      <Panel>
        <State kind="empty" text="No hosts yet" />
      </Panel>
    );

  return (
    <Panel>
      <Row head cols="1.4fr 110px 110px 1fr">
        <span>Host</span>
        <span>Compliance</span>
        <span>Freshness</span>
        <span>Last scan</span>
      </Row>
      {hosts.map((h, i) => {
        const age = ageLabel(h.last_scan_at);
        const cs = h.compliance_summary;
        const pct = cs && cs.total > 0 ? Math.round((cs.passing / cs.total) * 100) : null;
        return (
          <Row key={h.id} cols="1.4fr 110px 110px 1fr" first={i === 0}>
            <Link
              to="/hosts/$hostId"
              params={{ hostId: h.id }}
              style={{ color: 'var(--ow-link)', textDecoration: 'none', fontSize: 13 }}
            >
              {h.hostname}
            </Link>
            <span style={{ fontSize: 13, color: 'var(--ow-fg-1)' }}>
              {pct === null ? 'n/a' : `${pct}%`}
            </span>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 7,
                fontSize: 12,
                fontWeight: 500,
                color: TONE[age.tone],
              }}
            >
              <span
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  background: TONE[age.tone],
                  flexShrink: 0,
                }}
              />
              {age.tone === 'ok' ? 'current' : age.tone === 'warn' ? 'stale' : 'never'}
            </span>
            <span style={{ fontSize: 12, color: 'var(--ow-fg-3)' }}>{age.text}</span>
          </Row>
        );
      })}
    </Panel>
  );
}

function HistoryTab({ hostName }: { hostName: (id: string) => string }) {
  const q = useQuery({
    queryKey: ['fleet', 'recent_changes'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/fleet/recent-changes', {});
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
  });

  if (q.isError)
    return (
      <Panel>
        <State kind="error" text={apiErrorMessage(q.error, 'Failed to load history')} />
      </Panel>
    );
  if (q.isPending)
    return (
      <Panel>
        <State kind="loading" />
      </Panel>
    );
  const items = q.data.items;
  if (items.length === 0)
    return (
      <Panel>
        <State kind="empty" text="No compliance changes yet" />
      </Panel>
    );

  const statusTone: Record<string, string> = {
    pass: TONE.ok,
    fail: TONE.crit,
    skipped: 'var(--ow-fg-3)',
    error: TONE.warn,
  };

  return (
    <Panel>
      <Row head cols="150px 1.2fr 1fr 120px 120px">
        <span>When</span>
        <span>Host</span>
        <span>Rule</span>
        <span>Status</span>
        <span>Change</span>
      </Row>
      {items.map((t, i) => (
        <Row key={t.id} cols="150px 1.2fr 1fr 120px 120px" first={i === 0}>
          <span
            style={{
              fontSize: 12,
              color: 'var(--ow-fg-3)',
              fontFamily: 'var(--ow-font-mono, monospace)',
            }}
          >
            {new Date(t.occurred_at).toLocaleString(undefined, {
              month: 'short',
              day: 'numeric',
              hour: '2-digit',
              minute: '2-digit',
            })}
          </span>
          <Link
            to="/hosts/$hostId"
            params={{ hostId: t.host_id }}
            style={{ color: 'var(--ow-link)', textDecoration: 'none', fontSize: 13 }}
          >
            {hostName(t.host_id)}
          </Link>
          <span
            style={{
              fontSize: 12,
              fontFamily: 'var(--ow-font-mono, monospace)',
              color: 'var(--ow-fg-1)',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {t.rule_id}
          </span>
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              fontSize: 12,
              fontWeight: 500,
              color: statusTone[t.status] ?? 'var(--ow-fg-2)',
            }}
          >
            <span
              style={{
                width: 7,
                height: 7,
                borderRadius: '50%',
                background: statusTone[t.status] ?? 'var(--ow-fg-3)',
                flexShrink: 0,
              }}
            />
            {t.status}
          </span>
          <span style={{ fontSize: 12, color: 'var(--ow-fg-3)' }}>
            {t.change_kind.replace('_', ' ')}
          </span>
        </Row>
      ))}
    </Panel>
  );
}

function Kpi({
  label,
  value,
  unit,
  tone,
  sub,
}: {
  label: string;
  value: string;
  unit?: string;
  tone: 'ok' | 'warn' | 'info' | 'fg' | 'crit';
  sub: string;
}) {
  const color = tone === 'fg' ? 'var(--ow-fg-0)' : tone === 'info' ? 'var(--ow-info)' : TONE[tone];
  return (
    <div
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: '14px 16px',
      }}
    >
      <div
        style={{
          fontSize: 11,
          fontWeight: 500,
          color: 'var(--ow-fg-2)',
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontSize: 26,
          fontWeight: 600,
          lineHeight: 1,
          color,
          fontVariantNumeric: 'tabular-nums',
          display: 'flex',
          alignItems: 'baseline',
          gap: 6,
          marginTop: 8,
        }}
      >
        {value}
        {unit && (
          <span style={{ fontSize: 14, color: 'var(--ow-fg-2)', fontWeight: 500 }}>{unit}</span>
        )}
      </div>
      <div style={{ color: 'var(--ow-fg-3)', fontSize: 11, marginTop: 8 }}>{sub}</div>
    </div>
  );
}

function Tab({
  id,
  active,
  onClick,
  children,
}: {
  id: string;
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      role="tab"
      id={`scans-tab-${id}`}
      aria-selected={active}
      onClick={onClick}
      style={{
        height: 34,
        padding: '0 14px',
        border: 0,
        borderBottom: `2px solid ${active ? 'var(--ow-info)' : 'transparent'}`,
        background: 'transparent',
        color: active ? 'var(--ow-fg-0)' : 'var(--ow-fg-2)',
        fontFamily: 'inherit',
        fontSize: 13,
        fontWeight: 600,
        cursor: 'pointer',
      }}
    >
      {children}
    </button>
  );
}

function Panel({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        overflow: 'hidden',
      }}
    >
      {children}
    </div>
  );
}

function Row({
  children,
  cols,
  head,
  first,
}: {
  children: React.ReactNode;
  cols: string;
  head?: boolean;
  first?: boolean;
}) {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: cols,
        gap: 12,
        padding: head ? '10px 16px' : '11px 16px',
        alignItems: 'center',
        background: head ? 'var(--ow-bg-2)' : undefined,
        borderTop: head || first ? 'none' : '1px solid var(--ow-line)',
        borderBottom: head ? '1px solid var(--ow-line)' : undefined,
        fontSize: head ? 11 : 13,
        fontWeight: head ? 600 : undefined,
        textTransform: head ? 'uppercase' : undefined,
        letterSpacing: head ? '0.04em' : undefined,
        color: head ? 'var(--ow-fg-3)' : undefined,
      }}
    >
      {children}
    </div>
  );
}

function State({ kind, text }: { kind: 'loading' | 'error' | 'empty'; text?: string }) {
  const color = kind === 'error' ? 'var(--ow-crit)' : 'var(--ow-fg-3)';
  return (
    <div
      role={kind === 'error' ? 'alert' : 'status'}
      style={{
        padding: kind === 'empty' ? '40px 16px' : '16px',
        textAlign: kind === 'empty' ? 'center' : 'left',
        color,
        fontSize: 13,
      }}
    >
      {text ?? (kind === 'loading' ? 'Loading…' : 'No data')}
    </div>
  );
}
