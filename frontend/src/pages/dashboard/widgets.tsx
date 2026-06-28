import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { KpiValue, KpiSub, Sparkline, WidgetCard, WidgetState, toneVar } from './primitives';
import { relativeTime, severityLabel, severityTone, sourceLabel } from '@/api/eventDisplay';

// Dashboard widgets — each is a lens into a fleet endpoint, owning its
// own query so loading/empty/error states are independent. All read-only
// GETs behind system:read (the /dashboard route guard). No new backend:
// every endpoint here already ships.
//
// Spec: frontend-dashboard.

// Compliance score bands -> tone (mirrors the scheduler ladder intent).
function scoreTone(pct: number): 'crit' | 'warn' | 'ok' {
  if (pct < 50) return 'crit';
  if (pct < 80) return 'warn';
  return 'ok';
}

// ── KPI: Hosts online ──────────────────────────────────────────────
export function KpiHostsOnline() {
  const q = useQuery({
    queryKey: ['fleet', 'liveness'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/fleet/liveness', {});
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
  });
  return (
    <WidgetCard title="Hosts online" to="/hosts">
      {q.isPending ? (
        <WidgetState kind="loading" />
      ) : q.isError ? (
        <WidgetState kind="error" />
      ) : (
        (() => {
          const { reachable, unreachable, unknown, never_probed } = q.data;
          const total = reachable + unreachable + unknown + never_probed;
          const tone = reachable === total ? 'ok' : reachable === 0 ? 'crit' : 'warn';
          return (
            <>
              <KpiValue value={reachable} unit={`/ ${total}`} tone={tone} />
              <KpiSub>
                {unreachable} unreachable · {never_probed} never probed
              </KpiSub>
            </>
          );
        })()
      )}
    </WidgetCard>
  );
}

// ── KPI: Avg compliance ────────────────────────────────────────────
export function KpiAvgCompliance() {
  const q = useQuery({
    queryKey: ['fleet', 'score'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/fleet/score', {});
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
  });
  return (
    <WidgetCard title="Avg compliance" to="/hosts">
      {q.isPending ? (
        <WidgetState kind="loading" />
      ) : q.isError ? (
        <WidgetState kind="error" />
      ) : q.data.total_evaluations === 0 ? (
        <WidgetState kind="empty" message="No scans yet" />
      ) : (
        (() => {
          const pct = Math.round(q.data.passing_fraction * 100);
          return (
            <>
              <KpiValue value={pct} unit="%" tone={scoreTone(pct)} />
              <KpiSub>
                {q.data.total_evaluations.toLocaleString()} evaluations · target ≥ 80%
              </KpiSub>
            </>
          );
        })()
      )}
    </WidgetCard>
  );
}

// ── KPI: Scan queue ────────────────────────────────────────────────
export function KpiScanQueue() {
  const q = useQuery({
    queryKey: ['fleet', 'scan_queue'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/fleet/scan-queue', {});
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
  });
  return (
    <WidgetCard title="Scan queue">
      {q.isPending ? (
        <WidgetState kind="loading" />
      ) : q.isError ? (
        <WidgetState kind="error" />
      ) : (
        <>
          <KpiValue value={q.data.running} tone={q.data.running > 0 ? 'info' : 'fg'} />
          <KpiSub>
            {q.data.running} running · {q.data.queued} queued
          </KpiSub>
        </>
      )}
    </WidgetCard>
  );
}

// ── Compliance trend (30d sparkline) ───────────────────────────────
export function WidgetComplianceTrend() {
  const q = useQuery({
    queryKey: ['fleet', 'compliance', 'trend'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/fleet/compliance/trend', {});
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
  });
  return (
    <WidgetCard title="Compliance trend" to="/hosts">
      {q.isPending ? (
        <WidgetState kind="loading" />
      ) : q.isError ? (
        <WidgetState kind="error" />
      ) : q.data.days.length < 2 ? (
        <WidgetState kind="empty" message="Not enough history yet" />
      ) : (
        (() => {
          const days = q.data.days;
          const series = days.map((d) => d.avg_score_pct);
          // Guarded by days.length < 2 above, so both ends exist.
          const first = days[0]!;
          const last = days[days.length - 1]!;
          const up = last.avg_score_pct >= first.avg_score_pct;
          return (
            <>
              <div style={{ marginTop: 2 }}>
                <Sparkline
                  data={series}
                  color={up ? 'var(--ow-ok)' : 'var(--ow-crit)'}
                  height={70}
                />
              </div>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  marginTop: 6,
                  fontSize: 12,
                  color: 'var(--ow-fg-3)',
                }}
              >
                <span>
                  {days.length}d ago · {Math.round(first.avg_score_pct)}%
                </span>
                <span style={{ color: up ? 'var(--ow-ok)' : 'var(--ow-crit)' }}>
                  today · {Math.round(last.avg_score_pct)}%
                </span>
              </div>
            </>
          );
        })()
      )}
    </WidgetCard>
  );
}

// ── Top failed rules ───────────────────────────────────────────────
export function WidgetTopFailingRules() {
  const q = useQuery({
    queryKey: ['fleet', 'top_failing_rules'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/fleet/top-failing-rules', {
        params: { query: { limit: 6 } },
      });
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
  });
  return (
    <WidgetCard title="Top failed rules">
      {q.isPending ? (
        <WidgetState kind="loading" />
      ) : q.isError ? (
        <WidgetState kind="error" />
      ) : q.data.items.length === 0 ? (
        <WidgetState kind="empty" message="No failing rules" />
      ) : (
        <div>
          {q.data.items.slice(0, 6).map((r, i) => (
            <Row
              key={r.rule_id}
              first={i === 0}
              label={r.rule_id}
              mono
              value={`${r.failing_host_count} hosts`}
              dot="crit"
            />
          ))}
        </div>
      )}
    </WidgetCard>
  );
}

// ── Top failing hosts (resolves hostnames via the hosts list) ──────
export function WidgetTopFailingHosts() {
  const q = useQuery({
    queryKey: ['fleet', 'top_failing_hosts'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/fleet/top-failing-hosts', {
        params: { query: { limit: 6 } },
      });
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
  });
  const hostsQ = useQuery({
    queryKey: ['hosts', 'names'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/hosts', {});
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
  });
  const nameOf = (id: string) =>
    hostsQ.data?.hosts.find((h) => h.id === id)?.hostname ?? `${id.slice(0, 8)}…`;
  return (
    <WidgetCard title="Top failing hosts" to="/hosts">
      {q.isPending ? (
        <WidgetState kind="loading" />
      ) : q.isError ? (
        <WidgetState kind="error" />
      ) : q.data.items.length === 0 ? (
        <WidgetState kind="empty" message="No failing hosts" />
      ) : (
        <div>
          {q.data.items.slice(0, 6).map((h, i) => (
            <Row
              key={h.host_id}
              first={i === 0}
              label={nameOf(h.host_id)}
              to="/hosts/$hostId"
              params={{ hostId: h.host_id }}
              value={`${h.failing_rule_count} rules`}
              dot="warn"
            />
          ))}
        </div>
      )}
    </WidgetCard>
  );
}

// ── Recent activity ────────────────────────────────────────────────
export function WidgetRecentActivity() {
  const q = useQuery({
    queryKey: ['activity', 'dashboard'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/activity', {
        params: { query: { limit: 8 } },
      });
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
  });
  return (
    <WidgetCard title="Recent activity" to="/activity">
      {q.isPending ? (
        <WidgetState kind="loading" />
      ) : q.isError ? (
        <WidgetState kind="error" />
      ) : q.data.items.length === 0 ? (
        <WidgetState kind="empty" message="No recent activity" />
      ) : (
        <div>
          {q.data.items.slice(0, 8).map((a, i) => (
            <Row
              key={a.id}
              first={i === 0}
              label={a.title}
              sub={`${sourceLabel(a.source)} · ${relativeTime(a.occurred_at)}`}
              value={severityLabel(a.severity)}
              dot={severityTone(a.severity)}
            />
          ))}
        </div>
      )}
    </WidgetCard>
  );
}

// ── shared list row ────────────────────────────────────────────────
function Row({
  first,
  label,
  sub,
  value,
  dot,
  mono,
  to,
  params,
}: {
  first: boolean;
  label: string;
  sub?: string;
  value: string;
  dot: 'crit' | 'warn' | 'ok' | 'info';
  mono?: boolean;
  to?: string;
  params?: Record<string, string>;
}) {
  const labelNode = (
    <span
      style={{
        fontWeight: 500,
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
        fontFamily: mono ? 'var(--ow-font-mono, monospace)' : undefined,
        color: to ? 'var(--ow-link)' : 'var(--ow-fg-0)',
      }}
    >
      {label}
    </span>
  );
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        padding: '8px 0',
        borderTop: first ? 'none' : '1px solid var(--ow-line)',
        fontSize: 13,
      }}
    >
      <span
        style={{
          width: 8,
          height: 8,
          borderRadius: '50%',
          flexShrink: 0,
          background: toneVar(dot),
        }}
      />
      <span style={{ flex: 1, minWidth: 0 }}>
        {to && params ? (
          <Link to={to} params={params} style={{ textDecoration: 'none' }}>
            {labelNode}
          </Link>
        ) : (
          labelNode
        )}
        {sub && (
          <span
            style={{
              display: 'block',
              color: 'var(--ow-fg-3)',
              fontSize: 11,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {sub}
          </span>
        )}
      </span>
      <span style={{ color: 'var(--ow-fg-2)', fontSize: 12, whiteSpace: 'nowrap' }}>{value}</span>
    </div>
  );
}
