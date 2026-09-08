import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useDefaultLens } from '@/api/useDefaultLens';
import { KpiValue, KpiSub, WidgetCard, WidgetState, toneVar } from './primitives';
import { relativeTime, severityLabel, severityTone, sourceLabel } from '@/api/eventDisplay';
import { TrendChart } from '@/components/charts/TrendChart';

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
  // Score through the org default lens (family/key) so a single-framework
  // shop sees e.g. its STIG score here; empty = All rules (Kensa baseline).
  const lens = useDefaultLens();
  const q = useQuery({
    queryKey: ['fleet', 'score', lens],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/fleet/score', {
        params: lens ? { query: { framework: lens } } : {},
      });
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
      ) : q.data.score_pct === null ? (
        // No score is not zero percent. The fleet either has no hosts to
        // assess or none of them produced a verdict, and showing 0 would
        // report an absence of data as a total failure.
        <WidgetState
          kind="empty"
          message={q.data.hosts_total === 0 ? 'No hosts yet' : 'No host could be scored yet'}
        />
      ) : (
        (() => {
          // Taken as sent. The server computes the percentage; multiplying a
          // fraction here was a second implementation of the formula.
          const pct = q.data.score_pct;
          return (
            <>
              <KpiValue value={pct} unit="%" tone={scoreTone(pct)} />
              <KpiSub>
                {q.data.hosts_scored.toLocaleString()} of {q.data.hosts_total.toLocaleString()}{' '}
                hosts scored · target ≥ 80%
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
          // Direction compares the first and last days that have a score AND
          // were produced by the same formula.
          //
          // It used to compare them whatever formula each came from, so a
          // legacy_unknown day and an identified day were subtracted and the
          // result colored the chart line and the latest caption green or red.
          // That difference is a change of MEASUREMENT, not a change in
          // posture, and coloring it asserts something about the fleet that
          // nothing measured. A mixed day carries no score at all, so the
          // null filter already keeps it out of the comparison.
          const scoredDays = days.filter((d) => d.score_pct !== null);
          const first = scoredDays[0];
          const last = scoredDays[scoredDays.length - 1];
          // TWO DISTINCT scored days, sharing a formula state. With only one
          // scored day first and last are the same point, and comparing it
          // with itself yielded "up" and painted the widget green: a claim of
          // improvement from a single measurement.
          const comparable =
            first !== undefined &&
            last !== undefined &&
            first !== last &&
            first.formula_status === last.formula_status &&
            first.formula_status !== 'mixed';
          const up = comparable ? last!.score_pct! >= first!.score_pct! : null;
          // Neutral when there is nothing valid to compare. Never green or red
          // on a boundary: those colors are the claim.
          const lineColor = up === null ? 'var(--ow-fg-3)' : up ? 'var(--ow-ok)' : 'var(--ow-crit)';
          return (
            <>
              <TrendChart
                points={days.map((d) => ({
                  date: d.date,
                  scorePct: d.score_pct,
                  formulaStatus: d.formula_status,
                  tooltip: [
                    d.date,
                    ...fleetDayLines(d),
                    `${d.hosts} hosts`,
                    `${d.failing} failing rules`,
                    `${d.critical_hosts} with critical`,
                  ],
                }))}
                windowDays={30}
                color={lineColor}
                height={70}
              />
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  marginTop: 6,
                  fontSize: 12,
                  color: 'var(--ow-fg-3)',
                }}
              >
                <span>{first ? `oldest ${first.score_pct}%` : 'no scored day'}</span>
                <span style={{ color: lineColor }}>{last ? `latest ${last.score_pct}%` : ''}</span>
              </div>
              {up === null && scoredDays.length > 0 ? (
                <div role="note" style={{ marginTop: 4, fontSize: 11, color: 'var(--ow-fg-3)' }}>
                  {days.some((d) => d.formula_status === 'mixed')
                    ? 'No trend direction: a day in this window mixes scoring formulas.'
                    : 'No trend direction: these days were scored by different formulas.'}
                </div>
              ) : null}
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

// fleetDayLines explains a day's score, or its absence, in the tooltip.
//
// A null score has two different causes and a viewer needs to know which. A
// mixed day HAS hosts and snapshots and deliberately publishes no number,
// because the formulas behind them measure different things; a day where
// nothing could be assessed is a scanning problem. Rendering both as an empty
// point would hide the difference the API exists to report.
function fleetDayLines(d: {
  score_pct: number | null;
  formula_status: 'identified' | 'legacy_unknown' | 'mixed';
  hosts_scored: number;
}): string[] {
  if (d.formula_status === 'mixed') {
    return ['No score: this day mixes scoring formulas', 'Their average would not be comparable'];
  }
  if (d.score_pct === null) {
    return ['No score: no host could be assessed'];
  }
  const line = `${d.score_pct}% avg compliant (${d.hosts_scored} scored)`;
  return d.formula_status === 'legacy_unknown'
    ? [line, 'Earlier formula: not comparable with current days']
    : [line];
}
