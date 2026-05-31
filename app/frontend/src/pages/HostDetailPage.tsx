import { useQuery } from '@tanstack/react-query';
import { useParams, useSearch, useNavigate } from '@tanstack/react-router';
import { useState } from 'react';
import { ArrowLeft, RefreshCw, Circle } from 'lucide-react';
import { Link } from '@tanstack/react-router';
import api from '@/api/client';

// HostDetailPage — one host's identity + liveness + compliance + recent transactions.
//
// Spec: frontend-host-detail.
//
// Backend: GET /api/v1/hosts/{id} returns {host, liveness, compliance_summary}.
//          GET /api/v1/fleet/recent-changes is FLEET-wide (no host filter yet);
//          we filter client-side until the backend adds a host_id param.

interface HostDetailSearch {
  framework?: string;
}

interface HostResponse {
  id: string;
  hostname: string;
  ip_address: string;
  port?: number;
  environment?: string;
  tags?: string[];
}

interface HostLiveness {
  reachability_status: 'reachable' | 'unreachable' | 'unknown';
  last_probe_at?: string | null;
  last_response_ms?: number | null;
  consecutive_failures: number;
  last_state_change_at?: string | null;
  last_error_type?: string | null;
}

interface ComplianceSummary {
  passing: number;
  failing: number;
  skipped: number;
  error: number;
  total: number;
}

interface HostDetail {
  host: HostResponse;
  liveness: HostLiveness | null;
  compliance_summary: ComplianceSummary;
}

interface FleetTransaction {
  id: string;
  host_id: string;
  rule_id: string;
  status: 'pass' | 'fail' | 'skipped' | 'error';
  severity?: string;
  change_kind: 'first_seen' | 'state_changed' | 'severity_changed';
  occurred_at: string;
}

const PAGE_SIZE = 50;

export function HostDetailPage() {
  const params = useParams({ strict: false }) as { hostId?: string };
  const search = useSearch({ strict: false }) as HostDetailSearch;
  const navigate = useNavigate();
  const hostId = params.hostId ?? '';
  const framework = search.framework;

  const detailQuery = useQuery({
    queryKey: ['host', hostId, framework],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/hosts/{id}', {
        params: {
          path: { id: hostId },
          query: framework ? { framework } : {},
        },
      });
      if (response.status === 404) {
        const err = new Error('Host not found');
        (err as Error & { code?: string }).code = 'host_not_found';
        throw err;
      }
      if (response.status === 403) {
        const err = new Error('Access denied');
        (err as Error & { code?: string }).code = 'authz.permission_denied';
        throw err;
      }
      if (error) throw error;
      // Backend versions vary: the current spec returns
      // { host, liveness, compliance_summary } but older builds returned the
      // bare host object. Adapt either shape into HostDetail so the page
      // never crashes on a missing `host` key.
      const raw = data as unknown as Partial<HostDetail> & Partial<HostResponse>;
      if (raw && 'host' in raw && raw.host) {
        return {
          host: raw.host,
          liveness: raw.liveness ?? null,
          compliance_summary:
            raw.compliance_summary ?? { passing: 0, failing: 0, skipped: 0, error: 0, total: 0 },
        } satisfies HostDetail;
      }
      if (raw && typeof raw === 'object' && 'hostname' in raw && raw.hostname) {
        // Bare-host shape — wrap it. Enrichment fields stay empty so the
        // operator sees the host identity even when the backend doesn't
        // ship liveness/compliance yet.
        return {
          host: raw as HostResponse,
          liveness: null,
          compliance_summary: { passing: 0, failing: 0, skipped: 0, error: 0, total: 0 },
        } satisfies HostDetail;
      }
      const err = new Error(
        'Backend returned an unexpected response shape for /hosts/{id}. Expected HostDetailResponse.',
      );
      (err as Error & { code?: string }).code = 'response.shape_mismatch';
      throw err;
    },
    enabled: !!hostId,
  });

  const recentQuery = useQuery({
    queryKey: ['recent-changes', hostId, framework],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/fleet/recent-changes', {
        params: { query: framework ? { framework, limit: 1000 } : { limit: 1000 } },
      });
      // Older backends don't expose /fleet/recent-changes. Treat as empty
      // rather than throwing so the rest of the host detail page renders.
      if (response.status === 404) return [];
      if (error) throw error;
      const all = (data as unknown as { items?: FleetTransaction[] } | null)?.items ?? [];
      // Backend doesn't filter by host_id yet — filter client-side.
      return all.filter((t) => t.host_id === hostId);
    },
    enabled: !!hostId,
    retry: false,
  });

  return (
    <div style={{ padding: '20px 28px' }}>
      <title>
        {detailQuery.data?.host?.hostname
          ? `${detailQuery.data.host.hostname} — OpenWatch`
          : 'Host — OpenWatch'}
      </title>

      <div style={{ marginBottom: 14 }}>
        <Link
          to="/hosts"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            color: 'var(--ow-fg-2)',
            fontSize: 13,
            textDecoration: 'none',
          }}
        >
          <ArrowLeft size={14} /> Hosts
        </Link>
      </div>

      {detailQuery.isError && (
        <ErrorState
          code={(detailQuery.error as Error & { code?: string })?.code}
          message={(detailQuery.error as Error)?.message ?? 'Failed to load'}
          onRetry={() => detailQuery.refetch()}
        />
      )}

      {detailQuery.isLoading && <LoadingPlaceholder />}

      {detailQuery.data?.host && (
        <>
          <IdentityHeader
            host={detailQuery.data.host}
            liveness={detailQuery.data.liveness}
          />
          <ComplianceBody
            summary={detailQuery.data.compliance_summary}
            framework={framework}
            onFrameworkChange={(next) =>
              navigate({
                to: '/hosts/$hostId',
                params: { hostId },
                search: next ? { framework: next } : {},
              })
            }
          />
          <RecentTransactions
            isLoading={recentQuery.isLoading}
            isError={recentQuery.isError}
            transactions={recentQuery.data ?? []}
            onRetry={() => recentQuery.refetch()}
          />
        </>
      )}
    </div>
  );
}

function IdentityHeader({
  host,
  liveness,
}: {
  host: HostResponse;
  liveness: HostLiveness | null;
}) {
  return (
    <section
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: 18,
        marginBottom: 14,
      }}
      aria-labelledby="host-identity"
    >
      <div
        style={{ display: 'flex', justifyContent: 'space-between', gap: 20 }}
      >
        <div>
          <h1
            id="host-identity"
            style={{
              margin: 0,
              fontSize: 22,
              fontFamily: 'var(--ow-font-mono)',
            }}
          >
            {host.hostname}
          </h1>
          <div
            style={{
              color: 'var(--ow-fg-2)',
              fontSize: 13,
              marginTop: 4,
              display: 'flex',
              gap: 12,
            }}
          >
            <span style={{ fontFamily: 'var(--ow-font-mono)' }}>
              {host.ip_address}
              {host.port ? `:${host.port}` : ''}
            </span>
            {host.environment && (
              <span
                style={{
                  padding: '2px 8px',
                  background: 'var(--ow-bg-3)',
                  borderRadius: 'var(--ow-radius-full)',
                  fontSize: 11,
                }}
              >
                {host.environment}
              </span>
            )}
          </div>
        </div>
        <LivenessIndicator liveness={liveness} />
      </div>
    </section>
  );
}

function LivenessIndicator({ liveness }: { liveness: HostLiveness | null }) {
  if (liveness === null) {
    return (
      <div style={statusGroup}>
        <Circle size={10} fill="var(--ow-fg-3)" color="var(--ow-fg-3)" />
        <div>
          <div style={statusLabel}>Not yet probed</div>
          <div style={statusSub}>No liveness data</div>
        </div>
      </div>
    );
  }
  const colorMap = {
    reachable: 'var(--ow-ok)',
    unreachable: 'var(--ow-crit)',
    unknown: 'var(--ow-warn)',
  } as const;
  const labelMap = {
    reachable: 'Reachable',
    unreachable: 'Unreachable',
    unknown: 'Unknown',
  } as const;
  const c = colorMap[liveness.reachability_status];
  return (
    <div style={statusGroup}>
      <Circle size={10} fill={c} color={c} />
      <div>
        <div style={statusLabel}>{labelMap[liveness.reachability_status]}</div>
        <div style={statusSub}>
          {liveness.last_probe_at
            ? `Last probe ${new Date(liveness.last_probe_at).toLocaleString()}`
            : '—'}
        </div>
      </div>
    </div>
  );
}

function ComplianceBody({
  summary,
  framework,
  onFrameworkChange,
}: {
  summary: ComplianceSummary;
  framework: string | undefined;
  onFrameworkChange: (next: string | undefined) => void;
}) {
  const isEmpty = summary.total === 0;
  const pct = isEmpty ? 0 : Math.round((summary.passing / summary.total) * 100);
  return (
    <section
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: 18,
        marginBottom: 14,
      }}
      aria-labelledby="host-compliance"
    >
      <header
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          marginBottom: 14,
        }}
      >
        <h2
          id="host-compliance"
          style={{ margin: 0, fontSize: 14, fontWeight: 600 }}
        >
          Compliance
        </h2>
        <FrameworkFilter
          value={framework}
          onChange={onFrameworkChange}
        />
      </header>
      {isEmpty ? (
        <p
          role="status"
          style={{
            margin: 0,
            color: 'var(--ow-fg-2)',
            padding: 16,
            textAlign: 'center',
          }}
        >
          No compliance data for this host yet
        </p>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr 1.5fr', gap: 14 }}>
          <Stat n={summary.passing} label="passing" color="var(--ow-ok)" />
          <Stat n={summary.failing} label="failing" color="var(--ow-crit)" />
          <Stat n={summary.skipped} label="skipped" color="var(--ow-warn)" />
          <Stat n={summary.error} label="error" color="var(--ow-fg-2)" />
          <div>
            <div
              style={{
                fontSize: 32,
                fontWeight: 600,
                fontVariantNumeric: 'tabular-nums',
              }}
            >
              {pct}%
            </div>
            <div style={{ color: 'var(--ow-fg-2)', fontSize: 12 }}>
              {summary.passing} of {summary.total} passing
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

function Stat({ n, label, color }: { n: number; label: string; color: string }) {
  return (
    <div>
      <div
        style={{
          fontSize: 28,
          fontWeight: 600,
          color,
          fontVariantNumeric: 'tabular-nums',
        }}
      >
        {n}
      </div>
      <div
        style={{
          color: 'var(--ow-fg-2)',
          fontSize: 11,
          textTransform: 'uppercase',
          letterSpacing: '0.04em',
        }}
      >
        {label}
      </div>
    </div>
  );
}

function FrameworkFilter({
  value,
  onChange,
}: {
  value: string | undefined;
  onChange: (next: string | undefined) => void;
}) {
  // Static list for v0 — backend's framework registry endpoint lands later.
  const frameworks = [
    { value: '', label: 'All frameworks' },
    { value: 'cis_rhel9_v2.0.0', label: 'CIS RHEL 9 v2.0.0' },
    { value: 'stig_rhel9_v2r7', label: 'STIG RHEL 9 V2R7' },
    { value: 'nist_800_53_r5', label: 'NIST 800-53 R5' },
  ];
  return (
    <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
      <span style={{ fontSize: 12, color: 'var(--ow-fg-2)' }}>Framework</span>
      <select
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value || undefined)}
        style={{
          height: 28,
          padding: '0 8px',
          background: 'var(--ow-bg-2)',
          border: '1px solid var(--ow-line)',
          borderRadius: 6,
          color: 'var(--ow-fg-0)',
          fontFamily: 'inherit',
          fontSize: 12,
        }}
      >
        {frameworks.map((f) => (
          <option key={f.value} value={f.value}>
            {f.label}
          </option>
        ))}
      </select>
    </label>
  );
}

function RecentTransactions({
  isLoading,
  isError,
  transactions,
  onRetry,
}: {
  isLoading: boolean;
  isError: boolean;
  transactions: FleetTransaction[];
  onRetry: () => void;
}) {
  const [page, setPage] = useState(0);
  const start = page * PAGE_SIZE;
  const visible = transactions.slice(start, start + PAGE_SIZE);
  const hasMore = start + PAGE_SIZE < transactions.length;

  return (
    <section
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        overflow: 'hidden',
      }}
      aria-labelledby="host-recent"
    >
      <header
        style={{
          padding: '14px 18px',
          borderBottom: '1px solid var(--ow-line)',
          display: 'flex',
          justifyContent: 'space-between',
        }}
      >
        <h2 id="host-recent" style={{ margin: 0, fontSize: 14, fontWeight: 600 }}>
          Recent transactions
        </h2>
        <button
          type="button"
          onClick={onRetry}
          aria-label="Refresh transactions"
          style={iconBtn}
        >
          <RefreshCw size={14} />
        </button>
      </header>
      {isLoading && (
        <div role="status" style={{ padding: 24, textAlign: 'center', color: 'var(--ow-fg-2)' }}>
          Loading…
        </div>
      )}
      {isError && (
        <div role="alert" style={{ padding: 18 }}>
          Failed to load transactions.{' '}
          <button type="button" onClick={onRetry} style={textBtn}>
            Retry
          </button>
        </div>
      )}
      {!isLoading && !isError && visible.length === 0 && (
        <p style={{ padding: 24, color: 'var(--ow-fg-2)', textAlign: 'center', margin: 0 }}>
          No recent transactions
        </p>
      )}
      {!isLoading && !isError && visible.length > 0 && (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ background: 'var(--ow-bg-2)' }}>
              <th style={th}>Rule</th>
              <th style={th}>Status</th>
              <th style={th}>Severity</th>
              <th style={th}>Change</th>
              <th style={th}>When</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((t) => (
              <tr key={t.id} style={{ borderTop: '1px solid var(--ow-line)' }}>
                <td style={{ ...td, fontFamily: 'var(--ow-font-mono)' }}>{t.rule_id}</td>
                <td style={td}><StatusBadge status={t.status} /></td>
                <td style={td}>{t.severity ?? '—'}</td>
                <td style={td}>{t.change_kind.replace('_', ' ')}</td>
                <td style={{ ...td, color: 'var(--ow-fg-2)' }}>
                  {new Date(t.occurred_at).toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {hasMore && (
        <div style={{ padding: 14, textAlign: 'center', borderTop: '1px solid var(--ow-line)' }}>
          <button type="button" onClick={() => setPage(page + 1)} style={textBtn}>
            Show more
          </button>
        </div>
      )}
    </section>
  );
}

function StatusBadge({ status }: { status: FleetTransaction['status'] }) {
  const color = { pass: 'var(--ow-ok)', fail: 'var(--ow-crit)', skipped: 'var(--ow-warn)', error: 'var(--ow-fg-2)' }[status];
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '1px 8px',
        borderRadius: 'var(--ow-radius-full)',
        fontSize: 11,
        fontWeight: 600,
        textTransform: 'uppercase',
        color,
        background: `color-mix(in oklab, ${color} 16%, transparent)`,
      }}
    >
      {status}
    </span>
  );
}

function LoadingPlaceholder() {
  return (
    <div role="status" style={{ padding: 28, textAlign: 'center', color: 'var(--ow-fg-2)' }}>
      Loading host…
    </div>
  );
}

function ErrorState({
  code,
  message,
  onRetry,
}: {
  code: string | undefined;
  message: string;
  onRetry: () => void;
}) {
  if (code === 'host_not_found') {
    return (
      <div role="alert" style={errorPanel}>
        <h2 style={{ marginTop: 0 }}>Host not found</h2>
        <p>The host you're looking for doesn't exist or has been deleted.</p>
        <Link to="/hosts" style={primaryBtn}>
          Back to hosts
        </Link>
      </div>
    );
  }
  if (code === 'authz.permission_denied') {
    return (
      <div role="alert" style={errorPanel}>
        <h2 style={{ marginTop: 0 }}>Access denied</h2>
        <p>You don't have permission to view this host (<code>{code}</code>).</p>
      </div>
    );
  }
  return (
    <div role="alert" style={errorPanel}>
      <h2 style={{ marginTop: 0 }}>Failed to load host</h2>
      <p>{message}</p>
      <button type="button" onClick={onRetry} style={primaryBtn}>
        Retry
      </button>
    </div>
  );
}

const iconBtn: React.CSSProperties = {
  width: 28,
  height: 28,
  border: '1px solid var(--ow-line)',
  background: 'var(--ow-bg-2)',
  color: 'var(--ow-fg-1)',
  borderRadius: 6,
  display: 'inline-grid',
  placeItems: 'center',
  cursor: 'pointer',
};

const primaryBtn: React.CSSProperties = {
  display: 'inline-block',
  padding: '0 14px',
  height: 32,
  lineHeight: '32px',
  background: 'var(--ow-info)',
  color: 'var(--ow-info-on)',
  border: 0,
  borderRadius: 6,
  fontWeight: 600,
  fontSize: 13,
  cursor: 'pointer',
  textDecoration: 'none',
};

const textBtn: React.CSSProperties = {
  background: 'transparent',
  border: 0,
  color: 'var(--ow-info)',
  fontSize: 13,
  cursor: 'pointer',
  padding: 0,
};

const statusGroup: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: 8,
};

const statusLabel: React.CSSProperties = {
  fontWeight: 600,
  fontSize: 13,
};

const statusSub: React.CSSProperties = {
  fontSize: 11,
  color: 'var(--ow-fg-2)',
};

const th: React.CSSProperties = {
  textAlign: 'left',
  padding: '10px 14px',
  fontSize: 11,
  fontWeight: 600,
  color: 'var(--ow-fg-2)',
  textTransform: 'uppercase',
  letterSpacing: '0.04em',
};

const td: React.CSSProperties = {
  padding: '10px 14px',
  color: 'var(--ow-fg-1)',
};

const errorPanel: React.CSSProperties = {
  padding: 20,
  background: 'var(--ow-bg-1)',
  border: '1px solid var(--ow-line)',
  borderRadius: 'var(--ow-radius)',
};
