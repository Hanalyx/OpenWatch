import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useParams, useSearch, useNavigate, Link } from '@tanstack/react-router';
import { useEffect, useMemo, useState } from 'react';
import {
  Activity as ActivityIcon,
  ArrowLeft,
  Bell,
  Circle,
  Clock,
  FileText,
  LayoutGrid,
  MoreVertical,
  Package,
  Pencil,
  Play,
  RefreshCw,
  Server as ServerIcon,
  Shield,
  Terminal as TerminalIcon,
  Users as UsersIcon,
  Wifi,
  WifiOff,
  Wrench,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import api from '@/api/client';
import { EditHostModal } from '@/components/hosts/EditHostModal';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';

// HostDetailPage — prototype-faithful Host Detail surface (v1.0.0).
//
// Layout mirrors app/docs/prototypes/openwatch-v1/Host Detail.html:
//
//   1. Back link (chevron + label) to /hosts
//   2. Page-head row: hostname (mono) + status badge + sub-line metadata
//      (IP, environment chip, OS/Kernel/Uptime placeholder slots) +
//      action row (Maintenance toggle, Terminal, Run scan, Edit, kebab)
//   3. Conditional offline banner (band = down/critical AND dwell >= 5 min)
//   4. Tabs row — 10 tabs in prototype order; only Overview is functional
//   5. Hero stat strip — Compliance, Auto-scan, Connectivity, Watchlist
//   6. Two-column overview body
//      Left:  Top failed rules, Server intelligence, Compliance trend
//      Right: System, Recent activity
//
// Cards that depend on backend subsystems that don't exist yet
// (auto-scan, alerts, server intelligence, posture snapshots) render
// honest empty states naming the deferred BACKLOG.md item so operators
// can tell deferred-feature from broken-feature.
//
// Spec: app/specs/frontend/host-detail.spec.yaml v1.0.0.

interface HostDetailSearch {
  framework?: string;
  tab?: TabId;
}

interface HostResponse {
  id: string;
  hostname: string;
  ip_address: string;
  port?: number;
  environment?: string;
  tags?: string[];
  display_name?: string;
  description?: string;
  username?: string;
  maintenance_mode?: boolean;
  check_priority?: number;
}

type MonitoringBand =
  | 'online'
  | 'degraded'
  | 'critical'
  | 'down'
  | 'maintenance'
  | 'unknown';

interface HostLiveness {
  reachability_status: 'reachable' | 'unreachable' | 'unknown';
  monitoring_state?: MonitoringBand;
  last_probe_at?: string | null;
  last_response_ms?: number | null;
  consecutive_failures: number;
  ping_consecutive_failures?: number;
  ssh_consecutive_failures?: number;
  privilege_consecutive_failures?: number;
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

interface MonitoringHistoryEntry {
  id: number;
  host_id: string;
  check_time: string;
  monitoring_state: MonitoringBand;
  previous_state?: MonitoringBand | null;
  response_time_ms?: number | null;
  ping_ok?: boolean | null;
  ssh_ok?: boolean | null;
  privilege_ok?: boolean | null;
  failed_layer?: 'ping' | 'ssh' | 'privilege' | null;
  error_message?: string | null;
  error_type?: string | null;
}

type TabId =
  | 'overview'
  | 'compliance'
  | 'packages'
  | 'services'
  | 'users'
  | 'network'
  | 'audit_log'
  | 'activity'
  | 'remediation'
  | 'terminal';

// Prototype tab order — referenced by AC-18 + AC-28. Each entry carries
// its lucide icon; the TabsRow renderer mounts the icon beside the label.
const TAB_ORDER: { id: TabId; label: string; icon: LucideIcon }[] = [
  { id: 'overview', label: 'Overview', icon: LayoutGrid },
  { id: 'compliance', label: 'Compliance', icon: Shield },
  { id: 'packages', label: 'Packages', icon: Package },
  { id: 'services', label: 'Services', icon: ServerIcon },
  { id: 'users', label: 'Users', icon: UsersIcon },
  { id: 'network', label: 'Network', icon: Wifi },
  { id: 'audit_log', label: 'Audit log', icon: FileText },
  { id: 'activity', label: 'Activity', icon: ActivityIcon },
  { id: 'remediation', label: 'Remediation', icon: Wrench },
  { id: 'terminal', label: 'Terminal', icon: TerminalIcon },
];

// Backend subsystem that populates each tab when it lands. Surfaces
// inside the per-tab empty state so operators know what's deferred.
const TAB_BACKEND_SUBSYSTEM: Record<Exclude<TabId, 'overview'>, string> = {
  compliance:
    'Compliance scanner — runs Kensa-via-SSH per host; not yet wired in the Go rebuild.',
  packages:
    'Server Intelligence collection — installed-package inventory deferred (BACKLOG).',
  services:
    'Server Intelligence collection — running services inventory deferred (BACKLOG).',
  users:
    'Server Intelligence collection — user accounts inventory deferred (BACKLOG).',
  network:
    'Server Intelligence collection — interfaces and firewall rules deferred (BACKLOG).',
  audit_log:
    'Audit query API — host-scoped audit feed deferred to the unified /activity page (BACKLOG).',
  activity:
    'Unified Activity feed — combined transactions + audits + alerts deferred (BACKLOG).',
  remediation:
    'Remediation engine — Kensa-side remediation pipeline deferred (BACKLOG).',
  terminal:
    'Web terminal — SSH-in-browser deferred; use a host-side SSH client in the meantime.',
};

const DEFAULT_SUMMARY: ComplianceSummary = {
  passing: 0,
  failing: 0,
  skipped: 0,
  error: 0,
  total: 0,
};

const PAGE_SIZE = 50;

// ─────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────

export function HostDetailPage() {
  const params = useParams({ strict: false }) as { hostId?: string };
  const search = useSearch({ strict: false }) as HostDetailSearch;
  const navigate = useNavigate();
  const hostId = params.hostId ?? '';
  const framework = search.framework;
  const activeTab: TabId = search.tab ?? 'overview';
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);

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
      const raw = data as unknown as Partial<HostDetail> & Partial<HostResponse>;
      if (raw && 'host' in raw && raw.host) {
        return {
          host: raw.host,
          liveness: raw.liveness ?? null,
          compliance_summary: raw.compliance_summary ?? DEFAULT_SUMMARY,
        } satisfies HostDetail;
      }
      if (raw && typeof raw === 'object' && 'hostname' in raw && raw.hostname) {
        return {
          host: raw as HostResponse,
          liveness: null,
          compliance_summary: DEFAULT_SUMMARY,
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

  const historyQuery = useQuery({
    queryKey: ['host', hostId, 'monitoring-history'],
    queryFn: async () => {
      const { data, error, response } = await api.GET(
        '/api/v1/hosts/{host_id}/monitoring/history',
        {
          params: { path: { host_id: hostId }, query: { limit: 25 } },
        },
      );
      if (response.status === 404) return [] as MonitoringHistoryEntry[];
      if (error) throw error;
      const raw = data as unknown as { entries?: MonitoringHistoryEntry[] } | null;
      return raw?.entries ?? [];
    },
    enabled: !!hostId,
    retry: false,
  });

  // Topbar breadcrumb — pushes "Infrastructure / Hosts / <hostname>"
  // into the global useBreadcrumbStore so the sticky header renders
  // it (same pattern as HostsListPage). AC-27.
  const hostname = detailQuery.data?.host?.hostname;
  useEffect(() => {
    setCrumbs([
      { label: 'Infrastructure' },
      { label: 'Hosts', href: '/hosts' },
      ...(hostname ? [{ label: hostname }] : []),
    ]);
    return () => setCrumbs([]);
  }, [setCrumbs, hostname]);

  const goToTab = (tab: TabId) =>
    navigate({
      to: '/hosts/$hostId',
      params: { hostId },
      search: tab === 'overview' && !framework ? {} : { ...(framework ? { framework } : {}), tab },
    });

  const onFrameworkChange = (next: string | undefined) =>
    navigate({
      to: '/hosts/$hostId',
      params: { hostId },
      search: {
        ...(next ? { framework: next } : {}),
        ...(activeTab !== 'overview' ? { tab: activeTab } : {}),
      },
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
          {/* PAGE_HEAD */}
          <PageHead
            host={detailQuery.data.host}
            liveness={detailQuery.data.liveness}
          />

          {/* OFFLINE_BANNER */}
          <OfflineBanner liveness={detailQuery.data.liveness} />

          {/* TABS_ROW */}
          <TabsRow
            active={activeTab}
            onChange={goToTab}
            complianceFailing={detailQuery.data.compliance_summary.failing}
          />

          {activeTab === 'overview' ? (
            <>
              {/* HERO_STRIP */}
              <section
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(4, minmax(0, 1fr))',
                  gap: 14,
                  margin: '16px 0',
                }}
                aria-label="Host hero stats"
              >
                <HeroCompliance
                  summary={detailQuery.data.compliance_summary}
                  framework={framework}
                  onFrameworkChange={onFrameworkChange}
                />
                <HeroAutoScan />
                <HeroConnectivity
                  host={detailQuery.data.host}
                  liveness={detailQuery.data.liveness}
                />
                <HeroWatchlist />
              </section>

              {/* OVERVIEW_BODY */}
              <section
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)',
                  gap: 14,
                  alignItems: 'start',
                }}
                aria-label="Overview body"
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: 14, minWidth: 0 }}>
                  <CardTopFailed />
                  <CardServerIntel />
                  <CardComplianceTrend />
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 14, minWidth: 0 }}>
                  <CardSystem host={detailQuery.data.host} />
                  <CardRecentActivity
                    isLoading={historyQuery.isLoading}
                    isError={historyQuery.isError}
                    entries={historyQuery.data ?? []}
                    onRetry={() => historyQuery.refetch()}
                  />
                </div>
              </section>
            </>
          ) : (
            <TabStub
              tab={activeTab}
              subsystem={TAB_BACKEND_SUBSYSTEM[activeTab]}
            />
          )}
        </>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Page head — band 2
// ─────────────────────────────────────────────────────────────────────────

function PageHead({
  host,
  liveness,
}: {
  host: HostResponse;
  liveness: HostLiveness | null;
}) {
  const [editOpen, setEditOpen] = useState(false);
  const band: MonitoringBand =
    host.maintenance_mode === true
      ? 'maintenance'
      : liveness?.monitoring_state ?? 'unknown';

  // OS / Kernel / Uptime are populated by Server Intelligence
  // collection (BACKLOG). Until that lands, the slots show em-dash
  // placeholders (Kernel / Uptime keep their bare prefix; OS hides
  // entirely when unknown — see AC-15 v1.0.1).
  const osDistribution: string | undefined = undefined;
  const kernelVersion: string | undefined = undefined;
  const uptimeText: string | undefined = undefined;

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
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          gap: 16,
        }}
      >
        <div style={{ minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
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
            <StatusPill band={band} />
          </div>
          <div
            style={{
              color: 'var(--ow-fg-2)',
              fontSize: 13,
              marginTop: 6,
              display: 'flex',
              flexWrap: 'wrap',
              gap: 10,
              alignItems: 'center',
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
            {osDistribution && (
              <>
                <span style={{ color: 'var(--ow-fg-3)' }}>·</span>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  <span
                    style={{
                      display: 'inline-block',
                      width: 8,
                      height: 8,
                      borderRadius: '50%',
                      background: 'var(--ow-info)',
                    }}
                  />
                  <span style={{ color: 'var(--ow-fg-1)' }}>{osDistribution}</span>
                </span>
              </>
            )}
            <span style={{ color: 'var(--ow-fg-3)' }}>·</span>
            <span title="Kernel version — populated by Server Intelligence (BACKLOG)">
              {'Kernel '}
              <span style={{ color: 'var(--ow-fg-1)', fontFamily: 'var(--ow-font-mono)' }}>
                {kernelVersion ?? '—'}
              </span>
            </span>
            <span style={{ color: 'var(--ow-fg-3)' }}>·</span>
            <span title="Host uptime — populated by Server Intelligence (BACKLOG)">
              {'Uptime '}
              <span style={{ color: 'var(--ow-fg-1)' }}>{uptimeText ?? '—'}</span>
            </span>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
          <MaintenanceToggle host={host} />
          <button type="button" style={ghostBtn} title="Open terminal (deferred)" disabled>
            <TerminalIcon size={14} /> Terminal
          </button>
          <button type="button" style={primaryBtn} title="Run scan (deferred)" disabled>
            <Play size={14} /> Run scan
          </button>
          <button
            type="button"
            onClick={() => setEditOpen(true)}
            aria-label={`Edit ${host.hostname}`}
            style={ghostBtn}
          >
            <Pencil size={12} /> Edit
          </button>
          <button type="button" style={iconBtn} title="More" disabled>
            <MoreVertical size={14} />
          </button>
        </div>
      </div>
      <EditHostModal open={editOpen} onClose={() => setEditOpen(false)} host={host} />
    </section>
  );
}

// MaintenanceToggle — flips hosts.maintenance_mode via PUT
// /hosts/{id}/maintenance. While in maintenance the periodic probe
// skips the host entirely (no probe, no audit, no history row). Sits
// inline with the page-head action row (AC-07).
function MaintenanceToggle({ host }: { host: HostResponse }) {
  const queryClient = useQueryClient();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inMaintenance = host.maintenance_mode === true;

  const toggle = async () => {
    if (pending) return;
    setPending(true);
    setError(null);
    try {
      const { response, error: apiErr } = await api.PUT('/api/v1/hosts/{host_id}/maintenance', {
        params: { path: { host_id: host.id } },
        body: { enabled: !inMaintenance },
      });
      if (!response.ok) {
        const e = apiErr as { error?: { message?: string } } | undefined;
        setError(e?.error?.message ?? `HTTP ${response.status}`);
        return;
      }
      queryClient.invalidateQueries({ queryKey: ['host', host.id] });
      queryClient.invalidateQueries({ queryKey: ['hosts'] });
    } catch (e) {
      setError((e as Error)?.message ?? 'Network error');
    } finally {
      setPending(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <label
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 8,
          padding: '6px 12px',
          background: inMaintenance ? 'var(--ow-warn-bg)' : 'var(--ow-bg-2)',
          color: inMaintenance ? 'var(--ow-warn)' : 'var(--ow-fg-1)',
          border: '1px solid var(--ow-line)',
          borderRadius: 999,
          fontSize: 12,
          cursor: pending ? 'wait' : 'pointer',
          opacity: pending ? 0.6 : 1,
        }}
        title="Pause scans & alerts while maintenance is on"
      >
        <span>Maintenance</span>
        <input
          type="checkbox"
          checked={inMaintenance}
          onChange={toggle}
          disabled={pending}
          aria-label={`Toggle maintenance for ${host.hostname}`}
          style={{ margin: 0 }}
        />
      </label>
      {error && (
        <span role="alert" style={{ fontSize: 11, color: 'var(--ow-crit)' }}>
          {error}
        </span>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Status pill (band-aware) — used in page-head + connectivity card
// ─────────────────────────────────────────────────────────────────────────

const BAND_STYLE: Record<MonitoringBand, { label: string; fg: string; bg: string }> = {
  online: { label: 'ONLINE', fg: 'var(--ow-ok)', bg: 'var(--ow-ok-bg)' },
  degraded: { label: 'DEGRADED', fg: 'var(--ow-warn)', bg: 'var(--ow-warn-bg)' },
  critical: { label: 'CRITICAL', fg: 'var(--ow-crit)', bg: 'var(--ow-crit-bg)' },
  down: { label: 'DOWN', fg: 'var(--ow-crit)', bg: 'var(--ow-crit-bg)' },
  maintenance: { label: 'MAINTENANCE', fg: 'var(--ow-fg-2)', bg: 'var(--ow-bg-2)' },
  unknown: { label: 'UNKNOWN', fg: 'var(--ow-fg-3)', bg: 'var(--ow-bg-2)' },
};

function StatusPill({ band }: { band: MonitoringBand }) {
  const { label, fg, bg } = BAND_STYLE[band];
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        height: 22,
        padding: '0 8px',
        background: bg,
        borderRadius: 'var(--ow-radius-full)',
        fontSize: 11,
        color: fg,
        fontWeight: 600,
        letterSpacing: '0.02em',
      }}
      title={`Monitoring state: ${band}`}
    >
      <span
        style={{
          width: 6,
          height: 6,
          borderRadius: '50%',
          background: fg,
          boxShadow: `0 0 0 3px color-mix(in oklab, ${fg} 30%, transparent)`,
        }}
      />
      {label}
    </span>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Offline banner — band 3
// Renders only when band is down OR critical AND last_state_change_at
// is >= 5 minutes ago. The "5 * 60 * 1000" literal is intentional —
// AC-17 enforces the dwell threshold via source inspection.
// ─────────────────────────────────────────────────────────────────────────

function OfflineBanner({ liveness }: { liveness: HostLiveness | null }) {
  const band = liveness?.monitoring_state ?? 'unknown';
  // Banner only fires for hard-down hosts (band === 'down' or band === 'critical').
  const isBadBand = band === 'down' || band === 'critical';
  if (!isBadBand) return null;
  if (!liveness?.last_state_change_at) return null;
  const since = new Date(liveness.last_state_change_at).getTime();
  if (Number.isNaN(since)) return null;
  const dwellMs = Date.now() - since;
  if (dwellMs < 5 * 60 * 1000) return null;
  const minutes = Math.max(1, Math.round(dwellMs / 60_000));
  return (
    <div
      role="alert"
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 14,
        padding: '12px 18px',
        background: 'var(--ow-crit-bg)',
        border: '1px solid var(--ow-crit)',
        borderRadius: 'var(--ow-radius)',
        marginBottom: 14,
      }}
    >
      <WifiOff size={18} style={{ color: 'var(--ow-crit)', flexShrink: 0 }} />
      <div style={{ flex: 1 }}>
        <div style={{ fontWeight: 600, color: 'var(--ow-fg-0)' }}>
          Host unreachable for {minutes} minute{minutes === 1 ? '' : 's'}
        </div>
        <div style={{ color: 'var(--ow-fg-2)', fontSize: 12, marginTop: 2 }}>
          Compliance figures and inventory below reflect the last completed scan and may be stale
          until connectivity is restored.
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Tabs row — band 4
// ─────────────────────────────────────────────────────────────────────────

function TabsRow({
  active,
  onChange,
  complianceFailing,
}: {
  active: TabId;
  onChange: (tab: TabId) => void;
  complianceFailing: number;
}) {
  return (
    <nav
      role="tablist"
      aria-label="Host detail sections"
      style={{
        display: 'flex',
        gap: 4,
        borderBottom: '1px solid var(--ow-line)',
        marginBottom: 4,
        overflowX: 'auto',
      }}
    >
      {TAB_ORDER.map((t) => {
        const isActive = t.id === active;
        const Icon = t.icon;
        return (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={isActive}
            onClick={() => onChange(t.id)}
            style={{
              background: 'transparent',
              border: 0,
              padding: '10px 14px',
              fontSize: 13,
              color: isActive ? 'var(--ow-fg-0)' : 'var(--ow-fg-2)',
              borderBottom: isActive
                ? '2px solid var(--ow-info)'
                : '2px solid transparent',
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              whiteSpace: 'nowrap',
            }}
          >
            <Icon size={14} />
            {t.label}
            {t.id === 'compliance' && complianceFailing > 0 && (
              <span
                style={{
                  padding: '0 6px',
                  height: 16,
                  background: 'var(--ow-crit-bg)',
                  color: 'var(--ow-crit)',
                  borderRadius: 8,
                  fontSize: 10,
                  fontWeight: 600,
                  display: 'inline-flex',
                  alignItems: 'center',
                }}
              >
                {complianceFailing}
              </span>
            )}
          </button>
        );
      })}
    </nav>
  );
}

function TabStub({ tab, subsystem }: { tab: TabId; subsystem: string }) {
  return (
    <section
      role="tabpanel"
      aria-label={`${tab} (coming soon)`}
      style={{
        marginTop: 18,
        padding: '36px 28px',
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        textAlign: 'center',
      }}
    >
      <div style={{ color: 'var(--ow-fg-1)', fontSize: 15, fontWeight: 600, marginBottom: 6 }}>
        Not yet available
      </div>
      <div style={{ color: 'var(--ow-fg-2)', fontSize: 12, maxWidth: 520, margin: '0 auto' }}>
        {subsystem}
      </div>
    </section>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Hero stat strip — band 5
// ─────────────────────────────────────────────────────────────────────────

function HeroCompliance({
  summary,
  framework,
  onFrameworkChange,
}: {
  summary: ComplianceSummary;
  framework: string | undefined;
  onFrameworkChange: (next: string | undefined) => void;
}) {
  // AC-04 / AC-05: keep the canonical math expression + label strings.
  const isEmpty = summary.total === 0;
  const pct = isEmpty ? 0 : Math.round((summary.passing / summary.total) * 100);
  return (
    <article style={heroCard} aria-labelledby="hero-compliance-title">
      <header style={heroHead}>
        <span id="hero-compliance-title">Compliance</span>
        <FrameworkFilter value={framework} onChange={onFrameworkChange} />
      </header>
      {isEmpty ? (
        <div role="status" style={{ color: 'var(--ow-fg-2)', fontSize: 12 }}>
          No compliance data for this host yet
        </div>
      ) : (
        <>
          <div
            style={{
              fontSize: 32,
              fontWeight: 700,
              lineHeight: 1,
              fontVariantNumeric: 'tabular-nums',
              color: 'var(--ow-fg-0)',
            }}
          >
            {pct}
            <span style={{ fontSize: 16, color: 'var(--ow-fg-3)', marginLeft: 2 }}>%</span>
          </div>
          <div
            style={{
              display: 'flex',
              gap: 14,
              fontSize: 12,
              color: 'var(--ow-fg-2)',
              marginTop: 8,
              flexWrap: 'wrap',
            }}
          >
            <Stat n={summary.passing} label="passing" color="var(--ow-ok)" />
            <Stat n={summary.failing} label="failing" color="var(--ow-crit)" />
            <Stat n={summary.skipped} label="skipped" color="var(--ow-warn)" />
            <Stat n={summary.error} label="error" color="var(--ow-fg-2)" />
          </div>
        </>
      )}
    </article>
  );
}

function HeroAutoScan() {
  // Adaptive compliance scheduler is deferred (BACKLOG); render the
  // prototype's structured rows with placeholder values so the card
  // shape matches a future "Enabled" state. AC-29.
  return (
    <article style={heroCard} aria-labelledby="hero-autoscan-title">
      <header style={heroHead}>
        <span id="hero-autoscan-title">Auto-scan</span>
        <Clock size={14} aria-hidden />
      </header>
      <BandLine label="Disabled" color="var(--ow-fg-3)" />
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12 }}>
        <KvRow k={'Next'} v={<span style={{ color: 'var(--ow-fg-3)' }}>—</span>} />
        <KvRow k={'Interval'} v={<span style={{ color: 'var(--ow-fg-3)' }}>—</span>} />
      </div>
      <div
        style={{
          marginTop: 6,
          paddingTop: 8,
          borderTop: '1px solid var(--ow-line)',
          color: 'var(--ow-fg-3)',
          fontSize: 11,
          lineHeight: 1.5,
        }}
      >
        Populated by the adaptive compliance scheduler (BACKLOG).
      </div>
    </article>
  );
}

// bandLabel returns the human-facing label + accent color for a band.
// Used by HeroConnectivity's prominent status line (AC-31).
function bandLabel(band: MonitoringBand): { label: string; color: string } {
  switch (band) {
    case 'online':
      return { label: 'Online', color: 'var(--ow-ok)' };
    case 'degraded':
      return { label: 'Degraded', color: 'var(--ow-warn)' };
    case 'critical':
      return { label: 'Critical', color: 'var(--ow-crit)' };
    case 'down':
      return { label: 'Offline', color: 'var(--ow-crit)' };
    case 'maintenance':
      return { label: 'Maintenance', color: 'var(--ow-fg-2)' };
    default:
      return { label: 'Unknown', color: 'var(--ow-fg-3)' };
  }
}

function HeroConnectivity({
  host,
  liveness,
}: {
  host: HostResponse;
  liveness: HostLiveness | null;
}) {
  const band: MonitoringBand =
    host.maintenance_mode === true
      ? 'maintenance'
      : liveness?.monitoring_state ?? 'unknown';
  const { label: BAND_HEADLINE, color } = bandLabel(band);
  const lastSeen = liveness?.last_probe_at
    ? relativeMinutes(liveness.last_probe_at)
    : '—';
  return (
    <article style={heroCard} aria-labelledby="hero-conn-title">
      <header style={heroHead}>
        <span id="hero-conn-title">Connectivity</span>
        <Wifi size={14} aria-hidden />
      </header>
      <BandLine label={BAND_HEADLINE} color={color} />
      {liveness === null ? (
        <div style={{ color: 'var(--ow-fg-2)', fontSize: 12 }}>
          Not yet probed
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: 12 }}>
          <KvRow
            k="SSH"
            v={
              <span style={{ fontFamily: 'var(--ow-font-mono)' }}>
                {host.username ? `${host.username}@` : ''}
                {host.ip_address}:{host.port ?? 22}
              </span>
            }
          />
          <KvRow k="Auth" v={host.username ? 'system_default' : '—'} />
          <KvRow k="Last seen" v={lastSeen} />
        </div>
      )}
      <div
        style={{
          display: 'flex',
          gap: 6,
          marginTop: 6,
          paddingTop: 8,
          borderTop: '1px solid var(--ow-line)',
        }}
      >
        <button type="button" style={smallTextBtn} title="Reconnect (deferred)" disabled>
          Reconnect
        </button>
        <button type="button" style={smallTextBtn} title="Edit credentials (deferred)" disabled>
          Edit credentials
        </button>
      </div>
    </article>
  );
}

// BandLine — the "● <label>" prominent status line used in HeroAutoScan
// and HeroConnectivity. Matches the prototype's per-card state row.
function BandLine({ label, color }: { label: string; color: string }) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 6,
        fontSize: 16,
        fontWeight: 600,
        color,
      }}
    >
      <Circle size={8} fill={color} color={color} />
      {label}
    </div>
  );
}

function HeroWatchlist() {
  // Alerts + exceptions subsystem deferred (BACKLOG); render the
  // prototype's two-metric layout with 0s and empty-state subtext. AC-30.
  return (
    <article style={heroCard} aria-labelledby="hero-watch-title">
      <header style={heroHead}>
        <span id="hero-watch-title">Watchlist</span>
        <Bell size={14} aria-hidden />
      </header>
      <WatchlistRow
        label={'Active alerts'}
        value={0}
        subtext="No alerts firing"
      />
      <WatchlistRow
        label={'Exceptions'}
        value={0}
        subtext="No suppressed rules"
      />
      <div
        style={{
          marginTop: 6,
          paddingTop: 8,
          borderTop: '1px solid var(--ow-line)',
          color: 'var(--ow-fg-3)',
          fontSize: 11,
          lineHeight: 1.5,
        }}
      >
        Populated by the alerts subsystem (BACKLOG).
      </div>
    </article>
  );
}

function WatchlistRow({
  label,
  value,
  subtext,
}: {
  label: string;
  value: number;
  subtext: string;
}) {
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
        <span style={{ color: 'var(--ow-fg-2)' }}>{label}</span>
        <span style={{ color: 'var(--ow-fg-0)', fontWeight: 600 }}>{value}</span>
      </div>
      <div style={{ color: 'var(--ow-fg-3)', fontSize: 11, marginTop: 2 }}>{subtext}</div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Overview body — band 6
// Left column: CardTopFailed, CardServerIntel, CardComplianceTrend
// Right column: CardSystem, CardRecentActivity
// ─────────────────────────────────────────────────────────────────────────

function CardTopFailed() {
  return (
    <Card title="Top failed rules">
      <EmptyState
        primary="No scan results yet"
        secondary="Populated by the compliance scanner (Kensa). Until a scan completes, host_rule_state is empty for this host."
      />
    </Card>
  );
}

function CardServerIntel() {
  return (
    <Card title="Server intelligence">
      <EmptyState
        primary="Not yet collected"
        secondary="Server intelligence collection (packages, services, users, network, firewall, audit events) is deferred — see BACKLOG."
      />
    </Card>
  );
}

function CardComplianceTrend() {
  return (
    <Card title="Compliance trend · last 30 days">
      <EmptyState
        primary="Not enough data yet"
        secondary="Trend chart is populated by posture snapshots (point-in-time aggregates). The posture snapshot subsystem is deferred — see BACKLOG."
      />
    </Card>
  );
}

function CardSystem({ host }: { host: HostResponse }) {
  return (
    <Card title="System">
      <SpecGroup title="Operating system">
        <DefList
          rows={[
            ['Distribution', <span key="d">unknown</span>],
            ['Kernel', <span key="k" style={{ fontFamily: 'var(--ow-font-mono)' }}>unknown</span>],
            ['FQDN', <span key="f" style={{ fontFamily: 'var(--ow-font-mono)' }}>{host.hostname}</span>],
            ['Uptime', <span key="u">unknown</span>],
          ]}
        />
      </SpecGroup>
      <SpecGroup title="Hardware">
        <EmptyState
          primary="Hardware metrics not collected"
          secondary="Populated by Server Intelligence (CPU / disk / memory). Deferred — see BACKLOG."
          compact
        />
      </SpecGroup>
      <SpecGroup title="Network">
        <DefList
          rows={[
            ['Primary IP', <span key="ip" style={{ fontFamily: 'var(--ow-font-mono)' }}>{host.ip_address}</span>],
            [
              'SSH endpoint',
              <span key="ssh" style={{ fontFamily: 'var(--ow-font-mono)' }}>
                {host.username ? `${host.username}@` : ''}
                {host.ip_address}:{host.port ?? 22}
              </span>,
            ],
            ['Firewall', <span key="fw">unknown</span>],
          ]}
        />
      </SpecGroup>
    </Card>
  );
}

function CardRecentActivity({
  isLoading,
  isError,
  entries,
  onRetry,
}: {
  isLoading: boolean;
  isError: boolean;
  entries: MonitoringHistoryEntry[];
  onRetry: () => void;
}) {
  const visible = useMemo(() => entries.slice(0, PAGE_SIZE), [entries]);
  return (
    <Card title="Recent activity">
      {isLoading ? (
        <div style={{ color: 'var(--ow-fg-2)', fontSize: 12 }}>Loading…</div>
      ) : isError ? (
        <div style={{ color: 'var(--ow-crit)', fontSize: 12, display: 'flex', gap: 8, alignItems: 'center' }}>
          Failed to load activity{' '}
          <button type="button" onClick={onRetry} style={smallTextBtn}>
            <RefreshCw size={11} /> Retry
          </button>
        </div>
      ) : visible.length === 0 ? (
        <EmptyState
          primary="No activity yet"
          secondary="Sourced from host_monitoring_history (band transitions). The list will populate after the first probe records a state change."
        />
      ) : (
        <ol style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
          {visible.map((e) => (
            <ActivityRow key={e.id} entry={e} />
          ))}
        </ol>
      )}
    </Card>
  );
}

function ActivityRow({ entry }: { entry: MonitoringHistoryEntry }) {
  const sev = severityFor(entry.monitoring_state);
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
      <Circle size={8} fill={sev.dot} color={sev.dot} style={{ marginTop: 5 }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ color: 'var(--ow-fg-0)', fontSize: 13 }}>
          {entry.previous_state
            ? `${entry.previous_state} → ${entry.monitoring_state}`
            : `Now ${entry.monitoring_state}`}
          {entry.failed_layer ? (
            <span style={{ color: sev.fg, marginLeft: 8, fontSize: 11 }}>
              {entry.failed_layer} fail
            </span>
          ) : null}
        </div>
        {entry.error_message && (
          <div
            style={{
              color: 'var(--ow-fg-3)',
              fontSize: 11,
              marginTop: 2,
              fontFamily: 'var(--ow-font-mono)',
              overflowWrap: 'anywhere',
            }}
          >
            {entry.error_message}
          </div>
        )}
      </div>
      <div style={{ color: 'var(--ow-fg-3)', fontSize: 11, whiteSpace: 'nowrap' }}>
        {relativeMinutes(entry.check_time)}
      </div>
    </li>
  );
}

function severityFor(band: MonitoringBand): { fg: string; dot: string } {
  switch (band) {
    case 'down':
    case 'critical':
      return { fg: 'var(--ow-crit)', dot: 'var(--ow-crit)' };
    case 'degraded':
      return { fg: 'var(--ow-warn)', dot: 'var(--ow-warn)' };
    case 'online':
      return { fg: 'var(--ow-ok)', dot: 'var(--ow-ok)' };
    case 'maintenance':
      return { fg: 'var(--ow-fg-2)', dot: 'var(--ow-fg-2)' };
    default:
      return { fg: 'var(--ow-fg-3)', dot: 'var(--ow-fg-3)' };
  }
}

// ─────────────────────────────────────────────────────────────────────────
// Reusable bits (cards, kv rows, empty states, etc.)
// ─────────────────────────────────────────────────────────────────────────

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

function SpecGroup({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <h4
        style={{
          margin: '0 0 8px',
          fontSize: 11,
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          color: 'var(--ow-fg-2)',
        }}
      >
        {title}
      </h4>
      {children}
    </div>
  );
}

function DefList({ rows }: { rows: [string, React.ReactNode][] }) {
  return (
    <dl
      style={{
        display: 'grid',
        gridTemplateColumns: 'max-content 1fr',
        rowGap: 6,
        columnGap: 14,
        margin: 0,
        fontSize: 12,
      }}
    >
      {rows.map(([k, v]) => (
        <ReactFrag key={k}>
          <dt style={{ color: 'var(--ow-fg-3)' }}>{k}</dt>
          <dd style={{ margin: 0, color: 'var(--ow-fg-1)', minWidth: 0 }}>{v}</dd>
        </ReactFrag>
      ))}
    </dl>
  );
}

function ReactFrag({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}

function EmptyState({
  primary,
  secondary,
  compact,
}: {
  primary: string;
  secondary: string;
  compact?: boolean;
}) {
  return (
    <div
      role="status"
      style={{
        padding: compact ? '12px 0' : '20px 0',
        textAlign: 'center',
        color: 'var(--ow-fg-2)',
      }}
    >
      <div style={{ color: 'var(--ow-fg-1)', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>
        {primary}
      </div>
      <div style={{ fontSize: 11, color: 'var(--ow-fg-3)', maxWidth: 360, margin: '0 auto', lineHeight: 1.5 }}>
        {secondary}
      </div>
    </div>
  );
}

function KvRow({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10 }}>
      <span style={{ color: 'var(--ow-fg-3)' }}>{k}</span>
      <span style={{ color: 'var(--ow-fg-1)', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis' }}>{v}</span>
    </div>
  );
}

function Stat({ n, label, color }: { n: number; label: string; color: string }) {
  return (
    <div>
      <div
        style={{
          fontSize: 18,
          fontWeight: 600,
          color,
          fontVariantNumeric: 'tabular-nums',
          lineHeight: 1,
        }}
      >
        {n}
      </div>
      <div
        style={{
          color: 'var(--ow-fg-3)',
          fontSize: 10,
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          marginTop: 2,
        }}
        title={label}
        data-stat-label={label}
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
  const frameworks = [
    { value: '', label: 'All frameworks' },
    { value: 'cis_rhel9_v2.0.0', label: 'CIS RHEL 9 v2.0.0' },
    { value: 'stig_rhel9_v2r7', label: 'STIG RHEL 9 V2R7' },
    { value: 'nist_800_53_r5', label: 'NIST 800-53 R5' },
  ];
  return (
    <label style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <span style={{ fontSize: 11, color: 'var(--ow-fg-3)' }}>Framework</span>
      <select
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value || undefined)}
        style={{
          height: 22,
          padding: '0 4px',
          background: 'var(--ow-bg-2)',
          border: '1px solid var(--ow-line)',
          borderRadius: 4,
          color: 'var(--ow-fg-0)',
          fontFamily: 'inherit',
          fontSize: 11,
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

// ─────────────────────────────────────────────────────────────────────────
// Status / loading / error scaffolding
// ─────────────────────────────────────────────────────────────────────────

function LoadingPlaceholder() {
  return (
    <div
      role="status"
      aria-busy="true"
      style={{
        padding: 32,
        textAlign: 'center',
        color: 'var(--ow-fg-2)',
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
      }}
    >
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
        <p>The host you tried to open is not in this fleet. It may have been deleted.</p>
        <Link to="/hosts" style={{ color: 'var(--ow-info)' }}>
          Back to hosts
        </Link>
      </div>
    );
  }
  if (code === 'authz.permission_denied') {
    return (
      <div role="alert" style={errorPanel}>
        <h2 style={{ marginTop: 0 }}>Access denied</h2>
        <p>{message}</p>
      </div>
    );
  }
  return (
    <div role="alert" style={errorPanel}>
      <h2 style={{ marginTop: 0 }}>Could not load host</h2>
      <p>{message}</p>
      <button type="button" onClick={onRetry} style={primaryBtn}>
        <RefreshCw size={14} /> Retry
      </button>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Time helpers
// ─────────────────────────────────────────────────────────────────────────

function relativeMinutes(iso: string): string {
  const at = new Date(iso).getTime();
  if (Number.isNaN(at)) return '—';
  const m = Math.max(0, Math.round((Date.now() - at) / 60_000));
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

// ─────────────────────────────────────────────────────────────────────────
// Styles
// ─────────────────────────────────────────────────────────────────────────

const heroCard: React.CSSProperties = {
  background: 'var(--ow-bg-1)',
  border: '1px solid var(--ow-line)',
  borderRadius: 'var(--ow-radius)',
  padding: 16,
  display: 'flex',
  flexDirection: 'column',
  gap: 8,
  minHeight: 130,
};

const heroHead: React.CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  color: 'var(--ow-fg-2)',
  fontSize: 12,
  fontWeight: 500,
  textTransform: 'uppercase',
  letterSpacing: '0.04em',
};

const iconBtn: React.CSSProperties = {
  width: 28,
  height: 28,
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  background: 'var(--ow-bg-2)',
  border: '1px solid var(--ow-line)',
  borderRadius: 6,
  color: 'var(--ow-fg-1)',
  cursor: 'pointer',
};

const ghostBtn: React.CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: 6,
  background: 'var(--ow-bg-2)',
  border: '1px solid var(--ow-line)',
  borderRadius: 6,
  padding: '6px 12px',
  color: 'var(--ow-fg-1)',
  fontSize: 12,
  cursor: 'pointer',
};

const primaryBtn: React.CSSProperties = {
  ...ghostBtn,
  background: 'var(--ow-info)',
  color: 'var(--ow-info-on, #fff)',
  border: '1px solid var(--ow-info)',
};

const smallTextBtn: React.CSSProperties = {
  background: 'transparent',
  border: 0,
  color: 'var(--ow-info)',
  fontSize: 11,
  cursor: 'pointer',
  display: 'inline-flex',
  alignItems: 'center',
  gap: 4,
  padding: 0,
};

const errorPanel: React.CSSProperties = {
  padding: 20,
  background: 'var(--ow-bg-1)',
  border: '1px solid var(--ow-line)',
  borderRadius: 'var(--ow-radius)',
};
