import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useParams, useSearch, useNavigate, Link } from '@tanstack/react-router';
import { useEffect, useMemo, useState, type CSSProperties, type ReactNode } from 'react';
import {
  Activity as ActivityIcon,
  AlertTriangle,
  Bell,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Circle,
  Clock,
  FileText,
  LayoutGrid,
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
import { useHostExceptions } from '@/hooks/useHostExceptions';
import { useHostRemediations } from '@/hooks/useHostRemediations';
import { formatLift } from '@/components/hosts/RequestRemediationModal';
import { apiErrorCode, apiErrorMessage } from '@/api/errors';
import { relativeTime } from '@/api/eventDisplay';
import { EditHostModal } from '@/components/hosts/EditHostModal';
import { HostCredentialModal } from '@/components/hosts/HostCredentialModal';
import { HostActionsMenu } from '@/components/hosts/HostActionsMenu';
import { useAuthStore } from '@/store/useAuthStore';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import { CardSystem, pickNumber, pickString } from '@/pages/host-detail/CardSystem';
import { osDisplayLabel } from '@/utils/osLabel';
import { formatUptime } from '@/utils/formatUptime';
import { stripKernelDistroSuffix } from '@/utils/kernelVersion';
import { CardServerIntel } from '@/pages/host-detail/CardServerIntel';
import { ComplianceTab } from '@/pages/host-detail/ComplianceTab';
import { SeverityPill } from '@/pages/host-detail/SeverityPill';
import {
  PackagesTab,
  ServicesTab,
  UsersTab,
  NetworkTab,
  packagesCount,
  servicesCount,
  usersCount,
  networkCount,
  type InventorySnapshot,
} from '@/pages/host-detail/InventoryTabs';

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
  // v1.4.0 (api-hosts) — denormalized OS columns populated by
  // system-host-discovery. NULL until Discovery has run.
  os_family?: string | null;
  os_version?: string | null;
  architecture?: string | null;
  platform_identifier?: string | null;
  os_discovered_at?: string | null;
}

type MonitoringBand = 'online' | 'degraded' | 'critical' | 'down' | 'maintenance' | 'unknown';

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

// ActivityItem mirrors the api.Activity envelope returned by
// GET /api/v1/activity. Source-aware rendering branches on `source`.
// Replaces the prior MonitoringHistoryEntry shape — Recent Activity
// is now the unified union (monitoring band transitions + scan
// transactions + intelligence events + alerts + audit) per
// system-activity v1.1.0.
type ActivitySource = 'alert' | 'transaction' | 'intelligence' | 'audit' | 'monitoring';

type ActivitySeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

interface ActivityItem {
  id: string;
  source: ActivitySource;
  severity: ActivitySeverity;
  host_id?: string | null;
  title: string;
  summary?: string;
  occurred_at: string;
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
const TAB_BACKEND_SUBSYSTEM: Record<
  Exclude<TabId, 'overview' | 'compliance' | 'remediation'>,
  string
> = {
  packages: 'Server Intelligence collection — installed-package inventory deferred (BACKLOG).',
  services: 'Server Intelligence collection — running services inventory deferred (BACKLOG).',
  users: 'Server Intelligence collection — user accounts inventory deferred (BACKLOG).',
  network: 'Server Intelligence collection — interfaces and firewall rules deferred (BACKLOG).',
  audit_log:
    'Audit query API — host-scoped audit feed deferred to the unified /activity page (BACKLOG).',
  activity: 'Unified Activity feed — combined transactions + audits + alerts deferred (BACKLOG).',
  terminal: 'Web terminal — SSH-in-browser deferred; use a host-side SSH client in the meantime.',
};

const DEFAULT_SUMMARY: ComplianceSummary = {
  passing: 0,
  failing: 0,
  skipped: 0,
  error: 0,
  total: 0,
};

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

  // Recent Activity now consumes the unified /api/v1/activity feed
  // scoped to this host. system-activity v1.1.0 unions five sources:
  // alert, transaction, intelligence, audit, monitoring (band
  // transitions). The per-host filter excludes audit (it has no
  // host_id column — the leg evaluates FALSE under host filter).
  const activityQuery = useQuery({
    queryKey: ['host_activity', hostId],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/activity', {
        params: { query: { host_id: hostId, limit: 25 } },
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      if (error) throw new Error('activity fetch failed');
      const raw = data as unknown as { items?: ActivityItem[] } | null;
      return raw?.items ?? [];
    },
    enabled: !!hostId,
    retry: false,
  });

  // IntelligenceState feeds the System card (kernel_release, uptime_seconds).
  // 404 = no snapshot yet OR host unknown (handler intentionally
  // collapses both per api-os-intelligence C-04). We treat it as
  // "no snapshot" — the host-detail query owns the unknown-host path.
  // Query key matches frontend-host-detail-system-card C-05 / AC-06.
  const intelligenceStateQuery = useQuery({
    queryKey: ['intelligence_state', hostId],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/intelligence/state/{host_id}', {
        params: { path: { host_id: hostId } },
      });
      if (response.status === 404) return null;
      if (error) throw error;
      const raw = data as unknown as { snapshot?: Record<string, unknown> } | null;
      return raw?.snapshot ?? null;
    },
    enabled: !!hostId,
    retry: false,
  });

  // host_system_info — the latest Discovery snapshot of OS / kernel /
  // arch / memory / disk / firewall facts. Used by CardSystem's Hardware
  // and Network sections. 404 = no row yet OR unknown host (handler
  // collapses both per api-host-system-info C-03); treat as null.
  const systemInfoQuery = useQuery({
    queryKey: ['host_system_info', hostId],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/hosts/{id}/system-info', {
        params: { path: { id: hostId } },
      });
      if (response.status === 404) return null;
      if (error) throw error;
      return data ?? null;
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

  // Lens selection for the Compliance tab (frontend-host-compliance-tab
  // C-01) — updates the ?framework= search param. The host detail
  // queryKey embeds framework (api-hosts AC-08) and the ComplianceTab
  // lens queryKey does too, so both refetch on change.
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

      {detailQuery.isError && (
        <ErrorState
          code={apiErrorCode(detailQuery.error)}
          message={apiErrorMessage(detailQuery.error, 'Failed to load')}
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
            intelligenceSnapshot={intelligenceStateQuery.data ?? null}
          />

          {/* OFFLINE_BANNER */}
          <OfflineBanner liveness={detailQuery.data.liveness} />

          {/* TABS_ROW */}
          <TabsRow
            active={activeTab}
            onChange={goToTab}
            complianceFailing={detailQuery.data.compliance_summary.failing}
            inventory={(intelligenceStateQuery.data ?? null) as InventorySnapshot | null}
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
                <HeroCompliance summary={detailQuery.data.compliance_summary} lastScan={null} />
                <HeroAutoScan hostId={hostId} />
                <HeroConnectivity
                  host={detailQuery.data.host}
                  liveness={detailQuery.data.liveness}
                />
                <HeroWatchlist hostId={hostId} />
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
                  <CardTopFailed
                    hostId={detailQuery.data.host.id}
                    framework={framework}
                    hasScanData={detailQuery.data.compliance_summary.total > 0}
                    onViewAll={() => goToTab('compliance')}
                  />
                  <CardServerIntel hostId={detailQuery.data.host.id} />
                  <CardComplianceTrend hostId={hostId} />
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 14, minWidth: 0 }}>
                  <CardSystem
                    host={detailQuery.data.host}
                    intelligenceSnapshot={intelligenceStateQuery.data ?? null}
                    systemInfo={systemInfoQuery.data ?? null}
                  />
                  <CardRecentActivity
                    hostId={detailQuery.data.host.id}
                    isLoading={activityQuery.isLoading}
                    isError={activityQuery.isError}
                    items={activityQuery.data ?? []}
                    onRetry={() => activityQuery.refetch()}
                  />
                </div>
              </section>
            </>
          ) : activeTab === 'compliance' ? (
            <ComplianceTab
              hostId={detailQuery.data.host.id}
              framework={framework}
              onFrameworkChange={onFrameworkChange}
            />
          ) : activeTab === 'packages' ? (
            <PackagesTab
              isLoading={intelligenceStateQuery.isLoading}
              snapshot={(intelligenceStateQuery.data ?? null) as InventorySnapshot | null}
            />
          ) : activeTab === 'services' ? (
            <ServicesTab
              isLoading={intelligenceStateQuery.isLoading}
              snapshot={(intelligenceStateQuery.data ?? null) as InventorySnapshot | null}
            />
          ) : activeTab === 'users' ? (
            <UsersTab
              isLoading={intelligenceStateQuery.isLoading}
              snapshot={(intelligenceStateQuery.data ?? null) as InventorySnapshot | null}
            />
          ) : activeTab === 'network' ? (
            <NetworkTab
              isLoading={intelligenceStateQuery.isLoading}
              snapshot={(intelligenceStateQuery.data ?? null) as InventorySnapshot | null}
              firewall={
                systemInfoQuery.data
                  ? {
                      service: (systemInfoQuery.data as { firewall_service?: string | null })
                        .firewall_service,
                      status: (systemInfoQuery.data as { firewall_status?: string | null })
                        .firewall_status,
                    }
                  : null
              }
            />
          ) : activeTab === 'remediation' ? (
            <RemediationTab hostId={detailQuery.data.host.id} />
          ) : (
            <TabStub tab={activeTab} subsystem={TAB_BACKEND_SUBSYSTEM[activeTab]} />
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
  intelligenceSnapshot,
}: {
  host: HostResponse;
  liveness: HostLiveness | null;
  /** Same intelligence_state.snapshot the System card reads. */
  intelligenceSnapshot: Record<string, unknown> | null;
}) {
  const [editOpen, setEditOpen] = useState(false);
  const [credOpen, setCredOpen] = useState(false);
  const canWrite = useAuthStore((s) => s.hasPermission('host:write'));
  const canReadCred = useAuthStore((s) => s.hasPermission('credential:read'));
  const band: MonitoringBand =
    host.maintenance_mode === true ? 'maintenance' : (liveness?.monitoring_state ?? 'unknown');

  // OS / Kernel / Uptime are sourced from the same two queries the
  // System card uses — hosts (os_family, os_version, denormalized by
  // Discovery) and intelligence_state.snapshot (kernel_release,
  // uptime_seconds, populated by the OS Intelligence cycle). No
  // additional DB read; we reuse intelligenceStateQuery.data.
  const osDistribution =
    host.os_family || host.os_version
      ? `${osDisplayLabel(host.os_family)}${host.os_version ? ` ${host.os_version}` : ''}`
      : undefined;
  const kernelRelease = pickString(intelligenceSnapshot, 'kernel_release');
  const kernelVersion = kernelRelease ? stripKernelDistroSuffix(kernelRelease) : undefined;
  const uptimeSeconds = pickNumber(intelligenceSnapshot, 'uptime_seconds');
  const uptimeText = uptimeSeconds !== null ? formatUptime(uptimeSeconds) : undefined;

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
        <div style={{ display: 'flex', gap: 14, minWidth: 0, alignItems: 'flex-start' }}>
          <Link
            to="/hosts"
            aria-label="Back to hosts"
            title="Back to hosts"
            style={{
              flexShrink: 0,
              width: 36,
              height: 36,
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: 'var(--ow-bg-2)',
              border: '1px solid var(--ow-line)',
              borderRadius: 8,
              color: 'var(--ow-fg-1)',
              textDecoration: 'none',
            }}
          >
            <ChevronLeft size={16} />
          </Link>
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
              <span style={{ color: 'var(--ow-fg-3)' }}>·</span>
              <span
                style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
                title="OS distribution — from hosts.os_family / os_version (Discovery)"
              >
                {osDistribution ? (
                  <>
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
                  </>
                ) : (
                  <>
                    {'OS '}
                    <span style={{ color: 'var(--ow-fg-1)' }}>—</span>
                  </>
                )}
              </span>
              <span style={{ color: 'var(--ow-fg-3)' }}>·</span>
              <span title="Kernel — from intelligence_state.snapshot.kernel_release">
                {'Kernel '}
                <span style={{ color: 'var(--ow-fg-1)', fontFamily: 'var(--ow-font-mono)' }}>
                  {kernelVersion ?? '—'}
                </span>
              </span>
              <span style={{ color: 'var(--ow-fg-3)' }}>·</span>
              <span title="Uptime — from intelligence_state.snapshot.uptime_seconds">
                {'Uptime '}
                <span style={{ color: 'var(--ow-fg-1)' }}>{uptimeText ?? '—'}</span>
              </span>
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
          <MaintenanceToggle host={host} />
          <button type="button" style={ghostBtn} title="Open terminal (deferred)" disabled>
            <TerminalIcon size={14} /> Terminal
          </button>
          <RunScanButton host={host} />
          {canWrite && (
            <button
              type="button"
              onClick={() => setEditOpen(true)}
              aria-label={`Edit ${host.hostname}`}
              style={ghostBtn}
            >
              <Pencil size={12} /> Edit
            </button>
          )}
          <HostActionsMenu
            hostId={host.id}
            hostname={host.hostname}
            showEdit={false}
            afterDelete="navigate"
            buttonStyle={iconBtn}
          />
        </div>
      </div>
      <EditHostModal
        open={editOpen}
        onClose={() => setEditOpen(false)}
        host={host}
        onManageCredential={
          canReadCred
            ? () => {
                setEditOpen(false);
                setCredOpen(true);
              }
            : undefined
        }
      />
      <HostCredentialModal
        open={credOpen}
        onClose={() => setCredOpen(false)}
        host={{ id: host.id, hostname: host.hostname }}
      />
    </section>
  );
}

// RunScanButton — enqueues an on-demand compliance scan via
// POST /hosts/{id}/scans (idempotency-keyed). The scan itself is
// asynchronous: results refresh through the scan.completed SSE topic
// (useLiveEvents invalidates ['host', id] + ['hosts']), so there is no
// polling here. 409 means a scan is already queued/running for this
// host — surfaced as a transient inline note, not an error.
//
// Spec: frontend-host-detail (Run scan action) + api-host-scan.
function RunScanButton({ host }: { host: HostResponse }) {
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const runScan = async () => {
    if (busy) return;
    setBusy(true);
    setNote(null);
    try {
      const { response } = await api.POST('/api/v1/hosts/{id}/scans', {
        params: {
          path: { id: host.id },
          header: { 'Idempotency-Key': crypto.randomUUID() },
        },
      });
      if (response.status === 409) {
        setNote('Scan already running');
        return;
      }
      if (!response.ok) {
        setNote(`Scan request failed (${response.status})`);
        return;
      }
      setNote('Scan queued');
    } catch {
      setNote('Scan request failed');
    } finally {
      setBusy(false);
      // The note is transient feedback; the durable signal is the
      // scan.completed SSE refresh of the hero card.
      window.setTimeout(() => setNote(null), 5000);
    }
  };

  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
      {note && (
        <span role="status" style={{ color: 'var(--ow-fg-2)', fontSize: 12 }}>
          {note}
        </span>
      )}
      <button
        type="button"
        style={primaryBtn}
        onClick={runScan}
        disabled={busy}
        aria-label={`Run compliance scan on ${host.hostname}`}
        title="Run an on-demand compliance scan"
      >
        <Play size={14} /> {busy ? 'Queueing…' : 'Run scan'}
      </button>
    </span>
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
        setError(apiErrorMessage(apiErr, `HTTP ${response.status}`));
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

  // Switch-style control: a button with role="switch" + aria-checked.
  // The visible affordance is a label text + a small track with a
  // sliding round knob. AC-33.
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <button
        type="button"
        role="switch"
        aria-checked={inMaintenance}
        onClick={toggle}
        disabled={pending}
        aria-label={`Toggle maintenance for ${host.hostname}`}
        title="Pause scans & alerts while maintenance is on"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 10,
          padding: '6px 12px',
          background: inMaintenance ? 'var(--ow-warn-bg)' : 'var(--ow-bg-2)',
          color: inMaintenance ? 'var(--ow-warn)' : 'var(--ow-fg-1)',
          border: '1px solid var(--ow-line)',
          borderRadius: 999,
          fontSize: 12,
          cursor: pending ? 'wait' : 'pointer',
          opacity: pending ? 0.6 : 1,
        }}
      >
        <span>Maintenance</span>
        <span
          aria-hidden
          style={{
            position: 'relative',
            display: 'inline-block',
            width: 28,
            height: 16,
            background: inMaintenance ? 'var(--ow-warn)' : 'var(--ow-line)',
            borderRadius: 999,
            transition: 'background 120ms ease',
          }}
        >
          <span
            data-maintenance-knob
            style={{
              position: 'absolute',
              top: 2,
              left: inMaintenance ? 14 : 2,
              width: 12,
              height: 12,
              background: '#fff',
              borderRadius: '50%',
              transition: 'left 120ms ease',
              boxShadow: '0 1px 2px rgba(0,0,0,0.3)',
            }}
          />
        </span>
      </button>
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

// inferFailedLayer maps the liveness error signals to a human-readable
// "Failed at ping / SSH / privilege escalation" line. The mapping is
// belt-and-suspenders: last_error_type is the primary signal, and the
// per-layer counter that's > 0 is the fallback. AC-34.
function inferFailedLayer(liveness: HostLiveness | null): string | null {
  if (!liveness) return null;
  const errType = liveness.last_error_type ?? '';
  if (errType.startsWith('icmp_')) return 'ping';
  if (errType === 'privilege_denied') return 'privilege escalation';
  if (
    errType === 'banner_mismatch' ||
    errType === 'connection_refused' ||
    errType.startsWith('tcp_')
  )
    return 'SSH';
  // Fallback: pick the layer with the most recent failure spike.
  if ((liveness.ping_consecutive_failures ?? 0) > 0) return 'ping';
  if ((liveness.ssh_consecutive_failures ?? 0) > 0) return 'SSH';
  if ((liveness.privilege_consecutive_failures ?? 0) > 0) return 'privilege escalation';
  return null;
}

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
  const failedLayer = inferFailedLayer(liveness);
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
          {failedLayer ? (
            <>
              <strong style={{ color: 'var(--ow-fg-1)' }}>Failed at {failedLayer}.</strong>{' '}
              {failedLayer === 'ping' &&
                'Network team — host is off the LAN or ICMP is blocked upstream.'}
              {failedLayer === 'SSH' &&
                'Daemon down, port mismatch, or firewall rule — check sshd on the host.'}
              {failedLayer === 'privilege escalation' &&
                'sudo is broken or the credential lost privilege — host reachable but not scannable.'}
            </>
          ) : (
            'Compliance figures and inventory below reflect the last completed scan and may be stale until connectivity is restored.'
          )}
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
  inventory,
}: {
  active: TabId;
  onChange: (tab: TabId) => void;
  complianceFailing: number;
  inventory: InventorySnapshot | null;
}) {
  // Pre-compute counts once per render. Spec C-05.
  const pkgN = packagesCount(inventory);
  const svc = servicesCount(inventory);
  const usrN = usersCount(inventory);
  const netN = networkCount(inventory);
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
              borderBottom: isActive ? '2px solid var(--ow-info)' : '2px solid transparent',
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              whiteSpace: 'nowrap',
            }}
          >
            <Icon size={14} />
            {t.label}
            {t.id === 'packages' && pkgN > 0 && <TabCountBadge text={String(pkgN)} />}
            {t.id === 'services' && svc.total > 0 && (
              <TabCountBadge text={`${svc.active}/${svc.total}`} />
            )}
            {t.id === 'users' && usrN > 0 && <TabCountBadge text={String(usrN)} />}
            {t.id === 'network' && netN > 0 && <TabCountBadge text={String(netN)} />}
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

function TabCountBadge({ text }: { text: string }) {
  return (
    <span
      style={{
        padding: '0 6px',
        height: 16,
        background: 'var(--ow-bg-3)',
        color: 'var(--ow-fg-2)',
        borderRadius: 8,
        fontSize: 10,
        fontWeight: 600,
        display: 'inline-flex',
        alignItems: 'center',
      }}
    >
      {text}
    </span>
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
// Remediation tab — governance + single-rule apply surface.
//
// Lists this host's remediation requests (useHostRemediations, newest
// first) and drives the full per-rule lifecycle, which is now FREE core:
//   pending_approval -> approve | reject (remediation:approve)
//   approved         -> Fix / :execute (remediation:execute)
//   executing        -> "Applying..." (polled to executed | failed)
//   executed         -> Roll back / :rollback (remediation:rollback)
// Act permissions also pass with the 'admin' permission (|| isAdmin).
// The remaining OpenWatch+ paywall is BULK and AUTOMATED remediation
// (apply many rules / fleet-wide, scheduled auto-remediation), rendered
// as a DISABLED upsell never wired to any endpoint.
//
// Spec: frontend-remediation-tab AC-03..AC-07.
// ─────────────────────────────────────────────────────────────────────────

const REM_STATUS_STYLE: Record<string, { fg: string; bg: string; label: string }> = {
  pending_approval: { fg: 'var(--ow-warn)', bg: 'var(--ow-warn-bg)', label: 'Pending approval' },
  approved: { fg: 'var(--ow-info)', bg: 'var(--ow-bg-2)', label: 'Approved' },
  rejected: { fg: 'var(--ow-fg-3)', bg: 'var(--ow-bg-2)', label: 'Rejected' },
  dry_run_complete: { fg: 'var(--ow-info)', bg: 'var(--ow-bg-2)', label: 'Dry-run complete' },
  executing: { fg: 'var(--ow-warn)', bg: 'var(--ow-warn-bg)', label: 'Executing' },
  executed: { fg: 'var(--ow-ok)', bg: 'var(--ow-ok-bg)', label: 'Executed' },
  rolled_back: { fg: 'var(--ow-fg-2)', bg: 'var(--ow-bg-2)', label: 'Rolled back' },
  failed: { fg: 'var(--ow-crit)', bg: 'var(--ow-crit-bg)', label: 'Failed' },
};

function RemStatusChip({ status }: { status: string }) {
  const s = REM_STATUS_STYLE[status] ?? {
    fg: 'var(--ow-fg-2)',
    bg: 'var(--ow-bg-2)',
    label: status,
  };
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: '2px 8px',
        borderRadius: 999,
        background: s.bg,
        color: s.fg,
        fontSize: 11,
        fontWeight: 600,
        whiteSpace: 'nowrap',
      }}
    >
      <span aria-hidden style={{ width: 6, height: 6, borderRadius: '50%', background: s.fg }} />
      {s.label}
    </span>
  );
}

function RemediationTab({ hostId }: { hostId: string }) {
  const rem = useHostRemediations(hostId);
  const isAdmin = useAuthStore((s) => s.hasPermission('admin'));
  const canApprove = useAuthStore((s) => s.hasPermission('remediation:approve')) || isAdmin;
  const canExecute = useAuthStore((s) => s.hasPermission('remediation:execute')) || isAdmin;
  const canRollback = useAuthStore((s) => s.hasPermission('remediation:rollback')) || isAdmin;

  let body: ReactNode;
  if (rem.isPending) {
    body = (
      <div role="status" style={{ color: 'var(--ow-fg-3)', fontSize: 12, padding: '16px 0' }}>
        Loading remediation requests
      </div>
    );
  } else if (rem.isError) {
    body = (
      <div role="alert" style={{ color: 'var(--ow-crit)', fontSize: 12, padding: '16px 0' }}>
        Failed to load remediation requests.{' '}
        <button
          type="button"
          onClick={() => rem.refetch()}
          style={{
            background: 'none',
            border: '1px solid var(--ow-line)',
            borderRadius: 6,
            color: 'var(--ow-fg-1)',
            fontSize: 11,
            padding: '2px 8px',
            cursor: 'pointer',
          }}
        >
          Retry
        </button>
      </div>
    );
  } else if (rem.items.length === 0) {
    body = (
      <div role="status" style={{ color: 'var(--ow-fg-3)', fontSize: 12, padding: '16px 0' }}>
        No remediation requests for this host yet. Request a fix from a failing rule on the
        Compliance tab.
      </div>
    );
  } else {
    body = (
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <thead>
          <tr>
            <RemTh width={150}>Status</RemTh>
            <RemTh>Rule</RemTh>
            <RemTh width={200}>Projected lift</RemTh>
            <RemTh width={220}>Action</RemTh>
          </tr>
        </thead>
        <tbody>
          {rem.items.map((r) => {
            const lift = formatLift(r.projected_lift);
            return (
              <tr key={r.id} style={{ borderTop: '1px solid var(--ow-line)' }}>
                <td style={remTd}>
                  <RemStatusChip status={r.status} />
                </td>
                <td style={remTd}>
                  <span style={{ fontFamily: 'var(--ow-font-mono)', color: 'var(--ow-fg-0)' }}>
                    {r.rule_id}
                  </span>
                </td>
                <td
                  style={{ ...remTd, color: 'var(--ow-fg-2)', fontVariantNumeric: 'tabular-nums' }}
                >
                  {lift ?? <span style={{ color: 'var(--ow-fg-3)' }}>—</span>}
                </td>
                <td style={remTd}>
                  <RemediationRowAction
                    request={r}
                    hostId={hostId}
                    canApprove={canApprove}
                    canExecute={canExecute}
                    canRollback={canRollback}
                  />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    );
  }

  return (
    <section
      role="tabpanel"
      aria-label="Remediation"
      style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 16 }}
    >
      <RemediationExplainer />
      <section
        aria-label="Remediation requests"
        style={{
          background: 'var(--ow-bg-1)',
          border: '1px solid var(--ow-line)',
          borderRadius: 'var(--ow-radius)',
          padding: 18,
        }}
      >
        <h3 style={{ margin: '0 0 12px', fontSize: 14, fontWeight: 600 }}>Remediation requests</h3>
        {body}
      </section>
      <RemediationUpsell />
    </section>
  );
}

// RemediationExplainer states the atomic transaction model as static
// copy (the model the OpenWatch+ apply step follows): Capture, Apply,
// Validate, Commit, with a rollback to the captured state on failure.
function RemediationExplainer() {
  const phases = ['Capture', 'Apply', 'Validate', 'Commit'];
  return (
    <div
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: '14px 18px',
      }}
    >
      <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--ow-fg-0)', marginBottom: 8 }}>
        Atomic remediation model
      </div>
      <div
        style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}
      >
        {phases.map((p, i) => (
          <span key={p} style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                padding: '3px 10px',
                borderRadius: 999,
                border: '1px solid var(--ow-line)',
                background: 'var(--ow-bg-2)',
                color: 'var(--ow-fg-1)',
                fontSize: 12,
                fontWeight: 600,
              }}
            >
              {p}
            </span>
            {i < phases.length - 1 ? (
              <ChevronRight size={14} style={{ color: 'var(--ow-fg-3)' }} aria-hidden />
            ) : null}
          </span>
        ))}
      </div>
      <div style={{ color: 'var(--ow-fg-2)', fontSize: 12, lineHeight: 1.5 }}>
        Each approved fix captures the current host state, applies the change, validates the result,
        then commits. A failed validation rolls back to the captured state, so a host is never left
        half-fixed. Applying a single approved fix on the host (and rolling it back) is part of core.
        Bulk and automated remediation are OpenWatch+ features.
      </div>
    </div>
  );
}

// RemediationRowAction renders the per-row action, which now spans the
// full lifecycle because per-rule MANUAL execute + rollback are FREE
// core (no license):
//   pending_approval : Approve / Reject (remediation:approve), 409 inline
//   approved         : Fix (remediation:execute), POST :execute, 202
//                      queues, 409 if no longer approvable
//   executing        : non-interactive "Applying..." status (no button)
//   executed         : "Fixed" chip + Roll back (remediation:rollback),
//                      POST :rollback, 202, 409 if not executed
//   rolled_back      : "Rolled back" status
//   failed           : "Failed" status (with review_note reason if any)
//   rejected         : terminal, dash
// Each mutation invalidates ['host', hostId, 'remediations'] on success.
function RemediationRowAction({
  request,
  hostId,
  canApprove,
  canExecute,
  canRollback,
}: {
  request: { id: string; status: string; review_note?: string };
  hostId: string;
  canApprove: boolean;
  canExecute: boolean;
  canRollback: boolean;
}) {
  const queryClient = useQueryClient();
  const [note, setNote] = useState<string | null>(null);

  const review = useMutation({
    mutationFn: async (action: 'approve' | 'reject') => {
      const path = `/api/v1/remediation/requests/{rid}:${action}` as
        | '/api/v1/remediation/requests/{rid}:approve'
        | '/api/v1/remediation/requests/{rid}:reject';
      const { error, response } = await api.POST(path, {
        params: { path: { rid: request.id } },
        body: {},
      });
      if (error || !response.ok) {
        if (response.status === 409) {
          // The backend distinguishes the two 409 reasons by code: a
          // separation-of-duties block (you requested it) versus the row
          // having already been actioned by someone else. Surface the real
          // one rather than a single blanket message.
          const code = (error as { error?: { code?: string } } | undefined)?.error?.code;
          if (code === 'remediation.self_review') {
            throw new Error(
              'You cannot approve or reject your own request. A different reviewer must action it.',
            );
          }
          throw new Error(apiErrorMessage(error, 'This request already changed state.'));
        }
        throw new Error(apiErrorMessage(error, `Review failed (${response.status})`));
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['host', hostId, 'remediations'] });
    },
    onError: (e: Error) => {
      setNote(e.message);
      window.setTimeout(() => setNote(null), 5000);
    },
  });

  // act drives the host-mutating verbs. :execute applies an approved fix
  // (202 queued, then the row moves to 'executing' on refetch); :rollback
  // reverts an executed fix. A 409 means the row left the required state
  // (approved for execute, executed for rollback) since it was rendered.
  const act = useMutation({
    mutationFn: async (verb: 'execute' | 'rollback') => {
      const path = `/api/v1/remediation/requests/{rid}:${verb}` as
        | '/api/v1/remediation/requests/{rid}:execute'
        | '/api/v1/remediation/requests/{rid}:rollback';
      // These verbs take no request body (rid is a path param). 202
      // Accepted is the success path (the fix is queued), which response.ok
      // covers.
      const { error, response } = await api.POST(path, {
        params: { path: { rid: request.id } },
      });
      if (error || !response.ok) {
        if (response.status === 409) {
          throw new Error(
            apiErrorMessage(error, 'This request is not in an approvable state.'),
          );
        }
        throw new Error(apiErrorMessage(error, `Action failed (${response.status})`));
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['host', hostId, 'remediations'] });
    },
    onError: (e: Error) => {
      setNote(e.message);
      window.setTimeout(() => setNote(null), 5000);
    },
  });

  const inlineNote = note ? (
    <span role="alert" style={{ fontSize: 11, color: 'var(--ow-crit)' }}>
      {note}
    </span>
  ) : null;

  if (request.status === 'pending_approval') {
    if (!canApprove) {
      return <span style={{ color: 'var(--ow-fg-3)', fontSize: 11 }}>Awaiting approval</span>;
    }
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <button
          type="button"
          disabled={review.isPending}
          onClick={() => review.mutate('approve')}
          style={{
            height: 26,
            padding: '0 12px',
            background: 'var(--ow-info)',
            color: 'var(--ow-info-on)',
            border: 0,
            borderRadius: 7,
            fontSize: 11,
            fontWeight: 600,
            cursor: review.isPending ? 'default' : 'pointer',
            opacity: review.isPending ? 0.6 : 1,
          }}
        >
          Approve
        </button>
        <button
          type="button"
          disabled={review.isPending}
          onClick={() => review.mutate('reject')}
          style={{
            height: 26,
            padding: '0 12px',
            background: 'var(--ow-bg-2)',
            color: 'var(--ow-fg-1)',
            border: '1px solid var(--ow-line)',
            borderRadius: 7,
            fontSize: 11,
            fontWeight: 600,
            cursor: review.isPending ? 'default' : 'pointer',
            opacity: review.isPending ? 0.6 : 1,
          }}
        >
          Reject
        </button>
        {inlineNote}
      </span>
    );
  }

  if (request.status === 'approved') {
    if (!canExecute) {
      return <span style={{ color: 'var(--ow-fg-3)', fontSize: 11 }}>Approved</span>;
    }
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <button
          type="button"
          disabled={act.isPending}
          onClick={() => act.mutate('execute')}
          style={{
            height: 26,
            padding: '0 14px',
            background: 'var(--ow-ok)',
            color: 'var(--ow-ok-on)',
            border: 0,
            borderRadius: 7,
            fontSize: 11,
            fontWeight: 600,
            cursor: act.isPending ? 'default' : 'pointer',
            opacity: act.isPending ? 0.6 : 1,
          }}
        >
          Fix
        </button>
        {inlineNote}
      </span>
    );
  }

  if (request.status === 'executing') {
    return (
      <span
        role="status"
        style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--ow-warn)' }}
      >
        <span
          aria-hidden
          style={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            background: 'var(--ow-warn)',
            animation: 'ow-pulse 1.4s ease-in-out infinite',
          }}
        />
        Applying...
      </span>
    );
  }

  if (request.status === 'executed') {
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, fontWeight: 600, color: 'var(--ow-ok)' }}>
          <span aria-hidden style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--ow-ok)' }} />
          Fixed
        </span>
        {canRollback && (
          <button
            type="button"
            disabled={act.isPending}
            onClick={() => act.mutate('rollback')}
            style={{
              height: 26,
              padding: '0 12px',
              background: 'var(--ow-bg-2)',
              color: 'var(--ow-fg-1)',
              border: '1px solid var(--ow-line)',
              borderRadius: 7,
              fontSize: 11,
              fontWeight: 600,
              cursor: act.isPending ? 'default' : 'pointer',
              opacity: act.isPending ? 0.6 : 1,
            }}
          >
            Roll back
          </button>
        )}
        {inlineNote}
      </span>
    );
  }

  if (request.status === 'rolled_back') {
    return <span style={{ color: 'var(--ow-fg-2)', fontSize: 11 }}>Rolled back</span>;
  }

  if (request.status === 'failed') {
    return (
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--ow-crit)' }}>
        Failed
        {request.review_note ? (
          <span style={{ color: 'var(--ow-fg-3)' }}>({request.review_note})</span>
        ) : null}
      </span>
    );
  }

  // rejected and any other terminal state.
  return <span style={{ color: 'var(--ow-fg-3)', fontSize: 11 }}>—</span>;
}

// RemediationUpsell renders the ACTUAL OpenWatch+ boundary as a DISABLED
// upsell. Single-rule manual execute and rollback moved into free core,
// so the paywall is now bulk and automated remediation: applying many
// rules at once (fleet-wide) and scheduled auto-remediation. This control
// is intentionally NOT wired to any endpoint.
// TODO: when a frontend license/entitlement hook lands, surface the live
// bulk + auto-remediation controls instead of this upsell when licensed.
function RemediationUpsell() {
  return (
    <div
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px dashed var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: 18,
        display: 'flex',
        alignItems: 'center',
        gap: 16,
      }}
    >
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--ow-fg-0)', marginBottom: 4 }}>
          Bulk and automated remediation (OpenWatch+)
        </div>
        <div style={{ color: 'var(--ow-fg-2)', fontSize: 12, lineHeight: 1.5 }}>
          Applying a single approved fix (and rolling it back) is part of core. Applying many rules at
          once across the fleet, and scheduling auto-remediation so approved fixes apply without a
          per-rule click, are OpenWatch+ features.
        </div>
      </div>
      <button
        type="button"
        disabled
        aria-disabled="true"
        title="Bulk and automated remediation is an OpenWatch+ feature"
        style={{
          height: 32,
          padding: '0 16px',
          background: 'var(--ow-bg-2)',
          color: 'var(--ow-fg-3)',
          border: '1px solid var(--ow-line)',
          borderRadius: 7,
          fontSize: 12,
          fontWeight: 600,
          cursor: 'not-allowed',
          flexShrink: 0,
        }}
      >
        Bulk remediation (OpenWatch+)
      </button>
    </div>
  );
}

function RemTh({ children, width }: { children: ReactNode; width?: number }) {
  return (
    <th
      style={{
        width,
        textAlign: 'left',
        padding: '6px 10px 8px 0',
        color: 'var(--ow-fg-3)',
        fontSize: 11,
        fontWeight: 600,
        textTransform: 'uppercase',
        letterSpacing: '0.04em',
      }}
    >
      {children}
    </th>
  );
}

const remTd: CSSProperties = {
  padding: '9px 10px 9px 0',
  verticalAlign: 'top',
};

// ─────────────────────────────────────────────────────────────────────────
// Hero stat strip — band 5
// ─────────────────────────────────────────────────────────────────────────

function HeroCompliance({
  summary,
  lastScan,
}: {
  summary: ComplianceSummary;
  lastScan: string | null;
}) {
  // AC-04 / AC-05: keep the canonical math expression + label strings.
  // AC-35: subhead is "LAST SCAN <date>", NOT a Framework selector
  // (the Framework filter belongs on the Compliance tab when it ships).
  const isEmpty = summary.total === 0;
  const pct = isEmpty ? 0 : Math.round((summary.passing / summary.total) * 100);
  return (
    <article style={heroCard} aria-labelledby="hero-compliance-title">
      <header style={heroHead}>
        <span id="hero-compliance-title">Compliance</span>
        <span
          style={{
            fontSize: 11,
            color: 'var(--ow-fg-3)',
            textTransform: 'uppercase',
            letterSpacing: '0.04em',
          }}
        >
          LAST SCAN {lastScan ?? '—'}
        </span>
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

// HeroAutoScan is LIVE against GET /hosts/{id}/compliance/schedule
// (api-system-scan-config AC-10). The ['host', hostId] query-key
// prefix rides the scan.completed SSE invalidation, so the Next/
// Interval rows re-anchor right after each scan.
function HeroAutoScan({ hostId }: { hostId: string }) {
  const schedQuery = useQuery({
    queryKey: ['host', hostId, 'compliance_schedule'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/hosts/{id}/compliance/schedule', {
        params: { path: { id: hostId } },
      });
      if (error || !response.ok) {
        throw new Error(apiErrorMessage(error, `Failed to load (${response.status})`));
      }
      return data!;
    },
    enabled: !!hostId,
    refetchInterval: 60_000,
  });

  const sched = schedQuery.data;
  const status: { label: string; color: string } = !sched
    ? { label: schedQuery.isError ? 'Unavailable' : 'Loading', color: 'var(--ow-fg-3)' }
    : sched.scheduler_paused
      ? { label: 'Paused', color: 'var(--ow-warn)' }
      : sched.host_maintenance
        ? { label: 'Host paused', color: 'var(--ow-warn)' }
        : { label: 'On', color: 'var(--ow-ok)' };

  const nextLabel =
    sched?.next_scan_at && !sched.scheduler_paused && !sched.host_maintenance
      ? formatNextScan(sched.next_scan_at)
      : null;
  const intervalLabel =
    sched && sched.interval_minutes > 0 ? formatIntervalMins(sched.interval_minutes) : null;
  const stateLabel = sched ? sched.compliance_state.replace(/_/g, ' ') : null;

  return (
    <article style={heroCard} aria-labelledby="hero-autoscan-title">
      <header style={heroHead}>
        <span id="hero-autoscan-title">Auto-scan</span>
        <Clock size={14} aria-hidden />
      </header>
      <BandLine label={status.label} color={status.color} />
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12 }}>
        <KvRow
          k={'Next'}
          v={
            nextLabel ? (
              <span style={{ fontVariantNumeric: 'tabular-nums' }}>{nextLabel}</span>
            ) : (
              <span style={{ color: 'var(--ow-fg-3)' }}>—</span>
            )
          }
        />
        <KvRow
          k={'Interval'}
          v={
            intervalLabel ? (
              <span style={{ fontVariantNumeric: 'tabular-nums' }}>{intervalLabel}</span>
            ) : (
              <span style={{ color: 'var(--ow-fg-3)' }}>—</span>
            )
          }
        />
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
        {sched?.scheduler_paused
          ? 'Scheduler paused in Settings. On-demand scans stay available.'
          : sched?.host_maintenance
            ? 'This host is paused for maintenance. On-demand scans stay available.'
            : stateLabel
              ? `Cadence follows the compliance state (${stateLabel}).`
              : 'Cadence follows the adaptive compliance scheduler.'}
      </div>
    </article>
  );
}

// formatNextScan renders the next scheduled scan as a relative time
// ("in 4h", "in 25 min", "due now").
function formatNextScan(iso: string): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '—';
  const seconds = Math.round((t - Date.now()) / 1000);
  if (seconds <= 0) return 'due now';
  if (seconds < 3600) return `in ${Math.max(1, Math.round(seconds / 60))} min`;
  if (seconds < 86400) return `in ${Math.round(seconds / 3600)}h`;
  return `in ${Math.round(seconds / 86400)}d`;
}

// formatIntervalMins humanizes the per-state interval.
function formatIntervalMins(mins: number): string {
  if (mins < 60) return `Every ${mins} min`;
  const h = mins / 60;
  if (Number.isInteger(h) && h < 24) return `Every ${h}h`;
  if (Number.isInteger(h / 24)) return `Every ${h / 24}d`;
  return `Every ${mins} min`;
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
  const queryClient = useQueryClient();
  const canReadCred = useAuthStore((s) => s.hasPermission('credential:read'));
  const canWriteHost = useAuthStore((s) => s.hasPermission('host:write'));
  const [credOpen, setCredOpen] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const band: MonitoringBand =
    host.maintenance_mode === true ? 'maintenance' : (liveness?.monitoring_state ?? 'unknown');
  const { label: BAND_HEADLINE, color } = bandLabel(band);
  const lastSeen = liveness?.last_probe_at ? relativeMinutes(liveness.last_probe_at) : '—';

  // Resolve the host's effective credential for the Auth row (shared
  // query key with HostCredentialModal, so edits refresh this label).
  const credResolve = useQuery({
    queryKey: ['host-credential-resolve', host.id],
    enabled: canReadCred,
    queryFn: async () => {
      const { data, response } = await api.POST('/api/v1/hosts/{host_id}/credentials:resolve', {
        params: { path: { host_id: host.id } },
      });
      if (!response.ok) return null; // 404 none_available or any error
      return data as { scope: 'system' | 'host'; name: string };
    },
  });

  const authValue: ReactNode = (() => {
    if (!canReadCred) return host.username ? 'configured' : '—';
    if (credResolve.isLoading) return '…';
    const r = credResolve.data;
    if (!r) return 'none';
    return (
      <span title={r.name}>
        {r.name}{' '}
        <span style={{ color: 'var(--ow-fg-3)' }}>({r.scope === 'host' ? 'host' : 'default'})</span>
      </span>
    );
  })();

  // Reconnect = synchronous OS discovery (POST /discovery:run). It opens
  // one SSH session with the resolved credential and refreshes OS facts,
  // bypassing the scan queue entirely. A 502 means the credential or SSH
  // dial failed — exactly the signal an operator wants after editing it.
  const reconnect = useMutation({
    mutationFn: async () => {
      const { response } = await api.POST('/api/v1/hosts/{id}/discovery:run', {
        params: {
          path: { id: host.id },
          header: { 'Idempotency-Key': crypto.randomUUID() },
        },
      });
      if (response.status === 502) throw new Error('Host unreachable (SSH or credential failed)');
      if (!response.ok) throw new Error(`Reconnect failed (${response.status})`);
    },
    onSuccess: () => {
      setNote('Reconnected. OS facts refreshed.');
      queryClient.invalidateQueries({ queryKey: ['host', host.id] });
      queryClient.invalidateQueries({ queryKey: ['hosts'] });
      window.setTimeout(() => setNote(null), 5000);
    },
    onError: (e: Error) => {
      setNote(e.message);
      window.setTimeout(() => setNote(null), 6000);
    },
  });

  return (
    <article style={heroCard} aria-labelledby="hero-conn-title">
      <header style={heroHead}>
        <span id="hero-conn-title">Connectivity</span>
        <Wifi size={14} aria-hidden />
      </header>
      <BandLine label={BAND_HEADLINE} color={color} />
      {liveness === null ? (
        <div style={{ color: 'var(--ow-fg-2)', fontSize: 12 }}>Not yet probed</div>
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
          <KvRow k="Auth" v={authValue} />
          <KvRow k="Last seen" v={lastSeen} />
        </div>
      )}
      {note && (
        <div role="status" style={{ marginTop: 6, fontSize: 11, color: 'var(--ow-fg-2)' }}>
          {note}
        </div>
      )}
      <div
        style={{
          display: 'flex',
          gap: 10,
          marginTop: 6,
          paddingTop: 8,
          borderTop: '1px solid var(--ow-line)',
        }}
      >
        <button
          type="button"
          style={smallTextBtn}
          onClick={() => reconnect.mutate()}
          disabled={!canWriteHost || reconnect.isPending}
          title="Run OS discovery now: validates the SSH credential and refreshes facts, bypassing the scan queue"
        >
          {reconnect.isPending ? 'Reconnecting…' : 'Reconnect'}
        </button>
        <button
          type="button"
          style={smallTextBtn}
          onClick={() => setCredOpen(true)}
          disabled={!canReadCred}
          title="View or change this host's SSH credential"
        >
          Edit credentials
        </button>
      </div>
      <HostCredentialModal
        open={credOpen}
        onClose={() => setCredOpen(false)}
        host={{ id: host.id, hostname: host.hostname }}
      />
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

// severityRank orders alert severities so the subtext can name the
// worst one firing.
const SEVERITY_RANK: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

// HeroWatchlist: the Active alerts row is LIVE against
// GET /alerts?state=active&host_id= (api-alerts). The Exceptions row
// stays an honest pending state: operator rule waivers are the
// exception-governance work (scan plan, remediation track) and have
// no backend yet. AC-30.
function HeroWatchlist({ hostId }: { hostId: string }) {
  const alertsQuery = useQuery({
    queryKey: ['host', hostId, 'active_alerts'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/alerts', {
        params: { query: { state: 'active', host_id: hostId, limit: 100 } },
      });
      if (error || !response.ok) {
        throw new Error(apiErrorMessage(error, `Failed to load (${response.status})`));
      }
      return data!;
    },
    enabled: !!hostId,
    refetchInterval: 60_000,
  });

  const items = alertsQuery.data?.items ?? [];
  const count = items.length;
  const worst = items.reduce<string | null>(
    (acc, a) =>
      (SEVERITY_RANK[a.severity] ?? 0) > (acc ? (SEVERITY_RANK[acc] ?? 0) : 0) ? a.severity : acc,
    null,
  );
  const alertsSubtext = alertsQuery.isError
    ? 'Failed to load alerts'
    : alertsQuery.isPending
      ? 'Loading'
      : count === 0
        ? 'No alerts firing'
        : `Worst severity: ${worst}`;

  const exc = useHostExceptions(hostId);
  const excSubtext = exc.isError
    ? 'Failed to load exceptions'
    : exc.isPending
      ? 'Loading'
      : exc.activeCount === 0
        ? 'No suppressed rules'
        : `${exc.activeCount} rule${exc.activeCount === 1 ? '' : 's'} waived`;

  return (
    <article style={heroCard} aria-labelledby="hero-watch-title">
      <header style={heroHead}>
        <span id="hero-watch-title">Watchlist</span>
        <Bell size={14} aria-hidden />
      </header>
      <WatchlistRow label={'Active alerts'} value={count} subtext={alertsSubtext} />
      <WatchlistRow label={'Exceptions'} value={exc.activeCount} subtext={excSubtext} />
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
        {exc.pendingCount > 0
          ? `${exc.pendingCount} exception ${exc.pendingCount === 1 ? 'request awaits' : 'requests await'} review.`
          : 'Exceptions are operator-approved rule waivers (accepted risk).'}
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

// CardTopFailed renders the five worst failing rules from
// GET /hosts/{id}/compliance/failed-rules (severity-ordered server
// side). The query key is prefixed ['host', hostId] ON PURPOSE: the
// scan.completed SSE handler invalidates that prefix, so this card
// refreshes after every scan with no extra wiring. Evidence is never
// requested or displayed (api-host-compliance C-02).
//
// Spec: frontend-host-detail v1.2.0 AC-37.
function CardTopFailed({
  hostId,
  framework,
  hasScanData,
  onViewAll,
}: {
  hostId: string;
  framework?: string;
  hasScanData: boolean;
  onViewAll: () => void;
}) {
  const failedQuery = useQuery({
    queryKey: ['host', hostId, 'failed_rules', framework ?? null],
    queryFn: async () => {
      const { data, error, response } = await api.GET(
        '/api/v1/hosts/{id}/compliance/failed-rules',
        {
          params: {
            path: { id: hostId },
            query: { limit: 5, ...(framework ? { framework } : {}) },
          },
        },
      );
      if (error || !response.ok) {
        throw new Error(apiErrorMessage(error, `Failed to load (${response.status})`));
      }
      return data;
    },
  });

  let body: React.ReactNode;
  // isPending (not isLoading): isLoading goes false between retry
  // attempts, which would fall through to the zero-failing branch with
  // no data and render a false "No failing rules".
  if (failedQuery.isPending) {
    body = (
      <div role="status" style={{ color: 'var(--ow-fg-3)', fontSize: 12, padding: '12px 0' }}>
        Loading failed rules
      </div>
    );
  } else if (failedQuery.isError) {
    body = (
      <div
        role="alert"
        style={{
          color: 'var(--ow-crit)',
          fontSize: 12,
          padding: '12px 0',
          display: 'flex',
          gap: 10,
          alignItems: 'center',
        }}
      >
        <span>{apiErrorMessage(failedQuery.error, 'Failed to load failed rules')}</span>
        <button
          type="button"
          onClick={() => failedQuery.refetch()}
          style={{
            background: 'none',
            border: '1px solid var(--ow-line)',
            borderRadius: 6,
            color: 'var(--ow-fg-1)',
            fontSize: 11,
            padding: '2px 8px',
            cursor: 'pointer',
          }}
        >
          Retry
        </button>
      </div>
    );
  } else if (!hasScanData) {
    body = (
      <EmptyState
        primary="No scan results yet"
        secondary="Populated by the compliance scanner (Kensa). Until a scan completes, host_rule_state is empty for this host."
      />
    );
  } else if ((failedQuery.data?.total_failing ?? 0) === 0) {
    body = (
      <EmptyState
        primary="No failing rules"
        secondary="The last scan passed every rule that applies to this host."
      />
    );
  } else {
    const rules = failedQuery.data?.rules ?? [];
    const total = failedQuery.data?.total_failing ?? rules.length;
    body = (
      <>
        <div role="list" aria-label="Top failed rules">
          {rules.map((rule) => (
            <div
              key={rule.rule_id}
              role="listitem"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '8px 0',
                borderTop: '1px solid var(--ow-line)',
              }}
            >
              <SeverityPill severity={rule.severity} />
              <div style={{ minWidth: 0, flex: 1 }}>
                <div
                  style={{
                    color: 'var(--ow-fg-0)',
                    fontSize: 13,
                    fontWeight: 500,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {rule.title}
                </div>
                <div style={{ color: 'var(--ow-fg-3)', fontSize: 11 }}>
                  <span style={{ fontFamily: 'var(--ow-font-mono)' }}>
                    {rule.control_ids.length > 0 ? rule.control_ids.join(', ') : rule.rule_id}
                  </span>
                  {rule.category ? <span> · {rule.category}</span> : null}
                </div>
              </div>
            </div>
          ))}
        </div>
        <button
          type="button"
          onClick={onViewAll}
          style={{
            marginTop: 10,
            width: '100%',
            background: 'none',
            border: 'none',
            color: 'var(--ow-info)',
            fontSize: 12,
            cursor: 'pointer',
            textAlign: 'left',
            padding: 0,
          }}
        >
          View all {total} failed rules
        </button>
      </>
    );
  }

  return <Card title="Top failed rules">{body}</Card>;
}

// SeverityPill now lives in @/pages/host-detail/SeverityPill so the
// Compliance tab can share it (frontend-host-compliance-tab).

// CardComplianceTrend renders the 30-day score line from the daily
// posture snapshot rollup (api-compliance-trend). The query key carries
// the ['host', hostId] prefix so scan.completed SSE invalidation
// refreshes it with the rest of the page.
function CardComplianceTrend({ hostId }: { hostId: string }) {
  const trendQuery = useQuery({
    queryKey: ['host', hostId, 'compliance_trend'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/hosts/{id}/compliance/trend', {
        params: { path: { id: hostId }, query: { days: 30 } },
      });
      if (error || !response.ok) {
        throw new Error(apiErrorMessage(error, `Failed to load (${response.status})`));
      }
      return data!;
    },
    enabled: !!hostId,
  });

  const days = trendQuery.data?.days ?? [];
  let body: ReactNode;
  if (trendQuery.isPending) {
    body = <div style={{ color: 'var(--ow-fg-2)', fontSize: 12 }}>Loading…</div>;
  } else if (trendQuery.isError) {
    body = (
      <div style={{ color: 'var(--ow-crit)', fontSize: 12, display: 'flex', gap: 8 }}>
        Failed to load trend{' '}
        <button type="button" onClick={() => trendQuery.refetch()} style={smallTextBtn}>
          <RefreshCw size={11} /> Retry
        </button>
      </div>
    );
  } else if (days.length === 0) {
    body = (
      <EmptyState
        primary="No snapshots yet"
        secondary="Daily posture snapshots build this trend. The first point appears after the next hourly rollup of scan results."
      />
    );
  } else {
    const latest = days[days.length - 1]!;
    const first = days[0]!;
    const diff = Math.round((latest.score_pct - first.score_pct) * 10) / 10;
    body = (
      <>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
          <span
            style={{
              fontSize: 22,
              fontWeight: 700,
              fontVariantNumeric: 'tabular-nums',
              color: 'var(--ow-fg-0)',
            }}
          >
            {latest.score_pct}%
          </span>
          {days.length > 1 && (
            <span
              style={{
                fontSize: 11,
                fontWeight: 600,
                color: diff > 0 ? 'var(--ow-ok)' : diff < 0 ? 'var(--ow-crit)' : 'var(--ow-fg-3)',
              }}
            >
              {diff > 0 ? '+' : ''}
              {diff}% over {days.length} days
            </span>
          )}
        </div>
        <TrendSparkline days={days} />
      </>
    );
  }

  return <Card title="Compliance trend · last 30 days">{body}</Card>;
}

// TrendSparkline draws the score line (0..100 domain) over the
// snapshot points. Pure SVG, no chart dependency: the card needs one
// readable line, not an axis system.
function TrendSparkline({ days }: { days: { date: string; score_pct: number }[] }) {
  const W = 280;
  const H = 64;
  const PAD = 4;
  const n = days.length;
  const x = (i: number) => (n === 1 ? W / 2 : PAD + (i * (W - 2 * PAD)) / (n - 1));
  const y = (score: number) => PAD + (1 - score / 100) * (H - 2 * PAD);
  const points = days.map((d, i) => `${x(i)},${y(d.score_pct)}`).join(' ');
  return (
    <div style={{ marginTop: 10 }}>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        style={{ width: '100%', height: 64, display: 'block' }}
        role="img"
        aria-label="Compliance score trend"
      >
        {/* Target line at 80%. */}
        <line
          x1={PAD}
          x2={W - PAD}
          y1={y(80)}
          y2={y(80)}
          stroke="var(--ow-line)"
          strokeDasharray="3 3"
        />
        {n > 1 && <polyline points={points} fill="none" stroke="var(--ow-info)" strokeWidth={2} />}
        {days.map((d, i) => (
          <circle
            key={d.date}
            cx={x(i)}
            cy={y(d.score_pct)}
            r={n === 1 ? 3 : 2}
            fill="var(--ow-info)"
          />
        ))}
      </svg>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          fontSize: 10,
          color: 'var(--ow-fg-3)',
          marginTop: 2,
        }}
      >
        <span>{days[0]!.date}</span>
        <span>{days[days.length - 1]!.date}</span>
      </div>
    </div>
  );
}

// RECENT_LIMIT caps the overview card at the most-recent N rows.
// The mockup shows exactly 5; deeper history is reached via the
// "View all" link that routes to the activity tab.
const RECENT_LIMIT = 5;

function CardRecentActivity({
  hostId,
  isLoading,
  isError,
  items,
  onRetry,
}: {
  hostId: string;
  isLoading: boolean;
  isError: boolean;
  items: ActivityItem[];
  onRetry: () => void;
}) {
  const visible = useMemo(() => items.slice(0, RECENT_LIMIT), [items]);
  return (
    <Card
      title="Recent activity"
      headerRight={
        <Link
          to="/hosts/$hostId"
          params={{ hostId }}
          search={{ tab: 'activity' }}
          style={{
            color: 'var(--ow-link)',
            fontSize: 12,
            textDecoration: 'none',
            display: 'inline-flex',
            alignItems: 'center',
            gap: 2,
          }}
        >
          View all <ChevronRight size={12} />
        </Link>
      }
    >
      {isLoading ? (
        <div style={{ color: 'var(--ow-fg-2)', fontSize: 12 }}>Loading…</div>
      ) : isError ? (
        <div
          style={{
            color: 'var(--ow-crit)',
            fontSize: 12,
            display: 'flex',
            gap: 8,
            alignItems: 'center',
          }}
        >
          Failed to load activity{' '}
          <button type="button" onClick={onRetry} style={smallTextBtn}>
            <RefreshCw size={11} /> Retry
          </button>
        </div>
      ) : visible.length === 0 ? (
        <EmptyState
          primary="No activity yet"
          secondary="Sourced from the unified activity feed (band transitions, scan changes, intelligence diffs, alerts). The list will populate as the host accrues events."
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
          {visible.map((it) => (
            <ActivityRow key={`${it.source}-${it.id}`} item={it} />
          ))}
        </ol>
      )}
    </Card>
  );
}

function ActivityRow({ item }: { item: ActivityItem }) {
  const { Icon, color } = activityIconFor(item);
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
      <Icon size={14} color={color} style={{ marginTop: 2, flexShrink: 0 }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ color: 'var(--ow-fg-0)', fontSize: 13 }}>{item.title}</div>
        {item.summary ? (
          <div
            style={{
              color: 'var(--ow-fg-3)',
              fontSize: 11,
              marginTop: 2,
              overflowWrap: 'anywhere',
            }}
          >
            {item.summary}
          </div>
        ) : null}
      </div>
      <div style={{ color: 'var(--ow-fg-3)', fontSize: 11, whiteSpace: 'nowrap' }}>
        {relativeTime(item.occurred_at)}
      </div>
    </li>
  );
}

// activitySeverityColors maps the closed severity enum onto the
// existing OW color tokens.
function activitySeverityColors(s: ActivitySeverity): { fg: string; dot: string } {
  switch (s) {
    case 'critical':
      return { fg: 'var(--ow-crit)', dot: 'var(--ow-crit)' };
    case 'high':
      return { fg: 'var(--ow-crit)', dot: 'var(--ow-crit)' };
    case 'medium':
      return { fg: 'var(--ow-warn)', dot: 'var(--ow-warn)' };
    case 'low':
      return { fg: 'var(--ow-fg-2)', dot: 'var(--ow-fg-2)' };
    case 'info':
    default:
      return { fg: 'var(--ow-ok)', dot: 'var(--ow-ok)' };
  }
}

// activityIconFor picks the lucide glyph per source. Color follows
// severity — a downed host renders red WifiOff, an online recovery
// renders green Wifi. Sources without strong glyph semantics (alert,
// audit, intel) fall back to a representative icon per source.
function activityIconFor(item: ActivityItem): { Icon: LucideIcon; color: string } {
  const c = activitySeverityColors(item.severity);
  switch (item.source) {
    case 'monitoring':
      if (item.severity === 'critical' || item.severity === 'high') {
        return { Icon: WifiOff, color: c.fg };
      }
      if (item.severity === 'medium') {
        return { Icon: AlertTriangle, color: c.fg };
      }
      return { Icon: Wifi, color: c.fg };
    case 'transaction':
      if (item.severity === 'info' || item.severity === 'low') {
        return { Icon: CheckCircle2, color: c.fg };
      }
      return { Icon: RefreshCw, color: c.fg };
    case 'audit':
      return { Icon: FileText, color: c.fg };
    case 'intelligence':
      return { Icon: Package, color: c.fg };
    case 'alert':
      return { Icon: Bell, color: c.fg };
    default:
      return { Icon: ActivityIcon, color: c.fg };
  }
}


// ─────────────────────────────────────────────────────────────────────────
// Reusable bits (cards, kv rows, empty states, etc.)
// ─────────────────────────────────────────────────────────────────────────

function Card({
  title,
  headerRight,
  children,
}: {
  title: string;
  headerRight?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: 18,
      }}
    >
      <header
        style={{
          marginBottom: 12,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: 12,
        }}
      >
        <h3 style={{ margin: 0, fontSize: 14, fontWeight: 600 }}>{title}</h3>
        {headerRight ? <div>{headerRight}</div> : null}
      </header>
      <div>{children}</div>
    </section>
  );
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

function KvRow({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10 }}>
      <span style={{ color: 'var(--ow-fg-3)' }}>{k}</span>
      <span
        style={{
          color: 'var(--ow-fg-1)',
          minWidth: 0,
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {v}
      </span>
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
