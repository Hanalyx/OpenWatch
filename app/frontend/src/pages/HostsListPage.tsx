import { useQuery } from '@tanstack/react-query';
import { Link, useSearch, useNavigate } from '@tanstack/react-router';
import { useEffect, useMemo } from 'react';
import {
  Plus,
  RefreshCw,
  ServerOff,
  Search,
  Filter as FilterIcon,
  LayoutGrid,
  List as TableIcon,
  PlayCircle,
  BarChart3,
  MoreVertical,
  Server,
  Shield,
  AlertTriangle,
  Activity as ActivityIcon,
} from 'lucide-react';
import api from '@/api/client';
import { useAuthStore } from '@/store/useAuthStore';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import { osDisplayLabel } from '@/utils/osLabel';
import {
  devHosts,
  devKpis,
  devFleetAlert,
  isDevFixturesEnabled,
  type DevHost,
  type MonitoringBand,
} from '@/api/dev-fixtures';

// HostsListPage — Host Management surface, prototype-faithful.
//
// Layout matches app/docs/prototypes/openwatch-v1/Host Management.html
// pixel-for-pixel:
//
//   • Breadcrumb "Infrastructure / Hosts" (set into TopBar via Zustand)
//   • Page header — title + dynamic subtitle + Run scan / Add host
//   • 4 KPI cards (icon, label, value with unit, tier-colored bar, delta meta)
//   • Fleet alert banner (red) when fleet is in critical state
//   • Filter bar — search (⌘K hint), Group seg, Filters btn w/ count,
//     view toggle (Table / Cards)
//   • Cards view by default; Table view alternate
//
// Dev fixtures: when running under Vite dev AND the
// __ow_dev_fixtures localStorage flag is set, the prototype's host
// fixture and KPI numbers are rendered in place of empty backend data
// so the page layout can be verified end-to-end without a backend.
//
// Spec: frontend-hosts-list.

interface HostsListSearch {
  env?: string;
  tag?: string;
  q?: string;
  view?: 'table' | 'cards';
  group?: 'none' | 'team' | 'status' | 'os';
}

interface ApiHostLiveness {
  reachability_status: 'reachable' | 'unreachable' | 'unknown';
  monitoring_state?: MonitoringBand;
  last_probe_at?: string | null;
  consecutive_failures?: number;
  ssh_consecutive_failures?: number;
  privilege_consecutive_failures?: number;
}

export interface ApiHost {
  id: string;
  hostname: string;
  ip_address: string;
  port?: number;
  display_name?: string;
  environment?: string;
  tags?: string[];
  username?: string;
  created_at: string;
  updated_at: string;
  maintenance_mode?: boolean;
  check_priority?: number;
  /** v1.5.0 — MAX(host_rule_state.last_checked_at); null when never scanned. */
  last_scan_at?: string | null;
  liveness?: ApiHostLiveness | null;
  /**
   * v1.4.0 (api-hosts) — denormalized OS columns populated by
   * system-host-discovery via Kensa. NULL on hosts that have not yet
   * been discovered. Drives the OS column display per
   * frontend-host-list-os v1.0.0.
   */
  os_family?: string | null;
  os_version?: string | null;
  architecture?: string | null;
  platform_identifier?: string | null;
  os_discovered_at?: string | null;
}

// Per-vendor accent for the OS chip. Widened to a string-keyed map so
// that unmapped families (Unknown — pre-Discovery hosts) get the
// neutral var(--ow-fg-dim) fallback rather than crashing the lookup.
// Spec: frontend-host-list-os C-03.
const OS_COLOR: Record<string, string> = {
  Ubuntu: '#e95420',
  RHEL: '#ee0000',
  Debian: '#a80030',
  SUSE: '#30ba78',
};
const OS_COLOR_FALLBACK = 'var(--ow-fg-dim)';

function complianceTier(v: number | null): 'crit' | 'warn' | 'ok' {
  if (v == null || v < 40) return 'crit';
  if (v < 80) return 'warn';
  return 'ok';
}

export function HostsListPage() {
  const search = useSearch({ strict: false }) as HostsListSearch;
  const navigate = useNavigate();
  const canWrite = useAuthStore((s) => s.hasPermission('host:write'));
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);

  useEffect(() => {
    setCrumbs([
      { label: 'Infrastructure' },
      { label: 'Hosts' },
    ]);
    return () => setCrumbs([]);
  }, [setCrumbs]);

  const view: 'table' | 'cards' = search.view === 'table' ? 'table' : 'cards';
  const group = search.group ?? 'none';
  const query = (search.q ?? '').trim().toLowerCase();

  const hostsQuery = useQuery({
    queryKey: ['hosts', search.env, search.tag],
    queryFn: async () => {
      const params: Record<string, string> = {};
      if (search.env) params.environment = search.env;
      if (search.tag) params.tag = search.tag;
      const { data, error } = await api.GET('/api/v1/hosts', {
        params: { query: params },
      });
      if (error) throw error;
      return (data as { hosts: ApiHost[] }).hosts;
    },
    retry: 0,
  });

  // If the backend returns empty AND dev fixtures are enabled, populate
  // with the prototype's HOSTS fixture so the layout is testable.
  const useFixtures = isDevFixturesEnabled() && (hostsQuery.data?.length ?? 0) === 0;
  const hosts: DevHost[] = useFixtures
    ? devHosts
    : (hostsQuery.data ?? []).map(apiHostToDev);

  const visible = useMemo(() => {
    if (!query) return hosts;
    return hosts.filter((h) => {
      const hay = `${h.hostname} ${h.ip_address} ${h.os}`.toLowerCase();
      return hay.includes(query);
    });
  }, [hosts, query]);

  // Sort: down hosts first, then by compliance ascending (matches prototype).
  const sorted = useMemo(() => {
    return [...visible].sort((a, b) => {
      if (a.status !== b.status) return a.status === 'down' ? -1 : 1;
      return (a.compliance ?? -1) - (b.compliance ?? -1);
    });
  }, [visible]);

  const kpis = useFixtures
    ? devKpis
    : kpisFromHosts(hosts);

  const fleetAlert = useFixtures
    ? devFleetAlert
    : fleetAlertFromHosts(hosts);

  const hasFilter = !!(search.env || search.tag || query);

  const updateSearch = (next: Partial<HostsListSearch>) => {
    navigate({
      to: '/hosts',
      search: { ...(search as object), ...next } as HostsListSearch,
    });
  };

  const subtitle = useMemo(() => {
    if (hostsQuery.isLoading && !useFixtures) return 'Loading…';
    const total = hosts.length;
    if (total === 0) return 'No hosts yet.';
    const downCount = hosts.filter((h) => h.status === 'down').length;
    if (downCount > 0) {
      return `${downCount} of ${total} hosts down. ${kpis.criticalIssues.value} critical issues ${kpis.criticalIssues.scope}.`;
    }
    return `${total} host${total === 1 ? '' : 's'} tracked.`;
  }, [hosts, hostsQuery.isLoading, useFixtures, kpis.criticalIssues]);

  return (
    <div style={{ padding: '20px 28px' }}>
      <title>Host Management — OpenWatch</title>

      {/* Page header */}
      <header
        style={{
          display: 'flex',
          alignItems: 'flex-end',
          justifyContent: 'space-between',
          gap: 20,
          marginBottom: 18,
        }}
      >
        <div>
          <h1
            style={{
              margin: 0,
              fontSize: 24,
              fontWeight: 600,
              letterSpacing: '-0.01em',
            }}
          >
            Host Management
          </h1>
          <p
            style={{
              margin: '4px 0 0',
              color: 'var(--ow-fg-2)',
              fontSize: 13,
            }}
          >
            {subtitle}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button type="button" style={btnSecondary} aria-label="Run scan">
            <RefreshCw size={14} /> Run scan
          </button>
          {canWrite && (
            <Link to="/hosts/new" style={btnPrimary} aria-label="Add host">
              <Plus size={14} /> Add host
            </Link>
          )}
        </div>
      </header>

      {/* KPI row */}
      <section
        aria-label="Fleet KPIs"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: 14,
          marginBottom: 14,
        }}
      >
        <KPICard
          icon={<Server size={14} />}
          label="Hosts online"
          value={kpis.hostsOnline.value}
          unit={`/ ${kpis.hostsOnline.total}`}
          tier={
            kpis.hostsOnline.total > 0 && kpis.hostsOnline.value / kpis.hostsOnline.total < 0.3
              ? 'crit'
              : kpis.hostsOnline.value / Math.max(1, kpis.hostsOnline.total) < 0.7
              ? 'warn'
              : 'ok'
          }
          metaLeft={`${kpis.hostsOnline.total - kpis.hostsOnline.value} down`}
          metaRight={kpis.hostsOnline.delta}
          metaRightTier={kpis.hostsOnline.deltaTier}
          barPct={kpis.hostsOnline.total > 0 ? (kpis.hostsOnline.value / kpis.hostsOnline.total) * 100 : 0}
        />
        <KPICard
          icon={<Shield size={14} />}
          label="Avg. compliance"
          value={kpis.avgCompliance.value}
          unit="%"
          tier={complianceTier(kpis.avgCompliance.value)}
          metaLeft={`Target ≥ ${kpis.avgCompliance.target}%`}
          metaRight={kpis.avgCompliance.delta}
          metaRightTier={kpis.avgCompliance.deltaTier}
          barPct={kpis.avgCompliance.value}
        />
        <KPICard
          icon={<AlertTriangle size={14} />}
          label="Critical issues"
          value={kpis.criticalIssues.value}
          unit=""
          tier={
            kpis.criticalIssues.value === 0
              ? 'ok'
              : kpis.criticalIssues.value <= 3
              ? 'warn'
              : 'crit'
          }
          metaLeft={kpis.criticalIssues.scope}
          metaRight={kpis.criticalIssues.delta}
          metaRightTier={kpis.criticalIssues.deltaTier}
          // Bar = severity gauge: each open issue fills 10%; full bar at 10+ issues.
          barPct={Math.min(kpis.criticalIssues.value * 10, 100)}
        />
        <KPICard
          icon={<ActivityIcon size={14} />}
          label="Scan queue"
          value={kpis.scanQueue.value}
          unit=""
          tier={
            kpis.scanQueue.value === 0
              ? 'ok'
              : kpis.scanQueue.value < 10
              ? 'warn'
              : 'crit'
          }
          metaLeft={kpis.scanQueue.scope}
          metaRight={kpis.scanQueue.delta}
          metaRightTier={kpis.scanQueue.deltaTier}
          // Bar = queue depth gauge: empty queue → empty bar (healthy);
          // each pending job fills 5%; full bar at 20+ pending.
          barPct={Math.min(kpis.scanQueue.value * 5, 100)}
        />
      </section>

      {/* Fleet alert banner */}
      {fleetAlert && <FleetAlert alert={fleetAlert} />}

      {/* Filter bar */}
      <div
        style={{
          display: 'flex',
          gap: 8,
          alignItems: 'center',
          marginBottom: 14,
        }}
      >
        <SearchBox
          value={query}
          onChange={(v) => updateSearch({ q: v || undefined })}
        />
        <GroupSeg
          value={group}
          onChange={(v) => updateSearch({ group: v })}
        />
        <button type="button" style={btnSecondary} aria-label="Filters">
          <FilterIcon size={14} />
          Filters
          {hasFilter && (
            <span
              style={{
                marginLeft: 4,
                color: 'var(--ow-info)',
                fontWeight: 600,
              }}
            >
              {[search.env, search.tag].filter(Boolean).length || 2}
            </span>
          )}
        </button>
        <div style={{ flex: 1 }} />
        <ViewToggle value={view} onChange={(v) => updateSearch({ view: v })} />
      </div>

      {hostsQuery.isError && !useFixtures && (
        <ErrorRegion
          message={(hostsQuery.error as Error)?.message ?? 'Failed to load hosts'}
          onRetry={() => hostsQuery.refetch()}
        />
      )}
      {!hostsQuery.isError && sorted.length === 0 && !hostsQuery.isLoading && (
        <EmptyRegion
          canAdd={canWrite}
          hasFilter={hasFilter}
          onClear={() => navigate({ to: '/hosts', search: {} })}
        />
      )}
      {sorted.length > 0 &&
        (view === 'cards' ? (
          <HostsCards hosts={sorted} />
        ) : (
          <HostsTable hosts={sorted} />
        ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// KPI card
// ─────────────────────────────────────────────────────────────────────────

function KPICard({
  icon,
  label,
  value,
  unit,
  tier,
  metaLeft,
  metaRight,
  metaRightTier,
  barPct,
}: {
  icon: React.ReactNode;
  label: string;
  value: number | string;
  unit: string;
  tier: 'crit' | 'warn' | 'ok';
  metaLeft: string;
  metaRight: string;
  metaRightTier: 'crit' | 'warn' | 'ok' | 'neutral';
  barPct: number;
}) {
  const tierColor =
    tier === 'crit'
      ? 'var(--ow-crit)'
      : tier === 'warn'
      ? 'var(--ow-warn)'
      : 'var(--ow-ok)';
  const tierBg =
    tier === 'crit'
      ? 'var(--ow-crit-bg)'
      : tier === 'warn'
      ? 'var(--ow-warn-bg)'
      : null;
  // Prototype .kpi.crit / .kpi.warn — tinted gradient + saturated border.
  const cardBg = tierBg
    ? `linear-gradient(180deg, ${tierBg}, var(--ow-bg-1) 60%)`
    : 'var(--ow-bg-1)';
  const cardBorder = tier === 'crit'
    ? 'color-mix(in oklab, var(--ow-crit) 40%, var(--ow-line))'
    : tier === 'warn'
    ? 'color-mix(in oklab, var(--ow-warn) 35%, var(--ow-line))'
    : tier === 'ok'
    ? 'color-mix(in oklab, var(--ow-ok) 30%, var(--ow-line))'
    : 'var(--ow-line)';
  const metaRightColor =
    metaRightTier === 'crit'
      ? 'var(--ow-crit)'
      : metaRightTier === 'warn'
      ? 'var(--ow-warn)'
      : metaRightTier === 'ok'
      ? 'var(--ow-ok)'
      : 'var(--ow-fg-2)';
  return (
    <div
      style={{
        background: cardBg,
        border: `1px solid ${cardBorder}`,
        borderRadius: 'var(--ow-radius)',
        padding: '14px 16px',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          color: 'var(--ow-fg-2)',
          fontSize: 12,
          fontWeight: 500,
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
        }}
      >
        {icon}
        {label}
      </div>
      <div
        style={{
          marginTop: 10,
          fontSize: 30,
          fontWeight: 600,
          letterSpacing: '-0.02em',
          lineHeight: 1,
          color: tierColor,
          fontVariantNumeric: 'tabular-nums',
        }}
      >
        {value}
        {unit && (
          <span
            style={{
              fontSize: 16,
              color: 'var(--ow-fg-2)',
              fontWeight: 500,
              marginLeft: 2,
            }}
          >
            {unit}
          </span>
        )}
      </div>
      <div
        style={{
          marginTop: 12,
          height: 6,
          background: 'var(--ow-bg-3)',
          borderRadius: 3,
          overflow: 'hidden',
        }}
      >
        <span
          style={{
            display: 'block',
            height: '100%',
            width: `${Math.max(0, Math.min(100, barPct))}%`,
            background: tierColor,
          }}
        />
      </div>
      <div
        style={{
          marginTop: 10,
          display: 'flex',
          justifyContent: 'space-between',
          fontSize: 12,
          color: 'var(--ow-fg-2)',
        }}
      >
        <span>{metaLeft}</span>
        <span style={{ color: metaRightColor }}>{metaRight}</span>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Fleet alert banner
// ─────────────────────────────────────────────────────────────────────────

interface FleetAlertContent {
  title: string;
  body: string;
  downCount: number;
}

function FleetAlert({ alert }: { alert: FleetAlertContent }) {
  return (
    <div
      role="alert"
      style={{
        display: 'grid',
        gridTemplateColumns: 'auto 1fr auto auto',
        gap: 14,
        alignItems: 'center',
        padding: '14px 18px',
        background: 'color-mix(in oklab, var(--ow-crit) 10%, var(--ow-bg-1))',
        border: '1px solid color-mix(in oklab, var(--ow-crit) 30%, var(--ow-line))',
        borderLeft: '3px solid var(--ow-crit)',
        borderRadius: 'var(--ow-radius)',
        marginBottom: 14,
      }}
    >
      <div
        style={{
          width: 30,
          height: 30,
          borderRadius: 8,
          background: 'color-mix(in oklab, var(--ow-crit) 16%, transparent)',
          display: 'grid',
          placeItems: 'center',
          color: 'var(--ow-crit)',
        }}
      >
        <AlertTriangle size={18} />
      </div>
      <div style={{ fontSize: 13, color: 'var(--ow-fg-1)' }}>
        <strong style={{ color: 'var(--ow-fg-0)', display: 'block' }}>{alert.title}</strong>
        {alert.body}
      </div>
      <button type="button" style={btnSecondarySm}>
        View incident
      </button>
      <button
        type="button"
        style={{
          ...btnSecondarySm,
          background: 'var(--ow-crit)',
          borderColor: 'var(--ow-crit)',
          color: 'var(--ow-crit-on)',
          fontWeight: 600,
        }}
      >
        Triage {alert.downCount} hosts
      </button>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Filter bar pieces
// ─────────────────────────────────────────────────────────────────────────

function SearchBox({
  value,
  onChange,
}: {
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        padding: '0 10px',
        height: 34,
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 8,
        flex: 1,
        maxWidth: 380,
      }}
    >
      <Search size={14} color="var(--ow-fg-3)" />
      <input
        type="search"
        placeholder="Search by hostname, IP, or OS…"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-label="Search hosts"
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
      <kbd
        style={{
          padding: '1px 6px',
          background: 'var(--ow-bg-2)',
          border: '1px solid var(--ow-line)',
          borderRadius: 4,
          color: 'var(--ow-fg-3)',
          fontSize: 11,
          fontFamily: 'var(--ow-font-mono)',
        }}
      >
        ⌘K
      </kbd>
    </div>
  );
}

function GroupSeg({
  value,
  onChange,
}: {
  value: NonNullable<HostsListSearch['group']>;
  onChange: (v: NonNullable<HostsListSearch['group']>) => void;
}) {
  const options: { value: typeof value; label: string }[] = [
    { value: 'none', label: 'None' },
    { value: 'team', label: 'Team' },
    { value: 'status', label: 'Status' },
    { value: 'os', label: 'OS' },
  ];
  return (
    <div
      role="radiogroup"
      aria-label="Group hosts by"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        height: 34,
        padding: '0 4px 0 12px',
        gap: 4,
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 8,
      }}
    >
      <span style={{ fontSize: 12, color: 'var(--ow-fg-2)', marginRight: 4 }}>Group</span>
      {options.map((opt) => {
        const isActive = value === opt.value;
        return (
          <button
            key={opt.value}
            type="button"
            role="radio"
            aria-checked={isActive}
            onClick={() => onChange(opt.value)}
            style={{
              height: 26,
              padding: '0 10px',
              border: 0,
              background: isActive ? 'var(--ow-bg-3)' : 'transparent',
              color: isActive ? 'var(--ow-fg-0)' : 'var(--ow-fg-2)',
              fontFamily: 'inherit',
              fontSize: 12,
              fontWeight: 500,
              borderRadius: 5,
              cursor: 'pointer',
            }}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

function ViewToggle({
  value,
  onChange,
}: {
  value: 'table' | 'cards';
  onChange: (v: 'table' | 'cards') => void;
}) {
  return (
    <div
      role="radiogroup"
      aria-label="View"
      style={{
        display: 'inline-flex',
        padding: 3,
        height: 34,
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 8,
      }}
    >
      <button
        type="button"
        role="radio"
        aria-checked={value === 'table'}
        aria-label="Table view"
        title="Table view"
        onClick={() => onChange('table')}
        style={{
          ...segBtn,
          background: value === 'table' ? 'var(--ow-bg-3)' : 'transparent',
          color: value === 'table' ? 'var(--ow-fg-0)' : 'var(--ow-fg-2)',
        }}
      >
        <TableIcon size={14} />
      </button>
      <button
        type="button"
        role="radio"
        aria-checked={value === 'cards'}
        aria-label="Cards view"
        title="Cards view"
        onClick={() => onChange('cards')}
        style={{
          ...segBtn,
          background: value === 'cards' ? 'var(--ow-bg-3)' : 'transparent',
          color: value === 'cards' ? 'var(--ow-fg-0)' : 'var(--ow-fg-2)',
        }}
      >
        <LayoutGrid size={14} />
      </button>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Cards view — matches prototype `.card` block
// ─────────────────────────────────────────────────────────────────────────

function HostsCards({ hosts }: { hosts: DevHost[] }) {
  // Prototype renders ~4 cards per row at 1900px wide; let the grid
  // auto-fit at a minimum that keeps 4 cards on a typical 1440-1900px
  // viewport without crowding card content.
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(380px, 1fr))',
        gap: 14,
      }}
    >
      {hosts.map((host) => (
        <HostCard key={host.id} host={host} />
      ))}
    </div>
  );
}

function HostCard({ host }: { host: DevHost }) {
  const tier = complianceTier(host.compliance);
  const isDown = host.status === 'down';
  const displayName = host.hostname === '—' ? host.ip_address : host.hostname;
  const displaySub = host.hostname === '—' ? 'no hostname' : host.ip_address;
  const tierColor =
    tier === 'crit' ? 'var(--ow-crit)' : tier === 'warn' ? 'var(--ow-warn)' : 'var(--ow-ok)';
  const passPct = host.passed != null ? (host.passed / host.total) * 100 : 0;
  const failPct = host.failed != null ? (host.failed / host.total) * 100 : 0;

  // Prototype `.card.is-down.tinted` — subtle horizontal red wash.
  const cardBg = isDown
    ? 'linear-gradient(90deg, color-mix(in oklab, var(--ow-crit-bg) 70%, transparent), var(--ow-bg-1) 50%)'
    : 'var(--ow-bg-1)';
  return (
    <article
      style={{
        position: 'relative',
        background: cardBg,
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: 16,
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column',
        gap: 14,
      }}
    >
      {/* Card head */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <input
          type="checkbox"
          aria-label={`Select ${displayName}`}
          style={{ marginTop: 4 }}
        />
        <div
          style={{
            position: 'relative',
            width: 36,
            height: 36,
            borderRadius: 8,
            background: 'var(--ow-bg-3)',
            display: 'grid',
            placeItems: 'center',
            color: 'var(--ow-fg-2)',
            flexShrink: 0,
          }}
        >
          <Server size={16} />
          <span
            style={{
              position: 'absolute',
              right: -2,
              bottom: -2,
              width: 10,
              height: 10,
              borderRadius: '50%',
              background: isDown ? 'var(--ow-crit)' : 'var(--ow-ok)',
              border: '2px solid var(--ow-bg-1)',
            }}
          />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 15, fontWeight: 600 }}>
            <Link
              to="/hosts/$hostId"
              params={{ hostId: host.id }}
              style={{
                color: 'var(--ow-fg-0)',
                textDecoration: 'none',
                fontFamily: host.hostname === '—' ? 'var(--ow-font-mono)' : 'inherit',
              }}
            >
              {displayName}
            </Link>
          </div>
          <div
            style={{
              fontSize: 11,
              color: 'var(--ow-fg-3)',
              marginTop: 2,
              display: 'flex',
              alignItems: 'center',
              gap: 8,
            }}
          >
            <span style={{ fontFamily: 'var(--ow-font-mono)' }}>{displaySub}</span>
            <OSChip os={host.os} />
          </div>
        </div>
        <button type="button" style={iconBtnSm} aria-label="More">
          <MoreVertical size={14} />
        </button>
      </div>

      {/* Status row */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 8,
          fontSize: 12,
          color: 'var(--ow-fg-2)',
        }}
      >
        <StatusPill band={host.monitoring} />
        <span style={{ fontSize: 12, color: 'var(--ow-fg-2)' }}>
          {host.lastCheckMinutes === null
            ? 'Never probed'
            : `Checked ${formatMinutesAgo(host.lastCheckMinutes)}`}
        </span>
      </div>

      {/* Compliance metric */}
      <div
        style={{
          padding: '10px 12px',
          background: 'var(--ow-bg-2)',
          border: '1px solid var(--ow-line)',
          borderRadius: 6,
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'baseline',
          }}
        >
          <span
            style={{
              fontSize: 11,
              color: 'var(--ow-fg-2)',
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '0.04em',
            }}
          >
            Compliance
          </span>
          <span
            style={{
              fontSize: 18,
              fontWeight: 600,
              color: host.compliance == null ? 'var(--ow-fg-3)' : tierColor,
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            {host.compliance == null ? '—' : `${host.compliance.toFixed(1)}%`}
          </span>
        </div>
        {host.compliance == null ? (
          <>
            <div
              style={{
                marginTop: 8,
                height: 5,
                background: 'var(--ow-bg-3)',
                borderRadius: 3,
              }}
            />
            <div
              style={{
                marginTop: 8,
                display: 'flex',
                justifyContent: 'space-between',
                fontSize: 11,
                color: 'var(--ow-fg-3)',
              }}
            >
              <span>No scan data</span>
              <span>Scan needed</span>
            </div>
          </>
        ) : (
          <>
            <div
              style={{
                marginTop: 8,
                height: 5,
                background: 'var(--ow-bg-3)',
                borderRadius: 3,
                overflow: 'hidden',
                display: 'flex',
              }}
            >
              <span style={{ height: '100%', width: `${passPct}%`, background: 'var(--ow-ok)' }} />
              <span style={{ height: '100%', width: `${failPct}%`, background: 'var(--ow-crit)' }} />
            </div>
            <div
              style={{
                marginTop: 8,
                display: 'flex',
                justifyContent: 'space-between',
                fontSize: 11,
                color: 'var(--ow-fg-3)',
              }}
            >
              <span style={{ fontFamily: 'var(--ow-font-mono)' }}>
                <span style={{ color: 'var(--ow-ok)' }}>{host.passed}</span>
                <span style={{ color: 'var(--ow-fg-3)' }}> passed · </span>
                <span style={{ color: 'var(--ow-crit)' }}>{host.failed}</span>
                <span style={{ color: 'var(--ow-fg-3)' }}> failed</span>
              </span>
              <span style={{ fontFamily: 'var(--ow-font-mono)' }}>{host.total} rules</span>
            </div>
          </>
        )}
      </div>

      {/* Footer */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--ow-fg-2)' }}>
          <RefreshCw size={12} />
          Last scan {host.lastScan}
        </div>
        <div style={{ display: 'flex', gap: 4 }}>
          <button type="button" style={iconBtnSm} aria-label="View report">
            <BarChart3 size={14} />
          </button>
          <button
            type="button"
            style={{
              height: 28,
              padding: '0 12px',
              background: 'var(--ow-info)',
              color: 'var(--ow-info-on)',
              border: 0,
              borderRadius: 6,
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 5,
            }}
          >
            <PlayCircle size={12} />
            Scan
          </button>
        </div>
      </div>
    </article>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Table view (alternate)
// ─────────────────────────────────────────────────────────────────────────

function HostsTable({ hosts }: { hosts: DevHost[] }) {
  return (
    <div
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '12px 16px',
          borderBottom: '1px solid var(--ow-line)',
        }}
      >
        <div style={{ fontSize: 13, fontWeight: 600 }}>
          All hosts{' '}
          <span style={{ color: 'var(--ow-fg-2)', marginLeft: 6 }}>{hosts.length}</span>
        </div>
        <div style={{ color: 'var(--ow-fg-2)', fontSize: 12 }}>
          Sorted by status, compliance
        </div>
      </div>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <thead>
          <tr style={{ background: 'var(--ow-bg-2)' }}>
            <th style={{ ...th, width: 36 }}>
              <input type="checkbox" aria-label="Select all" />
            </th>
            <th style={th}>Host</th>
            <th style={th}>Status</th>
            <th style={th}>Compliance</th>
            <th style={th}>Rules</th>
            <th style={th}>Last scan</th>
            <th style={{ ...th, textAlign: 'right' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((host) => (
            <HostRow key={host.id} host={host} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function HostRow({ host }: { host: DevHost }) {
  const tier = complianceTier(host.compliance);
  const isDown = host.status === 'down';
  const displayName = host.hostname === '—' ? host.ip_address : host.hostname;
  const displaySub = host.hostname === '—' ? 'no hostname' : host.ip_address;
  const tierColor =
    tier === 'crit' ? 'var(--ow-crit)' : tier === 'warn' ? 'var(--ow-warn)' : 'var(--ow-ok)';
  return (
    <tr style={{ borderTop: '1px solid var(--ow-line)' }}>
      <td style={td}>
        <input type="checkbox" aria-label={`Select ${displayName}`} />
      </td>
      <td style={td}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <div
            style={{
              position: 'relative',
              width: 22,
              height: 22,
              borderRadius: 5,
              background: 'var(--ow-bg-3)',
              display: 'grid',
              placeItems: 'center',
              color: 'var(--ow-fg-2)',
            }}
          >
            <Server size={12} />
            <span
              style={{
                position: 'absolute',
                right: -2,
                bottom: -2,
                width: 7,
                height: 7,
                borderRadius: '50%',
                background: isDown ? 'var(--ow-crit)' : 'var(--ow-ok)',
                border: '2px solid var(--ow-bg-1)',
              }}
            />
          </div>
          <div>
            <div style={{ fontWeight: 500 }}>
              <Link
                to="/hosts/$hostId"
                params={{ hostId: host.id }}
                style={{ color: 'var(--ow-fg-0)', textDecoration: 'none' }}
              >
                {displayName}
              </Link>
            </div>
            <div
              style={{
                fontSize: 11,
                color: 'var(--ow-fg-3)',
                marginTop: 2,
                display: 'flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              <span style={{ fontFamily: 'var(--ow-font-mono)' }}>{displaySub}</span>
              <span style={{ color: 'var(--ow-fg-3)' }}>·</span>
              <OSChip os={host.os} />
            </div>
          </div>
        </div>
      </td>
      <td style={td}>
        <StatusPill band={host.monitoring} />
        <div style={{ color: 'var(--ow-fg-3)', fontSize: 11, marginTop: 2 }}>
          {host.lastCheckMinutes === null
            ? 'Never probed'
            : formatMinutesAgo(host.lastCheckMinutes)}
        </div>
      </td>
      <td style={td}>
        {host.compliance == null ? (
          <span style={{ color: 'var(--ow-fg-3)' }}>—</span>
        ) : (
          <div>
            <div
              style={{
                fontSize: 14,
                fontWeight: 600,
                color: tierColor,
                fontVariantNumeric: 'tabular-nums',
              }}
            >
              {host.compliance.toFixed(1)}%
            </div>
            <div
              style={{
                marginTop: 4,
                height: 4,
                background: 'var(--ow-bg-3)',
                borderRadius: 2,
                width: 120,
              }}
            >
              <span
                style={{
                  display: 'block',
                  height: '100%',
                  width: `${host.compliance}%`,
                  background: tierColor,
                  borderRadius: 2,
                }}
              />
            </div>
          </div>
        )}
      </td>
      <td style={td}>
        {host.passed == null ? (
          <span style={{ color: 'var(--ow-fg-3)' }}>—</span>
        ) : (
          <div style={{ fontFamily: 'var(--ow-font-mono)', fontSize: 12 }}>
            <div>
              <span style={{ color: 'var(--ow-ok)' }}>{host.passed}</span>
              <span style={{ color: 'var(--ow-fg-3)' }}> / {host.total} passed</span>
            </div>
            <div>
              <span style={{ color: 'var(--ow-crit)' }}>{host.failed}</span>
              <span style={{ color: 'var(--ow-fg-3)' }}> failed</span>
            </div>
          </div>
        )}
      </td>
      <td style={td}>
        <div style={{ fontFamily: 'var(--ow-font-mono)', fontSize: 12, color: 'var(--ow-fg-1)' }}>
          {host.lastScan}
        </div>
      </td>
      <td style={{ ...td, textAlign: 'right' }}>
        <div style={{ display: 'inline-flex', gap: 4, justifyContent: 'flex-end' }}>
          <button type="button" style={iconBtnSm} aria-label="Run scan">
            <PlayCircle size={14} />
          </button>
          <button type="button" style={iconBtnSm} aria-label="View report">
            <BarChart3 size={14} />
          </button>
          <button type="button" style={iconBtnSm} aria-label="More">
            <MoreVertical size={14} />
          </button>
        </div>
      </td>
    </tr>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Status pill + OS chip
// ─────────────────────────────────────────────────────────────────────────

// v1.3.0 — band → (label, color, halo bg) lookup. Six bands cover the
// full multi-layer state surface.
const BAND_STYLE: Record<
  MonitoringBand,
  { label: string; fg: string; bg: string }
> = {
  online: { label: 'ONLINE', fg: 'var(--ow-ok)', bg: 'var(--ow-ok-bg)' },
  degraded: {
    label: 'DEGRADED',
    fg: 'var(--ow-warn)',
    bg: 'var(--ow-warn-bg)',
  },
  critical: {
    label: 'CRITICAL',
    fg: 'var(--ow-crit)',
    bg: 'var(--ow-crit-bg)',
  },
  down: { label: 'DOWN', fg: 'var(--ow-crit)', bg: 'var(--ow-crit-bg)' },
  maintenance: {
    label: 'MAINTENANCE',
    fg: 'var(--ow-fg-2)',
    bg: 'var(--ow-bg-2)',
  },
  unknown: {
    label: 'UNKNOWN',
    fg: 'var(--ow-fg-3)',
    bg: 'var(--ow-bg-2)',
  },
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

function OSChip({ os }: { os: DevHost['os'] }) {
  const color = OS_COLOR[os] ?? OS_COLOR_FALLBACK;
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: '2px 8px 2px 6px',
        background: 'var(--ow-bg-3)',
        borderRadius: 4,
        fontSize: 12,
        color: 'var(--ow-fg-1)',
      }}
    >
      <span
        style={{
          width: 7,
          height: 7,
          borderRadius: '50%',
          background: color,
          display: 'inline-block',
        }}
      />
      {os}
    </span>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// State regions
// ─────────────────────────────────────────────────────────────────────────

function ErrorRegion({
  message,
  onRetry,
}: {
  message: string;
  onRetry: () => void;
}) {
  return (
    <div
      role="alert"
      style={{
        padding: 20,
        background: 'color-mix(in oklab, var(--ow-crit) 10%, var(--ow-bg-1))',
        border: '1px solid var(--ow-crit)',
        borderRadius: 'var(--ow-radius)',
        color: 'var(--ow-fg-1)',
      }}
    >
      <p style={{ margin: 0, marginBottom: 10 }}>
        <strong>Failed to load hosts.</strong> {message}
      </p>
      <button type="button" onClick={onRetry} style={btnPrimary} aria-label="Retry">
        Retry
      </button>
    </div>
  );
}

function EmptyRegion({
  canAdd,
  hasFilter,
  onClear,
}: {
  canAdd: boolean;
  hasFilter: boolean;
  onClear: () => void;
}) {
  if (hasFilter) {
    return (
      <div
        role="status"
        style={{
          padding: 32,
          textAlign: 'center',
          background: 'var(--ow-bg-1)',
          border: '1px solid var(--ow-line)',
          borderRadius: 'var(--ow-radius)',
        }}
      >
        <p style={{ marginTop: 0 }}>No hosts match your filters</p>
        <button type="button" onClick={onClear} style={btnSecondary}>
          Clear filters
        </button>
      </div>
    );
  }
  return (
    <div
      style={{
        padding: 40,
        textAlign: 'center',
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
      }}
    >
      <ServerOff size={32} color="var(--ow-fg-3)" style={{ marginBottom: 12 }} />
      <h2 style={{ marginTop: 0, fontWeight: 500 }}>No hosts yet</h2>
      <p style={{ color: 'var(--ow-fg-2)' }}>
        Add your first host to begin tracking compliance.
      </p>
      {canAdd && (
        <Link to="/hosts/new" style={btnPrimary}>
          <Plus size={14} /> Add your first host
        </Link>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// API → DevHost mapping (when backend has real data)
// ─────────────────────────────────────────────────────────────────────────

// formatMinutesAgo turns a minute count into a humane "Xm ago" / "Xh ago"
// / "Xd ago" string. Under 1m reads as "just now" since that's the
// 30-second tick range from the adaptive health checks loop.
function formatMinutesAgo(minutes: number): string {
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export function apiHostToDev(h: ApiHost): DevHost {
  // v1.3.0: derive both the legacy 'status' (online/down) for components
  // that still consume the binary view, AND the new 'monitoring' band so
  // the StatusPill can render degraded vs critical vs down distinctly.
  const reachable = h.liveness?.reachability_status === 'reachable';
  const monitoring: MonitoringBand =
    h.maintenance_mode === true
      ? 'maintenance'
      : h.liveness?.monitoring_state ?? 'unknown';
  let lastCheckMinutes: number | null = null;
  if (h.liveness?.last_probe_at) {
    const probedAt = new Date(h.liveness.last_probe_at).getTime();
    if (!Number.isNaN(probedAt)) {
      lastCheckMinutes = Math.max(0, Math.round((Date.now() - probedAt) / 60_000));
    }
  }
  // v1.5.0: lastScan derived from host_rule_state's MAX(last_checked_at).
  // "—" when no compliance check has ever run.
  let lastScan = '—';
  if (h.last_scan_at) {
    const at = new Date(h.last_scan_at).getTime();
    if (!Number.isNaN(at)) {
      const minutesAgo = Math.max(0, Math.round((Date.now() - at) / 60_000));
      lastScan = formatMinutesAgo(minutesAgo);
    }
  }
  return {
    id: h.id,
    hostname: h.hostname,
    ip_address: h.ip_address,
    os: osDisplayLabel(h.os_family),
    status: reachable ? 'online' : 'down',
    monitoring,
    maintenance: h.maintenance_mode === true,
    compliance: null,
    passed: null,
    failed: null,
    total: 0,
    lastCheckMinutes,
    lastScan,
  };
}

function kpisFromHosts(hosts: DevHost[]) {
  const total = hosts.length;
  const online = hosts.filter((h) => h.status === 'online').length;
  const totalRules = hosts.reduce((n, h) => n + h.total, 0);
  const totalPassed = hosts.reduce((n, h) => n + (h.passed ?? 0), 0);
  const avgCompliance = totalRules > 0 ? Math.round((totalPassed / totalRules) * 1000) / 10 : 0;
  const neutral: 'neutral' = 'neutral';
  return {
    hostsOnline: { value: online, total, delta: '', deltaTier: neutral },
    avgCompliance: { value: avgCompliance, target: 80, delta: '', deltaTier: neutral },
    criticalIssues: { value: 0, scope: 'No data', delta: '', deltaTier: neutral },
    scanQueue: { value: 0, scope: 'Idle', delta: '—', deltaTier: neutral },
  } satisfies import('@/api/dev-fixtures').DevKpis;
}

function fleetAlertFromHosts(hosts: DevHost[]): FleetAlertContent | null {
  if (hosts.length === 0) return null;
  const down = hosts.filter((h) => h.status === 'down').length;
  if (down / hosts.length < 0.5) return null;
  return {
    title: 'Fleet health critical',
    body: `${down} of ${hosts.length} hosts are unreachable.`,
    downCount: down,
  };
}

// ─────────────────────────────────────────────────────────────────────────
// Style atoms
// ─────────────────────────────────────────────────────────────────────────

const btnPrimary: React.CSSProperties = {
  height: 34,
  padding: '0 16px',
  background: 'var(--ow-info)',
  color: 'var(--ow-info-on)',
  border: 0,
  borderRadius: 8,
  fontWeight: 600,
  fontSize: 13,
  cursor: 'pointer',
  textDecoration: 'none',
  display: 'inline-flex',
  alignItems: 'center',
  gap: 6,
};

const btnSecondary: React.CSSProperties = {
  height: 34,
  padding: '0 14px',
  background: 'var(--ow-bg-1)',
  color: 'var(--ow-fg-0)',
  border: '1px solid var(--ow-line)',
  borderRadius: 8,
  fontWeight: 500,
  fontSize: 13,
  cursor: 'pointer',
  textDecoration: 'none',
  display: 'inline-flex',
  alignItems: 'center',
  gap: 6,
};

const btnSecondarySm: React.CSSProperties = {
  ...btnSecondary,
  height: 28,
  padding: '0 12px',
  fontSize: 12,
  borderRadius: 6,
};

const iconBtnSm: React.CSSProperties = {
  width: 26,
  height: 26,
  border: 0,
  background: 'transparent',
  color: 'var(--ow-fg-2)',
  borderRadius: 5,
  display: 'inline-grid',
  placeItems: 'center',
  cursor: 'pointer',
};

const segBtn: React.CSSProperties = {
  border: 0,
  fontFamily: 'inherit',
  padding: '4px 8px',
  borderRadius: 5,
  cursor: 'pointer',
  display: 'inline-grid',
  placeItems: 'center',
};

const th: React.CSSProperties = {
  textAlign: 'left',
  padding: '10px 14px',
  fontSize: 11,
  fontWeight: 600,
  color: 'var(--ow-fg-2)',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
};

const td: React.CSSProperties = {
  padding: '12px 14px',
  color: 'var(--ow-fg-1)',
  verticalAlign: 'middle',
};
