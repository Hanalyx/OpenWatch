import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Shield,
  Activity,
  RotateCcw,
  PlayCircle,
  HelpCircle,
  Loader2,
} from 'lucide-react';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import { SettingsLayout } from '@/components/settings/SettingsLayout';
import {
  PageHead,
  Section,
  SettingCard,
  SettingRow,
  FirstSettingRow,
  Toggle,
  Stepper,
  Select,
  Btn,
  SchedSummary,
  AdvancedDisclosure,
  BackendPendingBanner,
  Callout,
} from '@/components/settings/primitives';
import { OSIntelligenceSection } from '@/components/settings/OSIntelligenceSection';

// Settings → Scanning & monitoring.
//
// Spec: frontend-settings v1.1.0 (Scanning & monitoring section).
//
// Wiring honesty:
//
//   • Compliance scanner    — local state only. The Go backend has no
//                              compliance scheduler yet; tracked as
//                              post-Slice-B (Slice C).
//   • Connectivity monitor  — fully wired against
//                              GET /api/v1/system/connectivity/config,
//                              PUT /api/v1/system/connectivity/config,
//                              GET /api/v1/system/connectivity/status,
//                              GET /api/v1/fleet/connectivity/breakdown.
//   • OS discovery          — local state only. No OS-discovery
//                              scheduler in the backend yet.
//   • Maintenance (global)  — wired via the connectivity config's
//                              maintenance_global flag.
//   • Group maintenance     — local state only. No group entity yet.

// ─────────────────────────────────────────────────────────────────────────
// Compliance scanner — 5 state buckets with per-state intervals
//
// Backend pending. Defaults stay as visual UI; no save endpoint.
// ─────────────────────────────────────────────────────────────────────────

type Tier = 'crit' | 'warn' | 'info' | 'mostlyOk' | 'ok' | 'muted';

interface StateRowConfig {
  id: string;
  tier: Tier;
  name: string;
  desc: string;
  hosts: number;
  intervalMin: number;
  rangeText: string;
  cadenceText: (intervalMin: number, hosts: number) => string;
}

const COMPLIANCE_DEFAULTS: StateRowConfig[] = [
  {
    id: 'critical',
    tier: 'crit',
    name: 'Critical',
    desc: 'Compliance < 20%',
    hosts: 0,
    intervalMin: 60,
    rangeText: '15 min – 6h',
    cadenceText: (m, h) => (h === 0 ? '—' : `${Math.round((60 / m) * 24 * h)} scans/day`),
  },
  {
    id: 'low',
    tier: 'warn',
    name: 'Low',
    desc: 'Compliance 20–49%',
    hosts: 0,
    intervalMin: 120,
    rangeText: '30 min – 12h',
    cadenceText: (m, h) => (h === 0 ? '—' : `${Math.round((60 / m) * 24 * h)} scans/day`),
  },
  {
    id: 'partial',
    tier: 'info',
    name: 'Partial',
    desc: 'Compliance 50–69%',
    hosts: 0,
    intervalMin: 360,
    rangeText: '1h – 24h',
    cadenceText: (_m, _h) => '—',
  },
  {
    id: 'mostly',
    tier: 'mostlyOk',
    name: 'Mostly compliant',
    desc: 'Compliance 70–89%',
    hosts: 0,
    intervalMin: 720,
    rangeText: '6h – 48h',
    cadenceText: (_m, _h) => '—',
  },
  {
    id: 'compliant',
    tier: 'ok',
    name: 'Compliant',
    desc: 'Compliance ≥ 90%',
    hosts: 0,
    intervalMin: 1440,
    rangeText: '12h – 48h',
    cadenceText: (_m, _h) => '—',
  },
];

// ─────────────────────────────────────────────────────────────────────────
// Connectivity monitor — 4-state breakdown derived from host_liveness
// ─────────────────────────────────────────────────────────────────────────

interface ConnectivityRowSeed {
  id: string;
  tier: Tier;
  name: string;
  desc: string;
  rangeText: string;
}

// Visual seed only; hosts/intervalMin/cadenceText come from live data.
const CONNECTIVITY_ROW_SEEDS: ConnectivityRowSeed[] = [
  { id: 'never', tier: 'muted', name: 'Never probed', desc: 'New host · no probe yet', rangeText: '—' },
  { id: 'online', tier: 'ok', name: 'Online', desc: 'Reachable · 0 failures', rangeText: 'Healthy' },
  { id: 'degraded', tier: 'info', name: 'Degraded', desc: 'Reachable · 1+ recent failures', rangeText: 'Watch' },
  { id: 'critical', tier: 'warn', name: 'Critical', desc: 'Unreachable · 1–2 failures', rangeText: 'Backoff escalating' },
  { id: 'down', tier: 'crit', name: 'Down', desc: '3+ consecutive failures', rangeText: 'Use on-demand probe to retest' },
];

const GROUPS = [
  { id: 'production', name: 'Production', kind: 'Site', desc: '3 hosts · environment', paused: false },
  { id: 'development', name: 'Development', kind: 'Site', desc: '4 hosts · environment · currently paused', paused: true },
  { id: 'dr', name: 'DR · Warm standby', kind: 'Site', desc: '2 hosts · disaster recovery', paused: false },
  { id: 'rhel', name: 'RHEL', kind: 'OS', desc: '4 hosts · auto · caps.os.family == rhel', paused: false },
  { id: 'ubuntu', name: 'Ubuntu', kind: 'OS', desc: '3 hosts · auto · caps.os.family == ubuntu', paused: false },
];

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

function tierToColorVar(tier: Tier): string {
  switch (tier) {
    case 'crit':
      return 'var(--ow-crit)';
    case 'warn':
      return 'var(--ow-warn)';
    case 'info':
      return 'var(--ow-info)';
    case 'mostlyOk':
      return 'color-mix(in oklab, var(--ow-ok) 60%, transparent)';
    case 'ok':
      return 'var(--ow-ok)';
    default:
      return 'var(--ow-fg-3)';
  }
}

function formatCadence(intervalMin: number): string {
  if (intervalMin <= 0) return 'Immediate';
  if (intervalMin < 60) return `Every ${intervalMin} min`;
  const h = intervalMin / 60;
  if (Number.isInteger(h) && h < 24) return `Every ${h}h`;
  if (Number.isInteger(h / 24)) return `Every ${h / 24}d`;
  return `Every ${intervalMin} min`;
}

function formatTimeAgo(iso: string | null | undefined): string {
  if (!iso) return 'No tick yet';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return 'Unknown';
  const seconds = Math.round((Date.now() - t) / 1000);
  if (seconds < 60) return `${seconds} sec ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  return `${Math.round(seconds / 3600)} h ago`;
}

// ─────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────

interface ConnectivityConfigDraft {
  online_sec: number;
  degraded_sec: number;
  critical_sec: number;
  down_sec: number;
  maintenance_sec: number;
  timeout_sec: number;
  unreachable_threshold: number;
  rate_limit: number;
  maintenance_global: boolean;
}

export function ScanningPage() {
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);
  useEffect(() => {
    setCrumbs([{ label: 'Settings' }, { label: 'Scanning & monitoring' }]);
    return () => setCrumbs([]);
  }, [setCrumbs]);

  const queryClient = useQueryClient();

  // ─── Wired: connectivity config ────────────────────────────────────
  const configQuery = useQuery({
    queryKey: ['system', 'connectivity', 'config'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/system/connectivity/config', {});
      if (error) throw error;
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return data!;
    },
  });

  const statusQuery = useQuery({
    queryKey: ['system', 'connectivity', 'status'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/system/connectivity/status', {});
      if (error) throw error;
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return data!;
    },
    refetchInterval: 30_000,
  });

  const breakdownQuery = useQuery({
    queryKey: ['fleet', 'connectivity', 'breakdown'],
    queryFn: async () => {
      const { data, error, response } = await api.GET(
        '/api/v1/fleet/connectivity/breakdown',
        {},
      );
      if (error) throw error;
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return data!;
    },
    refetchInterval: 30_000,
  });

  // Local edit buffer over the server config — drives the save bar.
  const [draft, setDraft] = useState<ConnectivityConfigDraft | null>(null);
  useEffect(() => {
    if (configQuery.data && !draft) {
      setDraft({
        online_sec: configQuery.data.config.online_sec,
        degraded_sec: configQuery.data.config.degraded_sec,
        critical_sec: configQuery.data.config.critical_sec,
        down_sec: configQuery.data.config.down_sec,
        maintenance_sec: configQuery.data.config.maintenance_sec,
        timeout_sec: configQuery.data.config.timeout_sec,
        unreachable_threshold: configQuery.data.config.unreachable_threshold,
        rate_limit: configQuery.data.config.rate_limit,
        maintenance_global: configQuery.data.config.maintenance_global,
      });
    }
  }, [configQuery.data, draft]);

  const saveMutation = useMutation({
    mutationFn: async (body: ConnectivityConfigDraft) => {
      const { error, response } = await api.PUT('/api/v1/system/connectivity/config', {
        body,
      });
      if (error) throw error;
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['system', 'connectivity', 'config'] });
      queryClient.invalidateQueries({ queryKey: ['system', 'connectivity', 'status'] });
    },
  });

  const dirty = useMemo(() => {
    if (!draft || !configQuery.data) return false;
    const live = configQuery.data.config;
    return (
      draft.online_sec !== live.online_sec ||
      draft.degraded_sec !== live.degraded_sec ||
      draft.critical_sec !== live.critical_sec ||
      draft.down_sec !== live.down_sec ||
      draft.maintenance_sec !== live.maintenance_sec ||
      draft.timeout_sec !== live.timeout_sec ||
      draft.unreachable_threshold !== live.unreachable_threshold ||
      draft.rate_limit !== live.rate_limit ||
      draft.maintenance_global !== live.maintenance_global
    );
  }, [draft, configQuery.data]);

  const onResetConnectivity = () => {
    if (!configQuery.data) return;
    setDraft({
      online_sec: configQuery.data.defaults.online_sec,
      degraded_sec: configQuery.data.defaults.degraded_sec,
      critical_sec: configQuery.data.defaults.critical_sec,
      down_sec: configQuery.data.defaults.down_sec,
      maintenance_sec: configQuery.data.defaults.maintenance_sec,
      timeout_sec: configQuery.data.defaults.timeout_sec,
      unreachable_threshold: configQuery.data.defaults.unreachable_threshold,
      rate_limit: configQuery.data.defaults.rate_limit,
      maintenance_global: configQuery.data.defaults.maintenance_global,
    });
  };

  // ─── Local-only sections (compliance scanner + OS discovery + groups) ──
  const [complianceRows] = useState(COMPLIANCE_DEFAULTS);
  const [complianceEnabled, setComplianceEnabled] = useState(true);
  const [complianceAdvancedOpen, setComplianceAdvancedOpen] = useState(false);

  const [connectivityAdvancedOpen, setConnectivityAdvancedOpen] = useState(false);

  const [nightlyRescan, setNightlyRescan] = useState(true);
  const [detectOnFirstContact, setDetectOnFirstContact] = useState(true);

  const [autoResume, setAutoResume] = useState('4h');
  const [groupMaintenance, setGroupMaintenance] = useState(
    () => Object.fromEntries(GROUPS.map((g) => [g.id, g.paused])) as Record<string, boolean>,
  );

  // ─── Live-derived display values ─────────────────────────────────────
  const breakdown = breakdownQuery.data;
  const status = statusQuery.data;
  // Per-state interval (minutes) — comes from draft, which mirrors what
  // the backend's bandIntervalFor() will pick. Spec
  // services-connectivity-config v1.1.0 + system-liveness-loop v1.2.0.
  const bandIntervalMin = (seedId: string): number => {
    if (!draft) return 5;
    switch (seedId) {
      case 'online':
        return Math.round(draft.online_sec / 60);
      case 'degraded':
        return Math.round(draft.degraded_sec / 60);
      case 'critical':
        return Math.round(draft.critical_sec / 60);
      case 'down':
        return Math.round(draft.down_sec / 60);
      default:
        return 0; // never_probed: immediate
    }
  };
  const connectivityRows = useMemo<StateRowConfig[]>(
    () =>
      CONNECTIVITY_ROW_SEEDS.map((seed) => {
        const hosts = !breakdown
          ? 0
          : seed.id === 'online'
          ? Number(breakdown.online)
          : seed.id === 'degraded'
          ? Number(breakdown.degraded)
          : seed.id === 'critical'
          ? Number(breakdown.critical)
          : seed.id === 'down'
          ? Number(breakdown.down)
          : seed.id === 'never'
          ? Number(breakdown.never_probed)
          : 0;
        return {
          id: seed.id,
          tier: seed.tier,
          name: seed.name,
          desc: seed.desc,
          hosts,
          intervalMin: bandIntervalMin(seed.id),
          rangeText: seed.rangeText,
          cadenceText: (m: number) => (m > 0 ? `Every ${m} min` : 'Immediate'),
        };
      }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [breakdown, draft],
  );

  const breakdownTotal = breakdown
    ? Number(breakdown.online) +
      Number(breakdown.degraded) +
      Number(breakdown.critical) +
      Number(breakdown.down) +
      Number(breakdown.never_probed)
    : 0;

  const connectivitySubtitle = breakdown
    ? `${breakdown.online} online · ${breakdown.degraded} degraded · ${breakdown.critical} critical · ${breakdown.down} down · ${breakdown.never_probed} never probed`
    : 'Loading fleet breakdown…';

  return (
    <SettingsLayout>
      <PageHead
        title="Scanning & monitoring"
        description="Control how often OpenWatch scans hosts for compliance and probes them for connectivity."
        actions={
          <Btn onClick={onResetConnectivity} disabled={!configQuery.data || saveMutation.isPending}>
            <RotateCcw size={14} /> Reset connectivity to defaults
          </Btn>
        }
      />

      {/* ────────── Compliance scanner ────────── */}
      <Section title="Compliance scanner" badge="UI only" badgeTier="warn">
        <BackendPendingBanner
          slice="Compliance scheduler (post-Slice-B / Slice C)"
          text="The Go backend has no compliance scheduler yet — this section is a UI preview. Save is disabled."
        />
        <p style={leadStyle}>
          Re-runs the active CIS / STIG profile against each host. Cadence is set per compliance
          state — failing hosts get re-checked more often.
        </p>

        <SchedSummary
          icon={<Shield size={18} />}
          iconTier="info"
          title="Automatic compliance scanning"
          subtitle="Adaptive scheduler not yet implemented in the Go backend"
          rightLabel="Status"
          rightValue="UI only"
          toggleValue={complianceEnabled}
          onToggleChange={setComplianceEnabled}
        />

        <StateTable
          rows={complianceRows}
          readOnly
          onIntervalChange={() => {}}
        />

        <AdvancedDisclosure
          label="Advanced — quiet hours, jitter, retry policy (not yet wired)"
          open={complianceAdvancedOpen}
          onToggle={() => setComplianceAdvancedOpen((v) => !v)}
        >
          <SettingCard>
            <FirstSettingRow
              name="Quiet hours"
              description="Suppress all compliance scans during this window."
              control={
                <Select
                  value="00-06"
                  onChange={() => {}}
                  options={[
                    { value: 'off', label: 'Off' },
                    { value: '00-06', label: '00:00 – 06:00' },
                  ]}
                />
              }
            />
          </SettingCard>
        </AdvancedDisclosure>
      </Section>

      {/* ────────── Host connectivity monitor (LIVE) ────────── */}
      <Section
        title="Host connectivity monitor"
        badge={status?.maintenance_active ? 'Paused' : 'Running'}
        badgeTier={status?.maintenance_active ? 'warn' : 'ok'}
      >
        {configQuery.isError && (
          <Callout tier="crit">
            Failed to load connectivity config: {apiErrorMessage(configQuery.error, 'unknown error')}
          </Callout>
        )}

        <p style={leadStyle}>
          Pings each host over TCP port 22 to confirm it's reachable. The cadence + per-probe
          timeout + hysteresis threshold come from the values below; the periodic loop hot-reloads
          on save.
        </p>

        <SchedSummary
          icon={<Activity size={18} />}
          iconTier="ok"
          title="Adaptive health checks"
          subtitle={connectivitySubtitle}
          rightLabel="Last sweep"
          rightValue={formatTimeAgo(status?.last_probe_at)}
          toggleValue={!(draft?.maintenance_global ?? false)}
          onToggleChange={(v) => setDraft((d) => (d ? { ...d, maintenance_global: !v } : d))}
        />

        <StateTable
          rows={connectivityRows}
          readOnly
          onIntervalChange={() => {}}
          headers={['Host state', 'Hosts', 'Cadence', 'Notes']}
          rightColumnRenderer={(r) => (
            <div style={cadenceStyle}>
              <span style={cadenceStrong}>{r.cadenceText(r.intervalMin, r.hosts)}</span>
              {r.rangeText}
            </div>
          )}
        />

        <div style={{ marginTop: 14 }}>
          <SettingCard>
            <FirstSettingRow
              name={
                <>
                  Online interval{' '}
                  <HelpCircle
                    size={13}
                    color="var(--ow-fg-3)"
                    aria-label="Probe cadence for stable, reachable hosts (consecutive_failures = 0)"
                  />
                </>
              }
              description="Reachable hosts with no recent failures. Bias high — nothing's changing. (60..86400 sec)"
              control={
                <Stepper
                  value={draft?.online_sec ?? 900}
                  min={60}
                  max={86400}
                  step={60}
                  unit="sec"
                  onChange={(v) => setDraft((d) => (d ? { ...d, online_sec: v } : d))}
                />
              }
            />
            <SettingRow
              name="Degraded interval"
              description="Reachable hosts with at least one recent failure — watch closely. (60..86400 sec)"
              control={
                <Stepper
                  value={draft?.degraded_sec ?? 300}
                  min={60}
                  max={86400}
                  step={30}
                  unit="sec"
                  onChange={(v) => setDraft((d) => (d ? { ...d, degraded_sec: v } : d))}
                />
              }
            />
            <SettingRow
              name="Critical interval"
              description="Unreachable hosts still below the failure threshold — confirm fast. (60..86400 sec)"
              control={
                <Stepper
                  value={draft?.critical_sec ?? 120}
                  min={60}
                  max={86400}
                  step={30}
                  unit="sec"
                  onChange={(v) => setDraft((d) => (d ? { ...d, critical_sec: v } : d))}
                />
              }
            />
            <SettingRow
              name="Down interval"
              description="Hosts at or above the failure threshold — back off, don't hammer dead. (60..86400 sec)"
              control={
                <Stepper
                  value={draft?.down_sec ?? 1800}
                  min={60}
                  max={86400}
                  step={60}
                  unit="sec"
                  onChange={(v) => setDraft((d) => (d ? { ...d, down_sec: v } : d))}
                />
              }
            />
            <SettingRow
              name="Maintenance interval"
              description="Persisted for the per-host maintenance slice (not yet auto-applied). (60..86400 sec)"
              control={
                <Stepper
                  value={draft?.maintenance_sec ?? 3600}
                  min={60}
                  max={86400}
                  step={60}
                  unit="sec"
                  onChange={(v) => setDraft((d) => (d ? { ...d, maintenance_sec: v } : d))}
                />
              }
            />
            <SettingRow
              name="Probe timeout"
              description="Per-probe TCP-banner timeout (1..30 seconds)."
              control={
                <Stepper
                  value={draft?.timeout_sec ?? 5}
                  min={1}
                  max={30}
                  step={1}
                  unit="sec"
                  onChange={(v) => setDraft((d) => (d ? { ...d, timeout_sec: v } : d))}
                />
              }
            />
            <SettingRow
              name="Unreachable threshold"
              description="Consecutive failures before a reachable host flips to unreachable (1..10)."
              control={
                <Stepper
                  value={draft?.unreachable_threshold ?? 2}
                  min={1}
                  max={10}
                  step={1}
                  onChange={(v) => setDraft((d) => (d ? { ...d, unreachable_threshold: v } : d))}
                />
              }
            />
            <SettingRow
              name="Network rate limit"
              description="Max concurrent SSH-banner connections during fleet sweeps (1..200)."
              control={
                <Stepper
                  value={draft?.rate_limit ?? 50}
                  min={1}
                  max={200}
                  step={1}
                  unit="conns"
                  onChange={(v) => setDraft((d) => (d ? { ...d, rate_limit: v } : d))}
                />
              }
            />
          </SettingCard>
        </div>

        <AdvancedDisclosure
          label="Status snapshot"
          open={connectivityAdvancedOpen}
          onToggle={() => setConnectivityAdvancedOpen((v) => !v)}
        >
          <SettingCard>
            <FirstSettingRow
              name="Probe count"
              description={`${status?.probe_count ?? 0} probes since service start (${status?.probe_success_count ?? 0} success / ${status?.probe_failure_count ?? 0} failure).`}
              control={<></>}
            />
            <SettingRow
              name="State transitions"
              description={`${status?.state_transition_count ?? 0} reachability flips audited.`}
              control={<></>}
            />
            <SettingRow
              name="Fleet size (active hosts)"
              description={`${breakdownTotal} hosts in the active inventory (deleted_at IS NULL).`}
              control={<></>}
            />
          </SettingCard>
        </AdvancedDisclosure>
      </Section>

      {/* ────────── OS discovery (UI only) ────────── */}
      <Section title="OS discovery" badge="UI only" badgeTier="warn">
        <BackendPendingBanner
          slice="OS-discovery sweeper (post-Slice-B)"
          text="Per-host OS family + version detection lands with the OS discovery service. Toggles below are display-only."
        />
        <SettingCard>
          <FirstSettingRow
            name="Nightly re-scan"
            description="Sweeps any host with missing platform data — runs at 02:00 UTC when wired."
            control={
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <Btn size="sm" disabled>
                  <PlayCircle size={12} /> Run now
                </Btn>
                <Toggle value={nightlyRescan} onChange={setNightlyRescan} ariaLabel="Nightly re-scan" />
              </div>
            }
          />
          <SettingRow
            name="Detect on first contact"
            description="Always run platform detection when a host is added with credentials."
            control={
              <Toggle
                value={detectOnFirstContact}
                onChange={setDetectOnFirstContact}
                ariaLabel="Detect on first contact"
              />
            }
          />
        </SettingCard>
      </Section>

      {/* ────────── OS Intelligence scheduler (wired) ────────── */}
      {/* Spec: frontend-settings-intelligence-config v1.0 */}
      <OSIntelligenceSection />

      {/* ────────── Maintenance (global flag wired; groups UI only) ────────── */}
      <Section title="Maintenance">
        <p style={leadStyle}>
          When global maintenance is on, the connectivity monitor ticks but probes no hosts. The
          flag is persisted via the connectivity config.
        </p>
        <SettingCard>
          <FirstSettingRow
            name={
              <>
                Global maintenance mode{' '}
                <HelpCircle size={13} color="var(--ow-fg-3)" aria-label="Silences the entire fleet" />
              </>
            }
            description="Pause all connectivity probes across every host."
            control={
              <Toggle
                value={draft?.maintenance_global ?? false}
                onChange={(v) =>
                  setDraft((d) => (d ? { ...d, maintenance_global: v } : d))
                }
                ariaLabel="Global maintenance mode"
              />
            }
          />
          <SettingRow
            name="Auto-resume"
            description="(Not yet wired) Automatically lift global maintenance after a set duration."
            control={
              <Select
                value={autoResume}
                onChange={setAutoResume}
                options={[
                  { value: '1h', label: 'After 1 hour' },
                  { value: '4h', label: 'After 4 hours' },
                  { value: '8h', label: 'After 8 hours' },
                  { value: 'manual', label: 'Manual only' },
                ]}
              />
            }
          />
        </SettingCard>

        <div style={{ marginTop: 14 }}>
          <BackendPendingBanner
            slice="Group maintenance (groups entity)"
            text="Per-group pause requires a groups entity (not in the Go backend yet). Toggles below are display-only."
          />
        </div>
        <SettingCard>
          {GROUPS.map((group, i) => (
            <GroupRow
              key={group.id}
              isFirst={i === 0}
              name={group.name}
              kind={group.kind}
              desc={group.desc}
              paused={groupMaintenance[group.id] ?? false}
              onPauseChange={(v) =>
                setGroupMaintenance((s) => ({ ...s, [group.id]: v }))
              }
            />
          ))}
        </SettingCard>
      </Section>

      {dirty && draft && (
        <SaveBar
          onReset={() => {
            if (!configQuery.data) return;
            setDraft({
              online_sec: configQuery.data.config.online_sec,
              degraded_sec: configQuery.data.config.degraded_sec,
              critical_sec: configQuery.data.config.critical_sec,
              down_sec: configQuery.data.config.down_sec,
              maintenance_sec: configQuery.data.config.maintenance_sec,
              timeout_sec: configQuery.data.config.timeout_sec,
              unreachable_threshold: configQuery.data.config.unreachable_threshold,
              rate_limit: configQuery.data.config.rate_limit,
              maintenance_global: configQuery.data.config.maintenance_global,
            });
            saveMutation.reset();
          }}
          onSave={() => saveMutation.mutate(draft)}
          saving={saveMutation.isPending}
          error={
            saveMutation.error
              ? apiErrorMessage(saveMutation.error, 'Save failed')
              : null
          }
        />
      )}
    </SettingsLayout>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// State table
// ─────────────────────────────────────────────────────────────────────────

function StateTable({
  rows,
  headers = ['State', 'Hosts', 'Interval', 'Current'],
  onIntervalChange,
  rightColumnRenderer,
  readOnly = false,
}: {
  rows: StateRowConfig[];
  headers?: [string, string, string, string];
  onIntervalChange: (idx: number, v: number) => void;
  rightColumnRenderer?: (r: StateRowConfig) => React.ReactNode;
  readOnly?: boolean;
}) {
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
          display: 'grid',
          gridTemplateColumns: '1fr 200px 160px 120px',
          gap: 16,
          padding: '10px 20px',
          background: 'var(--ow-bg-2)',
          borderBottom: '1px solid var(--ow-line)',
          color: 'var(--ow-fg-2)',
          fontSize: 11,
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          fontWeight: 600,
        }}
      >
        <span>{headers[0]}</span>
        <span>{headers[1]}</span>
        <span style={{ textAlign: 'right' }}>{headers[2]}</span>
        <span style={{ textAlign: 'right' }}>{headers[3]}</span>
      </div>
      {rows.map((row, i) => (
        <StateRow
          key={row.id}
          row={row}
          isFirst={i === 0}
          onIntervalChange={(v) => onIntervalChange(i, v)}
          rightColumn={rightColumnRenderer ? rightColumnRenderer(row) : undefined}
          readOnly={readOnly}
        />
      ))}
    </div>
  );
}

function StateRow({
  row,
  isFirst,
  onIntervalChange,
  rightColumn,
  readOnly,
}: {
  row: StateRowConfig;
  isFirst: boolean;
  onIntervalChange: (v: number) => void;
  rightColumn?: React.ReactNode;
  readOnly?: boolean;
}) {
  const color = tierToColorVar(row.tier);
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '1fr 200px 160px 120px',
        gap: 16,
        padding: '14px 20px',
        alignItems: 'center',
        borderTop: isFirst ? 'none' : '1px solid var(--ow-line)',
        opacity: row.tier === 'muted' ? 0.85 : 1,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <span
          style={{
            width: 10,
            height: 10,
            borderRadius: '50%',
            flexShrink: 0,
            background: color,
            boxShadow:
              row.tier === 'crit'
                ? `0 0 0 3px color-mix(in oklab, ${color} 25%, transparent)`
                : undefined,
          }}
        />
        <div>
          <div style={{ fontWeight: 500, color: 'var(--ow-fg-0)' }}>{row.name}</div>
          <div style={{ color: 'var(--ow-fg-2)', fontSize: 12, marginTop: 2 }}>{row.desc}</div>
        </div>
      </div>
      <div style={{ color: 'var(--ow-fg-2)', fontSize: 12 }}>
        <span
          style={{
            fontWeight: 600,
            color: row.tier === 'crit' ? color : 'var(--ow-fg-0)',
            fontVariantNumeric: 'tabular-nums',
          }}
        >
          {row.hosts}
        </span>{' '}
        {row.hosts === 1 ? 'host' : 'hosts'}
      </div>
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        {readOnly ? (
          <span style={{ color: 'var(--ow-fg-2)', fontSize: 12 }}>
            {formatCadence(row.intervalMin)}
          </span>
        ) : (
          <Stepper
            value={row.intervalMin}
            onChange={onIntervalChange}
            min={0}
            max={1440 * 7}
            step={row.intervalMin >= 60 ? 30 : 1}
            unit="min"
          />
        )}
      </div>
      <div style={cadenceStyle}>
        {rightColumn ?? (
          <>
            <span style={cadenceStrong}>{formatCadence(row.intervalMin)}</span>
            {row.cadenceText(row.intervalMin, row.hosts)}
          </>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Group row
// ─────────────────────────────────────────────────────────────────────────

function GroupRow({
  name,
  kind,
  desc,
  paused,
  onPauseChange,
  isFirst,
}: {
  name: string;
  kind: string;
  desc: string;
  paused: boolean;
  onPauseChange: (v: boolean) => void;
  isFirst: boolean;
}) {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '1fr minmax(180px, auto)',
        gap: 20,
        alignItems: 'center',
        padding: '14px 20px',
        borderTop: isFirst ? 'none' : '1px solid var(--ow-line)',
      }}
    >
      <div>
        <div
          style={{
            fontWeight: 500,
            color: 'var(--ow-fg-0)',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          {name}
          <span
            style={{
              fontSize: 10,
              padding: '2px 7px',
              background: 'var(--ow-info-bg)',
              color: 'var(--ow-info)',
              borderRadius: 'var(--ow-radius-full)',
              fontWeight: 700,
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
            }}
          >
            {kind}
          </span>
        </div>
        <div style={{ color: 'var(--ow-fg-2)', fontSize: 12, marginTop: 4 }}>{desc}</div>
      </div>
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', justifyContent: 'flex-end' }}>
        <Btn size="sm" disabled>Schedule window</Btn>
        <Toggle value={paused} onChange={onPauseChange} ariaLabel={`Pause ${name}`} />
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Save bar
// ─────────────────────────────────────────────────────────────────────────

function SaveBar({
  onReset,
  onSave,
  saving,
  error,
}: {
  onReset: () => void;
  onSave: () => void;
  saving: boolean;
  error: string | null;
}) {
  return (
    <div
      role="region"
      aria-label="Unsaved changes"
      style={{
        position: 'sticky',
        bottom: 18,
        display: 'flex',
        alignItems: 'center',
        gap: 16,
        padding: '12px 18px',
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        boxShadow: 'var(--ow-shadow-md)',
        marginTop: 24,
      }}
    >
      <div style={{ flex: 1, fontSize: 13, color: 'var(--ow-fg-1)' }}>
        <strong>Unsaved changes.</strong>{' '}
        <span style={{ color: 'var(--ow-fg-2)' }}>
          Saving applies the new connectivity config and signals the live probe loop to reload.
        </span>
        {error && (
          <div style={{ marginTop: 4, color: 'var(--ow-crit)', fontSize: 12 }}>{error}</div>
        )}
      </div>
      <Btn onClick={onReset} disabled={saving}>Discard</Btn>
      <Btn variant="primary" onClick={onSave} disabled={saving}>
        {saving ? (
          <>
            <Loader2 size={14} /> Saving…
          </>
        ) : (
          'Save changes'
        )}
      </Btn>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Style atoms
// ─────────────────────────────────────────────────────────────────────────

const leadStyle: React.CSSProperties = {
  margin: '0 0 16px',
  color: 'var(--ow-fg-2)',
  fontSize: 13,
  maxWidth: 720,
};

const cadenceStyle: React.CSSProperties = {
  color: 'var(--ow-fg-2)',
  fontSize: 11,
  textAlign: 'right',
};

const cadenceStrong: React.CSSProperties = {
  color: 'var(--ow-fg-1)',
  fontWeight: 600,
  display: 'block',
  fontSize: 13,
  marginBottom: 2,
};
