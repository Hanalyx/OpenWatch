import { useEffect, useMemo, useState } from 'react';
import {
  Shield,
  Activity,
  RotateCcw,
  PlayCircle,
  HelpCircle,
} from 'lucide-react';
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

// Settings → Scanning & monitoring.
//
// Port of the prototype's full surface: two state-driven schedulers
// (compliance + connectivity), OS-discovery toggles, and fleet
// maintenance controls. Every value lives in local component state
// — backend save endpoints land with the scheduler API. The save
// bar at the bottom is the single confirmation point for "this
// would persist if backend were live."
//
// Spec: frontend-settings v1.1.0 (Scanning & monitoring section).

// ─────────────────────────────────────────────────────────────────────────
// Compliance scanner — 5 state buckets with per-state intervals
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
    hosts: 5,
    intervalMin: 60,
    rangeText: '15 min – 6h',
    cadenceText: (m, h) => `${(60 / m) * 24 * h} scans/day`,
  },
  {
    id: 'low',
    tier: 'warn',
    name: 'Low',
    desc: 'Compliance 20–49%',
    hosts: 2,
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

const CONNECTIVITY_DEFAULTS: StateRowConfig[] = [
  {
    id: 'unknown',
    tier: 'muted',
    name: 'Unknown',
    desc: 'Newly added · no checks yet',
    hosts: 0,
    intervalMin: 0,
    rangeText: '0–60 min',
    cadenceText: () => 'Immediate',
  },
  {
    id: 'online',
    tier: 'ok',
    name: 'Online',
    desc: 'Healthy · 0 failures',
    hosts: 2,
    intervalMin: 15,
    rangeText: '5–60 min',
    cadenceText: (m) => `Every ${m} min`,
  },
  {
    id: 'degraded',
    tier: 'info',
    name: 'Degraded',
    desc: '1 consecutive failure',
    hosts: 0,
    intervalMin: 5,
    rangeText: '1–15 min',
    cadenceText: (m) => `Every ${m} min`,
  },
  {
    id: 'crit-conn',
    tier: 'warn',
    name: 'Critical',
    desc: '2 consecutive failures',
    hosts: 0,
    intervalMin: 2,
    rangeText: '1–10 min',
    cadenceText: (m) => `Every ${m} min`,
  },
  {
    id: 'down',
    tier: 'crit',
    name: 'Down',
    desc: '3+ consecutive failures',
    hosts: 5,
    intervalMin: 30,
    rangeText: '10–120 min',
    cadenceText: (m) => `Every ${m} min`,
  },
  {
    id: 'maint-conn',
    tier: 'muted',
    name: 'Maintenance',
    desc: 'Manually paused by an operator',
    hosts: 0,
    intervalMin: 60,
    rangeText: '15 min – 24h',
    cadenceText: (m) => (m >= 60 ? `Every ${Math.round(m / 60)}h` : `Every ${m} min`),
  },
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

// ─────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────

export function ScanningPage() {
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);
  useEffect(() => {
    setCrumbs([{ label: 'Settings' }, { label: 'Scanning & monitoring' }]);
    return () => setCrumbs([]);
  }, [setCrumbs]);

  // Master state for each section.
  const [complianceRows, setComplianceRows] = useState(COMPLIANCE_DEFAULTS);
  const [complianceEnabled, setComplianceEnabled] = useState(true);
  const [complianceAdvancedOpen, setComplianceAdvancedOpen] = useState(false);

  const [connectivityRows, setConnectivityRows] = useState(CONNECTIVITY_DEFAULTS);
  const [connectivityEnabled, setConnectivityEnabled] = useState(true);
  const [connectivityAdvancedOpen, setConnectivityAdvancedOpen] = useState(false);
  const [maintenanceBehavior, setMaintenanceBehavior] = useState('reduced-60');
  const [networkRateLimit, setNetworkRateLimit] = useState(25);

  const [nightlyRescan, setNightlyRescan] = useState(true);
  const [detectOnFirstContact, setDetectOnFirstContact] = useState(true);

  const [globalMaintenance, setGlobalMaintenance] = useState(false);
  const [autoResume, setAutoResume] = useState('4h');
  const [groupMaintenance, setGroupMaintenance] = useState(
    () => Object.fromEntries(GROUPS.map((g) => [g.id, g.paused])) as Record<string, boolean>,
  );

  // Detect any "edits" — bare-bones dirty flag for the save bar.
  const dirty = useMemo(() => {
    return (
      JSON.stringify(complianceRows) !== JSON.stringify(COMPLIANCE_DEFAULTS) ||
      JSON.stringify(connectivityRows) !== JSON.stringify(CONNECTIVITY_DEFAULTS) ||
      !complianceEnabled ||
      !connectivityEnabled ||
      !nightlyRescan ||
      !detectOnFirstContact ||
      globalMaintenance ||
      maintenanceBehavior !== 'reduced-60' ||
      networkRateLimit !== 25 ||
      autoResume !== '4h' ||
      Object.entries(groupMaintenance).some(
        ([id, v]) => v !== (GROUPS.find((g) => g.id === id)?.paused ?? false),
      )
    );
  }, [
    complianceRows,
    connectivityRows,
    complianceEnabled,
    connectivityEnabled,
    nightlyRescan,
    detectOnFirstContact,
    globalMaintenance,
    maintenanceBehavior,
    networkRateLimit,
    autoResume,
    groupMaintenance,
  ]);

  const resetAll = () => {
    setComplianceRows(COMPLIANCE_DEFAULTS);
    setConnectivityRows(CONNECTIVITY_DEFAULTS);
    setComplianceEnabled(true);
    setConnectivityEnabled(true);
    setNightlyRescan(true);
    setDetectOnFirstContact(true);
    setGlobalMaintenance(false);
    setMaintenanceBehavior('reduced-60');
    setNetworkRateLimit(25);
    setAutoResume('4h');
    setGroupMaintenance(
      Object.fromEntries(GROUPS.map((g) => [g.id, g.paused])) as Record<string, boolean>,
    );
  };

  return (
    <SettingsLayout>
      <PageHead
        title="Scanning & monitoring"
        description="Control how often OpenWatch scans hosts for compliance and probes them for connectivity. Both schedulers adapt cadence based on host state."
        actions={
          <Btn onClick={resetAll}>
            <RotateCcw size={14} /> Reset to defaults
          </Btn>
        }
      />

      <BackendPendingBanner
        slice="Slice B (scheduler API)"
        text="UI is fully wired; values are local until POST /api/v1/scheduler/config ships."
      />

      {/* ────────── Compliance scanner ────────── */}
      <Section title="Compliance scanner" badge="Running" badgeTier="ok">
        <p style={leadStyle}>
          Re-runs the active CIS / STIG profile against each host. Cadence is set per
          compliance state — failing hosts get re-checked more often.
        </p>

        <SchedSummary
          icon={<Shield size={18} />}
          iconTier="info"
          title="Automatic compliance scanning"
          subtitle="Hard ceiling of 48h per host even when state hasn't changed"
          rightLabel="Next scan"
          rightValue="in 2 min · 5 hosts queued"
          toggleValue={complianceEnabled}
          onToggleChange={setComplianceEnabled}
        />

        <ScheduleStrip
          title="What this will run · next 24 hours"
          schedule={complianceRows.map((r) => ({
            intervalMin: r.intervalMin,
            color: tierToColorVar(r.tier),
            hosts: r.hosts,
          }))}
          legend={complianceRows.map((r) => ({
            color: tierToColorVar(r.tier),
            label: `${r.name} · ${formatCadence(r.intervalMin)}`,
          }))}
        />

        <StateTable
          rows={complianceRows}
          onIntervalChange={(idx, v) => {
            setComplianceRows((rows) =>
              rows.map((r, i) => (i === idx ? { ...r, intervalMin: v } : r)),
            );
          }}
        />

        <AdvancedDisclosure
          label="Advanced — quiet hours, jitter, retry policy"
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
                    { value: '22-06', label: '22:00 – 06:00' },
                  ]}
                />
              }
            />
            <SettingRow
              name="Jitter window"
              description="Random delay added per scan to avoid synchronized fleet pulses."
              control={<Stepper value={5} min={0} max={30} step={1} unit="min" onChange={() => {}} />}
            />
            <SettingRow
              name="Retry on transient failure"
              description="Apply the C-05 backoff ladder after a transient executor error."
              control={<Toggle value={true} onChange={() => {}} />}
            />
          </SettingCard>
        </AdvancedDisclosure>
      </Section>

      {/* ────────── Host connectivity monitor ────────── */}
      <Section title="Host connectivity monitor" badge="Running" badgeTier="ok">
        <p style={leadStyle}>
          Pings each host over SSH to confirm it's reachable. Frequency increases with
          consecutive failures.
        </p>

        <SchedSummary
          icon={<Activity size={18} />}
          iconTier="ok"
          title="Adaptive health checks"
          subtitle="2 online · 5 down · backs off automatically during maintenance"
          rightLabel="Last sweep"
          rightValue="38 sec ago"
          toggleValue={connectivityEnabled}
          onToggleChange={setConnectivityEnabled}
        />

        <StateTable
          rows={connectivityRows}
          onIntervalChange={(idx, v) => {
            setConnectivityRows((rows) =>
              rows.map((r, i) => (i === idx ? { ...r, intervalMin: v } : r)),
            );
          }}
          headers={['Host state', 'Hosts', 'Check every', 'Range']}
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
                  Maintenance mode behavior{' '}
                  <HelpCircle
                    size={13}
                    color="var(--ow-fg-3)"
                    aria-label="What OpenWatch does when an operator pauses a host"
                  />
                </>
              }
              description="When a host is put into maintenance, choose whether to keep checking it at a reduced cadence or pause entirely."
              control={
                <Select
                  value={maintenanceBehavior}
                  onChange={setMaintenanceBehavior}
                  options={[
                    { value: 'reduced-60', label: 'Reduced checks · 60 min' },
                    { value: 'pause', label: 'Pause checks entirely' },
                    { value: 'normal', label: 'Continue normal cadence' },
                  ]}
                  width={200}
                />
              }
            />
            <SettingRow
              name="Network rate limit"
              description="Cap concurrent SSH connections to prevent flooding during fleet-wide sweeps."
              control={
                <Stepper
                  value={networkRateLimit}
                  onChange={setNetworkRateLimit}
                  min={1}
                  max={200}
                  step={1}
                  unit="conns"
                />
              }
            />
          </SettingCard>
        </div>

        <AdvancedDisclosure
          label="Advanced — failure thresholds, jitter window, alert routing"
          open={connectivityAdvancedOpen}
          onToggle={() => setConnectivityAdvancedOpen((v) => !v)}
        >
          <SettingCard>
            <FirstSettingRow
              name="Failures before degraded"
              description="Consecutive failed probes that move a host into Degraded state."
              control={<Stepper value={1} min={1} max={5} step={1} onChange={() => {}} />}
            />
            <SettingRow
              name="Failures before down"
              description="Consecutive failed probes that move a host into Down state."
              control={<Stepper value={3} min={1} max={10} step={1} onChange={() => {}} />}
            />
            <SettingRow
              name="Probe jitter"
              description="Spread probe timing to prevent network synchronisation."
              control={<Stepper value={3} min={0} max={30} step={1} unit="sec" onChange={() => {}} />}
            />
          </SettingCard>
        </AdvancedDisclosure>
      </Section>

      {/* ────────── OS discovery ────────── */}
      <Section title="OS discovery" badge="Scheduled daily" badgeTier="ok">
        <p style={leadStyle}>
          Detects OS family, version, and platform on each host. Runs once on host
          registration, then nightly for anything still missing.
        </p>

        <SettingCard>
          <FirstSettingRow
            name="Nightly re-scan"
            description={
              <>
                Sweeps any host with missing platform data. Runs at{' '}
                <code style={{ fontFamily: 'var(--ow-font-mono)' }}>02:00 UTC</code>.
              </>
            }
            control={
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <Btn size="sm">
                  <PlayCircle size={12} />
                  Run now
                </Btn>
                <Toggle value={nightlyRescan} onChange={setNightlyRescan} ariaLabel="Nightly re-scan" />
              </div>
            }
          />
          <SettingRow
            name="Detect on first contact"
            description={
              <>
                Always run platform detection when a host is added with credentials.{' '}
                <em style={{ color: 'var(--ow-fg-3)' }}>Recommended.</em>
              </>
            }
            control={
              <Toggle
                value={detectOnFirstContact}
                onChange={setDetectOnFirstContact}
                ariaLabel="Detect on first contact"
              />
            }
          />
          <SettingRow
            name="Just-in-time detection"
            description={
              <>
                Re-detect during a scan if the recorded platform looks wrong.{' '}
                <em style={{ color: 'var(--ow-fg-3)' }}>Always on.</em>
              </>
            }
            control={<Toggle value={true} onChange={() => {}} disabled />}
          />
        </SettingCard>
      </Section>

      {/* ────────── Maintenance ────────── */}
      <Section title="Maintenance">
        <p style={leadStyle}>
          Pause scanning, connectivity checks, and alerting — fleet-wide, per group, or per
          host. A host is in maintenance if <strong>global</strong>,{' '}
          <strong>any of its groups</strong>, or the <strong>host itself</strong> is paused.
        </p>

        <div style={{ marginBottom: 14 }}>
          <SettingCard>
            <FirstSettingRow
              name={
                <>
                  Global maintenance mode{' '}
                  <HelpCircle size={13} color="var(--ow-fg-3)" aria-label="Silences the entire fleet" />
                </>
              }
              description={
                <>
                  Pause <strong>all</strong> scanning and alerting across every host. Use during
                  planned infrastructure-wide work.{' '}
                  <span style={{ color: 'var(--ow-warn)' }}>
                    Nothing is monitored while this is on.
                  </span>
                </>
              }
              control={
                <Toggle
                  value={globalMaintenance}
                  onChange={setGlobalMaintenance}
                  ariaLabel="Global maintenance mode"
                />
              }
            />
            <SettingRow
              name="Auto-resume"
              description="Automatically lift global maintenance after a set duration, so it can't be left on by accident."
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
        </div>

        <div style={{ marginBottom: 14 }}>
          <Callout tier="info">
            <strong style={{ color: 'var(--ow-fg-0)' }}>Precedence is OR, not override.</strong>{' '}
            Putting a group into maintenance pauses every host in it, even if the host's own
            toggle is off. Each host shows <em>why</em> it's paused (global, a group name, or
            direct).
          </Callout>
        </div>

        <h3
          style={{
            margin: '0 0 10px',
            fontSize: 13,
            color: 'var(--ow-fg-2)',
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            fontWeight: 600,
          }}
        >
          Group maintenance
        </h3>
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

      {/* Save bar */}
      {dirty && <SaveBar onReset={resetAll} />}
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
}: {
  rows: StateRowConfig[];
  headers?: [string, string, string, string];
  onIntervalChange: (idx: number, v: number) => void;
  rightColumnRenderer?: (r: StateRowConfig) => React.ReactNode;
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
}: {
  row: StateRowConfig;
  isFirst: boolean;
  onIntervalChange: (v: number) => void;
  rightColumn?: React.ReactNode;
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
        {row.hosts === 1 ? 'host' : row.hosts === 0 ? 'hosts' : 'of 7 hosts'}
      </div>
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <Stepper
          value={row.intervalMin}
          onChange={onIntervalChange}
          min={0}
          max={1440 * 7}
          step={row.intervalMin >= 60 ? 30 : 1}
          unit="min"
        />
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
// Schedule strip — 24h visualization with pulses per state
// ─────────────────────────────────────────────────────────────────────────

interface ScheduleEntry {
  intervalMin: number;
  color: string;
  hosts: number;
}

function ScheduleStrip({
  title,
  schedule,
  legend,
}: {
  title: string;
  schedule: ScheduleEntry[];
  legend: { color: string; label: string }[];
}) {
  const WIDTH_MIN = 24 * 60; // 24 hours
  return (
    <div
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: '16px 20px',
        marginBottom: 14,
      }}
    >
      <h4
        style={{
          margin: '0 0 12px',
          fontSize: 12,
          color: 'var(--ow-fg-2)',
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          fontWeight: 600,
        }}
      >
        {title}
      </h4>
      <div
        style={{
          position: 'relative',
          height: 64,
          background: 'var(--ow-bg-2)',
          borderRadius: 6,
          overflow: 'hidden',
          border: '1px solid var(--ow-line)',
        }}
      >
        {schedule.map((s, laneIdx) => (
          <div
            key={laneIdx}
            style={{
              position: 'absolute',
              left: 0,
              right: 0,
              top: 8 + laneIdx * 9,
              height: 6,
            }}
          >
            {s.intervalMin > 0 &&
              Array.from({ length: Math.floor(WIDTH_MIN / s.intervalMin) + 1 }, (_, i) => i).map(
                (i) => {
                  const t = i * s.intervalMin;
                  return (
                    <span
                      key={i}
                      style={{
                        position: 'absolute',
                        left: `calc(${(t / WIDTH_MIN) * 100}% - 1px)`,
                        top: 0,
                        height: '100%',
                        width: 1.5,
                        background: s.color,
                        opacity: s.hosts > 0 ? 1 : 0.25,
                        borderRadius: 1,
                      }}
                    />
                  );
                },
              )}
          </div>
        ))}
        <div
          style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            alignItems: 'flex-end',
            paddingBottom: 4,
            pointerEvents: 'none',
          }}
        >
          {['now', '+4h', '+8h', '+12h', '+16h', '+20h'].map((t, i) => (
            <span
              key={t}
              style={{
                flex: 1,
                textAlign: 'center',
                color: 'var(--ow-fg-3)',
                fontSize: 10,
                fontFamily: 'var(--ow-font-mono)',
                borderLeft:
                  i === 0
                    ? 'none'
                    : '1px solid color-mix(in oklab, var(--ow-line) 50%, transparent)',
              }}
            >
              {t}
            </span>
          ))}
        </div>
      </div>
      <div style={{ display: 'flex', gap: 16, marginTop: 10, flexWrap: 'wrap' }}>
        {legend.map((entry, i) => (
          <span
            key={i}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              color: 'var(--ow-fg-2)',
              fontSize: 12,
            }}
          >
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: 2,
                background: entry.color,
              }}
            />
            {entry.label}
          </span>
        ))}
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
        <Btn size="sm">Schedule window</Btn>
        <Toggle value={paused} onChange={onPauseChange} ariaLabel={`Pause ${name}`} />
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Save bar — sticky footer that appears when there are unsaved edits
// ─────────────────────────────────────────────────────────────────────────

function SaveBar({ onReset }: { onReset: () => void }) {
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
          Persisting requires the scheduler config endpoint (Slice B).
        </span>
      </div>
      <Btn onClick={onReset}>Discard</Btn>
      <Btn variant="primary" disabled>
        Save changes
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
