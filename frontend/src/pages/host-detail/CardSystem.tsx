// CardSystem — Host detail right-rail "System" card.
//
// Replaces the prior "unknown / unknown / unknown / unknown" placeholder
// rows with real data sourced from:
//
//   • HostResponse (denormalized hosts.os_family / os_version) — populated
//     by system-host-discovery via Kensa, exposed by api-hosts v1.4.0.
//   • IntelligenceState.snapshot.kernel_release + uptime_seconds —
//     populated by the scheduled intelligence cycle (api-os-intelligence).
//
// Pre-Discovery hosts (os_family null AND no IntelligenceState row)
// collapse to a single "Not discovered yet" empty state with a Re-run
// Discovery button (gated on host:write).
//
// Spec: frontend-host-detail-system-card v1.0.0.

import React, { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { RefreshCw } from 'lucide-react';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useAuthStore } from '@/store/useAuthStore';
import { osDisplayLabel } from '@/utils/osLabel';
import { formatUptime } from '@/utils/formatUptime';
import { stripKernelDistroSuffix } from '@/utils/kernelVersion';

// Minimal host shape needed by CardSystem. Mirrors the relevant subset
// of HostResponse — declared inline so the card stays testable without
// pulling in the full page-level type.
export interface CardSystemHost {
  id: string;
  hostname: string;
  ip_address: string;
  port?: number;
  username?: string;
  os_family?: string | null;
  os_version?: string | null;
}

// Per-category collection freshness. Mirrors the API CategoryFreshness map
// (system-host-discovery v1.6.0). status=stale means the value shown was
// carried forward from an earlier successful run — the most recent Discovery
// did not re-observe this category (SSH degraded, sudo denied, probe failed).
export interface CategoryFreshness {
  status: 'ok' | 'stale';
  observed_at: string;
  attempt_at: string;
}

// Subset of HostSystemInfo we render. Mirrors the API schema column
// names; null fields tolerate partial-collection rows (sudo unavailable,
// older snapshots).
export interface CardSystemInfo {
  architecture?: string | null;
  fqdn?: string | null;
  os_pretty_name?: string | null;
  mem_total_mb?: number | null;
  disk_total_gb?: number | null;
  disk_used_gb?: number | null;
  firewall_service?: string | null;
  firewall_status?: string | null;
  collected_at?: string;
  category_freshness?: Record<string, CategoryFreshness> | null;
}

interface CardSystemProps {
  host: CardSystemHost;
  /** snapshot field of IntelligenceState; null when no IntelligenceState row exists yet. */
  intelligenceSnapshot: Record<string, unknown> | null;
  /** Latest host_system_info row; null when no Discovery has run for this host. */
  systemInfo: CardSystemInfo | null;
}

const UNREACHABLE_MSG = 'Host unreachable — check SSH credentials and connectivity';

export function CardSystem({ host, intelligenceSnapshot, systemInfo }: CardSystemProps) {
  const canWrite = useAuthStore((s) => s.hasPermission('host:write'));
  const queryClient = useQueryClient();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Spec C-02: a host is "discovered" once Discovery has populated the
  // denormalized OS columns. Pre-Discovery → single empty state.
  const isDiscovered = !!host.os_family || !!host.os_version;

  // Pluck the two snapshot fields we render (kernel_release, uptime_seconds).
  const kernelRelease = pickString(intelligenceSnapshot, 'kernel_release');
  const uptimeSeconds = pickNumber(intelligenceSnapshot, 'uptime_seconds');

  const distribution = isDiscovered
    ? `${osDisplayLabel(host.os_family)}${host.os_version ? ` ${host.os_version}` : ''}`
    : null;

  async function onRerunDiscovery() {
    if (pending) return;
    setPending(true);
    setError(null);
    try {
      const idempotencyKey = crypto.randomUUID();
      const { response, error: apiErr } = await api.POST('/api/v1/hosts/{id}/discovery:run', {
        params: {
          path: { id: host.id },
          header: { 'Idempotency-Key': idempotencyKey },
        },
      });
      if (!response.ok) {
        if (response.status === 502) {
          setError(UNREACHABLE_MSG);
          return;
        }
        if (response.status === 403) {
          setError('Permission denied');
          return;
        }
        setError(apiErrorMessage(apiErr, `HTTP ${response.status}`));
        return;
      }
      // Spec C-05: both queries must refresh — denormalized OS fields
      // came from HostResponse, kernel/uptime from IntelligenceState.
      queryClient.invalidateQueries({ queryKey: ['host', host.id] });
      queryClient.invalidateQueries({ queryKey: ['intelligence_state', host.id] });
    } catch (e) {
      setError((e as Error)?.message ?? 'Network error');
    } finally {
      setPending(false);
    }
  }

  // Prefer the richer os_pretty_name from host_system_info when present
  // (e.g. "Red Hat Enterprise Linux 9.7 (Plow)"); fall back to the
  // denormalized hosts.os_family + os_version pair so pre-system-info
  // hosts still render.
  const distributionDisplay = systemInfo?.os_pretty_name || distribution;
  const fqdnDisplay = systemInfo?.fqdn || host.hostname;

  return (
    <Card title="System">
      <SpecGroup title="Operating system">
        {isDiscovered ? (
          <DefList
            rows={[
              [
                'Distribution',
                <div key="d">
                  <div>{distributionDisplay}</div>
                  {systemInfo?.architecture && (
                    <div style={subValueStyle}>{systemInfo.architecture}</div>
                  )}
                  <StaleNote freshness={systemInfo?.category_freshness} category="os_release" />
                </div>,
              ],
              [
                'Kernel',
                <span key="k" style={{ fontFamily: 'var(--ow-font-mono)' }}>
                  {kernelRelease ? stripKernelDistroSuffix(kernelRelease) : '—'}
                </span>,
              ],
              [
                'FQDN',
                <div key="f">
                  <span style={{ fontFamily: 'var(--ow-font-mono)' }}>{fqdnDisplay}</span>
                  <StaleNote freshness={systemInfo?.category_freshness} category="fqdn" />
                </div>,
              ],
              [
                'Uptime',
                <div key="u">
                  <div>{formatUptime(uptimeSeconds)}</div>
                  {uptimeSeconds !== null && (
                    <div style={subValueStyle}>Since {formatBootDate(uptimeSeconds)}</div>
                  )}
                </div>,
              ],
            ]}
          />
        ) : (
          <NotDiscoveredState
            canWrite={canWrite}
            pending={pending}
            error={error}
            onClick={onRerunDiscovery}
          />
        )}
      </SpecGroup>

      <SpecGroup title="Hardware">
        {systemInfo ? (
          <HardwareSection systemInfo={systemInfo} />
        ) : (
          <EmptyState
            primary="Hardware metrics not collected"
            secondary="Appears after the first Discovery run."
            compact
          />
        )}
      </SpecGroup>

      <SpecGroup title="Network">
        <DefList
          rows={[
            [
              'Primary IP',
              <span key="ip" style={{ fontFamily: 'var(--ow-font-mono)' }}>
                {host.ip_address}
              </span>,
            ],
            [
              'SSH endpoint',
              <span key="ssh" style={{ fontFamily: 'var(--ow-font-mono)' }}>
                {host.username ? `${host.username}@` : ''}
                {host.ip_address}:{host.port ?? 22}
              </span>,
            ],
            [
              'Firewall',
              <div key="fw">
                <FirewallStatus
                  status={systemInfo?.firewall_status ?? null}
                  service={systemInfo?.firewall_service ?? null}
                />
                <StaleNote freshness={systemInfo?.category_freshness} category="firewall" />
              </div>,
            ],
          ]}
        />
      </SpecGroup>
    </Card>
  );
}

// formatBootDate — uptime_seconds back-projected to a wall clock for
// the "Since YYYY-MM-DD, HH:MM" subtitle on the Uptime row. Uses the
// browser's local timezone so an operator's "since" matches what they'd
// see in their shell.
function formatBootDate(uptimeSeconds: number): string {
  const boot = new Date(Date.now() - uptimeSeconds * 1000);
  const date = boot.toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
  });
  const time = boot.toLocaleTimeString(undefined, {
    hour: 'numeric',
    minute: '2-digit',
  });
  return `${date}, ${time}`;
}

// HardwareSection renders CPU / Disk / Memory. CPU model + cores are
// not yet collected by Discovery (host_system_info has no cpu_*
// columns), so we surface an honest placeholder there. Disk + Memory
// come straight from host_system_info.
function HardwareSection({ systemInfo }: { systemInfo: CardSystemInfo }) {
  const diskTotal = systemInfo.disk_total_gb ?? null;
  const diskUsed = systemInfo.disk_used_gb ?? null;
  const diskPct =
    diskTotal !== null && diskUsed !== null && diskTotal > 0
      ? Math.min(100, Math.round((diskUsed / diskTotal) * 100))
      : null;
  const diskFree =
    diskTotal !== null && diskUsed !== null ? Math.max(0, diskTotal - diskUsed) : null;
  const memGb =
    systemInfo.mem_total_mb !== null && systemInfo.mem_total_mb !== undefined
      ? (systemInfo.mem_total_mb / 1024).toFixed(1)
      : null;

  return (
    <DefList
      rows={[
        [
          'CPU',
          <div key="cpu">
            <div style={{ color: 'var(--ow-fg-2)' }}>—</div>
            <div style={subValueStyle}>Hardware model not yet collected</div>
          </div>,
        ],
        [
          'Disk',
          <div key="disk">
            {diskTotal !== null && diskUsed !== null ? (
              <>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                  <DiskBar percent={diskPct ?? 0} />
                  <span style={{ fontFamily: 'var(--ow-font-mono)', whiteSpace: 'nowrap' }}>
                    {diskUsed}.0 / {diskTotal}.0 GB
                  </span>
                </div>
                {diskFree !== null && (
                  <div style={subValueStyle}>
                    {diskFree}.0 GB free · {diskPct ?? 0}% used
                  </div>
                )}
              </>
            ) : (
              <span style={{ color: 'var(--ow-fg-3)' }}>—</span>
            )}
            <StaleNote freshness={systemInfo.category_freshness} category="disk" />
          </div>,
        ],
        [
          'Memory',
          <div key="mem">
            <div style={{ fontFamily: 'var(--ow-font-mono)' }}>
              {memGb !== null ? `${memGb} GB` : '—'}
            </div>
            <div style={subValueStyle}>Live utilization not collected</div>
            <StaleNote freshness={systemInfo.category_freshness} category="memory" />
          </div>,
        ],
      ]}
    />
  );
}

function DiskBar({ percent }: { percent: number }) {
  // Color steps: green <60, amber 60-85, red >85. Matches the prototype's
  // intent of communicating headroom at a glance.
  const color =
    percent >= 85 ? 'var(--ow-crit)' : percent >= 60 ? 'var(--ow-warn)' : 'var(--ow-ok)';
  return (
    <div
      role="progressbar"
      aria-valuenow={percent}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={`Disk usage ${percent}%`}
      style={{
        flex: 1,
        height: 6,
        background: 'var(--ow-bg-3)',
        borderRadius: 3,
        overflow: 'hidden',
        alignSelf: 'center',
      }}
    >
      <div
        style={{
          width: `${percent}%`,
          height: '100%',
          background: color,
        }}
      />
    </div>
  );
}

function FirewallStatus({ status, service }: { status: string | null; service: string | null }) {
  if (!status) {
    return <span style={{ color: 'var(--ow-fg-3)' }}>—</span>;
  }
  const normalized = status.toLowerCase();
  const isActive = normalized === 'active' || normalized === 'enabled' || normalized === 'running';
  const label = isActive ? 'Active' : 'Inactive';
  const color = isActive ? 'var(--ow-ok)' : 'var(--ow-crit)';
  return (
    <div>
      <span style={{ color, fontWeight: 500 }}>{label}</span>
      {service && <div style={subValueStyle}>{service}</div>}
    </div>
  );
}

const subValueStyle: React.CSSProperties = {
  fontSize: 11,
  color: 'var(--ow-fg-3)',
  marginTop: 2,
};

// StaleNote — the honesty marker for "The Eye": when a rendered value was
// carried forward (the last Discovery did not re-observe this category), we
// tell the operator what they're looking at is last-known-good, not a fresh
// reading, and when it was last actually verified. An ok/absent category
// renders nothing (a fresh reading needs no caveat).
//
// `category` is a host_system_info freshness key: os_release, uname, memory,
// disk, hostname, fqdn, selinux, apparmor, firewall.
export function StaleNote({
  freshness,
  category,
}: {
  freshness: Record<string, CategoryFreshness> | null | undefined;
  category: string;
}) {
  const entry = freshness?.[category];
  if (!entry || entry.status !== 'stale') return null;
  return (
    <div
      style={{ ...subValueStyle, color: 'var(--ow-warn)' }}
      title={`Last verified ${entry.observed_at}`}
    >
      Last verified {formatTimeAgo(entry.observed_at)}
    </div>
  );
}

// formatTimeAgo — compact "Xm/Xh/Xd ago" from an ISO timestamp, for the
// stale-value caveat. Self-contained so CardSystem stays testable.
export function formatTimeAgo(iso: string): string {
  const then = new Date(iso).getTime();
  if (!Number.isFinite(then)) return 'earlier';
  const mins = Math.max(0, Math.round((Date.now() - then) / 60000));
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function NotDiscoveredState({
  canWrite,
  pending,
  error,
  onClick,
}: {
  canWrite: boolean;
  pending: boolean;
  error: string | null;
  onClick: () => void;
}) {
  return (
    <div
      role="status"
      style={{
        padding: '14px 0',
        textAlign: 'center',
        color: 'var(--ow-fg-2)',
      }}
    >
      <div style={{ color: 'var(--ow-fg-1)', fontSize: 13, fontWeight: 500, marginBottom: 4 }}>
        Not discovered yet
      </div>
      <div
        style={{
          fontSize: 11,
          color: 'var(--ow-fg-3)',
          maxWidth: 360,
          margin: '0 auto 10px',
          lineHeight: 1.5,
        }}
      >
        OS fingerprint, kernel, and uptime appear after the first Discovery run.
      </div>
      {canWrite && (
        <button
          type="button"
          onClick={onClick}
          disabled={pending}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            padding: '6px 12px',
            background: 'var(--ow-bg-2)',
            color: 'var(--ow-fg-1)',
            border: '1px solid var(--ow-line)',
            borderRadius: 6,
            fontSize: 12,
            cursor: pending ? 'wait' : 'pointer',
            opacity: pending ? 0.6 : 1,
          }}
        >
          <RefreshCw size={12} /> {pending ? 'Running…' : 'Re-run Discovery'}
        </button>
      )}
      {error && (
        <div
          role="alert"
          style={{
            color: 'var(--ow-crit)',
            fontSize: 11,
            marginTop: 8,
          }}
        >
          {error}
        </div>
      )}
    </div>
  );
}

// Exported so HostDetailPage's PageHead can read the same fields from
// the same intelligence_state query without duplicating the logic.
export function pickString(snap: Record<string, unknown> | null, key: string): string | null {
  if (!snap) return null;
  const v = snap[key];
  return typeof v === 'string' && v.length > 0 ? v : null;
}

export function pickNumber(snap: Record<string, unknown> | null, key: string): number | null {
  if (!snap) return null;
  const v = snap[key];
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

// ── Layout primitives ─────────────────────────────────────────────────────
// Inlined so CardSystem stays self-contained for testing. Behavior
// matches the page-local Card / SpecGroup / DefList / EmptyState
// exactly — moving them out of HostDetailPage in a follow-up would
// dedupe (BACKLOG).

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
        <React.Fragment key={k}>
          <dt style={{ color: 'var(--ow-fg-3)' }}>{k}</dt>
          <dd style={{ margin: 0, color: 'var(--ow-fg-1)', minWidth: 0 }}>{v}</dd>
        </React.Fragment>
      ))}
    </dl>
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
