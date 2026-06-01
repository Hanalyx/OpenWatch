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
import { useAuthStore } from '@/store/useAuthStore';
import { osDisplayLabel } from '@/utils/osLabel';
import { formatUptime } from '@/utils/formatUptime';

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

interface CardSystemProps {
  host: CardSystemHost;
  /** snapshot field of IntelligenceState; null when no IntelligenceState row exists yet. */
  intelligenceSnapshot: Record<string, unknown> | null;
}

const UNREACHABLE_MSG = 'Host unreachable — check SSH credentials and connectivity';

export function CardSystem({ host, intelligenceSnapshot }: CardSystemProps) {
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
      const { response, error: apiErr } = await api.POST(
        '/api/v1/hosts/{id}/discovery:run',
        {
          params: {
            path: { id: host.id },
            header: { 'Idempotency-Key': idempotencyKey },
          },
        },
      );
      if (!response.ok) {
        if (response.status === 502) {
          setError(UNREACHABLE_MSG);
          return;
        }
        if (response.status === 403) {
          setError('Permission denied');
          return;
        }
        const env = apiErr as { error?: { message?: string } } | undefined;
        setError(env?.error?.message ?? `HTTP ${response.status}`);
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

  return (
    <Card title="System">
      <SpecGroup title="Operating system">
        {isDiscovered ? (
          <DefList
            rows={[
              ['Distribution', <span key="d">{distribution}</span>],
              [
                'Kernel',
                <span key="k" style={{ fontFamily: 'var(--ow-font-mono)' }}>
                  {kernelRelease ?? '—'}
                </span>,
              ],
              [
                'FQDN',
                <span key="f" style={{ fontFamily: 'var(--ow-font-mono)' }}>
                  {host.hostname}
                </span>,
              ],
              ['Uptime', <span key="u">{formatUptime(uptimeSeconds)}</span>],
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
        <EmptyState
          primary="Hardware metrics not collected"
          secondary="Populated by Server Intelligence (CPU / disk / memory). Deferred — see BACKLOG."
          compact
        />
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
            ['Firewall', <span key="fw">—</span>],
          ]}
        />
      </SpecGroup>
    </Card>
  );
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

function pickString(snap: Record<string, unknown> | null, key: string): string | null {
  if (!snap) return null;
  const v = snap[key];
  return typeof v === 'string' && v.length > 0 ? v : null;
}

function pickNumber(snap: Record<string, unknown> | null, key: string): number | null {
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
