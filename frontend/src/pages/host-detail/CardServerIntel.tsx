// CardServerIntel — Host detail "Server intelligence" 2×3 stat grid.
//
// v2.0.0 of frontend-host-detail-intelligence-feed pivots this card
// away from the per-host event feed it shipped as in v1.0.0. The
// snapshot rollup answers the question operators actually ask on the
// overview page — "what is currently TRUE about this host" — not
// "what changed last cycle". The deltas live on the cross-host
// /activity page.
//
// Data source: GET /api/v1/intelligence/state/{host_id}, which
// returns the latest host_intelligence_state row's snapshot. 404
// means the host has never run an Intelligence cycle and the empty
// state names the collector so the operator knows where to look.
//
// Spec: frontend-host-detail-intelligence-feed v2.0.0.

import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { RefreshCw } from 'lucide-react';
import api from '@/api/client';
import { useHostExceptions } from '@/hooks/useHostExceptions';

// Snapshot keys mirror collector.Snapshot (Go struct in
// internal/intelligence/collector/types.go). additionalProperties is
// true on the OpenAPI side; we keep this interface narrow to the
// fields the card actually consumes so the type stays load-bearing.
//
// The snapshot is the BARE intelligence map (no envelope) — that
// shape matches the existing intelligenceStateQuery in
// HostDetailPage.tsx:285 which returns raw.snapshot ?? null. The two
// queries share queryKey ['intelligence_state', hostId] so they MUST
// agree on the cached value's shape; previously this card unwrapped
// query.data.snapshot expecting the envelope and rendered "Not
// collected yet" against every host because the cache returned the
// already-unwrapped map and .snapshot was undefined.
//
// `collected_at` is duplicated inside the snapshot (collector emits
// it as a snapshot key), so the header timestamp still works without
// needing the envelope.
export interface IntelligenceSnapshot {
  packages?: Record<string, string>;
  services?: Record<string, string>; // unit → "active" | "inactive" | "failed"
  users?: Record<string, unknown>;
  groups?: Record<string, string[]>;
  network_interfaces?: unknown[];
  listening_ports?: unknown[];
  firewall_rule_count?: number | null;
  collected_at?: string;
}

interface CardServerIntelProps {
  hostId: string;
}

export function CardServerIntel({ hostId }: CardServerIntelProps) {
  // Spec C-01 + C-02: single snapshot endpoint, query key matches
  // useLiveEvents.ts intelligence.event invalidation target AND
  // HostDetailPage's intelligenceStateQuery — sharing the cache
  // means just one network round-trip per host-detail render.
  const query = useQuery({
    queryKey: ['intelligence_state', hostId],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/intelligence/state/{host_id}', {
        params: { path: { host_id: hostId } },
      });
      if (response.status === 404) return null;
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      if (error) throw new Error('intelligence_state fetch failed');
      const raw = data as unknown as { snapshot?: IntelligenceSnapshot } | null;
      return raw?.snapshot ?? null;
    },
    retry: false,
  });

  // Open-exceptions tile data comes from the exception governance
  // service, not the intel snapshot (overlay model). Shared query key
  // with the Watchlist tile = one round-trip.
  const exc = useHostExceptions(hostId);

  // 404 → query.data === null (resolved success), the view renders the
  // "Not collected yet" empty state below.
  return (
    <CardServerIntelView
      isLoading={query.isLoading}
      isError={query.isError}
      notFound={!query.isLoading && !query.isError && query.data === null}
      snapshot={query.data ?? undefined}
      collectedAt={query.data?.collected_at}
      onRetry={() => query.refetch()}
      activeExceptions={exc.activeCount}
    />
  );
}

// Pure view component — tests mount it with explicit state without
// needing to stub useQuery internals. Spec AC-03..AC-08 exercise
// this directly.
export interface CardServerIntelViewProps {
  isLoading: boolean;
  isError: boolean;
  notFound: boolean;
  snapshot?: IntelligenceSnapshot;
  collectedAt?: string;
  onRetry: () => void;
  // Active (approved, unexpired) exception count for the Open
  // exceptions tile. Undefined renders the dash placeholder.
  activeExceptions?: number;
}

export function CardServerIntelView({
  isLoading,
  isError,
  notFound,
  snapshot,
  collectedAt,
  onRetry,
  activeExceptions,
}: CardServerIntelViewProps) {
  let body: React.ReactNode;
  if (isLoading) {
    body = (
      <div role="status" style={{ color: 'var(--ow-fg-2)', fontSize: 12 }}>
        Loading…
      </div>
    );
  } else if (notFound) {
    body = (
      <EmptyState
        primary="Not collected yet"
        secondary="The OS Intelligence collector populates this snapshot on each cycle (packages, services, users, network, firewall). Once the host runs Discovery and the first Intelligence cycle completes, these tiles will fill in."
      />
    );
  } else if (isError) {
    body = <ErrorState onRetry={onRetry} />;
  } else if (snapshot) {
    body = <TileGrid snapshot={snapshot} activeExceptions={activeExceptions} />;
  } else {
    // Defensive: success with null body — render as empty.
    body = (
      <EmptyState
        primary="Not collected yet"
        secondary="The OS Intelligence collector has not populated a snapshot for this host."
      />
    );
  }

  return (
    <Card title="Server intelligence" right={collectedAt ? collectedLabel(collectedAt) : undefined}>
      {body}
    </Card>
  );
}

// ── Tile grid ─────────────────────────────────────────────────────────────

function TileGrid({
  snapshot,
  activeExceptions,
}: {
  snapshot: IntelligenceSnapshot;
  activeExceptions?: number;
}) {
  const packagesCount = Object.keys(snapshot.packages ?? {}).length;
  const services = snapshot.services ?? {};
  const servicesTotal = Object.keys(services).length;
  const servicesRunning = Object.values(services).filter((s) => s === 'active').length;
  const usersCount = Object.keys(snapshot.users ?? {}).length;
  const sudoCount = countSudoUsers(snapshot.users, snapshot.groups);
  const interfacesCount = (snapshot.network_interfaces ?? []).length;
  const listeningPorts = (snapshot.listening_ports ?? []).length;
  const fwCount = snapshot.firewall_rule_count;
  const firewall = firewallSubline(fwCount);

  return (
    <div
      role="list"
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
        gap: 16,
      }}
    >
      <Tile label="Packages installed" value={packagesCount} subline="No updates pending" />
      <Tile
        label="Running services"
        value={
          servicesTotal === 0 ? (
            '—'
          ) : (
            <>
              {servicesRunning}
              <span style={{ color: 'var(--ow-fg-3)', fontSize: 16, fontWeight: 400 }}>
                {' / '}
                {servicesTotal}
              </span>
            </>
          )
        }
        subline={
          servicesTotal === 0
            ? 'No services registered'
            : `${Math.round((servicesRunning / servicesTotal) * 100)}% of registered services`
        }
      />
      <Tile
        label="User accounts"
        value={usersCount}
        subline={`${sudoCount} with sudo privileges`}
      />
      <Tile
        label="Network interfaces"
        value={interfacesCount}
        subline={`${listeningPorts} listening ports`}
      />
      <Tile
        label="Firewall rules"
        value={firewall.value}
        subline={firewall.subline}
        sublineTone={firewall.tone}
      />
      <Tile
        label="Open exceptions"
        value={activeExceptions === undefined ? '—' : String(activeExceptions)}
        subline={
          activeExceptions
            ? `${activeExceptions} rule${activeExceptions === 1 ? '' : 's'} waived`
            : 'No rules suppressed'
        }
      />
    </div>
  );
}

function Tile({
  label,
  value,
  subline,
  sublineTone = 'neutral',
}: {
  label: string;
  value: React.ReactNode;
  subline: string;
  sublineTone?: 'neutral' | 'warn';
}) {
  return (
    <div
      role="listitem"
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 4,
        minWidth: 0,
      }}
    >
      <div
        style={{
          color: 'var(--ow-fg-3)',
          fontSize: 11,
          textTransform: 'uppercase',
          letterSpacing: '0.04em',
        }}
      >
        {label}
      </div>
      <div
        style={{
          color: 'var(--ow-fg-0)',
          fontSize: 28,
          fontWeight: 600,
          lineHeight: 1.1,
          fontVariantNumeric: 'tabular-nums',
        }}
      >
        {value}
      </div>
      <div
        style={{
          color: sublineTone === 'warn' ? 'var(--ow-warn)' : 'var(--ow-fg-3)',
          fontSize: 12,
          marginTop: 2,
        }}
      >
        {subline}
      </div>
    </div>
  );
}

// ── Derivations ───────────────────────────────────────────────────────────

// countSudoUsers — set-union of sudo / wheel / admin group members,
// intersected with snapshot.users keys so we never report a stale
// group entry for a user that has been removed. Spec C-05.
export function countSudoUsers(
  users: Record<string, unknown> | undefined,
  groups: Record<string, string[]> | undefined,
): number {
  if (!users || !groups) return 0;
  const userSet = new Set(Object.keys(users));
  const sudoers = new Set<string>();
  for (const g of ['sudo', 'wheel', 'admin']) {
    const members = groups[g];
    if (!members) continue;
    for (const m of members) {
      if (userSet.has(m)) sudoers.add(m);
    }
  }
  return sudoers.size;
}

interface FirewallSubline {
  value: React.ReactNode;
  subline: string;
  tone: 'neutral' | 'warn';
}

// firewallSubline — closed mapping of firewall_rule_count states.
// Spec C-06, AC-07.
export function firewallSubline(fwCount: number | null | undefined): FirewallSubline {
  if (fwCount == null) {
    return { value: '—', subline: 'Not collected', tone: 'neutral' };
  }
  if (fwCount === -1) {
    return { value: '—', subline: 'No firewall detected', tone: 'neutral' };
  }
  if (fwCount === 0) {
    return { value: 0, subline: 'Firewall is inactive', tone: 'warn' };
  }
  return { value: fwCount, subline: `${fwCount} rules active`, tone: 'neutral' };
}

// collectedLabel — "Collected 4/19/2026 · 2:36 PM" style timestamp
// surfaced in the card header. Matches the mockup.
function collectedLabel(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const date = d.toLocaleDateString(undefined, {
    month: 'numeric',
    day: 'numeric',
    year: 'numeric',
  });
  const time = d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
  return `Collected ${date} · ${time}`;
}

// ── Visual primitives ─────────────────────────────────────────────────────

function ErrorState({ onRetry }: { onRetry: () => void }) {
  return (
    <div
      role="alert"
      style={{
        color: 'var(--ow-crit)',
        fontSize: 12,
        display: 'flex',
        gap: 8,
        alignItems: 'center',
      }}
    >
      Failed to load intelligence snapshot{' '}
      <button
        type="button"
        onClick={onRetry}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 4,
          padding: '2px 8px',
          background: 'transparent',
          color: 'var(--ow-fg-2)',
          border: '1px solid var(--ow-line)',
          borderRadius: 4,
          fontSize: 11,
          cursor: 'pointer',
        }}
      >
        <RefreshCw size={11} /> Retry
      </button>
    </div>
  );
}

function Card({
  title,
  right,
  children,
}: {
  title: string;
  right?: string;
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
          marginBottom: 16,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'baseline',
          gap: 12,
        }}
      >
        <h3 style={{ margin: 0, fontSize: 14, fontWeight: 600 }}>{title}</h3>
        {right ? <span style={{ color: 'var(--ow-fg-3)', fontSize: 11 }}>{right}</span> : null}
      </header>
      <div>{children}</div>
    </section>
  );
}

function EmptyState({ primary, secondary }: { primary: string; secondary: string }) {
  return (
    <div
      role="status"
      style={{
        padding: '20px 0',
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
