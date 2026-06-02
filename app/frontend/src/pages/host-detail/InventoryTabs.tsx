// InventoryTabs — Packages / Services / Users / Network tab bodies
// for the host detail page. Each component reads from the
// IntelligenceState.snapshot passed down from HostDetailPage; none
// issues its own useQuery (spec C-01 — parent fetches once).
//
// Spec: frontend-host-detail-inventory-tabs v1.0.0.

import React, { useMemo, useState } from 'react';

// Shape of the snapshot fields these tabs render. Each is optional
// because pre-cycle hosts have an empty snapshot OR no snapshot row.
export interface InventorySnapshot {
  packages?: Record<string, string>; // name -> version
  services?: Record<string, string>; // unit -> active|inactive|failed
  users?: Record<string, { uid?: number; locked?: boolean } | undefined>;
  listening_ports?: Array<{ protocol?: string; address?: string; port?: number }>;
}

interface CommonProps {
  isLoading: boolean;
  snapshot: InventorySnapshot | null;
}

// ────────────────────────────────────────────────────────────────────────────
// Count helpers — exported so the tab labels can render the badges
// without duplicating the snapshot read.
// ────────────────────────────────────────────────────────────────────────────

export function packagesCount(snap: InventorySnapshot | null): number {
  return Object.keys(snap?.packages ?? {}).length;
}

export function servicesCount(snap: InventorySnapshot | null): {
  active: number;
  total: number;
} {
  const all = Object.entries(snap?.services ?? {});
  const active = all.filter(([, v]) => v === 'active').length;
  return { active, total: all.length };
}

export function usersCount(snap: InventorySnapshot | null): number {
  return Object.keys(snap?.users ?? {}).length;
}

export function networkCount(snap: InventorySnapshot | null): number {
  return (snap?.listening_ports ?? []).length;
}

// ────────────────────────────────────────────────────────────────────────────
// Per-tab components
// ────────────────────────────────────────────────────────────────────────────

export function PackagesTab({ isLoading, snapshot }: CommonProps) {
  const entries = useMemo(
    () =>
      Object.entries(snapshot?.packages ?? {})
        .sort(([a], [b]) => a.localeCompare(b)),
    [snapshot],
  );
  return (
    <Shell
      isLoading={isLoading}
      entries={entries}
      emptyPrimary="No packages collected yet"
      emptySecondary="OS Intelligence collector populates packages on the first cycle. If you just registered this host, wait for the scheduler to run (default 1h cadence) or trigger a Discovery."
      searchPlaceholder="Search packages…"
      rows={(filtered) =>
        filtered.map(([name, version]) => (
          <Row key={name} label={name} value={String(version)} />
        ))
      }
      filterPredicate={(needle, [name]) =>
        name.toLowerCase().includes(needle)
      }
    />
  );
}

export function ServicesTab({ isLoading, snapshot }: CommonProps) {
  const entries = useMemo(
    () =>
      Object.entries(snapshot?.services ?? {})
        .sort(([a], [b]) => a.localeCompare(b)),
    [snapshot],
  );
  return (
    <Shell
      isLoading={isLoading}
      entries={entries}
      emptyPrimary="No services collected yet"
      emptySecondary="OS Intelligence reads systemd unit states on each cycle. First cycle hasn't completed for this host yet."
      searchPlaceholder="Search services…"
      rows={(filtered) =>
        filtered.map(([unit, state]) => (
          <Row
            key={unit}
            label={unit}
            value={String(state)}
            valueTint={
              state === 'active'
                ? 'var(--ow-ok)'
                : state === 'failed'
                  ? 'var(--ow-crit)'
                  : 'var(--ow-fg-3)'
            }
          />
        ))
      }
      filterPredicate={(needle, [unit]) =>
        unit.toLowerCase().includes(needle)
      }
    />
  );
}

export function UsersTab({ isLoading, snapshot }: CommonProps) {
  const entries = useMemo(
    () =>
      Object.entries(snapshot?.users ?? {})
        .sort(([a], [b]) => a.localeCompare(b)),
    [snapshot],
  );
  return (
    <Shell
      isLoading={isLoading}
      entries={entries}
      emptyPrimary="No user accounts collected yet"
      emptySecondary="OS Intelligence reads /etc/passwd + /etc/shadow on each cycle. First cycle hasn't completed for this host yet."
      searchPlaceholder="Search users…"
      rows={(filtered) =>
        filtered.map(([name, meta]) => {
          const m = meta ?? {};
          const tail = [
            m.uid != null ? `uid ${m.uid}` : '',
            m.locked ? 'locked' : '',
          ]
            .filter(Boolean)
            .join(' · ');
          return <Row key={name} label={name} value={tail || '—'} />;
        })
      }
      filterPredicate={(needle, [name]) =>
        name.toLowerCase().includes(needle)
      }
    />
  );
}

export function NetworkTab({ isLoading, snapshot }: CommonProps) {
  const ports = useMemo(
    () => (snapshot?.listening_ports ?? []).slice().sort(byPort),
    [snapshot],
  );
  return (
    <Shell
      isLoading={isLoading}
      entries={ports}
      emptyPrimary="No listening ports observed yet"
      emptySecondary="OS Intelligence reads `ss -tln` on each cycle. First cycle hasn't completed for this host yet."
      searchPlaceholder="Search ports…"
      rows={(filtered) =>
        filtered.map((p, i) => {
          const addr = p.address ?? '?';
          const port = p.port ?? '?';
          const proto = (p.protocol ?? 'tcp').toUpperCase();
          return (
            <Row
              key={`${addr}:${port}:${proto}:${i}`}
              label={`${addr}:${port}`}
              value={proto}
            />
          );
        })
      }
      filterPredicate={(needle, p) => {
        const haystack = `${p.address ?? ''} ${p.port ?? ''} ${p.protocol ?? ''}`.toLowerCase();
        return haystack.includes(needle);
      }}
    />
  );
}

function byPort(
  a: InventorySnapshot['listening_ports'] extends Array<infer T> | undefined ? T : never,
  b: InventorySnapshot['listening_ports'] extends Array<infer T> | undefined ? T : never,
): number {
  const aP = a?.port ?? 0;
  const bP = b?.port ?? 0;
  return aP - bP;
}

// ────────────────────────────────────────────────────────────────────────────
// Shell — search + loading/empty/populated states + row container
// ────────────────────────────────────────────────────────────────────────────

interface ShellProps<T> {
  isLoading: boolean;
  entries: T[];
  emptyPrimary: string;
  emptySecondary: string;
  searchPlaceholder: string;
  rows: (filtered: T[]) => React.ReactNode;
  filterPredicate: (needle: string, entry: T) => boolean;
}

function Shell<T>({
  isLoading,
  entries,
  emptyPrimary,
  emptySecondary,
  searchPlaceholder,
  rows,
  filterPredicate,
}: ShellProps<T>) {
  const [query, setQuery] = useState('');
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return entries;
    return entries.filter((e) => filterPredicate(needle, e));
  }, [entries, query, filterPredicate]);

  if (isLoading) {
    return (
      <div role="status" style={{ color: 'var(--ow-fg-2)', fontSize: 12, padding: '8px 0' }}>
        Loading…
      </div>
    );
  }
  if (entries.length === 0) {
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
          {emptyPrimary}
        </div>
        <div
          style={{
            fontSize: 11,
            color: 'var(--ow-fg-3)',
            maxWidth: 420,
            margin: '0 auto',
            lineHeight: 1.5,
          }}
        >
          {emptySecondary}
        </div>
      </div>
    );
  }
  return (
    <div>
      <div style={{ marginBottom: 10 }}>
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={searchPlaceholder}
          aria-label={searchPlaceholder}
          style={{
            width: '100%',
            padding: '6px 10px',
            background: 'var(--ow-bg-2)',
            border: '1px solid var(--ow-line)',
            borderRadius: 6,
            color: 'var(--ow-fg-0)',
            fontSize: 12,
          }}
        />
        {query && (
          <div style={{ marginTop: 4, color: 'var(--ow-fg-3)', fontSize: 11 }}>
            {filtered.length} of {entries.length}
          </div>
        )}
      </div>
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          background: 'var(--ow-bg-1)',
          border: '1px solid var(--ow-line)',
          borderRadius: 'var(--ow-radius)',
          maxHeight: 600,
          overflowY: 'auto',
        }}
      >
        {rows(filtered)}
      </div>
    </div>
  );
}

function Row({
  label,
  value,
  valueTint,
}: {
  label: string;
  value: string;
  valueTint?: string;
}) {
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: '8px 12px',
        borderBottom: '1px solid var(--ow-line)',
        fontSize: 12,
      }}
    >
      <span style={{ color: 'var(--ow-fg-1)', fontFamily: 'var(--ow-font-mono)' }}>
        {label}
      </span>
      <span style={{ color: valueTint ?? 'var(--ow-fg-3)', fontFamily: 'var(--ow-font-mono)' }}>
        {value}
      </span>
    </div>
  );
}
