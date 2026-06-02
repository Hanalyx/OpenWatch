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
  // Populated by the Intelligence cycle on/after the network-collection
  // commit. Pre-cycle hosts get an empty array; the tab renders honest
  // empty states rather than blowing up.
  network_interfaces?: NetworkInterfaceFact[];
  routes?: RouteFact[];
  // -1  = no firewall engine detected on the host
  //  0+ = engine present, N user-visible rules loaded
  // undefined = older snapshot, predating the field
  firewall_rule_count?: number;
}

export interface NetworkInterfaceFact {
  name: string;
  state?: string; // UP | DOWN | UNKNOWN
  type?: string;  // physical | loopback | virtual
  ipv4_addrs?: string[];
  ipv6_addrs?: string[];
  mac?: string;
  mtu?: number;
  driver?: string;
  speed_mbps?: number;
  duplex?: string;
  rx_bytes?: number;
  tx_bytes?: number;
}

export interface RouteFact {
  destination: string;
  gateway?: string;
  interface: string;
  metric?: number;
  protocol?: string;
  scope?: string;
}

// Sourced from host_system_info.firewall_*. Surfaces in the stat row
// and the inline callout when the firewall is not active.
export interface NetworkFirewallFact {
  service?: string | null; // firewalld | ufw | nftables | iptables | empty
  status?: string | null;  // active | inactive | ...
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

interface NetworkTabProps extends CommonProps {
  firewall?: NetworkFirewallFact | null;
}

// NetworkTab — prototype-faithful network surface. Three regions:
//
//   Stat row (4 cards): Interfaces, Firewall, Listening ports, Default
//   route. Each card reads from a different source (snapshot for
//   interfaces/ports/routes, system_info for firewall) but the row
//   layout collapses them into a single glanceable strip.
//
//   Two-column body:
//     Left  - one card per interface + a routing-table panel
//     Right - listening-ports panel + Firewall-inactive callout
//
// Pre-cycle hosts get honest empty states per region rather than a
// single page-level blank.
export function NetworkTab({ isLoading, snapshot, firewall }: NetworkTabProps) {
  const interfaces = useMemo(
    () => snapshot?.network_interfaces ?? [],
    [snapshot],
  );
  const routes = useMemo(() => snapshot?.routes ?? [], [snapshot]);
  const ports = useMemo(
    () => (snapshot?.listening_ports ?? []).slice().sort(byPort),
    [snapshot],
  );

  if (isLoading) {
    return (
      <div role="status" style={{ color: 'var(--ow-fg-2)', fontSize: 12, padding: '8px 0' }}>
        Loading…
      </div>
    );
  }

  const physicalCount = interfaces.filter((i) => i.type === 'physical').length;
  const loopbackCount = interfaces.filter((i) => i.type === 'loopback').length;
  const defaultRoute = routes.find((r) => r.destination === 'default');
  const firewallActive = isFirewallActive(firewall?.status ?? null);
  const firewallRuleCount = snapshot?.firewall_rule_count;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <NetworkStatRow
        interfaceCount={interfaces.length}
        physicalCount={physicalCount}
        loopbackCount={loopbackCount}
        firewall={firewall ?? null}
        firewallRuleCount={firewallRuleCount}
        portsCount={ports.length}
        defaultRoute={defaultRoute ?? null}
      />

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(0, 2fr) minmax(0, 1fr)',
          gap: 14,
          alignItems: 'start',
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14, minWidth: 0 }}>
          {interfaces.length === 0 ? (
            <NetworkCard>
              <NetEmptyState
                primary="No interface data yet"
                secondary="Captured by the Intelligence cycle (ip -j addr + /sys/class/net)."
              />
            </NetworkCard>
          ) : (
            interfaces.map((iface) => <InterfaceCard key={iface.name} iface={iface} />)
          )}
          <RoutingTable routes={routes} />
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 14, minWidth: 0 }}>
          <ListeningPortsPanel ports={ports} />
          {!firewallActive && firewall?.status && (
            <FirewallInactiveCallout service={firewall.service ?? null} />
          )}
        </div>
      </div>
    </div>
  );
}

function isFirewallActive(status: string | null): boolean {
  if (!status) return false;
  const s = status.toLowerCase();
  return s === 'active' || s === 'enabled' || s === 'running';
}

// composeFirewallSub builds the second line of the FIREWALL stat card.
// Combines the engine label ("firewalld", "ufw", ...) with a rule
// count when collected; degrades cleanly when either is missing.
//
// Examples:
//   firewalld + active + 0 rules   -> "firewalld · 0 rules loaded"
//   firewalld + active + 12 rules  -> "firewalld · 12 rules loaded"
//   firewalld + inactive + 0       -> "firewalld disabled · 0 rules loaded"
//   ufw       + inactive + n=undef -> "ufw disabled"  (older snapshot)
//   service=null                   -> "No firewall service detected"
//   service=null + n=-1            -> "No firewall service detected"
//   service set + n=-1             -> "<svc>" (engine reachable but probe failed)
export function composeFirewallSub(
  service: string | null,
  active: boolean,
  ruleCount: number | undefined,
): string {
  if (!service) return 'No firewall service detected';
  const engine = active ? service : `${service} disabled`;
  if (ruleCount === undefined || ruleCount < 0) return engine;
  const noun = ruleCount === 1 ? 'rule' : 'rules';
  return `${engine} · ${ruleCount} ${noun} loaded`;
}

// ─── Stat row ─────────────────────────────────────────────────────────────

function NetworkStatRow(props: {
  interfaceCount: number;
  physicalCount: number;
  loopbackCount: number;
  firewall: NetworkFirewallFact | null;
  firewallRuleCount?: number;
  portsCount: number;
  defaultRoute: RouteFact | null;
}) {
  const fwActive = isFirewallActive(props.firewall?.status ?? null);
  const fwValue =
    props.firewall?.status === null || props.firewall?.status === undefined
      ? '—'
      : fwActive
      ? 'Active'
      : 'Inactive';
  const fwSub = composeFirewallSub(
    props.firewall?.service ?? null,
    fwActive,
    props.firewallRuleCount,
  );

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, minmax(0, 1fr))',
        gap: 12,
      }}
    >
      <StatCard
        label="Interfaces"
        value={String(props.interfaceCount)}
        sub={`${props.physicalCount} physical · ${props.loopbackCount} loopback`}
      />
      <StatCard
        label="Firewall"
        value={fwValue}
        sub={fwSub}
        valueColor={fwActive ? 'ok' : props.firewall?.status ? 'crit' : undefined}
      />
      <StatCard
        label="Listening ports"
        value={String(props.portsCount)}
        sub={props.portsCount === 0 ? 'No services exposed' : 'External LISTEN sockets'}
      />
      <StatCard
        label="Default route"
        value={props.defaultRoute?.gateway || '—'}
        sub={props.defaultRoute ? `via ${props.defaultRoute.interface}` : 'Not detected'}
        valueMono
      />
    </div>
  );
}

function StatCard({
  label,
  value,
  sub,
  valueColor,
  valueMono,
}: {
  label: string;
  value: string;
  sub: string;
  valueColor?: 'ok' | 'crit';
  valueMono?: boolean;
}) {
  const color =
    valueColor === 'crit'
      ? 'var(--ow-crit)'
      : valueColor === 'ok'
      ? 'var(--ow-ok)'
      : 'var(--ow-fg-0)';
  return (
    <div
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: '14px 16px',
      }}
    >
      <div
        style={{
          fontSize: 11,
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          color: 'var(--ow-fg-2)',
        }}
      >
        {label}
      </div>
      <div
        style={{
          marginTop: 6,
          fontSize: 22,
          fontWeight: 600,
          color,
          fontFamily: valueMono ? 'var(--ow-font-mono)' : undefined,
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
      >
        {value}
      </div>
      <div style={{ marginTop: 4, fontSize: 11, color: 'var(--ow-fg-3)' }}>{sub}</div>
    </div>
  );
}

// ─── Interface card ───────────────────────────────────────────────────────

function InterfaceCard({ iface }: { iface: NetworkInterfaceFact }) {
  const stateUp = (iface.state ?? '').toUpperCase() === 'UP';
  const ipv4 = (iface.ipv4_addrs ?? []).join(', ');
  const ipv6 = (iface.ipv6_addrs ?? []).join(', ');
  return (
    <NetworkCard>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 12,
          marginBottom: 12,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
          <div
            style={{
              width: 24,
              height: 24,
              borderRadius: 5,
              background: 'var(--ow-bg-3)',
              display: 'grid',
              placeItems: 'center',
            }}
          >
            <span style={{ fontSize: 12, color: 'var(--ow-fg-2)' }}>
              {iface.type === 'loopback' ? '⟲' : '⇄'}
            </span>
          </div>
          <div
            style={{
              fontWeight: 600,
              fontFamily: 'var(--ow-font-mono)',
              fontSize: 14,
            }}
          >
            {iface.name}
          </div>
        </div>
        <StateBadge up={stateUp} label={iface.state ?? 'UNKNOWN'} />
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          rowGap: 10,
          columnGap: 24,
        }}
      >
        {ipv4 && <NetField label="IPv4" value={ipv4} mono />}
        {iface.mac && <NetField label="MAC" value={iface.mac} mono />}
        {ipv6 && <NetField label="IPv6" value={ipv6} mono />}
        {iface.driver && <NetField label="Driver" value={iface.driver} mono />}
        {iface.mtu !== undefined && <NetField label="MTU" value={String(iface.mtu)} mono />}
        {iface.type === 'loopback' ? (
          <NetField label="Type" value="loopback" />
        ) : (
          iface.speed_mbps !== undefined &&
          iface.speed_mbps > 0 && (
            <NetField
              label="Speed"
              value={`${formatSpeed(iface.speed_mbps)}${
                iface.duplex && iface.duplex !== 'unknown' ? ` · ${iface.duplex} duplex` : ''
              }`}
            />
          )
        )}
        {(iface.rx_bytes !== undefined || iface.tx_bytes !== undefined) && (
          <NetField
            label="RX / TX"
            value={`${formatBytes(iface.rx_bytes ?? 0)} / ${formatBytes(iface.tx_bytes ?? 0)}`}
            mono
          />
        )}
      </div>
    </NetworkCard>
  );
}

function StateBadge({ up, label }: { up: boolean; label: string }) {
  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        fontSize: 11,
        color: up ? 'var(--ow-ok)' : 'var(--ow-fg-3)',
      }}
    >
      <span
        style={{
          width: 8,
          height: 8,
          borderRadius: '50%',
          background: up ? 'var(--ow-ok)' : 'var(--ow-fg-3)',
          display: 'inline-block',
        }}
      />
      {up ? 'Up' : label}
    </div>
  );
}

function NetField({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <div style={{ fontSize: 11, color: 'var(--ow-fg-3)' }}>{label}</div>
      <div
        style={{
          fontSize: 13,
          color: 'var(--ow-fg-1)',
          marginTop: 2,
          fontFamily: mono ? 'var(--ow-font-mono)' : undefined,
          wordBreak: 'break-all',
        }}
      >
        {value}
      </div>
    </div>
  );
}

// ─── Right column panels ──────────────────────────────────────────────────

function ListeningPortsPanel({
  ports,
}: {
  ports: Array<{ protocol?: string; address?: string; port?: number }>;
}) {
  return (
    <NetworkCard>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'baseline',
          marginBottom: 10,
        }}
      >
        <div style={{ fontWeight: 600, fontSize: 13 }}>Listening ports</div>
        <div style={{ fontSize: 11, color: 'var(--ow-fg-3)' }}>{ports.length} ports</div>
      </div>
      {ports.length === 0 ? (
        <NetEmptyState
          primary="No services listening"
          secondary="The host has no LISTEN sockets bound to external interfaces (per ss -tln)."
        />
      ) : (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
          {ports.map((p, i) => (
            <li
              key={`${p.address}:${p.port}:${p.protocol}:${i}`}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                padding: '6px 0',
                borderTop: i === 0 ? 'none' : '1px solid var(--ow-line)',
                fontSize: 12,
              }}
            >
              <span style={{ fontFamily: 'var(--ow-font-mono)' }}>
                {p.address ?? '?'}:{p.port ?? '?'}
              </span>
              <span style={{ color: 'var(--ow-fg-3)' }}>
                {(p.protocol ?? 'tcp').toUpperCase()}
              </span>
            </li>
          ))}
        </ul>
      )}
    </NetworkCard>
  );
}

function FirewallInactiveCallout({ service }: { service: string | null }) {
  const svcLabel = service?.toUpperCase() ?? 'No firewall';
  return (
    <div
      role="alert"
      style={{
        background: 'var(--ow-crit-bg)',
        border: '1px solid var(--ow-crit)',
        borderRadius: 'var(--ow-radius)',
        padding: '12px 14px',
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: 12,
        }}
      >
        <div>
          <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--ow-fg-0)' }}>
            Firewall is inactive
          </div>
          <div
            style={{
              fontSize: 11,
              color: 'var(--ow-fg-2)',
              marginTop: 4,
              lineHeight: 1.5,
            }}
          >
            {svcLabel} is disabled. The host is unfiltered at the network layer.
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Routing table ────────────────────────────────────────────────────────

function RoutingTable({ routes }: { routes: RouteFact[] }) {
  return (
    <NetworkCard>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'baseline',
          marginBottom: 10,
        }}
      >
        <div style={{ fontWeight: 600, fontSize: 13 }}>Routing table</div>
        <div style={{ fontSize: 11, color: 'var(--ow-fg-3)' }}>
          {routes.length} {routes.length === 1 ? 'route' : 'routes'}
        </div>
      </div>
      {routes.length === 0 ? (
        <NetEmptyState
          primary="No routes captured"
          secondary="Populated from `ip -j route show` on each Intelligence cycle."
        />
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr>
              <RouteHeader>Destination</RouteHeader>
              <RouteHeader>Gateway</RouteHeader>
              <RouteHeader>Interface</RouteHeader>
              <RouteHeader>Metric</RouteHeader>
            </tr>
          </thead>
          <tbody>
            {routes.map((r, i) => (
              <tr key={`${r.destination}-${r.interface}-${i}`}>
                <RouteCell mono>{r.destination}</RouteCell>
                <RouteCell mono>{r.gateway || 'link-local'}</RouteCell>
                <RouteCell mono>{r.interface}</RouteCell>
                <RouteCell mono>{r.metric ?? 0}</RouteCell>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </NetworkCard>
  );
}

function RouteHeader({ children }: { children: React.ReactNode }) {
  return (
    <th
      style={{
        textAlign: 'left',
        fontWeight: 500,
        color: 'var(--ow-fg-3)',
        fontSize: 11,
        textTransform: 'uppercase',
        letterSpacing: '0.06em',
        padding: '6px 8px',
        borderBottom: '1px solid var(--ow-line)',
      }}
    >
      {children}
    </th>
  );
}

function RouteCell({
  children,
  mono,
}: {
  children: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <td
      style={{
        padding: '8px',
        color: 'var(--ow-fg-1)',
        borderBottom: '1px solid var(--ow-line)',
        fontFamily: mono ? 'var(--ow-font-mono)' : undefined,
      }}
    >
      {children}
    </td>
  );
}

// ─── Layout primitives ────────────────────────────────────────────────────

function NetworkCard({ children }: { children: React.ReactNode }) {
  return (
    <section
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: 16,
      }}
    >
      {children}
    </section>
  );
}

function NetEmptyState({
  primary,
  secondary,
}: {
  primary: string;
  secondary: string;
}) {
  return (
    <div
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

function formatSpeed(mbps: number): string {
  if (mbps >= 1000) return `${(mbps / 1000).toFixed(0)} Gbps`;
  return `${mbps} Mbps`;
}

function formatBytes(n: number): string {
  if (n >= 1024 ** 4) return `${(n / 1024 ** 4).toFixed(1)} TB`;
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(1)} GB`;
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
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
