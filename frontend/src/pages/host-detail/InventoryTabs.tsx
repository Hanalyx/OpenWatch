// InventoryTabs — Packages / Services / Users / Network tab bodies
// for the host detail page. Each component reads from the
// IntelligenceState.snapshot passed down from HostDetailPage; none
// issues its own useQuery (spec C-01 — parent fetches once).
//
// Spec: frontend-host-detail-inventory-tabs v1.0.0.

import React, { useMemo, useState } from 'react';

// Shape of the snapshot fields these tabs render. Each is optional
// because pre-cycle hosts have an empty snapshot OR no snapshot row.
export interface UserFact {
  uid?: number;
  locked?: boolean;
  shell?: string;
  gecos?: string;
  // Password-aging fields from /etc/shadow (v1.1.0 collector). Pointers on
  // the Go side → optional here. max_days 99999 / absent means "no policy";
  // password_expires_at is set only when a real policy is in force.
  last_change_days?: number;
  max_days?: number;
  password_expires_at?: string; // ISO 8601
}

export interface InventorySnapshot {
  packages?: Record<string, string>; // name -> version
  services?: Record<string, string>; // unit -> active|inactive|failed
  users?: Record<string, UserFact | undefined>;
  // group -> [usernames]; drives sudo/wheel/admin membership on the cards.
  groups?: Record<string, string[]>;
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
  type?: string; // physical | loopback | virtual
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
  status?: string | null; // active | inactive | ...
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
    () => Object.entries(snapshot?.packages ?? {}).sort(([a], [b]) => a.localeCompare(b)),
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
        filtered.map(([name, version]) => <Row key={name} label={name} value={String(version)} />)
      }
      filterPredicate={(needle, [name]) => name.toLowerCase().includes(needle)}
    />
  );
}

export function ServicesTab({ isLoading, snapshot }: CommonProps) {
  const entries = useMemo(
    () => Object.entries(snapshot?.services ?? {}).sort(([a], [b]) => a.localeCompare(b)),
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
      filterPredicate={(needle, [unit]) => unit.toLowerCase().includes(needle)}
    />
  );
}

// Account classification. A "human" login account is UID >= 1000 and not
// nobody (65534); everything below (root, daemon, bin, …) and nobody is a
// system/service account, collapsed by default. Matches the backend sweep's
// minHumanUID / nobodyUID gating (system-account-policy C-01).
const HUMAN_UID_MIN = 1000;
const NOBODY_UID = 65534;
// PASSWORD_WARN_DAYS is the amber cutoff for the aging line only (the real
// alert threshold is server-side config). Fixed here for a stable visual.
const PASSWORD_WARN_DAYS = 14;

function isHumanUID(uid?: number): boolean {
  return uid != null && uid >= HUMAN_UID_MIN && uid !== NOBODY_UID;
}

// sudoerSet — usernames in sudo/wheel/admin, intersected with known users so
// a stale group entry for a removed user is not reported. Mirrors
// countSudoUsers (CardServerIntel) but returns the set for per-card badges.
function sudoerSet(
  users: Record<string, UserFact | undefined>,
  groups: Record<string, string[]> | undefined,
): Set<string> {
  const out = new Set<string>();
  if (!groups) return out;
  const known = new Set(Object.keys(users));
  for (const g of ['sudo', 'wheel', 'admin']) {
    for (const m of groups[g] ?? []) {
      if (known.has(m)) out.add(m);
    }
  }
  return out;
}

function hasPasswordPolicy(u: UserFact): boolean {
  return u.max_days != null && u.max_days > 0 && u.max_days < 99999;
}

// passwordAging resolves the one-line aging status for a card. Six states:
// expired / expiring-soon / expiring / no-policy (age) / change-required /
// unknown. Returns null when there is nothing meaningful to show.
// Spec frontend-host-detail-inventory-tabs AC-10.
function passwordAging(
  u: UserFact,
  nowMs: number,
): { text: string; tone: 'neutral' | 'warn' | 'crit' } | null {
  const dayMs = 86_400_000;
  if (u.password_expires_at) {
    const exp = new Date(u.password_expires_at).getTime();
    if (Number.isNaN(exp)) return null;
    const days = Math.round((exp - nowMs) / dayMs);
    if (days < 0) return { text: `Password expired ${-days} days ago`, tone: 'crit' };
    if (days <= PASSWORD_WARN_DAYS)
      return { text: `Password expires in ${days} days`, tone: 'warn' };
    return { text: `Password expires in ${days} days`, tone: 'neutral' };
  }
  if (u.last_change_days === 0) {
    return { text: 'Password change required at next login', tone: 'warn' };
  }
  if (u.last_change_days == null) return null; // age unknown — omit the line
  const ageDays = Math.max(0, Math.round(nowMs / dayMs - u.last_change_days));
  if (!hasPasswordPolicy(u)) {
    return { text: `Password ${ageDays} days old · no expiry policy`, tone: 'warn' };
  }
  return { text: `Password ${ageDays} days old`, tone: 'neutral' };
}

function userInitials(name: string, gecos?: string): string {
  const src = (gecos && gecos.trim()) || name;
  const parts = src.split(/[\s._-]+/).filter(Boolean);
  const letters = parts.slice(0, 2).map((p) => p[0]!.toUpperCase());
  return letters.join('') || name.slice(0, 2).toUpperCase();
}

export function UsersTab({ isLoading, snapshot }: CommonProps) {
  const [showSystem, setShowSystem] = useState(false);
  const [query, setQuery] = useState('');
  // Memoize the `?? {}` so the derived useMemo below has a stable input
  // (a fresh literal each render would defeat it — react-hooks/exhaustive-deps).
  const users = useMemo(() => snapshot?.users ?? {}, [snapshot]);
  const groups = snapshot?.groups;
  const nowMs = Date.now();

  const { humans, system, sudoers, kpis } = useMemo(() => {
    const sudo = sudoerSet(users, groups);
    const entries = Object.entries(users).sort(([a], [b]) => a.localeCompare(b));
    const humanList = entries.filter(([, u]) => isHumanUID(u?.uid));
    const systemList = entries.filter(([, u]) => !isHumanUID(u?.uid));
    const locked = humanList.filter(([, u]) => u?.locked).length;
    // "Stale" = a human account with no rotation policy (PASS_MAX_DAYS unset/
    // 99999) or one whose password has already expired — the prototype's
    // STALE PASSWORDS tile.
    const stale = humanList.filter(([, u]) => {
      if (!u) return false;
      const expired = passwordAging(u, nowMs)?.tone === 'crit';
      const noPolicy = !hasPasswordPolicy(u) && u.last_change_days != null;
      return expired || noPolicy;
    }).length;
    return {
      humans: humanList,
      system: systemList,
      sudoers: sudo,
      kpis: {
        human: humanList.length,
        systemCount: systemList.length,
        sudo: sudo.size,
        locked,
        stale,
      },
    };
  }, [users, groups, nowMs]);

  if (isLoading) {
    return (
      <div role="status" style={{ color: 'var(--ow-fg-3)', fontSize: 12, padding: '20px 0' }}>
        Loading users…
      </div>
    );
  }
  if (Object.keys(users).length === 0) {
    return (
      <div style={{ padding: '28px 0', textAlign: 'center' }}>
        <div style={{ color: 'var(--ow-fg-1)', fontSize: 13 }}>No user accounts collected yet</div>
        <div style={{ color: 'var(--ow-fg-3)', fontSize: 12, marginTop: 4 }}>
          OS Intelligence reads /etc/passwd + /etc/shadow on each cycle. First cycle hasn&apos;t
          completed for this host yet.
        </div>
      </div>
    );
  }

  const needle = query.trim().toLowerCase();
  const shownHumans = needle ? humans.filter(([n]) => n.toLowerCase().includes(needle)) : humans;
  const shownSystem = needle ? system.filter(([n]) => n.toLowerCase().includes(needle)) : system;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <input
        type="search"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search users…"
        style={{
          width: '100%',
          padding: '8px 12px',
          background: 'var(--ow-bg-1)',
          border: '1px solid var(--ow-line)',
          borderRadius: 'var(--ow-radius)',
          color: 'var(--ow-fg-0)',
          fontSize: 13,
        }}
      />
      {/* KPI tiles */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 12 }}>
        <StatCard
          label="User accounts"
          value={String(kpis.human)}
          sub={`Plus ${kpis.systemCount} system accounts`}
        />
        <StatCard
          label="Sudo privileges"
          value={String(kpis.sudo)}
          sub={
            kpis.sudo === 0
              ? 'None'
              : [...sudoers].slice(0, 2).join(', ') + (kpis.sudo > 2 ? '…' : '')
          }
          valueColor={kpis.sudo > 0 ? 'crit' : undefined}
        />
        <StatCard
          label="Locked / disabled"
          value={String(kpis.locked)}
          sub={kpis.locked === 0 ? 'None' : 'Login disabled'}
        />
        <StatCard
          label="Stale passwords"
          value={String(kpis.stale)}
          sub={kpis.stale === 0 ? 'All within policy' : 'No expiry policy or expired'}
          valueColor={kpis.stale > 0 ? 'crit' : undefined}
        />
      </div>

      {/* Human account cards */}
      {shownHumans.length === 0 ? (
        <div style={{ color: 'var(--ow-fg-3)', fontSize: 12 }}>
          {needle
            ? 'No human accounts match your search.'
            : 'No human login accounts on this host.'}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {shownHumans.map(([name, u]) => (
            <UserAccountCard
              key={name}
              name={name}
              user={u ?? {}}
              sudo={sudoers.has(name)}
              groups={groups}
              nowMs={nowMs}
            />
          ))}
        </div>
      )}

      {/* System accounts — collapsed by default */}
      <div
        style={{
          background: 'var(--ow-bg-1)',
          border: '1px solid var(--ow-line)',
          borderRadius: 'var(--ow-radius)',
        }}
      >
        <button
          type="button"
          onClick={() => setShowSystem((s) => !s)}
          aria-expanded={showSystem || needle !== ''}
          style={{
            width: '100%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '12px 16px',
            background: 'transparent',
            border: 0,
            cursor: 'pointer',
            color: 'var(--ow-fg-1)',
            fontSize: 13,
            fontWeight: 600,
          }}
        >
          <span>System accounts</span>
          <span style={{ color: 'var(--ow-fg-3)', fontSize: 12, fontWeight: 400 }}>
            {system.length} service accounts · {showSystem || needle ? 'hide' : 'show all'}
          </span>
        </button>
        {(showSystem || needle !== '') && (
          <div style={{ borderTop: '1px solid var(--ow-line)', maxHeight: 420, overflowY: 'auto' }}>
            {shownSystem.map(([name, u]) => {
              const m = u ?? {};
              const tail = [m.uid != null ? `uid ${m.uid}` : '', m.locked ? 'locked' : '']
                .filter(Boolean)
                .join(' · ');
              return <Row key={name} label={name} value={tail || '—'} />;
            })}
          </div>
        )}
      </div>
    </div>
  );
}

// UserAccountCard renders one human login account: avatar + name + uid + sudo
// badge, the GECOS full name + shell, group chips, an Active/Locked status,
// and the password-aging line. Spec frontend-host-detail-inventory-tabs AC-10.
function UserAccountCard({
  name,
  user,
  sudo,
  groups,
  nowMs,
}: {
  name: string;
  user: UserFact;
  sudo: boolean;
  groups?: Record<string, string[]>;
  nowMs: number;
}) {
  const aging = passwordAging(user, nowMs);
  const agingColor =
    aging?.tone === 'crit'
      ? 'var(--ow-crit)'
      : aging?.tone === 'warn'
        ? 'var(--ow-warn)'
        : 'var(--ow-fg-3)';
  const memberOf = groups
    ? Object.entries(groups)
        .filter(([, members]) => members?.includes(name))
        .map(([g]) => g)
        .sort()
        .slice(0, 6)
    : [];
  return (
    <div
      style={{
        display: 'flex',
        gap: 12,
        padding: '14px 16px',
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
      }}
    >
      <div
        aria-hidden
        style={{
          width: 36,
          height: 36,
          flexShrink: 0,
          borderRadius: '50%',
          background: 'var(--ow-bg-3)',
          color: 'var(--ow-fg-1)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: 13,
          fontWeight: 600,
        }}
      >
        {userInitials(name, user.gecos)}
      </div>
      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--ow-fg-0)' }}>{name}</span>
          {user.uid != null && (
            <span
              style={{ fontSize: 11, color: 'var(--ow-fg-3)', fontFamily: 'var(--ow-font-mono)' }}
            >
              UID {user.uid}
            </span>
          )}
          {sudo && (
            <span
              style={{
                fontSize: 10,
                fontWeight: 700,
                letterSpacing: '0.04em',
                color: 'var(--ow-crit)',
                border: '1px solid color-mix(in oklab, var(--ow-crit) 40%, transparent)',
                borderRadius: 'var(--ow-radius-full)',
                padding: '1px 6px',
              }}
            >
              SUDO
            </span>
          )}
        </div>
        <div style={{ fontSize: 12, color: 'var(--ow-fg-2)', marginTop: 3 }}>
          {user.gecos ? (
            <>
              Full name <span style={{ color: 'var(--ow-fg-1)' }}>{user.gecos}</span>
              {' · '}
            </>
          ) : null}
          Shell{' '}
          <span style={{ color: 'var(--ow-fg-1)', fontFamily: 'var(--ow-font-mono)' }}>
            {user.shell || '—'}
          </span>
        </div>
        {memberOf.length > 0 && (
          <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginTop: 6 }}>
            {memberOf.map((g) => (
              <span
                key={g}
                style={{
                  fontSize: 11,
                  fontFamily: 'var(--ow-font-mono)',
                  color: 'var(--ow-fg-2)',
                  background: 'var(--ow-bg-2)',
                  borderRadius: 4,
                  padding: '1px 6px',
                }}
              >
                {g}
              </span>
            ))}
          </div>
        )}
      </div>
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'flex-end',
          gap: 6,
          flexShrink: 0,
        }}
      >
        <span
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            fontSize: 11,
            color: user.locked ? 'var(--ow-fg-3)' : 'var(--ow-ok)',
          }}
        >
          <span
            style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              background: user.locked ? 'var(--ow-fg-3)' : 'var(--ow-ok)',
            }}
          />
          {user.locked ? 'Locked' : 'Active'}
        </span>
        {aging && <span style={{ fontSize: 11, color: agingColor }}>{aging.text}</span>}
      </div>
    </div>
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
  const interfaces = useMemo(() => snapshot?.network_interfaces ?? [], [snapshot]);
  const routes = useMemo(() => snapshot?.routes ?? [], [snapshot]);
  const ports = useMemo(() => (snapshot?.listening_ports ?? []).slice().sort(byPort), [snapshot]);

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

function NetField({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
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
              <span style={{ color: 'var(--ow-fg-3)' }}>{(p.protocol ?? 'tcp').toUpperCase()}</span>
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

function RouteCell({ children, mono }: { children: React.ReactNode; mono?: boolean }) {
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

function NetEmptyState({ primary, secondary }: { primary: string; secondary: string }) {
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

function Row({ label, value, valueTint }: { label: string; value: string; valueTint?: string }) {
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
      <span style={{ color: 'var(--ow-fg-1)', fontFamily: 'var(--ow-font-mono)' }}>{label}</span>
      <span style={{ color: valueTint ?? 'var(--ow-fg-3)', fontFamily: 'var(--ow-font-mono)' }}>
        {value}
      </span>
    </div>
  );
}
