// Dev-mode fixtures — the exact fixture set used by
// app/docs/prototypes/openwatch-v1/Host Management.html. Returned in
// place of an empty API response when running under Vite dev AND the
// __ow_dev_fixtures localStorage flag is set. This lets designers /
// developers verify the page layout matches the prototype without
// having to spin up a backend with seed data.
//
// IMPORTANT: this file MUST NEVER be imported from non-dev code paths
// or surfaced in production builds with the flag forced on.

export interface DevHost {
  id: string;
  hostname: string;       // "—" if no hostname registered (display falls back to IP)
  ip_address: string;
  os: 'Ubuntu' | 'RHEL' | 'Debian' | 'SUSE';
  status: 'down' | 'online';
  compliance: number | null;  // 0..100, null when no scan data
  passed: number | null;
  failed: number | null;
  total: number;
  // null when no host_liveness row exists ("never probed"). The list
  // cell renders "—" in that case rather than the misleading "0m ago".
  lastCheckMinutes: number | null;
  lastScan: string;       // "Xh ago" or "Xm ago"
}

export const devHosts: DevHost[] = [
  { id: '1', hostname: 'owas-ub4m2', ip_address: '192.168.1.214', os: 'Ubuntu', status: 'down', compliance: null, passed: null, failed: null, total: 508, lastCheckMinutes: 18, lastScan: '2h ago' },
  { id: '2', hostname: '—',          ip_address: '192.168.1.212', os: 'Ubuntu', status: 'down', compliance: null, passed: null, failed: null, total: 508, lastCheckMinutes: 18, lastScan: '2h ago' },
  { id: '3', hostname: 'owas-tst02', ip_address: '192.168.1.211', os: 'RHEL',   status: 'down', compliance: 14.0, passed: 71,   failed: 437,  total: 508, lastCheckMinutes: 18, lastScan: '2h ago' },
  { id: '4', hostname: 'owas-rhn01', ip_address: '192.168.1.213', os: 'RHEL',   status: 'down', compliance: 14.0, passed: 71,   failed: 437,  total: 508, lastCheckMinutes: 18, lastScan: '2h ago' },
  { id: '5', hostname: 'owas-tst01', ip_address: '192.168.1.203', os: 'RHEL',   status: 'down', compliance: 14.0, passed: 71,   failed: 437,  total: 508, lastCheckMinutes: 16, lastScan: '2h ago' },
  { id: '6', hostname: 'owas-hrm01', ip_address: '192.168.1.202', os: 'RHEL',   status: 'down', compliance: 14.0, passed: 71,   failed: 437,  total: 508, lastCheckMinutes: 17, lastScan: '2h ago' },
  { id: '7', hostname: 'owas-ub5s2', ip_address: '192.168.1.217', os: 'Ubuntu', status: 'online', compliance: 37.6, passed: 191, failed: 317, total: 508, lastCheckMinutes: 8,  lastScan: '1h ago' },
];

export type DeltaTier = 'crit' | 'warn' | 'ok' | 'neutral';

export interface DevKpis {
  hostsOnline: { value: number; total: number; delta: string; deltaTier: DeltaTier };
  avgCompliance: { value: number; target: number; delta: string; deltaTier: DeltaTier };
  criticalIssues: { value: number; scope: string; delta: string; deltaTier: DeltaTier };
  scanQueue: { value: number; scope: string; delta: string; deltaTier: DeltaTier };
}

export const devKpis: DevKpis = {
  hostsOnline: { value: 1, total: 7, delta: '−5 vs. 24h', deltaTier: 'crit' },
  avgCompliance: { value: 19, target: 80, delta: '−4.2 pts', deltaTier: 'crit' },
  criticalIssues: { value: 5, scope: 'across 4 hosts', delta: '+2 today', deltaTier: 'warn' },
  scanQueue: { value: 0, scope: 'All hosts current', delta: 'Healthy', deltaTier: 'ok' },
};

export const devFleetAlert = {
  title: 'Fleet health critical',
  body:
    '6 hosts are unreachable and compliance dropped 4.2 points in the last 24h. The 6 down hosts share the owas-prod network — likely a connectivity issue.',
  downCount: 6,
};

export function isDevFixturesEnabled(): boolean {
  if (!import.meta.env.DEV) return false;
  if (typeof localStorage === 'undefined') return false;
  return localStorage.getItem('__ow_dev_fixtures') === '1';
}
