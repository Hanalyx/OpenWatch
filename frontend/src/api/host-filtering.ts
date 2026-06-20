// Pure grouping + filtering helpers for the /hosts fleet view. Kept
// separate from HostsListPage so the behavior is unit-testable in
// isolation (the page wiring stays a thin shell over these functions).
// Spec: frontend-hosts-list v1.7.0 C-10 (grouping) + C-11 (filters).

import type { DevHost, MonitoringBand } from './host-view-model';

// ─── Grouping ────────────────────────────────────────────────────────────

// Drop 'team': a host has no team/owner field (see api-hosts HostListItem),
// so only None/Status/OS are backed by real data.
export type GroupKey = 'none' | 'status' | 'os';

export interface HostGroup {
  key: string;
  label: string;
  hosts: DevHost[];
}

// Worst-first, mirroring the page's default down-first ordering so the
// most actionable groups surface at the top.
const STATUS_ORDER: MonitoringBand[] = [
  'critical',
  'down',
  'degraded',
  'online',
  'maintenance',
  'unknown',
];

const STATUS_LABEL: Record<MonitoringBand, string> = {
  online: 'Online',
  degraded: 'Degraded',
  critical: 'Critical',
  down: 'Down',
  maintenance: 'Maintenance',
  unknown: 'Unknown',
};

export function statusLabel(band: MonitoringBand): string {
  return STATUS_LABEL[band] ?? 'Unknown';
}

// groupHosts partitions the (already sorted/filtered) host list into
// labelled sections. group='none' returns a single anonymous group so the
// renderer can treat both paths uniformly. Empty groups are omitted.
export function groupHosts(hosts: DevHost[], group: GroupKey): HostGroup[] {
  if (group === 'none') {
    return [{ key: 'none', label: '', hosts }];
  }
  if (group === 'status') {
    return STATUS_ORDER.map((band) => ({
      key: band,
      label: statusLabel(band),
      hosts: hosts.filter((h) => h.monitoring === band),
    })).filter((g) => g.hosts.length > 0);
  }
  // group === 'os' — alphabetical, with the catch-all "Unknown" last.
  const byOs = new Map<string, DevHost[]>();
  for (const h of hosts) {
    const key = h.os || 'Unknown';
    (byOs.get(key) ?? byOs.set(key, []).get(key)!).push(h);
  }
  return [...byOs.entries()]
    .sort(([a], [b]) => {
      if (a === 'Unknown') return 1;
      if (b === 'Unknown') return -1;
      return a.localeCompare(b);
    })
    .map(([key, hs]) => ({ key, label: key, hosts: hs }));
}

// ─── Filtering ───────────────────────────────────────────────────────────

export type TierFilter = 'crit' | 'warn' | 'ok' | 'none';

export interface HostFilters {
  status: string[]; // MonitoringBand values
  os: string[]; // osDisplayLabel values (host.os)
  tier: string[]; // TierFilter values
}

const TIER_LABEL: Record<TierFilter, string> = {
  crit: 'Critical (<40%)',
  warn: 'Warning (40-80%)',
  ok: 'Compliant (>=80%)',
  none: 'No scan data',
};

export function tierLabel(t: TierFilter): string {
  return TIER_LABEL[t] ?? t;
}

// hostComplianceTier buckets a host's compliance score. A never-scanned
// host (compliance null) is its own 'none' bucket rather than 'crit', so
// "no data" and "actually failing" stay distinguishable in the filter.
export function hostComplianceTier(h: DevHost): TierFilter {
  if (h.compliance == null) return 'none';
  if (h.compliance < 40) return 'crit';
  if (h.compliance < 80) return 'warn';
  return 'ok';
}

function csv(v: string | undefined): string[] {
  if (!v) return [];
  return v
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export function parseHostFilters(search: {
  status?: string;
  os?: string;
  tier?: string;
}): HostFilters {
  return { status: csv(search.status), os: csv(search.os), tier: csv(search.tier) };
}

// applyHostFilters keeps a host only when it matches EVERY active
// dimension (AND across dimensions, OR within a dimension). An empty
// dimension imposes no constraint.
export function applyHostFilters(hosts: DevHost[], f: HostFilters): DevHost[] {
  return hosts.filter((h) => {
    if (f.status.length && !f.status.includes(h.monitoring)) return false;
    if (f.os.length && !f.os.includes(h.os || 'Unknown')) return false;
    if (f.tier.length && !f.tier.includes(hostComplianceTier(h))) return false;
    return true;
  });
}

export function activeFilterCount(f: HostFilters): number {
  return f.status.length + f.os.length + f.tier.length;
}
