// @spec frontend-hosts-list
//
// Behavioral coverage for the pure grouping + filtering helpers that back
// the /hosts Group control and Filters popover.
//   AC-23  grouping (None/Status/OS, worst-first, Unknown last)
//   AC-24  filtering (AND across dims / OR within, tier buckets, parsing)

import { describe, expect, test } from 'vitest';

import type { DevHost, MonitoringBand } from '@/api/host-view-model';
import {
  activeFilterCount,
  applyHostFilters,
  groupHosts,
  hostComplianceTier,
  parseHostFilters,
} from '@/api/host-filtering';

function host(overrides: Partial<DevHost> = {}): DevHost {
  return {
    id: Math.random().toString(36).slice(2),
    hostname: 'h',
    ip_address: '10.0.0.1',
    os: 'Ubuntu',
    status: 'online',
    monitoring: 'online',
    compliance: 90,
    passed: 9,
    failed: 1,
    total: 10,
    lastCheckMinutes: 0,
    lastScan: 'just now',
    latestScanId: null,
    scanState: null,
    ...overrides,
  };
}

describe('frontend-hosts-list/AC-23 — grouping', () => {
  test('none returns a single section with the input unchanged', () => {
    const hosts = [host(), host()];
    const groups = groupHosts(hosts, 'none');
    expect(groups).toHaveLength(1);
    expect(groups[0]!.hosts).toEqual(hosts);
  });

  test('status groups worst-first and omits empty bands', () => {
    const bands: MonitoringBand[] = ['online', 'critical', 'online', 'down', 'degraded'];
    const hosts = bands.map((b) => host({ monitoring: b }));
    const groups = groupHosts(hosts, 'status');
    // present bands in worst-first order: critical, down, degraded, online
    expect(groups.map((g) => g.key)).toEqual(['critical', 'down', 'degraded', 'online']);
    expect(groups.find((g) => g.key === 'online')!.hosts).toHaveLength(2);
    // maintenance/unknown absent → no empty sections
    expect(groups.some((g) => g.key === 'maintenance' || g.key === 'unknown')).toBe(false);
  });

  test('os groups alphabetically with Unknown last', () => {
    const hosts = [
      host({ os: 'RHEL' }),
      host({ os: 'Unknown' }),
      host({ os: 'Ubuntu' }),
      host({ os: 'Debian' }),
    ];
    const groups = groupHosts(hosts, 'os');
    expect(groups.map((g) => g.label)).toEqual(['Debian', 'RHEL', 'Ubuntu', 'Unknown']);
  });
});

describe('frontend-hosts-list/AC-24 — filtering', () => {
  test('compliance tier buckets; never-scanned is none, not crit', () => {
    expect(hostComplianceTier(host({ compliance: null }))).toBe('none');
    expect(hostComplianceTier(host({ compliance: 0 }))).toBe('crit');
    expect(hostComplianceTier(host({ compliance: 39.9 }))).toBe('crit');
    expect(hostComplianceTier(host({ compliance: 40 }))).toBe('warn');
    expect(hostComplianceTier(host({ compliance: 79.9 }))).toBe('warn');
    expect(hostComplianceTier(host({ compliance: 80 }))).toBe('ok');
    expect(hostComplianceTier(host({ compliance: 100 }))).toBe('ok');
  });

  test('empty filters keep everything', () => {
    const hosts = [host(), host({ monitoring: 'down' })];
    expect(applyHostFilters(hosts, parseHostFilters({}))).toEqual(hosts);
  });

  test('OR within a dimension', () => {
    const hosts = [
      host({ monitoring: 'online' }),
      host({ monitoring: 'down' }),
      host({ monitoring: 'critical' }),
    ];
    const out = applyHostFilters(hosts, parseHostFilters({ status: 'down,critical' }));
    expect(out.map((h) => h.monitoring).sort()).toEqual(['critical', 'down']);
  });

  test('AND across dimensions', () => {
    const hosts = [
      host({ monitoring: 'down', os: 'RHEL', compliance: 10 }), // matches all
      host({ monitoring: 'down', os: 'Ubuntu', compliance: 10 }), // wrong os
      host({ monitoring: 'online', os: 'RHEL', compliance: 10 }), // wrong status
      host({ monitoring: 'down', os: 'RHEL', compliance: 95 }), // wrong tier
    ];
    const out = applyHostFilters(
      hosts,
      parseHostFilters({ status: 'down', os: 'RHEL', tier: 'crit' }),
    );
    expect(out).toHaveLength(1);
    expect(out[0]!.compliance).toBe(10);
  });

  test('null-compliance host filtered by the none tier, not crit', () => {
    const hosts = [host({ compliance: null }), host({ compliance: 10 })];
    expect(applyHostFilters(hosts, parseHostFilters({ tier: 'none' }))).toHaveLength(1);
    expect(applyHostFilters(hosts, parseHostFilters({ tier: 'crit' }))[0]!.compliance).toBe(10);
  });

  test('parseHostFilters splits + trims; activeFilterCount sums facets', () => {
    const f = parseHostFilters({ status: 'down, critical', os: 'RHEL', tier: '' });
    expect(f.status).toEqual(['down', 'critical']);
    expect(f.os).toEqual(['RHEL']);
    expect(f.tier).toEqual([]);
    expect(activeFilterCount(f)).toBe(3);
    expect(activeFilterCount(parseHostFilters({}))).toBe(0);
  });
});
