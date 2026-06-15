// @spec frontend-hosts-list
//
// AC traceability (this file):
//
//   AC-02  test('frontend-hosts-list/AC-02 — empty no-filter renders first-run state')
//   AC-03  test('frontend-hosts-list/AC-03 — empty WITH filter renders no-match state')
//   AC-07  test('frontend-hosts-list/AC-07 — network failure renders distinct region')
//   AC-08  test('frontend-hosts-list/AC-08 — Add host link gated on host:write')
//   AC-12  test('frontend-hosts-list/AC-12 — uses openapi-fetch client, not raw fetch')
//   AC-13  test('frontend-hosts-list/AC-13 — per-host Scan buttons live')
//   AC-14  test('frontend-hosts-list/AC-14 — scan-queue KPI wired')
//   AC-15  test('frontend-hosts-list/AC-15 — no dead fleet Run scan header control')
//   AC-16  test('frontend-hosts-list/AC-16 — compliance_summary maps to real compliance with null honesty')
//   AC-17  test('frontend-hosts-list/AC-17 — avg compliance KPI excludes never-scanned hosts')
//   AC-18  test('frontend-hosts-list/AC-18 — critical issues KPI sums critical_failing with affected-hosts scope')

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  apiHostToDev,
  kpisFromHosts,
  type ApiHost,
  type ApiHostComplianceSummary,
} from '@/pages/HostsListPage';
import type { DevHost } from '@/api/dev-fixtures';

const PAGE_SRC = readFileSync(resolve(process.cwd(), 'src/pages/HostsListPage.tsx'), 'utf8');

function makeApiHost(overrides: Partial<ApiHost> = {}): ApiHost {
  return {
    id: 'h-1',
    hostname: 'owas-rhn01',
    ip_address: '10.0.0.1',
    created_at: '2026-05-01T00:00:00Z',
    updated_at: '2026-05-01T00:00:00Z',
    ...overrides,
  };
}

function makeSummary(overrides: Partial<ApiHostComplianceSummary> = {}): ApiHostComplianceSummary {
  return {
    passing: 0,
    failing: 0,
    skipped: 0,
    error: 0,
    total: 0,
    critical_failing: 0,
    ...overrides,
  };
}

function makeDevHost(overrides: Partial<DevHost> = {}): DevHost {
  return {
    id: 'd-1',
    hostname: 'owas-ub01',
    ip_address: '10.0.0.2',
    os: 'Ubuntu',
    status: 'online',
    monitoring: 'online',
    compliance: null,
    passed: null,
    failed: null,
    total: 0,
    lastCheckMinutes: null,
    lastScan: '—',
    ...overrides,
  };
}

describe('frontend-hosts-list — structural', () => {
  // @ac AC-02
  test('frontend-hosts-list/AC-02 — empty no-filter renders first-run state', () => {
    expect(PAGE_SRC).toContain('No hosts yet');
    expect(PAGE_SRC).toContain('Add your first host');
  });

  // @ac AC-03
  test('frontend-hosts-list/AC-03 — empty WITH filter renders no-match state', () => {
    expect(PAGE_SRC).toContain('No hosts match your filters');
    expect(PAGE_SRC).toContain('Clear filters');
  });

  // @ac AC-07
  test('frontend-hosts-list/AC-07 — network failure renders distinct region with Retry', () => {
    expect(PAGE_SRC).toContain('Failed to load hosts');
    expect(PAGE_SRC).toMatch(/role="alert"/);
    expect(PAGE_SRC).toContain('Retry');
  });

  // @ac AC-08
  test('frontend-hosts-list/AC-08 — Add host link gated on host:write', () => {
    // The button is rendered only when canWrite is true (which comes
    // from useAuthStore().hasPermission('host:write')).
    expect(PAGE_SRC).toContain("hasPermission('host:write')");
    // Guarded in JSX
    expect(PAGE_SRC).toMatch(/canWrite\s*&&/);
    // The empty-state also gates its add-host link.
    expect(PAGE_SRC).toMatch(/canAdd\s*&&/);
  });

  // @ac AC-12
  test('frontend-hosts-list/AC-12 — uses openapi-fetch client, not raw fetch', () => {
    // Must call the typed API client.
    expect(PAGE_SRC).toContain("api.GET('/api/v1/hosts'");
    // No raw fetch() calls that hardcode the path.
    expect(PAGE_SRC).not.toMatch(/\bfetch\s*\(\s*['"`]\/api\/v1\/hosts/);
  });
});

// @ac AC-13
test('frontend-hosts-list/AC-13 — per-host Scan buttons are live with idempotency + 409 note + write gating', () => {
  expect(PAGE_SRC).toContain("api.POST('/api/v1/hosts/{id}/scans'");
  expect(PAGE_SRC).toContain("'Idempotency-Key': crypto.randomUUID()");
  expect(PAGE_SRC).toContain('Scan already running');
  // Hidden without host:write.
  const btnSlice = PAGE_SRC.slice(
    PAGE_SRC.indexOf('function ScanHostButton'),
    PAGE_SRC.indexOf('function HostCard'),
  );
  expect(btnSlice).toContain("hasPermission('host:write')");
  expect(btnSlice).toContain('if (!canWrite) return null');
  // No polling loops.
  expect(btnSlice).not.toMatch(/setInterval/);
});

// @ac AC-14
test('frontend-hosts-list/AC-14 — scan-queue KPI wired to /fleet/scan-queue', () => {
  expect(PAGE_SRC).toContain("queryKey: ['fleet', 'scan_queue']");
  expect(PAGE_SRC).toContain("api.GET('/api/v1/fleet/scan-queue'");
  expect(PAGE_SRC).toMatch(/queued/);
  expect(PAGE_SRC).toMatch(/running/);
});

// @ac AC-15
test('frontend-hosts-list/AC-15 — no dead fleet-wide Run scan header control', () => {
  // The header must not render a Run scan button; per-host buttons live
  // inside ScanHostButton only.
  const beforeScanBtn = PAGE_SRC.slice(0, PAGE_SRC.indexOf('function ScanHostButton'));
  expect(beforeScanBtn).not.toMatch(/aria-label="Run scan"/);
});

describe('frontend-hosts-list — v1.3.0 real fleet compliance', () => {
  // @ac AC-16
  test('frontend-hosts-list/AC-16 — compliance_summary maps to real compliance with null honesty', () => {
    // Scanned host: percentage rounded to one decimal, counts carried.
    const scanned = apiHostToDev(
      makeApiHost({
        compliance_summary: makeSummary({
          passing: 400,
          failing: 100,
          skipped: 5,
          error: 3,
          total: 508,
          critical_failing: 4,
        }),
      }),
    );
    expect(scanned.compliance).toBe(78.7); // round(400/508*1000)/10
    expect(scanned.passed).toBe(400);
    expect(scanned.failed).toBe(100);
    expect(scanned.total).toBe(508);
    expect(scanned.criticalFailing).toBe(4);

    // Never-scanned host (null summary): everything stays null, no
    // placeholder zeros.
    const never = apiHostToDev(makeApiHost({ compliance_summary: null }));
    expect(never.compliance).toBeNull();
    expect(never.passed).toBeNull();
    expect(never.failed).toBeNull();
    expect(never.total).toBe(0);
    expect(never.criticalFailing).toBe(0);

    // Summary absent entirely (older payload): same null honesty.
    const absent = apiHostToDev(makeApiHost());
    expect(absent.compliance).toBeNull();
    expect(absent.passed).toBeNull();

    // Degenerate zero-rule summary must NOT divide by zero or render 0%.
    const empty = apiHostToDev(makeApiHost({ compliance_summary: makeSummary() }));
    expect(empty.compliance).toBeNull();
    expect(empty.passed).toBeNull();

    // The null branch keeps the honest copy in the card, and the
    // non-null branch renders via the shared tier helper.
    expect(PAGE_SRC).toContain('No scan data');
    expect(PAGE_SRC).toContain('Scan needed');
    expect(PAGE_SRC).toMatch(/complianceTier\(host\.compliance\)/);
  });

  // @ac AC-17
  test('frontend-hosts-list/AC-17 — avg compliance KPI excludes never-scanned hosts', () => {
    const hosts: DevHost[] = [
      makeDevHost({ id: 'a', compliance: 90, passed: 90, failed: 10, total: 100 }),
      // Never scanned: must NOT drag the average toward zero.
      makeDevHost({ id: 'b', compliance: null, passed: null, failed: null, total: 0 }),
      makeDevHost({ id: 'c', compliance: null, passed: null, failed: null, total: 0 }),
    ];
    const kpis = kpisFromHosts(hosts);
    // Weighted average over the single scanned host = 90, not 30.
    expect(kpis.avgCompliance.value).toBe(90);

    // All-never-scanned fleet: average is 0, not NaN.
    const noneScanned = kpisFromHosts([makeDevHost({ id: 'x' }), makeDevHost({ id: 'y' })]);
    expect(noneScanned.avgCompliance.value).toBe(0);
  });

  // @ac AC-18
  test('frontend-hosts-list/AC-18 — critical issues KPI sums critical_failing with affected-hosts scope', () => {
    const hosts: DevHost[] = [
      makeDevHost({ id: 'a', criticalFailing: 3 }),
      makeDevHost({ id: 'b', criticalFailing: 2 }),
      makeDevHost({ id: 'c', criticalFailing: 0 }),
      makeDevHost({ id: 'd' }), // never scanned, field absent
    ];
    const kpis = kpisFromHosts(hosts);
    expect(kpis.criticalIssues.value).toBe(5);
    expect(kpis.criticalIssues.scope).toBe('2 hosts affected');

    // Singular form.
    const one = kpisFromHosts([makeDevHost({ id: 'a', criticalFailing: 1 })]);
    expect(one.criticalIssues.scope).toBe('1 host affected');

    // Zero critical issues keeps the honest "No data" scope.
    const clean = kpisFromHosts([makeDevHost({ id: 'a' })]);
    expect(clean.criticalIssues.value).toBe(0);
    expect(clean.criticalIssues.scope).toBe('No data');
  });
});

describe('frontend-hosts-list v1.4.0 — fleet trend delta', () => {
  // @ac AC-19
  test('frontend-hosts-list/AC-19 — avg-compliance delta reads the fleet trend; empty below two days', () => {
    expect(PAGE_SRC).toContain("queryKey: ['fleet', 'compliance', 'trend']");
    expect(PAGE_SRC).toContain("api.GET('/api/v1/fleet/compliance/trend'");
    // Delta only renders with >= 2 snapshot days.
    expect(PAGE_SRC).toContain('if (days.length >= 2)');
    expect(PAGE_SRC).toMatch(/vs yesterday/);
    // Tier by direction.
    expect(PAGE_SRC).toContain("diff > 0 ? 'ok' : diff < 0 ? 'crit' : 'neutral'");
    // kpisFromHosts itself never fabricates a delta.
    expect(PAGE_SRC).toMatch(/avgCompliance: \{ value: avgCompliance, target: 80, delta: '',/);
  });
});

describe('frontend-hosts-list v1.5.0 — card/row actions menu', () => {
  // @ac AC-20
  test('frontend-hosts-list/AC-20 — card + row render HostActionsMenu; edit (host:write) + delete (host:delete) with confirm', () => {
    // Both the card and the table row mount the actions menu.
    expect(PAGE_SRC).toContain('HostActionsMenu');
    expect((PAGE_SRC.match(/<HostActionsMenu/g) ?? []).length).toBeGreaterThanOrEqual(2);

    const MENU_SRC = readFileSync(
      resolve(process.cwd(), 'src/components/hosts/HostActionsMenu.tsx'),
      'utf8',
    );
    // Permission gating: Edit -> host:write, Delete -> host:delete; a caller
    // with neither gets no menu.
    expect(MENU_SRC).toMatch(/hasPermission\('host:write'\)/);
    expect(MENU_SRC).toMatch(/hasPermission\('host:delete'\)/);
    expect(MENU_SRC).toMatch(/if \(!showEditItem && !canDelete\) return null/);
    // Edit fetches the full host then opens EditHostModal (PATCH path).
    expect(MENU_SRC).toContain("api.GET('/api/v1/hosts/{id}'");
    expect(MENU_SRC).toContain('EditHostModal');
    // The GET response nests the record under `host`; the menu MUST unwrap it
    // so the edit form pre-fills (passing the wrapper leaves every field blank).
    expect(MENU_SRC).toMatch(/\.host\b/);
    // Delete is confirmed before the DELETE call and invalidates ['hosts'].
    expect(MENU_SRC).toContain('DeleteHostModal');
    expect(MENU_SRC).toContain("api.DELETE('/api/v1/hosts/{id}'");
    expect(MENU_SRC).toMatch(/cannot be undone/i);
    expect(MENU_SRC).toContain("queryKey: ['hosts']");
  });
});
