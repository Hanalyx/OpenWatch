// @spec frontend-dashboard
//
// AC traceability (this file):
//   AC-01  router mounts DashboardPage at /dashboard; page composes the widgets
//   AC-02  each widget GETs its named live fleet/activity endpoint via useQuery
//   AC-03  every widget renders loading + error states (WidgetState)
//   AC-04  read-only (no api.POST/PUT/DELETE) + no em-dash copy

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const ROUTER_SRC = readFileSync(resolve(process.cwd(), 'src/routes/router.tsx'), 'utf8');
const PAGE_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/dashboard/DashboardPage.tsx'),
  'utf8',
);
const WIDGETS_SRC = readFileSync(resolve(process.cwd(), 'src/pages/dashboard/widgets.tsx'), 'utf8');
const PRIM_SRC = readFileSync(resolve(process.cwd(), 'src/pages/dashboard/primitives.tsx'), 'utf8');

function stripComments(s: string): string {
  return s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

const ENDPOINTS = [
  '/api/v1/fleet/liveness',
  '/api/v1/fleet/score',
  '/api/v1/fleet/scan-queue',
  '/api/v1/fleet/compliance/trend',
  '/api/v1/fleet/top-failing-rules',
  '/api/v1/fleet/top-failing-hosts',
  '/api/v1/activity',
];

describe('frontend-dashboard — fleet overview', () => {
  // @ac AC-01
  test('frontend-dashboard/AC-01 — DashboardPage mounted at /dashboard composes the widgets', () => {
    const dash = ROUTER_SRC.match(/const dashboardRoute = createRoute\(\{[\s\S]*?\}\);/);
    expect(dash).toBeTruthy();
    expect(dash![0]).toMatch(/path:\s*['"]dashboard['"]/);
    expect(dash![0]).toMatch(/getParentRoute:\s*\(\)\s*=>\s*protectedRoute/);
    expect(dash![0]).toMatch(/component:\s*DashboardPage/);
    // The page composes each widget.
    for (const w of [
      'KpiHostsOnline',
      'KpiAvgCompliance',
      'KpiScanQueue',
      'WidgetComplianceTrend',
      'WidgetTopFailingRules',
      'WidgetTopFailingHosts',
      'WidgetRecentActivity',
    ]) {
      expect(PAGE_SRC).toContain(`<${w} `.trimEnd());
    }
  });

  // @ac AC-02
  test('frontend-dashboard/AC-02 — each widget GETs its live endpoint via useQuery', () => {
    for (const ep of ENDPOINTS) {
      expect(WIDGETS_SRC).toContain(`api.GET('${ep}'`);
    }
    // Queries, not ad-hoc fetches.
    expect(WIDGETS_SRC).toMatch(/useQuery\(/);
    expect(WIDGETS_SRC).not.toMatch(/\bfetch\(/);
  });

  // @ac AC-03
  test('frontend-dashboard/AC-03 — widgets render independent loading + error states', () => {
    // Each widget branches on isPending / isError and uses the shared
    // WidgetState body. Count occurrences to ensure it is per-widget, not
    // a single page-level guard.
    expect(PRIM_SRC).toMatch(/export function WidgetState/);
    const pending = WIDGETS_SRC.match(/isPending/g) ?? [];
    const errored = WIDGETS_SRC.match(/isError/g) ?? [];
    expect(pending.length).toBeGreaterThanOrEqual(7);
    expect(errored.length).toBeGreaterThanOrEqual(7);
    expect(WIDGETS_SRC).toMatch(/WidgetState kind="loading"/);
    expect(WIDGETS_SRC).toMatch(/WidgetState kind="error"/);
  });

  // @ac AC-04
  test('frontend-dashboard/AC-04 — read-only + no em-dash copy', () => {
    for (const src of [PAGE_SRC, WIDGETS_SRC, PRIM_SRC]) {
      expect(src).not.toMatch(/api\.(POST|PUT|DELETE)/);
      expect(stripComments(src)).not.toContain('—');
    }
  });
});
