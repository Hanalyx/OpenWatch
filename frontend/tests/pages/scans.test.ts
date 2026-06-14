// @spec frontend-scans
//
// AC traceability (this file):
//   AC-01  scan-queue + hosts KPIs; route mounted; sidebar enabled
//   AC-02  Coverage freshness from last_scan_at; History from recent-changes
//   AC-03  read-only + no em-dash copy

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const PAGE_SRC = readFileSync(resolve(process.cwd(), 'src/pages/scans/ScansPage.tsx'), 'utf8');
const ROUTER_SRC = readFileSync(resolve(process.cwd(), 'src/routes/router.tsx'), 'utf8');
const SIDEBAR_SRC = readFileSync(
  resolve(process.cwd(), 'src/components/shell/Sidebar.tsx'),
  'utf8',
);

function stripComments(s: string): string {
  return s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

describe('frontend-scans — scan overview', () => {
  // @ac AC-01
  test('frontend-scans/AC-01 — scan-queue + hosts KPIs; route + sidebar', () => {
    expect(PAGE_SRC).toContain("api.GET('/api/v1/fleet/scan-queue'");
    expect(PAGE_SRC).toContain("api.GET('/api/v1/hosts'");
    expect(PAGE_SRC).toMatch(/Running/);
    expect(PAGE_SRC).toMatch(/Queued/);
    const route = ROUTER_SRC.match(/const scansRoute = createRoute\(\{[\s\S]*?\}\);/);
    expect(route).toBeTruthy();
    expect(route![0]).toMatch(/path:\s*'scans'/);
    expect(route![0]).toMatch(/getParentRoute:\s*\(\)\s*=>\s*protectedRoute/);
    expect(SIDEBAR_SRC).toMatch(/label: 'Scans'[^\n]*enabled: true/);
  });

  // @ac AC-02
  test('frontend-scans/AC-02 — Coverage freshness + History from recent-changes', () => {
    expect(PAGE_SRC).toMatch(/last_scan_at/);
    expect(PAGE_SRC).toMatch(/compliance_summary/);
    expect(PAGE_SRC).toContain("api.GET('/api/v1/fleet/recent-changes'");
    // freshness derived against a 48h window
    expect(PAGE_SRC).toMatch(/48 \* 3_600_000|FRESH_MS/);
  });

  // @ac AC-03
  test('frontend-scans/AC-03 — read-only + no em-dash copy', () => {
    expect(PAGE_SRC).not.toMatch(/api\.(POST|PUT|DELETE)/);
    expect(stripComments(PAGE_SRC)).not.toContain('—');
  });
});
