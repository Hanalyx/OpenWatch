// @spec frontend-activity
//
// AC traceability (this file):
//   AC-01  infinite query over /api/v1/activity + filters + cursor + hidden_count
//   AC-02  alert-source lifecycle actions gated by alert:write; route + sidebar
//   AC-03  drawer fetches /alerts/{id} only for source==='alert'; basic for all
//   AC-04  read-only apart from alert actions; no em-dash copy

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const PAGE_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/activity/ActivityPage.tsx'),
  'utf8',
);
const DRAWER_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/activity/ActivityDrawer.tsx'),
  'utf8',
);
const ACTIONS_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/activity/useAlertActions.ts'),
  'utf8',
);
const ROUTER_SRC = readFileSync(resolve(process.cwd(), 'src/routes/router.tsx'), 'utf8');
const SIDEBAR_SRC = readFileSync(
  resolve(process.cwd(), 'src/components/shell/Sidebar.tsx'),
  'utf8',
);

function stripComments(s: string): string {
  return s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

describe('frontend-activity — unified event feed', () => {
  // @ac AC-01
  test('frontend-activity/AC-01 — infinite query over /api/v1/activity with filters + cursor + hidden_count', () => {
    expect(PAGE_SRC).toMatch(/useInfiniteQuery\(/);
    expect(PAGE_SRC).toContain("api.GET('/api/v1/activity'");
    // filters wired into the query params
    expect(PAGE_SRC).toMatch(/source\s*\?\s*\{\s*source\s*\}/);
    expect(PAGE_SRC).toMatch(/severity\s*\?\s*\{\s*severity\s*\}/);
    expect(PAGE_SRC).toMatch(/host_id:\s*hostId/);
    // cursor pagination + hidden_count
    expect(PAGE_SRC).toMatch(/getNextPageParam/);
    expect(PAGE_SRC).toMatch(/next_cursor/);
    expect(PAGE_SRC).toMatch(/hidden_count/);
    expect(PAGE_SRC).toMatch(/hasNextPage/);
  });

  // @ac AC-02
  test('frontend-activity/AC-02 — alert-source lifecycle actions gated by alert:write; route + sidebar', () => {
    // gated on alert:write
    expect(PAGE_SRC).toMatch(/hasPermission\(\s*'alert:write'\s*\)/);
    // actions only on alert-source rows
    expect(PAGE_SRC).toMatch(/source === 'alert'/);
    expect(PAGE_SRC).toMatch(/isAlert && canAlertWrite/);
    // the mutation POSTs the colon-action against the alert id
    expect(ACTIONS_SRC).toMatch(/\/api\/v1\/alerts\/\{id\}:\$\{vars\.action\}/);
    expect(ACTIONS_SRC).toMatch(/api\.POST\(/);
    // route mounted + sidebar enabled
    const route = ROUTER_SRC.match(/const activityRoute = createRoute\(\{[\s\S]*?\}\);/);
    expect(route).toBeTruthy();
    expect(route![0]).toMatch(/path:\s*'activity'/);
    expect(route![0]).toMatch(/getParentRoute:\s*\(\)\s*=>\s*protectedRoute/);
    expect(SIDEBAR_SRC).toMatch(/label: 'Activity'[^\n]*enabled: true/);
  });

  // @ac AC-03
  test('frontend-activity/AC-03 — drawer enriches alert via /alerts/{id}; basic for all sources', () => {
    expect(DRAWER_SRC).toContain("api.GET('/api/v1/alerts/{id}'");
    // the alert fetch is gated on source === alert
    expect(DRAWER_SRC).toMatch(/isAlert\s*=\s*item\?\.source === 'alert'/);
    expect(DRAWER_SRC).toMatch(/enabled:\s*!!item && isAlert/);
    // basic fields render for any source (title in header, source/severity/time)
    expect(DRAWER_SRC).toMatch(/item\.title/);
    expect(DRAWER_SRC).toMatch(/item\.source/);
  });

  // @ac AC-04
  test('frontend-activity/AC-04 — read-only apart from alert actions; no em-dash copy', () => {
    // No mutation anywhere except the alert lifecycle POST.
    for (const src of [PAGE_SRC, DRAWER_SRC]) {
      expect(src).not.toMatch(/api\.(PUT|DELETE)/);
      expect(src).not.toMatch(/api\.POST/); // POSTs live only in useAlertActions
    }
    // the only POST is the alerts colon-action
    const posts = ACTIONS_SRC.match(/api\.POST\(/g) ?? [];
    expect(posts.length).toBe(1);
    // no em-dash in UI copy (comments stripped)
    for (const src of [PAGE_SRC, DRAWER_SRC]) {
      expect(stripComments(src)).not.toContain('—');
    }
  });
});
