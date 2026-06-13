// @spec frontend-homepage
//
// AC traceability (this file):
//   AC-01  router: public "/" route under rootRoute; dashboard at /dashboard
//   AC-02  HomePage Enter-console -> /login; no authenticated data call
//   AC-03  RadarField canvas aria-hidden; readout literals; no em-dash copy
//   AC-04  RadarField cancels rAF on cleanup + honors prefers-reduced-motion

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const ROUTER_SRC = readFileSync(resolve(process.cwd(), 'src/routes/router.tsx'), 'utf8');
const HOME_SRC = readFileSync(resolve(process.cwd(), 'src/pages/HomePage.tsx'), 'utf8');
const RADAR_SRC = readFileSync(resolve(process.cwd(), 'src/components/RadarField.tsx'), 'utf8');

// Strip block comments (incl. JSX {/* */}) and full-line // comments so a
// "no em-dash in copy" assertion does not trip on code comments, which
// the project copy rule exempts.
function stripComments(s: string): string {
  return s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

describe('frontend-homepage — public Radar hero', () => {
  // @ac AC-01
  test('frontend-homepage/AC-01 — "/" is a public route under rootRoute; dashboard moved to /dashboard', () => {
    const m = ROUTER_SRC.match(/const publicHomeRoute = createRoute\(\{[\s\S]*?\}\);/);
    expect(m).toBeTruthy();
    const block = m![0];
    expect(block).toMatch(/getParentRoute:\s*\(\)\s*=>\s*rootRoute/);
    expect(block).toMatch(/path:\s*['"]\/['"]/);
    expect(block).toMatch(/component:\s*HomePage/);
    // Public: the homepage route carries no auth guard.
    expect(block).not.toMatch(/beforeLoad/);
    // The dashboard now lives at /dashboard under the protected subtree.
    const dash = ROUTER_SRC.match(/const dashboardRoute = createRoute\(\{[\s\S]*?\}\);/);
    expect(dash).toBeTruthy();
    expect(dash![0]).toMatch(/getParentRoute:\s*\(\)\s*=>\s*protectedRoute/);
    expect(dash![0]).toMatch(/path:\s*['"]dashboard['"]/);
  });

  // @ac AC-02
  test('frontend-homepage/AC-02 — Enter console routes to /login; no authenticated data call', () => {
    expect(HOME_SRC).toMatch(/to=["']\/login["']/);
    // The public page makes no authenticated API calls.
    expect(HOME_SRC).not.toMatch(/api\.(GET|POST|PUT|DELETE)/);
    expect(HOME_SRC).not.toMatch(/\bfetch\(/);
    expect(HOME_SRC).not.toMatch(/useQuery/);
  });

  // @ac AC-03
  test('frontend-homepage/AC-03 — decorative canvas + static readout + no em-dash copy', () => {
    // The radar canvas is decoration (aria-hidden).
    expect(RADAR_SRC).toMatch(/aria-hidden=["']true["']/);
    // The readout is built from static literals, not a fetched query.
    expect(HOME_SRC).toMatch(/hosts acquired/);
    expect(HOME_SRC).not.toMatch(/useQuery/);
    // No em-dash in UI copy (code comments stripped first).
    expect(stripComments(HOME_SRC)).not.toContain('—');
  });

  // @ac AC-04
  test('frontend-homepage/AC-04 — radar animation cleans up + honors reduced motion', () => {
    expect(RADAR_SRC).toMatch(/cancelAnimationFrame/);
    expect(RADAR_SRC).toMatch(/prefers-reduced-motion/);
    // The effect returns a cleanup function.
    expect(RADAR_SRC).toMatch(/return\s*\(\)\s*=>\s*\{/);
  });
});
