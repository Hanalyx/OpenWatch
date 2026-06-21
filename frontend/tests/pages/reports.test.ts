// @spec frontend-reports
//
// AC traceability (source inspection over ReportsPage):
//   AC-01  single ['reports'] query against GET /api/v1/reports; Library
//          columns (title/kind/scope/data_as_of/generated_by/format);
//          route mounted at "reports"; sidebar Reports entry enabled
//   AC-02  Generate POSTs /api/v1/reports:generate, invalidates ['reports'],
//          gated on hasPermission('host:write')
//   AC-03  Templates + Scheduled tabs as deferred ComingSoon states;
//          honest loading / empty / error states via apiErrorMessage
//   AC-04  only mutation is the generate POST (no PUT/DELETE); --ow-* tokens;
//          no prose em-dash

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const PAGE_SRC = readFileSync(resolve(process.cwd(), 'src/pages/reports/ReportsPage.tsx'), 'utf8');
const ROUTER_SRC = readFileSync(resolve(process.cwd(), 'src/routes/router.tsx'), 'utf8');
const SIDEBAR_SRC = readFileSync(
  resolve(process.cwd(), 'src/components/shell/Sidebar.tsx'),
  'utf8',
);

function stripComments(s: string): string {
  return s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
}

describe('frontend-reports — reports library page', () => {
  // @ac AC-01
  test('frontend-reports/AC-01 — reports query, Library columns, route + sidebar', () => {
    // One query keyed ['reports'] against the list endpoint.
    expect(PAGE_SRC).toContain("queryKey: ['reports']");
    expect(PAGE_SRC).toContain("api.GET('/api/v1/reports'");
    // Library table is rendered off the response reports.
    expect(PAGE_SRC).toContain('reportsQ.data?.reports');
    // Each row reads the report fields off the row.
    expect(PAGE_SRC).toMatch(/r\.title/);
    expect(PAGE_SRC).toMatch(/r\.kind/);
    expect(PAGE_SRC).toMatch(/r\.scope_label/);
    expect(PAGE_SRC).toMatch(/r\.data_as_of/);
    expect(PAGE_SRC).toMatch(/r\.generated_by/);
    expect(PAGE_SRC).toMatch(/r\.format/);
    // kind renders as a type chip.
    expect(PAGE_SRC).toContain('<KindChip');
    // Route mounted at path 'reports' under protectedRoute.
    const route = ROUTER_SRC.match(/const reportsRoute = createRoute\(\{[\s\S]*?\}\);/);
    expect(route).toBeTruthy();
    expect(route![0]).toMatch(/path:\s*'reports'/);
    expect(route![0]).toMatch(/getParentRoute:\s*\(\)\s*=>\s*protectedRoute/);
    // Sidebar Reports entry is enabled.
    expect(SIDEBAR_SRC).toMatch(/label: 'Reports'[^\n]*enabled: true/);
  });

  // @ac AC-02
  test('frontend-reports/AC-02 — Generate POST, invalidation, host:write gate', () => {
    // Generate posts the action endpoint.
    expect(PAGE_SRC).toContain("api.POST('/api/v1/reports:generate'");
    // On success it invalidates the single reports query.
    expect(PAGE_SRC).toContain("invalidateQueries({ queryKey: ['reports'] })");
    // The control is gated on host:write via useAuthStore.hasPermission.
    expect(PAGE_SRC).toContain("hasPermission('host:write')");
    expect(PAGE_SRC).toContain('canGenerate');
    // The button is disabled when the caller cannot generate.
    expect(PAGE_SRC).toContain('disabled={!canGenerate');
  });

  // @ac AC-03
  test('frontend-reports/AC-03 — deferred Templates/Scheduled + honest states', () => {
    // Templates and Scheduled tabs render the deferred ComingSoon state.
    expect(PAGE_SRC).toContain('ComingSoon');
    expect(PAGE_SRC).toContain('what="Templates"');
    expect(PAGE_SRC).toContain('what="Scheduled"');
    expect(PAGE_SRC.toLowerCase()).toContain('coming soon');
    // Honest loading / empty / error states wired off the query.
    expect(PAGE_SRC).toContain('reportsQ.isPending');
    expect(PAGE_SRC).toContain('reportsQ.isError');
    expect(PAGE_SRC).toContain('apiErrorMessage');
    expect(PAGE_SRC).toContain('kind="loading"');
    expect(PAGE_SRC).toContain('kind="empty"');
    expect(PAGE_SRC).toContain('kind="error"');
  });

  // @ac AC-05
  test('frontend-reports/AC-05 — scope picker (group select) drives the generate body', () => {
    // A scope select bound to scopeGroupId, defaulting to "All hosts".
    expect(PAGE_SRC).toContain('scopeGroupId');
    expect(PAGE_SRC).toMatch(/<select[\s\S]*?value=\{scopeGroupId\}/);
    expect(PAGE_SRC).toContain('<option value="">All hosts</option>');
    // Options come from a ['groups'] query against the groups endpoint.
    expect(PAGE_SRC).toContain("queryKey: ['groups']");
    expect(PAGE_SRC).toContain("api.GET('/api/v1/groups'");
    // The groups query is a host:write affordance (enabled on canGenerate).
    expect(PAGE_SRC).toMatch(/enabled:\s*canGenerate/);
    // The generate body includes group_id only when a group is chosen.
    expect(PAGE_SRC).toMatch(/scopeGroupId\s*\?\s*\{\s*group_id:\s*scopeGroupId\s*\}\s*:\s*\{\}/);
  });

  // @ac AC-06
  test('frontend-reports/AC-06 — coverage caveat discloses stale/unreachable hosts', () => {
    // A CoverageCaveat component reading the coverage counts.
    expect(PAGE_SRC).toContain('function CoverageCaveat');
    expect(PAGE_SRC).toContain('hosts_stale');
    expect(PAGE_SRC).toContain('hosts_unreachable');
    // Renders nothing when the fleet is fully fresh + reachable.
    expect(PAGE_SRC).toMatch(/hosts_stale === 0 && hosts_unreachable === 0\) return null/);
    // ExecutiveBody narrows coverage and renders the caveat.
    expect(PAGE_SRC).toContain('asCoverage');
    expect(PAGE_SRC).toContain('<CoverageCaveat');
  });

  // @ac AC-07
  test('frontend-reports/AC-07 — report detail download controls (pdf/json export)', () => {
    // A downloadReportFace helper hits the export endpoint with the format.
    expect(PAGE_SRC).toContain('function downloadReportFace');
    expect(PAGE_SRC).toMatch(/\/api\/v1\/reports\/\$\{id\}\/export\?format=\$\{format\}/);
    // Cookie auth (same-origin credentials), no bearer token / Authorization.
    expect(PAGE_SRC).toContain("credentials: 'same-origin'");
    expect(PAGE_SRC.includes('Authorization')).toBe(false);
    // The blob is saved via an object URL.
    expect(PAGE_SRC).toContain('URL.createObjectURL');
    // The detail renders Download PDF + JSON controls calling onDownload,
    // with an in-flight disabled state and an error surface.
    expect(PAGE_SRC).toContain('Download PDF');
    expect(PAGE_SRC).toMatch(/onDownload\('pdf'\)/);
    expect(PAGE_SRC).toMatch(/onDownload\('json'\)/);
    expect(PAGE_SRC).toContain('downloading');
    expect(PAGE_SRC).toContain('downloadError');
  });

  // @ac AC-04
  test('frontend-reports/AC-04 — generate is the only mutation, tokens, no em-dash', () => {
    // The only mutating call is the generate POST; no PUT/DELETE.
    expect(PAGE_SRC.includes('api.PUT')).toBe(false);
    expect(PAGE_SRC.includes('api.DELETE')).toBe(false);
    const posts = PAGE_SRC.split('api.POST(').length - 1;
    expect(posts).toBe(1);
    // Chrome is styled with --ow-* tokens, not raw hex literals.
    expect(PAGE_SRC).toContain('var(--ow-bg-1)');
    expect(PAGE_SRC).toContain('var(--ow-line)');
    // No prose copy carries an em-dash (the one em-dash is a leading code
    // comment, which is exempt and stripped before the assertion).
    expect(stripComments(PAGE_SRC).includes('—')).toBe(false);
  });
});
