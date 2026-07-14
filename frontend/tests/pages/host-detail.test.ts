// @spec frontend-host-detail
//
// AC traceability (this file):
//
//   AC-02  test('frontend-host-detail/AC-02 — 404 renders distinct region')
//   AC-03  test('frontend-host-detail/AC-03 — 403 renders authz.permission_denied')
//   AC-04  test('frontend-host-detail/AC-04 — populated summary renders correct math')
//   AC-05  test('frontend-host-detail/AC-05 — empty summary renders friendly message')
//   AC-06  test('frontend-host-detail/AC-06 — liveness=null renders "Not yet probed"')
//   AC-08  test('frontend-host-detail/AC-08 — framework filter updates URL + re-fetches')
//   AC-09  test('frontend-host-detail/AC-09 — Edit button opens modal wired to PATCH /hosts/{id}')
//   AC-37  test('frontend-host-detail/AC-37 — Top failed rules card is live')
//   AC-14  test('frontend-host-detail/AC-14 — no PII field names in console.*')

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const PAGE_SRC = readFileSync(resolve(process.cwd(), 'src/pages/HostDetailPage.tsx'), 'utf8');
const TREND_SRC = readFileSync(
  resolve(process.cwd(), 'src/components/charts/TrendChart.tsx'),
  'utf8',
);

describe('frontend-host-detail — structural', () => {
  // @ac AC-02
  test('frontend-host-detail/AC-02 — 404 renders distinct region', () => {
    expect(PAGE_SRC).toContain('host_not_found');
    expect(PAGE_SRC).toContain('Host not found');
    expect(PAGE_SRC).toContain('Back to hosts');
  });

  // @ac AC-03
  test('frontend-host-detail/AC-03 — 403 renders authz.permission_denied', () => {
    expect(PAGE_SRC).toContain("'authz.permission_denied'");
    expect(PAGE_SRC).toContain('Access denied');
  });

  // @ac AC-04
  test('frontend-host-detail/AC-04 — populated summary math: passing / total', () => {
    // The component computes pct = Math.round(passing / total * 100).
    expect(PAGE_SRC).toContain('summary.passing / summary.total');
    expect(PAGE_SRC).toContain('Math.round');
    // Per-status renderers
    expect(PAGE_SRC).toMatch(/label="passing"/);
    expect(PAGE_SRC).toMatch(/label="failing"/);
    expect(PAGE_SRC).toMatch(/label="skipped"/);
    expect(PAGE_SRC).toMatch(/label="error"/);
  });

  // @ac AC-05
  test('frontend-host-detail/AC-05 — empty summary renders friendly message', () => {
    expect(PAGE_SRC).toContain('No compliance data for this host yet');
    expect(PAGE_SRC).toContain('summary.total === 0');
  });

  // @ac AC-06
  test('frontend-host-detail/AC-06 — liveness=null renders "Not yet probed"', () => {
    expect(PAGE_SRC).toContain('Not yet probed');
    expect(PAGE_SRC).toContain('liveness === null');
  });

  // @ac AC-08
  test('frontend-host-detail/AC-08 — framework filter updates URL + re-fetches', () => {
    expect(PAGE_SRC).toContain("'/api/v1/hosts/{id}'");
    expect(PAGE_SRC).toContain('framework');
    // Query key includes framework so TanStack Query refetches on change.
    expect(PAGE_SRC).toMatch(/queryKey:\s*\[\s*['"]host['"],\s*hostId,\s*framework\s*\]/);
    // URL update on framework change
    expect(PAGE_SRC).toContain('onFrameworkChange');
    expect(PAGE_SRC).toContain('navigate');
  });

  // @ac AC-09
  test('frontend-host-detail/AC-09 — Edit button opens modal wired to PATCH /hosts/{id}', () => {
    // Source of truth lives in EditHostModal; the page imports it and
    // mounts it from the IdentityHeader.
    expect(PAGE_SRC).toContain('EditHostModal');
    expect(PAGE_SRC).toContain('setEditOpen');
    expect(PAGE_SRC).toMatch(/aria-label=.*Edit \$\{host\.hostname\}/);

    const MODAL_SRC = readFileSync(
      resolve(process.cwd(), 'src/components/hosts/EditHostModal.tsx'),
      'utf8',
    );
    // The modal uses PATCH /hosts/{id} (api-hosts AC-09) and invalidates
    // both the per-host query and the list query on success.
    expect(MODAL_SRC).toContain("api.PATCH('/api/v1/hosts/{id}'");
    expect(MODAL_SRC).toContain("queryKey: ['host', host.id]");
    expect(MODAL_SRC).toContain("queryKey: ['hosts']");
    // Hostname is immutable per api-hosts C-04 — modal must say so.
    expect(MODAL_SRC).toContain('Hostname is immutable');
  });

  // @ac AC-36
  test('frontend-host-detail/AC-36 — Run scan button is live: POST + idempotency key + 409 note + no polling', () => {
    // Live wiring, not the disabled placeholder.
    expect(PAGE_SRC).not.toContain('Run scan (deferred)');
    expect(PAGE_SRC).toContain("api.POST('/api/v1/hosts/{id}/scans'");
    expect(PAGE_SRC).toContain("'Idempotency-Key': crypto.randomUUID()");
    // 409 is a transient note, not an error path.
    expect(PAGE_SRC).toContain('Scan already running');
    // No polling: the refresh comes from the scan.completed SSE topic
    // (frontend-live-events C-07); the page must not setInterval-poll
    // the host query after queueing a scan.
    expect(PAGE_SRC).not.toMatch(/setInterval\([^)]*host/);
  });

  // @ac AC-37
  test('frontend-host-detail/AC-37 — Top failed rules card is live: endpoint, key prefix, states, no evidence', () => {
    // Wired query under the ['host', hostId] prefix so scan.completed
    // SSE invalidation refreshes it for free.
    expect(PAGE_SRC).toContain("queryKey: ['host', hostId, 'failed_rules', framework ?? null]");
    expect(PAGE_SRC).toContain("'/api/v1/hosts/{id}/compliance/failed-rules'");
    expect(PAGE_SRC).toContain('limit: 5');
    // Footer count + Compliance tab routing.
    expect(PAGE_SRC).toContain('View all {total} failed rules');
    expect(PAGE_SRC).toMatch(/total_failing/);
    // Honest states: zero-failing copy exists alongside never-scanned copy.
    expect(PAGE_SRC).toContain('No failing rules');
    expect(PAGE_SRC).toContain('No scan results yet');
    // Evidence never displayed by the card (api-host-compliance C-02);
    // the response shape has no evidence field and the card must not
    // reference one.
    // Slice ends at CardComplianceTrend — SeverityPill moved to
    // host-detail/SeverityPill.tsx (frontend-host-compliance-tab v1.0.0).
    const cardSlice = PAGE_SRC.slice(
      PAGE_SRC.indexOf('function CardTopFailed'),
      PAGE_SRC.indexOf('function CardComplianceTrend'),
    );
    expect(cardSlice).not.toMatch(/evidence/i);
    // No dead Remediate action before Phase 7.
    expect(cardSlice).not.toContain('Remediate');
  });

  // @ac AC-46
  test('frontend-host-detail/AC-46 — Compliance trend uses the shared interactive TrendChart', () => {
    // Host card wires the shared chart with a per-point tooltip and a
    // first-snapshot-relative delta label (not a point count).
    expect(PAGE_SRC).toContain('TrendChart');
    expect(PAGE_SRC).toContain('scorePct: d.score_pct');
    expect(PAGE_SRC).toContain('passing`');
    expect(PAGE_SRC).toContain('% since {first.date}');
    // Shared chart: fixed 0..100 domain (score/100), 80% target line, hover
    // state + tooltip, and a gap-broken line (dayIndex delta != 1).
    expect(TREND_SRC).toContain('useState');
    expect(TREND_SRC).toContain('onMouseMove');
    expect(TREND_SRC).toMatch(/targetPct/);
    expect(TREND_SRC).toMatch(/\/\s*100/); // 0..100 domain
    expect(TREND_SRC).toMatch(/!==\s*1/); // gap-break: not exactly one day apart
    expect(TREND_SRC).toContain('tooltip');
  });

  // @ac AC-14
  test('frontend-host-detail/AC-14 — no PII field names in console.*', () => {
    const deny = ['evidence', 'token', 'password', 'secret'];
    for (const field of deny) {
      const re = new RegExp(`console\\.(log|warn|error)\\([^)]*['"]?${field}['"]?\\s*[:=]`, 'i');
      expect(PAGE_SRC).not.toMatch(re);
    }
  });

  // @ac AC-39
  test('frontend-host-detail/AC-39 — Edit gated on host:write; three-dot Delete gated on host:delete with confirm + navigate', () => {
    // Edit button is permission-gated (hidden without host:write).
    expect(PAGE_SRC).toMatch(/hasPermission\('host:write'\)/);
    expect(PAGE_SRC).toMatch(/canWrite\s*&&[\s\S]{0,200}setEditOpen\(true\)/);
    // The page-head mounts the actions menu in delete-only mode, navigating
    // back to /hosts after a successful delete.
    expect(PAGE_SRC).toContain('HostActionsMenu');
    expect(PAGE_SRC).toMatch(/showEdit=\{false\}/);
    expect(PAGE_SRC).toMatch(/afterDelete="navigate"/);

    const MENU_SRC = readFileSync(
      resolve(process.cwd(), 'src/components/hosts/HostActionsMenu.tsx'),
      'utf8',
    );
    // Delete is host:delete-gated, confirmed, and hits DELETE /hosts/{id}.
    expect(MENU_SRC).toMatch(/hasPermission\('host:delete'\)/);
    expect(MENU_SRC).toContain('DeleteHostModal');
    expect(MENU_SRC).toContain("api.DELETE('/api/v1/hosts/{id}'");
    expect(MENU_SRC).toMatch(/cannot be undone/i);
    // Navigates to /hosts on the detail variant after delete.
    expect(MENU_SRC).toMatch(/navigate\(\{\s*to:\s*'\/hosts'\s*\}\)/);
  });

  // @ac AC-45
  test('frontend-host-detail/AC-45 — hero + Run scan reflect in-flight scan_state', () => {
    // The detail query threads last_scan_at + scan_state through, and the
    // hero is no longer hardcoded lastScan={null}.
    expect(PAGE_SRC).toMatch(/last_scan_at:\s*raw\.last_scan_at/);
    expect(PAGE_SRC).toMatch(/scan_state:\s*raw\.scan_state/);
    expect(PAGE_SRC).not.toMatch(/<HeroCompliance[\s\S]*?lastScan=\{null\}/);
    expect(PAGE_SRC).toMatch(/scanState=\{detailQuery\.data\.scan_state/);
    // Hero shows a Running/Queued badge instead of LAST SCAN when active.
    expect(PAGE_SRC).toMatch(/scanState === 'running' \? 'Running' : 'Queued'/);
    // Run scan button stays disabled + labelled while active.
    expect(PAGE_SRC).toMatch(/const active = scanState === 'running' \|\| scanState === 'queued'/);
    expect(PAGE_SRC).toMatch(/disabled=\{busy \|\| active\}/);
    expect(PAGE_SRC).toMatch(/scanState === 'running'\s*\?\s*'Running…'/);
  });
});
