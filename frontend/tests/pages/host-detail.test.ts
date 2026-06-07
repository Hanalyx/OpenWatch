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
//   AC-14  test('frontend-host-detail/AC-14 — no PII field names in console.*')

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const PAGE_SRC = readFileSync(resolve(process.cwd(), 'src/pages/HostDetailPage.tsx'), 'utf8');

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

  // @ac AC-14
  test('frontend-host-detail/AC-14 — no PII field names in console.*', () => {
    const deny = ['evidence', 'token', 'password', 'secret'];
    for (const field of deny) {
      const re = new RegExp(`console\\.(log|warn|error)\\([^)]*['"]?${field}['"]?\\s*[:=]`, 'i');
      expect(PAGE_SRC).not.toMatch(re);
    }
  });
});
