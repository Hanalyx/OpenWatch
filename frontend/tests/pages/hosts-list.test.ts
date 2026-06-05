// @spec frontend-hosts-list
//
// AC traceability (this file):
//
//   AC-02  test('frontend-hosts-list/AC-02 — empty no-filter renders first-run state')
//   AC-03  test('frontend-hosts-list/AC-03 — empty WITH filter renders no-match state')
//   AC-07  test('frontend-hosts-list/AC-07 — network failure renders distinct region')
//   AC-08  test('frontend-hosts-list/AC-08 — Add host link gated on host:write')
//   AC-12  test('frontend-hosts-list/AC-12 — uses openapi-fetch client, not raw fetch')

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const PAGE_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/HostsListPage.tsx'),
  'utf8',
);

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
