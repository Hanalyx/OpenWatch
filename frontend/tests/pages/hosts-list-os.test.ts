// @spec frontend-host-list-os
//
// AC traceability (this file):
//
//   AC-04  test('frontend-host-list-os/AC-04 — apiHostToDev derives OS from os_family, not hostname')
//   AC-05  test('frontend-host-list-os/AC-05 — detectOS heuristic is removed from the page')
//   AC-06  test('frontend-host-list-os/AC-06 — osDisplayLabel is imported and used by apiHostToDev')
//   AC-07  test('frontend-host-list-os/AC-07 — OSChip falls back to OS_COLOR_FALLBACK for unmapped families')

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { apiHostToDev, type ApiHost } from '@/pages/HostsListPage';

const PAGE_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/HostsListPage.tsx'),
  'utf8',
);

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

describe('frontend-host-list-os — behavioral', () => {
  // @ac AC-04
  test('frontend-host-list-os/AC-04 — apiHostToDev derives OS from os_family, not hostname', () => {
    // Hostname suggests RHEL but os_family is null -> Unknown.
    // This is the proof-positive that the hostname heuristic is gone.
    const preDiscovery = apiHostToDev(
      makeApiHost({ hostname: 'owas-rhn01', os_family: null }),
    );
    expect(preDiscovery.os).toBe('Unknown');

    // Real os_family wins.
    const discovered = apiHostToDev(
      makeApiHost({ hostname: 'random-name', os_family: 'rhel' }),
    );
    expect(discovered.os).toBe('RHEL');

    const ubuntuHost = apiHostToDev(
      makeApiHost({ hostname: 'doesnt-matter', os_family: 'ubuntu' }),
    );
    expect(ubuntuHost.os).toBe('Ubuntu');
  });
});

describe('frontend-host-list-os — structural', () => {
  // @ac AC-05
  test('frontend-host-list-os/AC-05 — detectOS heuristic is removed from the page', () => {
    expect(PAGE_SRC).not.toContain('detectOS');
  });

  // @ac AC-06
  test('frontend-host-list-os/AC-06 — osDisplayLabel is imported and used by apiHostToDev', () => {
    // Imported from the shared util
    expect(PAGE_SRC).toMatch(/import\s*\{[^}]*osDisplayLabel[^}]*\}\s*from\s*['"]@\/utils\/osLabel['"]/);
    // apiHostToDev body references the helper
    const fnMatch = PAGE_SRC.match(
      /function\s+apiHostToDev\s*\([^)]*\)[^{]*\{([\s\S]*?)\n\}/,
    );
    expect(fnMatch).not.toBeNull();
    expect(fnMatch![1]).toContain('osDisplayLabel');
    expect(fnMatch![1]).toContain('os_family');
  });

  // @ac AC-07
  test('frontend-host-list-os/AC-07 — OSChip falls back to OS_COLOR_FALLBACK for unmapped families', () => {
    // The fallback constant exists
    expect(PAGE_SRC).toMatch(/const\s+OS_COLOR_FALLBACK\s*=/);
    // OS_COLOR is typed as an open string-keyed map (widened from the
    // closed union so unmapped families are well-typed at the lookup
    // site).
    expect(PAGE_SRC).toMatch(/OS_COLOR\s*:\s*Record<string,\s*string>/);
    // OSChip uses the ?? fallback pattern
    expect(PAGE_SRC).toMatch(/OS_COLOR\[[^\]]+\]\s*\?\?\s*OS_COLOR_FALLBACK/);
  });
});
