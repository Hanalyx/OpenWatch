/**
 * Audit Query Builder UX tests.
 *
 * Verifies that the scope selection step uses searchable Autocomplete
 * dropdowns (showing hostnames/group names) instead of raw UUID/ID
 * text fields. Users should never need to know or type UUIDs.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const SRC = path.resolve(__dirname, '../../../frontend/src');

function readSource(relativePath: string): string {
  return fs.readFileSync(path.join(SRC, relativePath), 'utf8');
}

describe('Audit Query Builder: scope uses Autocomplete selectors', () => {
  const source = readSource('pages/audit/AuditQueryBuilderPage.tsx');

  it('uses Autocomplete for host selection', () => {
    expect(source).toContain('Autocomplete');
  });

  it('fetches hosts via useHosts hook', () => {
    expect(source).toContain('useHosts');
  });

  it('does not use raw UUID text field for hosts', () => {
    expect(source).not.toContain('Host IDs (comma-separated UUIDs)');
  });

  it('does not use raw ID text field for host groups', () => {
    expect(source).not.toContain('Host Group IDs (comma-separated)');
  });

  it('shows hostname in Autocomplete options', () => {
    expect(source).toContain('hostname');
    expect(source).toContain('Search by hostname');
  });

  it('fetches host groups from API', () => {
    expect(source).toContain('/api/host-groups/');
  });

  it('shows group name in Autocomplete options', () => {
    expect(source).toContain('Search by group name');
  });
});
