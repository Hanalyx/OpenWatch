// @spec frontend-groups
//
// AC traceability (source inspection over GroupsPage):
//   AC-01  single ['groups'] query, summary + kind partition
//   AC-02  card rollup fields + member chips, --ow-* tokens
//   AC-03  write controls gated on hasPermission('host:write')
//   AC-04  create + maintenance endpoints, ['groups'] invalidation
//   AC-05  honest loading / empty / error states, no prose em-dash

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const SRC = readFileSync(resolve(process.cwd(), 'src/pages/groups/GroupsPage.tsx'), 'utf8');

describe('frontend-groups — source inspection', () => {
  // @ac AC-01
  test('frontend-groups/AC-01 — single groups query, summary read, kind partition', () => {
    // One query keyed ['groups'] against the combined GET endpoint.
    expect(SRC).toContain("queryKey: ['groups']");
    expect(SRC).toContain("api.GET('/api/v1/groups'");
    // KPI row + cards both come off the one response.
    expect(SRC).toContain('q.data?.summary');
    expect(SRC).toContain('q.data?.groups');
    // Partition the list by kind into Sites and OS categories.
    expect(SRC).toContain("groups.filter((g) => g.kind === 'site')");
    expect(SRC).toContain("groups.filter((g) => g.kind === 'os_category')");
    // KPI row reads the summary fields.
    expect(SRC).toContain('summary.groups');
    expect(SRC).toContain('summary.sites');
    expect(SRC).toContain('summary.os_categories');
    expect(SRC).toContain('summary.hosts_maintenance');
    expect(SRC).toContain('summary.ungrouped');
    expect(SRC).toContain('summary.avg_compliance_pct');
  });

  // @ac AC-02
  test('frontend-groups/AC-02 — card rollup fields + member chips on design tokens', () => {
    // Each card renders the rollup metrics.
    expect(SRC).toContain('r.hosts');
    expect(SRC).toContain('r.online');
    expect(SRC).toContain('r.down');
    expect(SRC).toContain('r.critical_hosts');
    expect(SRC).toContain('r.avg_compliance_pct');
    // Bounded member chip preview off rollup.members.
    expect(SRC).toContain('r.members.slice(0, 4)');
    expect(SRC).toContain('<HostChip');
    expect(SRC).toContain('member.hostname');
    // Card chrome is styled with --ow-* tokens, not raw hex literals.
    expect(SRC).toContain('var(--ow-bg-1)');
    expect(SRC).toContain('var(--ow-line)');
    expect(SRC).not.toMatch(/background:\s*'#[0-9a-fA-F]{3,6}'/);
  });

  // @ac AC-03
  test('frontend-groups/AC-03 — write controls gated on host:write', () => {
    expect(SRC).toContain("hasPermission('host:write')");
    // The page-level create control and the per-card write controls are
    // gated behind canWrite, which is the host:write flag.
    expect(SRC).toContain('canWrite');
    expect(SRC).toContain('{canWrite && (');
  });

  // @ac AC-04
  test('frontend-groups/AC-04 — create + maintenance endpoints, groups invalidation', () => {
    expect(SRC).toContain("api.POST('/api/v1/groups'");
    expect(SRC).toContain("api.POST('/api/v1/groups/{id}:maintenance'");
    expect(SRC).toContain("api.DELETE('/api/v1/groups/{id}'");
    // Every mutation invalidates the single groups query on success.
    const invalidations = SRC.match(/invalidateQueries\(\{ queryKey: \['groups'\] \}\)/g) ?? [];
    expect(invalidations.length).toBeGreaterThanOrEqual(3);
  });

  // @ac AC-05
  test('frontend-groups/AC-05 — honest loading / empty / error states, no prose em-dash', () => {
    // Loading + error states wired off the query, error text via apiErrorMessage.
    expect(SRC).toContain('q.isPending');
    expect(SRC).toContain('q.isError');
    expect(SRC).toContain('apiErrorMessage');
    // Empty sections render an explicit empty string, not a blank grid.
    expect(SRC).toContain('groups.length === 0');
    expect(SRC).toContain('emptyText');
    // No prose copy carries an em-dash. The only '—' occurrences are the
    // shared single-glyph no-data value placeholder (avg compliance with
    // nothing scanned), which is not prose copy: assert every '—' sits in
    // a `== null ? '—'` placeholder ternary.
    const emDashes = SRC.match(/—/g) ?? [];
    const placeholders = SRC.match(/== null \? '—'/g) ?? [];
    // GroupsPage has one em-dash in a leading code comment (exempt) plus
    // the two placeholder ternaries. Assert no em-dash appears inside a
    // JSX/string literal other than the value-placeholder ternary.
    expect(placeholders.length).toBe(2);
    // Comment line + 2 placeholders = 3 total; nothing else.
    expect(emDashes.length).toBe(3);
  });
});
