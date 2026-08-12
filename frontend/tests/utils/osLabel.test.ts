// @spec frontend-host-list-os
//
// AC traceability (this file):
//
//   AC-01  test('frontend-host-list-os/AC-01 — RHEL family maps to RHEL (case-insensitive)')
//   AC-02  test('frontend-host-list-os/AC-02 — ubuntu/debian/suse families map to expected labels')
//   AC-03  test('frontend-host-list-os/AC-03 — null/undefined/empty/unknown families fall back to Unknown')
//   AC-08  test('frontend-host-list-os/AC-08 — fedora is named, not Unknown and not RHEL')

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, test } from 'vitest';
import { osDisplayLabel } from '@/utils/osLabel';

describe('frontend-host-list-os — osDisplayLabel', () => {
  // @ac AC-01
  test('frontend-host-list-os/AC-01 — RHEL family maps to RHEL (case-insensitive)', () => {
    expect(osDisplayLabel('rhel')).toBe('RHEL');
    expect(osDisplayLabel('centos')).toBe('RHEL');
    expect(osDisplayLabel('rocky')).toBe('RHEL');
    expect(osDisplayLabel('almalinux')).toBe('RHEL');
    expect(osDisplayLabel('ol')).toBe('RHEL');
    expect(osDisplayLabel('oracle')).toBe('RHEL');
    // case folding
    expect(osDisplayLabel('RHEL')).toBe('RHEL');
    expect(osDisplayLabel('Rhel')).toBe('RHEL');
    expect(osDisplayLabel('  CentOS  ')).toBe('RHEL');
  });

  // @ac AC-02
  test('frontend-host-list-os/AC-02 — ubuntu/debian/suse families map to expected labels', () => {
    expect(osDisplayLabel('ubuntu')).toBe('Ubuntu');
    expect(osDisplayLabel('debian')).toBe('Debian');
    expect(osDisplayLabel('opensuse')).toBe('SUSE');
    expect(osDisplayLabel('sles')).toBe('SUSE');
  });

  // @ac AC-03
  test('frontend-host-list-os/AC-03 — null/undefined/empty/unknown families fall back to Unknown', () => {
    expect(osDisplayLabel(null)).toBe('Unknown');
    expect(osDisplayLabel(undefined)).toBe('Unknown');
    expect(osDisplayLabel('')).toBe('Unknown');
    expect(osDisplayLabel('   ')).toBe('Unknown');
    // Unsupported families. Fedora moved to AC-08 in spec v1.1.0.
    expect(osDisplayLabel('arch')).toBe('Unknown');
    expect(osDisplayLabel('freebsd')).toBe('Unknown');
  });

  // @ac AC-08
  test('frontend-host-list-os/AC-08 — fedora is named, not Unknown and not RHEL', () => {
    // Not 'Unknown': Discovery knows exactly what this host is, so 'Unknown'
    // reads as a detection failure that did not happen.
    expect(osDisplayLabel('fedora')).toBe('Fedora');
    // Not 'RHEL' either: Fedora is upstream of RHEL, not a rebuild of it, and
    // folding it into the RHEL bucket would distort the group-by-OS rollup.
    expect(osDisplayLabel('fedora')).not.toBe('RHEL');
    expect(osDisplayLabel('FEDORA')).toBe('Fedora');
  });

  // @ac AC-08
  test('frontend-host-list-os/AC-08 — the table warns it is not benchmark equivalence', () => {
    // The display table and framework.BenchmarkFamily agree on the EL rebuilds
    // and MUST NOT agree on Fedora: it displays as itself and has no EL
    // benchmark, so grading it against the RHEL 9 STIG would invent coverage.
    // The comment is what stops the next author copying this map backend-side.
    const src = readFileSync(resolve(__dirname, '../../src/utils/osLabel.ts'), 'utf8');
    expect(src).toMatch(/DISPLAY label, not a benchmark-equivalence claim/);
    expect(src).toMatch(/BenchmarkFamily/);
  });
});
