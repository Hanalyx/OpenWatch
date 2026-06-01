// @spec frontend-host-list-os
//
// AC traceability (this file):
//
//   AC-01  test('frontend-host-list-os/AC-01 — RHEL family maps to RHEL (case-insensitive)')
//   AC-02  test('frontend-host-list-os/AC-02 — ubuntu/debian/suse families map to expected labels')
//   AC-03  test('frontend-host-list-os/AC-03 — null/undefined/empty/unknown families fall back to Unknown')

import { describe, expect, test } from 'vitest';
import { osDisplayLabel } from '@/utils/osLabel';

describe('frontend-host-list-os — osDisplayLabel', () => {
  // @ac AC-01
  test('frontend-host-list-os/AC-01 — RHEL family maps to RHEL (case-insensitive)', () => {
    expect(osDisplayLabel('rhel')).toBe('RHEL');
    expect(osDisplayLabel('centos')).toBe('RHEL');
    expect(osDisplayLabel('rocky')).toBe('RHEL');
    expect(osDisplayLabel('almalinux')).toBe('RHEL');
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
    // Fedora is intentionally excluded (development stream, not enterprise)
    expect(osDisplayLabel('fedora')).toBe('Unknown');
    // Other unsupported families
    expect(osDisplayLabel('arch')).toBe('Unknown');
    expect(osDisplayLabel('freebsd')).toBe('Unknown');
  });
});
