import { describe, expect, test } from 'vitest';
import { stripKernelDistroSuffix } from '@/utils/kernelVersion';

describe('stripKernelDistroSuffix', () => {
  test('strips RHEL 9 marker + x86_64 arch', () => {
    expect(stripKernelDistroSuffix('5.14.0-611.42.1.el9_7.x86_64')).toBe('5.14.0-611.42.1');
  });

  test('strips RHEL marker without minor + aarch64 arch', () => {
    expect(stripKernelDistroSuffix('5.14.0-503.el9.aarch64')).toBe('5.14.0-503');
  });

  test('strips Fedora marker + x86_64 arch', () => {
    expect(stripKernelDistroSuffix('6.10.5-200.fc40.x86_64')).toBe('6.10.5-200');
  });

  test('leaves Ubuntu flavor suffix alone (no .elX_Y / arch token)', () => {
    expect(stripKernelDistroSuffix('6.8.0-45-generic')).toBe('6.8.0-45-generic');
  });

  test('leaves Debian flavor suffix alone', () => {
    expect(stripKernelDistroSuffix('6.1.0-25-amd64')).toBe('6.1.0-25-amd64');
  });

  test('leaves Alpine -lts suffix alone', () => {
    expect(stripKernelDistroSuffix('6.1.110-0-lts')).toBe('6.1.110-0-lts');
  });

  test('returns empty string for null / undefined / empty', () => {
    expect(stripKernelDistroSuffix(null)).toBe('');
    expect(stripKernelDistroSuffix(undefined)).toBe('');
    expect(stripKernelDistroSuffix('')).toBe('');
  });

  test('plain kernel version with no suffix passes through', () => {
    expect(stripKernelDistroSuffix('6.6.30')).toBe('6.6.30');
  });
});
