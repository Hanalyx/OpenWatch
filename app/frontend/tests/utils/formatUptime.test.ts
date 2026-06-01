// @spec frontend-host-detail-system-card
//
// AC traceability (this file):
//
//   AC-01  test('frontend-host-detail-system-card/AC-01 — formatUptime boundary table')

import { describe, expect, test } from 'vitest';
import { formatUptime } from '@/utils/formatUptime';

describe('frontend-host-detail-system-card — formatUptime', () => {
  // @ac AC-01
  test('frontend-host-detail-system-card/AC-01 — formatUptime boundary table', () => {
    // Null-ish
    expect(formatUptime(undefined)).toBe('—');
    expect(formatUptime(null)).toBe('—');
    expect(formatUptime(-1)).toBe('—');

    // <1m bucket
    expect(formatUptime(0)).toBe('<1m');
    expect(formatUptime(30)).toBe('<1m');
    expect(formatUptime(59)).toBe('<1m');

    // Minutes bucket
    expect(formatUptime(60)).toBe('1m');
    expect(formatUptime(3599)).toBe('59m');

    // Hours bucket
    expect(formatUptime(3600)).toBe('1h 0m');
    expect(formatUptime(86399)).toBe('23h 59m');

    // Days bucket
    expect(formatUptime(86400)).toBe('1d 0h');
    expect(formatUptime(1_000_000)).toBe('11d 13h');
  });
});
