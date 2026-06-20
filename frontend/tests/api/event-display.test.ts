// @spec frontend-activity
//
//   AC-06  shared eventDisplay helpers + adoption across surfaces

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, test } from 'vitest';

import {
  relativeTime,
  severityLabel,
  severityTone,
  sourceLabel,
} from '@/api/eventDisplay';

const read = (p: string) => readFileSync(resolve(process.cwd(), p), 'utf8');

describe('frontend-activity — shared event-display helpers', () => {
  // @ac AC-06
  test('frontend-activity/AC-06 — sourceLabel/severityLabel/severityTone map known + title-case unknown', () => {
    expect(sourceLabel('transaction')).toBe('Compliance');
    expect(sourceLabel('alert')).toBe('Alert');
    expect(sourceLabel('monitoring')).toBe('Monitoring');
    expect(sourceLabel('intelligence')).toBe('Intelligence');
    expect(sourceLabel('audit')).toBe('Audit');
    // graceful: unknown source never renders raw lowercase.
    expect(sourceLabel('newfangled')).toBe('Newfangled');

    expect(severityLabel('critical')).toBe('Critical');
    expect(severityLabel('info')).toBe('Info');
    expect(severityTone('critical')).toBe('crit');
    expect(severityTone('high')).toBe('crit');
    expect(severityTone('medium')).toBe('warn');
    expect(severityTone('low')).toBe('info');
    expect(severityTone('info')).toBe('info');
  });

  // @ac AC-06
  test('frontend-activity/AC-06 — relativeTime is human + em-dash-free', () => {
    expect(relativeTime(new Date().toISOString())).toBe('just now');
    const twoH = new Date(Date.now() - 2 * 3_600_000).toISOString();
    expect(relativeTime(twoH)).toBe('2h ago');
    // invalid date -> empty string, never an em-dash.
    expect(relativeTime('not-a-date')).toBe('');
    expect(relativeTime('not-a-date')).not.toContain('—');
  });

  // @ac AC-06
  test('frontend-activity/AC-06 — no surface renders a raw source/severity enum; per-surface copies removed', () => {
    const widgets = read('src/pages/dashboard/widgets.tsx');
    // dashboard widget adopts the shared helpers, not raw fields.
    expect(widgets).toContain('sourceLabel(a.source)');
    expect(widgets).toContain('severityLabel(a.severity)');
    expect(widgets).toContain('severityTone(a.severity)');
    expect(widgets).not.toMatch(/\$\{a\.source\} ·/); // old raw sub
    expect(widgets).not.toMatch(/function sevTone/);
    expect(widgets).not.toMatch(/function timeAgo/);

    // ActivityPage no longer RENDERS the bare {a.source} as a JSX child.
    // (The client-side search haystack still references ${a.source} in a
    // template string — that is filtering, not a UI render, so we exclude
    // the `$`-prefixed template usage from the check.)
    const page = read('src/pages/activity/ActivityPage.tsx');
    expect(page).not.toMatch(/[^$]\{a\.source\}/);
    expect(page).toContain("from '@/api/eventDisplay'");

    // The duplicate helpers are gone; the canonical ones are imported.
    const drawer = read('src/pages/activity/ActivityDrawer.tsx');
    expect(drawer).not.toMatch(/export function severityTone/);
    expect(drawer).toContain("from '@/api/eventDisplay'");
    const host = read('src/pages/HostDetailPage.tsx');
    expect(host).not.toMatch(/function activityRelativeTime/);
    expect(host).toContain("relativeTime(item.occurred_at)");
  });
});
