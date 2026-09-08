// @spec frontend-dashboard
//
// The compliance trend widget makes no comparison across a formula boundary.
// Every value comes from the AC-07 fixture, and the widget is rendered, so the
// caption text, the chart stroke color and the caption color are what is
// asserted rather than the shape of a helper.

import type React from 'react';
import { expect, test, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import yaml from 'js-yaml';

const { getMock } = vi.hoisted(() => ({ getMock: vi.fn() }));
vi.mock('@/api/client', () => ({ default: { GET: getMock } }));
// WidgetCard renders a router Link for its "view all" affordance, which needs
// a RouterProvider this test has no reason to build. The link is not what the
// criterion is about.
vi.mock('@tanstack/react-router', () => ({
  Link: ({ children }: { children?: React.ReactNode }) => <span>{children}</span>,
}));
vi.mock('@/api/useDefaultLens', () => ({ useDefaultLens: () => ({ lens: '' }) }));

import { WidgetComplianceTrend } from '@/pages/dashboard/widgets';

type AnyRec = Record<string, unknown>;

function tracked(obj: AnyRec, label: string) {
  const seen = new Set<string>();
  return {
    get<T>(key: string): T {
      if (!(key in obj)) throw new Error(`${label}: fixture has no key ${key}`);
      seen.add(key);
      return obj[key] as T;
    },
    allConsumed() {
      const missed = Object.keys(obj).filter((k) => !seen.has(k));
      expect(missed, `${label}: fixture keys never asserted`).toEqual([]);
    },
  };
}

function loadAC07() {
  const doc = yaml.load(
    readFileSync(resolve(process.cwd(), '../specs/frontend/dashboard.spec.yaml'), 'utf8'),
  ) as { spec: { acceptance_criteria: AnyRec[] } };
  const ac = doc.spec.acceptance_criteria.find((a) => a.id === 'AC-07');
  if (!ac) throw new Error('AC-07 not found in frontend-dashboard');
  return { inputs: ac.inputs as AnyRec, expected: ac.expected_output as AnyRec };
}

function dayPayload(d: AnyRec) {
  return {
    date: d.date,
    score_pct: d.score_pct,
    formula_status: d.formula_status,
    formula_version: d.formula_status === 'identified' ? 2 : null,
    hosts: 4,
    hosts_scored: d.score_pct === null ? 0 : 4,
    hosts_without_score: d.score_pct === null ? 4 : 0,
    failing: 3,
    critical_hosts: 1,
    envelope: {},
  };
}

function renderTrend() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <WidgetComplianceTrend />
    </QueryClientProvider>,
  );
}

// @ac AC-07
// AC-07: direction, color and explanation are each compared EXACTLY against
// the fixture. Same-formula and cross-formula cases are both present, so an
// implementation that disables every comparison fails the same-formula ones.
test('frontend-dashboard/AC-07 — no direction, color or delta across a formula boundary', async () => {
  const { inputs, expected } = loadAC07();
  const inp = tracked(inputs, 'AC-07 inputs');
  const exp = tracked(expected, 'AC-07 expected_output');

  const cases = inp.get<AnyRec[]>('cases');
  const forbidden = inp.get<string[]>('forbidden_when_incomparable');
  const directionalTokens = inp.get<string[]>('directional_color_tokens');
  const checkDirection = exp.get<boolean>('every_case_matches_its_expected_direction');
  const checkColor = exp.get<boolean>('every_case_matches_its_expected_color');
  const checkExplanation = exp.get<boolean>('every_case_matches_its_expected_explanation');
  const checkSegments = exp.get<boolean>('line_segments_match_fixture');
  const wantForbidden = exp.get<number>('forbidden_wording_occurrences');
  inp.allConsumed();
  exp.allConsumed();
  // The expectations are switches only if a false value silently disables a
  // check. Each is required true here, and each drives an exact comparison
  // below, so flipping one in the fixture fails rather than skips.
  for (const [name, flag] of [
    ['direction', checkDirection],
    ['color', checkColor],
    ['explanation', checkExplanation],
    ['segments', checkSegments],
  ] as const) {
    expect(flag, `AC-07 must require the ${name} comparison`).toBe(true);
  }

  let forbiddenHits = 0;
  for (const raw of cases) {
    const c = tracked(raw, `AC-07 case ${String(raw.id)}`);
    const id = c.get<string>('id');
    const days = c.get<AnyRec[]>('days');
    const wantDirection = c.get<string>('expect_direction');
    const wantColor = c.get<string>('expect_color_token');
    const wantSegments = c.get<number>('expect_line_segments');
    const wantExplanation = c.get<string | null>('expect_explanation');
    c.allConsumed();

    // Every nested day object is consumed too, so an unread field there fails.
    const payload = days.map((d) => {
      const day = tracked(d, `AC-07 case ${id} day`);
      const out = dayPayload({
        date: day.get<string>('date'),
        score_pct: day.get<number | null>('score_pct'),
        formula_status: day.get<string>('formula_status'),
      });
      day.allConsumed();
      return out;
    });

    getMock.mockReset();
    getMock.mockImplementation(async () => ({
      data: { days: payload },
      error: undefined,
      response: { ok: true, status: 200 },
    }));

    const { container, unmount } = renderTrend();
    await screen.findByText(/oldest/);
    const text = container.textContent ?? '';

    // Chart GEOMETRY. A joined segment needs two points that may be
    // connected, so a formula boundary produces none: the line breaks rather
    // than crossing it.
    const segments = Array.from(container.querySelectorAll('polyline')).filter((el) =>
      (el.getAttribute('points') ?? '').trim().includes(' '),
    );
    expect(segments.length, `${id}: joined line segments`).toBe(wantSegments);

    // The CHART stroke, not only the caption. AC-07 promises both, and a
    // change that hardcoded the TrendChart color while leaving the caption
    // correct would otherwise pass.
    for (const seg of segments) {
      expect(seg.getAttribute('stroke'), `${id}: chart stroke color`).toBe(wantColor);
    }

    // The caption color IS the directional claim. Compared exactly.
    const caption = Array.from(container.querySelectorAll('span')).find((el) =>
      (el.textContent ?? '').startsWith('latest'),
    );
    const captionColor = caption?.getAttribute('style') ?? '';
    expect(captionColor, `${id}: caption color`).toContain(wantColor);
    for (const other of directionalTokens.filter((t) => t !== wantColor)) {
      expect(captionColor, `${id}: must not use ${other}`).not.toContain(other);
    }

    // The OBSERVED direction, derived from the color the widget chose, then
    // compared with the fixture. Asserting only that an incomparable case is
    // not green would let "none" and "flat" swap places unnoticed.
    const observed = captionColor.includes('var(--ow-ok)')
      ? 'up'
      : captionColor.includes('var(--ow-crit)')
        ? 'down'
        : /No trend direction/.test(text)
          ? 'none'
          : 'flat';
    expect(observed, `${id}: observed direction`).toBe(wantDirection);

    // The EXACT explanation, per case, not merely the generic phrase.
    if (wantExplanation === null) {
      expect(text, `${id}: no explanation expected`).not.toMatch(/No trend direction/);
    } else {
      expect(text, `${id}: exact explanation`).toContain(wantExplanation);
    }

    if (wantDirection === 'none') {
      for (const phrase of forbidden) {
        if (new RegExp(phrase, 'i').test(text)) forbiddenHits += 1;
      }
    }

    unmount();
  }

  expect(forbiddenHits, 'comparison wording on an incomparable trend').toBe(wantForbidden);
});
