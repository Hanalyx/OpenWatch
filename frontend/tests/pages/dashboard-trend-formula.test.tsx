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
// AC-07: direction and directional color only when the compared endpoints
// share a formula state. Same-formula and cross-formula fixtures both present,
// so disabling every comparison fails the same-formula cases.
test('frontend-dashboard/AC-07 — no direction, color or delta across a formula boundary', async () => {
  const { inputs, expected } = loadAC07();
  const inp = tracked(inputs, 'AC-07 inputs');
  const exp = tracked(expected, 'AC-07 expected_output');

  const cases = inp.get<AnyRec[]>('cases');
  const forbidden = inp.get<string[]>('forbidden_when_incomparable');
  const neutral = inp.get<string>('neutral_color_token');
  const upColor = inp.get<string>('up_color_token');
  const downColor = inp.get<string>('down_color_token');
  const colorOnlyWhenComparable = exp.get<boolean>('directional_color_only_when_comparable');
  const segmentsMatch = exp.get<boolean>('line_segments_match_fixture');
  const explainWhenNot = exp.get<boolean>('explanation_shown_when_incomparable');
  const wantForbidden = exp.get<number>('forbidden_wording_occurrences');
  inp.allConsumed();
  exp.allConsumed();

  let forbiddenHits = 0;
  for (const raw of cases) {
    const c = tracked(raw, `AC-07 case ${String(raw.id)}`);
    const id = c.get<string>('id');
    const days = c.get<AnyRec[]>('days');
    const comparable = c.get<boolean>('comparable');
    const direction = c.get<string>('expect_direction');
    const wantSegments = c.get<number>('expect_line_segments');
    const wantExplanation = c.get<boolean>('expect_explanation');
    c.allConsumed();

    getMock.mockReset();
    getMock.mockImplementation(async () => ({
      data: { days: days.map(dayPayload) },
      error: undefined,
      response: { ok: true, status: 200 },
    }));

    const { container, unmount } = renderTrend();
    await screen.findByText(/oldest/);
    const text = container.textContent ?? '';

    // Chart GEOMETRY. A joined segment needs two points that may be
    // connected, so a formula boundary produces none: the line breaks rather
    // than crossing it. Counting segments is the geometric statement; the
    // stroke color on any that exist is the visual claim.
    const segments = Array.from(container.querySelectorAll('polyline')).filter((el) =>
      (el.getAttribute('points') ?? '').trim().includes(' '),
    );
    if (segmentsMatch) {
      expect(segments.length, `${id}: joined line segments`).toBe(wantSegments);
    }
    const stroked = segments
      .map((el) => el.getAttribute('stroke'))
      .filter((v): v is string => v !== null);
    const usesDirectional = stroked.some((v) => v === upColor || v === downColor);
    if (colorOnlyWhenComparable) {
      expect(usesDirectional, `${id}: directional stroke color`).toBe(comparable);
    }

    // The caption color, which carried the same claim as the line.
    const caption = Array.from(container.querySelectorAll('span')).find((el) =>
      (el.textContent ?? '').startsWith('latest'),
    );
    const captionColor = caption?.getAttribute('style') ?? '';
    if (comparable) {
      const wantColor = direction === 'up' ? upColor : downColor;
      expect(captionColor, `${id}: caption color ${wantColor}`).toContain(wantColor);
    } else {
      expect(captionColor, `${id}: caption must be neutral`).toContain(neutral);
      expect(captionColor, `${id}: caption must not be green`).not.toContain(upColor);
      expect(captionColor, `${id}: caption must not be red`).not.toContain(downColor);
    }

    // A visible explanation when nothing may be compared.
    if (explainWhenNot) {
      const explained = /No trend direction/.test(text);
      expect(explained, `${id}: explanation shown`).toBe(wantExplanation);
    }

    // Forbidden comparison wording, counted across the incomparable cases.
    if (!comparable) {
      for (const phrase of forbidden) {
        if (new RegExp(phrase, 'i').test(text)) forbiddenHits += 1;
      }
    }

    unmount();
  }

  expect(forbiddenHits, 'comparison wording on an incomparable trend').toBe(wantForbidden);
});
