// @spec frontend-host-detail
//
// The compliance trend delta makes no claim it cannot support. Every value
// comes from the AC-47 fixture, and the production card is rendered, so the
// caption text and its color are what is asserted.

import type React from 'react';
import { expect, test, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { loadCriterion, trackFixture, type AnyRec } from '../support/spec-fixture';

const { getMock } = vi.hoisted(() => ({ getMock: vi.fn() }));
vi.mock('@/api/client', () => ({ default: { GET: getMock } }));
vi.mock('@tanstack/react-router', () => ({
  Link: ({ children }: { children?: React.ReactNode }) => <span>{children}</span>,
  useParams: () => ({ hostId: 'h-1' }),
  useNavigate: () => () => undefined,
}));

import { CardComplianceTrend } from '@/pages/HostDetailPage';

// @ac AC-47
// AC-47: a delta needs two distinct scored days sharing a formula, and every
// impossible case names its own reason.
test('frontend-host-detail/AC-47 — trend delta never compares what it cannot', async () => {
  const { inputs, expected } = loadCriterion('host-detail', 'frontend-host-detail', 'AC-47');
  const inp = trackFixture(inputs, 'AC-47 inputs');
  const exp = trackFixture(expected, 'AC-47 expected_output');

  const cases = inp.get<AnyRec[]>('cases');
  const forbidden = inp.get<string[]>('forbidden_when_incomparable');
  const directionalTokens = inp.get<string[]>('directional_color_tokens');
  const checkCaption = exp.get<boolean>('every_case_matches_its_expected_caption');
  const checkColor = exp.get<boolean>('every_case_matches_its_expected_color');
  const wantForbidden = exp.get<number>('forbidden_wording_occurrences');
  inp.allConsumed();
  exp.allConsumed();
  expect(checkCaption, 'AC-47 must require the caption comparison').toBe(true);
  expect(checkColor, 'AC-47 must require the color comparison').toBe(true);

  let forbiddenHits = 0;
  for (const raw of cases) {
    const c = trackFixture(raw, `AC-47 case ${String(raw.id)}`);
    const id = c.get<string>('id');
    const days = c.get<AnyRec[]>('days');
    const wantCaption = c.get<string>('expect_caption');
    const wantColor = c.get<string>('expect_color_token');
    c.allConsumed();

    const payload = days.map((d) => {
      const day = trackFixture(d, `AC-47 case ${id} day`);
      const out = {
        date: day.get<string>('date'),
        score_pct: day.get<number | null>('score_pct'),
        formula_status: day.get<string>('formula_status'),
        formula_version: null,
        passing: 5,
        failing: 5,
        total: 10,
      };
      day.allConsumed();
      return out;
    });

    getMock.mockReset();
    getMock.mockImplementation(async () => ({
      data: { days: payload },
      error: undefined,
      response: { ok: true, status: 200 },
    }));

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { container, unmount } = render(
      <QueryClientProvider client={qc}>
        <CardComplianceTrend hostId="h-1" />
      </QueryClientProvider>,
    );
    await screen.findByText(new RegExp(wantCaption.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    const text = container.textContent ?? '';

    expect(text, `${id}: caption`).toContain(wantCaption);

    // The caption color IS the directional claim.
    const caption = Array.from(container.querySelectorAll('span')).find((el) =>
      (el.textContent ?? '').includes(wantCaption),
    );
    const style = caption?.getAttribute('style') ?? '';
    expect(style, `${id}: caption color ${wantColor}`).toContain(wantColor);
    for (const other of directionalTokens.filter((t) => t !== wantColor)) {
      expect(style, `${id}: must not use ${other}`).not.toContain(other);
    }

    if (wantCaption.startsWith('No comparison')) {
      for (const phrase of forbidden) {
        if (text.includes(phrase)) forbiddenHits += 1;
      }
    }

    unmount();
  }

  expect(forbiddenHits, 'comparison wording on an incomparable trend').toBe(wantForbidden);
});
