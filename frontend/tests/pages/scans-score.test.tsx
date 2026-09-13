// @spec frontend-scans
//
// The scans host table renders the server's compliance score and computes
// none. Every value comes from the tracked criterion.

import type React from 'react';
import { expect, test, vi } from 'vitest';
import { render } from '@testing-library/react';
import { loadCriterion, trackFixture } from '../support/spec-fixture';

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children }: { children?: React.ReactNode }) => <span>{children}</span>,
  useNavigate: () => () => undefined,
}));

import { CoverageTab } from '@/pages/scans/ScansPage';

// @ac AC-05
// AC-05: the scans table renders the server score, and an absent one is an
// explicit no-score state rather than an abbreviation claiming inapplicability.
test('frontend-scans/AC-05 — scan rows render the server score, absence stated', () => {
  const { inputs, expected } = loadCriterion('scans', 'frontend-scans', 'AC-05');
  const inp = trackFixture(inputs, 'AC-05 inputs');
  const exp = trackFixture(expected, 'AC-05 expected_output');

  const cases = inp.get<Record<string, unknown>[]>('cases');
  const forbidden = inp.get<string[]>('forbidden_copy');
  const checkText = exp.get<boolean>('every_case_matches_its_expected_text');
  const wantForbidden = exp.get<number>('forbidden_copy_occurrences');
  inp.allConsumed();
  exp.allConsumed();
  expect(checkText, 'AC-05 must require the text comparison').toBe(true);

  let hits = 0;
  for (const raw of cases) {
    const c = trackFixture(raw, `AC-05 case ${String(raw.id)}`);
    const id = c.get<string>('id');
    const scoreField = c.get<number | null | string>('score_pct');
    const wantText = c.get<string>('expect_text');
    c.allConsumed();

    // "absent" means the host carries no compliance_summary at all, which is
    // a different shape from a summary whose score is null.
    const host = {
      id: `h-${id}`,
      hostname: `host-${id}`,
      last_scan_at: '2026-09-01T00:00:00Z',
      scan_state: null,
      ...(scoreField === 'absent'
        ? {}
        : {
            compliance_summary: {
              passing: 9,
              failing: 1,
              total: 10,
              score_pct: scoreField as number | null,
            },
          }),
    };

    const { container, unmount } = render(
      <CoverageTab hosts={[host]} isPending={false} isError={false} error={null} />,
    );
    const text = container.textContent ?? '';
    // Exact node match here too, for the same reason.
    const cell = Array.from(container.querySelectorAll('*')).find(
      (el) => (el.textContent ?? '').trim() === wantText,
    );
    expect(cell, `${id}: rendered score ${wantText}`).toBeDefined();
    for (const phrase of forbidden) if (text.includes(phrase)) hits += 1;
    unmount();
  }
  expect(hits, 'forbidden copy').toBe(wantForbidden);
});
