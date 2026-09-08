// @spec frontend-groups
//
// The groups surface consumes the server aggregate and invents nothing. The
// criterion renders the production component and drives every value from the
// tracked spec.

import type React from 'react';
import { expect, test, vi } from 'vitest';
import { render } from '@testing-library/react';
import { loadCriterion, trackFixture } from '../support/spec-fixture';

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children }: { children?: React.ReactNode }) => <span>{children}</span>,
  useNavigate: () => () => undefined,
}));

import { KpiRow } from '@/pages/groups/GroupsPage';

// @ac AC-06
// AC-06: the groups aggregate is rendered as sent, an absent score is neutral
// rather than critical, and participation and coverage both come from it.
test('frontend-groups/AC-06 — group aggregate rendered as sent, absence is neutral', () => {
  const { inputs, expected } = loadCriterion('groups', 'frontend-groups', 'AC-06');
  const inp = trackFixture(inputs, 'AC-06 inputs');
  const exp = trackFixture(expected, 'AC-06 expected_output');

  const cases = inp.get<Record<string, unknown>[]>('cases');
  const forbidden = inp.get<string[]>('forbidden_copy');
  const criticalToken = inp.get<string>('critical_tone_token');
  const checkValue = exp.get<boolean>('every_case_matches_its_expected_value');
  const checkTone = exp.get<boolean>('every_case_matches_its_expected_tone');
  const checkParticipation = exp.get<boolean>('every_case_states_participation');
  const checkCoverage = exp.get<boolean>('every_case_states_coverage');
  const wantForbidden = exp.get<number>('forbidden_copy_occurrences');
  inp.allConsumed();
  exp.allConsumed();
  for (const [n, f] of [
    ['value', checkValue],
    ['tone', checkTone],
    ['participation', checkParticipation],
    ['coverage', checkCoverage],
  ] as const) {
    expect(f, `AC-06 must require the ${n} comparison`).toBe(true);
  }

  let hits = 0;
  for (const raw of cases) {
    const c = trackFixture(raw, `AC-06 case ${String(raw.id)}`);
    const id = c.get<string>('id');
    const score = {
      score_pct: c.get<number | null>('score_pct'),
      hosts_scored: c.get<number>('hosts_scored'),
      hosts_without_score: c.get<number>('hosts_without_score'),
      hosts_total: c.get<number>('hosts_total'),
      coverage_status: c.get<string>('coverage_status'),
      coverage_pct: c.get<number | null>('coverage_pct'),
      passing: 0,
      failing: 0,
      skipped: 0,
      error: 0,
      envelope: {},
    };
    const wantValue = c.get<string>('expect_value');
    const wantTone = c.get<string>('expect_tone');
    const wantParticipation = c.get<string>('expect_participation');
    const wantCoverage = c.get<string>('expect_coverage');
    c.allConsumed();

    const summary = {
      groups: 1,
      sites: 1,
      os_categories: 1,
      hosts_maintenance: 0,
      ungrouped: 0,
      score,
    };
    const { container, unmount } = render(<KpiRow summary={summary as never} />);
    const text = container.textContent ?? '';

    // EXACT node match, not a substring of the whole card. "0%" occurs inside
    // "100% coverage", so a substring check let a genuine zero collapse to
    // "No score" and still pass.
    const valueNode = Array.from(container.querySelectorAll('*')).find(
      (el) => (el.textContent ?? '').trim() === wantValue,
    );
    expect(valueNode, `${id}: rendered value ${wantValue}`).toBeDefined();
    expect(text, `${id}: participation`).toContain(wantParticipation);
    expect(text, `${id}: coverage`).toContain(wantCoverage);

    // The TONE is the claim. An absent score must never be painted critical:
    // that is a measurement gap rendered as total failure.
    const styles = Array.from(container.querySelectorAll('*'))
      .map((el) => el.getAttribute('style') ?? '')
      .join(' ');
    expect(styles, `${id}: tone ${wantTone}`).toContain(wantTone);
    if (wantTone !== criticalToken) {
      expect(
        valueNode?.getAttribute('style') ?? '',
        `${id}: must not be painted critical`,
      ).not.toContain(criticalToken);
    }

    for (const phrase of forbidden) if (text.includes(phrase)) hits += 1;
    unmount();
  }
  expect(hits, 'forbidden copy').toBe(wantForbidden);
});
