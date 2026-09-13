// @spec frontend-groups
//
// The groups surface consumes the server aggregate and invents nothing. The
// criterion renders the production component and drives every value from the
// tracked spec.

import type React from 'react';
import { expect, test, vi } from 'vitest';
import { render } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { loadCriterion, trackFixture } from '../support/spec-fixture';

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children }: { children?: React.ReactNode }) => <span>{children}</span>,
  useNavigate: () => () => undefined,
}));

import { GroupCard, KpiRow } from '@/pages/groups/GroupsPage';

// @ac AC-06
// AC-06: the groups aggregate is rendered as sent, an absent score is neutral
// rather than critical, and BOTH surfaces show the same participation and
// coverage. The fleet KPI and a group card are rendered from one fixture, so
// fixing only one of them fails.
test('frontend-groups/AC-06 — fleet KPI and group card share one honest presentation', () => {
  const { inputs, expected } = loadCriterion('groups', 'frontend-groups', 'AC-06');
  const inp = trackFixture(inputs, 'AC-06 inputs');
  const exp = trackFixture(expected, 'AC-06 expected_output');

  const cases = inp.get<Record<string, unknown>[]>('cases');
  const forbidden = inp.get<string[]>('forbidden_copy');
  const surfaces = inp.get<string[]>('surfaces');
  const checkValue = exp.get<boolean>('every_case_matches_its_expected_value');
  const checkTone = exp.get<boolean>('every_case_matches_its_expected_tone');
  const checkParticipation = exp.get<boolean>('every_case_states_participation');
  const checkCoverage = exp.get<boolean>('every_case_states_coverage');
  const bothSurfaces = exp.get<boolean>('both_surfaces_render_the_same_presentation');
  const wantForbidden = exp.get<number>('forbidden_copy_occurrences');
  inp.allConsumed();
  exp.allConsumed();
  for (const [n, f] of [
    ['value', checkValue],
    ['tone', checkTone],
    ['participation', checkParticipation],
    ['coverage', checkCoverage],
    ['both surfaces', bothSurfaces],
  ] as const) {
    expect(f, `AC-06 must require the ${n} comparison`).toBe(true);
  }
  expect(surfaces, 'both production surfaces named').toEqual(['fleet_kpi', 'group_card']);

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

    // BOTH production surfaces, from the same aggregate. Fixing only the KPI
    // while leaving a card score-only fails the second entry here.
    const renders: { surface: string; container: HTMLElement; unmount: () => void }[] = [];
    const kpi = render(
      <KpiRow
        summary={
          {
            groups: 1,
            sites: 1,
            os_categories: 1,
            hosts_maintenance: 0,
            ungrouped: 0,
            score,
          } as never
        }
      />,
    );
    renders.push({ surface: 'fleet_kpi', container: kpi.container, unmount: kpi.unmount });

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const card = render(
      <QueryClientProvider client={qc}>
        <GroupCard
          canWrite={false}
          group={
            {
              id: 'g-1',
              name: 'Production',
              kind: 'site',
              membership: 'manual',
              color: 'info',
              subtype: '',
              maintenance: false,
              created_at: '2026-09-01T00:00:00Z',
              updated_at: '2026-09-01T00:00:00Z',
              rollup: {
                hosts: score.hosts_total,
                online: 0,
                down: 0,
                critical_hosts: 0,
                members: [],
                score,
              },
            } as never
          }
        />
      </QueryClientProvider>,
    );
    renders.push({ surface: 'group_card', container: card.container, unmount: card.unmount });

    for (const { surface, container, unmount } of renders) {
      const text = container.textContent ?? '';
      const label = `${id}/${surface}`;

      // EXACT node match. "0%" occurs inside "100% coverage", so a substring
      // check let a genuine zero collapse to "No score" and still pass.
      const valueNode = Array.from(container.querySelectorAll('*')).find(
        (el) => (el.textContent ?? '').trim() === wantValue,
      );
      expect(valueNode, `${label}: rendered value ${wantValue}`).toBeDefined();

      // The tone of the SCORE NODE itself. Searching every element's style
      // let neutral text elsewhere satisfy a neutral expectation while the
      // score was painted a warning color.
      expect((valueNode as HTMLElement | undefined)?.style.color, `${label}: score tone`).toBe(
        wantTone,
      );

      expect(text, `${label}: participation`).toContain(wantParticipation);
      expect(text, `${label}: coverage`).toContain(wantCoverage);

      for (const phrase of forbidden) if (text.includes(phrase)) hits += 1;
      unmount();
    }
  }
  expect(hits, 'forbidden copy').toBe(wantForbidden);
});
