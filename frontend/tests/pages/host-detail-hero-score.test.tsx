// @spec frontend-host-detail
//
// The compliance hero card renders the server's score, and renders absence as
// absence. A completed all-skipped scan and a genuine zero sit in one fixture
// so neither a hardcoded null nor a hardcoded zero survives.

import { expect, test } from 'vitest';
import { render } from '@testing-library/react';
import { HeroCompliance } from '@/pages/HostDetailPage';

type Summary = Parameters<typeof HeroCompliance>[0]['summary'];

function summary(passing: number, failing: number, skipped: number, score: number | null): Summary {
  return {
    passing,
    failing,
    skipped,
    error: 0,
    total: passing + failing + skipped,
    score_pct: score,
  } as Summary;
}

// @ac AC-04
// AC-04: score_pct is rendered as sent, with no browser-side arithmetic, and
// the raw counts survive.
test('frontend-host-detail/AC-04 — hero renders the server score and distinguishes zero from absence', () => {
  const cases = [
    // A completed scan whose rules all skipped: no verdict, so no score.
    { id: 'all_skipped', s: summary(0, 0, 40, null), shows: 'No score', hides: '0%' },
    // Every evaluated rule failed. That is a real verdict and must read as 0%.
    { id: 'genuine_zero', s: summary(0, 5, 0, 0), shows: '0%', hides: 'No score' },
    // A host that has never been scanned at all is a different empty state.
    { id: 'never_scanned', s: summary(0, 0, 0, null), shows: 'No compliance data', hides: '0%' },
    { id: 'scored', s: summary(9, 1, 0, 90), shows: '90%', hides: 'No score' },
  ];

  for (const c of cases) {
    const { container, unmount } = render(
      <HeroCompliance summary={c.s} lastScan="2026-06-10" scanState={null} />,
    );
    const text = container.textContent ?? '';
    expect(text, `${c.id}: expected ${c.shows}`).toContain(c.shows);
    expect(text, `${c.id}: must not show ${c.hides}`).not.toContain(c.hides);
    // Never the literal null next to a percent sign.
    expect(text, `${c.id}: null% must never render`).not.toContain('null%');
    unmount();
  }
});
