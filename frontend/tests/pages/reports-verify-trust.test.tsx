// @spec frontend-reports
//
// What the browser check proves, said exactly. The artifact, the signature
// and the key all come from the same server, so a successful check shows they
// agree with each other and nothing more.

import { expect, test, vi, afterEach } from 'vitest';
import { render } from '@testing-library/react';
import { loadCriterion, trackFixture } from '../support/spec-fixture';
import { VerifyPanel, verifyReport, type VerifyResult } from '@/pages/reports/ReportsPage';

const HASH = '00'.repeat(32);
const OTHER = '11'.repeat(32);

function report(overrides: Record<string, unknown> = {}) {
  return {
    id: 'r-1',
    title: 'Fleet Compliance',
    kind: 'executive',
    signature: 'c2ln',
    signing_key_id: 'ed25519-abc',
    content_sha256: HASH,
    ...overrides,
  } as never;
}

/** stubs the fetches and Web Crypto one verification run makes. */
function arrange(opts: { digest: string; verify?: boolean; ed25519?: boolean }) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      if (url.includes('signing-key')) {
        return {
          ok: true,
          json: async () => ({ key_id: 'ed25519-abc', public_key: 'AAAA', ephemeral: false }),
        };
      }
      return { ok: true, arrayBuffer: async () => new ArrayBuffer(8) };
    }),
  );
  const bytes = new Uint8Array(opts.digest.match(/../g)!.map((h) => parseInt(h, 16)));
  vi.stubGlobal('crypto', {
    subtle: {
      digest: async () => bytes.buffer,
      importKey: async () => {
        if (opts.ed25519 === false) throw new Error('Ed25519 unsupported');
        return {};
      },
      verify: async () => opts.verify ?? true,
    },
  });
}

afterEach(() => vi.unstubAllGlobals());

// @ac AC-08
// AC-08: the rendered result states what was actually established, and a
// content-only run is a caution rather than a success.
test('frontend-reports/AC-08 — verification result states what it proved', async () => {
  const { inputs, expected } = loadCriterion('reports', 'frontend-reports', 'AC-08');
  const inp = trackFixture(inputs, 'AC-08 inputs');
  const exp = trackFixture(expected, 'AC-08 expected_output');

  const cases = inp.get<Record<string, unknown>[]>('cases');
  const forbidden = inp.get<string[]>('forbidden_copy');
  const badgeMeaning = inp.get<string>('badge_meaning');
  const checkCopy = exp.get<boolean>('every_case_matches_its_expected_copy');
  const checkTone = exp.get<boolean>('every_case_matches_its_expected_tone');
  const contentOnlyNotSuccess = exp.get<boolean>('content_only_is_not_success');
  const wantForbidden = exp.get<number>('forbidden_copy_occurrences');
  inp.allConsumed();
  exp.allConsumed();
  for (const [n, f] of [
    ['copy', checkCopy],
    ['tone', checkTone],
    ['content_only not success', contentOnlyNotSuccess],
  ] as const) {
    expect(f, `AC-08 must require the ${n} comparison`).toBe(true);
  }
  expect(badgeMeaning, 'badge meaning').toBe('a signature is present');

  let hits = 0;
  for (const raw of cases) {
    const c = trackFixture(raw, `AC-08 case ${String(raw.id)}`);
    const id = c.get<string>('id');
    const wantStatus = c.get<string>('status');
    const wantContains = c.get<string>('expect_contains');
    const wantAlso = c.get<string | null>('expect_also');
    const wantTone = c.get<string>('expect_tone');
    c.allConsumed();

    // The REAL helper produces the result, so the copy under test is the copy
    // a user sees rather than a constant restated here.
    if (id === 'consistent') arrange({ digest: HASH });
    else if (id === 'content_only') arrange({ digest: HASH, ed25519: false });
    else if (id === 'invalid_signature') arrange({ digest: HASH, verify: false });
    else arrange({ digest: OTHER });

    const result: VerifyResult = await verifyReport(report());
    expect(result.status, `${id}: status`).toBe(wantStatus);
    expect(result.detail, `${id}: copy`).toContain(wantContains);
    if (wantAlso !== null) {
      expect(result.detail, `${id}: trust qualification`).toContain(wantAlso);
    }

    // And the PRODUCTION panel's tone for that result.
    const { container, unmount } = render(<VerifyPanel result={result} />);
    const panel = container.querySelector('[role="status"]') as HTMLElement | null;
    expect(panel?.style.color, `${id}: tone`).toBe(wantTone);
    // A content-only run must never be painted as success.
    if (wantStatus === 'content_only') {
      expect(panel?.style.color, `${id}: must not read as success`).not.toBe(
        'var(--ow-ok, #2faf6a)',
      );
    }
    for (const phrase of forbidden) {
      if (new RegExp(phrase, 'i').test(result.detail)) hits += 1;
    }
    unmount();
  }
  expect(hits, 'forbidden copy in a verification result').toBe(wantForbidden);
});
