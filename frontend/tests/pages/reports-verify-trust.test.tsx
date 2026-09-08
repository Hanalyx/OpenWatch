// @spec frontend-reports
//
// What the browser check proves, said exactly. The artifact, the signature
// and the key all come from the same server, so a successful check shows they
// agree with each other and nothing more.

import { expect, test, vi, afterEach } from 'vitest';
import { render } from '@testing-library/react';
import { loadCriterion, loadSpecProse, trackFixture } from '../support/spec-fixture';
import {
  SignedBadge,
  VerifyPanel,
  verifyReport,
  type VerifyResult,
} from '@/pages/reports/ReportsPage';

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

/**
 * arrange stubs the fetches and Web Crypto from a case's OWN stimuli.
 *
 * It takes no case id. The previous version switched on the id and decided
 * for itself what each name meant, so a stimulus in the fixture could be
 * changed without changing anything the test did.
 */
function arrange(st: {
  digestMatches: boolean;
  ed25519Available: boolean;
  signatureValid: boolean;
  cryptoError: string | null;
}) {
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
  const hex = st.digestMatches ? HASH : OTHER;
  const bytes = new Uint8Array(hex.match(/../g)!.map((h) => parseInt(h, 16)));
  vi.stubGlobal('crypto', {
    subtle: {
      digest: async () => bytes.buffer,
      importKey: async () => {
        if (st.cryptoError) {
          const e = new Error(st.cryptoError);
          e.name = st.cryptoError;
          throw e;
        }
        if (!st.ed25519Available) {
          const e = new Error('NotSupportedError');
          e.name = 'NotSupportedError';
          throw e;
        }
        return {};
      },
      verify: async () => st.signatureValid,
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
  const badge = trackFixture(inp.get<Record<string, unknown>>('badge'), 'AC-08 badge');
  const checkCopy = exp.get<boolean>('every_case_matches_its_expected_copy');
  const checkTone = exp.get<boolean>('every_case_matches_its_expected_tone');
  const contentOnlyNotSuccess = exp.get<boolean>('content_only_is_not_success');
  const badgePresence = exp.get<boolean>('badge_states_presence_not_trust');
  const wantForbidden = exp.get<number>('forbidden_copy_occurrences');
  inp.allConsumed();
  exp.allConsumed();
  for (const [n, f] of [
    ['copy', checkCopy],
    ['tone', checkTone],
    ['content_only not success', contentOnlyNotSuccess],
    ['badge states presence', badgePresence],
  ] as const) {
    expect(f, `AC-08 must require the ${n} comparison`).toBe(true);
  }

  // The PRODUCTION badge, rendered. It used to be compared with a literal
  // here, so restoring "Signed by <key>" would have passed.
  {
    const { container, unmount } = render(<SignedBadge keyId="ed25519-abc" />);
    const el = container.querySelector('span') as HTMLElement | null;
    expect(el?.textContent, 'badge text').toBe(badge.get<string>('text'));
    expect(el?.getAttribute('title'), 'badge title').toContain(badge.get<string>('title_contains'));
    expect(el?.getAttribute('title'), 'badge must not claim authorship').not.toContain(
      badge.get<string>('title_forbids'),
    );
    // Neutral. Green says a check passed, and none has run when this renders.
    expect(el?.style.color, 'badge tone').toBe(badge.get<string>('tone'));
    badge.allConsumed();
    unmount();
  }

  // The SPEC's own active prose must not restore the claim the rendered copy
  // forbids. A criterion can ban a word in the UI while the context,
  // objective and scope keep promising it, and those are where a reader
  // learns what the product does.
  {
    const prose = loadSpecProse('reports', 'frontend-reports');
    const active = [prose.contextDescription, prose.objectiveSummary, ...prose.scopeIncludes].join(
      ' ',
    );
    for (const phrase of forbidden) {
      expect(active, `spec prose must not claim ${phrase}`).not.toMatch(new RegExp(phrase, 'i'));
    }
  }

  let hits = 0;
  for (const raw of cases) {
    const c = trackFixture(raw, `AC-08 case ${String(raw.id)}`);
    const id = c.get<string>('id');
    const wantStatus = c.get<string>('expect_status');
    const wantContains = c.get<string>('expect_contains');
    const wantAlso = c.get<string | null>('expect_also');
    const wantTone = c.get<string>('expect_tone');
    // The stimuli come from the fixture, so changing one here changes what
    // the helper is actually given.
    arrange({
      digestMatches: c.get<boolean>('digest_matches'),
      ed25519Available: c.get<boolean>('ed25519_available'),
      signatureValid: c.get<boolean>('signature_valid'),
      cryptoError: c.get<string | null>('crypto_error'),
    });
    c.allConsumed();

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
