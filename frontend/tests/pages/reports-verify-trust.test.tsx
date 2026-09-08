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
  VerifyControl,
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

/** The stimuli a case reaches. Absent means the stage is never entered. */
type Stimuli = {
  digestMatches: boolean;
  ed25519Available?: boolean;
  importException?: string;
  signatureValid?: boolean;
};

/**
 * arrange stubs the fetches and Web Crypto from a case's OWN stimuli, and
 * returns the spies so the test can prove which stages ran.
 *
 * Two earlier shapes were unsound. The first switched on a case id, so a
 * fixture value could change with no effect. The second gave every case every
 * field, which is the same defect wearing a fixture: importKey read
 * cryptoError before ed25519Available, and a hash mismatch returned before
 * either was touched, so three of four stimuli on most cases were inert.
 *
 * Now a stage that is not reached has no stimulus to supply, and the call
 * counts are asserted, so an inert field cannot hide.
 */
function arrange(st: Stimuli) {
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

  // A real DOMException, which is what WebCrypto throws. A plain Error with
  // .name assigned would let a handler keying on the wrong property pass.
  const importKey = vi.fn(async () => {
    if (st.ed25519Available === false) {
      throw new DOMException('Ed25519 is not supported', 'NotSupportedError');
    }
    if (st.importException) {
      throw new DOMException(`import failed: ${st.importException}`, st.importException);
    }
    return {};
  });
  const verify = vi.fn(async () => st.signatureValid!);
  vi.stubGlobal('crypto', { subtle: { digest: async () => bytes.buffer, importKey, verify } });
  return { importKey, verify };
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
  const control = trackFixture(inp.get<Record<string, unknown>>('verify_control'), 'AC-08 control');
  const realDomException = inp.get<boolean>('unsupported_is_a_real_dom_exception');
  const stagesGuarded = exp.get<boolean>('crypto_reached_only_the_stages_a_case_names');
  const trustGuarded = exp.get<boolean>('trust_language_guarded_on_badge_control_and_panel');
  inp.allConsumed();
  exp.allConsumed();
  for (const [n, f] of [
    ['copy', checkCopy],
    ['tone', checkTone],
    ['content_only not success', contentOnlyNotSuccess],
    ['badge states presence', badgePresence],
    ['stage reachability', stagesGuarded],
    ['trust language on all three surfaces', trustGuarded],
    ['a real DOMException', realDomException],
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
    for (const phrase of forbidden) {
      const seen = `${el?.textContent ?? ''} ${el?.getAttribute('title') ?? ''}`;
      expect(seen, `badge must not claim ${phrase}`).not.toMatch(new RegExp(phrase, 'i'));
    }
    badge.allConsumed();
    unmount();
  }

  // The PRODUCTION Verify control. Its title is a trust claim made BEFORE any
  // check runs, and the forbidden-copy scan below only ever reached the result
  // panel, so "Verify offline" could have been restored here unnoticed.
  {
    const { container, unmount } = render(<VerifyControl busy={false} onVerify={() => {}} />);
    const btn = container.querySelector('button') as HTMLElement | null;
    expect(btn?.textContent, 'verify control text').toBe(control.get<string>('text'));
    const title = btn?.getAttribute('title') ?? '';
    expect(title, 'verify control title').toContain(control.get<string>('title_contains'));
    for (const phrase of forbidden) {
      expect(title, `verify control must not claim ${phrase}`).not.toMatch(new RegExp(phrase, 'i'));
    }
    control.allConsumed();
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
  const stagesSeen = new Set<string>();
  for (const raw of cases) {
    const c = trackFixture(raw, `AC-08 case ${String(raw.id)}`);
    const id = c.get<string>('id');
    const stage = c.get<string>('stage');
    stagesSeen.add(stage);
    const wantStatus = c.get<string>('expect_status');
    const wantContains = c.get<string>('expect_contains');
    const wantAlso = c.get<string | null>('expect_also');
    const wantTone = c.get<string>('expect_tone');
    const wantImports = c.get<number>('expect_import_calls');
    const wantVerifies = c.get<number>('expect_verify_calls');

    // Only the stimuli this stage reaches. A case that stops at the digest
    // supplies nothing about the key, so there is no inert field to flip.
    const st: Stimuli = { digestMatches: c.get<boolean>('digest_matches') };
    if (stage !== 'digest') st.ed25519Available = c.get<boolean>('ed25519_available');
    if (c.has('import_exception')) st.importException = c.get<string>('import_exception');
    if (stage === 'verify') st.signatureValid = c.get<boolean>('signature_valid');
    const spies = arrange(st);
    c.allConsumed();

    const result: VerifyResult = await verifyReport(report());
    expect(result.status, `${id}: status`).toBe(wantStatus);
    expect(result.detail, `${id}: copy`).toContain(wantContains);
    if (wantAlso !== null) {
      expect(result.detail, `${id}: trust qualification`).toContain(wantAlso);
    }

    // Which stages actually ran. A hash mismatch that quietly imported a key
    // and checked a signature would still have produced the right words.
    expect(spies.importKey.mock.calls.length, `${id}: importKey calls`).toBe(wantImports);
    expect(spies.verify.mock.calls.length, `${id}: verify calls`).toBe(wantVerifies);

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
  // All three stages are exercised, so a fixture cannot drop to one stage and
  // leave the call-count assertions trivially satisfied.
  expect([...stagesSeen].sort(), 'stages exercised').toEqual(['digest', 'import', 'verify']);
  expect(hits, 'forbidden copy in a verification result').toBe(wantForbidden);
});
