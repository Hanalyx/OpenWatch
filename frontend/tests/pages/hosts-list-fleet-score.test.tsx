// @spec frontend-hosts-list
//
// The Avg compliance KPI, proven by mounting the page. Every earlier version
// of this criterion read the source and confirmed a query existed, which
// cannot tell an absent score from a bad one on screen.

import type React from 'react';
import { expect, test, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { loadCriterion, trackFixture } from '../support/spec-fixture';
import type { components } from '@/api/schema';

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children }: { children?: React.ReactNode }) => <span>{children}</span>,
  useNavigate: () => () => undefined,
  useSearch: () => ({}),
}));

vi.mock('@/store/useAuthStore', () => ({
  useAuthStore: (sel: (s: unknown) => unknown) => sel({ hasPermission: () => true }),
}));
vi.mock('@/store/useBreadcrumbStore', () => ({
  useBreadcrumbStore: (sel: (s: unknown) => unknown) => sel({ setCrumbs: () => undefined }),
}));
vi.mock('@/store/usePreferencesStore', () => ({
  usePreferencesStore: (sel: (s: unknown) => unknown) =>
    sel({ hostsViewDefault: 'grid', setHostsViewDefault: () => undefined }),
}));

const get = vi.fn();
vi.mock('@/api/client', () => ({ default: { GET: (...a: unknown[]) => get(...a) } }));

import { HostsListPage } from '@/pages/HostsListPage';

/** A host row carrying the pass/fail counts a local mean would be built from. */
type FixtureHost = { id: string; hostname: string; rules_passed: number; rules_failed: number };

type Schemas = components['schemas'];

/**
 * ENVELOPE is the smallest valid ScoreEnvelope, typed against the generated
 * contract so a field the API adds or renames breaks the build here.
 */
const ENVELOPE = {
  lens: 'all_rules',
  formula_version: 2,
  aggregation_method: 'none',
  engine_version: null,
  engine_identity_status: 'unavailable',
  engines: [],
  hosts_without_engine_identity: 0,
  corpus_identity_status: 'unavailable',
  corpora: [],
  hosts_without_corpus_identity: 0,
  corpus_version: null,
  corpus_digest: null,
} satisfies Schemas['ScoreEnvelope'];

/**
 * hostRow builds ONE list item against the generated schema.
 *
 * The earlier version of this fixture was an untyped object literal carrying
 * `passed` and `failed`. The contract's fields are `passing` and `failing`, so
 * those two keys reached nothing: the tempting per-host data the criterion
 * depends on was half absent and the test could not say so. `satisfies` makes
 * the compiler check it, which is the only thing that catches a field name the
 * page does not read.
 */
function hostRow(h: FixtureHost) {
  const total = h.rules_passed + h.rules_failed;
  return {
    id: h.id,
    hostname: h.hostname,
    ip_address: '10.0.0.1',
    port: 22,
    environment: 'production',
    last_scan_at: new Date().toISOString(),
    liveness: { reachability_status: 'reachable', monitoring_state: 'online' },
    os_family: 'rhel',
    os_version: '9.4',
    // The tempting data. A page computing its own fleet mean would average
    // these and print a number.
    compliance_summary: {
      passing: h.rules_passed,
      failing: h.rules_failed,
      skipped: 0,
      error: 0,
      total,
      critical_failing: 0,
      score_pct: Math.round((h.rules_passed / total) * 1000) / 10,
      coverage_status: 'available',
      coverage_pct: 100,
      envelope: ENVELOPE,
    },
  } satisfies Schemas['HostListItem'];
}

/**
 * routes answers every query the page makes. Only /fleet/score varies between
 * cases; everything else is fixed, so a difference on screen can only come
 * from the score.
 */
function routes(hosts: FixtureHost[], scorePct: number | null) {
  const hostList = { hosts: hosts.map(hostRow) } satisfies Schemas['HostListResponse'];
  return (url: string) => {
    if (url === '/api/v1/hosts') {
      return { data: hostList, error: undefined, response: { ok: true, status: 200 } };
    }
    if (url === '/api/v1/fleet/score') {
      return {
        data: { score_pct: scorePct },
        error: undefined,
        response: { ok: true, status: 200 },
      };
    }
    if (url === '/api/v1/fleet/scan-queue') {
      return {
        data: { queued: 0, running: 0 } satisfies Schemas['FleetScanQueue'],
        error: undefined,
        response: { ok: true, status: 200 },
      };
    }
    if (url === '/api/v1/fleet/compliance/trend') {
      return { data: { days: [] }, error: undefined, response: { ok: true, status: 200 } };
    }
    if (url === '/api/v1/system/compliance/config') {
      return {
        data: { default_framework: '' },
        error: undefined,
        response: { ok: true, status: 200 },
      };
    }
    return { data: undefined, error: undefined, response: { ok: true, status: 200 } };
  };
}

function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <HostsListPage />
    </QueryClientProvider>,
  );
}

beforeEach(() => get.mockReset());

// @ac AC-26
// AC-26: an authoritative absent fleet score renders as no score, and a
// genuine zero renders as a real zero. Both are read off the MOUNTED page.
test('frontend-hosts-list/AC-26 — absent fleet score is not a zero score', async () => {
  const { inputs, expected } = loadCriterion('hosts-list', 'frontend-hosts-list', 'AC-26');
  const inp = trackFixture(inputs, 'AC-26 inputs');
  const exp = trackFixture(expected, 'AC-26 expected_output');

  const hosts = inp.get<FixtureHost[]>('hosts');
  const localMean = String(inp.get<string | number>('local_mean_would_be'));
  const cases = inp.get<Record<string, unknown>[]>('cases');
  const pending = trackFixture(
    inp.get<Record<string, unknown>>('pending_fleet_score'),
    'AC-26 pending_fleet_score',
  );
  const mounted = exp.get<boolean>('page_is_mounted_not_inspected');
  const differ = exp.get<boolean>('null_and_zero_differ_on_value_unit_tone_meta_and_bar');
  const noLocalMean = exp.get<boolean>('local_mean_never_rendered');
  const noneWhilePending = exp.get<boolean>('no_local_score_while_the_fleet_query_is_pending');
  inp.allConsumed();
  exp.allConsumed();
  for (const [n, f] of [
    ['mounting', mounted],
    ['the null-versus-zero distinction', differ],
    ['no local mean', noLocalMean],
    ['no local score while the fleet query is pending', noneWhilePending],
  ] as const) {
    expect(f, `AC-26 must require ${n}`).toBe(true);
  }
  expect(hosts.length, 'the fixture must supply scoreable hosts').toBeGreaterThan(1);

  const observed: Record<string, string[]> = {};
  for (const raw of cases) {
    const c = trackFixture(raw, `AC-26 case ${String(raw.id)}`);
    const id = c.get<string>('id');
    const scorePct = c.get<number | null>('fleet_score_pct');
    const wantValue = String(c.get<string | number>('expect_value'));
    const wantUnit = String(c.get<string>('expect_unit'));
    const wantTone = c.get<string>('expect_tone');
    const wantMeta = c.get<string>('expect_meta_left');
    const wantBar = c.get<string>('expect_bar_fill');
    c.allConsumed();

    get.mockImplementation((url: string) => Promise.resolve(routes(hosts, scorePct)(url)));
    const { unmount } = mount();

    // BEFORE any query resolves. There is no client-side fallback, so the KPI
    // starts with no score rather than with a locally computed stand-in. A
    // placeholder is still a number an operator reads and acts on, and the
    // authoritative value overwriting it a moment later does not undo that.
    {
      const first = screen.getByTestId('kpi-avg-compliance-value');
      expect(first.firstChild?.textContent ?? '', `${id}: KPI before the query resolves`).toBe('—');
      expect(
        screen.getByTestId('kpi-avg-compliance').textContent ?? '',
        `${id}: no local mean before the query resolves`,
      ).not.toContain(localMean);
    }

    const card = await screen.findByTestId('kpi-avg-compliance');
    const valueCell = await screen.findByTestId('kpi-avg-compliance-value');
    await waitFor(() => {
      expect(valueCell.firstChild?.textContent ?? '').toBe(wantValue);
    });

    // The value digits, WITHOUT the unit span, so "0" and "0%" are distinct.
    const value = valueCell.firstChild?.textContent ?? '';
    expect(value, `${id}: KPI value`).toBe(wantValue);

    const unitEl = card.querySelector('[data-testid="kpi-avg-compliance-unit"]');
    expect(unitEl?.textContent ?? '', `${id}: KPI unit`).toBe(wantUnit);

    expect((valueCell as HTMLElement).style.color, `${id}: KPI tone`).toBe(wantTone);

    const meta = card.querySelector('[data-testid="kpi-avg-compliance-meta-left"]');
    expect(meta?.textContent ?? '', `${id}: KPI note`).toBe(wantMeta);

    // The bar. An absent score draws no fill; a genuine zero draws one at 0%,
    // which is a different picture from drawing nothing.
    const fill = card.querySelector('[data-testid="kpi-bar-fill"]') as HTMLElement | null;
    if (wantBar === 'absent') {
      expect(fill, `${id}: bar fill must be absent`).toBeNull();
    } else {
      expect(fill, `${id}: bar fill must be present`).not.toBeNull();
      expect(fill?.style.width, `${id}: bar width`).toBe('0%');
    }

    // The number a browser-side mean would have produced appears nowhere in
    // this card, in either case.
    expect(card.textContent ?? '', `${id}: no locally computed mean`).not.toContain(localMean);

    observed[id] = [
      value,
      unitEl?.textContent ?? '',
      (valueCell as HTMLElement).style.color,
      meta?.textContent ?? '',
      fill === null ? 'absent' : `present_at_${fill.style.width}`,
    ];
    unmount();
  }

  // Every dimension must actually differ between the two cases. A page that
  // rendered both identically would satisfy each individual assertion only if
  // the fixture agreed with it, and this catches a fixture that did.
  expect(Object.keys(observed).length, 'both cases ran').toBe(2);
  const [a, b] = Object.values(observed) as [string[], string[]];
  expect(a.length, 'both cases observed the same dimensions').toBe(b.length);
  for (let i = 0; i < a.length; i += 1) {
    expect(a[i], `null and zero must differ on dimension ${i}`).not.toBe(b[i]);
  }

  // The fleet endpoint slower than the hosts endpoint. The page now holds the
  // rows a local mean would be built from AND has no authoritative answer, so
  // any client-side fallback becomes visible here and nowhere else.
  {
    const wantHosts = pending.get<boolean>('hosts_have_loaded');
    const wantValue = String(pending.get<string>('expect_value'));
    pending.allConsumed();
    const answer = routes(hosts, null);
    get.mockImplementation((url: string) =>
      url === '/api/v1/fleet/score'
        ? new Promise(() => {}) // never resolves
        : Promise.resolve(answer(url)),
    );
    const { unmount } = mount();
    if (wantHosts) {
      // Proof the host rows really arrived, so the assertion below is made in
      // the state it claims and not merely before anything loaded.
      await screen.findByText(hosts[0]!.hostname);
    }
    const cell = screen.getByTestId('kpi-avg-compliance-value');
    expect(cell.firstChild?.textContent ?? '', 'pending fleet score: KPI value').toBe(wantValue);
    expect(
      screen.getByTestId('kpi-avg-compliance').textContent ?? '',
      'pending fleet score: no local mean',
    ).not.toContain(localMean);
    unmount();
  }
});
