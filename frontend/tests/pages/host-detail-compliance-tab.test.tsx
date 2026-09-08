// @spec frontend-host-compliance-tab
//
// AC traceability (this file):
//
//   AC-01  test('frontend-host-compliance-tab/AC-01 — tab replaces the stub: page mounts ComplianceTab, registry entry gone')
//   AC-02  test('frontend-host-compliance-tab/AC-02 — lens bar drives onFrameworkChange and the lens queryKey embeds framework')
//   AC-03  test('frontend-host-compliance-tab/AC-03 — summary, categories, and rules render from one response with reconciling counts')
//   AC-04  test('frontend-host-compliance-tab/AC-04 — status filter is client-side only: no refetch on filter click')
//   AC-05  test('frontend-host-compliance-tab/AC-05 — both query keys carry the [host, hostId] prefix')
//   AC-06  test('frontend-host-compliance-tab/AC-06 — never-scanned empty state names Run scan; errors render inline with Retry; isPending guard')
//   AC-07  test('frontend-host-compliance-tab/AC-07 — no stored check-output reference anywhere in the tab code')
//   AC-08  test('frontend-host-compliance-tab/AC-08 — Re-scan posts once with an Idempotency-Key; 409 renders Scan already running')

import { describe, expect, test, beforeEach, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { loadCriterion, trackFixture, type AnyRec } from '../support/spec-fixture';

const { getMock, postMock } = vi.hoisted(() => ({ getMock: vi.fn(), postMock: vi.fn() }));
vi.mock('@/api/client', () => ({ default: { GET: getMock, POST: postMock } }));

import { ComplianceTab } from '@/pages/host-detail/ComplianceTab';

const TAB_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/host-detail/ComplianceTab.tsx'),
  'utf8',
);
const PAGE_SRC = readFileSync(resolve(process.cwd(), 'src/pages/HostDetailPage.tsx'), 'utf8');

// ─────────────────────────────────────────────────────────────────────────
// Fixtures — summary numbers MUST equal the per-status aggregation of
// the rules array (api-host-compliance C-05), so AC-03 can assert the
// reconciliation visually.
// ─────────────────────────────────────────────────────────────────────────

const LENS = {
  scan_context: {
    last_scan_at: '2026-06-10T12:00:00Z',
    scan_id: '0c9e2f5a-1111-4222-8333-444455556666',
    policy_version: 'v3',
  },
  summary: {
    passing: 2,
    failing: 1,
    skipped: 1,
    error: 0,
    total: 4,
    score_pct: 50,
    coverage_status: 'unavailable_unclassified_skips',
    coverage_pct: null,
  },
  categories: [
    // score_pct is SENT by the server now, not derived in the component.
    // ssh: 1 of 2 verdicts. auth: 1 of 1, its second rule having produced none.
    { category: 'ssh', passing: 1, failing: 1, total: 2, score_pct: 50 },
    { category: 'auth', passing: 1, failing: 0, total: 2, score_pct: 100 },
  ],
  rules: [
    {
      rule_id: 'r-root-login',
      title: 'Disable root SSH login',
      category: 'ssh',
      severity: 'high',
      status: 'fail',
      control_ids: ['CIS-5.2.8'],
      last_checked_at: '2026-06-10T12:00:00Z',
    },
    {
      rule_id: 'r-ssh-proto',
      title: 'Enforce SSH protocol 2',
      category: 'ssh',
      severity: 'medium',
      status: 'pass',
      control_ids: [],
      last_checked_at: '2026-06-10T12:00:00Z',
    },
    {
      rule_id: 'r-pass-maxdays',
      title: 'Password max days',
      category: 'auth',
      severity: 'low',
      status: 'pass',
      control_ids: [],
      last_checked_at: '2026-06-10T12:00:00Z',
    },
    {
      rule_id: 'r-apparmor',
      title: 'AppArmor profile enforced',
      category: 'auth',
      severity: '',
      status: 'skipped',
      control_ids: [],
      last_checked_at: '2026-06-10T12:00:00Z',
    },
  ],
};

const NEVER_SCANNED = {
  scan_context: { last_scan_at: null, scan_id: null, policy_version: '' },
  summary: { passing: 0, failing: 0, skipped: 0, error: 0, total: 0, score_pct: 0 },
  categories: [],
  rules: [],
};

const FRAMEWORKS = {
  overall: { framework_id: 'all', rule_count: 4, passing: 2, failing: 1, score_pct: 50 },
  frameworks: [
    { framework_id: 'cis_rhel9', rule_count: 271, passing: 100, failing: 171, score_pct: 36.9 },
    { framework_id: 'stig_rhel9', rule_count: 338, passing: 115, failing: 223, score_pct: 34 },
  ],
};

function primeApi({
  lens = LENS as unknown,
  frameworks = FRAMEWORKS as unknown,
  lensFails = false,
}: { lens?: unknown; frameworks?: unknown; lensFails?: boolean } = {}) {
  getMock.mockImplementation(async (path: string) => {
    if (path === '/api/v1/hosts/{id}/compliance/frameworks') {
      return { data: frameworks, error: undefined, response: { ok: true, status: 200 } };
    }
    if (path === '/api/v1/hosts/{id}/compliance') {
      if (lensFails) {
        return {
          data: undefined,
          error: { error: { code: 'internal', message: 'boom' } },
          response: { ok: false, status: 500 },
        };
      }
      return { data: lens, error: undefined, response: { ok: true, status: 200 } };
    }
    throw new Error(`unexpected path: ${path}`);
  });
}

function renderTab(props: Partial<Parameters<typeof ComplianceTab>[0]> = {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <ComplianceTab
        hostId="h-1"
        framework={undefined}
        onFrameworkChange={() => undefined}
        {...props}
      />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  getMock.mockReset();
  postMock.mockReset();
});

// ─────────────────────────────────────────────────────────────────────────
// Structural (source inspection)
// ─────────────────────────────────────────────────────────────────────────

describe('frontend-host-compliance-tab — structural', () => {
  // @ac AC-01
  test('frontend-host-compliance-tab/AC-01 — tab replaces the stub: page mounts ComplianceTab, registry entry gone', () => {
    expect(PAGE_SRC).toMatch(
      /import\s*\{\s*ComplianceTab\s*\}\s*from\s*['"]@\/pages\/host-detail\/ComplianceTab['"]/,
    );
    expect(PAGE_SRC).toContain("activeTab === 'compliance' ? (");
    expect(PAGE_SRC).toContain('<ComplianceTab');
    // The stub registry no longer carries a compliance entry.
    expect(PAGE_SRC).not.toMatch(/^\s*compliance:\s*'/m);
    // remediation + activity + audit_log joined overview + compliance as live tabs.
    expect(PAGE_SRC).toContain(
      "Exclude<TabId, 'overview' | 'compliance' | 'remediation' | 'activity' | 'audit_log'>",
    );
  });

  // @ac AC-02
  test('frontend-host-compliance-tab/AC-02 — lens queryKey embeds framework so the cache key changes with the lens', () => {
    expect(TAB_SRC).toContain("queryKey: ['host', hostId, 'compliance', framework ?? null]");
    // Selection is driven through the parent's onFrameworkChange — the
    // tab never navigates itself.
    expect(TAB_SRC).toContain('onFrameworkChange');
    expect(TAB_SRC).not.toMatch(/useNavigate|navigate\(\{/);
  });

  // @ac AC-05
  test('frontend-host-compliance-tab/AC-05 — both query keys carry the [host, hostId] prefix', () => {
    expect(TAB_SRC).toContain("queryKey: ['host', hostId, 'compliance', framework ?? null]");
    expect(TAB_SRC).toContain("queryKey: ['host', hostId, 'compliance_frameworks']");
    // No unprefixed compliance keys that would dodge the SSE refresh.
    expect(TAB_SRC).not.toMatch(/queryKey:\s*\[\s*['"]compliance/);
  });

  // @ac AC-06 (loading-guard half — behavioral halves below)
  test('frontend-host-compliance-tab/AC-06 — loading guard is isPending, not isLoading', () => {
    expect(TAB_SRC).toContain('lensQuery.isPending');
    expect(TAB_SRC).not.toContain('lensQuery.isLoading');
  });

  // @ac AC-07
  test('frontend-host-compliance-tab/AC-07 — evidence drill-down via RuleDetailPanel, scan:read-gated, host lens stays evidence-free', () => {
    // The drill-down reaches the scan:read-gated /scans evidence surface
    // through the shared panel; it is NOT fetched from a /hosts endpoint.
    expect(TAB_SRC).toContain('RuleDetailPanel');
    expect(TAB_SRC).toMatch(/hasPermission\)\('scan:read'\)/);
    expect(TAB_SRC).toContain('scan_context.scan_id');
    // The host-compliance surface stays evidence-free: no evidence is
    // fetched from any /hosts compliance endpoint (evidence lives at /scans).
    expect(TAB_SRC).not.toMatch(/hosts\/\{id\}\/compliance[^']*evidence/i);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Behavioral
// ─────────────────────────────────────────────────────────────────────────

describe('frontend-host-compliance-tab — behavioral', () => {
  // @ac AC-02
  test('frontend-host-compliance-tab/AC-02 — lens bar drives onFrameworkChange and the lens queryKey embeds framework', async () => {
    primeApi();
    const onChange = vi.fn();
    renderTab({ onFrameworkChange: onChange });

    // Chips: All rules + one per frameworks[] entry, labeled with
    // framework_id and rule_count.
    const allChip = await screen.findByRole('button', { name: /All rules/ });
    const cisChip = await screen.findByRole('button', { name: /CIS RHEL 9\s*271 rules\s*36\.9%/ });
    await screen.findByRole('button', { name: /STIG RHEL 9\s*338 rules\s*34%/ });

    // With framework=undefined, "All rules" is the active chip.
    expect(allChip).toHaveAttribute('aria-pressed', 'true');
    expect(cisChip).toHaveAttribute('aria-pressed', 'false');

    fireEvent.click(cisChip);
    expect(onChange).toHaveBeenCalledWith('cis_rhel9');

    fireEvent.click(allChip);
    expect(onChange).toHaveBeenCalledWith(undefined);
  });

  test('frontend-host-compliance-tab/AC-02 — active chip reflects the framework prop', async () => {
    primeApi();
    renderTab({ framework: 'stig_rhel9' });
    const stigChip = await screen.findByRole('button', { name: /STIG RHEL 9\s*338 rules\s*34%/ });
    expect(stigChip).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByRole('button', { name: /All rules/ })).toHaveAttribute(
      'aria-pressed',
      'false',
    );
  });

  // @ac AC-03
  test('frontend-host-compliance-tab/AC-03 — summary, categories, and rules render from one response with reconciling counts', async () => {
    primeApi();
    renderTab();

    // Scan-context strip — headline renders immediately; the sub-line
    // fills in once the lens response lands.
    await screen.findByText('One scan, viewed through any framework');
    await screen.findByText(/Last scan/);
    // Policy version renders in BOTH the scan-context strip and the
    // Scan panel since the prototype-fidelity pass.
    expect(screen.getAllByText('v3').length).toBeGreaterThanOrEqual(1);

    // Summary tiles — values reconcile with the rules array (2 pass,
    // 1 fail, 1 skipped, 0 error, score 50%).
    const recomputed = {
      pass: LENS.rules.filter((r) => r.status === 'pass').length,
      fail: LENS.rules.filter((r) => r.status === 'fail').length,
      skipped: LENS.rules.filter((r) => r.status === 'skipped').length,
      error: LENS.rules.filter((r) => r.status === 'error').length,
    };
    expect(recomputed).toEqual({
      pass: LENS.summary.passing,
      fail: LENS.summary.failing,
      skipped: LENS.summary.skipped,
      error: LENS.summary.error,
    });
    // Donut panel: score + legend. Executed = passing + failing; the
    // Error row is omitted when error is 0 (prototype behavior).
    const scoreRegion = screen.getByLabelText('Compliance score');
    expect(scoreRegion).toHaveTextContent('50%');
    const legend = within(scoreRegion).getByLabelText('Status totals');
    expect(legend).toHaveTextContent(/Compliant\s*2/);
    expect(legend).toHaveTextContent(/Non-compliant\s*1/);
    expect(legend).toHaveTextContent(/No verdict\s*1/);
    expect(legend).toHaveTextContent(/Executed\s*3/);
    expect(within(legend).queryByText('Error')).toBeNull();
    // Result mix panel: Compliant / Non-compliant bars with counts.
    const summaryRegion = screen.getByLabelText('Result mix');
    expect(summaryRegion).toHaveTextContent('Compliant');
    expect(summaryRegion).toHaveTextContent('Non-compliant');
    expect(summaryRegion).toHaveTextContent('1 rules produced no verdict');
    // Scan panel (prototype right column) renders alongside.
    const scanRegion = screen.getByLabelText('Scan details');
    expect(scanRegion).toHaveTextContent('Ran');
    expect(scanRegion).toHaveTextContent('Coverage');

    // Category rows: numbered, "passing / failing" over EXECUTED rules
    // plus the banded pass percentage (N/A rows excluded).
    const catRegion = screen.getByLabelText('Category breakdown');
    expect(catRegion).toHaveTextContent('ssh');
    expect(catRegion).toHaveTextContent(/1\s*\/\s*1/); // ssh: 1 pass / 1 fail
    expect(catRegion).toHaveTextContent('50%');
    expect(catRegion).toHaveTextContent('auth');
    expect(catRegion).toHaveTextContent('100%'); // auth: 1 pass / 0 fail (skip excluded)

    // Rules table — one row per rules[] entry: title, mono control_ids
    // (joined) or rule_id, category, status chip.
    expect(screen.getByText('Disable root SSH login')).toBeInTheDocument();
    expect(screen.getByText('CIS-5.2.8')).toBeInTheDocument(); // control_ids joined
    expect(screen.getByText('r-ssh-proto')).toBeInTheDocument(); // rule_id fallback
    expect(screen.getByText('AppArmor profile enforced')).toBeInTheDocument();
    // Status chips — scope to the table so the filter chips above it
    // (which carry the same words) do not collide.
    const table = screen.getByRole('table');
    expect(within(table).getByText('Non-compliant')).toBeInTheDocument();
    expect(within(table).getAllByText('Compliant').length).toBe(2);
    expect(within(table).getByText('No verdict')).toBeInTheDocument();

    // ONE lens request + ONE frameworks request — everything rendered
    // from a single lens response.
    const lensCalls = getMock.mock.calls.filter(([p]) => p === '/api/v1/hosts/{id}/compliance');
    expect(lensCalls.length).toBe(1);
  });

  // @ac AC-04
  test('frontend-host-compliance-tab/AC-04 — status filter is client-side only: no refetch on filter click', async () => {
    primeApi();
    renderTab();
    await screen.findByText('Disable root SSH login');

    const callsBefore = getMock.mock.calls.length;

    // Narrow to Fail — only the failing rule remains.
    fireEvent.click(screen.getByRole('button', { name: /Non-compliant\s*1/ }));
    expect(screen.getByText('Disable root SSH login')).toBeInTheDocument();
    expect(screen.queryByText('Enforce SSH protocol 2')).toBeNull();
    expect(screen.queryByText('AppArmor profile enforced')).toBeNull();

    // Restore All — the full set returns.
    fireEvent.click(screen.getByRole('button', { name: /^All\s*4$/ }));
    expect(screen.getByText('Enforce SSH protocol 2')).toBeInTheDocument();

    // Search narrows by title substring, also without refetching.
    fireEvent.change(screen.getByLabelText('Search rules or framework IDs'), {
      target: { value: 'AppArmor' },
    });
    expect(screen.getByText('AppArmor profile enforced')).toBeInTheDocument();
    expect(screen.queryByText('Disable root SSH login')).toBeNull();
    fireEvent.change(screen.getByLabelText('Search rules or framework IDs'), {
      target: { value: '' },
    });
    expect(screen.getByText('Disable root SSH login')).toBeInTheDocument();

    // No network traffic from filtering or searching.
    expect(getMock.mock.calls.length).toBe(callsBefore);
  });

  // @ac AC-06
  test('frontend-host-compliance-tab/AC-06 — never-scanned renders empty state naming Run scan, no tiles or table', async () => {
    primeApi({
      lens: NEVER_SCANNED,
      frameworks: {
        overall: { framework_id: 'all', rule_count: 0, passing: 0, failing: 0, score_pct: 0 },
        frameworks: [],
      },
    });
    renderTab();

    await screen.findByText('No scan results yet');
    expect(screen.getByText(/Run scan button/)).toBeInTheDocument();
    expect(screen.getByText('No scan yet')).toBeInTheDocument();
    // No summary tiles and no rules table in the never-scanned state.
    expect(screen.queryByLabelText('Result mix')).toBeNull();
    expect(screen.queryByLabelText('Compliance score')).toBeNull();
    expect(screen.queryByRole('table')).toBeNull();
  });

  // @ac AC-06
  test('frontend-host-compliance-tab/AC-06 — lens error renders inline with a Retry control', async () => {
    primeApi({ lensFails: true });
    renderTab();

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/Failed to load|boom/);
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Re-scan button (AC-08) — same enqueue semantics as the page-head Run
// scan: one idempotency-keyed POST, 409 as an informational note.
// ─────────────────────────────────────────────────────────────────────────

describe('frontend-host-compliance-tab — re-scan', () => {
  // @ac AC-08
  test('frontend-host-compliance-tab/AC-08 — Re-scan posts once with an Idempotency-Key; 409 renders Scan already running', async () => {
    primeApi();
    postMock.mockResolvedValue({
      data: undefined,
      error: undefined,
      response: { ok: true, status: 202 },
    });
    renderTab();
    await screen.findByText('Disable root SSH login');

    fireEvent.click(screen.getByRole('button', { name: 'Re-scan this host' }));
    expect(await screen.findByText('Scan queued')).toBeInTheDocument();

    // Exactly one POST to the scan-enqueue endpoint, idempotency-keyed.
    expect(postMock.mock.calls.length).toBe(1);
    const [path, opts] = postMock.mock.calls[0]!;
    expect(path).toBe('/api/v1/hosts/{id}/scans');
    expect(opts.params.header['Idempotency-Key']).toMatch(/[0-9a-f-]{36}/);

    // 409 (scan already active) renders an informational note, not an
    // error surface — no alert role, no Retry.
    postMock.mockResolvedValue({
      data: undefined,
      error: { error: { code: 'scans.already_running' } },
      response: { ok: false, status: 409 },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Re-scan this host' }));
    expect(await screen.findByText('Scan already running')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull();

    // Source inspection: no Export control anywhere in the tab (C-04)
    // — comments may explain the deferral, but no rendered label.
    expect(TAB_SRC).not.toMatch(/>\s*Export\s*</);
    expect(TAB_SRC).not.toMatch(/aria-label=["']Export/);
  });
});

describe('frontend-host-compliance-tab v1.2.0 — exception overlay', () => {
  // @ac AC-09
  test('frontend-host-compliance-tab/AC-09 — waived/pending badges + request action; overlay never mutates the lens', () => {
    // Source inspection over the tab.
    expect(TAB_SRC).toContain('useHostExceptions(hostId)');
    expect(TAB_SRC).toContain("hasPermission)('exception:request')");
    // Exception column cell with the three states.
    expect(TAB_SRC).toContain('function ExceptionCell');
    expect(TAB_SRC).toMatch(/Waived/);
    expect(TAB_SRC).toMatch(/Pending/);
    expect(TAB_SRC).toContain('Request exception');
    // Request modal posts and invalidates the host exceptions key.
    expect(TAB_SRC).toContain('function RequestExceptionModal');
    expect(TAB_SRC).toContain("api.POST('/api/v1/hosts/{id}/exceptions'");
    expect(TAB_SRC).toContain(
      "queryClient.invalidateQueries({ queryKey: ['host', hostId, 'exceptions'] })",
    );
    // Reason required: submit disabled until non-empty.
    expect(TAB_SRC).toMatch(/disabled=\{reason\.trim\(\) === ''/);
    // Overlay model: the request button only on FAILING rules; the
    // status chip is untouched (no remap of r.status by the overlay).
    expect(TAB_SRC).toContain("rule.status === 'fail' && canRequest");
  });

  // @ac AC-10
  test('frontend-host-compliance-tab/AC-10 — Re-scan reflects in-flight scan_state', () => {
    // ScanContextStrip forwards scan_context.scan_state to RescanButton.
    expect(TAB_SRC).toMatch(/scanState=\{lensQuery\.data\?\.scan_context\.scan_state/);
    expect(TAB_SRC).toMatch(/<RescanButton hostId=\{hostId\} scanState=\{scanState\}/);
    // RescanButton stays disabled + labeled while a scan is in flight.
    expect(TAB_SRC).toMatch(/const active = scanState === 'running' \|\| scanState === 'queued'/);
    expect(TAB_SRC).toMatch(/disabled=\{busy \|\| active\}/);
    expect(TAB_SRC).toMatch(/scanState === 'running'\s*\?\s*'Running…'/);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// AC-11: absence renders as absence, coverage states are honest, and no
// skipped outcome is called "not applicable".
//
// Every value below comes from the SPEC. The fixture is read through js-yaml
// and every key is consumed, so editing the YAML changes what this test
// asserts and an unread key fails it. A test that restated the cases inline
// would let the spec drift without anything noticing.
// ─────────────────────────────────────────────────────────────────────────

// summaryFor builds a contract-shaped summary for one fixture case.
function summaryFor(c: {
  passing: number;
  failing: number;
  skipped: number;
  error: number;
  score_pct: number | null;
  coverage_status: string;
  coverage_pct?: number;
}) {
  return {
    passing: c.passing,
    failing: c.failing,
    skipped: c.skipped,
    error: c.error,
    total: c.passing + c.failing + c.skipped + c.error,
    score_pct: c.score_pct,
    coverage_status: c.coverage_status,
    coverage_pct: c.coverage_pct ?? null,
  };
}

// @ac AC-11
// AC-11: a completed all-skipped scan and a genuine zero appear in the same
// fixture, so neither a hardcoded null nor a hardcoded zero survives.
test('frontend-host-compliance-tab/AC-11 — absence renders as absence, coverage is honest, no "not applicable"', async () => {
  const { inputs, expected } = loadCriterion(
    'host-compliance-tab',
    'frontend-host-compliance-tab',
    'AC-11',
  );
  const inp = trackFixture(inputs, 'AC-11 inputs');
  const exp = trackFixture(expected, 'AC-11 expected_output');

  const cases = inp.get<AnyRec[]>('cases');
  const forbidden = inp.get<string[]>('forbidden_copy');
  const reasonPattern = new RegExp(inp.get<string>('coverage_reason_pattern'));
  const wantCounts = exp.get<string[]>('counts_asserted');
  const showsPct = exp.get<boolean>('coverage_available_shows_percentage');
  const showsReason = exp.get<boolean>('coverage_unavailable_shows_reason');
  const wantForbiddenCount = exp.get<number>('forbidden_copy_occurrences');
  if (!exp.get<boolean>('counts_preserved')) {
    throw new Error('fixture must require the raw counts to be preserved');
  }
  inp.allConsumed();
  exp.allConsumed();

  const rendered: string[] = [];
  for (const raw of cases) {
    const c = trackFixture(raw, `AC-11 case ${String(raw.id)}`);
    const id = c.get<string>('id');
    const counts = {
      passing: c.get<number>('passing'),
      failing: c.get<number>('failing'),
      skipped: c.get<number>('skipped'),
      error: c.get<number>('error'),
    };
    const scorePct = c.get<number | null>('score_pct');
    const coverageStatus = c.get<string>('coverage_status');
    const coveragePct = c.has('coverage_pct') ? c.get<number>('coverage_pct') : undefined;
    const renders = c.get<string>('renders');
    const forbids = c.get<string>('forbids');
    c.allConsumed();

    // The fixture must describe a response the SERVER could actually send.
    // A render test cannot catch an impossible one, because the value drives
    // both the mock and the expectation: genuine_zero once carried
    // coverage_pct 83.3 while its own counts give 100.0, and every assertion
    // still passed. Coverage is executed over in-scope, where in-scope is
    // pass + fail + error (system-compliance-scoring C-07).
    if (coverageStatus === 'available') {
      const inScope = counts.passing + counts.failing + counts.error;
      const executed = counts.passing + counts.failing;
      const computed = Math.round((executed / inScope) * 1000) / 10;
      expect(coveragePct, `${id}: coverage_pct must match its own counts`).toBe(computed);
    } else {
      expect(coveragePct, `${id}: an unavailable status carries no percentage`).toBeUndefined();
    }

    const summary = summaryFor({
      ...counts,
      score_pct: scorePct,
      coverage_status: coverageStatus,
      coverage_pct: coveragePct,
    });

    getMock.mockReset();
    getMock.mockImplementation(async (path: string) => {
      if (path === '/api/v1/hosts/{id}/compliance/frameworks') {
        return {
          data: { overall: { ...summary, framework_id: null }, frameworks: [] },
          error: undefined,
          response: { ok: true, status: 200 },
        };
      }
      return {
        data: { ...LENS, summary, categories: [], rules: [] },
        error: undefined,
        response: { ok: true, status: 200 },
      };
    });

    const { container, unmount } = renderTab();
    // Wait for the SCORE PANEL, not the page heading: the heading renders
    // during loading too, so awaiting it read the DOM mid-flight.
    await screen.findByLabelText('Compliance score');
    const text = container.textContent ?? '';
    rendered.push(text);

    expect(text, `${id}: expected ${renders}`).toContain(renders);
    expect(text, `${id}: must not show ${forbids}`).not.toContain(forbids);

    // Coverage: a percentage only when the contract says available, and a
    // stated reason when it does not.
    //
    // Compared EXACTLY against the expectation rather than used as an if.
    // Guarding the assertion on the boolean meant flipping the expectation to
    // false disabled the check instead of failing it, so the two
    // expected_output flags asserted nothing.
    if (coverageStatus === 'available') {
      const gotPct = text.includes(`${coveragePct}%`);
      expect(gotPct, `${id}: coverage percentage shown`).toBe(showsPct);
    } else {
      const gotReason =
        text.includes('Assessment coverage unavailable') && reasonPattern.test(text);
      expect(gotReason, `${id}: coverage unavailable with a stated reason`).toBe(showsReason);
    }

    // ALL FOUR raw counts survive whatever the score does, asserted PER ROW.
    // Searching the whole legend for the number was too weak: with several
    // zero counts any digit matched something, so a component that rendered a
    // constant would have passed.
    const legend = within(container).getByRole('list', { name: 'Status totals' });
    const rowLabel: Record<string, string> = {
      passing: 'Compliant',
      failing: 'Non-compliant',
      skipped: 'No verdict',
      error: 'Error',
    };
    for (const name of wantCounts) {
      const n = counts[name as keyof typeof counts];
      // The Error row renders only when there are errors, which is why the
      // fixture carries a nonzero-error case.
      if (name === 'error' && n === 0) continue;
      const label = rowLabel[name] ?? '';
      const row = within(legend)
        .getAllByRole('listitem')
        .find((el) => (el.textContent ?? '').startsWith(label));
      expect(row, `${id}: legend row for ${name}`).toBeDefined();
      expect(row?.textContent, `${id}: ${name} count is ${n}`).toBe(`${label}${n}`);
    }

    // Unmount between cases. Without it the next render lands beside this one
    // and findByLabelText resolves against the stale panel.
    unmount();
  }

  // Forbidden copy, from the fixture, across every rendered case.
  const all = rendered.join(' ');
  let hits = 0;
  for (const phrase of forbidden) {
    if (new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i').test(all)) {
      hits += 1;
      expect.fail(`rendered copy contains the forbidden phrase ${phrase}`);
    }
  }
  expect(hits).toBe(wantForbiddenCount);
});
