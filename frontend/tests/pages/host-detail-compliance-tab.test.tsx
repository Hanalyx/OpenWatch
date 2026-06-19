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
  summary: { passing: 2, failing: 1, skipped: 1, error: 0, total: 4, score_pct: 50 },
  categories: [
    { category: 'ssh', passing: 1, failing: 1, total: 2 },
    { category: 'auth', passing: 1, failing: 0, total: 2 },
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
    // remediation joined overview + compliance as a live (non-stub) tab.
    expect(PAGE_SRC).toContain("Exclude<TabId, 'overview' | 'compliance' | 'remediation'>");
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
    expect(legend).toHaveTextContent(/Not applicable\s*1/);
    expect(legend).toHaveTextContent(/Executed\s*3/);
    expect(within(legend).queryByText('Error')).toBeNull();
    // Result mix panel: Compliant / Non-compliant bars with counts.
    const summaryRegion = screen.getByLabelText('Result mix');
    expect(summaryRegion).toHaveTextContent('Compliant');
    expect(summaryRegion).toHaveTextContent('Non-compliant');
    expect(summaryRegion).toHaveTextContent('1 rules not applicable');
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
    expect(within(table).getByText('N/A')).toBeInTheDocument();

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
});
