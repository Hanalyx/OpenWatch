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

import { describe, expect, test, beforeEach, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const { getMock } = vi.hoisted(() => ({ getMock: vi.fn() }));
vi.mock('@/api/client', () => ({ default: { GET: getMock } }));

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
  frameworks: [
    { framework_id: 'cis-rhel9-v2.0.0', rule_count: 271 },
    { framework_id: 'stig-rhel9-v2r7', rule_count: 338 },
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
    expect(PAGE_SRC).toContain("Record<Exclude<TabId, 'overview' | 'compliance'>, string>");
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
  test('frontend-host-compliance-tab/AC-07 — no stored check-output reference anywhere in the tab code', () => {
    expect(TAB_SRC.toLowerCase()).not.toContain('evidence');
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
    const cisChip = await screen.findByRole('button', { name: /cis-rhel9-v2\.0\.0\s*271/ });
    await screen.findByRole('button', { name: /stig-rhel9-v2r7\s*338/ });

    // With framework=undefined, "All rules" is the active chip.
    expect(allChip).toHaveAttribute('aria-pressed', 'true');
    expect(cisChip).toHaveAttribute('aria-pressed', 'false');

    fireEvent.click(cisChip);
    expect(onChange).toHaveBeenCalledWith('cis-rhel9-v2.0.0');

    fireEvent.click(allChip);
    expect(onChange).toHaveBeenCalledWith(undefined);
  });

  test('frontend-host-compliance-tab/AC-02 — active chip reflects the framework prop', async () => {
    primeApi();
    renderTab({ framework: 'stig-rhel9-v2r7' });
    const stigChip = await screen.findByRole('button', { name: /stig-rhel9-v2r7\s*338/ });
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
    expect(screen.getByText('v3')).toBeInTheDocument();

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
    const summaryRegion = screen.getByLabelText('Compliance summary');
    expect(summaryRegion).toHaveTextContent('50%');
    expect(summaryRegion).toHaveTextContent('Passing');
    expect(summaryRegion).toHaveTextContent('Failing');
    expect(summaryRegion).toHaveTextContent('Skipped');
    expect(summaryRegion).toHaveTextContent('Error');

    // Category rows with passing/failing/total.
    const catRegion = screen.getByLabelText('Category breakdown');
    expect(catRegion).toHaveTextContent('ssh');
    expect(catRegion).toHaveTextContent('1 passing');
    expect(catRegion).toHaveTextContent('1 failing');
    expect(catRegion).toHaveTextContent('auth');

    // Rules table — one row per rules[] entry: title, mono control_ids
    // (joined) or rule_id, category, status chip.
    expect(screen.getByText('Disable root SSH login')).toBeInTheDocument();
    expect(screen.getByText('CIS-5.2.8')).toBeInTheDocument(); // control_ids joined
    expect(screen.getByText('r-ssh-proto')).toBeInTheDocument(); // rule_id fallback
    expect(screen.getByText('AppArmor profile enforced')).toBeInTheDocument();
    // Status chips — scope to the table so the filter chips above it
    // (which carry the same words) do not collide.
    const table = screen.getByRole('table');
    expect(within(table).getByText('Fail')).toBeInTheDocument();
    expect(within(table).getAllByText('Pass').length).toBe(2);
    expect(within(table).getByText('Skipped')).toBeInTheDocument();

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
    fireEvent.click(screen.getByRole('button', { name: /^Fail\s*1$/ }));
    expect(screen.getByText('Disable root SSH login')).toBeInTheDocument();
    expect(screen.queryByText('Enforce SSH protocol 2')).toBeNull();
    expect(screen.queryByText('AppArmor profile enforced')).toBeNull();

    // Restore All — the full set returns.
    fireEvent.click(screen.getByRole('button', { name: /^All\s*4$/ }));
    expect(screen.getByText('Enforce SSH protocol 2')).toBeInTheDocument();

    // No network traffic from filtering.
    expect(getMock.mock.calls.length).toBe(callsBefore);
  });

  // @ac AC-06
  test('frontend-host-compliance-tab/AC-06 — never-scanned renders empty state naming Run scan, no tiles or table', async () => {
    primeApi({ lens: NEVER_SCANNED, frameworks: { frameworks: [] } });
    renderTab();

    await screen.findByText('No scan results yet');
    expect(screen.getByText(/Run scan button/)).toBeInTheDocument();
    expect(screen.getByText('No scan yet')).toBeInTheDocument();
    // No summary tiles and no rules table in the never-scanned state.
    expect(screen.queryByLabelText('Compliance summary')).toBeNull();
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
