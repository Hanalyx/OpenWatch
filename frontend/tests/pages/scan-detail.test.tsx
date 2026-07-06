// @spec frontend-scan-detail
//
// AC traceability (this file):
//   AC-01  frontend-scan-detail/AC-01 — route mounted at scans/$scanId with scan:read guard
//   AC-02  frontend-scan-detail/AC-02 — breadcrumb + scan GET + no em-dash
//   AC-03  frontend-scan-detail/AC-03 — RuleDetailPanel Formatted/Evidence/OSCAL switch
//   AC-04  frontend-scan-detail/AC-04 — evidence fetched lazily (not under OSCAL)
//   AC-05  frontend-scan-detail/AC-05 — OSCAL download paths with credentials include
//   AC-06  frontend-scan-detail/AC-06 — /scans host expands to scan history linking to /scans/$scanId

import { describe, expect, test, beforeEach, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const { getMock } = vi.hoisted(() => ({ getMock: vi.fn() }));
vi.mock('@/api/client', () => ({ default: { GET: getMock } }));

import { RuleDetailPanel } from '@/pages/scans/RuleDetailPanel';

const PANEL_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/scans/RuleDetailPanel.tsx'),
  'utf8',
);
const PAGE_SRC = readFileSync(resolve(process.cwd(), 'src/pages/scans/ScanDetailPage.tsx'), 'utf8');
const SCANS_SRC = readFileSync(resolve(process.cwd(), 'src/pages/scans/ScansPage.tsx'), 'utf8');
const ROUTER_SRC = readFileSync(resolve(process.cwd(), 'src/routes/router.tsx'), 'utf8');

function stripComments(src: string): string {
  return src.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
}

function renderPanel(props: { hasEvidence?: boolean } = {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <RuleDetailPanel scanId="scan-123" ruleId="rule-x" hasEvidence={props.hasEvidence ?? true} />
    </QueryClientProvider>,
  );
}

const EVIDENCE = {
  rule_id: 'rule-x',
  status: 'pass',
  severity: 'medium',
  detail: 'host is compliant',
  checks: [
    {
      method: 'config_value',
      command: 'grep MaxAuthTries /etc/ssh/sshd_config',
      stdout: 'MaxAuthTries 4',
      exit_code: 0,
    },
  ],
  framework_refs: {},
};
const OSCAL_DOC = { 'assessment-results': { uuid: 'oscal-1', results: [] } };

const evidenceCalls = () =>
  getMock.mock.calls.filter((c) => String(c[0]).endsWith('/evidence')).length;
const oscalCalls = () => getMock.mock.calls.filter((c) => String(c[0]).endsWith('/oscal')).length;
const inPre = (needle: string) => (content: string, el: Element | null) =>
  el?.tagName === 'PRE' && content.includes(needle);

describe('frontend-scan-detail', () => {
  beforeEach(() => {
    getMock.mockReset();
    getMock.mockImplementation((path: string) =>
      Promise.resolve({
        data: String(path).endsWith('/oscal') ? OSCAL_DOC : EVIDENCE,
        error: undefined,
      }),
    );
  });

  // @ac AC-01
  test('frontend-scan-detail/AC-01 — route mounted at scans/$scanId with scan:read guard', () => {
    expect(ROUTER_SRC).toContain("path: 'scans/$scanId'");
    expect(ROUTER_SRC).toContain('ScanDetailPage');
    // beforeLoad guards scan:read -> /_forbidden.
    const guard = /scans\/\$scanId[\s\S]*?hasPermission\('scan:read'\)[\s\S]*?_forbidden/;
    expect(ROUTER_SRC).toMatch(guard);
  });

  // @ac AC-02
  test('frontend-scan-detail/AC-02 — breadcrumb + scan GET + no em-dash', () => {
    expect(PAGE_SRC).toContain('useBreadcrumbStore');
    expect(PAGE_SRC).toMatch(/setCrumbs\(\[/);
    expect(PAGE_SRC).toMatch(/return \(\) => setCrumbs\(\[\]\)/);
    expect(PAGE_SRC).toContain("label: 'Infrastructure'");
    expect(PAGE_SRC).toContain("label: 'Scans'");
    expect(PAGE_SRC).toContain("api.GET('/api/v1/scans/{id}'");
    expect(stripComments(PAGE_SRC)).not.toContain('—');
    expect(stripComments(PANEL_SRC)).not.toContain('—');
  });

  // @ac AC-03
  test('frontend-scan-detail/AC-03 — Formatted/Evidence/OSCAL switch; Evidence+OSCAL are raw JSON', async () => {
    renderPanel();
    // Three view tabs present.
    expect(screen.getByRole('tab', { name: 'Formatted' })).toBeTruthy();
    expect(screen.getByRole('tab', { name: 'Evidence' })).toBeTruthy();
    expect(screen.getByRole('tab', { name: 'OSCAL' })).toBeTruthy();
    // Formatted (default) shows the verdict detail.
    await waitFor(() => expect(screen.getByText('host is compliant')).toBeTruthy());
    // Evidence renders the full result as raw JSON (in a <pre>), not a formatted layout.
    fireEvent.click(screen.getByRole('tab', { name: 'Evidence' }));
    await waitFor(() =>
      expect(screen.getByText(inPre('grep MaxAuthTries /etc/ssh/sshd_config'))).toBeTruthy(),
    );
    expect(screen.getByText(inPre('"checks"'))).toBeTruthy();
    // OSCAL renders the OSCAL document as raw JSON.
    fireEvent.click(screen.getByRole('tab', { name: 'OSCAL' }));
    await waitFor(() => expect(screen.getByText(inPre('assessment-results'))).toBeTruthy());
    // Both views go through a JSON dump.
    expect(PANEL_SRC).toMatch(/JSON\.stringify/);
  });

  // @ac AC-04
  test('frontend-scan-detail/AC-04 — evidence fetched lazily; OSCAL fetched on demand without re-fetching evidence', async () => {
    // Source: evidence query key + lazy enabled gate; OSCAL has its own key.
    expect(PANEL_SRC).toMatch(/queryKey: \['scan', scanId, 'rule', ruleId, 'evidence'\]/);
    expect(PANEL_SRC).toMatch(/enabled: hasEvidence && view !== 'oscal'/);
    expect(PANEL_SRC).toMatch(/queryKey: \['scan', scanId, 'rule', ruleId, 'oscal'\]/);

    // Default Formatted view fetches evidence once.
    renderPanel();
    await waitFor(() => expect(evidenceCalls()).toBe(1));
    // Switching to OSCAL fetches OSCAL but does NOT re-fetch evidence.
    fireEvent.click(screen.getByRole('tab', { name: 'OSCAL' }));
    await waitFor(() => expect(oscalCalls()).toBe(1));
    expect(evidenceCalls()).toBe(1);
    // A rule with no evidence never fetches evidence.
    getMock.mockClear();
    renderPanel({ hasEvidence: false });
    await screen.findByText('No evidence was captured for this rule.');
    expect(evidenceCalls()).toBe(0);
  });

  // @ac AC-05
  test('frontend-scan-detail/AC-05 — OSCAL fetched per rule; whole-scan downloaded with credentials', () => {
    // Per-rule OSCAL fetched via the typed client from the oscal endpoint.
    expect(PANEL_SRC).toContain("api.GET('/api/v1/scans/{id}/rules/{ruleId}/oscal'");
    // Whole-scan OSCAL download from the page with the session cookie.
    expect(PAGE_SRC).toContain('/api/v1/scans/${scanId}/oscal');
    expect(PAGE_SRC).toMatch(/credentials: 'include'/);
  });

  // @ac AC-06
  test('frontend-scan-detail/AC-06 — /scans host expands to scan history linking to /scans/$scanId', () => {
    expect(SCANS_SRC).toContain("api.GET('/api/v1/scans'");
    expect(SCANS_SRC).toMatch(/host_id: hostId/);
    expect(SCANS_SRC).toContain('to="/scans/$scanId"');
    // The Coverage host cell is a toggle button, not a /hosts deep link.
    expect(SCANS_SRC).toMatch(/setOpenHost\(/);
  });

  // @ac AC-07
  test('frontend-scan-detail/AC-07 — rich rules table: status/severity/framework tags/verdict/search/filter', () => {
    // Status words + severity pills.
    expect(PAGE_SRC).toContain("label: 'Compliant'");
    expect(PAGE_SRC).toContain("label: 'Non-compliant'");
    expect(PAGE_SRC).toContain("label: 'N/A'");
    expect(PAGE_SRC).toMatch(/SEVERITY/);
    // Framework refs flattened into family-colored tags (CIS/STIG/NIST).
    expect(PAGE_SRC).toMatch(/function fwTag/);
    expect(PAGE_SRC).toMatch(/CIS-\$\{control\}/);
    expect(PAGE_SRC).toMatch(/flattenRefs/);
    // Sub-line shows the catalog description, falling back to skip_reason.
    expect(PAGE_SRC).toMatch(/rule\.description \|\| rule\.skip_reason/);
    // Search + status filter chips.
    expect(PAGE_SRC).toMatch(/Search rules or framework IDs/);
    expect(PAGE_SRC).toMatch(/setStatusFilter/);
    // Honest affordances: no Fix / remediation control on a historical scan.
    expect(PAGE_SRC).not.toMatch(/>Fix</);
    // No em-dash in copy.
    expect(stripComments(PAGE_SRC)).not.toContain('—');
  });

  // @ac AC-08
  test('frontend-scan-detail/AC-08 — Host field shows hostname || ip || short uuid, not a bare uuid', () => {
    // The Host Meta uses the hostname-then-IP-then-short-UUID fallback.
    expect(PAGE_SRC).toMatch(
      /scan\.hostname \|\| scan\.ip_address \|\| scan\.host_id\.slice\(0, 8\)/,
    );
    // And it is NOT the old bare-UUID render (slice as the sole child).
    expect(PAGE_SRC).not.toMatch(/>\s*\{scan\.host_id\.slice\(0, 8\)\}\s*</);
    // Still a Link to the host detail page.
    expect(PAGE_SRC).toContain('to="/hosts/$hostId"');
  });
});
