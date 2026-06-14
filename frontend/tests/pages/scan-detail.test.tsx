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

const PANEL_SRC = readFileSync(resolve(process.cwd(), 'src/pages/scans/RuleDetailPanel.tsx'), 'utf8');
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
  checks: [{ method: 'config_value', command: 'grep MaxAuthTries /etc/ssh/sshd_config', stdout: 'MaxAuthTries 4', exit_code: 0 }],
  framework_refs: {},
};

describe('frontend-scan-detail', () => {
  beforeEach(() => {
    getMock.mockReset();
    getMock.mockResolvedValue({ data: EVIDENCE, error: undefined });
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
  test('frontend-scan-detail/AC-03 — RuleDetailPanel Formatted/Evidence/OSCAL switch', async () => {
    renderPanel();
    // Three view tabs present.
    expect(screen.getByRole('tab', { name: 'Formatted' })).toBeTruthy();
    expect(screen.getByRole('tab', { name: 'Evidence' })).toBeTruthy();
    expect(screen.getByRole('tab', { name: 'OSCAL' })).toBeTruthy();
    // Formatted (default) shows the verdict detail.
    await waitFor(() => expect(screen.getByText('host is compliant')).toBeTruthy());
    // Evidence shows the raw command + stdout.
    fireEvent.click(screen.getByRole('tab', { name: 'Evidence' }));
    await waitFor(() => expect(screen.getByText('grep MaxAuthTries /etc/ssh/sshd_config')).toBeTruthy());
    expect(screen.getByText('MaxAuthTries 4')).toBeTruthy();
  });

  // @ac AC-04
  test('frontend-scan-detail/AC-04 — evidence fetched lazily (not under OSCAL)', async () => {
    // Source: query key + lazy enabled gate.
    expect(PANEL_SRC).toMatch(/queryKey: \['scan', scanId, 'rule', ruleId, 'evidence'\]/);
    expect(PANEL_SRC).toMatch(/enabled: hasEvidence && view !== 'oscal'/);

    // Render: open the panel, immediately switch to OSCAL — no evidence GET fires
    // for the OSCAL view (the formatted default fetches once, then OSCAL is inert).
    renderPanel();
    fireEvent.click(screen.getByRole('tab', { name: 'OSCAL' }));
    await screen.findByText('Download OSCAL');
    // Only the initial Formatted view's fetch happened; OSCAL adds none.
    expect(getMock.mock.calls.length).toBeLessThanOrEqual(1);
    // A rule with no evidence never fetches.
    getMock.mockClear();
    renderPanel({ hasEvidence: false });
    await screen.findByText('No evidence was captured for this rule.');
    expect(getMock).not.toHaveBeenCalled();
  });

  // @ac AC-05
  test('frontend-scan-detail/AC-05 — OSCAL download paths with credentials include', () => {
    // Per-rule OSCAL from the panel.
    expect(PANEL_SRC).toContain('/rules/${ruleId}/oscal');
    expect(PANEL_SRC).toMatch(/credentials: 'include'/);
    // Whole-scan OSCAL from the page.
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
});
