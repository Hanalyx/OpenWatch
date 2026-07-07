// @spec frontend-rules-library
//
// AC traceability (this file):
//   AC-01  frontend-rules-library/AC-01 — Rules tab mounted; GET /api/v1/rules ['rules']
//   AC-02  frontend-rules-library/AC-02 — rows render title + framework tag + counts
//   AC-03  frontend-rules-library/AC-03 — client-side search narrows, no extra fetch
//   AC-04  frontend-rules-library/AC-04 — CSV export; no bulk-select/kebab; no em-dash

import { describe, expect, test, beforeEach, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

const { getMock } = vi.hoisted(() => ({ getMock: vi.fn() }));
vi.mock('@/api/client', () => ({ default: { GET: getMock } }));

import { RulesTab } from '@/pages/scans/RulesTab';

const TAB_SRC = readFileSync(resolve(process.cwd(), 'src/pages/scans/RulesTab.tsx'), 'utf8');
const SCANS_SRC = readFileSync(resolve(process.cwd(), 'src/pages/scans/ScansPage.tsx'), 'utf8');

function stripComments(src: string): string {
  return src.replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
}

const RULES = {
  total: 3,
  rules: [
    {
      id: 'sshd-root-login-disabled',
      title: 'Disable SSH root login',
      description: 'Root login over SSH must be disabled.',
      severity: 'high',
      category: 'network',
      tags: ['ssh'],
      framework_refs: { cis_rhel9: ['5.2.8'], nist_800_53: ['AC-6'] },
      transactional: true,
      remediation: {
        available: true,
        mechanisms: ['config_set_dropin'],
        restarts_services: [],
        reboot_behavior: 'boot-param',
      },
    },
    {
      id: 'auditd-enabled',
      title: 'Install and enable auditd',
      description: 'The audit daemon must be installed and running.',
      severity: 'medium',
      category: 'audit',
      tags: [],
      framework_refs: { cis_rhel9: ['6.3.1.4'], stig_rhel9: ['V-258151'] },
      transactional: true,
      remediation: {
        available: true,
        mechanisms: ['service_enabled'],
        restarts_services: ['auditd'],
        reboot_behavior: 'none',
      },
    },
    {
      id: 'manual-rule',
      title: 'A manual rule',
      description: 'Fix by hand.',
      severity: 'low',
      category: 'system',
      tags: [],
      framework_refs: { nist_800_53: ['CM-6'] },
      transactional: false,
      remediation: {
        available: false,
        mechanisms: [],
        restarts_services: [],
        reboot_behavior: 'none',
      },
    },
  ],
};

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <RulesTab />
    </QueryClientProvider>,
  );
}

describe('frontend-rules-library', () => {
  beforeEach(() => {
    getMock.mockReset();
    getMock.mockResolvedValue({ data: RULES, error: undefined });
  });

  // @ac AC-01
  test('frontend-rules-library/AC-01 — Rules tab mounted; GET /api/v1/rules with key [rules]', () => {
    // ScansPage wires the tab + renders RulesTab.
    expect(SCANS_SRC).toMatch(/'coverage' \| 'history' \| 'rules'/);
    expect(SCANS_SRC).toContain('<RulesTab />');
    // RulesTab fetches the catalog.
    expect(TAB_SRC).toContain("api.GET('/api/v1/rules'");
    expect(TAB_SRC).toMatch(/queryKey: \['rules'\]/);
  });

  // @ac AC-02
  test('frontend-rules-library/AC-02 — rows render title + framework tag + counts', async () => {
    renderTab();
    await waitFor(() => expect(screen.getByText('Disable SSH root login')).toBeTruthy());
    // A CIS framework tag is rendered (prefixed).
    expect(screen.getByText('CIS-5.2.8')).toBeTruthy();
    // Header total + showing count.
    expect(screen.getByText('showing 3 of 3')).toBeTruthy();
  });

  // @ac AC-03
  test('frontend-rules-library/AC-03 — client-side search narrows without extra fetch', async () => {
    renderTab();
    await waitFor(() => expect(screen.getByText('Disable SSH root login')).toBeTruthy());
    expect(getMock).toHaveBeenCalledTimes(1);

    fireEvent.change(screen.getByLabelText('Search rules, IDs, frameworks'), {
      target: { value: 'auditd' },
    });
    await waitFor(() => expect(screen.getByText('showing 1 of 3')).toBeTruthy());
    expect(screen.getByText('Install and enable auditd')).toBeTruthy();
    expect(screen.queryByText('Disable SSH root login')).toBeNull();
    // No refetch on filter.
    expect(getMock).toHaveBeenCalledTimes(1);
    // Source: filter is a client-side useMemo over the fetched rules.
    expect(TAB_SRC).toMatch(/const shown = useMemo/);
  });

  // @ac AC-04
  test('frontend-rules-library/AC-04 — CSV export; no bulk-select/kebab; no em-dash', () => {
    // CSV export built client-side.
    expect(TAB_SRC).toMatch(/text\/csv/);
    expect(TAB_SRC).toMatch(/\.csv/);
    // Honest affordances: no bulk-select checkbox, no kebab/action menu.
    expect(TAB_SRC).not.toMatch(/type="checkbox"/);
    expect(TAB_SRC).not.toMatch(/kebab|⋮|MoreVert|action-menu/i);
    // No em-dash in copy.
    expect(stripComments(TAB_SRC)).not.toContain('—');
  });
});
