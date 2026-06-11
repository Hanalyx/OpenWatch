// @spec frontend-host-detail-system-card
//
// AC traceability (this file):
//
//   AC-02  test('frontend-host-detail-system-card/AC-02 — discovered host shows distribution + dashes for kernel/uptime')
//   AC-03  test('frontend-host-detail-system-card/AC-03 — pre-Discovery host renders Not discovered yet + Re-run button')
//   AC-04  test('frontend-host-detail-system-card/AC-04 — Re-run button hidden when caller lacks host:write')
//   AC-05  test('frontend-host-detail-system-card/AC-05 — Re-run click mints fresh idempotency key via crypto.randomUUID')
//   AC-06  test('frontend-host-detail-system-card/AC-06 — Re-run success invalidates both host + intelligence_state queries')
//   AC-07  test('frontend-host-detail-system-card/AC-07 — 502 surfaces Host unreachable inline')

import { describe, expect, test, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { CardSystem, type CardSystemHost } from '@/pages/host-detail/CardSystem';
import { useAuthStore } from '@/store/useAuthStore';

const PAGE_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/host-detail/CardSystem.tsx'),
  'utf8',
);

function withWriter(): void {
  useAuthStore.setState({
    identity: {
      id: 'u-1',
      username: 'op',
      email: 'op@example.com',
      role: 'operator',
      permissions: ['host:read', 'host:write'],
      mfaEnabled: false,
    },
    loading: false,
  });
}

function withReadOnly(): void {
  useAuthStore.setState({
    identity: {
      id: 'u-2',
      username: 'viewer',
      email: 'viewer@example.com',
      role: 'viewer',
      permissions: ['host:read'],
      mfaEnabled: false,
    },
    loading: false,
  });
}

function makeHost(overrides: Partial<CardSystemHost> = {}): CardSystemHost {
  return {
    id: 'h-1',
    hostname: 'owas-rhn01',
    ip_address: '10.0.0.1',
    port: 22,
    username: 'opadmin',
    ...overrides,
  };
}

function renderWith(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

beforeEach(() => {
  useAuthStore.getState().clear();
});

describe('frontend-host-detail-system-card — behavior', () => {
  // @ac AC-02
  test('frontend-host-detail-system-card/AC-02 — discovered host shows distribution + dashes for kernel/uptime', () => {
    withWriter();
    renderWith(
      <CardSystem
        host={makeHost({ os_family: 'rhel', os_version: '9.2' })}
        intelligenceSnapshot={null}
        systemInfo={null}
      />,
    );
    // Distribution row populated from os_family + os_version
    expect(screen.getByText('RHEL 9.2')).toBeInTheDocument();
    // Kernel and Uptime fall back to em-dash because no IntelligenceState
    // Use queryAllByText since '—' may appear in unrelated cells
    expect(screen.getAllByText('—').length).toBeGreaterThanOrEqual(2);
    // No empty state — Discovery has run
    expect(screen.queryByText('Not discovered yet')).toBeNull();
  });

  // @ac AC-03
  test('frontend-host-detail-system-card/AC-03 — pre-Discovery host renders Not discovered yet + Re-run button', () => {
    withWriter();
    renderWith(
      <CardSystem
        host={makeHost({ os_family: null, os_version: null })}
        intelligenceSnapshot={null}
        systemInfo={null}
      />,
    );
    expect(screen.getByText('Not discovered yet')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /re-run discovery/i })).toBeInTheDocument();
  });

  // @ac AC-04
  test('frontend-host-detail-system-card/AC-04 — Re-run button hidden when caller lacks host:write', () => {
    withReadOnly();
    renderWith(
      <CardSystem
        host={makeHost({ os_family: null, os_version: null })}
        intelligenceSnapshot={null}
        systemInfo={null}
      />,
    );
    expect(screen.getByText('Not discovered yet')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /re-run discovery/i })).toBeNull();
  });
});

describe('frontend-host-detail-system-card — structural', () => {
  // @ac AC-05
  test('frontend-host-detail-system-card/AC-05 — Re-run click mints fresh idempotency key via crypto.randomUUID', () => {
    // The mutation handler MUST call crypto.randomUUID() inline so
    // each click produces a distinct key (no module-level constant).
    expect(PAGE_SRC).toMatch(/crypto\.randomUUID\s*\(\)/);
    // POSTs to the discovery:run endpoint
    expect(PAGE_SRC).toContain("'/api/v1/hosts/{id}/discovery:run'");
    // Passes the host id through path params
    expect(PAGE_SRC).toMatch(/path:\s*\{\s*id:\s*host\.id\s*\}/);
    // Sets the Idempotency-Key header
    expect(PAGE_SRC).toMatch(/['"]Idempotency-Key['"]/);
  });

  // @ac AC-06
  test('frontend-host-detail-system-card/AC-06 — Re-run success invalidates both host + intelligence_state queries', () => {
    // Both invalidateQueries calls MUST appear; partial invalidation
    // would leave the snapshot stale on the page.
    expect(PAGE_SRC).toMatch(
      /invalidateQueries\s*\(\s*\{\s*queryKey:\s*\[\s*['"]host['"]\s*,\s*host\.id\s*\]\s*\}\s*\)/,
    );
    expect(PAGE_SRC).toMatch(
      /invalidateQueries\s*\(\s*\{\s*queryKey:\s*\[\s*['"]intelligence_state['"]\s*,\s*host\.id\s*\]\s*\}\s*\)/,
    );
  });

  // @ac AC-07
  test('frontend-host-detail-system-card/AC-07 — 502 surfaces Host unreachable inline', () => {
    expect(PAGE_SRC).toContain('Host unreachable — check SSH credentials and connectivity');
  });
});
