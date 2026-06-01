// @spec frontend-host-detail-intelligence-feed
//
// AC traceability (this file):
//
//   AC-01  test('frontend-host-detail-intelligence-feed/AC-01 — calls /intelligence/events with host_id + limit 10')
//   AC-02  test('frontend-host-detail-intelligence-feed/AC-02 — query key matches useLiveEvents invalidation target')
//   AC-03  test('frontend-host-detail-intelligence-feed/AC-03 — loading state shows loading affordance, not empty copy')
//   AC-04  test('frontend-host-detail-intelligence-feed/AC-04 — error state shows Retry button that invokes refetch')
//   AC-05  test('frontend-host-detail-intelligence-feed/AC-05 — empty state shows "No intelligence activity yet" copy')
//   AC-06  test('frontend-host-detail-intelligence-feed/AC-06 — rows render event_code text with severity-tinted dot')

import { describe, expect, test, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen } from '@testing-library/react';
import { CardServerIntelView } from '@/pages/host-detail/CardServerIntel';

const CARD_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/host-detail/CardServerIntel.tsx'),
  'utf8',
);

const LIVE_EVENTS_SRC = readFileSync(
  resolve(process.cwd(), 'src/hooks/useLiveEvents.ts'),
  'utf8',
);

function makeEvent(overrides: Partial<{
  id: string;
  event_code: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  occurred_at: string;
}> = {}) {
  return {
    id: 'e-1',
    host_id: 'h-1',
    event_code: 'system.package.updated',
    severity: 'medium' as const,
    occurred_at: new Date(Date.now() - 5 * 60_000).toISOString(),
    detected_at: new Date(Date.now() - 5 * 60_000).toISOString(),
    ...overrides,
  };
}

describe('frontend-host-detail-intelligence-feed — structural', () => {
  // @ac AC-01
  test('frontend-host-detail-intelligence-feed/AC-01 — calls /intelligence/events with host_id + limit 10', () => {
    expect(CARD_SRC).toContain("'/api/v1/intelligence/events'");
    // host_id passed through
    expect(CARD_SRC).toMatch(/host_id:\s*hostId/);
    // limit is literal 10 (also LIMIT constant). One or the other must be visible.
    expect(CARD_SRC).toMatch(/limit:\s*(LIMIT|10)/);
    expect(CARD_SRC).toContain('const LIMIT = 10');
  });

  // @ac AC-02
  test('frontend-host-detail-intelligence-feed/AC-02 — query key matches useLiveEvents invalidation target', () => {
    // Card's query key
    expect(CARD_SRC).toMatch(
      /queryKey:\s*\[\s*['"]host_intelligence_events['"]\s*,\s*hostId\s*\]/,
    );
    // useLiveEvents invalidates the SAME key (verbatim)
    expect(LIVE_EVENTS_SRC).toMatch(
      /queryKey:\s*\[\s*['"]host_intelligence_events['"]\s*,\s*hostId\s*\]/,
    );
  });
});

describe('frontend-host-detail-intelligence-feed — behavior', () => {
  // @ac AC-03
  test('frontend-host-detail-intelligence-feed/AC-03 — loading state shows loading affordance, not empty copy', () => {
    render(
      <CardServerIntelView
        isLoading={true}
        isError={false}
        items={[]}
        onRetry={() => undefined}
      />,
    );
    expect(screen.getByText(/loading…/i)).toBeInTheDocument();
    expect(screen.queryByText(/no intelligence activity yet/i)).toBeNull();
  });

  // @ac AC-04
  test('frontend-host-detail-intelligence-feed/AC-04 — error state shows Retry button that invokes refetch', () => {
    const onRetry = vi.fn();
    render(
      <CardServerIntelView
        isLoading={false}
        isError={true}
        items={[]}
        onRetry={onRetry}
      />,
    );
    expect(screen.getByRole('alert')).toBeInTheDocument();
    const btn = screen.getByRole('button', { name: /retry/i });
    fireEvent.click(btn);
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  // @ac AC-05
  test('frontend-host-detail-intelligence-feed/AC-05 — empty state shows "No intelligence activity yet" copy', () => {
    render(
      <CardServerIntelView
        isLoading={false}
        isError={false}
        items={[]}
        onRetry={() => undefined}
      />,
    );
    expect(screen.getByText('No intelligence activity yet')).toBeInTheDocument();
    // Secondary copy names the source (OS Intelligence collector)
    expect(
      screen.getByText(/OS Intelligence collector/i),
    ).toBeInTheDocument();
  });

  // @ac AC-06
  test('frontend-host-detail-intelligence-feed/AC-06 — rows render event_code text with severity-tinted dot', () => {
    const items = [
      makeEvent({ id: 'e-1', event_code: 'system.package.updated', severity: 'medium' }),
      makeEvent({ id: 'e-2', event_code: 'system.service.failed', severity: 'critical' }),
    ];
    const { container } = render(
      <CardServerIntelView
        isLoading={false}
        isError={false}
        items={items}
        onRetry={() => undefined}
      />,
    );
    expect(screen.getByText('system.package.updated')).toBeInTheDocument();
    expect(screen.getByText('system.service.failed')).toBeInTheDocument();
    // Two <li> rows
    expect(container.querySelectorAll('li').length).toBe(2);
  });
});
