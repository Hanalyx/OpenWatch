// @spec frontend-host-detail-intelligence-feed
//
// AC traceability (this file):
//
//   AC-01  test('frontend-host-detail-intelligence-feed/AC-01 — calls /intelligence/state/{host_id}; no /intelligence/events')
//   AC-02  test('frontend-host-detail-intelligence-feed/AC-02 — query key + useLiveEvents dual invalidation')
//   AC-03  test('frontend-host-detail-intelligence-feed/AC-03 — loading state')
//   AC-04  test('frontend-host-detail-intelligence-feed/AC-04 — generic error renders Retry')
//   AC-05  test('frontend-host-detail-intelligence-feed/AC-05 — 404 renders "Not collected yet" with no Retry')
//   AC-06  test('frontend-host-detail-intelligence-feed/AC-06 — snapshot renders six tiles with rollup values')
//   AC-07  test('frontend-host-detail-intelligence-feed/AC-07 — firewall_rule_count branches')
//   AC-08  test('frontend-host-detail-intelligence-feed/AC-08 — sudo count is union of sudo/wheel/admin, intersected with users')

import { describe, expect, test, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen } from '@testing-library/react';
import {
  CardServerIntelView,
  countSudoUsers,
  firewallSubline,
  type IntelligenceSnapshot,
} from '@/pages/host-detail/CardServerIntel';

const CARD_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/host-detail/CardServerIntel.tsx'),
  'utf8',
);

const LIVE_EVENTS_SRC = readFileSync(resolve(process.cwd(), 'src/hooks/useLiveEvents.ts'), 'utf8');

describe('frontend-host-detail-intelligence-feed — structural', () => {
  // @ac AC-01
  test('frontend-host-detail-intelligence-feed/AC-01 — calls /intelligence/state/{host_id}; no /intelligence/events', () => {
    expect(CARD_SRC).toContain("'/api/v1/intelligence/state/{host_id}'");
    expect(CARD_SRC).toMatch(/host_id:\s*hostId/);
    // v1.0.0 binding is gone.
    expect(CARD_SRC).not.toContain('/api/v1/intelligence/events');
    // The queryFn MUST unwrap the snapshot map so the cached value
    // matches HostDetailPage's intelligenceStateQuery shape — they
    // share queryKey ['intelligence_state', hostId] and a divergent
    // shape would leave one consumer reading undefined fields.
    expect(CARD_SRC).toMatch(/raw\?\.snapshot/);
  });

  // @ac AC-02
  test('frontend-host-detail-intelligence-feed/AC-02 — query key + useLiveEvents dual invalidation', () => {
    // Card's query key is the new snapshot key.
    expect(CARD_SRC).toMatch(/queryKey:\s*\[\s*['"]intelligence_state['"]\s*,\s*hostId\s*\]/);
    // useLiveEvents invalidates BOTH keys (event feed + snapshot tile grid).
    expect(LIVE_EVENTS_SRC).toMatch(
      /queryKey:\s*\[\s*['"]host_intelligence_events['"]\s*,\s*hostId\s*\]/,
    );
    expect(LIVE_EVENTS_SRC).toMatch(
      /queryKey:\s*\[\s*['"]intelligence_state['"]\s*,\s*hostId\s*\]/,
    );
  });
});

describe('frontend-host-detail-intelligence-feed — behavior', () => {
  // @ac AC-03
  test('frontend-host-detail-intelligence-feed/AC-03 — loading state', () => {
    render(
      <CardServerIntelView
        isLoading={true}
        isError={false}
        notFound={false}
        onRetry={() => undefined}
      />,
    );
    expect(screen.getByText(/loading…/i)).toBeInTheDocument();
    expect(screen.queryByText(/not collected yet/i)).toBeNull();
  });

  // @ac AC-04
  test('frontend-host-detail-intelligence-feed/AC-04 — generic error renders Retry', () => {
    const onRetry = vi.fn();
    render(
      <CardServerIntelView isLoading={false} isError={true} notFound={false} onRetry={onRetry} />,
    );
    expect(screen.getByRole('alert')).toBeInTheDocument();
    const btn = screen.getByRole('button', { name: /retry/i });
    fireEvent.click(btn);
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  // @ac AC-05
  test('frontend-host-detail-intelligence-feed/AC-05 — 404 renders "Not collected yet" with no Retry', () => {
    render(
      <CardServerIntelView
        isLoading={false}
        isError={false}
        notFound={true}
        onRetry={() => undefined}
      />,
    );
    expect(screen.getByText(/not collected yet/i)).toBeInTheDocument();
    expect(screen.getByText(/OS Intelligence collector/i)).toBeInTheDocument();
    // 404 must NOT show Retry — operators shouldn't poke a pre-Discovery host.
    expect(screen.queryByRole('button', { name: /retry/i })).toBeNull();
  });

  // @ac AC-06
  test('frontend-host-detail-intelligence-feed/AC-06 — snapshot renders six tiles with rollup values', () => {
    const snapshot: IntelligenceSnapshot = {
      packages: { a: '1', b: '2', c: '3' },
      services: { s1: 'active', s2: 'inactive' },
      users: { alice: {}, bob: {} },
      groups: { sudo: ['alice'] },
      network_interfaces: [{}, {}],
      listening_ports: [{}, {}, {}],
      firewall_rule_count: null,
    };
    render(
      <CardServerIntelView
        isLoading={false}
        isError={false}
        notFound={false}
        snapshot={snapshot}
        onRetry={() => undefined}
      />,
    );

    // Six tile labels present.
    expect(screen.getByText('Packages installed')).toBeInTheDocument();
    expect(screen.getByText('Running services')).toBeInTheDocument();
    expect(screen.getByText('User accounts')).toBeInTheDocument();
    expect(screen.getByText('Network interfaces')).toBeInTheDocument();
    expect(screen.getByText('Firewall rules')).toBeInTheDocument();
    expect(screen.getByText('Open exceptions')).toBeInTheDocument();

    // Values + sublines.
    expect(screen.getByText('3')).toBeInTheDocument(); // packages
    expect(screen.getByText(/50% of registered services/)).toBeInTheDocument();
    expect(screen.getByText('1 with sudo privileges')).toBeInTheDocument();
    expect(screen.getByText('3 listening ports')).toBeInTheDocument();
    // null firewall → "Not collected"
    expect(screen.getByText('Not collected')).toBeInTheDocument();
    // Open exceptions placeholder subline
    expect(screen.getByText('No rules suppressed')).toBeInTheDocument();
  });

  // @ac AC-07
  test('frontend-host-detail-intelligence-feed/AC-07 — firewall_rule_count branches', () => {
    // null
    expect(firewallSubline(null)).toMatchObject({
      value: '—',
      subline: 'Not collected',
      tone: 'neutral',
    });
    // -1 (no engine)
    expect(firewallSubline(-1)).toMatchObject({
      value: '—',
      subline: 'No firewall detected',
      tone: 'neutral',
    });
    // 0 (engine present, inactive)
    expect(firewallSubline(0)).toMatchObject({
      value: 0,
      subline: 'Firewall is inactive',
      tone: 'warn',
    });
    // N > 0
    const result = firewallSubline(7);
    expect(result.value).toBe(7);
    expect(result.subline).toMatch(/active/i);
    expect(result.tone).toBe('neutral');
  });

  // @ac AC-08
  test('frontend-host-detail-intelligence-feed/AC-08 — sudo count is union of sudo/wheel/admin, intersected with users', () => {
    const users = { alice: {}, bob: {}, carol: {}, dave: {} };
    const groups = {
      sudo: ['alice', 'bob'],
      wheel: ['bob'], // duplicate of bob — dedupes to 1
      admin: ['carol'],
      // dave is in NO sudo-shaped group → excluded
      other: ['dave'],
    };
    expect(countSudoUsers(users, groups)).toBe(3); // alice, bob, carol

    // A group member that's no longer in users.* is dropped.
    const usersAfterRemoval = { alice: {}, carol: {} };
    expect(countSudoUsers(usersAfterRemoval, groups)).toBe(2); // alice, carol

    // Defensive: missing inputs → 0.
    expect(countSudoUsers(undefined, groups)).toBe(0);
    expect(countSudoUsers(users, undefined)).toBe(0);
  });
});
