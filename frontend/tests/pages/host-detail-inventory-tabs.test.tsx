// @spec frontend-host-detail-inventory-tabs
//
// AC traceability (this file):
//
//   AC-01  test('frontend-host-detail-inventory-tabs/AC-01 — four tab components exported, none uses useQuery')
//   AC-02  test('frontend-host-detail-inventory-tabs/AC-02 — PackagesTab renders rows + counts packages')
//   AC-03  test('frontend-host-detail-inventory-tabs/AC-03 — ServicesTab renders rows + active/total badge')
//   AC-04  test('frontend-host-detail-inventory-tabs/AC-04 — UsersTab total badge + human/system split')
//   AC-10  test('frontend-host-detail-inventory-tabs/AC-10 — password-aging line + KPI tiles')
//   AC-05  test('frontend-host-detail-inventory-tabs/AC-05 — NetworkTab renders rows + total badge')
//   AC-06  test('frontend-host-detail-inventory-tabs/AC-06 — loading state hides rows and empty state')
//   AC-07  test('frontend-host-detail-inventory-tabs/AC-07 — null/empty snapshot renders empty state naming the source')
//   AC-08  test('frontend-host-detail-inventory-tabs/AC-08 — search input filters rows case-insensitively')
//   AC-09  test('frontend-host-detail-inventory-tabs/AC-09 — HostDetailPage mounts the four tab components and removes the legacy stubs')

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen } from '@testing-library/react';
import {
  PackagesTab,
  ServicesTab,
  UsersTab,
  NetworkTab,
  packagesCount,
  servicesCount,
  usersCount,
  networkCount,
  composeFirewallSub,
} from '@/pages/host-detail/InventoryTabs';

const INV_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/host-detail/InventoryTabs.tsx'),
  'utf8',
);

const PAGE_SRC = readFileSync(resolve(process.cwd(), 'src/pages/HostDetailPage.tsx'), 'utf8');

describe('frontend-host-detail-inventory-tabs — structural', () => {
  // @ac AC-01
  test('frontend-host-detail-inventory-tabs/AC-01 — four tab components exported, none uses useQuery', () => {
    for (const name of ['PackagesTab', 'ServicesTab', 'UsersTab', 'NetworkTab']) {
      expect(INV_SRC).toMatch(new RegExp(`export function ${name}\\(`));
    }
    // No useQuery anywhere — parent fetches once. Spec C-01.
    expect(INV_SRC).not.toMatch(/useQuery\(/);
  });

  // @ac AC-09
  test('frontend-host-detail-inventory-tabs/AC-09 — HostDetailPage mounts the four tab components and removes the legacy stubs', () => {
    expect(PAGE_SRC).toMatch(
      /import\s*\{[^}]*PackagesTab[^}]*ServicesTab[^}]*UsersTab[^}]*NetworkTab[^}]*\}\s*from\s*['"]@\/pages\/host-detail\/InventoryTabs['"]/,
    );
    // Each of the four tabs is mounted via the activeTab switch (no
    // TabStub for these four).
    for (const tag of ['<PackagesTab', '<ServicesTab', '<UsersTab', '<NetworkTab']) {
      expect(PAGE_SRC).toContain(tag);
    }
  });
});

describe('frontend-host-detail-inventory-tabs — behavioral', () => {
  // @ac AC-02
  test('frontend-host-detail-inventory-tabs/AC-02 — PackagesTab renders rows + counts packages', () => {
    const snap = { packages: { bash: '5.1', vim: '8.2' } };
    expect(packagesCount(snap)).toBe(2);
    render(<PackagesTab isLoading={false} snapshot={snap} />);
    expect(screen.getByText('bash')).toBeInTheDocument();
    expect(screen.getByText('vim')).toBeInTheDocument();
  });

  // @ac AC-03
  test('frontend-host-detail-inventory-tabs/AC-03 — ServicesTab renders rows + active/total badge', () => {
    const snap = {
      services: { sshd: 'active', ntpd: 'inactive', sssd: 'failed' },
    };
    expect(servicesCount(snap)).toEqual({ active: 1, total: 3 });
    render(<ServicesTab isLoading={false} snapshot={snap} />);
    expect(screen.getByText('sshd')).toBeInTheDocument();
    expect(screen.getByText('sssd')).toBeInTheDocument();
    expect(screen.getByText('ntpd')).toBeInTheDocument();
  });

  // @ac AC-04
  test('frontend-host-detail-inventory-tabs/AC-04 — UsersTab total badge + human/system split', () => {
    const snap = {
      users: {
        root: { uid: 0, locked: false }, // system → collapsed
        alice: { uid: 1000, locked: false }, // human → card
      },
    };
    // Badge counts every account (unchanged contract).
    expect(usersCount(snap)).toBe(2);
    render(<UsersTab isLoading={false} snapshot={snap} />);
    // The human account renders as a visible card.
    expect(screen.getByText('alice')).toBeInTheDocument();
    // The system account is collapsed behind "Show all", not rendered yet.
    expect(screen.queryByText('root')).not.toBeInTheDocument();
    // Expanding the system-accounts section reveals it.
    fireEvent.click(screen.getByText(/service accounts/));
    expect(screen.getByText('root')).toBeInTheDocument();
  });

  // @ac AC-10
  test('frontend-host-detail-inventory-tabs/AC-10 — password-aging line + KPI tiles', () => {
    const day = 86_400_000;
    const nowDays = Math.floor(Date.now() / day);
    const snap = {
      users: {
        // active 90-day policy, changed ~85 days ago → expires in ~5 days (warn)
        expiring: {
          uid: 1000,
          locked: false,
          gecos: 'Ex Piring',
          shell: '/bin/bash',
          last_change_days: nowDays - 85,
          max_days: 90,
          password_expires_at: new Date((nowDays - 85 + 90) * day).toISOString(),
        },
        // no policy (99999) → "N days old · no expiry policy" (stale)
        owadmin: {
          uid: 1001,
          locked: false,
          last_change_days: nowDays - 234,
          max_days: 99999,
        },
        sysd: { uid: 2, locked: true }, // system → collapsed, not a KPI human
      },
      groups: { sudo: ['owadmin'] },
    };
    render(<UsersTab isLoading={false} snapshot={snap} />);
    // KPI tiles: 2 human accounts, 1 sudo, 1 stale (no-policy owadmin).
    expect(screen.getByText('User accounts')).toBeInTheDocument();
    expect(screen.getByText('Sudo privileges')).toBeInTheDocument();
    expect(screen.getByText('Stale passwords')).toBeInTheDocument();
    // Policy account shows time-to-expiry; no-policy shows age + no-policy
    // (the "days old ·" prefix is unique to the card line, vs the tile sub).
    expect(screen.getByText(/expires in \d+ days/i)).toBeInTheDocument();
    expect(screen.getByText(/days old · no expiry policy/i)).toBeInTheDocument();
    // owadmin carries the SUDO badge.
    expect(screen.getByText('SUDO')).toBeInTheDocument();
  });

  // @ac AC-05
  test('frontend-host-detail-inventory-tabs/AC-05 — NetworkTab renders rows + total badge', () => {
    const snap = {
      listening_ports: [
        { protocol: 'tcp', address: '0.0.0.0', port: 22 },
        { protocol: 'tcp', address: '0.0.0.0', port: 80 },
      ],
    };
    expect(networkCount(snap)).toBe(2);
    render(<NetworkTab isLoading={false} snapshot={snap} />);
    expect(screen.getByText('0.0.0.0:22')).toBeInTheDocument();
    expect(screen.getByText('0.0.0.0:80')).toBeInTheDocument();
  });

  test('composeFirewallSub — combines service + active state + rule count', () => {
    expect(composeFirewallSub('firewalld', true, 0)).toBe('firewalld · 0 rules loaded');
    expect(composeFirewallSub('firewalld', true, 12)).toBe('firewalld · 12 rules loaded');
    expect(composeFirewallSub('ufw', false, 0)).toBe('ufw disabled · 0 rules loaded');
    expect(composeFirewallSub('ufw', true, 1)).toBe('ufw · 1 rule loaded');
    // older snapshot — rule count undefined
    expect(composeFirewallSub('ufw', false, undefined)).toBe('ufw disabled');
    // engine probe failed (-1) — fall back to just the engine label
    expect(composeFirewallSub('nftables', true, -1)).toBe('nftables');
    // no service detected — count irrelevant
    expect(composeFirewallSub(null, false, 0)).toBe('No firewall service detected');
    expect(composeFirewallSub(null, false, undefined)).toBe('No firewall service detected');
  });

  // @ac AC-06
  test('frontend-host-detail-inventory-tabs/AC-06 — loading state hides rows and empty state', () => {
    render(<PackagesTab isLoading={true} snapshot={{ packages: { bash: '5.1' } }} />);
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
    // Rows MUST not appear during loading
    expect(screen.queryByText('bash')).toBeNull();
    // Empty-state primary copy MUST not appear during loading
    expect(screen.queryByText(/No packages collected yet/i)).toBeNull();
  });

  // @ac AC-07
  test('frontend-host-detail-inventory-tabs/AC-07 — null/empty snapshot renders empty state naming the source', () => {
    render(<PackagesTab isLoading={false} snapshot={null} />);
    expect(screen.getByText(/No packages collected yet/i)).toBeInTheDocument();
    expect(screen.getByText(/OS Intelligence collector/i)).toBeInTheDocument();

    // Same for an empty key.
    render(<ServicesTab isLoading={false} snapshot={{ services: {} }} />);
    expect(screen.getByText(/No services collected yet/i)).toBeInTheDocument();
  });

  // @ac AC-08
  test('frontend-host-detail-inventory-tabs/AC-08 — search input filters rows case-insensitively', () => {
    const snap = {
      packages: { bash: '5.1', vim: '8.2', emacs: '27.1' },
    };
    render(<PackagesTab isLoading={false} snapshot={snap} />);
    expect(screen.getByText('bash')).toBeInTheDocument();
    expect(screen.getByText('vim')).toBeInTheDocument();
    expect(screen.getByText('emacs')).toBeInTheDocument();

    const search = screen.getByRole('searchbox');
    fireEvent.change(search, { target: { value: 'BA' } });
    expect(screen.getByText('bash')).toBeInTheDocument();
    expect(screen.queryByText('vim')).toBeNull();
    expect(screen.queryByText('emacs')).toBeNull();
  });
});
