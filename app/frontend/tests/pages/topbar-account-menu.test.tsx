// @spec frontend-shell-account-menu
//
// AC traceability (this file):
//
//   AC-01  test('frontend-shell-account-menu/AC-01 — avatar is a <button> with aria-haspopup, not a <div>')
//   AC-02  test('frontend-shell-account-menu/AC-02 — clicking the avatar opens the menu and flips aria-expanded')
//   AC-03  test('frontend-shell-account-menu/AC-03 — open menu shows a Sign out menuitem')
//   AC-04  test('frontend-shell-account-menu/AC-04 — clicking Sign out calls /auth/logout, clears identity, and navigates to /login')
//   AC-05  test('frontend-shell-account-menu/AC-05 — Escape closes the menu')
//   AC-06  test('frontend-shell-account-menu/AC-06 — click outside the menu closes it')
//   AC-07  test('frontend-shell-account-menu/AC-07 — without identity the avatar button does not render')

import { describe, expect, test, vi, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen } from '@testing-library/react';
import { TopBar } from '@/components/shell/TopBar';
import { useAuthStore } from '@/store/useAuthStore';

const TOPBAR_SRC = readFileSync(
  resolve(process.cwd(), 'src/components/shell/TopBar.tsx'),
  'utf8',
);

// Mock @tanstack/react-router so TopBar can call useNavigate without a router.
const navigateMock = vi.fn();
vi.mock('@tanstack/react-router', async () => {
  const actual = await vi.importActual<object>('@tanstack/react-router');
  return {
    ...actual,
    useNavigate: () => navigateMock,
    Link: ({ to, children, ...rest }: { to?: string; children: React.ReactNode } & Record<string, unknown>) =>
      ({
        type: 'a',
        props: { href: to, ...rest, children },
        key: null,
        ref: null,
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } as any),
  };
});

// Mock openapi-fetch client so we can capture the logout POST.
const logoutPostSpy = vi.fn(async (..._args: unknown[]) => ({
  response: { ok: true, status: 204 },
}));
vi.mock('@/api/client', () => ({
  default: { POST: (...args: unknown[]) => logoutPostSpy(...args) },
}));

function signIn() {
  useAuthStore.setState({
    identity: {
      id: 'u-1',
      username: 'fixture',
      email: 'fixture@local',
      role: 'admin',
      permissions: ['host:read'],
      mfaEnabled: false,
    },
    loading: false,
  });
}

beforeEach(() => {
  useAuthStore.getState().clear();
  navigateMock.mockReset();
  logoutPostSpy.mockClear();
});

describe('frontend-shell-account-menu — structural', () => {
  // @ac AC-01
  test('frontend-shell-account-menu/AC-01 — avatar is a <button> with aria-haspopup, not a <div>', () => {
    // The buggy original rendered a plain <div aria-label="Account: …">
    // for the account chip. The new code MUST be a button with the
    // menu-pattern ARIA hooks.
    expect(TOPBAR_SRC).toMatch(/<button[^>]*aria-haspopup\s*=\s*['"]menu['"]/);
    expect(TOPBAR_SRC).toMatch(/aria-expanded\s*=\s*\{[^}]*open/);
    // The legacy "<div aria-label={`Account: ..." pattern MUST be gone.
    expect(TOPBAR_SRC).not.toMatch(/<div[^>]*aria-label=\{\s*`Account:/);
  });
});

describe('frontend-shell-account-menu — behavioral', () => {
  // @ac AC-02
  test('frontend-shell-account-menu/AC-02 — clicking the avatar opens the menu and flips aria-expanded', () => {
    signIn();
    render(<TopBar />);
    const btn = screen.getByRole('button', { name: /account/i });
    expect(btn).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByRole('menu')).toBeNull();
    fireEvent.click(btn);
    expect(btn).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByRole('menu')).toBeInTheDocument();
  });

  // @ac AC-03
  test('frontend-shell-account-menu/AC-03 — open menu shows a Sign out menuitem', () => {
    signIn();
    render(<TopBar />);
    fireEvent.click(screen.getByRole('button', { name: /account/i }));
    const signOut = screen.getByRole('menuitem', { name: /sign out/i });
    expect(signOut).toBeInTheDocument();
  });

  // @ac AC-04
  test('frontend-shell-account-menu/AC-04 — clicking Sign out calls /auth/logout, clears identity, and navigates to /login', async () => {
    signIn();
    render(<TopBar />);
    fireEvent.click(screen.getByRole('button', { name: /account/i }));
    const signOut = screen.getByRole('menuitem', { name: /sign out/i });
    fireEvent.click(signOut);
    // The mutation runs asynchronously; flush microtasks.
    await Promise.resolve();
    await Promise.resolve();
    expect(logoutPostSpy).toHaveBeenCalledTimes(1);
    const firstCall = logoutPostSpy.mock.calls[0] ?? [];
    expect(firstCall[0]).toBe('/api/v1/auth/logout');
    expect(useAuthStore.getState().identity).toBeNull();
    expect(navigateMock).toHaveBeenCalledWith(expect.objectContaining({ to: '/login' }));
  });

  // @ac AC-05
  test('frontend-shell-account-menu/AC-05 — Escape closes the menu', () => {
    signIn();
    render(<TopBar />);
    fireEvent.click(screen.getByRole('button', { name: /account/i }));
    expect(screen.getByRole('menu')).toBeInTheDocument();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('menu')).toBeNull();
  });

  // @ac AC-06
  test('frontend-shell-account-menu/AC-06 — click outside the menu closes it', () => {
    signIn();
    render(<TopBar />);
    fireEvent.click(screen.getByRole('button', { name: /account/i }));
    expect(screen.getByRole('menu')).toBeInTheDocument();
    // Mousedown outside the menu container (the body itself).
    fireEvent.mouseDown(document.body);
    expect(screen.queryByRole('menu')).toBeNull();
  });

  // @ac AC-07
  test('frontend-shell-account-menu/AC-07 — without identity the avatar button does not render', () => {
    // useAuthStore identity is null by default after beforeEach.clear().
    render(<TopBar />);
    expect(screen.queryByRole('button', { name: /account/i })).toBeNull();
  });
});
