// @spec frontend-shell-account-menu
// @ac AC-03

import { describe, expect, test, beforeEach, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { signIn, clearAuth } from './shell-account-menu-helpers';

const navigateMock = vi.fn();
vi.mock('@tanstack/react-router', async () => {
  const actual = await vi.importActual<object>('@tanstack/react-router');
  return {
    ...actual,
    useNavigate: () => navigateMock,
    Link: ({ to, children, ...rest }: { to?: string; children: React.ReactNode } & Record<string, unknown>) =>
      ({ type: 'a', props: { href: to, ...rest, children }, key: null, ref: null } as any),
  };
});
vi.mock('@/api/client', () => ({
  default: { POST: vi.fn(async () => ({ response: { ok: true, status: 204 } })) },
}));

import { TopBar } from '@/components/shell/TopBar';

beforeEach(() => {
  clearAuth();
  navigateMock.mockReset();
});

describe('frontend-shell-account-menu — behavioral', () => {
  test('frontend-shell-account-menu/AC-03 — open menu shows a Sign out menuitem', () => {
    signIn();
    render(<TopBar />);
    fireEvent.click(screen.getByRole('button', { name: /account/i }));
    const signOut = screen.getByRole('menuitem', { name: /sign out/i });
    expect(signOut).toBeInTheDocument();
  });
});
