// @spec frontend-shell-account-menu
// @ac AC-04

import { describe, expect, test, beforeEach, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import { useAuthStore } from '@/store/useAuthStore';
import { signIn, clearAuth, renderTopBar } from './shell-account-menu-helpers';

const navigateMock = vi.fn();
const logoutPostSpy = vi.fn(async (..._args: unknown[]) => ({
  response: { ok: true, status: 204 },
}));
vi.mock('@tanstack/react-router', async () => {
  const actual = await vi.importActual<object>('@tanstack/react-router');
  return {
    ...actual,
    useNavigate: () => navigateMock,
    Link: ({
      to,
      children,
      ...rest
    }: { to?: string; children: React.ReactNode } & Record<string, unknown>) =>
      ({ type: 'a', props: { href: to, ...rest, children }, key: null, ref: null }) as any,
  };
});
vi.mock('@/api/client', () => ({
  default: { POST: (...args: unknown[]) => logoutPostSpy(...args) },
}));

beforeEach(() => {
  clearAuth();
  navigateMock.mockReset();
  logoutPostSpy.mockClear();
});

describe('frontend-shell-account-menu — behavioral', () => {
  test('frontend-shell-account-menu/AC-04 — clicking Sign out calls /auth/logout, clears identity, and navigates to /login', async () => {
    signIn();
    renderTopBar();
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
});
