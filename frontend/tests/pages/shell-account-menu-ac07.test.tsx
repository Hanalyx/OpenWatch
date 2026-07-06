// @spec frontend-shell-account-menu
// @ac AC-07

import { describe, expect, test, beforeEach, vi } from 'vitest';
import { screen } from '@testing-library/react';
import { clearAuth, renderTopBar } from './shell-account-menu-helpers';

const navigateMock = vi.fn();
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
  default: { POST: vi.fn(async () => ({ response: { ok: true, status: 204 } })) },
}));

beforeEach(() => {
  clearAuth();
  navigateMock.mockReset();
});

describe('frontend-shell-account-menu — behavioral', () => {
  test('frontend-shell-account-menu/AC-07 — without identity the avatar button does not render', () => {
    // useAuthStore identity is null by default after clearAuth.
    renderTopBar();
    expect(screen.queryByRole('button', { name: /account/i })).toBeNull();
  });
});
