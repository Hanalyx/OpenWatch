// @spec frontend-shell-account-menu
// @ac AC-05

import { describe, expect, test, beforeEach, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import { signIn, clearAuth, renderTopBar } from './shell-account-menu-helpers';

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
  test('frontend-shell-account-menu/AC-05 — Escape closes the menu', () => {
    signIn();
    renderTopBar();
    fireEvent.click(screen.getByRole('button', { name: /account/i }));
    expect(screen.getByRole('menu')).toBeInTheDocument();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('menu')).toBeNull();
  });
});
