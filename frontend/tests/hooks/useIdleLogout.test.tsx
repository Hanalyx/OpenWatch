// @spec frontend-session-idle
//
// AC traceability (this file):
//
//   AC-01  test('frontend-session-idle/AC-01 — idle past the window logs out (revoke + redirect)')
//   AC-02  test('frontend-session-idle/AC-02 — user input before the window resets the clock')
//   AC-03  test('frontend-session-idle/AC-03 — honors the configured window; falls back to 15m default')
//   AC-04  test('frontend-session-idle/AC-04 — a fresher cross-tab timestamp prevents logout')
//   AC-05  test('frontend-session-idle/AC-05 — AppFrame mounts the hook; listeners are user-input only')

import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ReactNode } from 'react';

import { api, onAuthFailure } from '@/api/client';
import { ACTIVITY_STORAGE_KEY, useIdleLogout } from '@/hooks/useIdleLogout';
import { useAuthStore } from '@/store/useAuthStore';

vi.mock('@/api/client', () => ({
  api: { GET: vi.fn(), POST: vi.fn() },
  onAuthFailure: vi.fn(),
}));

const mockedGet = vi.mocked(api.GET);
const mockedPost = vi.mocked(api.POST);
const mockedAuthFailure = vi.mocked(onAuthFailure);

const T0 = new Date('2026-01-01T00:00:00Z').getTime();

// Policy GET result helpers (the openapi-fetch result shape).
function policyOk(idleSeconds: number) {
  return {
    data: {
      require_mfa: false,
      session_idle_timeout_seconds: idleSeconds,
      session_absolute_timeout_seconds: 43200,
      updated_at: '2026-01-01T00:00:00Z',
    },
    error: undefined,
    response: { ok: true } as Response,
  };
}
function policyFail() {
  return { data: undefined, error: { code: 'x' }, response: { ok: false } as Response };
}

function wrapper({ children }: { children: ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

// Render the hook and let the auth-policy query settle so idleMsRef is primed.
async function mount() {
  const view = renderHook(() => useIdleLogout(), { wrapper });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0);
  });
  return view;
}

async function advance(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

describe('frontend-session-idle — client idle logout', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
    mockedGet.mockReset();
    mockedPost.mockReset();
    mockedAuthFailure.mockReset();
    mockedPost.mockResolvedValue({ data: {}, error: undefined, response: { ok: true } } as never);
    try {
      localStorage.clear();
    } catch {
      /* ignore */
    }
    useAuthStore.getState().setIdentity({
      id: 'u1',
      username: 'alice',
      email: 'alice@example.com',
      role: 'admin',
      permissions: [],
      mfaEnabled: false,
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    useAuthStore.getState().clear();
  });

  // @ac AC-01
  test('frontend-session-idle/AC-01 — idle past the window logs out (revoke + redirect)', async () => {
    mockedGet.mockResolvedValue(policyOk(60) as never);
    await mount();

    // No activity for 65s (> 60s window) → revoke + redirect.
    await advance(65_000);

    expect(mockedPost).toHaveBeenCalledWith('/api/v1/auth/logout');
    expect(mockedAuthFailure).toHaveBeenCalledTimes(1);
  });

  // @ac AC-02
  test('frontend-session-idle/AC-02 — user input before the window resets the clock', async () => {
    mockedGet.mockResolvedValue(policyOk(60) as never);
    await mount();

    // Sit idle for 50s, then the user presses a key (resets the clock).
    await advance(50_000);
    act(() => {
      window.dispatchEvent(new Event('keydown'));
    });
    // 50s more: 50s since the keypress (< 60s) → still NOT logged out.
    await advance(50_000);

    expect(mockedAuthFailure).not.toHaveBeenCalled();
    expect(mockedPost).not.toHaveBeenCalled();
  });

  // @ac AC-03
  test('frontend-session-idle/AC-03 — honors the configured window; falls back to 15m default', async () => {
    // Configured short window: fires at the configured value, not before.
    mockedGet.mockResolvedValue(policyOk(120) as never);
    await mount();
    await advance(100_000); // < 120s
    expect(mockedAuthFailure).not.toHaveBeenCalled();
    await advance(30_000); // now > 120s
    expect(mockedAuthFailure).toHaveBeenCalledTimes(1);
  });

  // @ac AC-03
  test('frontend-session-idle/AC-03b — policy unavailable falls back to the 15-minute default', async () => {
    mockedGet.mockResolvedValue(policyFail() as never);
    await mount();
    // 5 minutes idle is well past a short window but under the 15-min default →
    // must NOT log out (proves the safe default, not a 0/immediate timeout).
    await advance(5 * 60_000);
    expect(mockedAuthFailure).not.toHaveBeenCalled();
  });

  // @ac AC-04
  test('frontend-session-idle/AC-04 — a fresher cross-tab timestamp prevents logout', async () => {
    mockedGet.mockResolvedValue(policyOk(60) as never);
    await mount();

    // This tab sees no local input, but another tab records activity by writing
    // the shared key. Keep it fresh across the window.
    for (let i = 0; i < 6; i++) {
      localStorage.setItem(ACTIVITY_STORAGE_KEY, String(Date.now()));
      await advance(20_000); // 20s < 60s window each step
    }

    expect(mockedAuthFailure).not.toHaveBeenCalled();
    expect(mockedPost).not.toHaveBeenCalled();
  });

  // @ac AC-05
  test('frontend-session-idle/AC-05 — AppFrame mounts the hook; listeners are user-input only', () => {
    const appFrame = readFileSync(resolve(__dirname, '../../src/components/shell/AppFrame.tsx'), 'utf8');
    expect(appFrame).toContain('useIdleLogout');

    const hook = readFileSync(resolve(__dirname, '../../src/hooks/useIdleLogout.ts'), 'utf8');
    for (const ev of ['mousemove', 'mousedown', 'keydown', 'wheel', 'scroll', 'touchstart']) {
      expect(hook).toContain(`'${ev}'`);
    }
    // Tab focus / visibility and background HTTP must NOT count as activity.
    expect(hook).not.toContain('visibilitychange');
  });
});
