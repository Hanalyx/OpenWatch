// Spec: specs/frontend/auth-flow.spec.yaml
/**
 * Spec-enforcement tests for frontend auth flow state machine.
 *
 * Verifies login, MFA detection, logout, session expiry, route guards,
 * and service access patterns via source inspection and store behavior.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { act } from 'react';
import * as fs from 'fs';
import * as path from 'path';

// Mock storage to prevent localStorage side-effects
vi.mock('../../../frontend/src/services/storage', () => ({
  storageGet: vi.fn(() => null),
  storageSet: vi.fn(),
  storageRemove: vi.fn(),
  storageGetJSON: vi.fn(() => null),
  storageSetJSON: vi.fn(),
  storageClearAuth: vi.fn(),
  StorageKeys: {
    AUTH_TOKEN: 'auth_token',
    REFRESH_TOKEN: 'refresh_token',
    AUTH_USER: 'auth_user',
    SESSION_EXPIRY: 'session_expiry',
    THEME_MODE: 'themeMode',
    COMPLIANCE_RULES_VIEW_MODE: 'complianceRulesViewMode',
    SESSION_INACTIVITY_TIMEOUT: 'session_inactivity_timeout_minutes',
  },
}));

import { storageSet, storageClearAuth } from '../../../frontend/src/services/storage';
import { useAuthStore } from '../../../frontend/src/store/useAuthStore';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SRC = path.resolve(__dirname, '../../../frontend/src');

function readSource(relativePath: string): string {
  return fs.readFileSync(path.join(SRC, relativePath), 'utf8');
}

const testUser = {
  id: 'u1',
  username: 'alice',
  email: 'alice@example.com',
  role: 'admin',
  mfaEnabled: false,
};

const loginPayload = {
  user: testUser,
  token: 'tok-abc',
  refreshToken: 'ref-xyz',
  expiresIn: 3600,
};

function resetAuthStore(partial: Partial<ReturnType<typeof useAuthStore.getState>> = {}) {
  act(() => {
    useAuthStore.setState({
      user: null,
      token: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
      mfaRequired: false,
      sessionExpiry: null,
      ...partial,
    });
  });
}

// ---------------------------------------------------------------------------
// AC-1: loginSuccess sets isAuthenticated, user, token, sessionExpiry
// ---------------------------------------------------------------------------

describe('AC-1: loginSuccess transitions to authenticated state', () => {
  /**
   * AC-1: loginSuccess MUST set isAuthenticated=true, store user, token,
   * refreshToken, and calculate sessionExpiry as Date.now() + expiresIn * 1000.
   */
  beforeEach(() => {
    vi.clearAllMocks();
    resetAuthStore();
  });

  it('sets isAuthenticated to true', () => {
    act(() => useAuthStore.getState().loginSuccess(loginPayload));
    expect(useAuthStore.getState().isAuthenticated).toBe(true);
  });

  it('stores the user object', () => {
    act(() => useAuthStore.getState().loginSuccess(loginPayload));
    expect(useAuthStore.getState().user).toEqual(testUser);
  });

  it('stores the token', () => {
    act(() => useAuthStore.getState().loginSuccess(loginPayload));
    expect(useAuthStore.getState().token).toBe('tok-abc');
  });

  it('stores the refreshToken', () => {
    act(() => useAuthStore.getState().loginSuccess(loginPayload));
    expect(useAuthStore.getState().refreshToken).toBe('ref-xyz');
  });

  it('calculates sessionExpiry from expiresIn', () => {
    const before = Date.now();
    act(() => useAuthStore.getState().loginSuccess(loginPayload));
    const after = Date.now();
    const { sessionExpiry } = useAuthStore.getState();
    expect(sessionExpiry).toBeGreaterThanOrEqual(before + 3600 * 1000);
    expect(sessionExpiry).toBeLessThanOrEqual(after + 3600 * 1000);
  });
});

// ---------------------------------------------------------------------------
// AC-2: loginSuccess persists 4 keys to localStorage
// ---------------------------------------------------------------------------

describe('AC-2: loginSuccess persists auth data to localStorage', () => {
  /**
   * AC-2: loginSuccess MUST persist auth_token, refresh_token,
   * auth_user (JSON), and session_expiry to localStorage.
   */
  beforeEach(() => {
    vi.clearAllMocks();
    resetAuthStore();
  });

  it('persists token to auth_token', () => {
    act(() => useAuthStore.getState().loginSuccess(loginPayload));
    expect(storageSet).toHaveBeenCalledWith('auth_token', 'tok-abc');
  });

  it('persists refreshToken to refresh_token', () => {
    act(() => useAuthStore.getState().loginSuccess(loginPayload));
    expect(storageSet).toHaveBeenCalledWith('refresh_token', 'ref-xyz');
  });

  it('persists user as JSON to auth_user', () => {
    act(() => useAuthStore.getState().loginSuccess(loginPayload));
    expect(storageSet).toHaveBeenCalledWith('auth_user', JSON.stringify(testUser));
  });

  it('persists sessionExpiry to session_expiry', () => {
    act(() => useAuthStore.getState().loginSuccess(loginPayload));
    expect(storageSet).toHaveBeenCalledWith('session_expiry', expect.any(String));
  });
});

// ---------------------------------------------------------------------------
// AC-3: loginFailure sets error and detects MFA
// ---------------------------------------------------------------------------

describe('AC-3: loginFailure sets error and detects MFA required', () => {
  /**
   * AC-3: loginFailure MUST set isAuthenticated=false and store the error.
   * 'MFA required' in message -> mfaRequired=true. Otherwise false.
   */
  beforeEach(() => {
    vi.clearAllMocks();
    resetAuthStore();
  });

  it('sets isAuthenticated to false', () => {
    act(() => useAuthStore.getState().loginFailure('Bad password'));
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });

  it('stores the error message', () => {
    act(() => useAuthStore.getState().loginFailure('Bad password'));
    expect(useAuthStore.getState().error).toBe('Bad password');
  });

  it('sets mfaRequired=true when error contains MFA required', () => {
    act(() => useAuthStore.getState().loginFailure('MFA required for this account'));
    expect(useAuthStore.getState().mfaRequired).toBe(true);
  });

  it('leaves mfaRequired=false for other errors', () => {
    act(() => useAuthStore.getState().loginFailure('Invalid credentials'));
    expect(useAuthStore.getState().mfaRequired).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// AC-4: logout clears all auth state and localStorage
// ---------------------------------------------------------------------------

describe('AC-4: logout clears all auth state and localStorage', () => {
  /**
   * AC-4: logout MUST clear all auth state fields and call storageClearAuth().
   */
  beforeEach(() => {
    vi.clearAllMocks();
    resetAuthStore();
    act(() => useAuthStore.getState().loginSuccess(loginPayload));
    vi.clearAllMocks();
  });

  it('sets isAuthenticated to false', () => {
    act(() => useAuthStore.getState().logout());
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
  });

  it('clears user to null', () => {
    act(() => useAuthStore.getState().logout());
    expect(useAuthStore.getState().user).toBeNull();
  });

  it('clears token to null', () => {
    act(() => useAuthStore.getState().logout());
    expect(useAuthStore.getState().token).toBeNull();
  });

  it('clears refreshToken to null', () => {
    act(() => useAuthStore.getState().logout());
    expect(useAuthStore.getState().refreshToken).toBeNull();
  });

  it('clears sessionExpiry to null', () => {
    act(() => useAuthStore.getState().logout());
    expect(useAuthStore.getState().sessionExpiry).toBeNull();
  });

  it('calls storageClearAuth', () => {
    act(() => useAuthStore.getState().logout());
    expect(storageClearAuth).toHaveBeenCalledOnce();
  });
});

// ---------------------------------------------------------------------------
// AC-5: checkSessionExpiry detects expired sessions
// ---------------------------------------------------------------------------

describe('AC-5: checkSessionExpiry detects expired sessions', () => {
  /**
   * AC-5: When sessionExpiry is in the past, MUST transition to logged-out.
   * Null or future sessionExpiry MUST NOT be affected.
   */
  beforeEach(() => {
    vi.clearAllMocks();
    resetAuthStore();
  });

  it('logs out when sessionExpiry is in the past', () => {
    resetAuthStore({
      isAuthenticated: true,
      token: 'old-tok',
      user: testUser,
      sessionExpiry: Date.now() - 1000,
    });
    act(() => useAuthStore.getState().checkSessionExpiry());
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
    expect(useAuthStore.getState().error).toBe('Session expired. Please login again.');
  });

  it('does nothing when sessionExpiry is in the future', () => {
    resetAuthStore({
      isAuthenticated: true,
      token: 'valid-tok',
      user: testUser,
      sessionExpiry: Date.now() + 3600_000,
    });
    act(() => useAuthStore.getState().checkSessionExpiry());
    expect(useAuthStore.getState().isAuthenticated).toBe(true);
  });

  it('does nothing when sessionExpiry is null', () => {
    act(() => useAuthStore.getState().checkSessionExpiry());
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
    expect(useAuthStore.getState().error).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// AC-6: refreshTokenSuccess updates token and sessionExpiry
// ---------------------------------------------------------------------------

describe('AC-6: refreshTokenSuccess updates token and persists', () => {
  /**
   * AC-6: refreshTokenSuccess MUST update token, persist to localStorage,
   * and recalculate sessionExpiry.
   */
  beforeEach(() => {
    vi.clearAllMocks();
    resetAuthStore({ token: 'old-tok', isAuthenticated: true });
  });

  it('updates token in store', () => {
    act(() => useAuthStore.getState().refreshTokenSuccess({ token: 'new-tok', expiresIn: 7200 }));
    expect(useAuthStore.getState().token).toBe('new-tok');
  });

  it('persists new token to localStorage', () => {
    act(() => useAuthStore.getState().refreshTokenSuccess({ token: 'new-tok', expiresIn: 7200 }));
    expect(storageSet).toHaveBeenCalledWith('auth_token', 'new-tok');
  });

  it('recalculates sessionExpiry', () => {
    const before = Date.now();
    act(() => useAuthStore.getState().refreshTokenSuccess({ token: 'new-tok', expiresIn: 7200 }));
    const after = Date.now();
    const { sessionExpiry } = useAuthStore.getState();
    expect(sessionExpiry).toBeGreaterThanOrEqual(before + 7200 * 1000);
    expect(sessionExpiry).toBeLessThanOrEqual(after + 7200 * 1000);
  });
});

// ---------------------------------------------------------------------------
// AC-7: PrivateRoute redirects unauthenticated users to /login
// ---------------------------------------------------------------------------

describe('AC-7: PrivateRoute redirects unauthenticated users', () => {
  /**
   * AC-7: PrivateRoute source MUST check isAuthenticated and render
   * Navigate to /login when false, Outlet when true.
   */
  const source = readSource('components/common/PrivateRoute.tsx');

  it('PrivateRoute checks isAuthenticated from useAuthStore', () => {
    expect(source).toContain('useAuthStore');
    expect(source).toContain('isAuthenticated');
  });

  it('PrivateRoute renders Navigate to /login for unauthenticated', () => {
    expect(source).toContain('/login');
    expect(source).toContain('Navigate');
  });

  it('PrivateRoute renders Outlet for authenticated', () => {
    expect(source).toContain('Outlet');
  });
});

// ---------------------------------------------------------------------------
// AC-8: PublicRoute redirects authenticated users to /
// ---------------------------------------------------------------------------

describe('AC-8: PublicRoute redirects authenticated users', () => {
  /**
   * AC-8: PublicRoute source MUST check isAuthenticated and render
   * Navigate to / when true, Outlet when false.
   */
  const source = readSource('components/common/PublicRoute.tsx');

  it('PublicRoute checks isAuthenticated from useAuthStore', () => {
    expect(source).toContain('useAuthStore');
    expect(source).toContain('isAuthenticated');
  });

  it('PublicRoute renders Navigate for authenticated users', () => {
    expect(source).toContain('Navigate');
  });

  it('PublicRoute renders Outlet for unauthenticated users', () => {
    expect(source).toContain('Outlet');
  });
});

// ---------------------------------------------------------------------------
// AC-9: tokenService uses useAuthStore, not Redux
// ---------------------------------------------------------------------------

describe('AC-9: tokenService uses useAuthStore', () => {
  /**
   * AC-9: tokenService MUST import useAuthStore and use getState().
   * MUST NOT import from Redux store or authSlice.
   */
  const source = readSource('services/tokenService.ts');

  it('imports useAuthStore', () => {
    expect(source).toContain('useAuthStore');
  });

  it('calls useAuthStore.getState()', () => {
    expect(source).toContain('useAuthStore.getState()');
  });

  it('does not import from Redux store module', () => {
    expect(source).not.toContain("from '../store'");
  });

  it('does not import from authSlice', () => {
    expect(source).not.toContain('authSlice');
  });
});

// ---------------------------------------------------------------------------
// AC-10: activityTracker uses useAuthStore, not Redux
// ---------------------------------------------------------------------------

describe('AC-10: activityTracker uses useAuthStore', () => {
  /**
   * AC-10: activityTracker MUST import useAuthStore and use getState().
   * MUST NOT import from Redux store or authSlice.
   */
  const source = readSource('services/activityTracker.ts');

  it('imports useAuthStore', () => {
    expect(source).toContain('useAuthStore');
  });

  it('calls useAuthStore.getState()', () => {
    expect(source).toContain('useAuthStore.getState()');
  });

  it('does not import from Redux store module', () => {
    expect(source).not.toContain("from '../store'");
  });

  it('does not import from authSlice', () => {
    expect(source).not.toContain('authSlice');
  });
});
