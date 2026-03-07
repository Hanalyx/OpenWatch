// Spec: specs/frontend/state-management.spec.yaml
/**
 * Spec-enforcement tests for frontend state management architecture.
 *
 * Verifies that Zustand stores own auth and notification state,
 * deleted Redux slices are absent, service files use useAuthStore.getState(),
 * and all store actions fulfil their behavioral contracts.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { act } from 'react';
import * as fs from 'fs';
import * as path from 'path';

// Mock storage to prevent localStorage side-effects in source-inspection tests
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
    HOSTS_VIEW_MODE: 'hosts_view_mode',
    HOSTS_GROUP_BY: 'hosts_group_by',
  },
}));

import { storageSet, storageClearAuth } from '../../../frontend/src/services/storage';
import { useAuthStore } from '../../../frontend/src/store/useAuthStore';
import { useNotificationStore } from '../../../frontend/src/store/useNotificationStore';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SRC = path.resolve(__dirname, '../../../frontend/src');

function readSource(relativePath: string): string {
  return fs.readFileSync(path.join(SRC, relativePath), 'utf8');
}

function fileExists(relativePath: string): boolean {
  return fs.existsSync(path.join(SRC, relativePath));
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
// AC-1: Redux is fully uninstalled (no packages, no store, no hooks, no Provider)
// ---------------------------------------------------------------------------

describe('AC-1: Redux is fully uninstalled', () => {
  /**
   * AC-1: Redux MUST be fully uninstalled. store/index.ts and hooks/redux.ts
   * MUST NOT exist. @reduxjs/toolkit, react-redux, redux-persist MUST NOT
   * appear in package.json. index.tsx MUST NOT import or render a Provider.
   */

  it('store/index.ts does not exist', () => {
    expect(fileExists('store/index.ts')).toBe(false);
  });

  it('hooks/redux.ts does not exist', () => {
    expect(fileExists('hooks/redux.ts')).toBe(false);
  });

  it('package.json does not contain @reduxjs/toolkit', () => {
    const pkgJson = fs.readFileSync(path.resolve(SRC, '../package.json'), 'utf8');
    expect(pkgJson).not.toContain('@reduxjs/toolkit');
  });

  it('package.json does not contain react-redux', () => {
    const pkgJson = fs.readFileSync(path.resolve(SRC, '../package.json'), 'utf8');
    expect(pkgJson).not.toContain('react-redux');
  });

  it('package.json does not contain redux-persist', () => {
    const pkgJson = fs.readFileSync(path.resolve(SRC, '../package.json'), 'utf8');
    expect(pkgJson).not.toContain('redux-persist');
  });

  it('index.tsx does not import Provider from react-redux', () => {
    const indexSource = readSource('index.tsx');
    expect(indexSource).not.toContain('Provider');
    expect(indexSource).not.toContain('react-redux');
  });
});

// ---------------------------------------------------------------------------
// AC-2: Deleted Redux slice files must not exist
// ---------------------------------------------------------------------------

describe('AC-2: Deleted Redux slice files are absent', () => {
  /**
   * AC-2: All 8 deleted slice files MUST NOT exist on disk.
   */
  const deletedSlices = [
    'store/slices/authSlice.ts',
    'store/slices/notificationSlice.ts',
    'store/slices/hostSlice.ts',
    'store/slices/contentSlice.ts',
    'store/slices/scanSlice.ts',
    'store/slices/resultSlice.ts',
    'store/slices/userSlice.ts',
    'store/slices/auditSlice.ts',
  ];

  for (const slicePath of deletedSlices) {
    it(`${slicePath} does not exist`, () => {
      expect(fileExists(slicePath)).toBe(false);
    });
  }
});

// ---------------------------------------------------------------------------
// AC-3: useAuthStore exports all 8 required actions
// ---------------------------------------------------------------------------

describe('AC-3: useAuthStore exports all required actions', () => {
  /**
   * AC-3: All 8 auth actions MUST be callable on the store state.
   */
  const requiredActions = [
    'loginSuccess',
    'loginFailure',
    'logout',
    'clearError',
    'setMfaRequired',
    'setLoading',
    'refreshTokenSuccess',
    'checkSessionExpiry',
  ] as const;

  for (const action of requiredActions) {
    it(`useAuthStore.getState().${action} is a function`, () => {
      const state = useAuthStore.getState();
      expect(typeof state[action]).toBe('function');
    });
  }
});

// ---------------------------------------------------------------------------
// AC-4: useNotificationStore exports all 5 required actions
// ---------------------------------------------------------------------------

describe('AC-4: useNotificationStore exports all required actions', () => {
  /**
   * AC-4: All 5 notification actions MUST be callable on the store state.
   */
  const requiredActions = [
    'addNotification',
    'removeNotification',
    'clearNotifications',
    'setOSDiscoveryFailures',
    'setSystemAlerts',
  ] as const;

  for (const action of requiredActions) {
    it(`useNotificationStore.getState().${action} is a function`, () => {
      const state = useNotificationStore.getState();
      expect(typeof state[action]).toBe('function');
    });
  }
});

// ---------------------------------------------------------------------------
// AC-5: loginSuccess persists to localStorage; logout clears it
// ---------------------------------------------------------------------------

describe('AC-5: loginSuccess persists auth data; logout clears it', () => {
  /**
   * AC-5: loginSuccess MUST call storageSet for token, refreshToken,
   * user, and sessionExpiry. logout MUST call storageClearAuth.
   */
  beforeEach(() => {
    vi.clearAllMocks();
    resetAuthStore();
  });

  it('loginSuccess persists token to AUTH_TOKEN', () => {
    act(() => useAuthStore.getState().loginSuccess(loginPayload));
    expect(storageSet).toHaveBeenCalledWith('auth_token', 'tok-abc');
  });

  it('loginSuccess persists refreshToken to REFRESH_TOKEN', () => {
    act(() => useAuthStore.getState().loginSuccess(loginPayload));
    expect(storageSet).toHaveBeenCalledWith('refresh_token', 'ref-xyz');
  });

  it('loginSuccess persists user as JSON to AUTH_USER', () => {
    act(() => useAuthStore.getState().loginSuccess(loginPayload));
    expect(storageSet).toHaveBeenCalledWith('auth_user', JSON.stringify(testUser));
  });

  it('loginSuccess persists sessionExpiry to SESSION_EXPIRY', () => {
    act(() => useAuthStore.getState().loginSuccess(loginPayload));
    expect(storageSet).toHaveBeenCalledWith('session_expiry', expect.any(String));
  });

  it('logout calls storageClearAuth', () => {
    act(() => useAuthStore.getState().logout());
    expect(storageClearAuth).toHaveBeenCalledOnce();
  });

  it('logout clears isAuthenticated and token in store', () => {
    act(() => useAuthStore.getState().loginSuccess(loginPayload));
    act(() => useAuthStore.getState().logout());
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.token).toBeNull();
    expect(state.user).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// AC-6: checkSessionExpiry detects expired sessions
// ---------------------------------------------------------------------------

describe('AC-6: checkSessionExpiry detects expired sessions', () => {
  /**
   * AC-6: checkSessionExpiry MUST log out when sessionExpiry is in the past,
   * and leave state unchanged when it is in the future or null.
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
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.token).toBeNull();
    expect(state.user).toBeNull();
    expect(state.error).toBe('Session expired. Please login again.');
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
    expect(useAuthStore.getState().token).toBe('valid-tok');
  });

  it('does nothing when sessionExpiry is null', () => {
    act(() => useAuthStore.getState().checkSessionExpiry());
    expect(useAuthStore.getState().isAuthenticated).toBe(false);
    expect(useAuthStore.getState().error).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// AC-7: loginFailure sets mfaRequired when message contains 'MFA required'
// ---------------------------------------------------------------------------

describe('AC-7: loginFailure detects MFA required', () => {
  /**
   * AC-7: mfaRequired MUST be true when error includes 'MFA required',
   * false for all other errors.
   */
  beforeEach(() => {
    vi.clearAllMocks();
    resetAuthStore();
  });

  it('sets mfaRequired=true for "MFA required" error', () => {
    act(() => useAuthStore.getState().loginFailure('MFA required for this account'));
    expect(useAuthStore.getState().mfaRequired).toBe(true);
  });

  it('leaves mfaRequired=false for unrelated errors', () => {
    act(() => useAuthStore.getState().loginFailure('Invalid credentials'));
    expect(useAuthStore.getState().mfaRequired).toBe(false);
  });

  it('leaves mfaRequired=false for network errors', () => {
    act(() => useAuthStore.getState().loginFailure('Network error'));
    expect(useAuthStore.getState().mfaRequired).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// AC-8: tokenService imports from useAuthStore, not Redux store
// ---------------------------------------------------------------------------

describe('AC-8: tokenService uses useAuthStore, not Redux store', () => {
  /**
   * AC-8: tokenService.ts source MUST import useAuthStore and MUST NOT
   * import from '../store' (Redux) or authSlice.
   */
  const tokenServiceSource = readSource('services/tokenService.ts');

  it('tokenService imports useAuthStore', () => {
    expect(tokenServiceSource).toContain('useAuthStore');
  });

  it('tokenService calls useAuthStore.getState()', () => {
    expect(tokenServiceSource).toContain('useAuthStore.getState()');
  });

  it('tokenService does not import from Redux store module', () => {
    // Must not import from ../store (Redux index) for auth
    expect(tokenServiceSource).not.toContain("from '../store'");
  });

  it('tokenService does not import from authSlice', () => {
    expect(tokenServiceSource).not.toContain('authSlice');
  });
});

// ---------------------------------------------------------------------------
// AC-9: activityTracker imports from useAuthStore, not Redux store
// ---------------------------------------------------------------------------

describe('AC-9: activityTracker uses useAuthStore, not Redux store', () => {
  /**
   * AC-9: activityTracker.ts source MUST import useAuthStore and MUST NOT
   * import from '../store' (Redux) or authSlice.
   */
  const trackerSource = readSource('services/activityTracker.ts');

  it('activityTracker imports useAuthStore', () => {
    expect(trackerSource).toContain('useAuthStore');
  });

  it('activityTracker calls useAuthStore.getState()', () => {
    expect(trackerSource).toContain('useAuthStore.getState()');
  });

  it('activityTracker does not import from Redux store module', () => {
    expect(trackerSource).not.toContain("from '../store'");
  });

  it('activityTracker does not import from authSlice', () => {
    expect(trackerSource).not.toContain('authSlice');
  });
});

// ---------------------------------------------------------------------------
// AC-10: refreshTokenSuccess updates store AND persists to localStorage
// ---------------------------------------------------------------------------

describe('AC-10: refreshTokenSuccess updates store and localStorage', () => {
  /**
   * AC-10: refreshTokenSuccess MUST replace the token in store state
   * AND persist it to localStorage in the same action.
   */
  beforeEach(() => {
    vi.clearAllMocks();
    resetAuthStore({ token: 'old-tok', isAuthenticated: true });
  });

  it('updates token in store state', () => {
    act(() => useAuthStore.getState().refreshTokenSuccess({ token: 'new-tok', expiresIn: 7200 }));
    expect(useAuthStore.getState().token).toBe('new-tok');
  });

  it('persists new token to localStorage', () => {
    act(() => useAuthStore.getState().refreshTokenSuccess({ token: 'new-tok', expiresIn: 7200 }));
    expect(storageSet).toHaveBeenCalledWith('auth_token', 'new-tok');
  });

  it('updates sessionExpiry in store state', () => {
    const before = Date.now();
    act(() => useAuthStore.getState().refreshTokenSuccess({ token: 'new-tok', expiresIn: 7200 }));
    const after = Date.now();
    const { sessionExpiry } = useAuthStore.getState();
    expect(sessionExpiry).toBeGreaterThanOrEqual(before + 7200 * 1000);
    expect(sessionExpiry).toBeLessThanOrEqual(after + 7200 * 1000);
  });

  it('clears error in store state on successful refresh', () => {
    resetAuthStore({ error: 'previous error' });
    act(() => useAuthStore.getState().refreshTokenSuccess({ token: 'new-tok', expiresIn: 3600 }));
    expect(useAuthStore.getState().error).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// AC-11: Host view preferences persisted to localStorage
// ---------------------------------------------------------------------------

describe('AC-11: Host view preferences persisted to localStorage', () => {
  /**
   * AC-11: StorageKeys MUST include HOSTS_VIEW_MODE and HOSTS_GROUP_BY.
   * useHostsPage MUST initialize viewMode from storageGet(HOSTS_VIEW_MODE)
   * (default 'grid') and groupBy from storageGet(HOSTS_GROUP_BY) (default
   * 'all'). Changes MUST be persisted via storageSet.
   */

  it('StorageKeys includes HOSTS_VIEW_MODE', () => {
    const storageSource = readSource('services/storage.ts');
    expect(storageSource).toContain('HOSTS_VIEW_MODE');
  });

  it('StorageKeys includes HOSTS_GROUP_BY', () => {
    const storageSource = readSource('services/storage.ts');
    expect(storageSource).toContain('HOSTS_GROUP_BY');
  });

  it('useHostsPage reads viewMode from localStorage via storageGet(HOSTS_VIEW_MODE)', () => {
    const hookSource = readSource('pages/hosts/hooks/useHostsPage.ts');
    expect(hookSource).toContain('storageGet(StorageKeys.HOSTS_VIEW_MODE)');
  });

  it('useHostsPage reads groupBy from localStorage via storageGet(HOSTS_GROUP_BY)', () => {
    const hookSource = readSource('pages/hosts/hooks/useHostsPage.ts');
    expect(hookSource).toContain('storageGet(StorageKeys.HOSTS_GROUP_BY)');
  });

  it('useHostsPage persists viewMode changes via storageSet(HOSTS_VIEW_MODE)', () => {
    const hookSource = readSource('pages/hosts/hooks/useHostsPage.ts');
    expect(hookSource).toContain('storageSet(StorageKeys.HOSTS_VIEW_MODE');
  });

  it('useHostsPage persists groupBy changes via storageSet(HOSTS_GROUP_BY)', () => {
    const hookSource = readSource('pages/hosts/hooks/useHostsPage.ts');
    expect(hookSource).toContain('storageSet(StorageKeys.HOSTS_GROUP_BY');
  });
});
