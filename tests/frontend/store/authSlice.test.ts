import { describe, it, expect, beforeEach, vi } from 'vitest';
import { act } from 'react';
import { useAuthStore } from '../../../frontend/src/store/useAuthStore';

// Mock the storage module
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

const testUser = {
  id: '123',
  username: 'testuser',
  email: 'test@example.com',
  role: 'admin',
  mfaEnabled: false,
};

const loginPayload = {
  user: testUser,
  token: 'access-token-abc',
  refreshToken: 'refresh-token-xyz',
  expiresIn: 3600,
};

// Reset the store to initial state before each test
function resetStore() {
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
    });
  });
}

describe('useAuthStore', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetStore();
  });

  describe('initialState', () => {
    it('has correct default shape', () => {
      const state = useAuthStore.getState();
      expect(state.user).toBeNull();
      expect(state.token).toBeNull();
      expect(state.refreshToken).toBeNull();
      expect(state.isAuthenticated).toBe(false);
      expect(state.isLoading).toBe(false);
      expect(state.error).toBeNull();
      expect(state.mfaRequired).toBe(false);
      expect(state.sessionExpiry).toBeNull();
    });
  });

  describe('loginSuccess', () => {
    it('sets user, token, and authentication state', () => {
      act(() => useAuthStore.getState().loginSuccess(loginPayload));
      const state = useAuthStore.getState();

      expect(state.user).toEqual(testUser);
      expect(state.token).toBe('access-token-abc');
      expect(state.refreshToken).toBe('refresh-token-xyz');
      expect(state.isAuthenticated).toBe(true);
      expect(state.isLoading).toBe(false);
      expect(state.error).toBeNull();
      expect(state.mfaRequired).toBe(false);
    });

    it('sets sessionExpiry based on expiresIn', () => {
      const before = Date.now();
      act(() => useAuthStore.getState().loginSuccess(loginPayload));
      const after = Date.now();
      const state = useAuthStore.getState();

      expect(state.sessionExpiry).toBeGreaterThanOrEqual(before + 3600 * 1000);
      expect(state.sessionExpiry).toBeLessThanOrEqual(after + 3600 * 1000);
    });

    it('persists token to localStorage via storageSet', () => {
      act(() => useAuthStore.getState().loginSuccess(loginPayload));

      expect(storageSet).toHaveBeenCalledWith('auth_token', 'access-token-abc');
      expect(storageSet).toHaveBeenCalledWith('refresh_token', 'refresh-token-xyz');
      expect(storageSet).toHaveBeenCalledWith('auth_user', JSON.stringify(testUser));
    });
  });

  describe('loginFailure', () => {
    it('sets error and clears authentication', () => {
      act(() => useAuthStore.getState().loginFailure('Invalid credentials'));
      const state = useAuthStore.getState();

      expect(state.error).toBe('Invalid credentials');
      expect(state.isAuthenticated).toBe(false);
      expect(state.isLoading).toBe(false);
    });

    it('detects MFA required from error message', () => {
      act(() => useAuthStore.getState().loginFailure('MFA required for this account'));
      expect(useAuthStore.getState().mfaRequired).toBe(true);
    });

    it('does not set mfaRequired for other errors', () => {
      act(() => useAuthStore.getState().loginFailure('Network error'));
      expect(useAuthStore.getState().mfaRequired).toBe(false);
    });
  });

  describe('logout', () => {
    it('clears all auth state', () => {
      act(() => useAuthStore.getState().loginSuccess(loginPayload));
      act(() => useAuthStore.getState().logout());
      const state = useAuthStore.getState();

      expect(state.user).toBeNull();
      expect(state.token).toBeNull();
      expect(state.refreshToken).toBeNull();
      expect(state.isAuthenticated).toBe(false);
      expect(state.sessionExpiry).toBeNull();
      expect(state.error).toBeNull();
      expect(state.mfaRequired).toBe(false);
    });

    it('calls storageClearAuth', () => {
      act(() => useAuthStore.getState().logout());
      expect(storageClearAuth).toHaveBeenCalled();
    });
  });

  describe('clearError', () => {
    it('clears error state', () => {
      act(() => useAuthStore.getState().loginFailure('some error'));
      act(() => useAuthStore.getState().clearError());
      expect(useAuthStore.getState().error).toBeNull();
    });
  });

  describe('setLoading', () => {
    it('sets isLoading to true then false', () => {
      act(() => useAuthStore.getState().setLoading(true));
      expect(useAuthStore.getState().isLoading).toBe(true);
      act(() => useAuthStore.getState().setLoading(false));
      expect(useAuthStore.getState().isLoading).toBe(false);
    });
  });

  describe('setMfaRequired', () => {
    it('sets mfaRequired flag', () => {
      act(() => useAuthStore.getState().setMfaRequired(true));
      expect(useAuthStore.getState().mfaRequired).toBe(true);
      act(() => useAuthStore.getState().setMfaRequired(false));
      expect(useAuthStore.getState().mfaRequired).toBe(false);
    });
  });

  describe('refreshTokenSuccess', () => {
    it('updates token and sessionExpiry', () => {
      act(() => useAuthStore.getState().loginSuccess(loginPayload));
      const before = Date.now();
      act(() => useAuthStore.getState().refreshTokenSuccess({ token: 'new-token', expiresIn: 7200 }));
      const after = Date.now();
      const state = useAuthStore.getState();

      expect(state.token).toBe('new-token');
      expect(state.sessionExpiry).toBeGreaterThanOrEqual(before + 7200 * 1000);
      expect(state.sessionExpiry).toBeLessThanOrEqual(after + 7200 * 1000);
      expect(state.error).toBeNull();
    });

    it('persists new token to localStorage', () => {
      vi.clearAllMocks();
      act(() => useAuthStore.getState().refreshTokenSuccess({ token: 'refreshed-tok', expiresIn: 3600 }));
      expect(storageSet).toHaveBeenCalledWith('auth_token', 'refreshed-tok');
    });
  });

  describe('checkSessionExpiry', () => {
    it('logs out when session is expired', () => {
      act(() => useAuthStore.getState().loginSuccess(loginPayload));
      // Set sessionExpiry to the past
      act(() => useAuthStore.getState().refreshTokenSuccess({ token: 'tok', expiresIn: -1 }));
      act(() => useAuthStore.getState().checkSessionExpiry());
      const state = useAuthStore.getState();

      expect(state.isAuthenticated).toBe(false);
      expect(state.token).toBeNull();
      expect(state.user).toBeNull();
      expect(state.error).toBe('Session expired. Please login again.');
    });

    it('does nothing when session is still valid', () => {
      act(() => useAuthStore.getState().loginSuccess(loginPayload));
      act(() => useAuthStore.getState().checkSessionExpiry());
      const state = useAuthStore.getState();

      expect(state.isAuthenticated).toBe(true);
      expect(state.token).toBe('access-token-abc');
    });

    it('does nothing when sessionExpiry is null', () => {
      act(() => useAuthStore.getState().checkSessionExpiry());
      const state = useAuthStore.getState();

      expect(state.isAuthenticated).toBe(false);
      expect(state.error).toBeNull();
    });
  });
});
