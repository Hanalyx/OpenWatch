import { describe, it, expect, beforeEach, vi } from 'vitest';
import { configureStore } from '@reduxjs/toolkit';
import authReducer, {
  loginSuccess,
  loginFailure,
  logout,
  clearError,
  refreshTokenSuccess,
  checkSessionExpiry,
  setLoading,
  setMfaRequired,
} from '../slices/authSlice';

// Mock the storage module
vi.mock('../../services/storage', () => ({
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

import { storageSet, storageClearAuth } from '../../services/storage';

function makeStore() {
  return configureStore({ reducer: { auth: authReducer } });
}

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

describe('authSlice', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('initialState', () => {
    it('has correct default shape', () => {
      const store = makeStore();
      const state = store.getState().auth;
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
      const store = makeStore();
      store.dispatch(loginSuccess(loginPayload));
      const state = store.getState().auth;

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
      const store = makeStore();
      store.dispatch(loginSuccess(loginPayload));
      const after = Date.now();
      const state = store.getState().auth;

      expect(state.sessionExpiry).toBeGreaterThanOrEqual(before + 3600 * 1000);
      expect(state.sessionExpiry).toBeLessThanOrEqual(after + 3600 * 1000);
    });

    it('persists token to localStorage via storageSet', () => {
      const store = makeStore();
      store.dispatch(loginSuccess(loginPayload));

      expect(storageSet).toHaveBeenCalledWith('auth_token', 'access-token-abc');
      expect(storageSet).toHaveBeenCalledWith('refresh_token', 'refresh-token-xyz');
      expect(storageSet).toHaveBeenCalledWith('auth_user', JSON.stringify(testUser));
    });
  });

  describe('loginFailure', () => {
    it('sets error and clears authentication', () => {
      const store = makeStore();
      store.dispatch(loginFailure('Invalid credentials'));
      const state = store.getState().auth;

      expect(state.error).toBe('Invalid credentials');
      expect(state.isAuthenticated).toBe(false);
      expect(state.isLoading).toBe(false);
    });

    it('detects MFA required from error message', () => {
      const store = makeStore();
      store.dispatch(loginFailure('MFA required for this account'));
      const state = store.getState().auth;

      expect(state.mfaRequired).toBe(true);
    });

    it('does not set mfaRequired for other errors', () => {
      const store = makeStore();
      store.dispatch(loginFailure('Network error'));
      const state = store.getState().auth;

      expect(state.mfaRequired).toBe(false);
    });
  });

  describe('logout', () => {
    it('clears all auth state', () => {
      const store = makeStore();
      store.dispatch(loginSuccess(loginPayload));
      store.dispatch(logout());
      const state = store.getState().auth;

      expect(state.user).toBeNull();
      expect(state.token).toBeNull();
      expect(state.refreshToken).toBeNull();
      expect(state.isAuthenticated).toBe(false);
      expect(state.sessionExpiry).toBeNull();
      expect(state.error).toBeNull();
      expect(state.mfaRequired).toBe(false);
    });

    it('calls storageClearAuth', () => {
      const store = makeStore();
      store.dispatch(logout());
      expect(storageClearAuth).toHaveBeenCalled();
    });
  });

  describe('clearError', () => {
    it('clears error state', () => {
      const store = makeStore();
      store.dispatch(loginFailure('some error'));
      store.dispatch(clearError());
      expect(store.getState().auth.error).toBeNull();
    });
  });

  describe('setLoading', () => {
    it('sets isLoading to true', () => {
      const store = makeStore();
      store.dispatch(setLoading(true));
      expect(store.getState().auth.isLoading).toBe(true);
    });

    it('sets isLoading to false', () => {
      const store = makeStore();
      store.dispatch(setLoading(true));
      store.dispatch(setLoading(false));
      expect(store.getState().auth.isLoading).toBe(false);
    });
  });

  describe('setMfaRequired', () => {
    it('sets mfaRequired flag', () => {
      const store = makeStore();
      store.dispatch(setMfaRequired(true));
      expect(store.getState().auth.mfaRequired).toBe(true);
      store.dispatch(setMfaRequired(false));
      expect(store.getState().auth.mfaRequired).toBe(false);
    });
  });

  describe('refreshTokenSuccess', () => {
    it('updates token and sessionExpiry', () => {
      const store = makeStore();
      store.dispatch(loginSuccess(loginPayload));
      const before = Date.now();
      store.dispatch(refreshTokenSuccess({ token: 'new-token', expiresIn: 7200 }));
      const after = Date.now();
      const state = store.getState().auth;

      expect(state.token).toBe('new-token');
      expect(state.sessionExpiry).toBeGreaterThanOrEqual(before + 7200 * 1000);
      expect(state.sessionExpiry).toBeLessThanOrEqual(after + 7200 * 1000);
      expect(state.error).toBeNull();
    });

    it('persists new token to localStorage', () => {
      const store = makeStore();
      vi.clearAllMocks();
      store.dispatch(refreshTokenSuccess({ token: 'refreshed-tok', expiresIn: 3600 }));
      expect(storageSet).toHaveBeenCalledWith('auth_token', 'refreshed-tok');
    });
  });

  describe('checkSessionExpiry', () => {
    it('logs out when session is expired', () => {
      const store = makeStore();
      store.dispatch(loginSuccess(loginPayload));

      // Manually set sessionExpiry to the past
      store.dispatch(refreshTokenSuccess({ token: 'tok', expiresIn: -1 }));
      store.dispatch(checkSessionExpiry());
      const state = store.getState().auth;

      expect(state.isAuthenticated).toBe(false);
      expect(state.token).toBeNull();
      expect(state.user).toBeNull();
      expect(state.error).toBe('Session expired. Please login again.');
    });

    it('does nothing when session is still valid', () => {
      const store = makeStore();
      store.dispatch(loginSuccess(loginPayload));
      store.dispatch(checkSessionExpiry());
      const state = store.getState().auth;

      expect(state.isAuthenticated).toBe(true);
      expect(state.token).toBe('access-token-abc');
    });

    it('does nothing when sessionExpiry is null', () => {
      const store = makeStore();
      store.dispatch(checkSessionExpiry());
      const state = store.getState().auth;

      expect(state.isAuthenticated).toBe(false);
      expect(state.error).toBeNull();
    });
  });
});
