import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import React from 'react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import authReducer from '../../store/slices/authSlice';
import {
  useAuthHeaders,
  getAuthHeaders,
  isUserAuthenticated,
  getAuthToken,
} from '../useAuthHeaders';

// Mock storage module
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

import { storageGet } from '../../services/storage';

function makeWrapper(preloadedState: Record<string, unknown> = {}) {
  const store = configureStore({
    reducer: { auth: authReducer },
    preloadedState,
  });
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return React.createElement(Provider, { store }, children);
  };
}

describe('useAuthHeaders', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
  });

  it('returns auth header when token exists in Redux store', () => {
    const wrapper = makeWrapper({
      auth: {
        user: { id: '1', username: 'u', email: 'e', role: 'admin', mfaEnabled: false },
        token: 'store-token-123',
        refreshToken: null,
        isAuthenticated: true,
        isLoading: false,
        error: null,
        mfaRequired: false,
        sessionExpiry: null,
      },
    });

    const { result } = renderHook(() => useAuthHeaders(), { wrapper });

    expect(result.current.token).toBe('store-token-123');
    expect(result.current.isAuthenticated).toBe(true);
    expect(result.current.headers.Authorization).toBe('Bearer store-token-123');
    expect(result.current.headers['Content-Type']).toBe('application/json');
  });

  it('falls back to localStorage when store has no token', () => {
    vi.mocked(storageGet).mockReturnValue('local-token-456');

    const wrapper = makeWrapper({
      auth: {
        user: null,
        token: null,
        refreshToken: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
        mfaRequired: false,
        sessionExpiry: null,
      },
    });

    const { result } = renderHook(() => useAuthHeaders(), { wrapper });

    expect(result.current.token).toBe('local-token-456');
    expect(result.current.isAuthenticated).toBe(true);
    expect(result.current.headers.Authorization).toBe('Bearer local-token-456');
  });

  it('returns empty auth when no token is available', () => {
    vi.mocked(storageGet).mockReturnValue(null);

    const wrapper = makeWrapper({
      auth: {
        user: null,
        token: null,
        refreshToken: null,
        isAuthenticated: false,
        isLoading: false,
        error: null,
        mfaRequired: false,
        sessionExpiry: null,
      },
    });

    const { result } = renderHook(() => useAuthHeaders(), { wrapper });

    expect(result.current.token).toBeNull();
    expect(result.current.isAuthenticated).toBe(false);
    expect(result.current.headers.Authorization).toBeUndefined();
    expect(result.current.headers['Content-Type']).toBe('application/json');
  });
});

describe('getAuthHeaders', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns headers with token from localStorage', () => {
    vi.mocked(storageGet).mockReturnValue('my-token');
    const headers = getAuthHeaders();
    expect(headers.Authorization).toBe('Bearer my-token');
    expect(headers['Content-Type']).toBe('application/json');
  });

  it('returns headers without Authorization when no token', () => {
    vi.mocked(storageGet).mockReturnValue(null);
    const headers = getAuthHeaders();
    expect(headers.Authorization).toBeUndefined();
    expect(headers['Content-Type']).toBe('application/json');
  });
});

describe('isUserAuthenticated', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns true when token exists', () => {
    vi.mocked(storageGet).mockReturnValue('tok');
    expect(isUserAuthenticated()).toBe(true);
  });

  it('returns false when no token', () => {
    vi.mocked(storageGet).mockReturnValue(null);
    expect(isUserAuthenticated()).toBe(false);
  });
});

describe('getAuthToken', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns the raw token', () => {
    vi.mocked(storageGet).mockReturnValue('raw-tok');
    expect(getAuthToken()).toBe('raw-tok');
  });

  it('returns null when no token', () => {
    vi.mocked(storageGet).mockReturnValue(null);
    expect(getAuthToken()).toBeNull();
  });
});
