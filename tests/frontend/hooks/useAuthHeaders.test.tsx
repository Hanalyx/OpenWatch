import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useAuthStore } from '../../../frontend/src/store/useAuthStore';
import {
  useAuthHeaders,
  getAuthHeaders,
  isUserAuthenticated,
  getAuthToken,
} from '../../../frontend/src/hooks/useAuthHeaders';

// Mock storage module
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

import { storageGet } from '../../../frontend/src/services/storage';

function resetAuthStore(token: string | null = null) {
  act(() => {
    useAuthStore.setState({
      user: token
        ? { id: '1', username: 'u', email: 'e', role: 'admin', mfaEnabled: false }
        : null,
      token,
      refreshToken: null,
      isAuthenticated: !!token,
      isLoading: false,
      error: null,
      mfaRequired: false,
      sessionExpiry: null,
    });
  });
}

describe('useAuthHeaders', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetAuthStore(null);
  });

  it('returns auth header when token exists in Zustand store', () => {
    resetAuthStore('store-token-123');

    const { result } = renderHook(() => useAuthHeaders());

    expect(result.current.token).toBe('store-token-123');
    expect(result.current.isAuthenticated).toBe(true);
    expect(result.current.headers.Authorization).toBe('Bearer store-token-123');
    expect(result.current.headers['Content-Type']).toBe('application/json');
  });

  it('returns empty auth when no token is available', () => {
    vi.mocked(storageGet).mockReturnValue(null);

    const { result } = renderHook(() => useAuthHeaders());

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
