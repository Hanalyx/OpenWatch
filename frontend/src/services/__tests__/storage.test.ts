import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  StorageKeys,
  storageGet,
  storageSet,
  storageRemove,
  storageGetJSON,
  storageSetJSON,
  storageClearAuth,
} from '../storage';

describe('StorageKeys', () => {
  it('uses auth_token as the AUTH_TOKEN key (not token)', () => {
    expect(StorageKeys.AUTH_TOKEN).toBe('auth_token');
  });

  it('defines all expected keys', () => {
    expect(StorageKeys.REFRESH_TOKEN).toBe('refresh_token');
    expect(StorageKeys.AUTH_USER).toBe('auth_user');
    expect(StorageKeys.SESSION_EXPIRY).toBe('session_expiry');
    expect(StorageKeys.THEME_MODE).toBe('themeMode');
    expect(StorageKeys.COMPLIANCE_RULES_VIEW_MODE).toBe('complianceRulesViewMode');
    expect(StorageKeys.SESSION_INACTIVITY_TIMEOUT).toBe('session_inactivity_timeout_minutes');
  });
});

describe('storageGet', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('returns the stored value', () => {
    localStorage.setItem('auth_token', 'my-token');
    expect(storageGet(StorageKeys.AUTH_TOKEN)).toBe('my-token');
  });

  it('returns null for missing keys', () => {
    expect(storageGet(StorageKeys.AUTH_TOKEN)).toBeNull();
  });

  it('returns null when localStorage throws', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('Storage unavailable');
    });
    expect(storageGet(StorageKeys.AUTH_TOKEN)).toBeNull();
    vi.restoreAllMocks();
  });
});

describe('storageSet', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('stores a value', () => {
    storageSet(StorageKeys.AUTH_TOKEN, 'abc123');
    expect(localStorage.getItem('auth_token')).toBe('abc123');
  });

  it('does not throw when localStorage is unavailable', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('Quota exceeded');
    });
    expect(() => storageSet(StorageKeys.AUTH_TOKEN, 'x')).not.toThrow();
    vi.restoreAllMocks();
  });
});

describe('storageRemove', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('removes a value', () => {
    localStorage.setItem('auth_token', 'abc');
    storageRemove(StorageKeys.AUTH_TOKEN);
    expect(localStorage.getItem('auth_token')).toBeNull();
  });

  it('does not throw when localStorage is unavailable', () => {
    vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => {
      throw new Error('Storage unavailable');
    });
    expect(() => storageRemove(StorageKeys.AUTH_TOKEN)).not.toThrow();
    vi.restoreAllMocks();
  });
});

describe('storageGetJSON', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('parses stored JSON', () => {
    localStorage.setItem('auth_user', JSON.stringify({ name: 'admin' }));
    expect(storageGetJSON<{ name: string }>(StorageKeys.AUTH_USER)).toEqual({ name: 'admin' });
  });

  it('returns null for missing keys', () => {
    expect(storageGetJSON(StorageKeys.AUTH_USER)).toBeNull();
  });

  it('returns null for invalid JSON', () => {
    localStorage.setItem('auth_user', '{broken');
    expect(storageGetJSON(StorageKeys.AUTH_USER)).toBeNull();
  });
});

describe('storageSetJSON', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('serializes and stores JSON', () => {
    storageSetJSON(StorageKeys.AUTH_USER, { role: 'admin' });
    expect(JSON.parse(localStorage.getItem('auth_user')!)).toEqual({ role: 'admin' });
  });

  it('does not throw for circular references', () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(() => storageSetJSON(StorageKeys.AUTH_USER, circular)).not.toThrow();
  });
});

describe('storageClearAuth', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('removes all auth-related keys', () => {
    localStorage.setItem('auth_token', 'token');
    localStorage.setItem('refresh_token', 'refresh');
    localStorage.setItem('auth_user', '{}');
    localStorage.setItem('session_expiry', '12345');
    localStorage.setItem('themeMode', 'dark');

    storageClearAuth();

    expect(localStorage.getItem('auth_token')).toBeNull();
    expect(localStorage.getItem('refresh_token')).toBeNull();
    expect(localStorage.getItem('auth_user')).toBeNull();
    expect(localStorage.getItem('session_expiry')).toBeNull();
    // Non-auth keys should remain
    expect(localStorage.getItem('themeMode')).toBe('dark');
  });
});
