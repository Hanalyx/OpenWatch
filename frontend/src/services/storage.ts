/**
 * Centralized localStorage Service
 *
 * All localStorage access in the application MUST go through this service.
 * Provides type-safe access to known keys and handles serialization/errors.
 *
 * CRITICAL: The auth token key MUST be 'auth_token' (NOT 'token').
 * See frontend/CLAUDE.md for details.
 */

/** All known localStorage keys used by the application */
export const StorageKeys = {
  AUTH_TOKEN: 'auth_token',
  REFRESH_TOKEN: 'refresh_token',
  AUTH_USER: 'auth_user',
  SESSION_EXPIRY: 'session_expiry',
  THEME_MODE: 'themeMode',
  COMPLIANCE_RULES_VIEW_MODE: 'complianceRulesViewMode',
  SESSION_INACTIVITY_TIMEOUT: 'session_inactivity_timeout_minutes',
} as const;

export type StorageKey = (typeof StorageKeys)[keyof typeof StorageKeys];

/**
 * Get a string value from localStorage.
 * Returns null if the key doesn't exist or storage is unavailable.
 */
export function storageGet(key: StorageKey): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

/**
 * Set a string value in localStorage.
 * Silently fails if storage is unavailable (e.g., incognito mode quota exceeded).
 */
export function storageSet(key: StorageKey, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Storage unavailable — fail silently
  }
}

/**
 * Remove a key from localStorage.
 */
export function storageRemove(key: StorageKey): void {
  try {
    localStorage.removeItem(key);
  } catch {
    // Storage unavailable — fail silently
  }
}

/**
 * Get a JSON-parsed value from localStorage.
 * Returns null if the key doesn't exist, parsing fails, or storage is unavailable.
 */
export function storageGetJSON<T>(key: StorageKey): T | null {
  const raw = storageGet(key);
  if (raw === null) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

/**
 * Set a JSON-serialized value in localStorage.
 */
export function storageSetJSON(key: StorageKey, value: unknown): void {
  try {
    storageSet(key, JSON.stringify(value));
  } catch {
    // Serialization or storage failed — fail silently
  }
}

/**
 * Remove all auth-related keys from localStorage.
 * Used during logout and session expiry.
 */
export function storageClearAuth(): void {
  storageRemove(StorageKeys.AUTH_TOKEN);
  storageRemove(StorageKeys.REFRESH_TOKEN);
  storageRemove(StorageKeys.AUTH_USER);
  storageRemove(StorageKeys.SESSION_EXPIRY);
}
