// redirectOnAuthError is the global QueryCache/MutationCache onError
// handler. It must send the user to /login (clearing identity) for
// authentication-failure codes, and must leave every other error alone
// so an expired session never strands the user on a raw error envelope —
// while an authorization (permission) error does NOT log them out.

import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { useAuthStore } from '@/store/useAuthStore';
import { redirectOnAuthError, AUTH_FAILURE_CODES } from '@/api/auth-error-redirect';

// Build an openapi-fetch-style error body (the parsed ErrorEnvelope).
function envelope(code: string) {
  return { error: { code, human_message: `${code} message`, retryable: true } };
}

describe('api/auth-error-redirect — global auth-failure redirect', () => {
  let originalLocation: Location;
  let navigateSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    originalLocation = window.location;
    navigateSpy = vi.fn();
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: {
        pathname: '/hosts',
        assign: navigateSpy,
        replace: vi.fn(),
      } as unknown as Location,
    });
    useAuthStore.setState({
      identity: {
        id: 'u-1',
        username: 'tester',
        email: 'tester@example.com',
        role: 'admin',
        permissions: ['system:read'],
        mfaEnabled: false,
      },
      loading: false,
    });
  });

  afterEach(() => {
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: originalLocation,
    });
    vi.restoreAllMocks();
  });

  test.each([...AUTH_FAILURE_CODES])(
    'auth code %s → clears identity and navigates to /login',
    (code) => {
      redirectOnAuthError(envelope(code));
      expect(navigateSpy).toHaveBeenCalledWith('/login');
      expect(useAuthStore.getState().identity).toBeNull();
    },
  );

  test('authorization (permission) 401 does NOT log the user out', () => {
    redirectOnAuthError(envelope('authz.permission_denied'));
    expect(navigateSpy).not.toHaveBeenCalled();
    expect(useAuthStore.getState().identity).not.toBeNull();
  });

  test('a non-auth error (validation) is left alone', () => {
    redirectOnAuthError(envelope('validation.range_exceeded'));
    expect(navigateSpy).not.toHaveBeenCalled();
  });

  test('a non-envelope error (plain Error) is left alone', () => {
    redirectOnAuthError(new Error('network down'));
    expect(navigateSpy).not.toHaveBeenCalled();
  });

  test('already on /login → no redundant navigation', () => {
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: { pathname: '/login', assign: navigateSpy, replace: vi.fn() } as unknown as Location,
    });
    redirectOnAuthError(envelope('auth.session_invalid'));
    // identity still cleared, but no navigation loop on /login.
    expect(navigateSpy).not.toHaveBeenCalled();
  });
});
