// @spec system-auth-identity
// @ac AC-25
// AC-25 — transparent 401 retry middleware. On 401 the client calls
// POST /api/v1/auth/refresh-cookie once; on success the original
// request is replayed exactly once with the rotated cookies. On
// refresh-cookie itself returning 401 useAuthStore is cleared and
// window.location is navigated to /login.

import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { useAuthStore } from '@/store/useAuthStore';

// fetch is the underlying transport openapi-fetch uses. By stubbing
// global.fetch we can model the server's responses without spinning a
// real server up. Each test's queue of mock responses returns one
// Response per call in order.
function queueResponses(...responses: Response[]) {
  let i = 0;
  return vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
    const r = responses[i++];
    if (!r) throw new Error(`fetch called more times than mocked (${i} calls, ${responses.length} queued)`);
    return r;
  });
}

function envelope(code: string, msg: string): Response {
  return new Response(JSON.stringify({ error: { code, human_message: msg, retryable: code === 'auth.session_invalid' } }), {
    status: 401,
    headers: { 'Content-Type': 'application/json' },
  });
}

function jsonOK(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

describe('api/client — 401 retry middleware', () => {
  let originalFetch: typeof globalThis.fetch;
  let originalLocation: Location;
  let navigateSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    // jsdom's window.location is not configurable property-by-property,
    // so swap the whole object out and put it back in afterEach. Only
    // pathname + assign matter for the middleware under test.
    originalLocation = window.location;
    navigateSpy = vi.fn();
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: {
        href: 'http://localhost/settings/scanning',
        origin: 'http://localhost',
        protocol: 'http:',
        host: 'localhost',
        hostname: 'localhost',
        port: '',
        pathname: '/settings/scanning',
        search: '',
        hash: '',
        assign: navigateSpy,
        replace: vi.fn(),
        reload: vi.fn(),
        toString: () => 'http://localhost/settings/scanning',
        ancestorOrigins: { length: 0 } as DOMStringList,
      } as Location,
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
    globalThis.fetch = originalFetch;
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: originalLocation,
    });
    vi.restoreAllMocks();
  });

  test('system-auth-identity/AC-25 — 401 → refresh-cookie 200 → original request replayed and succeeds', async () => {
    const mock = queueResponses(
      // 1. original GET — 401
      envelope('auth.session_invalid', 'session expired'),
      // 2. POST /api/v1/auth/refresh-cookie — 200
      jsonOK({ username: 'tester', email: 't@e.com', role: 'admin', permissions: [] }),
      // 3. replayed original GET — 200
      jsonOK({ ok: true }),
    );
    globalThis.fetch = mock;

    // Import the client AFTER fetch is stubbed so the module reads our mock.
    const { default: api } = await import('@/api/client');
    const result = await api.GET('/api/v1/system/connectivity/config', {});

    expect(result.response.status).toBe(200);
    expect(mock).toHaveBeenCalledTimes(3);
    // Second call MUST be the refresh-cookie endpoint.
    const secondReq = mock.mock.calls[1]?.[0] as Request | string | undefined;
    const secondUrl = typeof secondReq === 'string' ? secondReq : secondReq?.url ?? '';
    expect(secondUrl).toContain('/api/v1/auth/refresh-cookie');
    // No navigation occurred — the user stays where they are.
    expect(navigateSpy).not.toHaveBeenCalled();
    // Identity remains populated.
    expect(useAuthStore.getState().identity).not.toBeNull();
  });

  test('system-auth-identity/AC-25 — refresh-cookie 401 → useAuthStore cleared and navigate to /login', async () => {
    const mock = queueResponses(
      // 1. original GET — 401
      envelope('auth.session_invalid', 'session expired'),
      // 2. POST /auth/refresh-cookie — 401 (refresh window blown)
      envelope('auth.refresh_invalid', 'refresh expired'),
    );
    globalThis.fetch = mock;

    const { default: api } = await import('@/api/client');
    const result = await api.GET('/api/v1/system/connectivity/config', {});

    // The caller sees the original 401 envelope.
    expect(result.response.status).toBe(401);
    expect(mock).toHaveBeenCalledTimes(2);
    expect(useAuthStore.getState().identity).toBeNull();
    expect(navigateSpy).toHaveBeenCalledWith('/login');
  });

  test('system-auth-identity/AC-25 — does not loop: a request marked with the retry header is not retried again', async () => {
    // Two consecutive 401s on the same logical call — the middleware
    // refreshes once, replays, and the replay still 401s. The replay
    // result MUST be returned to the caller; no third fetch is fired.
    const mock = queueResponses(
      // 1. original GET — 401
      envelope('auth.session_invalid', 'session expired'),
      // 2. refresh-cookie — 200 (refresh succeeded technically)
      jsonOK({ username: 'tester', email: 't@e.com', role: 'admin', permissions: [] }),
      // 3. replayed original GET — 401 again
      envelope('authz.permission_denied', 'no such permission'),
    );
    globalThis.fetch = mock;

    const { default: api } = await import('@/api/client');
    const result = await api.GET('/api/v1/system/connectivity/config', {});

    expect(result.response.status).toBe(401);
    expect(mock).toHaveBeenCalledTimes(3);
    // Did NOT loop into refresh again.
    const calls = mock.mock.calls.map((c) => {
      const arg = c[0];
      return typeof arg === 'string' ? arg : (arg as Request).url;
    });
    const refreshCalls = calls.filter((u) => u.includes('/auth/refresh-cookie')).length;
    expect(refreshCalls).toBe(1);
  });
});
