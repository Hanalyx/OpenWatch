import createClient from 'openapi-fetch';
import type { paths } from './schema';
import { useAuthStore } from '@/store/useAuthStore';

// API client — typed against app/api/openapi.yaml.
//
// Per app/docs/frontend_architecture_adr.md D-07/D-08:
//   - openapi-typescript generates `schema.d.ts` from openapi.yaml.
//   - openapi-fetch is a 4 KB typed fetch wrapper.
//   - credentials: 'include' carries the openwatch_session cookie
//     to / from the API on every request.
//   - X-CSRF-Token header echoes the XSRF-TOKEN cookie on every
//     mutating request (double-submit-cookie pattern).
//
// Per system-auth-identity AC-25 the client also installs an
// onResponse middleware that intercepts HTTP 401, calls
// POST /api/v1/auth/refresh-cookie once, and replays the original
// request with the rotated cookies. If refresh itself returns 401
// the middleware clears useAuthStore and triggers navigation to
// /login.

const CSRF_COOKIE = 'XSRF-TOKEN';
const CSRF_HEADER = 'X-CSRF-Token';
const REFRESH_PATH = '/api/v1/auth/refresh-cookie';
const LOGIN_PATH = '/login';

function readCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  const target = name + '=';
  for (const piece of document.cookie.split(';')) {
    const c = piece.trim();
    if (c.startsWith(target)) return decodeURIComponent(c.slice(target.length));
  }
  return null;
}

// Mark a request as already having been retried so the onResponse
// middleware doesn't try to refresh-and-retry a refresh itself or
// loop on a request that came back 401 after refresh.
const RETRY_MARK = 'x-openwatch-retried';

// In-flight refresh promise: dedupes parallel refresh attempts when
// several requests all 401 at once.
let refreshInFlight: Promise<boolean> | null = null;

// refresh calls the cookie-refresh endpoint, deduping concurrent
// callers. Returns true if cookies were rotated, false if the user
// must log in again.
async function refresh(): Promise<boolean> {
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      try {
        const res = await fetch(REFRESH_PATH, {
          method: 'POST',
          credentials: 'include',
        });
        return res.ok;
      } catch {
        return false;
      }
    })();
    // Clear the slot as soon as this promise settles so the next 401
    // wave starts a fresh attempt. Same-tick concurrent callers all
    // get the same promise; only later callers see a cleared slot.
    refreshInFlight.finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
}

// onAuthFailure clears the cached identity and navigates to login.
// Kept here (not in the store) so any caller — components or non-React
// helpers — gets the same behavior. Soft-references window so unit
// tests in jsdom don't blow up on import. Exported so the global
// QueryCache/MutationCache error handler (main.tsx) routes EVERY auth
// failure here, not just the ones this client's middleware sees.
export function onAuthFailure(): void {
  try {
    useAuthStore.getState().clear();
  } catch {
    // Store may not be hydrated yet (boot-time 401 before app mount).
  }
  if (typeof window !== 'undefined' && window.location.pathname !== LOGIN_PATH) {
    window.location.assign(LOGIN_PATH);
  }
}

// OpenAPI paths already start with /api/v1. Vite proxies /api/* to
// the Go backend in dev; in prod the SPA is served from the same
// origin so /api/* hits the backend directly. We resolve against
// window.location.origin explicitly so the URL openapi-fetch constructs
// internally is always absolute — necessary for jsdom tests that stub
// fetch without a document base. Empty string in non-DOM environments.
const baseUrl = typeof window !== 'undefined' && window.location ? window.location.origin : '';

const baseClient = createClient<paths>({
  baseUrl,
  credentials: 'include',
  // Resolve fetch dynamically rather than capturing it at module-load
  // time. The default openapi-fetch behavior captures globalThis.fetch
  // once when createClient runs, which prevents per-test reassignment
  // of fetch from taking effect.
  fetch: (...args) => globalThis.fetch(...args),
});

baseClient.use({
  onRequest({ request }) {
    const method = request.method.toUpperCase();
    if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
      return request;
    }
    const token = readCookie(CSRF_COOKIE);
    if (token) request.headers.set(CSRF_HEADER, token);
    return request;
  },
  // onResponse: transparent 401 retry.
  // Spec system-auth-identity AC-25.
  async onResponse({ request, response }) {
    if (response.status !== 401) return response;
    // Don't loop: a request already retried, or the refresh endpoint
    // itself returning 401, falls straight through to the caller.
    if (request.headers.get(RETRY_MARK) === '1') return response;
    const url = new URL(request.url);
    if (url.pathname === REFRESH_PATH) {
      onAuthFailure();
      return response;
    }
    const ok = await refresh();
    if (!ok) {
      onAuthFailure();
      return response;
    }
    // Replay the original request once. Body streams aren't replayable
    // after Request consumption, so re-clone from the original method +
    // headers + URL. openapi-fetch passes the raw Request, which we
    // clone defensively before mutation.
    const retried = new Request(request.url, {
      method: request.method,
      headers: new Headers(request.headers),
      body:
        request.method === 'GET' || request.method === 'HEAD'
          ? undefined
          : await request.clone().text(),
      credentials: 'include',
    });
    retried.headers.set(RETRY_MARK, '1');
    // If the original was a mutating call the CSRF cookie may have
    // rotated alongside the session — read it fresh.
    const method = retried.method.toUpperCase();
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
      const token = readCookie(CSRF_COOKIE);
      if (token) retried.headers.set(CSRF_HEADER, token);
    }
    // A replay that still 401s is handled by the global, code-aware
    // QueryCache/MutationCache onError handler (main.tsx): it redirects
    // only for auth.* codes, so an authz (permission) 401 is left alone.
    return fetch(retried);
  },
});

export const api = baseClient;
export default api;
