import createClient from 'openapi-fetch';
import type { paths } from './schema';

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
// Spec: frontend-auth-login C-01, C-06.

const CSRF_COOKIE = 'XSRF-TOKEN';
const CSRF_HEADER = 'X-CSRF-Token';

function readCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  const target = name + '=';
  for (const piece of document.cookie.split(';')) {
    const c = piece.trim();
    if (c.startsWith(target)) return decodeURIComponent(c.slice(target.length));
  }
  return null;
}

// No baseUrl — the OpenAPI paths already start with /api/v1. Vite
// proxies /api/* to the Go backend in dev; in prod the SPA is served
// from the same origin so /api/* hits the backend directly.
const baseClient = createClient<paths>({
  credentials: 'include',
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
});

export const api = baseClient;
export default api;
