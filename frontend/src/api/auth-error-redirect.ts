// Global auth-error → logout redirect.
//
// The api-client middleware (client.ts) handles the transparent 401 →
// refresh-cookie retry, and redirects to /login when refresh itself
// fails. But that only covers requests whose failure flows back through
// that middleware path. An expired session can also surface as a query
// or mutation error the component would otherwise render in place.
//
// This handler is wired as the QueryClient's QueryCache + MutationCache
// onError (main.tsx), so EVERY failed query and mutation passes through
// it. When the error envelope carries an authentication-failure code we
// clear the session and navigate to /login — the user is never left
// staring at a raw error envelope after their session expires.
//
// It is code-aware: only auth.* "you are not authenticated" codes trigger
// the redirect. An authz (permission) failure is NOT a session problem
// and must not log the user out.

import { onAuthFailure } from './client';
import { apiErrorCode } from './errors';

export const AUTH_FAILURE_CODES = new Set([
  'auth.session_invalid',
  'auth.session_expired',
  'auth.required',
]);

// redirectOnAuthError sends the user to /login (clearing identity) when
// `error` is an ErrorEnvelope with an authentication-failure code. A
// no-op for every other error so component-level handling still applies.
export function redirectOnAuthError(error: unknown): void {
  const code = apiErrorCode(error);
  if (code && AUTH_FAILURE_CODES.has(code)) {
    onAuthFailure();
  }
}
