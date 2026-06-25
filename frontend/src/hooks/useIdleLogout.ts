import { useEffect, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api, onAuthFailure } from '@/api/client';
import { useAuthStore } from '@/store/useAuthStore';

// useIdleLogout — client-side inactivity timeout.
//
// WHY this exists (and why the server-side window is not enough): the backend
// enforces the configured idle window in internal/identity/sessions.go, but it
// measures "idle" by HTTP request activity. The SPA polls several endpoints
// every 15-60s and holds a persistent SSE stream, so every background request
// slides the server's expires_at forward — the session never goes idle even
// when the human has walked away. This hook measures REAL user activity
// (pointer / keyboard / touch), so the Authentication-policy "Idle timeout"
// setting actually terminates an unattended session and returns to /login.
//
// It reads the operator-configured window from GET /api/v1/auth-policy and
// falls back to the backend default (15 min) when that can't be read — failing
// toward enforcing a timeout rather than leaving the session open forever.
//
// Mounted once from AppFrame (the authenticated shell), so it is armed only
// while a user is signed in.
//
// Spec: frontend-session-idle.

// Matches DefaultSessionInactivityWindow in internal/identity/sessions.go.
const DEFAULT_IDLE_SECONDS = 15 * 60;

// Shared "last user activity" timestamp (epoch ms) across tabs of the same
// origin. Activity in any tab keeps every tab's session alive; without this a
// background tab would log the user out while they work in another.
export const ACTIVITY_STORAGE_KEY = 'ow.session.lastActivity';

// How often we re-check elapsed idle time. This is the granularity of the
// check, not the timeout itself.
const CHECK_INTERVAL_MS = 5_000;

// Throttle how often raw activity events rewrite the shared timestamp so a
// burst of mousemove events is cheap.
const ACTIVITY_WRITE_THROTTLE_MS = 1_000;

// Real user-input signals only. Deliberately NOT HTTP/visibility driven — the
// whole point is to ignore background traffic and tab focus.
const ACTIVITY_EVENTS: readonly string[] = [
  'mousemove',
  'mousedown',
  'keydown',
  'wheel',
  'scroll',
  'touchstart',
];

function readLastActivity(fallback: number): number {
  try {
    const raw = localStorage.getItem(ACTIVITY_STORAGE_KEY);
    const n = raw ? Number(raw) : NaN;
    if (Number.isFinite(n)) return n;
  } catch {
    /* localStorage unavailable (private mode / SSR) — use the fallback */
  }
  return fallback;
}

export function useIdleLogout(): void {
  const identity = useAuthStore((s) => s.identity);

  const { data: policy } = useQuery({
    queryKey: ['auth-policy'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/auth-policy');
      if (error || !response.ok) throw new Error('failed to load auth policy');
      return data!;
    },
    // The window changes rarely; one fetch per shell mount is plenty. A short
    // refetch interval would itself be background traffic, which is the very
    // thing this hook exists to stop counting as activity.
    staleTime: 5 * 60 * 1000,
  });

  const idleSeconds = policy?.session_idle_timeout_seconds ?? DEFAULT_IDLE_SECONDS;

  // Hold the latest window in a ref so a policy change does not tear down and
  // rebuild the listeners/interval.
  const idleMsRef = useRef(idleSeconds * 1000);
  idleMsRef.current = idleSeconds * 1000;

  useEffect(() => {
    // Arm only while authenticated.
    if (!identity) return;

    let lastWrite = 0;
    let loggingOut = false;

    const markActivity = (): void => {
      const t = Date.now();
      if (t - lastWrite < ACTIVITY_WRITE_THROTTLE_MS) return;
      lastWrite = t;
      try {
        localStorage.setItem(ACTIVITY_STORAGE_KEY, String(t));
      } catch {
        /* ignore — readLastActivity falls back to lastWrite via the closure */
      }
    };

    const logout = async (): Promise<void> => {
      if (loggingOut) return;
      loggingOut = true;
      // Best-effort server-side revoke so the cookie session is actually dead,
      // not merely hidden from this tab. Redirect regardless of the result.
      try {
        await api.POST('/api/v1/auth/logout');
      } catch {
        /* ignore — we still clear the client and redirect */
      }
      try {
        localStorage.removeItem(ACTIVITY_STORAGE_KEY);
      } catch {
        /* ignore */
      }
      onAuthFailure();
    };

    const check = (): void => {
      if (loggingOut) return;
      const last = readLastActivity(lastWrite || Date.now());
      if (Date.now() - last >= idleMsRef.current) {
        void logout();
      }
    };

    // Seed an initial timestamp so a freshly-mounted shell is not treated as
    // already idle.
    lastWrite = 0;
    markActivity();

    for (const ev of ACTIVITY_EVENTS) {
      window.addEventListener(ev, markActivity, { passive: true });
    }
    const interval = window.setInterval(check, CHECK_INTERVAL_MS);

    return () => {
      window.clearInterval(interval);
      for (const ev of ACTIVITY_EVENTS) {
        window.removeEventListener(ev, markActivity);
      }
    };
  }, [identity]);
}
