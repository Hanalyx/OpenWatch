// openapi-fetch returns the raw response body as `error` for non-2xx
// responses — it is the parsed JSON envelope, not an Error instance.
// The canonical envelope (see openapi.yaml -> ErrorEnvelope) carries
// the operator-visible reason as `human_message`. Earlier consumers
// looked for `error.message` and silently fell back to "Failed to X
// (HTTP 400)", which hid the real cause from users.
//
// This module centralizes the lookup so every page surfaces the
// backend's message instead of a generic fallback.

interface EnvelopeShape {
  error?: {
    code?: string;
    human_message?: string;
    // Tolerated for any rare endpoint that still emits `message`. The
    // canonical envelope uses `human_message`.
    message?: string;
  };
}

// apiErrorMessage extracts the most useful human-readable string from an
// openapi-fetch error body. Order of preference:
//   1. error.human_message (canonical ErrorEnvelope)
//   2. error.message       (legacy / non-conforming endpoints)
//   3. error.code          (a code is still better than nothing)
//   4. fallback            (caller-supplied last resort)
export function apiErrorMessage(error: unknown, fallback: string): string {
  if (error && typeof error === 'object') {
    const env = error as EnvelopeShape;
    if (env.error?.human_message) return env.error.human_message;
    if (env.error?.message) return env.error.message;
    if (env.error?.code) return env.error.code;
  }
  if (typeof error === 'string' && error.length > 0) return error;
  return fallback;
}

// formatApiError combines the HTTP status with the extracted detail so
// the user always sees the status code, then the backend's reason. Use
// when the consumer wants a single "HTTP 400 — reason" string.
export function formatApiError(status: number, error: unknown): string {
  const detail = apiErrorMessage(error, '');
  return detail ? `HTTP ${status} — ${detail}` : `HTTP ${status}`;
}
