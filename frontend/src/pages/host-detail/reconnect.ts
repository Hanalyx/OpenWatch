import { apiErrorMessage } from '@/api/errors';

// The note the Connectivity card's Reconnect button shows when
// POST /api/v1/hosts/{id}/discovery:run fails. A 502 means the SSH dial or
// the credential failed. Anything else shows the server's own reason, for
// example a 409 discovery.in_progress ("a discovery for this host is already
// queued or running"), and falls back to the status only when the response
// carried no message. Spec frontend-host-detail C-11, AC-48.
export const RECONNECT_UNREACHABLE = 'Host unreachable (SSH or credential failed)';

export function reconnectFailureMessage(status: number, error: unknown): string {
  if (status === 502) return RECONNECT_UNREACHABLE;
  return apiErrorMessage(error, `Reconnect failed (HTTP ${status})`);
}
