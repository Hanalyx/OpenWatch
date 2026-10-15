// @spec frontend-host-detail
//
// The Connectivity card's Reconnect note on failure: a 502 is a credential
// or SSH failure; any other failure shows the server's own reason.

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { RECONNECT_UNREACHABLE, reconnectFailureMessage } from '@/pages/host-detail/reconnect';

const PAGE_SRC = readFileSync(resolve(process.cwd(), 'src/pages/HostDetailPage.tsx'), 'utf8');

const envelope = (code: string, humanMessage: string) => ({
  error: { code, human_message: humanMessage, category: 'client', retryable: true },
});

describe('frontend-host-detail v1.13.0 — Reconnect failure note', () => {
  // @ac AC-48
  test('frontend-host-detail/AC-48 — a 409 shows the server reason, not the status', () => {
    const note = reconnectFailureMessage(
      409,
      envelope('discovery.in_progress', 'a discovery for this host is already queued or running'),
    );
    expect(note).toBe('a discovery for this host is already queued or running');
    expect(note).not.toContain('409');
  });

  // @ac AC-48
  test('frontend-host-detail/AC-48 — 502 stays a credential or SSH failure, whatever the body says', () => {
    expect(
      reconnectFailureMessage(502, envelope('discovery.dial_failed', 'dial tcp: timeout')),
    ).toBe(RECONNECT_UNREACHABLE);
    expect(reconnectFailureMessage(502, undefined)).toBe(RECONNECT_UNREACHABLE);
  });

  // @ac AC-48
  test('frontend-host-detail/AC-48 — a failure with no message falls back to the status', () => {
    expect(reconnectFailureMessage(500, undefined)).toBe('Reconnect failed (HTTP 500)');
    expect(reconnectFailureMessage(500, {})).toBe('Reconnect failed (HTTP 500)');
  });

  // @ac AC-48
  test('frontend-host-detail/AC-48 — the Reconnect button uses it for every failure', () => {
    expect(PAGE_SRC).toContain(
      "const { response, error } = await api.POST('/api/v1/hosts/{id}/discovery:run'",
    );
    expect(PAGE_SRC).toContain('throw new Error(reconnectFailureMessage(response.status, error))');
    expect(PAGE_SRC).not.toContain('Reconnect failed (${response.status})');
  });
});
