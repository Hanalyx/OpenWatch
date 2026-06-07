import { describe, expect, test } from 'vitest';
import { apiErrorMessage, formatApiError } from '@/api/errors';

describe('api/errors — apiErrorMessage', () => {
  test('reads human_message from the canonical ErrorEnvelope', () => {
    const envelope = {
      error: {
        code: 'credentials.invalid_key',
        human_message:
          'ssh: key below NIST SP 800-57 minimum strength: RSA 1024 bits, minimum 2048',
      },
    };
    expect(apiErrorMessage(envelope, 'fallback')).toBe(
      'ssh: key below NIST SP 800-57 minimum strength: RSA 1024 bits, minimum 2048',
    );
  });

  test('falls back to error.message when human_message is absent', () => {
    const envelope = { error: { code: 'legacy.error', message: 'legacy reason' } };
    expect(apiErrorMessage(envelope, 'fallback')).toBe('legacy reason');
  });

  test('falls back to error.code when no message present', () => {
    const envelope = { error: { code: 'authz.permission_denied' } };
    expect(apiErrorMessage(envelope, 'fallback')).toBe('authz.permission_denied');
  });

  test('returns the fallback when the body is empty or unrecognized', () => {
    expect(apiErrorMessage(undefined, 'fallback')).toBe('fallback');
    expect(apiErrorMessage(null, 'fallback')).toBe('fallback');
    expect(apiErrorMessage({}, 'fallback')).toBe('fallback');
    expect(apiErrorMessage({ unrelated: 'shape' }, 'fallback')).toBe('fallback');
  });

  test('accepts a bare string', () => {
    expect(apiErrorMessage('boom', 'fallback')).toBe('boom');
  });
});

describe('api/errors — formatApiError', () => {
  test('prefixes the status and includes the extracted detail', () => {
    const envelope = {
      error: { code: 'validation.field_required', human_message: 'name is required' },
    };
    expect(formatApiError(400, envelope)).toBe('HTTP 400 — name is required');
  });

  test('omits the dash when no detail is available', () => {
    expect(formatApiError(500, undefined)).toBe('HTTP 500');
    expect(formatApiError(503, {})).toBe('HTTP 503');
  });
});
