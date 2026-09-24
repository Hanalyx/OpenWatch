// Messages for the sso_error values the SSO callback redirects with.
//
// `unconfirmed` is not a failure. The server could not confirm whether
// the sign-in transaction committed, so a session may or may not exist.
// Its message must not say sign-in failed, and must not tell the user to
// retry as if nothing happened. Spec frontend-auth-login C-12,
// system-sso C-06.
const SSO_ERROR_TEXT: Record<string, string> = {
  denied: 'Single sign-on was cancelled or denied by the provider.',
  signin: 'Single sign-on failed. Please try again or use your password.',
  provider: 'That sign-on provider is unavailable. Please try again later.',
  invalid: 'The sign-on response was invalid. Please try again.',
  session: 'Could not establish a session after sign-on. Please try again.',
  state: 'Your sign-on attempt expired. Please try again.',
  unavailable: 'Single sign-on is not configured for this workspace.',
  unconfirmed:
    'We could not confirm whether you were signed in. Reload this page to check before signing in again.',
};

const SSO_ERROR_FALLBACK = 'Single sign-on failed.';

// ssoErrorMessage returns the message for an sso_error value, or null
// when there is none.
export function ssoErrorMessage(code: string | undefined): string | null {
  if (!code) {
    return null;
  }
  return SSO_ERROR_TEXT[code] ?? SSO_ERROR_FALLBACK;
}
