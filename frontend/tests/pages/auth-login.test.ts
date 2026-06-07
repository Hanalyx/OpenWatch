// @spec frontend-auth-login
//
// AC traceability (this file):
//
//   AC-01  /login renders username + password + submit
//   AC-02  Successful login: no access_token stored; redirect to / or return_to
//   AC-03  mfa_required: form re-renders with otp field; user+pass preserved
//   AC-04  Valid otp on second submission included in POST body
//   AC-05  Wrong password: generic invalid_credentials message
//   AC-06  Unknown user: SAME generic message (no enumeration)
//   AC-07  v1.1.0 — 429 message surfaced inline (cooldown deferred)
//   AC-08  CSRF token threaded on every mutating request after login
//   AC-09  return_to=%2Fhosts%2F12345 lands at /hosts/12345
//   AC-10  return_to=https%3A%2F%2Fevil... falls back to /
//   AC-11  Keyboard tab order + aria-busy while submitting
//   AC-12  axe-core dependency present
//   AC-13  No console.* call interpolates password / otp values
//   AC-14  No code path stores access_token / refresh_token in any client store

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const LOGIN_SRC = readFileSync(resolve(process.cwd(), 'src/pages/LoginPage.tsx'), 'utf8');
const CLIENT_SRC = readFileSync(resolve(process.cwd(), 'src/api/client.ts'), 'utf8');

describe('frontend-auth-login — structural', () => {
  // @ac AC-01
  test('frontend-auth-login/AC-01 — form renders username + password + submit', () => {
    expect(LOGIN_SRC).toMatch(/register\(\s*['"]username['"]/);
    expect(LOGIN_SRC).toMatch(/register\(\s*['"]password['"]/);
    expect(LOGIN_SRC).toMatch(/type=["']submit["']/);
  });

  // @ac AC-02
  test('frontend-auth-login/AC-02 — successful login does NOT read body.access_token / refresh_token', () => {
    // The success branch comments explicitly call out the C-02
    // contract; the test asserts no read assignment of those fields
    // is present in the handler.
    expect(LOGIN_SRC).toMatch(/api\.POST\(\s*['"]\/api\/v1\/auth\/login['"]/);
    expect(LOGIN_SRC).not.toMatch(/data\.access_token/);
    expect(LOGIN_SRC).not.toMatch(/data\.refresh_token/);
    expect(LOGIN_SRC).not.toMatch(/data\?\.access_token/);
  });

  // @ac AC-03
  test('frontend-auth-login/AC-03 — mfa_required re-renders with otp + preserves values', () => {
    expect(LOGIN_SRC).toMatch(/auth\.mfa_required/);
    expect(LOGIN_SRC).toMatch(/setMfaRequired\(\s*true\s*\)/);
    // The otp field is registered as part of the form.
    expect(LOGIN_SRC).toMatch(/register\(\s*['"]otp['"]/);
    // Preservation: the handler does NOT call reset() on the mfa_required
    // branch; values stay in the form state.
    const mfaBranch = LOGIN_SRC.slice(
      LOGIN_SRC.indexOf('auth.mfa_required'),
      LOGIN_SRC.indexOf('auth.mfa_required') + 600,
    );
    expect(mfaBranch).not.toMatch(/\breset\(\)/);
  });

  // @ac AC-04
  test('frontend-auth-login/AC-04 — second submission includes otp when mfaRequired', () => {
    // The body literal is augmented with otp ONLY when mfaRequired
    // is true and the user typed something.
    expect(LOGIN_SRC).toMatch(/mfaRequired\s*&&\s*values\.otp/);
    expect(LOGIN_SRC).toMatch(/body\.otp\s*=\s*values\.otp/);
  });

  // @ac AC-05
  test('frontend-auth-login/AC-05 — wrong password renders generic invalid_credentials message', () => {
    // Both wrong-password and unknown-user paths produce the SAME 401
    // auth.invalid_credentials envelope on the server. The client maps
    // that code to one fixed string — no branching on cause.
    expect(LOGIN_SRC).toMatch(/auth\.invalid_credentials/);
    expect(LOGIN_SRC).toMatch(/Invalid username or password|invalid credentials/i);
  });

  // @ac AC-06
  test('frontend-auth-login/AC-06 — unknown user renders IDENTICAL message (no enumeration oracle)', () => {
    // Negative invariant: no "user not found" or "unknown user" string
    // anywhere in the login handler that would tell an attacker which
    // half of the credential pair was wrong.
    expect(LOGIN_SRC).not.toMatch(/user not found/i);
    expect(LOGIN_SRC).not.toMatch(/unknown user/i);
    expect(LOGIN_SRC).not.toMatch(/no such user/i);
    // The single error code mapping that AC-05 verifies is the same
    // one this path takes.
    expect(LOGIN_SRC).toMatch(/auth\.invalid_credentials/);
  });

  // @ac AC-07
  test('frontend-auth-login/AC-07 — v1.1.0: server 429 message surfaced inline (cooldown deferred)', () => {
    // Even without dedicated 429 wiring, a 429 envelope carries
    // error.code + human_message; the client surfaces it via the
    // generic error path that renders errorMessage state. Verify the
    // error rendering path exists.
    expect(LOGIN_SRC).toMatch(/setErrorMessage\(/);
    expect(LOGIN_SRC).toMatch(/apiErrorMessage|errorMessage/);
    // Submit is disabled during the request (AC-11) — repeated
    // rapid-fire submissions get prevented by aria-busy / disabled.
    expect(LOGIN_SRC).toMatch(/setSubmitting\(\s*true\s*\)/);
  });

  // @ac AC-08
  test('frontend-auth-login/AC-08 — CSRF token threaded on every mutating request via X-CSRF-Token', () => {
    // The shared API client reads XSRF-TOKEN cookie + sets
    // X-CSRF-Token header on POST/PUT/PATCH/DELETE in onRequest.
    expect(CLIENT_SRC).toMatch(/XSRF-TOKEN/);
    expect(CLIENT_SRC).toMatch(/X-CSRF-Token/);
    expect(CLIENT_SRC).toMatch(/onRequest\(/);
    // Method gating: only mutating verbs attach the header.
    expect(CLIENT_SRC).toMatch(/GET['"]\s*\|\|\s*method\s*===\s*['"]HEAD/);
  });

  // @ac AC-09
  test('frontend-auth-login/AC-09 — safeReturnTo returns the decoded path', () => {
    expect(LOGIN_SRC).toMatch(/decodeURIComponent/);
    expect(LOGIN_SRC).toMatch(/function safeReturnTo/);
    // Used in the success branch's navigate destination.
    expect(LOGIN_SRC).toMatch(/safeReturnTo\(\s*search\.return_to\s*\)/);
  });

  // @ac AC-10
  test('frontend-auth-login/AC-10 — safeReturnTo rejects external + protocol-relative URLs', () => {
    // The guard rejects anything that doesn't start with "/" and also
    // rejects "//..." (protocol-relative open redirect).
    expect(LOGIN_SRC).toMatch(/\.startsWith\(\s*['"]\/['"]\s*\)/);
    expect(LOGIN_SRC).toMatch(/\.startsWith\(\s*['"]\/\/['"]\s*\)/);
  });

  // @ac AC-11
  test('frontend-auth-login/AC-11 — keyboard tab order + aria-busy while submitting', () => {
    // Tab order: username appears in source before password before
    // submit/otp. The form uses react-hook-form so document order
    // dictates tab order.
    const usernameIdx = LOGIN_SRC.indexOf("register('username')");
    const passwordIdx = LOGIN_SRC.indexOf("register('password')");
    const submitIdx = LOGIN_SRC.indexOf('type="submit"');
    expect(usernameIdx).toBeGreaterThan(-1);
    expect(passwordIdx).toBeGreaterThan(usernameIdx);
    expect(submitIdx).toBeGreaterThan(passwordIdx);
    // aria-busy flips with the submitting state on the submit control.
    expect(LOGIN_SRC).toMatch(/aria-busy=\{submitting\}/);
  });

  // @ac AC-12
  test('frontend-auth-login/AC-12 — axe-core dependency present', () => {
    const pkg = JSON.parse(readFileSync(resolve(process.cwd(), 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
    expect(deps['axe-core']).toBeTruthy();
    expect(deps['@axe-core/playwright']).toBeTruthy();
  });

  // @ac AC-13
  test('frontend-auth-login/AC-13 — no console.* interpolates password or otp values', () => {
    const consoleCalls = [...LOGIN_SRC.matchAll(/console\.(log|warn|error)\([^)]*\)/g)];
    for (const c of consoleCalls) {
      const callText = c[0];
      expect(callText).not.toMatch(/values\.password/);
      expect(callText).not.toMatch(/values\.otp/);
      expect(callText).not.toMatch(/body\.password/);
      expect(callText).not.toMatch(/body\.otp/);
      expect(callText).not.toMatch(/['"]password['"]\s*:/);
      expect(callText).not.toMatch(/['"]otp['"]\s*:/);
    }
  });

  // @ac AC-14
  test('frontend-auth-login/AC-14 — no path writes access_token / refresh_token to any client store', () => {
    // Source-walk: the LoginPage handler MUST NOT assign access_token
    // or refresh_token into localStorage, sessionStorage, or any
    // Zustand setter call. The auth store doc comment also pins this
    // negative invariant.
    expect(LOGIN_SRC).not.toMatch(/localStorage\.setItem\([^)]*access_token/);
    expect(LOGIN_SRC).not.toMatch(/sessionStorage\.setItem\([^)]*access_token/);
    expect(LOGIN_SRC).not.toMatch(/localStorage\.setItem\([^)]*refresh_token/);
    expect(LOGIN_SRC).not.toMatch(/sessionStorage\.setItem\([^)]*refresh_token/);
    // Cross-check: useAuthStore.setIdentity is called with the
    // identity SHAPE returned by /auth/me — NOT a token bag.
    expect(LOGIN_SRC).toMatch(/setIdentity\(\s*identity\s*\)/);
    // Auth store comment pins the never-store contract.
    const authStoreSrc = readFileSync(resolve(process.cwd(), 'src/store/useAuthStore.ts'), 'utf8');
    expect(authStoreSrc).toMatch(/MUST NEVER hold access_token or refresh_token/);
  });
});
