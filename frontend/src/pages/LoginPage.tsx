import { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useNavigate, useSearch } from '@tanstack/react-router';
import api from '@/api/client';
import { useAuthStore, type Identity } from '@/store/useAuthStore';
import { RadarField } from '@/components/RadarField';
import { useVersion } from '@/hooks/useVersion';
import owIcon from '@/assets/openwatch-icon.png';

// Login page — frontend-auth-login spec.
//
// Per app/docs/frontend_architecture_adr.md D-08, login uses session
// cookies, not localStorage tokens. The body's access_token /
// refresh_token are IGNORED. On success we re-fetch /auth/me to
// populate the identity store, then redirect to return_to (or
// /dashboard, the authenticated home — "/" is now the public homepage).
//
// The visual treatment (Radar backdrop, console card) is ported from
// docs/engineering/prototypes/openwatch-v1/login.html. The Request
// access and Forgot password affordances have no backend endpoint yet,
// so they surface an honest "contact your administrator" note rather
// than a form that fakes a submission.

const schema = z.object({
  username: z.string().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required'),
  otp: z.string().optional(),
});

type FormShape = z.infer<typeof schema>;

interface LoginSearch {
  return_to?: string;
  sso_error?: string;
}

interface SSOOption {
  id: string;
  name: string;
}

const SSO_ERROR_TEXT: Record<string, string> = {
  denied: 'Single sign-on was cancelled or denied by the provider.',
  signin: 'Single sign-on failed. Please try again or use your password.',
  provider: 'That sign-on provider is unavailable. Please try again later.',
  invalid: 'The sign-on response was invalid. Please try again.',
  session: 'Could not establish a session after sign-on. Please try again.',
  state: 'Your sign-on attempt expired. Please try again.',
  unavailable: 'Single sign-on is not configured for this workspace.',
};

// Post-login default destination. "/" is the public homepage, so an
// authenticated user falls back to /dashboard, not /.
const DEFAULT_DEST = '/dashboard';

function safeReturnTo(raw: string | undefined): string {
  // Open-redirect prevention (C-07 / AC-10): only allow paths that
  // begin with "/" and not "//" (which is protocol-relative).
  if (!raw) return DEFAULT_DEST;
  let decoded: string;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    return DEFAULT_DEST;
  }
  if (!decoded.startsWith('/') || decoded.startsWith('//')) return DEFAULT_DEST;
  return decoded;
}

const SCAN = 'rgb(96,212,228)';

export function LoginPage() {
  const navigate = useNavigate();
  const search = useSearch({ strict: false }) as LoginSearch;
  const setIdentity = useAuthStore((s) => s.setIdentity);
  const identity = useAuthStore((s) => s.identity);
  const authLoading = useAuthStore((s) => s.loading);
  const version = useVersion();

  const [mfaRequired, setMfaRequired] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(
    search.sso_error ? (SSO_ERROR_TEXT[search.sso_error] ?? 'Single sign-on failed.') : null,
  );
  const [ssoProviders, setSsoProviders] = useState<SSOOption[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  // "Keep me signed in" is a UI preference only: the server-set session
  // cookie governs persistence, and login C-01 forbids extra fields on
  // the first submission, so this flag is not sent. Kept for parity with
  // the design; wires to a backend "remember" option when one ships.
  const [rememberMe, setRememberMe] = useState(true);
  // accessNote toggles the honest "contact your admin" note shared by
  // the Forgot password + Request access affordances (no backend yet).
  const [accessNote, setAccessNote] = useState(false);

  // Auto-redirect when a session cookie is already valid — bootstrapAuth
  // populates identity on app boot if /auth/me returns 200. If the user
  // arrives at /login already authenticated, send them straight to
  // return_to (or /dashboard).
  useEffect(() => {
    if (!authLoading && identity) {
      const dest = safeReturnTo(search.return_to);
      navigate({ to: dest, replace: true });
    }
  }, [authLoading, identity, navigate, search.return_to]);

  // Fetch the enabled SSO providers for the "Sign in with …" buttons. This
  // is an anonymous endpoint returning only {id, name}; an empty list (or a
  // failure) simply renders no buttons.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const { data, response } = await api.GET('/api/v1/sso/providers/enabled');
        if (!cancelled && response.ok && data) setSsoProviders(data.providers);
      } catch {
        /* no SSO buttons */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // SSO sign-in is a full-page navigation to the backend redirect endpoint
  // (it 302s to the IdP), not a SPA route. Forward the return_to through.
  const startSSO = (providerId: string) => {
    const rt = encodeURIComponent(safeReturnTo(search.return_to));
    window.location.href = `/api/v1/auth/sso/${providerId}/login?return_to=${rt}`;
  };

  const { register, handleSubmit, setValue, formState } = useForm<FormShape>({
    resolver: zodResolver(schema),
    mode: 'onTouched',
  });

  const onSubmit = async (values: FormShape) => {
    setErrorMessage(null);
    setSubmitting(true);
    try {
      const body: { username: string; password: string; otp?: string } = {
        username: values.username,
        password: values.password,
      };
      if (mfaRequired && values.otp) body.otp = values.otp;

      const {
        data: loginData,
        response,
        error,
      } = await api.POST('/api/v1/auth/login', {
        body,
      });

      if (response.ok) {
        // Soft require-MFA enforcement: the session is issued, but workspace
        // policy requires this user to enroll in MFA before doing anything
        // else. Land them on the profile page where enrollment lives.
        const enrollmentRequired = !!(
          loginData as { mfa_enrollment_required?: boolean } | undefined
        )?.mfa_enrollment_required;
        // IMPORTANT (C-02): we do NOT read access_token / refresh_token
        // from the response body. Session cookie is the credential.
        const { data: me } = await api.GET('/api/v1/auth/me');
        if (me) {
          const meTyped = me as {
            id: string;
            username: string;
            email: string;
            role: string;
            mfa_enabled?: boolean;
          };
          const nextIdentity: Identity = {
            id: meTyped.id,
            username: meTyped.username,
            email: meTyped.email,
            role: meTyped.role,
            permissions:
              meTyped.role === 'admin'
                ? [
                    'host:read',
                    'host:write',
                    'host:delete',
                    'credential:read',
                    'credential:write',
                    'scan:read',
                    'audit:read',
                    'notification:read',
                    'notification:write',
                    'notification:delete',
                    'notification:test',
                    'token:read',
                    'token:write',
                    'token:delete',
                    'system:auth_policy_read',
                    'system:auth_policy_write',
                    'admin:sso_provider',
                    'admin',
                  ]
                : ['host:read', 'scan:read'],
            mfaEnabled: !!meTyped.mfa_enabled,
          };
          setIdentity(nextIdentity);
        }
        if (enrollmentRequired) {
          navigate({ to: '/settings/profile' });
          return;
        }
        const dest = safeReturnTo(search.return_to);
        navigate({ to: dest });
        return;
      }

      const err = error as { error?: { code?: string; message?: string } } | undefined;
      const code = err?.error?.code;
      if (code === 'auth.mfa_required') {
        setMfaRequired(true);
        setErrorMessage('Enter the 6-digit code from your authenticator.');
        return;
      }
      if (code === 'auth.mfa_invalid') {
        setValue('otp', '');
        setErrorMessage('Invalid authenticator code.');
        return;
      }
      if (code === 'auth.invalid_credentials') {
        setValue('password', '');
        setErrorMessage('Invalid username or password.');
        return;
      }
      setErrorMessage('Sign-in failed. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  // While bootstrapAuth is still resolving, or if we already have an
  // identity (the useEffect above will fire), render nothing — the
  // form is only useful for anonymous visitors.
  if (authLoading || identity) {
    return null;
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        overflow: 'hidden',
        background: 'var(--ow-bg-0)',
        color: 'var(--ow-fg-0)',
      }}
    >
      <title>Sign in · OpenWatch</title>
      <style>{`
        @keyframes ow-pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
        @media (prefers-reduced-motion: reduce) { .ow-pulse { animation: none !important; } }
      `}</style>

      <RadarField dim />

      {/* vignette + scanlines — pure decoration */}
      <div
        aria-hidden="true"
        style={{
          position: 'fixed',
          inset: 0,
          pointerEvents: 'none',
          zIndex: 2,
          background:
            'radial-gradient(ellipse 90% 80% at 50% 45%, transparent 30%, rgba(3,5,9,0.7) 72%, rgba(3,5,9,0.96) 100%)',
        }}
      />
      <div
        aria-hidden="true"
        style={{
          position: 'fixed',
          inset: 0,
          pointerEvents: 'none',
          zIndex: 3,
          opacity: 0.3,
          mixBlendMode: 'multiply',
          background:
            'repeating-linear-gradient(to bottom, transparent 0 2px, rgba(0,0,0,0.18) 2px 3px)',
        }}
      />

      {/* top brand bar */}
      <div
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          zIndex: 6,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '30px 44px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div
            aria-hidden="true"
            style={{
              width: 34,
              height: 34,
              borderRadius: 9,
              background: '#fff',
              display: 'grid',
              placeItems: 'center',
              overflow: 'hidden',
              boxShadow: '0 0 0 1px rgba(255,255,255,0.10), 0 4px 16px rgba(0,0,0,0.35)',
            }}
          >
            <img
              src={owIcon}
              alt=""
              style={{ width: '84%', height: '84%', objectFit: 'contain', display: 'block' }}
            />
          </div>
          <span style={{ fontWeight: 700, letterSpacing: '0.02em', fontSize: 16 }}>OpenWatch</span>
        </div>
        <span
          style={{
            fontSize: 11.5,
            color: 'var(--ow-fg-2)',
            border: '1px solid var(--ow-line)',
            borderRadius: 999,
            padding: '5px 11px',
            display: 'inline-flex',
            alignItems: 'center',
            gap: 7,
            background: 'rgba(10,14,20,0.5)',
          }}
        >
          <span
            className="ow-pulse"
            aria-hidden="true"
            style={{
              width: 6,
              height: 6,
              borderRadius: '50%',
              background: SCAN,
              boxShadow: `0 0 8px ${SCAN}`,
              animation: 'ow-pulse 1.8s ease-in-out infinite',
            }}
          />
          <span style={{ color: 'var(--ow-fg-1)', fontWeight: 600 }}>Eyrie</span>
          {version && <span>· v{version}</span>}
        </span>
      </div>

      {/* sign-in card */}
      <div
        style={{
          position: 'fixed',
          inset: 0,
          zIndex: 5,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: 24,
        }}
      >
        <form
          onSubmit={handleSubmit(onSubmit)}
          noValidate
          aria-label="Sign in"
          style={{
            width: 420,
            maxWidth: '100%',
            background: 'var(--ow-bg-1)',
            border: '1px solid var(--ow-line)',
            borderRadius: 16,
            boxShadow: '0 30px 80px rgba(0,0,0,0.55)',
            padding: '34px 34px 28px',
          }}
        >
          <div
            style={{
              fontFamily: 'var(--ow-font-mono, monospace)',
              fontSize: 11,
              letterSpacing: '0.28em',
              textTransform: 'uppercase',
              color: SCAN,
            }}
          >
            Secure console access
          </div>
          <h1
            style={{
              fontSize: 26,
              fontWeight: 700,
              letterSpacing: '-0.02em',
              margin: '12px 0 6px',
            }}
          >
            Sign in to OpenWatch
          </h1>
          <p
            style={{ color: 'var(--ow-fg-2)', fontSize: 13.5, margin: '0 0 24px', lineHeight: 1.5 }}
          >
            Authenticate to enter the Eyrie console and view your fleet.
          </p>

          <label style={{ display: 'flex', flexDirection: 'column', gap: 7, marginBottom: 14 }}>
            <span style={{ fontSize: 12, color: 'var(--ow-fg-2)', fontWeight: 500 }}>Username</span>
            <input
              type="text"
              autoComplete="username"
              autoFocus
              disabled={submitting}
              {...register('username')}
              style={inputStyle}
            />
            {formState.errors.username && (
              <span role="alert" style={errorStyle}>
                {formState.errors.username.message}
              </span>
            )}
          </label>

          <label style={{ display: 'flex', flexDirection: 'column', gap: 7, marginBottom: 14 }}>
            <span style={{ fontSize: 12, color: 'var(--ow-fg-2)', fontWeight: 500 }}>Password</span>
            <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <input
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                disabled={submitting}
                {...register('password')}
                style={{ ...inputStyle, paddingRight: 40, width: '100%' }}
              />
              <button
                type="button"
                onClick={() => setShowPassword((v) => !v)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
                aria-pressed={showPassword}
                style={{
                  position: 'absolute',
                  right: 6,
                  height: 30,
                  width: 30,
                  display: 'grid',
                  placeItems: 'center',
                  background: 'transparent',
                  border: 0,
                  color: 'var(--ow-fg-3)',
                  cursor: 'pointer',
                }}
              >
                <svg
                  width="16"
                  height="16"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                >
                  <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
              </button>
            </div>
            {formState.errors.password && (
              <span role="alert" style={errorStyle}>
                {formState.errors.password.message}
              </span>
            )}
          </label>

          {mfaRequired && (
            <label style={{ display: 'flex', flexDirection: 'column', gap: 7, marginBottom: 14 }}>
              <span style={{ fontSize: 12, color: 'var(--ow-fg-2)', fontWeight: 500 }}>
                Authenticator code
              </span>
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                autoFocus
                disabled={submitting}
                {...register('otp')}
                style={inputStyle}
              />
            </label>
          )}

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              margin: '4px 0 20px',
            }}
          >
            <label
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                fontSize: 12.5,
                color: 'var(--ow-fg-1)',
                cursor: 'pointer',
              }}
            >
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                style={{ accentColor: 'var(--ow-info)' }}
              />
              Keep me signed in
            </label>
            <button
              type="button"
              onClick={() => setAccessNote((v) => !v)}
              style={{
                fontSize: 12.5,
                color: SCAN,
                background: 'none',
                border: 0,
                cursor: 'pointer',
                padding: 0,
              }}
            >
              Forgot password?
            </button>
          </div>

          {errorMessage && (
            <div role="alert" style={errorBanner}>
              {errorMessage}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            aria-busy={submitting}
            style={{
              width: '100%',
              height: 48,
              background: 'var(--ow-info)',
              color: 'var(--ow-info-on)',
              border: 0,
              borderRadius: 10,
              fontFamily: 'inherit',
              fontSize: 15,
              fontWeight: 700,
              cursor: submitting ? 'not-allowed' : 'pointer',
              opacity: submitting ? 0.7 : 1,
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 10,
            }}
          >
            {submitting ? 'Signing in…' : 'Enter console'}
          </button>

          {ssoProviders.length > 0 && (
            <>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  margin: '22px 0 16px',
                  color: 'var(--ow-fg-3)',
                  fontSize: 11.5,
                  fontFamily: 'var(--ow-font-mono, monospace)',
                  letterSpacing: '0.06em',
                }}
              >
                <span style={{ flex: 1, height: 1, background: 'var(--ow-line)' }} />
                OR CONTINUE WITH
                <span style={{ flex: 1, height: 1, background: 'var(--ow-line)' }} />
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {ssoProviders.map((p) => (
                  <button
                    key={p.id}
                    type="button"
                    onClick={() => startSSO(p.id)}
                    style={{
                      width: '100%',
                      height: 46,
                      background: 'rgba(10,14,20,0.5)',
                      color: 'var(--ow-fg-0)',
                      border: '1px solid var(--ow-line)',
                      borderRadius: 10,
                      fontFamily: 'inherit',
                      fontWeight: 600,
                      fontSize: 14,
                      cursor: 'pointer',
                    }}
                  >
                    Sign in with {p.name}
                  </button>
                ))}
              </div>
            </>
          )}

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              margin: '22px 0',
              color: 'var(--ow-fg-3)',
              fontSize: 11.5,
              fontFamily: 'var(--ow-font-mono, monospace)',
              letterSpacing: '0.06em',
            }}
          >
            <span style={{ flex: 1, height: 1, background: 'var(--ow-line)' }} />
            NEW TO OPENWATCH
            <span style={{ flex: 1, height: 1, background: 'var(--ow-line)' }} />
          </div>

          <button
            type="button"
            onClick={() => setAccessNote((v) => !v)}
            aria-expanded={accessNote}
            style={{
              width: '100%',
              height: 46,
              background: 'rgba(10,14,20,0.5)',
              color: 'var(--ow-fg-0)',
              border: '1px solid var(--ow-line)',
              borderRadius: 10,
              fontFamily: 'inherit',
              fontWeight: 600,
              fontSize: 14,
              cursor: 'pointer',
            }}
          >
            Request access
          </button>

          <p
            style={{
              fontSize: 12,
              color: 'var(--ow-fg-3)',
              textAlign: 'center',
              marginTop: 16,
              lineHeight: 1.5,
            }}
          >
            {accessNote
              ? 'Access and password resets are handled by your workspace administrator. Contact them to request a seat or reset your credentials.'
              : 'Access is provisioned by your workspace administrator.'}
          </p>
        </form>
      </div>

      <div
        aria-hidden="true"
        style={{
          position: 'fixed',
          left: 0,
          right: 0,
          bottom: 26,
          zIndex: 5,
          textAlign: 'center',
          fontFamily: 'var(--ow-font-mono, monospace)',
          fontSize: 11,
          color: 'var(--ow-fg-3)',
          letterSpacing: '0.08em',
        }}
      >
        {`OPENWATCH // ${version ? `v${version} // ` : ''}EYRIE`}
      </div>
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  height: 46,
  padding: '0 13px',
  background: 'var(--ow-bg-2)',
  border: '1px solid var(--ow-line)',
  borderRadius: 9,
  color: 'var(--ow-fg-0)',
  fontFamily: 'inherit',
  fontSize: 14,
};

const errorStyle: React.CSSProperties = {
  color: 'var(--ow-crit)',
  fontSize: 12,
};

const errorBanner: React.CSSProperties = {
  padding: '10px 12px',
  background: 'var(--ow-crit-bg)',
  border: '1px solid var(--ow-crit)',
  borderRadius: 8,
  color: 'var(--ow-crit)',
  fontSize: 13,
  marginBottom: 14,
};
