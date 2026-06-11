import { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useNavigate, useSearch } from '@tanstack/react-router';
import api from '@/api/client';
import { useAuthStore, type Identity } from '@/store/useAuthStore';

// Login page — frontend-auth-login spec.
//
// Per app/docs/frontend_architecture_adr.md D-08, login uses session
// cookies, not localStorage tokens. The body's access_token /
// refresh_token are IGNORED. On success we re-fetch /auth/me to
// populate the identity store, then redirect to return_to (or /).

const schema = z.object({
  username: z.string().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required'),
  otp: z.string().optional(),
});

type FormShape = z.infer<typeof schema>;

interface LoginSearch {
  return_to?: string;
}

function safeReturnTo(raw: string | undefined): string {
  // Open-redirect prevention (C-07 / AC-10): only allow paths that
  // begin with "/" and not "//" (which is protocol-relative).
  if (!raw) return '/';
  let decoded: string;
  try {
    decoded = decodeURIComponent(raw);
  } catch {
    return '/';
  }
  if (!decoded.startsWith('/') || decoded.startsWith('//')) return '/';
  return decoded;
}

export function LoginPage() {
  const navigate = useNavigate();
  const search = useSearch({ strict: false }) as LoginSearch;
  const setIdentity = useAuthStore((s) => s.setIdentity);
  const identity = useAuthStore((s) => s.identity);
  const authLoading = useAuthStore((s) => s.loading);

  const [mfaRequired, setMfaRequired] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Auto-redirect when a session cookie is already valid — bootstrapAuth
  // populates identity on app boot if /auth/me returns 200. If the user
  // arrives at /login already authenticated, send them straight to
  // return_to (or /).
  useEffect(() => {
    if (!authLoading && identity) {
      const dest = safeReturnTo(search.return_to);
      navigate({ to: dest, replace: true });
    }
  }, [authLoading, identity, navigate, search.return_to]);

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

      const { response, error } = await api.POST('/api/v1/auth/login', {
        body,
      });

      if (response.ok) {
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
          const identity: Identity = {
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
                    'admin',
                  ]
                : ['host:read'],
            mfaEnabled: !!meTyped.mfa_enabled,
          };
          setIdentity(identity);
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
        display: 'grid',
        placeItems: 'center',
        minHeight: '100vh',
        padding: 28,
        background: 'var(--ow-bg-0)',
      }}
    >
      <title>Sign in — OpenWatch</title>
      <form
        onSubmit={handleSubmit(onSubmit)}
        noValidate
        aria-label="Sign in"
        style={{
          width: 360,
          background: 'var(--ow-bg-1)',
          border: '1px solid var(--ow-line)',
          borderRadius: 'var(--ow-radius)',
          padding: 28,
          display: 'flex',
          flexDirection: 'column',
          gap: 14,
        }}
      >
        <h1 style={{ margin: 0, fontSize: 20, fontWeight: 600 }}>Sign in to OpenWatch</h1>

        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span style={{ fontSize: 13, color: 'var(--ow-fg-1)' }}>Username</span>
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

        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span style={{ fontSize: 13, color: 'var(--ow-fg-1)' }}>Password</span>
          <input
            type="password"
            autoComplete="current-password"
            disabled={submitting}
            {...register('password')}
            style={inputStyle}
          />
          {formState.errors.password && (
            <span role="alert" style={errorStyle}>
              {formState.errors.password.message}
            </span>
          )}
        </label>

        {mfaRequired && (
          <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <span style={{ fontSize: 13, color: 'var(--ow-fg-1)' }}>Authenticator code</span>
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
            height: 36,
            background: 'var(--ow-info)',
            color: 'var(--ow-info-on)',
            border: 0,
            borderRadius: 6,
            fontFamily: 'inherit',
            fontSize: 13,
            fontWeight: 600,
            cursor: submitting ? 'not-allowed' : 'pointer',
            opacity: submitting ? 0.7 : 1,
          }}
        >
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  height: 34,
  padding: '0 10px',
  background: 'var(--ow-bg-2)',
  border: '1px solid var(--ow-line)',
  borderRadius: 6,
  color: 'var(--ow-fg-0)',
  fontFamily: 'inherit',
  fontSize: 13,
};

const errorStyle: React.CSSProperties = {
  color: 'var(--ow-crit)',
  fontSize: 12,
};

const errorBanner: React.CSSProperties = {
  padding: '10px 12px',
  background: 'var(--ow-crit-bg)',
  border: '1px solid var(--ow-crit)',
  borderRadius: 6,
  color: 'var(--ow-crit)',
  fontSize: 13,
};
