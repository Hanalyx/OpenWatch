import { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useQueryClient } from '@tanstack/react-query';
import { LogOut } from 'lucide-react';
import api from '@/api/client';
import { useAuthStore } from '@/store/useAuthStore';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import { SettingsLayout } from '@/components/settings/SettingsLayout';
import {
  PageHead,
  Section,
  SettingCard,
  SettingRow,
  FirstSettingRow,
  Field,
  Select,
  Btn,
  StatusPill,
} from '@/components/settings/primitives';

// Settings → Profile (wired to backend).
//
// Backend wires:
//   • GET /api/v1/auth/me              — profile read
//   • POST /api/v1/auth/password:change — password update
//   • POST /api/v1/auth/mfa:enroll     — MFA enrollment start
//   • POST /api/v1/auth/mfa:verify     — MFA enrollment confirmation
//
// Profile-edit fields (full name, display name, job title, timezone,
// phone) are RENDERED but not POSTed — backend has no
// PATCH /auth/me endpoint yet. Edits stay in local form state; a
// follow-up wires PATCH when the endpoint lands.

const passwordSchema = z
  .object({
    current_password: z.string().min(1, 'Required'),
    new_password: z
      .string()
      .min(15, 'Password must be at least 15 characters'),
    confirm_password: z.string().min(1, 'Required'),
  })
  .refine((v) => v.new_password === v.confirm_password, {
    message: 'Passwords do not match',
    path: ['confirm_password'],
  })
  .refine((v) => v.new_password !== v.current_password, {
    message: 'New password must differ from current',
    path: ['new_password'],
  });

type PasswordForm = z.infer<typeof passwordSchema>;

const TIMEZONES = [
  { value: 'America/Los_Angeles', label: 'America/Los_Angeles (PT)' },
  { value: 'America/New_York', label: 'America/New_York (ET)' },
  { value: 'America/Chicago', label: 'America/Chicago (CT)' },
  { value: 'UTC', label: 'UTC' },
  { value: 'Europe/London', label: 'Europe/London (GMT)' },
  { value: 'Europe/Paris', label: 'Europe/Paris (CET)' },
];

export function ProfilePage() {
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);
  useEffect(() => {
    setCrumbs([{ label: 'Settings' }, { label: 'Profile' }]);
    return () => setCrumbs([]);
  }, [setCrumbs]);

  return (
    <SettingsLayout>
      <PageHead
        title="Profile"
        description="Your personal account details. Visible to other members of this workspace."
      />
      <ProfileSection />
      <PasswordSection />
      <MFASection />
      <SessionsSection />
    </SettingsLayout>
  );
}

function ProfileSection() {
  const identity = useAuthStore((s) => s.identity);
  const [fullName, setFullName] = useState(identity?.username ?? '');
  const [displayName, setDisplayName] = useState(identity?.username ?? '');
  const [email, setEmail] = useState(identity?.email ?? '');
  const [jobTitle, setJobTitle] = useState('');
  const [tz, setTz] = useState('UTC');
  const [phone, setPhone] = useState('');

  const initials = (identity?.username ?? identity?.email ?? '?')
    .split(/[\s._-]/)
    .map((s) => s[0]?.toUpperCase() ?? '')
    .slice(0, 2)
    .join('');

  return (
    <Section>
      <SettingCard>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 16,
            padding: 20,
            borderBottom: '1px solid var(--ow-line)',
          }}
        >
          <div
            style={{
              width: 64,
              height: 64,
              borderRadius: '50%',
              background: 'var(--ow-info)',
              color: 'var(--ow-info-on)',
              display: 'grid',
              placeItems: 'center',
              fontSize: 22,
              fontWeight: 600,
            }}
          >
            {initials}
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600, fontSize: 16 }}>
              {identity?.username ?? '—'}
            </div>
            <div style={{ color: 'var(--ow-fg-2)', fontSize: 13, marginTop: 2 }}>
              {identity?.email ?? ''}
              {identity?.role && (
                <>
                  <span style={{ color: 'var(--ow-fg-3)', margin: '0 6px' }}>·</span>
                  <span style={{ textTransform: 'capitalize' }}>{identity.role}</span>
                </>
              )}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <Btn size="sm" disabled>
              Upload photo
            </Btn>
            <Btn size="sm" variant="danger" disabled>
              Remove
            </Btn>
          </div>
        </div>

        <div
          style={{
            padding: 20,
            display: 'grid',
            gridTemplateColumns: 'repeat(2, 1fr)',
            gap: 16,
          }}
        >
          <Labeled label="Full name">
            <Field value={fullName} onChange={setFullName} />
          </Labeled>
          <Labeled label="Display name">
            <Field value={displayName} onChange={setDisplayName} />
          </Labeled>
          <Labeled label="Email" hint="Used for sign-in and email notifications.">
            <Field type="email" value={email} onChange={setEmail} />
          </Labeled>
          <Labeled label="Job title">
            <Field value={jobTitle} onChange={setJobTitle} />
          </Labeled>
          <Labeled label="Timezone">
            <Select value={tz} onChange={setTz} options={TIMEZONES} width="100%" />
          </Labeled>
          <Labeled label="Phone (for critical alerts)">
            <Field type="tel" value={phone} onChange={setPhone} />
          </Labeled>
        </div>

        <div
          style={{
            padding: '12px 20px',
            background: 'var(--ow-bg-2)',
            borderTop: '1px solid var(--ow-line)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            color: 'var(--ow-fg-3)',
            fontSize: 12,
          }}
        >
          <span>
            Profile edits aren't saved yet — backend{' '}
            <code style={{ fontFamily: 'var(--ow-font-mono)' }}>PATCH /auth/me</code> pending.
          </span>
          <Btn variant="primary" disabled>
            Save changes
          </Btn>
        </div>
      </SettingCard>
    </Section>
  );
}

function Labeled({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <span style={{ fontSize: 12, color: 'var(--ow-fg-2)' }}>{label}</span>
      {children}
      {hint && <span style={{ fontSize: 11, color: 'var(--ow-fg-3)' }}>{hint}</span>}
    </label>
  );
}

function PasswordSection() {
  const [showForm, setShowForm] = useState(false);
  const [banner, setBanner] = useState<
    { kind: 'success' | 'error'; text: string } | null
  >(null);
  const [submitting, setSubmitting] = useState(false);

  const { register, handleSubmit, reset, formState } = useForm<PasswordForm>({
    resolver: zodResolver(passwordSchema),
    mode: 'onTouched',
  });

  const onSubmit = async (values: PasswordForm) => {
    setBanner(null);
    setSubmitting(true);
    try {
      const { response, error } = await api.POST('/api/v1/auth/password:change', {
        body: {
          current_password: values.current_password,
          new_password: values.new_password,
        },
      });
      if (response.ok) {
        reset();
        setShowForm(false);
        setBanner({ kind: 'success', text: 'Password updated.' });
        return;
      }
      const err = error as { error?: { code?: string } } | undefined;
      const msg =
        err?.error?.code === 'auth.invalid_credentials'
          ? 'Current password is incorrect.'
          : 'Failed to update password.';
      setBanner({ kind: 'error', text: msg });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Section title="Password">
      <SettingCard>
        <FirstSettingRow
          name="Change password"
          description={
            <>
              Choose a strong password (at least 15 characters).{' '}
              {banner?.kind === 'success' && (
                <span style={{ color: 'var(--ow-ok)' }}>{banner.text}</span>
              )}
              {banner?.kind === 'error' && (
                <span style={{ color: 'var(--ow-crit)' }}>{banner.text}</span>
              )}
            </>
          }
          control={
            <Btn onClick={() => setShowForm((v) => !v)}>
              {showForm ? 'Cancel' : 'Update password'}
            </Btn>
          }
        />
        {showForm && (
          <form
            onSubmit={handleSubmit(onSubmit)}
            noValidate
            style={{
              padding: 20,
              borderTop: '1px solid var(--ow-line)',
              display: 'grid',
              gap: 12,
              maxWidth: 480,
            }}
          >
            <FormInput
              label="Current password"
              type="password"
              error={formState.errors.current_password?.message}
              registration={register('current_password')}
              disabled={submitting}
            />
            <FormInput
              label="New password"
              type="password"
              error={formState.errors.new_password?.message}
              registration={register('new_password')}
              disabled={submitting}
              hint="At least 15 characters."
            />
            <FormInput
              label="Confirm new password"
              type="password"
              error={formState.errors.confirm_password?.message}
              registration={register('confirm_password')}
              disabled={submitting}
            />
            <div style={{ display: 'flex', gap: 8 }}>
              <Btn type="submit" variant="primary" disabled={submitting}>
                {submitting ? 'Updating…' : 'Update password'}
              </Btn>
              <Btn onClick={() => { reset(); setShowForm(false); }} disabled={submitting}>
                Cancel
              </Btn>
            </div>
          </form>
        )}
      </SettingCard>
    </Section>
  );
}

function FormInput({
  label,
  type,
  error,
  registration,
  disabled,
  hint,
}: {
  label: string;
  type: string;
  error: string | undefined;
  registration: ReturnType<ReturnType<typeof useForm<PasswordForm>>['register']>;
  disabled?: boolean;
  hint?: string;
}) {
  return (
    <label style={{ display: 'block' }}>
      <div style={{ fontSize: 12, color: 'var(--ow-fg-2)', marginBottom: 4 }}>
        {label}
      </div>
      <input
        type={type}
        disabled={disabled}
        {...registration}
        style={{
          height: 32,
          width: '100%',
          padding: '0 10px',
          background: 'var(--ow-bg-2)',
          border: '1px solid var(--ow-line)',
          borderRadius: 6,
          color: 'var(--ow-fg-0)',
          fontFamily: 'inherit',
          fontSize: 13,
          outline: 0,
        }}
      />
      {hint && !error && (
        <div style={{ fontSize: 11, color: 'var(--ow-fg-3)', marginTop: 4 }}>
          {hint}
        </div>
      )}
      {error && (
        <div role="alert" style={{ fontSize: 11, color: 'var(--ow-crit)', marginTop: 4 }}>
          {error}
        </div>
      )}
    </label>
  );
}

function MFASection() {
  const identity = useAuthStore((s) => s.identity);
  const setIdentity = useAuthStore((s) => s.setIdentity);
  const queryClient = useQueryClient();
  const [enrollment, setEnrollment] = useState<{ secret: string; uri: string } | null>(null);
  const [otp, setOtp] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const enrolled = identity?.mfaEnabled ?? false;

  const beginEnroll = async () => {
    setError(null);
    setBusy(true);
    try {
      const { data, error: apiErr } = await api.POST('/api/v1/auth/mfa:enroll', {});
      if (apiErr) throw apiErr;
      const d = data as { provisioning_uri: string; secret: string };
      setEnrollment({ uri: d.provisioning_uri, secret: d.secret });
    } catch {
      setError('Failed to start enrollment.');
    } finally {
      setBusy(false);
    }
  };

  const verify = async () => {
    if (otp.length !== 6) {
      setError('Enter the 6-digit code from your authenticator app.');
      return;
    }
    setError(null);
    setBusy(true);
    try {
      const { response } = await api.POST('/api/v1/auth/mfa:verify', {
        body: { otp },
      });
      if (response.ok) {
        setEnrollment(null);
        setOtp('');
        if (identity) setIdentity({ ...identity, mfaEnabled: true });
        await queryClient.invalidateQueries({ queryKey: ['auth-me'] });
        return;
      }
      setError('Invalid code.');
    } catch {
      setError('Failed to verify.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Section title="Two-factor authentication">
      <SettingCard>
        <FirstSettingRow
          name="Authenticator app"
          description={
            enrolled
              ? 'TOTP authenticator is enrolled and required at sign-in.'
              : 'Add a code-based second factor (Authy, Google Authenticator, 1Password, etc.).'
          }
          control={
            enrolled ? (
              <StatusPill tier="ok">Enabled</StatusPill>
            ) : (
              <Btn onClick={beginEnroll} disabled={busy || !!enrollment}>
                {busy ? 'Starting…' : 'Begin enrollment'}
              </Btn>
            )
          }
        />
        {enrollment && !enrolled && (
          <div
            style={{
              padding: 20,
              borderTop: '1px solid var(--ow-line)',
              display: 'grid',
              gap: 12,
            }}
          >
            <p style={{ margin: 0, color: 'var(--ow-fg-1)', fontSize: 13 }}>
              Scan this URI in your authenticator app, or enter the secret manually,
              then enter the 6-digit code to confirm enrollment.
            </p>
            <code
              style={{
                fontFamily: 'var(--ow-font-mono)',
                fontSize: 12,
                background: 'var(--ow-bg-2)',
                padding: '10px 12px',
                border: '1px solid var(--ow-line)',
                borderRadius: 6,
                wordBreak: 'break-all',
              }}
            >
              {enrollment.uri}
            </code>
            <div>
              <span style={{ color: 'var(--ow-fg-2)', fontSize: 12, marginRight: 8 }}>
                Secret:
              </span>
              <code
                style={{
                  fontFamily: 'var(--ow-font-mono)',
                  fontSize: 13,
                  color: 'var(--ow-fg-0)',
                }}
              >
                {enrollment.secret}
              </code>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <input
                type="text"
                inputMode="numeric"
                maxLength={6}
                placeholder="000000"
                value={otp}
                onChange={(e) => setOtp(e.target.value.replace(/\D/g, ''))}
                aria-label="Authenticator code"
                style={{
                  height: 32,
                  width: 100,
                  padding: '0 10px',
                  background: 'var(--ow-bg-2)',
                  border: '1px solid var(--ow-line)',
                  borderRadius: 6,
                  color: 'var(--ow-fg-0)',
                  fontFamily: 'var(--ow-font-mono)',
                  fontSize: 14,
                  outline: 0,
                  letterSpacing: '0.1em',
                  textAlign: 'center',
                }}
              />
              <Btn variant="primary" onClick={verify} disabled={busy}>
                {busy ? 'Verifying…' : 'Verify and enable'}
              </Btn>
              <Btn onClick={() => { setEnrollment(null); setOtp(''); setError(null); }}>
                Cancel
              </Btn>
            </div>
            {error && (
              <div role="alert" style={{ color: 'var(--ow-crit)', fontSize: 12 }}>
                {error}
              </div>
            )}
          </div>
        )}
        {!enrollment && error && (
          <div
            role="alert"
            style={{
              padding: '12px 20px',
              borderTop: '1px solid var(--ow-line)',
              color: 'var(--ow-crit)',
              fontSize: 12,
            }}
          >
            {error}
          </div>
        )}
      </SettingCard>
    </Section>
  );
}

function SessionsSection() {
  // Backend doesn't yet expose a sessions list endpoint. The current
  // session is reflected as "active now"; revoke-other-sessions is
  // disabled until /auth/sessions ships.
  return (
    <Section title="Active sessions">
      <SettingCard>
        <FirstSettingRow
          name={
            <>
              This device{' '}
              <span
                style={{
                  fontSize: 10,
                  background: 'var(--ow-info-bg)',
                  color: 'var(--ow-info)',
                  padding: '1px 7px',
                  borderRadius: 'var(--ow-radius-full)',
                  fontWeight: 700,
                  marginLeft: 6,
                }}
              >
                CURRENT
              </span>
            </>
          }
          description={
            <span style={{ fontFamily: 'var(--ow-font-mono)' }}>
              Active now · session cookie
            </span>
          }
          control={
            <span style={{ color: 'var(--ow-fg-3)', fontSize: 12 }}>Current session</span>
          }
        />
        <SettingRow
          name="Sign out everywhere else"
          description="Backend session listing pending. When available, individual sessions will be revocable here."
          control={
            <Btn variant="danger" disabled>
              <LogOut size={14} /> Revoke all
            </Btn>
          }
        />
      </SettingCard>
    </Section>
  );
}
