import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useNavigate } from '@tanstack/react-router';
import api from '@/api/client';
import { BulkImportWizard } from '@/components/hosts/bulk/BulkImportWizard';

// AddHostPage — Single OR Bulk host onboarding.
//
// Spec: frontend-add-host v1.1.0.
//
// Single (AC-01..10) — POST /hosts then optional POST /credentials with
// best-effort rollback (DELETE /hosts/{id}) on credential failure.
// Bulk (AC-11..19) — CSV upload OR JSON paste → pre-flight review grid
// → sequential POSTs → outcome table → CSV download of failed rows.

// ─────────────────────────────────────────────────────────────────────────
// Shared zod schemas
// ─────────────────────────────────────────────────────────────────────────

const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const ipv6 = /^[0-9a-fA-F:]+$/;
const hostnameRe = /^[a-zA-Z0-9]([a-zA-Z0-9-.]*[a-zA-Z0-9])?$/;

const hostBaseSchema = z.object({
  hostname: z.string().min(1).max(256).regex(hostnameRe, 'Invalid hostname'),
  ip_address: z
    .string()
    .min(1)
    .max(64)
    .refine((v) => ipv4.test(v) || ipv6.test(v), 'Invalid IP'),
  port: z.number().int().min(1).max(65535).optional(),
  environment: z.string().max(64).optional(),
  username: z.string().max(256).optional(),
  tags: z.array(z.string().max(64)).optional(),
  group_id: z.string().uuid().nullable().optional(),
});

const singleSchema = hostBaseSchema.extend({
  auth_method: z.enum(['ssh_key', 'password', 'both']),
  password: z.string().optional(),
  private_key: z.string().optional(),
  private_key_passphrase: z.string().optional(),
  use_system_default: z.boolean(),
});

type SingleForm = z.infer<typeof singleSchema>;

// ─────────────────────────────────────────────────────────────────────────
// Tabbed shell
// ─────────────────────────────────────────────────────────────────────────

type Tab = 'single' | 'bulk';

export function AddHostPage() {
  const [tab, setTab] = useState<Tab>('single');

  return (
    <div style={{ padding: '20px 28px', maxWidth: 900 }}>
      <title>Add host — OpenWatch</title>
      <h1 style={{ margin: 0, fontSize: 22, fontWeight: 600 }}>Add host</h1>
      <p style={{ color: 'var(--ow-fg-2)', marginTop: 4, marginBottom: 16 }}>
        Onboard a single host with its credential, or import multiple hosts
        from CSV or JSON.
      </p>

      <div
        role="tablist"
        aria-label="Add host mode"
        style={{
          display: 'flex',
          gap: 4,
          marginBottom: 16,
          borderBottom: '1px solid var(--ow-line)',
        }}
      >
        <TabButton
          isActive={tab === 'single'}
          onClick={() => setTab('single')}
          label="Single"
          panelId="panel-single"
        />
        <TabButton
          isActive={tab === 'bulk'}
          onClick={() => setTab('bulk')}
          label="Bulk"
          panelId="panel-bulk"
        />
      </div>

      {tab === 'single' && (
        <div id="panel-single" role="tabpanel" aria-labelledby="tab-single">
          <SingleForm />
        </div>
      )}
      {tab === 'bulk' && (
        <div id="panel-bulk" role="tabpanel" aria-labelledby="tab-bulk">
          <BulkPanel />
        </div>
      )}
    </div>
  );
}

function TabButton({
  isActive,
  onClick,
  label,
  panelId,
}: {
  isActive: boolean;
  onClick: () => void;
  label: string;
  panelId: string;
}) {
  return (
    <button
      role="tab"
      id={`tab-${label.toLowerCase()}`}
      aria-selected={isActive}
      aria-controls={panelId}
      tabIndex={isActive ? 0 : -1}
      onClick={onClick}
      style={{
        background: 'transparent',
        border: 0,
        padding: '10px 18px',
        fontSize: 13,
        fontWeight: 500,
        color: isActive ? 'var(--ow-fg-0)' : 'var(--ow-fg-2)',
        cursor: 'pointer',
        borderBottom: isActive
          ? '2px solid var(--ow-info)'
          : '2px solid transparent',
        marginBottom: -1,
      }}
    >
      {label}
    </button>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Single mode
// ─────────────────────────────────────────────────────────────────────────

function SingleForm() {
  const navigate = useNavigate();
  const [submitting, setSubmitting] = useState(false);
  const [serverError, setServerError] = useState<string | null>(null);

  const { register, handleSubmit, formState, watch } = useForm<SingleForm>({
    resolver: zodResolver(singleSchema),
    mode: 'onTouched',
    defaultValues: {
      auth_method: 'ssh_key',
      use_system_default: false,
    },
  });

  const authMethod = watch('auth_method');
  const useSystemDefault = watch('use_system_default');

  const onSubmit = async (values: SingleForm) => {
    setServerError(null);
    setSubmitting(true);
    try {
      // Step 1: POST /hosts
      let hostResp: Response;
      let hostData: unknown;
      let hostErr: unknown;
      try {
        const r = await api.POST('/api/v1/hosts', {
          body: {
            hostname: values.hostname,
            ip_address: values.ip_address,
            port: values.port,
            environment: values.environment,
            username: values.username,
            tags: values.tags,
            group_id: values.group_id ?? null,
          },
        });
        hostResp = r.response;
        hostData = r.data;
        hostErr = r.error;
      } catch (e) {
        setServerError(
          e instanceof TypeError && /fetch|network/i.test(e.message)
            ? 'Cannot reach the OpenWatch API. Start the backend (./dist/openwatch serve) or check the Vite proxy target (https://localhost:8443).'
            : (e as Error)?.message ?? 'Failed to create host (network error)',
        );
        return;
      }
      if (!hostResp.ok || !hostData) {
        const err = hostErr as { error?: { code?: string; message?: string } };
        setServerError(err?.error?.message ?? `Failed to create host (HTTP ${hostResp.status})`);
        return;
      }
      const newHost = hostData as { id: string };
      if (!newHost?.id) {
        setServerError('Host created but the server response did not include an id.');
        return;
      }

      // Step 2: POST /credentials if not using system default
      if (!values.use_system_default) {
        const credBody: {
          scope: 'host';
          scope_id: string;
          name: string;
          username: string;
          auth_method: 'ssh_key' | 'password' | 'both';
          password?: string;
          private_key?: string;
          private_key_passphrase?: string;
        } = {
          scope: 'host',
          scope_id: newHost.id,
          name: `host:${values.hostname}`,
          username: values.username ?? 'root',
          auth_method: values.auth_method,
        };
        if (values.auth_method !== 'ssh_key' && values.password) {
          credBody.password = values.password;
        }
        if (values.auth_method !== 'password' && values.private_key) {
          credBody.private_key = values.private_key;
          if (values.private_key_passphrase) {
            credBody.private_key_passphrase = values.private_key_passphrase;
          }
        }
        let credResp: Response;
        let credErr: unknown;
        try {
          const r = await api.POST('/api/v1/credentials', { body: credBody });
          credResp = r.response;
          credErr = r.error;
        } catch (e) {
          // Network failure after host create — surface and skip rollback.
          setServerError(
            `Host ${newHost.id} created but the credential POST failed: ${(e as Error)?.message ?? 'network error'}. The host is live without an attached credential.`,
          );
          return;
        }
        if (!credResp.ok) {
          // Best-effort rollback.
          try {
            await api.DELETE('/api/v1/hosts/{id}', {
              params: { path: { id: newHost.id } },
            });
          } catch {
            // Best-effort; if rollback also fails the user sees the orphan in the hosts list.
          }
          const err = credErr as { error?: { message?: string } };
          setServerError(
            err?.error?.message ?? 'Failed to attach credential. Host was rolled back.',
          );
          return;
        }
      }

      navigate({ to: '/hosts/$hostId', params: { hostId: newHost.id } });
    } catch (e) {
      // Catch-all so unhandled exceptions never escape into the
      // ErrorBoundary — the form keeps the operator in context.
      setServerError(
        (e as Error)?.message ?? 'An unexpected error occurred while creating the host.',
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate>
      <Card title="Host details">
        <Field
          label="Hostname"
          error={formState.errors.hostname?.message}
          registration={register('hostname')}
          disabled={submitting}
          autoFocus
        />
        <Field
          label="IP address"
          error={formState.errors.ip_address?.message}
          registration={register('ip_address')}
          disabled={submitting}
        />
        <Field
          label="Port"
          type="number"
          hint="Defaults to 22 (SSH)"
          error={formState.errors.port?.message}
          registration={register('port', { valueAsNumber: true })}
          disabled={submitting}
        />
        <Field
          label="Environment"
          hint="e.g. production, staging, dev"
          error={formState.errors.environment?.message}
          registration={register('environment')}
          disabled={submitting}
        />
        <Field
          label="SSH username"
          hint="Default: root"
          error={formState.errors.username?.message}
          registration={register('username')}
          disabled={submitting}
        />
      </Card>

      <Card title="Credential">
        <label
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            marginBottom: 12,
          }}
        >
          <input
            type="checkbox"
            {...register('use_system_default')}
            disabled={submitting}
          />
          <span style={{ fontSize: 13 }}>
            Use system default credential
          </span>
        </label>

        {!useSystemDefault && (
          <>
            <fieldset
              style={{ border: 0, padding: 0, margin: '0 0 12px' }}
              disabled={submitting}
            >
              <legend style={labelText}>Auth method</legend>
              {(['ssh_key', 'password', 'both'] as const).map((method) => (
                <label
                  key={method}
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 6,
                    marginRight: 14,
                  }}
                >
                  <input
                    type="radio"
                    value={method}
                    {...register('auth_method')}
                  />
                  <span style={{ fontSize: 13 }}>
                    {method === 'ssh_key' ? 'SSH key' : method === 'password' ? 'Password' : 'Both'}
                  </span>
                </label>
              ))}
            </fieldset>

            {authMethod !== 'ssh_key' && (
              <Field
                label="Password"
                type="password"
                autoComplete="off"
                error={formState.errors.password?.message}
                registration={register('password')}
                disabled={submitting}
              />
            )}
            {authMethod !== 'password' && (
              <>
                <TextareaField
                  label="SSH private key"
                  rows={4}
                  registration={register('private_key')}
                  disabled={submitting}
                />
                <Field
                  label="Private key passphrase"
                  type="password"
                  autoComplete="off"
                  hint="Optional; leave blank if the key is unencrypted"
                  error={formState.errors.private_key_passphrase?.message}
                  registration={register('private_key_passphrase')}
                  disabled={submitting}
                />
              </>
            )}
          </>
        )}
      </Card>

      {serverError && (
        <div role="alert" style={errorPanel}>
          {serverError}
        </div>
      )}

      <button
        type="submit"
        disabled={submitting}
        aria-busy={submitting}
        style={primaryBtn}
      >
        {submitting ? 'Adding…' : 'Add host'}
      </button>
    </form>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Bulk mode
//
// 3-step wizard ported from the Python frontend's EnhancedBulkImportDialog
// (Upload → Map → Preview & Import). Lives in
// src/components/hosts/bulk/. Keeps this page lean — see BulkImportWizard.
// ─────────────────────────────────────────────────────────────────────────

function BulkPanel() {
  return <BulkImportWizard />;
}


// ─────────────────────────────────────────────────────────────────────────
// Small UI primitives
// ─────────────────────────────────────────────────────────────────────────

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        marginBottom: 14,
      }}
    >
      <header
        style={{
          padding: '12px 16px',
          borderBottom: '1px solid var(--ow-line)',
          fontSize: 13,
          fontWeight: 600,
        }}
      >
        {title}
      </header>
      <div style={{ padding: 16 }}>{children}</div>
    </section>
  );
}

function Field({
  label,
  type = 'text',
  autoComplete,
  hint,
  error,
  disabled,
  registration,
  autoFocus,
}: {
  label: string;
  type?: string;
  autoComplete?: string;
  hint?: string;
  error?: string;
  disabled?: boolean;
  registration: ReturnType<ReturnType<typeof useForm<SingleForm>>['register']>;
  autoFocus?: boolean;
}) {
  return (
    <label style={{ display: 'block', marginBottom: 10 }}>
      <div style={labelText}>{label}</div>
      <input
        type={type}
        autoComplete={autoComplete}
        autoFocus={autoFocus}
        disabled={disabled}
        {...registration}
        style={inputStyle}
      />
      {hint && !error && (
        <div style={{ fontSize: 11, color: 'var(--ow-fg-3)', marginTop: 2 }}>
          {hint}
        </div>
      )}
      {error && <div role="alert" style={errorText}>{error}</div>}
    </label>
  );
}

function TextareaField({
  label,
  rows,
  registration,
  disabled,
}: {
  label: string;
  rows: number;
  registration: ReturnType<ReturnType<typeof useForm<SingleForm>>['register']>;
  disabled?: boolean;
}) {
  return (
    <label style={{ display: 'block', marginBottom: 10 }}>
      <div style={labelText}>{label}</div>
      <textarea
        rows={rows}
        disabled={disabled}
        {...registration}
        style={{
          ...inputStyle,
          height: 'auto',
          fontFamily: 'var(--ow-font-mono)',
          fontSize: 12,
          padding: 8,
          resize: 'vertical',
        }}
      />
    </label>
  );
}

const inputStyle: React.CSSProperties = {
  height: 32,
  width: '100%',
  maxWidth: 420,
  padding: '0 10px',
  background: 'var(--ow-bg-2)',
  border: '1px solid var(--ow-line)',
  borderRadius: 6,
  color: 'var(--ow-fg-0)',
  fontFamily: 'inherit',
  fontSize: 13,
};

const labelText: React.CSSProperties = {
  fontSize: 12,
  color: 'var(--ow-fg-1)',
  marginBottom: 4,
};

const errorText: React.CSSProperties = {
  color: 'var(--ow-crit)',
  fontSize: 12,
  marginTop: 4,
};

const primaryBtn: React.CSSProperties = {
  height: 32,
  padding: '0 16px',
  background: 'var(--ow-info)',
  color: 'var(--ow-info-on)',
  border: 0,
  borderRadius: 6,
  fontFamily: 'inherit',
  fontWeight: 600,
  fontSize: 13,
  cursor: 'pointer',
};

const errorPanel: React.CSSProperties = {
  padding: '10px 12px',
  margin: '12px 0',
  background: 'var(--ow-crit-bg)',
  border: '1px solid var(--ow-crit)',
  borderRadius: 6,
  color: 'var(--ow-crit)',
  fontSize: 13,
};
