import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, KeyRound, Loader2 } from 'lucide-react';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { Modal, FormField, Btn, Callout } from '@/components/settings/primitives';

// Credential mutation modals — Add, Edit, Delete.
//
// Wired against:
//   • POST   /api/v1/credentials       (credential:write)
//   • PATCH  /api/v1/credentials/{id}   (credential:write)
//   • DELETE /api/v1/credentials/{id}   (credential:delete)
//
// Update strategy: a real in-place PATCH (api-credentials v1.2.0). Secret
// fields left blank keep the stored ciphertext — no re-entry needed — so
// editing name/username/auth_method does not require re-pasting the key or
// password. This replaced the old create-then-delete "Replace" workaround.
//
// Spec: frontend-settings (Credentials mutations).

// ─────────────────────────────────────────────────────────────────────────
// Shared types + schema
// ─────────────────────────────────────────────────────────────────────────

export interface Credential {
  id: string;
  scope: 'system' | 'host';
  scope_id?: string | null;
  name: string;
  description?: string;
  username: string;
  auth_method: 'ssh_key' | 'password' | 'both';
  is_default: boolean;
  created_at: string;
  updated_at: string;
}

export const credentialSchema = z
  .object({
    name: z.string().min(1, 'Required').max(256, 'Too long'),
    description: z.string().max(1024, 'Too long').optional(),
    username: z.string().min(1, 'Required').max(256, 'Too long'),
    auth_method: z.enum(['ssh_key', 'password', 'both']),
    password: z.string().optional(),
    private_key: z.string().optional(),
    private_key_passphrase: z.string().optional(),
    is_default: z.boolean(),
  })
  .superRefine((v, ctx) => {
    if (v.auth_method !== 'ssh_key' && (!v.password || v.password.length === 0)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['password'],
        message: 'Required for password / both methods',
      });
    }
    if (v.auth_method !== 'password' && (!v.private_key || v.private_key.length === 0)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['private_key'],
        message: 'Required for ssh_key / both methods',
      });
    }
  });

export type FormShape = z.infer<typeof credentialSchema>;

// Edit uses the same fields but secrets are always optional: a blank
// password / key means "keep the stored ciphertext" (PATCH semantics).
// If the operator switches auth_method to one whose secret the credential
// lacks and supplies nothing, the backend rejects it with
// credentials.missing_secret — surfaced as a server error rather than
// pre-validated here (the form can't see which secrets are stored).
export const credentialEditSchema = z.object({
  name: z.string().min(1, 'Required').max(256, 'Too long'),
  description: z.string().max(1024, 'Too long').optional(),
  username: z.string().min(1, 'Required').max(256, 'Too long'),
  auth_method: z.enum(['ssh_key', 'password', 'both']),
  password: z.string().optional(),
  private_key: z.string().optional(),
  private_key_passphrase: z.string().optional(),
  is_default: z.boolean(),
});

// Detect the openapi-fetch wrapper's network-failure case. fetch
// rejects with a plain TypeError when the connection refuses, DNS
// fails, or CORS blocks. We surface a clearer message so the operator
// doesn't see "Failed to fetch".
export function isNetworkError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  return (
    err.name === 'TypeError' &&
    /failed to fetch|network|load failed|ERR_CONNECTION_REFUSED/i.test(err.message)
  );
}

export function describeNetworkError(): string {
  return 'Cannot reach the OpenWatch API. Start the backend (./dist/openwatch serve) or check that the Vite proxy target (https://localhost:8443) is responding.';
}

// ─────────────────────────────────────────────────────────────────────────
// Add credential modal
// ─────────────────────────────────────────────────────────────────────────

export function AddCredentialModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [serverError, setServerError] = useState<string | null>(null);
  const { register, handleSubmit, watch, formState, reset } = useForm<FormShape>({
    resolver: zodResolver(credentialSchema),
    mode: 'onTouched',
    defaultValues: { auth_method: 'ssh_key', is_default: false },
  });

  const authMethod = watch('auth_method');

  const createMutation = useMutation({
    mutationFn: async (values: FormShape) => {
      const body: Record<string, unknown> = {
        scope: 'system',
        name: values.name,
        username: values.username,
        auth_method: values.auth_method,
        is_default: values.is_default,
      };
      if (values.description) body.description = values.description;
      if (values.auth_method !== 'ssh_key' && values.password) {
        body.password = values.password;
      }
      if (values.auth_method !== 'password' && values.private_key) {
        body.private_key = values.private_key;
        if (values.private_key_passphrase) {
          body.private_key_passphrase = values.private_key_passphrase;
        }
      }
      let response: Response;
      let error: unknown;
      try {
        const result = await api.POST('/api/v1/credentials', {
          body: body as never,
        });
        response = result.response;
        error = result.error;
      } catch (fetchErr) {
        if (isNetworkError(fetchErr)) throw new Error(describeNetworkError());
        throw fetchErr;
      }
      if (!response.ok) {
        throw new Error(
          apiErrorMessage(error, `Failed to create credential (HTTP ${response.status})`),
        );
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] });
      reset();
      setServerError(null);
      onClose();
    },
    onError: (err: Error) => {
      setServerError(err.message);
    },
  });

  const onSubmit = (values: FormShape) => {
    setServerError(null);
    createMutation.mutate(values);
  };

  const submitting = createMutation.isPending;

  const handleClose = () => {
    if (submitting) return;
    reset();
    setServerError(null);
    onClose();
  };

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title="Add credential"
      width={540}
      preventClose={submitting}
      footer={
        <>
          <Btn onClick={handleClose} disabled={submitting}>
            Cancel
          </Btn>
          <Btn
            variant="primary"
            type="submit"
            onClick={() => {
              void handleSubmit(onSubmit)();
            }}
            disabled={submitting}
          >
            {submitting ? (
              <>
                <Loader2 size={14} /> Creating…
              </>
            ) : (
              'Create credential'
            )}
          </Btn>
        </>
      }
    >
      <form onSubmit={handleSubmit(onSubmit)} noValidate>
        <CredentialFormFields
          register={register}
          authMethod={authMethod}
          errors={formState.errors}
          disabled={submitting}
        />
        {serverError && (
          <div style={{ marginTop: 12 }}>
            <Callout tier="crit">{serverError}</Callout>
          </div>
        )}
      </form>
    </Modal>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Edit credential modal — in-place PATCH (api-credentials v1.2.0)
// ─────────────────────────────────────────────────────────────────────────

export function EditCredentialModal({
  open,
  onClose,
  credential,
}: {
  open: boolean;
  onClose: () => void;
  credential: Credential | null;
}) {
  const queryClient = useQueryClient();
  const [serverError, setServerError] = useState<string | null>(null);

  const { register, handleSubmit, watch, formState, reset } = useForm<FormShape>({
    resolver: zodResolver(credentialEditSchema),
    mode: 'onTouched',
    values: credential
      ? {
          name: credential.name,
          description: credential.description ?? '',
          username: credential.username,
          auth_method: credential.auth_method,
          password: '',
          private_key: '',
          private_key_passphrase: '',
          is_default: credential.is_default,
        }
      : undefined,
  });

  const authMethod = watch('auth_method');

  const editMutation = useMutation({
    mutationFn: async (values: FormShape) => {
      if (!credential) throw new Error('No credential selected');

      // PATCH body: metadata always sent; secrets only when the operator
      // typed a new value (blank = keep the stored ciphertext).
      const body: Record<string, unknown> = {
        name: values.name,
        description: values.description ?? '',
        username: values.username,
        auth_method: values.auth_method,
        is_default: values.is_default,
      };
      if (values.auth_method !== 'ssh_key' && values.password) {
        body.password = values.password;
      }
      if (values.auth_method !== 'password' && values.private_key) {
        body.private_key = values.private_key;
        if (values.private_key_passphrase) {
          body.private_key_passphrase = values.private_key_passphrase;
        }
      }

      let response: Response;
      let error: unknown;
      try {
        const result = await api.PATCH('/api/v1/credentials/{id}', {
          params: { path: { id: credential.id } },
          body: body as never,
        });
        response = result.response;
        error = result.error;
      } catch (fetchErr) {
        if (isNetworkError(fetchErr)) throw new Error(describeNetworkError());
        throw fetchErr;
      }
      if (!response.ok) {
        throw new Error(
          apiErrorMessage(error, `Failed to update credential (HTTP ${response.status})`),
        );
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] });
      reset();
      setServerError(null);
      onClose();
    },
    onError: (err: Error) => {
      setServerError(err.message);
    },
  });

  const onSubmit = (values: FormShape) => {
    setServerError(null);
    editMutation.mutate(values);
  };

  const submitting = editMutation.isPending;
  const handleClose = () => {
    if (submitting) return;
    reset();
    setServerError(null);
    onClose();
  };

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title="Edit credential"
      width={540}
      preventClose={submitting}
      footer={
        <>
          <Btn onClick={handleClose} disabled={submitting}>
            Cancel
          </Btn>
          <Btn
            variant="primary"
            onClick={() => {
              void handleSubmit(onSubmit)();
            }}
            disabled={submitting || !credential}
          >
            {submitting ? (
              <>
                <Loader2 size={14} /> Saving…
              </>
            ) : (
              'Save changes'
            )}
          </Btn>
        </>
      }
    >
      <form onSubmit={handleSubmit(onSubmit)} noValidate>
        <CredentialFormFields
          register={register}
          authMethod={authMethod}
          errors={formState.errors}
          disabled={submitting}
          mode="edit"
        />
        {serverError && (
          <div style={{ marginTop: 12 }}>
            <Callout tier="crit">{serverError}</Callout>
          </div>
        )}
      </form>
    </Modal>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Delete confirmation modal
// ─────────────────────────────────────────────────────────────────────────

export function DeleteCredentialModal({
  open,
  onClose,
  credential,
}: {
  open: boolean;
  onClose: () => void;
  credential: Credential | null;
}) {
  const queryClient = useQueryClient();
  const [serverError, setServerError] = useState<string | null>(null);

  const deleteMutation = useMutation({
    mutationFn: async () => {
      if (!credential) throw new Error('No credential selected');
      let response: Response;
      let error: unknown;
      try {
        const result = await api.DELETE('/api/v1/credentials/{id}', {
          params: { path: { id: credential.id } },
        });
        response = result.response;
        error = result.error;
      } catch (fetchErr) {
        if (isNetworkError(fetchErr)) throw new Error(describeNetworkError());
        throw fetchErr;
      }
      if (!response.ok && response.status !== 204) {
        throw new Error(
          apiErrorMessage(error, `Failed to delete credential (HTTP ${response.status})`),
        );
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['credentials'] });
      setServerError(null);
      onClose();
    },
    onError: (err: Error) => setServerError(err.message),
  });

  const submitting = deleteMutation.isPending;
  const handleClose = () => {
    if (submitting) return;
    setServerError(null);
    onClose();
  };

  if (!credential) return null;

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={`Delete ${credential.name}?`}
      width={460}
      preventClose={submitting}
      footer={
        <>
          <Btn onClick={handleClose} disabled={submitting}>
            Cancel
          </Btn>
          <Btn variant="danger" onClick={() => deleteMutation.mutate()} disabled={submitting}>
            {submitting ? (
              <>
                <Loader2 size={14} /> Deleting…
              </>
            ) : (
              <>
                <AlertTriangle size={14} /> Delete credential
              </>
            )}
          </Btn>
        </>
      }
    >
      <div style={{ fontSize: 13, color: 'var(--ow-fg-1)', lineHeight: 1.5 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
          <div
            style={{
              width: 32,
              height: 32,
              borderRadius: 6,
              background: 'var(--ow-bg-3)',
              color: 'var(--ow-fg-1)',
              display: 'grid',
              placeItems: 'center',
            }}
          >
            <KeyRound size={14} />
          </div>
          <div>
            <div style={{ fontWeight: 500 }}>{credential.name}</div>
            <div
              style={{
                fontSize: 11,
                color: 'var(--ow-fg-3)',
                fontFamily: 'var(--ow-font-mono)',
                marginTop: 2,
              }}
            >
              {credential.username}@· {credential.auth_method}
              {credential.is_default ? ' · default' : ''}
            </div>
          </div>
        </div>
        <p style={{ margin: '0 0 14px' }}>
          This soft-deletes the credential (
          <code style={{ fontFamily: 'var(--ow-font-mono)' }}>is_active=false</code>). Hosts
          currently using this credential will fall back to whichever default applies — or fail to
          authenticate if no default exists.
        </p>
        {credential.is_default && (
          <Callout tier="warn">
            <strong style={{ color: 'var(--ow-fg-0)' }}>This is the system default.</strong> Every
            host without a host-scoped credential will lose authentication until a new default is
            added.
          </Callout>
        )}
        {serverError && (
          <div style={{ marginTop: 12 }}>
            <Callout tier="crit">{serverError}</Callout>
          </div>
        )}
      </div>
    </Modal>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Shared form fields
// ─────────────────────────────────────────────────────────────────────────

export function CredentialFormFields({
  register,
  authMethod,
  errors,
  disabled,
  mode = 'create',
}: {
  register: ReturnType<typeof useForm<FormShape>>['register'];
  authMethod: FormShape['auth_method'];
  errors: ReturnType<typeof useForm<FormShape>>['formState']['errors'];
  disabled?: boolean;
  mode?: 'create' | 'edit';
}) {
  // In edit mode a blank secret keeps the stored ciphertext, so the
  // field labels say so and don't imply re-entry is required.
  const keepHint = mode === 'edit' ? ' (leave blank to keep current)' : '';
  return (
    <>
      <FormField label="Name" error={errors.name?.message}>
        <input
          type="text"
          autoFocus
          disabled={disabled}
          {...register('name')}
          style={inputStyle}
          placeholder="owadmin"
        />
      </FormField>

      <FormField label="Description (optional)" error={errors.description?.message}>
        <input
          type="text"
          disabled={disabled}
          {...register('description')}
          style={inputStyle}
          placeholder="Workspace default for fleet automation"
        />
      </FormField>

      <FormField label="SSH username" error={errors.username?.message}>
        <input
          type="text"
          disabled={disabled}
          {...register('username')}
          style={inputStyle}
          placeholder="root"
        />
      </FormField>

      <FormField label="Auth method">
        <fieldset
          style={{ display: 'flex', gap: 14, border: 0, padding: 0, margin: 0 }}
          disabled={disabled}
        >
          {(['ssh_key', 'password', 'both'] as const).map((m) => (
            <label
              key={m}
              style={{
                display: 'inline-flex',
                gap: 6,
                alignItems: 'center',
                fontSize: 13,
                color: 'var(--ow-fg-0)',
              }}
            >
              <input type="radio" value={m} {...register('auth_method')} />
              {m === 'ssh_key' ? 'SSH key' : m === 'password' ? 'Password' : 'Both'}
            </label>
          ))}
        </fieldset>
      </FormField>

      {authMethod !== 'ssh_key' && (
        <FormField label={`Password${keepHint}`} error={errors.password?.message}>
          <input
            type="password"
            autoComplete="off"
            disabled={disabled}
            {...register('password')}
            style={inputStyle}
          />
        </FormField>
      )}

      {authMethod !== 'password' && (
        <>
          <FormField label={`SSH private key${keepHint}`} error={errors.private_key?.message}>
            <textarea
              rows={4}
              disabled={disabled}
              {...register('private_key')}
              style={{
                ...inputStyle,
                height: 'auto',
                padding: 8,
                fontFamily: 'var(--ow-font-mono)',
                fontSize: 12,
                resize: 'vertical',
              }}
              placeholder={'-----BEGIN OPENSSH ... KEY-----\n…'}
            />
          </FormField>
          <FormField
            label="Private key passphrase (optional)"
            error={errors.private_key_passphrase?.message}
          >
            <input
              type="password"
              autoComplete="off"
              disabled={disabled}
              {...register('private_key_passphrase')}
              style={inputStyle}
            />
          </FormField>
        </>
      )}

      <FormField label="">
        <label style={{ display: 'inline-flex', gap: 8, alignItems: 'center', fontSize: 13 }}>
          <input type="checkbox" disabled={disabled} {...register('is_default')} />
          <span>
            Use as workspace default
            <span style={{ color: 'var(--ow-fg-3)', marginLeft: 6, fontSize: 12 }}>
              applied to every host without an override
            </span>
          </span>
        </label>
      </FormField>
    </>
  );
}

const inputStyle: React.CSSProperties = {
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
};
