import { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Loader2 } from 'lucide-react';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useAuthStore } from '@/store/useAuthStore';
import { Modal, Btn, Callout } from '@/components/settings/primitives';
import {
  CredentialFormFields,
  credentialSchema,
  credentialEditSchema,
  isNetworkError,
  describeNetworkError,
  type FormShape,
} from '@/pages/settings/CredentialMutations';

// Per-host SSH credential management, shared by the host header Edit flow
// and the Connectivity card's "Edit credentials" link.
//
// A host resolves its credential via the tier model (api-credentials):
//   host-scope override (scope=host, scope_id=hostId) wins, else the
//   system default (scope=system, is_default=true). There is no
//   credential_id column on hosts — switching source means creating,
//   cloning, or deleting a host-scope credential.
//
// This modal reads the resolved source (POST /credentials:resolve) and
// lets the operator:
//   • edit the host override in place (PATCH /credentials/{id})
//   • revert to the system default (DELETE the host override)
//   • adopt a copy of the system default for this host (clone, keeps the
//     stored secret) or set a different host credential (POST scope=host)
//
// Spec: frontend-host-detail (credential management) + api-credentials v1.2.0.

interface ResolvedCred {
  id: string;
  scope: 'system' | 'host';
  scope_id?: string | null;
  name: string;
  description?: string;
  username: string;
  auth_method: 'ssh_key' | 'password' | 'both';
  is_default: boolean;
}

// Append only the secret fields the operator actually filled in. A blank
// secret means "keep" on PATCH and "omit" on POST.
function withSecrets(body: Record<string, unknown>, values: FormShape): Record<string, unknown> {
  if (values.auth_method !== 'ssh_key' && values.password) {
    body.password = values.password;
  }
  if (values.auth_method !== 'password' && values.private_key) {
    body.private_key = values.private_key;
    if (values.private_key_passphrase) {
      body.private_key_passphrase = values.private_key_passphrase;
    }
  }
  return body;
}

export function HostCredentialModal({
  open,
  onClose,
  host,
}: {
  open: boolean;
  onClose: () => void;
  host: { id: string; hostname: string };
}) {
  const canWrite = useAuthStore((s) => s.hasPermission('credential:write'));
  const queryClient = useQueryClient();
  const [mode, setMode] = useState<'overview' | 'newOverride'>('overview');
  const [serverError, setServerError] = useState<string | null>(null);
  const [confirmRevert, setConfirmRevert] = useState(false);

  const resolveQuery = useQuery({
    queryKey: ['host-credential-resolve', host.id],
    enabled: open,
    queryFn: async () => {
      const { data, response } = await api.POST('/api/v1/hosts/{host_id}/credentials:resolve', {
        params: { path: { host_id: host.id } },
      });
      if (response.status === 404) return null; // credentials.none_available
      if (!response.ok) throw new Error(`Could not resolve credential (HTTP ${response.status})`);
      return data as ResolvedCred;
    },
  });

  const resolved = resolveQuery.data ?? null;
  const source: 'host' | 'system' | 'none' =
    resolved == null ? 'none' : resolved.scope === 'host' ? 'host' : 'system';

  // Edit form (host override) — secrets optional, prefilled from resolve.
  const editForm = useForm<FormShape>({
    resolver: zodResolver(credentialEditSchema),
    mode: 'onTouched',
    values:
      resolved && resolved.scope === 'host'
        ? {
            name: resolved.name,
            description: resolved.description ?? '',
            username: resolved.username,
            auth_method: resolved.auth_method,
            password: '',
            private_key: '',
            private_key_passphrase: '',
            is_default: false,
          }
        : undefined,
  });

  // New host-override form — full create rules (secrets required).
  const newForm = useForm<FormShape>({
    resolver: zodResolver(credentialSchema),
    mode: 'onTouched',
    defaultValues: { auth_method: 'ssh_key', is_default: false },
  });

  useEffect(() => {
    if (open) {
      setMode('overview');
      setServerError(null);
      setConfirmRevert(false);
      newForm.reset({ auth_method: 'ssh_key', is_default: false });
    }
    // newForm is stable across renders; resetting on open/host change only.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, host.id]);

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['host-credential-resolve', host.id] });
    queryClient.invalidateQueries({ queryKey: ['host', host.id] });
    queryClient.invalidateQueries({ queryKey: ['hosts'] });
  };

  // Adopt a copy of the system default for this host (keeps the secret).
  const cloneMutation = useMutation({
    mutationFn: async () => {
      if (!resolved) throw new Error('No system default to copy');
      let response: Response;
      let error: unknown;
      try {
        const result = await api.POST('/api/v1/credentials/{id}:clone', {
          params: { path: { id: resolved.id } },
          body: { scope: 'host', scope_id: host.id } as never,
        });
        response = result.response;
        error = result.error;
      } catch (e) {
        if (isNetworkError(e)) throw new Error(describeNetworkError());
        throw e;
      }
      if (!response.ok) {
        throw new Error(apiErrorMessage(error, `Could not copy default (HTTP ${response.status})`));
      }
    },
    onSuccess: () => {
      invalidate();
      setServerError(null);
    },
    onError: (e: Error) => setServerError(e.message),
  });

  const createMutation = useMutation({
    mutationFn: async (values: FormShape) => {
      const body = withSecrets(
        {
          scope: 'host',
          scope_id: host.id,
          name: values.name,
          username: values.username,
          auth_method: values.auth_method,
          is_default: false,
          ...(values.description ? { description: values.description } : {}),
        },
        values,
      );
      let response: Response;
      let error: unknown;
      try {
        const result = await api.POST('/api/v1/credentials', { body: body as never });
        response = result.response;
        error = result.error;
      } catch (e) {
        if (isNetworkError(e)) throw new Error(describeNetworkError());
        throw e;
      }
      if (!response.ok) {
        throw new Error(
          apiErrorMessage(error, `Could not set host credential (HTTP ${response.status})`),
        );
      }
    },
    onSuccess: () => {
      invalidate();
      setServerError(null);
      setMode('overview');
    },
    onError: (e: Error) => setServerError(e.message),
  });

  const editMutation = useMutation({
    mutationFn: async (values: FormShape) => {
      if (!resolved) throw new Error('No host credential to edit');
      const body = withSecrets(
        {
          name: values.name,
          description: values.description ?? '',
          username: values.username,
          auth_method: values.auth_method,
        },
        values,
      );
      let response: Response;
      let error: unknown;
      try {
        const result = await api.PATCH('/api/v1/credentials/{id}', {
          params: { path: { id: resolved.id } },
          body: body as never,
        });
        response = result.response;
        error = result.error;
      } catch (e) {
        if (isNetworkError(e)) throw new Error(describeNetworkError());
        throw e;
      }
      if (!response.ok) {
        throw new Error(
          apiErrorMessage(error, `Could not update credential (HTTP ${response.status})`),
        );
      }
    },
    onSuccess: () => {
      invalidate();
      setServerError(null);
      onClose();
    },
    onError: (e: Error) => setServerError(e.message),
  });

  const revertMutation = useMutation({
    mutationFn: async () => {
      if (!resolved) throw new Error('No host credential to remove');
      let response: Response;
      let error: unknown;
      try {
        const result = await api.DELETE('/api/v1/credentials/{id}', {
          params: { path: { id: resolved.id } },
        });
        response = result.response;
        error = result.error;
      } catch (e) {
        if (isNetworkError(e)) throw new Error(describeNetworkError());
        throw e;
      }
      if (!response.ok && response.status !== 204) {
        throw new Error(
          apiErrorMessage(error, `Could not revert to default (HTTP ${response.status})`),
        );
      }
    },
    onSuccess: () => {
      invalidate();
      setServerError(null);
      setConfirmRevert(false);
    },
    onError: (e: Error) => setServerError(e.message),
  });

  const busy =
    cloneMutation.isPending ||
    createMutation.isPending ||
    editMutation.isPending ||
    revertMutation.isPending;

  const handleClose = () => {
    if (busy) return;
    onClose();
  };

  // Which form (if any) drives the primary footer button.
  const showingEditForm = source === 'host';
  const showingNewForm = source === 'none' || (source === 'system' && mode === 'newOverride');
  // The new-credential form reached from the system-default overview can
  // step back to the choice screen instead of closing outright.
  const backFromNew = source === 'system' && mode === 'newOverride';

  const submitEdit = () =>
    void editForm.handleSubmit((v) => {
      setServerError(null);
      editMutation.mutate(v);
    })();
  const submitNew = () =>
    void newForm.handleSubmit((v) => {
      setServerError(null);
      createMutation.mutate(v);
    })();

  const footer = (
    <>
      {backFromNew ? (
        <Btn onClick={() => setMode('overview')} disabled={busy}>
          Back
        </Btn>
      ) : (
        <Btn onClick={handleClose} disabled={busy}>
          Close
        </Btn>
      )}
      {canWrite && showingEditForm && (
        <Btn variant="primary" onClick={submitEdit} disabled={busy}>
          {editMutation.isPending ? (
            <>
              <Loader2 size={14} /> Saving…
            </>
          ) : (
            'Save changes'
          )}
        </Btn>
      )}
      {canWrite && showingNewForm && (
        <Btn variant="primary" onClick={submitNew} disabled={busy}>
          {createMutation.isPending ? (
            <>
              <Loader2 size={14} /> Saving…
            </>
          ) : (
            'Set host credential'
          )}
        </Btn>
      )}
    </>
  );

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={`SSH credential for ${host.hostname}`}
      width={540}
      preventClose={busy}
      footer={footer}
    >
      {resolveQuery.isLoading ? (
        <div style={{ color: 'var(--ow-fg-2)', fontSize: 13, padding: '8px 0' }}>
          <Loader2 size={14} /> Checking current credential…
        </div>
      ) : resolveQuery.isError ? (
        <Callout tier="crit">
          {(resolveQuery.error as Error)?.message ?? 'Could not resolve the host credential.'}
        </Callout>
      ) : (
        <>
          <SourceSummary source={source} resolved={resolved} hostname={host.hostname} />

          {!canWrite && (
            <div style={{ marginTop: 12 }}>
              <Callout tier="warn">
                You need the credential:write permission to change this host&apos;s credential.
              </Callout>
            </div>
          )}

          {/* Host override: edit in place, with a revert action. */}
          {canWrite && source === 'host' && (
            <form style={{ marginTop: 14 }} noValidate>
              <CredentialFormFields
                register={editForm.register}
                authMethod={editForm.watch('auth_method')}
                errors={editForm.formState.errors}
                disabled={busy}
                mode="edit"
              />
              <div
                style={{
                  marginTop: 14,
                  paddingTop: 12,
                  borderTop: '1px solid var(--ow-line)',
                }}
              >
                {confirmRevert ? (
                  <Callout tier="warn">
                    <div style={{ marginBottom: 8 }}>
                      Remove this host credential? The host will fall back to the system default.
                    </div>
                    <div style={{ display: 'flex', gap: 8 }}>
                      <Btn onClick={() => setConfirmRevert(false)} disabled={busy}>
                        Keep it
                      </Btn>
                      <Btn variant="danger" onClick={() => revertMutation.mutate()} disabled={busy}>
                        {revertMutation.isPending ? (
                          <>
                            <Loader2 size={14} /> Reverting…
                          </>
                        ) : (
                          'Revert to system default'
                        )}
                      </Btn>
                    </div>
                  </Callout>
                ) : (
                  <Btn onClick={() => setConfirmRevert(true)} disabled={busy}>
                    Revert to system default
                  </Btn>
                )}
              </div>
            </form>
          )}

          {/* Inherits the system default: adopt a copy or set a different one. */}
          {canWrite && source === 'system' && mode === 'overview' && (
            <div
              style={{
                marginTop: 14,
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
              }}
            >
              <Btn variant="primary" onClick={() => cloneMutation.mutate()} disabled={busy}>
                {cloneMutation.isPending ? (
                  <>
                    <Loader2 size={14} /> Copying…
                  </>
                ) : (
                  'Use a copy of the default for this host'
                )}
              </Btn>
              <Btn onClick={() => setMode('newOverride')} disabled={busy}>
                Set a different credential for this host
              </Btn>
              <div style={{ fontSize: 11, color: 'var(--ow-fg-3)', marginTop: 2 }}>
                A copy keeps the default&apos;s key or password. Setting a different credential lets
                you enter new secrets for this host only.
              </div>
            </div>
          )}

          {/* New host override form (no default, or chose "different"). */}
          {canWrite && showingNewForm && (
            <form style={{ marginTop: 14 }} noValidate>
              <CredentialFormFields
                register={newForm.register}
                authMethod={newForm.watch('auth_method')}
                errors={newForm.formState.errors}
                disabled={busy}
                mode="create"
              />
            </form>
          )}

          {serverError && (
            <div style={{ marginTop: 12 }}>
              <Callout tier="crit">{serverError}</Callout>
            </div>
          )}
        </>
      )}
    </Modal>
  );
}

function SourceSummary({
  source,
  resolved,
  hostname,
}: {
  source: 'host' | 'system' | 'none';
  resolved: ResolvedCred | null;
  hostname: string;
}) {
  let headline: string;
  if (source === 'host') headline = 'This host uses its own credential.';
  else if (source === 'system') headline = 'This host inherits the system default credential.';
  else headline = 'No credential is set for this host, and there is no system default.';

  return (
    <div
      style={{
        background: 'var(--ow-bg-2)',
        border: '1px solid var(--ow-line)',
        borderRadius: 6,
        padding: '10px 12px',
        fontSize: 12,
      }}
    >
      <div style={{ color: 'var(--ow-fg-0)', marginBottom: resolved ? 6 : 0 }}>{headline}</div>
      {resolved && (
        <div style={{ color: 'var(--ow-fg-2)', fontFamily: 'var(--ow-font-mono)' }}>
          {resolved.name} · {resolved.username}@{hostname} · {resolved.auth_method}
        </div>
      )}
    </div>
  );
}
