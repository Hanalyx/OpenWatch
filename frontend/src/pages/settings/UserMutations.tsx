import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Loader2, Trash2, X } from 'lucide-react';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { Modal, FormField, Btn, Callout, Select } from '@/components/settings/primitives';

// User mutation modals — Add (create) and Manage (roles + soft-delete).
//
// Wired against:
//   • POST   /api/v1/users                     (user:write)
//   • POST   /api/v1/users/{id}/roles:assign   (role:assign)
//   • POST   /api/v1/users/{id}/roles:unassign (role:assign)
//   • DELETE /api/v1/users/{id}                (user:delete)
//   • GET    /api/v1/roles                      (assignable role list)
//
// Spec: frontend-settings v1.4.0 (Users invite + manage).

export interface ManagedUser {
  id: string;
  username: string;
  email: string;
  roles?: string[];
}

const inputStyle = {
  background: 'var(--ow-bg-2)',
  border: '1px solid var(--ow-line)',
  borderRadius: 6,
  color: 'var(--ow-fg-0)',
  fontFamily: 'inherit',
  fontSize: 13,
  padding: '0 10px',
  height: 32,
  outline: 0,
  width: '100%',
} as const;

// ─────────────────────────────────────────────────────────────────────────
// Add member
// ─────────────────────────────────────────────────────────────────────────

const createSchema = z.object({
  username: z.string().min(1, 'Required').max(256, 'Too long'),
  email: z.string().min(3, 'Required').max(256, 'Too long').email('Enter a valid email'),
  password: z.string().min(8, 'At least 8 characters').max(256, 'Too long'),
});
type CreateShape = z.infer<typeof createSchema>;

export function AddUserModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [serverError, setServerError] = useState<string | null>(null);
  const { register, handleSubmit, formState, reset } = useForm<CreateShape>({
    resolver: zodResolver(createSchema),
    mode: 'onTouched',
  });

  const createMutation = useMutation({
    mutationFn: async (values: CreateShape) => {
      const { response, error } = await api.POST('/api/v1/users', {
        body: { username: values.username, email: values.email, password: values.password },
      });
      if (!response.ok) {
        throw new Error(
          apiErrorMessage(error, `Failed to create member (HTTP ${response.status})`),
        );
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      reset();
      setServerError(null);
      onClose();
    },
    onError: (err: Error) => setServerError(err.message),
  });

  const submitting = createMutation.isPending;
  const onSubmit = (values: CreateShape) => {
    setServerError(null);
    createMutation.mutate(values);
  };
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
      title="Invite member"
      width={460}
      footer={
        <>
          <Btn onClick={handleClose} disabled={submitting}>
            Cancel
          </Btn>
          <Btn
            variant="primary"
            type="submit"
            onClick={() => void handleSubmit(onSubmit)()}
            disabled={submitting}
          >
            {submitting ? (
              <>
                <Loader2 size={14} /> Creating.
              </>
            ) : (
              'Create member'
            )}
          </Btn>
        </>
      }
    >
      <form onSubmit={handleSubmit(onSubmit)} noValidate>
        <FormField label="Username" error={formState.errors.username?.message}>
          <input style={inputStyle} disabled={submitting} {...register('username')} />
        </FormField>
        <FormField label="Email" error={formState.errors.email?.message}>
          <input type="email" style={inputStyle} disabled={submitting} {...register('email')} />
        </FormField>
        <FormField label="Temporary password" error={formState.errors.password?.message}>
          <input
            type="password"
            style={inputStyle}
            disabled={submitting}
            autoComplete="new-password"
            {...register('password')}
          />
        </FormField>
        <p style={{ fontSize: 11, color: 'var(--ow-fg-3)', margin: '4px 0 0' }}>
          The member is created with the default role. Assign roles from Manage after creation.
        </p>
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
// Manage member — role assign/unassign + soft-delete
// ─────────────────────────────────────────────────────────────────────────

export function ManageUserModal({
  open,
  onClose,
  user,
}: {
  open: boolean;
  onClose: () => void;
  user: ManagedUser | null;
}) {
  const queryClient = useQueryClient();
  const [actionError, setActionError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [addRole, setAddRole] = useState('');

  // Assignable roles for the add-role picker.
  const rolesQuery = useQuery({
    queryKey: ['roles'],
    enabled: open,
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/roles');
      if (error || !response.ok) {
        throw new Error(apiErrorMessage(error, 'Failed to load roles'));
      }
      return data!.roles;
    },
  });

  const current = user?.roles ?? [];

  const assignMutation = useMutation({
    mutationFn: async ({ roleId, action }: { roleId: string; action: 'assign' | 'unassign' }) => {
      const path =
        action === 'assign'
          ? '/api/v1/users/{id}/roles:assign'
          : '/api/v1/users/{id}/roles:unassign';
      const { response, error } = await api.POST(path, {
        params: { path: { id: user!.id } },
        body: { role_id: roleId },
      });
      if (!response.ok) {
        throw new Error(apiErrorMessage(error, `Role change failed (HTTP ${response.status})`));
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setActionError(null);
      setAddRole('');
    },
    onError: (err: Error) => setActionError(err.message),
  });

  const deleteMutation = useMutation({
    mutationFn: async () => {
      const { response, error } = await api.DELETE('/api/v1/users/{id}', {
        params: { path: { id: user!.id } },
      });
      if (!response.ok) {
        throw new Error(
          apiErrorMessage(error, `Failed to remove member (HTTP ${response.status})`),
        );
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setActionError(null);
      setConfirmDelete(false);
      onClose();
    },
    onError: (err: Error) => setActionError(err.message),
  });

  const busy = assignMutation.isPending || deleteMutation.isPending;
  const assignable = (rolesQuery.data ?? []).map((r) => r.id).filter((id) => !current.includes(id));

  const handleClose = () => {
    if (busy) return;
    setActionError(null);
    setConfirmDelete(false);
    setAddRole('');
    onClose();
  };

  if (!user) return null;

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={`Manage ${user.username}`}
      width={480}
      footer={
        <Btn onClick={handleClose} disabled={busy}>
          Done
        </Btn>
      }
    >
      <div style={{ fontSize: 12, color: 'var(--ow-fg-2)', marginBottom: 16 }}>{user.email}</div>

      <div style={{ fontSize: 12, color: 'var(--ow-fg-1)', fontWeight: 500, marginBottom: 8 }}>
        Roles
      </div>
      {current.length === 0 ? (
        <div style={{ fontSize: 12, color: 'var(--ow-fg-3)', marginBottom: 12 }}>
          No roles assigned.
        </div>
      ) : (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 12 }}>
          {current.map((roleId) => (
            <span
              key={roleId}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                padding: '3px 6px 3px 10px',
                borderRadius: 'var(--ow-radius-sm)',
                background: 'var(--ow-bg-3)',
                color: 'var(--ow-fg-1)',
                fontSize: 12,
                fontFamily: 'var(--ow-font-mono)',
              }}
            >
              {roleId}
              <button
                type="button"
                aria-label={`Remove ${roleId}`}
                disabled={busy}
                onClick={() => assignMutation.mutate({ roleId, action: 'unassign' })}
                style={{
                  display: 'inline-flex',
                  background: 'transparent',
                  border: 0,
                  color: 'var(--ow-fg-3)',
                  cursor: busy ? 'not-allowed' : 'pointer',
                  padding: 0,
                }}
              >
                <X size={13} />
              </button>
            </span>
          ))}
        </div>
      )}

      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
        <Select
          value={addRole}
          onChange={setAddRole}
          ariaLabel="Add role"
          options={[
            { value: '', label: rolesQuery.isPending ? 'Loading roles.' : 'Add a role.' },
            ...assignable.map((id) => ({ value: id, label: id })),
          ]}
        />
        <Btn
          disabled={busy || !addRole}
          onClick={() => addRole && assignMutation.mutate({ roleId: addRole, action: 'assign' })}
        >
          Add
        </Btn>
      </div>

      <div
        style={{
          borderTop: '1px solid var(--ow-line)',
          marginTop: 16,
          paddingTop: 16,
        }}
      >
        {confirmDelete ? (
          <Callout tier="crit">
            <div style={{ marginBottom: 10 }}>
              Remove <strong>{user.username}</strong>? This soft-deletes the member.
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <Btn size="sm" onClick={() => setConfirmDelete(false)} disabled={busy}>
                Cancel
              </Btn>
              <Btn
                size="sm"
                variant="danger"
                disabled={busy}
                onClick={() => deleteMutation.mutate()}
              >
                {deleteMutation.isPending ? (
                  <>
                    <Loader2 size={13} /> Removing.
                  </>
                ) : (
                  'Confirm remove'
                )}
              </Btn>
            </div>
          </Callout>
        ) : (
          <Btn size="sm" variant="danger" disabled={busy} onClick={() => setConfirmDelete(true)}>
            <Trash2 size={13} /> Remove member
          </Btn>
        )}
      </div>

      {actionError && (
        <div style={{ marginTop: 12 }}>
          <Callout tier="crit">{actionError}</Callout>
        </div>
      )}
    </Modal>
  );
}
