import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';
import { Loader2 } from 'lucide-react';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { Modal, Btn, FormField, Callout } from '@/components/settings/primitives';

// EditHostModal — surfaces PATCH /api/v1/hosts/{id} so operators can fix
// drift in the patchable fields (IP, port, environment, tags, etc.)
// without rebuilding the host record. Hostname is intentionally not
// editable here per api-hosts C-04 (immutable in Slice A).

const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const ipv6 = /^[0-9a-fA-F:]+$/;

const editSchema = z.object({
  ip_address: z
    .string()
    .min(1, 'IP address is required')
    .max(64)
    .refine((v) => ipv4.test(v) || ipv6.test(v), 'Invalid IP address'),
  port: z.coerce.number().int().min(1).max(65535),
  environment: z.string().min(1, 'Environment is required').max(64),
  display_name: z.string().max(256).optional(),
  description: z.string().max(1024).optional(),
  username: z.string().max(256).optional(),
  // Tags edited as a comma-separated string; converted on submit.
  tags_csv: z.string().optional(),
});

type EditForm = z.infer<typeof editSchema>;

interface EditableHost {
  id: string;
  hostname: string;
  ip_address: string;
  port?: number;
  environment?: string;
  display_name?: string;
  description?: string;
  username?: string;
  tags?: string[];
}

interface Props {
  open: boolean;
  onClose: () => void;
  host: EditableHost;
}

function splitTags(csv: string | undefined): string[] {
  if (!csv) return [];
  return csv
    .split(',')
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}

export function EditHostModal({ open, onClose, host }: Props) {
  const queryClient = useQueryClient();
  const [serverError, setServerError] = useState<string | null>(null);
  const { register, handleSubmit, formState, reset } = useForm<EditForm>({
    resolver: zodResolver(editSchema),
    mode: 'onTouched',
    values: {
      ip_address: host.ip_address,
      port: host.port ?? 22,
      environment: host.environment ?? '',
      display_name: host.display_name ?? '',
      description: host.description ?? '',
      username: host.username ?? '',
      tags_csv: (host.tags ?? []).join(', '),
    },
  });

  const editMutation = useMutation({
    mutationFn: async (values: EditForm) => {
      // Only send fields the operator actually changed-or-kept-non-empty.
      // PATCH semantics: omitted fields are left unchanged. Sending empty
      // strings would clobber existing values, so coerce empties to
      // `undefined`.
      const body: Record<string, unknown> = {
        ip_address: values.ip_address,
        port: values.port,
        environment: values.environment,
        tags: splitTags(values.tags_csv),
      };
      if (values.display_name) body.display_name = values.display_name;
      if (values.description) body.description = values.description;
      if (values.username) body.username = values.username;

      const { response, error } = await api.PATCH('/api/v1/hosts/{id}', {
        params: { path: { id: host.id } },
        body: body as never,
      });
      if (!response.ok) {
        throw new Error(apiErrorMessage(error, `Failed to update host (HTTP ${response.status})`));
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['host', host.id] });
      queryClient.invalidateQueries({ queryKey: ['hosts'] });
      reset();
      setServerError(null);
      onClose();
    },
    onError: (err: Error) => {
      setServerError(err.message);
    },
  });

  const submitting = editMutation.isPending;

  const handleClose = () => {
    if (submitting) return;
    setServerError(null);
    onClose();
  };

  const onSubmit = (values: EditForm) => {
    setServerError(null);
    editMutation.mutate(values);
  };

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={`Edit ${host.hostname}`}
      width={520}
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
        <p
          style={{
            margin: '0 0 14px',
            fontSize: 12,
            color: 'var(--ow-fg-2)',
          }}
        >
          Hostname is immutable — to rename a host, remove it and add it again.
        </p>

        <FormField label="IP address" error={formState.errors.ip_address?.message}>
          <input type="text" {...register('ip_address')} style={inputStyle} />
        </FormField>

        <FormField label="SSH port" error={formState.errors.port?.message}>
          <input
            type="number"
            min={1}
            max={65535}
            {...register('port', { valueAsNumber: true })}
            style={inputStyle}
          />
        </FormField>

        <FormField label="Environment" error={formState.errors.environment?.message}>
          <input type="text" {...register('environment')} style={inputStyle} />
        </FormField>

        <FormField label="Display name" error={formState.errors.display_name?.message}>
          <input type="text" {...register('display_name')} style={inputStyle} />
        </FormField>

        <FormField label="Username" error={formState.errors.username?.message}>
          <input type="text" {...register('username')} style={inputStyle} />
        </FormField>

        <FormField
          label="Tags"
          hint="Comma-separated. Leave blank to clear all tags."
          error={formState.errors.tags_csv?.message}
        >
          <input type="text" {...register('tags_csv')} style={inputStyle} />
        </FormField>

        <FormField label="Description" error={formState.errors.description?.message}>
          <textarea
            rows={3}
            {...register('description')}
            style={{
              ...inputStyle,
              height: 'auto',
              padding: 8,
              fontFamily: 'inherit',
              resize: 'vertical',
            }}
          />
        </FormField>

        {serverError && (
          <div style={{ marginTop: 12 }}>
            <Callout tier="crit">{serverError}</Callout>
          </div>
        )}
      </form>
    </Modal>
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
};
