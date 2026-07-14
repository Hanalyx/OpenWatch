import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { Select } from '@/components/settings/primitives';

// HostTargetControl — the host's durable COMPLIANCE TARGET: the framework
// family this host is held to. It is the per-host override that wins over any
// site-group target and becomes the host's default lens
// (framework.EffectiveTarget). Empty means "inherit" (a site-group target, else
// the org default). Writes POST /api/v1/hosts/{id}:target (host:write, enforced
// server-side; matching the config cards the control is not client-gated — a
// caller without the permission gets a 403 banner). Families come from the same
// corpus-derived list as the org default lens (GET /compliance/frameworks).
export function HostTargetControl({
  hostId,
  currentTarget,
}: {
  hostId: string;
  currentTarget?: string | null;
}) {
  const queryClient = useQueryClient();
  const [banner, setBanner] = useState<string | null>(null);

  const frameworksQuery = useQuery({
    queryKey: ['compliance-frameworks'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/compliance/frameworks');
      if (!response.ok) throw new Error(apiErrorMessage(error, 'Failed to load frameworks'));
      return data!.frameworks;
    },
  });

  const [value, setValue] = useState(currentTarget ?? '');
  useEffect(() => setValue(currentTarget ?? ''), [currentTarget]);

  const mutation = useMutation({
    mutationFn: async (next: string) => {
      const { response, error } = await api.POST('/api/v1/hosts/{id}:target', {
        params: { path: { id: hostId } },
        body: { target_framework: next },
      });
      if (!response.ok) throw new Error(apiErrorMessage(error, 'Failed to save target'));
    },
    onSuccess: () => {
      setBanner(null);
      // Refresh every host-scoped query (the lens summary + the framework-
      // agnostic target self-query) so the score and the default lens reflect
      // the new target.
      queryClient.invalidateQueries({ queryKey: ['host', hostId] });
    },
    onError: (e: Error) => setBanner(e.message),
  });

  const options = [
    { value: '', label: 'Inherit (group or org default)' },
    ...(frameworksQuery.data ?? []).map((f) => ({ value: f.id, label: f.label })),
  ];

  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
      <span
        style={{
          fontSize: 11,
          fontWeight: 600,
          color: 'var(--ow-fg-3)',
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
        }}
      >
        Compliance target
      </span>
      <Select
        value={value}
        onChange={(v) => {
          setValue(v);
          setBanner(null);
          mutation.mutate(v);
        }}
        ariaLabel="Host compliance target"
        options={options}
        width="240px"
        disabled={frameworksQuery.isLoading || mutation.isPending}
      />
      {banner && (
        <span role="alert" style={{ color: 'var(--ow-crit)', fontSize: 11 }}>
          {banner}
        </span>
      )}
    </span>
  );
}
