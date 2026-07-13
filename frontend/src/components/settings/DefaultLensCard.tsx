import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { SettingCard, FirstSettingRow, Select } from './primitives';

// DefaultLensCard — the org-wide default compliance lens. An admin picks a
// framework FAMILY (or All rules); the score surfaces default to it. Wired to
// GET/PUT /api/v1/system/compliance/config and GET /api/v1/compliance/frameworks
// (the corpus-derived family list). The write is enforced server-side
// (system:config_write) — matching the other config cards, the control is not
// client-gated; a caller without the permission gets a 403 error banner.
export function DefaultLensCard() {
  const queryClient = useQueryClient();
  const [banner, setBanner] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);

  const configQuery = useQuery({
    queryKey: ['compliance-config'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/system/compliance/config');
      if (!response.ok) throw new Error(apiErrorMessage(error, 'Failed to load'));
      return data!;
    },
  });

  const frameworksQuery = useQuery({
    queryKey: ['compliance-frameworks'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/compliance/frameworks');
      if (!response.ok) throw new Error(apiErrorMessage(error, 'Failed to load frameworks'));
      return data!.frameworks;
    },
  });

  const [value, setValue] = useState('');
  useEffect(() => {
    if (configQuery.data) setValue(configQuery.data.default_framework ?? '');
  }, [configQuery.data]);

  const mutation = useMutation({
    mutationFn: async (next: string) => {
      const { response, error } = await api.PUT('/api/v1/system/compliance/config', {
        body: { default_framework: next },
      });
      if (!response.ok) throw new Error(apiErrorMessage(error, 'Failed to save'));
    },
    onSuccess: () => {
      setBanner({ kind: 'success', text: 'Default lens saved.' });
      queryClient.invalidateQueries({ queryKey: ['compliance-config'] });
    },
    onError: (e: Error) => setBanner({ kind: 'error', text: e.message }),
  });

  const options = [
    { value: '', label: 'All rules (full Kensa corpus)' },
    ...(frameworksQuery.data ?? []).map((f) => ({ value: f.id, label: f.label })),
  ];

  return (
    <SettingCard>
      <FirstSettingRow
        name="Default lens"
        description={
          <>
            The framework the dashboard, hosts, and host-detail compliance scores default to.
            Individual host views can still switch lens.{' '}
            {banner?.kind === 'success' && (
              <span style={{ color: 'var(--ow-ok)' }}>{banner.text}</span>
            )}
            {banner?.kind === 'error' && (
              <span style={{ color: 'var(--ow-crit)' }}>{banner.text}</span>
            )}
          </>
        }
        control={
          <Select
            value={value}
            onChange={(v) => {
              setValue(v);
              setBanner(null);
              mutation.mutate(v);
            }}
            ariaLabel="Default compliance lens"
            options={options}
            width="260px"
            disabled={configQuery.isLoading || mutation.isPending}
          />
        }
      />
    </SettingCard>
  );
}
