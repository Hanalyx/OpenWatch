import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { SettingCard, FirstSettingRow, SettingRow, Toggle } from './primitives';

// EnabledFrameworksCard — the Phase 2 enabled-frameworks allowlist. An admin
// restricts which framework families are offered as lenses. Wired to
// GET /api/v1/compliance/frameworks?all=true (the full corpus family list) and
// GET/PUT /api/v1/system/compliance/config (enabled_frameworks). An empty
// allowlist means every family is available (the factory default); the master
// toggle expresses that. The current default lens must stay enabled, so its
// row is locked on (the backend enforces the same invariant). The write is
// server-enforced (system:config_write) — not client-gated.
export function EnabledFrameworksCard() {
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

  // The full corpus family list (all=true bypasses the allowlist filter).
  const allFrameworksQuery = useQuery({
    queryKey: ['compliance-frameworks-all'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/compliance/frameworks', {
        params: { query: { all: true } },
      });
      if (!response.ok) throw new Error(apiErrorMessage(error, 'Failed to load frameworks'));
      return data!.frameworks;
    },
  });

  const mutation = useMutation({
    mutationFn: async (next: { default_framework: string; enabled_frameworks: string[] }) => {
      const { response, error } = await api.PUT('/api/v1/system/compliance/config', { body: next });
      if (!response.ok) throw new Error(apiErrorMessage(error, 'Failed to save'));
    },
    onSuccess: () => {
      setBanner({ kind: 'success', text: 'Enabled frameworks saved.' });
      // The narrowed picker list (['compliance-frameworks']) also changes.
      queryClient.invalidateQueries({ queryKey: ['compliance-config'] });
      queryClient.invalidateQueries({ queryKey: ['compliance-frameworks'] });
    },
    onError: (e: Error) => setBanner({ kind: 'error', text: e.message }),
  });

  const cfg = configQuery.data;
  const allFrameworks = allFrameworksQuery.data ?? [];
  const enabled = cfg?.enabled_frameworks ?? [];
  const defaultFramework = cfg?.default_framework ?? '';
  const restrict = enabled.length > 0;
  const busy = mutation.isPending || configQuery.isLoading || allFrameworksQuery.isLoading;

  const save = (enabledNext: string[]) => {
    setBanner(null);
    mutation.mutate({ default_framework: defaultFramework, enabled_frameworks: enabledNext });
  };

  const setRestrict = (on: boolean) => {
    // On: seed with every family (explicit) so it's a no-op until trimmed.
    // Off: empty list means every family is available.
    save(on ? allFrameworks.map((f) => f.id) : []);
  };

  const toggleFamily = (id: string, on: boolean) => {
    save(on ? [...enabled, id] : enabled.filter((x) => x !== id));
  };

  return (
    <SettingCard>
      <FirstSettingRow
        name="Limit lens options"
        description={
          <>
            Restrict which framework families are offered as compliance lenses. Off means every
            framework found in the corpus is available.{' '}
            {banner?.kind === 'success' && (
              <span style={{ color: 'var(--ow-ok)' }}>{banner.text}</span>
            )}
            {banner?.kind === 'error' && (
              <span style={{ color: 'var(--ow-crit)' }}>{banner.text}</span>
            )}
          </>
        }
        control={
          <Toggle
            value={restrict}
            onChange={setRestrict}
            ariaLabel="Limit lens options"
            disabled={busy}
          />
        }
      />
      {restrict &&
        allFrameworks.map((f) => {
          const isDefault = f.id === defaultFramework;
          return (
            <SettingRow
              key={f.id}
              name={f.label}
              description={isDefault ? 'The current default lens must stay enabled.' : undefined}
              control={
                <Toggle
                  value={enabled.includes(f.id)}
                  onChange={(on) => toggleFamily(f.id, on)}
                  ariaLabel={f.label}
                  disabled={busy || isDefault}
                />
              }
            />
          );
        })}
    </SettingCard>
  );
}
