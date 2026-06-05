// OSDiscoverySection — Settings > Scanning page section that exposes
// the four OS discovery scheduler knobs landed by
// api-system-discovery-config v1.0 + the manual sweep button.
//
// Spec: frontend-settings-discovery-config v1.0.0.
//
// Knobs:
//
//   interval_sec             — per-host cadence (3600..604800, default 86400)
//   rate_limit               — max enqueues per tick (1..500, default 25)
//   detect_on_first_contact  — gate POST /hosts auto-enqueue (default true)
//   maintenance_global       — boolean kill-switch
//
// Plus a "Run now" button that POSTs /api/v1/system/discovery/sweep
// and reports the enqueued count inline.

import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { PlayCircle, RefreshCw, RotateCcw } from 'lucide-react';
import api from '@/api/client';
import { apiErrorMessage, formatApiError } from '@/api/errors';
import {
  Section,
  SettingCard,
  FirstSettingRow,
  SettingRow,
  Stepper,
  Toggle,
  Btn,
} from './primitives';

interface DiscoveryConfig {
  interval_sec: number;
  rate_limit: number;
  detect_on_first_contact: boolean;
  maintenance_global: boolean;
}

interface DiscoveryConfigResponse {
  config: DiscoveryConfig;
  defaults: DiscoveryConfig;
}

// Container — wires the queries + mutations and delegates rendering to
// the pure view below.
export function OSDiscoverySection() {
  const queryClient = useQueryClient();

  const configQuery = useQuery<DiscoveryConfigResponse>({
    queryKey: ['system', 'discovery', 'config'],
    queryFn: async () => {
      const { data, error, response } = await api.GET(
        '/api/v1/system/discovery/config',
        {},
      );
      if (error || !response.ok) {
        throw new Error(formatApiError(response.status, error));
      }
      return data as DiscoveryConfigResponse;
    },
    retry: 0,
  });

  const [draft, setDraft] = useState<DiscoveryConfig | null>(null);
  useEffect(() => {
    if (configQuery.data && draft === null) {
      setDraft({ ...configQuery.data.config });
    }
  }, [configQuery.data, draft]);

  const saveMutation = useMutation({
    mutationFn: async (body: DiscoveryConfig) => {
      const { data, error, response } = await api.PUT(
        '/api/v1/system/discovery/config',
        { body },
      );
      if (error || !response.ok) {
        throw new Error(formatApiError(response.status, error));
      }
      return data as DiscoveryConfig;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['system', 'discovery', 'config'] });
    },
  });

  const sweepMutation = useMutation({
    mutationFn: async () => {
      const { data, error, response } = await api.POST(
        '/api/v1/system/discovery/sweep',
        {},
      );
      if (error || !response.ok) {
        throw new Error(formatApiError(response.status, error));
      }
      return data as { enqueued: number };
    },
  });

  useEffect(() => {
    if (saveMutation.isSuccess && configQuery.data) {
      setDraft({ ...configQuery.data.config });
      saveMutation.reset();
    }
  }, [saveMutation, configQuery.data]);

  const dirty = useMemo(() => {
    if (!draft || !configQuery.data) return false;
    const live = configQuery.data.config;
    return (
      draft.interval_sec !== live.interval_sec ||
      draft.rate_limit !== live.rate_limit ||
      draft.detect_on_first_contact !== live.detect_on_first_contact ||
      draft.maintenance_global !== live.maintenance_global
    );
  }, [draft, configQuery.data]);

  const onResetToLive = () => {
    if (configQuery.data) setDraft({ ...configQuery.data.config });
    saveMutation.reset();
  };

  const onResetToDefaults = () => {
    if (configQuery.data) setDraft({ ...configQuery.data.defaults });
    saveMutation.reset();
  };

  const onSave = () => {
    if (!draft) return;
    saveMutation.mutate(draft);
  };

  const onRunNow = () => {
    sweepMutation.mutate();
  };

  return (
    <OSDiscoverySectionView
      isLoading={configQuery.isLoading}
      isError={configQuery.isError}
      errorMessage={
        configQuery.error ? apiErrorMessage(configQuery.error, 'Failed to load') : null
      }
      onRetry={() => configQuery.refetch()}
      config={configQuery.data?.config ?? null}
      defaults={configQuery.data?.defaults ?? null}
      draft={draft}
      setDraft={setDraft}
      onResetToLive={onResetToLive}
      onResetToDefaults={onResetToDefaults}
      onSave={onSave}
      isSaving={saveMutation.isPending}
      saveError={
        saveMutation.error ? apiErrorMessage(saveMutation.error, 'Save failed') : null
      }
      dirty={dirty}
      onRunNow={onRunNow}
      isSweeping={sweepMutation.isPending}
      sweepResult={sweepMutation.data ?? null}
      sweepError={
        sweepMutation.error ? apiErrorMessage(sweepMutation.error, 'Sweep failed') : null
      }
    />
  );
}

// Pure view — accepts every state slice as props so tests can exercise
// the rendering logic without mocking useQuery or HTTP.
export function OSDiscoverySectionView(props: {
  isLoading: boolean;
  isError: boolean;
  errorMessage: string | null;
  onRetry?: () => void;
  config: DiscoveryConfig | null;
  defaults: DiscoveryConfig | null;
  draft: DiscoveryConfig | null;
  setDraft: React.Dispatch<React.SetStateAction<DiscoveryConfig | null>>;
  onResetToLive: () => void;
  onResetToDefaults: () => void;
  onSave: () => void;
  isSaving: boolean;
  saveError: string | null;
  dirty: boolean;
  onRunNow: () => void;
  isSweeping: boolean;
  sweepResult: { enqueued: number } | null;
  sweepError: string | null;
}) {
  const {
    isLoading,
    isError,
    errorMessage,
    onRetry,
    draft,
    setDraft,
    onResetToLive,
    onResetToDefaults,
    onSave,
    isSaving,
    saveError,
    dirty,
    onRunNow,
    isSweeping,
    sweepResult,
    sweepError,
  } = props;

  return (
    <Section title="OS discovery" badge="Wired" badgeTier="ok">
      {isLoading ? (
        <div role="status" style={{ color: 'var(--ow-fg-2)', fontSize: 12, padding: '8px 0' }}>
          Loading…
        </div>
      ) : isError ? (
        <div
          role="alert"
          style={{
            color: 'var(--ow-crit)',
            fontSize: 12,
            padding: '8px 0',
            display: 'flex',
            gap: 10,
            alignItems: 'center',
          }}
        >
          <span>
            Failed to load discovery config{errorMessage ? ` — ${errorMessage}` : ''}
          </span>
          {onRetry && (
            <Btn size="sm" onClick={onRetry}>
              <RefreshCw size={11} /> Retry
            </Btn>
          )}
        </div>
      ) : draft ? (
        <>
          <SettingCard>
            <FirstSettingRow
              name="Re-scan interval"
              description="A host whose os_discovered_at is older than this becomes due for re-discovery. Bounds: 1 h .. 7 d."
              control={
                <Stepper
                  value={draft.interval_sec}
                  min={3600}
                  max={604800}
                  step={3600}
                  unit="sec"
                  onChange={(v) =>
                    setDraft((d) => (d ? { ...d, interval_sec: v } : d))
                  }
                />
              }
            />
            <SettingRow
              name="Enqueues per tick"
              description="Cap on host.discovery jobs queued per scheduler tick. Bounds: 1 .. 500."
              control={
                <Stepper
                  value={draft.rate_limit}
                  min={1}
                  max={500}
                  step={5}
                  onChange={(v) =>
                    setDraft((d) => (d ? { ...d, rate_limit: v } : d))
                  }
                />
              }
            />
            <SettingRow
              name="Detect on first contact"
              description="When on, POST /hosts auto-enqueues a host.discovery job for the new host so it gets fingerprinted immediately. When off, the host stays at os_discovered_at NULL until the scheduler picks it up."
              control={
                <Toggle
                  value={draft.detect_on_first_contact}
                  onChange={(v) =>
                    setDraft((d) => (d ? { ...d, detect_on_first_contact: v } : d))
                  }
                  ariaLabel="Detect on first contact"
                />
              }
            />
            <SettingRow
              name="Pause scheduler globally"
              description="When on, the scheduler loop ticks but no host is enqueued. Also disables first-contact detection. Kill-switch for incident response."
              control={
                <Toggle
                  value={draft.maintenance_global}
                  onChange={(v) =>
                    setDraft((d) => (d ? { ...d, maintenance_global: v } : d))
                  }
                  ariaLabel="Pause scheduler globally"
                />
              }
            />
          </SettingCard>

          <div
            style={{
              display: 'flex',
              gap: 8,
              justifyContent: 'flex-end',
              alignItems: 'center',
              marginTop: 12,
              flexWrap: 'wrap',
            }}
          >
            {saveError && (
              <div role="alert" style={{ color: 'var(--ow-crit)', fontSize: 12, marginRight: 'auto' }}>
                {saveError}
              </div>
            )}
            {sweepError && !saveError && (
              <div role="alert" style={{ color: 'var(--ow-crit)', fontSize: 12, marginRight: 'auto' }}>
                {sweepError}
              </div>
            )}
            {sweepResult && !sweepError && !saveError && (
              <div role="status" style={{ color: 'var(--ow-fg-2)', fontSize: 12, marginRight: 'auto' }}>
                Queued {sweepResult.enqueued} discoveries.
              </div>
            )}
            <Btn onClick={onRunNow} disabled={isSweeping}>
              <PlayCircle size={12} /> {isSweeping ? 'Sweeping…' : 'Run now'}
            </Btn>
            <Btn onClick={onResetToDefaults} disabled={isLoading || isSaving}>
              <RotateCcw size={12} /> Reset to defaults
            </Btn>
            <Btn onClick={onResetToLive} disabled={!dirty || isSaving}>
              Discard changes
            </Btn>
            <Btn variant="primary" onClick={onSave} disabled={isLoading || !dirty || isSaving}>
              {isSaving ? 'Saving…' : 'Save changes'}
            </Btn>
          </div>
        </>
      ) : null}
    </Section>
  );
}
