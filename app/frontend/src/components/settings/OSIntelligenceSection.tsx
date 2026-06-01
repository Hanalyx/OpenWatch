// OSIntelligenceSection — Settings > Scanning page section that exposes
// the three OS Intelligence scheduler knobs landed by
// api-system-intelligence-config v1.0 (PR 8).
//
// Spec: frontend-settings-intelligence-config v1.0.0.
//
// Three knobs:
//
//   interval_sec       — per-host cadence (300..86400, default 3600)
//   rate_limit         — concurrent RunCycles cap (1..200, default 10)
//   maintenance_global — boolean kill-switch
//
// Section-local Save/Reset controls (not the page-level SaveBar) — the
// page-level bar is already scoped to the connectivity draft state;
// coupling another draft into it would muddy dirty/save semantics.

import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { RefreshCw, RotateCcw } from 'lucide-react';
import api from '@/api/client';
import {
  Section,
  SettingCard,
  FirstSettingRow,
  SettingRow,
  Stepper,
  Toggle,
  Btn,
} from './primitives';

interface IntelligenceConfig {
  interval_sec: number;
  rate_limit: number;
  maintenance_global: boolean;
}

interface IntelligenceConfigResponse {
  config: IntelligenceConfig;
  defaults: IntelligenceConfig;
}

// openapi-fetch returns the raw response body as `error` for non-2xx
// statuses — it's NOT an Error instance, so `(err as Error).message`
// is undefined. Normalize the value into a single string that always
// leads with the HTTP status, so the alert never reads "Failed to
// load — Failed to load" again. Pulls the message from the
// ErrorEnvelope shape when present, otherwise just surfaces the code.
function formatApiError(status: number, error: unknown): string {
  let detail = '';
  if (error && typeof error === 'object') {
    const env = error as { error?: { code?: string; message?: string } };
    if (env.error?.message) detail = env.error.message;
    else if (env.error?.code) detail = env.error.code;
  } else if (typeof error === 'string' && error.length > 0) {
    detail = error;
  }
  return `HTTP ${status}${detail ? ` — ${detail}` : ''}`;
}

// Container — wires the queries + mutation and delegates rendering to
// the pure view below.
export function OSIntelligenceSection() {
  const queryClient = useQueryClient();

  const configQuery = useQuery<IntelligenceConfigResponse>({
    queryKey: ['system', 'intelligence', 'config'],
    queryFn: async () => {
      const { data, error, response } = await api.GET(
        '/api/v1/system/intelligence/config',
        {},
      );
      if (error || !response.ok) {
        throw new Error(formatApiError(response.status, error));
      }
      return data as IntelligenceConfigResponse;
    },
    retry: 0,
  });

  const [draft, setDraft] = useState<IntelligenceConfig | null>(null);
  useEffect(() => {
    if (configQuery.data && draft === null) {
      setDraft({ ...configQuery.data.config });
    }
  }, [configQuery.data, draft]);

  const mutation = useMutation({
    mutationFn: async (body: IntelligenceConfig) => {
      const { data, error, response } = await api.PUT(
        '/api/v1/system/intelligence/config',
        { body },
      );
      if (error || !response.ok) {
        throw new Error(formatApiError(response.status, error));
      }
      return data as IntelligenceConfig;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['system', 'intelligence', 'config'] });
    },
  });

  // Re-sync the draft to the server config on the post-save edge.
  // Without this, a server-side clamp (or any future divergence
  // between client and server validation) would leave the user with a
  // stale draft that looks "saved" but doesn't match server truth.
  // The clobber is gated on mutation.isSuccess so an in-flight edit
  // is never overwritten by an unrelated refetch.
  useEffect(() => {
    if (mutation.isSuccess && configQuery.data) {
      setDraft({ ...configQuery.data.config });
      mutation.reset();
    }
  }, [mutation, configQuery.data]);

  const dirty = useMemo(() => {
    if (!draft || !configQuery.data) return false;
    const live = configQuery.data.config;
    return (
      draft.interval_sec !== live.interval_sec ||
      draft.rate_limit !== live.rate_limit ||
      draft.maintenance_global !== live.maintenance_global
    );
  }, [draft, configQuery.data]);

  const onResetToLive = () => {
    if (configQuery.data) setDraft({ ...configQuery.data.config });
    mutation.reset();
  };

  const onResetToDefaults = () => {
    if (configQuery.data) setDraft({ ...configQuery.data.defaults });
    mutation.reset();
  };

  const onSave = () => {
    if (!draft) return;
    mutation.mutate(draft);
  };

  return (
    <OSIntelligenceSectionView
      isLoading={configQuery.isLoading}
      isError={configQuery.isError}
      errorMessage={
        configQuery.error
          ? (configQuery.error as Error)?.message ?? 'Failed to load'
          : null
      }
      onRetry={() => configQuery.refetch()}
      config={configQuery.data?.config ?? null}
      defaults={configQuery.data?.defaults ?? null}
      draft={draft}
      setDraft={setDraft}
      onResetToLive={onResetToLive}
      onResetToDefaults={onResetToDefaults}
      onSave={onSave}
      isSaving={mutation.isPending}
      saveError={
        mutation.error
          ? (mutation.error as Error)?.message ?? 'Save failed'
          : null
      }
      dirty={dirty}
    />
  );
}

// Pure view — accepts every state slice as props so tests can exercise
// the rendering logic without mocking useQuery or HTTP.
export function OSIntelligenceSectionView(props: {
  isLoading: boolean;
  isError: boolean;
  errorMessage: string | null;
  onRetry?: () => void;
  config: IntelligenceConfig | null;
  defaults: IntelligenceConfig | null;
  draft: IntelligenceConfig | null;
  setDraft: React.Dispatch<React.SetStateAction<IntelligenceConfig | null>>;
  onResetToLive: () => void;
  onResetToDefaults: () => void;
  onSave: () => void;
  isSaving: boolean;
  saveError: string | null;
  dirty: boolean;
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
  } = props;

  return (
    <Section title="OS Intelligence scheduler" badge="Wired" badgeTier="ok">
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
            Failed to load intelligence config{errorMessage ? ` — ${errorMessage}` : ''}
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
              name="Cycle interval"
              description="How often the scheduler advances next_intelligence_at for a host after a successful RunCycle. Bounds: 5 min .. 24 h."
              control={
                <Stepper
                  value={draft.interval_sec}
                  min={300}
                  max={86400}
                  step={300}
                  unit="sec"
                  onChange={(v) =>
                    setDraft((d) => (d ? { ...d, interval_sec: v } : d))
                  }
                />
              }
            />
            <SettingRow
              name="Concurrent workers"
              description="Cap on simultaneous RunCycles per scheduler instance. Bounds: 1 .. 200."
              control={
                <Stepper
                  value={draft.rate_limit}
                  min={1}
                  max={200}
                  step={1}
                  onChange={(v) =>
                    setDraft((d) => (d ? { ...d, rate_limit: v } : d))
                  }
                />
              }
            />
            <SettingRow
              name="Pause scheduler globally"
              description="When on, the scheduler loop ticks but no host is polled. Kill-switch for incident response."
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
            }}
          >
            {saveError && (
              <div role="alert" style={{ color: 'var(--ow-crit)', fontSize: 12, marginRight: 'auto' }}>
                {saveError}
              </div>
            )}
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
