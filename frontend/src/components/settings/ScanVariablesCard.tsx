import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { Btn, Callout } from '@/components/settings/primitives';

// ─────────────────────────────────────────────────────────────────────────
// Scan variables — operator overrides for the kensa rule-template
// variables (GET/PUT /system/scan/variables). Only corpus-used
// variables are listed; the three organization-specific placeholder
// defaults carry a "Configure me" chip. Section-local save: the PUT
// replaces the full override map (values equal to the default are
// dropped server-side). The scan path picks the change up on the
// next scan. Lives on Settings > Compliance policies: the values
// define WHAT compliant means for the organization (policy content),
// not when scans run. Spec frontend-settings-scan-config v1.1.0.
// ─────────────────────────────────────────────────────────────────────────

export function ScanVariablesCard() {
  const queryClient = useQueryClient();
  const varsQuery = useQuery({
    queryKey: ['system', 'scan', 'variables'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/system/scan/variables', {});
      if (error) throw error;
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return data!;
    },
  });

  // Edits hold ONLY touched values; everything else renders straight
  // from the query data. No re-anchoring effect, so a refetch racing
  // a save can never resurrect stale values.
  const [edits, setEdits] = useState<Record<string, string>>({});

  const saveVarsMutation = useMutation({
    mutationFn: async (overrides: Record<string, string>) => {
      const { data, error, response } = await api.PUT('/api/v1/system/scan/variables', {
        body: { overrides },
      });
      if (error) throw error;
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return data!;
    },
    onSuccess: () => {
      setEdits({});
      queryClient.invalidateQueries({ queryKey: ['system', 'scan', 'variables'] });
    },
  });

  const vars = varsQuery.data?.variables;
  const varsDirty = useMemo(() => {
    if (!vars) return false;
    return vars.some((v) => edits[v.name] !== undefined && edits[v.name] !== v.value);
  }, [edits, vars]);

  if (varsQuery.isError) {
    return (
      <div style={{ marginTop: 14 }}>
        <Callout tier="crit">
          Failed to load scan variables: {apiErrorMessage(varsQuery.error, 'unknown error')}
        </Callout>
      </div>
    );
  }
  if (!vars || vars.length === 0) return null;

  const configureMeCount = vars.filter((v) => v.configure_me && !v.overridden).length;

  return (
    <div
      style={{
        marginTop: 14,
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: '14px 20px',
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'baseline',
          marginBottom: 4,
        }}
      >
        <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--ow-fg-1)' }}>
          Scan variables
        </span>
        <span style={{ fontSize: 11, color: 'var(--ow-fg-3)' }}>
          {vars.length} variables used by the rule corpus
        </span>
      </div>
      <p style={{ margin: '0 0 10px', color: 'var(--ow-fg-2)', fontSize: 12, lineHeight: 1.5 }}>
        Values are substituted into rule templates at scan time. Defaults are STIG-strict.
        {configureMeCount > 0 &&
          ` ${configureMeCount} placeholder ${configureMeCount === 1 ? 'value needs' : 'values need'} your organization's settings.`}
      </p>

      {vars.map((v, i) => {
        const value = edits[v.name] ?? v.value;
        const isDefault = value === v.default;
        return (
          <div
            key={v.name}
            style={{
              display: 'grid',
              gridTemplateColumns: 'minmax(0, 1fr) 320px',
              gap: 16,
              alignItems: 'center',
              padding: '10px 0',
              borderTop: i === 0 ? 'none' : '1px solid var(--ow-line)',
            }}
          >
            <div style={{ minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span
                  style={{
                    fontFamily: 'var(--ow-font-mono)',
                    fontSize: 12,
                    color: 'var(--ow-fg-0)',
                  }}
                >
                  {v.name}
                </span>
                {v.configure_me && !v.overridden && (
                  <span
                    style={{
                      fontSize: 10,
                      fontWeight: 600,
                      padding: '2px 7px',
                      borderRadius: 999,
                      background: 'color-mix(in oklab, var(--ow-warn) 18%, transparent)',
                      color: 'var(--ow-warn)',
                    }}
                  >
                    Configure me
                  </span>
                )}
              </div>
              <div style={{ color: 'var(--ow-fg-3)', fontSize: 11, marginTop: 2 }}>
                Affects {v.affects_rules} {v.affects_rules === 1 ? 'rule' : 'rules'}
                {!isDefault && <> · default: {v.default}</>}
              </div>
            </div>
            <input
              type="text"
              value={value}
              aria-label={`Value for ${v.name}`}
              onChange={(e) => setEdits((d) => ({ ...d, [v.name]: e.target.value }))}
              style={{
                height: 30,
                padding: '0 10px',
                background: 'var(--ow-bg-2)',
                border: `1px solid ${isDefault ? 'var(--ow-line)' : 'var(--ow-info)'}`,
                borderRadius: 7,
                color: 'var(--ow-fg-0)',
                fontFamily: 'var(--ow-font-mono)',
                fontSize: 12,
              }}
            />
          </div>
        );
      })}

      {varsDirty && (
        <div
          style={{
            display: 'flex',
            justifyContent: 'flex-end',
            gap: 8,
            marginTop: 12,
            alignItems: 'center',
          }}
        >
          {saveVarsMutation.error && (
            <span style={{ color: 'var(--ow-crit)', fontSize: 12 }}>
              {apiErrorMessage(saveVarsMutation.error, 'Save failed')}
            </span>
          )}
          <Btn onClick={() => setEdits({})}>Reset</Btn>
          <Btn
            variant="primary"
            disabled={saveVarsMutation.isPending}
            onClick={() => {
              if (!vars) return;
              const overrides: Record<string, string> = {};
              for (const v of vars) {
                const value = edits[v.name] ?? v.value;
                if (value !== v.default) overrides[v.name] = value;
              }
              saveVarsMutation.mutate(overrides);
            }}
          >
            {saveVarsMutation.isPending ? 'Saving' : 'Save variables'}
          </Btn>
        </div>
      )}
    </div>
  );
}
