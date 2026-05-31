import { useEffect, useMemo, useState } from 'react';
import { Link } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import {
  AlertCircle,
  CheckCircle2,
  Download,
  Loader2,
  Play,
  XCircle,
} from 'lucide-react';
import api from '@/api/client';
import type { FieldMapping, ImportOptions, ImportRowOutcome } from './types';
import { applyMappings, downloadFailedRowsCSV, type MappedRow } from './applyMappings';
import {
  card,
  cardBody,
  cardHeader,
  errorPanel,
  infoPanel,
  primaryBtn,
  secondaryBtn,
  td,
  th,
} from './wizardStyles';

interface CredentialListEntry {
  id: string;
  name: string;
  scope: 'system' | 'host';
  username: string;
  auth_method: 'ssh_key' | 'password' | 'both';
  is_default: boolean;
  is_active: boolean;
}

// Step 3: validate every row against the host-create zod schema, show a
// preview, and (when the operator clicks Import) submit sequentially via
// POST /api/v1/hosts. Two credential strategies are wired:
//
//   - 'system_default' (default) — POST /hosts, no follow-up. Each host
//     resolves to the system-default credential at scan time.
//   - 'clone_template' — POST /hosts, then POST /credentials/{srcId}:clone
//     with scope=host + scope_id=newHostId. The host gets a dedicated
//     host-scoped credential that mirrors the chosen template's secret
//     material verbatim (server-side ciphertext copy — no plaintext
//     crosses the wire). A failed clone surfaces as 'partial' so the
//     operator can fix the credential association without losing the host.

interface Props {
  csvText: string;
  mappings: FieldMapping[];
  options: ImportOptions;
  onOptionsChange: (next: ImportOptions) => void;
}

interface RowState {
  preview: MappedRow;
  outcome: ImportRowOutcome;
}

function isNetworkError(e: unknown): boolean {
  return e instanceof TypeError && /fetch|network/i.test(e.message);
}

function describeNetworkError(e: unknown): string {
  if (isNetworkError(e)) {
    return 'Cannot reach the OpenWatch API. Start the backend (./dist/openwatch serve) or check the Vite proxy target (https://localhost:8443).';
  }
  return (e as Error)?.message ?? 'Unexpected network error';
}

export function PreviewImportStep({ csvText, mappings, options, onOptionsChange }: Props) {
  const preview = useMemo(() => applyMappings(csvText, mappings), [csvText, mappings]);
  const [rowStates, setRowStates] = useState<RowState[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [globalError, setGlobalError] = useState<string | null>(null);
  const [finished, setFinished] = useState(false);

  const credentialsQuery = useQuery({
    queryKey: ['credentials'],
    queryFn: async () => {
      const { data, response, error } = await api.GET('/api/v1/credentials');
      if (!response.ok || error) {
        // 403 → operator can't read credentials. Treat as empty so the
        // wizard still works (system-default mode), instead of breaking.
        return [] as CredentialListEntry[];
      }
      const raw = data as unknown as { credentials?: CredentialListEntry[] } | null;
      return (raw?.credentials ?? []).filter((c) => c.is_active);
    },
  });

  const credentialOptions = useMemo(
    () => credentialsQuery.data ?? [],
    [credentialsQuery.data],
  );

  useEffect(() => {
    // Re-seed pending outcomes whenever the preview changes (e.g. operator
    // went back to step 2 and changed a mapping). Don't clobber a finished
    // run — keep the outcomes visible.
    if (finished) return;
    setRowStates(
      preview.map((p) => ({
        preview: p,
        outcome: {
          row: p.index + 1,
          hostname: p.payload?.hostname ?? p.rawRow['hostname'] ?? `row ${p.index + 1}`,
          status: p.validationError ? 'failed' : 'pending',
          error: p.validationError,
        },
      })),
    );
  }, [preview, finished]);

  const validRows = preview.filter((p) => p.payload !== undefined);
  const invalidRows = preview.filter((p) => p.validationError !== undefined);
  const canSubmit = validRows.length > 0 && !submitting;

  const submit = async () => {
    setSubmitting(true);
    setGlobalError(null);

    // Reset outcomes from preview so a re-submit starts clean.
    const states: RowState[] = preview.map((p) => ({
      preview: p,
      outcome: {
        row: p.index + 1,
        hostname: p.payload?.hostname ?? p.rawRow['hostname'] ?? `row ${p.index + 1}`,
        status: p.validationError ? 'failed' : 'pending',
        error: p.validationError,
      },
    }));
    setRowStates(states);

    for (let i = 0; i < states.length; i++) {
      const s = states[i]!;
      const { preview: row } = s;
      if (!row.payload) continue;

      states[i] = {
        preview: row,
        outcome: { ...s.outcome, status: 'pending' },
      };

      if (options.dryRun) {
        states[i] = {
          preview: row,
          outcome: { ...s.outcome, status: 'skipped', action: 'create' },
        };
        setRowStates([...states]);
        continue;
      }

      try {
        const { data, response, error } = await api.POST('/api/v1/hosts', {
          body: row.payload,
        });
        if (response.ok && data) {
          const hostId = (data as { id: string }).id;
          let credentialNote: string | undefined;

          // Clone-template mode: attach a host-scoped credential by
          // cloning the chosen system credential into this host's
          // scope. Server-side ciphertext copy — no secret material
          // crosses the wire.
          if (
            options.credentialMode === 'clone_template' &&
            options.cloneSourceId
          ) {
            try {
              const cloneRes = await api.POST(
                '/api/v1/credentials/{id}:clone',
                {
                  params: { path: { id: options.cloneSourceId } },
                  body: {
                    scope: 'host',
                    scope_id: hostId,
                    name: `${row.payload.hostname} credential`,
                  } as never,
                },
              );
              if (!cloneRes.response.ok) {
                const cerr = cloneRes.error as
                  | { error?: { message?: string } }
                  | undefined;
                credentialNote =
                  cerr?.error?.message ??
                  `Host created but credential attach failed (HTTP ${cloneRes.response.status}). Attach manually under Settings → Credentials.`;
              }
            } catch (cloneErr) {
              credentialNote =
                describeNetworkError(cloneErr) ||
                'Host created but credential attach failed. Attach manually under Settings → Credentials.';
            }
          }

          states[i] = {
            preview: row,
            outcome: {
              ...s.outcome,
              status: 'created',
              action: 'create',
              hostId,
              error: credentialNote,
            },
          };
        } else {
          const err = error as { error?: { code?: string; message?: string } } | undefined;
          const code = err?.error?.code;
          // 409 / conflict-style errors → treat as duplicate. When
          // updateExisting is set we'd issue PATCH/PUT here, but the
          // Go API doesn't yet expose a per-host update endpoint, so
          // surface as "skipped" with a clear reason.
          if (response.status === 409 || code === 'duplicate' || code === 'conflict') {
            states[i] = {
              preview: row,
              outcome: {
                ...s.outcome,
                status: options.updateExisting ? 'skipped' : 'skipped',
                error: options.updateExisting
                  ? 'Update of existing hosts not yet supported in bulk mode. Edit the host directly.'
                  : 'Host already exists. Re-run with "Update existing" once that feature ships.',
              },
            };
          } else {
            states[i] = {
              preview: row,
              outcome: {
                ...s.outcome,
                status: 'failed',
                error: err?.error?.message ?? `HTTP ${response.status}`,
              },
            };
          }
        }
      } catch (e) {
        const msg = describeNetworkError(e);
        // Network failure → mark this row failed AND stop the loop to
        // avoid hammering a dead backend.
        states[i] = {
          preview: row,
          outcome: { ...s.outcome, status: 'failed', error: msg },
        };
        setRowStates([...states]);
        setGlobalError(msg);
        setSubmitting(false);
        setFinished(true);
        return;
      }
      setRowStates([...states]);
    }

    setSubmitting(false);
    setFinished(true);
  };

  const created = rowStates.filter((s) => s.outcome.status === 'created').length;
  const failed = rowStates.filter((s) => s.outcome.status === 'failed').length;
  const skipped = rowStates.filter((s) => s.outcome.status === 'skipped').length;

  const failedRows: MappedRow[] = rowStates
    .filter((s) => s.outcome.status === 'failed')
    .map((s) => ({
      ...s.preview,
      validationError: s.outcome.error ?? s.preview.validationError ?? 'failed',
    }));

  return (
    <>
      <section style={card}>
        <header style={cardHeader}>Import options</header>
        <div style={cardBody}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <input
              type="checkbox"
              checked={options.dryRun}
              onChange={(e) => onOptionsChange({ ...options, dryRun: e.target.checked })}
              disabled={submitting}
            />
            <span style={{ fontSize: 13 }}>
              <strong>Dry run</strong> — validate every row but skip the POST. No hosts are created.
            </span>
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <input
              type="checkbox"
              checked={options.updateExisting}
              onChange={(e) => onOptionsChange({ ...options, updateExisting: e.target.checked })}
              disabled={submitting}
            />
            <span style={{ fontSize: 13 }}>
              <strong>Update existing</strong> — overwrite hosts with the same hostname. <em>Not yet wired</em>:
              the Go API has no per-host update endpoint, so duplicates currently surface as &quot;skipped&quot;
              regardless.
            </span>
          </label>

          <fieldset
            style={{
              border: '1px solid var(--ow-line)',
              borderRadius: 6,
              padding: '10px 14px',
              margin: 0,
            }}
            disabled={submitting}
          >
            <legend
              style={{
                fontSize: 12,
                fontWeight: 600,
                color: 'var(--ow-fg-1)',
                padding: '0 6px',
              }}
            >
              Credentials
            </legend>
            <label
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: 8,
                marginBottom: 8,
              }}
            >
              <input
                type="radio"
                name="bulk-credential-mode"
                value="system_default"
                checked={options.credentialMode === 'system_default'}
                onChange={() =>
                  onOptionsChange({
                    ...options,
                    credentialMode: 'system_default',
                    cloneSourceId: undefined,
                  })
                }
                style={{ marginTop: 3 }}
              />
              <span style={{ fontSize: 13 }}>
                <strong>Use system default</strong> — each imported host falls back to the system-default credential at scan time. No per-host credential is created.
              </span>
            </label>
            <label
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: 8,
              }}
            >
              <input
                type="radio"
                name="bulk-credential-mode"
                value="clone_template"
                checked={options.credentialMode === 'clone_template'}
                onChange={() =>
                  onOptionsChange({
                    ...options,
                    credentialMode: 'clone_template',
                    cloneSourceId:
                      options.cloneSourceId ?? credentialOptions[0]?.id,
                  })
                }
                disabled={credentialOptions.length === 0}
                style={{ marginTop: 3 }}
              />
              <div style={{ flex: 1 }}>
                <span style={{ fontSize: 13 }}>
                  <strong>Clone an existing credential</strong> — every imported host gets a dedicated host-scoped credential cloned from the template you choose. The template&apos;s key / password is copied server-side as ciphertext; no secret material crosses the wire.
                </span>
                {options.credentialMode === 'clone_template' && (
                  <div style={{ marginTop: 6 }}>
                    {credentialsQuery.isLoading ? (
                      <span style={{ fontSize: 12, color: 'var(--ow-fg-3)' }}>
                        Loading credentials…
                      </span>
                    ) : credentialOptions.length === 0 ? (
                      <span style={{ fontSize: 12, color: 'var(--ow-warn)' }}>
                        No credentials available. Add one under Settings → Credentials first.
                      </span>
                    ) : (
                      <select
                        value={options.cloneSourceId ?? ''}
                        onChange={(e) =>
                          onOptionsChange({
                            ...options,
                            cloneSourceId: e.target.value || undefined,
                          })
                        }
                        aria-label="Credential template to clone"
                        style={{
                          fontSize: 13,
                          padding: '4px 8px',
                          background: 'var(--ow-bg-2)',
                          color: 'var(--ow-fg-0)',
                          border: '1px solid var(--ow-line)',
                          borderRadius: 4,
                          minWidth: 320,
                        }}
                      >
                        {credentialOptions.map((c) => (
                          <option key={c.id} value={c.id}>
                            {c.name} — {c.username} ({c.auth_method})
                            {c.is_default ? ' · default' : ''}
                          </option>
                        ))}
                      </select>
                    )}
                  </div>
                )}
                {credentialOptions.length === 0 &&
                  options.credentialMode === 'system_default' && (
                    <div
                      style={{
                        fontSize: 11,
                        color: 'var(--ow-fg-3)',
                        marginTop: 4,
                      }}
                    >
                      You have no credentials yet — the clone option will become available once you add one.
                    </div>
                  )}
              </div>
            </label>
          </fieldset>
        </div>
      </section>

      <section style={card}>
        <header style={cardHeader}>
          Preview — {validRows.length} valid / {invalidRows.length} invalid
        </header>
        <div style={cardBody}>
          {invalidRows.length > 0 && (
            <div style={infoPanel}>
              <AlertCircle size={12} style={{ verticalAlign: 'middle', marginRight: 6 }} />
              {invalidRows.length} row{invalidRows.length === 1 ? '' : 's'} failed validation and will be skipped.
              Download the failures CSV after import to fix and re-import.
            </div>
          )}

          {globalError && (
            <div role="alert" style={errorPanel}>
              <AlertCircle size={12} style={{ verticalAlign: 'middle', marginRight: 6 }} />
              {globalError}
            </div>
          )}

          <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 12 }}>
            <button
              type="button"
              onClick={submit}
              disabled={!canSubmit}
              aria-busy={submitting}
              style={{
                ...primaryBtn,
                opacity: canSubmit ? 1 : 0.5,
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              {submitting ? (
                <Loader2 size={14} />
              ) : (
                <Play size={14} />
              )}
              {submitting
                ? 'Importing…'
                : options.dryRun
                ? `Dry-run ${validRows.length} valid row${validRows.length === 1 ? '' : 's'}`
                : `Import ${validRows.length} valid row${validRows.length === 1 ? '' : 's'}`}
            </button>
            {finished && (
              <span style={{ fontSize: 13, color: 'var(--ow-fg-2)' }}>
                {created > 0 && (
                  <>
                    <strong style={{ color: 'var(--ow-ok)' }}>{created}</strong> created
                  </>
                )}
                {created > 0 && (skipped > 0 || failed > 0) && ' · '}
                {skipped > 0 && (
                  <>
                    <strong style={{ color: 'var(--ow-warn)' }}>{skipped}</strong> skipped
                  </>
                )}
                {skipped > 0 && failed > 0 && ' · '}
                {failed > 0 && (
                  <>
                    <strong style={{ color: 'var(--ow-crit)' }}>{failed}</strong> failed
                  </>
                )}
              </span>
            )}
          </div>

          <div style={{ maxHeight: 360, overflow: 'auto', border: '1px solid var(--ow-line)', borderRadius: 6 }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ background: 'var(--ow-bg-2)', position: 'sticky', top: 0 }}>
                  <th style={th}>#</th>
                  <th style={th}>Hostname</th>
                  <th style={th}>IP</th>
                  <th style={th}>Env</th>
                  <th style={th}>Status</th>
                  <th style={th}>Detail</th>
                </tr>
              </thead>
              <tbody>
                {rowStates.map((s) => (
                  <tr key={s.preview.index} style={{ borderTop: '1px solid var(--ow-line)' }}>
                    <td style={td}>{s.outcome.row}</td>
                    <td style={{ ...td, fontFamily: 'var(--ow-font-mono)', color: 'var(--ow-fg-0)' }}>
                      {s.preview.payload?.hostname ?? s.preview.rawRow['hostname'] ?? ''}
                    </td>
                    <td style={{ ...td, fontFamily: 'var(--ow-font-mono)', color: 'var(--ow-fg-2)' }}>
                      {s.preview.payload?.ip_address ?? s.preview.rawRow['ip_address'] ?? ''}
                    </td>
                    <td style={td}>{s.preview.payload?.environment ?? s.preview.rawRow['environment'] ?? '—'}</td>
                    <td style={td}>
                      <OutcomeBadge status={s.outcome.status} />
                    </td>
                    <td style={td}>
                      {s.outcome.status === 'created' && s.outcome.hostId && (
                        <Link
                          to="/hosts/$hostId"
                          params={{ hostId: s.outcome.hostId }}
                          style={{ color: 'var(--ow-info)' }}
                        >
                          View host
                        </Link>
                      )}
                      {s.outcome.status === 'failed' && (
                        <span style={{ color: 'var(--ow-crit)' }}>{s.outcome.error}</span>
                      )}
                      {s.outcome.status === 'skipped' && (
                        <span style={{ color: 'var(--ow-fg-2)' }}>
                          {s.outcome.error ?? (options.dryRun ? 'Dry run — not submitted' : 'Skipped')}
                        </span>
                      )}
                      {s.outcome.status === 'pending' && (
                        <span style={{ color: 'var(--ow-fg-3)' }}>queued</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {finished && failed > 0 && (
            <button
              type="button"
              onClick={() => downloadFailedRowsCSV(failedRows)}
              style={{ ...secondaryBtn, marginTop: 14, display: 'inline-flex', alignItems: 'center', gap: 6 }}
            >
              <Download size={14} />
              Download failed rows as CSV
            </button>
          )}
        </div>
      </section>
    </>
  );
}

function OutcomeBadge({ status }: { status: ImportRowOutcome['status'] }) {
  switch (status) {
    case 'created':
      return (
        <span style={{ color: 'var(--ow-ok)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
          <CheckCircle2 size={12} /> created
        </span>
      );
    case 'updated':
      return (
        <span style={{ color: 'var(--ow-info)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
          <CheckCircle2 size={12} /> updated
        </span>
      );
    case 'skipped':
      return (
        <span style={{ color: 'var(--ow-warn)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
          <AlertCircle size={12} /> skipped
        </span>
      );
    case 'failed':
      return (
        <span style={{ color: 'var(--ow-crit)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
          <XCircle size={12} /> failed
        </span>
      );
    case 'pending':
    default:
      return <span style={{ color: 'var(--ow-fg-3)' }}>pending</span>;
  }
}
