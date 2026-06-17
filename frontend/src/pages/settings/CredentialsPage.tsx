import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { KeyRound, Plus, Check, Edit3, Copy, Trash2, HelpCircle, Upload } from 'lucide-react';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import { useAuthStore } from '@/store/useAuthStore';
import { SettingsLayout } from '@/components/settings/SettingsLayout';
import {
  PageHead,
  Section,
  SettingCard,
  SettingRow,
  FirstSettingRow,
  Toggle,
  Stepper,
  Select,
  Btn,
  StatusPill,
  StatMini,
  StatMiniRow,
  Callout,
} from '@/components/settings/primitives';
import {
  AddCredentialModal,
  EditCredentialModal,
  DeleteCredentialModal,
  type Credential as MutableCredential,
} from './CredentialMutations';

// Settings → SSH & credentials.
//
// Wired:
//   • GET /api/v1/credentials   — credentials table
//
// UI only (pending backend):
//   • POST /api/v1/credentials  — Add credential form (modal flow pending)
//   • DELETE /api/v1/credentials/{id} — Delete (modal flow pending)
//   • POST /api/v1/credentials/{id}:test — endpoint not in OpenAPI yet
//   • SSH keys — vault endpoint pending
//   • Connection defaults — ssh_config persistence endpoint pending
//   • Host key verification — known_hosts UI pending
//
// Spec: frontend-settings v1.1.0 (SSH & credentials section).

// ─────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────

interface Credential {
  id: string;
  scope: 'system' | 'host';
  scope_id?: string | null;
  name: string;
  description?: string;
  username: string;
  auth_method: 'ssh_key' | 'password' | 'both';
  ssh_key_fingerprint?: string;
  ssh_key_type?: string;
  ssh_key_bits?: number;
  ssh_key_comment?: string;
  is_default: boolean;
  is_active?: boolean;
  created_at: string;
  updated_at: string;
}

// SSH keys derived from credentials. Each key-bearing credential
// (auth_method ssh_key | both) contributes one row. The CredentialResponse
// already exposes the public key metadata (fingerprint, type, bits, comment);
// the private material stays in the workspace vault and is never returned.
interface KeyView {
  credentialId: string;
  displayName: string;
  fingerprint: string;
  type: string;
  bits: number;
  isDefault: boolean;
  addedAt: string;
  updatedAt: string;
}

function credentialsToKeys(credentials: Credential[]): KeyView[] {
  return credentials
    .filter(
      (c) => (c.auth_method === 'ssh_key' || c.auth_method === 'both') && c.ssh_key_fingerprint,
    )
    .map((c) => ({
      credentialId: c.id,
      displayName: c.ssh_key_comment || c.name,
      fingerprint: c.ssh_key_fingerprint ?? '',
      type: c.ssh_key_type ?? '—',
      bits: c.ssh_key_bits ?? 0,
      isDefault: c.is_default,
      addedAt: c.created_at,
      updatedAt: c.updated_at,
    }));
}

// ─────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────

export function CredentialsPage() {
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);
  const canWrite = useAuthStore((s) => s.hasPermission('credential:write'));
  const canDelete = useAuthStore((s) => s.hasPermission('credential:delete'));

  const [addOpen, setAddOpen] = useState(false);
  const [replaceTarget, setReplaceTarget] = useState<MutableCredential | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<MutableCredential | null>(null);

  useEffect(() => {
    setCrumbs([{ label: 'Settings' }, { label: 'SSH & credentials' }]);
    return () => setCrumbs([]);
  }, [setCrumbs]);

  const credsQuery = useQuery({
    queryKey: ['credentials'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/credentials');
      if (error) throw error;
      return (data as { credentials: Credential[] }).credentials ?? [];
    },
    retry: 0,
  });

  // Real host inventory — drives the "Covered hosts" coverage stat. A host
  // is covered when a credential resolves to it: a host-scoped credential,
  // or any default credential (which covers the whole fleet).
  const hostsQuery = useQuery({
    queryKey: ['hosts', 'coverage'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/hosts', {});
      if (error) throw error;
      return (data as { hosts: { id: string }[] }).hosts ?? [];
    },
    retry: 0,
  });

  const credentials = credsQuery.data ?? [];
  const defaultCount = credentials.filter((c) => c.is_default).length;
  const hostScopedCount = credentials.filter((c) => c.scope === 'host').length;
  const keys = credentialsToKeys(credentials);
  const activeKeys = keys.length;

  // Coverage from real data (no hardcoded fixture). A default credential
  // covers every host; otherwise only hosts with a host-scoped credential.
  const totalHosts = hostsQuery.data?.length ?? 0;
  const hasDefault = credentials.some((c) => c.is_default);
  const hostScopedTargets = new Set(
    credentials.filter((c) => c.scope === 'host' && c.scope_id).map((c) => c.scope_id),
  );
  const coveredHosts = hasDefault
    ? totalHosts
    : (hostsQuery.data ?? []).filter((h) => hostScopedTargets.has(h.id)).length;
  const coverageTier: 'ok' | 'warn' | 'crit' =
    totalHosts === 0
      ? 'warn'
      : coveredHosts >= totalHosts
        ? 'ok'
        : coveredHosts > 0
          ? 'warn'
          : 'crit';

  // Connection defaults (local state, persists pending backend).
  const [sshPort, setSshPort] = useState(22);
  const [connectTimeout, setConnectTimeout] = useState(30);
  const [keepAlive, setKeepAlive] = useState(60);
  const [concurrent, setConcurrent] = useState(25);

  // Host key verification.
  const [strictHostKey, setStrictHostKey] = useState('warn');
  const [autoAddKeys, setAutoAddKeys] = useState(true);
  const [allowedAlgos, setAllowedAlgos] = useState('modern');

  const dirty = useMemo(() => {
    return (
      sshPort !== 22 ||
      connectTimeout !== 30 ||
      keepAlive !== 60 ||
      concurrent !== 25 ||
      strictHostKey !== 'warn' ||
      !autoAddKeys ||
      allowedAlgos !== 'modern'
    );
  }, [sshPort, connectTimeout, keepAlive, concurrent, strictHostKey, autoAddKeys, allowedAlgos]);

  const resetDefaults = () => {
    setSshPort(22);
    setConnectTimeout(30);
    setKeepAlive(60);
    setConcurrent(25);
    setStrictHostKey('warn');
    setAutoAddKeys(true);
    setAllowedAlgos('modern');
  };

  return (
    <SettingsLayout>
      <PageHead
        title="SSH & credentials"
        description="Credentials OpenWatch uses to reach your hosts, plus global SSH client settings. Credentials are encrypted at rest with the workspace master key."
        actions={
          <Btn variant="primary" onClick={() => setAddOpen(true)} disabled={!canWrite}>
            <Plus size={14} /> Add credential
          </Btn>
        }
      />

      {/* Coverage stat row */}
      <StatMiniRow>
        <StatMini
          label="Covered hosts"
          value={coveredHosts}
          unit={<span style={{ color: 'var(--ow-fg-3)' }}> / {totalHosts}</span>}
          hint={
            hasDefault ? 'Default credential covers all hosts' : 'Hosts with a credential resolved'
          }
          tier={coverageTier}
        />
        <StatMini
          label="Credentials"
          value={credentials.length || 0}
          hint={`${defaultCount} default · ${hostScopedCount} host-specific`}
        />
        <StatMini label="Keys on file" value={keys.length} hint={`${activeKeys} in active use`} />
      </StatMiniRow>

      {/* ────────── Credentials table ────────── */}
      <Section title="Credentials">
        <p style={leadStyle}>
          A host inherits the <strong>default</strong> credential unless an override is set on the
          host page. Test a credential to verify it can authenticate before saving.
        </p>

        <SettingCard>
          {credsQuery.isLoading && (
            <div style={{ padding: 20, color: 'var(--ow-fg-2)', fontSize: 13 }}>
              Loading credentials…
            </div>
          )}
          {credsQuery.isError && (
            <div
              role="alert"
              style={{
                padding: 16,
                color: 'var(--ow-fg-1)',
                background: 'var(--ow-crit-bg)',
                borderLeft: '3px solid var(--ow-crit)',
                fontSize: 13,
              }}
            >
              <strong>Failed to load credentials.</strong> {apiErrorMessage(credsQuery.error, '')}{' '}
              <button
                type="button"
                onClick={() => credsQuery.refetch()}
                style={{
                  marginLeft: 12,
                  background: 'transparent',
                  border: 0,
                  color: 'var(--ow-info)',
                  cursor: 'pointer',
                  textDecoration: 'underline',
                }}
              >
                Retry
              </button>
            </div>
          )}
          {credsQuery.data && credentials.length === 0 && (
            <div
              style={{
                padding: 32,
                textAlign: 'center',
                color: 'var(--ow-fg-2)',
                fontSize: 13,
              }}
            >
              No credentials yet. Use Add credential to onboard your first host login.
            </div>
          )}
          {credentials.length > 0 && (
            <CredentialsTable
              credentials={credentials}
              canWrite={canWrite}
              canDelete={canDelete}
              onReplace={setReplaceTarget}
              onDelete={setDeleteTarget}
            />
          )}
          <div
            style={{
              padding: '12px 20px',
              borderTop: '1px solid var(--ow-line)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <span style={{ color: 'var(--ow-fg-3)', fontSize: 12 }}>
              A host can override the default in its own settings. Per-host overrides take
              precedence.
            </span>
            <Btn size="sm" onClick={() => setAddOpen(true)} disabled={!canWrite}>
              <Plus size={12} /> Add credential
            </Btn>
          </div>
        </SettingCard>
      </Section>

      {/* ────────── SSH keys ────────── */}
      <Section title="SSH keys">
        <p style={leadStyle}>
          Each row is the SSH key embedded in a credential. Adding a key creates a credential that
          owns it; replacing a key replaces the parent credential; removing a key removes the
          credential.
        </p>

        <div style={{ marginBottom: 14 }}>
          <Callout tier="info">
            <strong style={{ color: 'var(--ow-fg-0)' }}>Keys are owned by credentials.</strong> A
            standalone vault — share one key across many credentials — is a future enhancement and
            is tracked in BACKLOG.md. For now, manage keys through the parent credential.
          </Callout>
        </div>

        <SettingCard>
          {keys.length === 0 ? (
            <div
              style={{
                padding: 32,
                textAlign: 'center',
                color: 'var(--ow-fg-2)',
                fontSize: 13,
              }}
            >
              No SSH keys on file yet.{' '}
              {canWrite && (
                <button
                  type="button"
                  onClick={() => setAddOpen(true)}
                  style={{
                    background: 'transparent',
                    border: 0,
                    color: 'var(--ow-info)',
                    cursor: 'pointer',
                    textDecoration: 'underline',
                  }}
                >
                  Add an SSH credential
                </button>
              )}
            </div>
          ) : (
            keys.map((key, i) => {
              const parentCred = credentials.find((c) => c.id === key.credentialId);
              return (
                <KeyRow
                  key={key.credentialId}
                  keyView={key}
                  isFirst={i === 0}
                  canWrite={canWrite}
                  canDelete={canDelete}
                  onReplace={() => parentCred && setReplaceTarget(parentCred)}
                  onDelete={() => parentCred && setDeleteTarget(parentCred)}
                />
              );
            })
          )}
          <div
            style={{
              padding: '12px 20px',
              borderTop: '1px solid var(--ow-line)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <span style={{ color: 'var(--ow-fg-3)', fontSize: 12 }}>
              Private keys never leave the workspace vault. Only fingerprints are displayed.
            </span>
            <div style={{ display: 'flex', gap: 8 }}>
              <Btn size="sm" onClick={() => setAddOpen(true)} disabled={!canWrite}>
                <Upload size={12} /> Add key (via credential)
              </Btn>
            </div>
          </div>
        </SettingCard>
      </Section>

      {/* ────────── Connection defaults ────────── */}
      <Section title="Connection defaults">
        <p style={leadStyle}>
          Applied to every SSH connection unless a host overrides the value. These map onto standard{' '}
          <code style={{ fontFamily: 'var(--ow-font-mono)', color: 'var(--ow-fg-1)' }}>
            ssh_config
          </code>{' '}
          options.
        </p>

        <SettingCard>
          <FirstSettingRow
            name="Default SSH port"
            description={
              <>
                Port used when a host doesn't specify one. Standard is{' '}
                <code style={{ fontFamily: 'var(--ow-font-mono)' }}>22</code>.
              </>
            }
            control={
              <Stepper
                value={sshPort}
                onChange={setSshPort}
                min={1}
                max={65535}
                step={1}
                unit="port"
              />
            }
          />
          <SettingRow
            name="Connect timeout"
            description="How long to wait for a TCP handshake before giving up. Counts toward the connectivity-failure tally."
            control={
              <Stepper
                value={connectTimeout}
                onChange={setConnectTimeout}
                min={1}
                max={300}
                step={1}
                unit="sec"
              />
            }
          />
          <SettingRow
            name="Keep-alive interval"
            description={
              <>
                Send <code style={{ fontFamily: 'var(--ow-font-mono)' }}>ServerAliveInterval</code>{' '}
                probes during long scans so idle hosts don't drop the session.
              </>
            }
            control={
              <Stepper
                value={keepAlive}
                onChange={setKeepAlive}
                min={0}
                max={3600}
                step={5}
                unit="sec"
              />
            }
          />
          <SettingRow
            name="Concurrent connections"
            description="Cap on simultaneous SSH sessions across the fleet. Higher = faster sweeps, more network load."
            control={
              <Stepper
                value={concurrent}
                onChange={setConcurrent}
                min={1}
                max={200}
                step={1}
                unit="conns"
              />
            }
          />
        </SettingCard>
      </Section>

      {/* ────────── Host key verification ────────── */}
      <Section title="Host key verification">
        <p style={leadStyle}>
          Controls how OpenWatch handles new or changed SSH host keys. Stricter settings prevent
          man-in-the-middle attacks; relaxed settings make rotation easier.
        </p>

        <SettingCard>
          <FirstSettingRow
            name={
              <>
                Strict host key checking{' '}
                <HelpCircle
                  size={13}
                  color="var(--ow-fg-3)"
                  aria-label="Maps to ssh_config StrictHostKeyChecking"
                />
              </>
            }
            description="When a host key changes, what should OpenWatch do?"
            control={
              <Select
                value={strictHostKey}
                onChange={setStrictHostKey}
                options={[
                  { value: 'warn', label: 'Warn and continue (default)' },
                  { value: 'reject', label: 'Reject the connection' },
                  { value: 'accept', label: 'Accept silently — not recommended' },
                ]}
                width={260}
              />
            }
          />
          <SettingRow
            name="Auto-add new host keys"
            description={
              <>
                Add a host's public key to{' '}
                <code style={{ fontFamily: 'var(--ow-font-mono)' }}>known_hosts</code> on first
                contact. Disable to require manual approval.
              </>
            }
            control={
              <Toggle
                value={autoAddKeys}
                onChange={setAutoAddKeys}
                ariaLabel="Auto-add new host keys"
              />
            }
          />
          <SettingRow
            name="Allowed key algorithms"
            description="Restrict which host key types OpenWatch will accept. Older algorithms are disabled by default."
            control={
              <Select
                value={allowedAlgos}
                onChange={setAllowedAlgos}
                options={[
                  { value: 'modern', label: 'Modern (ED25519 + ECDSA + RSA-SHA2)' },
                  { value: 'strict', label: 'Strict (ED25519 only)' },
                  { value: 'permissive', label: 'Permissive (allow legacy RSA)' },
                ]}
                width={260}
              />
            }
          />
        </SettingCard>

        <div style={{ marginTop: 14 }}>
          <Callout tier="info">
            <strong style={{ color: 'var(--ow-fg-0)' }}>known_hosts is workspace-scoped.</strong>{' '}
            All connections share one trusted-keys database. To inspect or revoke individual
            entries, use{' '}
            <a href="#known-hosts" style={{ color: 'var(--ow-info)', fontWeight: 500 }}>
              Manage known hosts →
            </a>
          </Callout>
        </div>
      </Section>

      {dirty && <SaveBar onReset={resetDefaults} />}

      <AddCredentialModal open={addOpen} onClose={() => setAddOpen(false)} />
      <EditCredentialModal
        open={replaceTarget !== null}
        onClose={() => setReplaceTarget(null)}
        credential={replaceTarget as MutableCredential | null}
      />
      <DeleteCredentialModal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        credential={deleteTarget as MutableCredential | null}
      />
    </SettingsLayout>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Credentials table
// ─────────────────────────────────────────────────────────────────────────

function CredentialsTable({
  credentials,
  canWrite,
  canDelete,
  onReplace,
  onDelete,
}: {
  credentials: Credential[];
  canWrite: boolean;
  canDelete: boolean;
  onReplace: (c: MutableCredential) => void;
  onDelete: (c: MutableCredential) => void;
}) {
  return (
    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
      <thead>
        <tr>
          <th style={tableHeader}>Credential</th>
          <th style={tableHeader}>Username</th>
          <th style={tableHeader}>Method</th>
          <th style={tableHeader}>Used by</th>
          <th style={tableHeader}>Status</th>
          <th style={{ ...tableHeader, textAlign: 'right' }}>Actions</th>
        </tr>
      </thead>
      <tbody>
        {credentials.map((cred) => (
          <CredentialRow
            key={cred.id}
            cred={cred}
            canWrite={canWrite}
            canDelete={canDelete}
            onReplace={onReplace}
            onDelete={onDelete}
          />
        ))}
      </tbody>
    </table>
  );
}

function CredentialRow({
  cred,
  canWrite,
  canDelete,
  onReplace,
  onDelete,
}: {
  cred: Credential;
  canWrite: boolean;
  canDelete: boolean;
  onReplace: (c: MutableCredential) => void;
  onDelete: (c: MutableCredential) => void;
}) {
  const methodLabel =
    cred.auth_method === 'ssh_key'
      ? 'SSH key'
      : cred.auth_method === 'password'
        ? 'Password'
        : 'Key + password fallback';
  const usedByText = cred.is_default ? 'All hosts (default)' : '1 host';

  return (
    <tr style={{ borderTop: '1px solid var(--ow-line)' }}>
      <td style={tableCell}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div
            style={{
              width: 28,
              height: 28,
              borderRadius: 6,
              background: 'var(--ow-bg-3)',
              display: 'grid',
              placeItems: 'center',
              color: 'var(--ow-fg-1)',
              flexShrink: 0,
            }}
          >
            <KeyRound size={14} />
          </div>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontWeight: 500, display: 'flex', alignItems: 'center', gap: 8 }}>
              {cred.name}
              {cred.is_default && (
                <span
                  style={{
                    background: 'var(--ow-info-bg)',
                    color: 'var(--ow-info)',
                    fontSize: 10,
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    letterSpacing: '0.06em',
                    padding: '3px 7px',
                    borderRadius: 4,
                  }}
                >
                  Default
                </span>
              )}
            </div>
            <div
              style={{
                color: 'var(--ow-fg-3)',
                fontSize: 11,
                marginTop: 2,
                fontFamily: 'var(--ow-font-mono)',
              }}
            >
              Created {new Date(cred.created_at).toLocaleDateString()}
            </div>
          </div>
        </div>
      </td>
      <td style={{ ...tableCell, fontFamily: 'var(--ow-font-mono)', color: 'var(--ow-fg-1)' }}>
        {cred.username}
      </td>
      <td style={tableCell}>{methodLabel}</td>
      <td style={tableCell}>
        <span style={{ color: 'var(--ow-fg-1)', fontWeight: 500 }}>{usedByText}</span>
      </td>
      <td style={tableCell}>
        <StatusPill tier="ok">Active</StatusPill>
      </td>
      <td style={{ ...tableCell, textAlign: 'right', whiteSpace: 'nowrap' }}>
        <div style={{ display: 'inline-flex', gap: 4, justifyContent: 'flex-end' }}>
          <IconBtn label="Test connection (pending)" disabled>
            <Check size={12} />
          </IconBtn>
          <IconBtn label="Edit credential" disabled={!canWrite} onClick={() => onReplace(cred)}>
            <Edit3 size={12} />
          </IconBtn>
          <IconBtn
            label="Delete credential"
            tier="crit"
            disabled={!canDelete}
            onClick={() => onDelete(cred)}
          >
            <Trash2 size={12} />
          </IconBtn>
        </div>
      </td>
    </tr>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// SSH key row
// ─────────────────────────────────────────────────────────────────────────

function KeyRow({
  keyView,
  isFirst,
  canWrite,
  canDelete,
  onReplace,
  onDelete,
}: {
  keyView: KeyView;
  isFirst: boolean;
  canWrite: boolean;
  canDelete: boolean;
  onReplace: () => void;
  onDelete: () => void;
}) {
  const copyFingerprint = () => {
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      void navigator.clipboard.writeText(keyView.fingerprint);
    }
  };

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '1fr auto auto',
        gap: 16,
        alignItems: 'center',
        padding: '14px 20px',
        borderTop: isFirst ? 'none' : '1px solid var(--ow-line)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, minWidth: 0 }}>
        <div
          style={{
            width: 32,
            height: 32,
            borderRadius: 8,
            background: 'var(--ow-bg-3)',
            display: 'grid',
            placeItems: 'center',
            color: 'var(--ow-fg-1)',
            flexShrink: 0,
          }}
        >
          <KeyRound size={14} />
        </div>
        <div style={{ minWidth: 0 }}>
          <div
            style={{
              fontWeight: 500,
              color: 'var(--ow-fg-0)',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            {keyView.displayName}
            {keyView.isDefault && (
              <span
                style={{
                  background: 'var(--ow-info-bg)',
                  color: 'var(--ow-info)',
                  fontSize: 10,
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  padding: '2px 6px',
                  borderRadius: 4,
                }}
              >
                Default
              </span>
            )}
          </div>
          <div
            style={{
              color: 'var(--ow-fg-3)',
              fontSize: 11,
              marginTop: 2,
              fontFamily: 'var(--ow-font-mono)',
            }}
          >
            {keyView.fingerprint}
            {keyView.bits > 0 && <> · {keyView.bits}-bit</>} · added{' '}
            {new Date(keyView.addedAt).toLocaleDateString()}
          </div>
        </div>
      </div>
      <div style={{ display: 'flex', gap: 18, color: 'var(--ow-fg-2)', fontSize: 12 }}>
        <KeyMeta k="Type" v={keyView.type} />
        <KeyMeta k="Belongs to" v={<span style={{ color: 'var(--ow-fg-1)' }}>1 credential</span>} />
        <KeyMeta
          k="Updated"
          v={
            <span style={{ color: 'var(--ow-fg-1)' }}>
              {new Date(keyView.updatedAt).toLocaleDateString()}
            </span>
          }
        />
      </div>
      <div style={{ display: 'flex', gap: 4 }}>
        <IconBtn label="Copy fingerprint" onClick={copyFingerprint}>
          <Copy size={12} />
        </IconBtn>
        <IconBtn
          label="Edit key (edits parent credential)"
          disabled={!canWrite}
          onClick={onReplace}
        >
          <Edit3 size={12} />
        </IconBtn>
        <IconBtn
          label="Delete key (deletes parent credential)"
          tier="crit"
          disabled={!canDelete}
          onClick={onDelete}
        >
          <Trash2 size={12} />
        </IconBtn>
      </div>
    </div>
  );
}

function KeyMeta({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div>
      <div style={{ color: 'var(--ow-fg-3)', fontSize: 11 }}>{k}</div>
      <div style={{ color: 'var(--ow-fg-1)', marginTop: 2 }}>{v}</div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Atoms
// ─────────────────────────────────────────────────────────────────────────

function IconBtn({
  children,
  label,
  disabled,
  tier,
  onClick,
}: {
  children: React.ReactNode;
  label: string;
  disabled?: boolean;
  tier?: 'crit';
  onClick?: () => void;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      disabled={disabled}
      onClick={onClick}
      style={{
        width: 28,
        height: 28,
        border: 0,
        background: 'transparent',
        color: tier === 'crit' ? 'var(--ow-crit)' : 'var(--ow-fg-2)',
        borderRadius: 5,
        display: 'inline-grid',
        placeItems: 'center',
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.6 : 1,
      }}
    >
      {children}
    </button>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Save bar
// ─────────────────────────────────────────────────────────────────────────

function SaveBar({ onReset }: { onReset: () => void }) {
  return (
    <div
      role="region"
      aria-label="Unsaved changes"
      style={{
        position: 'sticky',
        bottom: 18,
        display: 'flex',
        alignItems: 'center',
        gap: 16,
        padding: '12px 18px',
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        boxShadow: 'var(--ow-shadow-md)',
        marginTop: 24,
      }}
    >
      <div style={{ flex: 1, fontSize: 13, color: 'var(--ow-fg-1)' }}>
        <strong>Unsaved changes.</strong>{' '}
        <span style={{ color: 'var(--ow-fg-2)' }}>
          Connection defaults persist when the SSH config endpoint ships.
        </span>
      </div>
      <Btn onClick={onReset}>Discard</Btn>
      <Btn variant="primary" disabled>
        Save changes
      </Btn>
    </div>
  );
}

const leadStyle: React.CSSProperties = {
  margin: '0 0 16px',
  color: 'var(--ow-fg-2)',
  fontSize: 13,
  maxWidth: 720,
};

const tableHeader: React.CSSProperties = {
  textAlign: 'left',
  fontWeight: 500,
  color: 'var(--ow-fg-2)',
  fontSize: 11,
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
  padding: '10px 20px',
  background: 'var(--ow-bg-2)',
  borderBottom: '1px solid var(--ow-line)',
};

const tableCell: React.CSSProperties = {
  padding: '14px 20px',
  color: 'var(--ow-fg-1)',
  verticalAlign: 'middle',
};
