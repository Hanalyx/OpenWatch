import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Copy, KeyRound, Plus, Trash2 } from 'lucide-react';
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
  BackendPendingBanner,
  Btn,
  StatusPill,
  Toggle,
  Stepper,
  Modal,
  FormField,
  Select,
  Callout,
} from '@/components/settings/primitives';
import { ForbiddenPage } from '@/pages/ForbiddenPage';
import type { components } from '@/api/schema';

type ApiToken = components['schemas']['ApiToken'];
type RoleEntry = components['schemas']['RoleEntry'];
type AuthPolicy = components['schemas']['AuthPolicy'];

// Settings -> Security & auth.
//
// API tokens (token:* ) are live: service-account tokens for automation,
// shown once at creation. Authentication policy (require-MFA + session
// timeouts) is live via system:auth_policy_*. SSO (OIDC/SAML) remains a
// backend-pending stub.
//
// Spec: frontend-settings v1.7.0, api-tokens, api-auth-policy.

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

function relTime(iso?: string | null): string {
  if (!iso) return 'never';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function SecurityPage() {
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);
  const isAdmin = useAuthStore((s) => s.hasPermission)('admin');
  const canRead = useAuthStore((s) => s.hasPermission)('token:read');
  const canWrite = useAuthStore((s) => s.hasPermission)('token:write');
  const canDelete = useAuthStore((s) => s.hasPermission)('token:delete');
  const canReadPolicy = useAuthStore((s) => s.hasPermission)('system:auth_policy_read');
  const canWritePolicy = useAuthStore((s) => s.hasPermission)('system:auth_policy_write');
  const [addOpen, setAddOpen] = useState(false);
  useEffect(() => {
    setCrumbs([{ label: 'Settings' }, { label: 'Security & auth' }]);
    return () => setCrumbs([]);
  }, [setCrumbs]);

  const tokensQuery = useQuery({
    queryKey: ['api-tokens'],
    enabled: isAdmin && canRead,
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/tokens');
      if (error || !response.ok) throw new Error(apiErrorMessage(error, 'Failed to load tokens'));
      return data!.tokens;
    },
  });

  if (!isAdmin) return <ForbiddenPage />;

  const tokens = tokensQuery.data ?? [];

  return (
    <SettingsLayout>
      <PageHead
        title="Security & auth"
        description="Single sign-on, authentication policy, and API tokens for the workspace."
      />

      <Section title="Single sign-on">
        <BackendPendingBanner
          slice="Slice C (SSO)"
          text="OIDC/SAML provider configuration is pending."
        />
      </Section>

      <Section title="Authentication policy">
        {canReadPolicy ? (
          <AuthPolicySection canWrite={canWritePolicy} />
        ) : (
          <Callout tier="info">
            You do not have permission to view the authentication policy.
          </Callout>
        )}
      </Section>

      <Section title="API tokens">
        {canWrite && (
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 10 }}>
            <Btn variant="primary" onClick={() => setAddOpen(true)}>
              <Plus size={14} /> Create token
            </Btn>
          </div>
        )}
        <SettingCard>
          {tokensQuery.isPending ? (
            <div style={pad}>Loading tokens.</div>
          ) : tokensQuery.isError ? (
            <div role="alert" style={pad}>
              Failed to load tokens. {apiErrorMessage(tokensQuery.error, '')}
            </div>
          ) : tokens.length === 0 ? (
            <div style={{ ...pad, textAlign: 'center' }}>
              No API tokens. Create one to let automation call the API.
            </div>
          ) : (
            tokens.map((t, i) => (
              <TokenRow key={t.id} token={t} isFirst={i === 0} canDelete={canDelete} />
            ))
          )}
        </SettingCard>
      </Section>

      {addOpen && <CreateTokenModal onClose={() => setAddOpen(false)} />}
    </SettingsLayout>
  );
}

const pad = { padding: 20, color: 'var(--ow-fg-2)', fontSize: 13 } as const;

// AuthPolicySection — live require-MFA + session-timeout policy.
// Timeouts are stored in seconds; presented as minutes (idle) and hours
// (absolute). Bounds mirror the server (idle 5m..24h, absolute 1h..30d).
// Spec: api-auth-policy, frontend-settings.
function AuthPolicySection({ canWrite }: { canWrite: boolean }) {
  const queryClient = useQueryClient();
  const [requireMfa, setRequireMfa] = useState(false);
  const [idleMin, setIdleMin] = useState(15);
  const [absHrs, setAbsHrs] = useState(12);
  const [saveError, setSaveError] = useState<string | null>(null);

  const policyQuery = useQuery({
    queryKey: ['auth-policy'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/auth-policy');
      if (error || !response.ok) throw new Error(apiErrorMessage(error, 'Failed to load policy'));
      return data!;
    },
  });

  // Seed local state once the policy loads.
  useEffect(() => {
    const p = policyQuery.data;
    if (!p) return;
    setRequireMfa(p.require_mfa);
    setIdleMin(Math.round(p.session_idle_timeout_seconds / 60));
    setAbsHrs(Math.round(p.session_absolute_timeout_seconds / 3600));
  }, [policyQuery.data]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      const body: AuthPolicy = {
        require_mfa: requireMfa,
        session_idle_timeout_seconds: idleMin * 60,
        session_absolute_timeout_seconds: absHrs * 3600,
        updated_at: new Date().toISOString(),
      };
      const { data, response, error } = await api.PUT('/api/v1/auth-policy', {
        body: body as never,
      });
      if (!response.ok || !data) throw new Error(apiErrorMessage(error, 'Save failed'));
      return data;
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['auth-policy'] }),
    onError: (e: Error) => setSaveError(e.message),
  });

  if (policyQuery.isPending) return <div style={pad}>Loading policy.</div>;
  if (policyQuery.isError) {
    return (
      <div role="alert" style={pad}>
        Failed to load authentication policy. {apiErrorMessage(policyQuery.error, '')}
      </div>
    );
  }

  const p = policyQuery.data;
  const dirty =
    p.require_mfa !== requireMfa ||
    Math.round(p.session_idle_timeout_seconds / 60) !== idleMin ||
    Math.round(p.session_absolute_timeout_seconds / 3600) !== absHrs;

  return (
    <>
      <SettingCard>
        <FirstSettingRow
          name="Require MFA"
          description="Every user must enroll in multi-factor authentication. Users without MFA are forced to enroll at next sign-in."
          control={
            <Toggle
              value={requireMfa}
              onChange={setRequireMfa}
              ariaLabel="Require MFA"
              disabled={!canWrite}
            />
          }
        />
        <SettingRow
          name="Idle timeout"
          description="A session ends after this period of inactivity (5 minutes to 24 hours)."
          control={
            <Stepper
              value={idleMin}
              min={5}
              max={1440}
              step={5}
              unit="min"
              onChange={setIdleMin}
              disabled={!canWrite}
            />
          }
        />
        <SettingRow
          name="Absolute timeout"
          description="A session cannot live longer than this regardless of activity (1 hour to 30 days)."
          control={
            <Stepper
              value={absHrs}
              min={1}
              max={720}
              step={1}
              unit="hr"
              onChange={setAbsHrs}
              disabled={!canWrite}
            />
          }
        />
      </SettingCard>
      {saveError && (
        <div style={{ marginTop: 10 }}>
          <Callout tier="crit">{saveError}</Callout>
        </div>
      )}
      {canWrite && (
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 12 }}>
          <Btn
            variant="primary"
            disabled={!dirty || saveMutation.isPending}
            onClick={() => {
              setSaveError(null);
              saveMutation.mutate();
            }}
          >
            {saveMutation.isPending ? 'Saving.' : 'Save policy'}
          </Btn>
        </div>
      )}
    </>
  );
}

function TokenRow({
  token,
  isFirst,
  canDelete,
}: {
  token: ApiToken;
  isFirst: boolean;
  canDelete: boolean;
}) {
  const queryClient = useQueryClient();
  const revoked = !!token.revoked_at;
  const revokeMutation = useMutation({
    mutationFn: async () => {
      const { response, error } = await api.DELETE('/api/v1/tokens/{id}', {
        params: { path: { id: token.id } },
      });
      if (!response.ok) throw new Error(apiErrorMessage(error, 'Revoke failed'));
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['api-tokens'] }),
  });

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '1fr 120px 130px 130px auto',
        gap: 12,
        alignItems: 'center',
        padding: '14px 20px',
        borderTop: isFirst ? 'none' : '1px solid var(--ow-line)',
        opacity: revoked ? 0.55 : 1,
      }}
    >
      <div style={{ minWidth: 0 }}>
        <div style={{ fontWeight: 500 }}>{token.name}</div>
        <div
          style={{
            color: 'var(--ow-fg-3)',
            fontSize: 11,
            marginTop: 2,
            fontFamily: 'var(--ow-font-mono)',
          }}
        >
          {token.prefix}…
        </div>
      </div>
      <span style={{ fontSize: 12, color: 'var(--ow-fg-1)' }}>{token.role_id}</span>
      <span style={{ fontSize: 12, color: 'var(--ow-fg-2)' }} title={token.last_used_at ?? ''}>
        used {relTime(token.last_used_at)}
      </span>
      <span>
        {revoked ? (
          <StatusPill tier="crit">Revoked</StatusPill>
        ) : token.expires_at && new Date(token.expires_at).getTime() < Date.now() ? (
          <StatusPill tier="warn">Expired</StatusPill>
        ) : (
          <StatusPill tier="ok">Active</StatusPill>
        )}
      </span>
      {!revoked && canDelete ? (
        <Btn
          size="sm"
          variant="danger"
          disabled={revokeMutation.isPending}
          onClick={() => revokeMutation.mutate()}
        >
          <Trash2 size={13} /> Revoke
        </Btn>
      ) : (
        <span />
      )}
    </div>
  );
}

function CreateTokenModal({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [roleId, setRoleId] = useState('');
  const [expiresDays, setExpiresDays] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [issued, setIssued] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const rolesQuery = useQuery({
    queryKey: ['roles'],
    queryFn: async () => {
      const { data, error: e, response } = await api.GET('/api/v1/roles');
      if (e || !response.ok) throw new Error(apiErrorMessage(e, 'Failed to load roles'));
      return data!.roles;
    },
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      const body: Record<string, unknown> = { name, role_id: roleId };
      const days = Number(expiresDays);
      if (days > 0) {
        body.expires_at = new Date(Date.now() + days * 86400_000).toISOString();
      }
      const {
        data,
        response,
        error: e,
      } = await api.POST('/api/v1/tokens', { body: body as never });
      if (!response.ok || !data) throw new Error(apiErrorMessage(e, 'Create failed'));
      return data.token;
    },
    onSuccess: (token) => {
      queryClient.invalidateQueries({ queryKey: ['api-tokens'] });
      setIssued(token);
    },
    onError: (e: Error) => setError(e.message),
  });

  function copy() {
    if (issued) {
      void navigator.clipboard?.writeText(issued);
      setCopied(true);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={issued ? 'Token created' : 'Create API token'}
      width={520}
      footer={
        issued ? (
          <Btn variant="primary" onClick={onClose}>
            Done
          </Btn>
        ) : (
          <>
            <Btn onClick={onClose} disabled={createMutation.isPending}>
              Cancel
            </Btn>
            <Btn
              variant="primary"
              disabled={createMutation.isPending || !name || !roleId}
              onClick={() => {
                setError(null);
                createMutation.mutate();
              }}
            >
              {createMutation.isPending ? 'Creating.' : 'Create token'}
            </Btn>
          </>
        )
      }
    >
      {issued ? (
        <div>
          <Callout tier="warn">
            Copy this token now. For your security it will not be shown again.
          </Callout>
          <div
            style={{
              display: 'flex',
              gap: 8,
              alignItems: 'center',
              marginTop: 12,
              padding: 12,
              background: 'var(--ow-bg-1)',
              border: '1px solid var(--ow-line)',
              borderRadius: 'var(--ow-radius)',
            }}
          >
            <code
              style={{
                flex: 1,
                fontFamily: 'var(--ow-font-mono)',
                fontSize: 12,
                color: 'var(--ow-fg-0)',
                wordBreak: 'break-all',
              }}
            >
              {issued}
            </code>
            <Btn size="sm" onClick={copy}>
              <Copy size={13} /> {copied ? 'Copied' : 'Copy'}
            </Btn>
          </div>
        </div>
      ) : (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <KeyRound size={16} style={{ color: 'var(--ow-fg-2)' }} />
            <span style={{ fontSize: 12, color: 'var(--ow-fg-2)' }}>
              The token acts as the chosen role and can be revoked any time.
            </span>
          </div>
          <FormField label="Name">
            <input style={inputStyle} value={name} onChange={(e) => setName(e.target.value)} />
          </FormField>
          <FormField label="Role">
            <Select
              value={roleId}
              onChange={setRoleId}
              ariaLabel="Token role"
              options={[
                { value: '', label: rolesQuery.isPending ? 'Loading roles.' : 'Select a role.' },
                ...(rolesQuery.data ?? []).map((r: RoleEntry) => ({ value: r.id, label: r.id })),
              ]}
            />
          </FormField>
          <FormField label="Expires in (days, optional)">
            <input
              style={inputStyle}
              type="number"
              value={expiresDays}
              placeholder="never"
              onChange={(e) => setExpiresDays(e.target.value)}
            />
          </FormField>
          {error && (
            <div style={{ marginTop: 12 }}>
              <Callout tier="crit">{error}</Callout>
            </div>
          )}
        </>
      )}
    </Modal>
  );
}
