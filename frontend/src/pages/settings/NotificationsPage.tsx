import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Plus, Send, Trash2 } from 'lucide-react';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import { useAuthStore } from '@/store/useAuthStore';
import { SettingsLayout } from '@/components/settings/SettingsLayout';
import {
  PageHead,
  Section,
  SettingCard,
  Btn,
  StatusPill,
  Modal,
  FormField,
  Select,
  Callout,
} from '@/components/settings/primitives';
import { ForbiddenPage } from '@/pages/ForbiddenPage';
import type { components } from '@/api/schema';

type Channel = components['schemas']['NotificationChannel'];

// Settings -> Notifications.
//
// CRUD + test for operator-managed alert-delivery channels (Slack /
// webhook) over /api/v1/notifications/channels. Secrets (url/token) are
// write-only: the API never returns them, so the list shows the
// non-secret target_hint. Gated on notification:read; write/delete/test
// controls gate on their own permissions.
//
// Spec: frontend-settings v1.5.0, api-notifications.

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

const SEVERITY_OPTIONS = [
  { value: '', label: 'All alerts (no filter)' },
  { value: 'critical', label: 'Critical only' },
  { value: 'high', label: 'High and above' },
];

export function NotificationsPage() {
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);
  const canRead = useAuthStore((s) => s.hasPermission)('notification:read');
  const canWrite = useAuthStore((s) => s.hasPermission)('notification:write');
  const canDelete = useAuthStore((s) => s.hasPermission)('notification:delete');
  const canTest = useAuthStore((s) => s.hasPermission)('notification:test');
  const [addOpen, setAddOpen] = useState(false);
  useEffect(() => {
    setCrumbs([{ label: 'Settings' }, { label: 'Notifications' }]);
    return () => setCrumbs([]);
  }, [setCrumbs]);

  const query = useQuery({
    queryKey: ['notification-channels'],
    enabled: canRead,
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/notifications/channels');
      if (error || !response.ok) {
        throw new Error(apiErrorMessage(error, 'Failed to load channels'));
      }
      return data!.channels;
    },
  });

  if (!canRead) return <ForbiddenPage />;

  const channels = query.data ?? [];

  return (
    <SettingsLayout>
      <PageHead
        title="Notifications"
        description="Deliver fired alerts to Slack or a webhook. Targets are stored encrypted and never shown again."
        actions={
          <Btn variant="primary" disabled={!canWrite} onClick={() => setAddOpen(true)}>
            <Plus size={14} /> Add channel
          </Btn>
        }
      />

      <Section title="Channels">
        <SettingCard>
          {query.isPending ? (
            <div style={pad}>Loading channels.</div>
          ) : query.isError ? (
            <div role="alert" style={pad}>
              Failed to load channels. {apiErrorMessage(query.error, '')}
            </div>
          ) : channels.length === 0 ? (
            <div style={{ ...pad, textAlign: 'center' }}>
              No channels yet. Add a Slack or webhook channel to start receiving alerts.
            </div>
          ) : (
            channels.map((c, i) => (
              <ChannelRow
                key={c.id}
                channel={c}
                isFirst={i === 0}
                canWrite={canWrite}
                canDelete={canDelete}
                canTest={canTest}
              />
            ))
          )}
        </SettingCard>
      </Section>

      {addOpen && <ChannelModal mode="create" onClose={() => setAddOpen(false)} />}
    </SettingsLayout>
  );
}

const pad = { padding: 20, color: 'var(--ow-fg-2)', fontSize: 13 } as const;

function ChannelRow({
  channel,
  isFirst,
  canWrite,
  canDelete,
  canTest,
}: {
  channel: Channel;
  isFirst: boolean;
  canWrite: boolean;
  canDelete: boolean;
  canTest: boolean;
}) {
  const queryClient = useQueryClient();
  const [editOpen, setEditOpen] = useState(false);
  const [note, setNote] = useState<{ tone: 'ok' | 'crit'; text: string } | null>(null);

  const testMutation = useMutation({
    mutationFn: async () => {
      const { response, error } = await api.POST('/api/v1/notifications/channels/{id}:test', {
        params: { path: { id: channel.id } },
      });
      if (!response.ok) throw new Error(apiErrorMessage(error, 'Test delivery failed'));
    },
    onSuccess: () => setNote({ tone: 'ok', text: 'Test alert delivered.' }),
    onError: (e: Error) => setNote({ tone: 'crit', text: e.message }),
  });

  const deleteMutation = useMutation({
    mutationFn: async () => {
      const { response, error } = await api.DELETE('/api/v1/notifications/channels/{id}', {
        params: { path: { id: channel.id } },
      });
      if (!response.ok) throw new Error(apiErrorMessage(error, 'Delete failed'));
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['notification-channels'] }),
    onError: (e: Error) => setNote({ tone: 'crit', text: e.message }),
  });

  const sevFilter = channel.tag_filter?.severity;

  return (
    <div style={{ borderTop: isFirst ? 'none' : '1px solid var(--ow-line)', padding: '14px 20px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontWeight: 500 }}>{channel.name}</span>
            <StatusPill tier={channel.enabled ? 'ok' : 'warn'}>
              {channel.enabled ? 'Enabled' : 'Disabled'}
            </StatusPill>
            <span
              style={{
                fontSize: 11,
                color: 'var(--ow-fg-3)',
                textTransform: 'uppercase',
                letterSpacing: '0.04em',
              }}
            >
              {channel.type}
            </span>
          </div>
          <div
            style={{
              color: 'var(--ow-fg-3)',
              fontSize: 12,
              marginTop: 3,
              fontFamily: 'var(--ow-font-mono)',
            }}
          >
            {channel.target_hint}
            {sevFilter ? (
              <span style={{ fontFamily: 'inherit' }}> · routes {sevFilter}+ severity</span>
            ) : (
              <span style={{ fontFamily: 'inherit' }}> · all alerts</span>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <Btn
            size="sm"
            disabled={!canTest || testMutation.isPending}
            onClick={() => {
              setNote(null);
              testMutation.mutate();
            }}
          >
            <Send size={13} /> {testMutation.isPending ? 'Sending.' : 'Test'}
          </Btn>
          <Btn size="sm" disabled={!canWrite} onClick={() => setEditOpen(true)}>
            Edit
          </Btn>
          <Btn
            size="sm"
            variant="danger"
            disabled={!canDelete || deleteMutation.isPending}
            onClick={() => deleteMutation.mutate()}
          >
            <Trash2 size={13} />
          </Btn>
        </div>
      </div>
      {note && (
        <div style={{ marginTop: 10 }}>
          <Callout tier={note.tone === 'ok' ? 'info' : 'crit'}>{note.text}</Callout>
        </div>
      )}
      {editOpen && (
        <ChannelModal mode="edit" channel={channel} onClose={() => setEditOpen(false)} />
      )}
    </div>
  );
}

function ChannelModal({
  mode,
  channel,
  onClose,
}: {
  mode: 'create' | 'edit';
  channel?: Channel;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [type, setType] = useState<'slack' | 'webhook' | 'email'>(
    (channel?.type as 'slack' | 'webhook' | 'email') ?? 'slack',
  );
  const [name, setName] = useState(channel?.name ?? '');
  // URL + token are secrets (slack/webhook) — never pre-filled.
  const [url, setUrl] = useState('');
  const [token, setToken] = useState('');
  // Email/SMTP fields pre-fill from the channel's NON-secret config on edit
  // (the read path returns smtp_host via target_hint, plus port/from/to/
  // username). The password is the only email secret and stays blank — the
  // server keeps the stored one unless re-entered.
  const isEmail = channel?.type === 'email';
  const [smtpHost, setSmtpHost] = useState(isEmail ? (channel?.target_hint ?? '') : '');
  const [smtpPort, setSmtpPort] = useState(channel?.smtp_port ? String(channel.smtp_port) : '587');
  const [username, setUsername] = useState(channel?.username ?? '');
  const [password, setPassword] = useState('');
  const [from, setFrom] = useState(channel?.from ?? '');
  const [to, setTo] = useState((channel?.to ?? []).join(', '));
  const [enabled, setEnabled] = useState(channel?.enabled ?? true);
  const [severity, setSeverity] = useState(channel?.tag_filter?.severity ?? '');
  const [error, setError] = useState<string | null>(null);

  const effectiveType = mode === 'edit' ? (channel?.type as string) : type;

  // secretFields collects the type-specific secret payload, shared by
  // create (always sent) and edit (sent only when the operator re-enters
  // a secret, so a blank leaves the stored one untouched).
  function secretFields(): Record<string, unknown> {
    if (effectiveType === 'email') {
      if (!smtpHost) return {};
      return {
        smtp_host: smtpHost,
        smtp_port: Number(smtpPort) || 0,
        from,
        to: to
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        ...(username ? { username } : {}),
        ...(password ? { password } : {}),
      };
    }
    if (!url) return {};
    return { url, ...(effectiveType === 'webhook' && token ? { token } : {}) };
  }

  const mutation = useMutation({
    mutationFn: async () => {
      const tagFilter = severity ? { severity } : {};
      if (mode === 'create') {
        const body: Record<string, unknown> = {
          type,
          name,
          enabled,
          tag_filter: tagFilter,
          ...secretFields(),
        };
        const { response, error: e } = await api.POST('/api/v1/notifications/channels', {
          body: body as never,
        });
        if (!response.ok) throw new Error(apiErrorMessage(e, 'Create failed'));
      } else {
        // A blank secret on edit leaves the existing config untouched.
        const body: Record<string, unknown> = {
          name,
          enabled,
          tag_filter: tagFilter,
          ...secretFields(),
        };
        const { response, error: e } = await api.PATCH('/api/v1/notifications/channels/{id}', {
          params: { path: { id: channel!.id } },
          body: body as never,
        });
        if (!response.ok) throw new Error(apiErrorMessage(e, 'Update failed'));
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-channels'] });
      onClose();
    },
    onError: (e: Error) => setError(e.message),
  });

  return (
    <Modal
      open
      onClose={onClose}
      title={mode === 'create' ? 'Add channel' : `Edit ${channel?.name}`}
      width={500}
      footer={
        <>
          <Btn onClick={onClose} disabled={mutation.isPending}>
            Cancel
          </Btn>
          <Btn
            variant="primary"
            disabled={mutation.isPending}
            onClick={() => {
              setError(null);
              mutation.mutate();
            }}
          >
            {mutation.isPending ? 'Saving.' : mode === 'create' ? 'Add channel' : 'Save'}
          </Btn>
        </>
      }
    >
      {mode === 'create' && (
        <FormField label="Type">
          <Select
            value={type}
            onChange={(v) => setType(v as 'slack' | 'webhook' | 'email')}
            ariaLabel="Channel type"
            options={[
              { value: 'slack', label: 'Slack (incoming webhook)' },
              { value: 'webhook', label: 'Generic webhook' },
              { value: 'email', label: 'Email (SMTP)' },
            ]}
          />
        </FormField>
      )}
      <FormField label="Name">
        <input style={inputStyle} value={name} onChange={(e) => setName(e.target.value)} />
      </FormField>
      {effectiveType === 'email' ? (
        <>
          <div style={{ display: 'flex', gap: 12 }}>
            <div style={{ flex: 2 }}>
              <FormField label="SMTP host">
                <input
                  style={inputStyle}
                  value={smtpHost}
                  placeholder={mode === 'edit' ? 'Leave blank to keep current' : 'smtp.example.com'}
                  onChange={(e) => setSmtpHost(e.target.value)}
                />
              </FormField>
            </div>
            <div style={{ flex: 1 }}>
              <FormField label="Port">
                <input
                  style={inputStyle}
                  type="number"
                  value={smtpPort}
                  onChange={(e) => setSmtpPort(e.target.value)}
                />
              </FormField>
            </div>
          </div>
          <FormField label="Username (optional)">
            <input
              style={inputStyle}
              value={username}
              autoComplete="off"
              placeholder={mode === 'edit' ? 'Leave blank to keep current' : ''}
              onChange={(e) => setUsername(e.target.value)}
            />
          </FormField>
          <FormField label="Password (optional)">
            <input
              style={inputStyle}
              type="password"
              value={password}
              autoComplete="new-password"
              placeholder={mode === 'edit' ? 'Leave blank to keep current' : ''}
              onChange={(e) => setPassword(e.target.value)}
            />
          </FormField>
          <FormField label="From address">
            <input
              style={inputStyle}
              type="email"
              value={from}
              placeholder="openwatch@example.com"
              onChange={(e) => setFrom(e.target.value)}
            />
          </FormField>
          <FormField label="Recipients (comma-separated)">
            <input
              style={inputStyle}
              value={to}
              placeholder="secops@example.com, oncall@example.com"
              onChange={(e) => setTo(e.target.value)}
            />
          </FormField>
        </>
      ) : (
        <>
          <FormField
            label={effectiveType === 'slack' ? 'Slack webhook URL (https)' : 'Webhook URL (https)'}
          >
            <input
              style={inputStyle}
              type="url"
              value={url}
              placeholder={
                mode === 'edit'
                  ? 'Leave blank to keep current'
                  : 'https://hooks.slack.com/services/...'
              }
              onChange={(e) => setUrl(e.target.value)}
            />
          </FormField>
          {effectiveType === 'webhook' && (
            <FormField label="Bearer token (optional)">
              <input
                style={inputStyle}
                type="password"
                value={token}
                placeholder={mode === 'edit' ? 'Leave blank to keep current' : ''}
                autoComplete="new-password"
                onChange={(e) => setToken(e.target.value)}
              />
            </FormField>
          )}
        </>
      )}
      <FormField label="Deliver for">
        <Select
          value={severity}
          onChange={setSeverity}
          ariaLabel="Severity filter"
          options={SEVERITY_OPTIONS}
        />
      </FormField>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, marginTop: 4 }}>
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        Enabled
      </label>
      {error && (
        <div style={{ marginTop: 12 }}>
          <Callout tier="crit">{error}</Callout>
        </div>
      )}
    </Modal>
  );
}
