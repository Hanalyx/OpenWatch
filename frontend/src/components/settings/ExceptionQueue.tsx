import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useAuthStore } from '@/store/useAuthStore';
import type { components } from '@/api/schema';
import { Callout } from '@/components/settings/primitives';

type Exception = components['schemas']['Exception'];

// ExceptionQueue is the approver surface for compliance exception
// governance (api-compliance-exceptions): the fleet exception list
// filtered by status, with approve/reject/revoke actions gated by the
// caller's permissions. Separation of duties + state guards are
// enforced server-side; the UI surfaces the 409s inline.
//
// Spec: frontend-settings-exception-queue v1.0.0.

const STATUS_FILTERS: { id: '' | Exception['status']; label: string }[] = [
  { id: 'requested', label: 'Pending' },
  { id: 'approved', label: 'Active' },
  { id: 'rejected', label: 'Rejected' },
  { id: 'revoked', label: 'Revoked' },
  { id: 'expired', label: 'Expired' },
  { id: '', label: 'All' },
];

const STATUS_TONE: Record<string, string> = {
  requested: 'var(--ow-warn)',
  approved: 'var(--ow-ok)',
  rejected: 'var(--ow-fg-3)',
  revoked: 'var(--ow-crit)',
  expired: 'var(--ow-fg-3)',
};

export function ExceptionQueue() {
  const queryClient = useQueryClient();
  const hasPermission = useAuthStore((s) => s.hasPermission);
  const canApprove = hasPermission('exception:approve');
  const canRevoke = hasPermission('exception:revoke');

  const [status, setStatus] = useState<'' | Exception['status']>('requested');

  const query = useQuery({
    queryKey: ['compliance', 'exceptions', status],
    queryFn: async (): Promise<Exception[]> => {
      const { data, error, response } = await api.GET('/api/v1/compliance/exceptions', {
        params: { query: status ? { status } : {} },
      });
      if (error || !response.ok) {
        throw new Error(apiErrorMessage(error, `Failed to load (${response.status})`));
      }
      return data!.exceptions;
    },
  });

  // One mutation factory for the three colon-actions. On success the
  // whole queue is invalidated (a transition moves a row between
  // filters).
  const review = useMutation({
    mutationFn: async (vars: { id: string; action: 'approve' | 'reject' | 'revoke' }) => {
      const path = `/api/v1/exceptions/{xid}:${vars.action}` as
        | '/api/v1/exceptions/{xid}:approve'
        | '/api/v1/exceptions/{xid}:reject'
        | '/api/v1/exceptions/{xid}:revoke';
      const { error, response } = await api.POST(path, {
        params: { path: { xid: vars.id } },
        body: {},
      });
      if (error || !response.ok) {
        if (response.status === 409) {
          // Prefer the server's specific 409 reason (state already changed,
          // separation-of-duties, or a lapsed-expiry request) so the approver
          // sees why; fall back to the generic hint if the envelope is empty.
          throw new Error(
            apiErrorMessage(error, 'This exception already changed state (refresh the queue).'),
          );
        }
        throw new Error(apiErrorMessage(error, `Action failed (${response.status})`));
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance', 'exceptions'] });
    },
  });

  const rows = query.data ?? [];

  return (
    <div>
      {query.isError && (
        <Callout tier="crit">
          Failed to load exceptions: {apiErrorMessage(query.error, 'unknown error')}
        </Callout>
      )}

      {/* status filter chips */}
      <div
        role="group"
        aria-label="Filter exceptions by status"
        style={{ display: 'flex', gap: 6, marginBottom: 12, flexWrap: 'wrap' }}
      >
        {STATUS_FILTERS.map((f) => {
          const active = status === f.id;
          return (
            <button
              key={f.id || 'all'}
              type="button"
              aria-pressed={active}
              onClick={() => setStatus(f.id)}
              style={{
                height: 30,
                padding: '0 12px',
                borderRadius: 7,
                border: `1px solid ${active ? 'var(--ow-info)' : 'var(--ow-line)'}`,
                background: active ? 'var(--ow-bg-2)' : 'var(--ow-bg-1)',
                color: active ? 'var(--ow-fg-0)' : 'var(--ow-fg-2)',
                fontSize: 12,
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              {f.label}
            </button>
          );
        })}
      </div>

      {review.error && (
        <div role="alert" style={{ color: 'var(--ow-crit)', fontSize: 12, marginBottom: 10 }}>
          {(review.error as Error).message}
        </div>
      )}

      <div
        style={{
          background: 'var(--ow-bg-1)',
          border: '1px solid var(--ow-line)',
          borderRadius: 'var(--ow-radius)',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1.4fr 1fr 90px 1fr 200px',
            gap: 12,
            padding: '10px 16px',
            background: 'var(--ow-bg-2)',
            borderBottom: '1px solid var(--ow-line)',
            fontSize: 11,
            fontWeight: 600,
            textTransform: 'uppercase',
            letterSpacing: '0.04em',
            color: 'var(--ow-fg-3)',
          }}
        >
          <span>Rule and host</span>
          <span>Reason</span>
          <span>Status</span>
          <span>Expires</span>
          <span style={{ textAlign: 'right' }}>Actions</span>
        </div>

        {query.isPending ? (
          <div style={{ padding: '14px 16px', color: 'var(--ow-fg-2)', fontSize: 12 }}>
            Loading…
          </div>
        ) : rows.length === 0 ? (
          <div
            role="status"
            style={{ padding: '14px 16px', color: 'var(--ow-fg-3)', fontSize: 12 }}
          >
            No exceptions in this view.
          </div>
        ) : (
          rows.map((e, i) => (
            <div
              key={e.id}
              style={{
                display: 'grid',
                gridTemplateColumns: '1.4fr 1fr 90px 1fr 200px',
                gap: 12,
                padding: '12px 16px',
                alignItems: 'center',
                borderTop: i === 0 ? 'none' : '1px solid var(--ow-line)',
                fontSize: 13,
              }}
            >
              <div style={{ minWidth: 0 }}>
                <div
                  style={{
                    fontFamily: 'var(--ow-font-mono)',
                    fontSize: 12,
                    color: 'var(--ow-fg-0)',
                  }}
                >
                  {e.rule_id}
                </div>
                <Link
                  to="/hosts/$hostId"
                  params={{ hostId: e.host_id }}
                  style={{ color: 'var(--ow-link)', fontSize: 11, textDecoration: 'none' }}
                >
                  {e.host_name || e.host_id}
                </Link>
              </div>
              <div style={{ color: 'var(--ow-fg-2)', fontSize: 12, minWidth: 0 }}>{e.reason}</div>
              <div>
                <span
                  style={{
                    fontSize: 11,
                    fontWeight: 600,
                    color: STATUS_TONE[e.status] ?? 'var(--ow-fg-2)',
                  }}
                >
                  {e.status}
                </span>
              </div>
              <div style={{ color: 'var(--ow-fg-3)', fontSize: 12 }}>
                {e.expires_at ? new Date(e.expires_at).toLocaleDateString() : 'No expiry'}
                {/* A pending row past its requested expiry is lapsed: it cannot be
                    approved (server 409) and the sweep will expire it. */}
                {e.status === 'requested' &&
                  e.expires_at &&
                  new Date(e.expires_at).getTime() <= Date.now() && (
                    <span style={{ color: 'var(--ow-warn)', marginLeft: 6, fontSize: 11 }}>
                      (lapsed)
                    </span>
                  )}
              </div>
              <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                {e.status === 'requested' && canApprove && (
                  <>
                    <ActionBtn
                      label="Approve"
                      tone="ok"
                      disabled={review.isPending}
                      onClick={() => review.mutate({ id: e.id, action: 'approve' })}
                    />
                    <ActionBtn
                      label="Reject"
                      tone="muted"
                      disabled={review.isPending}
                      onClick={() => review.mutate({ id: e.id, action: 'reject' })}
                    />
                  </>
                )}
                {e.status === 'approved' && canRevoke && (
                  <ActionBtn
                    label="Revoke"
                    tone="crit"
                    disabled={review.isPending}
                    onClick={() => review.mutate({ id: e.id, action: 'revoke' })}
                  />
                )}
                {((e.status === 'requested' && !canApprove) ||
                  (e.status === 'approved' && !canRevoke) ||
                  ['rejected', 'revoked', 'expired'].includes(e.status)) && (
                  <span style={{ color: 'var(--ow-fg-3)', fontSize: 11 }}>—</span>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function ActionBtn({
  label,
  tone,
  disabled,
  onClick,
}: {
  label: string;
  tone: 'ok' | 'crit' | 'muted';
  disabled: boolean;
  onClick: () => void;
}) {
  const color =
    tone === 'ok' ? 'var(--ow-ok)' : tone === 'crit' ? 'var(--ow-crit)' : 'var(--ow-fg-2)';
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      style={{
        height: 28,
        padding: '0 10px',
        background: 'var(--ow-bg-2)',
        color,
        border: '1px solid var(--ow-line)',
        borderRadius: 7,
        fontSize: 11,
        fontWeight: 600,
        cursor: disabled ? 'default' : 'pointer',
        opacity: disabled ? 0.6 : 1,
      }}
    >
      {label}
    </button>
  );
}
