// RequestRemediationModal confirms a remediation request for a single
// failing rule, then POSTs /api/v1/remediation/requests {host_id,
// rule_id}. The created row carries the projected compliance lift, so
// the modal previews the lift the host's compliance score should gain
// once the fix is approved and applied (the apply step itself is the
// OpenWatch+ track and is not driven from here).
//
// The host-detail remediations query is refreshed by the parent on
// success. A 409 (an open remediation already exists for this rule)
// surfaces inline. UI copy carries no em-dashes (project rule).
//
// Spec: frontend-remediation-tab AC-02.

import type { CSSProperties } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { components } from '@/api/schema';

type ProjectedLift = components['schemas']['ProjectedLift'];

// formatLift renders the projected per-framework lift as a compact
// readout, e.g. "CIS +33.33 / STIG +50". Returns null when the API
// supplied no lift figures (the create response may omit it).
export function formatLift(lift?: ProjectedLift | null): string | null {
  if (!lift) return null;
  const parts: string[] = [];
  const push = (label: string, v?: number | null) => {
    if (v != null && v !== 0) parts.push(`${label} +${Number(v.toFixed(2))}`);
  };
  push('CIS', lift.cis);
  push('STIG', lift.stig);
  push('NIST', lift.nist);
  return parts.length > 0 ? parts.join(' / ') : null;
}

export function RequestRemediationModal({
  hostId,
  ruleId,
  ruleTitle,
  onClose,
  onSuccess,
}: {
  hostId: string;
  ruleId: string;
  ruleTitle: string;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: async () => {
      const { error, response } = await api.POST('/api/v1/remediation/requests', {
        body: { host_id: hostId, rule_id: ruleId },
      });
      if (error || !response.ok) {
        if (response.status === 409) {
          throw new Error('A remediation has already been requested for this rule.');
        }
        throw new Error(apiErrorMessage(error, `Request failed (${response.status})`));
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['host', hostId, 'remediations'] });
      onSuccess();
    },
  });

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Request remediation"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.5)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 460,
          maxWidth: '90vw',
          background: 'var(--ow-bg-1)',
          border: '1px solid var(--ow-line)',
          borderRadius: 'var(--ow-radius)',
          padding: 20,
        }}
      >
        <h3 style={{ margin: '0 0 4px', fontSize: 14, fontWeight: 600 }}>Request remediation</h3>
        <div style={{ color: 'var(--ow-fg-2)', fontSize: 12, marginBottom: 4 }}>{ruleTitle}</div>
        <div
          style={{
            fontFamily: 'var(--ow-font-mono)',
            fontSize: 11,
            color: 'var(--ow-fg-3)',
            marginBottom: 14,
          }}
        >
          {ruleId}
        </div>

        <p style={{ color: 'var(--ow-fg-2)', fontSize: 12, lineHeight: 1.5, margin: '0 0 14px' }}>
          This files a remediation request for review. An approver decides whether the fix is
          applied. Applying the fix on the host is an OpenWatch+ feature: the free tier governs the
          request and approval only.
        </p>

        {mutation.error && (
          <div style={{ color: 'var(--ow-crit)', fontSize: 12, marginBottom: 12 }} role="alert">
            {(mutation.error as Error).message}
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <button type="button" onClick={onClose} style={cancelBtn}>
            Cancel
          </button>
          <button
            type="button"
            disabled={mutation.isPending}
            onClick={() => mutation.mutate()}
            style={{
              ...submitBtn,
              cursor: mutation.isPending ? 'default' : 'pointer',
              opacity: mutation.isPending ? 0.6 : 1,
            }}
          >
            {mutation.isPending ? 'Submitting' : 'Submit request'}
          </button>
        </div>
      </div>
    </div>
  );
}

const cancelBtn: CSSProperties = {
  height: 32,
  padding: '0 14px',
  background: 'var(--ow-bg-2)',
  color: 'var(--ow-fg-1)',
  border: '1px solid var(--ow-line)',
  borderRadius: 7,
  fontSize: 12,
  cursor: 'pointer',
};

const submitBtn: CSSProperties = {
  height: 32,
  padding: '0 14px',
  background: 'var(--ow-info)',
  color: 'var(--ow-info-on)',
  border: 0,
  borderRadius: 7,
  fontSize: 12,
  fontWeight: 600,
};
