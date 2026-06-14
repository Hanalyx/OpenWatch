import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { components } from '@/api/schema';

type Evidence = components['schemas']['ScanRuleEvidence'];
type Check = components['schemas']['ScanCheckEvidence'];
type View = 'formatted' | 'evidence' | 'oscal';

// RuleDetailPanel is the per-rule drill-down on the scan detail page. It
// shows the rule's verdict three ways: a Formatted human summary
// (default), the raw Evidence (the exact commands and their output), and
// an OSCAL export. Evidence is fetched lazily the first time the panel
// needs it; OSCAL is a download (and a one-shot inline fetch on demand).
//
// Spec: frontend-scan-detail.
export function RuleDetailPanel({
  scanId,
  ruleId,
  hasEvidence,
}: {
  scanId: string;
  ruleId: string;
  hasEvidence: boolean;
}) {
  const [view, setView] = useState<View>('formatted');

  // Formatted + Evidence read the same payload; fetch it once the panel is
  // open and either of those views is active. OSCAL is download-only.
  const evidenceQ = useQuery({
    queryKey: ['scan', scanId, 'rule', ruleId, 'evidence'],
    enabled: hasEvidence && view !== 'oscal',
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/scans/{id}/rules/{ruleId}/evidence', {
        params: { path: { id: scanId, ruleId } },
      });
      if (error || !data) throw new Error(apiErrorMessage(error, 'Failed to load evidence'));
      return data as Evidence;
    },
  });

  return (
    <div
      style={{
        background: 'var(--ow-bg-2)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: 14,
        marginTop: 8,
      }}
    >
      <div role="tablist" aria-label="Rule detail view" style={{ display: 'flex', gap: 4, marginBottom: 12 }}>
        <SwitchTab label="Formatted" active={view === 'formatted'} onClick={() => setView('formatted')} />
        <SwitchTab label="Evidence" active={view === 'evidence'} onClick={() => setView('evidence')} />
        <SwitchTab label="OSCAL" active={view === 'oscal'} onClick={() => setView('oscal')} />
      </div>

      {view === 'oscal' ? (
        <OscalView scanId={scanId} ruleId={ruleId} />
      ) : !hasEvidence ? (
        <Note>No evidence was captured for this rule.</Note>
      ) : evidenceQ.isPending ? (
        <Note>Loading evidence.</Note>
      ) : evidenceQ.isError ? (
        <Note tone="crit">{apiErrorMessage(evidenceQ.error, 'Failed to load evidence')}</Note>
      ) : view === 'formatted' ? (
        <FormattedView ev={evidenceQ.data} />
      ) : (
        <EvidenceView ev={evidenceQ.data} />
      )}
    </div>
  );
}

function FormattedView({ ev }: { ev: Evidence }) {
  return (
    <div style={{ fontSize: 13, color: 'var(--ow-fg-1)', lineHeight: 1.5 }}>
      {ev.detail ? <p style={{ margin: '0 0 12px' }}>{ev.detail}</p> : null}
      {ev.error ? <Note tone="crit">Check error: {ev.error}</Note> : null}
      {ev.checks.length === 0 ? (
        <Note>No commands were executed for this rule.</Note>
      ) : (
        ev.checks.map((c, i) => <CheckSummary key={i} c={c} />)
      )}
    </div>
  );
}

function CheckSummary({ c }: { c: Check }) {
  const exitOk = c.exit_code === 0;
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ fontSize: 12, color: 'var(--ow-fg-2)', marginBottom: 3 }}>{c.method}</div>
      {c.command ? (
        <code style={{ fontFamily: 'var(--ow-font-mono)', fontSize: 12, color: 'var(--ow-fg-0)' }}>{c.command}</code>
      ) : null}
      <div style={{ display: 'flex', gap: 16, marginTop: 4, fontSize: 12, color: 'var(--ow-fg-2)' }}>
        {c.expected !== undefined && c.expected !== '' ? <span>expected: {c.expected}</span> : null}
        {c.actual !== undefined && c.actual !== '' ? <span>actual: {c.actual}</span> : null}
        <span style={{ color: exitOk ? 'var(--ow-ok)' : 'var(--ow-warn)' }}>exit {c.exit_code}</span>
      </div>
    </div>
  );
}

// EvidenceView renders the full evidence result verbatim as JSON (the
// raw proof, not a formatted view).
function EvidenceView({ ev }: { ev: Evidence }) {
  return <JsonBlock data={ev} filename="evidence.json" />;
}

// OscalView lazily fetches and renders the full OSCAL 1.0.6 Assessment
// Results document as JSON (the standards artifact verbatim). Mounts only
// when the OSCAL tab is active, so the fetch is on demand.
function OscalView({ scanId, ruleId }: { scanId: string; ruleId: string }) {
  const q = useQuery({
    queryKey: ['scan', scanId, 'rule', ruleId, 'oscal'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/scans/{id}/rules/{ruleId}/oscal', {
        params: { path: { id: scanId, ruleId } },
      });
      if (error || !data) throw new Error(apiErrorMessage(error, 'Failed to load OSCAL'));
      return data as Record<string, unknown>;
    },
  });
  if (q.isPending) return <Note>Loading OSCAL.</Note>;
  if (q.isError) return <Note tone="crit">{apiErrorMessage(q.error, 'Failed to load OSCAL')}</Note>;
  return <JsonBlock data={q.data} filename={`oscal-${scanId}-${ruleId}.json`} />;
}

// JsonBlock pretty-prints any value as scrollable JSON with a Download
// action. Used for the Evidence and OSCAL views (raw result, not formatted).
function JsonBlock({ data, filename }: { data: unknown; filename: string }) {
  const text = JSON.stringify(data, null, 2);
  function download() {
    const blob = new Blob([text], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 6 }}>
        <button
          type="button"
          onClick={download}
          style={{
            background: 'transparent',
            color: 'var(--ow-link)',
            border: '1px solid var(--ow-line)',
            borderRadius: 'var(--ow-radius)',
            padding: '4px 10px',
            fontSize: 12,
            cursor: 'pointer',
          }}
        >
          Download
        </button>
      </div>
      <pre
        style={{
          margin: 0,
          padding: 12,
          background: 'var(--ow-bg-1)',
          border: '1px solid var(--ow-line)',
          borderRadius: 'var(--ow-radius)',
          fontFamily: 'var(--ow-font-mono)',
          fontSize: 12,
          lineHeight: 1.5,
          color: 'var(--ow-fg-1)',
          whiteSpace: 'pre',
          overflow: 'auto',
          maxHeight: 460,
        }}
      >
        {text}
      </pre>
    </div>
  );
}

function SwitchTab({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      role="tab"
      aria-selected={active}
      tabIndex={active ? 0 : -1}
      onClick={onClick}
      style={{
        background: 'transparent',
        border: 0,
        padding: '6px 14px',
        fontSize: 12,
        fontWeight: 500,
        color: active ? 'var(--ow-fg-0)' : 'var(--ow-fg-2)',
        cursor: 'pointer',
        borderBottom: active ? '2px solid var(--ow-info)' : '2px solid transparent',
      }}
    >
      {label}
    </button>
  );
}

function Note({ children, tone }: { children: React.ReactNode; tone?: 'crit' }) {
  return (
    <p style={{ margin: '8px 0 0', fontSize: 12, color: tone === 'crit' ? 'var(--ow-crit)' : 'var(--ow-fg-3)' }}>
      {children}
    </p>
  );
}
