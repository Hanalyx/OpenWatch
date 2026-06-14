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

function EvidenceView({ ev }: { ev: Evidence }) {
  if (ev.checks.length === 0) return <Note>No raw command evidence for this rule.</Note>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {ev.checks.map((c, i) => (
        <div key={i} style={{ borderTop: i === 0 ? 'none' : '1px solid var(--ow-line)', paddingTop: i === 0 ? 0 : 12 }}>
          <Field label="method" value={c.method} />
          {c.command ? <Field label="command" value={c.command} mono /> : null}
          {c.expected ? <Field label="expected" value={c.expected} /> : null}
          {c.actual ? <Field label="actual" value={c.actual} /> : null}
          <Field label="exit_code" value={String(c.exit_code)} />
          {c.stdout ? <Block label="stdout" value={c.stdout} /> : null}
          {c.stderr ? <Block label="stderr" value={c.stderr} /> : null}
          {c.truncated ? <Note>Output truncated at the capture cap.</Note> : null}
        </div>
      ))}
    </div>
  );
}

function OscalView({ scanId, ruleId }: { scanId: string; ruleId: string }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function download() {
    setBusy(true);
    setErr(null);
    try {
      const path = `/api/v1/scans/${scanId}/rules/${ruleId}/oscal`;
      const res = await fetch(`${window.location.origin}${path}`, { credentials: 'include' });
      if (!res.ok) {
        setErr(`Export failed (HTTP ${res.status}).`);
        return;
      }
      const blob = await res.blob();
      const objUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = objUrl;
      a.download = `oscal-${scanId}-${ruleId}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(objUrl);
    } catch {
      setErr('Export failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ fontSize: 13, color: 'var(--ow-fg-1)' }}>
      <p style={{ margin: '0 0 12px' }}>
        Export this rule as an OSCAL 1.0.6 Assessment Results document for an auditor or GRC tool.
      </p>
      <button
        type="button"
        onClick={download}
        disabled={busy}
        style={{
          background: 'var(--ow-info)',
          color: '#fff',
          border: 0,
          borderRadius: 'var(--ow-radius)',
          padding: '8px 16px',
          fontSize: 13,
          fontWeight: 500,
          cursor: busy ? 'default' : 'pointer',
          opacity: busy ? 0.6 : 1,
        }}
      >
        {busy ? 'Exporting.' : 'Download OSCAL'}
      </button>
      {err ? <Note tone="crit">{err}</Note> : null}
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

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div style={{ display: 'flex', gap: 8, fontSize: 12, marginBottom: 2 }}>
      <span style={{ color: 'var(--ow-fg-3)', minWidth: 76 }}>{label}</span>
      <span style={{ color: 'var(--ow-fg-0)', fontFamily: mono ? 'var(--ow-font-mono)' : undefined, wordBreak: 'break-all' }}>
        {value}
      </span>
    </div>
  );
}

function Block({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ marginTop: 6 }}>
      <div style={{ fontSize: 11, color: 'var(--ow-fg-3)', marginBottom: 3 }}>{label}</div>
      <pre
        style={{
          margin: 0,
          padding: 8,
          background: 'var(--ow-bg-1)',
          border: '1px solid var(--ow-line)',
          borderRadius: 'var(--ow-radius)',
          fontFamily: 'var(--ow-font-mono)',
          fontSize: 12,
          color: 'var(--ow-fg-1)',
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-all',
          maxHeight: 220,
          overflow: 'auto',
        }}
      >
        {value}
      </pre>
    </div>
  );
}

function Note({ children, tone }: { children: React.ReactNode; tone?: 'crit' }) {
  return (
    <p style={{ margin: '8px 0 0', fontSize: 12, color: tone === 'crit' ? 'var(--ow-crit)' : 'var(--ow-fg-3)' }}>
      {children}
    </p>
  );
}
