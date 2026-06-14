import { useEffect, useState } from 'react';
import { useParams, Link } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import type { components } from '@/api/schema';
import { RuleDetailPanel } from './RuleDetailPanel';

type ScanDetail = components['schemas']['ScanDetail'];
type RuleResult = components['schemas']['ScanRuleResult'];

const STATUS_TONE: Record<string, string> = {
  pass: 'var(--ow-ok)',
  fail: 'var(--ow-crit)',
  error: 'var(--ow-warn)',
  skipped: 'var(--ow-fg-3)',
};
const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

// ScanDetailPage — the durable detail of one compliance scan at
// /scans/$scanId: metadata header, per-rule results, and a per-rule
// drill-down (Formatted / Evidence / OSCAL). This is the evidence surface
// (scan:read); the host Compliance tab stays current-state + evidence-free.
//
// Spec: frontend-scan-detail.
export function ScanDetailPage() {
  const params = useParams({ strict: false }) as { scanId?: string };
  const scanId = params.scanId ?? '';
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<'all' | 'fail' | 'pass' | 'skipped' | 'error'>('all');

  useEffect(() => {
    setCrumbs([
      { label: 'Infrastructure' },
      { label: 'Scans', href: '/scans' },
      { label: scanId ? scanId.slice(0, 8) : 'Scan' },
    ]);
    return () => setCrumbs([]);
  }, [setCrumbs, scanId]);

  const q = useQuery({
    queryKey: ['scan', scanId, 'detail'],
    enabled: scanId !== '',
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/scans/{id}', { params: { path: { id: scanId } } });
      if (error || !data) throw new Error(apiErrorMessage(error, 'Failed to load scan'));
      return data as ScanDetail;
    },
  });

  if (q.isPending) return <Wrap><State text="Loading scan." /></Wrap>;
  if (q.isError) return <Wrap><State tone="crit" text={apiErrorMessage(q.error, 'Failed to load scan')} /></Wrap>;

  const { scan, results } = q.data;
  const rules = [...results].sort(
    (a, b) => (SEVERITY_RANK[a.severity] ?? 4) - (SEVERITY_RANK[b.severity] ?? 4) || a.rule_id.localeCompare(b.rule_id),
  );
  const shown = statusFilter === 'all' ? rules : rules.filter((r) => r.status === statusFilter);

  return (
    <Wrap>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 4 }}>
        <h1 style={{ fontSize: 20, fontWeight: 600, color: 'var(--ow-fg-0)', margin: 0 }}>Scan detail</h1>
        <OscalScanButton scanId={scanId} />
      </div>
      <p style={{ fontSize: 13, color: 'var(--ow-fg-2)', margin: '0 0 16px' }}>
        Point-in-time compliance result with retained evidence. Scan {scanId.slice(0, 8)}.
      </p>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
          gap: 1,
          background: 'var(--ow-line)',
          border: '1px solid var(--ow-line)',
          borderRadius: 'var(--ow-radius)',
          overflow: 'hidden',
          marginBottom: 20,
        }}
      >
        <Meta label="Host">
          <Link to="/hosts/$hostId" params={{ hostId: scan.host_id }} style={{ color: 'var(--ow-link)', textDecoration: 'none' }}>
            {scan.host_id.slice(0, 8)}
          </Link>
        </Meta>
        <Meta label="Status">{scan.status}</Meta>
        <Meta label="Finished">{scan.finished_at ? new Date(scan.finished_at).toLocaleString() : 'n/a'}</Meta>
        <Meta label="Policy">{scan.policy_version || 'n/a'}</Meta>
        <Meta label="Pass" tone="var(--ow-ok)">{scan.rules_pass}</Meta>
        <Meta label="Fail" tone="var(--ow-crit)">{scan.rules_fail}</Meta>
        <Meta label="Skipped">{scan.rules_skipped}</Meta>
        <Meta label="Error" tone="var(--ow-warn)">{scan.rules_error}</Meta>
      </div>

      <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
        {(['all', 'fail', 'pass', 'skipped', 'error'] as const).map((f) => (
          <FilterChip key={f} label={f} active={statusFilter === f} onClick={() => setStatusFilter(f)} />
        ))}
      </div>

      <div style={{ border: '1px solid var(--ow-line)', borderRadius: 'var(--ow-radius)', overflow: 'hidden' }}>
        {shown.length === 0 ? (
          <State text="No rules match this filter." />
        ) : (
          shown.map((r, i) => (
            <RuleRow
              key={r.rule_id}
              rule={r}
              scanId={scanId}
              first={i === 0}
              open={expanded === r.rule_id}
              onToggle={() => setExpanded(expanded === r.rule_id ? null : r.rule_id)}
            />
          ))
        )}
      </div>
    </Wrap>
  );
}

function RuleRow({
  rule,
  scanId,
  first,
  open,
  onToggle,
}: {
  rule: RuleResult;
  scanId: string;
  first: boolean;
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <div style={{ borderTop: first ? 'none' : '1px solid var(--ow-line)' }}>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        style={{
          width: '100%',
          display: 'grid',
          gridTemplateColumns: '20px 90px 80px 1fr auto',
          alignItems: 'center',
          gap: 12,
          padding: '10px 14px',
          background: open ? 'var(--ow-bg-2)' : 'transparent',
          border: 0,
          textAlign: 'left',
          cursor: 'pointer',
          color: 'var(--ow-fg-1)',
        }}
      >
        <span style={{ color: 'var(--ow-fg-3)', fontSize: 12 }}>{open ? '▾' : '▸'}</span>
        <span style={{ fontSize: 12, fontWeight: 600, color: STATUS_TONE[rule.status] ?? 'var(--ow-fg-2)' }}>
          {rule.status}
        </span>
        <span style={{ fontSize: 12, color: 'var(--ow-fg-2)' }}>{rule.severity || 'n/a'}</span>
        <span style={{ fontSize: 13, fontFamily: 'var(--ow-font-mono)', color: 'var(--ow-fg-0)' }}>{rule.rule_id}</span>
        <span style={{ fontSize: 11, color: rule.has_evidence ? 'var(--ow-fg-2)' : 'var(--ow-fg-3)' }}>
          {rule.has_evidence ? 'evidence' : 'no evidence'}
        </span>
      </button>
      {open ? (
        <div style={{ padding: '0 14px 14px' }}>
          <RuleDetailPanel scanId={scanId} ruleId={rule.rule_id} hasEvidence={rule.has_evidence} />
        </div>
      ) : null}
    </div>
  );
}

function OscalScanButton({ scanId }: { scanId: string }) {
  const [busy, setBusy] = useState(false);
  async function download() {
    setBusy(true);
    try {
      const res = await fetch(`${window.location.origin}/api/v1/scans/${scanId}/oscal`, { credentials: 'include' });
      if (!res.ok) return;
      const blob = await res.blob();
      const objUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = objUrl;
      a.download = `oscal-${scanId}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(objUrl);
    } finally {
      setBusy(false);
    }
  }
  return (
    <button
      type="button"
      onClick={download}
      disabled={busy || !scanId}
      style={{
        background: 'transparent',
        color: 'var(--ow-link)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: '6px 12px',
        fontSize: 12,
        fontWeight: 500,
        cursor: busy ? 'default' : 'pointer',
      }}
    >
      {busy ? 'Exporting.' : 'Export OSCAL'}
    </button>
  );
}

function Wrap({ children }: { children: React.ReactNode }) {
  return <div style={{ padding: '24px 28px', maxWidth: 1100 }}>{children}</div>;
}

function Meta({ label, children, tone }: { label: string; children: React.ReactNode; tone?: string }) {
  return (
    <div style={{ background: 'var(--ow-bg-1)', padding: '10px 14px' }}>
      <div style={{ fontSize: 11, color: 'var(--ow-fg-3)', marginBottom: 3 }}>{label}</div>
      <div style={{ fontSize: 14, fontWeight: 600, color: tone ?? 'var(--ow-fg-0)' }}>{children}</div>
    </div>
  );
}

function FilterChip({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        background: active ? 'var(--ow-bg-3)' : 'transparent',
        color: active ? 'var(--ow-fg-0)' : 'var(--ow-fg-2)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: '4px 12px',
        fontSize: 12,
        textTransform: 'capitalize',
        cursor: 'pointer',
      }}
    >
      {label}
    </button>
  );
}

function State({ text, tone }: { text: string; tone?: 'crit' }) {
  return (
    <div style={{ padding: 28, textAlign: 'center', fontSize: 13, color: tone === 'crit' ? 'var(--ow-crit)' : 'var(--ow-fg-3)' }}>
      {text}
    </div>
  );
}
