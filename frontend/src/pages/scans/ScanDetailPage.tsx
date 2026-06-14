import { useEffect, useMemo, useState } from 'react';
import { useParams, Link } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import type { components } from '@/api/schema';
import { RuleDetailPanel } from './RuleDetailPanel';

type ScanDetail = components['schemas']['ScanDetail'];
type RuleResult = components['schemas']['ScanRuleResult'];

// status -> {dot color, label} matching the prototype's STATUS column.
const STATUS: Record<string, { tone: string; label: string }> = {
  pass: { tone: 'var(--ow-ok)', label: 'Compliant' },
  fail: { tone: 'var(--ow-crit)', label: 'Non-compliant' },
  error: { tone: 'var(--ow-warn)', label: 'Error' },
  skipped: { tone: 'var(--ow-fg-3)', label: 'N/A' },
};

// severity -> short pill (HIGH red, MED amber, LOW blue, CRIT red).
const SEVERITY: Record<string, { label: string; fg: string; bg: string }> = {
  critical: { label: 'CRIT', fg: '#ff7b72', bg: 'rgba(248,81,73,0.15)' },
  high: { label: 'HIGH', fg: '#ff7b72', bg: 'rgba(248,81,73,0.15)' },
  medium: { label: 'MED', fg: '#e3b341', bg: 'rgba(219,154,4,0.15)' },
  low: { label: 'LOW', fg: '#6ea8ff', bg: 'rgba(56,139,253,0.15)' },
};
const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

// Framework-ref tag styling by framework family (CIS blue, STIG purple,
// NIST green, PCI amber), mirroring the prototype tags.
const TAG_TONE = {
  cis: { fg: '#7cc4ff', bg: 'rgba(56,139,253,0.15)' },
  stig: { fg: '#c8a2ff', bg: 'rgba(163,113,247,0.15)' },
  nist: { fg: '#6ee7a8', bg: 'rgba(63,185,80,0.15)' },
  pci: { fg: '#e3b341', bg: 'rgba(219,154,4,0.15)' },
  other: { fg: 'var(--ow-fg-2)', bg: 'var(--ow-bg-3)' },
};

function fwTag(frameworkId: string, control: string): { label: string; tone: keyof typeof TAG_TONE } {
  const f = frameworkId.toLowerCase();
  if (f.startsWith('cis')) return { label: `CIS-${control}`, tone: 'cis' };
  if (f.startsWith('stig') || f.startsWith('srg') || f.startsWith('ubtu')) return { label: control, tone: 'stig' };
  if (f.startsWith('nist')) return { label: control, tone: 'nist' };
  if (f.startsWith('pci')) return { label: `PCI-${control}`, tone: 'pci' };
  return { label: control, tone: 'other' };
}

// flattenRefs turns the framework_refs map into an ordered tag list
// (CIS first, then STIG, then NIST, then the rest) for stable rendering.
function flattenRefs(refs: Record<string, string[]>): { label: string; tone: keyof typeof TAG_TONE; key: string }[] {
  const order = (id: string) => (id.startsWith('cis') ? 0 : id.startsWith('stig') ? 1 : id.startsWith('nist') ? 2 : 3);
  return Object.keys(refs)
    .sort((a, b) => order(a) - order(b) || a.localeCompare(b))
    .flatMap((fid) =>
      (refs[fid] ?? []).map((c) => {
        const t = fwTag(fid, c);
        return { ...t, key: `${fid}:${c}` };
      }),
    );
}

// ScanDetailPage — the durable detail of one compliance scan at
// /scans/$scanId: metadata header, per-rule results (status, severity,
// title + verdict + framework tags, category), and a per-rule drill-down
// (Formatted / Evidence / OSCAL). The evidence surface (scan:read); the
// host Compliance tab stays current-state + evidence-free.
//
// Spec: frontend-scan-detail.
export function ScanDetailPage() {
  const params = useParams({ strict: false }) as { scanId?: string };
  const scanId = params.scanId ?? '';
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<'all' | 'fail' | 'pass' | 'skipped' | 'error'>('all');
  const [search, setSearch] = useState('');

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

  const results = useMemo(() => q.data?.results ?? [], [q.data]);
  const counts = useMemo(() => {
    const c = { fail: 0, pass: 0, skipped: 0, error: 0 };
    for (const r of results) c[r.status as keyof typeof c] = (c[r.status as keyof typeof c] ?? 0) + 1;
    return c;
  }, [results]);

  const shown = useMemo(() => {
    const term = search.trim().toLowerCase();
    const rows = [...results].sort(
      (a, b) => (SEVERITY_RANK[a.severity] ?? 4) - (SEVERITY_RANK[b.severity] ?? 4) || a.rule_id.localeCompare(b.rule_id),
    );
    return rows.filter((r) => {
      if (statusFilter !== 'all' && r.status !== statusFilter) return false;
      if (!term) return true;
      const hay = [r.rule_id, r.title, ...Object.values(r.framework_refs ?? {}).flat()].join(' ').toLowerCase();
      return hay.includes(term);
    });
  }, [results, statusFilter, search]);

  if (q.isPending) return <Wrap><State text="Loading scan." /></Wrap>;
  if (q.isError) return <Wrap><State tone="crit" text={apiErrorMessage(q.error, 'Failed to load scan')} /></Wrap>;

  const { scan } = q.data;

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

      {/* Search + status filter chips */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10, flexWrap: 'wrap' }}>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search rules or framework IDs"
          aria-label="Search rules or framework IDs"
          style={{
            flex: '1 1 280px',
            minWidth: 220,
            background: 'var(--ow-bg-2)',
            border: '1px solid var(--ow-line)',
            borderRadius: 'var(--ow-radius)',
            color: 'var(--ow-fg-0)',
            fontSize: 13,
            padding: '8px 12px',
          }}
        />
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <Chip label="All" count={results.length} active={statusFilter === 'all'} onClick={() => setStatusFilter('all')} />
          <Chip label="Non-compliant" count={counts.fail} tone="var(--ow-crit)" active={statusFilter === 'fail'} onClick={() => setStatusFilter('fail')} />
          <Chip label="Compliant" count={counts.pass} tone="var(--ow-ok)" active={statusFilter === 'pass'} onClick={() => setStatusFilter('pass')} />
          <Chip label="N/A" count={counts.skipped} tone="var(--ow-fg-3)" active={statusFilter === 'skipped'} onClick={() => setStatusFilter('skipped')} />
          {counts.error > 0 ? (
            <Chip label="Error" count={counts.error} tone="var(--ow-warn)" active={statusFilter === 'error'} onClick={() => setStatusFilter('error')} />
          ) : null}
        </div>
        <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--ow-fg-3)' }}>
          {shown.length} of {results.length} rules
        </span>
      </div>

      {/* Rules table */}
      <div style={{ border: '1px solid var(--ow-line)', borderRadius: 'var(--ow-radius)', overflow: 'hidden' }}>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '150px 90px 1fr 200px',
            gap: 12,
            padding: '9px 16px',
            background: 'var(--ow-bg-2)',
            borderBottom: '1px solid var(--ow-line)',
            fontSize: 11,
            fontWeight: 600,
            textTransform: 'uppercase',
            letterSpacing: '0.04em',
            color: 'var(--ow-fg-3)',
          }}
        >
          <span>Status</span>
          <span>Severity</span>
          <span>Rule &amp; framework refs</span>
          <span>Category</span>
        </div>
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
  const st = STATUS[rule.status] ?? { tone: 'var(--ow-fg-2)', label: rule.status };
  const sev = SEVERITY[rule.severity];
  const why = rule.detail || rule.skip_reason || '';
  const tags = flattenRefs(rule.framework_refs ?? {});
  return (
    <div style={{ borderTop: first ? 'none' : '1px solid var(--ow-line)' }}>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        style={{
          width: '100%',
          display: 'grid',
          gridTemplateColumns: '150px 90px 1fr 200px',
          alignItems: 'start',
          gap: 12,
          padding: '12px 16px',
          background: open ? 'var(--ow-bg-2)' : 'transparent',
          border: 0,
          textAlign: 'left',
          cursor: 'pointer',
        }}
      >
        {/* Status */}
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 7, fontSize: 12, fontWeight: 500, color: st.tone }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: st.tone, flexShrink: 0 }} />
          {st.label}
        </span>
        {/* Severity */}
        <span>
          {sev ? (
            <span style={{ fontSize: 11, fontWeight: 700, color: sev.fg, background: sev.bg, padding: '2px 8px', borderRadius: 4 }}>
              {sev.label}
            </span>
          ) : (
            <span style={{ fontSize: 12, color: 'var(--ow-fg-3)' }}>n/a</span>
          )}
        </span>
        {/* Rule + framework refs */}
        <span style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0 }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
            <span style={{ color: 'var(--ow-fg-3)', fontSize: 11 }} aria-hidden>{open ? '▾' : '▸'}</span>
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--ow-fg-0)' }}>{rule.title}</span>
          </span>
          {why ? <span style={{ fontSize: 12, color: 'var(--ow-fg-2)', paddingLeft: 19 }}>{why}</span> : null}
          {tags.length > 0 ? (
            <span style={{ display: 'flex', flexWrap: 'wrap', gap: 5, paddingLeft: 19 }}>
              {tags.map((t) => (
                <span
                  key={t.key}
                  style={{
                    fontSize: 11,
                    fontFamily: 'var(--ow-font-mono)',
                    color: TAG_TONE[t.tone].fg,
                    background: TAG_TONE[t.tone].bg,
                    padding: '1px 7px',
                    borderRadius: 4,
                  }}
                >
                  {t.label}
                </span>
              ))}
            </span>
          ) : null}
        </span>
        {/* Category */}
        <span style={{ fontSize: 12, color: 'var(--ow-fg-2)' }}>{rule.category}</span>
      </button>
      {open ? (
        <div style={{ padding: '0 16px 14px 35px' }}>
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
  return <div style={{ padding: '24px 28px', width: '100%' }}>{children}</div>;
}

function Meta({ label, children, tone }: { label: string; children: React.ReactNode; tone?: string }) {
  return (
    <div style={{ background: 'var(--ow-bg-1)', padding: '10px 14px' }}>
      <div style={{ fontSize: 11, color: 'var(--ow-fg-3)', marginBottom: 3 }}>{label}</div>
      <div style={{ fontSize: 14, fontWeight: 600, color: tone ?? 'var(--ow-fg-0)' }}>{children}</div>
    </div>
  );
}

function Chip({
  label,
  count,
  active,
  onClick,
  tone,
}: {
  label: string;
  count: number;
  active: boolean;
  onClick: () => void;
  tone?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 7,
        background: active ? 'var(--ow-bg-3)' : 'transparent',
        color: active ? 'var(--ow-fg-0)' : 'var(--ow-fg-2)',
        border: '1px solid var(--ow-line)',
        borderRadius: 999,
        padding: '4px 12px',
        fontSize: 12,
        cursor: 'pointer',
      }}
    >
      {tone ? <span style={{ width: 7, height: 7, borderRadius: '50%', background: tone }} /> : null}
      {label}
      <span style={{ color: 'var(--ow-fg-3)' }}>{count}</span>
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
