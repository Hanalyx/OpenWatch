import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { components } from '@/api/schema';

type Rule = components['schemas']['RuleListItem'];

const SEVERITY: Record<string, { label: string; fg: string; bg: string; rank: number }> = {
  critical: { label: 'CRIT', fg: '#ff7b72', bg: 'rgba(248,81,73,0.15)', rank: 0 },
  high: { label: 'HIGH', fg: '#ff7b72', bg: 'rgba(248,81,73,0.15)', rank: 1 },
  medium: { label: 'MED', fg: '#e3b341', bg: 'rgba(219,154,4,0.15)', rank: 2 },
  low: { label: 'LOW', fg: '#6ea8ff', bg: 'rgba(56,139,253,0.15)', rank: 3 },
};

// Framework-tag styling by family, identical to the scan-detail page so the
// tags read the same on both surfaces.
const TAG_TONE = {
  cis: { fg: '#7cc4ff', bg: 'rgba(56,139,253,0.15)' },
  stig: { fg: '#c8a2ff', bg: 'rgba(163,113,247,0.15)' },
  nist: { fg: '#6ee7a8', bg: 'rgba(63,185,80,0.15)' },
  pci: { fg: '#e3b341', bg: 'rgba(219,154,4,0.15)' },
  other: { fg: 'var(--ow-fg-2)', bg: 'var(--ow-bg-3)' },
};
type Tone = keyof typeof TAG_TONE;

function fwFamily(frameworkId: string): Tone {
  const f = frameworkId.toLowerCase();
  if (f.startsWith('cis')) return 'cis';
  if (f.startsWith('stig') || f.startsWith('srg') || f.startsWith('ubtu')) return 'stig';
  if (f.startsWith('nist')) return 'nist';
  if (f.startsWith('pci')) return 'pci';
  return 'other';
}
function fwTag(frameworkId: string, control: string): { label: string; tone: Tone } {
  const fam = fwFamily(frameworkId);
  if (fam === 'cis') return { label: `CIS-${control}`, tone: 'cis' };
  if (fam === 'pci') return { label: `PCI-${control}`, tone: 'pci' };
  return { label: control, tone: fam };
}
function flattenRefs(refs: Record<string, string[]>): { label: string; tone: Tone; key: string }[] {
  const order = (id: string) => (id.startsWith('cis') ? 0 : id.startsWith('stig') ? 1 : id.startsWith('nist') ? 2 : 3);
  return Object.keys(refs)
    .sort((a, b) => order(a) - order(b) || a.localeCompare(b))
    .flatMap((fid) => (refs[fid] ?? []).map((c) => ({ ...fwTag(fid, c), key: `${fid}:${c}` })));
}

const FAMILY_LABEL: Record<Tone, string> = { cis: 'CIS', stig: 'STIG', nist: 'NIST', pci: 'PCI-DSS', other: 'Other' };

// RulesTab — the Kensa rule-library browser on /scans. Reference data
// (GET /api/v1/rules), filtered entirely client-side: search, severity,
// category, and framework family. Export downloads the filtered set as CSV.
//
// Spec: frontend-rules-library.
export function RulesTab() {
  const [search, setSearch] = useState('');
  const [sev, setSev] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');
  const [category, setCategory] = useState('all');
  const [family, setFamily] = useState<'all' | Tone>('all');

  const q = useQuery({
    queryKey: ['rules'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/rules', {});
      if (error || !data) throw new Error(apiErrorMessage(error, 'Failed to load rules'));
      return data;
    },
    staleTime: 5 * 60_000, // reference data; cache aggressively
  });

  const rules: Rule[] = useMemo(() => q.data?.rules ?? [], [q.data]);

  const categories = useMemo(
    () => Array.from(new Set(rules.map((r) => r.category).filter(Boolean))).sort(),
    [rules],
  );
  const families = useMemo(() => {
    const fams = new Set<Tone>();
    for (const r of rules) for (const fid of Object.keys(r.framework_refs ?? {})) fams.add(fwFamily(fid));
    return (['cis', 'stig', 'nist', 'pci', 'other'] as Tone[]).filter((f) => fams.has(f));
  }, [rules]);
  const sevsPresent = useMemo(() => {
    const s = new Set(rules.map((r) => r.severity));
    return (['critical', 'high', 'medium', 'low'] as const).filter((x) => s.has(x));
  }, [rules]);

  const shown = useMemo(() => {
    const term = search.trim().toLowerCase();
    return rules.filter((r) => {
      if (sev !== 'all' && r.severity !== sev) return false;
      if (category !== 'all' && r.category !== category) return false;
      if (family !== 'all' && !Object.keys(r.framework_refs ?? {}).some((fid) => fwFamily(fid) === family)) return false;
      if (!term) return true;
      const hay = [r.id, r.title, r.description, ...Object.values(r.framework_refs ?? {}).flat()]
        .join(' ')
        .toLowerCase();
      return hay.includes(term);
    });
  }, [rules, search, sev, category, family]);

  if (q.isPending) return <Panel><State text="Loading rules." /></Panel>;
  if (q.isError) return <Panel><State tone="crit" text={apiErrorMessage(q.error, 'Failed to load rules')} /></Panel>;

  return (
    <div>
      {/* Filter bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12, flexWrap: 'wrap' }}>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search rules, IDs, frameworks"
          aria-label="Search rules, IDs, frameworks"
          style={{
            flex: '1 1 260px',
            minWidth: 200,
            background: 'var(--ow-bg-2)',
            border: '1px solid var(--ow-line)',
            borderRadius: 'var(--ow-radius)',
            color: 'var(--ow-fg-0)',
            fontSize: 13,
            padding: '8px 12px',
          }}
        />
        <div style={{ display: 'flex', gap: 6 }}>
          <SevChip label="All" active={sev === 'all'} onClick={() => setSev('all')} />
          {sevsPresent.map((s) => {
            const m = SEVERITY[s];
            if (!m) return null;
            return <SevChip key={s} label={m.label} tone={m.fg} active={sev === s} onClick={() => setSev(s)} />;
          })}
        </div>
        <Select value={category} onChange={setCategory} label="All categories" options={categories} />
        <Select
          value={family}
          onChange={(v) => setFamily(v as 'all' | Tone)}
          label="All frameworks"
          options={families}
          render={(f) => FAMILY_LABEL[f as Tone] ?? f}
        />
      </div>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 8 }}>
        <h2 style={{ fontSize: 15, fontWeight: 600, color: 'var(--ow-fg-0)', margin: 0 }}>
          Rule library <span style={{ color: 'var(--ow-fg-3)', fontWeight: 400 }}>{rules.length}</span>
        </h2>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <span style={{ fontSize: 12, color: 'var(--ow-fg-3)' }}>
            showing {shown.length} of {rules.length}
          </span>
          <ExportButton rules={shown} />
        </div>
      </div>

      {/* Table */}
      <div style={{ border: '1px solid var(--ow-line)', borderRadius: 'var(--ow-radius)', overflow: 'hidden' }}>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 220px 90px 150px 180px',
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
          <span>Rule</span>
          <span>Frameworks</span>
          <span>Severity</span>
          <span>Category</span>
          <span>Remediation</span>
        </div>
        {shown.length === 0 ? (
          <State text="No rules match these filters." />
        ) : (
          shown.map((r, i) => <RuleRow key={r.id} rule={r} first={i === 0} />)
        )}
      </div>
    </div>
  );
}

function RuleRow({ rule, first }: { rule: Rule; first: boolean }) {
  const sev = SEVERITY[rule.severity];
  const tags = flattenRefs(rule.framework_refs ?? {});
  const rem = rule.remediation;
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '1fr 220px 90px 150px 180px',
        gap: 12,
        alignItems: 'start',
        padding: '12px 16px',
        borderTop: first ? 'none' : '1px solid var(--ow-line)',
      }}
    >
      <span style={{ display: 'flex', flexDirection: 'column', gap: 3, minWidth: 0 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--ow-fg-0)' }}>{rule.title}</span>
        {rule.description ? (
          <span style={{ fontSize: 12, color: 'var(--ow-fg-2)', lineHeight: 1.4 }}>{rule.description}</span>
        ) : null}
        <span style={{ fontSize: 11, fontFamily: 'var(--ow-font-mono)', color: 'var(--ow-fg-3)' }}>{rule.id}</span>
      </span>
      <span style={{ display: 'flex', flexWrap: 'wrap', gap: 5, alignContent: 'flex-start' }}>
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
              height: 'fit-content',
            }}
          >
            {t.label}
          </span>
        ))}
      </span>
      <span>
        {sev ? (
          <span style={{ fontSize: 11, fontWeight: 700, color: sev.fg, background: sev.bg, padding: '2px 8px', borderRadius: 4 }}>
            {sev.label}
          </span>
        ) : (
          <span style={{ fontSize: 12, color: 'var(--ow-fg-3)' }}>{rule.severity}</span>
        )}
      </span>
      <span style={{ fontSize: 12, color: 'var(--ow-fg-2)' }}>{rule.category}</span>
      <span style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        <span style={{ fontSize: 12, fontFamily: 'var(--ow-font-mono)', color: rem.manual ? 'var(--ow-fg-3)' : 'var(--ow-fg-1)' }}>
          {rem.mechanism || 'none'}
        </span>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--ow-fg-3)' }}>
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              background: rem.manual ? 'var(--ow-fg-3)' : 'var(--ow-ok)',
            }}
          />
          {rem.manual ? 'manual' : 'atomic'}
        </span>
      </span>
    </div>
  );
}

function ExportButton({ rules }: { rules: Rule[] }) {
  function exportCsv() {
    const head = ['id', 'title', 'severity', 'category', 'frameworks', 'remediation'];
    const esc = (v: string) => `"${String(v).replace(/"/g, '""')}"`;
    const lines = [head.join(',')];
    for (const r of rules) {
      const fws = Object.entries(r.framework_refs ?? {})
        .flatMap(([fid, cs]) => cs.map((c) => fwTag(fid, c).label))
        .join(' ');
      lines.push([r.id, r.title, r.severity, r.category, fws, r.remediation.mechanism || 'none'].map(esc).join(','));
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'kensa-rules.csv';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }
  return (
    <button
      type="button"
      onClick={exportCsv}
      style={{
        background: 'transparent',
        color: 'var(--ow-link)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: '5px 12px',
        fontSize: 12,
        fontWeight: 500,
        cursor: 'pointer',
      }}
    >
      Export
    </button>
  );
}

function SevChip({ label, active, onClick, tone }: { label: string; active: boolean; onClick: () => void; tone?: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
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
    </button>
  );
}

function Select({
  value,
  onChange,
  label,
  options,
  render,
}: {
  value: string;
  onChange: (v: string) => void;
  label: string;
  options: string[];
  render?: (v: string) => string;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      aria-label={label}
      style={{
        background: 'var(--ow-bg-2)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        color: 'var(--ow-fg-1)',
        fontSize: 12,
        padding: '7px 10px',
        cursor: 'pointer',
      }}
    >
      <option value="all">{label}</option>
      {options.map((o) => (
        <option key={o} value={o}>
          {render ? render(o) : o}
        </option>
      ))}
    </select>
  );
}

function Panel({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ border: '1px solid var(--ow-line)', borderRadius: 'var(--ow-radius)', overflow: 'hidden' }}>
      {children}
    </div>
  );
}

function State({ text, tone }: { text: string; tone?: 'crit' }) {
  return (
    <div style={{ padding: 28, textAlign: 'center', fontSize: 13, color: tone === 'crit' ? 'var(--ow-crit)' : 'var(--ow-fg-3)' }}>
      {text}
    </div>
  );
}
