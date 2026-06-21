import { useEffect, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '@/api/client';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import { apiErrorMessage } from '@/api/errors';
import { useAuthStore } from '@/store/useAuthStore';
import type { components } from '@/api/schema';

// ReportsPage — the compliance-artifact library at /reports.
//
// MVP scope (matches docs/engineering/prototypes/openwatch-v1/Reports.html
// but built honestly): ONE template, the Fleet Compliance Executive
// Summary. "Generate report" computes a point-in-time posture snapshot
// from data that already exists (host_rule_state pass/fail + critical,
// the fleet rollup, recent drift) and stores it as a report row with
// JSON content. The Library tab lists those rows; clicking one opens a
// simple detail panel rendering the stored content JSON.
//
// Deferred (rendered as honest "coming soon" states, NOT faked): Ed25519
// signing + the "Signed" badge, PDF/OSCAL export, the Templates gallery,
// the Scheduled dispatcher. Those need crypto + a renderer + a scheduler
// that do not exist yet, so the prototype's signed PDFs are not faked.

type Report = components['schemas']['Report'];

// The executive-summary content shape (see api-reports spec). `content`
// is typed as an open map in the schema, so narrow it here for display.
interface ExecutiveContent {
  compliance_pct: number | null;
  host_count: number;
  passing_rules: number;
  failing_rules: number;
  critical_issues: number;
  top_failing_rules: { rule_id: string; failing_host_count: number }[];
}

function asExecutiveContent(content: Report['content']): ExecutiveContent {
  const c = content as Partial<ExecutiveContent>;
  return {
    compliance_pct: typeof c.compliance_pct === 'number' ? c.compliance_pct : null,
    host_count: typeof c.host_count === 'number' ? c.host_count : 0,
    passing_rules: typeof c.passing_rules === 'number' ? c.passing_rules : 0,
    failing_rules: typeof c.failing_rules === 'number' ? c.failing_rules : 0,
    critical_issues: typeof c.critical_issues === 'number' ? c.critical_issues : 0,
    top_failing_rules: Array.isArray(c.top_failing_rules) ? c.top_failing_rules : [],
  };
}

function kindLabel(kind: Report['kind']): string {
  if (kind === 'executive') return 'Executive';
  return kind;
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function ReportsPage() {
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);
  useEffect(() => {
    setCrumbs([{ label: 'Compliance' }, { label: 'Reports' }]);
    return () => setCrumbs([]);
  }, [setCrumbs]);

  const [tab, setTab] = useState<'library' | 'templates' | 'scheduled'>('library');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  // Scope for the next Generate. '' = all hosts (the unscoped summary).
  const [scopeGroupId, setScopeGroupId] = useState<string>('');

  const queryClient = useQueryClient();
  const canGenerate = useAuthStore((s) => s.hasPermission('host:write'));

  const reportsQ = useQuery({
    queryKey: ['reports'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/reports', {});
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
  });

  // Groups populate the scope picker. Only meaningful to generators, but
  // the list itself is host:read; tolerate failure by falling back to the
  // all-hosts-only picker.
  const groupsQ = useQuery({
    queryKey: ['groups'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/groups', {});
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
    enabled: canGenerate,
  });
  const groups = groupsQ.data?.groups ?? [];

  const generateMutation = useMutation({
    mutationFn: async () => {
      const body = scopeGroupId ? { group_id: scopeGroupId } : {};
      const { data, error, response } = await api.POST('/api/v1/reports:generate', { body });
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
    onSuccess: (report) => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
      setSelectedId(report.id);
    },
  });

  const reports = reportsQ.data?.reports ?? [];

  return (
    <div style={{ padding: '20px 28px 60px' }}>
      <title>Reports · OpenWatch</title>

      <header
        style={{
          display: 'flex',
          alignItems: 'flex-end',
          justifyContent: 'space-between',
          gap: 24,
          marginBottom: 16,
        }}
      >
        <div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 600, letterSpacing: '-0.01em' }}>
            Reports
          </h1>
          <div style={{ color: 'var(--ow-fg-2)', fontSize: 13, marginTop: 2, maxWidth: 640 }}>
            Point-in-time compliance artifacts for auditors and leadership. Generated from the last
            successful scans, not live.
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
          {canGenerate && (
            <select
              aria-label="Report scope"
              value={scopeGroupId}
              onChange={(e) => setScopeGroupId(e.target.value)}
              disabled={generateMutation.isPending}
              title="Scope the report to a group, or all hosts"
              style={{
                height: 34,
                padding: '0 10px',
                borderRadius: 'var(--ow-radius-sm, 6px)',
                border: '1px solid var(--ow-line)',
                background: 'var(--ow-bg-2)',
                color: 'var(--ow-fg-0)',
                fontFamily: 'inherit',
                fontSize: 13,
                cursor: generateMutation.isPending ? 'default' : 'pointer',
              }}
            >
              <option value="">All hosts</option>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          )}
          <button
            type="button"
            onClick={() => generateMutation.mutate()}
            disabled={!canGenerate || generateMutation.isPending}
            title={
              canGenerate
                ? 'Generate a Fleet Compliance Executive Summary'
                : 'Requires host:write permission'
            }
            style={{
              height: 34,
              padding: '0 14px',
              borderRadius: 'var(--ow-radius-sm, 6px)',
              border: '1px solid var(--ow-info)',
              background: 'var(--ow-info)',
              color: '#0a1424',
              fontFamily: 'inherit',
              fontSize: 13,
              fontWeight: 600,
              cursor: !canGenerate || generateMutation.isPending ? 'default' : 'pointer',
              opacity: !canGenerate || generateMutation.isPending ? 0.6 : 1,
              whiteSpace: 'nowrap',
              flexShrink: 0,
            }}
          >
            {generateMutation.isPending ? 'Generating…' : 'Generate report'}
          </button>
        </div>
      </header>

      {generateMutation.isError && (
        <div
          role="alert"
          style={{
            marginBottom: 14,
            padding: '10px 14px',
            borderRadius: 'var(--ow-radius)',
            border: '1px solid var(--ow-crit)',
            background: 'var(--ow-crit-bg, rgba(220,60,60,0.12))',
            color: 'var(--ow-crit)',
            fontSize: 13,
          }}
        >
          {apiErrorMessage(generateMutation.error, 'Failed to generate report')}
        </div>
      )}

      {/* tabs */}
      <div
        role="tablist"
        aria-label="Report views"
        style={{ display: 'flex', gap: 4, marginBottom: 14 }}
      >
        <Tab id="library" active={tab === 'library'} onClick={() => setTab('library')}>
          Library
        </Tab>
        <Tab id="templates" active={tab === 'templates'} onClick={() => setTab('templates')}>
          Templates
        </Tab>
        <Tab id="scheduled" active={tab === 'scheduled'} onClick={() => setTab('scheduled')}>
          Scheduled
        </Tab>
      </div>

      {tab === 'library' && (
        <LibraryTab
          reports={reports}
          isPending={reportsQ.isPending}
          isError={reportsQ.isError}
          error={reportsQ.error}
          onSelect={setSelectedId}
        />
      )}
      {tab === 'templates' && <ComingSoon what="Templates" />}
      {tab === 'scheduled' && <ComingSoon what="Scheduled" />}

      {selectedId && (
        <ReportDetail
          report={reports.find((r) => r.id === selectedId) ?? null}
          id={selectedId}
          onClose={() => setSelectedId(null)}
        />
      )}
    </div>
  );
}

function LibraryTab({
  reports,
  isPending,
  isError,
  error,
  onSelect,
}: {
  reports: Report[];
  isPending: boolean;
  isError: boolean;
  error: unknown;
  onSelect: (id: string) => void;
}) {
  if (isError)
    return (
      <Panel>
        <State kind="error" text={apiErrorMessage(error, 'Failed to load reports')} />
      </Panel>
    );
  if (isPending)
    return (
      <Panel>
        <State kind="loading" />
      </Panel>
    );
  if (reports.length === 0)
    return (
      <Panel>
        <State kind="empty" text="No reports yet. Generate one to populate the library." />
      </Panel>
    );

  return (
    <Panel>
      <Row head cols="2fr 120px 1fr 120px 1.4fr 90px">
        <span>Report</span>
        <span>Type</span>
        <span>Scope</span>
        <span>Data as of</span>
        <span>Generated by</span>
        <span>Format</span>
      </Row>
      {reports.map((r, i) => (
        <button
          key={r.id}
          type="button"
          onClick={() => onSelect(r.id)}
          style={{
            display: 'block',
            width: '100%',
            textAlign: 'left',
            border: 'none',
            background: 'transparent',
            padding: 0,
            cursor: 'pointer',
            font: 'inherit',
            color: 'inherit',
          }}
        >
          <Row cols="2fr 120px 1fr 120px 1.4fr 90px" first={i === 0} hover>
            <span style={{ minWidth: 0 }}>
              <span
                style={{
                  display: 'block',
                  fontSize: 13,
                  fontWeight: 500,
                  color: 'var(--ow-fg-0)',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}
              >
                {r.title}
              </span>
              <span
                style={{ display: 'block', fontSize: 11, color: 'var(--ow-fg-3)', marginTop: 1 }}
              >
                {formatDate(r.data_as_of)} . {r.scope_label}
              </span>
            </span>
            <span>
              <KindChip kind={r.kind} />
            </span>
            <span style={{ fontSize: 12, color: 'var(--ow-fg-2)' }}>{r.scope_label}</span>
            <span
              style={{
                fontSize: 12,
                color: 'var(--ow-fg-2)',
                fontFamily: 'var(--ow-font-mono, monospace)',
              }}
            >
              {formatDate(r.data_as_of)}
            </span>
            <span
              style={{
                fontSize: 12,
                color: 'var(--ow-fg-2)',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
            >
              {r.generated_by}
            </span>
            <span
              style={{
                fontSize: 11,
                color: 'var(--ow-fg-3)',
                fontFamily: 'var(--ow-font-mono, monospace)',
                textTransform: 'uppercase',
              }}
            >
              {r.format}
            </span>
          </Row>
        </button>
      ))}
    </Panel>
  );
}

function ReportDetail({
  report,
  id,
  onClose,
}: {
  report: Report | null;
  id: string;
  onClose: () => void;
}) {
  // The list query already holds every report, so we render from the row
  // the user clicked. Fall back to a direct fetch only if the row is not
  // in the cached list (defensive; should not happen in normal flow).
  const detailQ = useQuery({
    queryKey: ['reports', id],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/reports/{id}', {
        params: { path: { id } },
      });
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
    enabled: report === null,
  });

  const resolved = report ?? detailQ.data ?? null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Report detail"
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.6)',
        zIndex: 80,
        overflowY: 'auto',
        display: 'flex',
        justifyContent: 'center',
        padding: '40px 20px',
      }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          maxWidth: 760,
          width: '100%',
          height: 'fit-content',
          background: 'var(--ow-bg-1)',
          border: '1px solid var(--ow-line)',
          borderRadius: 'var(--ow-radius)',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            padding: '14px 20px',
            borderBottom: '1px solid var(--ow-line)',
          }}
        >
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--ow-fg-0)' }}>
              {resolved ? resolved.title : 'Report'}
            </div>
            {resolved && (
              <div style={{ fontSize: 12, color: 'var(--ow-fg-3)', marginTop: 1 }}>
                Data as of {formatDate(resolved.data_as_of)} . {resolved.scope_label} . generated by{' '}
                {resolved.generated_by}
              </div>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            style={{
              width: 32,
              height: 32,
              borderRadius: 6,
              border: '1px solid var(--ow-line)',
              background: 'var(--ow-bg-1)',
              color: 'var(--ow-fg-2)',
              cursor: 'pointer',
              fontSize: 16,
              lineHeight: 1,
            }}
          >
            ×
          </button>
        </div>

        <div style={{ padding: '20px 24px 28px' }}>
          {!resolved && detailQ.isPending && <State kind="loading" />}
          {!resolved && detailQ.isError && (
            <State kind="error" text={apiErrorMessage(detailQ.error, 'Failed to load report')} />
          )}
          {resolved && <ExecutiveBody content={asExecutiveContent(resolved.content)} />}
        </div>
      </div>
    </div>
  );
}

function ExecutiveBody({ content }: { content: ExecutiveContent }) {
  const pct = content.compliance_pct;
  const pctTone =
    pct === null
      ? 'var(--ow-fg-2)'
      : pct >= 80
        ? 'var(--ow-ok)'
        : pct >= 50
          ? 'var(--ow-warn)'
          : 'var(--ow-crit)';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <section>
        <SectionHead>Posture snapshot</SectionHead>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
            gap: 12,
          }}
        >
          <Stat
            label="Fleet compliance"
            value={pct === null ? 'n/a' : `${Math.round(pct)}%`}
            tone={pctTone}
          />
          <Stat label="Hosts" value={`${content.host_count}`} />
          <Stat label="Passing rules" value={`${content.passing_rules}`} tone="var(--ow-ok)" />
          <Stat label="Failing rules" value={`${content.failing_rules}`} tone="var(--ow-warn)" />
          <Stat
            label="Critical issues"
            value={`${content.critical_issues}`}
            tone="var(--ow-crit)"
          />
        </div>
      </section>

      <section>
        <SectionHead>Top failing rules</SectionHead>
        {content.top_failing_rules.length === 0 ? (
          <div style={{ fontSize: 13, color: 'var(--ow-fg-3)', padding: '8px 0' }}>
            No failing rules recorded.
          </div>
        ) : (
          <Panel>
            <Row head cols="1fr 140px">
              <span>Rule</span>
              <span>Failing hosts</span>
            </Row>
            {content.top_failing_rules.map((rule, i) => (
              <Row key={rule.rule_id} cols="1fr 140px" first={i === 0}>
                <span
                  style={{
                    fontSize: 12,
                    fontFamily: 'var(--ow-font-mono, monospace)',
                    color: 'var(--ow-fg-1)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {rule.rule_id}
                </span>
                <span style={{ fontSize: 13, color: 'var(--ow-fg-1)' }}>
                  {rule.failing_host_count}
                </span>
              </Row>
            ))}
          </Panel>
        )}
      </section>

      <div
        style={{
          fontSize: 12,
          color: 'var(--ow-fg-3)',
          lineHeight: 1.5,
          paddingTop: 4,
          borderTop: '1px solid var(--ow-line)',
        }}
      >
        Figures reflect the last successful scan per host, not current state. Signing, PDF, and
        OSCAL export are not part of this MVP.
      </div>
    </div>
  );
}

function ComingSoon({ what }: { what: string }) {
  return (
    <Panel>
      <div style={{ padding: '48px 24px', textAlign: 'center' }}>
        <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--ow-fg-1)' }}>
          {what} are coming soon
        </div>
        <div
          style={{
            fontSize: 13,
            color: 'var(--ow-fg-3)',
            marginTop: 8,
            maxWidth: 480,
            margin: '8px auto 0',
            lineHeight: 1.5,
          }}
        >
          {what === 'Templates'
            ? 'A gallery of report templates (attestation, remediation, exceptions) requires signing and PDF/OSCAL rendering, which are not built yet. Today the Library generates a Fleet Compliance Executive Summary.'
            : 'Scheduled report delivery requires a dispatcher and signing, which are not built yet. For now, generate reports on demand from the Library tab.'}
        </div>
      </div>
    </Panel>
  );
}

function KindChip({ kind }: { kind: Report['kind'] }) {
  return (
    <span
      style={{
        fontSize: 11,
        fontWeight: 600,
        padding: '2px 9px',
        borderRadius: 999,
        background: 'var(--ow-info-bg, rgba(70,130,220,0.16))',
        color: 'var(--ow-info)',
        whiteSpace: 'nowrap',
      }}
    >
      {kindLabel(kind)}
    </span>
  );
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div
      style={{
        background: 'var(--ow-bg-2)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: '12px 14px',
      }}
    >
      <div
        style={{
          color: 'var(--ow-fg-3)',
          fontSize: 11,
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontSize: 22,
          fontWeight: 600,
          marginTop: 4,
          color: tone ?? 'var(--ow-fg-0)',
          fontVariantNumeric: 'tabular-nums',
        }}
      >
        {value}
      </div>
    </div>
  );
}

function SectionHead({ children }: { children: React.ReactNode }) {
  return (
    <h2
      style={{
        fontSize: 11,
        textTransform: 'uppercase',
        letterSpacing: '0.1em',
        color: 'var(--ow-fg-3)',
        fontWeight: 600,
        margin: '0 0 12px',
        paddingBottom: 8,
        borderBottom: '1px solid var(--ow-line)',
      }}
    >
      {children}
    </h2>
  );
}

function Tab({
  id,
  active,
  onClick,
  children,
}: {
  id: string;
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      role="tab"
      id={`reports-tab-${id}`}
      aria-selected={active}
      onClick={onClick}
      style={{
        height: 34,
        padding: '0 14px',
        border: 0,
        borderBottom: `2px solid ${active ? 'var(--ow-info)' : 'transparent'}`,
        background: 'transparent',
        color: active ? 'var(--ow-fg-0)' : 'var(--ow-fg-2)',
        fontFamily: 'inherit',
        fontSize: 13,
        fontWeight: 600,
        cursor: 'pointer',
      }}
    >
      {children}
    </button>
  );
}

function Panel({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        overflow: 'hidden',
      }}
    >
      {children}
    </div>
  );
}

function Row({
  children,
  cols,
  head,
  first,
  hover,
}: {
  children: React.ReactNode;
  cols: string;
  head?: boolean;
  first?: boolean;
  hover?: boolean;
}) {
  return (
    <div
      data-hover={hover ? '1' : undefined}
      style={{
        display: 'grid',
        gridTemplateColumns: cols,
        gap: 12,
        padding: head ? '10px 16px' : '11px 16px',
        alignItems: 'center',
        background: head ? 'var(--ow-bg-2)' : undefined,
        borderTop: head || first ? 'none' : '1px solid var(--ow-line)',
        borderBottom: head ? '1px solid var(--ow-line)' : undefined,
        fontSize: head ? 11 : 13,
        fontWeight: head ? 600 : undefined,
        textTransform: head ? 'uppercase' : undefined,
        letterSpacing: head ? '0.04em' : undefined,
        color: head ? 'var(--ow-fg-3)' : undefined,
      }}
    >
      {children}
    </div>
  );
}

function State({ kind, text }: { kind: 'loading' | 'error' | 'empty'; text?: string }) {
  const color = kind === 'error' ? 'var(--ow-crit)' : 'var(--ow-fg-3)';
  return (
    <div
      role={kind === 'error' ? 'alert' : 'status'}
      style={{
        padding: kind === 'empty' ? '40px 16px' : '16px',
        textAlign: kind === 'empty' ? 'center' : 'left',
        color,
        fontSize: 13,
      }}
    >
      {text ?? (kind === 'loading' ? 'Loading…' : 'No data')}
    </div>
  );
}
