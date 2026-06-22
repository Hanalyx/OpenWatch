import { useEffect, useState, type CSSProperties } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import api from '@/api/client';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import { apiErrorMessage } from '@/api/errors';
import { useAuthStore } from '@/store/useAuthStore';
import type { components } from '@/api/schema';

// ReportsPage — the compliance-artifact library at /reports.
//
// Two report kinds, generatable from the Library's kind selector: the
// Fleet Compliance Executive Summary (leadership) and the Framework
// Attestation (auditor/GRC). "Generate report" computes a point-in-time,
// immutable snapshot from data that already exists and stores it as a
// report row; the Library lists those rows and the detail panel renders a
// kind-aware body (ExecutiveBody / AttestationBody) over the frozen content.
//
// Live: kind selector, scope + framework pickers, coverage caveat, Ed25519
// signing with a "Signed" badge + offline Verify, and downloadable faces
// (PDF cover, CSV evidence, OSCAL SAR, canonical JSON). Still deferred
// (honest "coming soon" states, NOT faked): the Templates gallery and the
// Scheduled dispatcher.

type Report = components['schemas']['Report'];

// The executive-summary content shape (see api-reports spec). `content`
// is typed as an open map in the schema, so narrow it here for display.
interface Coverage {
  hosts_total: number;
  hosts_fresh: number;
  hosts_stale: number;
  hosts_unreachable: number;
}

interface ExecutiveContent {
  compliance_pct: number | null;
  host_count: number;
  passing_rules: number;
  failing_rules: number;
  critical_issues: number;
  top_failing_rules: { rule_id: string; failing_host_count: number }[];
  coverage: Coverage;
}

function asCoverage(c: Partial<Coverage> | undefined): Coverage {
  return {
    hosts_total: typeof c?.hosts_total === 'number' ? c.hosts_total : 0,
    hosts_fresh: typeof c?.hosts_fresh === 'number' ? c.hosts_fresh : 0,
    hosts_stale: typeof c?.hosts_stale === 'number' ? c.hosts_stale : 0,
    hosts_unreachable: typeof c?.hosts_unreachable === 'number' ? c.hosts_unreachable : 0,
  };
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
    coverage: asCoverage(c.coverage as Partial<Coverage> | undefined),
  };
}

// The attestation-summary content shape (see api-reports spec). Unlike the
// executive shape it carries no pass/fail rollup — those numbers live in the
// downloadable faces (PDF/CSV/OSCAL). The in-app body shows coverage (hosts
// attested of in-scope) and the framework lens, then points at the faces.
interface AttestedHostRef {
  host_id: string;
  scan_id: string;
  scanned_at: string;
}

interface AttestationRollup {
  compliance_pct: number | null;
  total_checks: number;
  passing: number;
  failing: number;
  skipped: number;
  errored: number;
  top_failing: { rule_id: string; failing_host_count: number }[];
}

interface AttestationContent {
  framework: string;
  hosts_total: number;
  hosts_attested: number;
  attested: AttestedHostRef[];
  rollup: AttestationRollup;
}

function asAttestationRollup(r: Partial<AttestationRollup> | undefined): AttestationRollup {
  return {
    compliance_pct: typeof r?.compliance_pct === 'number' ? r.compliance_pct : null,
    total_checks: typeof r?.total_checks === 'number' ? r.total_checks : 0,
    passing: typeof r?.passing === 'number' ? r.passing : 0,
    failing: typeof r?.failing === 'number' ? r.failing : 0,
    skipped: typeof r?.skipped === 'number' ? r.skipped : 0,
    errored: typeof r?.errored === 'number' ? r.errored : 0,
    top_failing: Array.isArray(r?.top_failing) ? r.top_failing : [],
  };
}

function asAttestationContent(content: Report['content']): AttestationContent {
  const c = content as Partial<AttestationContent>;
  return {
    framework: typeof c.framework === 'string' ? c.framework : '',
    hosts_total: typeof c.hosts_total === 'number' ? c.hosts_total : 0,
    hosts_attested: typeof c.hosts_attested === 'number' ? c.hosts_attested : 0,
    attested: Array.isArray(c.attested) ? c.attested : [],
    rollup: asAttestationRollup(c.rollup as Partial<AttestationRollup> | undefined),
  };
}

// The exception-register content shape (see api-reports spec): a summary by
// state plus the register rows. The CSV face carries the full register; the
// in-app body shows the summary + a sampled soonest-expiring list.
interface ExceptionSummary {
  total: number;
  active: number;
  requested: number;
  approved: number;
  rejected: number;
  revoked: number;
  expired: number;
  expiring_soon: number;
}

interface ExceptionRow {
  host_name: string;
  rule_id: string;
  status: string;
  reason: string;
  requested_by: string;
  requested_at: string;
  reviewed_by: string;
  reviewed_at: string | null;
  expires_at: string | null;
  active: boolean;
}

interface ExceptionContent {
  summary: ExceptionSummary;
  exceptions: ExceptionRow[];
}

function asExceptionSummary(s: Partial<ExceptionSummary> | undefined): ExceptionSummary {
  const n = (v: unknown): number => (typeof v === 'number' ? v : 0);
  return {
    total: n(s?.total),
    active: n(s?.active),
    requested: n(s?.requested),
    approved: n(s?.approved),
    rejected: n(s?.rejected),
    revoked: n(s?.revoked),
    expired: n(s?.expired),
    expiring_soon: n(s?.expiring_soon),
  };
}

function asExceptionContent(content: Report['content']): ExceptionContent {
  const c = content as Partial<ExceptionContent>;
  return {
    summary: asExceptionSummary(c.summary as Partial<ExceptionSummary> | undefined),
    exceptions: Array.isArray(c.exceptions) ? c.exceptions : [],
  };
}

// The remediation-activity content shape (see api-reports spec): the period
// it covers, a summary by outcome, and the activity rows. The CSV face is
// the full log; the in-app body shows the period + summary + recent sample.
interface RemediationSummary {
  total: number;
  executed: number;
  rolled_back: number;
  failed: number;
  rejected: number;
  pending: number;
}

interface RemediationActRow {
  host_name: string;
  rule_id: string;
  status: string;
  mechanism: string;
  requested_by: string;
  requested_at: string;
  reviewed_by: string;
  reviewed_at: string | null;
}

interface RemediationContent {
  period_from: string;
  period_to: string;
  summary: RemediationSummary;
  activities: RemediationActRow[];
}

function asRemediationSummary(s: Partial<RemediationSummary> | undefined): RemediationSummary {
  const n = (v: unknown): number => (typeof v === 'number' ? v : 0);
  return {
    total: n(s?.total),
    executed: n(s?.executed),
    rolled_back: n(s?.rolled_back),
    failed: n(s?.failed),
    rejected: n(s?.rejected),
    pending: n(s?.pending),
  };
}

function asRemediationContent(content: Report['content']): RemediationContent {
  const c = content as Partial<RemediationContent>;
  return {
    period_from: typeof c.period_from === 'string' ? c.period_from : '',
    period_to: typeof c.period_to === 'string' ? c.period_to : '',
    summary: asRemediationSummary(c.summary as Partial<RemediationSummary> | undefined),
    activities: Array.isArray(c.activities) ? c.activities : [],
  };
}

function kindLabel(kind: Report['kind']): string {
  if (kind === 'executive') return 'Executive';
  if (kind === 'attestation') return 'Attestation';
  if (kind === 'exception') return 'Exception Register';
  if (kind === 'remediation') return 'Remediation Activity';
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
  // Kind + scope for the next Generate. '' = all hosts / all frameworks.
  const [reportKind, setReportKind] = useState<
    'executive' | 'attestation' | 'exception' | 'remediation'
  >('executive');
  const [scopeGroupId, setScopeGroupId] = useState<string>('');
  const [scopeFramework, setScopeFramework] = useState<string>('');
  // Look-back window (days) for the remediation activity kind.
  const [periodDays, setPeriodDays] = useState<number>(30);

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

  // Frameworks populate the lens picker (the fleet framework catalog).
  // host:read; tolerate failure by falling back to the all-frameworks lens.
  const frameworksQ = useQuery({
    queryKey: ['report-frameworks'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/reports/frameworks', {});
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
    enabled: canGenerate,
  });
  const frameworks = frameworksQ.data?.frameworks ?? [];

  const generateMutation = useMutation({
    mutationFn: async () => {
      const body: {
        kind?: 'executive' | 'attestation' | 'exception' | 'remediation';
        group_id?: string;
        framework?: string;
        period_days?: number;
      } = {};
      // executive is the implicit default; send kind only for the others.
      if (reportKind !== 'executive') body.kind = reportKind;
      if (scopeGroupId) body.group_id = scopeGroupId;
      if (scopeFramework) body.framework = scopeFramework;
      // The period window only applies to the remediation activity kind.
      if (reportKind === 'remediation') body.period_days = periodDays;
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
              aria-label="Report kind"
              value={reportKind}
              onChange={(e) =>
                setReportKind(
                  e.target.value as 'executive' | 'attestation' | 'exception' | 'remediation',
                )
              }
              disabled={generateMutation.isPending}
              title="Executive summary (leadership), Framework Attestation (auditor evidence), Exception Register (compliance waivers), or Remediation Activity (fixes over a period)"
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
              <option value="executive">Executive</option>
              <option value="attestation">Attestation</option>
              <option value="exception">Exception Register</option>
              <option value="remediation">Remediation Activity</option>
            </select>
          )}
          {canGenerate && reportKind === 'remediation' && (
            <select
              aria-label="Remediation period"
              value={periodDays}
              onChange={(e) => setPeriodDays(Number(e.target.value))}
              disabled={generateMutation.isPending}
              title="Look-back window for the remediation activity log"
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
              <option value={7}>Last 7 days</option>
              <option value={30}>Last 30 days</option>
              <option value={90}>Last 90 days</option>
            </select>
          )}
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
          {canGenerate && frameworks.length > 0 && (
            <select
              aria-label="Framework lens"
              value={scopeFramework}
              onChange={(e) => setScopeFramework(e.target.value)}
              disabled={generateMutation.isPending}
              title="Scope the report to one framework lens, or all frameworks"
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
              <option value="">All frameworks</option>
              {frameworks.map((f) => (
                <option key={f.framework} value={f.framework}>
                  {f.framework} ({f.rule_count})
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
      {tab === 'scheduled' && <SchedulesTab canGenerate={canGenerate} />}

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

// downloadReportFace fetches a rendered face of a report (pdf | json) and
// triggers a browser download. The export endpoint is a GET, so the
// session cookie authenticates it (same-origin credentials) and no CSRF
// token is needed; the filename comes from the server's
// Content-Disposition. Errors are surfaced to the caller.
async function downloadReportFace(
  id: string,
  format: 'pdf' | 'json' | 'csv' | 'oscal_sar',
): Promise<void> {
  const res = await fetch(`/api/v1/reports/${id}/export?format=${format}`, {
    credentials: 'same-origin',
  });
  if (!res.ok) {
    throw new Error(`Export failed (${res.status})`);
  }
  const blob = await res.blob();
  const cd = res.headers.get('Content-Disposition') ?? '';
  const match = cd.match(/filename="?([^"]+)"?/);
  const filename = match?.[1] ?? `openwatch-report.${format}`;
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// The domain-separation prefix the backend signs (report.signing.go).
const SIGN_DOMAIN = 'openwatch/report-snapshot/v1\n';

// base64ToBuffer / utf8ToBuffer return plain ArrayBuffers so the Web
// Crypto calls (digest/importKey/verify) get a BufferSource without the
// TS Uint8Array<ArrayBufferLike> generic mismatch.
function base64ToBuffer(b64: string): ArrayBuffer {
  const bin = atob(b64);
  const buf = new ArrayBuffer(bin.length);
  const view = new Uint8Array(buf);
  for (let i = 0; i < bin.length; i++) view[i] = bin.charCodeAt(i);
  return buf;
}

function utf8ToBuffer(s: string): ArrayBuffer {
  const u = new TextEncoder().encode(s);
  const buf = new ArrayBuffer(u.byteLength);
  new Uint8Array(buf).set(u);
  return buf;
}

function bytesToHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

interface VerifyResult {
  ok: boolean;
  detail: string;
}

// verifyReport checks a signed report offline in the browser: it fetches
// the published signing key, re-hashes the canonical JSON face and
// compares it to content_sha256 (content integrity), then Ed25519-verifies
// the signature over the same domain-separated payload the server signed.
// The Ed25519 step degrades gracefully where Web Crypto lacks it (the
// content hash is still verified).
async function verifyReport(report: Report): Promise<VerifyResult> {
  if (!report.signature || !report.signing_key_id) {
    return { ok: false, detail: 'This report is not signed.' };
  }
  const keyRes = await fetch('/api/v1/reports/signing-key', { credentials: 'same-origin' });
  if (!keyRes.ok)
    return { ok: false, detail: `Could not fetch the signing key (${keyRes.status}).` };
  const key = (await keyRes.json()) as {
    key_id: string;
    public_key: string;
    ephemeral: boolean;
  };
  if (key.key_id !== report.signing_key_id) {
    return { ok: false, detail: 'The signing key does not match this report.' };
  }

  const faceRes = await fetch(`/api/v1/reports/${report.id}/export?format=json`, {
    credentials: 'same-origin',
  });
  if (!faceRes.ok)
    return { ok: false, detail: `Could not fetch the report content (${faceRes.status}).` };
  const faceBuf = await faceRes.arrayBuffer();
  const hashHex = bytesToHex(await crypto.subtle.digest('SHA-256', faceBuf));
  if (hashHex !== report.content_sha256) {
    return {
      ok: false,
      detail: 'Content hash mismatch: the content does not match the signed hash.',
    };
  }

  const ephNote = key.ephemeral ? ' (development key, not durable across restarts)' : '';
  const payload = utf8ToBuffer(SIGN_DOMAIN + report.content_sha256);
  try {
    const pubKey = await crypto.subtle.importKey(
      'raw',
      base64ToBuffer(key.public_key),
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    const valid = await crypto.subtle.verify(
      { name: 'Ed25519' },
      pubKey,
      base64ToBuffer(report.signature),
      payload,
    );
    if (!valid) return { ok: false, detail: 'Signature is INVALID.' };
    return {
      ok: true,
      detail: `Verified: content matches and the signature is valid${ephNote}. Key ${key.key_id}.`,
    };
  } catch {
    // This browser's Web Crypto lacks Ed25519; the content hash is verified.
    return {
      ok: true,
      detail: `Content hash verified. Signature check is unavailable in this browser; verify the signature offline with key ${key.key_id}${ephNote}.`,
    };
  }
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
  const [downloading, setDownloading] = useState<'pdf' | 'json' | 'csv' | 'oscal_sar' | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);

  async function onDownload(format: 'pdf' | 'json' | 'csv' | 'oscal_sar') {
    setDownloading(format);
    setDownloadError(null);
    try {
      await downloadReportFace(id, format);
    } catch (e) {
      setDownloadError(e instanceof Error ? e.message : 'Download failed');
    } finally {
      setDownloading(null);
    }
  }

  async function onVerify(report: Report) {
    setVerifying(true);
    setVerifyResult(null);
    try {
      setVerifyResult(await verifyReport(report));
    } catch (e) {
      setVerifyResult({
        ok: false,
        detail: e instanceof Error ? e.message : 'Verification failed',
      });
    } finally {
      setVerifying(false);
    }
  }

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

  // The primary face follows the report kind: executive renders a one-page
  // PDF; attestation and exception lead with their CSV (the per-(host, rule)
  // evidence bundle / the full waiver register). JSON is offered for every
  // kind (it is the signed canonical face).
  const kind = resolved?.kind;
  const csvLed = kind === 'attestation' || kind === 'exception' || kind === 'remediation';
  const primaryFace: 'pdf' | 'csv' = csvLed ? 'csv' : 'pdf';
  const primaryLabel = csvLed ? 'Download CSV' : 'Download PDF';
  const primaryTitle =
    kind === 'attestation'
      ? 'Download the per-host, per-rule CSV evidence'
      : kind === 'exception'
        ? 'Download the full exception register (CSV)'
        : kind === 'remediation'
          ? 'Download the full remediation activity log (CSV)'
          : 'Download the one-page executive PDF';

  // Secondary faces offered beside the primary + JSON. An attestation also
  // exposes its bounded PDF cover and the fleet OSCAL SAR; an exception
  // exposes its bounded PDF summary; an executive has no extra faces (PDF is
  // its primary, JSON is shown for every kind below).
  const secondaryFaces: { face: 'pdf' | 'oscal_sar'; label: string; title: string }[] =
    kind === 'attestation'
      ? [
          { face: 'pdf', label: 'PDF', title: 'Download the one-page attestation cover PDF' },
          {
            face: 'oscal_sar',
            label: 'OSCAL SAR',
            title: 'Download the OSCAL assessment-results (evidence referenced by hash)',
          },
        ]
      : kind === 'exception'
        ? [{ face: 'pdf', label: 'PDF', title: 'Download the one-page exception summary PDF' }]
        : kind === 'remediation'
          ? [{ face: 'pdf', label: 'PDF', title: 'Download the one-page remediation summary PDF' }]
          : [];

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
                {resolved.signature && (
                  <span
                    title={`Signed by ${resolved.signing_key_id ?? 'the report key'}`}
                    style={{
                      marginLeft: 8,
                      padding: '1px 7px',
                      borderRadius: 999,
                      border: '1px solid var(--ow-ok, #2faf6a)',
                      color: 'var(--ow-ok, #2faf6a)',
                      fontSize: 11,
                      fontWeight: 600,
                      whiteSpace: 'nowrap',
                    }}
                  >
                    Signed
                  </span>
                )}
              </div>
            )}
          </div>
          {resolved && (
            <>
              {resolved.signature && (
                <button
                  type="button"
                  onClick={() => onVerify(resolved)}
                  disabled={verifying}
                  title="Verify the signature and content hash offline"
                  style={{
                    height: 32,
                    padding: '0 12px',
                    borderRadius: 6,
                    border: '1px solid var(--ow-line)',
                    background: 'var(--ow-bg-1)',
                    color: 'var(--ow-fg-1)',
                    fontFamily: 'inherit',
                    fontSize: 12,
                    fontWeight: 500,
                    cursor: verifying ? 'default' : 'pointer',
                    opacity: verifying ? 0.6 : 1,
                    whiteSpace: 'nowrap',
                  }}
                >
                  {verifying ? 'Verifying…' : 'Verify'}
                </button>
              )}
              <button
                type="button"
                onClick={() => onDownload(primaryFace)}
                disabled={downloading !== null}
                title={primaryTitle}
                style={{
                  height: 32,
                  padding: '0 12px',
                  borderRadius: 6,
                  border: '1px solid var(--ow-info)',
                  background: 'var(--ow-info)',
                  color: '#0a1424',
                  fontFamily: 'inherit',
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: downloading !== null ? 'default' : 'pointer',
                  opacity: downloading !== null ? 0.6 : 1,
                  whiteSpace: 'nowrap',
                }}
              >
                {downloading === primaryFace ? 'Preparing…' : primaryLabel}
              </button>
              {secondaryFaces.map((f) => (
                <button
                  key={f.face}
                  type="button"
                  onClick={() => onDownload(f.face)}
                  disabled={downloading !== null}
                  title={f.title}
                  style={{
                    height: 32,
                    padding: '0 12px',
                    borderRadius: 6,
                    border: '1px solid var(--ow-line)',
                    background: 'var(--ow-bg-1)',
                    color: 'var(--ow-fg-1)',
                    fontFamily: 'inherit',
                    fontSize: 12,
                    fontWeight: 500,
                    cursor: downloading !== null ? 'default' : 'pointer',
                    opacity: downloading !== null ? 0.6 : 1,
                    whiteSpace: 'nowrap',
                  }}
                >
                  {downloading === f.face ? 'Preparing…' : f.label}
                </button>
              ))}
              <button
                type="button"
                onClick={() => onDownload('json')}
                disabled={downloading !== null}
                title="Download the report data as JSON"
                style={{
                  height: 32,
                  padding: '0 12px',
                  borderRadius: 6,
                  border: '1px solid var(--ow-line)',
                  background: 'var(--ow-bg-1)',
                  color: 'var(--ow-fg-1)',
                  fontFamily: 'inherit',
                  fontSize: 12,
                  fontWeight: 500,
                  cursor: downloading !== null ? 'default' : 'pointer',
                  opacity: downloading !== null ? 0.6 : 1,
                  whiteSpace: 'nowrap',
                }}
              >
                JSON
              </button>
            </>
          )}
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
          {downloadError && (
            <div
              role="alert"
              style={{
                marginBottom: 14,
                padding: '8px 12px',
                borderRadius: 'var(--ow-radius)',
                border: '1px solid var(--ow-crit)',
                background: 'var(--ow-crit-bg, rgba(220,60,60,0.12))',
                color: 'var(--ow-crit)',
                fontSize: 12.5,
              }}
            >
              {downloadError}
            </div>
          )}
          {verifyResult && (
            <div
              role="status"
              style={{
                marginBottom: 14,
                padding: '8px 12px',
                borderRadius: 'var(--ow-radius)',
                border: `1px solid ${verifyResult.ok ? 'var(--ow-ok, #2faf6a)' : 'var(--ow-crit)'}`,
                background: verifyResult.ok
                  ? 'var(--ow-ok-bg, rgba(47,175,106,0.12))'
                  : 'var(--ow-crit-bg, rgba(220,60,60,0.12))',
                color: verifyResult.ok ? 'var(--ow-ok, #2faf6a)' : 'var(--ow-crit)',
                fontSize: 12.5,
              }}
            >
              {verifyResult.detail}
            </div>
          )}
          {resolved &&
            (resolved.kind === 'attestation' ? (
              <AttestationBody content={asAttestationContent(resolved.content)} />
            ) : resolved.kind === 'exception' ? (
              <ExceptionBody content={asExceptionContent(resolved.content)} />
            ) : resolved.kind === 'remediation' ? (
              <RemediationBody content={asRemediationContent(resolved.content)} />
            ) : (
              <ExecutiveBody content={asExecutiveContent(resolved.content)} />
            ))}
        </div>
      </div>
    </div>
  );
}

// CoverageCaveat is the staleness disclosure: it renders only when some
// in-scope hosts have stale data or are unreachable, so a reader knows how
// far to trust the headline numbers. When every host is fresh and
// reachable it renders nothing (no needless warning).
function CoverageCaveat({ coverage }: { coverage: Coverage }) {
  const { hosts_total, hosts_stale, hosts_unreachable } = coverage;
  if (hosts_stale === 0 && hosts_unreachable === 0) return null;

  const parts: string[] = [];
  if (hosts_stale > 0) {
    parts.push(
      `${hosts_stale} of ${hosts_total} ${hosts_stale === 1 ? 'host has' : 'hosts have'} compliance data older than 24 hours (or no scan yet)`,
    );
  }
  if (hosts_unreachable > 0) {
    parts.push(
      `${hosts_unreachable} ${hosts_unreachable === 1 ? 'host is' : 'hosts are'} currently unreachable`,
    );
  }

  return (
    <div
      role="note"
      style={{
        display: 'flex',
        gap: 12,
        alignItems: 'flex-start',
        padding: '12px 14px',
        borderRadius: 'var(--ow-radius)',
        border: '1px solid var(--ow-warn)',
        borderLeft: '3px solid var(--ow-warn)',
        background: 'var(--ow-warn-bg, rgba(200,160,40,0.12))',
        fontSize: 12.5,
        lineHeight: 1.5,
        color: 'var(--ow-fg-1)',
      }}
    >
      <span aria-hidden="true" style={{ color: 'var(--ow-warn)', flexShrink: 0 }}>
        !
      </span>
      <div>
        <strong>Figures reflect the last successful scan per host, not current state.</strong>{' '}
        {parts.join('. ')}. Posture for stale or unreachable hosts may have changed since.
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

      <CoverageCaveat coverage={content.coverage} />

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
        Figures reflect the last successful scan per host, not current state.
      </div>
    </div>
  );
}

function AttestationBody({ content }: { content: AttestationContent }) {
  const lens = content.framework || 'All frameworks';
  const notAttested = Math.max(0, content.hosts_total - content.hosts_attested);
  const r = content.rollup;
  const pct = r.compliance_pct;
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
        <SectionHead>Compliance</SectionHead>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
            gap: 12,
          }}
        >
          <Stat
            label="Compliance"
            value={pct === null ? 'n/a' : `${Math.round(pct)}%`}
            tone={pctTone}
          />
          <Stat label="Framework" value={lens} />
          <Stat
            label="Hosts attested"
            value={`${content.hosts_attested} of ${content.hosts_total}`}
            tone={notAttested > 0 ? 'var(--ow-warn)' : 'var(--ow-ok)'}
          />
          <Stat label="Checks evaluated" value={`${r.total_checks}`} />
          <Stat label="Passing" value={`${r.passing}`} tone="var(--ow-ok)" />
          <Stat label="Failing" value={`${r.failing}`} tone="var(--ow-warn)" />
          <Stat label="Skipped / error" value={`${r.skipped} / ${r.errored}`} />
        </div>
      </section>

      {notAttested > 0 && (
        <div
          role="note"
          style={{
            display: 'flex',
            gap: 12,
            alignItems: 'flex-start',
            padding: '12px 14px',
            borderRadius: 'var(--ow-radius)',
            border: '1px solid var(--ow-warn)',
            borderLeft: '3px solid var(--ow-warn)',
            background: 'var(--ow-warn-bg, rgba(200,160,40,0.12))',
            fontSize: 12.5,
            lineHeight: 1.5,
            color: 'var(--ow-fg-1)',
          }}
        >
          <span aria-hidden="true" style={{ color: 'var(--ow-warn)', flexShrink: 0 }}>
            !
          </span>
          <div>
            {notAttested} of {content.hosts_total} in-scope{' '}
            {notAttested === 1 ? 'host has' : 'hosts have'} no completed scan and{' '}
            {notAttested === 1 ? 'is' : 'are'} not attested here.
          </div>
        </div>
      )}

      <section>
        <SectionHead>Top failing rules</SectionHead>
        {r.top_failing.length === 0 ? (
          <div style={{ fontSize: 13, color: 'var(--ow-fg-3)', padding: '8px 0' }}>
            No failing rules recorded.
          </div>
        ) : (
          <Panel>
            <Row head cols="1fr 140px">
              <span>Rule</span>
              <span>Failing hosts</span>
            </Row>
            {r.top_failing.map((rule, i) => (
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
        Figures are frozen from the latest completed scan per host, not live. The full per-host,
        per-rule breakdown and evidence are in the downloadable PDF, CSV, and OSCAL faces above.
      </div>
    </div>
  );
}

function ExceptionBody({ content }: { content: ExceptionContent }) {
  const s = content.summary;
  const expiring = content.exceptions
    .filter((e) => e.active && e.expires_at)
    .sort((a, b) => (a.expires_at ?? '').localeCompare(b.expires_at ?? ''))
    .slice(0, 10);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <section>
        <SectionHead>Exception waivers</SectionHead>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
            gap: 12,
          }}
        >
          <Stat label="Total waivers" value={`${s.total}`} />
          <Stat label="Active" value={`${s.active}`} tone="var(--ow-ok)" />
          <Stat label="Pending review" value={`${s.requested}`} tone="var(--ow-warn)" />
          <Stat
            label="Expiring within 30 days"
            value={`${s.expiring_soon}`}
            tone={s.expiring_soon > 0 ? 'var(--ow-warn)' : undefined}
          />
          <Stat
            label="Rejected / revoked / expired"
            value={`${s.rejected} / ${s.revoked} / ${s.expired}`}
          />
        </div>
      </section>

      <section>
        <SectionHead>Soonest-expiring active waivers</SectionHead>
        {expiring.length === 0 ? (
          <div style={{ fontSize: 13, color: 'var(--ow-fg-3)', padding: '8px 0' }}>
            No active waivers with an expiry date.
          </div>
        ) : (
          <Panel>
            <Row head cols="1fr 1fr 120px">
              <span>Host</span>
              <span>Rule</span>
              <span>Expires</span>
            </Row>
            {expiring.map((e, i) => (
              <Row key={`${e.host_name}:${e.rule_id}`} cols="1fr 1fr 120px" first={i === 0}>
                <span
                  style={{
                    fontSize: 12,
                    color: 'var(--ow-fg-1)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {e.host_name}
                </span>
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
                  {e.rule_id}
                </span>
                <span style={{ fontSize: 13, color: 'var(--ow-fg-1)' }}>
                  {e.expires_at ? formatDate(e.expires_at) : ''}
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
        Point-in-time snapshot of compliance waivers. The full register (every waiver with its
        justification, approver, and dates) is in the downloadable CSV face above.
      </div>
    </div>
  );
}

function RemediationBody({ content }: { content: RemediationContent }) {
  const s = content.summary;
  const recent = content.activities.slice(0, 12);
  const period =
    content.period_from && content.period_to
      ? `${formatDate(content.period_from)} to ${formatDate(content.period_to)}`
      : 'n/a';
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <section>
        <SectionHead>Remediation requests</SectionHead>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
            gap: 12,
          }}
        >
          <Stat label="Period" value={period} />
          <Stat label="Total requests" value={`${s.total}`} />
          <Stat label="Executed" value={`${s.executed}`} tone="var(--ow-ok)" />
          <Stat label="Rolled back" value={`${s.rolled_back}`} tone="var(--ow-warn)" />
          <Stat label="Failed" value={`${s.failed}`} tone="var(--ow-crit)" />
          <Stat label="Rejected" value={`${s.rejected}`} />
          <Stat label="In progress" value={`${s.pending}`} />
        </div>
      </section>

      <section>
        <SectionHead>Recent activity</SectionHead>
        {recent.length === 0 ? (
          <div style={{ fontSize: 13, color: 'var(--ow-fg-3)', padding: '8px 0' }}>
            No remediation requests in this period.
          </div>
        ) : (
          <Panel>
            <Row head cols="1fr 1fr 120px">
              <span>Host</span>
              <span>Rule</span>
              <span>Status</span>
            </Row>
            {recent.map((r, i) => (
              <Row
                key={`${r.host_name}:${r.rule_id}:${r.requested_at}`}
                cols="1fr 1fr 120px"
                first={i === 0}
              >
                <span
                  style={{
                    fontSize: 12,
                    color: 'var(--ow-fg-1)',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {r.host_name}
                </span>
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
                  {r.rule_id}
                </span>
                <span style={{ fontSize: 13, color: 'var(--ow-fg-1)' }}>{r.status}</span>
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
        Remediation requests filed in the period above. The full activity log (every request with
        its requester, approver, mechanism, and timestamps) is in the downloadable CSV face above.
      </div>
    </div>
  );
}

type ReportScheduleRow = components['schemas']['ReportSchedule'];

// SchedulesTab manages report delivery schedules: a list with enable/disable
// + delete, and a create form. Delivery is by email through an email
// notification channel; the channel picker lists the email channels.
function SchedulesTab({ canGenerate }: { canGenerate: boolean }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [kind, setKind] = useState<'executive' | 'attestation' | 'exception' | 'remediation'>(
    'attestation',
  );
  const [frequency, setFrequency] = useState<'daily' | 'weekly' | 'monthly'>('weekly');
  const [weekday, setWeekday] = useState(1);
  const [dayOfMonth, setDayOfMonth] = useState(1);
  const [channelId, setChannelId] = useState('');
  const [formError, setFormError] = useState<string | null>(null);

  const schedulesQ = useQuery({
    queryKey: ['report-schedules'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/reports/schedules', {});
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
  });

  // Email channels back the delivery picker (only email can carry a PDF).
  const channelsQ = useQuery({
    queryKey: ['notification-channels'],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/notifications/channels', {});
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
    enabled: canGenerate,
  });
  const emailChannels = (channelsQ.data?.channels ?? []).filter((c) => c.type === 'email');

  const createMutation = useMutation({
    mutationFn: async () => {
      const body: {
        name: string;
        kind: typeof kind;
        frequency: typeof frequency;
        channel_id: string;
        weekday?: number;
        day_of_month?: number;
      } = { name, kind, frequency, channel_id: channelId };
      if (frequency === 'weekly') body.weekday = weekday;
      if (frequency === 'monthly') body.day_of_month = dayOfMonth;
      const { data, error, response } = await api.POST('/api/v1/reports/schedules', { body });
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
      return data!;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['report-schedules'] });
      setName('');
      setFormError(null);
    },
    onError: (e) => setFormError(e instanceof Error ? e.message : 'Failed to create schedule'),
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      const { error, response } = await api.PATCH('/api/v1/reports/schedules/{id}', {
        params: { path: { id } },
        body: { enabled },
      });
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['report-schedules'] }),
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const { error, response } = await api.DELETE('/api/v1/reports/schedules/{id}', {
        params: { path: { id } },
      });
      if (error || !response.ok)
        throw new Error(apiErrorMessage(error, `Failed (${response.status})`));
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['report-schedules'] }),
  });

  const schedules = schedulesQ.data?.schedules ?? [];
  const canSubmit = canGenerate && name.trim() !== '' && channelId !== '';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {canGenerate && (
        <Panel>
          <div style={{ padding: '16px 18px', display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--ow-fg-1)' }}>
              New schedule
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center' }}>
              <input
                aria-label="Schedule name"
                placeholder="Schedule name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                style={scheduleInputStyle}
              />
              <select
                aria-label="Schedule kind"
                value={kind}
                onChange={(e) => setKind(e.target.value as typeof kind)}
                style={scheduleInputStyle}
              >
                <option value="executive">Executive</option>
                <option value="attestation">Attestation</option>
                <option value="exception">Exception Register</option>
                <option value="remediation">Remediation Activity</option>
              </select>
              <select
                aria-label="Schedule frequency"
                value={frequency}
                onChange={(e) => setFrequency(e.target.value as typeof frequency)}
                style={scheduleInputStyle}
              >
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select>
              {frequency === 'weekly' && (
                <select
                  aria-label="Weekday"
                  value={weekday}
                  onChange={(e) => setWeekday(Number(e.target.value))}
                  style={scheduleInputStyle}
                >
                  {[
                    'Sunday',
                    'Monday',
                    'Tuesday',
                    'Wednesday',
                    'Thursday',
                    'Friday',
                    'Saturday',
                  ].map((d, i) => (
                    <option key={d} value={i}>
                      {d}
                    </option>
                  ))}
                </select>
              )}
              {frequency === 'monthly' && (
                <select
                  aria-label="Day of month"
                  value={dayOfMonth}
                  onChange={(e) => setDayOfMonth(Number(e.target.value))}
                  style={scheduleInputStyle}
                >
                  {Array.from({ length: 28 }, (_, i) => i + 1).map((d) => (
                    <option key={d} value={d}>
                      Day {d}
                    </option>
                  ))}
                </select>
              )}
              <select
                aria-label="Delivery channel"
                value={channelId}
                onChange={(e) => setChannelId(e.target.value)}
                style={scheduleInputStyle}
              >
                <option value="">Select email channel</option>
                {emailChannels.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </select>
              <button
                type="button"
                disabled={!canSubmit || createMutation.isPending}
                onClick={() => createMutation.mutate()}
                style={{
                  height: 34,
                  padding: '0 16px',
                  borderRadius: 6,
                  border: '1px solid var(--ow-info)',
                  background: canSubmit ? 'var(--ow-info)' : 'var(--ow-bg-2)',
                  color: canSubmit ? '#0a1424' : 'var(--ow-fg-3)',
                  fontFamily: 'inherit',
                  fontSize: 13,
                  fontWeight: 600,
                  cursor: canSubmit ? 'pointer' : 'default',
                }}
              >
                {createMutation.isPending ? 'Saving…' : 'Create schedule'}
              </button>
            </div>
            {emailChannels.length === 0 && (
              <div style={{ fontSize: 12, color: 'var(--ow-fg-3)' }}>
                No email notification channels yet. Add one in Settings to deliver scheduled
                reports.
              </div>
            )}
            {formError && (
              <div style={{ fontSize: 12.5, color: 'var(--ow-crit)' }}>{formError}</div>
            )}
          </div>
        </Panel>
      )}

      {schedulesQ.isPending ? (
        <State kind="loading" text="Loading schedules" />
      ) : schedulesQ.isError ? (
        <State kind="error" text={apiErrorMessage(schedulesQ.error, 'Failed to load schedules')} />
      ) : schedules.length === 0 ? (
        <State kind="empty" text="No schedules yet." />
      ) : (
        <Panel>
          <Row head cols="1.4fr 1fr 1fr 100px 90px">
            <span>Schedule</span>
            <span>Cadence</span>
            <span>Next run</span>
            <span>Status</span>
            <span />
          </Row>
          {schedules.map((s, i) => (
            <ScheduleRow
              key={s.id}
              schedule={s}
              first={i === 0}
              canGenerate={canGenerate}
              onToggle={(enabled) => toggleMutation.mutate({ id: s.id, enabled })}
              onDelete={() => deleteMutation.mutate(s.id)}
            />
          ))}
        </Panel>
      )}
    </div>
  );
}

function ScheduleRow({
  schedule,
  first,
  canGenerate,
  onToggle,
  onDelete,
}: {
  schedule: ReportScheduleRow;
  first: boolean;
  canGenerate: boolean;
  onToggle: (enabled: boolean) => void;
  onDelete: () => void;
}) {
  const cadence =
    schedule.frequency === 'weekly'
      ? `Weekly (day ${schedule.weekday ?? 0})`
      : schedule.frequency === 'monthly'
        ? `Monthly (day ${schedule.day_of_month ?? 1})`
        : 'Daily';
  return (
    <Row cols="1.4fr 1fr 1fr 100px 90px" first={first}>
      <span style={{ display: 'flex', flexDirection: 'column' }}>
        <span style={{ fontSize: 13, color: 'var(--ow-fg-1)' }}>{schedule.name}</span>
        <span style={{ fontSize: 11, color: 'var(--ow-fg-3)' }}>{kindLabel(schedule.kind)}</span>
      </span>
      <span style={{ fontSize: 12.5, color: 'var(--ow-fg-2)' }}>{cadence}</span>
      <span style={{ fontSize: 12.5, color: 'var(--ow-fg-2)' }}>
        {formatDate(schedule.next_run_at)}
      </span>
      <span style={{ fontSize: 12, color: schedule.enabled ? 'var(--ow-ok)' : 'var(--ow-fg-3)' }}>
        {schedule.enabled ? 'Active' : 'Paused'}
      </span>
      <span style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
        {canGenerate && (
          <>
            <button
              type="button"
              onClick={() => onToggle(!schedule.enabled)}
              title={schedule.enabled ? 'Pause' : 'Resume'}
              style={scheduleActionStyle}
            >
              {schedule.enabled ? 'Pause' : 'Resume'}
            </button>
            <button
              type="button"
              onClick={onDelete}
              title="Delete schedule"
              style={{ ...scheduleActionStyle, color: 'var(--ow-crit)' }}
            >
              Delete
            </button>
          </>
        )}
      </span>
    </Row>
  );
}

const scheduleInputStyle: CSSProperties = {
  height: 34,
  padding: '0 10px',
  borderRadius: 'var(--ow-radius-sm, 6px)',
  border: '1px solid var(--ow-line)',
  background: 'var(--ow-bg-2)',
  color: 'var(--ow-fg-0)',
  fontFamily: 'inherit',
  fontSize: 13,
};

const scheduleActionStyle: CSSProperties = {
  height: 26,
  padding: '0 8px',
  borderRadius: 5,
  border: '1px solid var(--ow-line)',
  background: 'var(--ow-bg-1)',
  color: 'var(--ow-fg-2)',
  fontFamily: 'inherit',
  fontSize: 11,
  cursor: 'pointer',
};

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
          The report kinds (executive, attestation, exception, remediation) are live in the Library
          tab, each with signed PDF, CSV, OSCAL, and JSON faces, and reports can be delivered on a
          schedule from the Scheduled tab. A gallery for building and saving custom report templates
          is not built yet.
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
