// ComplianceTab — Host Detail Compliance tab (lens model: one scan,
// viewed through any framework).
//
// Layout mirrors the prototype's compliance panel
// (docs/engineering/prototypes/openwatch-v1/Host Detail.html):
//
//   1. scan-context strip: headline + last-scan sub-line + the lens
//      explainer, plus a live Re-scan button (same enqueue endpoint as
//      the page-head Run scan). No Export button: that surface has no
//      backend yet and dead controls are banned.
//   2. lens bar: "View as" + an All rules chip plus one chip per
//      framework option, each carrying the per-lens score from the
//      frameworks endpoint (prototype: "CIS ... 36%"). Selection is
//      owned by the PARENT page (?framework= search param); this tab
//      only calls onFrameworkChange and re-renders when the prop
//      changes.
//   3. score + result-mix + scan panels (three columns): donut score
//      with the status legend (Executed = pass + fail; Error only when
//      present); Compliant / Non-compliant bars with an N/A note; scan
//      metadata (framework, ran at, duration, coverage).
//   4. numbered category rows: passing / failing over EXECUTED rules
//      with a banded pass percentage.
//   5. rules table: search box, client-side status filter chips with
//      counts, an "N of M rules" readout, and rows carrying title,
//      catalog description, control-id chips, category, status and
//      last-checked. The lens response is one bounded payload (~539
//      rules max), so search and filtering never refetch.
//
// Status wording follows the prototype: Compliant / Non-compliant /
// N/A (skipped) / Error.
//
// Data flow: ONE GET /hosts/{id}/compliance response renders sections
// 1 and 3-5; GET /hosts/{id}/compliance/frameworks feeds the lens bar
// (per-framework and overall scores). Both query keys carry the
// ['host', hostId] prefix so the scan.completed SSE invalidation
// refreshes the tab with no extra wiring. The stored per-rule check
// output never reaches this surface: the API omits it by contract
// (api-host-compliance C-02) and this file renders only catalog
// metadata + statuses.
//
// Spec: frontend-host-compliance-tab v1.1.0.

import { Fragment, useMemo, useState } from 'react';
import type { CSSProperties, ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { components } from '@/api/schema';
import { useAuthStore } from '@/store/useAuthStore';
import { RuleDetailPanel } from '@/pages/scans/RuleDetailPanel';
import { useHostExceptions } from '@/hooks/useHostExceptions';
import { useHostRemediations } from '@/hooks/useHostRemediations';
import { RequestRemediationModal } from '@/components/hosts/RequestRemediationModal';
import { SeverityPill } from '@/pages/host-detail/SeverityPill';

type LensResponse = components['schemas']['HostComplianceLensResponse'];
type LensRule = components['schemas']['HostComplianceRule'];
type LensCategory = components['schemas']['HostComplianceCategory'];
type FrameworksResponse = components['schemas']['HostComplianceFrameworksResponse'];

type StatusFilter = 'all' | 'fail' | 'pass' | 'skipped' | 'error';

// Prototype status wording. skipped renders as N/A ("not applicable").
const FILTER_ORDER: { id: StatusFilter; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'fail', label: 'Non-compliant' },
  { id: 'pass', label: 'Compliant' },
  { id: 'skipped', label: 'N/A' },
  { id: 'error', label: 'Error' },
];

export function ComplianceTab({
  hostId,
  framework,
  onFrameworkChange,
}: {
  hostId: string;
  framework?: string;
  onFrameworkChange: (next: string | undefined) => void;
}) {
  // Lens response — keyed under the ['host', hostId] prefix (free
  // scan.completed refresh) and embedding the framework so the cache
  // key changes with the lens. Spec C-02 / AC-05.
  const lensQuery = useQuery({
    queryKey: ['host', hostId, 'compliance', framework ?? null],
    queryFn: async (): Promise<LensResponse> => {
      const { data, error, response } = await api.GET('/api/v1/hosts/{id}/compliance', {
        params: {
          path: { id: hostId },
          query: framework ? { framework } : {},
        },
      });
      if (error || !response.ok) {
        throw new Error(apiErrorMessage(error, `Failed to load (${response.status})`));
      }
      return data as LensResponse;
    },
    enabled: !!hostId,
  });

  // Lens options — framework ids, mapped-rule counts and per-lens
  // scores for the picker, plus the all-rules aggregate.
  const frameworksQuery = useQuery({
    queryKey: ['host', hostId, 'compliance_frameworks'],
    queryFn: async (): Promise<FrameworksResponse> => {
      const { data, error, response } = await api.GET('/api/v1/hosts/{id}/compliance/frameworks', {
        params: { path: { id: hostId } },
      });
      if (error || !response.ok) {
        throw new Error(apiErrorMessage(error, `Failed to load (${response.status})`));
      }
      return data as FrameworksResponse;
    },
    enabled: !!hostId,
  });

  // CLIENT-SIDE status filter + search — clicking or typing never
  // refetches. Spec C-03 / AC-04.
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [search, setSearch] = useState('');

  // Exception overlay: which failing rules are waived (active) or have
  // a pending request. Never mutates the lens data (overlay model).
  const exc = useHostExceptions(hostId);
  const canRequest = useAuthStore((st) => st.hasPermission)('exception:request');
  // Remediation overlay: which failing rules already carry an in-flight
  // remediation request (open set), to suppress a duplicate per-rule
  // action. Parallel to the exception overlay; never mutates the lens.
  const rem = useHostRemediations(hostId);
  const canRequestRemediation = useAuthStore((st) => st.hasPermission)('remediation:request');
  // Evidence drill-down is gated scan:read (it reaches the scan:read-only
  // /scans evidence endpoints): the host lens itself stays evidence-free.
  const canViewEvidence = useAuthStore((st) => st.hasPermission)('scan:read');
  // The rule a Request-exception modal is open for (null = closed).
  const [requestRule, setRequestRule] = useState<LensRule | null>(null);
  // The rule a Request-remediation modal is open for (null = closed).
  const [remediateRule, setRemediateRule] = useState<LensRule | null>(null);

  let body: ReactNode;
  // isPending (not isLoading): isLoading goes false between retry
  // attempts, which would flash the never-scanned empty state with no
  // data. Spec C-04.
  if (lensQuery.isPending) {
    body = (
      <div role="status" style={{ color: 'var(--ow-fg-3)', fontSize: 12, padding: '20px 0' }}>
        Loading compliance data
      </div>
    );
  } else if (lensQuery.isError) {
    body = (
      <div
        role="alert"
        style={{
          color: 'var(--ow-crit)',
          fontSize: 12,
          padding: '16px 0',
          display: 'flex',
          gap: 10,
          alignItems: 'center',
        }}
      >
        <span>{apiErrorMessage(lensQuery.error, 'Failed to load compliance data')}</span>
        <button type="button" onClick={() => lensQuery.refetch()} style={retryBtn}>
          Retry
        </button>
      </div>
    );
  } else if (!lensQuery.data.scan_context.last_scan_at) {
    // Never scanned — honest empty state naming the page-head action.
    body = (
      <div role="status" style={{ padding: '28px 0', textAlign: 'center' }}>
        <div style={{ color: 'var(--ow-fg-1)', fontSize: 14, fontWeight: 600, marginBottom: 6 }}>
          No scan results yet
        </div>
        <div
          style={{
            color: 'var(--ow-fg-3)',
            fontSize: 12,
            maxWidth: 440,
            margin: '0 auto',
            lineHeight: 1.5,
          }}
        >
          Use the Run scan button in the page header to queue the first compliance scan. Results
          appear here when the scan completes.
        </div>
      </div>
    );
  } else {
    const lens = lensQuery.data;
    body = (
      <>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'minmax(240px, 17fr) minmax(0, 38fr) minmax(0, 39fr)',
            gap: 16,
            alignItems: 'stretch',
          }}
        >
          <ScorePanel summary={lens.summary} />
          <ResultMixPanel summary={lens.summary} framework={framework} />
          <ScanPanel
            scanContext={lens.scan_context}
            framework={framework}
            lensTotal={lens.summary.total}
          />
        </div>
        <CategoryRows categories={lens.categories} />
        <RulesTable
          rules={lens.rules}
          filter={statusFilter}
          onFilterChange={setStatusFilter}
          search={search}
          onSearchChange={setSearch}
          frameworkActive={!!framework}
          activeRuleIds={exc.activeRuleIds}
          pendingRuleIds={exc.pendingRuleIds}
          canRequest={canRequest}
          onRequest={setRequestRule}
          remediationOpenRuleIds={rem.openRuleIds}
          canRequestRemediation={canRequestRemediation}
          onRequestRemediation={setRemediateRule}
          scanId={lens.scan_context.scan_id ?? null}
          canViewEvidence={canViewEvidence}
        />
      </>
    );
  }

  return (
    <section
      role="tabpanel"
      aria-label="Compliance"
      style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 16 }}
    >
      <ScanContextStrip
        hostId={hostId}
        isPending={lensQuery.isPending}
        lastScanAt={lensQuery.data?.scan_context.last_scan_at ?? null}
        policyVersion={lensQuery.data?.scan_context.policy_version ?? ''}
        scanState={lensQuery.data?.scan_context.scan_state ?? null}
      />
      <LensBar
        framework={framework}
        options={frameworksQuery.data}
        onFrameworkChange={onFrameworkChange}
      />
      {body}
      {requestRule && (
        <RequestExceptionModal
          hostId={hostId}
          rule={requestRule}
          onClose={() => setRequestRule(null)}
          onSuccess={() => {
            setRequestRule(null);
            exc.refetch();
          }}
        />
      )}
      {remediateRule && (
        <RequestRemediationModal
          hostId={hostId}
          ruleId={remediateRule.rule_id}
          ruleTitle={remediateRule.title}
          onClose={() => setRemediateRule(null)}
          onSuccess={() => {
            setRemediateRule(null);
            rem.refetch();
          }}
        />
      )}
    </section>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// 1. Scan-context strip — headline, explainer, live Re-scan.
// ─────────────────────────────────────────────────────────────────────────

function ScanContextStrip({
  hostId,
  isPending,
  lastScanAt,
  policyVersion,
  scanState,
}: {
  hostId: string;
  isPending: boolean;
  lastScanAt: string | null;
  policyVersion: string;
  scanState: 'queued' | 'running' | null;
}) {
  let sub: ReactNode;
  if (isPending) {
    sub = 'Loading scan context';
  } else if (lastScanAt) {
    sub = (
      <>
        Last scan{' '}
        <span style={{ fontFamily: 'var(--ow-font-mono)', color: 'var(--ow-fg-1)' }}>
          {new Date(lastScanAt).toLocaleString()}
        </span>
        {policyVersion ? (
          <>
            {' · Policy '}
            <span style={{ fontFamily: 'var(--ow-font-mono)', color: 'var(--ow-fg-1)' }}>
              {policyVersion}
            </span>
          </>
        ) : null}
        {' · the scores below are views of the same per-rule results, regrouped by each'}
        {" rule's framework refs."}
      </>
    );
  } else {
    sub = 'No scan yet';
  }
  return (
    <div
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: '14px 18px',
        display: 'flex',
        alignItems: 'center',
        gap: 14,
      }}
    >
      <div style={{ minWidth: 0, flex: 1 }}>
        <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--ow-fg-0)' }}>
          One scan, viewed through any framework
        </div>
        <div style={{ color: 'var(--ow-fg-2)', fontSize: 12, marginTop: 2, lineHeight: 1.5 }}>
          {sub}
        </div>
      </div>
      <RescanButton hostId={hostId} scanState={scanState} />
    </div>
  );
}

// RescanButton — same enqueue endpoint and semantics as the page-head
// Run scan button (POST /hosts/{id}/scans, idempotency-keyed, 409 as a
// transient note). The result refresh arrives via scan.completed SSE.
function RescanButton({
  hostId,
  scanState,
}: {
  hostId: string;
  scanState: 'queued' | 'running' | null;
}) {
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  // While a scan is in flight (scan_context.scan_state, kept live by the
  // scan.started/scan.completed SSE topics) the button stays disabled
  // showing the live state. Spec frontend-host-compliance-tab AC-10.
  const active = scanState === 'running' || scanState === 'queued';

  const rescan = async () => {
    if (busy || active) return;
    setBusy(true);
    setNote(null);
    try {
      const { response } = await api.POST('/api/v1/hosts/{id}/scans', {
        params: {
          path: { id: hostId },
          header: { 'Idempotency-Key': crypto.randomUUID() },
        },
      });
      if (response.status === 409) {
        setNote('Scan already running');
      } else if (!response.ok) {
        setNote(`Scan failed (${response.status})`);
      } else {
        setNote('Scan queued');
      }
    } catch {
      setNote('Scan failed');
    } finally {
      setBusy(false);
      window.setTimeout(() => setNote(null), 4000);
    }
  };

  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
      {note && (
        <span role="status" style={{ fontSize: 11, color: 'var(--ow-fg-2)' }}>
          {note}
        </span>
      )}
      <button
        type="button"
        onClick={rescan}
        disabled={busy || active}
        aria-label="Re-scan this host"
        style={{
          height: 30,
          padding: '0 14px',
          background: 'var(--ow-info)',
          color: 'var(--ow-info-on)',
          border: 0,
          borderRadius: 7,
          fontSize: 12,
          fontWeight: 600,
          cursor: busy || active ? 'default' : 'pointer',
          opacity: busy || active ? 0.6 : 1,
        }}
      >
        {scanState === 'running'
          ? 'Running…'
          : scanState === 'queued'
            ? 'Queued…'
            : busy
              ? 'Queueing'
              : 'Re-scan'}
      </button>
    </span>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// 2. Lens bar — "View as" chips with per-lens scores. Selection routes
//    through the parent's onFrameworkChange so the URL (?framework=)
//    stays the single source of truth (api-hosts AC-08).
// ─────────────────────────────────────────────────────────────────────────

// frameworkLabel renders a friendly chip label from a framework id:
// cis_rhel8 -> "CIS RHEL 8", nist_800_53 -> "NIST 800-53",
// stig_rhel9 -> "STIG RHEL 9", pci_dss_4 -> "PCI DSS 4".
export function frameworkLabel(id: string): string {
  return id
    .split('_')
    .map((part) => {
      const m = /^([a-z]+)(\d+)$/.exec(part);
      if (m) return `${m[1]!.toUpperCase()} ${m[2]!}`;
      if (/^\d+$/.test(part)) return part;
      return part.toUpperCase();
    })
    .join(' ')
    .replace(/^NIST 800 53$/, 'NIST 800-53');
}

function LensBar({
  framework,
  options,
  onFrameworkChange,
}: {
  framework?: string;
  options?: FrameworksResponse;
  onFrameworkChange: (next: string | undefined) => void;
}) {
  return (
    <div
      role="group"
      aria-label="View as framework"
      style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}
    >
      <span
        style={{
          fontSize: 11,
          fontWeight: 600,
          color: 'var(--ow-fg-3)',
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          marginRight: 4,
        }}
      >
        View as
      </span>
      <LensChip active={!framework} onClick={() => onFrameworkChange(undefined)}>
        <span>All rules</span>
        <span style={lensChipMeta}>every mapped control</span>
        {options ? <span style={lensChipScore}>{options.overall.score_pct}%</span> : null}
      </LensChip>
      {(options?.frameworks ?? []).map((opt) => (
        <LensChip
          key={opt.framework_id}
          active={framework === opt.framework_id}
          onClick={() => onFrameworkChange(opt.framework_id)}
        >
          <span>{frameworkLabel(opt.framework_id)}</span>
          <span style={lensChipMeta}>{opt.rule_count} rules</span>
          <span style={lensChipScore}>{opt.score_pct}%</span>
        </LensChip>
      ))}
    </div>
  );
}

const lensChipMeta: CSSProperties = {
  color: 'var(--ow-fg-3)',
  fontSize: 11,
};

const lensChipScore: CSSProperties = {
  fontVariantNumeric: 'tabular-nums',
  fontWeight: 700,
  padding: '1px 7px',
  borderRadius: 999,
  fontSize: 11,
  background: 'var(--ow-bg-3)',
  color: 'var(--ow-fg-1)',
};

function LensChip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 8,
        height: 34,
        padding: '0 14px',
        borderRadius: 8,
        border: `1px solid ${active ? 'var(--ow-line-2, var(--ow-line))' : 'var(--ow-line)'}`,
        background: active ? 'var(--ow-bg-2)' : 'var(--ow-bg-1)',
        color: active ? 'var(--ow-fg-0)' : 'var(--ow-fg-2)',
        fontSize: 13,
        fontWeight: 500,
        cursor: 'pointer',
        boxShadow: active ? 'inset 0 -2px 0 var(--ow-info)' : 'none',
      }}
    >
      {children}
    </button>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// 3. Score donut + Result mix + Scan panels (prototype three-column
//    block). The donut panel carries the status legend; the result-mix
//    panel renders just the Compliant / Non-compliant bars + N/A note.
// ─────────────────────────────────────────────────────────────────────────

function ScorePanel({ summary }: { summary: LensResponse['summary'] }) {
  const executed = summary.passing + summary.failing;
  const legend: { label: string; value: number; color: string }[] = [
    { label: 'Compliant', value: summary.passing, color: 'var(--ow-ok)' },
    { label: 'Non-compliant', value: summary.failing, color: 'var(--ow-crit)' },
    { label: 'Not applicable', value: summary.skipped, color: 'var(--ow-fg-1)' },
    // Error is the exception path — surfaced only when present, like
    // the prototype (its zero-error host shows no Error row).
    ...(summary.error > 0
      ? [{ label: 'Error', value: summary.error, color: 'var(--ow-warn)' }]
      : []),
    { label: 'Executed', value: executed, color: 'var(--ow-fg-0)' },
  ];
  // Donut: green arc = compliant share of the lens, red remainder.
  const r = 34;
  const c = 2 * Math.PI * r;
  const frac = Math.max(0, Math.min(100, summary.score_pct)) / 100;
  return (
    <section
      aria-label="Compliance score"
      style={{ ...panel, display: 'flex', alignItems: 'center', gap: 18 }}
    >
      <div style={{ position: 'relative', width: 92, height: 92, flexShrink: 0 }}>
        <svg width={92} height={92} viewBox="0 0 92 92" aria-hidden>
          <circle
            cx={46}
            cy={46}
            r={r}
            fill="none"
            stroke={executed > 0 ? 'var(--ow-crit)' : 'var(--ow-bg-3)'}
            strokeWidth={7}
          />
          <circle
            cx={46}
            cy={46}
            r={r}
            fill="none"
            stroke="var(--ow-ok)"
            strokeWidth={7}
            strokeDasharray={`${frac * c} ${c}`}
            transform="rotate(-90 46 46)"
          />
        </svg>
        <div
          style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <span
            style={{
              fontSize: 19,
              fontWeight: 700,
              lineHeight: 1,
              color: 'var(--ow-fg-0)',
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            {summary.score_pct}%
          </span>
          <span
            style={{
              color: 'var(--ow-fg-3)',
              fontSize: 8,
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              marginTop: 3,
            }}
          >
            Compliant
          </span>
        </div>
      </div>
      <div style={{ flex: 1, minWidth: 0 }} role="list" aria-label="Status totals">
        {legend.map((l) => (
          <div
            key={l.label}
            role="listitem"
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 10,
              padding: '4px 0',
            }}
          >
            <span style={{ color: 'var(--ow-fg-2)', fontSize: 12 }}>{l.label}</span>
            <span
              style={{
                color: l.color,
                fontSize: 12,
                fontWeight: 600,
                fontVariantNumeric: 'tabular-nums',
              }}
            >
              {l.value}
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}

function ResultMixPanel({
  summary,
  framework,
}: {
  summary: LensResponse['summary'];
  framework?: string;
}) {
  const max = Math.max(1, summary.passing, summary.failing);
  const rows: { label: string; value: number; color: string }[] = [
    { label: 'Compliant', value: summary.passing, color: 'var(--ow-ok)' },
    { label: 'Non-compliant', value: summary.failing, color: 'var(--ow-crit)' },
  ];
  return (
    <section aria-label="Result mix" style={panel}>
      <h3 style={panelHead}>Result mix{framework ? ` · ${frameworkLabel(framework)}` : ''}</h3>
      {rows.map((row) => (
        <div
          key={row.label}
          style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '6px 0' }}
        >
          <span
            style={{
              width: 104,
              flexShrink: 0,
              color: row.color,
              fontSize: 10,
              fontWeight: 700,
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
            }}
          >
            {row.label}
          </span>
          <span
            aria-hidden
            style={{
              flex: 1,
              height: 6,
              borderRadius: 999,
              background: 'var(--ow-bg-3)',
              overflow: 'hidden',
            }}
          >
            <span
              style={{
                display: 'block',
                width: `${(row.value / max) * 100}%`,
                height: '100%',
                background: row.color,
                borderRadius: 999,
              }}
            />
          </span>
          <span
            style={{
              width: 44,
              textAlign: 'right',
              color: row.color,
              fontSize: 13,
              fontWeight: 700,
              fontVariantNumeric: 'tabular-nums',
              flexShrink: 0,
            }}
          >
            {row.value}
          </span>
        </div>
      ))}
      {summary.skipped > 0 ? (
        <div
          style={{
            marginTop: 12,
            padding: '9px 11px',
            borderRadius: 7,
            border: '1px dashed var(--ow-line)',
            background: 'var(--ow-bg-2)',
            color: 'var(--ow-fg-2)',
            fontSize: 11,
            lineHeight: 1.5,
          }}
        >
          <strong style={{ color: 'var(--ow-fg-1)' }}>
            {summary.skipped} rules not applicable
          </strong>
          : dropped by capability gates or missing a matching implementation on this host.
        </div>
      ) : null}
    </section>
  );
}

function ScanPanel({
  scanContext,
  framework,
  lensTotal,
}: {
  scanContext: LensResponse['scan_context'];
  framework?: string;
  lensTotal: number;
}) {
  const ran = scanContext.last_scan_at ? new Date(scanContext.last_scan_at).toLocaleString() : '';
  const coverage = framework
    ? `${lensTotal} of this host's rules carry a ${frameworkLabel(framework)} ref`
    : `${lensTotal} rules evaluated on this host`;
  return (
    <section aria-label="Scan details" style={panel}>
      <h3 style={panelHead}>Scan</h3>
      <dl style={{ margin: 0 }}>
        <ScanRow label="Framework">
          {framework ? frameworkLabel(framework) : 'All rules (no lens)'}
        </ScanRow>
        <ScanRow label="Ran">
          <span style={{ fontFamily: 'var(--ow-font-mono)' }}>{ran}</span>
          {scanContext.duration_seconds != null ? (
            <div style={{ color: 'var(--ow-fg-3)', marginTop: 2 }}>
              Duration {scanContext.duration_seconds}s
            </div>
          ) : null}
        </ScanRow>
        {scanContext.policy_version ? (
          <ScanRow label="Policy">
            <span style={{ fontFamily: 'var(--ow-font-mono)' }}>{scanContext.policy_version}</span>
          </ScanRow>
        ) : null}
        <ScanRow label="Coverage">{coverage}</ScanRow>
      </dl>
    </section>
  );
}

function ScanRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div
      style={{
        display: 'flex',
        gap: 12,
        padding: '6px 0',
        borderTop: '1px solid var(--ow-line)',
        fontSize: 12,
      }}
    >
      <dt
        style={{
          width: 90,
          flexShrink: 0,
          color: 'var(--ow-fg-3)',
          textTransform: 'uppercase',
          fontSize: 10,
          letterSpacing: '0.06em',
          paddingTop: 2,
        }}
      >
        {label}
      </dt>
      <dd style={{ margin: 0, color: 'var(--ow-fg-1)', minWidth: 0 }}>{children}</dd>
    </div>
  );
}

function scoreColor(pct: number): string {
  if (pct >= 80) return 'var(--ow-ok)';
  if (pct >= 50) return 'var(--ow-warn)';
  return 'var(--ow-crit)';
}

const panel: CSSProperties = {
  background: 'var(--ow-bg-1)',
  border: '1px solid var(--ow-line)',
  borderRadius: 'var(--ow-radius)',
  padding: 18,
};

const panelHead: CSSProperties = {
  margin: '0 0 12px',
  fontSize: 11,
  fontWeight: 600,
  color: 'var(--ow-fg-3)',
  textTransform: 'uppercase',
  letterSpacing: '0.06em',
};

// ─────────────────────────────────────────────────────────────────────────
// 4. Category rows — numbered, pass counts + percentage (prototype
//    "By section" block). Grouping is the Kensa catalog category;
//    grouping by framework section needs section names the corpus
//    does not carry yet (follow-up noted in the spec).
// ─────────────────────────────────────────────────────────────────────────

function CategoryRows({ categories }: { categories: LensCategory[] }) {
  if (categories.length === 0) return null;
  return (
    <section aria-label="Compliance categories" style={panel}>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'baseline',
          marginBottom: 12,
        }}
      >
        <h3 style={{ margin: 0, fontSize: 14, fontWeight: 600 }}>By category</h3>
        <span style={{ color: 'var(--ow-fg-3)', fontSize: 11 }}>
          Grouping follows the Kensa rule category
        </span>
      </div>
      <div role="list" aria-label="Category breakdown">
        {categories.map((c, i) => {
          // Prototype semantics: counts and percentage cover EXECUTED
          // rules only (pass + fail); not-applicable rows neither help
          // nor hurt a category's score.
          const executed = c.passing + c.failing;
          const passPct = executed > 0 ? Math.round((c.passing / executed) * 100) : 0;
          return (
            <div
              key={c.category}
              role="listitem"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 14,
                padding: '10px 0',
                borderTop: '1px solid var(--ow-line)',
              }}
            >
              <span
                style={{
                  width: 18,
                  flexShrink: 0,
                  color: 'var(--ow-fg-3)',
                  fontSize: 11,
                  fontVariantNumeric: 'tabular-nums',
                }}
              >
                {i + 1}
              </span>
              <span
                style={{
                  flex: 1,
                  minWidth: 0,
                  color: 'var(--ow-fg-0)',
                  fontWeight: 500,
                  fontSize: 13,
                }}
              >
                {c.category}
              </span>
              <span
                aria-hidden
                style={{
                  flex: '0 0 290px',
                  height: 6,
                  borderRadius: 999,
                  background: 'var(--ow-bg-3)',
                  overflow: 'hidden',
                  display: 'flex',
                }}
              >
                {executed > 0 ? (
                  <>
                    <span style={{ width: `${passPct}%`, background: 'var(--ow-ok)' }} />
                    <span style={{ width: `${100 - passPct}%`, background: 'var(--ow-crit)' }} />
                  </>
                ) : null}
              </span>
              <span
                style={{
                  width: 76,
                  textAlign: 'right',
                  fontSize: 12,
                  fontWeight: 600,
                  fontVariantNumeric: 'tabular-nums',
                  flexShrink: 0,
                }}
              >
                <span style={{ color: 'var(--ow-ok)' }}>{c.passing}</span>
                <span style={{ color: 'var(--ow-fg-3)' }}> / </span>
                <span style={{ color: 'var(--ow-crit)' }}>{c.failing}</span>
              </span>
              <span
                style={{
                  width: 44,
                  textAlign: 'right',
                  color: scoreColor(passPct),
                  fontWeight: 700,
                  fontSize: 12,
                  fontVariantNumeric: 'tabular-nums',
                  flexShrink: 0,
                }}
              >
                {passPct}%
              </span>
            </div>
          );
        })}
      </div>
    </section>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// 5. Rules table — search + counted status chips + "N of M" readout
// ─────────────────────────────────────────────────────────────────────────

function RulesTable({
  rules,
  filter,
  onFilterChange,
  search,
  onSearchChange,
  frameworkActive,
  activeRuleIds,
  pendingRuleIds,
  canRequest,
  onRequest,
  remediationOpenRuleIds,
  canRequestRemediation,
  onRequestRemediation,
  scanId,
  canViewEvidence,
}: {
  rules: LensRule[];
  filter: StatusFilter;
  onFilterChange: (next: StatusFilter) => void;
  search: string;
  onSearchChange: (next: string) => void;
  frameworkActive: boolean;
  activeRuleIds: Set<string>;
  pendingRuleIds: Set<string>;
  canRequest: boolean;
  onRequest: (rule: LensRule) => void;
  remediationOpenRuleIds: Set<string>;
  canRequestRemediation: boolean;
  onRequestRemediation: (rule: LensRule) => void;
  // scanId is the host's latest completed scan (scan_context.scan_id); the
  // per-rule evidence drill-down reaches /scans/{scanId}/rules/{ruleId}.
  // null when never scanned. canViewEvidence gates it on scan:read.
  scanId: string | null;
  canViewEvidence: boolean;
}) {
  // The rule whose evidence/OSCAL drill-down is expanded (one at a time).
  const [expanded, setExpanded] = useState<string | null>(null);
  const canDrill = canViewEvidence && !!scanId;
  const counts = useMemo(() => {
    const c: Record<StatusFilter, number> = {
      all: rules.length,
      pass: 0,
      fail: 0,
      skipped: 0,
      error: 0,
    };
    for (const r of rules) {
      if (
        r.status === 'pass' ||
        r.status === 'fail' ||
        r.status === 'skipped' ||
        r.status === 'error'
      ) {
        c[r.status] += 1;
      }
    }
    return c;
  }, [rules]);

  const visible = useMemo(() => {
    let out = filter === 'all' ? rules : rules.filter((r) => r.status === filter);
    const q = search.trim().toLowerCase();
    if (q) {
      out = out.filter(
        (r) =>
          r.title.toLowerCase().includes(q) ||
          r.rule_id.toLowerCase().includes(q) ||
          r.control_ids.some((cid) => cid.toLowerCase().includes(q)),
      );
    }
    return out;
  }, [rules, filter, search]);

  return (
    <section aria-label="Compliance rules" style={panel}>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          flexWrap: 'wrap',
          marginBottom: 12,
        }}
      >
        <input
          type="search"
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Search rules or framework IDs"
          aria-label="Search rules or framework IDs"
          style={{
            flex: '1 1 240px',
            maxWidth: 340,
            height: 32,
            padding: '0 12px',
            borderRadius: 7,
            border: '1px solid var(--ow-line)',
            background: 'var(--ow-bg-0)',
            color: 'var(--ow-fg-0)',
            fontSize: 12,
          }}
        />
        <div role="group" aria-label="Filter rules by status" style={{ display: 'flex', gap: 6 }}>
          {FILTER_ORDER.map((f) => (
            <button
              key={f.id}
              type="button"
              aria-pressed={filter === f.id}
              onClick={() => onFilterChange(f.id)}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                padding: '4px 10px',
                borderRadius: 999,
                border: '1px solid var(--ow-line)',
                background: filter === f.id ? 'var(--ow-bg-3)' : 'var(--ow-bg-2)',
                color: filter === f.id ? 'var(--ow-fg-0)' : 'var(--ow-fg-2)',
                fontSize: 12,
                cursor: 'pointer',
              }}
            >
              {f.id !== 'all' ? (
                <span
                  aria-hidden
                  style={{
                    width: 6,
                    height: 6,
                    borderRadius: '50%',
                    background: STATUS_STYLE[f.id]?.fg ?? 'var(--ow-fg-3)',
                  }}
                />
              ) : null}
              {f.label}
              <span style={{ fontVariantNumeric: 'tabular-nums', color: 'var(--ow-fg-3)' }}>
                {counts[f.id]}
              </span>
            </button>
          ))}
        </div>
        <span style={{ marginLeft: 'auto', color: 'var(--ow-fg-3)', fontSize: 11 }}>
          {visible.length} of {rules.length} {frameworkActive ? 'lens' : ''} rules
        </span>
      </div>

      {visible.length === 0 ? (
        <div role="status" style={{ color: 'var(--ow-fg-3)', fontSize: 12, padding: '12px 0' }}>
          No rules match the current filter.
        </div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr>
              <Th width={110}>Status</Th>
              <Th width={70}>Severity</Th>
              <Th>Rule and framework refs</Th>
              <Th width={160}>Category</Th>
              <Th width={110}>Last checked</Th>
              <Th width={150}>Exception</Th>
              <Th width={160}>Remediation</Th>
            </tr>
          </thead>
          <tbody>
            {visible.map((r) => {
              const open = expanded === r.rule_id;
              return (
                <Fragment key={r.rule_id}>
                  <tr style={{ borderTop: '1px solid var(--ow-line)' }}>
                    <td style={td}>
                      <StatusChip status={r.status} />
                    </td>
                    <td style={td}>
                      <SeverityPill severity={r.severity} />
                    </td>
                    <td style={td}>
                      {canDrill ? (
                        <button
                          type="button"
                          onClick={() => setExpanded(open ? null : r.rule_id)}
                          aria-expanded={open}
                          style={{
                            background: 'transparent',
                            border: 0,
                            padding: 0,
                            cursor: 'pointer',
                            textAlign: 'left',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 6,
                            color: 'var(--ow-fg-0)',
                            fontWeight: 500,
                          }}
                        >
                          <span aria-hidden style={{ color: 'var(--ow-fg-3)', fontSize: 11 }}>
                            {open ? '▾' : '▸'}
                          </span>
                          {r.title}
                        </button>
                      ) : (
                        <div style={{ color: 'var(--ow-fg-0)', fontWeight: 500 }}>{r.title}</div>
                      )}
                      {r.description ? (
                        <div style={{ color: 'var(--ow-fg-3)', fontSize: 11, marginTop: 2 }}>
                          {r.description}
                        </div>
                      ) : null}
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 5 }}>
                        {(r.control_ids.length > 0 ? r.control_ids : [r.rule_id]).map((cid) => (
                          <span key={cid} style={refChip}>
                            {cid}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td style={{ ...td, color: 'var(--ow-fg-2)' }}>{r.category}</td>
                    <td
                      style={{ ...td, color: 'var(--ow-fg-3)', whiteSpace: 'nowrap', fontSize: 12 }}
                    >
                      {relativeTime(r.last_checked_at)}
                    </td>
                    <td style={td}>
                      <ExceptionCell
                        rule={r}
                        waived={activeRuleIds.has(r.rule_id)}
                        pending={pendingRuleIds.has(r.rule_id)}
                        canRequest={canRequest}
                        onRequest={onRequest}
                      />
                    </td>
                    <td style={td}>
                      <RemediationCell
                        rule={r}
                        requested={remediationOpenRuleIds.has(r.rule_id)}
                        canRequest={canRequestRemediation}
                        onRequest={onRequestRemediation}
                      />
                    </td>
                  </tr>
                  {canDrill && open && scanId ? (
                    <tr>
                      <td colSpan={7} style={{ padding: '0 10px 12px 24px' }}>
                        <RuleDetailPanel scanId={scanId} ruleId={r.rule_id} hasEvidence />
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}

const refChip: CSSProperties = {
  fontFamily: 'var(--ow-font-mono)',
  fontSize: 10,
  padding: '1px 6px',
  borderRadius: 5,
  border: '1px solid var(--ow-line)',
  background: 'var(--ow-bg-2)',
  color: 'var(--ow-fg-2)',
};

function Th({ children, width }: { children: ReactNode; width?: number }) {
  return (
    <th
      style={{
        width,
        textAlign: 'left',
        padding: '6px 10px 8px 0',
        color: 'var(--ow-fg-3)',
        fontSize: 11,
        fontWeight: 600,
        textTransform: 'uppercase',
        letterSpacing: '0.04em',
      }}
    >
      {children}
    </th>
  );
}

// StatusChip — prototype wording: Compliant (ok), Non-compliant
// (crit), N/A (muted), Error (warn).
const STATUS_STYLE: Record<string, { fg: string; bg: string; label: string }> = {
  pass: { fg: 'var(--ow-ok)', bg: 'var(--ow-ok-bg)', label: 'Compliant' },
  fail: { fg: 'var(--ow-crit)', bg: 'var(--ow-crit-bg)', label: 'Non-compliant' },
  skipped: { fg: 'var(--ow-fg-3)', bg: 'var(--ow-bg-2)', label: 'N/A' },
  error: { fg: 'var(--ow-warn)', bg: 'var(--ow-warn-bg)', label: 'Error' },
};

function StatusChip({ status }: { status: string }) {
  const s = STATUS_STYLE[status] ?? {
    fg: 'var(--ow-fg-2)',
    bg: 'var(--ow-bg-2)',
    label: status,
  };
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: '2px 8px',
        borderRadius: 999,
        background: s.bg,
        color: s.fg,
        fontSize: 11,
        fontWeight: 600,
        whiteSpace: 'nowrap',
      }}
    >
      <span aria-hidden style={{ width: 6, height: 6, borderRadius: '50%', background: s.fg }} />
      {s.label}
    </span>
  );
}

// ExceptionCell renders, for a rule's row, the exception governance
// state: a Waived pill (active approved exception), a Pending pill (a
// request awaiting review), or - for an unwaived FAILING rule and a
// caller with exception:request - a Request button. Non-failing rules
// with no exception render nothing. The overlay never changes the
// rule's status chip.
function ExceptionCell({
  rule,
  waived,
  pending,
  canRequest,
  onRequest,
}: {
  rule: LensRule;
  waived: boolean;
  pending: boolean;
  canRequest: boolean;
  onRequest: (rule: LensRule) => void;
}) {
  if (waived) {
    return (
      <span style={{ ...excPill, color: 'var(--ow-info)', background: 'var(--ow-bg-2)' }}>
        Waived
      </span>
    );
  }
  if (pending) {
    return (
      <span style={{ ...excPill, color: 'var(--ow-warn)', background: 'var(--ow-bg-2)' }}>
        Pending
      </span>
    );
  }
  if (rule.status === 'fail' && canRequest) {
    return (
      <button
        type="button"
        onClick={() => onRequest(rule)}
        style={{
          height: 26,
          padding: '0 10px',
          background: 'var(--ow-bg-2)',
          color: 'var(--ow-fg-1)',
          border: '1px solid var(--ow-line)',
          borderRadius: 7,
          fontSize: 11,
          fontWeight: 600,
          cursor: 'pointer',
        }}
      >
        Request exception
      </button>
    );
  }
  return <span style={{ color: 'var(--ow-fg-3)', fontSize: 11 }}>—</span>;
}

const excPill: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  padding: '2px 8px',
  borderRadius: 999,
  fontSize: 11,
  fontWeight: 600,
  whiteSpace: 'nowrap',
};

// RemediationCell renders, for a rule's row, the remediation governance
// state: a "Remediation requested" pill when an open request already
// exists, or - for an unwaived FAILING rule and a caller with
// remediation:request - a Request button that opens the confirm modal.
// Non-failing rules with no open request render nothing. This is the
// request/approval half of the workflow only; applying the fix on the
// host is the OpenWatch+ track surfaced on the Remediation tab.
function RemediationCell({
  rule,
  requested,
  canRequest,
  onRequest,
}: {
  rule: LensRule;
  requested: boolean;
  canRequest: boolean;
  onRequest: (rule: LensRule) => void;
}) {
  if (requested) {
    return (
      <span style={{ ...excPill, color: 'var(--ow-info)', background: 'var(--ow-bg-2)' }}>
        Remediation requested
      </span>
    );
  }
  if (rule.status === 'fail' && canRequest) {
    return (
      <button
        type="button"
        onClick={() => onRequest(rule)}
        style={{
          height: 26,
          padding: '0 10px',
          background: 'var(--ow-bg-2)',
          color: 'var(--ow-fg-1)',
          border: '1px solid var(--ow-line)',
          borderRadius: 7,
          fontSize: 11,
          fontWeight: 600,
          cursor: 'pointer',
        }}
      >
        Request remediation
      </button>
    );
  }
  return <span style={{ color: 'var(--ow-fg-3)', fontSize: 11 }}>—</span>;
}

// RequestExceptionModal collects the reason (required) and an optional
// expiry, then POSTs /hosts/{id}/exceptions. The host-detail
// exceptions query is refreshed by the parent on success. A 409 (an
// open exception already exists) surfaces inline. Spec
// api-compliance-exceptions.
function RequestExceptionModal({
  hostId,
  rule,
  onClose,
  onSuccess,
}: {
  hostId: string;
  rule: LensRule;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const queryClient = useQueryClient();
  const [reason, setReason] = useState('');
  const [expires, setExpires] = useState('');

  const mutation = useMutation({
    mutationFn: async () => {
      const { error, response } = await api.POST('/api/v1/hosts/{id}/exceptions', {
        params: { path: { id: hostId } },
        body: {
          rule_id: rule.rule_id,
          reason: reason.trim(),
          expires_at: expires ? new Date(expires).toISOString() : null,
        },
      });
      if (error || !response.ok) {
        if (response.status === 409) {
          throw new Error('An open exception already exists for this rule.');
        }
        throw new Error(apiErrorMessage(error, `Request failed (${response.status})`));
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['host', hostId, 'exceptions'] });
      onSuccess();
    },
  });

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Request compliance exception"
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
        <h3 style={{ margin: '0 0 4px', fontSize: 14, fontWeight: 600 }}>Request exception</h3>
        <div style={{ color: 'var(--ow-fg-2)', fontSize: 12, marginBottom: 4 }}>{rule.title}</div>
        <div
          style={{
            fontFamily: 'var(--ow-font-mono)',
            fontSize: 11,
            color: 'var(--ow-fg-3)',
            marginBottom: 14,
          }}
        >
          {rule.rule_id}
        </div>

        <label style={{ display: 'block', fontSize: 12, color: 'var(--ow-fg-2)', marginBottom: 4 }}>
          Reason (required)
        </label>
        <textarea
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          rows={3}
          aria-label="Exception reason"
          placeholder="Why is this failure an accepted risk?"
          style={{
            width: '100%',
            background: 'var(--ow-bg-2)',
            border: '1px solid var(--ow-line)',
            borderRadius: 7,
            color: 'var(--ow-fg-0)',
            fontSize: 13,
            padding: 8,
            resize: 'vertical',
            marginBottom: 14,
          }}
        />

        <label style={{ display: 'block', fontSize: 12, color: 'var(--ow-fg-2)', marginBottom: 4 }}>
          Expires (optional)
        </label>
        <input
          type="date"
          value={expires}
          onChange={(e) => setExpires(e.target.value)}
          aria-label="Exception expiry date"
          style={{
            background: 'var(--ow-bg-2)',
            border: '1px solid var(--ow-line)',
            borderRadius: 7,
            color: 'var(--ow-fg-0)',
            fontSize: 13,
            padding: '6px 8px',
            marginBottom: 16,
          }}
        />

        {mutation.error && (
          <div style={{ color: 'var(--ow-crit)', fontSize: 12, marginBottom: 12 }} role="alert">
            {(mutation.error as Error).message}
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <button
            type="button"
            onClick={onClose}
            style={{
              height: 32,
              padding: '0 14px',
              background: 'var(--ow-bg-2)',
              color: 'var(--ow-fg-1)',
              border: '1px solid var(--ow-line)',
              borderRadius: 7,
              fontSize: 12,
              cursor: 'pointer',
            }}
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={reason.trim() === '' || mutation.isPending}
            onClick={() => mutation.mutate()}
            style={{
              height: 32,
              padding: '0 14px',
              background: 'var(--ow-info)',
              color: 'var(--ow-info-on)',
              border: 0,
              borderRadius: 7,
              fontSize: 12,
              fontWeight: 600,
              cursor: reason.trim() === '' || mutation.isPending ? 'default' : 'pointer',
              opacity: reason.trim() === '' || mutation.isPending ? 0.6 : 1,
            }}
          >
            {mutation.isPending ? 'Submitting' : 'Submit request'}
          </button>
        </div>
      </div>
    </div>
  );
}

// relativeTime — compact relative wording for fresh timestamps,
// absolute date past 30 days (same cutoff as the activity feed).
function relativeTime(iso: string): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return 'n/a';
  const minutes = Math.max(0, Math.round((Date.now() - t) / 60_000));
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days <= 30) return `${days}d ago`;
  return new Date(iso).toLocaleDateString(undefined, {
    month: 'numeric',
    day: 'numeric',
    year: 'numeric',
  });
}

const td: CSSProperties = {
  padding: '9px 10px 9px 0',
  verticalAlign: 'top',
};

const retryBtn: CSSProperties = {
  background: 'none',
  border: '1px solid var(--ow-line)',
  borderRadius: 6,
  color: 'var(--ow-fg-1)',
  fontSize: 11,
  padding: '2px 8px',
  cursor: 'pointer',
};
