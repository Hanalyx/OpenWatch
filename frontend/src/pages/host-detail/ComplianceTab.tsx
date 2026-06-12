// ComplianceTab — Host Detail Compliance tab (lens model: one scan,
// viewed through any framework).
//
// Layout mirrors the prototype's compliance panel
// (docs/engineering/prototypes/openwatch-v1/Host Detail.html):
//
//   1. scan-context strip: headline + last-scan sub-line (+ policy
//      version when present). No Export button (deferred, no dead
//      controls) and no duplicate Re-scan: the page-head Run scan
//      button owns scan enqueueing.
//   2. lens bar: "View as" + an All rules chip plus one chip per
//      framework option. Selection is owned by the PARENT page
//      (?framework= search param); this tab only calls
//      onFrameworkChange and re-renders when the prop changes.
//   3. summary tiles: score, passing, failing, skipped, error.
//   4. category rows with a small failing-tinted bar.
//   5. rules table with CLIENT-SIDE status filter chips. The lens
//      response is one bounded payload (~539 rules max), so filtering
//      never refetches.
//
// Data flow: ONE GET /hosts/{id}/compliance response renders sections
// 1 and 3-5; GET /hosts/{id}/compliance/frameworks feeds the lens bar.
// Both query keys carry the ['host', hostId] prefix so the
// scan.completed SSE invalidation refreshes the tab with no extra
// wiring. The stored per-rule check output never reaches this surface:
// the API omits it by contract (api-host-compliance C-02) and this
// file renders only catalog metadata + statuses.
//
// Spec: frontend-host-compliance-tab v1.0.0.

import { useMemo, useState } from 'react';
import type { CSSProperties, ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { components } from '@/api/schema';
import { SeverityPill } from '@/pages/host-detail/SeverityPill';

type LensResponse = components['schemas']['HostComplianceLensResponse'];
type LensRule = components['schemas']['HostComplianceRule'];
type LensCategory = components['schemas']['HostComplianceCategory'];
type FrameworkOption = components['schemas']['HostComplianceFramework'];

type StatusFilter = 'all' | 'pass' | 'fail' | 'skipped' | 'error';

const FILTER_ORDER: { id: StatusFilter; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'fail', label: 'Fail' },
  { id: 'pass', label: 'Pass' },
  { id: 'skipped', label: 'Skipped' },
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

  // Lens options — framework ids + mapped-rule counts for the picker.
  const frameworksQuery = useQuery({
    queryKey: ['host', hostId, 'compliance_frameworks'],
    queryFn: async (): Promise<FrameworkOption[]> => {
      const { data, error, response } = await api.GET('/api/v1/hosts/{id}/compliance/frameworks', {
        params: { path: { id: hostId } },
      });
      if (error || !response.ok) {
        throw new Error(apiErrorMessage(error, `Failed to load (${response.status})`));
      }
      return data?.frameworks ?? [];
    },
    enabled: !!hostId,
  });

  // CLIENT-SIDE status filter — clicking a chip never refetches.
  // Spec C-03 / AC-04.
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');

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
        <SummaryTiles summary={lens.summary} />
        <CategoryRows categories={lens.categories} />
        <RulesTable rules={lens.rules} filter={statusFilter} onFilterChange={setStatusFilter} />
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
        isPending={lensQuery.isPending}
        lastScanAt={lensQuery.data?.scan_context.last_scan_at ?? null}
        policyVersion={lensQuery.data?.scan_context.policy_version ?? ''}
      />
      <LensBar
        framework={framework}
        options={frameworksQuery.data ?? []}
        onFrameworkChange={onFrameworkChange}
      />
      {body}
    </section>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// 1. Scan-context strip
// ─────────────────────────────────────────────────────────────────────────

function ScanContextStrip({
  isPending,
  lastScanAt,
  policyVersion,
}: {
  isPending: boolean;
  lastScanAt: string | null;
  policyVersion: string;
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
      }}
    >
      <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--ow-fg-0)' }}>
        One scan, viewed through any framework
      </div>
      <div style={{ color: 'var(--ow-fg-2)', fontSize: 12, marginTop: 2 }}>{sub}</div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// 2. Lens bar — "View as" chips. Selection routes through the parent's
//    onFrameworkChange so the URL (?framework=) stays the single source
//    of truth (api-hosts AC-08).
// ─────────────────────────────────────────────────────────────────────────

function LensBar({
  framework,
  options,
  onFrameworkChange,
}: {
  framework?: string;
  options: FrameworkOption[];
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
        All rules
      </LensChip>
      {options.map((opt) => (
        <LensChip
          key={opt.framework_id}
          active={framework === opt.framework_id}
          onClick={() => onFrameworkChange(opt.framework_id)}
        >
          {opt.framework_id}
          <span
            style={{
              fontVariantNumeric: 'tabular-nums',
              fontWeight: 700,
              padding: '1px 7px',
              borderRadius: 999,
              fontSize: 11,
              background: 'var(--ow-bg-3)',
              color: 'var(--ow-fg-2)',
            }}
          >
            {opt.rule_count}
          </span>
        </LensChip>
      ))}
    </div>
  );
}

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
// 3. Summary tiles
// ─────────────────────────────────────────────────────────────────────────

function SummaryTiles({ summary }: { summary: LensResponse['summary'] }) {
  const tiles: { label: string; value: string; color: string }[] = [
    { label: 'Score', value: `${summary.score_pct}%`, color: 'var(--ow-fg-0)' },
    { label: 'Passing', value: String(summary.passing), color: 'var(--ow-ok)' },
    { label: 'Failing', value: String(summary.failing), color: 'var(--ow-crit)' },
    { label: 'Skipped', value: String(summary.skipped), color: 'var(--ow-warn)' },
    { label: 'Error', value: String(summary.error), color: 'var(--ow-fg-2)' },
  ];
  return (
    <div
      aria-label="Compliance summary"
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(5, minmax(0, 1fr))',
        gap: 14,
      }}
    >
      {tiles.map((t) => (
        <div
          key={t.label}
          style={{
            background: 'var(--ow-bg-1)',
            border: '1px solid var(--ow-line)',
            borderRadius: 'var(--ow-radius)',
            padding: 16,
          }}
        >
          <div
            style={{
              fontSize: 24,
              fontWeight: 700,
              lineHeight: 1,
              color: t.color,
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            {t.value}
          </div>
          <div
            style={{
              color: 'var(--ow-fg-3)',
              fontSize: 10,
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              marginTop: 6,
            }}
          >
            {t.label}
          </div>
        </div>
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// 4. Category rows — name + passing/failing/total + failing-tinted bar
// ─────────────────────────────────────────────────────────────────────────

function CategoryRows({ categories }: { categories: LensCategory[] }) {
  if (categories.length === 0) return null;
  return (
    <section
      aria-label="Compliance categories"
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: 18,
      }}
    >
      <h3 style={{ margin: '0 0 12px', fontSize: 14, fontWeight: 600 }}>Categories</h3>
      <div role="list" aria-label="Category breakdown">
        {categories.map((c) => {
          const failPct = c.total > 0 ? (c.failing / c.total) * 100 : 0;
          return (
            <div
              key={c.category}
              role="listitem"
              style={{ padding: '8px 0', borderTop: '1px solid var(--ow-line)' }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'baseline',
                  gap: 10,
                  fontSize: 13,
                }}
              >
                <span style={{ color: 'var(--ow-fg-0)', fontWeight: 500 }}>{c.category}</span>
                <span
                  style={{
                    color: 'var(--ow-fg-2)',
                    fontSize: 12,
                    fontVariantNumeric: 'tabular-nums',
                  }}
                >
                  <span style={{ color: 'var(--ow-ok)' }}>{c.passing} passing</span>
                  {' · '}
                  <span style={{ color: c.failing > 0 ? 'var(--ow-crit)' : 'var(--ow-fg-3)' }}>
                    {c.failing} failing
                  </span>
                  {' · '}
                  {c.total} total
                </span>
              </div>
              <div
                aria-hidden
                style={{
                  marginTop: 6,
                  height: 4,
                  borderRadius: 999,
                  background: 'var(--ow-bg-3)',
                  overflow: 'hidden',
                }}
              >
                <div
                  style={{
                    width: `${failPct}%`,
                    height: '100%',
                    background: 'var(--ow-crit)',
                    borderRadius: 999,
                  }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// 5. Rules table + client-side status filter chips
// ─────────────────────────────────────────────────────────────────────────

function RulesTable({
  rules,
  filter,
  onFilterChange,
}: {
  rules: LensRule[];
  filter: StatusFilter;
  onFilterChange: (next: StatusFilter) => void;
}) {
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

  const visible = useMemo(
    () => (filter === 'all' ? rules : rules.filter((r) => r.status === filter)),
    [rules, filter],
  );

  return (
    <section
      aria-label="Compliance rules"
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: 18,
      }}
    >
      <div
        role="group"
        aria-label="Filter rules by status"
        style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}
      >
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
            {f.label}
            <span style={{ fontVariantNumeric: 'tabular-nums', color: 'var(--ow-fg-3)' }}>
              {counts[f.id]}
            </span>
          </button>
        ))}
      </div>

      {visible.length === 0 ? (
        <div role="status" style={{ color: 'var(--ow-fg-3)', fontSize: 12, padding: '12px 0' }}>
          No rules with this status.
        </div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr>
              <Th width={70}>Severity</Th>
              <Th>Rule</Th>
              <Th width={160}>Category</Th>
              <Th width={90}>Status</Th>
              <Th width={120}>Last checked</Th>
            </tr>
          </thead>
          <tbody>
            {visible.map((r) => (
              <tr key={r.rule_id} style={{ borderTop: '1px solid var(--ow-line)' }}>
                <td style={td}>
                  <SeverityPill severity={r.severity} />
                </td>
                <td style={td}>
                  <div style={{ color: 'var(--ow-fg-0)', fontWeight: 500 }}>{r.title}</div>
                  <div
                    style={{
                      color: 'var(--ow-fg-3)',
                      fontSize: 11,
                      fontFamily: 'var(--ow-font-mono)',
                      marginTop: 2,
                    }}
                  >
                    {r.control_ids.length > 0 ? r.control_ids.join(', ') : r.rule_id}
                  </div>
                </td>
                <td style={{ ...td, color: 'var(--ow-fg-2)' }}>{r.category}</td>
                <td style={td}>
                  <StatusChip status={r.status} />
                </td>
                <td style={{ ...td, color: 'var(--ow-fg-3)', whiteSpace: 'nowrap', fontSize: 12 }}>
                  {relativeTime(r.last_checked_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

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

// StatusChip — pass ok-tint, fail crit-tint, skipped muted, error
// warn-tint (prototype status pips).
const STATUS_STYLE: Record<string, { fg: string; bg: string; label: string }> = {
  pass: { fg: 'var(--ow-ok)', bg: 'var(--ow-ok-bg)', label: 'Pass' },
  fail: { fg: 'var(--ow-crit)', bg: 'var(--ow-crit-bg)', label: 'Fail' },
  skipped: { fg: 'var(--ow-fg-3)', bg: 'var(--ow-bg-2)', label: 'Skipped' },
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
      }}
    >
      <span aria-hidden style={{ width: 6, height: 6, borderRadius: '50%', background: s.fg }} />
      {s.label}
    </span>
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
  padding: '8px 10px 8px 0',
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
