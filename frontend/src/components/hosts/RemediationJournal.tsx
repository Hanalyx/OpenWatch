import { AlertTriangle, Check, Clock, X } from 'lucide-react';
import type { components } from '@/api/schema';
import {
  phaseLabel,
  phaseNote,
  useRemediationPlan,
  useRemediationSteps,
} from '@/hooks/useRemediationSteps';

type RemediationPhase = components['schemas']['RemediationPhase'];
type RemediationPreState = components['schemas']['RemediationPreState'];

// RemediationJournal renders one request's Kensa transaction: the phases that
// ran, what each did, and what was captured before anything changed.
//
// This exists because the tab used to show the four phases as a static
// diagram. The model was described and the run was not, so a failed fix could
// say only "reverted, host unchanged" while the reason sat in the API unread.
export function RemediationJournal({
  hostId,
  requestId,
  expanded,
}: {
  hostId: string;
  requestId: string;
  expanded: boolean;
}) {
  const journal = useRemediationSteps(hostId, requestId, expanded);

  if (!expanded) return null;

  if (journal.isPending) {
    return <JournalNote>Loading the transaction journal...</JournalNote>;
  }
  if (journal.isError) {
    return <JournalNote tone="bad">{journal.error ?? 'Could not load the journal.'}</JournalNote>;
  }
  if (journal.steps.length === 0) {
    // Nothing has run yet, so show what WOULD run. This is the half of the
    // question the journal cannot answer: an operator deciding whether to
    // approve a fix needs to know what it will do, not only what it did.
    return <PlanPreview hostId={hostId} requestId={requestId} />;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, padding: '4px 2px 10px' }}>
      {journal.steps.map((step) => {
        const phases = step.phases ?? [];
        const pre = step.pre_state ?? [];
        return (
          <div key={step.id} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {phases.length === 0 ? (
              <JournalNote>
                This transaction recorded no phases. The outcome is {step.phase_result ?? 'unknown'}
                .
              </JournalNote>
            ) : (
              <ol
                style={{
                  listStyle: 'none',
                  margin: 0,
                  padding: 0,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 8,
                }}
              >
                {phases.map((p) => (
                  <PhaseRow key={p.index} phase={p} total={phases.length} />
                ))}
              </ol>
            )}
            <CapturedState entries={pre} />
          </div>
        );
      })}
    </div>
  );
}

function PhaseRow({ phase, total }: { phase: RemediationPhase; total: number }) {
  const note = phaseNote(phase);
  const tone = phase.staged ? 'warn' : phase.success ? 'ok' : 'bad';
  const Icon = phase.staged ? Clock : phase.success ? Check : X;
  const color =
    tone === 'ok' ? 'var(--ow-ok)' : tone === 'warn' ? 'var(--ow-warn)' : 'var(--ow-bad)';

  return (
    <li
      style={{
        display: 'grid',
        gridTemplateColumns: '20px 130px 1fr',
        gap: 10,
        alignItems: 'start',
      }}
    >
      <Icon size={15} style={{ color, marginTop: 2 }} aria-hidden />
      <div>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--ow-fg-0)' }}>
          {phaseLabel(phase, total)}
        </div>
        <div style={{ fontSize: 11, color: 'var(--ow-fg-3)', fontFamily: 'var(--ow-font-mono)' }}>
          {phase.mechanism}
        </div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        {/* Kensa's own account of what this phase did. This is the answer to
            "why did it fail", and it was previously discarded. */}
        {phase.detail ? (
          <div
            style={{
              fontSize: 12,
              color: 'var(--ow-fg-1)',
              fontFamily: 'var(--ow-font-mono)',
              lineHeight: 1.5,
              wordBreak: 'break-word',
            }}
          >
            {phase.detail}
          </div>
        ) : (
          <div style={{ fontSize: 12, color: 'var(--ow-fg-3)' }}>
            No detail recorded for this phase.
          </div>
        )}
        {note ? (
          <div
            style={{
              display: 'flex',
              gap: 6,
              alignItems: 'flex-start',
              fontSize: 11,
              color: 'var(--ow-fg-2)',
              background: 'var(--ow-bg-2)',
              border: '1px solid var(--ow-line)',
              borderRadius: 'var(--ow-radius-sm, 6px)',
              padding: '6px 8px',
            }}
          >
            <AlertTriangle
              size={12}
              style={{ color: 'var(--ow-warn)', marginTop: 1 }}
              aria-hidden
            />
            <span>{note}</span>
          </div>
        ) : null}
      </div>
    </li>
  );
}

// CapturedState shows what Kensa recorded before it changed anything.
//
// The data is deliberately not interpreted. Its layout is defined by whichever
// Kensa handler captured it, with no published schema, so decoding it here
// would couple this component to Kensa handler internals and break silently
// when one changes. Until Kensa exposes a display projection (features/
// KN-OW-016) this shows that a capture exists, which steps it covers, and the
// raw evidence, rather than a prettier guess at what it means.
function CapturedState({ entries }: { entries: RemediationPreState[] }) {
  if (entries.length === 0) return null;
  const restorable = entries.filter((e) => e.capturable);

  return (
    <details style={{ marginLeft: 30 }}>
      <summary
        style={{ cursor: 'pointer', fontSize: 12, color: 'var(--ow-fg-2)', userSelect: 'none' }}
      >
        Captured before the change: {restorable.length} of {entries.length}{' '}
        {entries.length === 1 ? 'step' : 'steps'} restorable
      </summary>
      <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 8 }}>
        {entries.map((e) => (
          <div key={e.index}>
            <div style={{ fontSize: 11, color: 'var(--ow-fg-2)' }}>
              <span style={{ fontFamily: 'var(--ow-font-mono)' }}>{e.mechanism}</span>
              {e.capturable ? null : (
                <span style={{ color: 'var(--ow-fg-3)' }}> (no pre-state, not restorable)</span>
              )}
            </div>
            {e.capturable && e.data ? (
              <pre
                style={{
                  margin: '4px 0 0',
                  padding: 8,
                  background: 'var(--ow-bg-2)',
                  border: '1px solid var(--ow-line)',
                  borderRadius: 'var(--ow-radius-sm, 6px)',
                  fontSize: 11,
                  color: 'var(--ow-fg-1)',
                  overflowX: 'auto',
                }}
              >
                {JSON.stringify(e.data, null, 2)}
              </pre>
            ) : null}
          </div>
        ))}
      </div>
    </details>
  );
}

function JournalNote({ children, tone }: { children: React.ReactNode; tone?: 'bad' }) {
  return (
    <div
      style={{
        fontSize: 12,
        color: tone === 'bad' ? 'var(--ow-bad)' : 'var(--ow-fg-3)',
        padding: '8px 2px 12px',
        lineHeight: 1.5,
      }}
    >
      {children}
    </div>
  );
}

// PlanPreview shows what a fix would do, before it does it.
//
// Shown in place of the journal when a request has not executed. Kensa plans
// the rule against the live host and reports the apply steps, the validators
// and the rollback, all read-only. Every string here is Kensa's own: the
// summaries are handler-authored, so this describes the actual mechanism
// rather than a generic restatement of the rule title.
function PlanPreview({ hostId, requestId }: { hostId: string; requestId: string }) {
  const { plan, isPending, isError, error } = useRemediationPlan(hostId, requestId, true);

  if (isPending) return <JournalNote>Planning against the host...</JournalNote>;
  if (isError) {
    // Planning reaches the host, so a failure here is about the host, not the
    // fix. Say so, and do not imply the fix itself is broken.
    return (
      <JournalNote tone="bad">
        {error ?? 'Could not plan this fix.'} Nothing was changed on the host.
      </JournalNote>
    );
  }
  if (!plan) return <JournalNote>No plan available.</JournalNote>;

  const steps = plan.steps ?? [];
  const checks = plan.checks ?? [];
  const undo = plan.undo ?? [];
  const warnings = plan.warnings ?? [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, padding: '4px 2px 12px' }}>
      <div style={{ fontSize: 12, color: 'var(--ow-fg-2)' }}>
        Nothing has run yet. This is what would happen, planned against the host now.
      </div>

      {plan.control_channel_sensitive ? (
        <Callout tone="warn">
          This fix touches SSH, networking, PAM or firewall state. Kensa arms a timer before
          applying it, so the change reverts by itself if the host stops answering. That is what
          stops a hardening fix from locking you out of the host you are hardening.
        </Callout>
      ) : null}
      {plan.transactional === false ? (
        <Callout tone="warn">
          This rule is not all-or-nothing. If a later step fails, earlier ones stay applied.
        </Callout>
      ) : null}
      {warnings.map((w) => (
        <Callout key={w} tone="warn">
          {w}
        </Callout>
      ))}

      <PlanSection title="What it will change" items={steps} empty="No apply steps." />
      <PlanSection title="How it will be checked" items={checks} empty="No validators." />
      <PlanSection
        title={`How it can be undone (${plan.reversible_steps} of ${steps.length} reversible)`}
        items={undo}
        empty="This fix cannot be rolled back."
      />

      {plan.estimated_seconds ? (
        <div style={{ fontSize: 11, color: 'var(--ow-fg-3)' }}>
          Estimated {Math.round(plan.estimated_seconds)}s.
        </div>
      ) : null}
    </div>
  );
}

type PlanItem = {
  index?: number;
  mechanism?: string;
  name?: string;
  summary?: string;
  capturable?: boolean;
};

function PlanSection({ title, items, empty }: { title: string; items: PlanItem[]; empty: string }) {
  return (
    <div>
      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--ow-fg-0)', marginBottom: 6 }}>
        {title}
      </div>
      {items.length === 0 ? (
        <div style={{ fontSize: 12, color: 'var(--ow-fg-3)' }}>{empty}</div>
      ) : (
        <ol
          style={{ margin: 0, paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 6 }}
        >
          {items.map((it, i) => (
            <li key={`${it.mechanism ?? it.name ?? i}-${i}`} style={{ fontSize: 12 }}>
              {/* Kensa's own words. If a handler gave no summary we show the
                  mechanism rather than inventing a description of it. */}
              <span style={{ color: 'var(--ow-fg-1)' }}>
                {it.summary ?? it.mechanism ?? it.name}
              </span>
              {it.summary && (it.mechanism || it.name) ? (
                <span
                  style={{
                    color: 'var(--ow-fg-3)',
                    fontFamily: 'var(--ow-font-mono)',
                    fontSize: 11,
                    marginLeft: 8,
                  }}
                >
                  {it.mechanism ?? it.name}
                </span>
              ) : null}
              {it.capturable === false ? (
                <span style={{ color: 'var(--ow-warn)', fontSize: 11, marginLeft: 8 }}>
                  not reversible
                </span>
              ) : null}
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

function Callout({ children, tone }: { children: React.ReactNode; tone: 'warn' }) {
  return (
    <div
      style={{
        display: 'flex',
        gap: 8,
        alignItems: 'flex-start',
        fontSize: 12,
        lineHeight: 1.5,
        color: 'var(--ow-fg-1)',
        background: 'var(--ow-bg-2)',
        border: '1px solid var(--ow-line)',
        borderLeft: `3px solid var(--ow-${tone})`,
        borderRadius: 'var(--ow-radius-sm, 6px)',
        padding: '8px 10px',
      }}
    >
      <AlertTriangle size={13} style={{ color: `var(--ow-${tone})`, marginTop: 2 }} aria-hidden />
      <span>{children}</span>
    </div>
  );
}
