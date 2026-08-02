import { AlertTriangle, Check, Clock, X } from 'lucide-react';
import type { components } from '@/api/schema';
import { phaseLabel, phaseNote, useRemediationSteps } from '@/hooks/useRemediationSteps';

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
    // Not an error: a request that was never executed has no journal. Saying
    // why is better than an empty panel that reads as a failure.
    return (
      <JournalNote>
        No transaction yet. Kensa records the phases when the fix runs, so this fills in once the
        request is executed.
      </JournalNote>
    );
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
