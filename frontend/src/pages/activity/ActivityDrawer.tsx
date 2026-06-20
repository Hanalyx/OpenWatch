import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import api from '@/api/client';
import { apiErrorMessage } from '@/api/errors';
import type { components } from '@/api/schema';
import { useAlertActions, type AlertAction } from './useAlertActions';
import { severityTone } from '@/api/eventDisplay';

type Activity = components['schemas']['Activity'];

// ActivityDrawer — the right-side detail panel for a clicked event.
//
// Basic fields (title, summary, source, severity, host, time) render for
// every source straight from the activity item. For source === "alert"
// it additionally fetches GET /alerts/{id} to show the alert body, tags,
// state, and the lifecycle actions. The other four sources are immutable
// logs whose richer payload has no per-id endpoint yet (see
// docs/engineering/activity_page_scope.md) — they show the basics only.
//
// Spec: frontend-activity.

const TONE: Record<string, string> = {
  crit: 'var(--ow-crit)',
  warn: 'var(--ow-warn)',
  info: 'var(--ow-info)',
};

export function ActivityDrawer({
  item,
  canAlertWrite,
  onClose,
}: {
  item: Activity | null;
  canAlertWrite: boolean;
  onClose: () => void;
}) {
  const isAlert = item?.source === 'alert';

  const alertQuery = useQuery({
    queryKey: ['alert', item?.id],
    queryFn: async () => {
      const { data, error, response } = await api.GET('/api/v1/alerts/{id}', {
        params: { path: { id: item!.id } },
      });
      if (error || !response.ok) {
        throw new Error(apiErrorMessage(error, `Failed to load alert (${response.status})`));
      }
      return data!;
    },
    enabled: !!item && isAlert,
  });

  const actions = useAlertActions();
  const alert = alertQuery.data;

  if (!item) return null;
  const tone = TONE[severityTone(item.severity)];

  const run = (action: AlertAction) => actions.mutate({ id: item.id, action });

  return (
    <>
      <div
        onClick={onClose}
        aria-hidden="true"
        style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0,0,0,0.5)',
          zIndex: 70,
        }}
      />
      <aside
        role="dialog"
        aria-label={`Event detail: ${item.title}`}
        style={{
          position: 'fixed',
          top: 0,
          right: 0,
          height: '100vh',
          width: 460,
          maxWidth: '92vw',
          background: 'var(--ow-bg-1)',
          borderLeft: '1px solid var(--ow-line)',
          zIndex: 80,
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        <header style={{ padding: '18px 20px', borderBottom: '1px solid var(--ow-line)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div
              style={{
                fontFamily: 'var(--ow-font-mono, monospace)',
                fontWeight: 600,
                fontSize: 15,
                display: 'flex',
                alignItems: 'center',
                gap: 10,
              }}
            >
              <span
                style={{ width: 10, height: 10, borderRadius: '50%', background: tone }}
                aria-hidden="true"
              />
              {item.title}
            </div>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close detail"
              style={{
                width: 30,
                height: 30,
                display: 'grid',
                placeItems: 'center',
                background: 'transparent',
                border: '1px solid var(--ow-line)',
                borderRadius: 6,
                color: 'var(--ow-fg-2)',
                cursor: 'pointer',
              }}
            >
              <svg
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                aria-hidden="true"
              >
                <path d="M18 6 6 18M6 6l12 12" />
              </svg>
            </button>
          </div>
          <div
            style={{
              color: 'var(--ow-fg-2)',
              fontSize: 12,
              marginTop: 8,
              display: 'flex',
              gap: 10,
              flexWrap: 'wrap',
            }}
          >
            <span style={{ textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              {item.source}
            </span>
            <span>{item.severity}</span>
            <span>{new Date(item.occurred_at).toLocaleString()}</span>
            {isAlert && alert && (
              <span style={{ color: tone, fontWeight: 600 }}>{alert.state}</span>
            )}
          </div>
        </header>

        <div style={{ flex: 1, overflowY: 'auto', padding: '18px 20px' }}>
          {(item.summary || alert?.body) && (
            <Section title="Message">
              <div style={{ color: 'var(--ow-fg-0)', fontSize: 14, lineHeight: 1.5 }}>
                {alert?.body || item.summary}
              </div>
            </Section>
          )}

          {item.host_id && (
            <Section title="Host">
              <Link
                to="/hosts/$hostId"
                params={{ hostId: item.host_id }}
                style={{
                  color: 'var(--ow-link)',
                  fontFamily: 'var(--ow-font-mono, monospace)',
                  fontSize: 12,
                }}
              >
                {item.host_id}
              </Link>
            </Section>
          )}

          {isAlert && alertQuery.isError && (
            <div role="alert" style={{ color: 'var(--ow-crit)', fontSize: 12 }}>
              {apiErrorMessage(alertQuery.error, 'Failed to load alert detail')}
            </div>
          )}

          {isAlert && alert?.tags && Object.keys(alert.tags).length > 0 && (
            <Section title="Tags">
              <dl
                style={{
                  display: 'grid',
                  gridTemplateColumns: '130px 1fr',
                  rowGap: 8,
                  columnGap: 12,
                  fontSize: 12,
                  margin: 0,
                }}
              >
                {Object.entries(alert.tags).map(([k, v]) => (
                  <div key={k} style={{ display: 'contents' }}>
                    <dt style={{ color: 'var(--ow-fg-2)' }}>{k}</dt>
                    <dd
                      style={{
                        margin: 0,
                        color: 'var(--ow-fg-1)',
                        fontFamily: 'var(--ow-font-mono, monospace)',
                      }}
                    >
                      {v}
                    </dd>
                  </div>
                ))}
              </dl>
            </Section>
          )}
        </div>

        {isAlert && canAlertWrite && alert && (
          <footer
            style={{
              padding: '14px 20px',
              borderTop: '1px solid var(--ow-line)',
              display: 'flex',
              gap: 8,
              flexWrap: 'wrap',
            }}
          >
            {alert.state === 'active' && (
              <ActionButton
                label="Acknowledge"
                primary
                disabled={actions.isPending}
                onClick={() => run('acknowledge')}
              />
            )}
            {(alert.state === 'active' || alert.state === 'acknowledged') && (
              <ActionButton
                label="Silence"
                disabled={actions.isPending}
                onClick={() => run('silence')}
              />
            )}
            {alert.state !== 'resolved' && alert.state !== 'dismissed' && (
              <ActionButton
                label="Resolve"
                disabled={actions.isPending}
                onClick={() => run('resolve')}
              />
            )}
            {actions.isError && (
              <span role="alert" style={{ color: 'var(--ow-crit)', fontSize: 12, width: '100%' }}>
                {(actions.error as Error).message}
              </span>
            )}
          </footer>
        )}
      </aside>
    </>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <h5
        style={{
          margin: '0 0 8px',
          fontSize: 11,
          color: 'var(--ow-fg-3)',
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
          fontWeight: 600,
        }}
      >
        {title}
      </h5>
      {children}
    </div>
  );
}

function ActionButton({
  label,
  primary,
  disabled,
  onClick,
}: {
  label: string;
  primary?: boolean;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      style={{
        height: 34,
        padding: '0 14px',
        borderRadius: 6,
        border: `1px solid ${primary ? 'var(--ow-info)' : 'var(--ow-line)'}`,
        background: primary ? 'var(--ow-info)' : 'var(--ow-bg-2)',
        color: primary ? 'var(--ow-info-on)' : 'var(--ow-fg-0)',
        fontFamily: 'inherit',
        fontSize: 13,
        fontWeight: 600,
        cursor: disabled ? 'default' : 'pointer',
        opacity: disabled ? 0.6 : 1,
      }}
    >
      {label}
    </button>
  );
}
