import type { ReactNode } from 'react';
import { Link } from '@tanstack/react-router';

// Dashboard widget primitives — the shared chrome every widget renders
// inside. Ported in spirit from the openwatch-v1 Dashboard.html widget
// shell (.widget / .w-head / .w-body), styled via the --ow-* tokens.
//
// Spec: frontend-dashboard.

type Tone = 'crit' | 'warn' | 'ok' | 'info' | 'fg';

const TONE_VAR: Record<Tone, string> = {
  crit: 'var(--ow-crit)',
  warn: 'var(--ow-warn)',
  ok: 'var(--ow-ok)',
  info: 'var(--ow-info)',
  fg: 'var(--ow-fg-0)',
};

export function toneVar(tone: Tone): string {
  return TONE_VAR[tone];
}

// WidgetCard — the titled container. `to` renders an "open" affordance
// linking to the page the widget is a lens into.
export function WidgetCard({
  title,
  to,
  children,
}: {
  title: string;
  to?: string;
  children: ReactNode;
}) {
  return (
    <section
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        minHeight: 0,
      }}
    >
      <header
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          padding: '12px 14px 10px',
        }}
      >
        <span
          style={{
            fontSize: 12,
            fontWeight: 600,
            color: 'var(--ow-fg-2)',
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
            flex: 1,
          }}
        >
          {title}
        </span>
        {to && (
          <Link
            to={to}
            aria-label={`Open ${title}`}
            style={{
              color: 'var(--ow-fg-3)',
              width: 24,
              height: 24,
              display: 'grid',
              placeItems: 'center',
              borderRadius: 5,
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
              <path d="M7 17 17 7M7 7h10v10" />
            </svg>
          </Link>
        )}
      </header>
      <div style={{ padding: '0 14px 14px', flex: 1 }}>{children}</div>
    </section>
  );
}

// KpiValue — the big tabular number with an optional unit and tone.
export function KpiValue({
  value,
  unit,
  tone = 'fg',
}: {
  value: ReactNode;
  unit?: string;
  tone?: Tone;
}) {
  return (
    <div
      style={{
        fontSize: 34,
        fontWeight: 600,
        letterSpacing: '-0.02em',
        lineHeight: 1,
        fontVariantNumeric: 'tabular-nums',
        display: 'flex',
        alignItems: 'baseline',
        gap: 6,
        color: TONE_VAR[tone],
      }}
    >
      {value}
      {unit && (
        <span style={{ fontSize: 15, color: 'var(--ow-fg-2)', fontWeight: 500 }}>{unit}</span>
      )}
    </div>
  );
}

export function KpiSub({ children }: { children: ReactNode }) {
  return <div style={{ color: 'var(--ow-fg-3)', fontSize: 12, marginTop: 8 }}>{children}</div>;
}

// Sparkline — area + line SVG from a numeric series (Dashboard.html spark()).
export function Sparkline({
  data,
  color,
  height = 70,
}: {
  data: number[];
  color: string;
  height?: number;
}) {
  const W = 240;
  const pad = 4;
  if (data.length < 2) return null;
  const max = Math.max(...data);
  const min = Math.min(...data);
  const x = (i: number) => pad + (i / (data.length - 1)) * (W - pad * 2);
  const y = (v: number) => height - pad - ((v - min) / (max - min || 1)) * (height - pad * 2);
  const line = data
    .map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)} ${y(v).toFixed(1)}`)
    .join(' ');
  const area = `${line} L${x(data.length - 1).toFixed(1)} ${height - pad} L${x(0).toFixed(1)} ${height - pad} Z`;
  return (
    <svg
      width="100%"
      height={height}
      viewBox={`0 0 ${W} ${height}`}
      preserveAspectRatio="none"
      aria-hidden="true"
    >
      <path d={area} fill={color} opacity="0.14" />
      <path d={line} fill="none" stroke={color} strokeWidth="2" />
    </svg>
  );
}

// WidgetState — uniform loading / error / empty bodies so each widget
// handles the three non-data states the same way.
export function WidgetState({
  kind,
  message,
}: {
  kind: 'loading' | 'error' | 'empty';
  message?: string;
}) {
  const color = kind === 'error' ? 'var(--ow-crit)' : 'var(--ow-fg-3)';
  const text =
    message ??
    (kind === 'loading' ? 'Loading…' : kind === 'error' ? 'Failed to load' : 'No data yet');
  return (
    <div
      role={kind === 'error' ? 'alert' : 'status'}
      style={{ color, fontSize: 12, padding: '6px 0' }}
    >
      {text}
    </div>
  );
}
