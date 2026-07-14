import { useState } from 'react';

// TrendChart is the shared interactive compliance-trend chart used by the host
// Compliance-trend card and the dashboard fleet-trend widget, so the two never
// diverge again. Design decisions (all deliberate):
//
//   - Fixed 0..100 score domain with an 80% target line. Auto min/max scaling
//     is banned: it exaggerates a 2% move into a cliff, which is misleading on a
//     compliance score.
//   - Date-positioned x-axis over the requested window (ending today), NOT an
//     index axis. A day with no snapshot (a host that was offline = not
//     compliant) MUST read as a real gap, so the line is broken wherever two
//     snapshots are more than one calendar day apart, and a missing recent
//     snapshot shows as empty space on the right.
//   - Hover anywhere reveals the nearest data point: a guide line, an enlarged
//     marker, and a tooltip with the point's date, score, and any extra lines
//     the caller supplies (fleet passes hosts / failing / critical).
//
// Pure SVG + one relative wrapper for the tooltip; no chart dependency.

export interface TrendPoint {
  date: string; // YYYY-MM-DD (the snapshot_date)
  scorePct: number; // 0..100
  // Tooltip lines shown on hover; line 0 renders muted (the date), the rest
  // emphasized. Callers assemble these so host vs fleet can differ.
  tooltip: string[];
}

const DAY_MS = 86400000;
const parseDay = (d: string) => Date.parse(d + 'T00:00:00Z');

export function TrendChart({
  points,
  windowDays,
  height = 72,
  targetPct = 80,
  color = 'var(--ow-info)',
}: {
  points: TrendPoint[];
  windowDays: number;
  height?: number;
  targetPct?: number;
  color?: string;
}) {
  const [hover, setHover] = useState<number | null>(null);

  const W = 300;
  const PAD = 4;
  const innerW = W - 2 * PAD;
  const innerH = height - 2 * PAD;

  // Right edge = today, so a missing recent snapshot is visible as trailing gap.
  const todayUTC = Math.floor(Date.now() / DAY_MS) * DAY_MS;
  const windowStart = todayUTC - (windowDays - 1) * DAY_MS;
  const dayIndex = (d: string) => Math.round((parseDay(d) - windowStart) / DAY_MS);

  const xFrac = (d: string) => (windowDays <= 1 ? 0.5 : dayIndex(d) / (windowDays - 1));
  const x = (d: string) => PAD + xFrac(d) * innerW;
  const y = (score: number) => PAD + (1 - Math.max(0, Math.min(100, score)) / 100) * innerH;

  // Break the polyline at gaps: two points join only when exactly one calendar
  // day apart. A gap leaves a real break instead of an interpolated line.
  const segments: TrendPoint[][] = [];
  for (let i = 0; i < points.length; i++) {
    const gapFromPrev = i === 0 || dayIndex(points[i]!.date) - dayIndex(points[i - 1]!.date) !== 1;
    if (gapFromPrev) segments.push([]);
    segments[segments.length - 1]!.push(points[i]!);
  }

  const onMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (points.length === 0) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const f = (e.clientX - rect.left) / rect.width;
    let best = 0;
    let bestDist = Infinity;
    points.forEach((p, i) => {
      const dist = Math.abs(xFrac(p.date) - f);
      if (dist < bestDist) {
        bestDist = dist;
        best = i;
      }
    });
    setHover(best);
  };

  const hp = hover !== null ? points[hover] : null;
  // Clamp the tooltip so it does not overflow the card edges.
  const hf = hp ? xFrac(hp.date) : 0.5;
  const tipTransform =
    hf < 0.2
      ? 'translate(0, -100%)'
      : hf > 0.8
        ? 'translate(-100%, -100%)'
        : 'translate(-50%, -100%)';

  return (
    <div style={{ marginTop: 10 }}>
      <div
        style={{ position: 'relative' }}
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
      >
        <svg
          viewBox={`0 0 ${W} ${height}`}
          style={{ width: '100%', height, display: 'block' }}
          role="img"
          aria-label={ariaSummary(points, targetPct)}
        >
          <line
            x1={PAD}
            x2={W - PAD}
            y1={y(targetPct)}
            y2={y(targetPct)}
            stroke="var(--ow-line)"
            strokeDasharray="3 3"
          />
          {segments.map((seg, si) =>
            seg.length > 1 ? (
              <polyline
                key={si}
                points={seg.map((p) => `${x(p.date)},${y(p.scorePct)}`).join(' ')}
                fill="none"
                stroke={color}
                strokeWidth={2}
              />
            ) : null,
          )}
          {points.map((p, i) => (
            <circle
              key={p.date}
              cx={x(p.date)}
              cy={y(p.scorePct)}
              r={hover === i ? 3.5 : 2}
              fill={color}
            />
          ))}
          {hp && (
            <line
              x1={x(hp.date)}
              x2={x(hp.date)}
              y1={PAD}
              y2={height - PAD}
              stroke="var(--ow-fg-3)"
              strokeWidth={1}
              strokeDasharray="2 2"
            />
          )}
        </svg>
        {hp && (
          <div
            role="status"
            style={{
              position: 'absolute',
              left: `${hf * 100}%`,
              top: -2,
              transform: tipTransform,
              background: 'var(--ow-bg-2)',
              border: '1px solid var(--ow-line)',
              borderRadius: 6,
              padding: '5px 8px',
              fontSize: 11,
              lineHeight: 1.45,
              color: 'var(--ow-fg-1)',
              whiteSpace: 'nowrap',
              pointerEvents: 'none',
              zIndex: 5,
            }}
          >
            {hp.tooltip.map((line, i) => (
              <div
                key={i}
                style={{
                  color: i === 0 ? 'var(--ow-fg-3)' : 'var(--ow-fg-0)',
                  fontVariantNumeric: 'tabular-nums',
                }}
              >
                {line}
              </div>
            ))}
          </div>
        )}
      </div>
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          fontSize: 10,
          color: 'var(--ow-fg-3)',
          marginTop: 2,
        }}
      >
        <span>{isoDay(windowStart)}</span>
        <span>{isoDay(todayUTC)}</span>
      </div>
    </div>
  );
}

// isoDay renders a UTC ms timestamp as YYYY-MM-DD (matches snapshot_date).
function isoDay(ms: number): string {
  return new Date(ms).toISOString().slice(0, 10);
}

// ariaSummary gives non-visual users the same headline the chart shows.
function ariaSummary(points: TrendPoint[], targetPct: number): string {
  if (points.length === 0) return 'Compliance score trend: no data';
  const last = points[points.length - 1]!;
  const first = points[0]!;
  return (
    `Compliance score trend, target ${targetPct}%. ` +
    `${points.length} snapshots from ${first.date} to ${last.date}. ` +
    `Latest ${last.scorePct}%.`
  );
}
