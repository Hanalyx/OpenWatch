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
//   - The line ALSO breaks at every formula boundary, and a day with no score
//     is drawn as a hollow marker off the line rather than skipped. Two scores
//     produced by different formulas are different quantities; joining them
//     draws a trend through a change of meaning, and a viewer reads a slope
//     that was never measured. The API already reports this correctly, so
//     connecting the points anyway would preserve the invalid comparison
//     visually while the contract described it accurately.
//   - Hover anywhere reveals the nearest data point: a guide line, an enlarged
//     marker, and a tooltip with the point's date, score, and any extra lines
//     the caller supplies (fleet passes hosts / failing / critical).
//
// Pure SVG + one relative wrapper for the tooltip; no chart dependency.

// FormulaStatus mirrors the API enum. identified and legacy_unknown scores are
// both real; they are simply not comparable with each other.
export type FormulaStatus = 'identified' | 'legacy_unknown' | 'mixed';

export interface TrendPoint {
  date: string; // YYYY-MM-DD (the snapshot_date)
  // null when nothing could be scored that day, or when the day's snapshots
  // disagree about the formula. Never coerce it to 0: that is the fabricated
  // verdict the whole scoring change exists to remove.
  scorePct: number | null;
  formulaStatus: FormulaStatus;
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
  // A no-score GUTTER below the score plot.
  //
  // Without it, a marker drawn at height - PAD sits exactly on y(0), because
  // y(0) IS height - PAD. A day nothing could assess would then be plotted at
  // zero percent, which is the fabricated verdict this whole change removes,
  // rendered rather than computed. The gutter gives those days a row of their
  // own, below the axis the score is measured on.
  const GUTTER = 10;
  const innerH = height - 2 * PAD - GUTTER;

  // Right edge = today, so a missing recent snapshot is visible as trailing gap.
  const todayUTC = Math.floor(Date.now() / DAY_MS) * DAY_MS;
  const windowStart = todayUTC - (windowDays - 1) * DAY_MS;
  const dayIndex = (d: string) => Math.round((parseDay(d) - windowStart) / DAY_MS);

  const xFrac = (d: string) => (windowDays <= 1 ? 0.5 : dayIndex(d) / (windowDays - 1));
  const x = (d: string) => PAD + xFrac(d) * innerW;
  const y = (score: number) => PAD + (1 - Math.max(0, Math.min(100, score)) / 100) * innerH;
  // The gutter's own row, strictly below y(0).
  const yGutter = PAD + innerH + GUTTER / 2;

  // Points that carry a score are the only ones that can be on a line.
  const scored = points.filter((p) => p.scorePct !== null);
  // Days with no score, drawn as hollow markers so the reason is hoverable
  // instead of the day silently disappearing.
  const unscored = points.filter((p) => p.scorePct === null);

  // Break the polyline at gaps AND at formula boundaries. Two points join only
  // when they are exactly one calendar day apart AND were produced by the same
  // formula. Joining a legacy_unknown point to an identified one would draw a
  // slope between two different measurements.
  const segments: TrendPoint[][] = [];
  for (let i = 0; i < scored.length; i++) {
    const prev = scored[i - 1];
    const breakHere =
      i === 0 ||
      dayIndex(scored[i]!.date) - dayIndex(prev!.date) !== 1 ||
      scored[i]!.formulaStatus !== prev!.formulaStatus;
    if (breakHere) segments.push([]);
    segments[segments.length - 1]!.push(scored[i]!);
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
                points={seg.map((p) => `${x(p.date)},${y(p.scorePct!)}`).join(' ')}
                fill="none"
                stroke={color}
                // A legacy segment is dashed, so a viewer can see at a glance
                // that it was measured by a formula the current one replaced.
                strokeDasharray={seg[0]!.formulaStatus === 'legacy_unknown' ? '4 3' : undefined}
                strokeWidth={2}
              />
            ) : null,
          )}
          {points.map((p, i) =>
            p.scorePct === null ? null : (
              <circle
                key={p.date}
                cx={x(p.date)}
                cy={y(p.scorePct)}
                r={hover === i ? 3.5 : 2}
                fill={color}
              />
            ),
          )}
          {/* The gutter divider. It separates the score axis from the row of
              days that have no score, so a marker below it cannot be read as a
              low score. */}
          {unscored.length > 0 && (
            <line
              x1={PAD}
              x2={W - PAD}
              y1={y(0) + GUTTER / 4}
              y2={y(0) + GUTTER / 4}
              stroke="var(--ow-line)"
              strokeWidth={1}
            />
          )}
          {/* Days with no score, in the gutter. NOT at y(0), which is a real
              compliance score of zero and a different claim entirely. */}
          {unscored.map((p) => (
            <circle
              key={`nil-${p.date}`}
              cx={x(p.date)}
              cy={yGutter}
              r={2.5}
              fill="none"
              stroke="var(--ow-fg-3)"
              strokeWidth={1.5}
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

// ariaSummary gives non-visual users the same headline the chart shows,
// including the parts a sighted user reads from the broken line.
function ariaSummary(points: TrendPoint[], targetPct: number): string {
  if (points.length === 0) return 'Compliance score trend: no data';
  const last = points[points.length - 1]!;
  const first = points[0]!;
  const scored = points.filter((p) => p.scorePct !== null);
  const legacy = points.filter((p) => p.formulaStatus === 'legacy_unknown').length;
  const mixed = points.filter((p) => p.formulaStatus === 'mixed').length;
  const noScore = points.length - scored.length;

  let s =
    `Compliance score trend, target ${targetPct}%. ` +
    `${points.length} snapshots from ${first.date} to ${last.date}. `;
  s += last.scorePct === null ? 'Latest day has no score. ' : `Latest ${last.scorePct}%. `;
  if (legacy > 0) {
    s +=
      `${legacy} ${legacy === 1 ? 'day was' : 'days were'} scored by an earlier formula ` +
      'and cannot be compared with the rest. ';
  }
  if (mixed > 0) {
    s += `${mixed} ${mixed === 1 ? 'day has' : 'days have'} no score because their snapshots mix formulas. `;
  }
  if (noScore > mixed) {
    s += `${noScore - mixed} ${noScore - mixed === 1 ? 'day' : 'days'} could not be assessed. `;
  }
  return s.trim();
}
