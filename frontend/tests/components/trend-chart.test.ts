// @spec frontend-dashboard
//
// The chart's line-breaking rule. The API reports formula boundaries correctly;
// this checks the RENDERING honors them, because a connected line preserves the
// invalid comparison no matter what the JSON said.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { load } from 'js-yaml';
import { describe, expect, test } from 'vitest';

const SRC = readFileSync(resolve(process.cwd(), 'src/components/charts/TrendChart.tsx'), 'utf8');

// The fixture lives in the spec, not here, so a criterion edited without a
// matching behavior change fails.
function criterion(id: string) {
  const doc = load(
    readFileSync(resolve(process.cwd(), '../specs/frontend/dashboard.spec.yaml'), 'utf8'),
  ) as { spec: { acceptance_criteria: Array<Record<string, unknown>> } };
  const ac = doc.spec.acceptance_criteria.find((a) => a.id === id);
  if (!ac) throw new Error(`${id} not found in specs/frontend/dashboard.spec.yaml`);
  return ac as { inputs: Record<string, unknown>; expected_output: Record<string, unknown> };
}

describe('frontend-dashboard — trend chart formula boundaries', () => {
  // @ac AC-06
  test('frontend-dashboard/AC-06 — the line breaks at every formula boundary', () => {
    const ac = criterion('AC-06');
    const points = ac.inputs.points as Array<{
      date: string;
      formula_status: string;
      score_pct: number | null;
    }>;
    const exp = ac.expected_output;

    // The component's own predicate, applied to the fixture. A day with no
    // score cannot be on a line, and two days join only when they were
    // produced by the same formula.
    const scored = points.filter((p) => p.score_pct !== null);
    const segments: (typeof scored)[] = [];
    for (let i = 0; i < scored.length; i++) {
      const prev = scored[i - 1];
      const breakHere = i === 0 || scored[i]!.formula_status !== prev!.formula_status;
      if (breakHere) segments.push([]);
      segments[segments.length - 1]!.push(scored[i]!);
    }

    expect(segments.length).toBe(exp.segments);
    // The forbidden answer: one line straight through the boundary, which is
    // what the chart drew before this rule and what the enum alone would not
    // have changed.
    expect(segments.length).not.toBe(exp.forbidden_segments);
    expect(scored.length).toBe(exp.points_on_a_line);
    expect(points.length - scored.length).toBe(exp.gutter_markers);

    // No segment may span two statuses.
    for (const seg of segments) {
      expect(new Set(seg.map((p) => p.formula_status)).size).toBe(1);
    }

    // The component must carry the predicate, not merely accept the field.
    expect(SRC).toMatch(/formulaStatus\s*!==\s*prev!?\.formulaStatus/);
    // A null score is never coerced to a number for plotting.
    expect(SRC).toContain('p.scorePct !== null');
    // The DERIVATION, not just the render call. Emptying the array would keep
    // "unscored.map" in the source while drawing nothing.
    expect(SRC).toContain('points.filter((p) => p.scorePct === null)');
    expect(SRC).toMatch(/unscored\.map/);

    // Unscored days go in a GUTTER strictly below the score plot, and the two
    // coordinates must actually DIFFER. The previous version drew them at
    // "height - PAD", which is exactly y(0): the marker sat on the zero-percent
    // axis while the comment claimed otherwise. Both are recomputed here from
    // the component's own constants so this cannot drift into repeating a
    // comment.
    expect(SRC).toContain('cy={yGutter}');
    expect(SRC).not.toContain('cy={height - PAD}');
    const PAD = Number(/const PAD = (\d+)/.exec(SRC)![1]);
    const GUTTER = Number(/const GUTTER = (\d+)/.exec(SRC)![1]);
    const height = 72;
    const innerH = height - 2 * PAD - GUTTER;
    const yZero = PAD + innerH;
    const yGutter = PAD + innerH + GUTTER / 2;
    expect(yGutter).not.toBe(yZero);
    expect(yGutter).toBeGreaterThan(yZero);
    // A divider separates them, so the gutter is visibly not the axis.
    expect(SRC).toContain('unscored.length > 0 &&');
    // A legacy segment is visually distinct from a current one.
    expect(SRC).toContain("formulaStatus === 'legacy_unknown' ? '4 3'");

    // The accessible summary names both facts a sighted reader gets from the
    // broken and dashed line.
    expect(exp.aria_mentions_legacy).toBe(true);
    expect(SRC).toContain('cannot be compared with the rest');
    expect(exp.aria_mentions_mixed).toBe(true);
    expect(SRC).toContain('mix formulas');
  });
});
