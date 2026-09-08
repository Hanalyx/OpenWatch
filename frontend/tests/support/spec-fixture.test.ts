// The fixture reader is the thing every spec-driven criterion trusts. If it
// stops noticing an unread key, every criterion using it silently weakens at
// once, and nothing else in the suite would report it.

import { describe, expect, test } from 'vitest';
import { loadCriterion, trackFixture } from './spec-fixture';

describe('trackFixture', () => {
  test('an unread key fails', () => {
    const f = trackFixture({ a: 1, b: 2 }, 'probe');
    f.get('a');
    expect(() => f.allConsumed()).toThrowError(/never asserted/);
  });

  test('reading every key passes', () => {
    const f = trackFixture({ a: 1, b: 2 }, 'probe');
    f.get('a');
    f.get('b');
    expect(() => f.allConsumed()).not.toThrow();
  });

  test('a missing requested key fails, rather than returning undefined', () => {
    const f = trackFixture({ a: 1 }, 'probe');
    expect(() => f.get('nope')).toThrowError(/has no key nope/);
  });

  test('a present null is distinct from a missing key', () => {
    const f = trackFixture({ present: null }, 'probe');
    // Present and null: readable, and its absence of value is the value.
    expect(f.get('present')).toBeNull();
    // has() reports presence, so an optional key can be consumed without
    // being required. A pointer-style check could not tell these apart.
    expect(f.has('present')).toBe(true);
    expect(f.has('absent')).toBe(false);
    expect(() => f.allConsumed()).not.toThrow();
  });

  test('has() marks an optional key consumed', () => {
    const f = trackFixture({ maybe: 3 }, 'probe');
    f.has('maybe');
    expect(() => f.allConsumed()).not.toThrow();
  });
});

describe('loadCriterion', () => {
  test('loads a real criterion with its inputs and expected_output', () => {
    const { inputs, expected } = loadCriterion('dashboard', 'frontend-dashboard', 'AC-07');
    expect(Array.isArray(inputs.cases)).toBe(true);
    expect(expected).toHaveProperty('forbidden_wording_occurrences');
  });

  test('a wrong spec id fails loudly rather than matching nothing', () => {
    expect(() => loadCriterion('dashboard', 'frontend-not-the-dashboard', 'AC-07')).toThrowError(
      /declares frontend-dashboard, expected frontend-not-the-dashboard/,
    );
  });

  test('an unknown acceptance criterion fails', () => {
    expect(() => loadCriterion('dashboard', 'frontend-dashboard', 'AC-999')).toThrowError(
      /AC-999 not found/,
    );
  });

  // The guard on the guard. If allConsumed became a no-op, every criterion
  // using it would keep passing while checking less, so this proves the
  // failure it is supposed to produce is really produced.
  test('a no-op allConsumed would not catch an unread key', () => {
    const noop = { allConsumed: () => undefined };
    // The stand-in silently accepts what the real one rejects.
    expect(() => noop.allConsumed()).not.toThrow();
    const real = trackFixture({ unread: 1 }, 'probe');
    expect(() => real.allConsumed()).toThrowError(/never asserted/);
  });
});
