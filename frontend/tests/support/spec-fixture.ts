// Shared reader for spec-driven frontend criteria.
//
// A criterion's inputs and expected_output live in the tracked spec, and a
// test that restates them proves the code agrees with the test rather than
// with the contract. These helpers load the YAML and record which keys were
// read, so an unconsumed field fails instead of sitting decoratively.
//
// One module rather than a copy per test file: three copies of a fixture
// loader drift, and the drift is invisible until one of them stops checking
// something the others still do.

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect } from 'vitest';
import yaml from 'js-yaml';

export type AnyRec = Record<string, unknown>;

/** trackFixture wraps a fixture object and records which keys were read. */
export function trackFixture(obj: AnyRec, label: string) {
  const seen = new Set<string>();
  return {
    get<T>(key: string): T {
      if (!(key in obj)) throw new Error(`${label}: fixture has no key ${key}`);
      seen.add(key);
      return obj[key] as T;
    },
    has(key: string) {
      seen.add(key);
      return key in obj;
    },
    allConsumed() {
      const missed = Object.keys(obj).filter((k) => !seen.has(k));
      expect(missed, `${label}: fixture keys never asserted`).toEqual([]);
    },
  };
}

/** The parts of a spec whose prose makes ACTIVE claims about the product. */
export type SpecProse = {
  contextDescription: string;
  objectiveSummary: string;
  scopeIncludes: string[];
};

/**
 * loadSpecProse returns a spec's active prose, excluding its constraints and
 * criteria.
 *
 * A criterion can forbid a claim in rendered copy while the spec's own
 * context, objective and scope keep making it. Those three are where a reader
 * learns what the product does, so a guard over rendered strings alone leaves
 * the claim standing in the place most likely to be quoted.
 */
export function loadSpecProse(file: string, specId: string): SpecProse {
  const doc = yaml.load(
    readFileSync(resolve(process.cwd(), `../specs/frontend/${file}.spec.yaml`), 'utf8'),
  ) as {
    spec: {
      id: string;
      context?: { description?: string };
      objective?: { summary?: string; scope?: { includes?: string[] } };
    };
  };
  if (doc.spec.id !== specId) {
    throw new Error(`${file}.spec.yaml declares ${doc.spec.id}, expected ${specId}`);
  }
  return {
    contextDescription: doc.spec.context?.description ?? '',
    objectiveSummary: doc.spec.objective?.summary ?? '',
    scopeIncludes: doc.spec.objective?.scope?.includes ?? [],
  };
}

/**
 * loadCriterion reads one acceptance criterion from a tracked frontend spec.
 *
 * file is the spec basename under specs/frontend, specId is asserted so a
 * renamed spec fails loudly rather than silently matching nothing.
 */
export function loadCriterion(
  file: string,
  specId: string,
  acId: string,
): { inputs: AnyRec; expected: AnyRec } {
  const doc = yaml.load(
    readFileSync(resolve(process.cwd(), `../specs/frontend/${file}.spec.yaml`), 'utf8'),
  ) as { spec: { id: string; acceptance_criteria: AnyRec[] } };
  if (doc.spec.id !== specId) {
    throw new Error(`${file}.spec.yaml declares ${doc.spec.id}, expected ${specId}`);
  }
  const ac = doc.spec.acceptance_criteria.find((a) => a.id === acId);
  if (!ac) throw new Error(`${acId} not found in ${specId}`);
  return { inputs: (ac.inputs ?? {}) as AnyRec, expected: (ac.expected_output ?? {}) as AnyRec };
}
