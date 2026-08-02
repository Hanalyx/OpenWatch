// @spec frontend-remediation-tab
//
//   AC-10  a request that has not run shows what the fix would do

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, test } from 'vitest';

const read = (p: string) => readFileSync(resolve(process.cwd(), p), 'utf8');
const journal = read('src/components/hosts/RemediationJournal.tsx');
const hooks = read('src/hooks/useRemediationSteps.ts');

describe('frontend-remediation-tab AC-10 - preview before the fix runs', () => {
  // @ac AC-10
  test('frontend-remediation-tab/AC-10 - an unexecuted request shows the plan, not an empty panel', () => {
    // The old behaviour was a bare "No transaction yet". Deciding whether to
    // approve a fix needs what it WILL do, not only what it did.
    expect(journal).toContain('<PlanPreview');
    expect(journal).toMatch(/What it will change/);
    expect(journal).toMatch(/How it will be checked/);
    expect(journal).toMatch(/How it can be undone/);
  });

  // @ac AC-10
  test('frontend-remediation-tab/AC-10 - control-channel risk is stated as a consequence', () => {
    // Naming the flag tells an operator nothing. What matters is that the
    // change undoes itself if the host stops answering, which is the
    // difference between a risky fix and one that can strand you.
    expect(journal).toMatch(/reverts by itself if the host stops answering/i);
    expect(journal).not.toMatch(/control_channel_sensitive is true/i);
  });

  // @ac AC-10
  test('frontend-remediation-tab/AC-10 - a non-transactional rule warns that earlier steps stay applied', () => {
    expect(journal).toMatch(/earlier ones stay applied/i);
  });

  // @ac AC-10
  test('frontend-remediation-tab/AC-10 - a planning failure says nothing was changed', () => {
    // First question on seeing an error next to a Fix button is whether it
    // half-ran. Answer it without being asked.
    expect(journal).toMatch(/Nothing was changed on the host/i);
  });

  // @ac AC-10
  test('frontend-remediation-tab/AC-10 - the plan is live, never cached or retried', () => {
    // A remembered plan describes a host that has since moved on, and
    // retrying a failed plan hammers a host that is already not answering.
    expect(hooks).toMatch(/staleTime:\s*0/);
    expect(hooks).toMatch(/retry:\s*false/);
  });

  // @ac AC-10
  test('frontend-remediation-tab/AC-10 - Kensa summaries are shown verbatim, not restated', () => {
    // Falls back to the mechanism when a handler gave no summary rather than
    // inventing a description of it.
    expect(journal).toContain('it.summary ?? it.mechanism ?? it.name');
  });

  // @ac AC-10
  test('frontend-remediation-tab/AC-10 - no em dashes in the copy', () => {
    expect(journal).not.toMatch(/—/);
    expect(hooks).not.toMatch(/—/);
  });
});
