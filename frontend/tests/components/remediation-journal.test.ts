// @spec frontend-remediation-tab
//
//   AC-09  the transaction journal is shown, and its consequences are worded

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, test } from 'vitest';

import { phaseLabel, phaseNote } from '@/hooks/useRemediationSteps';

const read = (p: string) => readFileSync(resolve(process.cwd(), p), 'utf8');

type Phase = Parameters<typeof phaseNote>[0];

const phase = (over: Partial<Phase> = {}): Phase => ({
  index: 0,
  mechanism: 'config_set',
  success: true,
  capturable: true,
  staged: false,
  stranded: false,
  ...over,
});

describe('frontend-remediation-tab AC-09 - the journal is shown, not described', () => {
  test('the four-phase transaction is named by phase, not by mechanism', () => {
    const four = [0, 1, 2, 3].map((index) => phase({ index }));
    expect(four.map((p) => phaseLabel(p, 4))).toEqual(['Capture', 'Apply', 'Validate', 'Commit']);
  });

  test('a transaction that is not four phases falls back to the mechanism', () => {
    // Inventing a phase name for a shape we do not recognise would be a
    // confident guess presented as fact. The mechanism is at least true.
    expect(phaseLabel(phase({ index: 4, mechanism: 'audit_ruleset' }), 6)).toBe('audit_ruleset');
  });

  test('stranded says rollback will not reverse it', () => {
    const note = phaseNote(phase({ stranded: true, capturable: false }));
    expect(note).toMatch(/not reversed by rollback/i);
  });

  test('staged says the running host has not changed yet', () => {
    // The dangerous reading is "done". A staged change leaves the host
    // unprotected until reboot, and a re-scan still reports the rule failing.
    const note = phaseNote(phase({ staged: true }));
    expect(note).toMatch(/has not changed/i);
    expect(note).toMatch(/reboot/i);
  });

  test('a successful ordinary phase says nothing extra', () => {
    expect(phaseNote(phase())).toBeNull();
  });

  test('stranded outranks staged when a phase is both', () => {
    // Both can be true on one step. Not-reversed-by-rollback is the one that
    // changes what the operator must do next.
    const note = phaseNote(phase({ stranded: true, staged: true }));
    expect(note).toMatch(/not reversed by rollback/i);
  });
});

describe('frontend-remediation-tab AC-09 - pre-state is evidence, not interpretation', () => {
  const journal = read('src/components/hosts/RemediationJournal.tsx');

  test('captured data is rendered verbatim, never decoded per mechanism', () => {
    // Decoding it here would couple this component to Kensa handler internals
    // and break silently when a handler changes its layout.
    expect(journal).toContain('JSON.stringify(e.data, null, 2)');
    expect(journal).toMatch(/KN-OW-016/);
  });

  test('a non-capturable capture is still shown, as a gap', () => {
    expect(journal).toMatch(/not restorable/i);
  });

  test('the detail Kensa returned is rendered', () => {
    expect(journal).toContain('phase.detail');
  });

  test('no em dashes in the copy', () => {
    expect(journal).not.toMatch(/—/);
    expect(read('src/hooks/useRemediationSteps.ts')).not.toMatch(/—/);
  });
});
