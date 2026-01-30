import { describe, it, expect } from 'vitest';
import { adaptRuleResult, adaptRuleResults } from '../scanAdapter';
import type { ApiRuleResult } from '../scanAdapter';

describe('adaptRuleResult', () => {
  it('maps a fully-populated rule', () => {
    const api: ApiRuleResult = {
      rule_id: 'xccdf_rule_001',
      title: 'Ensure SSH root login is disabled',
      severity: 'high',
      result: 'fail',
      description: 'Root login via SSH should be disabled.',
      rationale: 'Prevents brute-force attacks on root.',
      remediation: 'Set PermitRootLogin no in sshd_config.',
    };
    const rule = adaptRuleResult(api);
    expect(rule.ruleId).toBe('xccdf_rule_001');
    expect(rule.title).toBe('Ensure SSH root login is disabled');
    expect(rule.severity).toBe('high');
    expect(rule.result).toBe('fail');
    expect(rule.description).toBe('Root login via SSH should be disabled.');
    expect(rule.rationale).toBe('Prevents brute-force attacks on root.');
    expect(rule.remediation).toBe('Set PermitRootLogin no in sshd_config.');
  });

  it('normalizes valid severity values', () => {
    expect(adaptRuleResult({ severity: 'high' }).severity).toBe('high');
    expect(adaptRuleResult({ severity: 'medium' }).severity).toBe('medium');
    expect(adaptRuleResult({ severity: 'low' }).severity).toBe('low');
  });

  it('defaults unknown severity to unknown', () => {
    expect(adaptRuleResult({ severity: 'critical' }).severity).toBe('unknown');
    expect(adaptRuleResult({ severity: '' }).severity).toBe('unknown');
    expect(adaptRuleResult({}).severity).toBe('unknown');
  });

  it('normalizes valid result values', () => {
    expect(adaptRuleResult({ result: 'pass' }).result).toBe('pass');
    expect(adaptRuleResult({ result: 'fail' }).result).toBe('fail');
    expect(adaptRuleResult({ result: 'error' }).result).toBe('error');
    expect(adaptRuleResult({ result: 'notapplicable' }).result).toBe('notapplicable');
  });

  it('defaults unrecognized result to unknown', () => {
    expect(adaptRuleResult({ result: 'informational' }).result).toBe('unknown');
    expect(adaptRuleResult({}).result).toBe('unknown');
  });

  it('defaults missing fields', () => {
    const rule = adaptRuleResult({});
    expect(rule.ruleId).toBe('unknown');
    expect(rule.title).toBe('');
    expect(rule.description).toBe('');
    expect(rule.rationale).toBeUndefined();
    expect(rule.remediation).toBeUndefined();
  });
});

describe('adaptRuleResults', () => {
  it('maps an array of rule results', () => {
    const rules = adaptRuleResults([
      { rule_id: 'r1', severity: 'high', result: 'pass' },
      { rule_id: 'r2', severity: 'low', result: 'fail' },
    ]);
    expect(rules).toHaveLength(2);
    expect(rules[0].ruleId).toBe('r1');
    expect(rules[1].ruleId).toBe('r2');
  });

  it('returns empty array for empty input', () => {
    expect(adaptRuleResults([])).toEqual([]);
  });
});
