import { describe, it, expect } from 'vitest';
import { adaptComplianceRule, adaptComplianceRulesPage } from '../complianceAdapter';
import type { ApiComplianceRule, ApiComplianceRulesPage } from '../complianceAdapter';

describe('adaptComplianceRule', () => {
  it('maps all fields from snake_case to camelCase', () => {
    const api: ApiComplianceRule = {
      rule_id: 'xccdf_ssg_rule_enable_fips',
      title: 'Enable FIPS Mode',
      description: 'The system must enable FIPS 140-2 mode.',
      severity: 'high',
      platform_implementations: { rhel9: { bash: 'fips-mode-setup --enable' } },
      nist_r4_controls: ['SC-13'],
      nist_r5_controls: ['SC-13'],
      cis_controls: ['3.11'],
      stigid: 'RHEL-09-123456',
    };
    const rule = adaptComplianceRule(api);
    expect(rule.ruleId).toBe('xccdf_ssg_rule_enable_fips');
    expect(rule.title).toBe('Enable FIPS Mode');
    expect(rule.description).toBe('The system must enable FIPS 140-2 mode.');
    expect(rule.severity).toBe('high');
    expect(rule.platformImplementations).toEqual({ rhel9: { bash: 'fips-mode-setup --enable' } });
    expect(rule.nistR4Controls).toEqual(['SC-13']);
    expect(rule.nistR5Controls).toEqual(['SC-13']);
    expect(rule.cisControls).toEqual(['3.11']);
    expect(rule.stigId).toBe('RHEL-09-123456');
  });

  it('handles minimal rule with only required fields', () => {
    const rule = adaptComplianceRule({
      rule_id: 'r1',
      title: 'Test Rule',
    });
    expect(rule.ruleId).toBe('r1');
    expect(rule.title).toBe('Test Rule');
    expect(rule.description).toBeUndefined();
    expect(rule.nistR4Controls).toBeUndefined();
  });
});

describe('adaptComplianceRulesPage', () => {
  it('transforms paginated response', () => {
    const api: ApiComplianceRulesPage = {
      data: [
        { rule_id: 'r1', title: 'Rule 1' },
        { rule_id: 'r2', title: 'Rule 2' },
      ],
      total_count: 42,
      page: 1,
      page_size: 20,
    };
    const page = adaptComplianceRulesPage(api);
    expect(page.data).toHaveLength(2);
    expect(page.data[0].ruleId).toBe('r1');
    expect(page.total).toBe(42);
    expect(page.page).toBe(1);
    expect(page.pageSize).toBe(20);
  });
});
