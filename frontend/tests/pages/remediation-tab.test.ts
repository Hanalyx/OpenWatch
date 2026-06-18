// @spec frontend-remediation-tab
//
// AC traceability (source inspection over the hook + ComplianceTab +
// RequestRemediationModal + HostDetailPage):
//   AC-01  useHostRemediations: query key, endpoint, derived sets
//   AC-02  Compliance tab per-rule affordance: gating, open-state
//          suppression, POST body, 409 inline, no em-dashes
//   AC-03  Remediation tab: approve/reject gating + invalidation,
//          atomic-model explainer, OpenWatch+ upsell, act endpoints
//          never referenced

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const read = (p: string) => readFileSync(resolve(process.cwd(), p), 'utf8');

const HOOK = read('src/hooks/useHostRemediations.ts');
const COMPLIANCE = read('src/pages/host-detail/ComplianceTab.tsx');
const MODAL = read('src/components/hosts/RequestRemediationModal.tsx');
const PAGE = read('src/pages/HostDetailPage.tsx');

describe('frontend-remediation-tab — source inspection', () => {
  // @ac AC-01
  test('frontend-remediation-tab/AC-01 — hook query key, endpoint, derived sets', () => {
    expect(HOOK).toContain("queryKey: ['host', hostId, 'remediations']");
    expect(HOOK).toContain("api.GET('/api/v1/remediation/requests'");
    expect(HOOK).toContain('query: { host_id: hostId }');
    // openRuleIds covers the in-flight statuses.
    expect(HOOK).toContain("'pending_approval'");
    expect(HOOK).toContain("'approved'");
    expect(HOOK).toContain("'dry_run_complete'");
    expect(HOOK).toContain("'executing'");
    // pendingRuleIds derives from pending_approval.
    expect(HOOK).toContain("r.status === 'pending_approval'");
    expect(HOOK).toContain('openRuleIds');
    expect(HOOK).toContain('pendingRuleIds');
  });

  // @ac AC-02
  test('frontend-remediation-tab/AC-02 — per-rule affordance gating, suppression, POST, 409', () => {
    // Gated on remediation:request.
    expect(COMPLIANCE).toContain("hasPermission)('remediation:request')");
    // Open-state suppression renders the "requested" pill instead of the action.
    expect(COMPLIANCE).toContain('remediationOpenRuleIds');
    expect(COMPLIANCE).toContain('Remediation requested');
    expect(COMPLIANCE).toContain('Request remediation');
    // Modal POSTs the create endpoint with {host_id, rule_id}.
    expect(MODAL).toContain("api.POST('/api/v1/remediation/requests'");
    expect(MODAL).toContain('host_id: hostId, rule_id: ruleId');
    // 409 maps to an inline message.
    expect(MODAL).toMatch(/response\.status === 409/);
    expect(MODAL).toContain('already been requested');
    // No em-dashes in the user-facing copy (project hard rule).
    expect(MODAL).not.toContain('—');
  });

  // @ac AC-03
  test('frontend-remediation-tab/AC-03 — tab gating, explainer, upsell, no act endpoints', () => {
    // Approve/Reject gated on remediation:approve.
    expect(PAGE).toContain("hasPermission('remediation:approve')");
    expect(PAGE).toContain('Awaiting approval');
    // Review POSTs the approve/reject endpoints and invalidates the host key.
    expect(PAGE).toContain('/api/v1/remediation/requests/{rid}:approve');
    expect(PAGE).toContain('/api/v1/remediation/requests/{rid}:reject');
    expect(PAGE).toContain("queryKey: ['host', hostId, 'remediations']");
    expect(PAGE).toMatch(/response\.status === 409/);
    // Atomic transaction model explainer (Capture -> Apply -> Validate -> Commit).
    expect(PAGE).toContain("['Capture', 'Apply', 'Validate', 'Commit']");
    // OpenWatch+ upsell, disabled, never wired to the act endpoints.
    expect(PAGE).toContain('Execute on host (OpenWatch+)');
    expect(PAGE).toContain('RemediationUpsell');
    expect(PAGE).not.toContain(':execute');
    expect(PAGE).not.toContain(':rollback');
    expect(PAGE).not.toContain(':dry-run');
  });
});
