// @spec frontend-remediation-tab
//
// AC traceability (source inspection over the hook + ComplianceTab +
// RequestRemediationModal + HostDetailPage):
//   AC-01  useHostRemediations: query key, endpoint, derived sets
//   AC-02  Compliance tab per-rule affordance: gating, open-state
//          suppression, POST body, 409 inline, no em-dashes
//   AC-03  Remediation tab: approve/reject gating + invalidation,
//          atomic-model explainer
//   AC-04  Approved row: Fix button gated on remediation:execute||isAdmin
//          POSTing :execute, invalidate, 409 inline message
//   AC-05  Executed row: Fixed status + Roll back gated on
//          remediation:rollback||isAdmin POSTing :rollback
//   AC-06  Lifecycle status rendering + executing poll
//   AC-07  Bulk/automated OpenWatch+ upsell replaces the single-rule one

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const read = (p: string) => readFileSync(resolve(process.cwd(), p), 'utf8');

const HOOK = read('src/hooks/useHostRemediations.ts');
const COMPLIANCE = read('src/pages/host-detail/ComplianceTab.tsx');
const MODAL = read('src/components/hosts/RequestRemediationModal.tsx');
const PAGE = read('src/pages/HostDetailPage.tsx');

// The remediation tab + row action region of HostDetailPage. Used for
// presence assertions (Fix / Roll back / status labels) scoped to the
// tab rather than the (large) page file.
const TAB_REGION = PAGE.slice(
  PAGE.indexOf('function RemediationTab('),
  PAGE.indexOf('function RemTh('),
);

// The prose-bearing copy of the tab (explainer + upsell). The no-em-dash
// rule governs user-facing prose; the bare em-dash glyph is the codebase
// empty-value placeholder convention (used in table cells), not copy, so
// the prose slices below are what the rule applies to.
const EXPLAINER = PAGE.slice(
  PAGE.indexOf('function RemediationExplainer('),
  PAGE.indexOf('function RemediationRowAction('),
);
const UPSELL = PAGE.slice(
  PAGE.indexOf('function RemediationUpsell('),
  PAGE.indexOf('function RemTh('),
);

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
  test('frontend-remediation-tab/AC-03 — tab gating, explainer', () => {
    // Approve/Reject gated on remediation:approve (|| isAdmin).
    expect(PAGE).toContain("hasPermission('remediation:approve')");
    expect(PAGE).toContain('Awaiting approval');
    // Review POSTs the approve/reject endpoints and invalidates the host key.
    expect(PAGE).toContain('/api/v1/remediation/requests/{rid}:approve');
    expect(PAGE).toContain('/api/v1/remediation/requests/{rid}:reject');
    expect(PAGE).toContain("queryKey: ['host', hostId, 'remediations']");
    expect(PAGE).toMatch(/response\.status === 409/);
    // Atomic transaction model explainer (Capture -> Apply -> Validate -> Commit).
    expect(PAGE).toContain("['Capture', 'Apply', 'Validate', 'Commit']");
  });

  // @ac AC-04
  test('frontend-remediation-tab/AC-04 — approved row Fix button posts :execute, gated, 409 inline', () => {
    // isAdmin computed from the admin permission, mirrored across the act gates.
    expect(PAGE).toContain("useAuthStore((s) => s.hasPermission('admin'))");
    expect(PAGE).toContain(
      "useAuthStore((s) => s.hasPermission('remediation:execute')) || isAdmin",
    );
    // The Fix button posts :execute.
    expect(PAGE).toContain('/api/v1/remediation/requests/{rid}:execute');
    expect(TAB_REGION).toContain('Fix');
    // Approved state branch + canExecute gate.
    expect(PAGE).toContain("request.status === 'approved'");
    expect(PAGE).toContain('canExecute');
    expect(PAGE).toContain("act.mutate('execute')");
    // 409 surfaces the specific inline message via apiErrorMessage.
    expect(PAGE).toContain('This request is not in an approvable state.');
  });

  // @ac AC-05
  test('frontend-remediation-tab/AC-05 — executed row Fixed status + Roll back posts :rollback', () => {
    expect(PAGE).toContain(
      "useAuthStore((s) => s.hasPermission('remediation:rollback')) || isAdmin",
    );
    expect(PAGE).toContain("request.status === 'executed'");
    expect(TAB_REGION).toContain('Fixed');
    expect(TAB_REGION).toContain('Roll back');
    expect(PAGE).toContain('canRollback');
    expect(PAGE).toContain('/api/v1/remediation/requests/{rid}:rollback');
    expect(PAGE).toContain("act.mutate('rollback')");
    // Both act mutations invalidate the host remediations key.
    expect(PAGE).toContain("queryKey: ['host', hostId, 'remediations']");
  });

  // @ac AC-06
  test('frontend-remediation-tab/AC-06 — lifecycle status rendering + executing poll', () => {
    expect(PAGE).toContain("request.status === 'executing'");
    expect(TAB_REGION).toContain('Applying...');
    expect(PAGE).toContain("request.status === 'rolled_back'");
    expect(TAB_REGION).toContain('Rolled back');
    expect(PAGE).toContain("request.status === 'failed'");
    expect(TAB_REGION).toContain('Failed');
    // Failure reason surfaced from review_note when present.
    expect(PAGE).toContain('request.review_note');
    // The hook polls while any request is executing.
    expect(HOOK).toContain('refetchInterval');
    expect(HOOK).toContain("r.status === 'executing'");
  });

  // @ac AC-07
  test('frontend-remediation-tab/AC-07 — bulk/auto upsell replaces single-rule upsell, no em-dash', () => {
    expect(PAGE).toContain('RemediationUpsell');
    expect(PAGE).toContain('Bulk and automated remediation (OpenWatch+)');
    // The old single-rule execute upsell copy is gone.
    expect(PAGE).not.toContain('Execute on host (OpenWatch+)');
    // No em-dashes in the user-facing prose (project hard rule). The bare
    // em-dash placeholder glyph in table cells is a separate convention.
    expect(EXPLAINER).not.toContain('—');
    expect(UPSELL).not.toContain('—');
  });
});
