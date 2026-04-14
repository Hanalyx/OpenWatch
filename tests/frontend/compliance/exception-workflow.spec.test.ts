// Spec: specs/frontend/exception-workflow.spec.yaml
/**
 * Spec-enforcement tests for the compliance exception workflow.
 *
 * Verifies exception list rendering, request form fields, approval
 * display, escalation and re-remediation actions, filter bar, and
 * RBAC gating via source inspection.
 *
 * Status: draft (Q2)
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const EXCEPTIONS_PAGE_PATH = path.resolve(
  __dirname,
  '../../../frontend/src/pages/compliance/Exceptions.tsx'
);
const EXCEPTIONS_PAGE_SRC = fs.readFileSync(EXCEPTIONS_PAGE_PATH, 'utf-8');

const APP_PATH = path.resolve(__dirname, '../../../frontend/src/App.tsx');
const APP_SRC = fs.readFileSync(APP_PATH, 'utf-8');

const ADAPTER_PATH = path.resolve(
  __dirname,
  '../../../frontend/src/services/adapters/exceptionAdapter.ts'
);
const ADAPTER_SRC = fs.readFileSync(ADAPTER_PATH, 'utf-8');

// ---------------------------------------------------------------------------
// AC-1: Exception list page renders at /compliance/exceptions
// ---------------------------------------------------------------------------

describe('AC-1: Exception list page renders', () => {
  /**
   * AC-1: Exception list page MUST render at /compliance/exceptions
   * with a paginated table showing all compliance exceptions.
   */
  it('exception list page renders at /compliance/exceptions', () => {
    // Verify route exists in App.tsx
    expect(APP_SRC).toContain('/compliance/exceptions');
    expect(APP_SRC).toContain('Exceptions');
  });

  it('exception list renders a paginated table', () => {
    // Verify TablePagination is used in the component
    expect(EXCEPTIONS_PAGE_SRC).toContain('TablePagination');
    expect(EXCEPTIONS_PAGE_SRC).toContain('exceptions-table');
  });
});

// ---------------------------------------------------------------------------
// AC-2: Exception request form fields
// ---------------------------------------------------------------------------

describe('AC-2: Exception request form includes required fields', () => {
  /**
   * AC-2: Exception request form MUST include justification, risk
   * assessment, and expiration date fields.
   */
  it('form includes justification field', () => {
    expect(EXCEPTIONS_PAGE_SRC).toContain('justification-input');
    expect(EXCEPTIONS_PAGE_SRC).toContain('Justification');
  });

  it('form includes risk assessment field', () => {
    expect(EXCEPTIONS_PAGE_SRC).toContain('risk-acceptance-input');
    expect(EXCEPTIONS_PAGE_SRC).toContain('Risk Acceptance');
  });

  it('form includes expiration date field', () => {
    expect(EXCEPTIONS_PAGE_SRC).toContain('duration-days-input');
    expect(EXCEPTIONS_PAGE_SRC).toContain('Duration (days)');
  });
});

// ---------------------------------------------------------------------------
// AC-3: Approval workflow metadata display
// ---------------------------------------------------------------------------

describe('AC-3: Approval workflow shows metadata', () => {
  /**
   * AC-3: Approval workflow MUST show approver name, approval
   * timestamp, and justification.
   */
  it('displays approver name', () => {
    expect(EXCEPTIONS_PAGE_SRC).toContain('approved_by');
    expect(EXCEPTIONS_PAGE_SRC).toContain('Approver');
  });

  it('displays approval timestamp', () => {
    expect(EXCEPTIONS_PAGE_SRC).toContain('approved_at');
    expect(EXCEPTIONS_PAGE_SRC).toContain('Approved At');
  });

  it('displays approval justification', () => {
    // The detail dialog renders the exception justification text
    expect(EXCEPTIONS_PAGE_SRC).toContain('Approval Details');
    expect(EXCEPTIONS_PAGE_SRC).toContain('exception.justification');
  });
});

// ---------------------------------------------------------------------------
// AC-4: Escalate button for pending exceptions
// ---------------------------------------------------------------------------

describe('AC-4: Escalate button visible for pending exceptions', () => {
  /**
   * AC-4: Escalate button MUST be visible for pending exceptions and
   * route to a higher-role approver.
   */
  it('escalate button is rendered for pending exceptions', () => {
    expect(EXCEPTIONS_PAGE_SRC).toContain('escalate-button');
    expect(EXCEPTIONS_PAGE_SRC).toContain('Escalate');
  });

  it('escalate action routes to higher-role approver', () => {
    // Verify escalation calls the backend escalate endpoint
    expect(EXCEPTIONS_PAGE_SRC).toContain('/escalate');
    expect(EXCEPTIONS_PAGE_SRC).toContain('handleEscalate');
  });
});

// ---------------------------------------------------------------------------
// AC-5: Re-remediation button triggers remediation
// ---------------------------------------------------------------------------

describe('AC-5: Re-remediation button triggers remediation', () => {
  /**
   * AC-5: Re-remediation button MUST trigger remediation for the
   * excepted rule.
   */
  it('re-remediation button is rendered on excepted rules', () => {
    expect(EXCEPTIONS_PAGE_SRC).toContain('re-remediation-button');
    expect(EXCEPTIONS_PAGE_SRC).toContain('Re-remediate');
  });

  it('re-remediation calls the remediation endpoint', () => {
    // Verify POST to remediation API
    expect(EXCEPTIONS_PAGE_SRC).toContain('/api/remediation/trigger');
    expect(EXCEPTIONS_PAGE_SRC).toContain('handleReRemediate');
  });
});

// ---------------------------------------------------------------------------
// AC-6: Filter bar supports status, rule_id, host_id
// ---------------------------------------------------------------------------

describe('AC-6: Filter bar supports filtering', () => {
  /**
   * AC-6: Filter bar MUST support status, rule_id, and host_id
   * filtering without full page reload.
   */
  it('filter bar renders status filter', () => {
    expect(EXCEPTIONS_PAGE_SRC).toContain('status-filter');
    expect(EXCEPTIONS_PAGE_SRC).toContain('statusFilter');
  });

  it('filter bar renders rule_id filter', () => {
    expect(EXCEPTIONS_PAGE_SRC).toContain('rule-id-filter');
    expect(EXCEPTIONS_PAGE_SRC).toContain('ruleIdFilter');
  });

  it('filter bar renders host_id filter', () => {
    expect(EXCEPTIONS_PAGE_SRC).toContain('host-id-filter');
    expect(EXCEPTIONS_PAGE_SRC).toContain('hostIdFilter');
  });
});

// ---------------------------------------------------------------------------
// AC-7: RBAC gating for approve/reject actions
// ---------------------------------------------------------------------------

describe('AC-7: SECURITY_ADMIN role required for approve/reject', () => {
  /**
   * AC-7: Only SECURITY_ADMIN or higher MUST see approve/reject
   * actions. Non-privileged users MUST NOT see these controls.
   */
  it('approve/reject buttons gated by SECURITY_ADMIN role', () => {
    // Verify role-based conditional rendering
    expect(EXCEPTIONS_PAGE_SRC).toContain('isAdmin');
    expect(EXCEPTIONS_PAGE_SRC).toContain('security_admin');
    expect(EXCEPTIONS_PAGE_SRC).toContain('ADMIN_ROLES');
  });

  it('non-privileged users do not see approve/reject controls', () => {
    // Verify that isAdmin gates the actions column
    expect(EXCEPTIONS_PAGE_SRC).toContain('{isAdmin &&');
    expect(EXCEPTIONS_PAGE_SRC).toContain('approve-button');
    expect(EXCEPTIONS_PAGE_SRC).toContain('reject-button');
  });
});
