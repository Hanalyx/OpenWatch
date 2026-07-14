// @spec frontend-settings-exception-queue
//
// AC traceability (source inspection over ExceptionQueue + PoliciesPage):
//   AC-01  query key + endpoints + invalidation
//   AC-02  permission-gated actions
//   AC-03  409 inline + host link + stub removed
//   AC-04  lapsed indicator on a past-expiry pending row

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const SRC = readFileSync(
  resolve(process.cwd(), 'src/components/settings/ExceptionQueue.tsx'),
  'utf8',
);
const POLICIES = readFileSync(
  resolve(process.cwd(), 'src/pages/settings/PoliciesPage.tsx'),
  'utf8',
);

describe('frontend-settings-exception-queue — source inspection', () => {
  // @ac AC-01
  test('frontend-settings-exception-queue/AC-01 — query key, endpoints, default pending, invalidation', () => {
    expect(SRC).toContain("queryKey: ['compliance', 'exceptions', status]");
    expect(SRC).toContain("api.GET('/api/v1/compliance/exceptions'");
    expect(SRC).toContain("useState<'' | Exception['status']>('requested')");
    expect(SRC).toContain('/api/v1/exceptions/{xid}:${vars.action}');
    expect(SRC).toContain(
      "queryClient.invalidateQueries({ queryKey: ['compliance', 'exceptions'] })",
    );
  });

  // @ac AC-02
  test('frontend-settings-exception-queue/AC-02 — permission-gated approve/reject/revoke', () => {
    expect(SRC).toContain("hasPermission('exception:approve')");
    expect(SRC).toContain("hasPermission('exception:revoke')");
    // Approve/Reject only on requested rows under canApprove.
    expect(SRC).toContain("e.status === 'requested' && canApprove");
    // Revoke only on approved rows under canRevoke.
    expect(SRC).toContain("e.status === 'approved' && canRevoke");
    // Terminal / non-actionable rows render a dash.
    expect(SRC).toContain("['rejected', 'revoked', 'expired'].includes(e.status)");
  });

  // @ac AC-03
  test('frontend-settings-exception-queue/AC-03 — 409 inline, host link, stub removed', () => {
    expect(SRC).toContain('already changed state');
    expect(SRC).toMatch(/response\.status === 409/);
    // Host cell links to the host detail with host_name.
    expect(SRC).toContain('to="/hosts/$hostId"');
    expect(SRC).toContain('{e.host_name || e.host_id}');
    // PoliciesPage mounts the queue and the exception section no longer
    // carries the pending banner.
    expect(POLICIES).toContain('<ExceptionQueue />');
    const section = POLICIES.slice(POLICIES.indexOf('Exception workflow (LIVE)'), POLICIES.length);
    expect(section).not.toContain('BackendPendingBanner');
  });

  // @ac AC-04
  test('frontend-settings-exception-queue/AC-04 — lapsed indicator on a past-expiry pending row', () => {
    // A requested row whose expires_at is already in the past is marked lapsed.
    expect(SRC).toContain("e.status === 'requested'");
    expect(SRC).toMatch(/new Date\(e\.expires_at\)\.getTime\(\) <= Date\.now\(\)/);
    expect(SRC).toContain('(lapsed)');
  });
});
