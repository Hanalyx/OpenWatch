import { useEffect } from 'react';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import { SettingsLayout } from '@/components/settings/SettingsLayout';
import { PageHead, Section, BackendPendingBanner } from '@/components/settings/primitives';
import { ScanVariablesCard } from '@/components/settings/ScanVariablesCard';
import { DefaultLensCard } from '@/components/settings/DefaultLensCard';
import { ExceptionQueue } from '@/components/settings/ExceptionQueue';

// Settings → Compliance policies.
//
// Wiring honesty:
//
//   • Scan variables       — LIVE against GET/PUT /api/v1/system/scan/
//                             variables. The values define WHAT
//                             compliant means for the organization
//                             (rule-template policy content), which is
//                             why they live here rather than on the
//                             Scanning page (cadence).
//   • Framework lenses     — stub. Framework registry endpoints pending.
//   • Exception workflow   — stub. Exception endpoints pending.
//
// Spec: frontend-settings-scan-config (scan variables section) +
// frontend-settings (stub sections).
export function PoliciesPage() {
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);
  useEffect(() => {
    setCrumbs([{ label: 'Settings' }, { label: 'Compliance policies' }]);
    return () => setCrumbs([]);
  }, [setCrumbs]);

  return (
    <SettingsLayout>
      <PageHead
        title="Compliance policies"
        description="What compliant means for your organization: rule-template values, framework lenses, and the exception workflow."
      />

      {/* ────────── Scan variables (LIVE) ────────── */}
      <Section title="Scan variables" badge="Live" badgeTier="ok">
        <ScanVariablesCard />
      </Section>

      {/* ────────── Framework lenses ────────── */}
      <Section title="Framework lenses" badge="Live" badgeTier="ok">
        <p style={{ margin: '0 0 12px', color: 'var(--ow-fg-2)', fontSize: 13, lineHeight: 1.5 }}>
          Scans always run the full Kensa rule corpus; a framework lens is a read-time view over
          those results. Set the default lens the compliance scores (dashboard, hosts, host detail)
          use out of the box. "All rules" keeps the framework-agnostic Kensa score. Individual host
          views can still switch lens.
        </p>
        <DefaultLensCard />
        <div style={{ marginTop: 12 }}>
          <BackendPendingBanner
            slice="Enabled frameworks"
            text="Hiding frameworks you don't use (an allowlist) is a follow-up. Today every framework found in the corpus is available as a lens."
          />
        </div>
      </Section>

      {/* ────────── Exception workflow (LIVE) ────────── */}
      <Section title="Exception workflow" badge="Live" badgeTier="ok">
        <p
          style={{
            margin: '0 0 12px',
            color: 'var(--ow-fg-2)',
            fontSize: 13,
            lineHeight: 1.5,
          }}
        >
          Operator-approved rule waivers across the fleet. Approving an exception records accepted
          risk: the rule still fails in scans (the raw verdict is unchanged), but the failure is
          marked waived everywhere it surfaces. Pending requests need an approver
          (exception:approve); active exceptions can be revoked before they expire
          (exception:revoke).
        </p>
        <ExceptionQueue />
      </Section>
    </SettingsLayout>
  );
}
