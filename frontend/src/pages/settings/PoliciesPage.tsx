import { useEffect } from 'react';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import { SettingsLayout } from '@/components/settings/SettingsLayout';
import {
  PageHead,
  Section,
  SettingCard,
  BackendPendingBanner,
  Btn,
} from '@/components/settings/primitives';
import { ScanVariablesCard } from '@/components/settings/ScanVariablesCard';

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

      {/* ────────── Framework lenses (stub) ────────── */}
      <Section title="Framework lenses">
        <BackendPendingBanner
          slice="Framework registry endpoints"
          text="Framework enable/disable and the default lens are not configurable yet. Every framework found in the rule corpus is currently available as a lens."
        />
        <SettingCard>
          {[
            {
              name: 'Enabled frameworks',
              description:
                'CIS RHEL 9, STIG RHEL 9 V2R7, NIST 800-53 R5, PCI-DSS v4.0, FedRAMP Moderate.',
            },
            {
              name: 'Default lens',
              description: 'Which framework Hosts and Reports filter to by default.',
            },
          ].map((row, i) => (
            <div
              key={row.name}
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr minmax(180px, auto)',
                gap: 20,
                alignItems: 'center',
                padding: '16px 20px',
                borderTop: i === 0 ? 'none' : '1px solid var(--ow-line)',
                opacity: 0.7,
              }}
            >
              <div>
                <div style={{ fontWeight: 500, color: 'var(--ow-fg-0)' }}>{row.name}</div>
                <div
                  style={{ color: 'var(--ow-fg-2)', fontSize: 12, marginTop: 4, lineHeight: 1.5 }}
                >
                  {row.description}
                </div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <Btn disabled>Configure</Btn>
              </div>
            </div>
          ))}
        </SettingCard>
      </Section>

      {/* ────────── Exception workflow (stub) ────────── */}
      <Section title="Exception workflow">
        <BackendPendingBanner
          slice="Exception endpoints"
          text="Rule exceptions (approvals, expiry) are not built yet in the Go backend."
        />
        <SettingCard>
          {[
            { name: 'Approval levels', description: 'Who can approve a rule exception.' },
            {
              name: 'Expiry policy',
              description: 'Default duration before exceptions auto-expire.',
            },
          ].map((row, i) => (
            <div
              key={row.name}
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr minmax(180px, auto)',
                gap: 20,
                alignItems: 'center',
                padding: '16px 20px',
                borderTop: i === 0 ? 'none' : '1px solid var(--ow-line)',
                opacity: 0.7,
              }}
            >
              <div>
                <div style={{ fontWeight: 500, color: 'var(--ow-fg-0)' }}>{row.name}</div>
                <div
                  style={{ color: 'var(--ow-fg-2)', fontSize: 12, marginTop: 4, lineHeight: 1.5 }}
                >
                  {row.description}
                </div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <Btn disabled>Configure</Btn>
              </div>
            </div>
          ))}
        </SettingCard>
      </Section>
    </SettingsLayout>
  );
}
