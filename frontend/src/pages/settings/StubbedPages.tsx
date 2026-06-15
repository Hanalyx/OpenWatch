import { useEffect, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import api from '@/api/client';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import { useAuthStore } from '@/store/useAuthStore';
import { SettingsLayout } from '@/components/settings/SettingsLayout';
import {
  PageHead,
  Section,
  SettingCard,
  BackendPendingBanner,
  Btn,
  StatusPill,
} from '@/components/settings/primitives';
import { ForbiddenPage } from '@/pages/ForbiddenPage';

// Stubbed Settings pages.
//
// These render the prototype's structural shell — page-head + section
// titles + setting-card outlines — but the controls are disabled and a
// "Backend pending" banner identifies the slice that unblocks each one.
//
// Spec: frontend-settings (sections in includes:, banners in C-99).

function StubShell({
  title,
  description,
  slice,
  pendingText,
  crumb,
  children,
}: {
  title: string;
  description: string;
  slice: string;
  pendingText: string;
  crumb: string;
  children: ReactNode;
}) {
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);
  useEffect(() => {
    setCrumbs([{ label: 'Settings' }, { label: crumb }]);
    return () => setCrumbs([]);
  }, [setCrumbs, crumb]);

  return (
    <SettingsLayout>
      <PageHead title={title} description={description} />
      <BackendPendingBanner slice={slice} text={pendingText} />
      {children}
    </SettingsLayout>
  );
}

function StubCard({ rows }: { rows: { name: string; description: string }[] }) {
  return (
    <SettingCard>
      {rows.map((row, i) => (
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
            <div style={{ color: 'var(--ow-fg-2)', fontSize: 12, marginTop: 4, lineHeight: 1.5 }}>
              {row.description}
            </div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <Btn disabled>Configure</Btn>
          </div>
        </div>
      ))}
    </SettingCard>
  );
}

// ── Integrations ────────────────────────────────────────────────────────
export function IntegrationsPage() {
  return (
    <StubShell
      title="Integrations"
      description="Connect OpenWatch to your ticketing, observability, and identity tools."
      slice="Slice D (integrations API)"
      pendingText="Connector framework not yet shipped."
      crumb="Integrations"
    >
      <Section title="Available">
        <StubCard
          rows={[
            { name: 'Jira', description: 'Create tickets from compliance findings.' },
            { name: 'PagerDuty', description: 'Page on critical alerts.' },
            { name: 'Splunk', description: 'Forward audit events.' },
            { name: 'Grafana', description: 'Expose fleet metrics.' },
          ]}
        />
      </Section>
    </StubShell>
  );
}

// ── Security & auth ─────────────────────────────────────────────────────
export function SecurityPage() {
  const isAdmin = useAuthStore((s) => s.hasPermission('admin'));
  if (!isAdmin) return <ForbiddenPage />;
  return (
    <StubShell
      title="Security & auth"
      description="Single sign-on, authentication policies, and API tokens for the workspace."
      slice="Slice C (SSO + auth policy)"
      pendingText="OIDC/SAML configuration and authentication-policy endpoints pending."
      crumb="Security & auth"
    >
      <Section title="Single sign-on">
        <StubCard
          rows={[
            {
              name: 'OIDC provider',
              description: 'Configure the identity provider (Okta, Auth0, Google, Azure AD, etc.).',
            },
            { name: 'SAML provider', description: 'SP-initiated and IdP-initiated flows.' },
          ]}
        />
      </Section>
      <Section title="Authentication policy">
        <StubCard
          rows={[
            { name: 'Require MFA', description: 'Enforce TOTP for every member.' },
            { name: 'Session timeout', description: 'Idle and absolute session limits.' },
          ]}
        />
      </Section>
      <Section title="API tokens">
        <StubCard
          rows={[
            { name: 'Service tokens', description: 'Create long-lived tokens for automation.' },
          ]}
        />
      </Section>
    </StubShell>
  );
}

// ── About ───────────────────────────────────────────────────────────────
const LICENSE_TIER_LABEL: Record<string, string> = {
  free: 'Free',
  openwatch_plus: 'OpenWatch+',
  enterprise: 'Enterprise',
};
const LICENSE_STATUS: Record<string, { label: string; tier: 'ok' | 'warn' | 'crit' }> = {
  active: { label: 'Active', tier: 'ok' },
  grace: { label: 'Grace period', tier: 'warn' },
  expired: { label: 'Expired', tier: 'crit' },
  no_license: { label: 'No license', tier: 'warn' },
  invalid: { label: 'Invalid', tier: 'crit' },
};

export function AboutPage() {
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);
  useEffect(() => {
    setCrumbs([{ label: 'Settings' }, { label: 'About' }]);
    return () => setCrumbs([]);
  }, [setCrumbs]);

  // Versions come from the live binary (GET /api/v1/version) — never hardcoded.
  // OpenWatch is ldflags-injected; Kensa + Go are read from the binary's build
  // info / runtime at request time.
  const versionQuery = useQuery({
    queryKey: ['version'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/version');
      if (error) throw error;
      return data!;
    },
    staleTime: 5 * 60 * 1000,
  });
  const v = versionQuery.data;

  // License state from the live binary (GET /api/v1/license) — tier, status,
  // and entitled features are read at request time, never hardcoded.
  const licenseQuery = useQuery({
    queryKey: ['license'],
    queryFn: async () => {
      const { data, error } = await api.GET('/api/v1/license');
      if (error) throw error;
      return data!;
    },
    staleTime: 5 * 60 * 1000,
  });
  const lic = licenseQuery.data;

  return (
    <SettingsLayout>
      <PageHead
        title="About"
        description="Version, license, and support information for this OpenWatch deployment."
      />
      <Section title="Version">
        <SettingCard>
          <div
            style={{
              padding: 20,
              display: 'grid',
              gridTemplateColumns: '180px 1fr',
              rowGap: 10,
              fontSize: 13,
            }}
          >
            <span style={{ color: 'var(--ow-fg-2)' }}>OpenWatch</span>
            <span style={{ fontFamily: 'var(--ow-font-mono)' }}>{v ? v.openwatch : '…'}</span>
            <span style={{ color: 'var(--ow-fg-2)' }}>Kensa</span>
            <span style={{ fontFamily: 'var(--ow-font-mono)' }}>{v ? v.kensa : '…'}</span>
            <span style={{ color: 'var(--ow-fg-2)' }}>Go</span>
            <span style={{ fontFamily: 'var(--ow-font-mono)' }}>{v ? v.go : '…'}</span>
            <span style={{ color: 'var(--ow-fg-2)' }}>Build</span>
            <span style={{ fontFamily: 'var(--ow-font-mono)' }}>
              {v ? `${v.commit} · ${v.build_time}` : '…'}
            </span>
          </div>
        </SettingCard>
      </Section>
      <Section title="License">
        <SettingCard>
          {licenseQuery.isError ? (
            <div role="alert" style={{ padding: 20, color: 'var(--ow-fg-1)', fontSize: 13 }}>
              Failed to load license state.
            </div>
          ) : (
            <div
              style={{
                padding: 20,
                display: 'grid',
                gridTemplateColumns: '180px 1fr',
                rowGap: 12,
                alignItems: 'center',
                fontSize: 13,
              }}
            >
              <span style={{ color: 'var(--ow-fg-2)' }}>Tier</span>
              <span>{lic ? (LICENSE_TIER_LABEL[lic.tier] ?? lic.tier) : '…'}</span>

              <span style={{ color: 'var(--ow-fg-2)' }}>Status</span>
              <span>
                {lic ? (
                  <StatusPill tier={LICENSE_STATUS[lic.status]?.tier ?? 'warn'}>
                    {LICENSE_STATUS[lic.status]?.label ?? lic.status}
                  </StatusPill>
                ) : (
                  '…'
                )}
              </span>

              {lic?.customer_id ? (
                <>
                  <span style={{ color: 'var(--ow-fg-2)' }}>Customer</span>
                  <span style={{ fontFamily: 'var(--ow-font-mono)' }}>{lic.customer_id}</span>
                </>
              ) : null}

              {lic?.expires_at ? (
                <>
                  <span style={{ color: 'var(--ow-fg-2)' }}>Expires</span>
                  <span>
                    {new Date(lic.expires_at).toLocaleDateString()}
                    {lic.in_grace_period ? (
                      <span style={{ color: 'var(--ow-warn)', marginLeft: 8, fontSize: 12 }}>
                        (in grace period)
                      </span>
                    ) : null}
                  </span>
                </>
              ) : null}

              <span style={{ color: 'var(--ow-fg-2)', alignSelf: 'start' }}>Features</span>
              <span>
                {lic && lic.features.length > 0 ? (
                  <span style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {lic.features.map((f) => (
                      <span
                        key={f}
                        style={{
                          padding: '2px 8px',
                          borderRadius: 'var(--ow-radius-sm)',
                          background: 'var(--ow-bg-3)',
                          color: 'var(--ow-fg-1)',
                          fontSize: 12,
                          fontFamily: 'var(--ow-font-mono)',
                        }}
                      >
                        {f}
                      </span>
                    ))}
                  </span>
                ) : (
                  <span style={{ color: 'var(--ow-fg-3)' }}>
                    {lic ? 'No paid features entitled' : '…'}
                  </span>
                )}
              </span>
            </div>
          )}
        </SettingCard>
      </Section>
    </SettingsLayout>
  );
}
