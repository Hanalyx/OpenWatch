import { useEffect } from 'react';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import { useColorSchemeStore, type ColorScheme } from '@/store/useColorSchemeStore';
import {
  usePreferencesStore,
  type Density,
  type AccentColor,
  type LandingPage,
  type HostsViewDefault,
  type DateFormat,
} from '@/store/usePreferencesStore';
import { SettingsLayout } from '@/components/settings/SettingsLayout';
import {
  PageHead,
  Section,
  SettingCard,
  SettingRow,
  FirstSettingRow,
  Toggle,
  Segmented,
  Select,
} from '@/components/settings/primitives';

// Settings → Preferences — local-only, persisted in localStorage.

export function PreferencesPage() {
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);
  useEffect(() => {
    setCrumbs([{ label: 'Settings' }, { label: 'Preferences' }]);
    return () => setCrumbs([]);
  }, [setCrumbs]);

  return (
    <SettingsLayout>
      <PageHead
        title="Preferences"
        description="Personalize how OpenWatch looks and behaves for your account. Changes apply only to this browser."
      />
      <AppearanceSection />
      <DefaultsSection />
    </SettingsLayout>
  );
}

function AppearanceSection() {
  const mode = useColorSchemeStore((s) => s.mode);
  const setMode = useColorSchemeStore((s) => s.setMode);
  const density = usePreferencesStore((s) => s.density);
  const setDensity = usePreferencesStore((s) => s.setDensity);
  const accent = usePreferencesStore((s) => s.accentColor);
  const setAccent = usePreferencesStore((s) => s.setAccentColor);

  return (
    <Section title="Appearance">
      <SettingCard>
        <FirstSettingRow
          name="Theme"
          description="OpenWatch is designed for low-light NOC environments."
          control={
            <Segmented<ColorScheme>
              value={mode}
              options={[
                { value: 'light', label: 'Light' },
                { value: 'dark', label: 'Dark' },
                { value: 'system', label: 'System' },
              ]}
              onChange={setMode}
              ariaLabel="Theme"
            />
          }
        />
        <SettingRow
          name="Density"
          description="Compact fits more rows per screen on the Hosts and Rules tables."
          control={
            <Segmented<Density>
              value={density}
              options={[
                { value: 'comfortable', label: 'Comfortable' },
                { value: 'compact', label: 'Compact' },
              ]}
              onChange={setDensity}
              ariaLabel="Density"
            />
          }
        />
        <SettingRow
          name="Accent color"
          description="Used for primary actions and active states."
          control={
            <div style={{ display: 'flex', gap: 8 }}>
              <AccentSwatch
                tier="info"
                color="var(--ow-info)"
                active={accent === 'info'}
                onClick={() => setAccent('info')}
              />
              <AccentSwatch
                tier="ok"
                color="var(--ow-ok)"
                active={accent === 'ok'}
                onClick={() => setAccent('ok')}
              />
              <AccentSwatch
                tier="brand2"
                color="var(--ow-brand-2)"
                active={accent === 'brand2'}
                onClick={() => setAccent('brand2')}
              />
            </div>
          }
        />
      </SettingCard>
    </Section>
  );
}

function AccentSwatch({
  tier,
  color,
  active,
  onClick,
}: {
  tier: AccentColor;
  color: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-label={`Accent: ${tier}`}
      aria-pressed={active}
      onClick={onClick}
      style={{
        width: 24,
        height: 24,
        borderRadius: 6,
        background: color,
        border: 0,
        cursor: 'pointer',
        outline: active ? '2px solid var(--ow-fg-0)' : '2px solid transparent',
        outlineOffset: 2,
        padding: 0,
      }}
    />
  );
}

function DefaultsSection() {
  const landing = usePreferencesStore((s) => s.landingPage);
  const setLanding = usePreferencesStore((s) => s.setLandingPage);
  const hostsView = usePreferencesStore((s) => s.hostsViewDefault);
  const setHostsView = usePreferencesStore((s) => s.setHostsViewDefault);
  const dateFormat = usePreferencesStore((s) => s.dateFormat);
  const setDateFormat = usePreferencesStore((s) => s.setDateFormat);
  const reduceMotion = usePreferencesStore((s) => s.reduceMotion);
  const setReduceMotion = usePreferencesStore((s) => s.setReduceMotion);

  return (
    <Section title="Defaults">
      <SettingCard>
        <FirstSettingRow
          name="Landing page"
          description="Where OpenWatch takes you on sign-in."
          control={
            <Select
              value={landing}
              onChange={(v) => setLanding(v as LandingPage)}
              options={[
                { value: 'hosts', label: 'Hosts' },
                { value: 'dashboard', label: 'Dashboard' },
                { value: 'reports', label: 'Reports' },
              ]}
              ariaLabel="Landing page"
            />
          }
        />
        <SettingRow
          name="Default host view"
          description="Cards is the visual default; Table is denser."
          control={
            <Segmented<HostsViewDefault>
              value={hostsView}
              options={[
                { value: 'table', label: 'Table' },
                { value: 'cards', label: 'Cards' },
              ]}
              onChange={setHostsView}
              ariaLabel="Default host view"
            />
          }
        />
        <SettingRow
          name="Date & time format"
          description="How timestamps render across the app."
          control={
            <Select
              value={dateFormat}
              onChange={(v) => setDateFormat(v as DateFormat)}
              options={[
                { value: 'us12', label: '5/24/2026, 2:36 PM' },
                { value: 'iso24', label: '2026-05-24 14:36' },
                { value: 'long24', label: '24 May 2026, 14:36' },
              ]}
              ariaLabel="Date format"
            />
          }
        />
        <SettingRow
          name="Reduce motion"
          description="Minimize animations like the status-pulse and save bar."
          control={
            <Toggle value={reduceMotion} onChange={setReduceMotion} ariaLabel="Reduce motion" />
          }
        />
      </SettingCard>
    </Section>
  );
}
