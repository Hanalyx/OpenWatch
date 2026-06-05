// @spec frontend-settings-intelligence-config
//
// AC traceability (this file):
//
//   AC-01  test('frontend-settings-intelligence-config/AC-01 — useQuery wired to /system/intelligence/config with ["system","intelligence","config"] key')
//   AC-02  test('frontend-settings-intelligence-config/AC-02 — Cancel resets to config, Reset-to-defaults resets to defaults (distinct paths)')
//   AC-03  test('frontend-settings-intelligence-config/AC-03 — Stepper bounds: interval_sec 300..86400, rate_limit 1..200')
//   AC-04  test('frontend-settings-intelligence-config/AC-04 — save mutation invalidates the right query key; Save disabled triple-checked')
//   AC-05  test('frontend-settings-intelligence-config/AC-05 — visual states: loading, error, success-clean')
//   AC-06  test('frontend-settings-intelligence-config/AC-06 — edit -> Save flow toggles dirty/disabled')
//   AC-07  test('frontend-settings-intelligence-config/AC-07 — ScanningPage mounts OSIntelligenceSection between OS discovery and Maintenance')
//   AC-08  test('frontend-settings-intelligence-config/AC-08 — error alert surfaces the HTTP status (no "Failed to load — Failed to load")')
//   AC-09  test('frontend-settings-intelligence-config/AC-09 — error state renders a Retry button that invokes onRetry')
//   AC-10  test('frontend-settings-intelligence-config/AC-10 — post-save useEffect re-syncs draft from configQuery.data.config')

import { describe, expect, test, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen } from '@testing-library/react';
import { OSIntelligenceSectionView } from '@/components/settings/OSIntelligenceSection';

const SECTION_SRC = readFileSync(
  resolve(process.cwd(), 'src/components/settings/OSIntelligenceSection.tsx'),
  'utf8',
);

const SCANNING_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/settings/ScanningPage.tsx'),
  'utf8',
);

const liveConfig = { interval_sec: 1800, rate_limit: 20, maintenance_global: false };
const defaults = { interval_sec: 3600, rate_limit: 10, maintenance_global: false };

describe('frontend-settings-intelligence-config — structural', () => {
  // @ac AC-01
  test('frontend-settings-intelligence-config/AC-01 — useQuery wired to /system/intelligence/config with ["system","intelligence","config"] key', () => {
    expect(SECTION_SRC).toContain("'/api/v1/system/intelligence/config'");
    expect(SECTION_SRC).toMatch(
      /queryKey:\s*\[\s*['"]system['"]\s*,\s*['"]intelligence['"]\s*,\s*['"]config['"]\s*\]/,
    );
    expect(SECTION_SRC).toContain('useQuery');
  });

  // @ac AC-02
  test('frontend-settings-intelligence-config/AC-02 — Cancel resets to config, Reset-to-defaults resets to defaults (distinct paths)', () => {
    // Both the .config and .defaults sub-objects must be referenced by
    // distinct reset paths. Look for both substrings.
    expect(SECTION_SRC).toMatch(/configQuery\.data\??\.config/);
    expect(SECTION_SRC).toMatch(/configQuery\.data\??\.defaults/);
  });

  // @ac AC-03
  test('frontend-settings-intelligence-config/AC-03 — Stepper bounds: interval_sec 300..86400, rate_limit 1..200', () => {
    expect(SECTION_SRC).toMatch(/min=\{300\}/);
    expect(SECTION_SRC).toMatch(/max=\{86400\}/);
    expect(SECTION_SRC).toMatch(/min=\{1\}/);
    expect(SECTION_SRC).toMatch(/max=\{200\}/);
  });

  // @ac AC-04
  test('frontend-settings-intelligence-config/AC-04 — save mutation invalidates the right query key; Save disabled triple-checked', () => {
    expect(SECTION_SRC).toMatch(
      /invalidateQueries\s*\(\s*\{\s*queryKey:\s*\[\s*['"]system['"]\s*,\s*['"]intelligence['"]\s*,\s*['"]config['"]\s*\]\s*\}\s*\)/,
    );
    // Save disabled triple: loading + dirty + mutation pending. All three terms appear.
    expect(SECTION_SRC).toMatch(/isLoading/);
    expect(SECTION_SRC).toMatch(/dirty/);
    expect(SECTION_SRC).toMatch(/isPending/);
  });

  // @ac AC-10
  test('frontend-settings-intelligence-config/AC-10 — post-save useEffect re-syncs draft from configQuery.data.config', () => {
    // The post-save re-sync MUST exist and MUST be gated on
    // mutation.isSuccess so an in-flight edit is never clobbered by an
    // unrelated refetch. Look for both the dependency and the setDraft
    // call referencing configQuery.data.config inside a useEffect.
    expect(SECTION_SRC).toMatch(
      /useEffect\(\s*\(\)\s*=>\s*\{[\s\S]*?mutation\.isSuccess[\s\S]*?setDraft\(\s*\{[\s\S]*?configQuery\.data\??\.config[\s\S]*?\}\s*\)[\s\S]*?\}/,
    );
  });

  // @ac AC-07
  test('frontend-settings-intelligence-config/AC-07 — ScanningPage mounts OSIntelligenceSection between OS discovery and Maintenance', () => {
    expect(SCANNING_SRC).toMatch(
      /import\s*\{[^}]*OSIntelligenceSection[^}]*\}\s*from\s*['"]@\/components\/settings\/OSIntelligenceSection['"]/,
    );
    expect(SCANNING_SRC).toContain('<OSIntelligenceSection');
    // OS discovery is its own wired component now (<OSDiscoverySection>),
    // landed alongside system-discovery-scheduler v1.0. The structural
    // invariant here is the same: OS discovery comes BEFORE OS Intelligence
    // and Maintenance comes AFTER.
    const osDiscoveryIdx = SCANNING_SRC.indexOf('<OSDiscoverySection');
    const intelIdx = SCANNING_SRC.indexOf('<OSIntelligenceSection');
    const maintenanceIdx = SCANNING_SRC.indexOf('"Maintenance"');
    expect(osDiscoveryIdx).toBeGreaterThan(-1);
    expect(intelIdx).toBeGreaterThan(osDiscoveryIdx);
    expect(maintenanceIdx).toBeGreaterThan(intelIdx);
  });
});

describe('frontend-settings-intelligence-config — behavioral (pure view)', () => {
  function viewProps(overrides: Partial<Parameters<typeof OSIntelligenceSectionView>[0]> = {}) {
    return {
      isLoading: false,
      isError: false,
      errorMessage: null,
      config: liveConfig,
      defaults: defaults,
      draft: liveConfig,
      setDraft: vi.fn(),
      onResetToLive: vi.fn(),
      onResetToDefaults: vi.fn(),
      onSave: vi.fn(),
      isSaving: false,
      saveError: null,
      dirty: false,
      ...overrides,
    };
  }

  // @ac AC-05
  test('frontend-settings-intelligence-config/AC-05 — visual states: loading, error, success-clean', () => {
    // Loading
    const { unmount: u1 } = render(
      <OSIntelligenceSectionView {...viewProps({ isLoading: true, config: null, draft: null })} />,
    );
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
    u1();

    // Error: alert + NO setting card / Stepper
    const { unmount: u2 } = render(
      <OSIntelligenceSectionView
        {...viewProps({ isError: true, errorMessage: 'HTTP 500', config: null, draft: null })}
      />,
    );
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /save/i })).toBeNull();
    u2();

    // Success-clean: Save disabled
    render(<OSIntelligenceSectionView {...viewProps()} />);
    expect(screen.getByRole('button', { name: /save/i })).toBeDisabled();
  });

  // @ac AC-06
  test('frontend-settings-intelligence-config/AC-06 — edit -> Save flow toggles dirty/disabled', () => {
    // With dirty=true, Save is enabled
    const onSave = vi.fn();
    const { unmount } = render(
      <OSIntelligenceSectionView {...viewProps({ dirty: true, onSave })} />,
    );
    const saveBtn = screen.getByRole('button', { name: /save/i });
    expect(saveBtn).not.toBeDisabled();
    fireEvent.click(saveBtn);
    expect(onSave).toHaveBeenCalledTimes(1);
    unmount();

    // With isSaving=true, Save is disabled even when dirty. The Save
    // button label flips to "Saving…" while in-flight; we look for it
    // via the disabled-button query rather than the name regex (the
    // label change is itself the spinner affordance).
    render(<OSIntelligenceSectionView {...viewProps({ dirty: true, isSaving: true })} />);
    expect(screen.getByRole('button', { name: /saving/i })).toBeDisabled();
  });

  // @ac AC-08
  test('frontend-settings-intelligence-config/AC-08 — error alert surfaces the HTTP status (no "Failed to load — Failed to load")', () => {
    render(
      <OSIntelligenceSectionView
        {...viewProps({
          isError: true,
          errorMessage: 'HTTP 404',
          config: null,
          draft: null,
        })}
      />,
    );
    const alert = screen.getByRole('alert');
    // The alert MUST include the HTTP status. The buggy original would
    // have rendered "Failed to load intelligence config — Failed to load"
    // — assert the actual status is in there.
    expect(alert.textContent).toMatch(/HTTP\s+404/);
    // And it MUST NOT degenerate to the duplicated fallback.
    expect(alert.textContent).not.toMatch(/—\s*Failed to load$/i);
  });

  // @ac AC-09
  test('frontend-settings-intelligence-config/AC-09 — error state renders a Retry button that invokes onRetry', () => {
    const onRetry = vi.fn();
    render(
      <OSIntelligenceSectionView
        {...viewProps({
          isError: true,
          errorMessage: 'HTTP 500',
          onRetry,
          config: null,
          draft: null,
        })}
      />,
    );
    const retry = screen.getByRole('button', { name: /retry/i });
    fireEvent.click(retry);
    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});
