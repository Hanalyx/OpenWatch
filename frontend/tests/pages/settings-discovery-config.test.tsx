// @spec frontend-settings-discovery-config
//
// AC traceability (this file):
//
//   AC-01  test('frontend-settings-discovery-config/AC-01 — useQuery wired to /system/discovery/config with ["system","discovery","config"] key')
//   AC-02  test('frontend-settings-discovery-config/AC-02 — Cancel resets to config, Reset-to-defaults resets to defaults (distinct paths)')
//   AC-03  test('frontend-settings-discovery-config/AC-03 — Stepper bounds: interval_sec 3600..604800, rate_limit 1..500')
//   AC-04  test('frontend-settings-discovery-config/AC-04 — save mutation invalidates the right query key; Save disabled triple-checked')
//   AC-05  test('frontend-settings-discovery-config/AC-05 — sweep mutation hits /system/discovery/sweep and renders Queued N')
//   AC-06  test('frontend-settings-discovery-config/AC-06 — ScanningPage mounts OSDiscoverySection BEFORE OSIntelligenceSection')
//   AC-07  test('frontend-settings-discovery-config/AC-07 — visual states: loading, error, success-clean')
//   AC-08  test('frontend-settings-discovery-config/AC-08 — Run now button: label flips, callback invoked, queued count rendered')
//   AC-09  test('frontend-settings-discovery-config/AC-09 — section badge reflects maintenance state (Running vs Paused), not the static "Wired"')

import { describe, expect, test, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fireEvent, render, screen } from '@testing-library/react';
import { OSDiscoverySectionView } from '@/components/settings/OSDiscoverySection';

const SECTION_SRC = readFileSync(
  resolve(process.cwd(), 'src/components/settings/OSDiscoverySection.tsx'),
  'utf8',
);

const SCANNING_SRC = readFileSync(
  resolve(process.cwd(), 'src/pages/settings/ScanningPage.tsx'),
  'utf8',
);

const liveConfig = {
  interval_sec: 43200,
  rate_limit: 50,
  detect_on_first_contact: false,
  maintenance_global: false,
};
const defaults = {
  interval_sec: 86400,
  rate_limit: 25,
  detect_on_first_contact: true,
  maintenance_global: false,
};

describe('frontend-settings-discovery-config — structural', () => {
  // @ac AC-01
  test('frontend-settings-discovery-config/AC-01 — useQuery wired to /system/discovery/config with ["system","discovery","config"] key', () => {
    expect(SECTION_SRC).toContain("'/api/v1/system/discovery/config'");
    expect(SECTION_SRC).toMatch(
      /queryKey:\s*\[\s*['"]system['"]\s*,\s*['"]discovery['"]\s*,\s*['"]config['"]\s*\]/,
    );
    expect(SECTION_SRC).toContain('useQuery');
  });

  // @ac AC-02
  test('frontend-settings-discovery-config/AC-02 — Cancel resets to config, Reset-to-defaults resets to defaults (distinct paths)', () => {
    expect(SECTION_SRC).toMatch(/configQuery\.data\??\.config/);
    expect(SECTION_SRC).toMatch(/configQuery\.data\??\.defaults/);
  });

  // @ac AC-03
  test('frontend-settings-discovery-config/AC-03 — Stepper bounds: interval_sec 3600..604800, rate_limit 1..500', () => {
    expect(SECTION_SRC).toMatch(/min=\{3600\}/);
    expect(SECTION_SRC).toMatch(/max=\{604800\}/);
    expect(SECTION_SRC).toMatch(/min=\{1\}/);
    expect(SECTION_SRC).toMatch(/max=\{500\}/);
  });

  // @ac AC-04
  test('frontend-settings-discovery-config/AC-04 — save mutation invalidates the right query key; Save disabled triple-checked', () => {
    expect(SECTION_SRC).toMatch(
      /invalidateQueries\s*\(\s*\{\s*queryKey:\s*\[\s*['"]system['"]\s*,\s*['"]discovery['"]\s*,\s*['"]config['"]\s*\]\s*\}\s*\)/,
    );
    expect(SECTION_SRC).toMatch(/isLoading/);
    expect(SECTION_SRC).toMatch(/dirty/);
    expect(SECTION_SRC).toMatch(/isPending/);
  });

  // @ac AC-05
  test('frontend-settings-discovery-config/AC-05 — sweep mutation hits /system/discovery/sweep and renders Queued N', () => {
    expect(SECTION_SRC).toContain("'/api/v1/system/discovery/sweep'");
    // The "Queued N discoveries." copy is what renders sweepResult.enqueued.
    expect(SECTION_SRC).toMatch(/Queued\s+\{sweepResult\.enqueued\}\s+discoveries\./);
  });

  // @ac AC-06
  test('frontend-settings-discovery-config/AC-06 — ScanningPage mounts OSDiscoverySection BEFORE OSIntelligenceSection', () => {
    expect(SCANNING_SRC).toMatch(
      /import\s*\{[^}]*OSDiscoverySection[^}]*\}\s*from\s*['"]@\/components\/settings\/OSDiscoverySection['"]/,
    );
    expect(SCANNING_SRC).toContain('<OSDiscoverySection');
    const discoveryIdx = SCANNING_SRC.indexOf('<OSDiscoverySection');
    const intelIdx = SCANNING_SRC.indexOf('<OSIntelligenceSection');
    expect(discoveryIdx).toBeGreaterThan(-1);
    expect(intelIdx).toBeGreaterThan(discoveryIdx);
  });
});

describe('frontend-settings-discovery-config — behavioral (pure view)', () => {
  function viewProps(overrides: Partial<Parameters<typeof OSDiscoverySectionView>[0]> = {}) {
    return {
      isLoading: false,
      isError: false,
      errorMessage: null,
      config: liveConfig,
      defaults,
      draft: liveConfig,
      setDraft: vi.fn(),
      onResetToLive: vi.fn(),
      onResetToDefaults: vi.fn(),
      onSave: vi.fn(),
      isSaving: false,
      saveError: null,
      dirty: false,
      onRunNow: vi.fn(),
      isSweeping: false,
      sweepResult: null,
      sweepError: null,
      ...overrides,
    };
  }

  // @ac AC-07
  test('frontend-settings-discovery-config/AC-07 — visual states: loading, error, success-clean', () => {
    // Loading.
    const { rerender } = render(<OSDiscoverySectionView {...viewProps({ isLoading: true })} />);
    expect(screen.getByRole('status')).toHaveTextContent(/loading/i);
    // No setting card.
    expect(screen.queryByText(/re-scan interval/i)).toBeNull();

    // Error.
    rerender(
      <OSDiscoverySectionView
        {...viewProps({
          isError: true,
          errorMessage: 'HTTP 500 — boom',
          isLoading: false,
        })}
      />,
    );
    expect(screen.getByRole('alert')).toHaveTextContent(/HTTP 500 — boom/);

    // Success + clean (dirty=false) → Save disabled.
    rerender(<OSDiscoverySectionView {...viewProps()} />);
    expect(screen.getByRole('button', { name: /save changes/i })).toBeDisabled();
  });

  // @ac AC-08
  test('frontend-settings-discovery-config/AC-08 — Run now button: label flips, callback invoked, queued count rendered', () => {
    const onRunNow = vi.fn();
    const { rerender } = render(<OSDiscoverySectionView {...viewProps({ onRunNow })} />);
    const runBtn = screen.getByRole('button', { name: /run now/i });
    fireEvent.click(runBtn);
    expect(onRunNow).toHaveBeenCalledTimes(1);

    // While sweeping the label flips.
    rerender(<OSDiscoverySectionView {...viewProps({ isSweeping: true })} />);
    expect(screen.getByRole('button', { name: /sweeping/i })).toBeDisabled();

    // Sweep result shown.
    rerender(<OSDiscoverySectionView {...viewProps({ sweepResult: { enqueued: 7 } })} />);
    expect(screen.getByText(/queued\s+7\s+discoveries/i)).toBeInTheDocument();
  });

  // @ac AC-09
  test('frontend-settings-discovery-config/AC-09 — section badge reflects maintenance state (Running vs Paused), not the static "Wired"', () => {
    const { unmount } = render(
      <OSDiscoverySectionView
        {...viewProps({ draft: { ...liveConfig, maintenance_global: false } })}
      />,
    );
    expect(screen.getByText('Running')).toBeInTheDocument();
    expect(screen.queryByText('Wired')).toBeNull();
    unmount();

    render(
      <OSDiscoverySectionView
        {...viewProps({ draft: { ...liveConfig, maintenance_global: true } })}
      />,
    );
    expect(screen.getByText('Paused')).toBeInTheDocument();
  });
});
