// Spec: specs/frontend/scheduled-scans.spec.yaml
/**
 * Spec-enforcement tests for the scheduled scans management page.
 *
 * Verifies adaptive interval config rendering, per-state sliders,
 * per-host schedule table, preview histogram, and API persistence
 * via source inspection.
 *
 * Status: active
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const PAGE_PATH = path.resolve(
  __dirname,
  '../../../frontend/src/pages/scans/ScheduledScans.tsx'
);
const ADAPTER_PATH = path.resolve(
  __dirname,
  '../../../frontend/src/services/adapters/schedulerAdapter.ts'
);

const pageSource = fs.readFileSync(PAGE_PATH, 'utf-8');
const adapterSource = fs.readFileSync(ADAPTER_PATH, 'utf-8');

// ---------------------------------------------------------------------------
// AC-1: Scheduled scan management page renders
// ---------------------------------------------------------------------------

describe('AC-1: Scheduled scan management page renders', () => {
  /**
   * AC-1: Scheduled scan management page MUST render adaptive interval
   * configuration controls.
   */
  it('management page renders adaptive interval config', () => {
    // Verify component file exports a default React component
    expect(pageSource).toContain('export default ScheduledScans');
    // Verify it renders interval configuration
    expect(pageSource).toContain('IntervalConfig');
    expect(pageSource).toContain('Interval Configuration');
  });
});

// ---------------------------------------------------------------------------
// AC-2: Sliders adjust intervals per compliance state
// ---------------------------------------------------------------------------

describe('AC-2: Sliders adjust intervals per compliance state', () => {
  /**
   * AC-2: Sliders MUST allow adjusting intervals for critical, low,
   * partial, and compliant states.
   */
  it('slider renders for critical state', () => {
    expect(pageSource).toContain('interval_critical');
    expect(pageSource).toContain("'Critical (<20%)'");
  });

  it('slider renders for low state', () => {
    expect(pageSource).toContain('interval_low');
    expect(pageSource).toContain("'Low (20-49%)'");
  });

  it('slider renders for partial state', () => {
    expect(pageSource).toContain('interval_partial');
    expect(pageSource).toContain("'Partial (50-79%)'");
  });

  it('slider renders for compliant state', () => {
    expect(pageSource).toContain('interval_compliant');
    expect(pageSource).toContain("'Compliant (100%)'");
  });

  it('sliders reflect current backend configuration on load', () => {
    // Verify sliders are initialized from the config prop (backend data)
    expect(pageSource).toContain('config[slider.key]');
    expect(pageSource).toContain('schedulerService.getConfig');
  });
});

// ---------------------------------------------------------------------------
// AC-3: Per-host schedule table
// ---------------------------------------------------------------------------

describe('AC-3: Per-host schedule table displays columns', () => {
  /**
   * AC-3: Per-host schedule table MUST display next_scheduled_scan,
   * current_interval, and maintenance_mode.
   */
  it('table displays next_scheduled_scan column', () => {
    expect(pageSource).toContain('Next Scan');
    expect(pageSource).toContain('nextScheduledScan');
  });

  it('table displays current_interval column', () => {
    expect(pageSource).toContain('Interval');
    expect(pageSource).toContain('currentIntervalMinutes');
  });

  it('table displays maintenance_mode column', () => {
    expect(pageSource).toContain('Maintenance');
    expect(pageSource).toContain('maintenanceMode');
  });
});

// ---------------------------------------------------------------------------
// AC-4: Preview histogram of projected scans
// ---------------------------------------------------------------------------

describe('AC-4: Preview histogram shows projected scans', () => {
  /**
   * AC-4: Preview histogram MUST show projected scan counts for the
   * next 48 hours.
   */
  it('histogram component renders', () => {
    expect(pageSource).toContain('ScanProjectionHistogram');
    expect(pageSource).toContain('Projected Scans');
  });

  it('histogram covers 48-hour projection window', () => {
    expect(pageSource).toContain('const HOURS = 48');
    expect(pageSource).toContain('+48h');
  });
});

// ---------------------------------------------------------------------------
// AC-5: Changes call PUT /api/compliance/scheduler/config
// ---------------------------------------------------------------------------

describe('AC-5: Saving calls PUT /api/compliance/scheduler/config', () => {
  /**
   * AC-5: Saving interval changes MUST call PUT
   * /api/compliance/scheduler/config.
   */
  it('save action calls PUT /api/compliance/scheduler/config', () => {
    // Verify the adapter uses api.put with the correct endpoint
    expect(adapterSource).toContain("api.put");
    expect(adapterSource).toContain("'/api/compliance/scheduler/config'");
  });

  it('request payload includes updated interval configuration', () => {
    // Verify the page sends changed interval values to updateConfig
    expect(pageSource).toContain('schedulerService.updateConfig');
    expect(pageSource).toContain('saveMutation.mutate(update)');
  });
});
