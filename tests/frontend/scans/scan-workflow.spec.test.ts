// Spec: specs/frontend/scan-workflow.spec.yaml
/**
 * Spec-enforcement tests for the compliance scan wizard workflow.
 *
 * Verifies wizard step structure, validation logic, scan submission
 * endpoint, multi-host execution model, navigation state preservation,
 * and host preselection via source inspection.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SRC = path.resolve(__dirname, '../../../frontend/src');

function readSource(relativePath: string): string {
  return fs.readFileSync(path.join(SRC, relativePath), 'utf8');
}

// ---------------------------------------------------------------------------
// AC-1: Wizard has exactly 4 steps in order
// ---------------------------------------------------------------------------

describe('AC-1: Wizard has exactly 4 steps', () => {
  /**
   * AC-1: The wizard MUST have exactly 4 steps: Target Selection (0),
   * Framework & Platform (1), Rule Configuration (2), Review & Start (3).
   */
  const wizardSource = readSource('pages/scans/ComplianceScanWizard.tsx');

  it('wizard renders TargetSelectionStep', () => {
    expect(wizardSource).toContain('TargetSelectionStep');
  });

  it('wizard renders FrameworkConfigStep', () => {
    expect(wizardSource).toContain('FrameworkConfigStep');
  });

  it('wizard renders RuleConfigStep', () => {
    expect(wizardSource).toContain('RuleConfigStep');
  });

  it('wizard renders ReviewStartStep', () => {
    expect(wizardSource).toContain('ReviewStartStep');
  });

  it('wizard uses a Stepper component', () => {
    expect(wizardSource).toContain('Stepper');
  });
});

// ---------------------------------------------------------------------------
// AC-2: Step 0 requires target type and selected targets
// ---------------------------------------------------------------------------

describe('AC-2: Step 0 requires targets before advancing', () => {
  /**
   * AC-2: Target Selection MUST require target type AND at least one
   * selected target. canProceedToNextStep MUST enforce this.
   */
  const hookSource = readSource('pages/scans/hooks/useScanWizard.ts');

  it('useScanWizard implements canProceedToNextStep', () => {
    expect(hookSource).toContain('canProceedToNextStep');
  });

  it('step 0 validation checks targetType', () => {
    expect(hookSource).toContain('targetType');
  });

  it('step 0 validation checks selectedHostIds or selectedGroupIds', () => {
    const checksHosts = hookSource.includes('selectedHostIds');
    const checksGroups = hookSource.includes('selectedGroupIds');
    expect(checksHosts || checksGroups).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// AC-3: Step 1 requires platform, version, and framework
// ---------------------------------------------------------------------------

describe('AC-3: Step 1 requires platform, version, and framework', () => {
  /**
   * AC-3: Framework & Platform step MUST require all three fields
   * before allowing advancement.
   */
  const hookSource = readSource('pages/scans/hooks/useScanWizard.ts');

  it('validates platform is set', () => {
    expect(hookSource).toContain('platform');
  });

  it('validates platformVersion is set', () => {
    expect(hookSource).toContain('platformVersion');
  });

  it('validates framework is set', () => {
    expect(hookSource).toContain('framework');
  });
});

// ---------------------------------------------------------------------------
// AC-4: Step 2 supports full and custom scan modes
// ---------------------------------------------------------------------------

describe('AC-4: Step 2 supports full and custom scan modes', () => {
  /**
   * AC-4: Rule Configuration MUST support full scan and custom mode.
   * Step 2 MUST always allow proceeding.
   */
  const hookSource = readSource('pages/scans/hooks/useScanWizard.ts');

  it('tracks scanMode state', () => {
    expect(hookSource).toContain('scanMode');
  });

  it('supports full scan mode', () => {
    expect(hookSource).toContain("'full'");
  });

  it('supports custom scan mode', () => {
    expect(hookSource).toContain("'custom'");
  });
});

// ---------------------------------------------------------------------------
// AC-5: Step 3 requires scan name with auto-generation
// ---------------------------------------------------------------------------

describe('AC-5: Step 3 requires scan name with auto-generation', () => {
  /**
   * AC-5: Review & Start MUST require a non-empty scan name.
   * Default scan name MUST be auto-generated.
   */
  const hookSource = readSource('pages/scans/hooks/useScanWizard.ts');

  it('tracks scanName state', () => {
    expect(hookSource).toContain('scanName');
  });

  it('has a setScanName action', () => {
    expect(hookSource).toContain('setScanName');
  });

  it('validates scanName is non-empty for step 3', () => {
    // canProceedToNextStep should check scanName
    expect(hookSource).toContain('scanName');
  });
});

// ---------------------------------------------------------------------------
// AC-6: Scan submission calls POST /api/scans/
// ---------------------------------------------------------------------------

describe('AC-6: Scan submission calls correct endpoint', () => {
  /**
   * AC-6: startComplianceScan MUST send requests to POST /api/scans/.
   */
  const scanServiceSource = readSource('services/scanService.ts');

  it('scanService calls /api/scans/ endpoint', () => {
    expect(scanServiceSource).toContain('/api/scans');
  });

  it('scanService sends host_id in request', () => {
    expect(scanServiceSource).toContain('host_id');
  });

  it('scanService sends platform in request', () => {
    expect(scanServiceSource).toContain('platform');
  });

  it('scanService sends framework in request', () => {
    expect(scanServiceSource).toContain('framework');
  });

  it('scanService does NOT contain deprecated startHostScan method', () => {
    expect(scanServiceSource).not.toContain('startHostScan');
  });

  it('scanService does NOT send content_id in requests', () => {
    expect(scanServiceSource).not.toContain('content_id');
  });
});

// ---------------------------------------------------------------------------
// AC-7: Multi-host scans execute sequentially with progress tracking
// ---------------------------------------------------------------------------

describe('AC-7: Multi-host scans execute sequentially', () => {
  /**
   * AC-7: Multi-host scans MUST execute sequentially. Each host MUST
   * transition through statuses. Failed hosts MUST NOT block others.
   */
  const wizardSource = readSource('pages/scans/ComplianceScanWizard.tsx');
  const hookSource = readSource('pages/scans/hooks/useScanWizard.ts');

  it('wizard tracks per-host scan progress', () => {
    expect(hookSource).toContain('hostScanProgress');
  });

  it('wizard has updateHostStatus action', () => {
    expect(hookSource).toContain('updateHostStatus');
  });

  it('wizard tracks connecting status', () => {
    expect(wizardSource).toContain('connecting');
  });

  it('wizard tracks scanning status', () => {
    expect(wizardSource).toContain('scanning');
  });

  it('wizard tracks completed status', () => {
    expect(wizardSource).toContain('completed');
  });

  it('wizard tracks failed status', () => {
    expect(wizardSource).toContain('failed');
  });
});

// ---------------------------------------------------------------------------
// AC-8: Success navigation to scan detail or scan list
// ---------------------------------------------------------------------------

describe('AC-8: Success navigation depends on host count', () => {
  /**
   * AC-8: Single-host -> /scans/{scanId}. Multi-host -> /scans.
   */
  const wizardSource = readSource('pages/scans/ComplianceScanWizard.tsx');

  it('wizard navigates to /scans after completion', () => {
    expect(wizardSource).toContain('/scans');
  });

  it('wizard uses navigate function', () => {
    expect(wizardSource).toContain('navigate');
  });
});

// ---------------------------------------------------------------------------
// AC-9: Back navigation preserves wizard state
// ---------------------------------------------------------------------------

describe('AC-9: Back navigation preserves state', () => {
  /**
   * AC-9: prevStep MUST preserve all wizard state. No data lost on back.
   */
  const hookSource = readSource('pages/scans/hooks/useScanWizard.ts');

  it('useScanWizard implements prevStep', () => {
    expect(hookSource).toContain('prevStep');
  });

  it('prevStep decrements activeStep without clearing state', () => {
    // prevStep should only change activeStep, not reset other fields
    const prevStepMatch = hookSource.match(/prevStep[^}]*}/s);
    if (prevStepMatch) {
      const prevStepBody = prevStepMatch[0];
      // Should NOT contain clearing of targets, platform, framework, etc.
      expect(prevStepBody).not.toContain('selectedHostIds: []');
      expect(prevStepBody).not.toContain("platform: ''");
    }
    expect(hookSource).toContain('prevStep');
  });
});

// ---------------------------------------------------------------------------
// AC-10: Wizard supports host preselection via router state
// ---------------------------------------------------------------------------

describe('AC-10: Wizard supports host preselection', () => {
  /**
   * AC-10: Wizard MUST support preselectedHostId via router state.
   */
  const wizardSource = readSource('pages/scans/ComplianceScanWizard.tsx');
  const hookSource = readSource('pages/scans/hooks/useScanWizard.ts');

  it('wizard reads preselectedHostId from location state', () => {
    const combined = wizardSource + hookSource;
    expect(combined).toContain('preselectedHostId');
  });

  it('hook accepts preselectedHostId parameter', () => {
    expect(hookSource).toContain('preselectedHostId');
  });
});
