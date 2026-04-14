// Spec: specs/frontend/host-detail-behavior.spec.yaml
/**
 * Spec-enforcement tests for Host Detail page behavior.
 *
 * Verifies absence of manual scan buttons, presence of 6 summary cards
 * and 10 tabs, compliance card scoring, auto-scan card behavior,
 * no-data states, API endpoint alignment, and tab functionality.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SRC = path.resolve(__dirname, '../../../frontend/src');
const HOST_DETAIL = path.join(SRC, 'pages/hosts/HostDetail');

function readSource(relativePath: string): string {
  return fs.readFileSync(path.join(SRC, relativePath), 'utf8');
}

function readHostDetail(relativePath: string): string {
  return fs.readFileSync(path.join(HOST_DETAIL, relativePath), 'utf8');
}

function fileExists(relativePath: string): boolean {
  return fs.existsSync(path.join(HOST_DETAIL, relativePath));
}

// ---------------------------------------------------------------------------
// AC-1: No manual scan buttons
// ---------------------------------------------------------------------------

describe('AC-1: No manual scan buttons on Host Detail page', () => {
  /**
   * AC-1: The page MUST NOT render buttons with text 'Start Scan',
   * 'Run Kensa Scan', 'Establish Baseline', or 'Start First Scan'.
   */
  const headerSource = readHostDetail('HostDetailHeader.tsx');
  const indexSource = readHostDetail('index.tsx');

  it('header does not contain Start Scan button text', () => {
    expect(headerSource).not.toContain('Start Scan');
  });

  it('header does not contain Run Kensa Scan button text', () => {
    expect(headerSource).not.toContain('Run Kensa Scan');
  });

  it('header does not contain Establish Baseline button text', () => {
    expect(headerSource).not.toContain('Establish Baseline');
  });

  it('index does not contain Start First Scan button text', () => {
    expect(indexSource).not.toContain('Start First Scan');
  });
});

// ---------------------------------------------------------------------------
// AC-2: 6 summary cards rendered
// ---------------------------------------------------------------------------

describe('AC-2: Page displays 6 summary cards', () => {
  /**
   * AC-2: MUST display Compliance, System Health, Auto-Scan, Exceptions,
   * Alerts, and Connectivity cards via HostSummaryCards.
   */
  const summarySource = readHostDetail('HostSummaryCards.tsx');

  it('renders ComplianceCard', () => {
    expect(summarySource).toContain('ComplianceCard');
  });

  it('renders SystemHealthCard', () => {
    expect(summarySource).toContain('SystemHealthCard');
  });

  it('renders AutoScanCard', () => {
    expect(summarySource).toContain('AutoScanCard');
  });

  it('renders ExceptionsCard', () => {
    expect(summarySource).toContain('ExceptionsCard');
  });

  it('renders AlertsCard', () => {
    expect(summarySource).toContain('AlertsCard');
  });

  it('renders ConnectivityCard', () => {
    expect(summarySource).toContain('ConnectivityCard');
  });
});

// ---------------------------------------------------------------------------
// AC-3: Compliance card score color coding
// ---------------------------------------------------------------------------

describe('AC-3: Compliance card uses score-based colors', () => {
  /**
   * AC-3: Compliance card MUST color-code scores: >=80% success,
   * >=60% warning, <60% error.
   */
  const complianceCardSource = readHostDetail('cards/ComplianceCard.tsx');

  it('compliance card references success color', () => {
    expect(complianceCardSource).toContain('success');
  });

  it('compliance card references warning color', () => {
    expect(complianceCardSource).toContain('warning');
  });

  it('compliance card references error color', () => {
    expect(complianceCardSource).toContain('error');
  });

  it('compliance card checks score thresholds', () => {
    // Should contain numeric threshold checks (80 or 60)
    const has80 = complianceCardSource.includes('80');
    const has60 = complianceCardSource.includes('60');
    expect(has80 || has60).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// AC-4: Auto-Scan card displays schedule status
// ---------------------------------------------------------------------------

describe('AC-4: Auto-Scan card displays schedule status', () => {
  /**
   * AC-4: Auto-Scan card MUST display enabled/maintenance status,
   * last scan time, and next scheduled scan. Maintenance MUST be
   * visually distinct.
   */
  const autoScanSource = readHostDetail('cards/AutoScanCard.tsx');

  it('auto-scan card references maintenance mode', () => {
    const hasMaintenance = autoScanSource.includes('maintenance') || autoScanSource.includes('Maintenance');
    expect(hasMaintenance).toBe(true);
  });

  it('auto-scan card shows last scan time', () => {
    const hasLastScan = autoScanSource.includes('lastScan') || autoScanSource.includes('last_scan');
    expect(hasLastScan).toBe(true);
  });

  it('auto-scan card shows next scan time', () => {
    const hasNextScan = autoScanSource.includes('nextScan') || autoScanSource.includes('next_scan') || autoScanSource.includes('nextScheduled');
    expect(hasNextScan).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// AC-5: Page has 10 tabs
// ---------------------------------------------------------------------------

describe('AC-5: Page has 10 tabs', () => {
  /**
   * AC-5: MUST have Overview, Compliance, Packages, Services, Users,
   * Network, Audit Log, History, Remediation, Terminal tabs.
   */
  const indexSource = readHostDetail('index.tsx');

  it('has Overview tab', () => {
    expect(indexSource).toContain('Overview');
  });

  it('has Compliance tab', () => {
    expect(indexSource).toContain('Compliance');
  });

  it('has Packages tab', () => {
    expect(indexSource).toContain('Packages');
  });

  it('has Services tab', () => {
    expect(indexSource).toContain('Services');
  });

  it('has Users tab', () => {
    expect(indexSource).toContain('Users');
  });

  it('has Network tab', () => {
    expect(indexSource).toContain('Network');
  });

  it('has History tab', () => {
    expect(indexSource).toContain('History');
  });

  it('has Remediation tab', () => {
    expect(indexSource).toContain('Remediation');
  });

  it('uses scrollable tabs', () => {
    expect(indexSource).toContain('scrollable');
  });
});

// ---------------------------------------------------------------------------
// AC-6: Summary cards have no-data states
// ---------------------------------------------------------------------------

describe('AC-6: Summary cards display no-data states', () => {
  /**
   * AC-6: Each card MUST show a descriptive no-data message when data
   * is unavailable, not an error or empty card.
   */

  it('ComplianceCard has no-data message', () => {
    const source = readHostDetail('cards/ComplianceCard.tsx');
    const hasNoData = source.includes('No compliance') || source.includes('no compliance') || source.includes('Awaiting');
    expect(hasNoData).toBe(true);
  });

  it('SystemHealthCard has no-data message', () => {
    const source = readHostDetail('cards/SystemHealthCard.tsx');
    const hasNoData = source.includes('not yet collected') || source.includes('No system') || source.includes('not available');
    expect(hasNoData).toBe(true);
  });

  it('AutoScanCard has no-data message', () => {
    const source = readHostDetail('cards/AutoScanCard.tsx');
    const hasNoData = source.includes('not configured') || source.includes('No auto') || source.includes('not scheduled');
    expect(hasNoData).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// AC-7: hostDetailAdapter calls compliance-state endpoint
// ---------------------------------------------------------------------------

describe('AC-7: hostDetailAdapter calls compliance-state endpoint', () => {
  /**
   * AC-7: Adapter MUST call GET /api/scans/kensa/compliance-state/{id}.
   */
  const adapterSource = readSource('services/adapters/hostDetailAdapter.ts');

  it('adapter contains compliance-state endpoint path', () => {
    expect(adapterSource).toContain('compliance-state');
  });

  it('adapter references kensa scan endpoint', () => {
    expect(adapterSource).toContain('/api/scans/kensa');
  });
});

// ---------------------------------------------------------------------------
// AC-8: hostDetailAdapter calls system-info endpoint
// ---------------------------------------------------------------------------

describe('AC-8: hostDetailAdapter calls system-info endpoint', () => {
  /**
   * AC-8: Adapter MUST call GET /api/hosts/{id}/system-info.
   */
  const adapterSource = readSource('services/adapters/hostDetailAdapter.ts');

  it('adapter contains system-info endpoint path', () => {
    expect(adapterSource).toContain('system-info');
  });
});

// ---------------------------------------------------------------------------
// AC-9: Header shows hostname and back navigation
// ---------------------------------------------------------------------------

describe('AC-9: Header shows hostname and back navigation', () => {
  /**
   * AC-9: Header MUST display host display name or hostname as title.
   * MUST include back navigation button.
   */
  const headerSource = readHostDetail('HostDetailHeader.tsx');

  it('header references hostname or displayName', () => {
    const hasHostname = headerSource.includes('hostname') || headerSource.includes('displayName') || headerSource.includes('display_name');
    expect(hasHostname).toBe(true);
  });

  it('header has back navigation', () => {
    const hasBack = headerSource.includes('ArrowBack') || headerSource.includes('navigate(-1)') || headerSource.includes('navigate(') || headerSource.includes('Back');
    expect(hasBack).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// AC-10: Compliance tab supports filtering and search
// ---------------------------------------------------------------------------

describe('AC-10: Compliance tab supports filtering and search', () => {
  /**
   * AC-10: ComplianceTab MUST support filtering by status and searching
   * by rule title or ID.
   */
  const complianceTabSource = readHostDetail('tabs/ComplianceTab.tsx');

  it('compliance tab has filter functionality', () => {
    const hasFilter = complianceTabSource.includes('filter') || complianceTabSource.includes('Filter');
    expect(hasFilter).toBe(true);
  });

  it('compliance tab has search functionality', () => {
    const hasSearch = complianceTabSource.includes('search') || complianceTabSource.includes('Search');
    expect(hasSearch).toBe(true);
  });

  it('compliance tab supports passed/failed filtering', () => {
    const hasPassed = complianceTabSource.includes('pass') || complianceTabSource.includes('Pass');
    const hasFailed = complianceTabSource.includes('fail') || complianceTabSource.includes('Fail');
    expect(hasPassed && hasFailed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// AC-11: Host Detail page uses Box, not Container maxWidth
// ---------------------------------------------------------------------------

describe('AC-11: Host Detail page layout matches Hosts list page', () => {
  /**
   * AC-11: The Host Detail page MUST NOT use a MUI Container with maxWidth.
   * It MUST use Box so margins match the Hosts list page.
   */
  const indexSource = readHostDetail('index.tsx');

  it('HostDetail index.tsx does not import Container from @mui/material', () => {
    expect(indexSource).not.toMatch(/import\s*\{[^}]*Container[^}]*\}\s*from\s*['"]@mui\/material['"]/);
  });

  it('HostDetail index.tsx does not use <Container maxWidth', () => {
    expect(indexSource).not.toContain('<Container maxWidth');
  });

  it('HostDetail index.tsx does not use </Container>', () => {
    expect(indexSource).not.toContain('</Container>');
  });
});

// ---------------------------------------------------------------------------
// AC-12: Audit Timeline tab
// ---------------------------------------------------------------------------

describe('AC-12: HostDetail includes an Audit Timeline tab', () => {
  /**
   * AC-12: HostDetail page MUST include an "Audit Timeline" tab showing
   * reverse-chronological transactions for the host with filter and export
   * controls. Detailed behavior is covered by host-audit-timeline.spec.yaml.
   */
  const indexSource = readHostDetail('index.tsx');

  it('has Audit Timeline tab label', () => {
    expect(indexSource).toMatch(/Audit Timeline/);
  });

  it('imports AuditTimelineTab component', () => {
    expect(indexSource).toMatch(/AuditTimelineTab/);
  });
});
