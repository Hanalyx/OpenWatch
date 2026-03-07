/**
 * Page layout consistency tests.
 *
 * Verifies that route-level page components do NOT add outer padding
 * via <Box sx={{ p: 3 }}> since the <main> element already provides
 * 24px padding. Double-padding causes content to be inset 48px instead
 * of 24px from the sidebar, mismatching pages that use plain <Box>.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const SRC = path.resolve(__dirname, '../../../frontend/src');

function readSource(relativePath: string): string {
  return fs.readFileSync(path.join(SRC, relativePath), 'utf8');
}

// Route-level page components that must NOT wrap in <Box sx={{ p: 3 }}>
const ROUTE_PAGES = [
  'pages/audit/AuditQueriesPage.tsx',
  'pages/audit/AuditExportsPage.tsx',
  'pages/audit/AuditQueryBuilderPage.tsx',
  'pages/scans/ScanDetail.tsx',
  'pages/scans/ComplianceScanWizard.tsx',
  'pages/host-groups/ComplianceGroups.tsx',
  'pages/hosts/AddHost.tsx',
  'pages/hosts/Hosts.tsx',
];

describe('Page layout: no double-padding on route-level pages', () => {
  for (const page of ROUTE_PAGES) {
    it(`${page} does not use <Box sx={{ p: 3 }}> as outer return wrapper`, () => {
      const source = readSource(page);
      // Check that "return (\n    <Box sx={{ p: 3 }}>" pattern is absent
      const hasOuterPadding = /return\s*\(\s*\n\s*<Box\s+sx=\{\{\s*p:\s*3\s*\}\}>/m.test(source);
      expect(hasOuterPadding).toBe(false);
    });
  }
});

describe('Page layout: Host Detail uses Box, not Container', () => {
  it('HostDetail/index.tsx does not import Container', () => {
    const source = readSource('pages/hosts/HostDetail/index.tsx');
    expect(source).not.toMatch(/import\s*\{[^}]*Container[^}]*\}\s*from\s*['"]@mui\/material['"]/);
  });

  it('HostDetail/index.tsx does not use <Container maxWidth', () => {
    const source = readSource('pages/hosts/HostDetail/index.tsx');
    expect(source).not.toContain('<Container maxWidth');
  });
});
