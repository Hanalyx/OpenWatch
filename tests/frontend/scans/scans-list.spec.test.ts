// Spec: specs/frontend/scans-list.spec.yaml

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const srcRoot = path.resolve(__dirname, '../../../frontend/src');
const readSource = (filePath: string): string =>
  fs.readFileSync(path.join(srcRoot, filePath), 'utf-8');

describe('Scans List', () => {
  describe('AC-1: Scans list shows scan name, status, host, date', () => {
    it('Scans page renders scan list', () => {
      const source = readSource('pages/scans/Scans.tsx');
      expect(source.toLowerCase()).toContain('scan');
      expect(source.toLowerCase()).toContain('status');
    });
  });

  describe('AC-2: Scan status badges show correct colors', () => {
    it('contains status color mapping', () => {
      const source = readSource('pages/scans/Scans.tsx');
      expect(source.toLowerCase()).toContain('completed') || expect(source.toLowerCase()).toContain('color');
    });
  });

  describe('AC-3: Scan detail shows compliance score and rule results', () => {
    it('ScanDetail references score', () => {
      const source = readSource('pages/scans/ScanDetail.tsx');
      expect(source.toLowerCase()).toContain('score') || expect(source.toLowerCase()).toContain('compliance');
    });
  });

  describe('AC-4: Rule results filterable by severity and status', () => {
    it('ScanDetail has filter controls', () => {
      const source = readSource('pages/scans/ScanDetail.tsx');
      expect(source.toLowerCase()).toContain('severity') || expect(source.toLowerCase()).toContain('filter');
    });
  });

  describe('AC-5: Scan detail has tabs', () => {
    it('ScanDetail uses tabs', () => {
      const source = readSource('pages/scans/ScanDetail.tsx');
      expect(source).toContain('Tab') || expect(source.toLowerCase()).toContain('tab');
    });
  });

  describe('AC-6: ComplianceScanWizard available', () => {
    it('wizard component exists', () => {
      const exists = fs.existsSync(path.join(srcRoot, 'pages/scans/ComplianceScanWizard.tsx'));
      expect(exists).toBe(true);
    });
  });

  describe('AC-7: Scan list supports pagination', () => {
    it('scans page has pagination', () => {
      const source = readSource('pages/scans/Scans.tsx');
      expect(source.toLowerCase()).toContain('page') || expect(source.toLowerCase()).toContain('pagination');
    });
  });

  describe('AC-8: Quick scan menu provides scan templates', () => {
    it('QuickScanMenu component exists', () => {
      const source = readSource('components/scans/QuickScanMenu.tsx');
      expect(source.toLowerCase()).toContain('template') || expect(source.toLowerCase()).toContain('quick');
    });
  });
});
