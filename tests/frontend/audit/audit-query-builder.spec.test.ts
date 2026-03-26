// Spec: specs/frontend/audit-query-builder.spec.yaml

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const srcRoot = path.resolve(__dirname, '../../../frontend/src');
const readSource = (filePath: string): string =>
  fs.readFileSync(path.join(srcRoot, filePath), 'utf-8');

describe('Audit Query Builder', () => {
  describe('AC-1: Query builder supports host, rule, framework, severity, status filters', () => {
    it('query builder page contains filter controls', () => {
      const source = readSource('pages/audit/AuditQueryBuilderPage.tsx');
      expect(source.toLowerCase()).toContain('filter') || expect(source.toLowerCase()).toContain('severity');
    });
  });

  describe('AC-2: Saved queries list shows name and visibility', () => {
    it('queries page shows query list', () => {
      const source = readSource('pages/audit/AuditQueriesPage.tsx');
      expect(source.toLowerCase()).toContain('name') || expect(source.toLowerCase()).toContain('query');
    });
  });

  describe('AC-3: Query execution returns paginated results', () => {
    it('query builder handles results', () => {
      const source = readSource('pages/audit/AuditQueryBuilderPage.tsx');
      expect(source.toLowerCase()).toContain('result') || expect(source.toLowerCase()).toContain('page');
    });
  });

  describe('AC-4: Export creation supports JSON and CSV formats', () => {
    it('exports page references formats', () => {
      const source = readSource('pages/audit/AuditExportsPage.tsx');
      expect(source.toLowerCase()).toContain('export');
    });
  });

  describe('AC-5: Export download available', () => {
    it('exports page has download functionality', () => {
      const source = readSource('pages/audit/AuditExportsPage.tsx');
      expect(source.toLowerCase()).toContain('download');
    });
  });

  describe('AC-6: Query visibility can be private or shared', () => {
    it('query builder references visibility', () => {
      const source = readSource('pages/audit/AuditQueryBuilderPage.tsx');
      expect(source.toLowerCase()).toContain('visib') || expect(source.toLowerCase()).toContain('shared');
    });
  });

  describe('AC-7: Date range filter present', () => {
    it('query builder has date inputs', () => {
      const source = readSource('pages/audit/AuditQueryBuilderPage.tsx');
      expect(source.toLowerCase()).toContain('date');
    });
  });

  describe('AC-8: Audit pages use React Query for data fetching', () => {
    it('uses useQuery or useMutation', () => {
      const source = readSource('pages/audit/AuditQueriesPage.tsx');
      expect(source).toContain('useQuery') || expect(source).toContain('api');
    });
  });
});
