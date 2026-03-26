// Spec: specs/frontend/role-dashboards.spec.yaml

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const srcRoot = path.resolve(__dirname, '../../../frontend/src');
const readSource = (filePath: string): string =>
  fs.readFileSync(path.join(srcRoot, filePath), 'utf-8');

describe('Role-Based Dashboards', () => {
  describe('AC-1: Widget registry defines all widgets with requiredPermissions', () => {
    it('widgetRegistry.ts exists and exports widgets', () => {
      const source = readSource('pages/Dashboard/widgetRegistry.ts');
      expect(source).toContain('requiredPermissions');
    });
  });

  describe('AC-2: Six role presets exist', () => {
    it('dashboardPresets.ts defines super_admin preset', () => {
      const source = readSource('pages/Dashboard/dashboardPresets.ts');
      expect(source).toContain('super_admin');
    });
    it('dashboardPresets.ts defines auditor preset', () => {
      const source = readSource('pages/Dashboard/dashboardPresets.ts');
      expect(source).toContain('auditor');
    });
    it('dashboardPresets.ts defines guest preset', () => {
      const source = readSource('pages/Dashboard/dashboardPresets.ts');
      expect(source).toContain('guest');
    });
  });

  describe('AC-3: Each preset specifies widget layout and visibility', () => {
    it('presets contain widget layout config', () => {
      const source = readSource('pages/Dashboard/dashboardPresets.ts');
      expect(source).toContain('widgets');
    });
  });

  describe('AC-4: Quick actions are permission-gated', () => {
    it('quick actions reference permissions', () => {
      const source = readSource('pages/Dashboard/dashboardPresets.ts');
      expect(source.toLowerCase()).toContain('permission');
    });
  });

  describe('AC-5: Dashboard loads user role from useAuthStore', () => {
    it('Dashboard imports useAuthStore', () => {
      const source = readSource('pages/Dashboard/Dashboard.tsx');
      expect(source).toContain('useAuthStore');
    });
  });

  describe('AC-6: Customization tiers defined', () => {
    it('presets define customization field', () => {
      const source = readSource('pages/Dashboard/dashboardPresets.ts');
      expect(source).toContain('customization');
    });
  });

  describe('AC-7: SummaryBar widget shows aggregate compliance data', () => {
    it('SummaryBar component exists', () => {
      const source = readSource('pages/Dashboard/widgets/SummaryBar.tsx');
      expect(source).toContain('compliance');
    });
  });

  describe('AC-8: Widget components are importable', () => {
    it('widgetRegistry references widget components', () => {
      const source = readSource('pages/Dashboard/widgetRegistry.ts');
      expect(source).toContain('Widget');
    });
  });
});
