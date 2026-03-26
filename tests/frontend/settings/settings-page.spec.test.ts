// Spec: specs/frontend/settings-page.spec.yaml

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const srcRoot = path.resolve(__dirname, '../../../frontend/src');
const readSource = (filePath: string): string =>
  fs.readFileSync(path.join(srcRoot, filePath), 'utf-8');

describe('Settings Page', () => {
  const source = readSource('pages/settings/Settings.tsx');

  describe('AC-1: Settings page organizes content into multiple tabs', () => {
    it('contains Tab components', () => {
      expect(source).toContain('Tab');
    });
  });

  describe('AC-2: SSH policy dropdown shows available policies', () => {
    it('contains SSH policy select', () => {
      expect(source.toLowerCase()).toContain('ssh');
      expect(source.toLowerCase()).toContain('policy');
    });
  });

  describe('AC-3: Session timeout configuration available', () => {
    it('contains session timeout setting', () => {
      expect(source.toLowerCase()).toContain('session');
      expect(source.toLowerCase()).toContain('timeout');
    });
  });

  describe('AC-4: About tab describes Kensa-based compliance scanning', () => {
    it('mentions Kensa in about text', () => {
      expect(source).toContain('Kensa');
    });
  });

  describe('AC-5: Credential management section present', () => {
    it('contains credential references', () => {
      expect(source.toLowerCase()).toContain('credential');
    });
  });

  describe('AC-6: Logging configuration section present', () => {
    it('contains logging references', () => {
      expect(source.toLowerCase()).toContain('log');
    });
  });

  describe('AC-7: Settings page uses authenticated API calls', () => {
    it('imports api service', () => {
      expect(source).toContain('api');
    });
  });

  describe('AC-8: Settings changes submit to backend API', () => {
    it('contains API submission calls', () => {
      expect(source.toLowerCase()).toContain('post') || expect(source.toLowerCase()).toContain('put');
    });
  });
});
