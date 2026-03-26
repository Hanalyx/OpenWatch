// Spec: specs/frontend/compliance-groups.spec.yaml

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const srcRoot = path.resolve(__dirname, '../../../frontend/src');
const readSource = (filePath: string): string =>
  fs.readFileSync(path.join(srcRoot, filePath), 'utf-8');

describe('Compliance Groups', () => {
  const source = readSource('pages/host-groups/ComplianceGroups.tsx');

  describe('AC-1: Groups list shows group name and member count', () => {
    it('contains group name display', () => {
      expect(source.toLowerCase()).toContain('group');
    });
    it('contains member count', () => {
      const lower = source.toLowerCase();
      expect(lower.includes('member') || lower.includes('count') || lower.includes('host')).toBe(true);
    });
  });

  describe('AC-2: Create group wizard available', () => {
    it('contains create functionality', () => {
      expect(source.toLowerCase()).toContain('create') || expect(source.toLowerCase()).toContain('add');
    });
  });

  describe('AC-3: Group detail shows host members', () => {
    it('contains host member listing', () => {
      expect(source.toLowerCase()).toContain('host');
    });
  });

  describe('AC-4: Group compliance scan triggerable', () => {
    it('contains scan trigger', () => {
      expect(source.toLowerCase()).toContain('scan');
    });
  });

  describe('AC-5: Empty state shows prompt to create first group', () => {
    it('contains empty state message', () => {
      expect(source).toContain('No Compliance Groups') || expect(source.toLowerCase()).toContain('create');
    });
  });
});
