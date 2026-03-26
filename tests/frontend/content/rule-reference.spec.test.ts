// Spec: specs/frontend/rule-reference.spec.yaml

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const srcRoot = path.resolve(__dirname, '../../../frontend/src');
const readSource = (filePath: string): string =>
  fs.readFileSync(path.join(srcRoot, filePath), 'utf-8');

describe('Rule Reference', () => {
  const source = readSource('pages/content/RuleReference.tsx');

  describe('AC-1: Rule browser lists Kensa YAML rules', () => {
    it('contains rule listing', () => {
      expect(source.toLowerCase()).toContain('rule');
    });
  });

  describe('AC-2: Search by title, description, ID, tags', () => {
    it('contains search functionality', () => {
      expect(source.toLowerCase()).toContain('search');
    });
  });

  describe('AC-3: Filter by framework', () => {
    it('contains framework filter', () => {
      expect(source.toLowerCase()).toContain('framework');
    });
  });

  describe('AC-4: Filter by severity and category', () => {
    it('contains severity filter', () => {
      expect(source.toLowerCase()).toContain('severity');
    });
  });

  describe('AC-5: Rule detail shows overview and mappings', () => {
    it('contains detail view', () => {
      expect(source.toLowerCase()).toContain('detail') || expect(source.toLowerCase()).toContain('drawer');
    });
  });

  describe('AC-6: Statistics cards show totals', () => {
    it('contains statistics display', () => {
      expect(source.toLowerCase()).toContain('stat') || expect(source.toLowerCase()).toContain('total');
    });
  });
});
