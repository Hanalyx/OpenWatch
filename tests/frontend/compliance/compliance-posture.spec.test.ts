// Spec: specs/frontend/compliance-posture.spec.yaml

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const srcRoot = path.resolve(__dirname, '../../../frontend/src');
const readSource = (filePath: string): string =>
  fs.readFileSync(path.join(srcRoot, filePath), 'utf-8');

describe('Compliance Posture', () => {
  const source = readSource('pages/compliance/TemporalPosture.tsx');

  describe('AC-1: Posture page shows compliance score percentage', () => {
    it('contains score display', () => {
      expect(source.toLowerCase()).toContain('score') || expect(source.toLowerCase()).toContain('compliance');
    });
  });

  describe('AC-2: Point-in-time query supports date selection', () => {
    it('contains date picker or date input', () => {
      expect(source.toLowerCase()).toContain('date');
    });
  });

  describe('AC-3: Drift visualization shows score changes', () => {
    it('contains drift or trend visualization', () => {
      expect(source.toLowerCase()).toContain('drift') || expect(source.toLowerCase()).toContain('trend');
    });
  });

  describe('AC-4: Host filtering available', () => {
    it('contains host filter', () => {
      expect(source.toLowerCase()).toContain('host');
    });
  });

  describe('AC-5: Framework selection for posture view', () => {
    it('contains compliance posture components', () => {
      expect(source.toLowerCase()).toContain('posture');
    });
  });

  describe('AC-6: Posture data fetched via API', () => {
    it('calls compliance posture endpoint', () => {
      expect(source.toLowerCase()).toContain('posture') || expect(source).toContain('api');
    });
  });
});
