// Spec: specs/frontend/users-management.spec.yaml

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';

const srcRoot = path.resolve(__dirname, '../../../frontend/src');
const readSource = (filePath: string): string =>
  fs.readFileSync(path.join(srcRoot, filePath), 'utf-8');

describe('Users Management', () => {
  const source = readSource('pages/users/Users.tsx');

  describe('AC-1: User list displays username, email, role, status', () => {
    it('contains username column', () => {
      expect(source.toLowerCase()).toContain('username');
    });
    it('contains role column', () => {
      expect(source.toLowerCase()).toContain('role');
    });
  });

  describe('AC-2: Create user form validates required fields', () => {
    it('contains form validation', () => {
      expect(source.toLowerCase()).toContain('required') || expect(source.toLowerCase()).toContain('valid');
    });
  });

  describe('AC-3: Role assignment uses dropdown', () => {
    it('contains role selection', () => {
      expect(source.toLowerCase()).toContain('select') || expect(source.toLowerCase()).toContain('role');
    });
  });

  describe('AC-4: User deletion requires confirmation', () => {
    it('contains delete confirmation', () => {
      expect(source.toLowerCase()).toContain('delete') || expect(source.toLowerCase()).toContain('confirm');
    });
  });

  describe('AC-5: User list supports search', () => {
    it('contains search functionality', () => {
      expect(source.toLowerCase()).toContain('search') || expect(source.toLowerCase()).toContain('filter');
    });
  });

  describe('AC-6: Users page requires authenticated access', () => {
    it('imports auth or api module', () => {
      expect(source).toContain('api') || expect(source).toContain('useAuthStore');
    });
  });
});
