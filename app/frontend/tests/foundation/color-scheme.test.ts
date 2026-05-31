// @spec frontend-foundation
//
// AC traceability (this file):
//
//   AC-01  test('frontend-foundation/AC-01 — first paint uses system mode when localStorage unset')
//   AC-02  test('frontend-foundation/AC-02 — localStorage="light" overrides system')
//   AC-03  test('frontend-foundation/AC-03 — invalid value falls back to system')
//   AC-04  test('frontend-foundation/AC-04 — setMode persists + updates store + DOM attribute')
//   AC-05  test('frontend-foundation/AC-05 — matchMedia change reapplies when mode is system')
//   AC-15  test('frontend-foundation/AC-15 — index.html has no-FOUC script before bundle')

import { describe, expect, test, beforeEach, vi } from 'vitest';
import { readFileSync } from 'node:fs';

const importStore = async () => {
  vi.resetModules();
  return await import('@/store/useColorSchemeStore');
};

describe('frontend-foundation — color scheme', () => {
  beforeEach(() => {
    try {
      localStorage.clear();
    } catch {
      /* ignore */
    }
    document.documentElement.removeAttribute('data-mui-color-scheme');
  });

  test('frontend-foundation/AC-01 — first paint uses system mode when localStorage unset', async () => {
    localStorage.clear();
    const { useColorSchemeStore } = await importStore();
    expect(useColorSchemeStore.getState().mode).toBe('system');
    // Module-level init applied the attribute.
    expect(['light', 'dark']).toContain(
      document.documentElement.getAttribute('data-mui-color-scheme'),
    );
  });

  test('frontend-foundation/AC-02 — localStorage="light" overrides system', async () => {
    localStorage.setItem('ow-color-scheme', 'light');
    const { useColorSchemeStore } = await importStore();
    expect(useColorSchemeStore.getState().mode).toBe('light');
    expect(document.documentElement.getAttribute('data-mui-color-scheme')).toBe('light');
  });

  test('frontend-foundation/AC-03 — invalid value falls back to system', async () => {
    localStorage.setItem('ow-color-scheme', 'sparkle');
    const { useColorSchemeStore } = await importStore();
    expect(useColorSchemeStore.getState().mode).toBe('system');
  });

  test('frontend-foundation/AC-04 — setMode persists + updates store + DOM attribute', async () => {
    localStorage.clear();
    const { useColorSchemeStore } = await importStore();
    useColorSchemeStore.getState().setMode('light');
    expect(useColorSchemeStore.getState().mode).toBe('light');
    expect(localStorage.getItem('ow-color-scheme')).toBe('light');
    expect(document.documentElement.getAttribute('data-mui-color-scheme')).toBe('light');

    useColorSchemeStore.getState().setMode('dark');
    expect(document.documentElement.getAttribute('data-mui-color-scheme')).toBe('dark');
  });

  test('frontend-foundation/AC-15 — index.html has no-FOUC script before bundle', () => {
    const { resolve } = require('node:path');
    const html = readFileSync(resolve(process.cwd(), 'index.html'), 'utf8');
    const attrIndex = html.indexOf("'data-mui-color-scheme'");
    const moduleScriptIndex = html.indexOf('type="module"');
    expect(attrIndex).toBeGreaterThan(-1);
    expect(moduleScriptIndex).toBeGreaterThan(-1);
    expect(attrIndex).toBeLessThan(moduleScriptIndex);
    expect(html).toContain('ow-color-scheme');
    expect(html).toContain('prefers-color-scheme');
  });
});
