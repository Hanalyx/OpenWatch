// @spec frontend-foundation
//
// AC traceability (this file):
//
//   AC-06  test('frontend-foundation/AC-06 — every documented token present')
//   AC-07  test('frontend-foundation/AC-07 — no --mui-* references in source')

import { describe, expect, test } from 'vitest';
import { darkTokens, lightTokens, structural, tokenCssVarNames } from '@/theme/tokens';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

// Source directories scanned for the --mui-* exclusion (AC-07).
// process.cwd() is the frontend/ dir under vitest.
const SRC_DIR = resolve(process.cwd(), 'src');

function listFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) out.push(...listFiles(full));
    else if (/\.(ts|tsx|css)$/.test(name)) out.push(full);
  }
  return out;
}

describe('frontend-foundation', () => {
  // @ac AC-06
  test('frontend-foundation/AC-06 — every documented token is present', () => {
    // Surfaces
    const surfaceKeys = ['bg0', 'bg1', 'bg2', 'bg3', 'line', 'line2'] as const;
    for (const k of surfaceKeys) {
      expect(darkTokens[k]).toBeTruthy();
      expect(lightTokens[k]).toBeTruthy();
    }

    // Text tiers
    const textKeys = ['fg0', 'fg1', 'fg2', 'fg3'] as const;
    for (const k of textKeys) {
      expect(darkTokens[k]).toBeTruthy();
      expect(lightTokens[k]).toBeTruthy();
    }

    // Severity (base + on + bg)
    const sev = ['crit', 'warn', 'ok', 'info'] as const;
    for (const s of sev) {
      expect(darkTokens[s]).toBeTruthy();
      expect(darkTokens[`${s}On` as const]).toBeTruthy();
      expect(darkTokens[`${s}Bg` as const]).toBeTruthy();
      expect(lightTokens[s]).toBeTruthy();
      expect(lightTokens[`${s}On` as const]).toBeTruthy();
      expect(lightTokens[`${s}Bg` as const]).toBeTruthy();
    }

    // Brand secondary
    expect(darkTokens.brand2).toBeTruthy();
    expect(lightTokens.brand2).toBeTruthy();

    // Shadows
    expect(darkTokens.shadowSm).toBeTruthy();
    expect(darkTokens.shadowMd).toBeTruthy();
    expect(darkTokens.shadowLg).toBeTruthy();
    expect(lightTokens.shadowSm).toBeTruthy();
    expect(lightTokens.shadowMd).toBeTruthy();
    expect(lightTokens.shadowLg).toBeTruthy();

    // Structural
    expect(structural.fontSans).toContain('Inter');
    expect(structural.fontMono).toContain('JetBrains Mono');
    expect(structural.radius).toBe('8px');
    expect(structural.radiusSm).toBe('6px');
    expect(structural.radiusFull).toBe('999px');
    expect(structural.motionFast).toBe('120ms');
    expect(structural.motionBase).toBe('150ms');
    expect(structural.motionSlow).toBe('200ms');

    // CSS var-name map covers every token key.
    const expectedTokenKeys = new Set([
      ...surfaceKeys,
      ...textKeys,
      'crit',
      'critOn',
      'critBg',
      'warn',
      'warnOn',
      'warnBg',
      'ok',
      'okOn',
      'okBg',
      'info',
      'infoOn',
      'infoBg',
      'brand2',
      'shadowSm',
      'shadowMd',
      'shadowLg',
    ]);
    for (const k of expectedTokenKeys) {
      expect(
        (tokenCssVarNames as Record<string, string>)[k],
        `tokenCssVarNames missing ${k}`,
      ).toMatch(/^--ow-/);
    }
  });

  // @ac AC-07
  test('frontend-foundation/AC-07 — no var(--mui-*) references in source', () => {
    const offenders: string[] = [];
    for (const f of listFiles(SRC_DIR)) {
      const src = readFileSync(f, 'utf8');
      if (/var\(--mui-/.test(src)) {
        offenders.push(f);
      }
    }
    expect(
      offenders,
      `files reference --mui-* (must use --ow-*): ${offenders.join(', ')}`,
    ).toHaveLength(0);
  });
});
