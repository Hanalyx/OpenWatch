// Design tokens for app/frontend/.
//
// SSOT: app/docs/frontend_design_tokens.md. If a token here disagrees
// with the doc, the doc wins — update this file to match.
//
// Each token is namespaced under --ow-* via MUI v7's cssVarPrefix: 'ow'.
// Light + dark values exist for every color-bearing token; structural
// tokens (radii, motion, spacing, type) are mode-invariant.
//
// Spec: frontend-foundation AC-06 (this file is the test target).

/* eslint-disable sort-keys */

export interface ModeColorTokens {
  bg0: string;
  bg1: string;
  bg2: string;
  bg3: string;
  line: string;
  line2: string;

  fg0: string;
  fg1: string;
  fg2: string;
  fg3: string;

  crit: string;
  critOn: string;
  critBg: string;
  critHex: string; // sRGB equivalent of crit; required by MUI augmentColor

  warn: string;
  warnOn: string;
  warnBg: string;
  warnHex: string;

  ok: string;
  okOn: string;
  okBg: string;
  okHex: string;

  info: string;
  infoOn: string;
  infoBg: string;
  infoHex: string;

  brand2: string;
  brand2Hex: string;

  shadowSm: string;
  shadowMd: string;
  shadowLg: string;
}

export const darkTokens: ModeColorTokens = {
  bg0: '#0b0c0f',
  bg1: '#111317',
  bg2: '#161a20',
  bg3: '#1c2129',
  line: '#232831',
  line2: '#2c323d',

  fg0: '#f3f5f8',
  fg1: '#cfd4dd',
  fg2: '#8a93a3',
  fg3: '#5b6473',

  crit: 'oklch(64% 0.20 25)',
  critOn: '#0a1424',
  critBg: 'oklch(35% 0.12 25 / 0.18)',
  critHex: '#e36161',

  warn: 'oklch(78% 0.15 75)',
  warnOn: '#0a1424',
  warnBg: 'oklch(50% 0.12 75 / 0.16)',
  warnHex: '#e4a647',

  ok: 'oklch(72% 0.16 155)',
  okOn: '#0a1424',
  okBg: 'oklch(45% 0.10 155 / 0.18)',
  okHex: '#4ec894',

  info: 'oklch(70% 0.13 245)',
  infoOn: '#0a1424',
  infoBg: 'oklch(45% 0.12 245 / 0.18)',
  infoHex: '#5b9eff',

  brand2: 'oklch(60% 0.20 290)',
  brand2Hex: '#a26ddc',

  shadowSm: '0 1px 2px rgba(0,0,0,0.3)',
  shadowMd: '0 4px 12px rgba(0,0,0,0.4)',
  shadowLg: '0 16px 40px rgba(0,0,0,0.45)',
};

export const lightTokens: ModeColorTokens = {
  bg0: '#ffffff',
  bg1: '#f6f7f9',
  bg2: '#eef0f3',
  bg3: '#e3e6eb',
  line: '#d8dce2',
  line2: '#c4ccd6',

  fg0: '#0b0c0f',
  fg1: '#1c2129',
  fg2: '#5b6473',
  fg3: '#8a93a3',

  crit: 'oklch(52% 0.22 25)',
  critOn: '#ffffff',
  critBg: 'oklch(95% 0.04 25)',
  critHex: '#c63b30',

  warn: 'oklch(58% 0.15 75)',
  warnOn: '#ffffff',
  warnBg: 'oklch(96% 0.06 75)',
  warnHex: '#b67821',

  ok: 'oklch(48% 0.16 155)',
  okOn: '#ffffff',
  okBg: 'oklch(95% 0.05 155)',
  okHex: '#2a8e62',

  info: 'oklch(52% 0.15 245)',
  infoOn: '#ffffff',
  infoBg: 'oklch(95% 0.04 245)',
  infoHex: '#2d6cd1',

  brand2: 'oklch(52% 0.20 290)',
  brand2Hex: '#7d4cb5',

  shadowSm: '0 1px 2px rgba(11,12,15,0.08)',
  shadowMd: '0 4px 12px rgba(11,12,15,0.10)',
  shadowLg: '0 16px 40px rgba(11,12,15,0.15)',
};

// OS brand colors (rare; mode-invariant).
export const osBrand = {
  ubuntu: '#e95420',
  rhel: '#ee0000',
};

// Structural tokens — mode-invariant.
export const structural = {
  fontSans: "'Inter', system-ui, -apple-system, sans-serif",
  fontMono: "'JetBrains Mono', ui-monospace, monospace",
  fontSizeBase: '14px',
  lineHeightBase: 1.45,

  radius: '8px',
  radiusSm: '6px',
  radiusFull: '999px',

  motionFast: '120ms',
  motionBase: '150ms',
  motionSlow: '200ms',

  space1: '4px',
  space2: '8px',
  space3: '12px',
  space4: '16px',
  space5: '20px',
  space6: '24px',
  space7: '28px',
};

// Token-name → CSS-variable-name map. Used by tests (AC-06) to validate
// that every documented token is present and that MUI maps it through.
//
// Spec: frontend-foundation AC-06 / AC-16.
export const tokenCssVarNames = {
  bg0: '--ow-bg-0',
  bg1: '--ow-bg-1',
  bg2: '--ow-bg-2',
  bg3: '--ow-bg-3',
  line: '--ow-line',
  line2: '--ow-line-2',
  fg0: '--ow-fg-0',
  fg1: '--ow-fg-1',
  fg2: '--ow-fg-2',
  fg3: '--ow-fg-3',
  crit: '--ow-crit',
  critOn: '--ow-crit-on',
  critBg: '--ow-crit-bg',
  warn: '--ow-warn',
  warnOn: '--ow-warn-on',
  warnBg: '--ow-warn-bg',
  ok: '--ow-ok',
  okOn: '--ow-ok-on',
  okBg: '--ow-ok-bg',
  info: '--ow-info',
  infoOn: '--ow-info-on',
  infoBg: '--ow-info-bg',
  brand2: '--ow-brand-2',
  shadowSm: '--ow-shadow-sm',
  shadowMd: '--ow-shadow-md',
  shadowLg: '--ow-shadow-lg',
} as const;
