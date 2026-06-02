// @spec frontend-shell-account-menu
// @ac AC-01
//
// AC-01: source-inspection — the avatar MUST be rendered as a <button>
// with aria-haspopup="menu" and aria-expanded driven by an `open`
// state. The legacy <div aria-label={`Account: ...`}> markup MUST be
// gone. This is the only AC in this file by design — specter v0.13.2's
// coverage walker has a per-file AC-credit bug; one AC per file
// sidesteps it.

import { describe, expect, test, beforeEach } from 'vitest';
import { TOPBAR_SRC, clearAuth } from './shell-account-menu-helpers';

beforeEach(clearAuth);

describe('frontend-shell-account-menu — structural', () => {
  test('frontend-shell-account-menu/AC-01 — avatar is a <button> with aria-haspopup, not a <div>', () => {
    expect(TOPBAR_SRC).toMatch(/<button[^>]*aria-haspopup\s*=\s*['"]menu['"]/);
    expect(TOPBAR_SRC).toMatch(/aria-expanded\s*=\s*\{[^}]*open/);
    expect(TOPBAR_SRC).not.toMatch(/<div[^>]*aria-label=\{\s*`Account:/);
  });
});
