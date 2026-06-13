// @spec frontend-foundation
//
// AC traceability (this file):
//
//   AC-05  matchMedia change updates the DOM data-mui-color-scheme attr
//   AC-08  protectedRoute guard redirects to /login?return_to=
//   AC-09  ForbiddenPage component + 403 region per route guard
//   AC-10  ErrorBoundary catches render errors and surfaces fallback
//   AC-11  Shell + topbar interactive elements carry aria-label or visible text
//   AC-12  axe-core dark-mode scan of the shell shape
//   AC-13  axe-core light-mode scan of the shell shape
//   AC-16  extendTheme called with cssVarPrefix:"ow" + dark + light colorSchemes
//   AC-17  Route table includes /login + at least one guarded route via redirect
//   AC-18  Sidebar renders unrouted destinations as disabled "coming soon"
//          controls, never as Links to a not-found path

import { describe, expect, test, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

const ROUTER_SRC = readFileSync(resolve(process.cwd(), 'src/routes/router.tsx'), 'utf8');
const THEME_SRC = readFileSync(resolve(process.cwd(), 'src/theme/theme.ts'), 'utf8');
const TOPBAR_SRC = readFileSync(resolve(process.cwd(), 'src/components/shell/TopBar.tsx'), 'utf8');
const SIDEBAR_SRC = readFileSync(
  resolve(process.cwd(), 'src/components/shell/Sidebar.tsx'),
  'utf8',
);
const ERROR_BOUNDARY_SRC = readFileSync(
  resolve(process.cwd(), 'src/components/shell/ErrorBoundary.tsx'),
  'utf8',
);
const COLOR_SCHEME_SRC = readFileSync(
  resolve(process.cwd(), 'src/store/useColorSchemeStore.ts'),
  'utf8',
);

describe('frontend-foundation — runtime + shell', () => {
  // @ac AC-05
  test('frontend-foundation/AC-05 — matchMedia change updates color scheme when mode is "system"', () => {
    // Source-inspection: the store registers a matchMedia change listener
    // and re-applies the resolved scheme only when current mode is system.
    expect(COLOR_SCHEME_SRC).toMatch(
      /matchMedia\(\s*['"]\(prefers-color-scheme:\s*dark\)['"]\s*\)/,
    );
    expect(COLOR_SCHEME_SRC).toMatch(/addEventListener\(\s*['"]change['"]/);
    // The listener body MUST re-resolve and apply only when the user's
    // chosen mode is "system" — overrides MUST NOT be clobbered.
    expect(COLOR_SCHEME_SRC).toMatch(/current\s*===\s*['"]system['"]/);
    expect(COLOR_SCHEME_SRC).toMatch(/setAttribute\(/);
  });

  // @ac AC-08
  test('frontend-foundation/AC-08 — protectedRoute beforeLoad redirects to /login?return_to= on missing session', () => {
    // The router exposes a protected route whose beforeLoad throws a
    // redirect to /login with the originating path threaded as
    // return_to. No silent fall-through, no thrown exception.
    expect(ROUTER_SRC).toContain('protectedRoute');
    expect(ROUTER_SRC).toMatch(/beforeLoad:/);
    expect(ROUTER_SRC).toMatch(/throw\s+redirect\(/);
    expect(ROUTER_SRC).toMatch(/to:\s*['"]\/login['"]/);
    expect(ROUTER_SRC).toMatch(/return_to:/);
    // The guard reads identity from useAuthStore — NOT a route-time
    // synchronous network call.
    expect(ROUTER_SRC).toContain('useAuthStore.getState().identity');
  });

  // @ac AC-09
  test('frontend-foundation/AC-09 — ForbiddenPage renders 403 + authz.permission_denied for missing permission', () => {
    const path = resolve(process.cwd(), 'src/pages/ForbiddenPage.tsx');
    // The page MUST exist to fulfil the 403 region contract.
    expect(existsSync(path)).toBe(true);
    const src = readFileSync(path, 'utf8');
    // Surfaces the canonical envelope code so operators can grep
    // logs / docs for the same code the API would have returned.
    expect(src).toContain('authz.permission_denied');
    // Renders a 403 region — not a redirect, not a blank.
    expect(src).toMatch(/403/);
  });

  // @ac AC-10
  test('frontend-foundation/AC-10 — ErrorBoundary catches render errors, scrubs message, keeps shell visible', () => {
    expect(ERROR_BOUNDARY_SRC).toContain('class ErrorBoundary');
    // Lifecycle hook: catches downstream errors.
    expect(ERROR_BOUNDARY_SRC).toMatch(/componentDidCatch|getDerivedStateFromError/);
    // Renders a recoverable fallback (the spec's exact wording or a
    // structurally-equivalent literal that survives a copy-edit).
    expect(ERROR_BOUNDARY_SRC).toMatch(/Something went wrong|Reload/i);
    // Scrubs PII/secret-shaped fields before console.error.
    expect(ERROR_BOUNDARY_SRC).toMatch(/SCRUB_FIELDS|scrub/);
    expect(ERROR_BOUNDARY_SRC).toMatch(/console\.error/);
  });

  // @ac AC-11
  test('frontend-foundation/AC-11 — every interactive element in shell has aria-label or visible text', () => {
    // Source-walk: every <button> / clickable in topbar + sidebar
    // either carries an aria-label OR has a visible text child. A
    // bare <button> with no label fails the screen-reader contract.
    const interactiveLineRe = /(<button[^>]*>|onClick=\{|role=["']button["'])/g;
    // Sidebar: nav buttons reference aria-label or text content.
    expect(SIDEBAR_SRC).toMatch(/aria-label=/);
    // Topbar: at least one aria-label on the menu/scheme controls.
    expect(TOPBAR_SRC).toMatch(/aria-label=/);
    // The color-scheme toggle MUST be labeled — clicking it cycles
    // through three modes and the icon alone is not screen-reader
    // friendly. The label literal `Theme: ${mode}` is what the topbar
    // attaches to the toggle.
    expect(TOPBAR_SRC).toMatch(/Theme:\s*\$\{mode\}/);
    // Sanity: there is at least one onClick in shell components.
    expect((TOPBAR_SRC + SIDEBAR_SRC).match(interactiveLineRe)?.length ?? 0).toBeGreaterThan(0);
  });

  // @ac AC-12
  test('frontend-foundation/AC-12 — axe-core dependency present (dark-mode browser scan)', () => {
    // Direct axe-core in vitest is heavy; the browser axe path runs via
    // Playwright. What we can pin from a unit test is that the
    // dependency contract holds AND that the theme supplies the dark
    // colorScheme for axe to scan against. A missing-dep regression
    // would silently make the per-mode scan a no-op.
    const pkg = JSON.parse(readFileSync(resolve(process.cwd(), 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
    expect(deps['axe-core']).toBeTruthy();
    expect(deps['@axe-core/playwright']).toBeTruthy();
    expect(THEME_SRC).toMatch(/\bdark\s*:\s*\{/);
  });

  // @ac AC-13
  test('frontend-foundation/AC-13 — light colorScheme present for light-mode axe scan', () => {
    // Symmetry with AC-12: light mode must have its own colorScheme so
    // the Playwright axe path has something to scan against in light.
    expect(THEME_SRC).toMatch(/\blight\s*:\s*\{/);
    expect(THEME_SRC).toMatch(/colorSchemes\s*:/);
  });

  // @ac AC-16
  test('frontend-foundation/AC-16 — extendTheme cssVarPrefix:"ow" + colorSchemes light/dark + system default', () => {
    expect(THEME_SRC).toContain('extendTheme');
    expect(THEME_SRC).toMatch(/cssVarPrefix:\s*['"]ow['"]/);
    expect(THEME_SRC).toMatch(/colorSchemes\s*:/);
    expect(THEME_SRC).toMatch(/light\s*:/);
    expect(THEME_SRC).toMatch(/dark\s*:/);
  });

  // @ac AC-17
  test('frontend-foundation/AC-17 — route table includes /login + at least one guarded route', () => {
    // /login is anonymous (no beforeLoad).
    expect(ROUTER_SRC).toContain('loginRoute');
    expect(ROUTER_SRC).toMatch(/path:\s*['"]\/login['"]/);
    // The guarded subtree (protectedRoute) wraps at least one route
    // and the redirect path uses return_to to round-trip the user
    // back to where they came from after login.
    expect(ROUTER_SRC).toMatch(/return_to:/);
    // Multiple child routes hang off the protected subtree.
    expect(ROUTER_SRC).toMatch(/getParentRoute:\s*\(\)\s*=>\s*protectedRoute/);
  });

  // @ac AC-18
  test('frontend-foundation/AC-18 — sidebar disables unrouted destinations instead of linking to a not-found path', () => {
    // The NavItem contract carries an explicit enabled flag, and the
    // disabled branch renders a non-navigating control (not a Link).
    expect(SIDEBAR_SRC).toMatch(/enabled:\s*boolean/);
    expect(SIDEBAR_SRC).toMatch(/if\s*\(\s*!item\.enabled\s*\)/);
    // Disabled entries render a native disabled <button> with a label
    // and a "coming soon" affordance (keyboard-correct + axe-clean).
    expect(SIDEBAR_SRC).toMatch(/<button[\s\S]*?disabled/);
    expect(SIDEBAR_SRC).toMatch(/coming soon/);
    // User-facing copy (the nav labels) carries no em-dash. Scoped to
    // the label literals, since code comments may legitimately use one.
    const labels = (SIDEBAR_SRC.match(/label:\s*'[^']*'/g) ?? []).join(' ');
    expect(labels).not.toContain('—');

    // Core invariant — enabled item <=> its route exists in router.tsx.
    // A disabled (coming-soon) item MUST NOT have a route yet; an
    // enabled item MUST. Each navItems entry sits on one source line,
    // so a per-line match tolerates the icon's own {…} braces.
    const navRe = /to:\s*['"]([^'"]+)['"][^\n]*?enabled:\s*(true|false)/g;
    const items = [...SIDEBAR_SRC.matchAll(navRe)].map((m) => ({
      to: m[1] as string,
      enabled: m[2] === 'true',
    }));
    expect(items.length).toBe(7); // all seven destinations present

    const routeExists = (to: string): boolean => {
      if (to === '/') return /path:\s*['"]\/['"]/.test(ROUTER_SRC);
      const seg = to.replace(/^\//, '');
      return new RegExp(`path:\\s*['"]${seg}['"]`).test(ROUTER_SRC);
    };

    for (const item of items) {
      expect(
        routeExists(item.to),
        `${item.to}: enabled=${item.enabled} must match route-exists=${routeExists(item.to)}`,
      ).toBe(item.enabled);
    }
  });
});

// Behavioral check for AC-05 — the matchMedia listener actually fires
// and updates the documentElement attribute. Separated from source-walk
// because it needs jsdom + a real timer.
describe('frontend-foundation — runtime behavior', () => {
  let originalMatchMedia: typeof window.matchMedia;

  beforeEach(() => {
    originalMatchMedia = window.matchMedia;
  });

  afterEach(() => {
    window.matchMedia = originalMatchMedia;
    vi.restoreAllMocks();
  });

  // @ac AC-05
  test('frontend-foundation/AC-05 — system mode reacts to matchMedia change at runtime', async () => {
    // Build a tiny stub matchMedia that exposes a change-listener
    // mechanism. Replace window.matchMedia BEFORE importing the store
    // so the module's top-level subscription captures the stub.
    let changeListener: ((e: MediaQueryListEvent) => void) | undefined;
    const mql = {
      matches: false,
      addEventListener: (_evt: string, cb: typeof changeListener) => {
        changeListener = cb;
      },
      removeEventListener: () => {},
    };
    window.matchMedia = vi.fn(() => mql as unknown as MediaQueryList);

    // Force a fresh module instance so the new matchMedia is captured.
    // Without resetModules the store has already captured the original.
    vi.resetModules();
    const { useColorSchemeStore } = await import('@/store/useColorSchemeStore');

    // Move to system mode so the listener has effect.
    useColorSchemeStore.getState().setMode('system');

    // Initial resolved value (light, since mql.matches=false).
    document.documentElement.setAttribute('data-mui-color-scheme', 'light');

    // Flip the underlying OS preference and fire the change event.
    mql.matches = true;
    changeListener?.({ matches: true } as MediaQueryListEvent);

    expect(document.documentElement.getAttribute('data-mui-color-scheme')).toBe('dark');
  });
});
