# OpenWatch Frontend Design Tokens

> **Status:** Locked 2026-05-30
> **Authority:** This document defines every `--ow-*` CSS variable consumed by `frontend/`. If the executable theme at `frontend/src/theme/` disagrees with this table, the executable form is wrong.
> **Audience:** Anyone writing or reviewing frontend components.

---

## What this document is

Every visible surface in the OpenWatch frontend ultimately resolves through a CSS variable defined here. MUI v7's CSS-vars mode reads these variables; component styles reference them; the dark and light color schemes differ only in the values assigned to them.

The token names come from the prototype at `docs/engineering/prototypes/openwatch-v1/`. Prototype values become the **dark** scheme; **light** values are computed in this document.

Naming rule: every variable is prefixed `--ow-*`. This is set via MUI v7's `cssVarPrefix: 'ow'` so there are no collisions with library-default `--mui-*` variables.

---

## Surfaces (background + line)

The frontend uses a 4-tier surface scale. `bg-0` is the page canvas; `bg-1` is the lightest elevated surface (sidebar, top bar, widgets); `bg-2` is hover surfaces; `bg-3` is the most elevated surface (active states, drawers).

| Token | Dark | Light | Usage |
|-------|------|-------|-------|
| `--ow-bg-0` | `#0b0c0f` | `#ffffff` | Page canvas |
| `--ow-bg-1` | `#111317` | `#f6f7f9` | Sidebar, topbar, widgets |
| `--ow-bg-2` | `#161a20` | `#eef0f3` | Hover states |
| `--ow-bg-3` | `#1c2129` | `#e3e6eb` | Active states, drawers |
| `--ow-line` | `#232831` | `#d8dce2` | Borders, dividers |
| `--ow-line-2` | `#2c323d` | `#c4ccd6` | Hover borders, separators |

Light values target ≥4.5:1 contrast for primary text on `--ow-bg-0` and ≥3:1 for borders on adjacent surfaces.

## Text

Four tiers of text emphasis. `fg-0` is the most prominent; `fg-3` is decorative/disabled.

| Token | Dark | Light | Usage |
|-------|------|-------|-------|
| `--ow-fg-0` | `#f3f5f8` | `#0b0c0f` | Primary text |
| `--ow-fg-1` | `#cfd4dd` | `#1c2129` | Secondary text |
| `--ow-fg-2` | `#8a93a3` | `#5b6473` | Muted labels |
| `--ow-fg-3` | `#5b6473` | `#8a93a3` | Tertiary, placeholders |

## Severity / semantic colors

Four semantic colors. Each carries three forms:

- **base** — the fill or stroke color (e.g., button background, icon color, status dot)
- **on** — the foreground that's legible on top of `base` (text on a primary button, icon on a status pill)
- **bg** — the soft-tinted background that pairs with base (alert chip background, hover ring)

The dark severity values come from the prototype's `oklch()` colors. Light values lower the L% to ~52–58 so text on white passes WCAG 2.1 AA (4.5:1).

### Critical (red)

| Token | Dark | Light |
|-------|------|-------|
| `--ow-crit` | `oklch(64% 0.20 25)` | `oklch(52% 0.22 25)` |
| `--ow-crit-on` | `#0a1424` | `#ffffff` |
| `--ow-crit-bg` | `oklch(35% 0.12 25 / 0.18)` | `oklch(95% 0.04 25)` |

### Warning (amber)

| Token | Dark | Light |
|-------|------|-------|
| `--ow-warn` | `oklch(78% 0.15 75)` | `oklch(58% 0.15 75)` |
| `--ow-warn-on` | `#0a1424` | `#ffffff` |
| `--ow-warn-bg` | `oklch(50% 0.12 75 / 0.16)` | `oklch(96% 0.06 75)` |

### Ok (green)

| Token | Dark | Light |
|-------|------|-------|
| `--ow-ok` | `oklch(72% 0.16 155)` | `oklch(48% 0.16 155)` |
| `--ow-ok-on` | `#0a1424` | `#ffffff` |
| `--ow-ok-bg` | `oklch(45% 0.10 155 / 0.18)` | `oklch(95% 0.05 155)` |

### Info (blue) — also the brand accent

| Token | Dark | Light |
|-------|------|-------|
| `--ow-info` | `oklch(70% 0.13 245)` | `oklch(52% 0.15 245)` |
| `--ow-info-on` | `#0a1424` | `#ffffff` |
| `--ow-info-bg` | `oklch(45% 0.12 245 / 0.18)` | `oklch(95% 0.04 245)` |

### Brand secondary (logo gradient tail)

| Token | Dark | Light |
|-------|------|-------|
| `--ow-brand-2` | `oklch(60% 0.20 290)` | `oklch(52% 0.20 290)` |

Used only in the logo gradient. Not a general-purpose color.

### OS brand colors (rare)

| Token | Both modes |
|-------|------------|
| `--ow-os-ubuntu` | `#e95420` |
| `--ow-os-rhel` | `#ee0000` |

Used only in OS-identity decoration on Host Detail. Same color in both modes (OS brand identity does not adapt).

## Typography

| Token | Value |
|-------|-------|
| `--ow-font-sans` | `'Inter', system-ui, -apple-system, sans-serif` |
| `--ow-font-mono` | `'JetBrains Mono', ui-monospace, monospace` |
| `--ow-font-size-base` | `14px` |
| `--ow-line-height-base` | `1.45` |

Inter weights loaded: 400, 500, 600, 700. JetBrains Mono weights loaded: 400, 500. Fonts ship via Google Fonts in `index.html` (matches prototype) or self-hosted (decision deferred to v0.2 — for v0 we accept the Google Fonts CDN dependency).

## Border radius

| Token | Value | Usage |
|-------|-------|-------|
| `--ow-radius` | `8px` | Cards, drawers, dialogs |
| `--ow-radius-sm` | `6px` | Inputs, small chips, buttons |
| `--ow-radius-full` | `999px` | Pills, status badges |

## Shadows / elevation

Shadows differ per mode — the dark-mode `rgba(0,0,0,0.45)` shadows are too heavy for light surfaces.

| Token | Dark | Light |
|-------|------|-------|
| `--ow-shadow-sm` | `0 1px 2px rgba(0,0,0,0.3)` | `0 1px 2px rgba(11,12,15,0.08)` |
| `--ow-shadow-md` | `0 4px 12px rgba(0,0,0,0.4)` | `0 4px 12px rgba(11,12,15,0.10)` |
| `--ow-shadow-lg` | `0 16px 40px rgba(0,0,0,0.45)` | `0 16px 40px rgba(11,12,15,0.15)` |

Drawer / floating menu use `--ow-shadow-lg`; widgets use no shadow (border-only); avatar dropdown uses `--ow-shadow-md`.

## Motion

| Token | Value | Usage |
|-------|-------|-------|
| `--ow-motion-fast` | `120ms` | Button/link hover state transitions |
| `--ow-motion-base` | `150ms` | Drawer slide, modal fade |
| `--ow-motion-slow` | `200ms` | Tray panels, large drawers |

All transitions use the default `ease` curve unless explicitly overridden in a component.

## Spacing scale

Tied to MUI v7's `theme.spacing(n)` function — `n` × 4px — but selected scale points are exposed as tokens for direct CSS use:

| Token | Value |
|-------|-------|
| `--ow-space-1` | `4px` |
| `--ow-space-2` | `8px` |
| `--ow-space-3` | `12px` |
| `--ow-space-4` | `16px` |
| `--ow-space-5` | `20px` |
| `--ow-space-6` | `24px` |
| `--ow-space-7` | `28px` (sidebar→content gutter) |

---

## How MUI v7 sees this

`extendTheme({ cssVarPrefix: 'ow', colorSchemes: { light: {...}, dark: {...} }, defaultColorScheme: 'dark' })` produces theme objects whose `palette.*` fields reference the variables above. Example:

```ts
{
  palette: {
    background: {
      default: 'var(--ow-bg-0)',
      paper: 'var(--ow-bg-1)',
    },
    text: {
      primary: 'var(--ow-fg-0)',
      secondary: 'var(--ow-fg-1)',
      disabled: 'var(--ow-fg-3)',
    },
    primary: {
      main: 'var(--ow-info)',
      contrastText: 'var(--ow-info-on)',
    },
    error: {
      main: 'var(--ow-crit)',
      contrastText: 'var(--ow-crit-on)',
    },
    warning: {
      main: 'var(--ow-warn)',
      contrastText: 'var(--ow-warn-on)',
    },
    success: {
      main: 'var(--ow-ok)',
      contrastText: 'var(--ow-ok-on)',
    },
    info: {
      main: 'var(--ow-info)',
      contrastText: 'var(--ow-info-on)',
    },
    divider: 'var(--ow-line)',
  },
  shape: { borderRadius: 8 /* matches --ow-radius */ },
}
```

The `colorSchemes.light` and `colorSchemes.dark` variants supply the same MUI palette structure pointing at the same `--ow-*` variables; MUI v7 emits the appropriate variable values per `data-mui-color-scheme` attribute on `<html>`.

## How a component sees this

Components prefer the MUI `sx` prop or `styled()` wrappers, which receive the theme and resolve to `var(--ow-*)`. Direct CSS that bypasses MUI (e.g. in a custom hand-styled component) reads variables straight:

```tsx
const Surface = styled('div')(({ theme }) => ({
  background: 'var(--ow-bg-1)',
  border: '1px solid var(--ow-line)',
  borderRadius: 'var(--ow-radius)',
  color: 'var(--ow-fg-0)',
}));
```

## How no-FOUC works

A synchronous `<script>` in `index.html` `<head>` (before the React bundle parses) reads `localStorage.getItem('ow-color-scheme')`, falls back to `system` (which resolves via `window.matchMedia('(prefers-color-scheme: dark)')`), and sets `data-mui-color-scheme="light"` or `"dark"` on `<html>`. MUI v7 ships this helper as `getInitColorSchemeScript({ attribute: 'data-mui-color-scheme', defaultMode: 'system' })`. We use it verbatim.

When React mounts and a user selects a different mode via the Settings toggle, `useColorScheme().setMode(newMode)` updates the attribute, re-renders subscribing components, and persists to `localStorage`.

## How system-mode change propagation works

```ts
useEffect(() => {
  const mq = window.matchMedia('(prefers-color-scheme: dark)');
  const onChange = () => {
    // mode === 'system' → re-resolve and re-apply
    if (mode === 'system') setSystemMode(mq.matches ? 'dark' : 'light');
  };
  mq.addEventListener('change', onChange);
  return () => mq.removeEventListener('change', onChange);
}, [mode]);
```

(MUI v7's `useColorScheme()` does this internally; we don't write it ourselves.)

---

## Per-token audit checklist (for the foundation spec's AC tests)

The `frontend-foundation` spec asserts the executable theme matches this document. A test reads `frontend/src/theme/tokens.ts` and verifies:

1. Every token from §Surfaces, §Text, §Severity, §Typography, §Radius, §Shadows, §Motion, §Spacing is present.
2. Every token in this document maps to an exported constant or theme path.
3. The dark + light values exactly match the tables above.
4. No `var(--mui-*)` references slip in (must be `var(--ow-*)`).
5. axe-core scan of a rendered shell passes WCAG 2.1 AA in **both** dark and light modes.

When this document and `tokens.ts` disagree, this document wins. Update `tokens.ts` to match, never the other way.

---

## Open follow-ups

- **Self-host Inter + JetBrains Mono** — current decision is Google Fonts CDN. For air-gapped deployments this fails. Self-host in v0.2.
- **Component-specific tokens** — once Storybook is in place, document per-component overrides (e.g., dashboard-widget elevation) as a sub-set of these tokens.
- **Reduced-motion mode** — `prefers-reduced-motion: reduce` should zero out `--ow-motion-*`. Implement at the same time as the foundation spec.
