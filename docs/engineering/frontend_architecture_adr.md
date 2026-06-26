# OpenWatch Frontend Architecture (ADR)

> **Status:** Locked 2026-05-30
> **Authority:** This document is the rulebook for `frontend/`. If code at `frontend/` violates a rule here, the code is wrong.
> **Audience:** Anyone scaffolding, specing, or implementing frontend modules for OpenWatch.

---

## Why this document exists

The Go rebuild ships a fresh frontend at `frontend/`. Without an ADR up front, every spec downstream is built on assumed defaults — router choice leaks into data-fetching choice leaks into auth-flow choice, and the first three specs disagree on which library owns which concern.

This document **locks** the stack and the conventions. It is reviewed only when a hard external pressure forces a change (library deprecation, breaking version, security CVE in a transitive dep). Day-to-day work consults this; it does not edit it.

---

## Context

- **Backend**: Go (chi router, pgx, sqlc, embed.FS, OpenAPI 3.1 SSOT).
- **Serving**: Single binary. Frontend embedded into the binary via `//go:embed all:spa` in `internal/server/spa.go` (the `vite build` output is copied into `internal/server/spa/` at build time). No nginx, no separate SPA host (per `openwatch_roadmap.md` L21, L87).
- **Auth contract** (per `stage_2_slice_a.md` L25): both session cookies (browser) and JWT (API consumers). The browser frontend uses **session cookies** with CSRF protection — **not** JWT in `localStorage`.
- **Prototype** at `docs/engineering/prototypes/openwatch-v1/` defines the visual language (9 HTML pages, dark-only). The frontend implements the same language in a real component system with both dark and light modes.
- **Page rollout** is slice-driven, not page-list-driven. Each backend slice unblocks the corresponding frontend pages.

---

## Decisions

### D-01: React 19 (latest stable)

React 19 is the foundation. Adopt R19 conventions:

- **Ref as prop** — no `forwardRef` in custom components.
- **`<Context value={...}>`** — no `.Provider` suffix.
- **`use(promise)`** — paired with TanStack Query `useSuspenseQuery` for declarative loading-state composition.
- **`useActionState` + `useFormStatus`** — reduces react-hook-form boilerplate around pending/error states in forms.
- **`useOptimistic`** — optimistic UI for toggles, mute/ack, and widget reorder.
- **Document metadata in JSX** — `<title>`, `<meta>` per page without `react-helmet`.

### D-02: TypeScript (strict mode, no implicit any)

`tsconfig.json` enables `strict`, `noUncheckedIndexedAccess`, `noFallthroughCasesInSwitch`, `noImplicitOverride`. Type holes are bugs, not style preferences.

### D-03: MUI v7 with CSS-vars mode

`@mui/material` v7 in CSS-variables mode (`extendTheme` + `<CssVarsProvider>`).

- **Why CSS-vars**: matches the prototype's `var(--*)` token model exactly; component-level theme overrides become trivial; per-mode tokens are real CSS variables, not JS-runtime branching.
- **Why MUI v7**: A11y baked in, mature component coverage (Drawer, Menu, ToggleButtonGroup, DataGrid), peer-supports R19.
- `cssVarPrefix: 'ow'` — every variable is `--ow-*`. No collisions with library-default `--mui-*`.

### D-04: Vite (latest)

- TS support is native; HMR is fast; output is what `go:embed` consumes.
- `vite.config.ts` sets `build.outDir: 'dist'` (the path embedded by Go).
- Dev server proxies `/api → https://localhost:8443` with `secure: false` to accept the dev self-signed cert.

### D-05: TanStack Router v1

- Type-safe routes. Route params and search params are typed at the call site.
- File-based routing optional; we use the declarative-tree API for explicitness.
- Pairs cleanly with TanStack Query for prefetching on route enter.

### D-06: TanStack Query v5 for server state

- `useSuspenseQuery` + `<Suspense>` for loading states.
- Cursor-paginated lists use `useInfiniteQuery` (matches backend pagination contract in `api_design_principles.md`).
- Mutations call `queryClient.invalidateQueries` on success, or use `useOptimistic` when the change is local.

### D-07: API client via `openapi-typescript` + `openapi-fetch`

- `openapi-typescript` generates types from `api/openapi.yaml` into `frontend/src/api/schema.d.ts`.
- `openapi-fetch` is a 4 KB typed fetch wrapper. No heavier `orval` / RTK Query lock-in.
- **Spec is the contract**: when `openapi.yaml` changes, the TS types regenerate. Type errors at compile time are the contract drift signal.
- Generation command in `package.json`: `"api:types": "openapi-typescript ../api/openapi.yaml -o src/api/schema.d.ts"`. Run by CI and pre-commit.

### D-08: Session-cookie auth + CSRF (not JWT in localStorage)

Per `stage_2_slice_a.md`:

- Login (`POST /api/v1/auth/login`) returns a session cookie (`openwatch_session`, HttpOnly, Secure, SameSite=Lax) AND a body containing `{access_token, refresh_token, user}`.
- **The browser frontend ignores the body tokens**. The cookie is the only credential carried on subsequent requests.
- A **CSRF token** is read from a `XSRF-TOKEN` cookie (server-set, non-HttpOnly) and echoed on mutating requests via the `X-CSRF-Token` header. This is the double-submit-cookie pattern.
- No `localStorage` for auth state. The frontend reads identity only from `GET /api/v1/auth/me` and Zustand caches it in memory.

### D-09: Forms — react-hook-form + zod

- `react-hook-form` for form state.
- `zod` schemas for validation.
- For shapes that appear in `openapi.yaml`, **derive zod schemas from the generated TS types** where feasible (or keep them hand-written but unit-test they match the OpenAPI shape).

### D-10: Client state — Zustand v5

- Single store per concern: `useAuthStore`, `useColorSchemeStore`, `useNotificationStore`.
- No Redux. No Context for shared mutable state (Context is reserved for theme/color-scheme propagation only).
- Stores expose actions; components consume slices via selectors.

### D-11: Drag & drop — @dnd-kit/core v6.3+

For the dashboard widget reorder (when the dashboard slice unblocks). Used nowhere else without explicit need.

### D-12: Icons — lucide-react

- Matches the prototype's visual language (every prototype SVG is a Lucide icon).
- Per-icon imports keep the bundle small.
- Do **not** mix `@mui/icons-material` into the same surface — pick one library, stick with it.

### D-13: Three-mode color scheme — light, dark, system

- Default mode = `system` (follows `prefers-color-scheme`).
- User override persists to `localStorage` under key `ow-color-scheme` ∈ `{'light','dark','system'}`.
- **No FOUC**: a synchronous script in `index.html` `<head>` reads the stored preference and sets `data-mui-color-scheme="light|dark"` on `<html>` before React mounts. MUI v7 ships `getInitColorSchemeScript()` — we use it verbatim.
- System changes propagate live: `matchMedia('(prefers-color-scheme: dark)').addEventListener('change', ...)` updates the mode without reload.
- Settings UX: a three-segment toggle (Light / Dark / System). When System is selected, the label shows what it currently resolves to: "System (currently dark)".

### D-14: Design tokens — dual-mode, prefixed

- Every token is a `--ow-*` CSS variable defined per mode.
- Severity colors include explicit on-color foregrounds: `--ow-info`, `--ow-info-on`, `--ow-info-bg` (and the same for crit/warn/ok).
- Shadows, line/border, surface elevations all per-mode.
- Full table lives in `docs/engineering/frontend_design_tokens.md`. The frontend's `theme/index.ts` is the executable form; the doc is the human-readable form.

### D-15: Testing — Vitest + RTL 16 + Playwright

- **Vitest** (Vite-native, Jest-compatible API) for unit and integration tests of components/hooks/stores.
- **`@testing-library/react` v16** (required for R19) for component tests.
- **Playwright** for e2e flows (login → hosts → host detail).
- **axe-core** runs in Playwright e2e as the WCAG gate. Zero violations on `wcag2a` + `wcag2aa` rule sets.

### D-16: A11y target — WCAG 2.1 AA

- Every interactive element keyboard-reachable.
- Every form control labelled (no placeholder-as-label).
- Every page passes axe-core in CI before merge.
- The findings-ui spec (template) already encodes this — every page spec inherits AC-12-style axe assertions.

### D-17: Spec home — `specs/frontend/`

- New directory parallel to `specs/{api,system,release}/`.
- Same Specter `.spec.yaml` schema as backend specs.
- Spec IDs prefix with `frontend-`: `frontend-foundation`, `frontend-auth-login`, etc.
- **Tier 1** for security-sensitive UX (auth, RBAC gating, foundation).
- **Tier 2** for feature pages (hosts, host detail, settings tabs).
- Coverage thresholds enforced by `specter.yaml`: Tier 1 = 100%, Tier 2 = 80%.

### D-18: Where the frontend lives + how it ships

- **Tree**: `frontend/` — sibling of `internal/`, `cmd/`, `api/`.
- **Build output**: `frontend/dist/` (set in `vite.config.ts`).
- **Embed**: `make build` copies the `frontend/dist/` output into `internal/server/spa/`, which `internal/server/spa.go` embeds via `//go:embed all:spa`. SPA fallback (non-`/api/` requests serve `index.html`) is implemented in `newSPAHandler`.
- **Single artifact**: frontend updates require a binary rebuild. No separate SPA hotfix path. Acceptable trade-off for security tooling with infrequent UI changes (per `openwatch_roadmap.md` L245).

### D-19: Dev server proxy

- `vite.config.ts` proxies `/api` to `https://localhost:8443` with `secure: false`.
- Dev workflow: `make run` (Go server on :8443) in one terminal; `npm run dev` (Vite on :5173) in another. Browser opens `http://localhost:5173`; the proxy routes API calls.
- CSRF cookie is set by the Go server on first response; Vite passes cookies through transparently.

### D-20: React Compiler — deferred

- Optional R19 feature. Stable but new in early 2026.
- We ship v0 without it. Add later as a pure build-step change (no source edits required).
- This decision reviewed when 3+ teams in the React ecosystem report it as low-friction.

### D-21: Internationalization — deferred

- English only in v0. No `react-i18next`.
- Strings live inline in components for v0. The first paying customer with a non-English ask drives the i18n decision.

---

## Consequences

### Positive

- One stack to learn. Every page has the same shape: route → suspense → query → form → mutation → invalidate.
- A11y is non-optional and CI-gated.
- Auth follows the security recommendation in the roadmap (cookies + CSRF, not localStorage tokens).
- Single-binary install survives the frontend (`go:embed`).

### Negative

- Frontend updates require a backend rebuild. CI release surface includes the frontend build every cut.
- TanStack Router is less broadly known than React Router; onboarding cost is real but small.
- CSS-vars mode in MUI is mature but pre-existing tutorials lean on the legacy palette API.

### Trade-offs explicitly accepted

- **No SSR** — pure SPA. Initial paint shows a skeleton until the bundle parses. Acceptable: this is an internal admin tool, not a public marketing site.
- **No code-splitting by route in v0** — Vite splits vendor automatically; per-route splits added when bundle audit shows the need.
- **English only** — see D-21.
- **No React Compiler** — see D-20.

---

## Stack summary

| Concern | Choice | Min version |
|---------|--------|-------------|
| Framework | React | 19.x |
| Language | TypeScript | 5.x (strict) |
| Build tool | Vite | 5.x or 6.x (latest stable) |
| UI library | MUI Material | 7.x (CSS-vars mode) |
| Icons | lucide-react | 0.460+ |
| Router | @tanstack/react-router | 1.85+ |
| Server state | @tanstack/react-query | 5.59+ |
| API types | openapi-typescript | 7.x |
| API client | openapi-fetch | 0.13+ |
| Forms | react-hook-form | 7.54+ |
| Validation | zod | 3.x |
| Client state | zustand | 5.x |
| DnD | @dnd-kit/core | 6.3+ |
| Test runner | vitest | 2.1+ |
| Component testing | @testing-library/react | 16.x |
| E2E | @playwright/test | latest |
| A11y CI | @axe-core/playwright | latest |

---

## Open follow-ups (not blocking v0)

- **Real-time transport for Activity page** (`Live` toggle). SSE vs. WebSocket. Decided when OS Intelligence backend lands. See `docs/engineering/activity_and_os_intelligence.md`.
- **React Compiler adoption** — reviewed when ecosystem reports stabilize.
- **Bundle splitting per route** — when initial-paint metrics warrant.
- **i18n** — when a customer demands non-English UI.
- **Storybook** — useful for design-system maintenance; deferred until token-set proves stable in real pages.
