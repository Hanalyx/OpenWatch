# OpenWatch v1 visual prototype — read-only design reference

> **Status:** Design source — **do not modify, do not build**, do not import from production code.
> **Captured:** 2026-05-30
> **Purpose:** Anchor the design system for the React + MUI v7 frontend at `app/frontend/`.

## What this is

Nine HTML pages plus two prototype-host JS files. Each HTML page is a self-contained dark-mode mockup of an OpenWatch screen, sharing a single design-token block at the top of every `<style>`. There is no real data; every value is hardcoded for visual fidelity.

| File | Page concept |
|------|--------------|
| `Dashboard.html` | Role-segmented dashboard with draggable widget grid |
| `Host Management.html` | Host inventory list/table |
| `Host Detail.html` | Compliance summary, framework filter, transactions, evidence |
| `Groups.html` | Group fleet |
| `Scans.html` | Scans list + detail |
| `Activity.html` | Unified incoming events (alerts + transactions + audit + intel) |
| `Reports.html` | Generated report list |
| `Terminal.html` | Embedded host shell |
| `Settings.html` | Profile + SSO + notifications + frameworks + known hosts |
| `tweaks-panel.jsx` | Prototype dev-tooling (edit-mode protocol) — **not production** |
| `kensa.js` | Fixture data only — **not production** |

## What it locks

- Dark color tokens (oklch semantic colors over a four-tier neutral scale)
- Layout shells (56px icon sidebar, sticky topbar with backdrop blur, 4-col widget grid, right drawer)
- Primitive component patterns (`.barline`, `.listrow`, `.sev-tag`, role-segment control)
- Inter + JetBrains Mono typography
- Icon vocabulary (Lucide)

## What it does NOT lock

- Light-mode values — derived in the token spec (`app/docs/frontend_design_tokens.md`)
- Real data shapes — those come from `app/api/openapi.yaml`
- Auth flow specifics — see the frontend architecture ADR
- Real-time transport — deferred (see `app/docs/activity_and_os_intelligence.md`)

## How the production frontend uses this

Production code (`app/frontend/`) implements the same visual language using MUI v7 components themed via CSS variables. The token names in this prototype (`--bg-0`, `--info`, etc.) become `--ow-bg-0`, `--ow-info`, etc. in MUI v7's CSS-vars mode — see the design-token spec for the full mapping.

## Why read-only

The prototype's CSS is hand-authored, the JS uses prototype-host messaging, and there is no test or accessibility scaffolding. Treating it as buildable would invite drift between the design source and the production implementation. Instead, the production code is the build target; the prototype is the design contract it implements against.
