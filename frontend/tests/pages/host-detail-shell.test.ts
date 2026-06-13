// @spec frontend-host-detail
//
// Prototype-shell ACs (v1.0.1 — Path A).
//
// AC traceability (this file):
//
//   AC-01  test('frontend-host-detail/AC-01 — six structural bands in order')
//   AC-07  test('frontend-host-detail/AC-07 — maintenance toggle in page-head action row')
//   AC-15  test('frontend-host-detail/AC-15 — sub-line metadata: prototype-style prefixes')
//   AC-16  test('frontend-host-detail/AC-16 — status badge uses 5-band StatusPill')
//   AC-17  test('frontend-host-detail/AC-17 — offline banner conditional on band + dwell time')
//   AC-18  test('frontend-host-detail/AC-18 — tabs row renders 10 tabs in prototype order')
//   AC-19  test('frontend-host-detail/AC-19 — 4 hero stat cards in prototype order')
//   AC-20  test('frontend-host-detail/AC-20 — connectivity card SSH endpoint + last seen + actions')
//   AC-21  test('frontend-host-detail/AC-21 — auto-scan empty state names backend subsystem')
//   AC-22  test('frontend-host-detail/AC-22 — watchlist carries no coming-soon blob; only the exceptions footer pends')
//   AC-23  test('frontend-host-detail/AC-23 — overview body two-column grid with named children')
//   AC-24  test('frontend-host-detail/AC-24 — top failed / server intel / trend cards have empty states')
//   AC-25  test('frontend-host-detail/AC-25 — system card has 3 spec-groups with placeholders')
//   AC-26  test('frontend-host-detail/AC-26 — recent activity card pulls from monitoring history')
//   AC-27  test('frontend-host-detail/AC-27 — breadcrumb above back link')
//   AC-28  test('frontend-host-detail/AC-28 — tabs row has lucide icons next to labels')
//   AC-29  test('frontend-host-detail/AC-29 — Auto-scan tile is live against the schedule endpoint')
//   AC-30  test('frontend-host-detail/AC-30 — Watchlist: live Active alerts row, honest Exceptions pending')
//   AC-31  test('frontend-host-detail/AC-31 — Connectivity hero has prominent band status line')
//   AC-32  test('frontend-host-detail/AC-32 — round chevron back button in page-head')
//   AC-33  test('frontend-host-detail/AC-33 — Maintenance toggle is a switch with knob')
//   AC-34  test('frontend-host-detail/AC-34 — offline banner names failing layer')
//   AC-35  test('frontend-host-detail/AC-35 — Compliance hero subhead is LAST SCAN, not Framework selector')

import { describe, expect, test } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const PAGE_SRC = readFileSync(resolve(process.cwd(), 'src/pages/HostDetailPage.tsx'), 'utf8');

// Source-position of each band's sentinel marker. AC-01 asserts these
// appear in declaration order — moving any of them out of place fails.
const BAND_MARKERS = [
  '/* PAGE_HEAD */',
  '/* OFFLINE_BANNER */',
  '/* TABS_ROW */',
  '/* HERO_STRIP */',
  '/* OVERVIEW_BODY */',
] as const;

describe('frontend-host-detail — prototype shell', () => {
  // @ac AC-01
  test('frontend-host-detail/AC-01 — five structural band markers in declaration order', () => {
    // The back-link affordance moved inside PageHead (the round chevron
    // pill, AC-32) and the breadcrumb lives in the TopBar (AC-27), so
    // AC-01 only enforces the five JSX band markers' relative order.
    let prevIdx = -1;
    for (const marker of BAND_MARKERS) {
      const idx = PAGE_SRC.indexOf(marker);
      expect(idx, `${marker} missing from HostDetailPage`).toBeGreaterThan(-1);
      expect(idx, `${marker} out of order`).toBeGreaterThan(prevIdx);
      prevIdx = idx;
    }
  });

  // @ac AC-07
  test('frontend-host-detail/AC-07 — maintenance toggle in page-head action row', () => {
    // MaintenanceToggle JSX usage must appear inside the PageHead
    // function body (the page-head action row), not in any other
    // sibling component.
    const pageHeadStart = PAGE_SRC.indexOf('function PageHead(');
    expect(pageHeadStart).toBeGreaterThan(-1);
    // The body of PageHead ends at the next top-level `function ` decl.
    const nextFnAfterPageHead = PAGE_SRC.indexOf('\nfunction ', pageHeadStart + 1);
    expect(nextFnAfterPageHead).toBeGreaterThan(pageHeadStart);
    const pageHeadBody = PAGE_SRC.slice(pageHeadStart, nextFnAfterPageHead);
    expect(pageHeadBody).toContain('<MaintenanceToggle');
  });

  // @ac AC-15
  test('frontend-host-detail/AC-15 — sub-line metadata: OS, Kernel, Uptime in order', () => {
    // v1.0.4: OS slot ALWAYS renders before Kernel — even when the
    // distribution is unknown. Bare prefixes (no colon).
    expect(PAGE_SRC).not.toMatch(/'OS:'/);
    expect(PAGE_SRC).not.toMatch(/'Kernel:'/);
    expect(PAGE_SRC).not.toMatch(/'Uptime:'/);
    expect(PAGE_SRC).toContain("'OS '");
    expect(PAGE_SRC).toContain("'Kernel '");
    expect(PAGE_SRC).toContain("'Uptime '");
    // Order: OS prefix MUST appear before Kernel prefix, which MUST
    // appear before Uptime prefix.
    const osIdx = PAGE_SRC.indexOf("'OS '");
    const kernelIdx = PAGE_SRC.indexOf("'Kernel '");
    const uptimeIdx = PAGE_SRC.indexOf("'Uptime '");
    expect(osIdx).toBeLessThan(kernelIdx);
    expect(kernelIdx).toBeLessThan(uptimeIdx);
    // osDistribution variable still drives the colored-dot path.
    expect(PAGE_SRC).toMatch(/osDistribution|os_distribution/);
  });

  // @ac AC-16
  test('frontend-host-detail/AC-16 — status badge uses 5-band StatusPill', () => {
    // The page imports a band-aware StatusPill. The legacy 'online'/'down'
    // binary literal pair should not appear as a JSX prop.
    expect(PAGE_SRC).toMatch(/StatusPill[^>]+band=/);
    // Reject the legacy binary prop: status={isDown ? 'down' : 'online'}.
    expect(PAGE_SRC).not.toMatch(/status=\{isDown\s*\?\s*['"]down['"]\s*:\s*['"]online['"]\}/);
  });

  // @ac AC-17
  test('frontend-host-detail/AC-17 — offline banner is conditional on band + dwell time', () => {
    // Banner only renders when the band is down or critical AND the
    // host has been in that band for at least 5 minutes.
    expect(PAGE_SRC).toContain('OFFLINE_BANNER');
    // Render gate referencing the band.
    expect(PAGE_SRC).toMatch(/(band\s*===\s*['"]down['"]|band\s*===\s*['"]critical['"])/);
    // Dwell threshold (5 minutes in ms).
    expect(PAGE_SRC).toMatch(/5\s*\*\s*60\s*\*\s*1000|300_000|300000/);
  });

  // @ac AC-18
  test('frontend-host-detail/AC-18 — tabs row renders 10 tabs in prototype order', () => {
    // TABS_ROW marker must exist (band 4 of the layout).
    expect(PAGE_SRC.indexOf('/* TABS_ROW */')).toBeGreaterThan(-1);
    // The 10 canonical tab labels must appear in order somewhere in
    // source (TAB_ORDER literal enforces this).
    const expected = [
      'Overview',
      'Compliance',
      'Packages',
      'Services',
      'Users',
      'Network',
      'Audit log',
      'Activity',
      'Remediation',
      'Terminal',
    ];
    let prev = -1;
    for (const label of expected) {
      const idx = PAGE_SRC.indexOf(`'${label}'`);
      expect(idx, `tab "${label}" missing`).toBeGreaterThan(-1);
      expect(idx, `tab "${label}" out of prototype order`).toBeGreaterThan(prev);
      prev = idx;
    }
  });

  // @ac AC-19
  test('frontend-host-detail/AC-19 — 4 hero stat cards in prototype order', () => {
    const expected = ['HeroCompliance', 'HeroAutoScan', 'HeroConnectivity', 'HeroWatchlist'];
    let prev = PAGE_SRC.indexOf('/* HERO_STRIP */');
    expect(prev).toBeGreaterThan(-1);
    for (const name of expected) {
      const idx = PAGE_SRC.indexOf(`<${name}`);
      expect(idx, `${name} not rendered`).toBeGreaterThan(-1);
      expect(idx, `${name} out of prototype order`).toBeGreaterThan(prev);
      prev = idx;
    }
  });

  // @ac AC-20
  test('frontend-host-detail/AC-20 — connectivity card SSH endpoint + last seen + actions', () => {
    expect(PAGE_SRC).toContain('HeroConnectivity');
    // SSH endpoint line — built from username + ip + port.
    expect(PAGE_SRC).toMatch(/host\.username/);
    expect(PAGE_SRC).toMatch(/host\.ip_address/);
    // Actions match the prototype labels.
    expect(PAGE_SRC).toContain('Reconnect');
    expect(PAGE_SRC).toContain('Edit credentials');
    // Empty state when never probed.
    expect(PAGE_SRC).toContain('Not yet probed');
  });

  // @ac AC-21
  test('frontend-host-detail/AC-21 — auto-scan empty state names backend subsystem', () => {
    expect(PAGE_SRC).toContain('HeroAutoScan');
    // The card must say the backend is missing and name it.
    expect(PAGE_SRC).toMatch(/adaptive compliance scheduler/i);
  });

  // @ac AC-22
  test('frontend-host-detail/AC-22 — watchlist carries no coming-soon blob; only the exceptions footer pends', () => {
    expect(PAGE_SRC).toContain('HeroWatchlist');
    // Both halves are live now (alerts + exceptions); no coming-soon
    // blob, no remediation-track placeholder remains.
    expect(PAGE_SRC).not.toMatch(/alerts? (subsystem|backend).*(BACKLOG|coming soon)/i);
    expect(PAGE_SRC).not.toContain('ship with the remediation work');
  });

  // @ac AC-23
  test('frontend-host-detail/AC-23 — overview body two-column grid with named children', () => {
    const bodyIdx = PAGE_SRC.indexOf('/* OVERVIEW_BODY */');
    expect(bodyIdx).toBeGreaterThan(-1);
    // Two-column grid declaration.
    expect(PAGE_SRC.slice(bodyIdx)).toMatch(/grid(Template)?Columns/);
    // Left column children in order.
    const leftOrder = ['<CardTopFailed', '<CardServerIntel', '<CardComplianceTrend'];
    let prev = bodyIdx;
    for (const name of leftOrder) {
      const idx = PAGE_SRC.indexOf(name);
      expect(idx, `${name} missing from left column`).toBeGreaterThan(-1);
      expect(idx).toBeGreaterThan(prev);
      prev = idx;
    }
    // Right column children in order. They appear after the left
    // column in source order because the JSX renders left-then-right.
    const rightOrder = ['<CardSystem', '<CardRecentActivity'];
    for (const name of rightOrder) {
      const idx = PAGE_SRC.indexOf(name);
      expect(idx, `${name} missing from right column`).toBeGreaterThan(-1);
      expect(idx).toBeGreaterThan(prev);
      prev = idx;
    }
  });

  // @ac AC-24
  test('frontend-host-detail/AC-24 — left-column empty-state cards name their backend', () => {
    // Each card identifies the subsystem that will populate it.
    expect(PAGE_SRC).toMatch(/compliance scanner/i);
    expect(PAGE_SRC).toMatch(/server intelligence/i);
    expect(PAGE_SRC).toMatch(/posture snapshot/i);
  });

  // @ac AC-25
  test('frontend-host-detail/AC-25 — system card has 3 spec-groups (Operating system / Hardware / Network)', () => {
    // CardSystem is now extracted to its own file (PR 6 / frontend-host-detail-system-card v1.0.0).
    // The page imports + mounts it; the three group headings live there.
    expect(PAGE_SRC).toContain('CardSystem');
    const cardSrc = readFileSync(
      resolve(process.cwd(), 'src/pages/host-detail/CardSystem.tsx'),
      'utf8',
    );
    expect(cardSrc).toMatch(/Operating system/);
    expect(cardSrc).toMatch(/Hardware/);
    expect(cardSrc).toMatch(/Network/);
    // v1.0.5: the prior "unknown" placeholder string is gone — pre-Discovery
    // hosts collapse to a "Not discovered yet" empty state instead.
    expect(cardSrc).toMatch(/Not discovered yet/);
  });

  // @ac AC-26
  test('frontend-host-detail/AC-26 — recent activity card sources from unified /activity feed, slices to 5, links to Activity tab', () => {
    expect(PAGE_SRC).toContain('CardRecentActivity');
    // The card fetches GET /api/v1/activity scoped by host_id —
    // system-activity v1.1.0 union (alert + transaction +
    // intelligence + audit + monitoring). The legacy
    // /monitoring/history binding is gone.
    expect(PAGE_SRC).toContain("'/api/v1/activity'");
    expect(PAGE_SRC).toMatch(/host_id:\s*hostId/);
    expect(PAGE_SRC).not.toContain('/monitoring/history');
    // Slice cap.
    expect(PAGE_SRC).toMatch(/RECENT_LIMIT\s*=\s*5/);
    // "View all" affordance routes to the host's Activity tab.
    expect(PAGE_SRC).toMatch(/View all/);
    expect(PAGE_SRC).toMatch(/tab:\s*['"]activity['"]/);
    // Empty-state copy preserved.
    expect(PAGE_SRC).toMatch(/No activity yet/i);
  });

  // @ac AC-27
  test('frontend-host-detail/AC-27 — breadcrumb rendered by the TopBar via useBreadcrumbStore', () => {
    // Page pushes "Infrastructure / Hosts / <hostname>" into the
    // global useBreadcrumbStore (same pattern as HostsListPage). The
    // TopBar reads them. No inline Crumbs component on the page.
    expect(PAGE_SRC).toContain('useBreadcrumbStore');
    expect(PAGE_SRC).toContain('setCrumbs');
    expect(PAGE_SRC).toContain("'Infrastructure'");
    expect(PAGE_SRC).toContain("'Hosts'");
    expect(PAGE_SRC).toContain("href: '/hosts'");
    // The hostname crumb is conditionally appended.
    expect(PAGE_SRC).toMatch(/hostname\s*\?\s*\[/);
  });

  // @ac AC-28
  test('frontend-host-detail/AC-28 — tabs row has lucide icons next to labels', () => {
    // TAB_ORDER entries carry an `icon` field; the renderer mounts
    // the icon component beside the label.
    expect(PAGE_SRC).toMatch(/TAB_ORDER[\s\S]{0,2000}icon:/);
    // Confirm the specific icon imports we picked.
    expect(PAGE_SRC).toMatch(/LayoutGrid|Grid3x3/);
    expect(PAGE_SRC).toMatch(/Shield/);
    expect(PAGE_SRC).toMatch(/Wrench/);
  });

  // @ac AC-29
  test('frontend-host-detail/AC-29 — Auto-scan tile is live against the schedule endpoint', () => {
    const tile = PAGE_SRC.slice(
      PAGE_SRC.indexOf('function HeroAutoScan'),
      PAGE_SRC.indexOf('function formatNextScan'),
    );
    expect(tile.length).toBeGreaterThan(0);
    expect(tile).toContain("queryKey: ['host', hostId, 'compliance_schedule']");
    expect(tile).toContain("api.GET('/api/v1/hosts/{id}/compliance/schedule'");
    // Status states: On / Paused / Host paused.
    expect(tile).toContain("{ label: 'On', color: 'var(--ow-ok)' }");
    expect(tile).toContain("{ label: 'Paused', color: 'var(--ow-warn)' }");
    expect(tile).toContain("{ label: 'Host paused', color: 'var(--ow-warn)' }");
    // Structured rows survive: Next + Interval with dash fallbacks.
    expect(tile).toContain("k={'Next'}");
    expect(tile).toContain("k={'Interval'}");
    // Footer explains the pause cause or the cadence driver; the
    // BACKLOG placeholder is gone.
    expect(tile).toContain('Scheduler paused in Settings.');
    expect(tile).toContain('Cadence follows the compliance state');
    expect(PAGE_SRC).not.toContain('adaptive compliance scheduler (BACKLOG)');
    // The page passes the host id into the tile.
    expect(PAGE_SRC).toContain('<HeroAutoScan hostId={hostId} />');
  });

  // @ac AC-30
  test('frontend-host-detail/AC-30 — Watchlist: live Active alerts row, honest Exceptions pending', () => {
    const tile = PAGE_SRC.slice(
      PAGE_SRC.indexOf('function HeroWatchlist'),
      PAGE_SRC.indexOf('function WatchlistRow'),
    );
    expect(tile.length).toBeGreaterThan(0);
    // Live alerts read, host-scoped and state-filtered.
    expect(tile).toContain("queryKey: ['host', hostId, 'active_alerts']");
    expect(tile).toContain("api.GET('/api/v1/alerts'");
    expect(tile).toContain("state: 'active', host_id: hostId");
    // Zero state + worst-severity subtext + honest load/error states.
    expect(tile).toContain("'No alerts firing'");
    expect(tile).toContain('Worst severity:');
    expect(tile).toContain("'Failed to load alerts'");
    // Exceptions row is LIVE against the host exceptions hook: the
    // active count + a subtext that names waived rules or the pending
    // queue; the remediation-track placeholder is gone.
    expect(tile).toContain('useHostExceptions(hostId)');
    expect(tile).toContain('value={exc.activeCount}');
    expect(tile).toContain("'No suppressed rules'");
    expect(tile).toContain('waived');
    expect(tile).toMatch(/review/);
    expect(tile).not.toContain('ship with the remediation work');
    expect(PAGE_SRC).not.toContain('alerts subsystem (BACKLOG)');
    expect(PAGE_SRC).toContain('<HeroWatchlist hostId={hostId} />');
  });

  // @ac AC-31
  test('frontend-host-detail/AC-31 — Connectivity hero has prominent band status line', () => {
    const connFn = PAGE_SRC.indexOf('function HeroConnectivity');
    expect(connFn).toBeGreaterThan(-1);
    const next = PAGE_SRC.indexOf('\nfunction ', connFn + 1);
    const body = PAGE_SRC.slice(connFn, next);
    // BAND_LABEL_TEXT or similar derives the human label from the band.
    expect(body).toMatch(/bandLabel|BAND_HEADLINE/);
  });

  // @ac AC-32
  test('frontend-host-detail/AC-32 — round chevron back button in page-head', () => {
    // Round chevron pill back button inside PageHead, NOT a separate
    // text link above the page.
    const pageHeadStart = PAGE_SRC.indexOf('function PageHead(');
    const nextFn = PAGE_SRC.indexOf('\nfunction ', pageHeadStart + 1);
    const body = PAGE_SRC.slice(pageHeadStart, nextFn);
    expect(body).toContain('ChevronLeft');
    expect(body).toMatch(/aria-label=["'`]Back to hosts/);
    // The standalone "Hosts" text link is removed from the page body.
    // Specifically: no <ArrowLeft size={14} /> Hosts</Link> pattern.
    expect(PAGE_SRC).not.toMatch(/<ArrowLeft size=\{14\} \/> Hosts/);
  });

  // @ac AC-33
  test('frontend-host-detail/AC-33 — Maintenance toggle is a switch with knob', () => {
    const mtFn = PAGE_SRC.indexOf('function MaintenanceToggle');
    expect(mtFn).toBeGreaterThan(-1);
    const next = PAGE_SRC.indexOf('\nfunction ', mtFn + 1);
    const body = PAGE_SRC.slice(mtFn, next);
    // The switch has a track + knob element; we mark the knob node so
    // a future regression is easy to catch.
    expect(body).toMatch(/data-maintenance-knob/);
    // No checkbox input — the switch is a button with role="switch".
    expect(body).toMatch(/role=["'`]switch["'`]/);
    expect(body).toMatch(/aria-checked=/);
  });

  // @ac AC-35
  test('frontend-host-detail/AC-35 — Compliance hero subhead is LAST SCAN, not Framework selector', () => {
    const heroFn = PAGE_SRC.indexOf('function HeroCompliance');
    expect(heroFn).toBeGreaterThan(-1);
    const next = PAGE_SRC.indexOf('\nfunction ', heroFn + 1);
    const body = PAGE_SRC.slice(heroFn, next);
    // The Last-Scan subhead is mounted in the header sub-cell.
    expect(body).toMatch(/LAST SCAN/);
    // No FrameworkFilter mounted inside the hero card.
    expect(body).not.toContain('<FrameworkFilter');
  });

  // @ac AC-34
  test('frontend-host-detail/AC-34 — offline banner names failing layer', () => {
    const bannerFn = PAGE_SRC.indexOf('function OfflineBanner');
    expect(bannerFn).toBeGreaterThan(-1);
    const next = PAGE_SRC.indexOf('\nfunction ', bannerFn + 1);
    const body = PAGE_SRC.slice(bannerFn, next);
    // failedLayer derivation + the human label in the banner body.
    expect(body).toMatch(/failedLayer|failed_layer|inferFailedLayer/);
    expect(body).toMatch(/Failed at/);
    // The three known layer names appear so source inspection confirms
    // each branch of the mapping is wired.
    expect(body).toMatch(/['"]ping['"]/);
    expect(body).toMatch(/['"]SSH['"]/);
    expect(body).toMatch(/['"]privilege escalation['"]/);
  });
});

describe('frontend-host-detail v1.4.0 — live compliance trend card', () => {
  // @ac AC-38
  test('frontend-host-detail/AC-38 — trend card queries the snapshot endpoint with the host-prefixed key; honest states', () => {
    const card = PAGE_SRC.slice(
      PAGE_SRC.indexOf('function CardComplianceTrend'),
      PAGE_SRC.indexOf('function TrendSparkline'),
    );
    expect(card.length).toBeGreaterThan(0);
    expect(card).toContain("queryKey: ['host', hostId, 'compliance_trend']");
    expect(card).toContain("api.GET('/api/v1/hosts/{id}/compliance/trend'");
    // isPending guard (isLoading goes false between retries).
    expect(card).toContain('trendQuery.isPending');
    expect(card).not.toContain('trendQuery.isLoading');
    // Honest empty state names the rollup, no fabricated zero line.
    expect(card).toContain('No snapshots yet');
    expect(card).toMatch(/hourly rollup/);
    // Chart renders latest score + over-window delta when data exists.
    expect(card).toContain('<TrendSparkline days={days} />');
    expect(card).toMatch(/over \{days\.length\} days/);
    // The page passes the host id into the card.
    expect(PAGE_SRC).toContain('<CardComplianceTrend hostId={hostId} />');
  });
});
