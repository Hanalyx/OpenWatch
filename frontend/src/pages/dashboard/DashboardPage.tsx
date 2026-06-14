import { useEffect } from 'react';
import { useAuthStore } from '@/store/useAuthStore';
import { useBreadcrumbStore } from '@/store/useBreadcrumbStore';
import {
  KpiHostsOnline,
  KpiAvgCompliance,
  KpiScanQueue,
  WidgetComplianceTrend,
  WidgetTopFailingRules,
  WidgetTopFailingHosts,
  WidgetRecentActivity,
} from './widgets';

// DashboardPage — the authenticated fleet overview at /dashboard.
//
// MVP scope (frontend-dashboard): a single default grid of widgets wired
// to the live /fleet/* + /activity endpoints, behind the system:read
// route guard. The role presets, range control, and drag/drop edit mode
// from the openwatch-v1 Dashboard.html prototype are intentionally
// deferred; this ships one sensible layout with honest per-widget
// loading / empty / error states.

export function DashboardPage() {
  const setCrumbs = useBreadcrumbStore((s) => s.setCrumbs);
  useEffect(() => {
    setCrumbs([{ label: 'Dashboard' }]);
    return () => setCrumbs([]);
  }, [setCrumbs]);

  const identity = useAuthStore((s) => s.identity);

  return (
    <div style={{ padding: '20px 28px 60px' }}>
      <title>Dashboard · OpenWatch</title>

      <header style={{ marginBottom: 18 }}>
        <h1 style={{ margin: 0, fontSize: 22, fontWeight: 600, letterSpacing: '-0.01em' }}>
          {identity?.username ? `Welcome back, ${identity.username}` : 'Dashboard'}
        </h1>
        <div style={{ color: 'var(--ow-fg-2)', fontSize: 13, marginTop: 2 }}>
          Fleet compliance overview
        </div>
      </header>

      {/* KPI row */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: 14,
          marginBottom: 14,
        }}
      >
        <KpiHostsOnline />
        <KpiAvgCompliance />
        <KpiScanQueue />
      </div>

      {/* widgets grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: 14,
        }}
      >
        <WidgetComplianceTrend />
        <WidgetTopFailingRules />
        <WidgetTopFailingHosts />
        <WidgetRecentActivity />
      </div>
    </div>
  );
}
