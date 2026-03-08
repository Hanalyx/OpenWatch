import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { Box, Skeleton, Alert, Button, Typography } from '@mui/material';
import Grid from '@mui/material/Grid';
import { useNavigate } from 'react-router-dom';
import { AddCircle, Assessment, Storage as StorageIcon } from '@mui/icons-material';

// Dashboard components
import SmartAlertBar from '../components/dashboard/SmartAlertBar';
import QuickActionCard from '../components/dashboard/QuickActionCard';
import FleetHealthWidget from '../components/dashboard/FleetHealthWidget';
import ActivityFeed, { type ActivityItem } from '../components/dashboard/ActivityFeed';
import ComplianceTrend from '../components/dashboard/ComplianceTrend';
import PriorityHosts from '../components/dashboard/PriorityHosts';
import DriftAlertsWidget from '../components/baselines/DriftAlertsWidget';
import {
  SchedulerStatusWidget,
  SummaryBar,
  SecurityEventsWidget,
  PostureWidget,
  SavedQueriesWidget,
} from './Dashboard/widgets';
import { api } from '../services/api';
import {
  owcaService,
  type FleetStatistics,
  type FleetComplianceTrend,
} from '../services/owcaService';
import DashboardErrorBoundary from '../components/dashboard/DashboardErrorBoundary';
import { useSecurityStats, type AuditEvent } from '../hooks/useSecurityStats';
import { useMonitoringStats } from '../hooks/useMonitoringStats';
import { useAuthStore } from '../store/useAuthStore';
import { getPresetForRole } from './Dashboard/dashboardPresets';
import { hasPermission, Permission } from './Dashboard/widgetRegistry';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ComplianceTrendData {
  date: string;
  overall: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface DashboardStats {
  onlineHosts: number;
  degradedHosts: number;
  criticalHosts: number;
  downHosts: number;
  scanningHosts: number;
  maintenanceHosts: number;
  totalHosts: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  passed: number;
  avgCompliance: number;
}

interface DashboardPriorityHost {
  id: string;
  hostname: string;
  displayName: string;
  ipAddress: string;
  operatingSystem: string;
  status: string;
  complianceScore: number;
  issueType: 'critical_issues' | 'not_scanned' | 'degrading' | 'offline';
  issue: string;
  severity: 'critical' | 'high' | 'medium';
  lastScan: string;
  criticalIssues: number;
  highIssues: number;
  mediumIssues: number;
  lowIssues: number;
  passedRules: number;
}

interface DashboardData {
  stats: DashboardStats;
  hosts: NormalizedHost[];
  scans: RawScanData[];
  activities: ActivityItem[];
  priorityHosts: DashboardPriorityHost[];
  trendData: ComplianceTrendData[];
}

interface RawHostData {
  id?: string;
  hostname?: string;
  display_name?: string;
  displayName?: string;
  ip_address?: string;
  ipAddress?: string;
  operating_system?: string;
  operatingSystem?: string;
  status?: string;
  critical_issues?: number;
  criticalIssues?: number;
  high_issues?: number;
  highIssues?: number;
  medium_issues?: number;
  mediumIssues?: number;
  low_issues?: number;
  lowIssues?: number;
  passed_rules?: number;
  passedRules?: number;
  compliance_score?: number | null;
  complianceScore?: number | null;
  last_scan?: string;
  lastScan?: string;
  [key: string]: unknown;
}

interface RawScanData {
  id?: string;
  host_name?: string;
  hostname?: string;
  status?: string;
  completed_at?: string;
  started_at?: string;
  results?: {
    score?: number;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

interface NormalizedHost {
  id: string;
  hostname: string;
  criticalIssues: number;
  highIssues: number;
  mediumIssues: number;
  lowIssues: number;
  passedRules: number;
  complianceScore: number | null;
  displayName: string;
  ipAddress: string;
  operatingSystem: string;
  lastScan?: string;
  status: string;
}

// ---------------------------------------------------------------------------
// Helper: check if a widget ID is in a preset's widget lists
// ---------------------------------------------------------------------------

function presetHasWidget(preset: ReturnType<typeof getPresetForRole>, widgetId: string): boolean {
  return (
    preset.topWidgets.includes(widgetId) ||
    preset.mainWidgets.includes(widgetId) ||
    preset.sidebarWidgets.includes(widgetId)
  );
}

/**
 * Role-Based Dashboard
 *
 * Renders a widget layout based on the authenticated user's role.
 * Uses presets from dashboardPresets.ts and permission checks from
 * widgetRegistry.ts to filter widgets per role.
 *
 * Spec: specs/frontend/role-dashboards.spec.yaml
 */
const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const user = useAuthStore((state) => state.user);
  const userRole = user?.role || 'guest';
  const preset = useMemo(() => getPresetForRole(userRole), [userRole]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [owcaError, setOwcaError] = useState<string | null>(null);
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [timeRange, setTimeRange] = useState<'7d' | '30d' | '90d'>(preset.defaultTrendRange);
  const [_fleetStats, setFleetStats] = useState<FleetStatistics | null>(null);

  // Command Center: Security and Monitoring stats from hooks
  const { data: securityStats } = useSecurityStats();
  const { data: monitoringStats } = useMonitoringStats();

  // Dashboard data state
  const [onlineHosts, setOnlineHosts] = useState(0);
  const [degradedHosts, setDegradedHosts] = useState(0);
  const [criticalHosts, setCriticalHosts] = useState(0);
  const [downHosts, setDownHosts] = useState(0);
  const [scanningHosts, setScanningHosts] = useState(0);
  const [maintenanceHosts, setMaintenanceHosts] = useState(0);
  const [totalHosts, setTotalHosts] = useState(0);
  const [criticalIssues, setCriticalIssues] = useState(0);
  const [trendData, setTrendData] = useState<ComplianceTrendData[]>([]);
  const [activities, setActivities] = useState<ActivityItem[]>([]);
  const [priorityHosts, setPriorityHosts] = useState<DashboardPriorityHost[]>([]);

  // Permission-gated quick actions (AC-10)
  const canCreateHost = hasPermission(userRole, Permission.HOST_CREATE);
  const canExecuteScan = hasPermission(userRole, Permission.SCAN_EXECUTE);
  const canAccessAudit = hasPermission(userRole, Permission.AUDIT_READ);
  const canViewReports = hasPermission(userRole, Permission.REPORTS_GENERATE);

  // Fetch trend data only (called when time range changes)
  const fetchTrendData = useCallback(async (range: '7d' | '30d' | '90d') => {
    const trendDays = range === '7d' ? 7 : range === '90d' ? 90 : 30;

    try {
      const fleetTrend: FleetComplianceTrend | null = await owcaService.getFleetTrend(trendDays);

      if (fleetTrend && fleetTrend.data_points && fleetTrend.data_points.length > 0) {
        const trendDataArray = fleetTrend.data_points.map((point) => ({
          date: point.date,
          overall: Math.max(0, Math.min(100, point.average_compliance)),
          critical: point.total_critical_issues,
          high: point.total_high_issues,
          medium: point.total_medium_issues,
          low: point.total_low_issues,
        }));
        setTrendData(trendDataArray);
      }
    } catch (trendError) {
      console.warn('Failed to fetch fleet trend data:', trendError);
    }
  }, []);

  const handleTimeRangeChange = useCallback(
    (range: '7d' | '30d' | '90d') => {
      setTimeRange(range);
      fetchTrendData(range);
    },
    [fetchTrendData]
  );

  // Fetch dashboard data
  const fetchDashboardData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      let hosts: RawHostData[] = [];
      let scans: RawScanData[] = [];
      let owcaFleetStats: FleetStatistics | null = null;

      try {
        const [hostsData, scansData, fetchedFleetStats] = await Promise.all([
          api.get<RawHostData[]>('/api/hosts/'),
          api.get<{ scans: RawScanData[] }>('/api/scans/'),
          owcaService.getFleetStatistics(),
        ]);

        hosts = hostsData || [];
        scans = scansData.scans || [];
        owcaFleetStats = fetchedFleetStats;

        setFleetStats(fetchedFleetStats);
        setOwcaError(null);
      } catch (apiError) {
        console.error('Failed to fetch dashboard data:', apiError);

        const errorCode = (apiError as { code?: string }).code;
        const errorMessage = (apiError as { message?: string }).message;
        const responseStatus = (apiError as { response?: { status?: number } }).response?.status;
        const requestUrl = (apiError as { config?: { url?: string } }).config?.url;

        if (requestUrl?.includes('/api/compliance/owca/')) {
          setOwcaError(
            'OWCA compliance service is unavailable. Dashboard metrics cannot be displayed without canonical compliance calculations. Please contact your administrator.'
          );
          throw new Error('OWCA service unavailable - compliance metrics cannot be calculated');
        }

        if (errorCode === 'NETWORK_ERROR' || errorMessage?.includes('Network Error')) {
          throw new Error('Unable to connect to the server. Please check your connection.');
        } else if (responseStatus === 401) {
          throw new Error('Authentication required. Please log in again.');
        } else if (responseStatus === 403) {
          throw new Error('Access denied. You do not have permission to view this data.');
        } else {
          throw new Error('Unable to connect to the server. Please check your connection.');
        }
      }

      if (!Array.isArray(hosts) || !Array.isArray(scans)) {
        console.warn('Invalid data format received from API', {
          hosts: typeof hosts,
          scans: typeof scans,
        });
        throw new Error('Invalid data format received from server');
      }

      const normalizedHosts: NormalizedHost[] = hosts.map((host: RawHostData) => ({
        id: host.id || '',
        hostname: host.hostname || '',
        criticalIssues: host.critical_issues || host.criticalIssues || 0,
        highIssues: host.high_issues || host.highIssues || 0,
        mediumIssues: host.medium_issues || host.mediumIssues || 0,
        lowIssues: host.low_issues || host.lowIssues || 0,
        passedRules: host.passed_rules || host.passedRules || 0,
        complianceScore:
          host.compliance_score !== undefined && host.compliance_score !== null
            ? host.compliance_score
            : (host.complianceScore ?? null),
        displayName: host.display_name || host.displayName || host.hostname || '',
        ipAddress: host.ip_address || host.ipAddress || '',
        operatingSystem: host.operating_system || host.operatingSystem || 'Unknown',
        lastScan: host.last_scan || host.lastScan,
        status: host.status || 'offline',
      }));

      const onlineCount = normalizedHosts.filter(
        (h) => h.status === 'online' || h.status === 'reachable'
      ).length;
      const degradedCount = normalizedHosts.filter((h) => h.status === 'degraded').length;
      const criticalCount = normalizedHosts.filter((h) => h.status === 'critical').length;
      const downCount = normalizedHosts.filter(
        (h) => h.status === 'down' || h.status === 'offline'
      ).length;
      const scanningCount = normalizedHosts.filter((h) => h.status === 'scanning').length;
      const maintenanceCount = normalizedHosts.filter((h) => h.status === 'maintenance').length;
      const totalCount = normalizedHosts.length;

      if (!owcaFleetStats) {
        throw new Error('OWCA fleet statistics unavailable - cannot display compliance metrics');
      }

      const totalCritical = owcaFleetStats.total_critical_issues;
      const totalHigh = owcaFleetStats.total_high_issues;
      const totalMedium = owcaFleetStats.total_medium_issues;
      const totalLow = owcaFleetStats.total_low_issues;
      const totalPassed = 0;
      const overallCompliance = Math.round(owcaFleetStats.average_compliance);

      // Fetch trend data using the role's default range
      let trendDataArray: ComplianceTrendData[] = [];
      const defaultDays =
        preset.defaultTrendRange === '7d' ? 7 : preset.defaultTrendRange === '90d' ? 90 : 30;

      try {
        const fleetTrend: FleetComplianceTrend | null =
          await owcaService.getFleetTrend(defaultDays);

        if (fleetTrend && fleetTrend.data_points && fleetTrend.data_points.length > 0) {
          trendDataArray = fleetTrend.data_points.map((point) => ({
            date: point.date,
            overall: Math.max(0, Math.min(100, point.average_compliance)),
            critical: point.total_critical_issues,
            high: point.total_high_issues,
            medium: point.total_medium_issues,
            low: point.total_low_issues,
          }));
        }
      } catch (trendError) {
        console.warn('Failed to fetch fleet trend data, using current state only:', trendError);
      }

      if (trendDataArray.length === 0) {
        const today = new Date().toISOString().split('T')[0];
        trendDataArray =
          normalizedHosts.length > 0
            ? [
                {
                  date: today,
                  overall: Math.max(0, Math.min(100, overallCompliance)),
                  critical: Math.max(0, totalCritical),
                  high: Math.max(0, totalHigh),
                  medium: Math.max(0, totalMedium),
                  low: Math.max(0, totalLow),
                },
              ]
            : [{ date: today, overall: 0, critical: 0, high: 0, medium: 0, low: 0 }];
      }

      // Generate activity items
      const activitiesArray: ActivityItem[] = [];

      scans
        .filter((scan: RawScanData) => scan.completed_at && scan.id)
        .slice(0, 5)
        .forEach((scan: RawScanData) => {
          const scanId = scan.id as string;
          const hostname = scan.host_name || scan.hostname || 'Unknown';
          const activityType: ActivityItem['type'] =
            scan.status === 'completed' ? 'scan_completed' : 'scan_failed';
          const activitySeverity: ActivityItem['severity'] =
            scan.status === 'completed' ? 'success' : 'error';
          activitiesArray.push({
            id: `scan-${scanId}`,
            type: activityType,
            message:
              scan.status === 'completed'
                ? `Scan completed on ${hostname}`
                : `Scan failed on ${hostname}`,
            timestamp: new Date(scan.completed_at || scan.started_at || new Date().toISOString()),
            severity: activitySeverity,
            metadata: { scanId, hostname, complianceScore: scan.results?.score },
            action: { label: 'View', onClick: () => navigate(`/scans/${scanId}`) },
          });
        });

      // Only fetch security events if user has audit:read permission
      if (hasPermission(userRole, Permission.AUDIT_READ)) {
        try {
          const eventsResponse = await api.get<{ events: AuditEvent[]; total: number }>(
            '/api/audit/events?page=1&limit=10'
          );
          const securityEvents = eventsResponse?.events || [];

          securityEvents.slice(0, 5).forEach((event: AuditEvent) => {
            let activityType: ActivityItem['type'] = 'security_event';
            let message = event.action;
            let severity: ActivityItem['severity'] = 'info';

            if (event.action.includes('LOGIN_FAILED') || event.action.includes('FAILED_LOGIN')) {
              activityType = 'login_failed';
              message = `Failed login attempt`;
              severity = 'warning';
            } else if (event.severity === 'error' || event.severity === 'critical') {
              severity = 'error';
              message = event.details || event.action.replace(/_/g, ' ').toLowerCase();
            } else if (event.severity === 'warning') {
              severity = 'warning';
              message = event.details || event.action.replace(/_/g, ' ').toLowerCase();
            } else {
              severity = 'info';
              message = event.details || event.action.replace(/_/g, ' ').toLowerCase();
            }

            activitiesArray.push({
              id: `event-${event.id}`,
              type: activityType,
              message,
              timestamp: new Date(event.timestamp),
              severity,
              metadata: { username: event.username },
            });
          });
        } catch (eventsError) {
          console.warn('Failed to fetch security events for activity feed:', eventsError);
        }
      }

      activitiesArray.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
      const sortedActivities = activitiesArray.slice(0, 10);

      // Priority hosts
      let priorityHostsArray: DashboardPriorityHost[] = [];
      const owcaPriorityHosts = await owcaService.getTopPriorityHosts(5);

      priorityHostsArray = owcaPriorityHosts.map((owcaHost) => {
        const matchingHost = normalizedHosts.find((h) => h.id === owcaHost.host_id);

        let issueType: DashboardPriorityHost['issueType'] = 'critical_issues';
        let issue = '';
        let severity: DashboardPriorityHost['severity'] = 'medium';

        if (owcaHost.critical_issues > 0) {
          issueType = 'critical_issues';
          issue = `${owcaHost.critical_issues} critical security issues detected`;
          severity = 'critical';
        } else if (owcaHost.high_issues > 0) {
          issueType = 'critical_issues';
          issue = `${owcaHost.high_issues} high security issues detected`;
          severity = 'high';
        } else if (owcaHost.compliance_score < 70) {
          issueType = 'degrading';
          issue = `Compliance score below threshold (${owcaHost.compliance_score}%)`;
          severity = owcaHost.compliance_score < 50 ? 'high' : 'medium';
        }

        return {
          id: owcaHost.host_id,
          hostname: owcaHost.hostname,
          displayName: owcaHost.hostname,
          ipAddress: owcaHost.ip_address,
          operatingSystem: matchingHost?.operatingSystem || 'Unknown',
          status: matchingHost?.status || 'unknown',
          complianceScore: owcaHost.compliance_score,
          issueType,
          issue,
          severity,
          lastScan: owcaHost.last_scan,
          criticalIssues: owcaHost.critical_issues,
          highIssues: owcaHost.high_issues,
          mediumIssues: matchingHost?.mediumIssues || 0,
          lowIssues: matchingHost?.lowIssues || 0,
          passedRules: matchingHost?.passedRules || 0,
        };
      });

      setOnlineHosts(onlineCount);
      setDegradedHosts(degradedCount);
      setCriticalHosts(criticalCount);
      setDownHosts(downCount);
      setScanningHosts(scanningCount);
      setMaintenanceHosts(maintenanceCount);
      setTotalHosts(totalCount);
      setCriticalIssues(totalCritical);
      setTrendData(trendDataArray);
      setActivities(sortedActivities);
      setPriorityHosts(priorityHostsArray);

      setDashboardData({
        stats: {
          onlineHosts: onlineCount,
          degradedHosts: degradedCount,
          criticalHosts: criticalCount,
          downHosts: downCount,
          scanningHosts: scanningCount,
          maintenanceHosts: maintenanceCount,
          totalHosts: totalCount,
          critical: totalCritical,
          high: totalHigh,
          medium: totalMedium,
          low: totalLow,
          passed: totalPassed,
          avgCompliance: overallCompliance,
        },
        hosts: normalizedHosts,
        scans,
        activities: sortedActivities,
        priorityHosts: priorityHostsArray,
        trendData: trendDataArray,
      });
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      setError(
        error instanceof Error
          ? error.message
          : 'Unable to load dashboard data. Please check your connection and try again.'
      );

      setTotalHosts(0);
      setOnlineHosts(0);
      setDownHosts(0);
      setScanningHosts(0);
      setCriticalIssues(0);
      setTrendData([]);
      setActivities([]);
      setPriorityHosts([]);
    } finally {
      setLoading(false);
    }
  }, [navigate, userRole, preset.defaultTrendRange]);

  useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  const handleFilterClick = (status: string) => {
    navigate('/hosts', { state: { filter: status } });
  };

  // ---------------------------------------------------------------------------
  // Widget renderers — each widget ID maps to its JSX
  // ---------------------------------------------------------------------------

  const widgetRenderers: Record<string, () => React.ReactNode> = useMemo(
    () => ({
      'summary-bar': () => (
        <SummaryBar
          compliancePercent={dashboardData?.stats?.avgCompliance ?? null}
          onlineHosts={onlineHosts}
          totalHosts={totalHosts}
          failedLogins={securityStats?.failed_logins ?? 0}
          totalEvents={securityStats?.total_events ?? 0}
          activeAlerts={criticalIssues}
          avgResponseMs={monitoringStats?.avg_response_time_ms ?? null}
          isLoading={loading}
        />
      ),

      'smart-alert-bar': () => (
        <SmartAlertBar
          stats={{
            critical: criticalIssues,
            high: dashboardData?.stats?.high || 0,
            medium: dashboardData?.stats?.medium || 0,
            low: dashboardData?.stats?.low || 0,
            passed: dashboardData?.stats?.passed || 0,
            overallCompliance: dashboardData?.stats?.avgCompliance || 0,
            trend: (() => {
              const avg = dashboardData?.stats?.avgCompliance ?? 0;
              if (avg > 85) return 'up' as const;
              if (avg > 70) return 'stable' as const;
              return 'down' as const;
            })(),
          }}
          onFilterClick={handleFilterClick}
        />
      ),

      'quick-actions': () => {
        const actions: React.ReactNode[] = [];
        if (canCreateHost) {
          actions.push(
            <Grid size={{ xs: 12, sm: 6, md: 3 }} key="add-host">
              <QuickActionCard
                title="Add Host"
                subtitle="Register new system"
                icon={<AddCircle />}
                color="success"
                onClick={() => navigate('/hosts/add-host')}
                badge={0}
              />
            </Grid>
          );
        }
        if (canViewReports) {
          actions.push(
            <Grid size={{ xs: 12, sm: 6, md: 3 }} key="reports">
              <QuickActionCard
                title="View Reports"
                subtitle="Security audit & monitoring"
                icon={<Assessment />}
                color="info"
                onClick={() => navigate('/oview')}
                badge={0}
              />
            </Grid>
          );
        }
        if (canAccessAudit) {
          actions.push(
            <Grid size={{ xs: 12, sm: 6, md: 3 }} key="queries">
              <QuickActionCard
                title="Saved Queries"
                subtitle="Audit query builder"
                icon={<StorageIcon />}
                color="secondary"
                onClick={() => navigate('/audit/queries')}
                badge={0}
              />
            </Grid>
          );
        }
        if (canExecuteScan || canCreateHost) {
          actions.push(
            <Grid size={{ xs: 12, sm: 6, md: 3 }} key="alerts">
              <QuickActionCard
                title="Active Alerts"
                subtitle="Compliance drift & issues"
                icon={<Assessment />}
                color="error"
                onClick={() => navigate('/hosts')}
                badge={criticalIssues}
              />
            </Grid>
          );
        }
        if (actions.length === 0) return null;
        return (
          <Box sx={{ mb: 4 }}>
            <Grid container spacing={3}>
              {actions}
            </Grid>
          </Box>
        );
      },

      'security-events': () => (
        <DashboardErrorBoundary onRetry={fetchDashboardData}>
          <SecurityEventsWidget />
        </DashboardErrorBoundary>
      ),

      'fleet-health': () => (
        <DashboardErrorBoundary onRetry={fetchDashboardData}>
          <FleetHealthWidget
            data={{
              online: onlineHosts,
              degraded: degradedHosts,
              critical: criticalHosts,
              down: downHosts,
              scanning: scanningHosts,
              maintenance: maintenanceHosts,
            }}
            onSegmentClick={handleFilterClick}
          />
        </DashboardErrorBoundary>
      ),

      'priority-hosts': () => (
        <DashboardErrorBoundary onRetry={fetchDashboardData}>
          <PriorityHosts
            hosts={priorityHosts.map((host) => ({
              id: host.id,
              hostname: host.hostname,
              displayName: host.displayName,
              issue: host.issue,
              issueType: host.issueType,
              severity: host.severity,
              lastScan: host.lastScan ? new Date(host.lastScan) : undefined,
              complianceScore: host.complianceScore,
              previousScore: undefined,
              criticalCount: host.criticalIssues,
              daysUntilExpiry: undefined,
              action: {
                label:
                  host.issueType === 'not_scanned' || host.issueType === 'critical_issues'
                    ? 'Quick Scan'
                    : 'Fix',
                onClick: () => {
                  if (host.issueType === 'not_scanned' || host.issueType === 'critical_issues') {
                    navigate('/scans/create', { state: { preselectedHostId: host.id } });
                  } else {
                    navigate(`/hosts/${host.id}`);
                  }
                },
              },
            }))}
          />
        </DashboardErrorBoundary>
      ),

      'compliance-trend': () => (
        <DashboardErrorBoundary onRetry={fetchDashboardData}>
          <ComplianceTrend
            data={trendData}
            timeRange={timeRange}
            onTimeRangeChange={handleTimeRangeChange}
          />
        </DashboardErrorBoundary>
      ),

      'scheduler-status': () => (
        <DashboardErrorBoundary onRetry={fetchDashboardData}>
          <SchedulerStatusWidget />
        </DashboardErrorBoundary>
      ),

      posture: () => (
        <DashboardErrorBoundary onRetry={fetchDashboardData}>
          <PostureWidget />
        </DashboardErrorBoundary>
      ),

      'drift-alerts': () => (
        <DashboardErrorBoundary onRetry={fetchDashboardData}>
          <DriftAlertsWidget limit={5} autoRefresh={true} refreshInterval={30000} />
        </DashboardErrorBoundary>
      ),

      'saved-queries': () => (
        <DashboardErrorBoundary onRetry={fetchDashboardData}>
          <SavedQueriesWidget />
        </DashboardErrorBoundary>
      ),

      'activity-feed': () => (
        <DashboardErrorBoundary onRetry={fetchDashboardData}>
          <ActivityFeed activities={activities} />
        </DashboardErrorBoundary>
      ),
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [
      dashboardData,
      onlineHosts,
      degradedHosts,
      criticalHosts,
      downHosts,
      scanningHosts,
      maintenanceHosts,
      totalHosts,
      criticalIssues,
      trendData,
      activities,
      priorityHosts,
      timeRange,
      loading,
      securityStats,
      monitoringStats,
      canCreateHost,
      canExecuteScan,
      canAccessAudit,
      canViewReports,
    ]
  );

  /**
   * Render a widget by ID if it exists in the preset and the user has permission.
   * Returns null if the widget is not in the preset or permission is lacking.
   */
  const renderWidget = useCallback(
    (widgetId: string, key?: string) => {
      if (!presetHasWidget(preset, widgetId)) return null;
      const renderer = widgetRenderers[widgetId];
      if (!renderer) return null;
      return <React.Fragment key={key || widgetId}>{renderer()}</React.Fragment>;
    },
    [preset, widgetRenderers]
  );

  // ---------------------------------------------------------------------------
  // Loading state
  // ---------------------------------------------------------------------------

  if (loading) {
    return (
      <Box>
        <Box sx={{ mb: 4 }}>
          <Skeleton variant="rectangular" height={32} width="40%" sx={{ mb: 2 }} />
          <Skeleton variant="rectangular" height={20} width="60%" />
        </Box>
        <Skeleton variant="rectangular" height={80} sx={{ mb: 3 }} />
        <Grid container spacing={3}>
          {[1, 2, 3, 4].map((i) => (
            <Grid size={{ xs: 12, sm: 6, md: 3 }} key={i}>
              <Skeleton variant="rectangular" height={120} />
            </Grid>
          ))}
        </Grid>
      </Box>
    );
  }

  // ---------------------------------------------------------------------------
  // Error state
  // ---------------------------------------------------------------------------

  if (error) {
    return (
      <Box>
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
        <Button onClick={fetchDashboardData} variant="contained">
          Retry
        </Button>
      </Box>
    );
  }

  // ---------------------------------------------------------------------------
  // Determine grid layout from preset
  // ---------------------------------------------------------------------------

  const isSingleColumn = preset.columns === 1;
  const mainColumnSize = isSingleColumn ? 12 : 8;
  const sidebarColumnSize = isSingleColumn ? 12 : 4;

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <Box>
      {/* Role-contextual header (AC-14) */}
      <Box sx={{ mb: 3 }}>
        <Typography
          variant="h4"
          component="h1"
          gutterBottom
          sx={{ overflow: 'visible', wordBreak: 'normal', whiteSpace: 'normal' }}
        >
          {preset.title}
        </Typography>
        <Typography
          variant="body1"
          color="text.secondary"
          sx={{ overflow: 'visible', wordBreak: 'normal', whiteSpace: 'normal' }}
        >
          {preset.subtitle}
        </Typography>
      </Box>

      {/* OWCA Error Alert */}
      {owcaError && (
        <Alert severity="error" sx={{ mb: 3 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 'bold', mb: 1 }}>
            OWCA Compliance Service Unavailable
          </Typography>
          <Typography variant="body2" sx={{ mb: 2 }}>
            {owcaError}
          </Typography>
          <Button onClick={fetchDashboardData} variant="contained" color="error" size="small">
            Retry Connection
          </Button>
        </Alert>
      )}

      {/* Top widgets — full width, rendered in preset order */}
      {preset.topWidgets.map((widgetId) => renderWidget(widgetId))}

      {/* Main content grid — column layout driven by preset (AC-15) */}
      {isSingleColumn ? (
        /* Single-column layout for auditor/guest */
        <Grid container spacing={3}>
          <Grid size={{ xs: 12 }}>
            <Grid container spacing={3}>
              {preset.mainWidgets.map((widgetId) => (
                <Grid size={{ xs: 12 }} key={widgetId}>
                  {renderWidget(widgetId)}
                </Grid>
              ))}
            </Grid>
          </Grid>
        </Grid>
      ) : (
        /* Multi-column layout for admin/analyst/officer roles */
        <Grid container spacing={3}>
          {/* Main column */}
          <Grid size={{ xs: 12, lg: mainColumnSize }}>
            <Grid container spacing={3}>
              {preset.mainWidgets.map((widgetId) => {
                // Security Events and Fleet Health render side-by-side in admin presets
                const isHalfWidth =
                  (widgetId === 'security-events' || widgetId === 'fleet-health') &&
                  preset.columns === 3;
                return (
                  <Grid size={{ xs: 12, md: isHalfWidth ? 6 : 12 }} key={widgetId}>
                    {renderWidget(widgetId)}
                  </Grid>
                );
              })}
            </Grid>
          </Grid>

          {/* Sidebar column */}
          {preset.sidebarWidgets.length > 0 && (
            <Grid size={{ xs: 12, lg: sidebarColumnSize }}>
              <Grid container spacing={3}>
                {preset.sidebarWidgets.map((widgetId) => (
                  <Grid size={{ xs: 12 }} key={widgetId}>
                    {renderWidget(widgetId)}
                  </Grid>
                ))}
              </Grid>
            </Grid>
          )}
        </Grid>
      )}
    </Box>
  );
};

export default Dashboard;
