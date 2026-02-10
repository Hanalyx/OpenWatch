import React, { useState, useEffect, useCallback } from 'react';
import { Container, Box, Skeleton, Alert, Button, Typography } from '@mui/material';
import Grid from '@mui/material/Grid';
import { useNavigate } from 'react-router-dom';
import { Scanner, AddCircle, Warning, Assessment } from '@mui/icons-material';

// Dashboard components
import SmartAlertBar from '../components/dashboard/SmartAlertBar';
import QuickActionCard from '../components/dashboard/QuickActionCard';
import FleetHealthWidget from '../components/dashboard/FleetHealthWidget';
import ActivityFeed, { type ActivityItem } from '../components/dashboard/ActivityFeed';
import ComplianceTrend from '../components/dashboard/ComplianceTrend';
import PriorityHosts from '../components/dashboard/PriorityHosts';
import DriftAlertsWidget from '../components/baselines/DriftAlertsWidget';
import { SchedulerStatusWidget } from './Dashboard/widgets';
import { api } from '../services/api';
import { owcaService, type FleetStatistics } from '../services/owcaService';
import DashboardErrorBoundary from '../components/dashboard/DashboardErrorBoundary';

/**
 * Compliance trend data point for dashboard charts
 * Represents historical compliance metrics across severity levels
 */
interface ComplianceTrendData {
  date: string;
  overall: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/**
 * Dashboard statistics for compliance metrics
 */
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

/**
 * Priority host for dashboard display
 */
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

/**
 * Aggregated dashboard data from backend
 * Combined metrics from hosts, scans, and compliance data
 */
interface DashboardData {
  stats: DashboardStats;
  hosts: NormalizedHost[];
  scans: RawScanData[];
  activities: ActivityItem[];
  priorityHosts: DashboardPriorityHost[];
  trendData: ComplianceTrendData[];
}

/**
 * Raw host data from backend API
 * May contain either snake_case or camelCase fields (backend inconsistency)
 */
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
  // Allow additional fields from backend
  [key: string]: unknown;
}

/**
 * Raw scan data from backend API
 * May contain either snake_case or camelCase fields (backend inconsistency)
 */
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
  // Allow additional fields from backend
  [key: string]: unknown;
}

/**
 * Normalized host data after transformation
 * Consistent camelCase field naming for frontend use
 */
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

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [owcaError, setOwcaError] = useState<string | null>(null);
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [timeRange, setTimeRange] = useState<'7d' | '30d' | '90d'>('30d');
  const [_fleetStats, setFleetStats] = useState<FleetStatistics | null>(null);

  // Dashboard data state - adaptive monitoring states
  const [onlineHosts, setOnlineHosts] = useState(0);
  const [degradedHosts, setDegradedHosts] = useState(0);
  const [criticalHosts, setCriticalHosts] = useState(0);
  const [downHosts, setDownHosts] = useState(0);
  const [scanningHosts, setScanningHosts] = useState(0);
  const [maintenanceHosts, setMaintenanceHosts] = useState(0);
  const [_totalHosts, setTotalHosts] = useState(0);
  const [criticalIssues, setCriticalIssues] = useState(0);
  const [trendData, setTrendData] = useState<ComplianceTrendData[]>([]);
  const [activities, setActivities] = useState<ActivityItem[]>([]);
  const [priorityHosts, setPriorityHosts] = useState<
    Array<{
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
    }>
  >([]);

  // Fetch dashboard data
  const fetchDashboardData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      // Raw data from backend API (may have inconsistent field naming)
      let hosts: RawHostData[] = [];
      let scans: RawScanData[] = [];
      let owcaFleetStats: FleetStatistics | null = null;

      try {
        // Fetch data from API using OWCA for fleet statistics
        // OWCA provides canonical compliance calculations (single source of truth)
        // No fallback to manual calculations - OWCA failure triggers error alert
        const [hostsData, scansData, fetchedFleetStats] = await Promise.all([
          api.get<RawHostData[]>('/api/hosts/'),
          api.get<{ scans: RawScanData[] }>('/api/scans/'),
          owcaService.getFleetStatistics(), // Propagate errors - no fallback
        ]);

        hosts = hostsData || [];
        scans = scansData.scans || [];
        owcaFleetStats = fetchedFleetStats;

        // Store OWCA fleet statistics for use in dashboard
        setFleetStats(fetchedFleetStats);
        setOwcaError(null); // Clear any previous OWCA errors
      } catch (apiError) {
        // Type-safe error handling: check error properties with type guards
        console.error('Failed to fetch dashboard data:', apiError);

        // Check for network errors
        const errorCode = (apiError as { code?: string }).code;
        const errorMessage = (apiError as { message?: string }).message;
        const responseStatus = (apiError as { response?: { status?: number } }).response?.status;
        const requestUrl = (apiError as { config?: { url?: string } }).config?.url;

        // Detect OWCA-specific failures (compliance applications require accurate data)
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

      // Ensure we have arrays to work with and normalize data
      if (!Array.isArray(hosts) || !Array.isArray(scans)) {
        console.warn('Invalid data format received from API', {
          hosts: typeof hosts,
          scans: typeof scans,
        });
        throw new Error('Invalid data format received from server');
      }

      // Normalize host data to ensure consistent field naming
      // Use RawHostData type for backend data that may have inconsistent naming
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

      // Process data for dashboard using normalized hosts with adaptive monitoring states
      // Use NormalizedHost type for type-safe access to status field
      const onlineCount = normalizedHosts.filter(
        (h: NormalizedHost) => h.status === 'online' || h.status === 'reachable'
      ).length;
      const degradedCount = normalizedHosts.filter(
        (h: NormalizedHost) => h.status === 'degraded'
      ).length;
      const criticalCount = normalizedHosts.filter(
        (h: NormalizedHost) => h.status === 'critical'
      ).length;
      const downCount = normalizedHosts.filter(
        (h: NormalizedHost) => h.status === 'down' || h.status === 'offline'
      ).length;
      const scanningCount = normalizedHosts.filter(
        (h: NormalizedHost) => h.status === 'scanning'
      ).length;
      const maintenanceCount = normalizedHosts.filter(
        (h: NormalizedHost) => h.status === 'maintenance'
      ).length;
      const totalCount = normalizedHosts.length;

      // Calculate compliance stats using OWCA fleet statistics (canonical source)
      // OWCA is the ONLY source for compliance calculations - no fallback to manual calculations
      // Compliance applications require accurate, canonical data - unavailability triggers error alert
      if (!owcaFleetStats) {
        throw new Error('OWCA fleet statistics unavailable - cannot display compliance metrics');
      }

      const totalCritical = owcaFleetStats.total_critical_issues;
      const totalHigh = owcaFleetStats.total_high_issues;
      const totalMedium = owcaFleetStats.total_medium_issues;
      const totalLow = owcaFleetStats.total_low_issues;
      const totalPassed = 0; // TODO: Add total_passed_rules to FleetStatistics model
      const overallCompliance = Math.round(owcaFleetStats.average_compliance);

      // Generate trend data showing current compliance state
      // Use ComplianceTrendData interface for type-safe trend chart data
      // TODO(feature): Implement historical trend data from OWCA trend analysis API
      // Currently showing single data point (current state)
      // Future: Replace with actual historical data from /api/compliance/owca/host/{id}/trend
      const today = new Date().toISOString().split('T')[0];
      const trendDataArray: ComplianceTrendData[] =
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
          : [
              // Fallback data when no hosts exist
              { date: today, overall: 0, critical: 0, high: 0, medium: 0, low: 0 },
            ];

      // Generate activity items from recent scans
      // Use RawScanData type for backend scan data with snake_case/camelCase fields
      const activitiesArray: ActivityItem[] = scans
        .filter((scan: RawScanData) => scan.completed_at && scan.id)
        .slice(0, 10)
        .map((scan: RawScanData): ActivityItem => {
          const scanId = scan.id as string; // Safe due to filter above
          const activityType: ActivityItem['type'] =
            scan.status === 'completed' ? 'scan_completed' : 'scan_failed';
          const activitySeverity: ActivityItem['severity'] =
            scan.status === 'completed' ? 'success' : 'error';
          return {
            id: scanId,
            type: activityType,
            message: `Scan ${scan.status} for ${scan.host_name || scan.hostname || 'Unknown host'}`,
            timestamp: new Date(scan.completed_at || scan.started_at || new Date().toISOString()),
            severity: activitySeverity,
            metadata: {
              scanId,
              complianceScore: scan.results?.score,
            },
            action: {
              label: 'View Report',
              onClick: () => navigate(`/scans/${scanId}`),
            },
          };
        });

      // Identify priority hosts using normalized data
      // Type definition for priority host array (used by both OWCA and fallback)
      let priorityHostsArray: Array<{
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
      }> = [];

      // Fetch OWCA priority hosts (uses OWCA risk scoring algorithm)
      // No fallback - OWCA is required for accurate risk prioritization
      const owcaPriorityHosts = await owcaService.getTopPriorityHosts(5);

      // Map OWCA priority hosts to dashboard format
      // OWCA provides sophisticated prioritization based on risk score
      priorityHostsArray = owcaPriorityHosts.map((owcaHost) => {
        // Find matching host in normalized hosts for additional metadata
        const matchingHost = normalizedHosts.find((h) => h.id === owcaHost.host_id);

        let issueType: 'critical_issues' | 'not_scanned' | 'degrading' | 'offline' =
          'critical_issues';
        let issue = '';
        let severity: 'critical' | 'high' | 'medium' = 'medium';

        // Determine primary issue based on OWCA prioritization
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

      // Update state with processed data
      setOnlineHosts(onlineCount);
      setDegradedHosts(degradedCount);
      setCriticalHosts(criticalCount);
      setDownHosts(downCount);
      setScanningHosts(scanningCount);
      setMaintenanceHosts(maintenanceCount);
      setTotalHosts(totalCount);
      setCriticalIssues(totalCritical);
      setTrendData(trendDataArray);
      setActivities(activitiesArray);
      setPriorityHosts(priorityHostsArray);

      // Store complete dashboard data
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
        activities: activitiesArray,
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

      // Reset all counts to 0 when there's an error
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
    // ESLint disable: timeRange is intentionally included as useCallback dependency for data refresh
    // This is correct - we want to refetch when timeRange changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [navigate, timeRange]);

  // Load data on component mount
  useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  // Handle filter clicks
  const handleFilterClick = (status: string) => {
    navigate('/hosts', { state: { filter: status } });
  };

  // Show loading state
  if (loading) {
    return (
      <Container maxWidth="xl">
        <Box sx={{ mb: 4 }}>
          <Skeleton variant="rectangular" height={32} width="40%" sx={{ mb: 2 }} />
          <Skeleton variant="rectangular" height={20} width="60%" />
        </Box>
        <Grid container spacing={3}>
          {[1, 2, 3, 4].map((i) => (
            <Grid size={{ xs: 12, sm: 6, md: 3 }} key={i}>
              <Skeleton variant="rectangular" height={120} />
            </Grid>
          ))}
        </Grid>
      </Container>
    );
  }

  // Show error state
  if (error) {
    return (
      <Container maxWidth="xl">
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
        <Button onClick={fetchDashboardData} variant="contained">
          Retry
        </Button>
      </Container>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 3 }}>
        <Typography
          variant="h4"
          component="h1"
          gutterBottom
          sx={{ overflow: 'visible', wordBreak: 'normal', whiteSpace: 'normal' }}
        >
          Security Compliance Dashboard
        </Typography>
        <Typography
          variant="body1"
          color="text.secondary"
          sx={{ overflow: 'visible', wordBreak: 'normal', whiteSpace: 'normal' }}
        >
          Monitor your infrastructure security posture and compliance status
        </Typography>
      </Box>

      {/* OWCA Error Alert - Compliance applications require accurate data */}
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

      {/* Smart Alert Bar */}
      <SmartAlertBar
        stats={{
          critical: criticalIssues,
          high: dashboardData?.stats?.high || 0,
          medium: dashboardData?.stats?.medium || 0,
          low: dashboardData?.stats?.low || 0,
          passed: dashboardData?.stats?.passed || 0,
          overallCompliance: dashboardData?.stats?.avgCompliance || 0,
          trend: (() => {
            const avgCompliance = dashboardData?.stats?.avgCompliance ?? 0;
            if (avgCompliance > 85) return 'up';
            if (avgCompliance > 70) return 'stable';
            return 'down';
          })(),
        }}
        onFilterClick={handleFilterClick}
      />

      {/* Quick Actions */}
      <Box sx={{ mb: 4 }}>
        <Grid container spacing={3}>
          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <QuickActionCard
              title="Manual Scan"
              subtitle="Run ad-hoc compliance check"
              icon={<Scanner />}
              color="secondary"
              onClick={() => navigate('/scans/create')}
              badge={0}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <QuickActionCard
              title="Add Host"
              subtitle="Register new system"
              icon={<AddCircle />}
              color="success"
              onClick={() => navigate('/hosts/add-host')}
              badge={0}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <QuickActionCard
              title="View Reports"
              subtitle="Compliance reports"
              icon={<Assessment />}
              color="info"
              onClick={() => navigate('/oview')}
              badge={0}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 6, md: 3 }}>
            <QuickActionCard
              title="Active Alerts"
              subtitle="Compliance drift & issues"
              icon={<Warning />}
              color="error"
              onClick={() => navigate('/hosts')}
              badge={criticalIssues}
            />
          </Grid>
        </Grid>
      </Box>

      {/* Main Content Grid */}
      <Grid container spacing={3}>
        {/* Left Column - Fleet Health & Compliance */}
        <Grid size={{ xs: 12, lg: 8 }}>
          <Grid container spacing={3}>
            {/* Fleet Health Widget */}
            <Grid size={{ xs: 12, md: 6 }}>
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
            </Grid>

            {/* Compliance Trend */}
            <Grid size={{ xs: 12, md: 6 }}>
              <DashboardErrorBoundary onRetry={fetchDashboardData}>
                <ComplianceTrend
                  data={trendData}
                  timeRange={timeRange}
                  onTimeRangeChange={setTimeRange}
                />
              </DashboardErrorBoundary>
            </Grid>

            {/* Priority Hosts */}
            <Grid size={{ xs: 12 }}>
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
                        if (
                          host.issueType === 'not_scanned' ||
                          host.issueType === 'critical_issues'
                        ) {
                          navigate('/scans/create', {
                            state: {
                              preselectedHostId: host.id,
                            },
                          });
                        } else {
                          navigate(`/hosts/${host.id}`);
                        }
                      },
                    },
                  }))}
                />
              </DashboardErrorBoundary>
            </Grid>
          </Grid>
        </Grid>

        {/* Right Column - Activity Feed */}
        <Grid size={{ xs: 12, lg: 4 }}>
          <Grid container spacing={3}>
            {/* Scheduler Status Widget */}
            <Grid size={{ xs: 12 }}>
              <DashboardErrorBoundary onRetry={fetchDashboardData}>
                <SchedulerStatusWidget />
              </DashboardErrorBoundary>
            </Grid>

            {/* Drift Alerts Widget */}
            <Grid size={{ xs: 12 }}>
              <DashboardErrorBoundary onRetry={fetchDashboardData}>
                <DriftAlertsWidget limit={5} autoRefresh={true} refreshInterval={30000} />
              </DashboardErrorBoundary>
            </Grid>

            {/* Activity Feed */}
            <Grid size={{ xs: 12 }}>
              <DashboardErrorBoundary onRetry={fetchDashboardData}>
                <ActivityFeed activities={activities} />
              </DashboardErrorBoundary>
            </Grid>
          </Grid>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;
