import React, { useState, useEffect, useCallback } from 'react';
import {
  Container,
  Grid,
  Box,
  Paper,
  Skeleton,
  Alert,
  Button,
  Typography
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import {
  Scanner,
  AddCircle,
  Warning,
  Assessment,
  Computer
} from '@mui/icons-material';

// Dashboard components
import SmartAlertBar from '../components/dashboard/SmartAlertBar';
import QuickActionCard from '../components/dashboard/QuickActionCard';
import FleetHealthWidget from '../components/dashboard/FleetHealthWidget';
import ActivityFeed, { ActivityItem } from '../components/dashboard/ActivityFeed';
import ComplianceTrend from '../components/dashboard/ComplianceTrend';
import PriorityHosts, { PriorityHost } from '../components/dashboard/PriorityHosts';
import { EmptyState } from '../components/design-system';
import { tokenService } from '../services/tokenService';
import QuickScanDialog from '../components/scans/QuickScanDialog';

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [dashboardData, setDashboardData] = useState<any>(null);
  const [timeRange, setTimeRange] = useState<'7d' | '30d' | '90d'>('30d');
  const [quickScanOpen, setQuickScanOpen] = useState(false);

  // Dashboard data state
  const [onlineHosts, setOnlineHosts] = useState(0);
  const [offlineHosts, setOfflineHosts] = useState(0);
  const [scanningHosts, setScanningHosts] = useState(0);
  const [totalHosts, setTotalHosts] = useState(0);
  const [criticalIssues, setCriticalIssues] = useState(0);
  const [trendData, setTrendData] = useState<any[]>([]);
  const [activities, setActivities] = useState<ActivityItem[]>([]);
  const [priorityHosts, setPriorityHosts] = useState<Array<{
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
  }>>([]);

  // Fetch dashboard data
  const fetchDashboardData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      // Fetch multiple endpoints in parallel using authenticated fetch
      const [hostsRes, scansRes] = await Promise.all([
        tokenService.authenticatedFetch('/api/hosts/'),
        tokenService.authenticatedFetch('/api/scans/')
      ]);

      if (!hostsRes.ok || !scansRes.ok) {
        throw new Error('Failed to fetch dashboard data');
      }

      const hosts = await hostsRes.json() || [];
      const scansData = await scansRes.json() || {};
      const scans = scansData.scans || [];

      // Ensure we have arrays to work with
      if (!Array.isArray(hosts) || !Array.isArray(scans)) {
        console.warn('Invalid data format received from API', { hosts: typeof hosts, scans: typeof scans });
        throw new Error('Invalid data format received from server');
      }

      // Process data for dashboard
      const onlineCount = hosts.filter((h: any) => h.status === 'online' || h.status === 'reachable').length;
      const offlineCount = hosts.filter((h: any) => h.status === 'offline').length;
      const scanningCount = hosts.filter((h: any) => h.status === 'scanning').length;
      const totalCount = hosts.length;
      
      // Calculate compliance stats
      let totalCritical = 0, totalHigh = 0, totalMedium = 0, totalLow = 0, totalPassed = 0;
      let totalCompliance = 0;
      let complianceCount = 0;

      hosts.forEach((host: any) => {
        if (host.compliance_score !== null && host.compliance_score !== undefined) {
          totalCompliance += host.compliance_score;
          complianceCount++;
        }
        totalCritical += host.critical_issues || 0;
        totalHigh += host.high_issues || 0;
        totalMedium += host.medium_issues || 0;
        totalLow += host.low_issues || 0;
        totalPassed += host.passed_rules || 0;
      });

      const overallCompliance = complianceCount > 0 ? Math.round(totalCompliance / complianceCount) : 0;

      // TODO: Fetch real trend data from backend API
      // For now, use empty array until real data is available
      const trendDataArray: any[] = [];

      // Generate activity items from recent scans
      const activitiesArray: ActivityItem[] = scans
        .filter((scan: any) => scan.completed_at)
        .slice(0, 10)
        .map((scan: any) => ({
          id: scan.id,
          type: scan.status === 'completed' ? 'scan_completed' : 'scan_failed',
          message: `Scan ${scan.status} for ${scan.host_name || scan.hostname || 'Unknown host'}`,
          timestamp: new Date(scan.completed_at || scan.started_at),
          severity: scan.status === 'completed' ? 'success' : 'error',
          metadata: {
            scanId: scan.id,
            complianceScore: scan.results?.score
          },
          action: {
            label: 'View Report',
            onClick: () => navigate(`/scans/${scan.id}`)
          }
        }));

      // Identify priority hosts
      const priorityHostsArray: Array<{
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
      }> = hosts
        .filter((host: any) => {
          // Critical issues
          if (host.critical_issues > 0) return true;
          // Not scanned in 30 days
          if (!host.last_scan || daysSince(host.last_scan) > 30) return true;
          // Offline
          if (host.status === 'offline') return true;
          // Degrading compliance
          if (host.compliance_score < 70) return true;
          return false;
        })
        .slice(0, 5)
        .map((host: any) => {
          let issueType: 'critical_issues' | 'not_scanned' | 'degrading' | 'offline' = 'critical_issues';
          let issue = '';
          let severity: 'critical' | 'high' | 'medium' = 'medium';

          if (host.critical_issues > 0) {
            issueType = 'critical_issues';
            issue = `${host.critical_issues} critical security issues detected`;
            severity = 'critical';
          } else if (!host.last_scan || daysSince(host.last_scan) > 30) {
            issueType = 'not_scanned';
            issue = host.last_scan ? `Not scanned in ${daysSince(host.last_scan)} days` : 'Never scanned';
            severity = daysSince(host.last_scan) > 60 ? 'high' : 'medium';
          } else if (host.status === 'offline') {
            issueType = 'offline';
            issue = 'Host is currently offline';
            severity = 'high';
          } else if (host.compliance_score < 70) {
            issueType = 'degrading';
            issue = `Compliance score below threshold (${host.compliance_score}%)`;
            severity = host.compliance_score < 50 ? 'high' : 'medium';
          }

          return {
            id: host.id,
            hostname: host.hostname,
            displayName: host.display_name || host.hostname,
            ipAddress: host.ip_address,
            operatingSystem: host.operating_system,
            status: host.status,
            complianceScore: host.compliance_score,
            issueType,
            issue,
            severity,
            lastScan: host.last_scan,
            criticalIssues: host.critical_issues || 0,
            highIssues: host.high_issues || 0,
            mediumIssues: host.medium_issues || 0,
            lowIssues: host.low_issues || 0,
            passedRules: host.passed_rules || 0,
          };
        });

      // Update state with processed data
      setOnlineHosts(onlineCount);
      setOfflineHosts(offlineCount);
      setScanningHosts(scanningCount);
      setTotalHosts(totalCount);
      setCriticalIssues(totalCritical);
      setTrendData(trendDataArray);
      setActivities(activitiesArray);
      setPriorityHosts(priorityHostsArray);

      // Store complete dashboard data
      setDashboardData({
        stats: {
          onlineHosts: onlineCount,
          offlineHosts: offlineCount,
          scanningHosts: scanningCount,
          totalHosts: totalCount,
          critical: totalCritical,
          high: totalHigh,
          medium: totalMedium,
          low: totalLow,
          passed: totalPassed,
          avgCompliance: overallCompliance,
        },
        hosts,
        scans,
        activities: activitiesArray,
        priorityHosts: priorityHostsArray,
        trendData: trendDataArray,
      });

    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      setError(error instanceof Error ? error.message : 'Failed to fetch dashboard data');
    } finally {
      setLoading(false);
    }
  }, [navigate, timeRange]);

  // Load data on component mount
  useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  // Handle filter clicks
  const handleFilterClick = (status: string) => {
    navigate('/hosts', { state: { filter: status } });
  };

  // Helper function to calculate days since a date
  const daysSince = (dateStr: string): number => {
    const date = new Date(dateStr);
    const now = new Date();
    const diffTime = Math.abs(now.getTime() - date.getTime());
    return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
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
            <Grid item xs={12} sm={6} md={3} key={i}>
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

  const handleSegmentClick = (status: 'online' | 'offline' | 'scanning' | 'maintenance') => {
    navigate('/hosts', { state: { filter: status } });
  };

  return (
    <Container maxWidth="xl">
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Security Compliance Dashboard
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Monitor your infrastructure security posture and compliance status
        </Typography>
      </Box>

      {/* Smart Alert Bar */}
      <SmartAlertBar 
        stats={{
          critical: criticalIssues,
          high: 0, // TODO: Calculate from dashboard data
          medium: 0, // TODO: Calculate from dashboard data
          low: 0, // TODO: Calculate from dashboard data
          passed: 0, // TODO: Calculate from dashboard data
          overallCompliance: 0, // TODO: Calculate from dashboard data
          trend: 'stable' // TODO: Calculate from dashboard data
        }}
        onFilterClick={handleFilterClick}
      />

      {/* Quick Actions */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h5" component="h2" gutterBottom>
          Quick Actions
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} sm={6} md={3}>
            <QuickActionCard
              title="New Scan"
              subtitle="Start a compliance scan"
              icon={<Scanner />}
              color="primary"
              onClick={() => setQuickScanOpen(true)}
              badge={0}
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <QuickActionCard
              title="Add Host"
              subtitle="Register new system"
              icon={<AddCircle />}
              color="success"
              onClick={() => navigate('/hosts/add-host')}
              badge={0}
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <QuickActionCard
              title="View Reports"
              subtitle="Compliance reports"
              icon={<Assessment />}
              color="info"
              onClick={() => navigate('/oview')}
              badge={0}
            />
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <QuickActionCard
              title="Critical Issues"
              subtitle="High priority alerts"
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
        <Grid item xs={12} lg={8}>
          <Grid container spacing={3}>
            {/* Fleet Health Widget */}
            <Grid item xs={12} md={6}>
              <FleetHealthWidget
                data={{
                  online: onlineHosts,
                  offline: offlineHosts,
                  scanning: scanningHosts,
                  maintenance: 0
                }}
                onSegmentClick={handleFilterClick}
              />
            </Grid>
            
            {/* Compliance Trend */}
            <Grid item xs={12} md={6}>
              <ComplianceTrend
                data={trendData}
                timeRange={timeRange}
                onTimeRangeChange={setTimeRange}
              />
            </Grid>
            
            {/* Priority Hosts */}
            <Grid item xs={12}>
              <PriorityHosts 
                hosts={priorityHosts.map(host => ({
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
                    label: host.issueType === 'not_scanned' || host.issueType === 'critical_issues' ? 'Quick Scan' : 'Fix',
                    onClick: () => {
                      if (host.issueType === 'not_scanned' || host.issueType === 'critical_issues') {
                        navigate('/scans/new', { 
                          state: { 
                            hostId: host.id, 
                            quickScan: true,
                            suggestedTemplate: host.issueType === 'critical_issues' ? 'security-audit' : 'quick-compliance'
                          } 
                        });
                      } else {
                        navigate(`/hosts/${host.id}`);
                      }
                    }
                  }
                }))}
              />
            </Grid>
          </Grid>
        </Grid>

        {/* Right Column - Activity Feed */}
        <Grid item xs={12} lg={4}>
          <ActivityFeed activities={activities} />
        </Grid>
      </Grid>

      {/* Quick Scan Dialog */}
      <QuickScanDialog
        open={quickScanOpen}
        onClose={() => setQuickScanOpen(false)}
        hostId=""
        hostName="General Scan"
        onScanStarted={(scanId) => {
          setQuickScanOpen(false);
          navigate(`/scans/${scanId}`);
        }}
      />
    </Container>
  );
};


export default Dashboard;