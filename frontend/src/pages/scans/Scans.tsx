import React, { useState, useEffect, useRef } from 'react';
import { storageGet, StorageKeys } from '../../services/storage';
import {
  Box,
  Button,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  LinearProgress,
  IconButton,
  Alert,
  CircularProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Badge,
  Menu,
  MenuItem,
  Divider,
  Avatar,
  Stack,
  Tooltip,
} from '@mui/material';
import {
  MoreVert as MoreVertIcon,
  ExpandMore as ExpandMoreIcon,
  Computer as ComputerIcon,
  Visibility as VisibilityIcon,
  GetApp as ExportIcon,
  PlayArrow as PlayIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Cancel as CancelIcon,
  Flag as FlagIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';
import StatusChip from '../../components/design-system/StatusChip';
import { DEFAULT_FRAMEWORK } from '../../constants/complianceFrameworks';
import type { HostStatus } from '../../types/host';

interface Scan {
  id: string;
  name: string;
  host_name: string;
  host_id: string; // Required - foreign key constraint ensures this exists
  content_name: string;
  profile_id: string;
  status: string;
  progress: number;
  started_at: string;
  completed_at?: string;
}

interface BackendScan {
  id: string;
  name: string;
  host_id: string;
  host?: {
    id: string;
    name?: string;
    hostname?: string;
    ip_address?: string;
    status?: 'online' | 'offline';
  };
  content_name: string;
  profile_id: string;
  status: string;
  progress: number;
  started_at: string;
  completed_at?: string;
}

interface HostWithScans {
  host_name: string;
  host_id: string; // Required - all scans must have valid host association
  ip_address?: string;
  status: HostStatus;
  scans: Scan[];
  completedCount: number;
  totalCount: number;
  mostRecentScan: Scan;
  mostRecentDate: string;
}

const Scans: React.FC = () => {
  const navigate = useNavigate();
  const [_scans, setScans] = useState<Scan[]>([]);
  const [hostGroups, setHostGroups] = useState<HostWithScans[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedHosts, setExpandedHosts] = useState<Set<string>>(new Set());
  const [exportMenuAnchor, setExportMenuAnchor] = useState<HTMLElement | null>(null);
  const [selectedHostForExport, setSelectedHostForExport] = useState<string>('');
  const scansRef = useRef<Scan[]>([]);

  // Phase 1 UX Improvements: Filter state
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  // Transform backend scan data to frontend format
  const transformScanData = (
    backendScans: BackendScan[]
  ): { scans: Scan[]; hostStatusMap: Map<string, { status: string; ip_address?: string }> } => {
    const hostStatusMap = new Map<string, { status: string; ip_address?: string }>();

    const scans = backendScans
      .filter((scan): scan is BackendScan & { host: NonNullable<BackendScan['host']> } => {
        if (!scan.host || !scan.host_id) {
          console.warn(`Scan ${scan.id} (${scan.name}) has no host association - skipping`);
          return false;
        }
        if (!scan.host.name && !scan.host.hostname) {
          console.warn(`Scan ${scan.id} host has no name - using ID`);
        }
        return true;
      })
      .map((scan): Scan => {
        // Extract host status and IP for later use in grouping
        const hostKey = scan.host.name || scan.host.hostname || `Host-${scan.host_id.slice(0, 8)}`;
        if (!hostStatusMap.has(hostKey)) {
          hostStatusMap.set(hostKey, {
            status: scan.host.status || 'offline',
            ip_address: scan.host.ip_address,
          });
        }

        return {
          id: scan.id,
          name: scan.name,
          host_name: hostKey,
          host_id: scan.host_id,
          content_name: scan.content_name,
          profile_id: scan.profile_id,
          status: scan.status,
          progress: scan.progress,
          started_at: scan.started_at,
          completed_at: scan.completed_at,
        };
      });

    return { scans, hostStatusMap };
  };

  // Utility function to filter scans to last 30 days
  const filterLast30Days = (scans: Scan[]): Scan[] => {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    return scans.filter((scan) => {
      const scanDate = new Date(scan.started_at);
      return scanDate >= thirtyDaysAgo;
    });
  };

  // Utility function to group scans by host with validation
  const groupScansByHost = (
    scans: Scan[],
    hostStatusMap?: Map<string, { status: string; ip_address?: string }>
  ): HostWithScans[] => {
    // Filter out any scans that somehow lack host association
    const validScans = scans.filter((scan) => {
      if (!scan.host_name || !scan.host_id) {
        console.error(`Invalid scan found: ${scan.id} missing host_name or host_id`, scan);
        return false;
      }
      return true;
    });

    if (validScans.length !== scans.length) {
      console.warn(
        `Filtered out ${scans.length - validScans.length} scans with missing host associations`
      );
    }

    const grouped = validScans.reduce(
      (acc, scan) => {
        const hostName = scan.host_name;
        const hostId = scan.host_id;

        if (!acc[hostName]) {
          // Get host status and IP from the status map
          const hostInfo = hostStatusMap?.get(hostName);
          acc[hostName] = {
            host_name: hostName,
            host_id: hostId,
            ip_address: hostInfo?.ip_address,
            // Type-safe cast: backend status string to HostStatus union type
            status: (hostInfo?.status as HostStatus) || 'offline',
            scans: [],
            completedCount: 0,
            totalCount: 0,
            mostRecentScan: scan,
            mostRecentDate: scan.started_at,
          };
        } else {
          // Validate that all scans for the same host_name have the same host_id
          if (acc[hostName].host_id !== hostId) {
            console.warn(
              `Host name collision: "${hostName}" has multiple host_ids: ${acc[hostName].host_id} and ${hostId}`
            );
          }
        }

        acc[hostName].scans.push(scan);
        acc[hostName].totalCount++;

        if (scan.status === 'completed') {
          acc[hostName].completedCount++;
        }

        // Update most recent scan
        if (new Date(scan.started_at) > new Date(acc[hostName].mostRecentDate)) {
          acc[hostName].mostRecentScan = scan;
          acc[hostName].mostRecentDate = scan.started_at;
        }

        return acc;
      },
      {} as Record<string, HostWithScans>
    );

    // Convert to array and sort by most recent scan date
    return Object.values(grouped).sort(
      (a, b) => new Date(b.mostRecentDate).getTime() - new Date(a.mostRecentDate).getTime()
    );
  };

  const fetchScans = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.get<{ scans: BackendScan[] }>('/api/scans/');
      const backendScans = data.scans || [];

      // Transform backend data to frontend format with validation
      const { scans: transformedScans, hostStatusMap } = transformScanData(backendScans);

      // Filter to last 30 days and group by host
      const filteredScans = filterLast30Days(transformedScans);
      const groupedHosts = groupScansByHost(filteredScans, hostStatusMap);

      if (transformedScans.length !== backendScans.length) {
        const skippedCount = backendScans.length - transformedScans.length;
        console.warn(`Data transformation filtered out ${skippedCount} invalid scans`);
        setError(
          `Warning: ${skippedCount} scans without proper host associations were excluded from the view.`
        );
      }

      setScans(transformedScans); // Keep all transformed scans for periodic refresh logic
      setHostGroups(groupedHosts);
      scansRef.current = transformedScans;
    } catch (error: unknown) {
      console.error('Failed to load scans:', error);

      // Type-safe error property access
      const isNetworkError =
        error && typeof error === 'object' && 'isNetworkError' in error && error.isNetworkError;
      const status = error && typeof error === 'object' && 'status' in error ? error.status : null;

      // Show user-friendly error message
      if (isNetworkError) {
        setError('Network error: Unable to connect to server');
      } else if (status === 401) {
        setError('Authentication required');
      } else {
        setError('Failed to load scans data');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();

    // Set up periodic refresh for running scans using ref to avoid infinite loop
    const interval = setInterval(() => {
      if (scansRef.current.some((scan) => scan.status === 'running')) {
        fetchScans();
      }
    }, 10000); // Refresh every 10 seconds if there are running scans

    return () => clearInterval(interval);
    // ESLint disable: fetchScans function is not memoized to avoid complex dependency chain
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Empty dependency array - only run once

  // Phase 1 UX Improvements: Helper functions for visual health indicators
  const getHealthColor = (successRate: number): string => {
    if (successRate >= 90) return 'success.main';
    if (successRate >= 70) return 'warning.main';
    return 'error.main';
  };

  const getHealthIcon = (successRate: number): React.ReactElement => {
    if (successRate >= 90) return <CheckCircleIcon />;
    if (successRate >= 70) return <WarningIcon />;
    return <ErrorIcon />;
  };

  // Phase 1 UX Improvements: Filter logic
  const getFilteredHostGroups = (): HostWithScans[] => {
    let filtered = [...hostGroups];

    // Apply status filter
    if (statusFilter === 'failed') {
      filtered = filtered.filter((host) => host.scans.some((scan) => scan.status === 'failed'));
    } else if (statusFilter === 'running') {
      filtered = filtered.filter((host) =>
        host.scans.some((scan) => scan.status === 'running' || scan.status === 'pending')
      );
    } else if (statusFilter === 'completed') {
      filtered = filtered.filter((host) => host.scans.some((scan) => scan.status === 'completed'));
    }

    // Apply severity filter (critical issues)
    if (severityFilter === 'critical') {
      // Filter hosts that have scans with low success rate (indicating critical issues)
      filtered = filtered.filter((host) => {
        const successRate = host.totalCount > 0 ? (host.completedCount / host.totalCount) * 100 : 0;
        return successRate < 70; // Less than 70% success rate = critical
      });
    }

    return filtered;
  };

  const filteredHostGroups = getFilteredHostGroups();

  // Host-level action handlers
  const handleToggleHost = (hostName: string) => {
    const newExpanded = new Set(expandedHosts);
    if (newExpanded.has(hostName)) {
      newExpanded.delete(hostName);
    } else {
      newExpanded.add(hostName);
    }
    setExpandedHosts(newExpanded);
  };

  const handleRescan = async (hostGroup: HostWithScans) => {
    try {
      // Validate host association before rescanning
      if (!hostGroup.host_id) {
        setError('Cannot rescan: Host ID is missing');
        return;
      }

      setLoading(true);
      setError(null);

      // Fetch host details
      const hostData = await api.get<{ platform?: string; platform_version?: string }>(
        `/api/hosts/${hostGroup.host_id}`
      );

      // Get platform information from host data OR infer from previous scan
      const mostRecentScan = hostGroup.mostRecentScan;
      let platform = hostData?.platform;
      let platformVersion = hostData?.platform_version;

      // If platform info not in host data, try to infer from scan name
      if (!platform || !platformVersion) {
        // Try to extract platform/version from scan name (e.g., "MongoDB Scan - rhel 8 - disa_stig")
        const scanName = mostRecentScan.name.toLowerCase();

        // Platform detection patterns
        if (scanName.includes('rhel') || scanName.includes('red hat')) {
          platform = 'rhel';
          // Try to extract version (7, 8, 9)
          const versionMatch = scanName.match(/rhel\s*(\d+)|red\s*hat\s*(\d+)/i);
          if (versionMatch) {
            platformVersion = versionMatch[1] || versionMatch[2];
          }
        } else if (scanName.includes('ubuntu')) {
          platform = 'ubuntu';
          // Try to extract version (20.04, 22.04, 24.04)
          const versionMatch = scanName.match(/ubuntu\s*(\d+\.\d+)/i);
          if (versionMatch) {
            platformVersion = versionMatch[1];
          }
        } else if (scanName.includes('debian')) {
          platform = 'debian';
          const versionMatch = scanName.match(/debian\s*(\d+)/i);
          if (versionMatch) {
            platformVersion = versionMatch[1];
          }
        }
      }

      // If still no platform info, provide helpful error with navigation to host edit
      if (!platform || !platformVersion) {
        setError(
          `Cannot rescan: Host platform information is missing. Please update the host details to include platform (e.g., rhel, ubuntu) and platform version (e.g., 8, 22.04).`
        );
        setLoading(false);
        return;
      }

      // Use profile_id from previous scan as framework
      // Only use DEFAULT_FRAMEWORK if profile_id is genuinely missing (should rarely happen)
      const framework = mostRecentScan.profile_id || DEFAULT_FRAMEWORK;

      // Call compliance scan API
      const response = await fetch('/api/scans/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
        body: JSON.stringify({
          host_id: hostGroup.host_id,
          hostname: hostGroup.host_name,
          platform,
          platform_version: platformVersion,
          framework,
          include_enrichment: true,
          generate_report: true,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || 'Failed to start rescan');
      }

      const result = await response.json();

      // Show success message with scan ID
      setError(null);
      // Rescan initiated successfully with compliance scanning
      void result; // Scan result available for tracking

      // Refresh scans list to show new scan
      await fetchScans();
    } catch (error: unknown) {
      console.error('Failed to start rescan:', error);
      // Type-safe error message extraction
      const errorMessage = error instanceof Error ? error.message : 'Failed to start rescan';
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const handleViewHostDetails = (hostGroup: HostWithScans) => {
    // host_id is now guaranteed to exist due to interface change
    navigate(`/hosts/${hostGroup.host_id}`);
  };

  const handleExportReports = (event: React.MouseEvent<HTMLElement>, hostName: string) => {
    setExportMenuAnchor(event.currentTarget);
    setSelectedHostForExport(hostName);
  };

  const handleCloseExportMenu = () => {
    setExportMenuAnchor(null);
    setSelectedHostForExport('');
  };

  const handleExportScans = async (filter: 'all' | 'completed' | 'failed') => {
    try {
      const hostGroup = hostGroups.find((h) => h.host_name === selectedHostForExport);
      if (!hostGroup) return;

      let scansToExport = hostGroup.scans;
      if (filter === 'completed') {
        scansToExport = hostGroup.scans.filter((scan) => scan.status === 'completed');
      } else if (filter === 'failed') {
        scansToExport = hostGroup.scans.filter((scan) => scan.status === 'failed');
      }

      // Export functionality - could implement CSV/PDF export here
      const exportData = scansToExport.map((scan) => ({
        host: scan.host_name,
        scan_name: scan.name,
        status: scan.status,
        started: scan.started_at,
        completed: scan.completed_at || 'N/A',
      }));

      // Create and download CSV
      const csvContent = [
        'Host,Scan Name,Status,Started,Completed',
        ...exportData.map(
          (row) => `${row.host},${row.scan_name},${row.status},${row.started},${row.completed}`
        ),
      ].join('\n');

      const blob = new Blob([csvContent], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${hostGroup.host_name}-scans-${filter}.csv`;
      a.click();
      window.URL.revokeObjectURL(url);

      handleCloseExportMenu();
    } catch (error) {
      console.error('Export failed:', error);
      setError('Failed to export scan reports');
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'success';
      case 'running':
        return 'primary';
      case 'failed':
        return 'error';
      case 'pending':
        return 'warning';
      default:
        return 'default';
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Scan History
        </Typography>
        <Typography variant="body1" color="text.secondary">
          View compliance scan history and results across your infrastructure
        </Typography>
      </Box>

      {/* Phase 1 UX Improvement: Quick Filters */}
      <Stack direction="row" spacing={1} sx={{ mb: 2, flexWrap: 'wrap', gap: 1 }}>
        <Chip
          label="All Scans"
          color={statusFilter === 'all' ? 'primary' : 'default'}
          onClick={() => setStatusFilter('all')}
          variant={statusFilter === 'all' ? 'filled' : 'outlined'}
        />
        <Chip
          label="Failed Only"
          color={statusFilter === 'failed' ? 'error' : 'default'}
          onClick={() => setStatusFilter('failed')}
          icon={<CancelIcon />}
          variant={statusFilter === 'failed' ? 'filled' : 'outlined'}
        />
        <Chip
          label="Critical Issues"
          color={severityFilter === 'critical' ? 'error' : 'default'}
          onClick={() => {
            setSeverityFilter(severityFilter === 'critical' ? 'all' : 'critical');
            setStatusFilter('all'); // Reset status filter when applying severity filter
          }}
          icon={<FlagIcon />}
          variant={severityFilter === 'critical' ? 'filled' : 'outlined'}
        />
        <Chip
          label="In Progress"
          color={statusFilter === 'running' ? 'primary' : 'default'}
          onClick={() => setStatusFilter('running')}
          icon={<PlayIcon />}
          variant={statusFilter === 'running' ? 'filled' : 'outlined'}
        />
        <Chip
          label="Completed"
          color={statusFilter === 'completed' ? 'success' : 'default'}
          onClick={() => setStatusFilter('completed')}
          icon={<CheckCircleIcon />}
          variant={statusFilter === 'completed' ? 'filled' : 'outlined'}
        />
        {(statusFilter !== 'all' || severityFilter !== 'all') && (
          <Chip
            label="Clear Filters"
            onClick={() => {
              setStatusFilter('all');
              setSeverityFilter('all');
            }}
            onDelete={() => {
              setStatusFilter('all');
              setSeverityFilter('all');
            }}
            size="small"
          />
        )}
      </Stack>

      {/* Error Display */}
      {error && (
        <Alert
          severity="error"
          sx={{ mb: 3 }}
          action={
            <Button
              color="inherit"
              size="small"
              onClick={fetchScans}
              disabled={loading}
              startIcon={loading ? <CircularProgress size={16} /> : undefined}
            >
              {loading ? 'Retrying...' : 'Retry'}
            </Button>
          }
          onClose={() => setError(null)}
        >
          {error}
        </Alert>
      )}

      {/* Host-Centric Accordion View */}
      <Box>
        {loading ? (
          <Paper sx={{ p: 4 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', py: 4 }}>
              <LinearProgress sx={{ width: '100%' }} />
            </Box>
          </Paper>
        ) : filteredHostGroups.length === 0 ? (
          <Paper sx={{ p: 4 }}>
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <Typography variant="body1" color="text.secondary" gutterBottom>
                {statusFilter !== 'all' || severityFilter !== 'all'
                  ? 'No scans match the selected filters'
                  : 'No scans found in the last 30 days'}
              </Typography>
            </Box>
          </Paper>
        ) : (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {filteredHostGroups.map((hostGroup) => (
              <Accordion
                key={hostGroup.host_name}
                expanded={expandedHosts.has(hostGroup.host_name)}
                onChange={() => handleToggleHost(hostGroup.host_name)}
                sx={{
                  '&:before': {
                    display: 'none',
                  },
                  boxShadow: 1,
                  borderRadius: '8px !important',
                  '&.Mui-expanded': {
                    margin: 0,
                  },
                }}
              >
                <AccordionSummary
                  expandIcon={<ExpandMoreIcon />}
                  sx={{
                    borderRadius: '8px',
                    '&.Mui-expanded': {
                      borderBottomLeftRadius: 0,
                      borderBottomRightRadius: 0,
                    },
                  }}
                >
                  <Box
                    sx={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      width: '100%',
                      pr: 2,
                    }}
                  >
                    {/* Host Icon and Name - Phase 1: Added Critical Findings Badge */}
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                      <ComputerIcon color="primary" />
                      <Box>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="h6" fontWeight="medium">
                            {hostGroup.host_name}
                          </Typography>
                          {(() => {
                            const successRate =
                              hostGroup.totalCount > 0
                                ? (hostGroup.completedCount / hostGroup.totalCount) * 100
                                : 0;
                            const failedCount = hostGroup.totalCount - hostGroup.completedCount;

                            // Phase 1: Critical Findings Badge
                            if (successRate < 70 && failedCount > 0) {
                              return (
                                <Chip
                                  icon={<WarningIcon />}
                                  label={`${failedCount} Critical`}
                                  color="error"
                                  size="small"
                                />
                              );
                            }
                            return null;
                          })()}
                          {hostGroup.scans.some(
                            (scan) => scan.status === 'running' || scan.status === 'pending'
                          ) && <Chip label="Scanning" color="primary" size="small" />}
                        </Box>
                        {hostGroup.ip_address && (
                          <Typography variant="body2" color="text.secondary">
                            {hostGroup.ip_address}
                          </Typography>
                        )}
                      </Box>
                    </Box>

                    {/* Success Ratio and Metrics - Phase 1: Added Visual Health Indicator */}
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                      {/* Phase 1: Visual Health Indicator with Icon */}
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {(() => {
                          const successRate =
                            hostGroup.totalCount > 0
                              ? (hostGroup.completedCount / hostGroup.totalCount) * 100
                              : 0;
                          return (
                            <Tooltip title={`${successRate.toFixed(1)}% Scan Success Rate`}>
                              <Avatar
                                sx={{
                                  bgcolor: getHealthColor(successRate),
                                  width: 32,
                                  height: 32,
                                }}
                              >
                                {getHealthIcon(successRate)}
                              </Avatar>
                            </Tooltip>
                          );
                        })()}
                        <Box sx={{ textAlign: 'left' }}>
                          <Typography variant="h6" fontWeight="bold">
                            {hostGroup.completedCount}/{hostGroup.totalCount}
                          </Typography>
                          <Typography
                            variant="caption"
                            color={(() => {
                              const successRate =
                                hostGroup.totalCount > 0
                                  ? (hostGroup.completedCount / hostGroup.totalCount) * 100
                                  : 0;
                              return getHealthColor(successRate);
                            })()}
                          >
                            {hostGroup.totalCount > 0
                              ? `${((hostGroup.completedCount / hostGroup.totalCount) * 100).toFixed(1)}% Completed`
                              : 'No Data'}
                          </Typography>
                        </Box>
                      </Box>

                      {/* Most Recent Scan Date */}
                      <Box sx={{ textAlign: 'center' }}>
                        <Typography variant="body2" fontWeight="medium">
                          {formatDate(hostGroup.mostRecentDate)}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          Last Scan
                        </Typography>
                      </Box>

                      {/* Host Status Badge */}
                      <Badge
                        badgeContent={hostGroup.totalCount}
                        color="primary"
                        sx={{
                          '& .MuiBadge-badge': {
                            right: -3,
                            top: 13,
                          },
                        }}
                      >
                        <StatusChip status={hostGroup.status} size="small" showIcon={true} />
                      </Badge>

                      {/* Host Actions Menu */}
                      <IconButton
                        size="small"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleExportReports(e, hostGroup.host_name);
                        }}
                      >
                        <MoreVertIcon />
                      </IconButton>
                    </Box>
                  </Box>
                </AccordionSummary>

                <AccordionDetails sx={{ pt: 0 }}>
                  <Divider sx={{ mb: 2 }} />

                  {/* Host Actions Bar */}
                  <Box
                    sx={{
                      display: 'flex',
                      gap: 1,
                      mb: 3,
                      justifyContent: 'flex-start',
                    }}
                  >
                    <Button
                      size="small"
                      variant="contained"
                      startIcon={<PlayIcon />}
                      onClick={(e) => {
                        e.stopPropagation();
                        handleRescan(hostGroup);
                      }}
                    >
                      Rescan
                    </Button>
                    <Button
                      size="small"
                      variant="outlined"
                      startIcon={<VisibilityIcon />}
                      onClick={(e) => {
                        e.stopPropagation();
                        handleViewHostDetails(hostGroup);
                      }}
                    >
                      View Host Details
                    </Button>
                    <Button
                      size="small"
                      variant="outlined"
                      startIcon={<ExportIcon />}
                      onClick={(e) => handleExportReports(e, hostGroup.host_name)}
                    >
                      Export Reports
                    </Button>
                  </Box>

                  {/* Individual Scans Table */}
                  <TableContainer component={Paper} variant="outlined">
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Scan Name</TableCell>
                          <TableCell>Content</TableCell>
                          <TableCell>Status</TableCell>
                          <TableCell>Started</TableCell>
                          <TableCell>Completed</TableCell>
                          <TableCell>Actions</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {hostGroup.scans.map((scan) => (
                          <TableRow key={scan.id} hover>
                            <TableCell>
                              <Typography variant="body2" fontWeight="medium">
                                {scan.name}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2">{scan.content_name}</Typography>
                            </TableCell>
                            <TableCell>
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                <Chip
                                  label={scan.status}
                                  color={getStatusColor(scan.status)}
                                  size="small"
                                  variant="filled"
                                />
                                {scan.status === 'running' && (
                                  <Box
                                    sx={{ display: 'flex', alignItems: 'center', gap: 1, ml: 1 }}
                                  >
                                    <LinearProgress
                                      variant="determinate"
                                      value={scan.progress}
                                      sx={{ width: 60 }}
                                    />
                                    <Typography variant="caption" color="text.secondary">
                                      {scan.progress}%
                                    </Typography>
                                  </Box>
                                )}
                              </Box>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2">{formatDate(scan.started_at)}</Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2">
                                {scan.completed_at ? formatDate(scan.completed_at) : '-'}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Box sx={{ display: 'flex', gap: 0.5 }}>
                                <IconButton
                                  size="small"
                                  title="View Results"
                                  onClick={() => navigate(`/scans/${scan.id}`)}
                                >
                                  <VisibilityIcon fontSize="small" />
                                </IconButton>
                                {scan.status === 'completed' && (
                                  <IconButton
                                    size="small"
                                    title="Download Report"
                                    onClick={() => {
                                      // TODO: Implement scan report download functionality
                                      void scan.id; // Scan ID for report generation
                                    }}
                                  >
                                    <ExportIcon fontSize="small" />
                                  </IconButton>
                                )}
                                <IconButton size="small" title="More Actions">
                                  <MoreVertIcon fontSize="small" />
                                </IconButton>
                              </Box>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>
            ))}
          </Box>
        )}

        {/* Export Menu */}
        <Menu
          anchorEl={exportMenuAnchor}
          open={Boolean(exportMenuAnchor)}
          onClose={handleCloseExportMenu}
        >
          <MenuItem onClick={() => handleExportScans('all')}>Export All Scans</MenuItem>
          <MenuItem onClick={() => handleExportScans('completed')}>Export Completed Scans</MenuItem>
          <MenuItem onClick={() => handleExportScans('failed')}>Export Failed Scans</MenuItem>
        </Menu>
      </Box>
    </Box>
  );
};

export default Scans;
