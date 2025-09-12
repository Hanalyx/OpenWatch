import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  Button,
  Container,
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
  Divider
} from '@mui/material';
import {
  Add as AddIcon,
  MoreVert as MoreVertIcon,
  ExpandMore as ExpandMoreIcon,
  Computer as ComputerIcon,
  Refresh as RefreshIcon,
  Visibility as VisibilityIcon,
  GetApp as ExportIcon,
  PlayArrow as PlayIcon
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { api } from '../../services/api';
import StatusChip from '../../components/design-system/StatusChip';

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
  status: 'online' | 'offline' | 'reachable' | 'ping_only' | 'scanning' | 'error' | 'maintenance' | 'pending';
  scans: Scan[];
  completedCount: number;
  totalCount: number;
  mostRecentScan: Scan;
  mostRecentDate: string;
}

const Scans: React.FC = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState<Scan[]>([]);
  const [hostGroups, setHostGroups] = useState<HostWithScans[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedHosts, setExpandedHosts] = useState<Set<string>>(new Set());
  const [exportMenuAnchor, setExportMenuAnchor] = useState<HTMLElement | null>(null);
  const [selectedHostForExport, setSelectedHostForExport] = useState<string>('');
  const scansRef = useRef<Scan[]>([]);

  // Transform backend scan data to frontend format
  const transformScanData = (backendScans: BackendScan[]): { scans: Scan[], hostStatusMap: Map<string, { status: string, ip_address?: string }> } => {
    const hostStatusMap = new Map<string, { status: string, ip_address?: string }>();
    
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
            ip_address: scan.host.ip_address
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
          completed_at: scan.completed_at
        };
      });

    return { scans, hostStatusMap };
  };

  // Utility function to filter scans to last 30 days
  const filterLast30Days = (scans: Scan[]): Scan[] => {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    return scans.filter(scan => {
      const scanDate = new Date(scan.started_at);
      return scanDate >= thirtyDaysAgo;
    });
  };

  // Utility function to group scans by host with validation
  const groupScansByHost = (scans: Scan[], hostStatusMap?: Map<string, { status: string, ip_address?: string }>): HostWithScans[] => {
    // Filter out any scans that somehow lack host association
    const validScans = scans.filter(scan => {
      if (!scan.host_name || !scan.host_id) {
        console.error(`Invalid scan found: ${scan.id} missing host_name or host_id`, scan);
        return false;
      }
      return true;
    });

    if (validScans.length !== scans.length) {
      console.warn(`Filtered out ${scans.length - validScans.length} scans with missing host associations`);
    }

    const grouped = validScans.reduce((acc, scan) => {
      const hostName = scan.host_name;
      const hostId = scan.host_id;

      if (!acc[hostName]) {
        // Get host status and IP from the status map
        const hostInfo = hostStatusMap?.get(hostName);
        acc[hostName] = {
          host_name: hostName,
          host_id: hostId,
          ip_address: hostInfo?.ip_address,
          status: (hostInfo?.status as any) || 'offline', // Cast to satisfy TypeScript
          scans: [],
          completedCount: 0,
          totalCount: 0,
          mostRecentScan: scan,
          mostRecentDate: scan.started_at
        };
      } else {
        // Validate that all scans for the same host_name have the same host_id
        if (acc[hostName].host_id !== hostId) {
          console.warn(`Host name collision: "${hostName}" has multiple host_ids: ${acc[hostName].host_id} and ${hostId}`);
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
    }, {} as Record<string, HostWithScans>);

    // Convert to array and sort by most recent scan date
    return Object.values(grouped).sort((a, b) => 
      new Date(b.mostRecentDate).getTime() - new Date(a.mostRecentDate).getTime()
    );
  };

  const fetchScans = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.get<{scans: BackendScan[]}>('/api/scans/');
      const backendScans = data.scans || [];
      
      // Transform backend data to frontend format with validation
      const { scans: transformedScans, hostStatusMap } = transformScanData(backendScans);
      
      // Filter to last 30 days and group by host
      const filteredScans = filterLast30Days(transformedScans);
      const groupedHosts = groupScansByHost(filteredScans, hostStatusMap);
      
      if (transformedScans.length !== backendScans.length) {
        const skippedCount = backendScans.length - transformedScans.length;
        console.warn(`Data transformation filtered out ${skippedCount} invalid scans`);
        setError(`Warning: ${skippedCount} scans without proper host associations were excluded from the view.`);
      }
      
      setScans(transformedScans); // Keep all transformed scans for periodic refresh logic
      setHostGroups(groupedHosts);
      scansRef.current = transformedScans;
    } catch (error: any) {
      console.error('Failed to load scans:', error);
      
      // Show user-friendly error message
      if (error.isNetworkError) {
        setError('Network error: Unable to connect to server');
      } else if (error.status === 401) {
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
      if (scansRef.current.some(scan => scan.status === 'running')) {
        fetchScans();
      }
    }, 10000); // Refresh every 10 seconds if there are running scans
    
    return () => clearInterval(interval);
  }, []); // Empty dependency array - only run once

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

      // Use most recent scan configuration for one-click rescan
      const mostRecentScan = hostGroup.mostRecentScan;
      const payload = {
        host_id: hostGroup.host_id, // Now guaranteed to exist
        content_id: mostRecentScan.profile_id, // Assuming this maps to content
        profile_id: mostRecentScan.profile_id,
        name: `Rescan - ${hostGroup.host_name} - ${new Date().toISOString()}`
      };
      
      await api.post('/api/scans/', payload);
      
      // Refresh scans list to show new scan
      fetchScans();
    } catch (error) {
      console.error('Failed to start rescan:', error);
      setError('Failed to start rescan');
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
      const hostGroup = hostGroups.find(h => h.host_name === selectedHostForExport);
      if (!hostGroup) return;

      let scansToExport = hostGroup.scans;
      if (filter === 'completed') {
        scansToExport = hostGroup.scans.filter(scan => scan.status === 'completed');
      } else if (filter === 'failed') {
        scansToExport = hostGroup.scans.filter(scan => scan.status === 'failed');
      }

      // Export functionality - could implement CSV/PDF export here
      const exportData = scansToExport.map(scan => ({
        host: scan.host_name,
        scan_name: scan.name,
        status: scan.status,
        started: scan.started_at,
        completed: scan.completed_at || 'N/A'
      }));

      // Create and download CSV
      const csvContent = [
        'Host,Scan Name,Status,Started,Completed',
        ...exportData.map(row => 
          `${row.host},${row.scan_name},${row.status},${row.started},${row.completed}`
        )
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
      minute: '2-digit'
    });
  };

  return (
    <Container maxWidth="xl">
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Compliance Scans
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Monitor and manage security compliance scans across your infrastructure
        </Typography>
      </Box>

      {/* Actions Bar */}
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => navigate('/scans/compliance')}
          size="large"
        >
          New Scan
        </Button>
        <Button
          variant="text"
          disabled
          sx={{ color: 'text.secondary' }}
        >
          Start All Pending
        </Button>
      </Box>

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
        ) : hostGroups.length === 0 ? (
          <Paper sx={{ p: 4 }}>
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <Typography variant="body1" color="text.secondary" gutterBottom>
                No scans found in the last 30 days
              </Typography>
              <Button
                variant="contained"
                startIcon={<AddIcon />}
                onClick={() => navigate('/scans/compliance')}
              >
                Create Your First Scan
              </Button>
            </Box>
          </Paper>
        ) : (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {hostGroups.map((hostGroup) => (
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
                  <Box sx={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    justifyContent: 'space-between',
                    width: '100%',
                    pr: 2 
                  }}>
                    {/* Host Icon and Name */}
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                      <ComputerIcon color="primary" />
                      <Box>
                        <Typography variant="h6" fontWeight="medium">
                          {hostGroup.host_name}
                        </Typography>
                        {hostGroup.ip_address && (
                          <Typography variant="body2" color="text.secondary">
                            {hostGroup.ip_address}
                          </Typography>
                        )}
                      </Box>
                    </Box>

                    {/* Success Ratio and Metrics */}
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                      {/* Success Ratio */}
                      <Box sx={{ textAlign: 'center' }}>
                        <Typography variant="h6" fontWeight="bold" color="primary">
                          {hostGroup.completedCount}/{hostGroup.totalCount}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          Success Ratio
                        </Typography>
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
                        <StatusChip
                          status={hostGroup.status}
                          size="small"
                          showIcon={true}
                        />
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
                  <Box sx={{ 
                    display: 'flex', 
                    gap: 1, 
                    mb: 3,
                    justifyContent: 'flex-start'
                  }}>
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
                              <Typography variant="body2">
                                {scan.content_name}
                              </Typography>
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
                                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, ml: 1 }}>
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
                              <Typography variant="body2">
                                {formatDate(scan.started_at)}
                              </Typography>
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
                                      // Implement download functionality
                                      console.log(`Download report for scan ${scan.id}`);
                                    }}
                                  >
                                    <ExportIcon fontSize="small" />
                                  </IconButton>
                                )}
                                <IconButton 
                                  size="small" 
                                  title="More Actions"
                                >
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
          <MenuItem onClick={() => handleExportScans('all')}>
            Export All Scans
          </MenuItem>
          <MenuItem onClick={() => handleExportScans('completed')}>
            Export Completed Scans
          </MenuItem>
          <MenuItem onClick={() => handleExportScans('failed')}>
            Export Failed Scans
          </MenuItem>
        </Menu>
      </Box>
    </Container>
  );
};

export default Scans;