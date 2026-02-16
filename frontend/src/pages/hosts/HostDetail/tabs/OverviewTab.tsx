/**
 * Overview Tab
 *
 * Displays system information summary, compliance trend chart,
 * and quick stats for the host.
 *
 * Part of OpenWatch OS Transformation - Host Detail Page Redesign.
 *
 * @module pages/hosts/HostDetail/tabs/OverviewTab
 */

import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  List,
  ListItem,
  ListItemText,
  Alert,
  Skeleton,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import ComplianceTrendChart from '../../../../components/baselines/ComplianceTrendChart';
import type {
  SystemInfo,
  ServerIntelligenceSummary,
  ScanHistoryItem,
} from '../../../../types/hostDetail';

interface OverviewTabProps {
  systemInfo: SystemInfo | null | undefined;
  systemInfoLoading?: boolean;
  intelligenceSummary: ServerIntelligenceSummary | null | undefined;
  intelligenceLoading?: boolean;
  scanHistory: ScanHistoryItem[];
  scanHistoryLoading?: boolean;
}

/**
 * Format uptime in human-readable format
 */
function formatUptime(seconds: number | null): string {
  if (!seconds) return 'Unknown';

  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  const parts = [];
  if (days > 0) parts.push(`${days} days`);
  if (hours > 0) parts.push(`${hours} hours`);
  if (minutes > 0 && days === 0) parts.push(`${minutes} minutes`);

  return parts.join(', ') || 'Less than a minute';
}

/**
 * Format memory with units
 */
function formatMemory(mb: number | null): string {
  if (!mb) return 'Unknown';
  const gb = mb / 1024;
  return gb >= 1 ? `${gb.toFixed(1)} GB` : `${mb} MB`;
}

/**
 * Format disk space
 */
function formatDisk(gb: number | null): string {
  if (!gb) return 'Unknown';
  return `${gb.toFixed(1)} GB`;
}

const OverviewTab: React.FC<OverviewTabProps> = ({
  systemInfo,
  systemInfoLoading,
  intelligenceSummary,
  intelligenceLoading,
  scanHistory,
  scanHistoryLoading,
}) => {
  // Transform scan history for trend chart
  const trendData = scanHistory
    .filter((scan) => scan.completedAt && scan.results)
    .map((scan) => ({
      timestamp: scan.completedAt!,
      score: parseFloat(scan.results?.score || '0'),
      passed_rules: scan.results?.passedRules || 0,
      failed_rules: scan.results?.failedRules || 0,
      total_rules: scan.results?.totalRules || 0,
      scan_id: scan.id,
    }))
    .reverse(); // Oldest first for chart

  return (
    <Box>
      <Grid container spacing={3}>
        {/* System Information */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                System Information
              </Typography>

              {systemInfoLoading ? (
                <Box>
                  <Skeleton variant="text" width="80%" />
                  <Skeleton variant="text" width="70%" />
                  <Skeleton variant="text" width="60%" />
                  <Skeleton variant="text" width="75%" />
                </Box>
              ) : systemInfo ? (
                <List dense disablePadding>
                  <ListItem disablePadding sx={{ py: 0.5 }}>
                    <ListItemText
                      primary="Operating System"
                      secondary={systemInfo.osPrettyName || systemInfo.osName || 'Unknown'}
                    />
                  </ListItem>
                  <ListItem disablePadding sx={{ py: 0.5 }}>
                    <ListItemText
                      primary="Kernel"
                      secondary={`${systemInfo.kernelName || 'Linux'} ${systemInfo.kernelRelease || 'Unknown'}`}
                    />
                  </ListItem>
                  <ListItem disablePadding sx={{ py: 0.5 }}>
                    <ListItemText
                      primary="Architecture"
                      secondary={systemInfo.architecture || 'Unknown'}
                    />
                  </ListItem>
                  <ListItem disablePadding sx={{ py: 0.5 }}>
                    <ListItemText
                      primary="Hostname / FQDN"
                      secondary={systemInfo.fqdn || systemInfo.hostname || 'Unknown'}
                    />
                  </ListItem>
                  <ListItem disablePadding sx={{ py: 0.5 }}>
                    <ListItemText
                      primary="Primary IP"
                      secondary={systemInfo.primaryIp || 'Unknown'}
                    />
                  </ListItem>
                  <ListItem disablePadding sx={{ py: 0.5 }}>
                    <ListItemText
                      primary="Uptime"
                      secondary={formatUptime(systemInfo.uptimeSeconds)}
                    />
                  </ListItem>
                </List>
              ) : (
                <Alert severity="info">
                  System information not yet collected. Data will be available after the next scan.
                </Alert>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Hardware & Resources */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Hardware & Resources
              </Typography>

              {systemInfoLoading ? (
                <Box>
                  <Skeleton variant="text" width="70%" />
                  <Skeleton variant="text" width="60%" />
                  <Skeleton variant="text" width="65%" />
                  <Skeleton variant="text" width="75%" />
                </Box>
              ) : systemInfo ? (
                <List dense disablePadding>
                  <ListItem disablePadding sx={{ py: 0.5 }}>
                    <ListItemText
                      primary="CPU"
                      secondary={
                        systemInfo.cpuModel
                          ? `${systemInfo.cpuModel} (${systemInfo.cpuCores || '?'} cores, ${systemInfo.cpuThreads || '?'} threads)`
                          : `${systemInfo.cpuCores || '?'} cores`
                      }
                    />
                  </ListItem>
                  <ListItem disablePadding sx={{ py: 0.5 }}>
                    <ListItemText
                      primary="Memory"
                      secondary={formatMemory(systemInfo.memoryTotalMb)}
                    />
                  </ListItem>
                  <ListItem disablePadding sx={{ py: 0.5 }}>
                    <ListItemText
                      primary="Disk"
                      secondary={
                        systemInfo.diskTotalGb
                          ? `${formatDisk(systemInfo.diskUsedGb)} used of ${formatDisk(systemInfo.diskTotalGb)} (${formatDisk(systemInfo.diskFreeGb)} free)`
                          : 'Unknown'
                      }
                    />
                  </ListItem>
                  {systemInfo.selinuxStatus && (
                    <ListItem disablePadding sx={{ py: 0.5 }}>
                      <ListItemText
                        primary="SELinux"
                        secondary={`${systemInfo.selinuxStatus} (${systemInfo.selinuxMode || 'unknown mode'})`}
                      />
                    </ListItem>
                  )}
                  {systemInfo.firewallStatus && (
                    <ListItem disablePadding sx={{ py: 0.5 }}>
                      <ListItemText
                        primary="Firewall"
                        secondary={`${systemInfo.firewallStatus} (${systemInfo.firewallService || 'unknown'})`}
                      />
                    </ListItem>
                  )}
                </List>
              ) : (
                <Alert severity="info">Hardware information not yet collected.</Alert>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Server Intelligence Summary */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Server Intelligence
              </Typography>

              {intelligenceLoading ? (
                <Box>
                  <Skeleton variant="text" width="60%" />
                  <Skeleton variant="text" width="50%" />
                  <Skeleton variant="text" width="55%" />
                </Box>
              ) : intelligenceSummary ? (
                <List dense disablePadding>
                  <ListItem disablePadding sx={{ py: 0.5 }}>
                    <ListItemText
                      primary="Packages"
                      secondary={`${intelligenceSummary.packagesCount} installed`}
                    />
                  </ListItem>
                  <ListItem disablePadding sx={{ py: 0.5 }}>
                    <ListItemText
                      primary="Services"
                      secondary={`${intelligenceSummary.runningServicesCount} running of ${intelligenceSummary.servicesCount} total`}
                    />
                  </ListItem>
                  <ListItem disablePadding sx={{ py: 0.5 }}>
                    <ListItemText
                      primary="Users"
                      secondary={`${intelligenceSummary.usersCount} accounts (${intelligenceSummary.sudoUsersCount} with sudo)`}
                    />
                  </ListItem>
                  <ListItem disablePadding sx={{ py: 0.5 }}>
                    <ListItemText
                      primary="Network"
                      secondary={`${intelligenceSummary.networkInterfacesCount} interfaces, ${intelligenceSummary.listeningPortsCount} listening ports`}
                    />
                  </ListItem>
                  <ListItem disablePadding sx={{ py: 0.5 }}>
                    <ListItemText
                      primary="Firewall Rules"
                      secondary={`${intelligenceSummary.firewallRulesCount} rules`}
                    />
                  </ListItem>
                  {intelligenceSummary.lastCollectedAt && (
                    <ListItem disablePadding sx={{ py: 0.5 }}>
                      <ListItemText
                        primary="Last Collected"
                        secondary={new Date(intelligenceSummary.lastCollectedAt).toLocaleString()}
                      />
                    </ListItem>
                  )}
                </List>
              ) : (
                <Alert severity="info">Intelligence data not yet collected.</Alert>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Compliance Trend */}
        <Grid size={{ xs: 12, md: 6 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Compliance Trend
              </Typography>

              {scanHistoryLoading ? (
                <Skeleton variant="rectangular" height={200} />
              ) : trendData.length > 0 ? (
                <ComplianceTrendChart data={trendData} height={200} />
              ) : (
                <Alert severity="info">
                  No scan history available yet. Trend data will appear after scans complete.
                </Alert>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default OverviewTab;
