import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  IconButton,
  Chip,
  Avatar,
  Menu,
  MenuItem,
  Checkbox,
  Tooltip,
  LinearProgress,
  Divider,
  ListItemIcon,
  ListItemText,
  useTheme,
  alpha,
} from '@mui/material';
import {
  MoreVert,
  Computer,
  PlayArrow,
  Delete,
  Edit,
  NetworkCheck,
  VpnKey,
  Timeline,
  Assessment,
  Memory,
  Storage as StorageIcon,
  Scanner,
  Info,
  Visibility,
} from '@mui/icons-material';
import { StatusChip, type ViewMode } from '../../../components/design-system';
import type { Host } from '../../../types/host';
import { getComplianceScoreColor } from '../../../utils/hostStatus';

/**
 * Props for the HostCard component.
 *
 * Previously this component was defined inline inside the Hosts page component
 * and accessed many parent-scope variables via closure. Those closure references
 * are now expressed as explicit props so the component can live in its own file.
 */
export interface HostCardProps {
  /** The host data to render. */
  host: Host;
  /** Card layout variant. Defaults to 'grid'. */
  viewMode?: ViewMode;
  /** IDs of currently selected hosts (for checkbox state and border highlight). */
  selectedHosts: string[];
  /** Router navigate function. */
  navigate: (path: string, options?: Record<string, unknown>) => void;
  /** Toggle selection of a host by ID. */
  handleSelectHost: (hostId: string) => void;
  /** Trigger a quick scan with pre-scan JIT validation. */
  handleQuickScanWithValidation: (host: Host) => Promise<void>;
  /** Open the host edit dialog/form. */
  handleEditHost: (host: Host) => void;
  /** Open the host delete confirmation. */
  handleDeleteHost: (host: Host) => void;
  /** Trigger a connectivity / status check for a host. */
  checkHostStatus: (hostId: string) => Promise<void>;
  /** Open the quick-scan dialog for a specific host. */
  setQuickScanDialog: (d: { open: boolean; host: Host | null }) => void;
}

/**
 * HostCard renders a single host in one of three view modes: compact, list, or grid.
 *
 * Each mode provides progressively more detail:
 * - **compact** - Minimal 120px card with name, status, and compliance chip.
 * - **list** - Horizontal row with OS chip, compliance ring, and context menu.
 * - **grid** (default) - Full card with compliance ring, resource usage, tags,
 *   scan history, and quick-action buttons.
 */
const HostCard: React.FC<HostCardProps> = ({
  host,
  viewMode = 'grid',
  selectedHosts,
  navigate,
  handleSelectHost,
  handleQuickScanWithValidation,
  handleEditHost,
  handleDeleteHost,
  checkHostStatus,
  setQuickScanDialog,
}) => {
  const theme = useTheme();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

  // ---------------------------------------------------------------------------
  // Compact view - simplified card with minimal height
  // ---------------------------------------------------------------------------
  if (viewMode === 'compact') {
    return (
      <Card
        onClick={() => navigate(`/hosts/${host.id}`)}
        sx={{
          height: 120,
          display: 'flex',
          flexDirection: 'column',
          position: 'relative',
          transition: 'all 0.3s',
          cursor: 'pointer',
          '&:hover': {
            transform: 'translateY(-2px)',
            boxShadow: theme.shadows[4],
          },
          ...(selectedHosts.includes(host.id) && {
            borderColor: theme.palette.primary.main,
            borderWidth: 2,
            borderStyle: 'solid',
          }),
        }}
      >
        <CardContent sx={{ p: 1.5, pb: '8px !important' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
            <Checkbox
              checked={selectedHosts.includes(host.id)}
              onChange={() => handleSelectHost(host.id)}
              onClick={(e) => e.stopPropagation()}
              size="small"
            />
            <Avatar
              sx={{
                bgcolor: alpha(getComplianceScoreColor(host.complianceScore, theme), 0.1),
                color: getComplianceScoreColor(host.complianceScore, theme),
                mr: 1,
                width: 32,
                height: 32,
              }}
            >
              <Computer fontSize="small" />
            </Avatar>
            <Box sx={{ flexGrow: 1, minWidth: 0 }}>
              <Typography variant="body2" fontWeight="bold" noWrap>
                {host.displayName}
              </Typography>
              <Typography variant="caption" color="text.secondary" noWrap>
                {host.hostname}
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: 'flex', gap: 0.5, alignItems: 'center' }}>
            <StatusChip status={host.status} size="small" variant="filled" />
            {host.complianceScore !== null && (
              <Chip
                label={`${host.complianceScore.toFixed(0)}%`}
                size="small"
                color={
                  host.complianceScore >= 70
                    ? 'success'
                    : host.complianceScore >= 40
                      ? 'warning'
                      : 'error'
                }
                sx={{ height: 18, fontSize: '0.65rem' }}
              />
            )}
          </Box>
        </CardContent>
      </Card>
    );
  }

  // ---------------------------------------------------------------------------
  // List view - horizontal layout
  // ---------------------------------------------------------------------------
  if (viewMode === 'list') {
    return (
      <Card
        onClick={() => navigate(`/hosts/${host.id}`)}
        sx={{
          display: 'flex',
          alignItems: 'center',
          p: 2,
          transition: 'all 0.3s',
          cursor: 'pointer',
          '&:hover': {
            boxShadow: theme.shadows[4],
            bgcolor: alpha(theme.palette.primary.main, 0.02),
          },
          ...(selectedHosts.includes(host.id) && {
            borderColor: theme.palette.primary.main,
            borderWidth: 2,
            borderStyle: 'solid',
          }),
        }}
      >
        <Checkbox
          checked={selectedHosts.includes(host.id)}
          onChange={() => handleSelectHost(host.id)}
          onClick={(e) => e.stopPropagation()}
          size="small"
          sx={{ mr: 2 }}
        />
        <Avatar
          sx={{
            bgcolor: alpha(getComplianceScoreColor(host.complianceScore, theme), 0.1),
            color: getComplianceScoreColor(host.complianceScore, theme),
            mr: 2,
          }}
        >
          <Computer />
        </Avatar>
        <Box sx={{ flexGrow: 1, mr: 2, minWidth: 0 }}>
          <Typography variant="subtitle1" fontWeight="bold" noWrap>
            {host.displayName}
          </Typography>
          <Typography variant="body2" color="text.secondary" noWrap>
            {host.hostname} • {host.ipAddress}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, minWidth: 0, flexShrink: 0 }}>
          <StatusChip status={host.status} size="small" variant="filled" />
          <Chip label={host.operatingSystem} size="small" variant="outlined" />
          {host.complianceScore !== null && (
            <Chip
              label={`${host.complianceScore.toFixed(0)}%`}
              size="small"
              color={
                host.complianceScore >= 70
                  ? 'success'
                  : host.complianceScore >= 40
                    ? 'warning'
                    : 'error'
              }
              sx={{ height: 20, fontSize: '0.7rem', fontWeight: 'bold' }}
            />
          )}
          <IconButton
            size="small"
            onClick={(e) => {
              e.stopPropagation();
              setAnchorEl(e.currentTarget);
            }}
          >
            <MoreVert />
          </IconButton>
          <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={() => setAnchorEl(null)}>
            <MenuItem
              onClick={() => {
                setQuickScanDialog({ open: true, host });
                setAnchorEl(null);
              }}
            >
              <ListItemIcon>
                <Scanner fontSize="small" />
              </ListItemIcon>
              <ListItemText>Quick Scan</ListItemText>
            </MenuItem>
            <MenuItem onClick={() => handleEditHost(host)}>
              <ListItemIcon>
                <Edit fontSize="small" />
              </ListItemIcon>
              <ListItemText>Edit</ListItemText>
            </MenuItem>
            <MenuItem>
              <ListItemIcon>
                <VpnKey fontSize="small" />
              </ListItemIcon>
              <ListItemText>SSH Connect</ListItemText>
            </MenuItem>
            <MenuItem
              onClick={(e) => {
                e.stopPropagation();
                setAnchorEl(null);
                navigate(`/hosts/${host.id}`);
              }}
            >
              <ListItemIcon>
                <Timeline fontSize="small" />
              </ListItemIcon>
              <ListItemText>View History</ListItemText>
            </MenuItem>
            <Divider />
            <MenuItem onClick={() => checkHostStatus(host.id)}>
              <ListItemIcon>
                <NetworkCheck fontSize="small" />
              </ListItemIcon>
              <ListItemText>Check Status</ListItemText>
            </MenuItem>
            <Divider />
            <MenuItem onClick={() => handleDeleteHost(host)} sx={{ color: 'error.main' }}>
              <ListItemIcon>
                <Delete fontSize="small" color="error" />
              </ListItemIcon>
              <ListItemText>Remove</ListItemText>
            </MenuItem>
          </Menu>
        </Box>
      </Card>
    );
  }

  // ---------------------------------------------------------------------------
  // Default grid view - full card layout
  // ---------------------------------------------------------------------------
  return (
    <Card
      onClick={() => navigate(`/hosts/${host.id}`)}
      sx={{
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        position: 'relative',
        transition: 'all 0.3s',
        cursor: 'pointer',
        '&:hover': {
          transform: 'translateY(-4px)',
          boxShadow: theme.shadows[8],
        },
        ...(selectedHosts.includes(host.id) && {
          borderColor: theme.palette.primary.main,
          borderWidth: 2,
          borderStyle: 'solid',
        }),
      }}
    >
      <CardContent sx={{ pb: 1 }}>
        {/* Header */}
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <Checkbox
            checked={selectedHosts.includes(host.id)}
            onChange={() => handleSelectHost(host.id)}
            onClick={(e) => e.stopPropagation()}
            size="small"
          />
          <Avatar
            sx={{
              bgcolor: alpha(getComplianceScoreColor(host.complianceScore, theme), 0.1),
              color: getComplianceScoreColor(host.complianceScore, theme),
              mr: 1,
            }}
          >
            <Computer />
          </Avatar>
          <Box sx={{ flexGrow: 1 }}>
            <Typography variant="subtitle1" fontWeight="bold" noWrap>
              {host.displayName}
            </Typography>
            <Typography variant="caption" color="text.secondary" noWrap>
              {host.hostname} • {host.ipAddress}
            </Typography>
          </Box>
          <IconButton
            size="small"
            onClick={(e) => {
              e.stopPropagation();
              setAnchorEl(e.currentTarget);
            }}
            sx={{ ml: 'auto' }}
          >
            <MoreVert />
          </IconButton>
          <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={() => setAnchorEl(null)}>
            <MenuItem
              onClick={() => {
                setQuickScanDialog({ open: true, host });
                setAnchorEl(null);
              }}
            >
              <ListItemIcon>
                <Scanner fontSize="small" />
              </ListItemIcon>
              <ListItemText>Quick Scan</ListItemText>
            </MenuItem>
            <MenuItem onClick={() => handleEditHost(host)}>
              <ListItemIcon>
                <Edit fontSize="small" />
              </ListItemIcon>
              <ListItemText>Edit</ListItemText>
            </MenuItem>
            <MenuItem>
              <ListItemIcon>
                <VpnKey fontSize="small" />
              </ListItemIcon>
              <ListItemText>SSH Connect</ListItemText>
            </MenuItem>
            <MenuItem
              onClick={(e) => {
                e.stopPropagation();
                setAnchorEl(null);
                navigate(`/hosts/${host.id}`);
              }}
            >
              <ListItemIcon>
                <Timeline fontSize="small" />
              </ListItemIcon>
              <ListItemText>View History</ListItemText>
            </MenuItem>
            <Divider />
            <MenuItem onClick={() => checkHostStatus(host.id)}>
              <ListItemIcon>
                <NetworkCheck fontSize="small" />
              </ListItemIcon>
              <ListItemText>Check Status</ListItemText>
            </MenuItem>
            <Divider />
            <MenuItem onClick={() => handleDeleteHost(host)} sx={{ color: 'error.main' }}>
              <ListItemIcon>
                <Delete fontSize="small" color="error" />
              </ListItemIcon>
              <ListItemText>Remove</ListItemText>
            </MenuItem>
          </Menu>
        </Box>

        {/* Status and OS */}
        <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
          <StatusChip status={host.status} size="small" variant="filled" />
          <Chip label={host.operatingSystem} size="small" variant="outlined" />
        </Box>

        {/* System Resources - Only show if data is available */}
        {(host.cpuUsage !== null || host.diskUsage !== null) && (
          <Box sx={{ mb: 2 }}>
            {host.cpuUsage !== null && (
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 0.5 }}>
                <Memory fontSize="small" sx={{ mr: 1, color: 'text.secondary' }} />
                <Typography variant="caption" sx={{ mr: 1, minWidth: 30 }}>
                  CPU
                </Typography>
                <LinearProgress
                  variant="determinate"
                  value={host.cpuUsage}
                  sx={{ flexGrow: 1, mr: 1, height: 4, borderRadius: 2 }}
                />
                <Typography variant="caption">{host.cpuUsage}%</Typography>
              </Box>
            )}
            {host.diskUsage !== null && (
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 0.5 }}>
                <StorageIcon fontSize="small" sx={{ mr: 1, color: 'text.secondary' }} />
                <Typography variant="caption" sx={{ mr: 1, minWidth: 30 }}>
                  Disk
                </Typography>
                <LinearProgress
                  variant="determinate"
                  value={host.diskUsage}
                  sx={{ flexGrow: 1, mr: 1, height: 4, borderRadius: 2 }}
                  color={host.diskUsage > 80 ? 'warning' : 'primary'}
                />
                <Typography variant="caption">{host.diskUsage}%</Typography>
              </Box>
            )}
          </Box>
        )}

        {/* Tags - Only show if there are tags */}
        {host.tags && host.tags.length > 0 && (
          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
            {host.tags.map((tag) => (
              <Chip key={tag} label={tag} size="small" sx={{ height: 20, fontSize: '0.7rem' }} />
            ))}
          </Box>
        )}

        {/* Last Check and Last Scan - Show footer with available info */}
        <Box sx={{ mt: 2, pt: 2, borderTop: 1, borderColor: 'divider' }}>
          {/* Last Check - Always show if available */}
          {host.lastCheck && (
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 0.5 }}>
              Last check:{' '}
              {(() => {
                const lastCheck = new Date(host.lastCheck);
                const now = new Date();
                const diffMinutes = Math.floor(
                  Math.abs(now.getTime() - lastCheck.getTime()) / (1000 * 60)
                );

                if (diffMinutes < 1) return 'Just now';
                if (diffMinutes < 60)
                  return `${diffMinutes} minute${diffMinutes > 1 ? 's' : ''} ago`;

                const diffHours = Math.floor(diffMinutes / 60);
                if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;

                const diffDays = Math.floor(diffHours / 24);
                return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
              })()}
            </Typography>
          )}

          {/* Latest Scan Information */}
          {host.latestScanId ? (
            <Box>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 0.5 }}>
                <Typography variant="caption" color="text.secondary" sx={{ flexGrow: 1 }}>
                  Latest scan: {host.latestScanName || 'SCAP Compliance Scan'}
                </Typography>
                {host.scanStatus === 'running' && (
                  <Chip
                    label={`${host.scanProgress || 0}%`}
                    size="small"
                    color="primary"
                    sx={{ height: 16, fontSize: '0.6rem' }}
                  />
                )}
                {host.scanStatus === 'completed' && host.complianceScore !== null && (
                  <Chip
                    label={`${host.complianceScore.toFixed(1)}%`}
                    size="small"
                    color={
                      host.complianceScore >= 70
                        ? 'success'
                        : host.complianceScore >= 40
                          ? 'warning'
                          : 'error'
                    }
                    sx={{ height: 16, fontSize: '0.6rem' }}
                  />
                )}
                {host.scanStatus === 'failed' && (
                  <Chip
                    label="Failed"
                    size="small"
                    color="error"
                    sx={{ height: 16, fontSize: '0.6rem' }}
                  />
                )}
              </Box>

              {host.scanStatus === 'running' && (
                <Box sx={{ mb: 0.5 }}>
                  <LinearProgress
                    variant="determinate"
                    value={host.scanProgress || 0}
                    sx={{ height: 3, borderRadius: 2 }}
                  />
                </Box>
              )}

              {host.scanStatus === 'completed' && host.totalRules && host.totalRules > 0 && (
                <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.65rem' }}>
                  {host.passedRules}/{host.totalRules} rules passed • {host.failedRules} failed
                </Typography>
              )}

              {host.lastScan && (
                <Typography
                  variant="caption"
                  color="text.secondary"
                  sx={{ fontSize: '0.65rem', display: 'block' }}
                >
                  {new Date(host.lastScan).toLocaleString()}
                </Typography>
              )}
            </Box>
          ) : host.lastScan ? (
            <Typography variant="caption" color="text.secondary">
              Last scan: {new Date(host.lastScan).toLocaleDateString()}
            </Typography>
          ) : null}

          {/* No Check or Scan Message */}
          {!host.lastCheck && !host.lastScan && (
            <Typography variant="caption" color="text.secondary">
              Never monitored - Awaiting first connectivity check
            </Typography>
          )}
        </Box>
      </CardContent>

      {/* Quick Actions */}
      <Box
        sx={{
          mt: 'auto',
          p: 1,
          borderTop: 1,
          borderColor: 'divider',
          display: 'flex',
          justifyContent: 'space-around',
        }}
      >
        <Tooltip title={host.scanStatus === 'running' ? 'View Running Scan' : 'Start New Scan'}>
          <IconButton
            size="small"
            color="primary"
            onClick={(e) => {
              e.stopPropagation();
              if (host.latestScanId && host.scanStatus === 'running') {
                navigate(`/scans/${host.latestScanId}`);
              } else {
                // WEEK 2 PHASE 1: Use pre-scan JIT validation
                handleQuickScanWithValidation(host);
              }
            }}
          >
            {host.scanStatus === 'running' ? <Visibility /> : <PlayArrow />}
          </IconButton>
        </Tooltip>
        <Tooltip title={host.latestScanId ? 'View Latest Scan Results' : 'View Host Details'}>
          <IconButton
            size="small"
            onClick={(e) => {
              e.stopPropagation();
              if (host.latestScanId) {
                navigate(`/scans/${host.latestScanId}`);
              } else {
                navigate(`/hosts/${host.id}`);
              }
            }}
          >
            {host.latestScanId ? <Assessment /> : <Info />}
          </IconButton>
        </Tooltip>
        <Tooltip title="Edit Host">
          <IconButton
            size="small"
            onClick={(e) => {
              e.stopPropagation();
              handleEditHost(host);
            }}
          >
            <Edit />
          </IconButton>
        </Tooltip>
        <Tooltip title="SSH Connect">
          <IconButton size="small">
            <VpnKey />
          </IconButton>
        </Tooltip>
        <Tooltip title="Delete Host">
          <IconButton
            size="small"
            color="error"
            onClick={(e) => {
              e.stopPropagation();
              handleDeleteHost(host);
            }}
          >
            <Delete />
          </IconButton>
        </Tooltip>
      </Box>
    </Card>
  );
};

export default HostCard;
