import React from 'react';
import {
  Card,
  CardContent,
  CardActions,
  Box,
  Typography,
  Chip,
  IconButton,
  Avatar,
  LinearProgress,
  Tooltip,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Badge
} from '@mui/material';
import {
  Computer,
  MoreVert,
  CheckCircle,
  Warning,
  Error as ErrorIcon,
  Schedule,
  Edit,
  Delete,
  NetworkCheck,
  PlayArrow,
  Stop,
  Assessment,
  Security,
  Wifi,
  WifiOff
} from '@mui/icons-material';
import { QuickScanDropdown } from '../scans';

interface Host {
  id: string;
  hostname: string;
  displayName: string;
  ipAddress: string;
  operatingSystem: string;
  status: 'online' | 'degraded' | 'critical' | 'down' | 'offline' | 'maintenance' | 'scanning' | 'reachable' | 'ping_only' | 'error' | 'unknown';
  complianceScore?: number;
  complianceTrend?: 'up' | 'down' | 'stable';
  lastScan?: string;
  lastCheck?: string;
  nextScan?: string;
  criticalIssues: number;
  highIssues: number;
  mediumIssues: number;
  lowIssues: number;
  tags: string[];
  group: string;
  group_id?: number;
  group_name?: string;
  group_description?: string;
  group_color?: string;
  owner: string;
  cpuUsage?: number;
  memoryUsage?: number;
  diskUsage?: number;
  uptime?: string;
  osVersion?: string;
  lastBackup?: string;
  sshKey: boolean;
  agent: 'installed' | 'not_installed' | 'error';
  profile?: string;
  port: number;
  username: string;
  authMethod: string;
  ssh_key_fingerprint?: string;
  ssh_key_type?: string;
  ssh_key_bits?: number;
  ssh_key_comment?: string;
  latestScanId?: string;
  latestScanName?: string;
  scanStatus?: 'pending' | 'running' | 'completed' | 'failed';
  scanProgress?: number;
  failedRules: number;
  passedRules: number;
  totalRules: number;
}

interface HostCardProps {
  host: Host;
  viewMode: 'card' | 'list' | 'compact';
  selected?: boolean;
  onSelect?: (hostId: string) => void;
  onEdit?: (host: Host) => void;
  onDelete?: (host: Host) => void;
  onCheckStatus?: (hostId: string) => void;
}

const HostCard: React.FC<HostCardProps> = ({
  host,
  viewMode,
  selected = false,
  onSelect,
  onEdit,
  onDelete,
  onCheckStatus
}) => {
  const [menuAnchor, setMenuAnchor] = React.useState<null | HTMLElement>(null);

  const handleMenuClick = (event: React.MouseEvent<HTMLElement>) => {
    event.stopPropagation();
    setMenuAnchor(event.currentTarget);
  };

  const handleMenuClose = () => {
    setMenuAnchor(null);
  };

  const getStatusColor = () => {
    switch (host.status) {
      case 'online': return 'success';
      case 'degraded': return 'warning';
      case 'critical': return 'error';
      case 'down': return 'error';
      case 'scanning': return 'primary';
      case 'maintenance': return 'info';
      case 'error': return 'error';
      case 'offline': return 'default';
      default: return 'default';
    }
  };

  const getStatusIcon = () => {
    switch (host.status) {
      case 'online': return <Wifi color="success" />;
      case 'degraded': return <Wifi color="warning" />;
      case 'critical': return <ErrorIcon color="error" />;
      case 'down': return <ErrorIcon color="error" />;
      case 'scanning': return <PlayArrow color="primary" />;
      case 'error': return <ErrorIcon color="error" />;
      default: return <WifiOff color="disabled" />;
    }
  };

  const getComplianceColor = (score?: number) => {
    if (!score) return 'default';
    if (score >= 90) return 'success';
    if (score >= 75) return 'warning';
    return 'error';
  };

  const formatLastScan = (lastScan?: string) => {
    if (!lastScan) return 'Never scanned';
    
    const date = new Date(lastScan);
    const now = new Date();
    const diffDays = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60 * 24));
    
    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;
    return 'Over a week ago';
  };

  const handleScanStarted = (scanId: string, scanName: string) => {
    console.log(`Scan started for ${host.hostname}: ${scanId} - ${scanName}`);
    // The parent component will handle refreshing the data
  };

  const cardContent = (
    <>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flex: 1 }}>
          <Avatar
            sx={{
              bgcolor: host.group_color || 'primary.main',
              width: 40,
              height: 40
            }}
          >
            <Computer />
          </Avatar>
          <Box sx={{ flex: 1 }}>
            <Typography variant="h6" noWrap title={host.displayName}>
              {host.displayName}
            </Typography>
            <Typography variant="body2" color="text.secondary" noWrap>
              {host.ipAddress} • {host.operatingSystem}
            </Typography>
          </Box>
        </Box>
        
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          {getStatusIcon()}
          <IconButton
            size="small"
            onClick={handleMenuClick}
          >
            <MoreVert />
          </IconButton>
        </Box>
      </Box>

      {/* Status and Compliance */}
      <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
        <Chip
          label={host.status.toUpperCase()}
          size="small"
          color={getStatusColor() as any}
          variant="outlined"
        />
        {host.complianceScore !== undefined && (
          <Chip
            icon={<Security />}
            label={`${host.complianceScore}% Compliant`}
            size="small"
            color={getComplianceColor(host.complianceScore) as any}
            variant="outlined"
          />
        )}
        {host.group && (
          <Chip
            label={host.group}
            size="small"
            variant="outlined"
            sx={{ 
              backgroundColor: host.group_color ? `${host.group_color}20` : undefined,
              borderColor: host.group_color || undefined
            }}
          />
        )}
      </Box>

      {/* Scan Progress */}
      {host.scanStatus === 'running' && host.scanProgress !== undefined && (
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.5 }}>
            <Typography variant="body2" color="primary">
              Scanning in progress...
            </Typography>
            <Typography variant="body2" color="primary">
              {host.scanProgress}%
            </Typography>
          </Box>
          <LinearProgress variant="determinate" value={host.scanProgress} />
        </Box>
      )}

      {/* Issues Summary */}
      {(host.criticalIssues > 0 || host.highIssues > 0 || host.mediumIssues > 0) && (
        <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
          {host.criticalIssues > 0 && (
            <Badge badgeContent={host.criticalIssues} color="error">
              <ErrorIcon fontSize="small" color="error" />
            </Badge>
          )}
          {host.highIssues > 0 && (
            <Badge badgeContent={host.highIssues} color="warning">
              <Warning fontSize="small" color="warning" />
            </Badge>
          )}
          {host.mediumIssues > 0 && (
            <Badge badgeContent={host.mediumIssues} color="info">
              <Warning fontSize="small" color="info" />
            </Badge>
          )}
        </Box>
      )}

      {/* Last Scan Info */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <Schedule fontSize="small" color="action" />
        <Typography variant="body2" color="text.secondary">
          Last scan: {formatLastScan(host.lastScan)}
        </Typography>
      </Box>

      {/* Compliance Progress Bar */}
      {host.complianceScore !== undefined && (
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.5 }}>
            <Typography variant="body2" color="text.secondary">
              Compliance Score
            </Typography>
            <Typography variant="body2" fontWeight="medium">
              {host.complianceScore}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={host.complianceScore}
            color={getComplianceColor(host.complianceScore) as any}
            sx={{ height: 6, borderRadius: 3 }}
          />
        </Box>
      )}
    </>
  );

  return (
    <>
      <Card
        sx={{
          height: '100%',
          border: selected ? 2 : 1,
          borderColor: selected ? 'primary.main' : 'divider',
          cursor: onSelect ? 'pointer' : 'default',
          '&:hover': {
            boxShadow: 3,
            transform: 'translateY(-2px)'
          },
          transition: 'all 0.2s'
        }}
        onClick={() => onSelect && onSelect(host.id)}
      >
        <CardContent sx={{ pb: 1 }}>
          {cardContent}
        </CardContent>
        
        <CardActions sx={{ pt: 0, justifyContent: 'space-between' }}>
          {/* Phase 2: Quick Scan Dropdown */}
          <QuickScanDropdown
            hostId={host.id}
            hostName={host.displayName}
            disabled={host.status !== 'online'}
            onScanStarted={handleScanStarted}
            onError={(error) => console.error('Quick scan error:', error)}
          />

          <Box sx={{ display: 'flex', gap: 0.5 }}>
            {onCheckStatus && (
              <Tooltip title="Check connectivity">
                <IconButton
                  size="small"
                  onClick={(e) => {
                    e.stopPropagation();
                    onCheckStatus(host.id);
                  }}
                >
                  <NetworkCheck fontSize="small" />
                </IconButton>
              </Tooltip>
            )}
            
            <Tooltip title="View details">
              <IconButton
                size="small"
                onClick={(e) => {
                  e.stopPropagation();
                  // Navigate to host details
                }}
              >
                <Assessment fontSize="small" />
              </IconButton>
            </Tooltip>
          </Box>
        </CardActions>
      </Card>

      {/* Context Menu */}
      <Menu
        anchorEl={menuAnchor}
        open={Boolean(menuAnchor)}
        onClose={handleMenuClose}
        onClick={(e) => e.stopPropagation()}
      >
        {onEdit && (
          <MenuItem
            onClick={() => {
              onEdit(host);
              handleMenuClose();
            }}
          >
            <ListItemIcon>
              <Edit fontSize="small" />
            </ListItemIcon>
            <ListItemText>Edit Host</ListItemText>
          </MenuItem>
        )}
        
        {onCheckStatus && (
          <MenuItem
            onClick={() => {
              onCheckStatus(host.id);
              handleMenuClose();
            }}
          >
            <ListItemIcon>
              <NetworkCheck fontSize="small" />
            </ListItemIcon>
            <ListItemText>Check Status</ListItemText>
          </MenuItem>
        )}
        
        <Divider />
        
        {onDelete && (
          <MenuItem
            onClick={() => {
              onDelete(host);
              handleMenuClose();
            }}
            sx={{ color: 'error.main' }}
          >
            <ListItemIcon>
              <Delete fontSize="small" color="error" />
            </ListItemIcon>
            <ListItemText>Delete Host</ListItemText>
          </MenuItem>
        )}
      </Menu>
    </>
  );
};

export default HostCard;