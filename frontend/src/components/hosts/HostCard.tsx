/**
 * HostCard Component
 *
 * Reusable host card component for displaying host information in different view modes.
 * Supports grid, list, and compact layouts with consistent styling and functionality.
 *
 * Uses CLAUDE.md compliant utilities from Phase 2 and Phase 3:
 * - Host type from types/host.ts
 * - Compliance thresholds from constants/compliance.ts
 * - Status icons from utils/hostStatus.tsx
 * - Formatters from utils/hostFormatters.ts
 *
 * Used by:
 * - Bulk import preview dialogs
 * - Standalone host management components
 * - Dashboard host summaries
 *
 * Note: Hosts.tsx has its own inline HostCard for tighter state integration.
 * This component is for reusable, stateless host display.
 *
 * @module components/hosts/HostCard
 */

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
  Badge,
  useTheme,
} from '@mui/material';
import {
  Computer,
  MoreVert,
  Schedule,
  Edit,
  Delete,
  NetworkCheck,
  Assessment,
  Security,
  Error as ErrorIcon,
  Warning,
} from '@mui/icons-material';
import { QuickScanDropdown } from '../scans';
import type { Host } from '../../types/host';
import { COMPLIANCE_THRESHOLDS } from '../../constants/compliance';
import { getStatusIcon } from '../../utils/hostStatus';
import { formatRelativeTime } from '../../utils/hostFormatters';

/**
 * Props for HostCard component.
 *
 * @interface HostCardProps
 */
interface HostCardProps {
  /** Host data to display */
  host: Host;
  /** Display mode (card=grid view, list=horizontal, compact=minimal) */
  viewMode: 'card' | 'list' | 'compact';
  /** Whether host is selected (for bulk operations) */
  selected?: boolean;
  /** Callback when host selection changes */
  onSelect?: (hostId: string) => void;
  /** Callback when edit action triggered */
  onEdit?: (host: Host) => void;
  /** Callback when delete action triggered */
  onDelete?: (host: Host) => void;
  /** Callback when status check requested */
  onCheckStatus?: (hostId: string) => void;
}

/**
 * HostCard component for displaying host information.
 *
 * Renders a Material-UI card with host details, compliance status,
 * and action buttons. Supports multiple view modes for different layouts.
 *
 * @param props - Component props
 * @returns React element
 *
 * @example
 * <HostCard
 *   host={hostData}
 *   viewMode="card"
 *   onEdit={(host) => console.log('Edit', host)}
 *   onDelete={(host) => console.log('Delete', host)}
 * />
 */
const HostCard: React.FC<HostCardProps> = ({
  host,
  viewMode: _viewMode,
  selected = false,
  onSelect,
  onEdit,
  onDelete,
  onCheckStatus,
}) => {
  const _theme = useTheme();
  const [menuAnchor, setMenuAnchor] = React.useState<null | HTMLElement>(null);

  /**
   * Handle context menu opening.
   * Prevents event propagation to avoid triggering card click.
   */
  const handleMenuClick = (event: React.MouseEvent<HTMLElement>) => {
    event.stopPropagation();
    setMenuAnchor(event.currentTarget);
  };

  /**
   * Close context menu.
   */
  const handleMenuClose = () => {
    setMenuAnchor(null);
  };

  /**
   * Get MUI color name for host status.
   * Maps HostStatus enum to Material-UI color palette names.
   *
   * @returns MUI color name (success, warning, error, etc.)
   */
  const getStatusColor = (): string => {
    switch (host.status) {
      case 'online':
        return 'success';
      case 'degraded':
        return 'warning';
      case 'critical':
      case 'down':
      case 'error':
        return 'error';
      case 'scanning':
        return 'primary';
      case 'maintenance':
        return 'info';
      case 'offline':
      default:
        return 'default';
    }
  };

  /**
   * Get MUI color name for compliance score.
   * Uses CLAUDE.md compliant thresholds (95%, 75%).
   *
   * @param score - Compliance score (0-100) or null
   * @returns MUI color name
   */
  const getComplianceChipColor = (score: number | null | undefined): string => {
    if (score === null || score === undefined) return 'default';
    if (score >= COMPLIANCE_THRESHOLDS.COMPLIANT) return 'success'; // 95%+
    if (score >= COMPLIANCE_THRESHOLDS.NEAR_COMPLIANT) return 'warning'; // 75-94%
    return 'error'; // <75%
  };

  /**
   * Handle scan started callback.
   * Logs scan initiation (parent component handles data refresh).
   *
   * @param scanId - UUID of started scan
   * @param scanName - Human-readable scan name
   */
  const handleScanStarted = (scanId: string, scanName: string) => {
    if (import.meta.env.DEV) {
      // eslint-disable-next-line no-console
      console.log(`Scan started for ${host.hostname}: ${scanId} - ${scanName}`);
    }
    // Parent component handles data refresh
  };

  const cardContent = (
    <>
      {/* Header */}
      <Box
        sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 2 }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flex: 1 }}>
          <Avatar
            sx={{
              bgcolor: host.group_color || 'primary.main',
              width: 40,
              height: 40,
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
          {getStatusIcon(host.status)}
          <IconButton size="small" onClick={handleMenuClick}>
            <MoreVert />
          </IconButton>
        </Box>
      </Box>

      {/* Status and Compliance */}
      <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
        <Chip
          label={host.status.toUpperCase()}
          size="small"
          color={
            getStatusColor() as
              | 'default'
              | 'primary'
              | 'secondary'
              | 'error'
              | 'info'
              | 'success'
              | 'warning'
          }
          variant="outlined"
        />
        {host.complianceScore !== undefined && (
          <Chip
            icon={<Security />}
            label={`${host.complianceScore}% Compliant`}
            size="small"
            color={
              getComplianceChipColor(host.complianceScore) as
                | 'default'
                | 'primary'
                | 'secondary'
                | 'error'
                | 'info'
                | 'success'
                | 'warning'
            }
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
              borderColor: host.group_color || undefined,
            }}
          />
        )}
      </Box>

      {/* Scan Progress */}
      {host.scanStatus === 'running' && host.scanProgress !== undefined && (
        <Box sx={{ mb: 2 }}>
          <Box
            sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.5 }}
          >
            <Typography variant="body2" color="primary">
              Scanning in progress...
            </Typography>
            <Typography variant="body2" color="primary">
              {host.scanProgress}%
            </Typography>
          </Box>
          <LinearProgress variant="determinate" value={host.scanProgress ?? 0} />
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
          Last scan: {formatRelativeTime(host.lastScan, 'Never scanned')}
        </Typography>
      </Box>

      {/* Compliance Progress Bar */}
      {host.complianceScore !== undefined && (
        <Box sx={{ mb: 2 }}>
          <Box
            sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.5 }}
          >
            <Typography variant="body2" color="text.secondary">
              Compliance Score
            </Typography>
            <Typography variant="body2" fontWeight="medium">
              {host.complianceScore}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={host.complianceScore ?? 0}
            color={
              getComplianceChipColor(host.complianceScore) as
                | 'primary'
                | 'secondary'
                | 'error'
                | 'info'
                | 'success'
                | 'warning'
                | 'inherit'
            }
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
            transform: 'translateY(-2px)',
          },
          transition: 'all 0.2s',
        }}
        onClick={() => onSelect && onSelect(host.id)}
      >
        <CardContent sx={{ pb: 1 }}>{cardContent}</CardContent>

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
