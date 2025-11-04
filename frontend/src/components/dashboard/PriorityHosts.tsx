import React from 'react';
import {
  Card,
  CardContent,
  Box,
  Typography,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Button,
  Chip,
  useTheme,
  alpha,
  LinearProgress,
  IconButton,
} from '@mui/material';
import {
  Error as ErrorIcon,
  Warning,
  Schedule,
  Security,
  TrendingDown,
  PlayArrow,
  Build,
  CalendarToday,
  MoreVert,
} from '@mui/icons-material';
import { formatDistanceToNow } from 'date-fns';

export interface PriorityHost {
  id: string;
  hostname: string;
  displayName?: string;
  issue: string;
  issueType: 'critical_issues' | 'not_scanned' | 'degrading' | 'certificate_expiring' | 'offline';
  severity: 'critical' | 'high' | 'medium';
  lastScan?: Date;
  complianceScore?: number;
  previousScore?: number;
  criticalCount?: number;
  daysUntilExpiry?: number;
  action: {
    label: string;
    onClick: () => void;
    icon?: React.ReactNode;
  };
}

interface PriorityHostsProps {
  hosts: PriorityHost[];
  onViewAll?: () => void;
  loading?: boolean;
}

const PriorityHosts: React.FC<PriorityHostsProps> = ({ hosts, onViewAll, loading = false }) => {
  const theme = useTheme();

  // Ensure hosts is an array and filter out invalid entries
  const safeHosts = Array.isArray(hosts)
    ? hosts.filter(
        (host) => host && host.id && host.hostname && host.issue && host.issueType && host.severity
      )
    : [];

  const getIssueIcon = (issueType: PriorityHost['issueType']) => {
    switch (issueType) {
      case 'critical_issues':
        return <ErrorIcon sx={{ color: theme.palette.error.main }} />;
      case 'not_scanned':
        return <Schedule sx={{ color: theme.palette.warning.main }} />;
      case 'degrading':
        return <TrendingDown sx={{ color: theme.palette.warning.dark }} />;
      case 'certificate_expiring':
        return <Security sx={{ color: theme.palette.warning.main }} />;
      case 'offline':
        return <Warning sx={{ color: theme.palette.error.main }} />;
      default:
        return <Warning />;
    }
  };

  const getSeverityColor = (severity: PriorityHost['severity']) => {
    switch (severity) {
      case 'critical':
        return theme.palette.error.main;
      case 'high':
        return theme.palette.warning.dark;
      case 'medium':
        return theme.palette.warning.main;
      default:
        return theme.palette.text.secondary;
    }
  };

  const getActionIcon = (issueType: PriorityHost['issueType']) => {
    switch (issueType) {
      case 'critical_issues':
      case 'not_scanned':
      case 'degrading':
        return <PlayArrow />;
      case 'certificate_expiring':
        return <Build />;
      case 'offline':
        return <Build />;
      default:
        return <PlayArrow />;
    }
  };

  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Typography variant="h6">Hosts Requiring Attention</Typography>
          {onViewAll && (
            <Button size="small" onClick={onViewAll}>
              View All
            </Button>
          )}
        </Box>

        {loading && <LinearProgress sx={{ mb: 2 }} />}

        <List sx={{ py: 0 }}>
          {safeHosts.length === 0 ? (
            <ListItem>
              <ListItemText
                primary={
                  <Typography variant="body2" color="text.secondary" align="center">
                    All hosts are in good standing
                  </Typography>
                }
              />
            </ListItem>
          ) : (
            safeHosts.map((host) => (
              <ListItem
                key={host.id}
                sx={{
                  px: 0,
                  py: 1.5,
                  borderLeft: `3px solid ${getSeverityColor(host.severity)}`,
                  pl: 2,
                  mb: 1,
                  bgcolor: alpha(getSeverityColor(host.severity), 0.04),
                  borderRadius: '0 4px 4px 0',
                  '&:hover': {
                    bgcolor: alpha(getSeverityColor(host.severity), 0.08),
                  },
                }}
              >
                <ListItemIcon sx={{ minWidth: 40 }}>{getIssueIcon(host.issueType)}</ListItemIcon>
                <ListItemText
                  primaryTypographyProps={{
                    component: 'div',
                    sx: { display: 'flex', alignItems: 'center', gap: 1 },
                  }}
                  secondaryTypographyProps={{
                    component: 'div',
                  }}
                  primary={
                    <>
                      <Typography component="span" variant="subtitle2" fontWeight="medium">
                        {host.displayName || host.hostname}
                      </Typography>
                      {host.complianceScore !== undefined &&
                        typeof host.complianceScore === 'number' && (
                          <Chip
                            label={`${Math.round(host.complianceScore)}%`}
                            size="small"
                            color={
                              host.complianceScore >= 90
                                ? 'success'
                                : host.complianceScore >= 70
                                  ? 'warning'
                                  : 'error'
                            }
                            sx={{ height: 20, fontSize: '0.7rem' }}
                          />
                        )}
                      {host.previousScore !== undefined && host.complianceScore !== undefined && (
                        <Typography
                          component="span"
                          variant="caption"
                          sx={{
                            color:
                              host.complianceScore < host.previousScore
                                ? theme.palette.error.main
                                : theme.palette.success.main,
                          }}
                        >
                          {host.complianceScore < host.previousScore ? '↓' : '↑'}
                          {Math.abs(host.complianceScore - host.previousScore)}%
                        </Typography>
                      )}
                    </>
                  }
                  secondary={
                    <>
                      <Typography
                        component="span"
                        variant="body2"
                        color="text.secondary"
                        display="block"
                      >
                        {host.issue}
                      </Typography>
                      <Box
                        component="span"
                        sx={{ display: 'inline-flex', alignItems: 'center', gap: 2, mt: 0.5 }}
                      >
                        {host.lastScan && (
                          <Typography component="span" variant="caption" color="text.secondary">
                            <CalendarToday
                              sx={{ fontSize: 12, mr: 0.5, verticalAlign: 'middle' }}
                            />
                            Last scan: {formatDistanceToNow(host.lastScan, { addSuffix: true })}
                          </Typography>
                        )}
                        {host.criticalCount !== undefined && host.criticalCount > 0 && (
                          <Chip
                            label={`${host.criticalCount} critical`}
                            size="small"
                            color="error"
                            sx={{ height: 18, fontSize: '0.7rem' }}
                          />
                        )}
                        {host.daysUntilExpiry !== undefined && (
                          <Chip
                            label={`Expires in ${host.daysUntilExpiry}d`}
                            size="small"
                            color="warning"
                            sx={{ height: 18, fontSize: '0.7rem' }}
                          />
                        )}
                      </Box>
                    </>
                  }
                />
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Button
                    size="small"
                    variant="contained"
                    startIcon={host.action.icon || getActionIcon(host.issueType)}
                    onClick={host.action.onClick}
                    sx={{
                      textTransform: 'none',
                      fontSize: '0.875rem',
                      py: 0.5,
                      px: 1.5,
                    }}
                  >
                    {host.action.label}
                  </Button>
                  <IconButton size="small">
                    <MoreVert fontSize="small" />
                  </IconButton>
                </Box>
              </ListItem>
            ))
          )}
        </List>
      </CardContent>
    </Card>
  );
};

export default PriorityHosts;
