import React from 'react';
import {
  Card,
  CardContent,
  Box,
  Typography,
  List,
  ListItem,
  ListItemText,
  IconButton,
  Chip,
  useTheme,
  alpha,
} from '@mui/material';
import { ArrowForward, Refresh } from '@mui/icons-material';
import { formatDistanceToNow } from 'date-fns';

export interface ActivityItem {
  id: string;
  type:
    | 'scan_completed'
    | 'scan_failed'
    | 'host_added'
    | 'host_offline'
    | 'host_online'
    | 'drift_detected'
    | 'baseline_created'
    | 'exception_approved'
    | 'exception_rejected'
    | 'login_failed'
    | 'security_event'
    | 'settings_changed';
  message: string;
  timestamp: Date;
  severity?: 'success' | 'error' | 'warning' | 'info';
  metadata?: {
    hostId?: string;
    hostname?: string;
    scanId?: string;
    ruleCount?: number;
    complianceScore?: number;
    previousScore?: number;
    username?: string;
  };
  action?: {
    label: string;
    onClick: () => void;
  };
}

interface ActivityFeedProps {
  activities: ActivityItem[];
  onRefresh?: () => void;
  loading?: boolean;
  maxItems?: number;
}

const ActivityFeed: React.FC<ActivityFeedProps> = ({
  activities,
  onRefresh,
  loading = false,
  maxItems = 10,
}) => {
  const theme = useTheme();

  // Ensure activities is an array and filter out invalid entries
  const safeActivities = Array.isArray(activities)
    ? activities.filter(
        (activity) =>
          activity && activity.id && activity.type && activity.message && activity.timestamp
      )
    : [];

  // Get severity color for the status dot
  const getSeverityColor = (severity?: ActivityItem['severity']) => {
    switch (severity) {
      case 'success':
        return theme.palette.success.main;
      case 'error':
        return theme.palette.error.main;
      case 'warning':
        return theme.palette.warning.main;
      case 'info':
        return theme.palette.info.main;
      default:
        return theme.palette.text.secondary;
    }
  };

  // Get plural label for grouped activities
  const getGroupedLabel = (type: ActivityItem['type'], count: number): string => {
    const labels: Record<string, string> = {
      scan_completed: 'scans completed',
      scan_failed: 'scans failed',
      host_added: 'hosts added',
      host_offline: 'hosts went offline',
      host_online: 'hosts came online',
      drift_detected: 'drift events',
      baseline_created: 'baselines created',
      exception_approved: 'exceptions approved',
      exception_rejected: 'exceptions rejected',
      login_failed: 'failed logins',
      security_event: 'security events',
      settings_changed: 'settings changes',
    };
    return `${count} ${labels[type] || type.replace(/_/g, ' ')}`;
  };

  const displayActivities = safeActivities.slice(0, maxItems);

  // Group consecutive similar activities
  const groupedActivities = displayActivities.reduce(
    (acc, activity, index) => {
      const lastGroup = acc[acc.length - 1];

      if (
        lastGroup &&
        lastGroup.type === activity.type &&
        index > 0 &&
        index - lastGroup.indices[lastGroup.indices.length - 1] === 1
      ) {
        lastGroup.items.push(activity);
        lastGroup.indices.push(index);
      } else {
        acc.push({
          type: activity.type,
          items: [activity],
          indices: [index],
        });
      }

      return acc;
    },
    [] as Array<{ type: string; items: ActivityItem[]; indices: number[] }>
  );

  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Typography variant="h6">Recent Activity</Typography>
          {onRefresh && (
            <IconButton
              size="small"
              onClick={onRefresh}
              disabled={loading}
              sx={{
                animation: loading ? 'spin 1s linear infinite' : 'none',
                '@keyframes spin': {
                  '0%': { transform: 'rotate(0deg)' },
                  '100%': { transform: 'rotate(360deg)' },
                },
              }}
            >
              <Refresh />
            </IconButton>
          )}
        </Box>

        <List sx={{ py: 0 }}>
          {groupedActivities.length === 0 ? (
            <ListItem>
              <ListItemText
                primary={
                  <Typography variant="body2" color="text.secondary" align="center">
                    No recent activity
                  </Typography>
                }
              />
            </ListItem>
          ) : (
            groupedActivities.map((group, groupIndex) => {
              const firstItem = group.items[0];
              const isGrouped = group.items.length > 1;

              return (
                <ListItem
                  key={`group-${groupIndex}`}
                  sx={{
                    px: 0,
                    py: 0.75,
                    '&:hover': {
                      bgcolor: alpha(theme.palette.action.hover, 0.04),
                    },
                  }}
                  secondaryAction={
                    firstItem.action && (
                      <IconButton
                        size="small"
                        onClick={firstItem.action.onClick}
                        sx={{ color: theme.palette.primary.main }}
                      >
                        <ArrowForward fontSize="small" />
                      </IconButton>
                    )
                  }
                >
                  {/* Status dot */}
                  <Box
                    sx={{
                      width: 8,
                      height: 8,
                      borderRadius: '50%',
                      bgcolor: getSeverityColor(firstItem.severity),
                      mr: 1.5,
                      flexShrink: 0,
                    }}
                  />
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="body2" sx={{ wordBreak: 'break-word' }}>
                          {isGrouped
                            ? getGroupedLabel(firstItem.type, group.items.length)
                            : firstItem.message}
                        </Typography>
                        {firstItem.metadata?.complianceScore !== undefined &&
                          typeof firstItem.metadata.complianceScore === 'number' && (
                            <Chip
                              label={`${Math.round(firstItem.metadata.complianceScore)}%`}
                              size="small"
                              color={
                                firstItem.metadata.complianceScore >= 90
                                  ? 'success'
                                  : firstItem.metadata.complianceScore >= 70
                                    ? 'warning'
                                    : 'error'
                              }
                              sx={{ height: 20, fontSize: '0.75rem' }}
                            />
                          )}
                      </Box>
                    }
                    secondary={
                      <Typography variant="caption" color="text.secondary">
                        {formatDistanceToNow(firstItem.timestamp, { addSuffix: true })}
                        {firstItem.metadata?.hostname && ` • ${firstItem.metadata.hostname}`}
                        {firstItem.metadata?.username && ` • ${firstItem.metadata.username}`}
                      </Typography>
                    }
                  />
                </ListItem>
              );
            })
          )}
        </List>
      </CardContent>
    </Card>
  );
};

export default ActivityFeed;
