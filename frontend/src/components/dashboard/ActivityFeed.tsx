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
  IconButton,
  Chip,
  useTheme,
  alpha,
} from '@mui/material';
import {
  CheckCircle,
  Error,
  Warning,
  Info,
  Computer,
  Security,
  Settings,
  ArrowForward,
  Refresh,
} from '@mui/icons-material';
import { formatDistanceToNow } from 'date-fns';

export interface ActivityItem {
  id: string;
  type:
    | 'scan_completed'
    | 'scan_failed'
    | 'host_added'
    | 'host_offline'
    | 'rule_failed'
    | 'settings_changed';
  message: string;
  timestamp: Date;
  severity?: 'success' | 'error' | 'warning' | 'info';
  metadata?: {
    hostId?: string;
    scanId?: string;
    ruleCount?: number;
    complianceScore?: number;
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

  const getIcon = (type: ActivityItem['type']) => {
    switch (type) {
      case 'scan_completed':
        return <CheckCircle sx={{ color: theme.palette.success.main }} />;
      case 'scan_failed':
        return <Error sx={{ color: theme.palette.error.main }} />;
      case 'host_added':
        return <Computer sx={{ color: theme.palette.info.main }} />;
      case 'host_offline':
        return <Warning sx={{ color: theme.palette.warning.main }} />;
      case 'rule_failed':
        return <Security sx={{ color: theme.palette.error.main }} />;
      case 'settings_changed':
        return <Settings sx={{ color: theme.palette.grey[600] }} />;
      default:
        return <Info />;
    }
  };

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
                    py: 1,
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
                  <ListItemIcon sx={{ minWidth: 40 }}>
                    {getIcon(firstItem.type, firstItem.severity)}
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="body2" sx={{ wordBreak: 'break-word' }}>
                          {isGrouped
                            ? `${group.items.length} ${firstItem.type.replace('_', ' ')}s`
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
                        {firstItem.metadata?.ruleCount &&
                          ` • ${firstItem.metadata.ruleCount} rules`}
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
