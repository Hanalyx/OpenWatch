import React from 'react';
import {
  Box,
  Chip,
  Typography,
  useTheme,
  alpha,
  LinearProgress
} from '@mui/material';
import {
  Error as ErrorIcon,
  Warning,
  CheckCircle,
  TrendingUp,
  TrendingDown
} from '@mui/icons-material';

interface AlertStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
  passed: number;
  overallCompliance: number;
  trend?: 'up' | 'down' | 'stable';
  trendValue?: number;
}

interface SmartAlertBarProps {
  stats: AlertStats;
  onFilterClick?: (severity: 'critical' | 'high' | 'medium' | 'low') => void;
  loading?: boolean;
}

const SmartAlertBar: React.FC<SmartAlertBarProps> = ({
  stats,
  onFilterClick,
  loading = false
}) => {
  const theme = useTheme();

  const getComplianceColor = (score: number) => {
    if (score >= 90) return theme.palette.success.main;
    if (score >= 70) return theme.palette.warning.main;
    return theme.palette.error.main;
  };

  const getTrendIcon = () => {
    if (!stats.trend) return null;
    
    const icons = {
      up: <TrendingUp sx={{ fontSize: 16 }} />,
      down: <TrendingDown sx={{ fontSize: 16 }} />,
      stable: null
    };
    
    return icons[stats.trend];
  };

  const alerts = [
    { severity: 'critical' as const, count: stats.critical, icon: <ErrorIcon fontSize="small" />, color: theme.palette.error.main },
    { severity: 'high' as const, count: stats.high, icon: <Warning fontSize="small" />, color: theme.palette.warning.dark },
    { severity: 'medium' as const, count: stats.medium, icon: <Warning fontSize="small" />, color: theme.palette.warning.main },
    { severity: 'low' as const, count: stats.low, icon: <Warning fontSize="small" />, color: theme.palette.info.main }
  ];

  const totalIssues = stats.critical + stats.high + stats.medium + stats.low;

  return (
    <Box
      sx={{
        bgcolor: 'background.paper',
        borderRadius: 2,
        p: 2,
        mb: 3,
        boxShadow: theme.shadows[1],
        position: 'relative'
      }}
    >
      {loading && (
        <LinearProgress 
          sx={{ 
            position: 'absolute', 
            top: 0, 
            left: 0, 
            right: 0,
            height: 2
          }} 
        />
      )}
      
      <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2, width: '100%' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap', minWidth: 0, flex: 1 }}>
          {alerts.map((alert) => (
            <Chip
              key={alert.severity}
              icon={alert.icon}
              label={`${alert.count} ${alert.severity}`}
              onClick={() => onFilterClick?.(alert.severity)}
              sx={{
                bgcolor: alpha(alert.color, 0.1),
                color: alert.color,
                border: `1px solid ${alpha(alert.color, 0.2)}`,
                '& .MuiChip-icon': {
                  color: alert.color
                },
                '&:hover': {
                  bgcolor: alpha(alert.color, 0.2),
                  cursor: onFilterClick ? 'pointer' : 'default'
                },
                fontWeight: alert.count > 0 ? 'bold' : 'normal'
              }}
            />
          ))}
          
          {stats.passed > 0 && (
            <Chip
              icon={<CheckCircle fontSize="small" />}
              label={`${stats.passed} passed`}
              sx={{
                bgcolor: alpha(theme.palette.success.main, 0.1),
                color: theme.palette.success.main,
                border: `1px solid ${alpha(theme.palette.success.main, 0.2)}`,
                '& .MuiChip-icon': {
                  color: theme.palette.success.main
                }
              }}
            />
          )}
        </Box>

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, flexShrink: 0 }}>
          {totalIssues > 0 && (
            <Typography variant="body2" color="text.secondary">
              {totalIssues} total issues
            </Typography>
          )}
          
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography
              variant="h6"
              sx={{
                color: getComplianceColor(stats.overallCompliance),
                fontWeight: 'bold'
              }}
            >
              {stats.overallCompliance}% Compliant
            </Typography>
            
            {stats.trend && stats.trendValue !== undefined && (
              <Box
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 0.5,
                  color: stats.trend === 'up' ? theme.palette.success.main : 
                         stats.trend === 'down' ? theme.palette.error.main : 
                         theme.palette.text.secondary
                }}
              >
                {getTrendIcon()}
                <Typography variant="caption" fontWeight="medium">
                  {stats.trend === 'up' ? '+' : stats.trend === 'down' ? '-' : ''}{stats.trendValue}%
                </Typography>
              </Box>
            )}
          </Box>
        </Box>
      </Box>
    </Box>
  );
};

export default SmartAlertBar;