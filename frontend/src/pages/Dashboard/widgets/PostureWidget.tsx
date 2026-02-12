/**
 * Compliance Posture Widget
 *
 * Displays fleet-wide compliance posture summary:
 * - Average compliance score across all hosts
 * - Total pass/fail counts
 * - Severity breakdown (critical/high/medium/low)
 * - Host tier distribution
 * - Expand button to /compliance/posture for per-host details
 *
 * Part of Command Center Dashboard.
 *
 * @module pages/Dashboard/widgets/PostureWidget
 */

import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Card,
  CardContent,
  Typography,
  Box,
  IconButton,
  Chip,
  Skeleton,
  Alert,
  Tooltip,
  LinearProgress,
  useTheme,
  alpha,
} from '@mui/material';
import {
  OpenInFull as OpenInFullIcon,
  Assessment as AssessmentIcon,
  TrendingDown as TrendingDownIcon,
  Computer as ComputerIcon,
} from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';
import { owcaService, type FleetStatistics } from '../../../services/owcaService';

/**
 * Get color based on compliance score
 */
function getScoreColor(score: number): 'success' | 'warning' | 'error' {
  if (score >= 90) return 'success';
  if (score >= 70) return 'warning';
  return 'error';
}

/**
 * Get severity chip color
 */
function getSeverityColor(severity: string): 'error' | 'warning' | 'info' | 'default' {
  switch (severity) {
    case 'critical':
      return 'error';
    case 'high':
      return 'warning';
    case 'medium':
      return 'info';
    default:
      return 'default';
  }
}

/**
 * Hook to fetch fleet statistics from OWCA
 */
function useFleetStatistics() {
  return useQuery<FleetStatistics>({
    queryKey: ['fleetStatistics'],
    queryFn: () => owcaService.getFleetStatistics(),
    staleTime: 60000, // 1 minute
    refetchInterval: 60000, // 1 minute auto-refresh
  });
}

const PostureWidget: React.FC = () => {
  const navigate = useNavigate();
  const theme = useTheme();

  // Fetch fleet-wide statistics from OWCA
  const { data: fleetStats, isLoading, error } = useFleetStatistics();

  const handleExpand = () => {
    navigate('/compliance/posture');
  };

  // Loading state
  if (isLoading) {
    return (
      <Card sx={{ height: '100%' }}>
        <CardContent>
          <Box
            sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}
          >
            <Skeleton variant="text" width="50%" />
            <Skeleton variant="circular" width={32} height={32} />
          </Box>
          <Skeleton variant="text" width="30%" height={40} />
          <Skeleton variant="text" sx={{ my: 1 }} />
          <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
            <Skeleton variant="rounded" width={60} height={24} />
            <Skeleton variant="rounded" width={60} height={24} />
          </Box>
        </CardContent>
      </Card>
    );
  }

  // Error state
  if (error) {
    return (
      <Card sx={{ height: '100%' }}>
        <CardContent>
          <Box
            sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <AssessmentIcon color="primary" />
              <Typography variant="h6">Compliance Posture</Typography>
            </Box>
            <IconButton size="small" onClick={handleExpand}>
              <OpenInFullIcon fontSize="small" />
            </IconButton>
          </Box>
          <Alert severity="warning" variant="outlined">
            Unable to load compliance posture
          </Alert>
        </CardContent>
      </Card>
    );
  }

  // No data available
  if (!fleetStats || fleetStats.total_hosts === 0) {
    return (
      <Card sx={{ height: '100%' }}>
        <CardContent>
          <Box
            sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <AssessmentIcon color="primary" />
              <Typography variant="h6">Compliance Posture</Typography>
            </Box>
            <IconButton size="small" onClick={handleExpand}>
              <OpenInFullIcon fontSize="small" />
            </IconButton>
          </Box>
          <Alert severity="info" variant="outlined">
            No hosts available. Add hosts and run scans to view compliance posture.
          </Alert>
        </CardContent>
      </Card>
    );
  }

  const score = fleetStats.average_compliance;
  const scoreColor = getScoreColor(score);

  // Build severity counts
  const severityCounts = [
    { severity: 'critical', count: fleetStats.total_critical_issues },
    { severity: 'high', count: fleetStats.total_high_issues },
    { severity: 'medium', count: fleetStats.total_medium_issues },
    { severity: 'low', count: fleetStats.total_low_issues },
  ].filter((s) => s.count > 0);

  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        {/* Header */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <AssessmentIcon color="primary" />
            <Typography variant="h6">Compliance Posture</Typography>
          </Box>
          <Tooltip title="View All Hosts">
            <IconButton size="small" onClick={handleExpand}>
              <OpenInFullIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>

        {/* Fleet Average Score */}
        <Box sx={{ mb: 2 }}>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Fleet Average ({fleetStats.scanned_hosts} of {fleetStats.total_hosts} hosts scanned)
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1 }}>
            <Typography
              variant="h3"
              color={`${scoreColor}.main`}
              sx={{ fontWeight: 'bold', lineHeight: 1 }}
            >
              {score.toFixed(1)}%
            </Typography>
            {score < 70 && (
              <Tooltip title="Below recommended threshold">
                <TrendingDownIcon color="error" />
              </Tooltip>
            )}
          </Box>
          {/* Progress bar */}
          <LinearProgress
            variant="determinate"
            value={score}
            color={scoreColor}
            sx={{
              mt: 1,
              height: 6,
              borderRadius: 1,
              bgcolor: alpha(theme.palette[scoreColor].main, 0.2),
            }}
          />
        </Box>

        {/* Host Tier Distribution */}
        <Box sx={{ display: 'flex', gap: 1.5, mb: 2, flexWrap: 'wrap' }}>
          <Tooltip title="Excellent (90-100%)">
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <ComputerIcon fontSize="small" color="success" />
              <Typography variant="body2" fontWeight="medium">
                {fleetStats.hosts_excellent}
              </Typography>
            </Box>
          </Tooltip>
          <Tooltip title="Good (75-89%)">
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <ComputerIcon fontSize="small" color="info" />
              <Typography variant="body2" fontWeight="medium">
                {fleetStats.hosts_good}
              </Typography>
            </Box>
          </Tooltip>
          <Tooltip title="Fair (60-74%)">
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <ComputerIcon fontSize="small" color="warning" />
              <Typography variant="body2" fontWeight="medium">
                {fleetStats.hosts_fair}
              </Typography>
            </Box>
          </Tooltip>
          <Tooltip title="Poor (<60%)">
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <ComputerIcon fontSize="small" color="error" />
              <Typography variant="body2" fontWeight="medium">
                {fleetStats.hosts_poor}
              </Typography>
            </Box>
          </Tooltip>
        </Box>

        {/* Severity Breakdown */}
        {severityCounts.length > 0 && (
          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
            {severityCounts.map(({ severity, count }) => (
              <Chip
                key={severity}
                label={`${severity}: ${count}`}
                size="small"
                color={getSeverityColor(severity)}
                variant="outlined"
                sx={{
                  height: 22,
                  '& .MuiChip-label': {
                    px: 1,
                    py: 0,
                    fontSize: '0.7rem',
                    textTransform: 'capitalize',
                  },
                }}
              />
            ))}
          </Box>
        )}

        {/* Hosts needing attention */}
        {fleetStats.hosts_with_critical > 0 && (
          <Typography variant="caption" color="error.main" sx={{ mt: 1, display: 'block' }}>
            {fleetStats.hosts_with_critical} host{fleetStats.hosts_with_critical > 1 ? 's' : ''}{' '}
            with critical issues
          </Typography>
        )}
      </CardContent>
    </Card>
  );
};

export default PostureWidget;
