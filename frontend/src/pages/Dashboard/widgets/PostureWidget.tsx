/**
 * Compliance Posture Widget
 *
 * Displays fleet-wide compliance posture summary.
 * Clean, minimal design without decorative icons.
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
  Skeleton,
  Alert,
  Tooltip,
  LinearProgress,
  useTheme,
  alpha,
} from '@mui/material';
import { OpenInFull as OpenInFullIcon } from '@mui/icons-material';
import { useQuery } from '@tanstack/react-query';
import { owcaService, type FleetStatistics } from '../../../services/owcaService';

function getScoreColor(score: number): 'success' | 'warning' | 'error' {
  if (score >= 90) return 'success';
  if (score >= 70) return 'warning';
  return 'error';
}

function useFleetStatistics() {
  return useQuery<FleetStatistics>({
    queryKey: ['fleetStatistics'],
    queryFn: () => owcaService.getFleetStatistics(),
    staleTime: 60000,
    refetchInterval: 60000,
  });
}

const PostureWidget: React.FC = () => {
  const navigate = useNavigate();
  const theme = useTheme();
  const { data: fleetStats, isLoading, error } = useFleetStatistics();

  const handleExpand = () => {
    navigate('/compliance/posture');
  };

  // Loading state
  if (isLoading) {
    return (
      <Card sx={{ height: '100%' }}>
        <CardContent sx={{ py: 2 }}>
          <Skeleton variant="text" width="60%" />
          <Skeleton variant="text" width="40%" height={32} sx={{ my: 1 }} />
          <Skeleton variant="rectangular" height={4} />
        </CardContent>
      </Card>
    );
  }

  // Error state
  if (error) {
    return (
      <Card sx={{ height: '100%' }}>
        <CardContent sx={{ py: 2 }}>
          <Box
            sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}
          >
            <Typography variant="subtitle1" fontWeight="medium">
              Compliance Posture
            </Typography>
            <IconButton size="small" onClick={handleExpand}>
              <OpenInFullIcon fontSize="small" />
            </IconButton>
          </Box>
          <Alert severity="warning" variant="outlined" sx={{ py: 0.5 }}>
            Unable to load
          </Alert>
        </CardContent>
      </Card>
    );
  }

  // No data
  if (!fleetStats || fleetStats.total_hosts === 0) {
    return (
      <Card sx={{ height: '100%' }}>
        <CardContent sx={{ py: 2 }}>
          <Box
            sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}
          >
            <Typography variant="subtitle1" fontWeight="medium">
              Compliance Posture
            </Typography>
            <IconButton size="small" onClick={handleExpand}>
              <OpenInFullIcon fontSize="small" />
            </IconButton>
          </Box>
          <Typography variant="body2" color="text.secondary">
            No hosts scanned yet
          </Typography>
        </CardContent>
      </Card>
    );
  }

  const score = fleetStats.average_compliance;
  const scoreColor = getScoreColor(score);

  return (
    <Card sx={{ height: '100%' }}>
      <CardContent sx={{ py: 2 }}>
        {/* Header */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
          <Typography variant="subtitle1" fontWeight="medium">
            Compliance Posture
          </Typography>
          <Tooltip title="View Details">
            <IconButton size="small" onClick={handleExpand}>
              <OpenInFullIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>

        {/* Score */}
        <Box sx={{ mb: 1.5 }}>
          <Typography
            variant="h4"
            color={`${scoreColor}.main`}
            sx={{ fontWeight: 'bold', lineHeight: 1.2 }}
          >
            {score.toFixed(1)}%
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {fleetStats.scanned_hosts} of {fleetStats.total_hosts} hosts
          </Typography>
        </Box>

        {/* Progress bar */}
        <LinearProgress
          variant="determinate"
          value={score}
          color={scoreColor}
          sx={{
            height: 4,
            borderRadius: 1,
            bgcolor: alpha(theme.palette[scoreColor].main, 0.15),
            mb: 1.5,
          }}
        />

        {/* Host distribution - simple dots */}
        <Box sx={{ display: 'flex', gap: 2, mb: 1 }}>
          <Tooltip title="Excellent (90%+)">
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: 'success.main' }} />
              <Typography variant="body2">{fleetStats.hosts_excellent}</Typography>
            </Box>
          </Tooltip>
          <Tooltip title="Good (75-89%)">
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: 'info.main' }} />
              <Typography variant="body2">{fleetStats.hosts_good}</Typography>
            </Box>
          </Tooltip>
          <Tooltip title="Fair (60-74%)">
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: 'warning.main' }} />
              <Typography variant="body2">{fleetStats.hosts_fair}</Typography>
            </Box>
          </Tooltip>
          <Tooltip title="Poor (<60%)">
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: 'error.main' }} />
              <Typography variant="body2">{fleetStats.hosts_poor}</Typography>
            </Box>
          </Tooltip>
        </Box>

        {/* Issues summary - single line */}
        <Typography variant="caption" color="text.secondary">
          {fleetStats.total_critical_issues > 0 && (
            <Typography component="span" variant="caption" color="error.main" sx={{ mr: 1 }}>
              {fleetStats.total_critical_issues} critical
            </Typography>
          )}
          {fleetStats.total_high_issues > 0 && (
            <Typography component="span" variant="caption" color="warning.main" sx={{ mr: 1 }}>
              {fleetStats.total_high_issues} high
            </Typography>
          )}
          {fleetStats.total_medium_issues + fleetStats.total_low_issues > 0 && (
            <Typography component="span" variant="caption">
              {fleetStats.total_medium_issues + fleetStats.total_low_issues} other
            </Typography>
          )}
        </Typography>
      </CardContent>
    </Card>
  );
};

export default PostureWidget;
