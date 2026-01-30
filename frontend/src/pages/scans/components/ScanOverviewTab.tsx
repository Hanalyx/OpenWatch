/**
 * Overview tab content for ScanDetail.
 * Shows charts and summary statistics for completed scans,
 * progress display for running scans, and error for failed.
 */

import React from 'react';
import { Box, Paper, Typography, LinearProgress, Alert, CircularProgress } from '@mui/material';
import Grid from '@mui/material/GridLegacy';
import { Refresh as RefreshIcon } from '@mui/icons-material';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as ChartTooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import type { ScanDetails } from './scanTypes';

interface ScanOverviewTabProps {
  scan: ScanDetails;
}

const ScanOverviewTab: React.FC<ScanOverviewTabProps> = ({ scan }) => {
  if (scan.status === 'completed' && scan.results) {
    const pieData = [
      { name: 'Passed', value: scan.results.passed_rules, color: '#4caf50' },
      { name: 'Failed', value: scan.results.failed_rules, color: '#f44336' },
      { name: 'Error', value: scan.results.error_rules, color: '#ff9800' },
      { name: 'N/A', value: scan.results.not_applicable_rules, color: '#9e9e9e' },
    ].filter((item) => item.value > 0);

    const severityData = [
      { name: 'High', value: scan.results.severity_high, color: '#f44336' },
      { name: 'Medium', value: scan.results.severity_medium, color: '#ff9800' },
      { name: 'Low', value: scan.results.severity_low, color: '#ffeb3b' },
    ];

    return (
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Typography variant="h6" gutterBottom>
            Compliance Summary
          </Typography>
          <Box height={300}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <ChartTooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </Box>
        </Grid>

        <Grid item xs={12} md={6}>
          <Typography variant="h6" gutterBottom>
            Severity Distribution
          </Typography>
          <Box height={300}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <ChartTooltip />
                <Bar dataKey="value" fill="#8884d8">
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </Box>
        </Grid>

        <Grid item xs={12}>
          <Typography variant="h6" gutterBottom>
            Summary Statistics
          </Typography>
          <Grid container spacing={2}>
            {[
              { value: scan.results.total_rules, label: 'Total Rules', color: 'primary' },
              { value: scan.results.passed_rules, label: 'Passed', color: 'success.main' },
              { value: scan.results.failed_rules, label: 'Failed', color: 'error.main' },
              { value: scan.results.error_rules, label: 'Errors', color: 'warning.main' },
              { value: scan.results.not_applicable_rules, label: 'N/A', color: 'text.secondary' },
              { value: scan.results.unknown_rules, label: 'Unknown', color: 'info.main' },
            ].map((stat) => (
              <Grid item xs={6} sm={4} md={2} key={stat.label}>
                <Paper variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                  <Typography variant="h4" color={stat.color}>
                    {stat.value}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {stat.label}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Grid>
      </Grid>
    );
  }

  if (scan.status === 'running' || scan.status === 'pending') {
    return (
      <Box textAlign="center" py={4}>
        <CircularProgress size={60} />
        <Typography variant="h6" sx={{ mt: 2 }}>
          {scan.status === 'pending' ? 'Scan Initializing...' : 'Scan in Progress...'}
        </Typography>
        <LinearProgress
          variant="determinate"
          value={scan.progress || 0}
          sx={{ mt: 2, maxWidth: 400, mx: 'auto' }}
        />
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          {scan.progress || 0}% Complete
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1, fontSize: '0.875rem' }}>
          {scan.progress === 0 && 'Initializing scan task...'}
          {scan.progress === 5 && 'Setting up scan environment...'}
          {scan.progress === 10 && 'Processing credentials...'}
          {scan.progress === 20 && 'Testing SSH connection...'}
          {scan.progress === 30 && 'Executing security scan...'}
          {scan.progress >= 90 && 'Finalizing results...'}
          {scan.progress > 30 && scan.progress < 90 && 'Running compliance checks...'}
        </Typography>
        {scan.started_at && (
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1, fontSize: '0.75rem' }}>
            Started: {new Date(scan.started_at).toLocaleString()}
          </Typography>
        )}
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            mt: 2,
            gap: 1,
          }}
        >
          <RefreshIcon sx={{ fontSize: '1rem', animation: 'spin 2s linear infinite' }} />
          <Typography variant="caption" color="text.secondary">
            Auto-refreshing every 5 seconds...
          </Typography>
        </Box>
        <style>{`
          @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
          }
        `}</style>
      </Box>
    );
  }

  if (scan.status === 'failed') {
    return (
      <Alert severity="error" sx={{ mt: 2 }}>
        <Typography variant="h6">Scan Failed</Typography>
        <Typography variant="body2" sx={{ mb: 1 }}>
          {scan.error_message || 'Unknown error occurred'}
        </Typography>
        {scan.progress > 0 && (
          <Typography variant="body2" color="text.secondary">
            Progress reached: {scan.progress}% before failure
          </Typography>
        )}
        {scan.completed_at && (
          <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.75rem', mt: 1 }}>
            Failed at: {new Date(scan.completed_at).toLocaleString()}
          </Typography>
        )}
      </Alert>
    );
  }

  return null;
};

export default ScanOverviewTab;
