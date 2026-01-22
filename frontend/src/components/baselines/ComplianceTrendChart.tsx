/**
 * Compliance Trend Chart
 *
 * Displays compliance score trend over time with baseline and drift indicators.
 * Uses Recharts library (already installed, version 2.15.4) for visualization.
 *
 * Features:
 * - Baseline reference line
 * - Drift event markers
 * - Per-severity trend lines (optional)
 * - Interactive tooltips with detailed metrics
 */

import React, { useMemo } from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ReferenceLine,
  Dot,
} from 'recharts';
import { Box, Typography, Paper, useTheme } from '@mui/material';
import { Warning as WarningIcon, TrendingUp as TrendingUpIcon } from '@mui/icons-material';

interface ScanDataPoint {
  timestamp: string;
  score: number;
  passed_rules: number;
  failed_rules: number;
  total_rules: number;
  scan_id: string;
  drift_type?: 'major' | 'minor' | 'improvement' | 'stable' | null;
  drift_magnitude?: number;
}

interface ComplianceTrendChartProps {
  data: ScanDataPoint[];
  baselineScore?: number;
  showSeverityBreakdown?: boolean;
  height?: number;
}

const ComplianceTrendChart: React.FC<ComplianceTrendChartProps> = ({
  data,
  baselineScore,
  showSeverityBreakdown: _showSeverityBreakdown = false,
  height = 300,
}) => {
  const theme = useTheme();

  // Memoize CustomTooltip to prevent recreation on each render
  const CustomTooltip = useMemo(
    () =>
      ({
        active,
        payload,
      }: {
        active?: boolean;
        payload?: Array<{
          value: number;
          payload: {
            timestamp: string;
            date: string;
            score: number;
            passed_rules: number;
            total_rules: number;
            drift_type?: string;
            drift_magnitude?: number;
          };
        }>;
      }) => {
        if (!active || !payload || payload.length === 0) {
          return null;
        }

        const dataPoint = payload[0].payload;

        return (
          <Paper sx={{ p: 1.5, border: 1, borderColor: 'divider' }}>
            <Typography variant="caption" color="text.secondary">
              {new Date(dataPoint.timestamp).toLocaleString()}
            </Typography>
            <Typography variant="h6" color="primary" fontWeight="bold">
              {dataPoint.score.toFixed(1)}%
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {dataPoint.passed_rules}/{dataPoint.total_rules} rules passed
            </Typography>
            {dataPoint.drift_type && dataPoint.drift_type !== 'stable' && (
              <Box display="flex" alignItems="center" mt={0.5}>
                {dataPoint.drift_type === 'improvement' ? (
                  <TrendingUpIcon fontSize="small" color="success" sx={{ mr: 0.5 }} />
                ) : (
                  <WarningIcon fontSize="small" color="error" sx={{ mr: 0.5 }} />
                )}
                <Typography variant="caption" fontWeight="bold">
                  {dataPoint.drift_type === 'major' && 'Major Drift'}
                  {dataPoint.drift_type === 'minor' && 'Minor Drift'}
                  {dataPoint.drift_type === 'improvement' && 'Improvement'}
                  {dataPoint.drift_magnitude !== undefined &&
                    ` (${dataPoint.drift_magnitude > 0 ? '+' : ''}${dataPoint.drift_magnitude.toFixed(1)}pp)`}
                </Typography>
              </Box>
            )}
          </Paper>
        );
      },
    [] // Empty deps - component doesn't depend on external values
  );

  // Memoize CustomDot to prevent recreation on each render
  const CustomDot = useMemo(
    () =>
      (props: { cx?: number; cy?: number; payload?: { drift_type?: string } }) => {
        const { cx, cy, payload } = props;

        if (!payload || !payload.drift_type || payload.drift_type === 'stable') {
          return <Dot cx={cx} cy={cy} r={3} fill={theme.palette.primary.main} />;
        }

        let fillColor = theme.palette.grey[400];
        if (payload.drift_type === 'major') {
          fillColor = theme.palette.error.main;
        } else if (payload.drift_type === 'minor') {
          fillColor = theme.palette.warning.main;
        } else if (payload.drift_type === 'improvement') {
          fillColor = theme.palette.success.main;
        }

        return <Dot cx={cx} cy={cy} r={6} fill={fillColor} stroke="#fff" strokeWidth={2} />;
      },
    [theme] // Depends on theme
  );

  if (!data || data.length === 0) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height={height}>
        <Typography variant="body2" color="text.secondary">
          No scan data available
        </Typography>
      </Box>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke={theme.palette.divider} />
        <XAxis
          dataKey="timestamp"
          tickFormatter={(timestamp) =>
            new Date(timestamp).toLocaleDateString(undefined, {
              month: 'short',
              day: 'numeric',
            })
          }
          stroke={theme.palette.text.secondary}
          style={{ fontSize: '12px' }}
        />
        <YAxis
          domain={[0, 100]}
          stroke={theme.palette.text.secondary}
          style={{ fontSize: '12px' }}
          label={{
            value: 'Compliance Score (%)',
            angle: -90,
            position: 'insideLeft',
            style: { textAnchor: 'middle', fill: theme.palette.text.secondary },
          }}
        />
        <Tooltip content={<CustomTooltip />} />
        <Legend />

        {baselineScore !== undefined && (
          <ReferenceLine
            y={baselineScore}
            stroke={theme.palette.info.main}
            strokeDasharray="5 5"
            label={{
              value: `Baseline (${baselineScore.toFixed(1)}%)`,
              position: 'right',
              fill: theme.palette.info.main,
              fontSize: 12,
            }}
          />
        )}

        <Line
          type="monotone"
          dataKey="score"
          stroke={theme.palette.primary.main}
          strokeWidth={2}
          dot={<CustomDot />}
          activeDot={{ r: 8 }}
          name="Compliance Score"
        />
      </LineChart>
    </ResponsiveContainer>
  );
};

export default ComplianceTrendChart;
