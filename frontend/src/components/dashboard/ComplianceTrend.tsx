import React, { useState } from 'react';
import {
  Card,
  CardContent,
  Box,
  Typography,
  ToggleButton,
  ToggleButtonGroup,
  useTheme,
  alpha,
} from '@mui/material';
import {
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Area,
  AreaChart,
} from 'recharts';
import { format } from 'date-fns';

/**
 * Compliance data point for trend visualization
 * Represents compliance scores at a specific point in time
 *
 * Note: The trend chart now shows overall compliance score over time.
 * Severity counts (critical, high, medium, low) are available for
 * tooltip display but are NOT shown as chart lines since they represent
 * issue counts (0-n) not percentages (0-100%).
 */
interface ComplianceDataPoint {
  date: string;
  overall: number; // Overall compliance percentage (0-100)
  critical?: number; // Critical issue count (for tooltip only)
  high?: number; // High issue count (for tooltip only)
  medium?: number; // Medium issue count (for tooltip only)
  low?: number; // Low issue count (for tooltip only)
}

/**
 * Recharts tooltip payload entry
 * Structure provided by Recharts for each data series in the tooltip
 */
interface TooltipPayloadEntry {
  name: string;
  value: number;
  color: string;
  dataKey: string;
  payload: ComplianceDataPoint;
}

/**
 * Recharts custom tooltip props
 * Props passed to custom tooltip component by Recharts
 */
interface CustomTooltipProps {
  active?: boolean;
  payload?: TooltipPayloadEntry[];
  label?: string;
}

interface ComplianceTrendProps {
  data: ComplianceDataPoint[];
  timeRange?: '7d' | '30d' | '90d';
  onTimeRangeChange?: (range: '7d' | '30d' | '90d') => void;
  onDataPointClick?: (data: ComplianceDataPoint) => void;
}

const ComplianceTrend: React.FC<ComplianceTrendProps> = ({
  data,
  timeRange = '30d',
  onTimeRangeChange,
  onDataPointClick,
}) => {
  const theme = useTheme();
  const [hoveredData, _setHoveredData] = useState<ComplianceDataPoint | null>(null);

  // Ensure data is valid and properly formatted
  const safeData = Array.isArray(data)
    ? data.filter(
        (item) => item && typeof item.date === 'string' && typeof item.overall === 'number'
      )
    : [];

  // Custom tooltip for Recharts - displays compliance metrics for hovered data point
  // Using callback component pattern to avoid React Compiler immutability issues
  const CustomTooltip = React.useCallback(
    ({ active, payload, label }: CustomTooltipProps) => {
      if (active && payload && payload.length) {
        const dataPoint = payload[0]?.payload;
        return (
          <Box
            sx={{
              bgcolor: 'background.paper',
              p: 2,
              borderRadius: 1,
              boxShadow: theme.shadows[4],
              border: `1px solid ${theme.palette.divider}`,
            }}
          >
            <Typography variant="subtitle2" gutterBottom>
              {format(new Date(label || ''), 'MMM dd, yyyy')}
            </Typography>
            {/* Overall compliance percentage */}
            {payload.map((entry: TooltipPayloadEntry) => (
              <Box key={entry.name} sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                <Box
                  sx={{
                    width: 12,
                    height: 12,
                    borderRadius: '50%',
                    bgcolor: entry.color,
                  }}
                />
                <Typography variant="caption">
                  {entry.name}: <strong>{entry.value.toFixed(1)}%</strong>
                </Typography>
              </Box>
            ))}
            {/* Issue counts (if available) */}
            {dataPoint && (dataPoint.critical !== undefined || dataPoint.high !== undefined) && (
              <Box sx={{ mt: 1, pt: 1, borderTop: `1px solid ${theme.palette.divider}` }}>
                <Typography
                  variant="caption"
                  color="text.secondary"
                  sx={{ display: 'block', mb: 0.5 }}
                >
                  Issues:
                </Typography>
                <Typography variant="caption" sx={{ display: 'block' }}>
                  Critical: {dataPoint.critical ?? 0} | High: {dataPoint.high ?? 0}
                </Typography>
                <Typography variant="caption" sx={{ display: 'block' }}>
                  Medium: {dataPoint.medium ?? 0} | Low: {dataPoint.low ?? 0}
                </Typography>
              </Box>
            )}
          </Box>
        );
      }
      return null;
    },
    [theme]
  );

  const formatXAxis = (tickItem: string) => {
    const date = new Date(tickItem);
    return format(date, 'MMM d');
  };

  // Colors for chart visualization
  // Only 'overall' is used for the chart line; others kept for potential future use
  const colors = {
    overall: theme.palette.mode === 'dark' ? '#90caf9' : theme.palette.primary.main,
  };

  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Typography variant="h6">Compliance Trends</Typography>
          {onTimeRangeChange && (
            <ToggleButtonGroup
              value={timeRange}
              exclusive
              onChange={(_, value) => value && onTimeRangeChange(value)}
              size="small"
            >
              <ToggleButton value="7d">7D</ToggleButton>
              <ToggleButton value="30d">30D</ToggleButton>
              <ToggleButton value="90d">90D</ToggleButton>
            </ToggleButtonGroup>
          )}
        </Box>

        <Box
          sx={{
            height: 300,
            backgroundColor:
              theme.palette.mode === 'dark'
                ? alpha(theme.palette.background.paper, 0.8)
                : 'transparent',
            borderRadius: 1,
          }}
        >
          {safeData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%" minHeight={300}>
              <AreaChart
                data={safeData}
                width={400}
                height={300}
                margin={{ top: 10, right: 30, left: 0, bottom: 0 }}
                onClick={(e: unknown) => {
                  const event = e as {
                    activePayload?: Array<{ payload: ComplianceDataPoint }>;
                  } | null;
                  if (event && event.activePayload && onDataPointClick) {
                    onDataPointClick(event.activePayload[0].payload);
                  }
                }}
              >
                <defs>
                  <linearGradient id="colorOverall" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={colors.overall} stopOpacity={0.8} />
                    <stop offset="95%" stopColor={colors.overall} stopOpacity={0.1} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={theme.palette.divider} />
                <XAxis
                  dataKey="date"
                  tickFormatter={formatXAxis}
                  stroke={theme.palette.text.secondary}
                  style={{ fontSize: '0.75rem' }}
                />
                <YAxis
                  domain={[0, 100]}
                  stroke={theme.palette.text.secondary}
                  style={{ fontSize: '0.75rem' }}
                />
                {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
                <Tooltip content={CustomTooltip as any} />
                <Legend wrapperStyle={{ fontSize: '0.875rem' }} iconType="circle" />
                {/* Overall compliance trend - the primary metric */}
                <Area
                  type="monotone"
                  dataKey="overall"
                  name="Overall Compliance"
                  stroke={colors.overall}
                  fillOpacity={1}
                  fill="url(#colorOverall)"
                  strokeWidth={3}
                />
                {/*
                  NOTE: Severity issue counts (critical, high, medium, low) are NOT shown as
                  chart lines because they are raw counts (0-n), not percentages (0-100%).
                  These values are available in the tooltip when hovering data points.

                  The trend chart focuses on overall compliance percentage over time,
                  which is the key metric for understanding fleet compliance health.
                */}
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <Box
              sx={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                color: 'text.secondary',
                textAlign: 'center',
              }}
            >
              <Box>
                <Typography variant="h6" gutterBottom>
                  No trend data available
                </Typography>
                <Typography variant="body2">
                  Run some scans to see compliance trends over time
                </Typography>
              </Box>
            </Box>
          )}
        </Box>

        {hoveredData && safeData.length > 0 && (
          <Box
            sx={{
              mt: 2,
              p: 1.5,
              bgcolor: alpha(theme.palette.primary.main, 0.04),
              borderRadius: 1,
            }}
          >
            <Typography variant="caption" color="text.secondary">
              Hover insight: Compliance{' '}
              {hoveredData.overall >= (safeData[0]?.overall || 0) ? 'improved' : 'decreased'} by{' '}
              {Math.abs(hoveredData.overall - (safeData[0]?.overall || 0)).toFixed(1)}% since{' '}
              {format(new Date(safeData[0]?.date || ''), 'MMM d')}
            </Typography>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

export default ComplianceTrend;
