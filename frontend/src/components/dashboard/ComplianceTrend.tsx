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
  LineChart,
  Line,
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

interface ComplianceDataPoint {
  date: string;
  overall: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
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
  const [hoveredData, setHoveredData] = useState<ComplianceDataPoint | null>(null);

  // Ensure data is valid and properly formatted
  const safeData = Array.isArray(data)
    ? data.filter(
        (item) => item && typeof item.date === 'string' && typeof item.overall === 'number'
      )
    : [];

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
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
            {format(new Date(label), 'MMM dd, yyyy')}
          </Typography>
          {payload.map((entry: any) => (
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
                {entry.name}: <strong>{entry.value}%</strong>
              </Typography>
            </Box>
          ))}
        </Box>
      );
    }
    return null;
  };

  const formatXAxis = (tickItem: string) => {
    const date = new Date(tickItem);
    return format(date, 'MMM d');
  };

  const colors = {
    overall: theme.palette.mode === 'dark' ? '#90caf9' : theme.palette.primary.main,
    critical: theme.palette.mode === 'dark' ? '#f44336' : theme.palette.error.main,
    high: theme.palette.mode === 'dark' ? '#ff9800' : theme.palette.warning.dark,
    medium: theme.palette.mode === 'dark' ? '#ffb74d' : theme.palette.warning.main,
    low: theme.palette.mode === 'dark' ? '#64b5f6' : theme.palette.info.main,
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
                onClick={(e) => {
                  if (e && e.activePayload && onDataPointClick) {
                    onDataPointClick(e.activePayload[0].payload);
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
                <Tooltip content={<CustomTooltip />} />
                <Legend wrapperStyle={{ fontSize: '0.875rem' }} iconType="circle" />
                <Area
                  type="monotone"
                  dataKey="overall"
                  name="Overall"
                  stroke={colors.overall}
                  fillOpacity={1}
                  fill="url(#colorOverall)"
                  strokeWidth={3}
                />
                <Area
                  type="monotone"
                  dataKey="critical"
                  name="Critical"
                  stroke={colors.critical}
                  strokeWidth={3}
                  fill="none"
                />
                <Area
                  type="monotone"
                  dataKey="high"
                  name="High"
                  stroke={colors.high}
                  strokeWidth={3}
                  fill="none"
                  strokeDasharray="5 5"
                />
                <Area
                  type="monotone"
                  dataKey="medium"
                  name="Medium"
                  stroke={colors.medium}
                  strokeWidth={2}
                  fill="none"
                  strokeDasharray="3 3"
                />
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
