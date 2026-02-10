/**
 * Temporal Posture Page
 *
 * Displays compliance posture over time with:
 * - Current posture view
 * - Historical posture chart
 * - Drift analysis between dates
 *
 * Part of Phase 2: Temporal Compliance (Aegis Integration Plan)
 *
 * @module pages/compliance/TemporalPosture
 */

import React, { useState, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Box,
  Typography,
  Paper,
  Card,
  CardContent,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Tabs,
  Tab,
  Chip,
  Skeleton,
  Alert,
  LinearProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  IconButton,
  ToggleButton,
  ToggleButtonGroup,
  TextField,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  TrendingFlat as TrendingFlatIcon,
  History as HistoryIcon,
  CompareArrows as CompareArrowsIcon,
  CheckCircle as CheckCircleIcon,
  Cancel as CancelIcon,
  Info as InfoIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as ChartTooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { format, subDays, parseISO } from 'date-fns';
import { useHosts } from '../../hooks/useHosts';
import { useCurrentPosture, usePostureHistory, useDriftAnalysis } from '../../hooks/usePosture';
import type { DriftEvent } from '../../types/posture';

// =============================================================================
// Tab Panel Component
// =============================================================================

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel({ children, value, index, ...other }: TabPanelProps) {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`posture-tabpanel-${index}`}
      aria-labelledby={`posture-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

// =============================================================================
// Score Display Component
// =============================================================================

interface ScoreDisplayProps {
  score: number;
  size?: 'small' | 'medium' | 'large';
  showLabel?: boolean;
}

function ScoreDisplay({ score, size = 'medium', showLabel = true }: ScoreDisplayProps) {
  const getColor = (s: number) => {
    if (s >= 90) return 'success.main';
    if (s >= 70) return 'warning.main';
    return 'error.main';
  };

  const fontSize = size === 'large' ? 'h2' : size === 'medium' ? 'h4' : 'h6';

  return (
    <Box sx={{ textAlign: 'center' }}>
      <Typography variant={fontSize} color={getColor(score)} fontWeight="bold">
        {score.toFixed(1)}%
      </Typography>
      {showLabel && (
        <Typography variant="caption" color="text.secondary">
          Compliance Score
        </Typography>
      )}
    </Box>
  );
}

// =============================================================================
// Current Posture View
// =============================================================================

interface CurrentPostureViewProps {
  hostId: string;
}

function CurrentPostureView({ hostId }: CurrentPostureViewProps) {
  const { data: posture, isLoading, error, refetch } = useCurrentPosture(hostId);

  if (isLoading) {
    return (
      <Grid container spacing={3}>
        {[1, 2, 3, 4].map((i) => (
          <Grid size={{ xs: 12, sm: 6, md: 3 }} key={i}>
            <Skeleton variant="rectangular" height={120} />
          </Grid>
        ))}
      </Grid>
    );
  }

  if (error) {
    return (
      <Alert severity="error">Failed to load current posture: {(error as Error).message}</Alert>
    );
  }

  if (!posture) {
    return (
      <Alert severity="info">
        No compliance data available for this host. Run an Aegis scan to collect posture data.
      </Alert>
    );
  }

  const severityOrder = ['critical', 'high', 'medium', 'low'];

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h6">Current Posture</Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="caption" color="text.secondary">
            As of {format(parseISO(posture.snapshot_date), 'PPpp')}
          </Typography>
          <IconButton size="small" onClick={() => refetch()}>
            <RefreshIcon fontSize="small" />
          </IconButton>
        </Box>
      </Box>

      <Grid container spacing={3}>
        {/* Compliance Score Card */}
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <ScoreDisplay score={posture.compliance_score} size="large" />
            </CardContent>
          </Card>
        </Grid>

        {/* Pass/Fail Summary Card */}
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <Card>
            <CardContent>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                Rules Summary
              </Typography>
              <Box sx={{ display: 'flex', gap: 2, mt: 1 }}>
                <Box sx={{ textAlign: 'center' }}>
                  <Typography variant="h4" color="success.main">
                    {posture.passed}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Passed
                  </Typography>
                </Box>
                <Box sx={{ textAlign: 'center' }}>
                  <Typography variant="h4" color="error.main">
                    {posture.failed}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Failed
                  </Typography>
                </Box>
              </Box>
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                {posture.total_rules} total rules
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* Severity Breakdown Card */}
        <Grid size={{ xs: 12, sm: 6, md: 6 }}>
          <Card>
            <CardContent>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                By Severity
              </Typography>
              <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mt: 1 }}>
                {severityOrder.map((severity) => {
                  const breakdown = posture.severity_breakdown[severity];
                  if (!breakdown) return null;
                  const total = breakdown.passed + breakdown.failed;
                  if (total === 0) return null;

                  return (
                    <Box key={severity} sx={{ textAlign: 'center', minWidth: 80 }}>
                      <Typography
                        variant="caption"
                        sx={{ textTransform: 'capitalize', display: 'block', mb: 0.5 }}
                      >
                        {severity}
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 0.5, justifyContent: 'center' }}>
                        <Chip
                          size="small"
                          label={breakdown.passed}
                          color="success"
                          variant="outlined"
                        />
                        <Chip
                          size="small"
                          label={breakdown.failed}
                          color="error"
                          variant="outlined"
                        />
                      </Box>
                    </Box>
                  );
                })}
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}

// =============================================================================
// History View
// =============================================================================

interface HistoryViewProps {
  hostId: string;
}

function HistoryView({ hostId }: HistoryViewProps) {
  const [dateRange, setDateRange] = useState<'7d' | '30d' | '90d'>('30d');

  const getDaysForRange = (range: string) => {
    switch (range) {
      case '7d':
        return 7;
      case '30d':
        return 30;
      case '90d':
        return 90;
      default:
        return 30;
    }
  };

  const startDate = useMemo(
    () => format(subDays(new Date(), getDaysForRange(dateRange)), 'yyyy-MM-dd'),
    [dateRange]
  );
  const endDate = useMemo(() => format(new Date(), 'yyyy-MM-dd'), []);

  const {
    data: history,
    isLoading,
    error,
  } = usePostureHistory({
    host_id: hostId,
    start_date: startDate,
    end_date: endDate,
    limit: 100,
  });

  const chartData = useMemo(() => {
    if (!history?.snapshots) return [];
    return history.snapshots
      .map((snapshot) => ({
        date: format(parseISO(snapshot.snapshot_date), 'MM/dd'),
        fullDate: snapshot.snapshot_date,
        score: snapshot.compliance_score,
        passed: snapshot.passed,
        failed: snapshot.failed,
      }))
      .reverse();
  }, [history]);

  if (isLoading) {
    return <Skeleton variant="rectangular" height={400} />;
  }

  if (error) {
    const errorMessage = (error as Error).message;
    if (errorMessage.includes('subscription') || errorMessage.includes('403')) {
      return (
        <Alert severity="info" icon={<InfoIcon />}>
          <Typography variant="subtitle2">OpenWatch+ Required</Typography>
          <Typography variant="body2">
            Posture history queries require an OpenWatch+ subscription. Upgrade to view historical
            compliance data and trends.
          </Typography>
        </Alert>
      );
    }
    return <Alert severity="error">Failed to load history: {errorMessage}</Alert>;
  }

  if (!history || history.snapshots.length === 0) {
    return (
      <Alert severity="info">
        No historical posture data available. Snapshots are created daily when scans complete.
      </Alert>
    );
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h6">Compliance History</Typography>
        <ToggleButtonGroup
          value={dateRange}
          exclusive
          onChange={(_, value) => value && setDateRange(value)}
          size="small"
        >
          <ToggleButton value="7d">7D</ToggleButton>
          <ToggleButton value="30d">30D</ToggleButton>
          <ToggleButton value="90d">90D</ToggleButton>
        </ToggleButtonGroup>
      </Box>

      <Paper sx={{ p: 2 }}>
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={chartData} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="date" />
            <YAxis domain={[0, 100]} />
            <ChartTooltip
              formatter={(value, name) => {
                const numValue = typeof value === 'number' ? value : 0;
                return [
                  name === 'score' ? `${numValue.toFixed(1)}%` : numValue,
                  name === 'score' ? 'Compliance Score' : String(name),
                ];
              }}
              labelFormatter={(label) => `Date: ${label}`}
            />
            <Legend />
            <Line
              type="monotone"
              dataKey="score"
              stroke="#1976d2"
              strokeWidth={2}
              dot={{ r: 3 }}
              activeDot={{ r: 6 }}
              name="Compliance Score"
            />
          </LineChart>
        </ResponsiveContainer>

        <Typography variant="caption" color="text.secondary" sx={{ mt: 2, display: 'block' }}>
          {history.total_snapshots} snapshots over selected period
        </Typography>
      </Paper>
    </Box>
  );
}

// =============================================================================
// Drift Analysis View
// =============================================================================

interface DriftViewProps {
  hostId: string;
}

function DriftView({ hostId }: DriftViewProps) {
  const [startDate, setStartDate] = useState<string>(format(subDays(new Date(), 7), 'yyyy-MM-dd'));
  const [endDate, setEndDate] = useState<string>(format(new Date(), 'yyyy-MM-dd'));

  const {
    data: drift,
    isLoading,
    error,
  } = useDriftAnalysis(
    startDate && endDate
      ? {
          host_id: hostId,
          start_date: startDate,
          end_date: endDate,
        }
      : undefined
  );

  const getDriftIcon = (type: string) => {
    switch (type) {
      case 'improvement':
        return <TrendingUpIcon color="success" />;
      case 'major':
      case 'minor':
        return <TrendingDownIcon color="error" />;
      default:
        return <TrendingFlatIcon color="action" />;
    }
  };

  const getDriftColor = (direction: string) => {
    return direction === 'improvement' ? 'success' : 'error';
  };

  if (error) {
    const errorMessage = (error as Error).message;
    if (errorMessage.includes('subscription') || errorMessage.includes('403')) {
      return (
        <Alert severity="info" icon={<InfoIcon />}>
          <Typography variant="subtitle2">OpenWatch+ Required</Typography>
          <Typography variant="body2">
            Drift analysis requires an OpenWatch+ subscription. Upgrade to compare compliance
            posture between dates.
          </Typography>
        </Alert>
      );
    }
    return <Alert severity="error">Failed to load drift analysis: {errorMessage}</Alert>;
  }

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Drift Analysis
      </Typography>

      {/* Date Range Picker */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid size={{ xs: 12, sm: 5 }}>
            <TextField
              label="Start Date"
              type="date"
              value={startDate}
              onChange={(e) => setStartDate(e.target.value)}
              fullWidth
              size="small"
              InputLabelProps={{ shrink: true }}
            />
          </Grid>
          <Grid size={{ xs: 12, sm: 2 }} sx={{ textAlign: 'center' }}>
            <CompareArrowsIcon color="action" />
          </Grid>
          <Grid size={{ xs: 12, sm: 5 }}>
            <TextField
              label="End Date"
              type="date"
              value={endDate}
              onChange={(e) => setEndDate(e.target.value)}
              fullWidth
              size="small"
              InputLabelProps={{ shrink: true }}
            />
          </Grid>
        </Grid>
      </Paper>

      {isLoading && <LinearProgress sx={{ mb: 2 }} />}

      {drift && (
        <>
          {/* Drift Summary */}
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid size={{ xs: 12, sm: 4 }}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                    {getDriftIcon(drift.drift_type)}
                    <Typography variant="subtitle2" sx={{ textTransform: 'capitalize' }}>
                      {drift.drift_type} Drift
                    </Typography>
                  </Box>
                  <Typography
                    variant="h4"
                    color={drift.score_delta >= 0 ? 'success.main' : 'error.main'}
                  >
                    {drift.score_delta >= 0 ? '+' : ''}
                    {drift.score_delta.toFixed(1)}%
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Score change
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid size={{ xs: 12, sm: 4 }}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', gap: 2 }}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="body2" color="text.secondary">
                        Start
                      </Typography>
                      <Typography variant="h5">{drift.start_score.toFixed(1)}%</Typography>
                    </Box>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <CompareArrowsIcon color="action" />
                    </Box>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="body2" color="text.secondary">
                        End
                      </Typography>
                      <Typography variant="h5">{drift.end_score.toFixed(1)}%</Typography>
                    </Box>
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            <Grid size={{ xs: 12, sm: 4 }}>
              <Card>
                <CardContent>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Rule Changes
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 2, mt: 1 }}>
                    <Tooltip title="Rules that improved (fail -> pass)">
                      <Chip
                        icon={<TrendingUpIcon />}
                        label={drift.rules_improved}
                        color="success"
                        size="small"
                      />
                    </Tooltip>
                    <Tooltip title="Rules that regressed (pass -> fail)">
                      <Chip
                        icon={<TrendingDownIcon />}
                        label={drift.rules_regressed}
                        color="error"
                        size="small"
                      />
                    </Tooltip>
                    <Tooltip title="Rules unchanged">
                      <Chip
                        icon={<TrendingFlatIcon />}
                        label={drift.rules_unchanged}
                        variant="outlined"
                        size="small"
                      />
                    </Tooltip>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Drift Events Table */}
          {drift.drift_events.length > 0 && (
            <Paper>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Rule</TableCell>
                      <TableCell>Severity</TableCell>
                      <TableCell>Previous</TableCell>
                      <TableCell>Current</TableCell>
                      <TableCell>Direction</TableCell>
                      <TableCell>Detected</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {drift.drift_events.map((event: DriftEvent, index: number) => (
                      <TableRow key={`${event.rule_id}-${index}`}>
                        <TableCell>
                          <Typography variant="body2" fontWeight="medium">
                            {event.rule_id}
                          </Typography>
                          {event.rule_title && (
                            <Typography variant="caption" color="text.secondary">
                              {event.rule_title}
                            </Typography>
                          )}
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={event.severity}
                            size="small"
                            color={
                              event.severity === 'critical'
                                ? 'error'
                                : event.severity === 'high'
                                  ? 'warning'
                                  : 'default'
                            }
                          />
                        </TableCell>
                        <TableCell>
                          {event.previous_status === 'pass' ? (
                            <CheckCircleIcon color="success" fontSize="small" />
                          ) : (
                            <CancelIcon color="error" fontSize="small" />
                          )}
                        </TableCell>
                        <TableCell>
                          {event.current_status === 'pass' ? (
                            <CheckCircleIcon color="success" fontSize="small" />
                          ) : (
                            <CancelIcon color="error" fontSize="small" />
                          )}
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={event.direction}
                            size="small"
                            color={getDriftColor(event.direction)}
                            variant="outlined"
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">
                            {format(parseISO(event.detected_at), 'PP')}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          )}

          {drift.drift_events.length === 0 && (
            <Alert severity="success" icon={<TrendingFlatIcon />}>
              No drift detected between the selected dates. Compliance posture remained stable.
            </Alert>
          )}
        </>
      )}
    </Box>
  );
}

// =============================================================================
// Main Component
// =============================================================================

export default function TemporalPosture() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [selectedTab, setSelectedTab] = useState(0);

  // Get host from URL or default to first
  const hostIdParam = searchParams.get('host_id');

  // Fetch hosts for selector
  const { data: hosts, isLoading: hostsLoading } = useHosts();

  // Use first host if none selected
  const selectedHostId = hostIdParam || hosts?.[0]?.id;

  const handleHostChange = (hostId: string) => {
    setSearchParams({ host_id: hostId });
  };

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          Temporal Compliance
        </Typography>
        <Typography variant="body1" color="text.secondary">
          View compliance posture over time, track history, and analyze drift
        </Typography>
      </Box>

      {/* Host Selector */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <FormControl fullWidth size="small">
          <InputLabel>Select Host</InputLabel>
          <Select
            value={selectedHostId || ''}
            label="Select Host"
            onChange={(e) => handleHostChange(e.target.value)}
            disabled={hostsLoading}
          >
            {hosts?.map((host) => (
              <MenuItem key={host.id} value={host.id}>
                {host.displayName || host.hostname} ({host.ipAddress})
              </MenuItem>
            ))}
          </Select>
        </FormControl>
      </Paper>

      {/* Tabs */}
      {selectedHostId && (
        <>
          <Paper sx={{ mb: 2 }}>
            <Tabs
              value={selectedTab}
              onChange={(_, newValue) => setSelectedTab(newValue)}
              aria-label="posture tabs"
            >
              <Tab
                icon={<CheckCircleIcon />}
                iconPosition="start"
                label="Current Posture"
                id="posture-tab-0"
              />
              <Tab icon={<HistoryIcon />} iconPosition="start" label="History" id="posture-tab-1" />
              <Tab
                icon={<CompareArrowsIcon />}
                iconPosition="start"
                label="Drift Analysis"
                id="posture-tab-2"
              />
            </Tabs>
          </Paper>

          <TabPanel value={selectedTab} index={0}>
            <CurrentPostureView hostId={selectedHostId} />
          </TabPanel>

          <TabPanel value={selectedTab} index={1}>
            <HistoryView hostId={selectedHostId} />
          </TabPanel>

          <TabPanel value={selectedTab} index={2}>
            <DriftView hostId={selectedHostId} />
          </TabPanel>
        </>
      )}

      {!selectedHostId && !hostsLoading && (
        <Alert severity="info">
          No hosts available. Add a host first to view compliance posture.
        </Alert>
      )}
    </Box>
  );
}
