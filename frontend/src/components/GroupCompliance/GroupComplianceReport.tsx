import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  LinearProgress,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Alert,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  CircularProgress,
} from '@mui/material';
import GridLegacy from '@mui/material/GridLegacy';
import {
  Assessment,
  Warning,
  CheckCircle,
  Error,
  Download,
  Refresh,
  Computer,
} from '@mui/icons-material';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
} from 'recharts';

interface ComplianceReportProps {
  groupId: number;
  groupName: string;
}

/**
 * Framework distribution data - compliance metrics per framework
 * Contains host count and average compliance score for each framework
 */
interface FrameworkDistributionData {
  hosts: number;
  avg_score: number;
  // Additional framework-specific metrics from backend
  [key: string]: string | number | boolean | undefined;
}

interface ComplianceReport {
  group_id: number;
  group_name: string;
  total_hosts: number;
  overall_compliance_score: number;
  total_rules_evaluated: number;
  total_passed_rules: number;
  total_failed_rules: number;
  high_risk_hosts: number;
  medium_risk_hosts: number;
  // Maps framework name to compliance metrics for that framework
  framework_distribution: Record<string, FrameworkDistributionData>;
  compliance_trend: Array<{ date: string; score: number; scan_count: number }>;
  top_failed_rules: Array<{
    rule_id: string;
    rule_title: string;
    severity: string;
    failure_count: number;
    failure_percentage: number;
  }>;
  host_compliance_summary: Array<{
    host_id: string;
    hostname: string;
    ip_address: string;
    compliance_score: number;
    high_severity_issues: number;
    last_scan_date: string;
  }>;
}

const COLORS = {
  success: '#4caf50',
  warning: '#ff9800',
  error: '#f44336',
  info: '#2196f3',
  primary: '#1976d2',
};

export const GroupComplianceReport: React.FC<ComplianceReportProps> = ({ groupId, groupName }) => {
  const [report, setReport] = useState<ComplianceReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedFramework, setSelectedFramework] = useState<string>('');
  const [dateRange, setDateRange] = useState<string>('30d');
  const [showHostDetails, setShowHostDetails] = useState(false);

  // Load compliance report when groupId, framework, or date range changes
  // ESLint disable: loadComplianceReport function is not memoized to avoid complex dependency chain
  useEffect(() => {
    loadComplianceReport();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groupId, selectedFramework, dateRange]);

  const loadComplianceReport = async () => {
    setLoading(true);
    setError(null);

    try {
      const params = new URLSearchParams();
      if (selectedFramework) params.append('framework', selectedFramework);
      if (dateRange !== '30d') {
        const days = parseInt(dateRange.replace('d', ''));
        const fromDate = new Date();
        fromDate.setDate(fromDate.getDate() - days);
        params.append('date_from', fromDate.toISOString());
      }

      const response = await fetch(`/api/host-groups/${groupId}/compliance/report?${params}`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setReport(data);
      } else {
        setError('Failed to load compliance report');
      }
    } catch {
      setError('Failed to load compliance report');
    } finally {
      setLoading(false);
    }
  };

  const downloadReport = async (format: 'pdf' | 'csv' | 'json') => {
    try {
      const params = new URLSearchParams({ format });
      if (selectedFramework) params.append('framework', selectedFramework);

      const response = await fetch(
        `/api/host-groups/${groupId}/compliance/report/download?${params}`,
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
          },
        }
      );

      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = `compliance_report_${groupName}_${new Date().toISOString().split('T')[0]}.${format}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
      }
    } catch (error) {
      console.error('Failed to download report:', error);
    }
  };

  const getComplianceScoreColor = (score: number): string => {
    if (score >= 90) return COLORS.success;
    if (score >= 75) return COLORS.warning;
    return COLORS.error;
  };

  const getRiskLevel = (highIssues: number): { level: string; color: string } => {
    if (highIssues === 0) return { level: 'Low', color: COLORS.success };
    if (highIssues <= 5) return { level: 'Medium', color: COLORS.warning };
    return { level: 'High', color: COLORS.error };
  };

  // Format framework distribution data for chart display
  // Transforms Record<string, FrameworkDistributionData> to array format for Recharts
  const formatFrameworkDistribution = () => {
    if (!report?.framework_distribution) return [];

    return Object.entries(report.framework_distribution).map(
      ([framework, data]: [string, FrameworkDistributionData]) => ({
        name: framework,
        hosts: data.hosts,
        score: data.avg_score,
      })
    );
  };

  const formatHostRiskDistribution = () => {
    if (!report) return [];

    const lowRisk = report.total_hosts - report.high_risk_hosts - report.medium_risk_hosts;
    return [
      { name: 'Low Risk', value: lowRisk, color: COLORS.success },
      { name: 'Medium Risk', value: report.medium_risk_hosts, color: COLORS.warning },
      { name: 'High Risk', value: report.high_risk_hosts, color: COLORS.error },
    ];
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight={400}>
        <CircularProgress />
      </Box>
    );
  }

  if (error || !report) {
    return (
      <Alert severity="error" action={<Button onClick={loadComplianceReport}>Retry</Button>}>
        {error || 'No compliance data available'}
      </Alert>
    );
  }

  return (
    <Box>
      {/* Header with Controls */}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1" display="flex" alignItems="center" gap={1}>
          <Assessment color="primary" />
          Compliance Report - {report.group_name}
        </Typography>

        <Box display="flex" gap={2} alignItems="center">
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Framework</InputLabel>
            <Select
              value={selectedFramework}
              onChange={(e) => setSelectedFramework(e.target.value)}
              label="Framework"
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="disa-stig">DISA STIG</MenuItem>
              <MenuItem value="cis">CIS</MenuItem>
              <MenuItem value="nist-800-53">NIST 800-53</MenuItem>
            </Select>
          </FormControl>

          <FormControl size="small" sx={{ minWidth: 100 }}>
            <InputLabel>Period</InputLabel>
            <Select value={dateRange} onChange={(e) => setDateRange(e.target.value)} label="Period">
              <MenuItem value="7d">7 days</MenuItem>
              <MenuItem value="30d">30 days</MenuItem>
              <MenuItem value="90d">90 days</MenuItem>
            </Select>
          </FormControl>

          <Tooltip title="Refresh">
            <IconButton onClick={loadComplianceReport}>
              <Refresh />
            </IconButton>
          </Tooltip>

          <Button variant="outlined" startIcon={<Download />} onClick={() => downloadReport('pdf')}>
            Export
          </Button>
        </Box>
      </Box>

      {/* Key Metrics Cards */}
      <GridLegacy container spacing={3} sx={{ mb: 3 }}>
        <GridLegacy item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Overall Compliance
                  </Typography>
                  <Typography variant="h3" component="div">
                    {report.overall_compliance_score.toFixed(1)}%
                  </Typography>
                </Box>
                <Box
                  sx={{
                    width: 60,
                    height: 60,
                    borderRadius: '50%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    backgroundColor: getComplianceScoreColor(report.overall_compliance_score),
                  }}
                >
                  <CheckCircle sx={{ color: 'white', fontSize: 30 }} />
                </Box>
              </Box>
            </CardContent>
          </Card>
        </GridLegacy>

        <GridLegacy item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Total Hosts
                  </Typography>
                  <Typography variant="h3" component="div">
                    {report.total_hosts}
                  </Typography>
                </Box>
                <Computer sx={{ fontSize: 40, color: COLORS.info }} />
              </Box>
            </CardContent>
          </Card>
        </GridLegacy>

        <GridLegacy item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    Failed Rules
                  </Typography>
                  <Typography variant="h3" component="div">
                    {report.total_failed_rules}
                  </Typography>
                </Box>
                <Error sx={{ fontSize: 40, color: COLORS.error }} />
              </Box>
            </CardContent>
          </Card>
        </GridLegacy>

        <GridLegacy item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="textSecondary" gutterBottom>
                    High Risk Hosts
                  </Typography>
                  <Typography variant="h3" component="div">
                    {report.high_risk_hosts}
                  </Typography>
                </Box>
                <Warning sx={{ fontSize: 40, color: COLORS.error }} />
              </Box>
            </CardContent>
          </Card>
        </GridLegacy>
      </GridLegacy>

      {/* Charts Section */}
      <GridLegacy container spacing={3} sx={{ mb: 3 }}>
        {/* Compliance Trend */}
        <GridLegacy item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Compliance Trend Over Time
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={report.compliance_trend}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis
                    dataKey="date"
                    tickFormatter={(date) => new Date(date).toLocaleDateString()}
                  />
                  <YAxis domain={[0, 100]} />
                  <RechartsTooltip
                    labelFormatter={(date) => new Date(date).toLocaleDateString()}
                    formatter={(value: number | undefined) =>
                      value !== undefined ? [`${value.toFixed(1)}%`, 'Compliance Score'] : ['N/A', 'Compliance Score']
                    }
                  />
                  <Line
                    type="monotone"
                    dataKey="score"
                    stroke={COLORS.primary}
                    strokeWidth={2}
                    dot={{ fill: COLORS.primary, strokeWidth: 2 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </GridLegacy>

        {/* Risk Distribution */}
        <GridLegacy item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Host Risk Distribution
              </Typography>
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={formatHostRiskDistribution()}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }: { name: string; percent?: number }) =>
                      percent !== undefined ? `${name}: ${(percent * 100).toFixed(0)}%` : `${name}: N/A`
                    }
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {formatHostRiskDistribution().map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </GridLegacy>
      </GridLegacy>

      {/* Framework Distribution */}
      {formatFrameworkDistribution().length > 0 && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Framework Distribution
            </Typography>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={formatFrameworkDistribution()}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis yAxisId="left" orientation="left" />
                <YAxis yAxisId="right" orientation="right" />
                <RechartsTooltip />
                <Bar yAxisId="left" dataKey="hosts" fill={COLORS.info} name="Hosts" />
                <Bar yAxisId="right" dataKey="score" fill={COLORS.success} name="Avg Score %" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      )}

      {/* Top Failed Rules */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Most Common Compliance Failures
          </Typography>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Rule</TableCell>
                  <TableCell>Severity</TableCell>
                  <TableCell align="right">Failed Hosts</TableCell>
                  <TableCell align="right">Failure Rate</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {report.top_failed_rules.slice(0, 10).map((rule) => (
                  <TableRow key={rule.rule_id}>
                    <TableCell>
                      <Typography variant="body2" fontWeight="medium">
                        {rule.rule_title}
                      </Typography>
                      <Typography variant="caption" color="textSecondary">
                        {rule.rule_id}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={rule.severity}
                        color={
                          rule.severity === 'high'
                            ? 'error'
                            : rule.severity === 'medium'
                              ? 'warning'
                              : 'default'
                        }
                        size="small"
                      />
                    </TableCell>
                    <TableCell align="right">{rule.failure_count}</TableCell>
                    <TableCell align="right">
                      <Box display="flex" alignItems="center" justifyContent="flex-end">
                        <LinearProgress
                          variant="determinate"
                          value={rule.failure_percentage}
                          sx={{ width: 60, mr: 1 }}
                          color={rule.failure_percentage > 50 ? 'error' : 'warning'}
                        />
                        {rule.failure_percentage.toFixed(1)}%
                      </Box>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>

      {/* Host Summary */}
      <Card>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Typography variant="h6">Host Compliance Summary</Typography>
            <Button onClick={() => setShowHostDetails(true)}>View All Hosts</Button>
          </Box>

          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Host</TableCell>
                  <TableCell>IP Address</TableCell>
                  <TableCell align="right">Compliance Score</TableCell>
                  <TableCell align="right">High Risk Issues</TableCell>
                  <TableCell>Last Scan</TableCell>
                  <TableCell>Risk Level</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {report.host_compliance_summary.slice(0, 10).map((host) => {
                  const riskLevel = getRiskLevel(host.high_severity_issues);
                  return (
                    <TableRow key={host.host_id}>
                      <TableCell>{host.hostname}</TableCell>
                      <TableCell>{host.ip_address}</TableCell>
                      <TableCell align="right">
                        <Box display="flex" alignItems="center" justifyContent="flex-end">
                          <LinearProgress
                            variant="determinate"
                            value={host.compliance_score}
                            sx={{ width: 80, mr: 1 }}
                            color={
                              host.compliance_score >= 90
                                ? 'success'
                                : host.compliance_score >= 75
                                  ? 'warning'
                                  : 'error'
                            }
                          />
                          {host.compliance_score.toFixed(1)}%
                        </Box>
                      </TableCell>
                      <TableCell align="right">{host.high_severity_issues}</TableCell>
                      <TableCell>{new Date(host.last_scan_date).toLocaleDateString()}</TableCell>
                      <TableCell>
                        <Chip
                          label={riskLevel.level}
                          sx={{ backgroundColor: riskLevel.color, color: 'white' }}
                          size="small"
                        />
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>

      {/* Host Details Dialog */}
      <Dialog
        open={showHostDetails}
        onClose={() => setShowHostDetails(false)}
        maxWidth="lg"
        fullWidth
      >
        <DialogTitle>Complete Host Compliance Summary</DialogTitle>
        <DialogContent>
          <TableContainer component={Paper} sx={{ maxHeight: 500 }}>
            <Table stickyHeader>
              <TableHead>
                <TableRow>
                  <TableCell>Host</TableCell>
                  <TableCell>IP Address</TableCell>
                  <TableCell align="right">Score</TableCell>
                  <TableCell align="right">Passed</TableCell>
                  <TableCell align="right">Failed</TableCell>
                  <TableCell align="right">High Risk</TableCell>
                  <TableCell>Last Scan</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {report.host_compliance_summary.map((host) => (
                  <TableRow key={host.host_id}>
                    <TableCell>{host.hostname}</TableCell>
                    <TableCell>{host.ip_address}</TableCell>
                    <TableCell align="right">{host.compliance_score.toFixed(1)}%</TableCell>
                    <TableCell align="right">
                      {/* Would need passed_rules in the schema */}
                    </TableCell>
                    <TableCell align="right">
                      {/* Would need failed_rules in the schema */}
                    </TableCell>
                    <TableCell align="right">{host.high_severity_issues}</TableCell>
                    <TableCell>{new Date(host.last_scan_date).toLocaleDateString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </DialogContent>
      </Dialog>
    </Box>
  );
};
