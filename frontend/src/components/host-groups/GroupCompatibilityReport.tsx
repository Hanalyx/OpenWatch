import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Typography,
  Box,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Chip,
  Alert,
  CircularProgress,
  Grid,
  Card,
  CardContent,
  LinearProgress,
  Divider,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Tooltip,
} from '@mui/material';
import {
  Computer as HostIcon,
  CheckCircle as SuccessIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Assessment as ReportIcon,
  ExpandMore as ExpandMoreIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  TrendingFlat as TrendingFlatIcon,
} from '@mui/icons-material';

interface HostGroup {
  id: number;
  name: string;
  description?: string;
  os_family?: string;
  os_version_pattern?: string;
  compliance_framework?: string;
  scap_content_name?: string;
}

interface CompatibilityReport {
  group: {
    id: number;
    name: string;
    description?: string;
    os_family?: string;
    os_version_pattern?: string;
    compliance_framework?: string;
  };
  statistics: {
    total_hosts: number;
    fully_compatible: number;
    partially_compatible: number;
    incompatible: number;
  };
  hosts: Array<{
    id: string;
    hostname: string;
    os?: string;
    compatibility_score: number;
    is_compatible: boolean;
    issues: string[];
    warnings: string[];
  }>;
  issues: string[];
  recommendations: Array<{
    type: string;
    message: string;
    action: string;
  }>;
}

interface GroupCompatibilityReportProps {
  open: boolean;
  onClose: () => void;
  group: HostGroup;
}

const GroupCompatibilityReport: React.FC<GroupCompatibilityReportProps> = ({
  open,
  onClose,
  group,
}) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<CompatibilityReport | null>(null);

  useEffect(() => {
    if (open && group) {
      fetchCompatibilityReport();
    }
  }, [open, group]);

  const fetchCompatibilityReport = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch(`/api/host-groups/${group.id}/compatibility-report`, {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch compatibility report');
      }

      const data = await response.json();
      setReport(data);
    } catch (err) {
      console.error('Error fetching compatibility report:', err);
      setError(err instanceof Error ? err.message : 'Failed to load compatibility report');
    } finally {
      setLoading(false);
    }
  };

  const getCompatibilityColor = (score: number) => {
    if (score >= 95) return 'success';
    if (score >= 80) return 'info';
    if (score >= 60) return 'warning';
    return 'error';
  };

  const getCompatibilityIcon = (score: number) => {
    if (score >= 95) return <SuccessIcon color="success" />;
    if (score >= 80) return <InfoIcon color="info" />;
    if (score >= 60) return <WarningIcon color="warning" />;
    return <ErrorIcon color="error" />;
  };

  const getTrendIcon = (type: string) => {
    switch (type) {
      case 'improving':
        return <TrendingUpIcon color="success" />;
      case 'declining':
        return <TrendingDownIcon color="error" />;
      default:
        return <TrendingFlatIcon color="info" />;
    }
  };

  const getRecommendationSeverity = (type: string): 'error' | 'warning' | 'info' | 'success' => {
    switch (type) {
      case 'error':
        return 'error';
      case 'warning':
        return 'warning';
      case 'info':
        return 'info';
      default:
        return 'info';
    }
  };

  const renderOverviewStats = () => {
    if (!report) return null;

    const { statistics } = report;
    const totalHosts = statistics.total_hosts;
    const compatibilityRate =
      totalHosts > 0
        ? ((statistics.fully_compatible + statistics.partially_compatible) / totalHosts) * 100
        : 0;

    return (
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" color="primary">
                {statistics.total_hosts}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Total Hosts
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" color="success.main">
                {statistics.fully_compatible}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Fully Compatible
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" color="warning.main">
                {statistics.partially_compatible}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Partially Compatible
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" color="error.main">
                {statistics.incompatible}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Incompatible
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Overall Compatibility: {compatibilityRate.toFixed(1)}%
              </Typography>
              <LinearProgress
                variant="determinate"
                value={compatibilityRate}
                color={getCompatibilityColor(compatibilityRate)}
                sx={{ height: 10, borderRadius: 5 }}
              />
              <Box sx={{ mt: 1, display: 'flex', justifyContent: 'space-between' }}>
                <Typography variant="caption">
                  {statistics.fully_compatible + statistics.partially_compatible} compatible
                </Typography>
                <Typography variant="caption">{statistics.incompatible} incompatible</Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    );
  };

  const renderHostDetails = () => {
    if (!report || !report.hosts.length) return null;

    return (
      <Accordion defaultExpanded>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">Host Compatibility Details</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Host</TableCell>
                  <TableCell>Operating System</TableCell>
                  <TableCell>Compatibility Score</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Issues</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {report.hosts.map((host) => (
                  <TableRow key={host.id}>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <HostIcon />
                        <Box>
                          <Typography variant="body2" fontWeight="medium">
                            {host.hostname}
                          </Typography>
                        </Box>
                      </Box>
                    </TableCell>

                    <TableCell>
                      {host.os ? (
                        <Chip label={host.os} size="small" />
                      ) : (
                        <Typography variant="caption" color="text.secondary">
                          Unknown
                        </Typography>
                      )}
                    </TableCell>

                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Box sx={{ minWidth: 100 }}>
                          <LinearProgress
                            variant="determinate"
                            value={host.compatibility_score}
                            color={getCompatibilityColor(host.compatibility_score)}
                            sx={{ height: 6, borderRadius: 3 }}
                          />
                        </Box>
                        <Typography variant="caption">
                          {host.compatibility_score.toFixed(1)}%
                        </Typography>
                      </Box>
                    </TableCell>

                    <TableCell>
                      <Chip
                        icon={getCompatibilityIcon(host.compatibility_score)}
                        label={host.is_compatible ? 'Compatible' : 'Incompatible'}
                        color={host.is_compatible ? 'success' : 'error'}
                        size="small"
                      />
                    </TableCell>

                    <TableCell>
                      {host.issues.length > 0 ? (
                        <Tooltip title={host.issues.join('\n')}>
                          <Chip
                            label={`${host.issues.length} issue${host.issues.length !== 1 ? 's' : ''}`}
                            color="error"
                            size="small"
                          />
                        </Tooltip>
                      ) : host.warnings.length > 0 ? (
                        <Tooltip title={host.warnings.join('\n')}>
                          <Chip
                            label={`${host.warnings.length} warning${host.warnings.length !== 1 ? 's' : ''}`}
                            color="warning"
                            size="small"
                          />
                        </Tooltip>
                      ) : (
                        <Chip label="No issues" color="success" size="small" />
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </AccordionDetails>
      </Accordion>
    );
  };

  const renderIssuesAndRecommendations = () => {
    if (!report) return null;

    return (
      <Box sx={{ mt: 3 }}>
        {/* Common Issues */}
        {report.issues.length > 0 && (
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Common Issues ({report.issues.length})</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <List>
                {report.issues.map((issue, index) => (
                  <ListItem key={index}>
                    <ListItemIcon>
                      <ErrorIcon color="error" />
                    </ListItemIcon>
                    <ListItemText primary={issue} />
                  </ListItem>
                ))}
              </List>
            </AccordionDetails>
          </Accordion>
        )}

        {/* Recommendations */}
        {report.recommendations.length > 0 && (
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">
                Recommendations ({report.recommendations.length})
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                {report.recommendations.map((recommendation, index) => (
                  <Alert
                    key={index}
                    severity={getRecommendationSeverity(recommendation.type)}
                    action={
                      <Button color="inherit" size="small">
                        {recommendation.action}
                      </Button>
                    }
                  >
                    <Typography variant="body2">{recommendation.message}</Typography>
                  </Alert>
                ))}
              </Box>
            </AccordionDetails>
          </Accordion>
        )}
      </Box>
    );
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="lg"
      fullWidth
      PaperProps={{ sx: { minHeight: '70vh' } }}
    >
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <ReportIcon color="primary" />
          <Box>
            <Typography variant="h6">Compatibility Report: {group.name}</Typography>
            <Typography variant="body2" color="text.secondary">
              Detailed analysis of host compatibility with group requirements
            </Typography>
          </Box>
        </Box>
      </DialogTitle>

      <DialogContent>
        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
            <CircularProgress />
          </Box>
        ) : error ? (
          <Alert severity="error">{error}</Alert>
        ) : report ? (
          <Box>
            {/* Group Information */}
            <Paper sx={{ p: 2, mb: 3, bgcolor: 'background.default' }}>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" color="text.secondary">
                    OS Requirements
                  </Typography>
                  <Typography variant="body2">
                    {report.group.os_family} {report.group.os_version_pattern || 'Any version'}
                  </Typography>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Compliance Framework
                  </Typography>
                  <Typography variant="body2">
                    {report.group.compliance_framework || 'Not specified'}
                  </Typography>
                </Grid>
              </Grid>
            </Paper>

            {/* Overview Statistics */}
            {renderOverviewStats()}

            {/* Host Details */}
            {renderHostDetails()}

            {/* Issues and Recommendations */}
            {renderIssuesAndRecommendations()}
          </Box>
        ) : (
          <Typography color="text.secondary">No compatibility data available</Typography>
        )}
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose}>Close</Button>
        {report && (
          <Button variant="outlined" onClick={() => window.print()}>
            Print Report
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
};

export default GroupCompatibilityReport;
