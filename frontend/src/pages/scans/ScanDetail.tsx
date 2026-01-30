/**
 * ScanDetail Page
 *
 * Orchestrator component for scan detail view. All state, data fetching,
 * and handlers live in useScanDetail hook. Visual sections are delegated
 * to focused sub-components (<300 LOC each).
 *
 * Sub-components:
 *  - ScanMetricsCards: 4 info cards (host, scores, risk)
 *  - ScanOverviewTab: charts + summary stats / progress / error
 *  - ScanRulesTable: shared table for Failed Rules & All Rules tabs
 *  - ScanDialogs: Remediation stepper dialog + Export rule dialog
 *
 * @module pages/scans/ScanDetail
 */

import React from 'react';
import {
  Box,
  Paper,
  Typography,
  Chip,
  Button,
  IconButton,
  Tabs,
  Tab,
  Alert,
  CircularProgress,
  Tooltip,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Menu,
  MenuItem,
  Snackbar,
  Stack,
} from '@mui/material';
import Grid from '@mui/material/GridLegacy';
import {
  ArrowBack as ArrowBackIcon,
  CheckCircle as CheckCircleIcon,
  GetApp as DownloadIcon,
  Build as BuildIcon,
  MoreVert as MoreVertIcon,
  Refresh as RefreshIcon,
  PlayArrow as PlayArrowIcon,
  Print as PrintIcon,
  FilterList as FilterIcon,
} from '@mui/icons-material';
import RemediationPanel from '../../components/remediation/RemediationPanel';

import { useScanDetail } from './hooks/useScanDetail';
import { getStatusColor } from './components/scanUtils';
import { generateRemediationSteps } from './components/scanUtils';
import ScanMetricsCards from './components/ScanMetricsCards';
import ScanOverviewTab from './components/ScanOverviewTab';
import ScanRulesTable from './components/ScanRulesTable';
import { ScanRemediationDialog, ScanExportRuleDialog } from './components/ScanDialogs';

// ---------------------------------------------------------------------------
// TabPanel helper
// ---------------------------------------------------------------------------

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`scan-tabpanel-${index}`}
      aria-labelledby={`scan-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ pt: 3 }}>{children}</Box>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// ScanDetail
// ---------------------------------------------------------------------------

const ScanDetail: React.FC = () => {
  const {
    navigate,
    scan,
    filteredRules,
    loading,
    refreshing,
    isLoading,
    searchQuery,
    setSearchQuery,
    severityFilter,
    setSeverityFilter,
    resultFilter,
    setResultFilter,
    page,
    rowsPerPage,
    handleChangePage,
    handleChangeRowsPerPage,
    tabValue,
    handleTabChange,
    anchorEl,
    handleMenuOpen,
    handleMenuClose,
    snackbar,
    showSnackbar,
    closeSnackbar,
    remediationDialog,
    setRemediationDialog,
    exportRuleDialog,
    setExportRuleDialog,
    reviewedRules,
    handleToggleReview,
    handleRefresh,
    handleExportReport,
    handleRescan,
    handleRescanRule,
    handleExportRuleDetails,
    fetchScanDetails,
  } = useScanDetail();

  // --- Loading / not found guards ---

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="80vh">
        <CircularProgress />
      </Box>
    );
  }

  if (!scan) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Scan not found</Alert>
        <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/scans')} sx={{ mt: 2 }}>
          Back to Scans
        </Button>
      </Box>
    );
  }

  // --- Local callbacks for dialog actions ---

  const handleViewRemediation = (rule: typeof remediationDialog.rule) => {
    setRemediationDialog({ open: true, rule });
  };

  const handleExportRule = (rule: typeof exportRuleDialog.rule) => {
    setExportRuleDialog({ open: true, rule });
  };

  const handleCopyRemediationSteps = () => {
    if (remediationDialog.rule) {
      const steps = generateRemediationSteps(remediationDialog.rule);
      const text = steps
        .map(
          (step, i) =>
            `${i + 1}. ${step.title}\n${step.description}${step.command ? `\n\nCommand: ${step.command}` : ''}`
        )
        .join('\n\n---\n\n');
      navigator.clipboard.writeText(text);
      showSnackbar('Remediation steps copied to clipboard', 'success');
    }
  };

  // For the tab change that sets tabValue directly (quick action bar buttons)
  const setTabValue = (index: number) => {
    handleTabChange({} as React.SyntheticEvent, index);
  };

  // --- Render ---

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box display="flex" alignItems="center" gap={2}>
          <IconButton onClick={() => navigate('/scans')}>
            <ArrowBackIcon />
          </IconButton>
          <Typography variant="h4" component="h1">
            Scan Details
          </Typography>
          <Chip
            label={scan.status.toUpperCase()}
            color={getStatusColor(scan.status)}
            size="small"
          />
        </Box>

        <Box display="flex" gap={1}>
          <Button
            variant="outlined"
            startIcon={refreshing ? <CircularProgress size={20} /> : <RefreshIcon />}
            onClick={handleRefresh}
            disabled={refreshing}
          >
            Refresh
          </Button>
          <Button variant="outlined" startIcon={<DownloadIcon />} onClick={handleMenuOpen}>
            Export
          </Button>
          <IconButton onClick={handleMenuOpen}>
            <MoreVertIcon />
          </IconButton>
        </Box>
      </Box>

      {/* Quick Action Bar */}
      {scan.status === 'completed' && scan.results && (
        <Paper
          sx={{
            p: 2,
            mb: 3,
            borderRadius: 2,
            boxShadow: 2,
            bgcolor: scan.results.failed_rules > 0 ? 'error.50' : 'success.50',
          }}
        >
          <Stack direction="row" spacing={2} justifyContent="space-between" alignItems="center">
            <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
              {scan.results.failed_rules > 0 ? (
                <>
                  <Button
                    variant="contained"
                    color="error"
                    size="large"
                    startIcon={<BuildIcon />}
                    onClick={() => setTabValue(3)}
                  >
                    Remediate {scan.results.failed_rules} Failed Rules
                  </Button>
                  <Button
                    variant="outlined"
                    color="error"
                    startIcon={<FilterIcon />}
                    onClick={() => setTabValue(1)}
                  >
                    View Failures
                  </Button>
                </>
              ) : (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <CheckCircleIcon color="success" sx={{ fontSize: 40 }} />
                  <Box>
                    <Typography variant="h6" color="success.main" fontWeight="bold">
                      All Checks Passed!
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      System is compliant with the selected profile
                    </Typography>
                  </Box>
                </Box>
              )}
            </Box>

            <Box sx={{ display: 'flex', gap: 1 }}>
              <Tooltip title="Export report">
                <Button
                  variant="outlined"
                  startIcon={<DownloadIcon />}
                  onClick={handleMenuOpen}
                  size="medium"
                >
                  Export
                </Button>
              </Tooltip>
              <Tooltip title="Run new scan with same configuration">
                <Button
                  variant="outlined"
                  startIcon={<RefreshIcon />}
                  onClick={handleRescan}
                  size="medium"
                >
                  Rescan
                </Button>
              </Tooltip>
            </Box>
          </Stack>
        </Paper>
      )}

      {/* Metrics Cards */}
      <ScanMetricsCards scan={scan} />

      {/* Main Content Tabs */}
      <Paper sx={{ width: '100%' }}>
        <Tabs
          value={tabValue}
          onChange={handleTabChange}
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab label="Overview" />
          <Tab label="Failed Rules" />
          <Tab label="All Rules" />
          <Tab label="Remediation" />
          <Tab label="Scan Information" />
        </Tabs>

        {/* Tab 0: Overview */}
        <TabPanel value={tabValue} index={0}>
          <ScanOverviewTab scan={scan} />
        </TabPanel>

        {/* Tab 1: Failed Rules */}
        <TabPanel value={tabValue} index={1}>
          <ScanRulesTable
            variant="failed"
            filteredRules={filteredRules}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            severityFilter={severityFilter}
            onSeverityFilterChange={setSeverityFilter}
            resultFilter={resultFilter}
            onResultFilterChange={setResultFilter}
            page={page}
            rowsPerPage={rowsPerPage}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
            reviewedRules={reviewedRules}
            onToggleReview={handleToggleReview}
            onViewRemediation={handleViewRemediation}
            onExportRule={handleExportRule}
            onRescanRule={handleRescanRule}
            isLoading={isLoading}
          />
        </TabPanel>

        {/* Tab 2: All Rules */}
        <TabPanel value={tabValue} index={2}>
          <ScanRulesTable
            variant="all"
            filteredRules={filteredRules}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            severityFilter={severityFilter}
            onSeverityFilterChange={setSeverityFilter}
            resultFilter={resultFilter}
            onResultFilterChange={setResultFilter}
            page={page}
            rowsPerPage={rowsPerPage}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
            reviewedRules={reviewedRules}
            onToggleReview={handleToggleReview}
            onViewRemediation={handleViewRemediation}
            onExportRule={handleExportRule}
            onRescanRule={handleRescanRule}
            isLoading={isLoading}
          />
        </TabPanel>

        {/* Tab 3: Remediation */}
        <TabPanel value={tabValue} index={3}>
          <RemediationPanel
            scanId={scan.id?.toString() || ''}
            hostId={scan.host_id || ''}
            scanStatus={scan.status || ''}
            onRemediationStarted={() => {
              fetchScanDetails();
            }}
          />
        </TabPanel>

        {/* Tab 4: Scan Information */}
        <TabPanel value={tabValue} index={4}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom>
                Scan Configuration
              </Typography>
              <List>
                <ListItem>
                  <ListItemText primary="Scan Name" secondary={scan.name} />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Scan ID" secondary={scan.id} />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Profile ID" secondary={scan.profile_id} />
                </ListItem>
                <ListItem>
                  <ListItemText
                    primary="Started At"
                    secondary={new Date(scan.started_at).toLocaleString()}
                  />
                </ListItem>
                {scan.completed_at && (
                  <ListItem>
                    <ListItemText
                      primary="Completed At"
                      secondary={new Date(scan.completed_at).toLocaleString()}
                    />
                  </ListItem>
                )}
                <ListItem>
                  <ListItemText
                    primary="Duration"
                    secondary={
                      scan.completed_at
                        ? `${Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)} seconds`
                        : 'In progress...'
                    }
                  />
                </ListItem>
              </List>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="h6" gutterBottom>
                Technical Details
              </Typography>
              <List>
                <ListItem>
                  <ListItemText
                    primary="Result File"
                    secondary={scan.result_file || 'Not available'}
                  />
                </ListItem>
                <ListItem>
                  <ListItemText
                    primary="Report File"
                    secondary={scan.report_file || 'Not available'}
                  />
                </ListItem>
                {scan.error_message && (
                  <ListItem>
                    <ListItemText
                      primary="Error Message"
                      secondary={scan.error_message}
                      secondaryTypographyProps={{ color: 'error' }}
                    />
                  </ListItem>
                )}
              </List>

              {scan.scan_options &&
              typeof scan.scan_options === 'object' &&
              Object.keys(scan.scan_options as Record<string, unknown>).length > 0 ? (
                <>
                  <Typography variant="h6" gutterBottom sx={{ mt: 2 }}>
                    Scan Options
                  </Typography>
                  <Paper variant="outlined" sx={{ p: 2 }}>
                    <pre style={{ margin: 0, overflow: 'auto' }}>
                      {JSON.stringify(scan.scan_options, null, 2)}
                    </pre>
                  </Paper>
                </>
              ) : null}
            </Grid>
          </Grid>
        </TabPanel>
      </Paper>

      {/* Action Menu */}
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleMenuClose}>
        <MenuItem onClick={() => handleExportReport('html')}>
          <ListItemIcon>
            <DownloadIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Export as HTML</ListItemText>
        </MenuItem>
        <MenuItem onClick={() => handleExportReport('json')}>
          <ListItemIcon>
            <DownloadIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Export as JSON</ListItemText>
        </MenuItem>
        <MenuItem onClick={() => handleExportReport('csv')}>
          <ListItemIcon>
            <DownloadIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Export as CSV</ListItemText>
        </MenuItem>
        <Divider />
        <MenuItem onClick={handleRescan}>
          <ListItemIcon>
            <PlayArrowIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Run New Scan</ListItemText>
        </MenuItem>
        <MenuItem onClick={() => window.print()}>
          <ListItemIcon>
            <PrintIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Print Report</ListItemText>
        </MenuItem>
      </Menu>

      {/* Dialogs */}
      <ScanRemediationDialog
        open={remediationDialog.open}
        rule={remediationDialog.rule}
        onClose={() => setRemediationDialog({ open: false, rule: null })}
        onCopySteps={handleCopyRemediationSteps}
        showSnackbar={showSnackbar}
      />

      <ScanExportRuleDialog
        open={exportRuleDialog.open}
        rule={exportRuleDialog.rule}
        onClose={() => setExportRuleDialog({ open: false, rule: null })}
        onExport={handleExportRuleDetails}
      />

      {/* Snackbar */}
      <Snackbar open={snackbar.open} autoHideDuration={6000} onClose={closeSnackbar}>
        <Alert onClose={closeSnackbar} severity={snackbar.severity} sx={{ width: '100%' }}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default ScanDetail;
