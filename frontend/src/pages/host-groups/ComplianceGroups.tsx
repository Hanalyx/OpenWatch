import React, { useState, useEffect } from 'react';
import { storageGet, StorageKeys } from '../../services/storage';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Chip,
  Button,
  IconButton,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Dialog,
  DialogTitle,
  DialogContent,
  Alert,
  Tooltip,
  LinearProgress,
  Divider,
  Paper,
  Stack,
  Badge,
} from '@mui/material';
import Grid from '@mui/material/GridLegacy';
import {
  Add as AddIcon,
  MoreVert as MoreIcon,
  Group as GroupIcon,
  Computer as HostIcon,
  Security as SecurityIcon,
  Assessment as ComplianceIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  PlayArrow as ScanIcon,
  Visibility as ViewIcon,
  CheckCircle,
  CheckCircle as SuccessIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Schedule as ScheduleIcon,
  Settings as ConfigIcon,
} from '@mui/icons-material';
import { useAppSelector } from '../../hooks/redux';
import SmartGroupCreationWizard from '../../components/host-groups/SmartGroupCreationWizard';
import GroupEditDialog from '../../components/host-groups/GroupEditDialog';
import GroupCompatibilityReport from '../../components/host-groups/GroupCompatibilityReport';
import ScanProgressDialog from '../../components/host-groups/ScanProgressDialog';
import BulkConfigurationDialog from '../../components/host-groups/BulkConfigurationDialog';
import { GroupComplianceScanner, GroupComplianceReport } from '../../components/GroupCompliance';
// ScanService removed - using unified host-groups API

interface HostGroup {
  id: number;
  name: string;
  description?: string;
  color?: string;
  host_count: number;
  created_by: number;
  created_at: string;
  updated_at: string;
  os_family?: string;
  os_version_pattern?: string;
  architecture?: string;
  scap_content_id?: number;
  default_profile_id?: string;
  compliance_framework?: string;
  auto_scan_enabled: boolean;
  scan_schedule?: string;
  // Validation rules structure from backend (varies by compliance framework)
  validation_rules?: Record<string, unknown>;
  scap_content_name?: string;
  compatibility_summary?: {
    total_hosts: number;
    compatible_hosts: number;
    incompatible_hosts: number;
    compatibility_score: number;
  };
}

const ComplianceGroups: React.FC = () => {
  const [groups, setGroups] = useState<HostGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [selectedGroup, setSelectedGroup] = useState<HostGroup | null>(null);
  const [showCreateWizard, setShowCreateWizard] = useState(false);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [showCompatibilityReport, setShowCompatibilityReport] = useState(false);
  const [showScanProgress, setShowScanProgress] = useState(false);
  const [showBulkConfig, setShowBulkConfig] = useState(false);
  const [activeScanSession, setActiveScanSession] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [showComplianceScanner, setShowComplianceScanner] = useState(false);
  const [showComplianceReport, setShowComplianceReport] = useState(false);
  const [complianceGroup, setComplianceGroup] = useState<HostGroup | null>(null);

  // User data from auth state - reserved for future user-specific group permissions
  const _user = useAppSelector((state) => state.auth.user);

  useEffect(() => {
    fetchGroups();
  }, []);

  const fetchGroups = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch('/api/host-groups/', {
        headers: {
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to fetch compliance groups');
      }

      const data = await response.json();
      setGroups(data);
    } catch (err) {
      console.error('Error fetching compliance groups:', err);
      setError(err instanceof Error ? err.message : 'Failed to load compliance groups');
    } finally {
      setLoading(false);
    }
  };

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>, group: HostGroup) => {
    setAnchorEl(event.currentTarget);
    setSelectedGroup(group);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
    setSelectedGroup(null);
  };

  const handleEditGroup = () => {
    setShowEditDialog(true);
    handleMenuClose();
  };

  const handleDeleteGroup = async () => {
    if (!selectedGroup) return;

    if (
      !confirm(
        `Are you sure you want to delete the group "${selectedGroup.name}"? All hosts will be ungrouped.`
      )
    ) {
      handleMenuClose();
      return;
    }

    try {
      const response = await fetch(`/api/host-groups/${selectedGroup.id}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
      });

      if (!response.ok) {
        throw new Error('Failed to delete group');
      }

      await fetchGroups();
      handleMenuClose();
    } catch (err) {
      console.error('Error deleting group:', err);
      setError(err instanceof Error ? err.message : 'Failed to delete group');
    }
  };

  const handleScanGroup = async () => {
    if (!selectedGroup) return;

    try {
      setScanError(null);
      setError(null);

      // Check if group has hosts
      if (selectedGroup.host_count === 0) {
        setError('Cannot scan group: No hosts assigned to this group');
        handleMenuClose();
        return;
      }

      // Check if group has SCAP content configured
      if (!selectedGroup.scap_content_id || !selectedGroup.default_profile_id) {
        setError(
          'Cannot scan group: SCAP content and profile must be configured. Click Edit Group to add compliance configuration.'
        );
        handleMenuClose();
        return;
      }

      // Use unified host-groups API
      const response = await fetch(`/api/host-groups/${selectedGroup.id}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
        body: JSON.stringify({
          scap_content_id: selectedGroup.scap_content_id,
          profile_id: selectedGroup.default_profile_id,
          compliance_framework: selectedGroup.compliance_framework,
          remediation_mode: 'report_only',
          email_notifications: false,
          generate_reports: true,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to start compliance scan');
      }

      const scanData = await response.json();
      setActiveScanSession(scanData.session_id);
      setShowScanProgress(true);
      handleMenuClose();

      // Show success message
      setError(`✅ Compliance scan started successfully. Session: ${scanData.session_id}`);
      setTimeout(() => setError(null), 5000);
    } catch (err) {
      console.error('Error starting group scan:', err);
      const errorMessage = err instanceof Error ? err.message : 'Failed to start group scan';
      setScanError(errorMessage);
      setError(
        `❌ ${errorMessage}. Please check that the group has hosts assigned and SCAP content configured.`
      );
      handleMenuClose();
    }
  };

  const handleViewCompatibility = () => {
    setShowCompatibilityReport(true);
    handleMenuClose();
  };

  const handleComplianceScanning = () => {
    if (selectedGroup) {
      setComplianceGroup(selectedGroup);
      setShowComplianceScanner(true);
    }
    handleMenuClose();
  };

  const handleComplianceReport = () => {
    if (selectedGroup) {
      setComplianceGroup(selectedGroup);
      setShowComplianceReport(true);
    }
    handleMenuClose();
  };

  const getComplianceScoreColor = (score: number) => {
    if (score >= 95) return 'success';
    if (score >= 80) return 'info';
    if (score >= 60) return 'warning';
    return 'error';
  };

  const getComplianceScoreIcon = (score: number) => {
    if (score >= 95) return <SuccessIcon />;
    if (score >= 80) return <InfoIcon />;
    if (score >= 60) return <WarningIcon />;
    return <ErrorIcon />;
  };

  const renderGroupCard = (group: HostGroup) => {
    const compatibilityScore = group.compatibility_summary?.compatibility_score || 0;
    const hasCompatibilityIssues =
      group.compatibility_summary && group.compatibility_summary.incompatible_hosts > 0;

    return (
      <Card
        key={group.id}
        sx={{
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          position: 'relative',
          '&:hover': {
            boxShadow: 4,
            transform: 'translateY(-2px)',
            transition: 'all 0.2s ease-in-out',
          },
        }}
      >
        {/* Group Color Indicator */}
        <Box
          sx={{
            position: 'absolute',
            top: 0,
            left: 0,
            width: '4px',
            height: '100%',
            bgcolor: group.color || '#666',
            borderRadius: '4px 0 0 4px',
          }}
        />

        <CardContent sx={{ flexGrow: 1, pl: 3 }}>
          <Box
            sx={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'flex-start',
              mb: 2,
            }}
          >
            <Box sx={{ flexGrow: 1 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <Typography variant="h6" component="h2">
                  {group.name}
                </Typography>

                {/* SCAP Configuration Status Indicator */}
                {group.scap_content_id && group.default_profile_id ? (
                  <Tooltip title="SCAP configuration complete - Ready to scan">
                    <CheckCircle sx={{ color: 'success.main', fontSize: 20 }} />
                  </Tooltip>
                ) : (
                  <Tooltip title="SCAP configuration required - Click Edit Group to configure">
                    <WarningIcon sx={{ color: 'warning.main', fontSize: 20 }} />
                  </Tooltip>
                )}
              </Box>

              {group.description && (
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  {group.description}
                </Typography>
              )}
            </Box>

            <IconButton onClick={(e) => handleMenuOpen(e, group)} size="small" sx={{ ml: 1 }}>
              <MoreIcon />
            </IconButton>
          </Box>

          {/* Group Configuration */}
          <Stack spacing={1} sx={{ mb: 2 }}>
            {group.os_family && (
              <Chip
                icon={<HostIcon />}
                label={`${group.os_family} ${group.os_version_pattern || ''}`}
                size="small"
                variant="outlined"
              />
            )}

            {group.compliance_framework && (
              <Chip
                icon={<SecurityIcon />}
                label={group.compliance_framework}
                size="small"
                color="primary"
                variant="outlined"
              />
            )}

            {/* SCAP Configuration Status Chip */}
            {group.scap_content_id && group.default_profile_id ? (
              <Chip
                icon={<CheckCircle />}
                label={group.scap_content_name || 'SCAP Configured'}
                size="small"
                color="success"
                variant="filled"
              />
            ) : (
              <Chip
                icon={<WarningIcon />}
                label="SCAP Config Required"
                size="small"
                color="warning"
                variant="filled"
              />
            )}
          </Stack>

          {/* Host Count and Compatibility */}
          <Box
            sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Badge badgeContent={group.host_count} color="primary">
                <HostIcon />
              </Badge>
              <Typography variant="body2">
                {group.host_count} host{group.host_count !== 1 ? 's' : ''}
              </Typography>
            </Box>

            {group.compatibility_summary && (
              <Tooltip title={`Compatibility: ${compatibilityScore.toFixed(1)}%`}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  {getComplianceScoreIcon(compatibilityScore)}
                  <Typography variant="body2" color={getComplianceScoreColor(compatibilityScore)}>
                    {compatibilityScore.toFixed(1)}%
                  </Typography>
                </Box>
              </Tooltip>
            )}
          </Box>

          {/* Compatibility Progress Bar */}
          {group.compatibility_summary && (
            <Box sx={{ mb: 2 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                <Typography variant="caption">Compatibility</Typography>
                <Typography variant="caption">
                  {group.compatibility_summary.compatible_hosts}/
                  {group.compatibility_summary.total_hosts}
                </Typography>
              </Box>
              <LinearProgress
                variant="determinate"
                value={
                  (group.compatibility_summary.compatible_hosts /
                    group.compatibility_summary.total_hosts) *
                  100
                }
                color={getComplianceScoreColor(compatibilityScore)}
                sx={{ height: 6, borderRadius: 3 }}
              />
            </Box>
          )}

          {/* Auto-scan Status */}
          {group.auto_scan_enabled && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 1 }}>
              <ScheduleIcon color="primary" fontSize="small" />
              <Typography variant="caption" color="primary">
                Auto-scan: {group.scan_schedule || 'Enabled'}
              </Typography>
            </Box>
          )}

          {/* Scan Readiness Status */}
          <Box sx={{ display: 'flex', gap: 1, mt: 1, flexWrap: 'wrap' }}>
            {group.host_count > 0 && group.scap_content_id && group.default_profile_id ? (
              <Chip
                icon={<ScanIcon />}
                label="Scan Ready"
                size="small"
                color="success"
                variant="outlined"
              />
            ) : (
              <Chip
                icon={<WarningIcon />}
                label={group.host_count === 0 ? 'No hosts assigned' : 'SCAP content required'}
                size="small"
                color="warning"
                variant="outlined"
              />
            )}

            {/* Compliance Framework Indicator */}
            {group.compliance_framework && (
              <Chip
                icon={<SecurityIcon />}
                label={group.compliance_framework.toUpperCase()}
                size="small"
                color="primary"
                variant="outlined"
              />
            )}

            {/* Advanced Compliance Features Indicator */}
            {group.host_count > 0 && (
              <Chip
                icon={<ComplianceIcon />}
                label="Compliance Reports Available"
                size="small"
                color="info"
                variant="outlined"
                onClick={(e) => {
                  e.stopPropagation();
                  setComplianceGroup(group);
                  setShowComplianceReport(true);
                }}
                sx={{ cursor: 'pointer' }}
              />
            )}
          </Box>

          {/* Warning for compatibility issues */}
          {hasCompatibilityIssues && (
            <Alert severity="warning" sx={{ mt: 1 }}>
              {group.compatibility_summary!.incompatible_hosts} incompatible hosts detected
            </Alert>
          )}

          {/* Quick Action Buttons */}
          {group.host_count > 0 && (
            <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
              <Button
                size="small"
                variant="outlined"
                startIcon={<SecurityIcon />}
                onClick={(e) => {
                  e.stopPropagation();
                  setComplianceGroup(group);
                  setShowComplianceScanner(true);
                }}
                disabled={group.host_count === 0}
              >
                Advanced Scan
              </Button>
              <Button
                size="small"
                variant="outlined"
                startIcon={<ComplianceIcon />}
                onClick={(e) => {
                  e.stopPropagation();
                  setComplianceGroup(group);
                  setShowComplianceReport(true);
                }}
              >
                Report
              </Button>
            </Box>
          )}
        </CardContent>
      </Card>
    );
  };

  if (loading) {
    return (
      <Box sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
          <LinearProgress sx={{ width: '100%' }} />
        </Box>
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Box>
            <Typography variant="h4" component="h1" gutterBottom>
              Compliance Groups
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Organize hosts into smart compliance groups with automated validation and scanning
            </Typography>
          </Box>

          <Box sx={{ display: 'flex', gap: 2 }}>
            {/* Show bulk config button only if there are unconfigured groups */}
            {groups.some((g) => !g.scap_content_id || !g.default_profile_id) && (
              <Button
                variant="outlined"
                startIcon={<ConfigIcon />}
                onClick={() => setShowBulkConfig(true)}
                size="large"
                color="warning"
              >
                Bulk Configure SCAP
              </Button>
            )}

            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={() => setShowCreateWizard(true)}
              size="large"
            >
              Create Group
            </Button>
          </Box>
        </Box>

        {/* Stats Summary */}
        <Paper sx={{ p: 2, mb: 3 }}>
          <Grid container spacing={3}>
            <Grid item xs={12} sm={3}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h4" color="primary">
                  {groups.length}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Total Groups
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={3}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h4" color="secondary">
                  {groups.reduce((sum, group) => sum + group.host_count, 0)}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Managed Hosts
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={3}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h4" color="success.main">
                  {groups.filter((g) => g.auto_scan_enabled).length}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Auto-scan Enabled
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={3}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h4" color="warning.main">
                  {
                    groups.filter(
                      (g) =>
                        g.compatibility_summary && g.compatibility_summary.incompatible_hosts > 0
                    ).length
                  }
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Need Attention
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </Paper>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {scanError && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setScanError(null)}>
          {scanError}
        </Alert>
      )}

      {/* Groups Grid */}
      {groups.length === 0 ? (
        <Box sx={{ textAlign: 'center', py: 8 }}>
          <GroupIcon sx={{ fontSize: 96, color: 'text.secondary', mb: 2 }} />
          <Typography variant="h5" color="text.secondary" gutterBottom>
            No Compliance Groups
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Create your first compliance group to organize hosts by OS, compliance framework, and
            SCAP content
          </Typography>
          <Button
            variant="contained"
            size="large"
            startIcon={<AddIcon />}
            onClick={() => setShowCreateWizard(true)}
          >
            Create Your First Group
          </Button>
        </Box>
      ) : (
        <Grid container spacing={3}>
          {groups.map((group) => (
            <Grid item xs={12} sm={6} md={4} key={group.id}>
              {renderGroupCard(group)}
            </Grid>
          ))}
        </Grid>
      )}

      {/* Context Menu */}
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleMenuClose}>
        <MenuItem onClick={handleViewCompatibility}>
          <ListItemIcon>
            <ViewIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>View Compatibility</ListItemText>
        </MenuItem>

        <MenuItem
          onClick={handleScanGroup}
          disabled={
            !selectedGroup ||
            selectedGroup.host_count === 0 ||
            !selectedGroup.scap_content_id ||
            !selectedGroup.default_profile_id
          }
        >
          <ListItemIcon>
            <ScanIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>
            Run Group Scan
            {selectedGroup &&
              (selectedGroup.host_count === 0
                ? ' (No hosts)'
                : !selectedGroup.scap_content_id || !selectedGroup.default_profile_id
                  ? ' (SCAP configuration required - Click Edit Group)'
                  : '')}
          </ListItemText>
        </MenuItem>

        <MenuItem
          onClick={handleComplianceScanning}
          disabled={!selectedGroup || selectedGroup.host_count === 0}
        >
          <ListItemIcon>
            <SecurityIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Advanced Compliance Scan</ListItemText>
        </MenuItem>

        <MenuItem onClick={handleComplianceReport}>
          <ListItemIcon>
            <ComplianceIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Compliance Report</ListItemText>
        </MenuItem>

        <Divider />

        <MenuItem onClick={handleEditGroup}>
          <ListItemIcon>
            <EditIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Edit Group</ListItemText>
        </MenuItem>

        <MenuItem onClick={handleDeleteGroup} sx={{ color: 'error.main' }}>
          <ListItemIcon>
            <DeleteIcon fontSize="small" color="error" />
          </ListItemIcon>
          <ListItemText>Delete Group</ListItemText>
        </MenuItem>
      </Menu>

      {/* Smart Group Creation Wizard */}
      <SmartGroupCreationWizard
        open={showCreateWizard}
        onClose={() => setShowCreateWizard(false)}
        onGroupCreated={fetchGroups}
      />

      {/* Group Edit Dialog */}
      {selectedGroup && (
        <GroupEditDialog
          open={showEditDialog}
          onClose={() => setShowEditDialog(false)}
          group={selectedGroup}
          onGroupUpdated={fetchGroups}
        />
      )}

      {/* Group Compatibility Report */}
      {selectedGroup && (
        <GroupCompatibilityReport
          open={showCompatibilityReport}
          onClose={() => setShowCompatibilityReport(false)}
          group={selectedGroup}
        />
      )}

      {/* Scan Progress Dialog */}
      {selectedGroup && activeScanSession && (
        <ScanProgressDialog
          open={showScanProgress}
          onClose={() => setShowScanProgress(false)}
          sessionId={activeScanSession}
          groupId={selectedGroup.id}
          groupName={selectedGroup.name}
          onCancel={async (sessionId: string) => {
            try {
              const response = await fetch(
                `/api/host-groups/${selectedGroup.id}/scan-sessions/${sessionId}/cancel`,
                {
                  method: 'POST',
                  headers: {
                    Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
                  },
                }
              );
              if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Failed to cancel scan');
              }
            } catch (err) {
              console.error('Error cancelling scan:', err);
              setScanError(err instanceof Error ? err.message : 'Failed to cancel scan');
            }
          }}
          onViewResults={(scanId: string) => {
            // Navigate to scan results view
            window.open(`/scans/${scanId}/results`, '_blank');
          }}
        />
      )}

      {/* Bulk Configuration Dialog */}
      <BulkConfigurationDialog
        open={showBulkConfig}
        onClose={() => setShowBulkConfig(false)}
        groups={groups}
        onConfigurationComplete={fetchGroups}
      />

      {/* Advanced Compliance Scanner Dialog */}
      <Dialog
        open={showComplianceScanner}
        onClose={() => setShowComplianceScanner(false)}
        maxWidth="lg"
        fullWidth
      >
        <DialogTitle>Advanced Compliance Scanning - {complianceGroup?.name}</DialogTitle>
        <DialogContent>
          {complianceGroup && (
            <GroupComplianceScanner
              groupId={complianceGroup.id}
              groupName={complianceGroup.name}
              onScanStarted={(sessionId) => {
                setActiveScanSession(sessionId);
                setShowScanProgress(true);
                setShowComplianceScanner(false);
              }}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* Compliance Report Dialog */}
      <Dialog
        open={showComplianceReport}
        onClose={() => setShowComplianceReport(false)}
        maxWidth="xl"
        fullWidth
      >
        <DialogTitle>Compliance Report - {complianceGroup?.name}</DialogTitle>
        <DialogContent>
          {complianceGroup && (
            <GroupComplianceReport groupId={complianceGroup.id} groupName={complianceGroup.name} />
          )}
        </DialogContent>
      </Dialog>
    </Box>
  );
};

export default ComplianceGroups;
