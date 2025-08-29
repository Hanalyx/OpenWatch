import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
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
  Fab,
  Tooltip,
  LinearProgress,
  Divider,
  Paper,
  Stack,
  Avatar,
  Badge
} from '@mui/material';
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
  Settings as ConfigIcon
} from '@mui/icons-material';
import { useAppSelector } from '../../hooks/redux';
import SmartGroupCreationWizard from '../../components/host-groups/SmartGroupCreationWizard';
import GroupEditDialog from '../../components/host-groups/GroupEditDialog';
import GroupCompatibilityReport from '../../components/host-groups/GroupCompatibilityReport';
import ScanProgressDialog from '../../components/host-groups/ScanProgressDialog';
import BulkConfigurationDialog from '../../components/host-groups/BulkConfigurationDialog';
import { ScanService } from '../../services/scanService';

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
  validation_rules?: any;
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
  
  const user = useAppSelector((state) => state.auth.user);

  useEffect(() => {
    fetchGroups();
  }, []);

  const fetchGroups = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch('/api/host-groups/', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
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
    
    if (!confirm(`Are you sure you want to delete the group "${selectedGroup.name}"? All hosts will be ungrouped.`)) {
      handleMenuClose();
      return;
    }

    try {
      const response = await fetch(`/api/host-groups/${selectedGroup.id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
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
        setError('Cannot scan group: SCAP content and profile must be configured. Click Edit Group to add compliance configuration.');
        handleMenuClose();
        return;
      }
      
      // Initiate group scan using the scan service
      const scanSession = await ScanService.startGroupScan(selectedGroup.id, {
        scan_name: `${selectedGroup.name} Compliance Scan`,
        profile_id: selectedGroup.default_profile_id,
        priority: 'normal'
      });
      
      // Show scan progress dialog
      setActiveScanSession(scanSession.session_id);
      setShowScanProgress(true);
      handleMenuClose();
      
    } catch (err) {
      console.error('Error starting group scan:', err);
      setScanError(err instanceof Error ? err.message : 'Failed to start group scan');
      setError(err instanceof Error ? err.message : 'Failed to start group scan');
      handleMenuClose();
    }
  };

  const handleViewCompatibility = () => {
    setShowCompatibilityReport(true);
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
    const hasCompatibilityIssues = group.compatibility_summary && 
      group.compatibility_summary.incompatible_hosts > 0;

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
            transition: 'all 0.2s ease-in-out'
          }
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
            borderRadius: '4px 0 0 4px'
          }} 
        />
        
        <CardContent sx={{ flexGrow: 1, pl: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
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
            
            <IconButton
              onClick={(e) => handleMenuOpen(e, group)}
              size="small"
              sx={{ ml: 1 }}
            >
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
                label={group.scap_content_name || "SCAP Configured"}
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
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
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
                  <Typography 
                    variant="body2" 
                    color={getComplianceScoreColor(compatibilityScore)}
                  >
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
                  {group.compatibility_summary.compatible_hosts}/{group.compatibility_summary.total_hosts}
                </Typography>
              </Box>
              <LinearProgress
                variant="determinate"
                value={(group.compatibility_summary.compatible_hosts / group.compatibility_summary.total_hosts) * 100}
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
          {group.host_count > 0 && group.scap_content_id && group.default_profile_id ? (
            <Chip
              icon={<ScanIcon />}
              label="Scan Ready"
              size="small"
              color="success"
              variant="outlined"
              sx={{ mt: 1 }}
            />
          ) : (
            <Chip
              icon={<WarningIcon />}
              label={
                group.host_count === 0 
                  ? "No hosts assigned" 
                  : "SCAP content required"
              }
              size="small"
              color="warning"
              variant="outlined"
              sx={{ mt: 1 }}
            />
          )}

          {/* Warning for compatibility issues */}
          {hasCompatibilityIssues && (
            <Alert severity="warning" sx={{ mt: 1 }}>
              {group.compatibility_summary!.incompatible_hosts} incompatible hosts detected
            </Alert>
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
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
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
            {groups.some(g => !g.scap_content_id || !g.default_profile_id) && (
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
                  {groups.filter(g => g.auto_scan_enabled).length}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Auto-scan Enabled
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={3}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h4" color="warning.main">
                  {groups.filter(g => 
                    g.compatibility_summary && 
                    g.compatibility_summary.incompatible_hosts > 0
                  ).length}
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
            Create your first compliance group to organize hosts by OS, compliance framework, and SCAP content
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
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
      >
        <MenuItem onClick={handleViewCompatibility}>
          <ListItemIcon>
            <ViewIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>View Compatibility</ListItemText>
        </MenuItem>
        
        <MenuItem 
          onClick={handleScanGroup}
          disabled={!selectedGroup || selectedGroup.host_count === 0 || !selectedGroup.scap_content_id || !selectedGroup.default_profile_id}
        >
          <ListItemIcon>
            <ScanIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>
            Run Group Scan
            {selectedGroup && (
              selectedGroup.host_count === 0 
                ? " (No hosts)" 
                : !selectedGroup.scap_content_id || !selectedGroup.default_profile_id 
                  ? " (SCAP configuration required - Click Edit Group)"
                  : ""
            )}
          </ListItemText>
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
              await ScanService.cancelGroupScan(selectedGroup.id, sessionId);
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
    </Box>
  );
};

export default ComplianceGroups;