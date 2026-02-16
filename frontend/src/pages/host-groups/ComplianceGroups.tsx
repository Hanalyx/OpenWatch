import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { storageGet, StorageKeys } from '../../services/storage';
import {
  Box,
  Card,
  CardContent,
  Typography,
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
  LinearProgress,
  Divider,
  Paper,
  Snackbar,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  Add as AddIcon,
  MoreVert as MoreIcon,
  Group as GroupIcon,
  Computer as HostIcon,
  Assessment as ComplianceIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  PlayCircleOutline as QuickScanIcon,
} from '@mui/icons-material';
import { useAppSelector } from '../../hooks/redux';
import SmartGroupCreationWizard from '../../components/host-groups/SmartGroupCreationWizard';
import GroupEditDialog from '../../components/host-groups/GroupEditDialog';
import { GroupComplianceReport } from '../../components/GroupCompliance';

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
  compliance_framework?: string;
  auto_scan_enabled: boolean;
  scan_schedule?: string;
  // Validation rules structure from backend (varies by compliance framework)
  validation_rules?: Record<string, unknown>;
  compatibility_summary?: {
    total_hosts: number;
    compatible_hosts: number;
    incompatible_hosts: number;
    compatibility_score: number;
  };
}

const ComplianceGroups: React.FC = () => {
  const navigate = useNavigate();
  const [groups, setGroups] = useState<HostGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [selectedGroup, setSelectedGroup] = useState<HostGroup | null>(null);
  const [showCreateWizard, setShowCreateWizard] = useState(false);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [editingGroup, setEditingGroup] = useState<HostGroup | null>(null);
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
    if (selectedGroup) {
      setEditingGroup(selectedGroup);
      setShowEditDialog(true);
    }
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

  const handleViewScans = (group: HostGroup, event?: React.MouseEvent) => {
    if (event) {
      event.stopPropagation();
    }
    // Navigate to scans page filtered by hosts in this group
    navigate(`/scans?host_group_id=${group.id}`);
  };

  const handleComplianceReport = (group: HostGroup, event?: React.MouseEvent) => {
    if (event) {
      event.stopPropagation();
    }
    setComplianceGroup(group);
    setShowComplianceReport(true);
  };

  const handleQuickScan = async (group: HostGroup, event?: React.MouseEvent) => {
    // Prevent event bubbling if called from button click
    if (event) {
      event.stopPropagation();
    }

    // Check if group has hosts
    if (group.host_count === 0) {
      setError('Cannot scan group: No hosts assigned to this group');
      return;
    }

    try {
      setError(null);
      setSuccessMessage(null);

      // Use quick scan endpoint with host_group_id
      const response = await fetch('/api/scans/quick', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
        body: JSON.stringify({
          host_group_id: group.id,
          framework: 'cis', // Default to CIS
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to start quick scan');
      }

      const scanData = await response.json();

      // Show success message with scan count
      setSuccessMessage(
        `Queued ${scanData.scan_count} scan(s) for "${group.name}". Click View to monitor progress.`
      );
    } catch (err) {
      console.error('Error starting quick scan:', err);
      const errorMessage = err instanceof Error ? err.message : 'Failed to start quick scan';
      setError(errorMessage);
    }
  };

  const renderGroupCard = (group: HostGroup) => {
    return (
      <Card
        key={group.id}
        sx={{
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          '&:hover': {
            boxShadow: 4,
            transform: 'translateY(-2px)',
            transition: 'all 0.2s ease-in-out',
          },
        }}
      >
        <CardContent sx={{ flexGrow: 1 }}>
          {/* Header: Name + Menu */}
          <Box
            sx={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'flex-start',
              mb: 1,
            }}
          >
            <Typography variant="h6" component="h2">
              {group.name}
            </Typography>
            <IconButton onClick={(e) => handleMenuOpen(e, group)} size="small">
              <MoreIcon />
            </IconButton>
          </Box>

          {/* Description */}
          {group.description && (
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              {group.description}
            </Typography>
          )}

          {/* Host count + OS info */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
            <HostIcon fontSize="small" color="action" />
            <Typography variant="body2">
              {group.host_count} host{group.host_count !== 1 ? 's' : ''}
              {group.os_family &&
                ` • ${group.os_family}${group.os_version_pattern ? ` ${group.os_version_pattern}` : ''}`}
            </Typography>
          </Box>

          {/* Action Buttons */}
          <Box sx={{ display: 'flex', gap: 1, mt: 'auto' }}>
            <Button
              size="small"
              variant="contained"
              color="primary"
              startIcon={<QuickScanIcon />}
              onClick={(e) => handleQuickScan(group, e)}
              disabled={group.host_count === 0}
            >
              Scan
            </Button>
            <Button
              size="small"
              variant="outlined"
              startIcon={<ViewIcon />}
              onClick={(e) => handleViewScans(group, e)}
            >
              View
            </Button>
            <Button
              size="small"
              variant="outlined"
              startIcon={<ComplianceIcon />}
              onClick={(e) => handleComplianceReport(group, e)}
            >
              Report
            </Button>
          </Box>
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

          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setShowCreateWizard(true)}
            size="large"
          >
            Create Group
          </Button>
        </Box>

        {/* Stats Summary */}
        <Paper sx={{ p: 2, mb: 3 }}>
          <Grid container spacing={3}>
            <Grid size={{ xs: 12, sm: 3 }}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h4" color="primary">
                  {groups.length}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Total Groups
                </Typography>
              </Box>
            </Grid>
            <Grid size={{ xs: 12, sm: 3 }}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h4" color="secondary">
                  {groups.reduce((sum, group) => sum + group.host_count, 0)}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Managed Hosts
                </Typography>
              </Box>
            </Grid>
            <Grid size={{ xs: 12, sm: 3 }}>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h4" color="success.main">
                  {groups.filter((g) => g.auto_scan_enabled).length}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Auto-scan Enabled
                </Typography>
              </Box>
            </Grid>
            <Grid size={{ xs: 12, sm: 3 }}>
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

      {/* Success Snackbar - moved to end of component for better positioning */}

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
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
            <Grid size={{ xs: 12, sm: 6, md: 4 }} key={group.id}>
              {renderGroupCard(group)}
            </Grid>
          ))}
        </Grid>
      )}

      {/* Context Menu */}
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleMenuClose}>
        <MenuItem
          onClick={() => {
            if (selectedGroup) {
              handleQuickScan(selectedGroup);
            }
            handleMenuClose();
          }}
          disabled={!selectedGroup || selectedGroup.host_count === 0}
        >
          <ListItemIcon>
            <QuickScanIcon fontSize="small" color="primary" />
          </ListItemIcon>
          <ListItemText>
            <Typography color="primary" fontWeight="medium">
              Scan Group
            </Typography>
          </ListItemText>
        </MenuItem>

        <MenuItem
          onClick={() => {
            if (selectedGroup) {
              handleViewScans(selectedGroup);
            }
            handleMenuClose();
          }}
        >
          <ListItemIcon>
            <ViewIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>View Scans</ListItemText>
        </MenuItem>

        <MenuItem
          onClick={() => {
            if (selectedGroup) {
              handleComplianceReport(selectedGroup);
            }
            handleMenuClose();
          }}
        >
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
      {editingGroup && (
        <GroupEditDialog
          open={showEditDialog}
          onClose={() => {
            setShowEditDialog(false);
            setEditingGroup(null);
          }}
          group={editingGroup}
          onGroupUpdated={fetchGroups}
        />
      )}

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

      {/* Success Snackbar */}
      <Snackbar
        open={Boolean(successMessage)}
        autoHideDuration={8000}
        onClose={() => setSuccessMessage(null)}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
      >
        <Alert
          onClose={() => setSuccessMessage(null)}
          severity="success"
          variant="filled"
          sx={{ width: '100%' }}
        >
          {successMessage}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default ComplianceGroups;
