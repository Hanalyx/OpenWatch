import React, { useState, useEffect } from 'react';
import { storageGet, StorageKeys } from '../../services/storage';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Box,
  Typography,
  FormControlLabel,
  Switch,
  Alert,
  CircularProgress,
  Divider,
  Chip,
  Paper,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  ListItemSecondaryAction,
  IconButton,
  Tooltip,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  Edit as EditIcon,
  Computer as HostIcon,
  Add as AddIcon,
  Remove as RemoveIcon,
} from '@mui/icons-material';
import {
  OS_FAMILY_OPTIONS,
  ARCHITECTURE_OPTIONS,
  COMPLIANCE_FRAMEWORK_OPTIONS,
  SCAN_SCHEDULE_OPTIONS,
} from '../../constants/formOptions';

interface Host {
  id: string;
  hostname: string;
  ip_address: string;
  operating_system?: string;
  os_family?: string;
  os_version?: string;
}

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
  // Flexible validation rules object from backend - structure varies by validation type
  // May include: required_fields, pattern_matchers, custom_validators, etc.
  validation_rules?: Record<string, unknown>;
}

interface GroupEditDialogProps {
  open: boolean;
  onClose: () => void;
  group: HostGroup;
  onGroupUpdated: () => void;
}

const DEFAULT_COLORS = [
  '#1976d2', // Blue
  '#388e3c', // Green
  '#f57c00', // Orange
  '#7b1fa2', // Purple
  '#d32f2f', // Red
  '#00796b', // Teal
  '#5d4037', // Brown
  '#616161', // Grey
];

const GroupEditDialog: React.FC<GroupEditDialogProps> = ({
  open,
  onClose,
  group,
  onGroupUpdated,
}) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Form fields
  const [name, setName] = useState(group.name);
  const [description, setDescription] = useState(group.description || '');
  const [color, setColor] = useState(group.color || DEFAULT_COLORS[0]);
  const [osFamily, setOsFamily] = useState(group.os_family || '');
  const [osVersionPattern, setOsVersionPattern] = useState(group.os_version_pattern || '');
  const [architecture, setArchitecture] = useState(group.architecture || '');
  const [complianceFramework, setComplianceFramework] = useState(group.compliance_framework || '');
  const [autoScanEnabled, setAutoScanEnabled] = useState(group.auto_scan_enabled);
  const [scanSchedule, setScanSchedule] = useState(group.scan_schedule || '');

  // Available data
  const [groupHosts, setGroupHosts] = useState<Host[]>([]);
  const [availableHosts, setAvailableHosts] = useState<Host[]>([]);

  // UI state
  const [showHostManagement, setShowHostManagement] = useState(false);

  useEffect(() => {
    if (open && group) {
      fetchGroupHosts();
      fetchAvailableHosts();
      resetForm();
    }
    // ESLint disable: Functions are not memoized to avoid complex dependency chain
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, group]);

  const resetForm = () => {
    setName(group.name);
    setDescription(group.description || '');
    setColor(group.color || DEFAULT_COLORS[0]);
    setOsFamily(group.os_family || '');
    setOsVersionPattern(group.os_version_pattern || '');
    setArchitecture(group.architecture || '');
    setComplianceFramework(group.compliance_framework || '');
    setAutoScanEnabled(group.auto_scan_enabled);
    setScanSchedule(group.scan_schedule || '');
    setError(null);
  };

  const fetchGroupHosts = async () => {
    try {
      const response = await fetch(`/api/host-groups/${group.id}/hosts`, {
        headers: {
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        const hostList = Array.isArray(data.hosts) ? data.hosts : Array.isArray(data) ? data : [];
        setGroupHosts(hostList);
      }
    } catch (err) {
      console.error('Error fetching group hosts:', err);
    }
  };

  const fetchAvailableHosts = async () => {
    try {
      const response = await fetch('/api/hosts/', {
        headers: {
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        const hostList = Array.isArray(data.hosts) ? data.hosts : Array.isArray(data) ? data : [];
        setAvailableHosts(hostList);
      }
    } catch (err) {
      console.error('Error fetching available hosts:', err);
    }
  };

  const handleSubmit = async () => {
    try {
      setLoading(true);
      setError(null);

      const updateData = {
        name: name.trim(),
        description: description.trim() || null,
        color,
        os_family: osFamily.trim() || null,
        os_version_pattern: osVersionPattern.trim() || null,
        architecture: architecture.trim() || null,
        compliance_framework: complianceFramework.trim() || null,
        auto_scan_enabled: autoScanEnabled,
        scan_schedule: scanSchedule.trim() || null,
      };

      const response = await fetch(`/api/host-groups/${group.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
        body: JSON.stringify(updateData),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to update group');
      }

      onGroupUpdated();
      onClose();
    } catch (err) {
      console.error('Error updating group:', err);
      setError(err instanceof Error ? err.message : 'Failed to update group');
    } finally {
      setLoading(false);
    }
  };

  const handleAddHost = async (host: Host) => {
    try {
      // Validate compatibility first
      const validateResponse = await fetch(`/api/host-groups/${group.id}/validate-hosts`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
        body: JSON.stringify({
          host_ids: [host.id],
        }),
      });

      if (validateResponse.ok) {
        const validation = await validateResponse.json();

        if (validation.incompatible.length > 0) {
          const reasons = validation.incompatible[0].reasons || [];
          if (
            !confirm(
              `Host "${host.hostname}" may not be compatible with this group:\n\n${reasons.join('\n')}\n\nAdd anyway?`
            )
          ) {
            return;
          }
        }
      }

      // Add host to group
      const response = await fetch(`/api/host-groups/${group.id}/hosts`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
        body: JSON.stringify({
          host_ids: [host.id],
        }),
      });

      if (response.ok) {
        await fetchGroupHosts();
        await fetchAvailableHosts();
      }
    } catch (err) {
      console.error('Error adding host to group:', err);
    }
  };

  const handleRemoveHost = async (host: Host) => {
    try {
      const response = await fetch(`/api/host-groups/${group.id}/hosts/${host.id}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${storageGet(StorageKeys.AUTH_TOKEN)}`,
        },
      });

      if (response.ok) {
        await fetchGroupHosts();
        await fetchAvailableHosts();
      }
    } catch (err) {
      console.error('Error removing host from group:', err);
    }
  };

  const unassignedHosts = availableHosts.filter(
    (host) => !groupHosts.some((groupHost) => groupHost.id === host.id)
  );

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="md"
      fullWidth
      PaperProps={{ sx: { minHeight: '60vh' } }}
    >
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <EditIcon color="primary" />
          <Typography variant="h6">Edit Group: {group.name}</Typography>
        </Box>
      </DialogTitle>

      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Grid container spacing={3}>
          {/* Basic Information */}
          <Grid size={{ xs: 12 }}>
            <Typography variant="h6" gutterBottom>
              Basic Information
            </Typography>
          </Grid>

          <Grid size={{ xs: 12, sm: 6 }}>
            <TextField
              label="Group Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              fullWidth
              required
            />
          </Grid>

          <Grid size={{ xs: 12, sm: 6 }}>
            <TextField
              label="Description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              fullWidth
              multiline
              rows={2}
            />
          </Grid>

          <Grid size={{ xs: 12 }}>
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Group Color
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                {DEFAULT_COLORS.map((colorOption) => (
                  <Tooltip key={colorOption} title={`Select ${colorOption}`}>
                    <Box
                      sx={{
                        width: 32,
                        height: 32,
                        bgcolor: colorOption,
                        borderRadius: '50%',
                        cursor: 'pointer',
                        border: color === colorOption ? '3px solid #000' : '2px solid #ddd',
                        '&:hover': {
                          transform: 'scale(1.1)',
                        },
                      }}
                      onClick={() => setColor(colorOption)}
                    />
                  </Tooltip>
                ))}
              </Box>
            </Box>
          </Grid>

          <Grid size={{ xs: 12 }}>
            <Divider />
          </Grid>

          {/* System Requirements */}
          <Grid size={{ xs: 12 }}>
            <Typography variant="h6" gutterBottom>
              System Requirements
            </Typography>
          </Grid>

          <Grid size={{ xs: 12, sm: 4 }}>
            <FormControl fullWidth>
              <InputLabel>OS Family</InputLabel>
              <Select
                value={osFamily}
                onChange={(e) => setOsFamily(e.target.value)}
                label="OS Family"
              >
                <MenuItem value="">
                  <em>None</em>
                </MenuItem>
                {OS_FAMILY_OPTIONS.map((option) => (
                  <MenuItem key={option.value} value={option.value}>
                    <Box>
                      <Typography>{option.label}</Typography>
                      {option.description && (
                        <Typography variant="caption" color="text.secondary">
                          {option.description}
                        </Typography>
                      )}
                    </Box>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>

          <Grid size={{ xs: 12, sm: 4 }}>
            <TextField
              label="OS Version Pattern"
              value={osVersionPattern}
              onChange={(e) => setOsVersionPattern(e.target.value)}
              fullWidth
              helperText="e.g., 8.*, 22.04"
            />
          </Grid>

          <Grid size={{ xs: 12, sm: 4 }}>
            <FormControl fullWidth>
              <InputLabel>Architecture</InputLabel>
              <Select
                value={architecture}
                onChange={(e) => setArchitecture(e.target.value)}
                label="Architecture"
              >
                <MenuItem value="">
                  <em>None</em>
                </MenuItem>
                {ARCHITECTURE_OPTIONS.map((option) => (
                  <MenuItem key={option.value} value={option.value}>
                    <Box>
                      <Typography>{option.label}</Typography>
                      {option.description && (
                        <Typography variant="caption" color="text.secondary">
                          {option.description}
                        </Typography>
                      )}
                    </Box>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>

          <Grid size={{ xs: 12 }}>
            <Divider />
          </Grid>

          {/* Compliance Configuration */}
          <Grid size={{ xs: 12 }}>
            <Typography variant="h6" gutterBottom>
              Compliance Configuration
            </Typography>
          </Grid>

          <Grid size={{ xs: 12, sm: 6 }}>
            <FormControl fullWidth>
              <InputLabel>Compliance Framework</InputLabel>
              <Select
                value={complianceFramework}
                onChange={(e) => setComplianceFramework(e.target.value)}
                label="Compliance Framework"
              >
                <MenuItem value="">
                  <em>None</em>
                </MenuItem>
                {COMPLIANCE_FRAMEWORK_OPTIONS.map((option) => (
                  <MenuItem key={option.value} value={option.value}>
                    <Box>
                      <Typography>{option.label}</Typography>
                      {option.description && (
                        <Typography
                          variant="caption"
                          color="text.secondary"
                          sx={{ display: 'block' }}
                        >
                          {option.description}
                        </Typography>
                      )}
                    </Box>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>

          <Grid size={{ xs: 12, sm: 6 }}>
            <FormControlLabel
              control={
                <Switch
                  checked={autoScanEnabled}
                  onChange={(e) => setAutoScanEnabled(e.target.checked)}
                />
              }
              label="Enable automatic scanning"
            />

            {autoScanEnabled && (
              <Box sx={{ mt: 1 }}>
                {(() => {
                  // Check if current schedule matches any predefined option
                  const isPredefinedSchedule = SCAN_SCHEDULE_OPTIONS.some(
                    (option) => option.value === scanSchedule
                  );

                  if (isPredefinedSchedule || !scanSchedule) {
                    return (
                      <FormControl fullWidth size="small">
                        <InputLabel>Scan Schedule</InputLabel>
                        <Select
                          value={scanSchedule}
                          onChange={(e) => setScanSchedule(e.target.value)}
                          label="Scan Schedule"
                        >
                          {SCAN_SCHEDULE_OPTIONS.map((option) => (
                            <MenuItem key={option.value} value={option.value}>
                              <Box>
                                <Typography>{option.label}</Typography>
                                {option.description && (
                                  <Typography variant="caption" color="text.secondary">
                                    {option.description}
                                  </Typography>
                                )}
                              </Box>
                            </MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                    );
                  } else {
                    return (
                      <TextField
                        label="Custom Cron Expression"
                        value={scanSchedule}
                        onChange={(e) => setScanSchedule(e.target.value)}
                        fullWidth
                        size="small"
                        helperText="Enter custom cron expression (e.g., 0 2 * * *)"
                      />
                    );
                  }
                })()}
              </Box>
            )}
          </Grid>

          <Grid size={{ xs: 12 }}>
            <Divider />
          </Grid>

          {/* Host Management */}
          <Grid size={{ xs: 12 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography variant="h6">Host Management ({groupHosts.length} hosts)</Typography>
              <Button variant="outlined" onClick={() => setShowHostManagement(!showHostManagement)}>
                {showHostManagement ? 'Hide' : 'Manage'} Hosts
              </Button>
            </Box>
          </Grid>

          {showHostManagement && (
            <>
              <Grid size={{ xs: 12, sm: 6 }}>
                <Paper sx={{ p: 2, maxHeight: 300, overflow: 'auto' }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Hosts in Group
                  </Typography>
                  <List dense>
                    {groupHosts.map((host) => (
                      <ListItem key={host.id}>
                        <ListItemIcon>
                          <HostIcon />
                        </ListItemIcon>
                        <ListItemText primary={host.hostname} secondary={host.ip_address} />
                        <ListItemSecondaryAction>
                          <Tooltip title="Remove from group">
                            <IconButton
                              edge="end"
                              onClick={() => handleRemoveHost(host)}
                              size="small"
                            >
                              <RemoveIcon />
                            </IconButton>
                          </Tooltip>
                        </ListItemSecondaryAction>
                      </ListItem>
                    ))}
                    {groupHosts.length === 0 && (
                      <Typography variant="body2" color="text.secondary" sx={{ p: 2 }}>
                        No hosts in this group
                      </Typography>
                    )}
                  </List>
                </Paper>
              </Grid>

              <Grid size={{ xs: 12, sm: 6 }}>
                <Paper sx={{ p: 2, maxHeight: 300, overflow: 'auto' }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Available Hosts ({unassignedHosts.length})
                  </Typography>
                  <List dense>
                    {unassignedHosts.slice(0, 10).map((host) => (
                      <ListItem key={host.id}>
                        <ListItemIcon>
                          <HostIcon />
                        </ListItemIcon>
                        <ListItemText
                          primary={host.hostname}
                          secondary={
                            <Box>
                              <Typography variant="caption" display="block">
                                {host.ip_address}
                              </Typography>
                              {host.operating_system && (
                                <Chip
                                  label={host.operating_system}
                                  size="small"
                                  sx={{ mt: 0.5, fontSize: '0.7rem', height: 20 }}
                                />
                              )}
                            </Box>
                          }
                        />
                        <ListItemSecondaryAction>
                          <Tooltip title="Add to group">
                            <IconButton edge="end" onClick={() => handleAddHost(host)} size="small">
                              <AddIcon />
                            </IconButton>
                          </Tooltip>
                        </ListItemSecondaryAction>
                      </ListItem>
                    ))}
                    {unassignedHosts.length === 0 && (
                      <Typography variant="body2" color="text.secondary" sx={{ p: 2 }}>
                        All hosts are assigned to groups
                      </Typography>
                    )}
                    {unassignedHosts.length > 10 && (
                      <Typography variant="caption" color="text.secondary" sx={{ p: 2 }}>
                        ... and {unassignedHosts.length - 10} more hosts
                      </Typography>
                    )}
                  </List>
                </Paper>
              </Grid>
            </>
          )}
        </Grid>
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose} disabled={loading}>
          Cancel
        </Button>
        <Button variant="contained" onClick={handleSubmit} disabled={loading || !name.trim()}>
          {loading ? <CircularProgress size={20} /> : 'Update Group'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default GroupEditDialog;
