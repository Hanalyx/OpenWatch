/**
 * TargetSelectionStep - Step 1 of the ComplianceScanWizard
 *
 * Allows users to select scan targets:
 * - Choose between individual hosts or host groups
 * - Multi-select with checkboxes
 * - Search and filter capability
 * - Status indicators (online/offline)
 * - Support for preselected hosts from router state
 *
 * @module TargetSelectionStep
 * @see docs/UNIFIED_SCAN_WIZARD_PLAN.md for design specifications
 */

import React, { useState, useMemo, useEffect } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  TextField,
  InputAdornment,
  Checkbox,
  FormControlLabel,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Chip,
  Alert,
  Divider,
  Paper,
  LinearProgress,
} from '@mui/material';
import {
  Computer as ComputerIcon,
  Folder as FolderIcon,
  Search as SearchIcon,
  CheckCircle as CheckCircleIcon,
  Cancel as CancelIcon,
  HelpOutline as HelpIcon,
} from '@mui/icons-material';
import type { WizardHost, WizardHostGroup, TargetType } from '../hooks/useScanWizard';

/**
 * Props for TargetSelectionStep component
 */
interface TargetSelectionStepProps {
  /** Currently selected target type (hosts or groups) */
  targetType: TargetType;
  /** Array of selected host IDs */
  selectedHostIds: string[];
  /** Array of selected group IDs */
  selectedGroupIds: number[];
  /** Available hosts to select from */
  hosts: WizardHost[];
  /** Available host groups to select from */
  hostGroups: WizardHostGroup[];
  /** Whether data is currently loading */
  isLoading: boolean;
  /** Preselected host ID from router state */
  preselectedHostId?: string;
  /** Callback when target type changes */
  onTargetTypeChange: (type: TargetType) => void;
  /** Callback when a host is toggled */
  onToggleHost: (hostId: string) => void;
  /** Callback when a group is toggled */
  onToggleGroup: (groupId: number) => void;
  /** Callback to select all hosts */
  onSelectAllHosts: (hostIds: string[]) => void;
  /** Callback to clear all host selections */
  onClearHosts: () => void;
  /** Callback to select all groups */
  onSelectAllGroups: (groupIds: number[]) => void;
  /** Callback to clear all group selections */
  onClearGroups: () => void;
}

/**
 * Get status icon component based on host status
 */
function getStatusIcon(status: string): React.ReactNode {
  switch (status) {
    case 'online':
      return <CheckCircleIcon fontSize="small" color="success" />;
    case 'offline':
      return <CancelIcon fontSize="small" color="error" />;
    default:
      return <HelpIcon fontSize="small" color="disabled" />;
  }
}

/**
 * Get chip color based on host status
 */
function getStatusColor(status: string): 'success' | 'error' | 'warning' | 'default' {
  switch (status) {
    case 'online':
      return 'success';
    case 'offline':
      return 'error';
    default:
      return 'default';
  }
}

/**
 * TargetSelectionStep Component
 *
 * First step of the scan wizard that allows users to select
 * which hosts or host groups to scan.
 */
const TargetSelectionStep: React.FC<TargetSelectionStepProps> = ({
  targetType,
  selectedHostIds,
  selectedGroupIds,
  hosts,
  hostGroups,
  isLoading,
  preselectedHostId,
  onTargetTypeChange,
  onToggleHost,
  onToggleGroup,
  onSelectAllHosts,
  onClearHosts,
  onSelectAllGroups,
  onClearGroups,
}) => {
  // Search filter state
  const [searchQuery, setSearchQuery] = useState('');

  // Auto-select preselected host on mount
  useEffect(() => {
    if (preselectedHostId && !selectedHostIds.includes(preselectedHostId)) {
      // Automatically set target type to hosts and select the preselected host
      if (targetType !== 'hosts') {
        onTargetTypeChange('hosts');
      }
      onToggleHost(preselectedHostId);
    }
    // Only run on mount or when preselectedHostId changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [preselectedHostId]);

  /**
   * Filter hosts based on search query
   * Searches hostname, displayName, operatingSystem, and IP-like patterns
   */
  const filteredHosts = useMemo(() => {
    if (!searchQuery.trim()) return hosts;

    const query = searchQuery.toLowerCase().trim();
    return hosts.filter((host) => {
      return (
        host.hostname.toLowerCase().includes(query) ||
        host.displayName.toLowerCase().includes(query) ||
        host.operatingSystem.toLowerCase().includes(query) ||
        host.status.toLowerCase().includes(query)
      );
    });
  }, [hosts, searchQuery]);

  /**
   * Filter host groups based on search query
   */
  const filteredGroups = useMemo(() => {
    if (!searchQuery.trim()) return hostGroups;

    const query = searchQuery.toLowerCase().trim();
    return hostGroups.filter((group) => {
      return (
        group.name.toLowerCase().includes(query) ||
        (group.description?.toLowerCase().includes(query) ?? false)
      );
    });
  }, [hostGroups, searchQuery]);

  /**
   * Check if all visible hosts are selected
   */
  const allHostsSelected = useMemo(() => {
    if (filteredHosts.length === 0) return false;
    return filteredHosts.every((host) => selectedHostIds.includes(host.id));
  }, [filteredHosts, selectedHostIds]);

  /**
   * Check if all visible groups are selected
   */
  const allGroupsSelected = useMemo(() => {
    if (filteredGroups.length === 0) return false;
    return filteredGroups.every((group) => selectedGroupIds.includes(group.id));
  }, [filteredGroups, selectedGroupIds]);

  /**
   * Handle select all toggle for hosts
   */
  const handleSelectAllHosts = () => {
    if (allHostsSelected) {
      onClearHosts();
    } else {
      onSelectAllHosts(filteredHosts.map((h) => h.id));
    }
  };

  /**
   * Handle select all toggle for groups
   */
  const handleSelectAllGroups = () => {
    if (allGroupsSelected) {
      onClearGroups();
    } else {
      onSelectAllGroups(filteredGroups.map((g) => g.id));
    }
  };

  /**
   * Get selection summary text
   */
  const getSelectionSummary = (): string => {
    if (targetType === 'hosts') {
      const count = selectedHostIds.length;
      return count === 0
        ? 'No hosts selected'
        : count === 1
          ? '1 host selected'
          : `${count} hosts selected`;
    } else if (targetType === 'groups') {
      const count = selectedGroupIds.length;
      const totalHosts = hostGroups
        .filter((g) => selectedGroupIds.includes(g.id))
        .reduce((sum, g) => sum + g.hostCount, 0);
      if (count === 0) return 'No groups selected';
      return count === 1
        ? `1 group selected (${totalHosts} hosts)`
        : `${count} groups selected (${totalHosts} hosts)`;
    }
    return 'Select a target type above';
  };

  return (
    <Box>
      {/* Step Header */}
      <Typography variant="h6" gutterBottom>
        Select Scan Targets
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Choose individual hosts or host groups to scan for compliance.
      </Typography>

      {/* Loading State */}
      {isLoading && (
        <Box sx={{ mb: 3 }}>
          <LinearProgress />
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            Loading hosts and groups...
          </Typography>
        </Box>
      )}

      {/* Target Type Selection Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        {/* Host Groups Option */}
        <Grid item xs={12} sm={6}>
          <Card
            sx={{
              cursor: 'pointer',
              border: 2,
              borderColor: targetType === 'groups' ? 'primary.main' : 'divider',
              transition: 'all 0.2s ease-in-out',
              '&:hover': {
                borderColor: 'primary.main',
                boxShadow: 2,
              },
            }}
            onClick={() => onTargetTypeChange('groups')}
          >
            <CardContent sx={{ textAlign: 'center', py: 3 }}>
              <FolderIcon
                sx={{
                  fontSize: 48,
                  color: targetType === 'groups' ? 'primary.main' : 'text.secondary',
                  mb: 1,
                }}
              />
              <Typography variant="h6" gutterBottom>
                Host Groups
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Scan entire groups at once
              </Typography>
              <Chip
                label={`${hostGroups.length} groups available`}
                size="small"
                sx={{ mt: 1 }}
                variant="outlined"
              />
            </CardContent>
          </Card>
        </Grid>

        {/* Individual Hosts Option */}
        <Grid item xs={12} sm={6}>
          <Card
            sx={{
              cursor: 'pointer',
              border: 2,
              borderColor: targetType === 'hosts' ? 'primary.main' : 'divider',
              transition: 'all 0.2s ease-in-out',
              '&:hover': {
                borderColor: 'primary.main',
                boxShadow: 2,
              },
            }}
            onClick={() => onTargetTypeChange('hosts')}
          >
            <CardContent sx={{ textAlign: 'center', py: 3 }}>
              <ComputerIcon
                sx={{
                  fontSize: 48,
                  color: targetType === 'hosts' ? 'primary.main' : 'text.secondary',
                  mb: 1,
                }}
              />
              <Typography variant="h6" gutterBottom>
                Individual Hosts
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Select specific hosts to scan
              </Typography>
              <Chip
                label={`${hosts.length} hosts available`}
                size="small"
                sx={{ mt: 1 }}
                variant="outlined"
              />
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Selection List - Only show after target type is selected */}
      {targetType && (
        <Paper variant="outlined" sx={{ p: 2 }}>
          {/* Search and Select All */}
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 2,
              mb: 2,
              flexWrap: 'wrap',
            }}
          >
            <TextField
              placeholder={`Search ${targetType === 'hosts' ? 'hosts' : 'groups'}...`}
              size="small"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              sx={{ flexGrow: 1, minWidth: 200 }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon color="action" />
                  </InputAdornment>
                ),
              }}
            />
            <FormControlLabel
              control={
                <Checkbox
                  checked={targetType === 'hosts' ? allHostsSelected : allGroupsSelected}
                  indeterminate={
                    targetType === 'hosts'
                      ? selectedHostIds.length > 0 && !allHostsSelected
                      : selectedGroupIds.length > 0 && !allGroupsSelected
                  }
                  onChange={targetType === 'hosts' ? handleSelectAllHosts : handleSelectAllGroups}
                />
              }
              label="Select All"
            />
          </Box>

          <Divider sx={{ mb: 2 }} />

          {/* Host List */}
          {targetType === 'hosts' && (
            <>
              {filteredHosts.length === 0 ? (
                <Alert severity="info">
                  {hosts.length === 0
                    ? 'No hosts available. Add hosts before creating scans.'
                    : 'No hosts match your search criteria.'}
                </Alert>
              ) : (
                <List
                  dense
                  sx={{
                    maxHeight: 350,
                    overflow: 'auto',
                    bgcolor: 'background.paper',
                  }}
                >
                  {filteredHosts.map((host) => (
                    <ListItem key={host.id} disablePadding>
                      <ListItemButton
                        onClick={() => onToggleHost(host.id)}
                        selected={selectedHostIds.includes(host.id)}
                        sx={{
                          borderRadius: 1,
                          mb: 0.5,
                          '&.Mui-selected': {
                            bgcolor: 'primary.lighter',
                          },
                        }}
                      >
                        <ListItemIcon sx={{ minWidth: 36 }}>
                          <Checkbox
                            edge="start"
                            checked={selectedHostIds.includes(host.id)}
                            tabIndex={-1}
                            disableRipple
                          />
                        </ListItemIcon>
                        <ListItemIcon sx={{ minWidth: 36 }}>
                          <ComputerIcon color={host.status === 'online' ? 'success' : 'disabled'} />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                              <Typography variant="body1">{host.displayName}</Typography>
                              {host.id === preselectedHostId && (
                                <Chip
                                  label="Pre-selected"
                                  size="small"
                                  color="info"
                                  variant="outlined"
                                />
                              )}
                            </Box>
                          }
                          secondary={
                            <Typography variant="body2" color="text.secondary">
                              {host.hostname} - {host.operatingSystem}
                            </Typography>
                          }
                        />
                        <Chip
                          icon={getStatusIcon(host.status)}
                          label={host.status}
                          size="small"
                          color={getStatusColor(host.status)}
                          variant="outlined"
                        />
                      </ListItemButton>
                    </ListItem>
                  ))}
                </List>
              )}
            </>
          )}

          {/* Host Group List */}
          {targetType === 'groups' && (
            <>
              {filteredGroups.length === 0 ? (
                <Alert severity="info">
                  {hostGroups.length === 0
                    ? 'No host groups available. Create host groups to scan multiple hosts at once.'
                    : 'No groups match your search criteria.'}
                </Alert>
              ) : (
                <List
                  dense
                  sx={{
                    maxHeight: 350,
                    overflow: 'auto',
                    bgcolor: 'background.paper',
                  }}
                >
                  {filteredGroups.map((group) => (
                    <ListItem key={group.id} disablePadding>
                      <ListItemButton
                        onClick={() => onToggleGroup(group.id)}
                        selected={selectedGroupIds.includes(group.id)}
                        sx={{
                          borderRadius: 1,
                          mb: 0.5,
                          '&.Mui-selected': {
                            bgcolor: 'primary.lighter',
                          },
                        }}
                      >
                        <ListItemIcon sx={{ minWidth: 36 }}>
                          <Checkbox
                            edge="start"
                            checked={selectedGroupIds.includes(group.id)}
                            tabIndex={-1}
                            disableRipple
                          />
                        </ListItemIcon>
                        <ListItemIcon sx={{ minWidth: 36 }}>
                          <FolderIcon color="primary" />
                        </ListItemIcon>
                        <ListItemText
                          primary={group.name}
                          secondary={group.description || 'No description'}
                        />
                        <Chip label={`${group.hostCount} hosts`} size="small" variant="outlined" />
                      </ListItemButton>
                    </ListItem>
                  ))}
                </List>
              )}
            </>
          )}

          {/* Selection Summary */}
          <Divider sx={{ my: 2 }} />
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Typography variant="body2" color="text.secondary">
              {getSelectionSummary()}
            </Typography>
            {targetType === 'hosts' && selectedHostIds.length > 0 && (
              <Chip
                label={`${hosts.filter((h) => selectedHostIds.includes(h.id) && h.status === 'online').length} online`}
                size="small"
                color="success"
                variant="outlined"
              />
            )}
          </Box>
        </Paper>
      )}

      {/* Warning for offline hosts */}
      {targetType === 'hosts' &&
        selectedHostIds.some((id) => {
          const host = hosts.find((h) => h.id === id);
          return host && host.status !== 'online';
        }) && (
          <Alert severity="warning" sx={{ mt: 2 }}>
            Some selected hosts are offline. Pre-flight validation will check connectivity before
            starting the scan.
          </Alert>
        )}
    </Box>
  );
};

export default TargetSelectionStep;
