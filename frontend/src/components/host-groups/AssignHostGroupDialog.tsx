import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Box,
  Typography,
  Alert,
  CircularProgress,
  Chip
} from '@mui/material';
import {
  Group as GroupIcon,
  Computer as ComputerIcon
} from '@mui/icons-material';

interface HostGroup {
  id: number;
  name: string;
  description?: string;
  color?: string;
  host_count: number;
}

interface Host {
  id: string;
  hostname: string;
  display_name?: string;
  group_id?: number;
  group_name?: string;
}

interface AssignHostGroupDialogProps {
  open: boolean;
  onClose: () => void;
  selectedHosts: Host[];
  onAssigned: () => void;
}

const AssignHostGroupDialog: React.FC<AssignHostGroupDialogProps> = ({
  open,
  onClose,
  selectedHosts,
  onAssigned
}) => {
  const [groups, setGroups] = useState<HostGroup[]>([]);
  const [selectedGroupId, setSelectedGroupId] = useState<number | ''>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      fetchGroups();
      // Reset selection when dialog opens
      setSelectedGroupId('');
      setError(null);
    }
  }, [open]);

  const fetchGroups = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/host-groups/', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        setGroups(data);
      } else {
        throw new Error('Failed to fetch groups');
      }
    } catch (error) {
      console.error('Error fetching groups:', error);
      setError('Failed to load host groups');
    } finally {
      setLoading(false);
    }
  };

  const handleAssign = async () => {
    if (selectedGroupId === '') {
      setError('Please select a group');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      const response = await fetch(`/api/host-groups/${selectedGroupId}/hosts`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
        },
        body: JSON.stringify({
          host_ids: selectedHosts.map(host => host.id)
        })
      });

      if (response.ok) {
        onAssigned();
        onClose();
      } else {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to assign hosts to group');
      }
    } catch (error) {
      console.error('Error assigning hosts:', error);
      setError(error instanceof Error ? error.message : 'Failed to assign hosts');
    } finally {
      setLoading(false);
    }
  };

  const handleRemoveFromGroup = async () => {
    try {
      setLoading(true);
      setError(null);

      // Remove each host from their current group
      for (const host of selectedHosts) {
        if (host.group_id) {
          await fetch(`/api/host-groups/${host.group_id}/hosts/${host.id}`, {
            method: 'DELETE',
            headers: {
              'Authorization': `Bearer ${localStorage.getItem('auth_token')}`
            }
          });
        }
      }

      onAssigned();
      onClose();
    } catch (error) {
      console.error('Error removing hosts from groups:', error);
      setError('Failed to remove hosts from groups');
    } finally {
      setLoading(false);
    }
  };

  const selectedGroup = groups.find(g => g.id === selectedGroupId);

  return (
    <Dialog 
      open={open} 
      onClose={onClose}
      maxWidth="sm"
      fullWidth
    >
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <GroupIcon color="primary" />
          <Typography variant="h6">Assign Hosts to Group</Typography>
        </Box>
      </DialogTitle>
      
      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {/* Selected Hosts Summary */}
        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle1" sx={{ mb: 1, display: 'flex', alignItems: 'center', gap: 1 }}>
            <ComputerIcon fontSize="small" />
            Selected Hosts ({selectedHosts.length})
          </Typography>
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
            {selectedHosts.map((host) => (
              <Chip
                key={host.id}
                label={host.display_name || host.hostname}
                size="small"
                variant="outlined"
                icon={<ComputerIcon />}
              />
            ))}
          </Box>
        </Box>

        {/* Current Group Info */}
        {selectedHosts.length === 1 && selectedHosts[0].group_name && (
          <Alert severity="info" sx={{ mb: 2 }}>
            <Typography variant="body2">
              <strong>{selectedHosts[0].display_name || selectedHosts[0].hostname}</strong> is currently in group: 
              <strong> {selectedHosts[0].group_name}</strong>
            </Typography>
          </Alert>
        )}

        {/* Group Selection */}
        <FormControl fullWidth margin="normal">
          <InputLabel>Select Group</InputLabel>
          <Select
            value={selectedGroupId}
            label="Select Group"
            onChange={(e) => setSelectedGroupId(e.target.value as number)}
            disabled={loading}
          >
            {groups.map((group) => (
              <MenuItem key={group.id} value={group.id}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
                  <Box
                    sx={{
                      width: 12,
                      height: 12,
                      borderRadius: '50%',
                      bgcolor: group.color || '#666'
                    }}
                  />
                  <Box sx={{ flexGrow: 1 }}>
                    <Typography variant="body1">{group.name}</Typography>
                    {group.description && (
                      <Typography variant="caption" color="text.secondary">
                        {group.description}
                      </Typography>
                    )}
                  </Box>
                  <Chip
                    label={`${group.host_count} hosts`}
                    size="small"
                    variant="outlined"
                  />
                </Box>
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        {/* Selected Group Info */}
        {selectedGroup && (
          <Box sx={{ mt: 2, p: 2, bgcolor: 'grey.50', borderRadius: 1 }}>
            <Typography variant="subtitle2" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Box
                sx={{
                  width: 12,
                  height: 12,
                  borderRadius: '50%',
                  bgcolor: selectedGroup.color || '#666'
                }}
              />
              {selectedGroup.name}
            </Typography>
            {selectedGroup.description && (
              <Typography variant="body2" color="text.secondary">
                {selectedGroup.description}
              </Typography>
            )}
            <Typography variant="caption" color="text.secondary">
              Currently has {selectedGroup.host_count} hosts
            </Typography>
          </Box>
        )}

        {loading && (
          <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
            <CircularProgress />
          </Box>
        )}
      </DialogContent>
      
      <DialogActions>
        <Button onClick={onClose} disabled={loading}>
          Cancel
        </Button>
        
        {/* Show remove from group option if hosts are currently in groups */}
        {selectedHosts.some(host => host.group_id) && (
          <Button
            onClick={handleRemoveFromGroup}
            disabled={loading}
            color="warning"
          >
            Remove from Groups
          </Button>
        )}
        
        <Button
          onClick={handleAssign}
          variant="contained"
          disabled={loading || selectedGroupId === ''}
        >
          Assign to Group
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default AssignHostGroupDialog;