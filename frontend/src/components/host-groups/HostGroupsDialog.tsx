import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Box,
  Typography,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Chip,
  Alert,
  CircularProgress,
  Fab,
  Tooltip,
  Divider,
} from '@mui/material';
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  Edit as EditIcon,
  Group as GroupIcon,
} from '@mui/icons-material';

interface HostGroup {
  id: number;
  name: string;
  description?: string;
  color?: string;
  host_count: number;
  created_by: number;
  created_at: string;
  updated_at: string;
}

interface HostGroupsDialogProps {
  open: boolean;
  onClose: () => void;
  onGroupCreated?: () => void;
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

const HostGroupsDialog: React.FC<HostGroupsDialogProps> = ({ open, onClose, onGroupCreated }) => {
  const [groups, setGroups] = useState<HostGroup[]>([]);
  const [loading, setLoading] = useState(false);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [editingGroup, setEditingGroup] = useState<HostGroup | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    color: DEFAULT_COLORS[0],
  });
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      fetchGroups();
    }
  }, [open]);

  const fetchGroups = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/host-groups/', {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        },
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

  const handleSubmit = async () => {
    try {
      setLoading(true);
      setError(null);

      const url = editingGroup ? `/api/host-groups/${editingGroup.id}` : '/api/host-groups/';

      const method = editingGroup ? 'PUT' : 'POST';

      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        },
        body: JSON.stringify(formData),
      });

      if (response.ok) {
        await fetchGroups();
        setShowCreateForm(false);
        setEditingGroup(null);
        setFormData({ name: '', description: '', color: DEFAULT_COLORS[0] });
        if (onGroupCreated) onGroupCreated();
      } else {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to save group');
      }
    } catch (error) {
      console.error('Error saving group:', error);
      setError(error instanceof Error ? error.message : 'Failed to save group');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (groupId: number) => {
    if (
      !confirm(
        'Are you sure you want to delete this group? All hosts will be moved to "Ungrouped".'
      )
    ) {
      return;
    }

    try {
      setLoading(true);
      const response = await fetch(`/api/host-groups/${groupId}`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        },
      });

      if (response.ok) {
        await fetchGroups();
        if (onGroupCreated) onGroupCreated();
      } else {
        throw new Error('Failed to delete group');
      }
    } catch (error) {
      console.error('Error deleting group:', error);
      setError('Failed to delete group');
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (group: HostGroup) => {
    setEditingGroup(group);
    setFormData({
      name: group.name,
      description: group.description || '',
      color: group.color || DEFAULT_COLORS[0],
    });
    setShowCreateForm(true);
  };

  const handleCancel = () => {
    setShowCreateForm(false);
    setEditingGroup(null);
    setFormData({ name: '', description: '', color: DEFAULT_COLORS[0] });
    setError(null);
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <GroupIcon color="primary" />
          <Typography variant="h6">Manage Host Groups</Typography>
        </Box>
      </DialogTitle>

      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {showCreateForm ? (
          <Box sx={{ mb: 3 }}>
            <Typography variant="h6" sx={{ mb: 2 }}>
              {editingGroup ? 'Edit Group' : 'Create New Group'}
            </Typography>

            <TextField
              label="Group Name"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              fullWidth
              margin="normal"
              required
            />

            <TextField
              label="Description (Optional)"
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              fullWidth
              margin="normal"
              multiline
              rows={2}
            />

            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                Group Color
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                {DEFAULT_COLORS.map((color) => (
                  <Tooltip key={color} title={`Select ${color}`}>
                    <Box
                      sx={{
                        width: 32,
                        height: 32,
                        bgcolor: color,
                        borderRadius: '50%',
                        cursor: 'pointer',
                        border: formData.color === color ? '3px solid #000' : '2px solid #ddd',
                        '&:hover': {
                          transform: 'scale(1.1)',
                        },
                      }}
                      onClick={() => setFormData({ ...formData, color })}
                    />
                  </Tooltip>
                ))}
              </Box>
            </Box>

            <Box sx={{ mt: 3, display: 'flex', gap: 2 }}>
              <Button
                variant="contained"
                onClick={handleSubmit}
                disabled={loading || !formData.name.trim()}
              >
                {loading ? <CircularProgress size={20} /> : editingGroup ? 'Update' : 'Create'}
              </Button>
              <Button variant="outlined" onClick={handleCancel} disabled={loading}>
                Cancel
              </Button>
            </Box>
          </Box>
        ) : (
          <Box>
            <Box
              sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}
            >
              <Typography variant="h6">Existing Groups ({groups.length})</Typography>
              <Fab
                size="small"
                color="primary"
                onClick={() => setShowCreateForm(true)}
                disabled={loading}
              >
                <AddIcon />
              </Fab>
            </Box>

            {loading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                <CircularProgress />
              </Box>
            ) : groups.length === 0 ? (
              <Box sx={{ textAlign: 'center', py: 4 }}>
                <GroupIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
                <Typography variant="h6" color="text.secondary">
                  No Groups Created
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Create your first host group to organize your systems
                </Typography>
              </Box>
            ) : (
              <List>
                {groups.map((group, index) => (
                  <React.Fragment key={group.id}>
                    {index > 0 && <Divider />}
                    <ListItem>
                      <Box
                        sx={{
                          width: 16,
                          height: 16,
                          borderRadius: '50%',
                          bgcolor: group.color || '#666',
                          mr: 2,
                          flexShrink: 0,
                        }}
                      />
                      <ListItemText
                        primary={group.name}
                        secondary={
                          <Box>
                            {group.description && (
                              <Typography variant="body2" color="text.secondary">
                                {group.description}
                              </Typography>
                            )}
                            <Chip
                              label={`${group.host_count} hosts`}
                              size="small"
                              sx={{ mt: 0.5 }}
                            />
                          </Box>
                        }
                      />
                      <ListItemSecondaryAction>
                        <Tooltip title="Edit group">
                          <IconButton
                            edge="end"
                            onClick={() => handleEdit(group)}
                            disabled={loading}
                          >
                            <EditIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete group">
                          <IconButton
                            edge="end"
                            onClick={() => handleDelete(group.id)}
                            disabled={loading}
                            sx={{ ml: 1 }}
                          >
                            <DeleteIcon />
                          </IconButton>
                        </Tooltip>
                      </ListItemSecondaryAction>
                    </ListItem>
                  </React.Fragment>
                ))}
              </List>
            )}
          </Box>
        )}
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
};

export default HostGroupsDialog;
