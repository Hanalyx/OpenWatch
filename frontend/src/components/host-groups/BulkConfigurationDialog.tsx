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
  Typography,
  Box,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Checkbox,
  CircularProgress,
  Alert,
  Divider,
} from '@mui/material';
import { Warning as WarningIcon, Group as GroupIcon } from '@mui/icons-material';

interface HostGroup {
  id: number;
  name: string;
  description?: string;
  scap_content_id?: number | null;
  default_profile_id?: string | null;
  host_count: number;
}

interface SCAPContent {
  id: number;
  name: string;
  profiles: Array<{
    id: string;
    title: string;
    description?: string;
  }>;
}

interface BulkConfigurationDialogProps {
  open: boolean;
  onClose: () => void;
  groups: HostGroup[];
  onConfigurationComplete: () => void;
}

const BulkConfigurationDialog: React.FC<BulkConfigurationDialogProps> = ({
  open,
  onClose,
  groups,
  onConfigurationComplete,
}) => {
  const [selectedGroups, setSelectedGroups] = useState<number[]>([]);
  const [scapContent, setScapContent] = useState<number | ''>('');
  const [profile, setProfile] = useState<string>('');
  const [availableScapContent, setAvailableScapContent] = useState<SCAPContent[]>([]);
  const [availableProfiles, setAvailableProfiles] = useState<Array<{ id: string; title: string }>>(
    []
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filter unconfigured groups
  const unconfiguredGroups = groups.filter(
    (group) => !group.scap_content_id || !group.default_profile_id
  );

  useEffect(() => {
    if (open) {
      fetchScapContent();
      // Select all unconfigured groups by default
      setSelectedGroups(unconfiguredGroups.map((g) => g.id));
    }
  }, [open]);

  useEffect(() => {
    if (scapContent) {
      const content = availableScapContent.find((c) => c.id === scapContent);
      setAvailableProfiles(content?.profiles || []);
      setProfile(''); // Reset profile selection
    }
  }, [scapContent, availableScapContent]);

  const fetchScapContent = async () => {
    try {
      // MongoDB compliance rules endpoint - returns bundles that can be used for scanning
      const response = await fetch('/api/compliance-rules/?view_mode=bundles', {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        // MongoDB returns bundles in 'bundles' field, not 'scap_content'
        const contentList = Array.isArray(data.bundles) ? data.bundles : [];
        setAvailableScapContent(contentList);
      }
    } catch (err) {
      console.error('Error fetching SCAP content:', err);
      setError('Failed to load SCAP content');
    }
  };

  const handleGroupToggle = (groupId: number) => {
    setSelectedGroups((prev) =>
      prev.includes(groupId) ? prev.filter((id) => id !== groupId) : [...prev, groupId]
    );
  };

  const handleApplyConfiguration = async () => {
    if (selectedGroups.length === 0) {
      setError('Please select at least one group');
      return;
    }

    if (!scapContent || !profile) {
      setError('Please select both SCAP content and profile');
      return;
    }

    try {
      setLoading(true);
      setError(null);

      // Update each selected group
      const updatePromises = selectedGroups.map((groupId) =>
        fetch(`/api/host-groups/${groupId}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
          },
          body: JSON.stringify({
            scap_content_id: scapContent,
            default_profile_id: profile,
          }),
        })
      );

      await Promise.all(updatePromises);

      onConfigurationComplete();
      onClose();
    } catch (err) {
      console.error('Error applying bulk configuration:', err);
      setError('Failed to apply configuration to selected groups');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <WarningIcon color="warning" />
          Bulk SCAP Configuration
        </Box>
      </DialogTitle>

      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        <Typography variant="body1" gutterBottom>
          Configure SCAP compliance settings for multiple groups at once.
          {unconfiguredGroups.length} groups need SCAP configuration.
        </Typography>

        <Divider sx={{ my: 2 }} />

        {/* Group Selection */}
        <Typography variant="h6" gutterBottom>
          Select Groups to Configure
        </Typography>

        <List
          sx={{
            maxHeight: 200,
            overflow: 'auto',
            border: 1,
            borderColor: 'divider',
            borderRadius: 1,
          }}
        >
          {unconfiguredGroups.map((group) => (
            <ListItem key={group.id} dense button onClick={() => handleGroupToggle(group.id)}>
              <ListItemIcon>
                <Checkbox checked={selectedGroups.includes(group.id)} tabIndex={-1} disableRipple />
              </ListItemIcon>
              <ListItemIcon>
                <GroupIcon />
              </ListItemIcon>
              <ListItemText primary={group.name} secondary={`${group.host_count} hosts`} />
            </ListItem>
          ))}
        </List>

        <Box sx={{ mt: 3 }}>
          <Typography variant="body2" color="text.secondary">
            {selectedGroups.length} of {unconfiguredGroups.length} groups selected
          </Typography>
        </Box>

        <Divider sx={{ my: 2 }} />

        {/* SCAP Configuration */}
        <Typography variant="h6" gutterBottom>
          SCAP Configuration
        </Typography>

        <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
          <FormControl fullWidth>
            <InputLabel>SCAP Content</InputLabel>
            <Select
              value={scapContent}
              onChange={(e) => setScapContent(e.target.value as number)}
              label="SCAP Content"
            >
              <MenuItem value="">
                <em>Select SCAP Content</em>
              </MenuItem>
              {availableScapContent.map((content) => (
                <MenuItem key={content.id} value={content.id}>
                  {content.name}
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          <FormControl fullWidth disabled={!scapContent}>
            <InputLabel>Default Profile</InputLabel>
            <Select
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
              label="Default Profile"
            >
              <MenuItem value="">
                <em>Select Profile</em>
              </MenuItem>
              {availableProfiles.map((profileOption) => (
                <MenuItem key={profileOption.id} value={profileOption.id}>
                  {profileOption.title}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Box>

        {scapContent && profile && (
          <Alert severity="info" sx={{ mt: 2 }}>
            Configuration will be applied to {selectedGroups.length} selected groups.
          </Alert>
        )}
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose} disabled={loading}>
          Cancel
        </Button>
        <Button
          variant="contained"
          onClick={handleApplyConfiguration}
          disabled={loading || selectedGroups.length === 0 || !scapContent || !profile}
        >
          {loading ? <CircularProgress size={20} /> : `Configure ${selectedGroups.length} Groups`}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default BulkConfigurationDialog;
