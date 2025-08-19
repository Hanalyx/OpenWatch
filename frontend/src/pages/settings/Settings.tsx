import React, { useState, useEffect } from 'react';
import {
  Container,
  Typography,
  Box,
  Card,
  CardContent,
  Tabs,
  Tab,
  Button,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Alert,
  Snackbar
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Security as SecurityIcon,
  Schedule as ScheduleIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon
} from '@mui/icons-material';
import { api } from '../../services/api';
import { SSHKeyDisplay, type SSHKeyInfo } from '../../components/design-system';

interface SystemCredentials {
  id: number;
  name: string;
  description?: string;
  username: string;
  auth_method: string;
  is_default: boolean;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  ssh_key_fingerprint?: string | null;
  ssh_key_type?: string | null;
  ssh_key_bits?: number | null;
  ssh_key_comment?: string | null;
}

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
      id={`settings-tabpanel-${index}`}
      aria-labelledby={`settings-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

const Settings: React.FC = () => {
  const [tabValue, setTabValue] = useState(0);
  const [credentials, setCredentials] = useState<SystemCredentials[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingCredential, setEditingCredential] = useState<SystemCredentials | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    username: '',
    auth_method: 'password',
    password: '',
    private_key: '',
    private_key_passphrase: '',
    is_default: false,
    replaceKey: false
  });
  const [keyActionLoading, setKeyActionLoading] = useState(false);

  // Scheduler settings state
  const [schedulerSettings, setSchedulerSettings] = useState({
    enabled: false,
    interval_minutes: 5,
    status: 'stopped'
  });
  const [schedulerLoading, setSchedulerLoading] = useState(false);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const loadCredentials = async () => {
    try {
      setLoading(true);
      const response = await api.get('/api/system/credentials');
      setCredentials(response); // API directly returns array
    } catch (err: any) {
      setError('Failed to load system credentials');
      console.error('Error loading credentials:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadSchedulerSettings = async () => {
    try {
      setLoading(true);
      const response = await api.get('/api/system/scheduler');
      setSchedulerSettings(response);
    } catch (err: any) {
      setError('Failed to load scheduler settings');
      console.error('Error loading scheduler settings:', err);
    } finally {
      setLoading(false);
    }
  };

  const toggleScheduler = async () => {
    try {
      setSchedulerLoading(true);
      const newEnabled = !schedulerSettings.enabled;
      
      if (newEnabled) {
        await api.post('/api/system/scheduler/start', {
          interval_minutes: schedulerSettings.interval_minutes
        });
        setSuccess('Host monitoring scheduler started');
      } else {
        await api.post('/api/system/scheduler/stop');
        setSuccess('Host monitoring scheduler stopped');
      }
      
      // Reload settings to get updated status
      await loadSchedulerSettings();
    } catch (err: any) {
      setError('Failed to toggle scheduler');
      console.error('Error toggling scheduler:', err);
    } finally {
      setSchedulerLoading(false);
    }
  };

  const updateSchedulerInterval = async (newInterval: number) => {
    try {
      setSchedulerLoading(true);
      await api.put('/api/system/scheduler', {
        interval_minutes: newInterval
      });
      setSchedulerSettings(prev => ({
        ...prev,
        interval_minutes: newInterval
      }));
      setSuccess('Scheduler interval updated');
    } catch (err: any) {
      setError('Failed to update scheduler interval');
      console.error('Error updating scheduler interval:', err);
    } finally {
      setSchedulerLoading(false);
    }
  };

  useEffect(() => {
    if (tabValue === 0) { // System Settings tab
      loadCredentials();
      loadSchedulerSettings();
    }
  }, [tabValue]);

  const handleAddCredential = () => {
    setEditingCredential(null);
    setFormData({
      name: '',
      description: '',
      username: '',
      auth_method: 'password',
      password: '',
      private_key: '',
      private_key_passphrase: '',
      is_default: false,
      replaceKey: false
    });
    setKeyActionLoading(false);
    setDialogOpen(true);
  };

  const handleEditCredential = (credential: SystemCredentials) => {
    setEditingCredential(credential);
    setFormData({
      name: credential.name,
      description: credential.description || '',
      username: credential.username,
      auth_method: credential.auth_method,
      password: '',
      private_key: '',
      private_key_passphrase: '',
      is_default: credential.is_default,
      replaceKey: false
    });
    setKeyActionLoading(false);
    setDialogOpen(true);
  };

  const handleDeleteCredential = async (id: number) => {
    if (!confirm('Are you sure you want to delete this credential set?')) {
      return;
    }

    try {
      await api.delete(`/api/system/credentials/${id}`);
      setSuccess('Credential set deleted successfully');
      loadCredentials();
    } catch (err: any) {
      const errorMessage = err.response?.data?.detail || 'Failed to delete credential set';
      setError(errorMessage);
      console.error('Error deleting credential:', err);
    }
  };

  const handleSaveCredential = async () => {
    try {
      setLoading(true);
      
      if (editingCredential) {
        // Update existing credential
        await api.put(`/api/system/credentials/${editingCredential.id}`, formData);
        setSuccess('Credential set updated successfully');
      } else {
        // Create new credential
        await api.post('/api/system/credentials', formData);
        setSuccess('Credential set created successfully');
      }
      
      setDialogOpen(false);
      loadCredentials();
    } catch (err: any) {
      setError(editingCredential ? 'Failed to update credential set' : 'Failed to create credential set');
      console.error('Error saving credential:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleFormChange = (field: string, value: any) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const handleDeleteSSHKey = async () => {
    if (!editingCredential) return;
    
    try {
      setKeyActionLoading(true);
      await api.delete(`/api/system/credentials/${editingCredential.id}/ssh-key`);
      setSuccess('SSH key deleted successfully');
      
      // Update local state to reflect the key deletion
      const updatedCredential = {
        ...editingCredential,
        ssh_key_fingerprint: null,
        ssh_key_type: null,
        ssh_key_bits: null,
        ssh_key_comment: null,
        auth_method: editingCredential.auth_method === 'both' ? 'password' : editingCredential.auth_method
      };
      setEditingCredential(updatedCredential);
      
      // Reload credentials to get updated data
      loadCredentials();
    } catch (err: any) {
      const errorMessage = err.response?.data?.detail || 'Failed to delete SSH key';
      setError(errorMessage);
      console.error('Error deleting SSH key:', err);
    } finally {
      setKeyActionLoading(false);
    }
  };

  return (
    <Container maxWidth="lg" sx={{ py: 2 }}>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          Settings
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Configure system-wide settings and preferences
        </Typography>
      </Box>

      <Card>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={tabValue} onChange={handleTabChange}>
            <Tab label="System Settings" />
            <Tab label="User Preferences" disabled />
            <Tab label="Security" disabled />
          </Tabs>
        </Box>

        <TabPanel value={tabValue} index={0}>
          {/* Scheduler Configuration Section */}
          <Card sx={{ mb: 4, p: 3 }}>
            <Box sx={{ mb: 3 }}>
              <Typography variant="h6" gutterBottom>
                <ScheduleIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                Host Monitoring Scheduler
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Configure automatic host monitoring to check connectivity and SSH access at regular intervals.
              </Typography>
            </Box>

            <Box sx={{ display: 'flex', alignItems: 'center', gap: 3, mb: 3 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={schedulerSettings.enabled}
                    onChange={toggleScheduler}
                    disabled={schedulerLoading}
                  />
                }
                label={schedulerSettings.enabled ? "Automatic monitoring enabled" : "Automatic monitoring disabled"}
              />
              
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography variant="body2" color="text.secondary">
                  Status:
                </Typography>
                <Typography 
                  variant="body2" 
                  color={schedulerSettings.status === 'running' ? 'success.main' : 'text.secondary'}
                  fontWeight="medium"
                >
                  {schedulerSettings.status?.toUpperCase() || 'UNKNOWN'}
                </Typography>
              </Box>
            </Box>

            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
              <TextField
                label="Check Interval (minutes)"
                type="number"
                size="small"
                value={schedulerSettings.interval_minutes}
                onChange={(e) => {
                  const value = parseInt(e.target.value);
                  if (value >= 1 && value <= 1440) { // 1 minute to 24 hours
                    setSchedulerSettings(prev => ({
                      ...prev,
                      interval_minutes: value
                    }));
                  }
                }}
                onBlur={() => updateSchedulerInterval(schedulerSettings.interval_minutes)}
                inputProps={{ min: 1, max: 1440 }}
                sx={{ width: 200 }}
                helperText="1-1440 minutes"
                disabled={schedulerLoading}
              />
              
              <Button
                variant="outlined"
                size="small"
                startIcon={schedulerSettings.enabled ? <StopIcon /> : <PlayIcon />}
                onClick={toggleScheduler}
                disabled={schedulerLoading}
              >
                {schedulerLoading ? 'Updating...' : schedulerSettings.enabled ? 'Stop Scheduler' : 'Start Scheduler'}
              </Button>
            </Box>

            <Alert severity="info" sx={{ mt: 2 }}>
              When enabled, the system will automatically check all hosts every {schedulerSettings.interval_minutes} minutes to update their connectivity status (ping, port accessibility, and SSH login capability).
            </Alert>
          </Card>

          <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Box>
              <Typography variant="h6" gutterBottom>
                <SecurityIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                SSH Credentials
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Configure master SSH credentials for hosts. If a host doesn't have specific credentials, it will inherit these default settings.
              </Typography>
            </Box>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={handleAddCredential}
            >
              Add Credentials
            </Button>
          </Box>

          {/* Warning for placeholder credentials */}
          {credentials.length > 0 && credentials.some(cred => cred.name.includes("Setup Required")) && (
            <Alert severity="warning" sx={{ mb: 3 }}>
              <Typography variant="subtitle2" gutterBottom>
                Action Required: Update Default SSH Credentials
              </Typography>
              <Typography variant="body2">
                Default placeholder credentials were created during system initialization. 
                Please update these credentials with your actual SSH username, password, or SSH key to enable remote scanning and host monitoring.
              </Typography>
            </Alert>
          )}

          {/* Info for empty credentials */}
          {credentials.length === 0 && (
            <Alert severity="info" sx={{ mb: 3 }}>
              <Typography variant="subtitle2" gutterBottom>
                SSH Credentials Required
              </Typography>
              <Typography variant="body2">
                Configure SSH credentials to enable remote scanning and host monitoring. 
                These credentials will be used when individual hosts don't have specific credentials configured.
              </Typography>
            </Alert>
          )}

          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Name</TableCell>
                  <TableCell>Username</TableCell>
                  <TableCell>Auth Method</TableCell>
                  <TableCell>Default</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {credentials && credentials.map((credential) => (
                  <TableRow key={credential.id}>
                    <TableCell>
                      <Box>
                        <Typography variant="body2" fontWeight="medium">
                          {credential.name}
                        </Typography>
                        {credential.description && (
                          <Typography variant="caption" color="text.secondary">
                            {credential.description}
                          </Typography>
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>{credential.username}</TableCell>
                    <TableCell>
                      {credential.auth_method === 'password' ? 'Password' : 
                       credential.auth_method === 'ssh_key' ? 'SSH Key' : 'Both'}
                    </TableCell>
                    <TableCell>
                      {credential.is_default && (
                        <Typography variant="caption" color="primary" fontWeight="medium">
                          DEFAULT
                        </Typography>
                      )}
                    </TableCell>
                    <TableCell>
                      <Typography
                        variant="caption"
                        color={credential.is_active ? 'success.main' : 'error.main'}
                        fontWeight="medium"
                      >
                        {credential.is_active ? 'ACTIVE' : 'INACTIVE'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <IconButton
                        size="small"
                        onClick={() => handleEditCredential(credential)}
                        sx={{ mr: 1 }}
                      >
                        <EditIcon />
                      </IconButton>
                      <IconButton
                        size="small"
                        onClick={() => handleDeleteCredential(credential.id)}
                        color="error"
                      >
                        <DeleteIcon />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
                {credentials.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={6} align="center">
                      <Typography color="text.secondary">
                        No system credentials configured
                      </Typography>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </TabPanel>

        <TabPanel value={tabValue} index={1}>
          <Typography variant="h6">User Preferences</Typography>
          <Typography color="text.secondary">Coming soon...</Typography>
        </TabPanel>

        <TabPanel value={tabValue} index={2}>
          <Typography variant="h6">Security Settings</Typography>
          <Typography color="text.secondary">Coming soon...</Typography>
        </TabPanel>
      </Card>

      {/* Add/Edit Credential Dialog */}
      <Dialog open={dialogOpen} onClose={() => {
        setDialogOpen(false);
        // Reset replaceKey flag when closing dialog
        setFormData(prev => ({ ...prev, replaceKey: false }));
        setKeyActionLoading(false);
      }} maxWidth="md" fullWidth>
        <DialogTitle>
          {editingCredential ? 'Edit SSH Credentials' : 'Add SSH Credentials'}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2, display: 'grid', gap: 2 }}>
            <TextField
              label="Name"
              fullWidth
              value={formData.name}
              onChange={(e) => handleFormChange('name', e.target.value)}
              helperText="A descriptive name for this credential set"
            />
            
            <TextField
              label="Description"
              fullWidth
              multiline
              rows={2}
              value={formData.description}
              onChange={(e) => handleFormChange('description', e.target.value)}
              helperText="Optional description of when to use these credentials"
            />
            
            <TextField
              label="Username"
              fullWidth
              value={formData.username}
              onChange={(e) => handleFormChange('username', e.target.value)}
              helperText="SSH username for remote hosts"
            />
            
            <FormControl fullWidth>
              <InputLabel>Authentication Method</InputLabel>
              <Select
                value={formData.auth_method}
                onChange={(e) => handleFormChange('auth_method', e.target.value)}
                label="Authentication Method"
              >
                <MenuItem value="password">Password</MenuItem>
                <MenuItem value="ssh_key">SSH Key</MenuItem>
                <MenuItem value="both">Both (Password + SSH Key)</MenuItem>
              </Select>
            </FormControl>
            
            {(formData.auth_method === 'password' || formData.auth_method === 'both') && (
              <TextField
                label="Password"
                type="password"
                fullWidth
                value={formData.password}
                onChange={(e) => handleFormChange('password', e.target.value)}
                helperText={editingCredential ? "Leave blank to keep existing password" : "SSH password"}
              />
            )}
            
            {(formData.auth_method === 'ssh_key' || formData.auth_method === 'both') && (
              <>
                {editingCredential && editingCredential.ssh_key_fingerprint ? (
                  // Show SSH key information when editing existing credential
                  <>
                    <Typography variant="subtitle2" sx={{ mb: 1 }}>
                      Current SSH Key
                    </Typography>
                    <SSHKeyDisplay
                      sshKeyInfo={{
                        fingerprint: editingCredential.ssh_key_fingerprint,
                        keyType: editingCredential.ssh_key_type,
                        keyBits: editingCredential.ssh_key_bits,
                        keyComment: editingCredential.ssh_key_comment,
                        createdAt: editingCredential.created_at,
                        lastUsed: editingCredential.updated_at // Use updated_at as approximation for last used
                      }}
                      showActions={true}
                      onReplace={() => {
                        // Enable key replacement by clearing the display and showing text field
                        setFormData({ ...formData, replaceKey: true });
                      }}
                      onDelete={handleDeleteSSHKey}
                      loading={keyActionLoading}
                      compact={false}
                    />
                    {formData.replaceKey ? (
                      <Box sx={{ mt: 2 }}>
                        <TextField
                          label="New Private Key"
                          fullWidth
                          multiline
                          rows={6}
                          value={formData.private_key}
                          onChange={(e) => handleFormChange('private_key', e.target.value)}
                          helperText="Enter new SSH private key (PEM format)"
                          placeholder="-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----"
                        />
                        <Box sx={{ mt: 1, display: 'flex', gap: 1 }}>
                          <Button
                            size="small"
                            onClick={() => setFormData({ ...formData, replaceKey: false, private_key: '' })}
                          >
                            Cancel
                          </Button>
                        </Box>
                      </Box>
                    ) : null}
                  </>
                ) : (
                  // Show text field for new credential or when no existing key
                  <TextField
                    label="Private Key"
                    fullWidth
                    multiline
                    rows={6}
                    value={formData.private_key}
                    onChange={(e) => handleFormChange('private_key', e.target.value)}
                    helperText="SSH private key (PEM format)"
                    placeholder="-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----"
                  />
                )}
                
                <TextField
                  label="Private Key Passphrase"
                  type="password"
                  fullWidth
                  value={formData.private_key_passphrase}
                  onChange={(e) => handleFormChange('private_key_passphrase', e.target.value)}
                  helperText="Optional passphrase for encrypted private key"
                />
              </>
            )}
            
            <FormControlLabel
              control={
                <Switch
                  checked={formData.is_default}
                  onChange={(e) => handleFormChange('is_default', e.target.checked)}
                />
              }
              label="Set as default credentials"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => {
            setDialogOpen(false);
            // Reset replaceKey flag when canceling
            setFormData(prev => ({ ...prev, replaceKey: false }));
            setKeyActionLoading(false);
          }}>Cancel</Button>
          <Button
            onClick={handleSaveCredential}
            variant="contained"
            disabled={loading || !formData.name || !formData.username}
          >
            {loading ? 'Saving...' : editingCredential ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Success/Error Snackbars */}
      <Snackbar
        open={!!success}
        autoHideDuration={6000}
        onClose={() => setSuccess(null)}
      >
        <Alert onClose={() => setSuccess(null)} severity="success">
          {success}
        </Alert>
      </Snackbar>
      
      <Snackbar
        open={!!error}
        autoHideDuration={6000}
        onClose={() => setError(null)}
      >
        <Alert onClose={() => setError(null)} severity="error">
          {error}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default Settings;