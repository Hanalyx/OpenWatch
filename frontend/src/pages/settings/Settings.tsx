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
  Snackbar,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Security as SecurityIcon,
  Schedule as ScheduleIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  VpnKey as VpnKeyIcon,
  SettingsEthernet as SettingsEthernetIcon,
  Shield as ShieldIcon,
  Policy as PolicyIcon,
} from '@mui/icons-material';
import { api } from '../../services/api';
import { SSHKeyDisplay, type SSHKeyInfo } from '../../components/design-system';
import { useSelector } from 'react-redux';
import { RootState } from '../../store';
import AdaptiveSchedulerSettings from '../../components/settings/AdaptiveSchedulerSettings';

interface SystemCredentials {
  id: string; // WEEK 2 MIGRATION: Changed from number to UUID string for v2 API
  name: string;
  description?: string;
  scope?: string; // WEEK 2 MIGRATION: Added for v2 API (always "system")
  target_id?: string | null; // WEEK 2 MIGRATION: Added for v2 API (always null for system)
  username: string;
  auth_method: string;
  is_default: boolean;
  is_active: boolean; // WEEK 2 FIX: Include is_active for compliance visibility
  created_at: string;
  updated_at: string;
  ssh_key_fingerprint?: string | null;
  ssh_key_type?: string | null;
  ssh_key_bits?: number | null;
  ssh_key_comment?: string | null;
}

interface SSHPolicy {
  policy: string;
  trusted_networks: string[];
  description: string;
}

interface KnownHost {
  id: number;
  hostname: string;
  ip_address?: string;
  key_type: string;
  fingerprint: string;
  first_seen: string;
  last_verified?: string;
  is_trusted: boolean;
  notes?: string;
}

interface LoggingPolicy {
  id: number;
  name: string;
  enabled: boolean;
  frameworks: string[];
  created_at: string;
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
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

const Settings: React.FC = () => {
  const [tabValue, setTabValue] = useState(0);
  const [credentials, setCredentials] = useState<SystemCredentials[]>([]);
  const [showInactive, setShowInactive] = useState(false); // WEEK 2: Toggle for inactive credentials
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
    replaceKey: false,
  });
  const [keyActionLoading, setKeyActionLoading] = useState(false);

  // SSH Configuration state
  const [sshPolicy, setSSHPolicy] = useState<SSHPolicy>({
    policy: 'auto_add',
    trusted_networks: [],
    description: '',
  });
  const [knownHosts, setKnownHosts] = useState<KnownHost[]>([]);
  const [sshLoading, setSSHLoading] = useState(false);
  const [addHostKeyOpen, setAddHostKeyOpen] = useState(false);
  const [newHostKey, setNewHostKey] = useState({
    hostname: '',
    ip_address: '',
    key_type: 'rsa',
    public_key: '',
    notes: '',
  });

  // Security settings state
  const [loggingPolicies, setLoggingPolicies] = useState<LoggingPolicy[]>([]);
  const [securityLoading, setSecurityLoading] = useState(false);

  // Get user from Redux store
  const user = useSelector((state: RootState) => state.auth.user);
  const isSuperAdmin = user?.role === 'super_admin';

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const loadCredentials = async () => {
    // Only load credentials if user has super admin permissions
    if (!isSuperAdmin) {
      return;
    }

    try {
      setLoading(true);
      // Use unified credentials API with scope filter and inactive toggle
      const params = new URLSearchParams({
        scope: 'system',
        include_inactive: showInactive.toString(),
      });
      const response = await api.get(`/api/system/credentials?${params}`);
      setCredentials(response); // API directly returns array
    } catch (err: any) {
      setError('Failed to load system credentials');
      console.error('Error loading credentials:', err);
    } finally {
      setLoading(false);
    }
  };

  // SSH Configuration functions
  const loadSSHPolicy = async () => {
    try {
      setSSHLoading(true);
      const response = await api.get('/api/ssh-settings/policy');
      setSSHPolicy(response);
    } catch (err: any) {
      setError('Failed to load SSH policy');
      console.error('Error loading SSH policy:', err);
    } finally {
      setSSHLoading(false);
    }
  };

  const loadKnownHosts = async () => {
    try {
      setSSHLoading(true);
      const response = await api.get('/api/ssh-settings/known-hosts');
      setKnownHosts(response);
    } catch (err: any) {
      setError('Failed to load known hosts');
      console.error('Error loading known hosts:', err);
    } finally {
      setSSHLoading(false);
    }
  };

  const updateSSHPolicy = async (newPolicy: string, trustedNetworks: string[]) => {
    try {
      setSSHLoading(true);
      const response = await api.post('/api/ssh-settings/policy', {
        policy: newPolicy,
        trusted_networks: trustedNetworks,
      });
      setSSHPolicy(response);
      setSuccess('SSH policy updated successfully');
    } catch (err: any) {
      setError('Failed to update SSH policy');
      console.error('Error updating SSH policy:', err);
    } finally {
      setSSHLoading(false);
    }
  };

  const addKnownHost = async () => {
    try {
      setSSHLoading(true);
      await api.post('/api/ssh-settings/known-hosts', newHostKey);
      setSuccess('Host key added successfully');
      setAddHostKeyOpen(false);
      setNewHostKey({
        hostname: '',
        ip_address: '',
        key_type: 'rsa',
        public_key: '',
        notes: '',
      });
      await loadKnownHosts();
    } catch (err: any) {
      setError('Failed to add host key');
      console.error('Error adding host key:', err);
    } finally {
      setSSHLoading(false);
    }
  };

  const removeKnownHost = async (hostname: string, keyType?: string) => {
    if (!confirm(`Are you sure you want to remove the host key for ${hostname}?`)) {
      return;
    }

    try {
      setSSHLoading(true);
      const params = keyType ? `?key_type=${keyType}` : '';
      await api.delete(`/api/ssh-settings/known-hosts/${hostname}${params}`);
      setSuccess('Host key removed successfully');
      await loadKnownHosts();
    } catch (err: any) {
      setError('Failed to remove host key');
      console.error('Error removing host key:', err);
    } finally {
      setSSHLoading(false);
    }
  };

  // Security functions
  const loadLoggingPolicies = async () => {
    try {
      setSecurityLoading(true);
      // This is a placeholder - implement when backend API is available
      setLoggingPolicies([]);
    } catch (err: any) {
      setError('Failed to load logging policies');
      console.error('Error loading logging policies:', err);
    } finally {
      setSecurityLoading(false);
    }
  };

  useEffect(() => {
    if (tabValue === 0) {
      // System Settings tab
      loadCredentials();
    } else if (tabValue === 1) {
      // SSH Configuration tab
      loadSSHPolicy();
      loadKnownHosts();
    } else if (tabValue === 3) {
      // Security tab
      loadLoggingPolicies();
    }
  }, [tabValue, isSuperAdmin, showInactive]); // WEEK 2: Reload when showInactive changes

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
      replaceKey: false,
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
      replaceKey: false,
    });
    setKeyActionLoading(false);
    setDialogOpen(true);
  };

  const handleDeleteCredential = async (id: string) => {
    if (!confirm('Are you sure you want to delete this credential set?')) {
      return;
    }

    try {
      // Use unified credentials API DELETE endpoint
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
        // Update existing credential using unified credentials API
        await api.put(`/api/system/credentials/${editingCredential.id}`, formData);
        setSuccess('Credential set updated successfully');
      } else {
        // Create new credential using unified credentials API
        const createFormData = {
          ...formData,
          scope: 'system',
          target_id: null,
        };
        await api.post('/api/system/credentials', createFormData);
        setSuccess('Credential set created successfully');
      }

      setDialogOpen(false);
      loadCredentials();
    } catch (err: any) {
      // Get more specific error message from the response
      let errorMessage = editingCredential
        ? 'Failed to update credential set'
        : 'Failed to create credential set';

      if (err.response?.data?.detail) {
        errorMessage = err.response.data.detail;
      } else if (err.message && err.message !== 'API request failed') {
        errorMessage = err.message;
      }

      setError(errorMessage);
      console.error('Error saving credential:', err);
      console.error('Error response:', err.response?.data);
      console.error('Error status:', err.response?.status);
    } finally {
      setLoading(false);
    }
  };

  const handleFormChange = (field: string, value: any) => {
    setFormData((prev) => ({
      ...prev,
      [field]: value,
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
        auth_method:
          editingCredential.auth_method === 'both' ? 'password' : editingCredential.auth_method,
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
            <Tab label="SSH Configuration" />
            <Tab label="User Preferences" />
            <Tab label="Security" />
          </Tabs>
        </Box>

        <TabPanel value={tabValue} index={0}>
          {/* Adaptive Scheduler Configuration Section */}
          <AdaptiveSchedulerSettings onSuccess={setSuccess} onError={setError} />

          <Box
            sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
          >
            <Box>
              <Typography variant="h6" gutterBottom>
                <SecurityIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                SSH Credentials
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Configure master SSH credentials for hosts. If a host doesn't have specific
                credentials, it will inherit these default settings.
              </Typography>
              {!isSuperAdmin && (
                <Alert severity="info" sx={{ mt: 1 }}>
                  <Typography variant="body2">
                    <strong>SSH Credentials Required:</strong> Only Super Administrators can manage
                    SSH credentials for security reasons.
                  </Typography>
                </Alert>
              )}
            </Box>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={handleAddCredential}
              disabled={!isSuperAdmin}
            >
              Add Credentials
            </Button>
          </Box>

          {/* Helpful info for empty credentials */}
          {credentials.length === 0 && (
            <Alert severity="info" sx={{ mb: 3 }}>
              <Typography variant="subtitle2" gutterBottom>
                No System Credentials Configured (Optional)
              </Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>
                System credentials provide a default SSH credential set for all hosts. This is
                optional - you can:
              </Typography>
              <Typography variant="body2" component="ul" sx={{ ml: 2, mb: 0 }}>
                <li>Add system credentials here to use as defaults for all hosts</li>
                <li>Configure individual credentials per host (under Hosts → Edit Host)</li>
                <li>
                  Use a combination of both (host-specific credentials override system defaults)
                </li>
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
                {credentials &&
                  credentials.map((credential) => (
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
                        {credential.auth_method === 'password'
                          ? 'Password'
                          : credential.auth_method === 'ssh_key'
                            ? 'SSH Key'
                            : 'Both'}
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
                          disabled={!isSuperAdmin}
                        >
                          <EditIcon />
                        </IconButton>
                        <IconButton
                          size="small"
                          onClick={() => handleDeleteCredential(credential.id)}
                          color="error"
                          disabled={!isSuperAdmin}
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
          {/* SSH Configuration Section */}
          <Card sx={{ mb: 4, p: 3 }}>
            <Box sx={{ mb: 3 }}>
              <Typography variant="h6" gutterBottom>
                <VpnKeyIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                SSH Host Key Policy
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Configure how OpenWatch handles SSH host key verification for secure connections.
              </Typography>
            </Box>

            <FormControl fullWidth sx={{ mb: 3 }}>
              <InputLabel>SSH Host Key Policy</InputLabel>
              <Select
                value={sshPolicy.policy}
                onChange={(e) => updateSSHPolicy(e.target.value, sshPolicy.trusted_networks)}
                disabled={sshLoading}
              >
                <MenuItem value="strict">
                  <Box>
                    <Typography variant="body2" fontWeight="medium">
                      Strict
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Reject unknown hosts (most secure)
                    </Typography>
                  </Box>
                </MenuItem>
                <MenuItem value="auto_add">
                  <Box>
                    <Typography variant="body2" fontWeight="medium">
                      Auto Add
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Automatically accept and save unknown host keys
                    </Typography>
                  </Box>
                </MenuItem>
                <MenuItem value="bypass_trusted">
                  <Box>
                    <Typography variant="body2" fontWeight="medium">
                      Bypass Trusted
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Auto-add hosts in trusted network ranges
                    </Typography>
                  </Box>
                </MenuItem>
              </Select>
            </FormControl>

            {sshPolicy.policy !== 'strict' && (
              <Alert severity="info" sx={{ mb: 3 }}>
                <Typography variant="body2">
                  {sshPolicy.policy === 'auto_add'
                    ? 'Automatically accept and save unknown host keys'
                    : 'Auto-add hosts in trusted network ranges'}
                </Typography>
              </Alert>
            )}

            {sshPolicy.policy === 'bypass_trusted' && (
              <Box sx={{ mb: 3 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Trusted Networks
                </Typography>
                <TextField
                  fullWidth
                  placeholder="192.168.1.0/24, 10.0.0.0/8"
                  value={sshPolicy.trusted_networks.join(', ')}
                  onChange={(e) => {
                    const networks = e.target.value
                      .split(',')
                      .map((n) => n.trim())
                      .filter((n) => n);
                    updateSSHPolicy(sshPolicy.policy, networks);
                  }}
                  helperText="Comma-separated list of trusted network ranges (CIDR notation)"
                  disabled={sshLoading}
                />
              </Box>
            )}
          </Card>

          {/* Known SSH Hosts Section */}
          <Card sx={{ p: 3 }}>
            <Box
              sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
            >
              <Box>
                <Typography variant="h6" gutterBottom>
                  <SettingsEthernetIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                  Known SSH Hosts
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Manage trusted SSH host keys for secure connections.
                </Typography>
              </Box>
              <Button
                variant="contained"
                startIcon={<AddIcon />}
                onClick={() => setAddHostKeyOpen(true)}
                disabled={sshLoading}
              >
                Add Host Key
              </Button>
            </Box>

            <TableContainer component={Paper} variant="outlined">
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Hostname</TableCell>
                    <TableCell>IP Address</TableCell>
                    <TableCell>Key Type</TableCell>
                    <TableCell>Fingerprint</TableCell>
                    <TableCell>First Seen</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {knownHosts.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} align="center" sx={{ py: 4 }}>
                        <Typography color="text.secondary">No known hosts configured</Typography>
                      </TableCell>
                    </TableRow>
                  ) : (
                    knownHosts.map((host) => (
                      <TableRow key={`${host.hostname}-${host.key_type}`}>
                        <TableCell>{host.hostname}</TableCell>
                        <TableCell>{host.ip_address || '-'}</TableCell>
                        <TableCell>{host.key_type.toUpperCase()}</TableCell>
                        <TableCell>
                          <Typography
                            variant="body2"
                            sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}
                          >
                            {host.fingerprint}
                          </Typography>
                        </TableCell>
                        <TableCell>{new Date(host.first_seen).toLocaleDateString()}</TableCell>
                        <TableCell align="right">
                          <IconButton
                            size="small"
                            color="error"
                            onClick={() => removeKnownHost(host.hostname, host.key_type)}
                            disabled={sshLoading}
                          >
                            <DeleteIcon />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          </Card>
        </TabPanel>

        <TabPanel value={tabValue} index={2}>
          <Card sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Display Preferences
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Configure how credentials and other data are displayed in the interface.
            </Typography>

            <Box sx={{ mt: 2 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={showInactive}
                    onChange={(e) => setShowInactive(e.target.checked)}
                    color="primary"
                  />
                }
                label="Show Inactive Credentials"
              />
              <Typography
                variant="caption"
                display="block"
                color="text.secondary"
                sx={{ ml: 4, mt: 0.5 }}
              >
                Display deleted/inactive credentials for compliance audit (90-day retention)
              </Typography>
            </Box>
          </Card>
        </TabPanel>

        <TabPanel value={tabValue} index={3}>
          {/* Security Settings Section */}
          <Card sx={{ mb: 4, p: 3 }}>
            <Box
              sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
            >
              <Box>
                <Typography variant="h6" gutterBottom>
                  <PolicyIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                  Logging Policy Management
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Configure centralized audit logging policies for applications, database, and
                  network events.
                </Typography>
              </Box>
              <Button variant="contained" startIcon={<AddIcon />} disabled={securityLoading}>
                Create Policy
              </Button>
            </Box>

            {loggingPolicies.length === 0 ? (
              <Box sx={{ textAlign: 'center', py: 4 }}>
                <Typography color="text.secondary">
                  No logging policies configured. Create a policy to enable centralized audit
                  logging.
                </Typography>
              </Box>
            ) : (
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Policy Name</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Frameworks</TableCell>
                      <TableCell>Created</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {loggingPolicies.map((policy) => (
                      <TableRow key={policy.id}>
                        <TableCell>{policy.name}</TableCell>
                        <TableCell>
                          <Typography
                            variant="body2"
                            color={policy.enabled ? 'success.main' : 'text.secondary'}
                          >
                            {policy.enabled ? 'Enabled' : 'Disabled'}
                          </Typography>
                        </TableCell>
                        <TableCell>{policy.frameworks.join(', ')}</TableCell>
                        <TableCell>{new Date(policy.created_at).toLocaleDateString()}</TableCell>
                        <TableCell align="right">
                          <IconButton size="small">
                            <EditIcon />
                          </IconButton>
                          <IconButton size="small" color="error">
                            <DeleteIcon />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Card>

          {/* Compliance Framework Support Section */}
          <Card sx={{ p: 3 }}>
            <Box sx={{ mb: 3 }}>
              <Typography variant="h6" gutterBottom>
                <ShieldIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                Compliance Framework Support
              </Typography>
              <Typography variant="body2" color="text.secondary">
                OpenWatch supports the following compliance frameworks for audit logging:
              </Typography>
            </Box>

            <Box
              sx={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
                gap: 2,
              }}
            >
              {[
                { name: 'SOC2', description: 'System and Organization Controls', enabled: true },
                { name: 'HIPAA', description: 'Health Insurance Portability', enabled: true },
                { name: 'PCI-DSS', description: 'Payment Card Industry', enabled: true },
                { name: 'GDPR', description: 'General Data Protection', enabled: true },
              ].map((framework) => (
                <Card
                  key={framework.name}
                  variant="outlined"
                  sx={{
                    p: 2,
                    textAlign: 'center',
                    backgroundColor: framework.enabled ? 'action.selected' : 'background.paper',
                  }}
                >
                  <Typography variant="h6" gutterBottom>
                    {framework.name}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {framework.description}
                  </Typography>
                </Card>
              ))}
            </Box>
          </Card>
        </TabPanel>
      </Card>

      {/* Add/Edit Credential Dialog */}
      <Dialog
        open={dialogOpen}
        onClose={() => {
          setDialogOpen(false);
          // Reset replaceKey flag when closing dialog
          setFormData((prev) => ({ ...prev, replaceKey: false }));
          setKeyActionLoading(false);
        }}
        maxWidth="md"
        fullWidth
      >
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
                helperText={
                  editingCredential ? 'Leave blank to keep existing password' : 'SSH password'
                }
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
                        lastUsed: editingCredential.updated_at, // Use updated_at as approximation for last used
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
                            onClick={() =>
                              setFormData({ ...formData, replaceKey: false, private_key: '' })
                            }
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
          <Button
            onClick={() => {
              setDialogOpen(false);
              // Reset replaceKey flag when canceling
              setFormData((prev) => ({ ...prev, replaceKey: false }));
              setKeyActionLoading(false);
            }}
          >
            Cancel
          </Button>
          <Button
            onClick={handleSaveCredential}
            variant="contained"
            disabled={loading || !formData.name || !formData.username}
          >
            {loading ? 'Saving...' : editingCredential ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Add Host Key Dialog */}
      <Dialog
        open={addHostKeyOpen}
        onClose={() => setAddHostKeyOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Add SSH Host Key</DialogTitle>
        <DialogContent>
          <Box sx={{ mt: 2, display: 'grid', gap: 2 }}>
            <TextField
              label="Hostname"
              fullWidth
              value={newHostKey.hostname}
              onChange={(e) => setNewHostKey((prev) => ({ ...prev, hostname: e.target.value }))}
              helperText="The hostname or FQDN for this host key"
              required
            />

            <TextField
              label="IP Address"
              fullWidth
              value={newHostKey.ip_address}
              onChange={(e) => setNewHostKey((prev) => ({ ...prev, ip_address: e.target.value }))}
              helperText="Optional IP address for this host"
            />

            <FormControl fullWidth>
              <InputLabel>Key Type</InputLabel>
              <Select
                value={newHostKey.key_type}
                onChange={(e) => setNewHostKey((prev) => ({ ...prev, key_type: e.target.value }))}
              >
                <MenuItem value="rsa">RSA</MenuItem>
                <MenuItem value="ecdsa">ECDSA</MenuItem>
                <MenuItem value="ed25519">Ed25519</MenuItem>
                <MenuItem value="dsa">DSA</MenuItem>
              </Select>
            </FormControl>

            <TextField
              label="Public Key"
              fullWidth
              multiline
              rows={4}
              value={newHostKey.public_key}
              onChange={(e) => setNewHostKey((prev) => ({ ...prev, public_key: e.target.value }))}
              helperText="The SSH public key for this host (base64 encoded)"
              placeholder="AAAAB3NzaC1yc2EAAAA..."
              required
            />

            <TextField
              label="Notes"
              fullWidth
              multiline
              rows={2}
              value={newHostKey.notes}
              onChange={(e) => setNewHostKey((prev) => ({ ...prev, notes: e.target.value }))}
              helperText="Optional notes about this host key"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAddHostKeyOpen(false)}>Cancel</Button>
          <Button
            onClick={addKnownHost}
            variant="contained"
            disabled={sshLoading || !newHostKey.hostname || !newHostKey.public_key}
          >
            {sshLoading ? 'Adding...' : 'Add Host Key'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Success/Error Snackbars */}
      <Snackbar open={!!success} autoHideDuration={6000} onClose={() => setSuccess(null)}>
        <Alert onClose={() => setSuccess(null)} severity="success">
          {success}
        </Alert>
      </Snackbar>

      <Snackbar open={!!error} autoHideDuration={6000} onClose={() => setError(null)}>
        <Alert onClose={() => setError(null)} severity="error">
          {error}
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default Settings;
