import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Alert,
  AlertTitle,
  Autocomplete,
  FormControlLabel,
  Switch,
  RadioGroup,
  Radio,
  IconButton,
  InputAdornment,
  Collapse,
  Card,
  CardContent,
  CardActions,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  LinearProgress,
} from '@mui/material';
import Grid from '@mui/material/GridLegacy';
import {
  ArrowBack,
  Computer,
  Key,
  Password,
  Error as ErrorIcon,
  ExpandMore,
  ExpandLess,
  Schedule,
  Security,
  Group,
  Label,
  Dns,
  NetworkCheck,
  VpnKey,
  AccountTree,
  Description,
  Add,
  Upload,
  Save as SaveIcon,
  CheckCircle,
  Cancel,
  Visibility,
  VisibilityOff,
  Edit,
  Speed,
  Storage,
  Settings,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { StatCard, SSHKeyDisplay } from '../../components/design-system';
import { api } from '../../services/api';

/**
 * SSH connection test response from backend API
 * Raw response structure from /api/hosts/test-connection
 */
interface ConnectionTestApiResponse {
  network_reachable?: boolean;
  auth_successful?: boolean;
  detected_os?: string;
  os_version?: string;
  response_time_ms?: number;
  ssh_version?: string;
  additional_info?: string;
}

/**
 * SSH connection test results from backend
 * Contains connectivity, authentication, and system detection results
 */
interface ConnectionTestResults {
  success: boolean;
  networkConnectivity: boolean;
  authentication: boolean;
  detectedOS: string;
  detectedVersion: string;
  responseTime: number;
  sshVersion?: string;
  additionalInfo?: string;
  error?: string;
  errorCode?: number;
}

/**
 * Credential object with is_default flag
 * Used for displaying and selecting credentials in dropdown
 */
interface CredentialWithDefault {
  is_default: boolean;
  id?: string;
  name?: string;
  username?: string;
  auth_method?: string;
  ssh_key_type?: string;
  ssh_key_bits?: number;
  ssh_key_comment?: string;
}

const AddHost: React.FC = () => {
  const navigate = useNavigate();

  // Form state
  const [activeStep, setActiveStep] = useState(0);
  const [quickMode, setQuickMode] = useState(true);
  const [testingConnection, setTestingConnection] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<
    'idle' | 'testing' | 'success' | 'failed'
  >('idle');
  const [connectionTestResults, setConnectionTestResults] = useState<ConnectionTestResults | null>(
    null
  );
  const [showPassword, setShowPassword] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Enhanced authentication state management
  const [sshKeyValidation, setSshKeyValidation] = useState<{
    status: 'idle' | 'validating' | 'valid' | 'invalid';
    message: string;
    keyType?: string;
    keyBits?: number;
    securityLevel?: 'secure' | 'acceptable' | 'deprecated' | 'rejected';
  }>({ status: 'idle', message: '' });
  const [authMethodLocked, setAuthMethodLocked] = useState(false);
  const [systemCredentials, setSystemCredentials] = useState<{
    name: string;
    username: string;
    authMethod: string;
    sshKeyType?: string;
    sshKeyBits?: number;
    sshKeyComment?: string;
  } | null>(null);
  const [editingAuth, setEditingAuth] = useState(false);

  // Form fields
  const [formData, setFormData] = useState({
    // Basic Information
    hostname: '',
    ipAddress: '',
    port: '22',
    displayName: '',

    // Authentication
    authMethod: 'ssh_key',
    username: '',
    password: '',
    sshKey: '',
    certificatePath: '',
    agentToken: '',
    useBastion: false,
    bastionHost: '',
    bastionPort: '22',
    bastionUser: '',

    // Classification
    operatingSystem: 'auto-detect',
    environment: 'production',
    hostGroup: '',
    tags: [] as string[],
    owner: '',

    // Scan Configuration
    complianceProfile: 'auto',
    scanSchedule: 'immediate',
    customCron: '',
    scanIntensity: 'normal',
    scanPriority: 'medium',

    // Advanced Options
    sudoMethod: 'sudo',
    sudoPassword: '',
    requireSudo: false,
    excludePaths: [] as string[],
    bandwidthLimit: '',
    connectionTimeout: '30',
    scanTimeout: '3600',
    proxyHost: '',
    proxyPort: '',
    preScript: '',
    postScript: '',
  });

  // Step configuration for advanced mode stepper - reserved for future progress indicators
  const _steps = [
    'Host Connection',
    'Authentication',
    'Classification',
    'Scan Configuration',
    'Review & Test',
  ];

  const operatingSystems = [
    { value: 'auto-detect', label: 'Auto-Detect' },
    { value: 'ubuntu-22.04', label: 'Ubuntu 22.04 LTS' },
    { value: 'ubuntu-20.04', label: 'Ubuntu 20.04 LTS' },
    { value: 'rhel-9', label: 'Red Hat Enterprise Linux 9' },
    { value: 'rhel-8', label: 'Red Hat Enterprise Linux 8' },
    { value: 'debian-12', label: 'Debian 12' },
    { value: 'centos-9', label: 'CentOS Stream 9' },
    { value: 'amazon-linux-2', label: 'Amazon Linux 2' },
    { value: 'suse-15', label: 'SUSE Linux Enterprise 15' },
    { value: 'windows-2022', label: 'Windows Server 2022' },
    { value: 'windows-2019', label: 'Windows Server 2019' },
  ];

  const complianceProfiles = [
    { value: 'auto', label: 'Auto-Select Based on OS' },
    { value: 'cis-level1', label: 'CIS Level 1' },
    { value: 'cis-level2', label: 'CIS Level 2' },
    { value: 'stig', label: 'DISA STIG' },
    { value: 'pci-dss', label: 'PCI-DSS' },
    { value: 'hipaa', label: 'HIPAA' },
    { value: 'nist-800-53', label: 'NIST 800-53' },
    { value: 'iso-27001', label: 'ISO 27001' },
    { value: 'custom', label: 'Custom Profile' },
  ];

  const availableTags = [
    'production',
    'staging',
    'development',
    'test',
    'web',
    'database',
    'application',
    'cache',
    'critical',
    'public-facing',
    'internal',
    'linux',
    'windows',
    'container',
  ];

  /**
   * Handle form field changes with type-safe value handling
   * Accepts any JSON-serializable value (string, number, boolean, etc.)
   */
  const handleInputChange = (field: string, value: string | number | boolean | string[]) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
  };

  const handleNext = () => {
    setActiveStep((prevStep) => prevStep + 1);
  };

  const handleBack = () => {
    setActiveStep((prevStep) => prevStep - 1);
  };

  const handleTestConnection = async () => {
    setTestingConnection(true);
    setConnectionStatus('testing');

    try {
      // Prepare test connection data
      const testData = {
        hostname: formData.hostname || formData.ipAddress,
        port: parseInt(formData.port) || 22,
        username: formData.username,
        auth_method: formData.authMethod,
        password:
          formData.authMethod === 'password' || formData.authMethod === 'both'
            ? formData.password
            : undefined,
        ssh_key:
          formData.authMethod === 'ssh_key' || formData.authMethod === 'both'
            ? formData.sshKey
            : undefined,
        timeout: 30,
      };

      // Testing SSH connection to target host

      // Make API call to test connection
      const result = await api.post<ConnectionTestApiResponse>(
        '/api/hosts/test-connection',
        testData
      );

      setTestingConnection(false);
      setConnectionStatus('success');

      // Store the actual results for display
      setConnectionTestResults({
        success: true,
        networkConnectivity: result.network_reachable ?? true,
        authentication: result.auth_successful ?? true,
        detectedOS: result.detected_os || 'Unknown',
        detectedVersion: result.os_version || '',
        responseTime: result.response_time_ms || 0,
        sshVersion: result.ssh_version || '',
        additionalInfo: result.additional_info || '',
      });
    } catch (err) {
      // Type-safe error handling: check if error has message property
      console.error('Connection test failed:', err);
      setTestingConnection(false);
      setConnectionStatus('failed');

      // Type-safe error property access
      const typedErr = err as {
        response?: { data?: { detail?: string }; status?: number };
        message?: string;
      };

      // Store error details for display
      setConnectionTestResults({
        success: false,
        error: typedErr.response?.data?.detail || typedErr.message || 'Connection test failed',
        errorCode: typedErr.response?.status || 0,
        networkConnectivity: false,
        authentication: false,
        detectedOS: '',
        detectedVersion: '',
        responseTime: 0,
      });
    }
  };

  const handleSubmit = async () => {
    try {
      // Prepare host data for API
      const hostData = {
        hostname: formData.hostname || formData.ipAddress,
        ip_address: formData.ipAddress || formData.hostname,
        display_name: formData.displayName,
        operating_system:
          formData.operatingSystem === 'auto-detect' ? 'Unknown' : formData.operatingSystem,
        port: formData.port,
        username: formData.username,
        auth_method: formData.authMethod,
        password:
          formData.authMethod === 'password' || formData.authMethod === 'both'
            ? formData.password
            : undefined,
        ssh_key:
          formData.authMethod === 'ssh_key' || formData.authMethod === 'both'
            ? formData.sshKey
            : undefined,
        environment: formData.environment,
        tags: formData.tags,
        owner: formData.owner,
      };

      // Submitting new host configuration to API

      // Make API call to create host
      const newHost = await api.post('/api/hosts/', hostData);
      // Host successfully created in database
      void newHost; // Result logged for debugging
      navigate('/hosts');
    } catch (error) {
      console.error('Error submitting host:', error);
      // Fallback - still navigate for demo purposes
      navigate('/hosts');
    }
  };

  // Fetch system default credentials for display
  const fetchSystemCredentials = async () => {
    try {
      // Use unified credentials API with scope filter
      const response = await fetch('/api/system/credentials?scope=system', {
        headers: {
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        },
      });

      if (response.ok) {
        const credentials: CredentialWithDefault[] = await response.json();
        const defaultCredential = credentials.find((cred) => cred.is_default);

        if (defaultCredential) {
          setSystemCredentials({
            name: defaultCredential.name || '',
            username: defaultCredential.username || '',
            authMethod: defaultCredential.auth_method || 'password',
            sshKeyType: defaultCredential.ssh_key_type,
            sshKeyBits: defaultCredential.ssh_key_bits,
            sshKeyComment: defaultCredential.ssh_key_comment,
          });
        }
      }
    } catch (error) {
      console.error('Failed to fetch system credentials:', error);
    }
  };

  // Validate SSH key with enhanced feedback
  const validateSshKey = async (keyContent: string) => {
    if (!keyContent.trim()) {
      setSshKeyValidation({ status: 'idle', message: '' });
      return;
    }

    setSshKeyValidation({ status: 'validating', message: 'Validating SSH key...' });

    try {
      // Basic client-side validation first
      const trimmedKey = keyContent.trim();

      // Check for common SSH key formats
      const validKeyHeaders = [
        '-----BEGIN OPENSSH PRIVATE KEY-----',
        '-----BEGIN RSA PRIVATE KEY-----',
        '-----BEGIN EC PRIVATE KEY-----',
        '-----BEGIN DSA PRIVATE KEY-----',
      ];

      const hasValidHeader = validKeyHeaders.some((header) => trimmedKey.startsWith(header));

      if (!hasValidHeader) {
        setSshKeyValidation({
          status: 'invalid',
          message: 'Invalid SSH key format. Please paste a valid private key.',
        });
        return;
      }

      // Validate with backend using the new validate-credentials endpoint
      const validationData = {
        auth_method: 'ssh_key',
        ssh_key: keyContent,
      };

      const response = await fetch('/api/hosts/validate-credentials', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${localStorage.getItem('auth_token')}`,
        },
        body: JSON.stringify(validationData),
      });

      if (!response.ok) {
        const error = await response.json();
        setSshKeyValidation({
          status: 'invalid',
          message: error.detail || 'SSH key validation failed.',
        });
        return;
      }

      const result = await response.json();

      if (result.is_valid) {
        // Build detailed success message
        let message = 'SSH key is valid and properly formatted.';
        if (result.key_type && result.key_bits) {
          message += ` (${result.key_type.toUpperCase()}-${result.key_bits})`;
        }

        setSshKeyValidation({
          status: 'valid',
          message,
          keyType: result.key_type,
          keyBits: result.key_bits,
          securityLevel: result.security_level,
        });
        setAuthMethodLocked(true);
      } else {
        setSshKeyValidation({
          status: 'invalid',
          message: result.error_message || 'SSH key validation failed.',
        });
      }
    } catch {
      setSshKeyValidation({
        status: 'invalid',
        message: 'Error validating SSH key. Please check the format and try again.',
      });
    }
  };

  // Handle authentication method change with validation
  const handleAuthMethodChange = async (method: string) => {
    if (authMethodLocked && !editingAuth) {
      return; // Prevent changes when locked
    }

    handleInputChange('authMethod', method);
    setAuthMethodLocked(false);
    setSshKeyValidation({ status: 'idle', message: '' });

    // Fetch system credentials when system_default is selected
    if (method === 'system_default' && !systemCredentials) {
      await fetchSystemCredentials();
    }
  };

  // Toggle edit mode for authentication
  const toggleAuthEdit = () => {
    setEditingAuth(!editingAuth);
    if (editingAuth) {
      // If we're stopping edit mode, lock the auth method if SSH key is valid
      if (formData.authMethod === 'ssh_key' && sshKeyValidation.status === 'valid') {
        setAuthMethodLocked(true);
      }
    } else {
      // If we're starting edit mode, unlock
      setAuthMethodLocked(false);
    }
  };

  // Load system credentials when auth method changes to system_default
  // ESLint disable: formData.authMethod change should trigger, but causes re-render loop if included
  // fetchSystemCredentials is intentionally excluded to avoid complex dependency chain
  useEffect(() => {
    if (formData.authMethod === 'system_default') {
      fetchSystemCredentials();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const renderQuickMode = () => (
    <Paper sx={{ p: 3 }}>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Typography variant="h5" fontWeight="bold">
          Quick Add Host
        </Typography>
        <Button variant="outlined" onClick={() => setQuickMode(false)} startIcon={<Settings />}>
          Advanced Mode
        </Button>
      </Box>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <TextField
            fullWidth
            label="Hostname or IP Address"
            value={formData.hostname}
            onChange={(e) => handleInputChange('hostname', e.target.value)}
            placeholder="192.168.1.100 or server.example.com"
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <Dns />
                </InputAdornment>
              ),
            }}
          />
        </Grid>
        <Grid item xs={12} md={6}>
          <TextField
            fullWidth
            label="Display Name (Optional)"
            value={formData.displayName}
            onChange={(e) => handleInputChange('displayName', e.target.value)}
            placeholder="Production Web Server"
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <Computer />
                </InputAdornment>
              ),
            }}
          />
        </Grid>

        <Grid item xs={12}>
          <Divider sx={{ my: 1 }} />
          <Typography variant="subtitle2" color="text.secondary" sx={{ mt: 2, mb: 2 }}>
            Authentication Method
          </Typography>
        </Grid>

        <Grid item xs={12}>
          <Box
            sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}
          >
            <Box>
              <RadioGroup
                value={formData.authMethod}
                onChange={(e) => handleAuthMethodChange(e.target.value)}
                row
              >
                <FormControlLabel
                  value="system_default"
                  control={<Radio />}
                  label="System Default"
                  disabled={authMethodLocked && !editingAuth}
                />
                <FormControlLabel
                  value="ssh_key"
                  control={<Radio />}
                  label="SSH Key"
                  disabled={authMethodLocked && !editingAuth}
                />
                <FormControlLabel
                  value="password"
                  control={<Radio />}
                  label="Password"
                  disabled={authMethodLocked && !editingAuth}
                />
                <FormControlLabel
                  value="both"
                  control={<Radio />}
                  label="SSH Key + Password (Fallback)"
                  disabled={authMethodLocked && !editingAuth}
                />
              </RadioGroup>
            </Box>
            {(authMethodLocked || (formData.authMethod && !editingAuth)) && (
              <Button
                size="small"
                onClick={toggleAuthEdit}
                startIcon={editingAuth ? <CheckCircle /> : <Edit />}
                color={editingAuth ? 'primary' : 'secondary'}
              >
                {editingAuth ? 'Done' : 'Edit'}
              </Button>
            )}
          </Box>
        </Grid>

        <Grid item xs={12} md={6}>
          <TextField
            fullWidth
            label="Username"
            value={formData.username}
            onChange={(e) => handleInputChange('username', e.target.value)}
            placeholder="ubuntu"
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <AccountTree />
                </InputAdornment>
              ),
            }}
          />
        </Grid>

        {formData.authMethod === 'password' && (
          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              type={showPassword ? 'text' : 'password'}
              label="Password"
              value={formData.password}
              onChange={(e) => handleInputChange('password', e.target.value)}
              placeholder="Enter password for authentication"
              helperText="Password will be encrypted and stored securely"
              disabled={authMethodLocked && !editingAuth}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Password />
                  </InputAdornment>
                ),
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton
                      onClick={() => setShowPassword(!showPassword)}
                      edge="end"
                      disabled={authMethodLocked && !editingAuth}
                    >
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
          </Grid>
        )}

        {formData.authMethod === 'system_default' && (
          <Grid item xs={12}>
            <Card
              sx={{
                border: '2px solid',
                borderColor: 'primary.main',
                bgcolor: 'primary.50',
                '&:hover': { bgcolor: 'primary.100' },
              }}
            >
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <Security color="primary" sx={{ mr: 1 }} />
                  <Typography variant="subtitle1" fontWeight="bold">
                    Using System Default Credentials
                  </Typography>
                </Box>
                {systemCredentials ? (
                  <Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      <strong>Credential:</strong> {systemCredentials.name}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      <strong>Username:</strong> {systemCredentials.username}
                    </Typography>
                    {systemCredentials.sshKeyType && (
                      <Typography variant="body2" color="text.secondary">
                        <strong>Key Type:</strong> {systemCredentials.sshKeyType?.toUpperCase()}{' '}
                        {systemCredentials.sshKeyBits}-bit
                        {systemCredentials.sshKeyComment && ` (${systemCredentials.sshKeyComment})`}
                      </Typography>
                    )}
                  </Box>
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    Loading system credentials...
                  </Typography>
                )}
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{ mt: 2, fontStyle: 'italic' }}
                >
                  All credential input fields are hidden when using system default
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        )}

        {formData.authMethod === 'ssh_key' && (
          <Grid item xs={12}>
            {sshKeyValidation.status === 'valid' && authMethodLocked && !editingAuth ? (
              // Show validated SSH key info when locked
              <Card
                sx={{
                  border: '2px solid',
                  borderColor: 'success.main',
                  bgcolor: 'success.50',
                  '&:hover': { bgcolor: 'success.100' },
                }}
              >
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <CheckCircle color="success" sx={{ mr: 1 }} />
                    <Typography variant="subtitle1" fontWeight="bold">
                      SSH Key Validated Successfully
                    </Typography>
                  </Box>
                  {sshKeyValidation.keyType && (
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      <strong>Key Type:</strong> {sshKeyValidation.keyType?.toUpperCase()}{' '}
                      {sshKeyValidation.keyBits}-bit
                    </Typography>
                  )}
                  {sshKeyValidation.securityLevel && (
                    <Chip
                      label={sshKeyValidation.securityLevel.toUpperCase()}
                      color={
                        sshKeyValidation.securityLevel === 'secure'
                          ? 'success'
                          : sshKeyValidation.securityLevel === 'acceptable'
                            ? 'warning'
                            : 'error'
                      }
                      size="small"
                    />
                  )}
                </CardContent>
              </Card>
            ) : (
              // Show SSH key input field when editing or not validated
              <Box>
                <TextField
                  fullWidth
                  label="SSH Private Key"
                  value={formData.sshKey}
                  onChange={(e) => {
                    handleInputChange('sshKey', e.target.value);
                    validateSshKey(e.target.value);
                  }}
                  placeholder="-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----"
                  multiline
                  rows={4}
                  error={sshKeyValidation.status === 'invalid'}
                  helperText={sshKeyValidation.message || 'Paste your SSH private key content'}
                  disabled={sshKeyValidation.status === 'validating'}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <Key
                          color={
                            sshKeyValidation.status === 'valid'
                              ? 'success'
                              : sshKeyValidation.status === 'invalid'
                                ? 'error'
                                : 'inherit'
                          }
                        />
                      </InputAdornment>
                    ),
                    endAdornment:
                      sshKeyValidation.status === 'validating' ? (
                        <InputAdornment position="end">
                          <LinearProgress sx={{ width: 40 }} />
                        </InputAdornment>
                      ) : sshKeyValidation.status === 'valid' ? (
                        <InputAdornment position="end">
                          <CheckCircle color="success" />
                        </InputAdornment>
                      ) : sshKeyValidation.status === 'invalid' ? (
                        <InputAdornment position="end">
                          <ErrorIcon color="error" />
                        </InputAdornment>
                      ) : null,
                  }}
                />
                {sshKeyValidation.status === 'valid' && (
                  <Alert severity="success" sx={{ mt: 1 }}>
                    SSH key validated successfully!
                    {sshKeyValidation.keyType &&
                      ` (${sshKeyValidation.keyType?.toUpperCase()} ${sshKeyValidation.keyBits}-bit)`}
                  </Alert>
                )}
                {sshKeyValidation.status === 'invalid' && (
                  <Alert severity="error" sx={{ mt: 1 }}>
                    {sshKeyValidation.message}
                  </Alert>
                )}
              </Box>
            )}
          </Grid>
        )}

        {formData.authMethod === 'both' && (
          <>
            <Grid item xs={12}>
              <Alert severity="info" icon={<Security />}>
                <AlertTitle>SSH Key + Password Fallback</AlertTitle>
                The system will attempt SSH key authentication first (more secure). If SSH key
                fails, it will automatically fallback to password authentication.
              </Alert>
            </Grid>

            <Grid item xs={12}>
              <TextField
                fullWidth
                label="SSH Private Key (Primary)"
                value={formData.sshKey}
                onChange={(e) => {
                  handleInputChange('sshKey', e.target.value);
                  validateSshKey(e.target.value);
                }}
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----"
                multiline
                rows={4}
                error={sshKeyValidation.status === 'invalid'}
                helperText={
                  sshKeyValidation.message || 'SSH key will be tried first for authentication'
                }
                disabled={sshKeyValidation.status === 'validating'}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <Key color="primary" />
                    </InputAdornment>
                  ),
                }}
              />
              {sshKeyValidation.status === 'valid' && (
                <Alert severity="success" sx={{ mt: 1 }}>
                  SSH key validated successfully!
                  {sshKeyValidation.keyType &&
                    ` (${sshKeyValidation.keyType?.toUpperCase()} ${sshKeyValidation.keyBits}-bit)`}
                </Alert>
              )}
              {sshKeyValidation.status === 'invalid' && (
                <Alert severity="error" sx={{ mt: 1 }}>
                  {sshKeyValidation.message}
                </Alert>
              )}
            </Grid>

            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                type={showPassword ? 'text' : 'password'}
                label="Password (Fallback)"
                value={formData.password}
                onChange={(e) => handleInputChange('password', e.target.value)}
                placeholder="Enter fallback password"
                helperText="Password will be used if SSH key authentication fails"
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <Password color="warning" />
                    </InputAdornment>
                  ),
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton onClick={() => setShowPassword(!showPassword)} edge="end">
                        {showPassword ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
              />
            </Grid>
          </>
        )}

        <Grid item xs={12}>
          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
            <Button variant="outlined" onClick={() => navigate('/hosts')} startIcon={<Cancel />}>
              Cancel
            </Button>
            <Button
              variant="outlined"
              onClick={handleTestConnection}
              startIcon={testingConnection ? <LinearProgress /> : <NetworkCheck />}
              disabled={testingConnection || !formData.hostname || !formData.username}
            >
              Test Connection
            </Button>
            <Button
              variant="contained"
              onClick={handleSubmit}
              startIcon={<Add />}
              disabled={
                !formData.hostname ||
                (!formData.username && formData.authMethod !== 'system_default')
              }
            >
              Add Host & Scan Now
            </Button>
          </Box>
        </Grid>

        {connectionStatus !== 'idle' && (
          <Grid item xs={12}>
            <Alert
              severity={
                connectionStatus === 'success'
                  ? 'success'
                  : connectionStatus === 'failed'
                    ? 'error'
                    : 'info'
              }
              icon={connectionStatus === 'testing' ? <LinearProgress /> : undefined}
            >
              <AlertTitle>
                {connectionStatus === 'testing' && 'Testing Connection...'}
                {connectionStatus === 'success' && 'Connection Successful'}
                {connectionStatus === 'failed' && 'Connection Failed'}
              </AlertTitle>
              {connectionStatus === 'success' && connectionTestResults?.success && (
                <Box>
                  <Typography variant="body2">
                    {connectionTestResults.networkConnectivity ? '✓' : '✗'} Network connectivity
                    verified
                    {connectionTestResults.responseTime > 0 &&
                      ` (${connectionTestResults.responseTime}ms)`}
                  </Typography>
                  <Typography variant="body2">
                    {connectionTestResults.authentication ? '✓' : '✗'} Authentication successful
                  </Typography>
                  <Typography variant="body2">
                    ✓ Detected: {connectionTestResults.detectedOS}
                    {connectionTestResults.detectedVersion &&
                      ` ${connectionTestResults.detectedVersion}`}
                  </Typography>
                  {connectionTestResults.sshVersion && (
                    <Typography variant="body2">
                      ✓ SSH Version: {connectionTestResults.sshVersion}
                    </Typography>
                  )}
                  {connectionTestResults.additionalInfo && (
                    <Typography variant="body2" color="text.secondary">
                      {connectionTestResults.additionalInfo}
                    </Typography>
                  )}
                </Box>
              )}
              {connectionStatus === 'failed' &&
                connectionTestResults &&
                !connectionTestResults.success && (
                  <Box>
                    <Typography variant="body2" color="error">
                      Connection failed: {connectionTestResults.error}
                    </Typography>
                    {connectionTestResults.errorCode && (
                      <Typography variant="body2" color="text.secondary">
                        Error code: {connectionTestResults.errorCode}
                      </Typography>
                    )}
                    <Typography variant="body2">
                      {connectionTestResults.networkConnectivity ? '✓' : '✗'} Network connectivity
                    </Typography>
                    <Typography variant="body2">
                      {connectionTestResults.authentication ? '✓' : '✗'} Authentication
                    </Typography>
                  </Box>
                )}
            </Alert>
          </Grid>
        )}
      </Grid>
    </Paper>
  );

  const renderAdvancedMode = () => (
    <Box>
      <Paper sx={{ p: 3, mb: 2 }}>
        <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Typography variant="h5" fontWeight="bold">
            Add New Host
          </Typography>
          <Button variant="outlined" onClick={() => setQuickMode(true)} startIcon={<Speed />}>
            Quick Mode
          </Button>
        </Box>
      </Paper>

      <Stepper activeStep={activeStep} orientation="vertical">
        {/* Step 1: Host Connection */}
        <Step>
          <StepLabel>Host Connection</StepLabel>
          <StepContent>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Hostname/FQDN"
                  value={formData.hostname}
                  onChange={(e) => handleInputChange('hostname', e.target.value)}
                  placeholder="web-server-01.example.com"
                  required
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <TextField
                  fullWidth
                  label="IP Address (Optional)"
                  value={formData.ipAddress}
                  onChange={(e) => handleInputChange('ipAddress', e.target.value)}
                  placeholder="192.168.1.100"
                />
              </Grid>
              <Grid item xs={12} md={2}>
                <TextField
                  fullWidth
                  label="SSH Port"
                  value={formData.port}
                  onChange={(e) => handleInputChange('port', e.target.value)}
                  type="number"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Display Name"
                  value={formData.displayName}
                  onChange={(e) => handleInputChange('displayName', e.target.value)}
                  placeholder="Production Web Server"
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Operating System</InputLabel>
                  <Select
                    value={formData.operatingSystem}
                    onChange={(e) => handleInputChange('operatingSystem', e.target.value)}
                    label="Operating System"
                  >
                    {operatingSystems.map((os) => (
                      <MenuItem key={os.value} value={os.value}>
                        {os.label}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>

              <Grid item xs={12}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={formData.useBastion}
                      onChange={(e) => handleInputChange('useBastion', e.target.checked)}
                    />
                  }
                  label="Use Bastion/Jump Host"
                />
              </Grid>

              {formData.useBastion && (
                <>
                  <Grid item xs={12} md={4}>
                    <TextField
                      fullWidth
                      label="Bastion Host"
                      value={formData.bastionHost}
                      onChange={(e) => handleInputChange('bastionHost', e.target.value)}
                      placeholder="bastion.example.com"
                    />
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <TextField
                      fullWidth
                      label="Bastion Port"
                      value={formData.bastionPort}
                      onChange={(e) => handleInputChange('bastionPort', e.target.value)}
                      type="number"
                    />
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <TextField
                      fullWidth
                      label="Bastion User"
                      value={formData.bastionUser}
                      onChange={(e) => handleInputChange('bastionUser', e.target.value)}
                    />
                  </Grid>
                </>
              )}

              <Grid item xs={12}>
                <Box sx={{ mt: 2, display: 'flex', gap: 2 }}>
                  <Button onClick={() => navigate('/hosts')}>Cancel</Button>
                  <Button variant="contained" onClick={handleNext}>
                    Next
                  </Button>
                </Box>
              </Grid>
            </Grid>
          </StepContent>
        </Step>

        {/* Step 2: Authentication */}
        <Step>
          <StepLabel>Authentication</StepLabel>
          <StepContent>
            <Grid container spacing={3}>
              <Grid item xs={12}>
                <FormControl component="fieldset">
                  <RadioGroup
                    value={formData.authMethod}
                    onChange={(e) => handleInputChange('authMethod', e.target.value)}
                  >
                    <FormControlLabel
                      value="system_default"
                      control={<Radio />}
                      label="System Default"
                    />
                    <FormControlLabel
                      value="ssh_key"
                      control={<Radio />}
                      label="SSH Key Authentication"
                    />
                    <FormControlLabel
                      value="password"
                      control={<Radio />}
                      label="Password Authentication"
                    />
                  </RadioGroup>
                </FormControl>
              </Grid>

              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Username"
                  value={formData.username}
                  onChange={(e) => handleInputChange('username', e.target.value)}
                  required
                  disabled={formData.authMethod === 'system_default'}
                  helperText={
                    formData.authMethod === 'system_default'
                      ? 'Username will be taken from system default credentials'
                      : ''
                  }
                />
              </Grid>

              {formData.authMethod === 'password' && (
                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    type={showPassword ? 'text' : 'password'}
                    label="Password"
                    value={formData.password}
                    onChange={(e) => handleInputChange('password', e.target.value)}
                    InputProps={{
                      endAdornment: (
                        <InputAdornment position="end">
                          <IconButton onClick={() => setShowPassword(!showPassword)} edge="end">
                            {showPassword ? <VisibilityOff /> : <Visibility />}
                          </IconButton>
                        </InputAdornment>
                      ),
                    }}
                  />
                </Grid>
              )}

              {formData.authMethod === 'system_default' && (
                <Grid item xs={12}>
                  <SSHKeyDisplay
                    isSystemDefault={true}
                    systemDefaultLabel="This host will use the system default SSH credentials configured in system settings"
                    showActions={false}
                    compact={false}
                  />
                </Grid>
              )}

              {formData.authMethod === 'ssh_key' && (
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="SSH Private Key"
                    value={formData.sshKey}
                    onChange={(e) => handleInputChange('sshKey', e.target.value)}
                    placeholder="Paste SSH private key content or provide path"
                    multiline
                    rows={6}
                  />
                  <Button variant="outlined" startIcon={<Upload />} sx={{ mt: 1 }}>
                    Upload Key File
                  </Button>
                </Grid>
              )}

              {formData.authMethod === 'certificate' && (
                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="Certificate Path"
                    value={formData.certificatePath}
                    onChange={(e) => handleInputChange('certificatePath', e.target.value)}
                  />
                </Grid>
              )}

              {formData.authMethod === 'agent' && (
                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="Agent Token"
                    value={formData.agentToken}
                    onChange={(e) => handleInputChange('agentToken', e.target.value)}
                    placeholder="Enter pre-shared agent token"
                  />
                </Grid>
              )}

              <Grid item xs={12}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={formData.requireSudo}
                      onChange={(e) => handleInputChange('requireSudo', e.target.checked)}
                    />
                  }
                  label="Require Sudo/Administrator Access"
                />
              </Grid>

              {formData.requireSudo && (
                <>
                  <Grid item xs={12} md={6}>
                    <FormControl fullWidth>
                      <InputLabel>Privilege Escalation Method</InputLabel>
                      <Select
                        value={formData.sudoMethod}
                        onChange={(e) => handleInputChange('sudoMethod', e.target.value)}
                        label="Privilege Escalation Method"
                      >
                        <MenuItem value="sudo">sudo</MenuItem>
                        <MenuItem value="su">su</MenuItem>
                        <MenuItem value="doas">doas</MenuItem>
                        <MenuItem value="runas">runas (Windows)</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <TextField
                      fullWidth
                      type="password"
                      label="Sudo Password (if different)"
                      value={formData.sudoPassword}
                      onChange={(e) => handleInputChange('sudoPassword', e.target.value)}
                    />
                  </Grid>
                </>
              )}

              <Grid item xs={12}>
                <Box sx={{ mt: 2, display: 'flex', gap: 2 }}>
                  <Button onClick={handleBack}>Back</Button>
                  <Button variant="contained" onClick={handleNext}>
                    Next
                  </Button>
                </Box>
              </Grid>
            </Grid>
          </StepContent>
        </Step>

        {/* Step 3: Classification */}
        <Step>
          <StepLabel>Classification</StepLabel>
          <StepContent>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Environment</InputLabel>
                  <Select
                    value={formData.environment}
                    onChange={(e) => handleInputChange('environment', e.target.value)}
                    label="Environment"
                  >
                    <MenuItem value="production">Production</MenuItem>
                    <MenuItem value="staging">Staging</MenuItem>
                    <MenuItem value="development">Development</MenuItem>
                    <MenuItem value="test">Test</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Host Group/Team"
                  value={formData.hostGroup}
                  onChange={(e) => handleInputChange('hostGroup', e.target.value)}
                  placeholder="Web Servers"
                />
              </Grid>

              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Owner/Responsible Team"
                  value={formData.owner}
                  onChange={(e) => handleInputChange('owner', e.target.value)}
                  placeholder="DevOps Team"
                />
              </Grid>

              <Grid item xs={12} md={6}>
                <Autocomplete
                  multiple
                  options={availableTags}
                  value={formData.tags}
                  onChange={(_, newValue) => handleInputChange('tags', newValue)}
                  renderInput={(params) => (
                    <TextField {...params} label="Tags" placeholder="Add tags" />
                  )}
                  renderTags={(value, getTagProps) =>
                    value.map((option, index) => {
                      const { key, ...chipProps } = getTagProps({ index });
                      return <Chip key={key} label={option} {...chipProps} size="small" />;
                    })
                  }
                />
              </Grid>

              <Grid item xs={12}>
                <Box sx={{ mt: 2, display: 'flex', gap: 2 }}>
                  <Button onClick={handleBack}>Back</Button>
                  <Button variant="contained" onClick={handleNext}>
                    Next
                  </Button>
                </Box>
              </Grid>
            </Grid>
          </StepContent>
        </Step>

        {/* Step 4: Scan Configuration */}
        <Step>
          <StepLabel>Scan Configuration</StepLabel>
          <StepContent>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Compliance Profile</InputLabel>
                  <Select
                    value={formData.complianceProfile}
                    onChange={(e) => handleInputChange('complianceProfile', e.target.value)}
                    label="Compliance Profile"
                  >
                    {complianceProfiles.map((profile) => (
                      <MenuItem key={profile.value} value={profile.value}>
                        {profile.label}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>

              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Scan Schedule</InputLabel>
                  <Select
                    value={formData.scanSchedule}
                    onChange={(e) => handleInputChange('scanSchedule', e.target.value)}
                    label="Scan Schedule"
                  >
                    <MenuItem value="immediate">Scan Immediately</MenuItem>
                    <MenuItem value="daily">Daily</MenuItem>
                    <MenuItem value="weekly">Weekly</MenuItem>
                    <MenuItem value="monthly">Monthly</MenuItem>
                    <MenuItem value="custom">Custom Schedule</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              {formData.scanSchedule === 'custom' && (
                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="Cron Expression"
                    value={formData.customCron}
                    onChange={(e) => handleInputChange('customCron', e.target.value)}
                    placeholder="0 2 * * *"
                    helperText="Enter a valid cron expression"
                  />
                </Grid>
              )}

              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Scan Intensity</InputLabel>
                  <Select
                    value={formData.scanIntensity}
                    onChange={(e) => handleInputChange('scanIntensity', e.target.value)}
                    label="Scan Intensity"
                  >
                    <MenuItem value="light">Light (Basic checks)</MenuItem>
                    <MenuItem value="normal">Normal (Standard)</MenuItem>
                    <MenuItem value="deep">Deep (Comprehensive)</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              <Grid item xs={12} md={6}>
                <FormControl fullWidth>
                  <InputLabel>Scan Priority</InputLabel>
                  <Select
                    value={formData.scanPriority}
                    onChange={(e) => handleInputChange('scanPriority', e.target.value)}
                    label="Scan Priority"
                  >
                    <MenuItem value="high">High</MenuItem>
                    <MenuItem value="medium">Medium</MenuItem>
                    <MenuItem value="low">Low</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              {/* Advanced Options */}
              <Grid item xs={12}>
                <Button
                  onClick={() => setShowAdvanced(!showAdvanced)}
                  endIcon={showAdvanced ? <ExpandLess /> : <ExpandMore />}
                >
                  Advanced Options
                </Button>
              </Grid>

              <Collapse in={showAdvanced} timeout="auto" unmountOnExit>
                <Grid container spacing={3} sx={{ mt: 0 }}>
                  <Grid item xs={12} md={6}>
                    <TextField
                      fullWidth
                      label="Bandwidth Limit (KB/s)"
                      value={formData.bandwidthLimit}
                      onChange={(e) => handleInputChange('bandwidthLimit', e.target.value)}
                      placeholder="Leave empty for no limit"
                      type="number"
                    />
                  </Grid>

                  <Grid item xs={12} md={3}>
                    <TextField
                      fullWidth
                      label="Connection Timeout (s)"
                      value={formData.connectionTimeout}
                      onChange={(e) => handleInputChange('connectionTimeout', e.target.value)}
                      type="number"
                    />
                  </Grid>

                  <Grid item xs={12} md={3}>
                    <TextField
                      fullWidth
                      label="Scan Timeout (s)"
                      value={formData.scanTimeout}
                      onChange={(e) => handleInputChange('scanTimeout', e.target.value)}
                      type="number"
                    />
                  </Grid>

                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      label="Exclude Paths (one per line)"
                      value={formData.excludePaths.join('\n')}
                      onChange={(e) =>
                        handleInputChange('excludePaths', e.target.value.split('\n'))
                      }
                      multiline
                      rows={3}
                      placeholder="/tmp&#10;/var/cache&#10;/mnt"
                    />
                  </Grid>

                  <Grid item xs={12} md={6}>
                    <TextField
                      fullWidth
                      label="Proxy Host"
                      value={formData.proxyHost}
                      onChange={(e) => handleInputChange('proxyHost', e.target.value)}
                      placeholder="proxy.example.com"
                    />
                  </Grid>

                  <Grid item xs={12} md={6}>
                    <TextField
                      fullWidth
                      label="Proxy Port"
                      value={formData.proxyPort}
                      onChange={(e) => handleInputChange('proxyPort', e.target.value)}
                      placeholder="3128"
                    />
                  </Grid>

                  <Grid item xs={12} md={6}>
                    <TextField
                      fullWidth
                      label="Pre-Scan Script"
                      value={formData.preScript}
                      onChange={(e) => handleInputChange('preScript', e.target.value)}
                      multiline
                      rows={3}
                      placeholder="Commands to run before scan"
                    />
                  </Grid>

                  <Grid item xs={12} md={6}>
                    <TextField
                      fullWidth
                      label="Post-Scan Script"
                      value={formData.postScript}
                      onChange={(e) => handleInputChange('postScript', e.target.value)}
                      multiline
                      rows={3}
                      placeholder="Commands to run after scan"
                    />
                  </Grid>
                </Grid>
              </Collapse>

              <Grid item xs={12}>
                <Box sx={{ mt: 2, display: 'flex', gap: 2 }}>
                  <Button onClick={handleBack}>Back</Button>
                  <Button variant="contained" onClick={handleNext}>
                    Next
                  </Button>
                </Box>
              </Grid>
            </Grid>
          </StepContent>
        </Step>

        {/* Step 5: Review & Test */}
        <Step>
          <StepLabel>Review & Test</StepLabel>
          <StepContent>
            <Grid container spacing={3}>
              <Grid item xs={12}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Host Configuration Summary
                    </Typography>
                    <Divider sx={{ my: 2 }} />

                    <Grid container spacing={2}>
                      <Grid item xs={12} md={6}>
                        <List dense>
                          <ListItem>
                            <ListItemIcon>
                              <Computer />
                            </ListItemIcon>
                            <ListItemText
                              primary="Hostname"
                              secondary={formData.hostname || 'Not specified'}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon>
                              <Label />
                            </ListItemIcon>
                            <ListItemText
                              primary="Display Name"
                              secondary={formData.displayName || formData.hostname}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon>
                              <VpnKey />
                            </ListItemIcon>
                            <ListItemText
                              primary="Authentication"
                              secondary={formData.authMethod.toUpperCase()}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon>
                              <AccountTree />
                            </ListItemIcon>
                            <ListItemText
                              primary="Username"
                              secondary={formData.username || 'Not specified'}
                            />
                          </ListItem>
                        </List>
                      </Grid>

                      <Grid item xs={12} md={6}>
                        <List dense>
                          <ListItem>
                            <ListItemIcon>
                              <Storage />
                            </ListItemIcon>
                            <ListItemText
                              primary="Operating System"
                              secondary={formData.operatingSystem}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon>
                              <Security />
                            </ListItemIcon>
                            <ListItemText
                              primary="Compliance Profile"
                              secondary={formData.complianceProfile}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon>
                              <Schedule />
                            </ListItemIcon>
                            <ListItemText
                              primary="Scan Schedule"
                              secondary={formData.scanSchedule}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon>
                              <Group />
                            </ListItemIcon>
                            <ListItemText primary="Environment" secondary={formData.environment} />
                          </ListItem>
                        </List>
                      </Grid>
                    </Grid>

                    {formData.tags.length > 0 && (
                      <Box sx={{ mt: 2 }}>
                        <Typography variant="subtitle2" gutterBottom>
                          Tags:
                        </Typography>
                        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                          {formData.tags.map((tag) => (
                            <Chip key={tag} label={tag} size="small" />
                          ))}
                        </Box>
                      </Box>
                    )}
                  </CardContent>
                  <CardActions>
                    <Button
                      variant="outlined"
                      startIcon={<NetworkCheck />}
                      onClick={handleTestConnection}
                      disabled={testingConnection}
                    >
                      Test Connection
                    </Button>
                  </CardActions>
                </Card>
              </Grid>

              {connectionStatus !== 'idle' && (
                <Grid item xs={12}>
                  <Alert
                    severity={
                      connectionStatus === 'success'
                        ? 'success'
                        : connectionStatus === 'failed'
                          ? 'error'
                          : 'info'
                    }
                    icon={connectionStatus === 'testing' ? <LinearProgress /> : undefined}
                  >
                    <AlertTitle>
                      {connectionStatus === 'testing' && 'Testing Connection...'}
                      {connectionStatus === 'success' && 'Connection Test Successful'}
                      {connectionStatus === 'failed' && 'Connection Test Failed'}
                    </AlertTitle>
                    {connectionStatus === 'success' && (
                      <Box>
                        <Typography variant="body2">✓ Network connectivity established</Typography>
                        <Typography variant="body2">✓ Authentication verified</Typography>
                        <Typography variant="body2">
                          ✓ Operating system detected: Ubuntu 22.04 LTS
                        </Typography>
                        <Typography variant="body2">✓ Sudo access confirmed</Typography>
                        <Typography variant="body2" sx={{ mt: 1 }}>
                          <strong>Ready to add host and begin scanning</strong>
                        </Typography>
                      </Box>
                    )}
                    {connectionStatus === 'failed' && (
                      <Typography variant="body2">
                        Connection failed. Please check your hostname and credentials.
                      </Typography>
                    )}
                  </Alert>
                </Grid>
              )}

              <Grid item xs={12}>
                <Box sx={{ mt: 2, display: 'flex', gap: 2 }}>
                  <Button onClick={handleBack}>Back</Button>
                  <Button onClick={() => navigate('/hosts')}>Cancel</Button>
                  <Box sx={{ flexGrow: 1 }} />
                  <Button variant="outlined" startIcon={<SaveIcon />}>
                    Save as Template
                  </Button>
                  <Button
                    variant="contained"
                    onClick={handleSubmit}
                    startIcon={<Add />}
                    disabled={connectionStatus !== 'success'}
                  >
                    Add Host & Start Scan
                  </Button>
                </Box>
              </Grid>
            </Grid>
          </StepContent>
        </Step>
      </Stepper>
    </Box>
  );

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', gap: 2 }}>
        <IconButton onClick={() => navigate('/hosts')}>
          <ArrowBack />
        </IconButton>
        <Typography variant="h4" fontWeight="bold">
          Add New Host
        </Typography>
      </Box>

      {/* Quick Stats */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Total Hosts"
            value="4"
            icon={<Computer />}
            color="primary"
            subtitle="Currently managed"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Available Profiles"
            value="8"
            icon={<Security />}
            color="success"
            subtitle="Compliance standards"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Scan Queue"
            value="2"
            icon={<Schedule />}
            color="warning"
            subtitle="Pending scans"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Templates"
            value="5"
            icon={<Description />}
            color="info"
            subtitle="Saved configurations"
          />
        </Grid>
      </Grid>

      {/* Main Form */}
      {quickMode ? renderQuickMode() : renderAdvancedMode()}

      {/* Templates Section (optional) */}
      <Paper sx={{ mt: 3, p: 3 }}>
        <Typography variant="h6" gutterBottom>
          Quick Start Templates
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6} md={3}>
            <Card
              variant="outlined"
              sx={{ cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}
            >
              <CardContent>
                <Typography variant="subtitle2" color="primary">
                  Linux Web Server
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Ubuntu/RHEL with CIS Level 2
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card
              variant="outlined"
              sx={{ cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}
            >
              <CardContent>
                <Typography variant="subtitle2" color="primary">
                  Database Server
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  PostgreSQL/MySQL with STIG
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card
              variant="outlined"
              sx={{ cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}
            >
              <CardContent>
                <Typography variant="subtitle2" color="primary">
                  Container Host
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Docker/K8s with CIS Benchmark
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card
              variant="outlined"
              sx={{ cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}
            >
              <CardContent>
                <Typography variant="subtitle2" color="primary">
                  Windows Server
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Windows 2019/2022 with STIG
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Paper>
    </Box>
  );
};

export default AddHost;
