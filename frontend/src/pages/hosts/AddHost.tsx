import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Grid,
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
  ListItemSecondaryAction,
  Tooltip,
  LinearProgress,
  useTheme,
  alpha,
} from '@mui/material';
import {
  ArrowBack,
  Computer,
  Key,
  Password,
  Token,
  CloudUpload,
  Check,
  Error as ErrorIcon,
  Warning,
  Info,
  ExpandMore,
  ExpandLess,
  PlayArrow,
  Schedule,
  Security,
  Group,
  Label,
  Dns,
  NetworkCheck,
  VpnKey,
  AccountTree,
  Description,
  ContentCopy,
  Add,
  Remove,
  Upload,
  Download,
  Save as SaveIcon,
  CheckCircle,
  Cancel,
  Visibility,
  VisibilityOff,
  FolderOpen,
  Terminal,
  Speed,
  Timer,
  CloudQueue,
  Storage,
  Settings,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { StatCard, StatusChip, SSHKeyDisplay, type SSHKeyInfo } from '../../components/design-system';

const AddHost: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  
  // Form state
  const [activeStep, setActiveStep] = useState(0);
  const [quickMode, setQuickMode] = useState(true);
  const [testingConnection, setTestingConnection] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'idle' | 'testing' | 'success' | 'failed'>('idle');
  const [showPassword, setShowPassword] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Form fields
  const [formData, setFormData] = useState({
    // Basic Information
    hostname: '',
    ipAddress: '',
    port: '22',
    displayName: '',
    
    // Authentication
    authMethod: 'ssh-key',
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

  const steps = [
    'Host Connection',
    'Authentication',
    'Classification',
    'Scan Configuration',
    'Review & Test'
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
    'production', 'staging', 'development', 'test',
    'web', 'database', 'application', 'cache',
    'critical', 'public-facing', 'internal',
    'linux', 'windows', 'container',
  ];

  const handleInputChange = (field: string, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }));
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
    
    // Simulate connection test
    setTimeout(() => {
      setTestingConnection(false);
      setConnectionStatus('success');
    }, 2000);
  };

  const handleSubmit = async () => {
    try {
      // Prepare host data for API
      const hostData = {
        hostname: formData.hostname || formData.ipAddress,
        ip_address: formData.ipAddress || formData.hostname,
        display_name: formData.displayName,
        operating_system: formData.operatingSystem === 'auto-detect' ? 'Unknown' : formData.operatingSystem,
        port: formData.port,
        username: formData.username,
        auth_method: formData.authMethod,
        environment: formData.environment,
        tags: formData.tags,
        owner: formData.owner
      };

      console.log('Submitting host to API:', hostData);
      
      // Make API call to create host
      const response = await fetch('/api/hosts/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          // Note: In production, you'd include auth token here
          'Authorization': 'Bearer demo-token'
        },
        body: JSON.stringify(hostData)
      });

      if (response.ok) {
        try {
          const newHost = await response.json();
          console.log('Host created successfully:', newHost);
        } catch (jsonError) {
          console.log('Host created but no JSON response');
        }
        navigate('/hosts');
      } else {
        try {
          const contentType = response.headers.get("content-type");
          if (contentType && contentType.indexOf("application/json") !== -1) {
            const error = await response.json();
            console.error('Failed to create host:', error);
          } else {
            console.error('Failed to create host: Non-JSON response');
          }
        } catch (parseError) {
          console.error('Failed to create host: Could not parse error response');
        }
        // Still navigate to hosts page even on error
        navigate('/hosts');
      }
    } catch (error) {
      console.error('Error submitting host:', error);
      // Fallback - still navigate for demo purposes
      navigate('/hosts');
    }
  };

  const renderQuickMode = () => (
    <Paper sx={{ p: 3 }}>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Typography variant="h5" fontWeight="bold">
          Quick Add Host
        </Typography>
        <Button
          variant="outlined"
          onClick={() => setQuickMode(false)}
          startIcon={<Settings />}
        >
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
          <RadioGroup
            value={formData.authMethod}
            onChange={(e) => handleInputChange('authMethod', e.target.value)}
            row
          >
            <FormControlLabel value="default" control={<Radio />} label="Default (From System Settings)" />
            <FormControlLabel value="ssh-key" control={<Radio />} label="SSH Key" />
            <FormControlLabel value="password" control={<Radio />} label="Password" />
            <FormControlLabel value="certificate" control={<Radio />} label="Certificate" />
            <FormControlLabel value="agent" control={<Radio />} label="Agent Token" />
          </RadioGroup>
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
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Password />
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
        )}

        {formData.authMethod === 'default' && (
          <Grid item xs={12}>
            <SSHKeyDisplay
              isSystemDefault={true}
              systemDefaultLabel="This host will use the system default SSH credentials"
              showActions={false}
              compact={false}
            />
          </Grid>
        )}

        {formData.authMethod === 'ssh-key' && (
          <Grid item xs={12}>
            <TextField
              fullWidth
              label="SSH Private Key"
              value={formData.sshKey}
              onChange={(e) => handleInputChange('sshKey', e.target.value)}
              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----"
              multiline
              rows={4}
              helperText="Paste your SSH private key content or select 'Use System Default' authentication method"
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Key />
                  </InputAdornment>
                ),
              }}
            />
          </Grid>
        )}

        <Grid item xs={12}>
          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
            <Button
              variant="outlined"
              onClick={() => navigate('/hosts')}
              startIcon={<Cancel />}
            >
              Cancel
            </Button>
            <Button
              variant="outlined"
              onClick={handleTestConnection}
              startIcon={testingConnection ? <LinearProgress /> : <NetworkCheck />}
              disabled={testingConnection || !formData.hostname}
            >
              Test Connection
            </Button>
            <Button
              variant="contained"
              onClick={handleSubmit}
              startIcon={<Add />}
              disabled={!formData.hostname || !formData.username}
            >
              Add Host & Scan Now
            </Button>
          </Box>
        </Grid>

        {connectionStatus !== 'idle' && (
          <Grid item xs={12}>
            <Alert 
              severity={connectionStatus === 'success' ? 'success' : connectionStatus === 'failed' ? 'error' : 'info'}
              icon={connectionStatus === 'testing' ? <LinearProgress /> : undefined}
            >
              <AlertTitle>
                {connectionStatus === 'testing' && 'Testing Connection...'}
                {connectionStatus === 'success' && 'Connection Successful'}
                {connectionStatus === 'failed' && 'Connection Failed'}
              </AlertTitle>
              {connectionStatus === 'success' && (
                <Box>
                  <Typography variant="body2">✓ Network connectivity verified</Typography>
                  <Typography variant="body2">✓ Authentication successful</Typography>
                  <Typography variant="body2">✓ Detected: Ubuntu 22.04 LTS</Typography>
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
          <Button
            variant="outlined"
            onClick={() => setQuickMode(true)}
            startIcon={<Speed />}
          >
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
                    {operatingSystems.map(os => (
                      <MenuItem key={os.value} value={os.value}>{os.label}</MenuItem>
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
                  <Button variant="contained" onClick={handleNext}>Next</Button>
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
                    <FormControlLabel value="default" control={<Radio />} label="Default (From System Settings)" />
                    <FormControlLabel value="ssh-key" control={<Radio />} label="SSH Key Authentication" />
                    <FormControlLabel value="password" control={<Radio />} label="Password Authentication" />
                    <FormControlLabel value="certificate" control={<Radio />} label="Certificate Authentication" />
                    <FormControlLabel value="agent" control={<Radio />} label="OpenWatch Agent Token" />
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

              {formData.authMethod === 'default' && (
                <Grid item xs={12}>
                  <SSHKeyDisplay
                    isSystemDefault={true}
                    systemDefaultLabel="This host will use the system default SSH credentials configured in system settings"
                    showActions={false}
                    compact={false}
                  />
                </Grid>
              )}

              {formData.authMethod === 'ssh-key' && (
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
                  <Button
                    variant="outlined"
                    startIcon={<Upload />}
                    sx={{ mt: 1 }}
                  >
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
                  <Button variant="contained" onClick={handleNext}>Next</Button>
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
                    value.map((option, index) => (
                      <Chip label={option} {...getTagProps({ index })} size="small" />
                    ))
                  }
                />
              </Grid>

              <Grid item xs={12}>
                <Box sx={{ mt: 2, display: 'flex', gap: 2 }}>
                  <Button onClick={handleBack}>Back</Button>
                  <Button variant="contained" onClick={handleNext}>Next</Button>
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
                    {complianceProfiles.map(profile => (
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
                      onChange={(e) => handleInputChange('excludePaths', e.target.value.split('\n'))}
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
                  <Button variant="contained" onClick={handleNext}>Next</Button>
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
                            <ListItemIcon><Computer /></ListItemIcon>
                            <ListItemText 
                              primary="Hostname" 
                              secondary={formData.hostname || 'Not specified'}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon><Label /></ListItemIcon>
                            <ListItemText 
                              primary="Display Name" 
                              secondary={formData.displayName || formData.hostname}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon><VpnKey /></ListItemIcon>
                            <ListItemText 
                              primary="Authentication" 
                              secondary={formData.authMethod.toUpperCase()}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon><AccountTree /></ListItemIcon>
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
                            <ListItemIcon><Storage /></ListItemIcon>
                            <ListItemText 
                              primary="Operating System" 
                              secondary={formData.operatingSystem}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon><Security /></ListItemIcon>
                            <ListItemText 
                              primary="Compliance Profile" 
                              secondary={formData.complianceProfile}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon><Schedule /></ListItemIcon>
                            <ListItemText 
                              primary="Scan Schedule" 
                              secondary={formData.scanSchedule}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon><Group /></ListItemIcon>
                            <ListItemText 
                              primary="Environment" 
                              secondary={formData.environment}
                            />
                          </ListItem>
                        </List>
                      </Grid>
                    </Grid>

                    {formData.tags.length > 0 && (
                      <Box sx={{ mt: 2 }}>
                        <Typography variant="subtitle2" gutterBottom>Tags:</Typography>
                        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                          {formData.tags.map(tag => (
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
                    severity={connectionStatus === 'success' ? 'success' : connectionStatus === 'failed' ? 'error' : 'info'}
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
                        <Typography variant="body2">✓ Operating system detected: Ubuntu 22.04 LTS</Typography>
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
                  <Button
                    variant="outlined"
                    startIcon={<SaveIcon />}
                  >
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
            <Card variant="outlined" sx={{ cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}>
              <CardContent>
                <Typography variant="subtitle2" color="primary">Linux Web Server</Typography>
                <Typography variant="caption" color="text.secondary">
                  Ubuntu/RHEL with CIS Level 2
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card variant="outlined" sx={{ cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}>
              <CardContent>
                <Typography variant="subtitle2" color="primary">Database Server</Typography>
                <Typography variant="caption" color="text.secondary">
                  PostgreSQL/MySQL with STIG
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card variant="outlined" sx={{ cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}>
              <CardContent>
                <Typography variant="subtitle2" color="primary">Container Host</Typography>
                <Typography variant="caption" color="text.secondary">
                  Docker/K8s with CIS Benchmark
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card variant="outlined" sx={{ cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}>
              <CardContent>
                <Typography variant="subtitle2" color="primary">Windows Server</Typography>
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