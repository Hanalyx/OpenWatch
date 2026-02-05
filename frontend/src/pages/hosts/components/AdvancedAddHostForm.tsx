import React from 'react';
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
import Grid from '@mui/material/Grid';
import {
  Computer,
  ExpandMore,
  ExpandLess,
  Schedule,
  Security,
  Group,
  Label,
  NetworkCheck,
  VpnKey,
  AccountTree,
  Upload,
  Save as SaveIcon,
  Add,
  Visibility,
  VisibilityOff,
  Storage,
  Speed,
} from '@mui/icons-material';
import { SSHKeyDisplay } from '../../../components/design-system';
import type { AddHostFormData } from '../hooks/useAddHostForm';

export const operatingSystems = [
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

export const complianceProfiles = [
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

export const availableTags = [
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

interface AdvancedAddHostFormProps {
  formData: AddHostFormData;
  activeStep: number;
  showPassword: boolean;
  showAdvanced: boolean;
  connectionStatus: 'idle' | 'testing' | 'success' | 'failed';
  testingConnection: boolean;
  onInputChange: (field: string, value: string | number | boolean | string[]) => void;
  onNext: () => void;
  onBack: () => void;
  onTestConnection: () => Promise<void>;
  onSubmit: () => Promise<void>;
  onShowPasswordToggle: (show: boolean) => void;
  onShowAdvancedToggle: (show: boolean) => void;
  onModeChange: (quick: boolean) => void;
  onCancel: () => void;
}

export const AdvancedAddHostForm: React.FC<AdvancedAddHostFormProps> = ({
  formData,
  activeStep,
  showPassword,
  showAdvanced,
  connectionStatus,
  testingConnection,
  onInputChange,
  onNext,
  onBack,
  onTestConnection,
  onSubmit,
  onShowPasswordToggle,
  onShowAdvancedToggle,
  onModeChange,
  onCancel,
}) => (
  <Box>
    <Paper sx={{ p: 3, mb: 2 }}>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Typography variant="h5" fontWeight="bold">
          Add New Host
        </Typography>
        <Button variant="outlined" onClick={() => onModeChange(true)} startIcon={<Speed />}>
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
            <Grid size={{ xs: 12, md: 6 }}>
              <TextField
                fullWidth
                label="Hostname/FQDN"
                value={formData.hostname}
                onChange={(e) => onInputChange('hostname', e.target.value)}
                placeholder="web-server-01.example.com"
                required
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <TextField
                fullWidth
                label="IP Address (Optional)"
                value={formData.ipAddress}
                onChange={(e) => onInputChange('ipAddress', e.target.value)}
                placeholder="192.168.1.100"
              />
            </Grid>
            <Grid size={{ xs: 12, md: 2 }}>
              <TextField
                fullWidth
                label="SSH Port"
                value={formData.port}
                onChange={(e) => onInputChange('port', e.target.value)}
                type="number"
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <TextField
                fullWidth
                label="Display Name"
                value={formData.displayName}
                onChange={(e) => onInputChange('displayName', e.target.value)}
                placeholder="Production Web Server"
              />
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <FormControl fullWidth>
                <InputLabel>Operating System</InputLabel>
                <Select
                  value={formData.operatingSystem}
                  onChange={(e) => onInputChange('operatingSystem', e.target.value)}
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

            <Grid size={{ xs: 12 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={formData.useBastion}
                    onChange={(e) => onInputChange('useBastion', e.target.checked)}
                  />
                }
                label="Use Bastion/Jump Host"
              />
            </Grid>

            {formData.useBastion && (
              <>
                <Grid size={{ xs: 12, md: 4 }}>
                  <TextField
                    fullWidth
                    label="Bastion Host"
                    value={formData.bastionHost}
                    onChange={(e) => onInputChange('bastionHost', e.target.value)}
                    placeholder="bastion.example.com"
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 4 }}>
                  <TextField
                    fullWidth
                    label="Bastion Port"
                    value={formData.bastionPort}
                    onChange={(e) => onInputChange('bastionPort', e.target.value)}
                    type="number"
                  />
                </Grid>
                <Grid size={{ xs: 12, md: 4 }}>
                  <TextField
                    fullWidth
                    label="Bastion User"
                    value={formData.bastionUser}
                    onChange={(e) => onInputChange('bastionUser', e.target.value)}
                  />
                </Grid>
              </>
            )}

            <Grid size={{ xs: 12 }}>
              <Box sx={{ mt: 2, display: 'flex', gap: 2 }}>
                <Button onClick={onCancel}>Cancel</Button>
                <Button variant="contained" onClick={onNext}>
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
            <Grid size={{ xs: 12 }}>
              <FormControl component="fieldset">
                <RadioGroup
                  value={formData.authMethod}
                  onChange={(e) => onInputChange('authMethod', e.target.value)}
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

            <Grid size={{ xs: 12, md: 6 }}>
              <TextField
                fullWidth
                label="Username"
                value={formData.username}
                onChange={(e) => onInputChange('username', e.target.value)}
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
              <Grid size={{ xs: 12, md: 6 }}>
                <TextField
                  fullWidth
                  type={showPassword ? 'text' : 'password'}
                  label="Password"
                  value={formData.password}
                  onChange={(e) => onInputChange('password', e.target.value)}
                  InputProps={{
                    endAdornment: (
                      <InputAdornment position="end">
                        <IconButton onClick={() => onShowPasswordToggle(!showPassword)} edge="end">
                          {showPassword ? <VisibilityOff /> : <Visibility />}
                        </IconButton>
                      </InputAdornment>
                    ),
                  }}
                />
              </Grid>
            )}

            {formData.authMethod === 'system_default' && (
              <Grid size={{ xs: 12 }}>
                <SSHKeyDisplay
                  isSystemDefault={true}
                  systemDefaultLabel="This host will use the system default SSH credentials configured in system settings"
                  showActions={false}
                  compact={false}
                />
              </Grid>
            )}

            {formData.authMethod === 'ssh_key' && (
              <Grid size={{ xs: 12 }}>
                <TextField
                  fullWidth
                  label="SSH Private Key"
                  value={formData.sshKey}
                  onChange={(e) => onInputChange('sshKey', e.target.value)}
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
              <Grid size={{ xs: 12, md: 6 }}>
                <TextField
                  fullWidth
                  label="Certificate Path"
                  value={formData.certificatePath}
                  onChange={(e) => onInputChange('certificatePath', e.target.value)}
                />
              </Grid>
            )}

            {formData.authMethod === 'agent' && (
              <Grid size={{ xs: 12, md: 6 }}>
                <TextField
                  fullWidth
                  label="Agent Token"
                  value={formData.agentToken}
                  onChange={(e) => onInputChange('agentToken', e.target.value)}
                  placeholder="Enter pre-shared agent token"
                />
              </Grid>
            )}

            <Grid size={{ xs: 12 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={formData.requireSudo}
                    onChange={(e) => onInputChange('requireSudo', e.target.checked)}
                  />
                }
                label="Require Sudo/Administrator Access"
              />
            </Grid>

            {formData.requireSudo && (
              <>
                <Grid size={{ xs: 12, md: 6 }}>
                  <FormControl fullWidth>
                    <InputLabel>Privilege Escalation Method</InputLabel>
                    <Select
                      value={formData.sudoMethod}
                      onChange={(e) => onInputChange('sudoMethod', e.target.value)}
                      label="Privilege Escalation Method"
                    >
                      <MenuItem value="sudo">sudo</MenuItem>
                      <MenuItem value="su">su</MenuItem>
                      <MenuItem value="doas">doas</MenuItem>
                      <MenuItem value="runas">runas (Windows)</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    type="password"
                    label="Sudo Password (if different)"
                    value={formData.sudoPassword}
                    onChange={(e) => onInputChange('sudoPassword', e.target.value)}
                  />
                </Grid>
              </>
            )}

            <Grid size={{ xs: 12 }}>
              <Box sx={{ mt: 2, display: 'flex', gap: 2 }}>
                <Button onClick={onBack}>Back</Button>
                <Button variant="contained" onClick={onNext}>
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
            <Grid size={{ xs: 12, md: 6 }}>
              <FormControl fullWidth>
                <InputLabel>Environment</InputLabel>
                <Select
                  value={formData.environment}
                  onChange={(e) => onInputChange('environment', e.target.value)}
                  label="Environment"
                >
                  <MenuItem value="production">Production</MenuItem>
                  <MenuItem value="staging">Staging</MenuItem>
                  <MenuItem value="development">Development</MenuItem>
                  <MenuItem value="test">Test</MenuItem>
                </Select>
              </FormControl>
            </Grid>

            <Grid size={{ xs: 12, md: 6 }}>
              <TextField
                fullWidth
                label="Host Group/Team"
                value={formData.hostGroup}
                onChange={(e) => onInputChange('hostGroup', e.target.value)}
                placeholder="Web Servers"
              />
            </Grid>

            <Grid size={{ xs: 12, md: 6 }}>
              <TextField
                fullWidth
                label="Owner/Responsible Team"
                value={formData.owner}
                onChange={(e) => onInputChange('owner', e.target.value)}
                placeholder="DevOps Team"
              />
            </Grid>

            <Grid size={{ xs: 12, md: 6 }}>
              <Autocomplete
                multiple
                options={availableTags}
                value={formData.tags}
                onChange={(_, newValue) => onInputChange('tags', newValue)}
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

            <Grid size={{ xs: 12 }}>
              <Box sx={{ mt: 2, display: 'flex', gap: 2 }}>
                <Button onClick={onBack}>Back</Button>
                <Button variant="contained" onClick={onNext}>
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
            <Grid size={{ xs: 12, md: 6 }}>
              <FormControl fullWidth>
                <InputLabel>Compliance Profile</InputLabel>
                <Select
                  value={formData.complianceProfile}
                  onChange={(e) => onInputChange('complianceProfile', e.target.value)}
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

            <Grid size={{ xs: 12, md: 6 }}>
              <FormControl fullWidth>
                <InputLabel>Scan Schedule</InputLabel>
                <Select
                  value={formData.scanSchedule}
                  onChange={(e) => onInputChange('scanSchedule', e.target.value)}
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
              <Grid size={{ xs: 12, md: 6 }}>
                <TextField
                  fullWidth
                  label="Cron Expression"
                  value={formData.customCron}
                  onChange={(e) => onInputChange('customCron', e.target.value)}
                  placeholder="0 2 * * *"
                  helperText="Enter a valid cron expression"
                />
              </Grid>
            )}

            <Grid size={{ xs: 12, md: 6 }}>
              <FormControl fullWidth>
                <InputLabel>Scan Intensity</InputLabel>
                <Select
                  value={formData.scanIntensity}
                  onChange={(e) => onInputChange('scanIntensity', e.target.value)}
                  label="Scan Intensity"
                >
                  <MenuItem value="light">Light (Basic checks)</MenuItem>
                  <MenuItem value="normal">Normal (Standard)</MenuItem>
                  <MenuItem value="deep">Deep (Comprehensive)</MenuItem>
                </Select>
              </FormControl>
            </Grid>

            <Grid size={{ xs: 12, md: 6 }}>
              <FormControl fullWidth>
                <InputLabel>Scan Priority</InputLabel>
                <Select
                  value={formData.scanPriority}
                  onChange={(e) => onInputChange('scanPriority', e.target.value)}
                  label="Scan Priority"
                >
                  <MenuItem value="high">High</MenuItem>
                  <MenuItem value="medium">Medium</MenuItem>
                  <MenuItem value="low">Low</MenuItem>
                </Select>
              </FormControl>
            </Grid>

            {/* Advanced Options */}
            <Grid size={{ xs: 12 }}>
              <Button
                onClick={() => onShowAdvancedToggle(!showAdvanced)}
                endIcon={showAdvanced ? <ExpandLess /> : <ExpandMore />}
              >
                Advanced Options
              </Button>
            </Grid>

            <Collapse in={showAdvanced} timeout="auto" unmountOnExit>
              <Grid container spacing={3} sx={{ mt: 0 }}>
                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    label="Bandwidth Limit (KB/s)"
                    value={formData.bandwidthLimit}
                    onChange={(e) => onInputChange('bandwidthLimit', e.target.value)}
                    placeholder="Leave empty for no limit"
                    type="number"
                  />
                </Grid>

                <Grid size={{ xs: 12, md: 3 }}>
                  <TextField
                    fullWidth
                    label="Connection Timeout (s)"
                    value={formData.connectionTimeout}
                    onChange={(e) => onInputChange('connectionTimeout', e.target.value)}
                    type="number"
                  />
                </Grid>

                <Grid size={{ xs: 12, md: 3 }}>
                  <TextField
                    fullWidth
                    label="Scan Timeout (s)"
                    value={formData.scanTimeout}
                    onChange={(e) => onInputChange('scanTimeout', e.target.value)}
                    type="number"
                  />
                </Grid>

                <Grid size={{ xs: 12 }}>
                  <TextField
                    fullWidth
                    label="Exclude Paths (one per line)"
                    value={formData.excludePaths.join('\n')}
                    onChange={(e) => onInputChange('excludePaths', e.target.value.split('\n'))}
                    multiline
                    rows={3}
                    placeholder={'/tmp\n/var/cache\n/mnt'}
                  />
                </Grid>

                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    label="Proxy Host"
                    value={formData.proxyHost}
                    onChange={(e) => onInputChange('proxyHost', e.target.value)}
                    placeholder="proxy.example.com"
                  />
                </Grid>

                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    label="Proxy Port"
                    value={formData.proxyPort}
                    onChange={(e) => onInputChange('proxyPort', e.target.value)}
                    placeholder="3128"
                  />
                </Grid>

                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    label="Pre-Scan Script"
                    value={formData.preScript}
                    onChange={(e) => onInputChange('preScript', e.target.value)}
                    multiline
                    rows={3}
                    placeholder="Commands to run before scan"
                  />
                </Grid>

                <Grid size={{ xs: 12, md: 6 }}>
                  <TextField
                    fullWidth
                    label="Post-Scan Script"
                    value={formData.postScript}
                    onChange={(e) => onInputChange('postScript', e.target.value)}
                    multiline
                    rows={3}
                    placeholder="Commands to run after scan"
                  />
                </Grid>
              </Grid>
            </Collapse>

            <Grid size={{ xs: 12 }}>
              <Box sx={{ mt: 2, display: 'flex', gap: 2 }}>
                <Button onClick={onBack}>Back</Button>
                <Button variant="contained" onClick={onNext}>
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
            <Grid size={{ xs: 12 }}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Host Configuration Summary
                  </Typography>
                  <Divider sx={{ my: 2 }} />

                  <Grid container spacing={2}>
                    <Grid size={{ xs: 12, md: 6 }}>
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

                    <Grid size={{ xs: 12, md: 6 }}>
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
                          <ListItemText primary="Scan Schedule" secondary={formData.scanSchedule} />
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
                    onClick={onTestConnection}
                    disabled={testingConnection}
                  >
                    Test Connection
                  </Button>
                </CardActions>
              </Card>
            </Grid>

            {connectionStatus !== 'idle' && (
              <Grid size={{ xs: 12 }}>
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
                      <Typography variant="body2">Network connectivity established</Typography>
                      <Typography variant="body2">Authentication verified</Typography>
                      <Typography variant="body2">
                        Operating system detected: Ubuntu 22.04 LTS
                      </Typography>
                      <Typography variant="body2">Sudo access confirmed</Typography>
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

            <Grid size={{ xs: 12 }}>
              <Box sx={{ mt: 2, display: 'flex', gap: 2 }}>
                <Button onClick={onBack}>Back</Button>
                <Button onClick={onCancel}>Cancel</Button>
                <Box sx={{ flexGrow: 1 }} />
                <Button variant="outlined" startIcon={<SaveIcon />}>
                  Save as Template
                </Button>
                <Button
                  variant="contained"
                  onClick={onSubmit}
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
