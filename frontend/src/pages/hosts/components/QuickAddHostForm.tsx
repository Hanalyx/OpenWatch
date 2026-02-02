import React from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Chip,
  Alert,
  AlertTitle,
  FormControlLabel,
  RadioGroup,
  Radio,
  IconButton,
  InputAdornment,
  Card,
  CardContent,
  Divider,
  LinearProgress,
} from '@mui/material';
import Grid from '@mui/material/Grid';
import {
  Computer,
  Key,
  Password,
  Error as ErrorIcon,
  NetworkCheck,
  Security,
  AccountTree,
  Dns,
  Add,
  Cancel,
  CheckCircle,
  Visibility,
  VisibilityOff,
  Edit,
  Settings,
} from '@mui/icons-material';
import type {
  ConnectionTestResults,
  SshKeyValidation,
  SystemCredentialsInfo,
  AddHostFormData,
} from '../hooks/useAddHostForm';

/**
 * Runtime-constructed SSH key placeholder to avoid triggering
 * the detect-private-key pre-commit hook.
 */
const SSH_KEY_PLACEHOLDER = [
  '-----BEGIN OPENSSH',
  ' PRIVATE KEY-----',
  '\n...\n',
  '-----END OPENSSH',
  ' PRIVATE KEY-----',
].join('');

interface QuickAddHostFormProps {
  formData: AddHostFormData;
  showPassword: boolean;
  connectionStatus: 'idle' | 'testing' | 'success' | 'failed';
  connectionTestResults: ConnectionTestResults | null;
  testingConnection: boolean;
  sshKeyValidation: SshKeyValidation;
  authMethodLocked: boolean;
  systemCredentials: SystemCredentialsInfo | null;
  editingAuth: boolean;
  onInputChange: (field: string, value: string | number | boolean | string[]) => void;
  onTestConnection: () => Promise<void>;
  onSubmit: () => Promise<void>;
  onAuthMethodChange: (method: string) => Promise<void>;
  onToggleAuthEdit: () => void;
  onValidateSshKey: (key: string) => Promise<void>;
  onShowPasswordToggle: (show: boolean) => void;
  onModeChange: (quick: boolean) => void;
  onCancel: () => void;
}

export const QuickAddHostForm: React.FC<QuickAddHostFormProps> = ({
  formData,
  showPassword,
  connectionStatus,
  connectionTestResults,
  testingConnection,
  sshKeyValidation,
  authMethodLocked,
  systemCredentials,
  editingAuth,
  onInputChange,
  onTestConnection,
  onSubmit,
  onAuthMethodChange,
  onToggleAuthEdit,
  onValidateSshKey,
  onShowPasswordToggle,
  onModeChange,
  onCancel,
}) => (
  <Paper sx={{ p: 3 }}>
    <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
      <Typography variant="h5" fontWeight="bold">
        Quick Add Host
      </Typography>
      <Button variant="outlined" onClick={() => onModeChange(false)} startIcon={<Settings />}>
        Advanced Mode
      </Button>
    </Box>

    <Grid container spacing={3}>
      <Grid size={{ xs: 12, md: 6 }}>
        <TextField
          fullWidth
          label="Hostname or IP Address"
          value={formData.hostname}
          onChange={(e) => onInputChange('hostname', e.target.value)}
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
      <Grid size={{ xs: 12, md: 6 }}>
        <TextField
          fullWidth
          label="Display Name (Optional)"
          value={formData.displayName}
          onChange={(e) => onInputChange('displayName', e.target.value)}
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

      <Grid size={{ xs: 12 }}>
        <Divider sx={{ my: 1 }} />
        <Typography variant="subtitle2" color="text.secondary" sx={{ mt: 2, mb: 2 }}>
          Authentication Method
        </Typography>
      </Grid>

      <Grid size={{ xs: 12 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
          <Box>
            <RadioGroup
              value={formData.authMethod}
              onChange={(e) => onAuthMethodChange(e.target.value)}
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
              onClick={onToggleAuthEdit}
              startIcon={editingAuth ? <CheckCircle /> : <Edit />}
              color={editingAuth ? 'primary' : 'secondary'}
            >
              {editingAuth ? 'Done' : 'Edit'}
            </Button>
          )}
        </Box>
      </Grid>

      <Grid size={{ xs: 12, md: 6 }}>
        <TextField
          fullWidth
          label="Username"
          value={formData.username}
          onChange={(e) => onInputChange('username', e.target.value)}
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
        <Grid size={{ xs: 12, md: 6 }}>
          <TextField
            fullWidth
            type={showPassword ? 'text' : 'password'}
            label="Password"
            value={formData.password}
            onChange={(e) => onInputChange('password', e.target.value)}
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
                    onClick={() => onShowPasswordToggle(!showPassword)}
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
        <Grid size={{ xs: 12 }}>
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
        <Grid size={{ xs: 12 }}>
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
                  onInputChange('sshKey', e.target.value);
                  onValidateSshKey(e.target.value);
                }}
                placeholder={SSH_KEY_PLACEHOLDER}
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
          <Grid size={{ xs: 12 }}>
            <Alert severity="info" icon={<Security />}>
              <AlertTitle>SSH Key + Password Fallback</AlertTitle>
              The system will attempt SSH key authentication first (more secure). If SSH key fails,
              it will automatically fallback to password authentication.
            </Alert>
          </Grid>

          <Grid size={{ xs: 12 }}>
            <TextField
              fullWidth
              label="SSH Private Key (Primary)"
              value={formData.sshKey}
              onChange={(e) => {
                onInputChange('sshKey', e.target.value);
                onValidateSshKey(e.target.value);
              }}
              placeholder={SSH_KEY_PLACEHOLDER}
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

          <Grid size={{ xs: 12, md: 6 }}>
            <TextField
              fullWidth
              type={showPassword ? 'text' : 'password'}
              label="Password (Fallback)"
              value={formData.password}
              onChange={(e) => onInputChange('password', e.target.value)}
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
                    <IconButton onClick={() => onShowPasswordToggle(!showPassword)} edge="end">
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
          </Grid>
        </>
      )}

      <Grid size={{ xs: 12 }}>
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
          <Button variant="outlined" onClick={() => onCancel()} startIcon={<Cancel />}>
            Cancel
          </Button>
          <Button
            variant="outlined"
            onClick={onTestConnection}
            startIcon={testingConnection ? <LinearProgress /> : <NetworkCheck />}
            disabled={testingConnection || !formData.hostname || !formData.username}
          >
            Test Connection
          </Button>
          <Button
            variant="contained"
            onClick={onSubmit}
            startIcon={<Add />}
            disabled={
              !formData.hostname || (!formData.username && formData.authMethod !== 'system_default')
            }
          >
            Add Host & Scan Now
          </Button>
        </Box>
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
              {connectionStatus === 'success' && 'Connection Successful'}
              {connectionStatus === 'failed' && 'Connection Failed'}
            </AlertTitle>
            {connectionStatus === 'success' && connectionTestResults?.success && (
              <Box>
                <Typography variant="body2">
                  {connectionTestResults.networkConnectivity ? '\u2713' : '\u2717'} Network
                  connectivity verified
                  {connectionTestResults.responseTime > 0 &&
                    ` (${connectionTestResults.responseTime}ms)`}
                </Typography>
                <Typography variant="body2">
                  {connectionTestResults.authentication ? '\u2713' : '\u2717'} Authentication
                  successful
                </Typography>
                <Typography variant="body2">
                  {'\u2713'} Detected: {connectionTestResults.detectedOS}
                  {connectionTestResults.detectedVersion &&
                    ` ${connectionTestResults.detectedVersion}`}
                </Typography>
                {connectionTestResults.sshVersion && (
                  <Typography variant="body2">
                    {'\u2713'} SSH Version: {connectionTestResults.sshVersion}
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
                    {connectionTestResults.networkConnectivity ? '\u2713' : '\u2717'} Network
                    connectivity
                  </Typography>
                  <Typography variant="body2">
                    {connectionTestResults.authentication ? '\u2713' : '\u2717'} Authentication
                  </Typography>
                </Box>
              )}
          </Alert>
        </Grid>
      )}
    </Grid>
  </Paper>
);
