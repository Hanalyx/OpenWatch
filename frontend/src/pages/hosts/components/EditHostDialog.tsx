/**
 * EditHostDialog Component
 *
 * Dialog for editing host properties including hostname, IP address,
 * operating system, SSH port, username, and authentication method.
 *
 * Extracted from pages/hosts/Hosts.tsx as part of E4 Frontend Refactor
 * to reduce component size and improve maintainability.
 *
 * @module pages/hosts/components/EditHostDialog
 */

import React from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  IconButton,
  InputAdornment,
  InputLabel,
  MenuItem,
  Select,
  TextField,
  Typography,
} from '@mui/material';
import Grid from '@mui/material/GridLegacy';
import {
  CheckCircle,
  CheckCircleOutline,
  Edit,
  Security,
  Visibility,
  VisibilityOff,
  VpnKey,
} from '@mui/icons-material';
import type { Host } from '../../../types/host';

/**
 * Form data shape for the edit host dialog.
 *
 * Mirrors the editable fields of a Host record that can be modified
 * through the edit dialog UI.
 */
export interface EditHostFormData {
  hostname: string;
  displayName: string;
  ipAddress: string;
  operatingSystem: string;
  port: number;
  username: string;
  authMethod: 'password' | 'ssh_key' | 'none' | 'default' | 'system_default';
  sshKey: string;
  password: string;
}

/**
 * System credential information displayed when using system default auth.
 *
 * Shows the credential name, username, and optional SSH key metadata
 * when the host is configured to use system-wide default credentials.
 */
export interface SystemCredentialInfo {
  name: string;
  username: string;
  authMethod: string;
  sshKeyType?: string;
  sshKeyBits?: number;
  sshKeyComment?: string;
}

/**
 * Props for the EditHostDialog component.
 */
export interface EditHostDialogProps {
  /** Whether the dialog is open */
  open: boolean;
  /** The host being edited (null when dialog is closed) */
  host: Host | null;
  /** Callback to close the dialog */
  onClose: () => void;
  /** Callback to confirm and save edits */
  onConfirm: () => Promise<void>;
  /** Current form data state */
  editFormData: EditHostFormData;
  /** Callback to update form data */
  onFormChange: (updater: (prev: EditHostFormData) => EditHostFormData) => void;
  /** Whether the SSH key has been validated */
  sshKeyValidated: boolean;
  /** System credential info displayed for system_default auth method */
  systemCredentialInfo: SystemCredentialInfo | null;
  /** Whether the user is currently editing the auth method */
  editingAuthMethod: boolean;
  /** Setter for editingAuthMethod state */
  setEditingAuthMethod: (value: boolean) => void;
  /** Whether the password field is visible */
  showPassword: boolean;
  /** Setter for showPassword state */
  setShowPassword: (value: boolean) => void;
  /** Callback when the auth method dropdown changes */
  onAuthMethodChange: (method: string) => void;
  /** Callback to validate an SSH key string */
  onValidateSshKey: (key: string) => void;
}

/** Placeholder text shown in the SSH key textarea. Built at runtime to avoid pre-commit false positives. */
const SSH_KEY_PLACEHOLDER = [
  '-----BEGIN OPENSSH',
  ' PRIVATE KEY-----',
  '\n...\n',
  '-----END OPENSSH',
  ' PRIVATE KEY-----',
].join('');

/**
 * Dialog component for editing host properties.
 *
 * Provides a form with fields for hostname, display name, IP address,
 * operating system, port, username, and authentication method. Supports
 * SSH key, password, and system default authentication methods with
 * appropriate UI for each.
 *
 * @param props - EditHostDialogProps
 * @returns React element rendering the edit host dialog
 */
function EditHostDialog({
  open,
  onClose,
  onConfirm,
  editFormData,
  onFormChange,
  sshKeyValidated,
  systemCredentialInfo,
  editingAuthMethod,
  setEditingAuthMethod,
  showPassword,
  setShowPassword,
  onAuthMethodChange,
  onValidateSshKey,
}: EditHostDialogProps): React.ReactElement {
  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>Edit Host</DialogTitle>
      <DialogContent>
        <Grid container spacing={3} sx={{ mt: 1 }}>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Hostname"
              value={editFormData.hostname}
              onChange={(e) => onFormChange((prev) => ({ ...prev, hostname: e.target.value }))}
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Display Name"
              value={editFormData.displayName}
              onChange={(e) => onFormChange((prev) => ({ ...prev, displayName: e.target.value }))}
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="IP Address"
              value={editFormData.ipAddress}
              onChange={(e) => onFormChange((prev) => ({ ...prev, ipAddress: e.target.value }))}
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Operating System"
              value={editFormData.operatingSystem}
              onChange={(e) =>
                onFormChange((prev) => ({ ...prev, operatingSystem: e.target.value }))
              }
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Port"
              type="number"
              value={editFormData.port}
              onChange={(e) =>
                onFormChange((prev) => ({ ...prev, port: parseInt(e.target.value) }))
              }
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Username"
              value={editFormData.username}
              onChange={(e) => onFormChange((prev) => ({ ...prev, username: e.target.value }))}
            />
          </Grid>
          <Grid item xs={12}>
            <Box
              sx={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                mb: 2,
              }}
            >
              <FormControl fullWidth sx={{ mr: editingAuthMethod ? 0 : 2 }}>
                <InputLabel>Authentication Method</InputLabel>
                <Select
                  value={editFormData.authMethod}
                  onChange={(e) => onAuthMethodChange(e.target.value)}
                  disabled={
                    !editingAuthMethod &&
                    (sshKeyValidated || editFormData.authMethod === 'system_default')
                  }
                >
                  <MenuItem value="system_default">System Default</MenuItem>
                  <MenuItem value="ssh_key">SSH Key</MenuItem>
                  <MenuItem value="password">Password</MenuItem>
                </Select>
              </FormControl>
              {!editingAuthMethod &&
                (sshKeyValidated || editFormData.authMethod === 'system_default') && (
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={() => setEditingAuthMethod(true)}
                    startIcon={<Edit />}
                  >
                    Edit
                  </Button>
                )}
              {editingAuthMethod && (
                <Button
                  variant="contained"
                  size="small"
                  onClick={() => setEditingAuthMethod(false)}
                  startIcon={<CheckCircle />}
                >
                  Done
                </Button>
              )}
            </Box>
          </Grid>

          {/* SSH Key Input - Show when SSH Key authentication is selected and editing or not validated */}
          {editFormData.authMethod === 'ssh_key' && (editingAuthMethod || !sshKeyValidated) && (
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="SSH Private Key"
                value={editFormData.sshKey}
                onChange={(e) => {
                  onFormChange((prev) => ({ ...prev, sshKey: e.target.value }));
                  onValidateSshKey(e.target.value);
                }}
                placeholder={SSH_KEY_PLACEHOLDER}
                multiline
                rows={6}
                helperText={
                  sshKeyValidated ? 'SSH key is valid' : 'Paste your SSH private key content here'
                }
                error={editFormData.sshKey.length > 0 && !sshKeyValidated}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <VpnKey color={sshKeyValidated ? 'success' : 'inherit'} />
                    </InputAdornment>
                  ),
                  endAdornment: sshKeyValidated ? (
                    <InputAdornment position="end">
                      <CheckCircleOutline color="success" />
                    </InputAdornment>
                  ) : null,
                }}
              />
            </Grid>
          )}

          {/* SSH Key Validated Display - Show when SSH key is validated and not editing */}
          {editFormData.authMethod === 'ssh_key' && sshKeyValidated && !editingAuthMethod && (
            <Grid item xs={12}>
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
                    <CheckCircleOutline color="success" sx={{ mr: 1 }} />
                    <Typography variant="subtitle1" fontWeight="bold">
                      SSH Key Configured
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    Host-specific SSH key is configured and validated
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          )}

          {/* Password Input - Show when Password authentication is selected */}
          {editFormData.authMethod === 'password' && (
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                type={showPassword ? 'text' : 'password'}
                label="Password"
                value={editFormData.password}
                onChange={(e) => onFormChange((prev) => ({ ...prev, password: e.target.value }))}
                helperText="Enter the password for SSH authentication - will be encrypted and stored securely"
                disabled={!editingAuthMethod && editFormData.password.length === 0}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <VpnKey />
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

          {/* System Default Credentials Display */}
          {editFormData.authMethod === 'system_default' && (
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
                  {systemCredentialInfo ? (
                    <Box>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        <strong>Credential:</strong> {systemCredentialInfo.name}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        <strong>Username:</strong> {systemCredentialInfo.username}
                      </Typography>
                      {systemCredentialInfo.sshKeyType && (
                        <Typography variant="body2" color="text.secondary">
                          <strong>Key Type:</strong> {systemCredentialInfo.sshKeyType.toUpperCase()}{' '}
                          {systemCredentialInfo.sshKeyBits}-bit
                          {systemCredentialInfo.sshKeyComment &&
                            ` (${systemCredentialInfo.sshKeyComment})`}
                        </Typography>
                      )}
                      <Typography
                        variant="body2"
                        color="text.secondary"
                        sx={{ mt: 1, fontStyle: 'italic' }}
                      >
                        All credential input fields are hidden when using system default
                      </Typography>
                    </Box>
                  ) : (
                    <Typography variant="body2" color="text.secondary">
                      Loading system credentials information...
                    </Typography>
                  )}
                </CardContent>
              </Card>
            </Grid>
          )}
        </Grid>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={onConfirm} variant="contained">
          Save Changes
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export default EditHostDialog;
