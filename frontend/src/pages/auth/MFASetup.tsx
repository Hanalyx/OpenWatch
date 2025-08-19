import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Paper,
  Typography,
  Box,
  Button,
  TextField,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Alert,
  CircularProgress,
  Grid,
  Card,
  CardContent,
  Chip,
  QRCodeSVG,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Switch,
  FormControlLabel,
} from '@mui/material';
import {
  Security,
  Smartphone,
  QrCode,
  Check,
  Warning,
  ContentCopy,
  Download,
  VerifiedUser,
  Key,
  Shield,
} from '@mui/icons-material';
import { useForm } from 'react-hook-form';
import { useAppSelector, useAppDispatch } from '../../hooks/redux';
import { tokenService } from '../../services/tokenService';
import { announcer } from '../../utils/accessibility';

// QR Code component placeholder - in real implementation, use a proper QR code library
const QRCode: React.FC<{ value: string; size?: number }> = ({ value, size = 200 }) => (
  <Box
    sx={{
      width: size,
      height: size,
      border: '1px solid',
      borderColor: 'divider',
      borderRadius: 2,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      bgcolor: 'background.paper',
    }}
  >
    <Typography variant="caption" color="text.secondary" align="center">
      QR Code: {value.substring(0, 20)}...
    </Typography>
  </Box>
);

interface MFASetupData {
  verificationCode: string;
  backupCodes: string[];
  backupOption: boolean;
}

interface MFASecret {
  secret: string;
  qr_code: string;
  backup_codes: string[];
  issuer: string;
  account_name: string;
}

const MFASetup: React.FC = () => {
  const navigate = useNavigate();
  const dispatch = useAppDispatch();
  const { user } = useAppSelector((state) => state.auth);
  
  const [activeStep, setActiveStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mfaSecret, setMfaSecret] = useState<MFASecret | null>(null);
  const [setupComplete, setSetupComplete] = useState(false);
  const [backupCodesVisible, setBackupCodesVisible] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors },
    watch,
  } = useForm<MFASetupData>();

  useEffect(() => {
    // Initialize MFA setup when component mounts
    initializeMFASetup();
  }, []);

  const initializeMFASetup = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await tokenService.authenticatedFetch('/api/auth/mfa/setup', {
        method: 'POST',
      });

      if (!response.ok) {
        throw new Error('Failed to initialize MFA setup');
      }

      const data: MFASecret = await response.json();
      setMfaSecret(data);
      announcer.announce('MFA setup initialized. Please scan the QR code with your authenticator app.');
    } catch (err: any) {
      setError(err.message || 'Failed to initialize MFA setup');
      announcer.announce('Error initializing MFA setup', 'assertive');
    } finally {
      setLoading(false);
    }
  };

  const verifyAndEnableMFA = async (data: MFASetupData) => {
    if (!mfaSecret) return;

    setLoading(true);
    setError(null);

    try {
      const response = await tokenService.authenticatedFetch('/api/auth/mfa/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          verification_code: data.verificationCode,
          enable_mfa: true,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to verify MFA code');
      }

      setSetupComplete(true);
      setActiveStep(2);
      announcer.announce('MFA setup completed successfully!');
    } catch (err: any) {
      setError(err.message || 'Failed to verify MFA code');
      announcer.announce('MFA verification failed', 'assertive');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      announcer.announce('Copied to clipboard');
    } catch (err) {
      console.warn('Failed to copy to clipboard');
    }
  };

  const downloadBackupCodes = () => {
    if (!mfaSecret?.backup_codes) return;

    const content = [
      'Hanalyx SecureOps - MFA Backup Codes',
      '=======================================',
      '',
      'These backup codes can be used to access your account if you lose access to your authenticator device.',
      'Each code can only be used once. Store them in a secure location.',
      '',
      ...mfaSecret.backup_codes.map((code, index) => `${index + 1}. ${code}`),
      '',
      `Generated on: ${new Date().toLocaleDateString()}`,
      `Account: ${user?.username}`,
    ].join('\n');

    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `openwatch-backup-codes-${user?.username}-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    announcer.announce('Backup codes downloaded');
  };

  const steps = [
    {
      label: 'Install Authenticator App',
      description: 'Choose and install a compatible authenticator application',
    },
    {
      label: 'Scan QR Code',
      description: 'Add your account to the authenticator app',
    },
    {
      label: 'Verify Setup',
      description: 'Confirm your authenticator is working correctly',
    },
  ];

  if (loading && !mfaSecret) {
    return (
      <Container component="main" maxWidth="sm">
        <Box sx={{ mt: 8, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <CircularProgress />
          <Typography sx={{ mt: 2 }}>Initializing MFA setup...</Typography>
        </Box>
      </Container>
    );
  }

  return (
    <Container component="main" maxWidth="md">
      <Box sx={{ mt: 4, mb: 4 }}>
        <Paper elevation={3} sx={{ p: 4 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
            <Security sx={{ mr: 2, fontSize: 32, color: 'primary.main' }} />
            <Box>
              <Typography variant="h4" gutterBottom>
                Multi-Factor Authentication Setup
              </Typography>
              <Typography variant="body1" color="text.secondary">
                Enhance your account security with two-factor authentication
              </Typography>
            </Box>
          </Box>

          {error && (
            <Alert severity="error" sx={{ mb: 3 }} role="alert">
              {error}
            </Alert>
          )}

          {setupComplete ? (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <VerifiedUser sx={{ fontSize: 64, color: 'success.main', mb: 2 }} />
              <Typography variant="h5" gutterBottom>
                MFA Setup Complete!
              </Typography>
              <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                Your account is now protected with multi-factor authentication.
              </Typography>
              <Button
                variant="contained"
                size="large"
                onClick={() => navigate('/dashboard')}
              >
                Continue to Dashboard
              </Button>
            </Box>
          ) : (
            <Stepper activeStep={activeStep} orientation="vertical">
              {/* Step 1: Install Authenticator App */}
              <Step>
                <StepLabel>Install Authenticator App</StepLabel>
                <StepContent>
                  <Typography variant="body1" gutterBottom>
                    Choose and install a compatible authenticator application on your mobile device:
                  </Typography>
                  
                  <Grid container spacing={2} sx={{ mt: 2, mb: 3 }}>
                    {[
                      { name: 'Google Authenticator', icon: '🔐' },
                      { name: 'Microsoft Authenticator', icon: '🔑' },
                      { name: 'Authy', icon: '🛡️' },
                      { name: 'LastPass Authenticator', icon: '🔒' },
                    ].map((app) => (
                      <Grid item xs={12} sm={6} key={app.name}>
                        <Card variant="outlined" sx={{ height: '100%' }}>
                          <CardContent sx={{ textAlign: 'center', py: 2 }}>
                            <Typography variant="h4" sx={{ mb: 1 }}>
                              {app.icon}
                            </Typography>
                            <Typography variant="body2">
                              {app.name}
                            </Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                    ))}
                  </Grid>

                  <Alert severity="info" sx={{ mb: 2 }}>
                    <Typography variant="body2">
                      We recommend Google Authenticator or Microsoft Authenticator for the best experience.
                    </Typography>
                  </Alert>

                  <Button
                    variant="contained"
                    onClick={() => setActiveStep(1)}
                    sx={{ mr: 1 }}
                  >
                    App Installed
                  </Button>
                </StepContent>
              </Step>

              {/* Step 2: Scan QR Code */}
              <Step>
                <StepLabel>Scan QR Code</StepLabel>
                <StepContent>
                  {mfaSecret && (
                    <Grid container spacing={3}>
                      <Grid item xs={12} md={6}>
                        <Box sx={{ textAlign: 'center' }}>
                          <Typography variant="h6" gutterBottom>
                            Scan this QR code
                          </Typography>
                          <QRCode value={mfaSecret.qr_code} size={200} />
                          <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                            Or enter the key manually
                          </Typography>
                        </Box>
                      </Grid>
                      
                      <Grid item xs={12} md={6}>
                        <Typography variant="h6" gutterBottom>
                          Manual Entry
                        </Typography>
                        <List>
                          <ListItem>
                            <ListItemIcon>
                              <Key />
                            </ListItemIcon>
                            <ListItemText
                              primary="Account"
                              secondary={mfaSecret.account_name}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon>
                              <Shield />
                            </ListItemIcon>
                            <ListItemText
                              primary="Issuer"
                              secondary={mfaSecret.issuer}
                            />
                          </ListItem>
                          <ListItem>
                            <ListItemIcon>
                              <ContentCopy />
                            </ListItemIcon>
                            <ListItemText
                              primary="Secret Key"
                              secondary={
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                  <Typography
                                    component="code"
                                    sx={{
                                      fontFamily: 'monospace',
                                      fontSize: '0.875rem',
                                      bgcolor: 'grey.100',
                                      p: 0.5,
                                      borderRadius: 1,
                                      wordBreak: 'break-all',
                                    }}
                                  >
                                    {mfaSecret.secret}
                                  </Typography>
                                  <Button
                                    size="small"
                                    startIcon={<ContentCopy />}
                                    onClick={() => copyToClipboard(mfaSecret.secret)}
                                  >
                                    Copy
                                  </Button>
                                </Box>
                              }
                            />
                          </ListItem>
                        </List>
                      </Grid>
                    </Grid>
                  )}

                  <Box sx={{ mt: 3 }}>
                    <Button
                      variant="contained"
                      onClick={() => setActiveStep(2)}
                      sx={{ mr: 1 }}
                    >
                      QR Code Scanned
                    </Button>
                    <Button onClick={() => setActiveStep(0)}>
                      Back
                    </Button>
                  </Box>
                </StepContent>
              </Step>

              {/* Step 3: Verify Setup */}
              <Step>
                <StepLabel>Verify Setup</StepLabel>
                <StepContent>
                  <Typography variant="body1" gutterBottom>
                    Enter the 6-digit code from your authenticator app to verify the setup:
                  </Typography>

                  <Box component="form" onSubmit={handleSubmit(verifyAndEnableMFA)} sx={{ mt: 2 }}>
                    <TextField
                      fullWidth
                      label="Verification Code"
                      placeholder="000000"
                      {...register('verificationCode', {
                        required: 'Verification code is required',
                        pattern: {
                          value: /^[0-9]{6}$/,
                          message: 'Code must be 6 digits',
                        },
                      })}
                      error={!!errors.verificationCode}
                      helperText={errors.verificationCode?.message}
                      inputProps={{
                        maxLength: 6,
                        autoComplete: 'one-time-code',
                        'aria-describedby': 'verification-code-help',
                      }}
                      sx={{ mb: 2 }}
                      autoFocus
                    />

                    <Typography
                      id="verification-code-help"
                      variant="caption"
                      color="text.secondary"
                      sx={{ display: 'block', mb: 2 }}
                    >
                      The code refreshes every 30 seconds in your authenticator app
                    </Typography>

                    {mfaSecret?.backup_codes && (
                      <Box sx={{ mt: 3, mb: 2 }}>
                        <Divider sx={{ mb: 2 }} />
                        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                          <Typography variant="h6">
                            Backup Codes
                          </Typography>
                          <FormControlLabel
                            control={
                              <Switch
                                checked={backupCodesVisible}
                                onChange={(e) => setBackupCodesVisible(e.target.checked)}
                              />
                            }
                            label="Show codes"
                          />
                        </Box>
                        
                        <Alert severity="warning" sx={{ mb: 2 }}>
                          <Typography variant="body2">
                            Save these backup codes in a secure location. They can be used to access your account if you lose your authenticator device.
                          </Typography>
                        </Alert>

                        {backupCodesVisible && (
                          <Box sx={{ mb: 2 }}>
                            <Grid container spacing={1}>
                              {mfaSecret.backup_codes.map((code, index) => (
                                <Grid item xs={6} key={index}>
                                  <Chip
                                    label={code}
                                    variant="outlined"
                                    sx={{
                                      fontFamily: 'monospace',
                                      fontSize: '0.875rem',
                                      width: '100%',
                                    }}
                                  />
                                </Grid>
                              ))}
                            </Grid>
                            <Button
                              startIcon={<Download />}
                              onClick={downloadBackupCodes}
                              sx={{ mt: 2 }}
                            >
                              Download Backup Codes
                            </Button>
                          </Box>
                        )}
                      </Box>
                    )}

                    <Box sx={{ mt: 3 }}>
                      <Button
                        type="submit"
                        variant="contained"
                        disabled={loading}
                        sx={{ mr: 1 }}
                      >
                        {loading ? <CircularProgress size={24} /> : 'Verify & Enable MFA'}
                      </Button>
                      <Button onClick={() => setActiveStep(1)}>
                        Back
                      </Button>
                    </Box>
                  </Box>
                </StepContent>
              </Step>
            </Stepper>
          )}
        </Paper>
      </Box>
    </Container>
  );
};

export default MFASetup;