import React, { useState } from 'react';
import {
  Box,
  Typography,
  Chip,
  Button,
  Stack,
  Card,
  CardContent,
  useTheme,
  alpha,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  DialogContentText,
} from '@mui/material';
import {
  VpnKey,
  Security,
  Warning,
  Error,
  Edit,
  Delete,
  Info,
  Schedule,
} from '@mui/icons-material';

export interface SSHKeyInfo {
  fingerprint?: string | null;
  keyType?: string | null;
  keyBits?: number | null;
  keyComment?: string | null;
  createdAt?: string | null;
  lastUsed?: string | null;
}

export interface SSHKeyDisplayProps {
  sshKeyInfo?: SSHKeyInfo;
  isSystemDefault?: boolean;
  showActions?: boolean;
  onEdit?: () => void;
  onDelete?: () => void;
  onReplace?: () => void;
  compact?: boolean;
  systemDefaultLabel?: string;
  loading?: boolean;
}

const SSHKeyDisplay: React.FC<SSHKeyDisplayProps> = ({
  sshKeyInfo,
  isSystemDefault = false,
  showActions = false,
  onEdit,
  onDelete,
  onReplace,
  compact = false,
  systemDefaultLabel = 'Uses system default SSH key',
  loading = false,
}) => {
  const theme = useTheme();
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);

  // Security level determination
  const getSecurityLevel = () => {
    if (!sshKeyInfo?.keyType || !sshKeyInfo?.keyBits) {
      return { level: 'unknown', color: theme.palette.info.main, icon: Info };
    }

    const keyType = sshKeyInfo.keyType.toLowerCase();
    const bits = sshKeyInfo.keyBits;

    if (keyType === 'ed25519') {
      return { level: 'secure', color: theme.palette.success.main, icon: Security };
    } else if (keyType === 'rsa') {
      if (bits >= 3072) {
        return { level: 'secure', color: theme.palette.success.main, icon: Security };
      } else if (bits >= 2048) {
        return { level: 'acceptable', color: theme.palette.warning.main, icon: Warning };
      } else {
        return { level: 'deprecated', color: theme.palette.error.main, icon: Error };
      }
    } else if (keyType === 'ecdsa') {
      if (bits >= 256) {
        return { level: 'secure', color: theme.palette.success.main, icon: Security };
      } else {
        return { level: 'acceptable', color: theme.palette.warning.main, icon: Warning };
      }
    } else if (keyType === 'dsa') {
      return { level: 'deprecated', color: theme.palette.error.main, icon: Error };
    }

    return { level: 'unknown', color: theme.palette.info.main, icon: Info };
  };

  const security = getSecurityLevel();
  const SecurityIcon = security.icon;

  // Format fingerprint for display (GitHub-style: show full fingerprint)
  const formatFingerprint = (fingerprint: string) => {
    // GitHub shows the full fingerprint, so we'll do the same
    return fingerprint;
  };

  // Format date for display (GitHub-style relative dates)
  const formatDate = (dateString: string | null) => {
    if (!dateString) return null;

    const date = new Date(dateString);
    const now = new Date();
    const diffTime = Math.abs(now.getTime() - date.getTime());
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    if (diffDays === 0) {
      return 'today';
    } else if (diffDays === 1) {
      return '1 day ago';
    } else if (diffDays < 7) {
      return `${diffDays} days ago`;
    } else if (diffDays < 14) {
      return 'within the last 2 weeks';
    } else if (diffDays < 30) {
      return 'within the last month';
    } else {
      return date.toLocaleDateString();
    }
  };

  const handleDeleteClick = () => {
    setDeleteDialogOpen(true);
  };

  const handleDeleteConfirm = () => {
    setDeleteDialogOpen(false);
    onDelete?.();
  };

  const handleDeleteCancel = () => {
    setDeleteDialogOpen(false);
  };

  // Format key type and bits
  const formatKeyType = () => {
    if (!sshKeyInfo?.keyType) return '';
    const type = sshKeyInfo.keyType.toUpperCase();
    const bits = sshKeyInfo.keyBits ? ` ${sshKeyInfo.keyBits}-bit` : '';
    return `${type}${bits}`;
  };

  // System default display
  if (isSystemDefault) {
    return (
      <Card variant="outlined" sx={{ bgcolor: alpha(theme.palette.info.main, 0.05) }}>
        <CardContent sx={{ py: compact ? 1.5 : 2 }}>
          <Stack
            direction={compact ? 'column' : 'row'}
            spacing={2}
            alignItems={compact ? 'flex-start' : 'center'}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <VpnKey sx={{ color: theme.palette.info.main }} />
              <Typography variant="body2" color="text.secondary">
                {systemDefaultLabel}
              </Typography>
            </Box>
            {showActions && (
              <Stack direction="row" spacing={1} sx={{ ml: 'auto' }}>
                <Button size="small" variant="outlined" onClick={onEdit} startIcon={<Edit />}>
                  Configure System Default
                </Button>
              </Stack>
            )}
          </Stack>
        </CardContent>
      </Card>
    );
  }

  // No SSH key configured
  if (!sshKeyInfo?.fingerprint) {
    return (
      <Card variant="outlined" sx={{ bgcolor: alpha(theme.palette.grey[500], 0.05) }}>
        <CardContent sx={{ py: compact ? 1.5 : 2 }}>
          <Stack
            direction={compact ? 'column' : 'row'}
            spacing={2}
            alignItems={compact ? 'flex-start' : 'center'}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <VpnKey sx={{ color: theme.palette.text.secondary }} />
              <Typography variant="body2" color="text.secondary">
                No SSH key configured
              </Typography>
            </Box>
            {showActions && (
              <Stack direction="row" spacing={1} sx={{ ml: 'auto' }}>
                <Button size="small" variant="contained" onClick={onEdit} startIcon={<VpnKey />}>
                  Add SSH Key
                </Button>
              </Stack>
            )}
          </Stack>
        </CardContent>
      </Card>
    );
  }

  // SSH key configured - show details (GitHub-style layout)
  return (
    <>
      <Card variant="outlined">
        <CardContent sx={{ py: compact ? 1.5 : 2 }}>
          <Stack spacing={compact ? 1 : 2}>
            {/* Fingerprint - GitHub style with monospace font */}
            <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}>
              <VpnKey sx={{ color: theme.palette.primary.main, mt: 0.5 }} />
              <Box sx={{ flexGrow: 1 }}>
                <Typography
                  variant="body2"
                  component="div"
                  sx={{
                    fontFamily: 'monospace',
                    fontSize: '0.875rem',
                    color: theme.palette.text.primary,
                    fontWeight: 500,
                    wordBreak: 'break-all',
                    lineHeight: 1.4,
                  }}
                >
                  {formatFingerprint(sshKeyInfo.fingerprint)}
                </Typography>

                {/* GitHub-style metadata line */}
                <Box
                  sx={{ mt: 1, display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}
                >
                  {/* Creation date */}
                  {sshKeyInfo.createdAt && (
                    <Typography variant="caption" color="text.secondary">
                      Added on {new Date(sshKeyInfo.createdAt).toLocaleDateString()}
                    </Typography>
                  )}

                  {/* Last used */}
                  {sshKeyInfo.lastUsed && (
                    <>
                      <Typography variant="caption" color="text.secondary">
                        •
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Last used {formatDate(sshKeyInfo.lastUsed)}
                      </Typography>
                    </>
                  )}

                  {/* Access level - always show Read/write for SSH keys */}
                  <Typography variant="caption" color="text.secondary">
                    •
                  </Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 500 }}>
                    Read/write
                  </Typography>
                </Box>

                {/* Key type and security indicator */}
                <Box sx={{ mt: 1, display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Chip
                    icon={<SecurityIcon />}
                    label={formatKeyType()}
                    size="small"
                    sx={{
                      bgcolor: alpha(security.color, 0.1),
                      color: security.color,
                      '& .MuiChip-icon': {
                        color: security.color,
                      },
                    }}
                  />

                  {/* Key comment */}
                  {sshKeyInfo.keyComment && (
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{ fontStyle: 'italic', ml: 1 }}
                    >
                      "{sshKeyInfo.keyComment}"
                    </Typography>
                  )}
                </Box>
              </Box>
            </Box>

            {/* Actions */}
            {showActions && (
              <Stack direction="row" spacing={1} sx={{ pt: 1 }}>
                {onReplace && (
                  <Button
                    size="small"
                    variant="outlined"
                    onClick={onReplace}
                    startIcon={<Edit />}
                    disabled={loading}
                  >
                    Replace Key
                  </Button>
                )}
                {onDelete && (
                  <Button
                    size="small"
                    variant="outlined"
                    color="error"
                    onClick={handleDeleteClick}
                    startIcon={<Delete />}
                    disabled={loading}
                  >
                    Delete Key
                  </Button>
                )}
              </Stack>
            )}
          </Stack>
        </CardContent>
      </Card>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onClose={handleDeleteCancel} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Delete color="error" />
          Delete SSH Key
        </DialogTitle>
        <DialogContent>
          <DialogContentText>
            Are you sure you want to delete this SSH key? This action cannot be undone.
          </DialogContentText>
          {sshKeyInfo.fingerprint && (
            <Box sx={{ mt: 2, p: 2, bgcolor: 'grey.50', borderRadius: 1 }}>
              <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                {formatFingerprint(sshKeyInfo.fingerprint)}
              </Typography>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleDeleteCancel}>Cancel</Button>
          <Button
            onClick={handleDeleteConfirm}
            color="error"
            variant="contained"
            startIcon={<Delete />}
          >
            Delete Key
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default SSHKeyDisplay;
