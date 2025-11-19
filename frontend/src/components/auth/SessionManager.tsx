import React, { useState, useEffect } from 'react';
import {
  Snackbar,
  Alert,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Typography,
  Box,
  LinearProgress,
} from '@mui/material';
import { useAppSelector, useAppDispatch } from '../../hooks/redux';
import { logout, clearError } from '../../store/slices/authSlice';
import { tokenService } from '../../services/tokenService';

const SessionManager: React.FC = () => {
  const dispatch = useAppDispatch();
  const { isAuthenticated, sessionExpiry, error } = useAppSelector((state) => state.auth);
  const [showExpiryWarning, setShowExpiryWarning] = useState(false);
  const [timeLeft, setTimeLeft] = useState<number | null>(null);
  const [isExtending, setIsExtending] = useState(false);
  const [extendError, setExtendError] = useState<string | null>(null);

  useEffect(() => {
    if (!isAuthenticated || !sessionExpiry) {
      setShowExpiryWarning(false);
      setTimeLeft(null);
      // Resume auto-refresh when not authenticated
      tokenService.resumeAutoRefresh();
      return;
    }

    let forceLogoutTimer: NodeJS.Timeout | null = null;

    const checkExpiry = () => {
      const now = Date.now();
      const remaining = sessionExpiry - now;

      // Show warning if 5 minutes or less remaining
      if (remaining <= 5 * 60 * 1000 && remaining > 0) {
        setTimeLeft(Math.floor(remaining / 1000));
        setShowExpiryWarning(true);
        // Pause auto-refresh during manual session management
        tokenService.pauseAutoRefresh();
        // Clear any existing force logout timer
        if (forceLogoutTimer) {
          clearTimeout(forceLogoutTimer);
          forceLogoutTimer = null;
        }
      } else if (remaining <= 0) {
        // Session has expired, but don't close the warning yet
        // Let the user see the 0:00 countdown and try to extend
        setTimeLeft(0);
        setShowExpiryWarning(true);

        // Set a force logout timer if not already set
        if (!forceLogoutTimer) {
          forceLogoutTimer = setTimeout(() => {
            dispatch(logout());
          }, 60000); // Force logout after 1 minute at 0:00
        }
      } else {
        setShowExpiryWarning(false);
        setTimeLeft(null);
        // Resume auto-refresh when not in warning period
        tokenService.resumeAutoRefresh();
        // Clear any existing force logout timer
        if (forceLogoutTimer) {
          clearTimeout(forceLogoutTimer);
          forceLogoutTimer = null;
        }
      }
    };

    // Check immediately and then every second
    checkExpiry();
    const interval = setInterval(checkExpiry, 1000);

    return () => {
      clearInterval(interval);
      if (forceLogoutTimer) {
        clearTimeout(forceLogoutTimer);
      }
    };
  }, [isAuthenticated, sessionExpiry, dispatch]);

  const handleExtendSession = async () => {
    setIsExtending(true);
    setExtendError(null);

    // Security check: Don't allow extension if session has been expired for more than 60 seconds
    const now = Date.now();
    const gracePeriod = 60 * 1000; // 1 minute grace period
    if (sessionExpiry && now > sessionExpiry + gracePeriod) {
      setExtendError('Session expired too long ago. Please log in again for security.');
      setTimeout(() => dispatch(logout()), 2000);
      return;
    }

    try {
      // Use manual refresh mode to prevent automatic logout
      const success = await tokenService.refreshToken(true);
      if (success) {
        setShowExpiryWarning(false);
        setTimeLeft(null);
        setExtendError(null);
        // Resume auto-refresh after successful manual extension
        tokenService.resumeAutoRefresh();
        // Session extension completed - token refresh succeeded
      } else {
        // Security: Failed refresh should force logout
        setExtendError('Failed to extend session. You will be logged out for security.');
        setTimeout(() => dispatch(logout()), 3000);
      }
    } catch (error) {
      // Security: Network errors during token refresh should force logout
      setExtendError(
        'Network error during session extension. You will be logged out for security.'
      );
      console.error('Failed to extend session:', error);
      setTimeout(() => dispatch(logout()), 3000);
    } finally {
      setIsExtending(false);
    }
  };

  const handleLogout = () => {
    dispatch(logout());
    setShowExpiryWarning(false);
    // Resume auto-refresh on manual logout
    tokenService.resumeAutoRefresh();
  };

  const formatTime = (seconds: number) => {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
  };

  const progressValue = timeLeft ? Math.max(0, (timeLeft / (5 * 60)) * 100) : 0;

  return (
    <>
      <style>
        {`
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
        `}
      </style>

      {/* Session expiry warning dialog */}
      <Dialog
        open={showExpiryWarning}
        onClose={() => {}} // Prevent closing by clicking outside
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="h6">Session Expiring Soon</Typography>
          </Box>
        </DialogTitle>
        <DialogContent>
          <Typography variant="body1" gutterBottom>
            Your session will expire in <strong>{timeLeft ? formatTime(timeLeft) : '0:00'}</strong>.
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            You will be automatically logged out for security purposes.
          </Typography>

          <Box sx={{ mb: 2 }}>
            <LinearProgress
              variant="determinate"
              value={progressValue}
              color={progressValue > 50 ? 'primary' : progressValue > 20 ? 'warning' : 'error'}
              sx={{ height: 8, borderRadius: 4 }}
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleLogout} color="inherit">
            Logout Now
          </Button>
          <Button
            onClick={handleExtendSession}
            variant="contained"
            disabled={isExtending}
            startIcon={
              isExtending ? (
                <div
                  style={{
                    width: 16,
                    height: 16,
                    border: '2px solid transparent',
                    borderTop: '2px solid currentColor',
                    borderRadius: '50%',
                    animation: 'spin 1s linear infinite',
                  }}
                />
              ) : null
            }
          >
            {isExtending ? 'Extending...' : 'Extend Session'}
          </Button>
        </DialogActions>

        {extendError && (
          <Box sx={{ px: 3, pb: 2 }}>
            <Typography variant="body2" color="error" sx={{ textAlign: 'center' }}>
              {extendError}
            </Typography>
          </Box>
        )}
      </Dialog>

      {/* Error notifications */}
      <Snackbar
        open={!!error}
        autoHideDuration={6000}
        onClose={() => dispatch(clearError())}
        anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        <Alert onClose={() => dispatch(clearError())} severity="error" variant="filled">
          {error}
        </Alert>
      </Snackbar>
    </>
  );
};

export default SessionManager;
