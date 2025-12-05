import React, { useState, useEffect, useCallback } from 'react';
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
import { activityTracker } from '../../services/activityTracker';

const SessionManager: React.FC = () => {
  const dispatch = useAppDispatch();
  const { isAuthenticated, error } = useAppSelector((state) => state.auth);
  const [showExpiryWarning, setShowExpiryWarning] = useState(false);
  const [timeLeft, setTimeLeft] = useState<number | null>(null);
  const [isExtending, setIsExtending] = useState(false);
  const [extendError, setExtendError] = useState<string | null>(null);

  // Warning threshold: show warning when 5 minutes remain
  const WARNING_THRESHOLD_SECONDS = 5 * 60;

  // Handle inactivity warning callback
  const handleInactivityWarning = useCallback((timeLeftSeconds: number) => {
    setTimeLeft(timeLeftSeconds);
    setShowExpiryWarning(true);
    // Pause auto-refresh during manual session management
    tokenService.pauseAutoRefresh();
  }, []);

  // Handle inactivity logout callback
  const handleInactivityLogout = useCallback(() => {
    dispatch(logout());
  }, [dispatch]);

  useEffect(() => {
    if (!isAuthenticated) {
      setShowExpiryWarning(false);
      setTimeLeft(null);
      activityTracker.stop();
      tokenService.resumeAutoRefresh();
      return;
    }

    // Fetch timeout setting from backend and start activity tracking
    const initializeActivityTracking = async () => {
      // Fetch admin-configured timeout from backend (falls back to local cache/default)
      await activityTracker.fetchTimeoutFromBackend();
      // Start activity tracking when authenticated
      activityTracker.start(handleInactivityWarning, handleInactivityLogout);
    };

    initializeActivityTracking();

    // Update countdown every second when warning is shown
    let countdownInterval: NodeJS.Timeout | null = null;

    if (showExpiryWarning) {
      countdownInterval = setInterval(() => {
        const remaining = activityTracker.getTimeRemainingSeconds();
        setTimeLeft(remaining);

        if (remaining <= 0) {
          // Grace period expired, force logout
          dispatch(logout());
        }
      }, 1000);
    }

    return () => {
      if (countdownInterval) {
        clearInterval(countdownInterval);
      }
    };
  }, [
    isAuthenticated,
    showExpiryWarning,
    dispatch,
    handleInactivityWarning,
    handleInactivityLogout,
  ]);

  const handleExtendSession = async () => {
    setIsExtending(true);
    setExtendError(null);

    try {
      // Refresh the token to extend the session
      const success = await tokenService.refreshToken(true);
      if (success) {
        // Reset activity tracker and hide warning
        activityTracker.resetActivity();
        setShowExpiryWarning(false);
        setTimeLeft(null);
        setExtendError(null);
        // Resume auto-refresh after successful manual extension
        tokenService.resumeAutoRefresh();
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
    activityTracker.stop();
    tokenService.resumeAutoRefresh();
  };

  const formatTime = (seconds: number) => {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
  };

  // Progress bar based on warning threshold (5 minutes)
  const progressValue = timeLeft ? Math.max(0, (timeLeft / WARNING_THRESHOLD_SECONDS) * 100) : 0;

  // Get configured timeout for display
  const timeoutMinutes = activityTracker.getTimeoutMinutes();

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
            <Typography variant="h6">Session Expiring Due to Inactivity</Typography>
          </Box>
        </DialogTitle>
        <DialogContent>
          <Typography variant="body1" gutterBottom>
            Your session will expire in <strong>{timeLeft ? formatTime(timeLeft) : '0:00'}</strong>{' '}
            due to inactivity.
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            You will be automatically logged out for security purposes. The inactivity timeout is
            set to {timeoutMinutes} minute{timeoutMinutes !== 1 ? 's' : ''}.
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
            {isExtending ? 'Extending...' : 'Continue Session'}
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
