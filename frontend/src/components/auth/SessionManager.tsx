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
  LinearProgress
} from '@mui/material';
import { useAppSelector, useAppDispatch } from '../../hooks/redux';
import { logout, clearError } from '../../store/slices/authSlice';
import { tokenService } from '../../services/tokenService';

const SessionManager: React.FC = () => {
  const dispatch = useAppDispatch();
  const { isAuthenticated, sessionExpiry, error } = useAppSelector(state => state.auth);
  const [showExpiryWarning, setShowExpiryWarning] = useState(false);
  const [timeLeft, setTimeLeft] = useState<number | null>(null);

  useEffect(() => {
    if (!isAuthenticated || !sessionExpiry) {
      setShowExpiryWarning(false);
      setTimeLeft(null);
      return;
    }

    const checkExpiry = () => {
      const now = Date.now();
      const remaining = sessionExpiry - now;
      
      // Show warning if 5 minutes or less remaining
      if (remaining <= 5 * 60 * 1000 && remaining > 0) {
        setTimeLeft(Math.floor(remaining / 1000));
        setShowExpiryWarning(true);
      } else if (remaining <= 0) {
        setShowExpiryWarning(false);
        setTimeLeft(null);
      } else {
        setShowExpiryWarning(false);
        setTimeLeft(null);
      }
    };

    // Check immediately and then every second
    checkExpiry();
    const interval = setInterval(checkExpiry, 1000);

    return () => clearInterval(interval);
  }, [isAuthenticated, sessionExpiry]);

  const handleExtendSession = async () => {
    try {
      const success = await tokenService.refreshToken();
      if (success) {
        setShowExpiryWarning(false);
        setTimeLeft(null);
      }
    } catch (error) {
      console.error('Failed to extend session:', error);
    }
  };

  const handleLogout = () => {
    dispatch(logout());
    setShowExpiryWarning(false);
  };

  const formatTime = (seconds: number) => {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
  };

  const progressValue = timeLeft ? Math.max(0, (timeLeft / (5 * 60)) * 100) : 0;

  return (
    <>
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
          <Button onClick={handleExtendSession} variant="contained">
            Extend Session
          </Button>
        </DialogActions>
      </Dialog>

      {/* Error notifications */}
      <Snackbar
        open={!!error}
        autoHideDuration={6000}
        onClose={() => dispatch(clearError())}
        anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
      >
        <Alert 
          onClose={() => dispatch(clearError())} 
          severity="error"
          variant="filled"
        >
          {error}
        </Alert>
      </Snackbar>
    </>
  );
};

export default SessionManager;