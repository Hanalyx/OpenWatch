import React from 'react';
import { Snackbar, Alert, type AlertProps } from '@mui/material';

interface NotificationToastProps {
  open: boolean;
  onClose: () => void;
  message: string;
  severity?: AlertProps['severity'];
  duration?: number;
  action?: React.ReactNode;
}

const NotificationToast: React.FC<NotificationToastProps> = ({
  open,
  onClose,
  message,
  severity = 'info',
  duration = 6000,
  action,
}) => {
  return (
    <Snackbar
      open={open}
      autoHideDuration={duration}
      onClose={onClose}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
    >
      <Alert
        onClose={onClose}
        severity={severity}
        variant="filled"
        action={action}
        sx={{ width: '100%' }}
      >
        {message}
      </Alert>
    </Snackbar>
  );
};

export default NotificationToast;
