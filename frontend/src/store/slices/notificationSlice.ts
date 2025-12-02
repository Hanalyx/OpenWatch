import { createSlice, type PayloadAction } from '@reduxjs/toolkit';

interface Notification {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  message: string;
  duration?: number;
}

/**
 * System alert counts from various subsystems (fetched from API)
 */
interface SystemAlerts {
  osDiscoveryFailures: number;
  // Future: Add more system alert counts here
  // hostConnectivityIssues: number;
  // pendingRemediations: number;
}

interface NotificationState {
  notifications: Notification[];
  systemAlerts: SystemAlerts;
}

const initialState: NotificationState = {
  notifications: [],
  systemAlerts: {
    osDiscoveryFailures: 0,
  },
};

const notificationSlice = createSlice({
  name: 'notifications',
  initialState,
  reducers: {
    addNotification: (state, action: PayloadAction<Omit<Notification, 'id'>>) => {
      const notification: Notification = {
        ...action.payload,
        id: Date.now().toString(),
        duration: action.payload.duration || 5000,
      };
      state.notifications.push(notification);
    },
    removeNotification: (state, action: PayloadAction<string>) => {
      state.notifications = state.notifications.filter(
        (notification) => notification.id !== action.payload
      );
    },
    clearNotifications: (state) => {
      state.notifications = [];
    },
    setOSDiscoveryFailures: (state, action: PayloadAction<number>) => {
      state.systemAlerts.osDiscoveryFailures = action.payload;
    },
    setSystemAlerts: (state, action: PayloadAction<Partial<SystemAlerts>>) => {
      state.systemAlerts = { ...state.systemAlerts, ...action.payload };
    },
  },
});

export const {
  addNotification,
  removeNotification,
  clearNotifications,
  setOSDiscoveryFailures,
  setSystemAlerts,
} = notificationSlice.actions;
export default notificationSlice.reducer;
