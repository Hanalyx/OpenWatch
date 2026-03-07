import { create } from 'zustand';

interface Notification {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  message: string;
  duration?: number;
}

interface SystemAlerts {
  osDiscoveryFailures: number;
}

interface NotificationState {
  notifications: Notification[];
  systemAlerts: SystemAlerts;
}

interface NotificationActions {
  addNotification: (notification: Omit<Notification, 'id'>) => void;
  removeNotification: (id: string) => void;
  clearNotifications: () => void;
  setOSDiscoveryFailures: (count: number) => void;
  setSystemAlerts: (alerts: Partial<SystemAlerts>) => void;
}

export const useNotificationStore = create<NotificationState & NotificationActions>()((set) => ({
  notifications: [],
  systemAlerts: {
    osDiscoveryFailures: 0,
  },

  addNotification: (notification) =>
    set((state) => ({
      notifications: [
        ...state.notifications,
        {
          ...notification,
          id: Date.now().toString(),
          duration: notification.duration ?? 5000,
        },
      ],
    })),

  removeNotification: (id) =>
    set((state) => ({
      notifications: state.notifications.filter((n) => n.id !== id),
    })),

  clearNotifications: () => set({ notifications: [] }),

  setOSDiscoveryFailures: (count) =>
    set((state) => ({
      systemAlerts: { ...state.systemAlerts, osDiscoveryFailures: count },
    })),

  setSystemAlerts: (alerts) =>
    set((state) => ({
      systemAlerts: { ...state.systemAlerts, ...alerts },
    })),
}));
