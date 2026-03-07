import { configureStore } from '@reduxjs/toolkit';
import ruleReducer from './slices/ruleSlice';

// Minimal Redux store — only ruleSlice remains pending Zustand migration.
// Auth and notification state have moved to useAuthStore / useNotificationStore (Zustand).
export const store = configureStore({
  reducer: {
    rules: ruleReducer,
  },
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
