import { configureStore } from '@reduxjs/toolkit';
import authReducer from './slices/authSlice';
import hostReducer from './slices/hostSlice';
import contentReducer from './slices/contentSlice';
import scanReducer from './slices/scanSlice';
import resultReducer from './slices/resultSlice';
import userReducer from './slices/userSlice';
import auditReducer from './slices/auditSlice';
import notificationReducer from './slices/notificationSlice';

// Simple store without persistence for now to avoid initialization issues
export const store = configureStore({
  reducer: {
    auth: authReducer,
    hosts: hostReducer,
    content: contentReducer,
    scans: scanReducer,
    results: resultReducer,
    users: userReducer,
    audit: auditReducer,
    notifications: notificationReducer,
  },
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;