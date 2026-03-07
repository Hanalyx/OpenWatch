// Redux store — all slices removed. Retained for Provider compatibility only.
// Global state is owned by Zustand: useAuthStore, useNotificationStore.
// TODO: remove configureStore + Provider once redux-persist is uninstalled.
import { configureStore } from '@reduxjs/toolkit';

export const store = configureStore({
  reducer: {},
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
