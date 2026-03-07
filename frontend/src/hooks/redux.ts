// Typed Redux hooks — used only by ruleSlice consumers pending full Zustand migration.
// Auth and notification state: use useAuthStore / useNotificationStore instead.
import { type TypedUseSelectorHook, useDispatch, useSelector } from 'react-redux';
import type { RootState, AppDispatch } from '../store';

export const useAppDispatch = () => useDispatch<AppDispatch>();
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector;
