/**
 * Host UI State Slice (Client-Only)
 *
 * Manages client-side UI state for host management. Server state (host list,
 * CRUD operations) is handled by React Query hooks in hooks/useHosts.ts.
 *
 * This slice is intentionally minimal — it stores only UI preferences and
 * selection state that don't belong in server cache.
 */

import { createSlice, type PayloadAction } from '@reduxjs/toolkit';

interface HostUIState {
  /** Currently selected host ID (for detail panel, actions, etc.) */
  selectedHostId: string | null;
}

const initialState: HostUIState = {
  selectedHostId: null,
};

const hostSlice = createSlice({
  name: 'hosts',
  initialState,
  reducers: {
    selectHost: (state, action: PayloadAction<string | null>) => {
      state.selectedHostId = action.payload;
    },
  },
});

export const { selectHost } = hostSlice.actions;
export default hostSlice.reducer;
