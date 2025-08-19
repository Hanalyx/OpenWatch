import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { api } from '../../services/api';

interface Scan {
  id: string;
  host_id: string;
  host_name: string;
  content_id: string;
  content_name: string;
  profile_id: string;
  profile_name: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  progress: number;
  started_at: string;
  completed_at: string | null;
  result_id: string | null;
  error_message: string | null;
}

interface ScanState {
  scans: Scan[];
  activeScan: Scan | null;
  isLoading: boolean;
  error: string | null;
}

const initialState: ScanState = {
  scans: [],
  activeScan: null,
  isLoading: false,
  error: null,
};

export const fetchScans = createAsyncThunk('scans/fetchScans', async () => {
  const response = await api.get('/scans');
  return response.data;
});

export const fetchScan = createAsyncThunk(
  'scans/fetchScan',
  async (id: string) => {
    const response = await api.get(`/scans/${id}`);
    return response.data;
  }
);

export const createScan = createAsyncThunk(
  'scans/createScan',
  async (scanData: {
    host_id: string;
    content_id: string;
    profile_id: string;
  }) => {
    const response = await api.post('/scans', scanData);
    return response.data;
  }
);

export const cancelScan = createAsyncThunk(
  'scans/cancelScan',
  async (id: string) => {
    const response = await api.post(`/scans/${id}/cancel`);
    return response.data;
  }
);

const scanSlice = createSlice({
  name: 'scans',
  initialState,
  reducers: {
    setActiveScan: (state, action) => {
      state.activeScan = action.payload;
    },
    updateScanProgress: (state, action) => {
      const { id, progress } = action.payload;
      const scan = state.scans.find((s) => s.id === id);
      if (scan) {
        scan.progress = progress;
      }
      if (state.activeScan?.id === id) {
        state.activeScan!.progress = progress;
      }
    },
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchScans.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(fetchScans.fulfilled, (state, action) => {
        state.isLoading = false;
        state.scans = action.payload;
      })
      .addCase(fetchScans.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.error.message || 'Failed to fetch scans';
      })
      .addCase(fetchScan.fulfilled, (state, action) => {
        state.activeScan = action.payload;
        const index = state.scans.findIndex((s) => s.id === action.payload.id);
        if (index !== -1) {
          state.scans[index] = action.payload;
        }
      })
      .addCase(createScan.fulfilled, (state, action) => {
        state.scans.unshift(action.payload);
        state.activeScan = action.payload;
      })
      .addCase(cancelScan.fulfilled, (state, action) => {
        const index = state.scans.findIndex((s) => s.id === action.payload.id);
        if (index !== -1) {
          state.scans[index] = action.payload;
        }
        if (state.activeScan?.id === action.payload.id) {
          state.activeScan = action.payload;
        }
      });
  },
});

export const { setActiveScan, updateScanProgress, clearError } = scanSlice.actions;
export default scanSlice.reducer;