import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { api } from '../../services/api';

interface Host {
  id: string;
  name: string;
  ip_address: string;
  ssh_port: number;
  auth_method: 'ssh_key' | 'password' | 'both' | 'system_default' | 'default';
  status: 'online' | 'offline' | 'unknown';
  last_scan: string | null;
  created_at: string;
  updated_at: string;
}

interface HostState {
  hosts: Host[];
  selectedHost: Host | null;
  isLoading: boolean;
  error: string | null;
}

const initialState: HostState = {
  hosts: [],
  selectedHost: null,
  isLoading: false,
  error: null,
};

export const fetchHosts = createAsyncThunk('hosts/fetchHosts', async () => {
  return api.get<Host[]>('/hosts');
});

export const createHost = createAsyncThunk('hosts/createHost', async (hostData: Partial<Host>) => {
  return api.post<Host>('/hosts', hostData);
});

export const updateHost = createAsyncThunk(
  'hosts/updateHost',
  async ({ id, data }: { id: string; data: Partial<Host> }) => {
    return api.put<Host>(`/hosts/${id}`, data);
  }
);

export const deleteHost = createAsyncThunk('hosts/deleteHost', async (id: string) => {
  await api.delete(`/hosts/${id}`);
  return id;
});

const hostSlice = createSlice({
  name: 'hosts',
  initialState,
  reducers: {
    selectHost: (state, action) => {
      state.selectedHost = action.payload;
    },
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchHosts.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(fetchHosts.fulfilled, (state, action) => {
        state.isLoading = false;
        state.hosts = action.payload;
      })
      .addCase(fetchHosts.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.error.message || 'Failed to fetch hosts';
      })
      .addCase(createHost.fulfilled, (state, action) => {
        state.hosts.push(action.payload);
      })
      .addCase(updateHost.fulfilled, (state, action) => {
        const index = state.hosts.findIndex((h) => h.id === action.payload.id);
        if (index !== -1) {
          state.hosts[index] = action.payload;
        }
        if (state.selectedHost?.id === action.payload.id) {
          state.selectedHost = action.payload;
        }
      })
      .addCase(deleteHost.fulfilled, (state, action) => {
        state.hosts = state.hosts.filter((h) => h.id !== action.payload);
        if (state.selectedHost?.id === action.payload) {
          state.selectedHost = null;
        }
      });
  },
});

export const { selectHost, clearError } = hostSlice.actions;
export default hostSlice.reducer;
