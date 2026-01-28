import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { api } from '../../services/api';

/**
 * Audit log details - action-specific metadata
 * Contains common fields with extensibility for action-specific data
 */
export interface AuditLogDetails {
  // Common audit fields
  timestamp?: string;
  status?: string;
  // Resource changes
  old_value?: string | number | boolean | object;
  new_value?: string | number | boolean | object;
  // Request/response metadata
  request_id?: string;
  duration_ms?: number;
  // Error information
  error_code?: string;
  error_message?: string;
  // Additional action-specific metadata
  [key: string]: string | number | boolean | object | undefined;
}

interface AuditLog {
  id: string;
  user_id: string;
  username: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  // Action-specific details stored as JSON in backend
  details: AuditLogDetails;
  ip_address: string;
  user_agent: string;
  created_at: string;
}

interface AuditState {
  logs: AuditLog[];
  isLoading: boolean;
  error: string | null;
  totalCount: number;
  page: number;
  pageSize: number;
}

const initialState: AuditState = {
  logs: [],
  isLoading: false,
  error: null,
  totalCount: 0,
  page: 1,
  pageSize: 50,
};

export const fetchAuditLogs = createAsyncThunk(
  'audit/fetchLogs',
  async (params: {
    page?: number;
    pageSize?: number;
    startDate?: string;
    endDate?: string;
    userId?: string;
    action?: string;
  }) => {
    return api.get<{ logs: AuditLog[]; total: number; page: number; pageSize: number }>(
      '/audit',
      { params }
    );
  }
);

export const exportAuditLogs = createAsyncThunk(
  'audit/exportLogs',
  async (params: { format: 'csv' | 'json'; startDate?: string; endDate?: string }) => {
    const response = await api.get('/audit/export', {
      params,
      responseType: 'blob',
    });
    return response;
  }
);

const auditSlice = createSlice({
  name: 'audit',
  initialState,
  reducers: {
    setPage: (state, action) => {
      state.page = action.payload;
    },
    setPageSize: (state, action) => {
      state.pageSize = action.payload;
    },
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchAuditLogs.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(fetchAuditLogs.fulfilled, (state, action) => {
        state.isLoading = false;
        state.logs = action.payload.logs;
        state.totalCount = action.payload.total;
        state.page = action.payload.page;
        state.pageSize = action.payload.pageSize;
      })
      .addCase(fetchAuditLogs.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.error.message || 'Failed to fetch audit logs';
      });
  },
});

export const { setPage, setPageSize, clearError } = auditSlice.actions;
export default auditSlice.reducer;
