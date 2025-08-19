import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import { api } from '../../services/api';

interface RuleResult {
  id: string;
  rule: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  result: 'pass' | 'fail' | 'error' | 'unknown' | 'notapplicable';
  description: string;
  remediation: string;
}

interface Result {
  id: string;
  scan_id: string;
  host_name: string;
  profile_name: string;
  score: number;
  passed: number;
  failed: number;
  errors: number;
  unknown: number;
  notapplicable: number;
  rules: RuleResult[];
  html_report_url: string;
  xml_report_url: string;
  created_at: string;
}

interface ResultState {
  results: Result[];
  selectedResult: Result | null;
  isLoading: boolean;
  error: string | null;
}

const initialState: ResultState = {
  results: [],
  selectedResult: null,
  isLoading: false,
  error: null,
};

export const fetchResults = createAsyncThunk('results/fetchResults', async () => {
  const response = await api.get('/results');
  return response.data;
});

export const fetchResult = createAsyncThunk(
  'results/fetchResult',
  async (id: string) => {
    const response = await api.get(`/results/${id}`);
    return response.data;
  }
);

export const downloadReport = createAsyncThunk(
  'results/downloadReport',
  async ({ id, format }: { id: string; format: 'html' | 'xml' }) => {
    const response = await api.get(`/results/${id}/download`, {
      params: { format },
      responseType: 'blob',
    });
    return response;
  }
);

const resultSlice = createSlice({
  name: 'results',
  initialState,
  reducers: {
    selectResult: (state, action) => {
      state.selectedResult = action.payload;
    },
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchResults.pending, (state) => {
        state.isLoading = true;
        state.error = null;
      })
      .addCase(fetchResults.fulfilled, (state, action) => {
        state.isLoading = false;
        state.results = action.payload;
      })
      .addCase(fetchResults.rejected, (state, action) => {
        state.isLoading = false;
        state.error = action.error.message || 'Failed to fetch results';
      })
      .addCase(fetchResult.fulfilled, (state, action) => {
        state.selectedResult = action.payload;
        const index = state.results.findIndex((r) => r.id === action.payload.id);
        if (index !== -1) {
          state.results[index] = action.payload;
        }
      });
  },
});

export const { selectResult, clearError } = resultSlice.actions;
export default resultSlice.reducer;